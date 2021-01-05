#include "dsa.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <gmp.h>

#include "sha.h"

#define SIZE_Q 160
#define SIZE_P 512

typedef unsigned int uint;

static gmp_randstate_t state;
static int state_init;

static __attribute__((unused)) void print_num_base(const char *msg,
                                                   const mpz_t num, uint base)
{
    printf("%s(%zu bits) = ", msg, mpz_sizeinbase(num, 2));
    mpz_out_str(stdout, base, num);
    printf("\n");
}

static __attribute__((unused)) void print_num(const char *msg, const mpz_t num)
{
    print_num_base(msg, num, 16);
}

static void gen_q(mpz_t q)
{
    mpz_urandomb(q, state, SIZE_Q);
    mpz_setbit(q, SIZE_Q - 1);
    mpz_nextprime(q, q);
}

static void gen_p(mpz_t p, const mpz_t q)
{
    mpz_t tmp;

    mpz_init(tmp);

    /* Make random even multiplier */
    mpz_urandomb(tmp, state, SIZE_P - SIZE_Q);
    mpz_clrbit(tmp, 0);
    mpz_setbit(tmp, SIZE_P - SIZE_Q - 1);

    /* Init p with q * tmp and make it odd */
    mpz_mul(p, q, tmp);
    mpz_add_ui(p, p, 1);

    /* Make q * 2 number */
    mpz_mul_ui(tmp, q, 2);

    /* Add tmp until prime */
    while (mpz_probab_prime_p(p, 30) == 0) {
        mpz_add(p, p, tmp);
    }

    mpz_clear(tmp);
}

static void gen_g(mpz_t g, const mpz_t p, const mpz_t q)
{
    mpz_t dv, p1;

    mpz_init(dv);
    mpz_init(p1);

    mpz_set(p1, p);
    mpz_sub_ui(p1, p1, 1);
    mpz_div(dv, p1, q);

    /* Use random g from 2 to q-1 */
    mpz_set_ui(g, 2);
    mpz_powm(g, g, dv, p);
    /* TODO: Try again if g == 1 */

    mpz_clear(dv);
    mpz_clear(p1);
}

static void gen_x(mpz_t x, const mpz_t q)
{
    /* TODO: Check for 1 <= x <= q - 1 */
    mpz_urandomm(x, state, q);
}

static void gen_y(mpz_t y, const mpz_t g,const  mpz_t x, const mpz_t p)
{
    mpz_powm(y, g, x, p);
}

static void gen_k(mpz_t k, const mpz_t q)
{
    /* TODO: Check for 1 <= k <= q - 1 */
    mpz_urandomm(k, state, q);
}

static void gen_r(mpz_t r, const mpz_t g, const mpz_t k, const mpz_t p,
                  const mpz_t q)
{
    mpz_powm(r, g, k, p);
    mpz_mod(r, r, q);
    /* TODO: If r == 0 - start again with another k */
}

static void gen_s(mpz_t s, const mpz_t k, const mpz_t x, const mpz_t r,
                  const mpz_t q, const char *msg, size_t size)
{
    uint8_t sha_bytes[20];
    mpz_t sha;
    mpz_t tmp;

    mpz_init(sha);
    mpz_init(tmp);

    sha1_calculate(msg, size, sha_bytes, sizeof(sha_bytes));
    mpz_import(sha, sizeof(sha_bytes), 1, sizeof(sha_bytes[0]), 0, 0,
               sha_bytes);

    mpz_mul(s, x, r);
    mpz_add(s, s, sha);
    mpz_mod(s, s, q);
    mpz_invert(tmp, k, q);
    mpz_mul(s, s, tmp);
    mpz_mod(s, s, q);

    mpz_clear(sha);
    mpz_clear(tmp);
}

static void gen_w(mpz_t w, const mpz_t s, const mpz_t q)
{
    mpz_invert(w, s, q);
}

static void gen_u1(mpz_t u1, const mpz_t w, const mpz_t q, const char *msg,
                   size_t size)
{
    uint8_t sha_bytes[20];
    mpz_t sha;

    mpz_init(sha);

    sha1_calculate(msg, size, sha_bytes, sizeof(sha_bytes));
    mpz_import(sha, sizeof(sha_bytes), 1, sizeof(sha_bytes[0]), 0, 0,
               sha_bytes);

    mpz_mul(u1, sha, w);
    mpz_mod(u1, u1, q);
    
    mpz_clear(sha);
}

static void gen_u2(mpz_t u2, const mpz_t r, const mpz_t w, const mpz_t q)
{
    mpz_mul(u2, r, w);
    mpz_mod(u2, u2, q);
}

static void gen_v(mpz_t v, const mpz_t g, const mpz_t u1, const mpz_t y,
                  const mpz_t u2, const mpz_t p, const mpz_t q)
{
    mpz_t tmp;

    mpz_init(tmp);

    mpz_powm(tmp, g, u1, p);
    mpz_powm(v, y, u2, p);
    mpz_mul(v, v, tmp);
    mpz_mod(v, v, p);
    mpz_mod(v, v, q);

    mpz_clear(tmp);
}

static void dsa_mpz_import(const char *data, mpz_t num)
{
    mpz_init_set_str(num, data, 16);
}

static int dsa_mpz_export(const mpz_t num, char *data, size_t data_size)
{
    void (*freefunc)(void *, size_t);
    char *tmp_str;
    size_t len;

    tmp_str = mpz_get_str(NULL, 16, num);
    len = strlen(tmp_str) + 1;
    if (data_size < len) {
        return -1;
    }

    memcpy(data, tmp_str, len);
    mp_get_memory_functions(NULL, NULL, &freefunc);
    freefunc(tmp_str, len);

    return 0;
}

int dsa_init(void)
{
    uint seed;
    int fd;

    if (!state_init) {
        fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) {
            return -1;
        }

        read(fd, &seed, sizeof(seed));
        close(fd);

        gmp_randinit_mt(state);
        gmp_randseed_ui(state, seed);

        state_init = 1;
    }

    return 0;
}

int dsa_generate_param(dsa_param_t *param)
{
    mpz_t q, p, g;
    int ret = 0;

    if (!param) {
        return -1;
    }

    mpz_init(q);
    mpz_init(p);
    mpz_init(g);

    gen_q(q);
    gen_p(p, q);
    gen_g(g, p, q);

    if (dsa_mpz_export(q, param->q, sizeof(param->q)) ||
        dsa_mpz_export(p, param->p, sizeof(param->p)) ||
        dsa_mpz_export(g, param->g, sizeof(param->g))) {
        ret = -1;
    }

    mpz_clear(q);
    mpz_clear(p);
    mpz_clear(g);

    return ret;
}

int dsa_generate_keypair(const dsa_param_t *param, dsa_keypair_t *keypair)
{
    mpz_t g, p, q, x, y;
    int ret = 0;

    if (!param || !keypair) {
        return -1;
    }

    mpz_init(q);
    mpz_init(p);
    mpz_init(g);

    mpz_init(x);
    mpz_init(y);

    dsa_mpz_import(param->q, q);
    dsa_mpz_import(param->p, p);
    dsa_mpz_import(param->g, g);

    gen_x(x, q);
    gen_y(y, g, x, p);

    if (dsa_mpz_export(x, keypair->x, sizeof(keypair->x)) ||
        dsa_mpz_export(y, keypair->y, sizeof(keypair->y))) {
        ret = -1;
    }

    mpz_clear(q);
    mpz_clear(p);
    mpz_clear(g);

    mpz_clear(x);
    mpz_clear(y);

    return ret;
}

int dsa_sign(const dsa_param_t *param, const dsa_keypair_t *keypair,
             const char *msg, size_t msg_size, dsa_signature_t *signature)
{
    mpz_t g, p, q, x, y, k, r, s;
    int ret = 0;

    if (!param || !keypair || !signature || !msg || !msg_size) {
        return -1;
    }

    mpz_init(q);
    mpz_init(p);
    mpz_init(g);

    mpz_init(x);
    mpz_init(y);

    mpz_init(k);
    mpz_init(r);
    mpz_init(s);

    dsa_mpz_import(param->q, q);
    dsa_mpz_import(param->p, p);
    dsa_mpz_import(param->g, g);

    dsa_mpz_import(keypair->x, x);
    dsa_mpz_import(keypair->y, y);

    gen_k(k, q);
    gen_r(r, g, k, p, q);
    gen_s(s, k, x, r, q, msg, msg_size);

    if (dsa_mpz_export(r, signature->r, sizeof(signature->r)) ||
        dsa_mpz_export(s, signature->s, sizeof(signature->s))) {
        ret = -1;
    }

    mpz_clear(q);
    mpz_clear(p);
    mpz_clear(g);

    mpz_clear(x);
    mpz_clear(y);

    mpz_clear(k);
    mpz_clear(r);
    mpz_clear(s);

    return ret;
}

int dsa_validate(const dsa_param_t *param, const dsa_keypair_t *keypair,
                 const char *msg, size_t msg_size,
                 const dsa_signature_t *signature)
{
    mpz_t g, p, q, x, y, k, r, s, w, u1, u2, v;
    int ret = 0;

    if (!param || !keypair || !signature || !msg || !msg_size) {
        return -1;
    }

    mpz_init(q);
    mpz_init(p);
    mpz_init(g);

    mpz_init(x);
    mpz_init(y);

    mpz_init(k);
    mpz_init(r);
    mpz_init(s);

    mpz_init(w);
    mpz_init(u1);
    mpz_init(u2);
    mpz_init(v);

    dsa_mpz_import(param->q, q);
    dsa_mpz_import(param->p, p);
    dsa_mpz_import(param->g, g);

    dsa_mpz_import(keypair->x, x);
    dsa_mpz_import(keypair->y, y);

    dsa_mpz_import(signature->r, r);
    dsa_mpz_import(signature->s, s);

    gen_w(w, s, q);
    gen_u1(u1, w, q, msg, msg_size);
    gen_u2(u2, r, w, q);
    gen_v(v, g, u1, y, u2, p, q);

    if (mpz_cmp(r, v) != 0) {
        ret = -1;
    }

    mpz_clear(q);
    mpz_clear(p);
    mpz_clear(g);

    mpz_clear(x);
    mpz_clear(y);

    mpz_clear(k);
    mpz_clear(r);
    mpz_clear(s);

    mpz_clear(w);
    mpz_clear(u1);
    mpz_clear(u2);
    mpz_clear(v);

    return ret;
}

void dsa_destroy(void)
{
    if (state_init) {
        gmp_randclear(state);
    }
}

/* Debug functionality */
int dsa_self_test(void)
{
    mpz_t g, p, q, x, y, k, r, s, w, u1, u2, v;
    uint seed;
    int fd;
    int ret = 0;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    read(fd, &seed, sizeof(seed));
    close(fd);

    gmp_randinit_mt(state);
    gmp_randseed_ui(state, seed);

    mpz_init(q);
    mpz_init(p);
    mpz_init(g);

    mpz_init(x);
    mpz_init(y);

    mpz_init(k);
    mpz_init(r);
    mpz_init(s);

    mpz_init(w);
    mpz_init(u1);
    mpz_init(u2);
    mpz_init(v);

    gen_q(q);
    gen_p(p, q);
    gen_g(g, p, q);
    gen_x(x, q);
    gen_y(y, g, x, p);
    gen_k(k, q);
    gen_r(r, g, k, p, q);
    gen_s(s, k, x, r, q, "Hello", 5);
    gen_w(w, s, q);
    gen_u1(u1, w, q, "Hello", 5);
    gen_u2(u2, r, w, q);
    gen_v(v, g, u1, y, u2, p, q);

    if (mpz_cmp(r, v) != 0) {
        ret = -1;
    }

    gmp_randclear(state);

    mpz_clear(q);
    mpz_clear(p);
    mpz_clear(g);

    mpz_clear(x);
    mpz_clear(y);

    mpz_clear(k);
    mpz_clear(r);
    mpz_clear(s);

    mpz_clear(w);
    mpz_clear(u1);
    mpz_clear(u2);
    mpz_clear(v);

    return ret;
}
