#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <gmp.h>

#include "sha.h"

#define SIZE_Q 160
#define SIZE_P 512

typedef unsigned int uint;

static gmp_randstate_t state;

void print_num_base(const char *msg, mpz_t num, uint base)
{
    printf("%s(%zu bits) = ", msg, mpz_sizeinbase(num, 2));
    mpz_out_str(stdout, base, num);
    printf("\n");
}

void print_num(const char *msg, mpz_t num)
{
    print_num_base(msg, num, 10);
}

void gen_q(mpz_t q)
{
    mpz_urandomb(q, state, SIZE_Q);
    mpz_setbit(q, SIZE_Q - 1);
    mpz_nextprime(q, q);
}

void gen_p(mpz_t p, mpz_t q)
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

void gen_g(mpz_t g, mpz_t p, mpz_t q)
{
    mpz_t dv, p1;

    mpz_init(dv);
    mpz_init(p1);

    mpz_set(p1, p);
    mpz_sub_ui(p1, p1, 1);
    mpz_div(dv, p1, q);

    // use random g from 2 to q-1
    mpz_set_ui(g, 2);
    mpz_powm(g, g, dv, p);
    // try again if 1

    mpz_clear(dv);
    mpz_clear(p1);
}

void gen_x(mpz_t x, mpz_t q)
{
    // 1 <= x <= q - 1
    mpz_urandomm(x, state, q);
}

void gen_y(mpz_t y, mpz_t g, mpz_t x, mpz_t p)
{
    mpz_powm(y, g, x, p);
}

void gen_k(mpz_t k, mpz_t q)
{
    // 1 <= k <= q - 1
    mpz_urandomm(k, state, q);
}

void gen_r(mpz_t r, mpz_t g, mpz_t k, mpz_t p, mpz_t q)
{
    mpz_powm(r, g, k, p);
    mpz_mod(r, r, q);
    // If r == 0 - start again with another k
}

void gen_s(mpz_t s, mpz_t k, mpz_t x, mpz_t r, mpz_t q, uint8_t *msg, size_t size)
{
    uint8_t sha_bytes[20];
    mpz_t sha;
    mpz_t tmp;

    mpz_init(sha);
    mpz_init(tmp);

    sha1_calculate(msg, size, sha_bytes, sizeof(sha_bytes));
    mpz_import(sha, 20, 1, sizeof(sha_bytes[0]), 0, 0, sha_bytes);

    mpz_mul(s, x, r);
    mpz_add(s, s, sha);
    mpz_mod(s, s, q);
    mpz_invert(tmp, k, q);
    mpz_mul(s, s, tmp);
    mpz_mod(s, s, q);

    mpz_clear(sha);
    mpz_clear(tmp);
}

void gen_w(mpz_t w, mpz_t s, mpz_t q)
{
    mpz_invert(w, s, q);
}

void gen_u1(mpz_t u1, mpz_t w, mpz_t q, uint8_t *msg, size_t size)
{
    uint8_t sha_bytes[20];
    mpz_t sha;

    mpz_init(sha);

    sha1_calculate(msg, size, sha_bytes, sizeof(sha_bytes));
    mpz_import(sha, 20, 1, sizeof(sha_bytes[0]), 0, 0, sha_bytes);

    mpz_mul(u1, sha, w);
    mpz_mod(u1, u1, q);
    
    mpz_clear(sha);
}

void gen_u2(mpz_t u2, mpz_t r, mpz_t w, mpz_t q)
{
    mpz_mul(u2, r, w);
    mpz_mod(u2, u2, q);
}

void gen_v(mpz_t v, mpz_t g, mpz_t u1, mpz_t y, mpz_t u2, mpz_t p, mpz_t q)
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

int dsa_test(void)
{
    mpz_t g, p, p1, q, x, y, k, r, s, w, u1, u2, v;
    uint seed;
    uint8_t sha[20];
    int fd;

    fd = open("/dev/urandom", O_RDONLY);
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
    print_num("q - ", q);

    gen_p(p, q);
    print_num("P - ", p);

    gen_g(g, p, q);
    print_num("G - ", g);

    gen_x(x, q);
    print_num("x - ", x);

    gen_y(y, g, x, p);
    print_num("y - ", y);

    gen_k(k, q);
    print_num("k - ", k);

    gen_r(r, g, k, p, q);
    print_num("r - ", r);

    gen_s(s, k, x, r, q, "Hello", 5);
    print_num("s - ", s);

    gen_w(w, s, q);
    print_num("w - ", w);
    
    gen_u1(u1, w, q, "Hello", 5);
    print_num("u1 - ", u1);
    
    gen_u2(u2, r, w, q);
    print_num("u2 - ", u2);
    
    gen_v(v, g, u1, y, u2, p, q);
    print_num("v - ", v);

    if (mpz_cmp(r, v) == 0) {
        printf("Signature is valid\n");
    } else {
        printf("Signature invalid\n");
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

    return 0;
}
