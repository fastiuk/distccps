#ifndef __DSA_H__
#define __DSA_H__

#include <inttypes.h>
#include <stdio.h>

#define DSA_ELEM_SZ 150

typedef struct {
    uint8_t q[DSA_ELEM_SZ];
    uint8_t p[DSA_ELEM_SZ];
    uint8_t g[DSA_ELEM_SZ];
} dsa_param_t;

typedef struct {
    uint8_t x[DSA_ELEM_SZ];
    uint8_t y[DSA_ELEM_SZ];
} dsa_keypair_t;

typedef struct {
    uint8_t r[DSA_ELEM_SZ];
    uint8_t s[DSA_ELEM_SZ];
} dsa_signature_t;

int dsa_init(dsa_param_t *param, dsa_keypair_t *keypair,
             dsa_signature_t *signature);

int dsa_generate_param(dsa_param_t *param);
int dsa_generate_keypair(const dsa_param_t *param, dsa_keypair_t *keypair);

int dsa_sign(const dsa_param_t *param, const dsa_keypair_t *keypair,
             const char *msg, size_t msg_size, dsa_signature_t *signature);

int dsa_validate(const dsa_param_t *param, const dsa_keypair_t *keypair,
                 const char *msg, size_t msg_size,
                 const dsa_signature_t *signature);

int dsa_destroy(dsa_param_t *param, dsa_keypair_t *keypair,
                dsa_signature_t *signature);

/* Debug functionality */
int dsa_self_test(void);

#endif /* ifndef __DSA_H__ */
