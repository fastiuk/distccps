#ifndef __DSA_H__
#define __DSA_H__

#include <stdio.h>

#define DSA_ELEM_SZ 150

typedef struct {
    char q[DSA_ELEM_SZ];
    char p[DSA_ELEM_SZ];
    char g[DSA_ELEM_SZ];
} dsa_param_t;

typedef struct {
    char x[DSA_ELEM_SZ];
    char y[DSA_ELEM_SZ];
} dsa_keypair_t;

typedef struct {
    char r[DSA_ELEM_SZ];
    char s[DSA_ELEM_SZ];
} dsa_signature_t;

int dsa_init(void);
int dsa_generate_param(dsa_param_t *param);
int dsa_generate_keypair(const dsa_param_t *param, dsa_keypair_t *keypair);

int dsa_sign(const dsa_param_t *param, const dsa_keypair_t *keypair,
             const char *msg, size_t msg_size, dsa_signature_t *signature);

int dsa_validate(const dsa_param_t *param, const dsa_keypair_t *keypair,
                 const char *msg, size_t msg_size,
                 const dsa_signature_t *signature);

void dsa_destroy(void);

/* Debug functionality */
int dsa_self_test(void);

#endif /* ifndef __DSA_H__ */
