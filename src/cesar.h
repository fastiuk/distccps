#ifndef __CESAR_H__
#define __CESAR_H__

#include <inttypes.h>
#include <stdlib.h>

int cesar_keygen(uint8_t *key, size_t ksize);
int cesar_encrypt(uint8_t *key, size_t ksize, uint8_t *data, size_t dsize);
int cesar_decrypt(uint8_t *key, size_t ksize, uint8_t *data, size_t dsize);
int cesar_shuffle_key(uint8_t *key, size_t ksize);

#endif /* ifndef __CESAR_H__ */
