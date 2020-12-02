#ifndef SHA_H
#define SHA_H

#include <inttypes.h>
#include <stdio.h>

#define SHASUM_SIZE 20

int sha1_calculate(const char *msg, size_t msg_size, uint8_t *out,
                   size_t out_size);

#endif // SHA_H
