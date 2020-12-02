#include <errno.h>
#include <string.h>
#include "sha.h"

#define CONST_H0    0x67452301
#define CONST_H1    0xEFCDAB89
#define CONST_H2    0x98BADCFE
#define CONST_H3    0x10325476
#define CONST_H4    0xC3D2E1F0
#define CONST_K1    0x5A827999
#define CONST_K2    0x6ED9EBA1
#define CONST_K3    0x8F1BBCDC
#define CONST_K4    0xCA62C1D6

#define CHUNK_WORDS 16
#define CHUNK_BYTES 64
#define CHUNK_BITS  512
#define STEPS       80
#define DATA_WORDS  STEPS
#define MAX_PADDING 56

typedef unsigned int uint;

uint32_t byte_flip4(uint32_t word)
{
    uint8_t *b = (uint8_t *)&word;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | ((uint32_t)b[3]);
}

uint64_t byte_flip8(uint64_t dword)
{
    uint8_t *b = (uint8_t *)&dword;
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8) | ((uint64_t)b[7]);
}

uint32_t circ_lshift(uint n, uint32_t word)
{
    return (word << n) | (word >> (32 - n));
}

uint32_t f(uint i, uint32_t b, uint32_t c, uint32_t d)
{
    if (i < 20) {
        return (b & c) | ((~b) & d);
    } else if (i < 40) {
        return b ^ c ^ d;
    } else if (i < 60) {
        return (b & c) | (b & d) | (c & d);
    } else {
        return b ^ c ^ d;
    }
}

uint32_t k(uint i)
{
    if (i < 20) {
        return CONST_K1;
    } else if (i < 40) {
        return CONST_K2;
    } else if (i < 60) {
        return CONST_K3;
    } else {
        return CONST_K4;
    }
}

int sha1_calculate(const char *msg, size_t msg_size, uint8_t *sha,
                   size_t sha_size)
{
    uint8_t padding[CHUNK_BYTES] = {0x80, 0x0};
    uint16_t padding_size;
    uint32_t w[DATA_WORDS];
    uint8_t *msg_chunk = (uint8_t *)w;
    uint64_t length_bits;

    uint32_t h0 = CONST_H0;
    uint32_t h1 = CONST_H1;
    uint32_t h2 = CONST_H2;
    uint32_t h3 = CONST_H3;
    uint32_t h4 = CONST_H4;
    uint32_t a, b, c, d, e, temp;

    if ((!msg && msg_size) || !sha || (sha_size < SHASUM_SIZE)) {
        return -EINVAL;
    }

    length_bits = msg_size * 8;
    padding_size = (MAX_PADDING - (msg_size % CHUNK_BYTES));

    if (!padding_size) {
        padding_size = MAX_PADDING;
    }

    // For each message chunk
    for (uint64_t chunk = 0; chunk <= (msg_size / CHUNK_BYTES); ++chunk) {
        if (chunk < (msg_size / CHUNK_BYTES)) {
            memcpy(msg_chunk, msg + chunk * CHUNK_BYTES, CHUNK_BYTES);
        } else {
            memcpy(msg_chunk, msg, msg_size % CHUNK_BYTES);
            msg_chunk += msg_size % CHUNK_BYTES;
            memcpy(msg_chunk, padding, padding_size);
            msg_chunk += padding_size;
            *(uint64_t *)msg_chunk = byte_flip8(length_bits);
        }

        // Flip bytes (convert from string to data)
        for (uint i = 0; i < 16; ++i) {
            w[i] = byte_flip4(w[i]);
        }

        // Extend into eighty words
        for (uint i = CHUNK_WORDS; i < DATA_WORDS; ++i) {
            w[i] = circ_lshift(1, w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]);
        }

        // Calculating SHA1 for one chunk
        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;

        for (uint i = 0; i < STEPS; ++i) {
            temp = circ_lshift(5, a) + f(i, b, c, d) + e + w[i] + k(i);
            e = d;
            d = c;
            c = circ_lshift(30, b);
            b = a;
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    // Copy SHA1 into buffer
    ((uint32_t *)sha)[0] = byte_flip4(h0);
    ((uint32_t *)sha)[1] = byte_flip4(h1);
    ((uint32_t *)sha)[2] = byte_flip4(h2);
    ((uint32_t *)sha)[3] = byte_flip4(h3);
    ((uint32_t *)sha)[4] = byte_flip4(h4);

    return 0;
}
