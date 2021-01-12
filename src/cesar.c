#include "cesar.h"

#include <fcntl.h>
#include <unistd.h>

int cesar_keygen(uint8_t *key, size_t ksize)
{
    uint32_t seed;
    int fd;

    if (!key || !ksize) {
        return -1;
    }

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    read(fd, &seed, sizeof(seed));
    close(fd);
    srand(seed);

    for (size_t i = 0; i < ksize; ++i) {
        key[i] = rand() % 256;
    }

    return 0;
}

int cesar_encrypt(uint8_t *key, size_t ksize, uint8_t *data, size_t dsize)
{
    uint8_t x = 0;

    if (!key || !ksize || !data || !dsize) {
        return -1;
    }

    for (size_t i = 0; i < ksize; ++i) {
        x += key[i];
    }

    for (size_t i = 0; i < dsize; ++i) {
        data[i] += x;
    }

    return 0;
}

int cesar_decrypt(uint8_t *key, size_t ksize, uint8_t *data, size_t dsize)
{
    uint8_t x = 0;

    if (!key || !ksize || !data || !dsize) {
        return -1;
    }

    for (size_t i = 0; i < ksize; ++i) {
        x += key[i];
    }

    for (size_t i = 0; i < dsize; ++i) {
        data[i] -= x;
    }

    return 0;
}

int cesar_shuffle_key(uint8_t *key, size_t ksize)
{
    if (!key || !ksize) {
        return -1;
    }

    for (size_t i = 0; i < ksize / 2; ++i) {
        size_t j = ksize - i - 1;
        key[i] = key[i] ^ key[j];
        key[j] = key[i] ^ key[j];
        key[i] = key[i] ^ key[j];
    }

    return 0;
}
