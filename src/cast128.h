#ifndef __CAST_H__
#define __CAST_H__

#include <inttypes.h>

typedef struct {
	uint32_t xkey[32];
	unsigned rounds;
} cast_key_t;

enum {
	CAST_ENCRYPT,
	CAST_DECRYPT,
};

enum {
    CAST_KEY_12 = 12,
    CAST_KEY_16 = 16,
};

int cast128_set_key(cast_key_t *key, uint8_t *rawkey, unsigned keybytes);
void cast128_crypt(cast_key_t *key, uint8_t *block, uint8_t op);

/* Debug functionality */
int cast128_self_test(void);

#endif /* ifndef __CAST_H__ */
