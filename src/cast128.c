#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "cast128.h"
#include "cast128_sboxes.h"

/* Macros to access 8-bit bytes out of a 32-bit word */
#define U8a(x) ((uint8_t)(x>>24))
#define U8b(x) ((uint8_t)((x>>16)&255))
#define U8c(x) ((uint8_t)((x>>8)&255))
#define U8d(x) ((uint8_t)((x)&255))

/* CAST-128 uses three different round functions */
#define F1(l, r, i, t) \
	t = circ_lshift(key->xkey[i+16], key->xkey[i] + r); \
	l ^= ((sbox_s1[U8a(t)] ^ sbox_s2[U8b(t)]) \
	 - sbox_s3[U8c(t)]) + sbox_s4[U8d(t)];
#define F2(l, r, i, t) \
	t = circ_lshift(key->xkey[i+16], key->xkey[i] ^ r); \
	l ^= ((sbox_s1[U8a(t)] - sbox_s2[U8b(t)]) \
	 + sbox_s3[U8c(t)]) ^ sbox_s4[U8d(t)];
#define F3(l, r, i, t) \
	t = circ_lshift(key->xkey[i+16], key->xkey[i] - r); \
	l ^= ((sbox_s1[U8a(t)] + sbox_s2[U8b(t)]) \
	 ^ sbox_s3[U8c(t)]) - sbox_s4[U8d(t)];

#define CAST_SMALL_KEY 		10
#define CAST_SMALL_ROUNDS 	12
#define CAST_FULL_ROUNDS 	16
#define CAST_KEY_SIZE		16
#define CAST_BLOCK_SIZE		8
#define CAST_SIZE			sizeof(cast_key_t)

#define TEST_CIPHER			"434e25460c8c9525"

static uint32_t circ_lshift(uint8_t n, uint32_t word)
{
    return (word << n) | (word >> (32 - n));
}

static void F(cast_key_t *key, uint8_t i, uint32_t *r, uint32_t *l, uint32_t *t)
{
	if (i % 2 == 0) {
		if (i % 3 == 0) {
			F1(*l, *r, i, *t);
		} else if (i % 3 == 1) {
			F2(*l, *r, i, *t);
		} else {
			F3(*l, *r, i, *t);
		}
	} else {
		if (i % 3 == 0) {
			F1(*r, *l, i, *t);
		} else if (i % 3 == 1) {
			F2(*r, *l, i, *t);
		} else {
			F3(*r, *l, i, *t);
		}
	}
}

int cast128_set_key(cast_key_t *key, uint8_t *rawkey, unsigned keybytes)
{
	uint32_t t[4], z[4], x[4];
	unsigned i;

	/* Set number of rounds to 12 or 16, depending on key length */
	key->rounds = (keybytes <= CAST_SMALL_KEY)
	    ? CAST_SMALL_ROUNDS : CAST_FULL_ROUNDS;


	/* Copy key to workspace x */
	for (i = 0; i < 4; i++) {
		x[i] = 0;
        z[i] = 0;
        t[i] = 0;
		if ((i * 4 + 0) < keybytes)
			x[i] = (uint32_t) rawkey[i * 4 + 0] << 24;
		if ((i * 4 + 1) < keybytes)
			x[i] |= (uint32_t) rawkey[i * 4 + 1] << 16;
		if ((i * 4 + 2) < keybytes)
			x[i] |= (uint32_t) rawkey[i * 4 + 2] << 8;
		if ((i * 4 + 3) < keybytes)
			x[i] |= (uint32_t) rawkey[i * 4 + 3];
	}
	/* Generate 32 subkeys, four at a time */
	for (i = 0; i < 32; i += 4) {
		switch (i & 4) {
		case 0:
			t[0] = z[0] = x[0] ^ sbox_s5[U8b(x[3])]
			    ^ sbox_s6[U8d(x[3])] ^ sbox_s7[U8a(x[3])]
			    ^ sbox_s8[U8c(x[3])] ^
			    sbox_s7[U8a(x[2])];
			t[1] = z[1] = x[2] ^ sbox_s5[U8a(z[0])]
			    ^ sbox_s6[U8c(z[0])] ^ sbox_s7[U8b(z[0])]
			    ^ sbox_s8[U8d(z[0])] ^
			    sbox_s8[U8c(x[2])];
			t[2] = z[2] = x[3] ^ sbox_s5[U8d(z[1])]
			    ^ sbox_s6[U8c(z[1])] ^ sbox_s7[U8b(z[1])]
			    ^ sbox_s8[U8a(z[1])] ^
			    sbox_s5[U8b(x[2])];
			t[3] = z[3] =
			    x[1] ^ sbox_s5[U8c(z[2])] ^
			    sbox_s6[U8b(z[2])] ^ sbox_s7[U8d(z[2])]
			    ^ sbox_s8[U8a(z[2])] ^
			    sbox_s6[U8d(x[2])];
			break;
		case 4:
			t[0] = x[0] = z[2] ^ sbox_s5[U8b(z[1])]
			    ^ sbox_s6[U8d(z[1])] ^ sbox_s7[U8a(z[1])]
			    ^ sbox_s8[U8c(z[1])] ^
			    sbox_s7[U8a(z[0])];
			t[1] = x[1] = z[0] ^ sbox_s5[U8a(x[0])]
			    ^ sbox_s6[U8c(x[0])] ^ sbox_s7[U8b(x[0])]
			    ^ sbox_s8[U8d(x[0])] ^
			    sbox_s8[U8c(z[0])];
			t[2] = x[2] = z[1] ^ sbox_s5[U8d(x[1])]
			    ^ sbox_s6[U8c(x[1])] ^ sbox_s7[U8b(x[1])]
			    ^ sbox_s8[U8a(x[1])] ^
			    sbox_s5[U8b(z[0])];
			t[3] = x[3] = z[3] ^ sbox_s5[U8c(x[2])]
			    ^ sbox_s6[U8b(x[2])] ^ sbox_s7[U8d(x[2])]
			    ^ sbox_s8[U8a(x[2])] ^
			    sbox_s6[U8d(z[0])];
			break;
		}
		switch (i & 12) {
		case 0:
		case 12:
			key->xkey[i + 0] =
			    sbox_s5[U8a(t[2])] ^ sbox_s6[U8b(t[2])]
			    ^ sbox_s7[U8d(t[1])] ^
			    sbox_s8[U8c(t[1])];
			key->xkey[i + 1] =
			    sbox_s5[U8c(t[2])] ^ sbox_s6[U8d(t[2])]
			    ^ sbox_s7[U8b(t[1])] ^
			    sbox_s8[U8a(t[1])];
			key->xkey[i + 2] =
			    sbox_s5[U8a(t[3])] ^ sbox_s6[U8b(t[3])]
			    ^ sbox_s7[U8d(t[0])] ^
			    sbox_s8[U8c(t[0])];
			key->xkey[i + 3] =
			    sbox_s5[U8c(t[3])] ^ sbox_s6[U8d(t[3])]
			    ^ sbox_s7[U8b(t[0])] ^
			    sbox_s8[U8a(t[0])];
			break;
		case 4:
		case 8:
			key->xkey[i + 0] =
			    sbox_s5[U8d(t[0])] ^ sbox_s6[U8c(t[0])]
			    ^ sbox_s7[U8a(t[3])] ^
			    sbox_s8[U8b(t[3])];
			key->xkey[i + 1] =
			    sbox_s5[U8b(t[0])] ^ sbox_s6[U8a(t[0])]
			    ^ sbox_s7[U8c(t[3])] ^
			    sbox_s8[U8d(t[3])];
			key->xkey[i + 2] =
			    sbox_s5[U8d(t[1])] ^ sbox_s6[U8c(t[1])]
			    ^ sbox_s7[U8a(t[2])] ^
			    sbox_s8[U8b(t[2])];
			key->xkey[i + 3] =
			    sbox_s5[U8b(t[1])] ^ sbox_s6[U8a(t[1])]
			    ^ sbox_s7[U8c(t[2])] ^
			    sbox_s8[U8d(t[2])];
			break;
		}
		switch (i & 12) {
		case 0:
			key->xkey[i + 0] ^= sbox_s5[U8c(z[0])];
			key->xkey[i + 1] ^= sbox_s6[U8c(z[1])];
			key->xkey[i + 2] ^= sbox_s7[U8b(z[2])];
			key->xkey[i + 3] ^= sbox_s8[U8a(z[3])];
			break;
		case 4:
			key->xkey[i + 0] ^= sbox_s5[U8a(x[2])];
			key->xkey[i + 1] ^= sbox_s6[U8b(x[3])];
			key->xkey[i + 2] ^= sbox_s7[U8d(x[0])];
			key->xkey[i + 3] ^= sbox_s8[U8d(x[1])];
			break;
		case 8:
			key->xkey[i + 0] ^= sbox_s5[U8b(z[2])];
			key->xkey[i + 1] ^= sbox_s6[U8a(z[3])];
			key->xkey[i + 2] ^= sbox_s7[U8c(z[0])];
			key->xkey[i + 3] ^= sbox_s8[U8c(z[1])];
			break;
		case 12:
			key->xkey[i + 0] ^= sbox_s5[U8d(x[0])];
			key->xkey[i + 1] ^= sbox_s6[U8d(x[1])];
			key->xkey[i + 2] ^= sbox_s7[U8a(x[2])];
			key->xkey[i + 3] ^= sbox_s8[U8b(x[3])];
			break;
		}
		if (i >= 16) {
			key->xkey[i + 0] &= 31;
			key->xkey[i + 1] &= 31;
			key->xkey[i + 2] &= 31;
			key->xkey[i + 3] &= 31;
		}
	}
	/* Wipe clean */
	for (i = 0; i < 4; i++) {
		t[i] = x[i] = z[i] = 0;
	}
	return 0;
}

void cast128_crypt(cast_key_t *key, uint8_t *block, uint8_t op)
{
	uint32_t t, l, r;
	uint8_t ii;

	/* Get inblock into l,r */
	l = ((uint32_t) block[0] << 24) | ((uint32_t) block[1] << 16)
		| ((uint32_t) block[2] << 8) | (uint32_t) block[3];
	r = ((uint32_t) block[4] << 24) | ((uint32_t) block[5] << 16)
		| ((uint32_t) block[6] << 8) | (uint32_t) block[7];

	if (op == CAST_DECRYPT) {
		l = l ^ r;
		r = l ^ r;
		l = l ^ r;
	}

	/* Do the work */
	for (int i = 0; i < key->rounds; ++i) {
		ii = op == CAST_ENCRYPT ? i : key->rounds - i - 1;
		F(key, ii, &r, &l, &t);
	}
	
	if (op == CAST_DECRYPT) {
		l = l ^ r;
		r = l ^ r;
		l = l ^ r;
	}

	/* Put l,r into outblock */
	block[0] = U8a(r);
	block[1] = U8b(r);
	block[2] = U8c(r);
	block[3] = U8d(r);
	block[4] = U8a(l);
	block[5] = U8b(l);
	block[6] = U8c(l);
	block[7] = U8d(l);

	/* Wipe clean */
	t = l = r = 0;
}

int cast128_self_test(void)
{
	char *keyword;
	char plaintext[16];
	char ciphertext[16];
	int blocksize = CAST_BLOCK_SIZE, j;
	void *key;
	unsigned char cipher_tmp[200];

	keyword = calloc(1, CAST_KEY_SIZE);
	if (keyword == NULL)
		return -1;

	for (j = 0; j < CAST_KEY_SIZE; j++) {
		keyword[j] = ((j * 2 + 10) % 256);
	}

	for (j = 0; j < blocksize; j++) {
		plaintext[j] = j % 256;
	}
	key = malloc(CAST_SIZE);
	if (key == NULL)
		return -1;

	memcpy(ciphertext, plaintext, blocksize);

	cast128_set_key(key, (void *) keyword, CAST_KEY_SIZE);
	free(keyword);
	cast128_crypt(key, (void *) ciphertext, CAST_ENCRYPT);

	for (j = 0; j < blocksize; j++) {
		sprintf(&((char *) cipher_tmp)[2 * j], "%.2x",
			(unsigned char)ciphertext[j]);
	}

	if (strcmp((char *) cipher_tmp, TEST_CIPHER) != 0) {
		printf("failed compatibility\n");
		printf("Expected: %s\nGot: %s\n", TEST_CIPHER,
		       (char *) cipher_tmp);
		free(key);
		return -1;
	}
	cast128_crypt(key, (void *) ciphertext, CAST_DECRYPT);
	free(key);

	if (strcmp(ciphertext, plaintext) != 0) {
		printf("failed internally\n");
		return -1;
	}

	return 0;
}
