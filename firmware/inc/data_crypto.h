#ifndef __DATA_CRYPTO_H__
#define __DATA_CRYPTO_H__

#include <stddef.h>
#include <stdint.h>

#define DATA_CRYPTO_KEY_SIZE 16

void derive_data_key(const char *label, uint8_t out_key[DATA_CRYPTO_KEY_SIZE]);
void crypt_buffer(uint8_t *buf, size_t len, const uint8_t key[DATA_CRYPTO_KEY_SIZE], uint32_t nonce);
uint32_t keyed_mac32(const uint8_t *buf, size_t len, const uint8_t key[DATA_CRYPTO_KEY_SIZE], uint32_t nonce);

#endif
