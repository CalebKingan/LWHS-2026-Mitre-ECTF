#include "data_crypto.h"
#include "crypto.h"
#include "secrets.h"

#include <string.h>

#define HASH_INPUT_MAX (ROOT_KEY_SIZE + 64U)

static void u32_to_be(uint32_t value, uint8_t out[4])
{
    out[0] = (uint8_t)(value >> 24U);
    out[1] = (uint8_t)(value >> 16U);
    out[2] = (uint8_t)(value >> 8U);
    out[3] = (uint8_t)value;
}

void derive_data_key(const char *label, uint8_t out_key[DATA_CRYPTO_KEY_SIZE])
{
    uint8_t digest[HASH_SIZE] = {0};
    uint8_t input[HASH_INPUT_MAX] = {0};
    size_t label_len = 0;

    while (label[label_len] != '\0' && label_len < (HASH_INPUT_MAX - ROOT_KEY_SIZE)) {
        label_len++;
    }

    memcpy(input, GLOBAL_ROOT_KEY, ROOT_KEY_SIZE);
    memcpy(input + ROOT_KEY_SIZE, label, label_len);

    if (hash(input, ROOT_KEY_SIZE + label_len, digest) != 0) {
        memset(out_key, 0, DATA_CRYPTO_KEY_SIZE);
        return;
    }

    memcpy(out_key, digest, DATA_CRYPTO_KEY_SIZE);
}

void crypt_buffer(uint8_t *buf, size_t len, const uint8_t key[DATA_CRYPTO_KEY_SIZE], uint32_t nonce)
{
    uint8_t counter_blk[BLOCK_SIZE] = {0};
    uint8_t keystream[BLOCK_SIZE] = {0};
    size_t offset = 0;
    uint32_t counter = 0;

    while (offset < len) {
        memset(counter_blk, 0, sizeof(counter_blk));
        u32_to_be(nonce, counter_blk);
        u32_to_be(counter, counter_blk + 4U);

        if (encrypt_sym(counter_blk, BLOCK_SIZE, (uint8_t *)key, keystream) != 0) {
            return;
        }

        for (size_t i = 0; i < BLOCK_SIZE && offset < len; i++, offset++) {
            buf[offset] ^= keystream[i];
        }

        counter++;
    }
}

uint32_t keyed_mac32(const uint8_t *buf, size_t len, const uint8_t key[DATA_CRYPTO_KEY_SIZE], uint32_t nonce)
{
    uint8_t payload_hash[HASH_SIZE] = {0};
    uint8_t digest[HASH_SIZE] = {0};
    uint8_t nonce_bytes[4] = {0};
    uint8_t prefix[DATA_CRYPTO_KEY_SIZE + 4 + HASH_SIZE] = {0};

    if (hash((void *)buf, len, payload_hash) != 0) {
        return 0;
    }

    memcpy(prefix, key, DATA_CRYPTO_KEY_SIZE);
    u32_to_be(nonce, nonce_bytes);
    memcpy(prefix + DATA_CRYPTO_KEY_SIZE, nonce_bytes, 4);
    memcpy(prefix + DATA_CRYPTO_KEY_SIZE + 4, payload_hash, HASH_SIZE);

    if (hash(prefix, sizeof(prefix), digest) != 0) {
        return 0;
    }

    return ((uint32_t)digest[0] << 24U) |
           ((uint32_t)digest[1] << 16U) |
           ((uint32_t)digest[2] << 8U) |
           ((uint32_t)digest[3]);
}
