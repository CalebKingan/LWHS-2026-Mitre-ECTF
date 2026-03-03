/**
 * @file "crypto.c"
 * @author Lakota West High School eCTF Team (Original Design Ben Janis)
 * @brief Simplified Crypto API Implementation
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "crypto.h"
#include <stdint.h>
#include <string.h>

static uint32_t load_be32(const uint8_t in[4])
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static void store_be32(uint8_t out[4], uint32_t v)
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}

static void store_be64(uint8_t out[8], uint64_t v)
{
    out[0] = (uint8_t)(v >> 56);
    out[1] = (uint8_t)(v >> 48);
    out[2] = (uint8_t)(v >> 40);
    out[3] = (uint8_t)(v >> 32);
    out[4] = (uint8_t)(v >> 24);
    out[5] = (uint8_t)(v >> 16);
    out[6] = (uint8_t)(v >> 8);
    out[7] = (uint8_t)v;
}

static void gcm_inc32(uint8_t ctr[16])
{
    uint32_t low = load_be32(&ctr[12]);
    low++;
    store_be32(&ctr[12], low);
}

static void xor_block(uint8_t dst[16], const uint8_t src[16])
{
    for (uint8_t i = 0; i < 16; i++) {
        dst[i] ^= src[i];
    }
}

static void gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16])
{
    uint8_t z[16] = {0};
    uint8_t v[16];
    memcpy(v, y, sizeof(v));

    for (uint8_t i = 0; i < 16; i++) {
        for (uint8_t bit = 0; bit < 8; bit++) {
            if ((x[i] & (uint8_t)(0x80U >> bit)) != 0U) {
                xor_block(z, v);
            }

            uint8_t lsb = (uint8_t)(v[15] & 1U);
            for (int j = 15; j > 0; j--) {
                v[j] = (uint8_t)((v[j] >> 1) | ((v[j - 1] & 1U) << 7));
            }
            v[0] >>= 1;
            if (lsb != 0U) {
                v[0] ^= 0xE1U;
            }
        }
    }

    memcpy(out, z, 16);
    memset(z, 0, sizeof(z));
    memset(v, 0, sizeof(v));
}

static int ghash_update(uint8_t y[16], const uint8_t h[16], const uint8_t* data, size_t len)
{
    uint8_t block[16];
    size_t offset = 0;

    while (offset < len) {
        size_t chunk = len - offset;
        if (chunk > 16U) {
            chunk = 16U;
        }

        memset(block, 0, sizeof(block));
        memcpy(block, data + offset, chunk);
        xor_block(y, block);
        gf128_mul(y, h, y);
        offset += chunk;
    }

    memset(block, 0, sizeof(block));
    return 0;
}

static int aes_encrypt_block_with_setkey(const uint8_t *key, const uint8_t in[16], uint8_t out[16]);

static int aes_gcm_compute_tag(const uint8_t *key,
                               const uint8_t nonce[12],
                               const uint8_t *aad,
                               size_t aad_len,
                               const uint8_t *ct,
                               size_t ct_len,
                               uint8_t tag_out[16])
{
    uint8_t h[16] = {0};
    uint8_t y[16] = {0};
    uint8_t j0[16] = {0};
    uint8_t s[16] = {0};
    uint8_t len_block[16] = {0};
    int rc;

    rc = aes_encrypt_block_with_setkey(key, h, h);
    if (rc != 0) {
        return rc;
    }

    memcpy(j0, nonce, 12);
    j0[15] = 1U;

    (void)ghash_update(y, h, aad, aad_len);
    (void)ghash_update(y, h, ct, ct_len);
    store_be64(&len_block[0], (uint64_t)aad_len * 8U);
    store_be64(&len_block[8], (uint64_t)ct_len * 8U);
    xor_block(y, len_block);
    gf128_mul(y, h, y);

    rc = aes_encrypt_block_with_setkey(key, j0, s);
    if (rc != 0) {
        return rc;
    }

    for (uint8_t i = 0; i < 16; i++) {
        tag_out[i] = (uint8_t)(y[i] ^ s[i]);
    }

    memset(h, 0, sizeof(h));
    memset(y, 0, sizeof(y));
    memset(j0, 0, sizeof(j0));
    memset(s, 0, sizeof(s));
    memset(len_block, 0, sizeof(len_block));
    return 0;
}

static int secure_tag_equal(const uint8_t a[16], const uint8_t b[16])
{
    uint8_t diff = 0;
    for (uint8_t i = 0; i < 16; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0 ? 0 : -1;
}


static int aes_encrypt_block_with_setkey(const uint8_t *key, const uint8_t in[16], uint8_t out[16])
{
    Aes aes;
    static const uint8_t zero_iv[BLOCK_SIZE] = {0};
    int rc;

    memset(&aes, 0, sizeof(aes));
    rc = wc_AesSetKey(&aes, key, KEY_SIZE, zero_iv, AES_ENCRYPTION);
    if (rc != 0) {
        memset(&aes, 0, sizeof(aes));
        return rc;
    }

    rc = wc_AesCbcEncrypt(&aes, out, in, BLOCK_SIZE);
    memset(&aes, 0, sizeof(aes));
    return rc;
}

int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext) {
    Aes ctx; // Context for encryption
    int result; // Library result

    if (!plaintext || !key || !ciphertext)
        return -1;

    if (len == 0 || len % BLOCK_SIZE)
        return -1;

    static const uint8_t zero_iv[BLOCK_SIZE] = {0};

    result = wc_AesSetKey(&ctx, key, KEY_SIZE, zero_iv, AES_ENCRYPTION);
    if (result != 0)
        return result;

    return wc_AesCbcEncrypt(&ctx, ciphertext, plaintext, len);
}

int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
    Aes ctx; // Context for decryption
    int result; // Library result

    if (!ciphertext || !key || !plaintext)
        return -1;

    if (len == 0 || len % BLOCK_SIZE)
        return -1;

    static const uint8_t zero_iv[BLOCK_SIZE] = {0};

    result = wc_AesSetKey(&ctx, key, KEY_SIZE, zero_iv, AES_DECRYPTION);
    if (result != 0)
        return result;

    return wc_AesCbcDecrypt(&ctx, plaintext, ciphertext, len);
}

int hash(void *data, size_t len, uint8_t *hash_out) {
    if (!data || !hash_out)
        return -1;

    return wc_Sha256Hash((uint8_t *)data, len, hash_out);
}

int encrypt_transfer_gcm(const uint8_t *pt, size_t pt_len,
                         const uint8_t *key,
                         const uint8_t nonce[12],
                         const uint8_t *aad, size_t aad_len,
                         uint8_t *ct_out,
                         uint8_t tag_out[16])
{
    uint8_t ctr[16] = {0};
    uint8_t stream[16];
    int rc;

    if (pt == NULL || key == NULL || nonce == NULL || ct_out == NULL || tag_out == NULL) {
        return -1;
    }

    memcpy(ctr, nonce, 12);
    ctr[15] = 1U;

    for (size_t off = 0; off < pt_len; off += 16U) {
        size_t chunk = pt_len - off;
        if (chunk > 16U) {
            chunk = 16U;
        }

        gcm_inc32(ctr);
        rc = aes_encrypt_block_with_setkey(key, ctr, stream);
        if (rc != 0) {
            memset(stream, 0, sizeof(stream));
            return rc;
        }

        for (size_t i = 0; i < chunk; i++) {
            ct_out[off + i] = (uint8_t)(pt[off + i] ^ stream[i]);
        }
    }

    rc = aes_gcm_compute_tag(key, nonce, aad, aad_len, ct_out, pt_len, tag_out);

    memset(stream, 0, sizeof(stream));
    memset(ctr, 0, sizeof(ctr));
    return rc;
}

int decrypt_transfer_gcm(const uint8_t *ct, size_t ct_len,
                         const uint8_t *key,
                         const uint8_t nonce[12],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t tag[16],
                         uint8_t *pt_out)
{
    int rc;
    uint8_t expected_tag[16];
    uint8_t ctr[16] = {0};
    uint8_t stream[16];

    if (ct == NULL || key == NULL || nonce == NULL || tag == NULL || pt_out == NULL) {
        return -1;
    }

    rc = aes_gcm_compute_tag(key, nonce, aad, aad_len, ct, ct_len, expected_tag);
    if (rc != 0 || secure_tag_equal(expected_tag, tag) != 0) {
        memset(expected_tag, 0, sizeof(expected_tag));
        return -1;
    }

    memcpy(ctr, nonce, 12);
    ctr[15] = 1U;

    for (size_t off = 0; off < ct_len; off += 16U) {
        size_t chunk = ct_len - off;
        if (chunk > 16U) {
            chunk = 16U;
        }

        gcm_inc32(ctr);
        rc = aes_encrypt_block_with_setkey(key, ctr, stream);
        if (rc != 0) {
            memset(stream, 0, sizeof(stream));
            memset(expected_tag, 0, sizeof(expected_tag));
            return rc;
        }

        for (size_t i = 0; i < chunk; i++) {
            pt_out[off + i] = (uint8_t)(ct[off + i] ^ stream[i]);
        }
    }

    memset(stream, 0, sizeof(stream));
    memset(ctr, 0, sizeof(ctr));
    memset(expected_tag, 0, sizeof(expected_tag));
    return 0;
}
