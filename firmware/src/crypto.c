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
#include "security.h"
#include <stdint.h>
#include <string.h>

static void derive_iv(uint8_t *key, uint8_t *iv) {
    uint8_t full_hash[WC_SHA256_DIGEST_SIZE] = {0};

    /*
     * Derive a non-zero IV from the key material so we can avoid ECB mode
     * without changing the external function signatures.
     */
    wc_Sha256Hash(key, KEY_SIZE, full_hash);
    memcpy(iv, full_hash, BLOCK_SIZE);
}


/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts plaintext using a symmetric cipher
 *
 * @param plaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param len The length of the plaintext to encrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for encryption
 * @param ciphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext) {
    Aes ctx; // Context for encryption
    uint8_t iv[BLOCK_SIZE] = {0};
    int result; // Library result

    // Ensure valid length
    if (!plaintext || !key || !ciphertext)
        return -1;

    if (len == 0 || len % BLOCK_SIZE)
        return -1;

    derive_iv(key, iv);

    // Set the key for encryption
    result = wc_AesSetKey(&ctx, key, KEY_SIZE, iv, AES_ENCRYPTION);
    if (result != 0)
        return result; // Report error

    return wc_AesCbcEncrypt(&ctx, ciphertext, plaintext, len);
}

/** @brief Decrypts ciphertext using a symmetric cipher
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *          ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for decryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *          plaintext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
    Aes ctx; // Context for decryption
    uint8_t iv[BLOCK_SIZE] = {0};
    int result; // Library result

    // Ensure valid length
    if (!ciphertext || !key || !plaintext)
        return -1;

    if (len == 0 || len % BLOCK_SIZE)
        return -1;

    derive_iv(key, iv);

    // Set the key for decryption
    result = wc_AesSetKey(&ctx, key, KEY_SIZE, iv, AES_DECRYPTION);
    if (result != 0)
        return result; // Report error

    return wc_AesCbcDecrypt(&ctx, plaintext, ciphertext, len);
}

/** @brief Hashes arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 *          to be hashed
 * @param len The length of the plaintext to hash
 * @param hash_out A pointer to a buffer of length HASH_SIZE (32 bytes) where the resulting
 *          hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int hash(void *data, size_t len, uint8_t *hash_out) {
    if (!data || !hash_out)
        return -1;

    return wc_Sha256Hash((uint8_t *)data, len, hash_out);
}
