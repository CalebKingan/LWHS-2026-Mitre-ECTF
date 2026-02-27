/**
 * @file filesystem.c
 * @author Lakota West High School eCTF Team (Original Design Samuel Meyers)
 * @brief eCTF flash-based filesystem management
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <stdint.h>

#include "filesystem.h"
#include "flash.h"
#include "crypto.h"
#include "secrets.h"


#define FILE_ENCRYPTED_FLAG 0x8000U

static uint16_t round_up_block(uint16_t len) {
    if (len == 0U) {
        return 0U;
    }
    return (uint16_t)((len + (BLOCK_SIZE - 1U)) / BLOCK_SIZE) * BLOCK_SIZE;
}


static void derive_storage_key(uint8_t *key_out) {
    const char key_seed[] = HSM_PIN;
    const size_t seed_len = sizeof(key_seed) - 1U;

    memset(key_out, 0, KEY_SIZE);
    if (seed_len == 0U) {
        return;
    }

    for (size_t i = 0; i < KEY_SIZE; i++) {
        key_out[i] = (uint8_t)key_seed[i % seed_len];
    }
}

static bool is_slot_valid(slot_t slot){
    return slot < MAX_FILE_COUNT;
}

static bool is_valid_file_region(uint32_t flash_addr, uint32_t length) {
    uint32_t storage_start = FILES_START_ADDR;
    uint32_t storage_end = FILES_START_ADDR + (MAX_FILE_COUNT * STORED_FILE_SIZE);
    uint32_t write_end;

    if (length > STORED_FILE_SIZE)
        return false;

    if (flash_addr < storage_start || flash_addr >= storage_end)
        return false;

    if (flash_addr >= (uint32_t)_FLASH_FAT_START)
        return false;

    write_end = flash_addr + length;
    if (write_end < flash_addr)
        return false;

    if (write_end > storage_end || write_end > (uint32_t)_FLASH_FAT_START)
        return false;

    return true;

}

int load_fat() {
    flash_read((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
    return 0;
}

int store_fat() {
    flash_erase_page(_FLASH_FAT_START);
    return flash_write((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
}

/** @brief Initialize the filesystem
 *
 *
 * @return 0 upon success. A negative value on error.
*/
int init_fs() {
    return load_fat();
}

/** @brief Check whether a file is in use
 *
 *  @param slot The slot to check
 *
 * @return True if the slot is in use. False otherwise.
*/
bool is_slot_in_use(slot_t slot) {
    file_t temp_file;

    if (!is_slot_valid(slot)){
        return false;
    }
    return (!read_file(slot, &temp_file) && temp_file.in_use == FILE_IN_USE);
}

/** @brief Create a new file object in memory
 *
 *  @param slot The slot to check
 *
 * @return 0 upon success. A negative value otherwise.
*/
int create_file(
    file_t *dest,
    group_id_t group_id,
    char *name,
    uint16_t contents_len,
    uint8_t *contents
) {
    memset(dest, 0, sizeof(file_t));

    dest->in_use = FILE_IN_USE;
    dest->group_id = group_id;
    dest->contents_len = contents_len;

    if (contents_len > MAX_CONTENTS_SIZE) 
    {
        return -1;
    } 
    dest->contents_len = contents_len;
    memset(dest->name, 0, MAX_NAME_SIZE);
    memcpy(dest->name, name, MAX_NAME_SIZE -1);

    memcpy(dest->contents, contents, contents_len);
    return 0;
}

/** @brief Create a new file object in memory
 *
 *  @param slot The slot to write the file to
 *  @param src The sourc file to store
 *  @param uuid The UUID to store in the FAT
 *
 * @return 0 upon success. A negative value otherwise.
*/
int write_file(slot_t slot, file_t *src, uint8_t *uuid) {
    unsigned int length, flash_addr;
    uint8_t key[KEY_SIZE];
    uint16_t original_len;
    uint16_t padded_len;
    int crypto_result;

    if (!is_slot_valid(slot) || src == NULL || uuid == NULL)
        return -1;

    if (src->contents_len > MAX_CONTENTS_SIZE)
        return -1;

    original_len = src->contents_len;
    padded_len = round_up_block(original_len);
    if (padded_len > MAX_CONTENTS_SIZE)
        return -1;

    if (padded_len > 0U) {
        if (padded_len > original_len) {
            memset(src->contents + original_len, 0, padded_len - original_len);
        }

        derive_storage_key(key);
        crypto_result = encrypt_sym(src->contents, padded_len, key, src->contents);
        if (crypto_result != 0) {
            return -1;
        }
        src->contents_len = padded_len;
    }

    flash_addr = FILE_START_PAGE_FROM_SLOT(slot);
    length = FILE_TOTAL_SIZE(src->contents_len);

    if (length > STORED_FILE_SIZE)
        return -1;

    if (!is_valid_file_region(flash_addr, length))
        return -1;

    memcpy(&FILE_ALLOCATION_TABLE[slot].uuid, uuid, UUID_SIZE);
    FILE_ALLOCATION_TABLE[slot].flash_addr = flash_addr;
    FILE_ALLOCATION_TABLE[slot].length = length;
    FILE_ALLOCATION_TABLE[slot].padding = (padded_len > 0U)
        ? (uint16_t)(original_len | FILE_ENCRYPTED_FLAG)
        : 0U;
    store_fat();

    // erase the pages that will store the file
    for (int i = 0; i < FILE_PAGE_COUNT; i++) {
        flash_erase_page(flash_addr + (FLASH_PAGE_SIZE * i));
    }

    // now write the file
    return flash_write(FILE_ALLOCATION_TABLE[slot].flash_addr, src, length);
}

/** @brief Read a file from persistent storage into memory
 *
 *  @param slot The slot to read
 *  @param dest The destination address to store the file
 *
 * @return 0 upon success. A negative value otherwise.
*/
int read_file(slot_t slot, file_t *dest) {
    uint32_t flash_addr, file_size;
    uint16_t packed_len;
    uint16_t original_len;
    uint16_t padded_len;
    uint8_t key[KEY_SIZE];
    int crypto_result;

    if (!is_slot_valid(slot) || dest == NULL)
        return -1;

    flash_addr = FILE_ALLOCATION_TABLE[slot].flash_addr;
    file_size = FILE_ALLOCATION_TABLE[slot].length;

    if(!is_valid_file_region(flash_addr, file_size))
        return -1;

    flash_read(flash_addr, dest, file_size);

    packed_len = FILE_ALLOCATION_TABLE[slot].padding;
    if ((packed_len & FILE_ENCRYPTED_FLAG) != 0U) {
        original_len = (uint16_t)(packed_len & (uint16_t)~FILE_ENCRYPTED_FLAG);
        if (original_len > MAX_CONTENTS_SIZE) {
            return -1;
        }

        padded_len = round_up_block(original_len);
        if (padded_len == 0U || padded_len > dest->contents_len) {
            return -1;
        }

        derive_storage_key(key);
        crypto_result = decrypt_sym(dest->contents, padded_len, key, dest->contents);
        if (crypto_result != 0) {
            return -1;
        }

        dest->contents_len = original_len;
    }

    return 0;
}

/** @brief Get a read-only pointer to a file's metadata
 *
 *  @param slot The slot to get metadata for
 *
 * @return A filesystem_entry_t * on success. NULL on error.
*/
const filesystem_entry_t *get_file_metadata(slot_t slot) {
    if (!is_slot_valid(slot))
        return NULL;
    return &FILE_ALLOCATION_TABLE[slot];
}
