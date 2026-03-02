/**
 * @file "flash.c"
 * @author Lakota West High School eCTF Team (Original Design Samuel Meyers)
 * @brief Flash Interface Implementation
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "flash.h"

/**
 * @brief Flash Erase Page
 *
 * @param address: uint32_t, address of flash page to erase
 *
 * @return int: return negative if failure, zero if success
 *
 * This function erases a page of flash such that it can be updated.
 * Flash memory can only be erased in a large block size called a page (or sector).
 * Once erased, memory can only be written one way e.g. 1->0.
 * In order to be re-written the entire page must be erased.
*/
int flash_erase_page(uint32_t address) {
    volatile DL_FLASHCTL_COMMAND_STATUS cmdStatus;
    DL_FlashCTL_executeClearStatus(FLASHCTL);
    DL_FlashCTL_unprotectSector(FLASHCTL, address, DL_FLASHCTL_REGION_SELECT_MAIN);

    cmdStatus = DL_FlashCTL_eraseMemoryFromRAM(
        FLASHCTL, address, DL_FLASHCTL_COMMAND_SIZE_SECTOR);
    if (cmdStatus == DL_FLASHCTL_COMMAND_STATUS_FAILED) {
        return -1;
    }
    // returns a boolean, so handle that accordingly
    bool ret = DL_FlashCTL_waitForCmdDone(FLASHCTL);
    if (ret == false) {
        return -1;
    }
    return 0;
}

/**
 * @brief Flash Read
 *
 * @param address: uint32_t, address of flash page to read
 * @param buffer: void*, pointer to buffer for data to be read into
 * @param size: uint32_t, number of bytes to read from flash
 *
 * This function reads data from the specified flash page into the buffer
 * with the specified amount of bytes
*/
void flash_read(uint32_t address, void* buffer, uint32_t size) {
    // flash is memory mapped, and the flash controller has no read functionality
    memcpy(buffer, (void *)address, size);
}

/**
 * @brief Flash Write
 *
 * @param address: uint32_t, address of flash page to write
 * @param buffer: void*, pointer to buffer to write data from
 * @param size: uint32_t, number of bytes to write from flash
 *
 * @return int: return negative if failure, zero if success
 *
 * This function writes data to the specified flash page from the buffer passed
 * with the specified amount of bytes. Flash memory can only be written in one
 * way e.g. 1->0. To rewrite previously written memory see the
 * flash_erase_page documentation.
*/
int flash_write(uint32_t address, void* buffer, uint32_t size) {
    volatile DL_FLASHCTL_COMMAND_STATUS cmdStatus;
    uint8_t *src = (uint8_t *)buffer;
    uint32_t bytes_remaining = size;

    /* Program in small chunks to avoid large stack allocations on 32KB SRAM target. */
    enum { FLASH_WRITE_CHUNK_WORDS = 64U, FLASH_WRITE_CHUNK_BYTES = FLASH_WRITE_CHUNK_WORDS * 4U };
    uint32_t write_data[FLASH_WRITE_CHUNK_WORDS];

    if (buffer == NULL) {
        return -1;
    }

    DL_FlashCTL_executeClearStatus(FLASHCTL);
    DL_FlashCTL_unprotectSector(FLASHCTL, address, DL_FLASHCTL_REGION_SELECT_MAIN);

    while (bytes_remaining > 0U) {
        uint32_t chunk_bytes = (bytes_remaining > FLASH_WRITE_CHUNK_BYTES) ? FLASH_WRITE_CHUNK_BYTES : bytes_remaining;
        uint32_t chunk_words = (chunk_bytes + 3U) / 4U;

        /* 64-bit + ECC write API requires an even number of 32-bit words. */
        if ((chunk_words & 1U) != 0U) {
            chunk_words++;
        }

        memset(write_data, 0xFF, chunk_words * sizeof(uint32_t));
        memcpy(write_data, src, chunk_bytes);

        cmdStatus = DL_FlashCTL_programMemoryBlockingFromRAM64WithECCGenerated(
            FLASHCTL, address, write_data, chunk_words, DL_FLASHCTL_REGION_SELECT_MAIN
        );
        if (cmdStatus == DL_FLASHCTL_COMMAND_STATUS_FAILED) {
            return -1;
        }

        if (!DL_FlashCTL_waitForCmdDone(FLASHCTL)) {
            return -1;
        }

        address += chunk_words * sizeof(uint32_t);
        src += chunk_bytes;
        bytes_remaining -= chunk_bytes;
    }

    return 0;
}
