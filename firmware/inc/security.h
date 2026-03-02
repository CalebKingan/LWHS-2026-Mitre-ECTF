/**
 * @file security.h
 * @author Lakota West High School eCTF Team (Original Design Samuel Meyers)
 * @brief Stub file to hold security checks
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */
#ifndef __SECURITY_H__
#define __SECURITY_H__

#include <stdbool.h>
#include <stdint.h>

#define MAX_PERMS 8
#define PIN_LENGTH 6
#define INVALID_PIN_DELAY_MS 200U
#define INVALID_PIN_DELAY_CYCLES ((CPUCLK_FREQ / 1000U) * INVALID_PIN_DELAY_MS)

typedef enum {
    PERM_READ = 'R',
    PERM_WRITE = 'W',
    PERM_RECEIVE = 'C',
} permission_enum_t;

typedef struct {
    uint16_t group_id;
    bool read;
    bool write;
    bool receive;
} group_permission_t;

/** @brief Validate a pin against the HSM's pin
 *
 *  @param pin Requested pin to validate.
 *
 *  @return True if the pin is valid. False if not.
*/
bool check_pin(unsigned char *pin);

/** @brief Ensure the HSM has the requested permission
 *
 *  @param group_id Group ID.
 *  @param perm Permission type.
 *
 *  @return True if the HSM has the correct permission. False if not.
*/
bool validate_permission(uint16_t group_id, permission_enum_t perm);


int security_rng_generate(uint8_t *out, uint32_t len);
int get_or_create_transfer_key(uint8_t key_out[16]);
int get_and_increment_transfer_counter(uint64_t *counter_out);
int get_last_seen_counter(uint64_t *counter_out);
int set_last_seen_counter(uint64_t counter);

#endif  // __SECURITY_H__
