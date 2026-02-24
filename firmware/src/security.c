/**
 * @file security.c
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
#include "security.h"
#include "host_messaging.h"
#include "secrets.h"
#include <string.h>
#include "ti_msp_dl_config.h"

static bool constant_time_pin_match(const unsigned char *pin) {
    volatile uint8_t diff = 0;

    for (uint32_t i = 0; i<PIN_LENGTH; i++)
        diff |= (uint8_t)(pin[i] ^ (uint8_t)HSM_PIN[i]);
   
    return diff == 0;

}

bool check_pin(unsigned char *pin) {
    if (pin && constant_time_pin_match(pin))
            return true;

    delay_cycles(CPUCLK_FREQ * INVALID_PIN_DELAY);
    return false;
}



bool validate_permission(uint16_t group_id, permission_enum_t perm) {
    for (int i = 0; i < MAX_PERMS; i++) {
        if (global_permissions[i].group_id == group_id) {
            switch (perm) {
                case PERM_READ:    return global_permissions[i].read;
                case PERM_WRITE:   return global_permissions[i].write;
                case PERM_RECEIVE: return global_permissions[i].receive;
                default: return false;
            }
        }
    }
    return false; // deny by default
}
