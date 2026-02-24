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

/*
 * Lightweight software-only noise + fault-injection hardening helpers.
 */
#define PIN_MASKING_ROUNDS 3U
#define NOISE_MAX_DELAY_CYCLES (CPUCLK_FREQ / 25000U)
#define FI_COMPARE_REPETITIONS 2U
#define FI_DELAY_TAG 0xC3D2E1F0U

static uint32_t noise_state = 0x6B1E4A2DU;

static uint32_t next_noise_u32(void)
{
    /* xorshift32 */
    noise_state ^= noise_state << 13U;
    noise_state ^= noise_state >> 17U;
    noise_state ^= noise_state << 5U;
    return noise_state;
}

static void apply_fake_noise_delay(void)
{
    uint32_t seed = (uint32_t)SysTick->VAL ^ next_noise_u32();
    uint32_t jitter_cycles = seed % (NOISE_MAX_DELAY_CYCLES + 1U);
    volatile uint32_t sink = jitter_cycles ^ 0xA5A5A5A5U;

    for (uint32_t i = 0; i < 32U; i++) {
        sink ^= (sink << 3U) + 0x7F4A7C15U + (sink >> 2U);
    }

    delay_cycles(jitter_cycles);
    (void)sink;
}

static void fi_hardened_delay(uint32_t cycles)
{
    volatile uint32_t guard_a = FI_DELAY_TAG;
    volatile uint32_t guard_b = ~FI_DELAY_TAG;

    while (cycles > 0U) {
        uint32_t chunk = (cycles > 1024U) ? 1024U : cycles;
        guard_a ^= (chunk + cycles);
        guard_b ^= ~(chunk + cycles);
        delay_cycles(chunk);
        cycles -= chunk;
    }

    if ((guard_a ^ guard_b) != 0xFFFFFFFFU) {
        delay_cycles(CPUCLK_FREQ * INVALID_PIN_DELAY);
    }
}

static uint8_t constant_time_pin_match_masked_once(const unsigned char *pin)
{
    volatile uint8_t diff = 0;

    for (uint32_t round = 0; round < PIN_MASKING_ROUNDS; round++) {
        uint8_t round_mask = (uint8_t)next_noise_u32();

        for (uint32_t i = 0; i < PIN_LENGTH; i++) {
            uint8_t lane_mask = (uint8_t)(round_mask ^ (uint8_t)next_noise_u32());
            uint8_t masked_pin = (uint8_t)(pin[i] ^ lane_mask);
            uint8_t masked_ref = (uint8_t)(((uint8_t)HSM_PIN[i]) ^ lane_mask);

            diff |= (uint8_t)(masked_pin ^ masked_ref);
        }

        apply_fake_noise_delay();
    }

    apply_fake_noise_delay();
    return diff;
}

static bool constant_time_pin_match_masked_fi(const unsigned char *pin)
{
    uint8_t diff_or = 0;
    uint8_t diff_and = 0xFFU;

    for (uint32_t rep = 0; rep < FI_COMPARE_REPETITIONS; rep++) {
        uint8_t diff = constant_time_pin_match_masked_once(pin);
        diff_or |= diff;
        diff_and &= diff;
    }

    /*
     * Fault-injection guard:
     * both repeated evaluations must agree on zero/non-zero.
     */
    if (((diff_or == 0U) && (diff_and == 0U)) ||
        ((diff_or != 0U) && (diff_and != 0U))) {
        return diff_or == 0U;
    }

    return false;
}

bool check_pin(unsigned char *pin)
{
    bool pin_valid = false;

    if (pin != NULL) {
        pin_valid = constant_time_pin_match_masked_fi(pin);
    }

    if (pin_valid) {
        apply_fake_noise_delay();
        return true;
    }

    fi_hardened_delay(CPUCLK_FREQ * INVALID_PIN_DELAY);
    apply_fake_noise_delay();
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
