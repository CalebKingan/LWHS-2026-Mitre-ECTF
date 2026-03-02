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
 * Keep countermeasures lightweight so command latency stays within protocol
 * expectations while still adding jitter and FI-resistant decisions.
 */
#define NOISE_MAX_DELAY_CYCLES (CPUCLK_FREQ / 100000U) /* <= 320 cycles */
#define FI_COMPARE_REPETITIONS 2U
#define INVALID_PIN_DELAY_CYCLES ((CPUCLK_FREQ / 1000U) * INVALID_PIN_DELAY_MS)
#define FI_DECISION_TRUE 0x13579BDFU
#define FI_DECISION_FALSE 0xECA86420U

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
    uint32_t jitter_cycles = next_noise_u32() % (NOISE_MAX_DELAY_CYCLES + 1U);
    volatile uint32_t sink = jitter_cycles ^ 0xA5A5A5A5U;

    for (uint32_t i = 0; i < 8U; i++) {
        sink ^= (sink << 3U) + 0x7F4A7C15U + (sink >> 2U);
    }

    delay_cycles(jitter_cycles);
    (void)sink;
}

/* One constant-time compare pass. Returns 0 on match, non-zero otherwise. */
static uint8_t constant_time_pin_match_once(const unsigned char *pin)
{
    volatile uint8_t diff = 0U;

    for (uint32_t i = 0; i < PIN_LENGTH; i++) {
        diff |= (uint8_t)(pin[i] ^ (uint8_t)HSM_PIN[i]);
    }

    return diff;
}

/* Repeat compare and require agreement to harden against transient FI glitches. */
static bool constant_time_pin_match_fi(const unsigned char *pin)
{
    uint8_t diff_or = 0;
    uint8_t diff_and = 0xFFU;

    for (uint32_t rep = 0; rep < FI_COMPARE_REPETITIONS; rep++) {
        uint8_t diff = constant_time_pin_match_once(pin);
        diff_or |= diff;
        diff_and &= diff;
    }

    if (((diff_or == 0U) && (diff_and == 0U)) ||
        ((diff_or != 0U) && (diff_and != 0U))) {
        return diff_or == 0U;
    }

    return false;
}

bool check_pin(unsigned char *pin)
{
    bool pin_valid = false;
    volatile uint32_t decision = FI_DECISION_FALSE;
    volatile uint32_t decision_inv = ~FI_DECISION_FALSE;

    if (pin != NULL) {
        pin_valid = constant_time_pin_match_fi(pin);
    }

    if (pin_valid) {
        decision = FI_DECISION_TRUE;
        decision_inv = ~FI_DECISION_TRUE;
    }

    if ((decision == FI_DECISION_TRUE) &&
        (decision_inv == ~FI_DECISION_TRUE)) {
        apply_fake_noise_delay();
        return true;
    }

    /* Keep invalid-PIN delay bounded to exactly configured budget (5s). */
    delay_cycles(INVALID_PIN_DELAY_CYCLES);
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
