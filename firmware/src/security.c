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
#include "flash.h"
#include "crypto.h"
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

#define TRANSFER_STATE_FLASH_ADDR 0x0003A400U
#define TRANSFER_STATE_MAGIC 0x54524652U /* 'TRFR' */
#define TRANSFER_STATE_VERSION 1U
#define TRANSFER_REC_TYPE_NEXT_SEND 1U
#define TRANSFER_REC_TYPE_LAST_SEEN 2U
#define TRANSFER_COUNTER_MAX UINT64_MAX

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint8_t key[16];
    uint8_t reserved[8];
} transfer_state_header_t;

typedef struct {
    uint8_t type;
    uint8_t reserved[7];
    uint64_t value;
} transfer_counter_record_t;

#define TRANSFER_RECORD_CAPACITY ((FLASH_PAGE_SIZE - sizeof(transfer_state_header_t)) / sizeof(transfer_counter_record_t))

static uint32_t noise_state = 0x6B1E4A2DU;
static bool transfer_state_loaded = false;
static uint8_t cached_transfer_key[16];
static uint64_t cached_next_send_counter = 1U;
static uint64_t cached_last_seen_counter = 0U;
static uint16_t cached_record_index = 0U;

static uint64_t prng_counter = 0U;

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

static uint32_t sample_entropy_word(void)
{
    uint32_t t = noise_state ^ (uint32_t)prng_counter;
    t ^= (noise_state << 7U) ^ (noise_state >> 3U);
    t ^= (uint32_t)(uintptr_t)&t;
    t ^= (uint32_t)(CPUCLK_FREQ);
    return t;
}

int security_rng_generate(uint8_t *out, uint32_t len)
{
    uint8_t digest[HASH_SIZE];
    uint8_t seed[24];
    uint32_t produced = 0U;

    if (out == NULL || len == 0U) {
        return -1;
    }

    while (produced < len) {
        uint32_t entropy = sample_entropy_word();
        prng_counter++;

        memcpy(seed, &noise_state, sizeof(noise_state));
        memcpy(seed + 4, &entropy, sizeof(entropy));
        memcpy(seed + 8, &prng_counter, sizeof(prng_counter));
        memcpy(seed + 16, &produced, sizeof(produced));
        memcpy(seed + 20, &len, sizeof(len));

        if (wc_Sha256Hash(seed, sizeof(seed), digest) != 0) {
            memset(digest, 0, sizeof(digest));
            memset(seed, 0, sizeof(seed));
            return -1;
        }

        uint32_t chunk = len - produced;
        if (chunk > sizeof(digest)) {
            chunk = sizeof(digest);
        }
        memcpy(out + produced, digest, chunk);
        produced += chunk;

        noise_state ^= entropy ^ digest[0];
    }

    memset(digest, 0, sizeof(digest));
    memset(seed, 0, sizeof(seed));
    return 0;
}

static int derive_transfer_key_from_secret(uint8_t key_out[16])
{
    uint8_t material[HASH_SIZE];
    char seed[32];

    memset(seed, 0, sizeof(seed));
    memcpy(seed, HSM_PIN, PIN_LENGTH);
    memcpy(seed + PIN_LENGTH, "|TRANSFER|", 10);

    if (wc_Sha256Hash((const uint8_t *)seed, sizeof(seed), material) != 0) {
        memset(material, 0, sizeof(material));
        memset(seed, 0, sizeof(seed));
        return -1;
    }

    memcpy(key_out, material, 16);
    memset(material, 0, sizeof(material));
    memset(seed, 0, sizeof(seed));
    return 0;
}

static int persist_transfer_state(void)
{
    transfer_state_header_t header;
    transfer_counter_record_t rec;
    uint32_t addr = TRANSFER_STATE_FLASH_ADDR;

    if (flash_erase_page(TRANSFER_STATE_FLASH_ADDR) != 0) {
        return -1;
    }

    memset(&header, 0xFF, sizeof(header));
    header.magic = TRANSFER_STATE_MAGIC;
    header.version = TRANSFER_STATE_VERSION;
    memcpy(header.key, cached_transfer_key, sizeof(cached_transfer_key));

    if (flash_write(addr, &header, sizeof(header)) != 0) {
        return -1;
    }
    addr += sizeof(header);

    memset(&rec, 0xFF, sizeof(rec));
    rec.type = TRANSFER_REC_TYPE_NEXT_SEND;
    rec.value = cached_next_send_counter;
    if (flash_write(addr, &rec, sizeof(rec)) != 0) {
        return -1;
    }
    addr += sizeof(rec);

    memset(&rec, 0xFF, sizeof(rec));
    rec.type = TRANSFER_REC_TYPE_LAST_SEEN;
    rec.value = cached_last_seen_counter;
    if (flash_write(addr, &rec, sizeof(rec)) != 0) {
        return -1;
    }

    cached_record_index = 2U;
    return 0;
}

static int append_transfer_record(uint8_t type, uint64_t value)
{
    transfer_counter_record_t rec;
    uint32_t addr;

    if (cached_record_index >= TRANSFER_RECORD_CAPACITY) {
        return persist_transfer_state();
    }

    addr = TRANSFER_STATE_FLASH_ADDR + sizeof(transfer_state_header_t) +
           (cached_record_index * sizeof(transfer_counter_record_t));
    memset(&rec, 0xFF, sizeof(rec));
    rec.type = type;
    rec.value = value;

    if (flash_write(addr, &rec, sizeof(rec)) != 0) {
        return -1;
    }

    cached_record_index++;
    return 0;
}

static int load_or_init_transfer_state(void)
{
    transfer_state_header_t header;
    transfer_counter_record_t rec;

    if (transfer_state_loaded) {
        return 0;
    }

    flash_read(TRANSFER_STATE_FLASH_ADDR, &header, sizeof(header));

    if (header.magic != TRANSFER_STATE_MAGIC || header.version != TRANSFER_STATE_VERSION) {
        if (derive_transfer_key_from_secret(cached_transfer_key) != 0) {
            return -1;
        }
        cached_next_send_counter = 1U;
        cached_last_seen_counter = 0U;
        if (persist_transfer_state() != 0) {
            memset(cached_transfer_key, 0, sizeof(cached_transfer_key));
            return -1;
        }
        transfer_state_loaded = true;
        return 0;
    }

    memcpy(cached_transfer_key, header.key, sizeof(cached_transfer_key));
    cached_next_send_counter = 1U;
    cached_last_seen_counter = 0U;
    cached_record_index = 0U;

    for (uint16_t i = 0; i < TRANSFER_RECORD_CAPACITY; i++) {
        uint32_t addr = TRANSFER_STATE_FLASH_ADDR + sizeof(transfer_state_header_t) +
                        (i * sizeof(transfer_counter_record_t));
        flash_read(addr, &rec, sizeof(rec));

        if (rec.type == 0xFFU) {
            break;
        }

        if (rec.type == TRANSFER_REC_TYPE_NEXT_SEND) {
            cached_next_send_counter = rec.value;
        } else if (rec.type == TRANSFER_REC_TYPE_LAST_SEEN) {
            cached_last_seen_counter = rec.value;
        }

        cached_record_index = (uint16_t)(i + 1U);
    }

    transfer_state_loaded = true;
    return 0;
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

int get_or_create_transfer_key(uint8_t key_out[16])
{
    if (key_out == NULL) {
        return -1;
    }

    if (load_or_init_transfer_state() != 0) {
        return -1;
    }

    memcpy(key_out, cached_transfer_key, 16);
    return 0;
}

int get_and_increment_transfer_counter(uint64_t *counter_out)
{
    uint64_t current;

    if (counter_out == NULL) {
        return -1;
    }

    if (load_or_init_transfer_state() != 0) {
        return -1;
    }

    current = cached_next_send_counter;
    if (current == TRANSFER_COUNTER_MAX) {
        return -1;
    }

    cached_next_send_counter = current + 1U;
    if (append_transfer_record(TRANSFER_REC_TYPE_NEXT_SEND, cached_next_send_counter) != 0) {
        return -1;
    }

    *counter_out = current;
    return 0;
}

int get_last_seen_counter(uint64_t *counter_out)
{
    if (counter_out == NULL) {
        return -1;
    }

    if (load_or_init_transfer_state() != 0) {
        return -1;
    }

    *counter_out = cached_last_seen_counter;
    return 0;
}

int set_last_seen_counter(uint64_t counter)
{
    if (load_or_init_transfer_state() != 0) {
        return -1;
    }

    cached_last_seen_counter = counter;
    return append_transfer_record(TRANSFER_REC_TYPE_LAST_SEEN, counter);
}
