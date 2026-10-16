/* TECU-3 diagnostic security module - public interface. */

#ifndef TECU_SECURITY_H
#define TECU_SECURITY_H

#include <stdint.h>

struct tecu_rom_tables {
    uint8_t  sbox[256];        /* substitution box (FIPS-197) */
    uint8_t  key_a[16];        /* lane A AES key */
    uint8_t  key_b[16];        /* lane B AES key */
    uint8_t  mask_a[4];        /* lane A output mask */
    uint8_t  mask_b[4];        /* lane B output mask */
    uint8_t  rcon[11];         /* key schedule round constants */
    uint32_t selftest_seed;    /* power-on self-test seed */
    uint8_t  selftest_key[8];  /* expected self-test key */
};

extern const struct tecu_rom_tables tecu_rom;

void tecu_key_expansion(const uint8_t key[16], uint8_t roundkeys[160]);
void tecu_compute_key(uint32_t seed, uint8_t out[8]);

#endif /* TECU_SECURITY_H */
