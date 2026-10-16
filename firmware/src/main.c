/* TECU-3 application: power-on self-test of the security module, then
 * the diagnostic main loop (idle on this training build).
 */

#include <stdint.h>
#include "tecu_security.h"
#include "generated_constants.h"

/* Non-secret identification strings - the kind of thing `strings` finds
 * first in every real dump. */
const char fw_version[]  __attribute__((used)) = "HB-TECU3 SEC FW 1.7.2";
const char fw_build[]    __attribute__((used)) = "BUILD 2026-10-16";
const char fw_module[]   __attribute__((used)) = "TECU-3 DIAGNOSTIC SECURITY MODULE";

/* Unrelated filler table: makes the blob look like a real image and gives
 * the constant scanner something to trip over before it finds the S-box. */
const uint8_t engine_cal_table[32] __attribute__((used)) = {
    0x8E, 0x01, 0xC4, 0x00, 0x35, 0x02, 0xA7, 0x03,
    0x19, 0x00, 0x5C, 0x01, 0xE2, 0x02, 0x77, 0x00,
    0x0D, 0x03, 0xB1, 0x01, 0x48, 0x00, 0x9A, 0x02,
    0x26, 0x01, 0xD3, 0x00, 0x6F, 0x03, 0xFA, 0x01,
};

/* Self-test result visible to the diagnostic stack (1 = pass). */
uint8_t tecu_selftest_result;

static uint8_t bytes_equal(const uint8_t *a, const uint8_t *b, unsigned n)
{
    unsigned i;
    for (i = 0; i < n; i++)
        if (a[i] != b[i])
            return 0u;
    return 1u;
}

int main(void)
{
    uint8_t key[8];

    /* Power-on known-answer test of the security module. */
    tecu_compute_key(tecu_rom.selftest_seed, key);
    tecu_selftest_result = bytes_equal(key, tecu_rom.selftest_key, 8u);

    for (;;)                          /* training build: nothing to do */
        __asm volatile ("wfi");
}
