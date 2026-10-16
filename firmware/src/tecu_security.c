/* TECU-3 diagnostic security module - synthetic training firmware.
 *
 * Implements the security access (UDS 0x27) key computation for
 * diagnostic security level 0x11: a modified AES core (nine rounds
 * instead of the AES-128 standard ten) feeding two bespoke byte
 * scramblers. Written for the Hunt-Benito training exercise; the
 * structure imitates the flavour of real automotive seed-key code
 * but every constant is synthetic.
 */

#include <stdint.h>
#include "tecu_security.h"
#include "generated_constants.h"

/* All security tables live in one contiguous ROM region (.secro) so the
 * linker keeps them clustered - find one, find them all. */
const struct tecu_rom_tables tecu_rom __attribute__((used, section(".secro"))) = {
    .sbox         = TECU_SBOX,
    .key_a        = TECU_KEY_A,
    .key_b        = TECU_KEY_B,
    .mask_a       = TECU_MASK_A,
    .mask_b       = TECU_MASK_B,
    .rcon         = TECU_RCON,
    .selftest_seed = TECU_SELFTEST_SEED,
    .selftest_key = TECU_SELFTEST_KEY,
};

static uint32_t rol32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32u - n));
}

static uint8_t ror8b(uint8_t x, unsigned n)
{
    return (uint8_t)((x >> n) | (x << (8u - n)));
}

static uint8_t rol8b(uint8_t x, unsigned n)
{
    return (uint8_t)((x << n) | (x >> (8u - n)));
}

/* CRC-8, polynomial 0x07, init 0x00 (SMBus flavour) */
static uint8_t crc8(const uint8_t *data, unsigned len)
{
    unsigned crc = 0u;
    unsigned i, b;
    for (i = 0; i < len; i++) {
        crc ^= data[i];
        for (b = 0; b < 8u; b++) {
            crc <<= 1;
            if (crc & 0x100u)
                crc ^= 0x107u;               /* x^8 + x^2 + x + 1 */
            crc &= 0xFFu;
        }
    }
    return (uint8_t)crc;
}

/* multiply by x in GF(2^8) - FIPS-197 section 4.2 */
static uint8_t xtime(uint8_t a)
{
    unsigned x = a;
    x <<= 1;
    if (x & 0x100u)
        x ^= 0x11Bu;
    return (uint8_t)x;
}

/* state byte order matches the block byte order: byte i of the block is
 * row (i % 4), column (i / 4). Accessor keeps the FIPS-197 row/column
 * vocabulary readable in the loops below. */
#define S(st, r, c) ((st)[4u * (c) + (r)])

/* Standard AES-128 key schedule (FIPS-197 5.2). The TECU-3 always expands
 * to ten round keys; the encryption loop below simply stops one round
 * earlier than stock AES-128 would. */
void tecu_key_expansion(const uint8_t key[16], uint8_t roundkeys[160])
{
    unsigned i, j;
    uint8_t temp[4];

    for (i = 0; i < 16u; i++)
        roundkeys[i] = key[i];

    for (i = 4; i < 40u; i++) {
        for (j = 0; j < 4u; j++)
            temp[j] = roundkeys[4u * (i - 1u) + j];
        if ((i & 3u) == 0u) {
            uint8_t t = temp[0];              /* RotWord */
            temp[0] = tecu_rom.sbox[temp[1]];
            temp[1] = tecu_rom.sbox[temp[2]];
            temp[2] = tecu_rom.sbox[temp[3]];
            temp[3] = tecu_rom.sbox[t];
            temp[0] ^= tecu_rom.rcon[i >> 2]; /* SubWord + Rcon */
        }
        for (j = 0; j < 4u; j++)
            roundkeys[4u * i + j] =
                (uint8_t)(roundkeys[4u * (i - 4u) + j] ^ temp[j]);
    }
}

/* The modified core: AES-128 data path, NINE rounds. Eight full rounds
 * (SubBytes, ShiftRows, MixColumns, AddRoundKey) plus a final round
 * without MixColumns. Stock libraries run ten; that difference alone
 * makes every stock-AES implementation useless against this ECU. */
static void aes9_block(const uint8_t in[16], const uint8_t key[16],
                       uint8_t out[16])
{
    uint8_t st[16];
    uint8_t rk[160];
    unsigned r, c, rnd;

    tecu_key_expansion(key, rk);

    for (r = 0; r < 4u; r++)
        for (c = 0; c < 4u; c++)
            S(st, r, c) = (uint8_t)(S(in, r, c) ^ rk[4u * c + r]);

    for (rnd = 1; rnd < 9u; rnd++) {
        for (r = 0; r < 4u; r++)              /* SubBytes */
            for (c = 0; c < 4u; c++)
                S(st, r, c) = tecu_rom.sbox[S(st, r, c)];

        {   /* ShiftRows: row r rotates left by r */
            uint8_t t;
            t = S(st, 1, 0); S(st, 1, 0) = S(st, 1, 1); S(st, 1, 1) = S(st, 1, 2); S(st, 1, 2) = S(st, 1, 3); S(st, 1, 3) = t;
            t = S(st, 2, 0); S(st, 2, 0) = S(st, 2, 2); S(st, 2, 2) = t; t = S(st, 2, 1); S(st, 2, 1) = S(st, 2, 3); S(st, 2, 3) = t;
            t = S(st, 3, 0); S(st, 3, 0) = S(st, 3, 3); S(st, 3, 3) = S(st, 3, 2); S(st, 3, 2) = S(st, 3, 1); S(st, 3, 1) = t;
        }

        for (c = 0; c < 4u; c++) {            /* MixColumns */
            uint8_t a0 = S(st, 0, c), a1 = S(st, 1, c);
            uint8_t a2 = S(st, 2, c), a3 = S(st, 3, c);
            uint8_t x = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
            S(st, 0, c) = (uint8_t)(a0 ^ x ^ xtime((uint8_t)(a0 ^ a1)));
            S(st, 1, c) = (uint8_t)(a1 ^ x ^ xtime((uint8_t)(a1 ^ a2)));
            S(st, 2, c) = (uint8_t)(a2 ^ x ^ xtime((uint8_t)(a2 ^ a3)));
            S(st, 3, c) = (uint8_t)(a3 ^ x ^ xtime((uint8_t)(a3 ^ a0)));
        }

        for (r = 0; r < 4u; r++)              /* AddRoundKey */
            for (c = 0; c < 4u; c++)
                S(st, r, c) ^= rk[16u * rnd + 4u * c + r];
    }

    for (r = 0; r < 4u; r++)                  /* final round: no MixColumns */
        for (c = 0; c < 4u; c++)
            S(st, r, c) = tecu_rom.sbox[S(st, r, c)];
    {   /* ShiftRows */
        uint8_t t;
        t = S(st, 1, 0); S(st, 1, 0) = S(st, 1, 1); S(st, 1, 1) = S(st, 1, 2); S(st, 1, 2) = S(st, 1, 3); S(st, 1, 3) = t;
        t = S(st, 2, 0); S(st, 2, 0) = S(st, 2, 2); S(st, 2, 2) = t; t = S(st, 2, 1); S(st, 2, 1) = S(st, 2, 3); S(st, 2, 3) = t;
        t = S(st, 3, 0); S(st, 3, 0) = S(st, 3, 3); S(st, 3, 3) = S(st, 3, 2); S(st, 3, 2) = S(st, 3, 1); S(st, 3, 1) = t;
    }
    for (r = 0; r < 4u; r++)
        for (c = 0; c < 4u; c++)
            S(st, r, c) ^= rk[144u + 4u * c + r];

    for (r = 0; r < 4u; r++)
        for (c = 0; c < 4u; c++)
            S(out, r, c) = S(st, r, c);
}

/* Lane A scrambler: rotate/xor mix followed by a chained rotate/xor rollup. */
static void scramble_a(const uint8_t ea[16], uint8_t out[4])
{
    uint8_t u[4], v[4];
    unsigned j;

    for (j = 0; j < 4u; j++)
        u[j] = (uint8_t)(ror8b(ea[j], 5u) ^ ea[8u + j]);
    v[0] = u[0];
    for (j = 1; j < 4u; j++)
        v[j] = (uint8_t)(u[j] ^ rol8b(v[j - 1u], 3u));
    for (j = 0; j < 4u; j++)
        out[j] = (uint8_t)(v[j] ^ tecu_rom.mask_a[j]);
}

/* Lane B scrambler: CRC-8 of each quarter of the ciphertext, masked. */
static void scramble_b(const uint8_t eb[16], uint8_t out[4])
{
    unsigned j;
    for (j = 0; j < 4u; j++)
        out[j] = (uint8_t)(crc8(&eb[4u * j], 4u) ^ tecu_rom.mask_b[j]);
}

/* Diagnostic security access level 0x11: seed (4 bytes) -> key (8 bytes).
 * Called by the 0x27 service handler on receipt of a new seed. */
void tecu_compute_key(uint32_t seed, uint8_t out[8])
{
    uint32_t w[4];
    uint8_t block[16];
    uint8_t ea[16], eb[16];
    unsigned i;

    w[0] = seed;                     /* block builder: seed-derived words */
    w[1] = seed ^ TECU_C1_WORD;
    w[2] = rol32(seed, 13u);
    w[3] = seed + TECU_C2_WORD;
    for (i = 0; i < 4u; i++) {
        block[4u * i + 0u] = (uint8_t)(w[i] >> 24);
        block[4u * i + 1u] = (uint8_t)(w[i] >> 16);
        block[4u * i + 2u] = (uint8_t)(w[i] >> 8);
        block[4u * i + 3u] = (uint8_t)(w[i]);
    }

    aes9_block(block, tecu_rom.key_a, ea);
    aes9_block(block, tecu_rom.key_b, eb);

    scramble_a(ea, &out[0]);
    scramble_b(eb, &out[4]);
}
