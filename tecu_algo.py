#!/usr/bin/env python3
"""TECU-3 security access algorithm - reimplementation target for the article.

This file is what the walkthrough in the article reverse engineers towards.
Every constant here was lifted from the TECU-3 training firmware blob
(firmware/tecu3_fw.bin) using only static analysis - no cheating.

Algorithm summary (security access level 0x11):

  seed : 4 bytes (big-endian integer, as delivered by UDS 0x27 sub 0x11)
  key  : 8 bytes (sent with UDS 0x27 sub 0x12)

  1) message block construction (16 bytes):
       w0 = seed
       w1 = seed ^ C1
       w2 = ROL32(seed, 13)
       w3 = (seed + C2) mod 2**32
       block = w0 || w1 || w2 || w3        (each word big-endian)

  2) two lanes of a modified AES-128 ("aes9"):
       EA = aes9(block, KEY_A)
       EB = aes9(block, KEY_B)
     aes9 uses the standard AES-128 data path (SubBytes, ShiftRows,
     MixColumns, AddRoundKey) and the standard key schedule - but only
     NINE rounds: eight full rounds plus a final round without
     MixColumns. Stock AES-128 uses ten. The key schedule still
     produces ten round keys; round nine simply never happens.

  3) output scramblers:
       lane A (16 -> 4 bytes):
         u[j]  = ROR8(EA[j], 5) ^ EA[8 + j]         j = 0..3
         v[0]  = u[0]
         v[j]  = u[j] ^ ROL8(v[j-1], 3)             j = 1..3
         outA[j] = v[j] ^ MASK_A[j]
       lane B (16 -> 4 bytes):
         p[j]  = CRC-8 (poly 0x07, init 0x00) of EB[4j : 4j+4]
         outB[j] = p[j] ^ MASK_B[j]
       key = outA || outB

All constants below are synthetic - invented for the TECU-3 training
target. The structure deliberately imitates the flavour of real
automotive seed-key schemes (a crypto core plus bespoke byte mangling)
without matching any of them.
"""

from __future__ import annotations

import sys

# ---------------------------------------------------------------------------
# Constants extracted from the firmware blob (offsets are file offsets in
# tecu3_fw.bin, flash base 0x08000000)
# ---------------------------------------------------------------------------

SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)  # offset 0x08000520 - the FIPS-197 substitution box

RCON = bytes.fromhex("0001020408102040801b36")  # offset 0x08000648 (index 0 unused)

KEY_A = bytes.fromhex("f7a1c303075a145cdb6d7849e6a57766")  # offset 0x08000620
KEY_B = bytes.fromhex("2a97498b9929151e7f03ed63c129ab79")  # offset 0x08000630
MASK_A = bytes.fromhex("46a08c7a")  # offset 0x08000640
MASK_B = bytes.fromhex("76bfd6a1")  # offset 0x08000644

C1 = 0xEF3CEB7F  # offset 0x08000398+ (word XOR constant inside tecu_compute_key)
C2 = 0x64487893  # offset 0x08000398+ (word ADD constant inside tecu_compute_key)

# Firmware power-on self-test vector (stored in the ROM table struct):
#   selftest_seed at 0x08000654, little-endian: 4D 3C 2B 1A -> 0x1A2B3C4D
#   selftest_key  at 0x08000658: F7 E1 27 45 F5 B0 E0 46
SELFTEST_SEED = 0x1A2B3C4D
SELFTEST_KEY = bytes.fromhex("f7e12745f5b0e046")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def rol32(x: int, n: int) -> int:
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def ror8(x: int, n: int) -> int:
    n &= 7
    return ((x >> n) | (x << (8 - n))) & 0xFF


def rol8(x: int, n: int) -> int:
    n &= 7
    return ((x << n) | (x >> (8 - n))) & 0xFF


def crc8(data: bytes) -> int:
    """CRC-8 with polynomial 0x07, init 0x00 (the SMBus/CRC-8 flavour)."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def xtime(a: int) -> int:
    """Multiply by x in GF(2^8) - the MixColumns building block (FIPS-197 4.2)."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


# ---------------------------------------------------------------------------
# AES core, parameterised by round count
# ---------------------------------------------------------------------------

def key_expansion(key: bytes, rounds: int):
    """Standard AES-128 key schedule (FIPS-197 5.2), (rounds+1) round keys."""
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    i = 1
    while len(words) < 4 * (rounds + 1):
        temp = list(words[-1])
        if len(words) % 4 == 0:
            temp = temp[1:] + temp[:1]              # RotWord
            temp = [SBOX[b] for b in temp]          # SubWord
            temp[0] ^= RCON[i]
            i += 1
        words.append([words[-4][k] ^ temp[k] for k in range(4)])
    return words


def aes_encrypt_block(block: bytes, key: bytes, rounds: int) -> bytes:
    """AES-128 data path with a configurable round count.

    rounds=10 is stock AES-128 (verified against the FIPS-197 C.1 vector
    in --selftest). The TECU-3 runs rounds=9 - the single modification
    that makes stock crypto libraries useless against it.
    """
    state = [list(block[i::4]) for i in range(4)]   # state[r][c], FIPS-197 3.4
    rk = key_expansion(key, rounds)

    def add_round_key(rnd):
        for c in range(4):
            for r in range(4):
                state[r][c] ^= rk[4 * rnd + c][r]

    add_round_key(0)
    for rnd in range(1, rounds):
        for c in range(4):                          # SubBytes
            for r in range(4):
                state[r][c] = SBOX[state[r][c]]
        for r in range(1, 4):                       # ShiftRows
            state[r] = state[r][r:] + state[r][:r]
        for c in range(4):                          # MixColumns
            col = [state[r][c] for r in range(4)]
            for r in range(4):
                state[r][c] = (xtime(col[r]) ^ xtime(col[(r + 1) % 4]) ^ col[(r + 1) % 4]
                               ^ col[(r + 2) % 4] ^ col[(r + 3) % 4])
        add_round_key(rnd)
    for c in range(4):                              # final round (no MixColumns)
        for r in range(4):
            state[r][c] = SBOX[state[r][c]]
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]
    add_round_key(rounds)
    return bytes(state[r][c] for c in range(4) for r in range(4))


def aes9(block: bytes, key: bytes) -> bytes:
    return aes_encrypt_block(block, key, rounds=9)


# ---------------------------------------------------------------------------
# The TECU-3 algorithm
# ---------------------------------------------------------------------------

def build_block(seed: int) -> bytes:
    w0 = seed & 0xFFFFFFFF
    w1 = w0 ^ C1
    w2 = rol32(w0, 13)
    w3 = (w0 + C2) & 0xFFFFFFFF
    return b"".join(w.to_bytes(4, "big") for w in (w0, w1, w2, w3))


def scramble_a(ea: bytes) -> bytes:
    u = [ror8(ea[j], 5) ^ ea[8 + j] for j in range(4)]
    v = [u[0]]
    for j in range(1, 4):
        v.append(u[j] ^ rol8(v[j - 1], 3))
    return bytes(v[j] ^ MASK_A[j] for j in range(4))


def scramble_b(eb: bytes) -> bytes:
    return bytes(crc8(eb[4 * j:4 * j + 4]) ^ MASK_B[j] for j in range(4))


def tecu_compute_key(seed: int) -> bytes:
    """Compute the 8-byte security access key for a 4-byte seed."""
    block = build_block(seed)
    ea = aes9(block, KEY_A)
    eb = aes9(block, KEY_B)
    return scramble_a(ea) + scramble_b(eb)


def tecu_compute_key_int(seed: int) -> int:
    """Same as tecu_compute_key, as a big-endian integer (udscope convention)."""
    return int.from_bytes(tecu_compute_key(seed), "big")


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

FIPS197_C1 = (
    bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
    bytes.fromhex("00112233445566778899aabbccddeeff"),
    bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"),
)


def run_selftest() -> bool:
    ok = True

    key, plaintext, expected = FIPS197_C1
    got = aes_encrypt_block(plaintext, key, rounds=10)
    verdict = "PASS" if got == expected else "FAIL"
    ok &= got == expected
    print(f"[1] AES core, 10 rounds vs FIPS-197 C.1 vector ....... {verdict}")
    if got != expected:
        print(f"    expected {expected.hex()} got {got.hex()}")

    got9 = aes_encrypt_block(plaintext, key, rounds=9)
    verdict = "PASS" if got9 != expected else "FAIL (round count has no effect?)"
    ok &= got9 != expected
    print(f"[2] Same input at 9 rounds differs from AES-128 ....... {verdict}")

    check = crc8(b"123456789")
    verdict = "PASS" if check == 0xF4 else "FAIL"
    ok &= check == 0xF4
    print(f"[3] CRC-8/0x07 check value ('123456789' -> 0xF4) ...... {verdict}")

    got = tecu_compute_key(SELFTEST_SEED)
    verdict = "PASS" if got == SELFTEST_KEY else "FAIL"
    ok &= got == SELFTEST_KEY
    print(f"[4] Firmware self-test vector (seed 0x{SELFTEST_SEED:08X}) ........ {verdict}")
    print(f"    firmware expects {SELFTEST_KEY.hex()}, we compute {got.hex()}")
    return ok


def main() -> int:
    if "--selftest" in sys.argv:
        return 0 if run_selftest() else 1
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <hex seed> | --selftest", file=sys.stderr)
        return 2
    seed = int(sys.argv[1], 16)
    if not 0 <= seed <= 0xFFFFFFFF:
        print("seed must fit in 4 bytes", file=sys.stderr)
        return 2
    print(f"seed 0x{seed:08X} -> key {tecu_compute_key(seed).hex(' ')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
