#!/usr/bin/env python3
"""Map the security region that clusters around a found S-box.

Firmware authors (and linkers) usually keep a module's tables together:
once the S-box scanner gives you an offset, the bytes that follow it are
the highest-value real estate in the whole dump. This script dumps the
cluster, fingerprints the AES round-constant sequence (a second AES
identifier people forget to look for), and lists the candidate
constants between the S-box and the end of the cluster.

Usage:
    python3 02_map_blob.py [offset-hex] [firmware/tecu3_fw.bin]
"""
from __future__ import annotations

import sys

DEFAULT_BLOB = "firmware/tecu3_fw.bin"
BASE = 0x08000000

# Rcon for AES-128 key schedules: x^(i-1) in GF(2^8), i = 1..10,
# with the customary unused leading byte. A doubling chain, so it is
# trivially recognisable even when the S-box has been tweaked.
AES_RCON = bytes.fromhex("0001020408102040801b36")

CLUSTER_LEN = 0x140          # how far past the S-box to inspect


def ascii_repr(b: bytes) -> str:
    return "".join(chr(x) if 32 <= x < 127 else "." for x in b)


def hexdump(data: bytes, base_off: int) -> None:
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        pad = " " * (3 * (16 - len(chunk)))
        print(f"  {BASE + base_off + i:08X}: {hexpart}{pad}  |{ascii_repr(chunk)}|")


def main() -> int:
    sbox_off = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x520
    path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_BLOB
    blob = open(path, "rb").read()

    print(f"security cluster at file 0x{sbox_off:04X} (S-box first, then"
          f" {CLUSTER_LEN:#x} bytes of neighbours):")
    print()

    # S-box head and tail for the record
    print(f"  S-box        0x{BASE + sbox_off:08X} .. 0x{BASE + sbox_off + 255:08X}")
    print(f"    head: {blob[sbox_off:sbox_off + 8].hex(' ')}")
    print(f"    tail: {blob[sbox_off + 248:sbox_off + 256].hex(' ')}")
    print()

    region = blob[sbox_off + 256:sbox_off + 256 + CLUSTER_LEN]
    print(f"  cluster after the S-box (file 0x{sbox_off + 256:04X}+):")
    hexdump(region, sbox_off + 256)
    print()

    # fingerprint the Rcon doubling chain anywhere in the cluster
    rcon_off = blob.find(AES_RCON, sbox_off, sbox_off + 256 + CLUSTER_LEN)
    if rcon_off >= 0:
        print(f"  [+] AES Rcon signature at 0x{BASE + rcon_off:08X}"
              f" (file 0x{rcon_off:04X}) - key schedule confirmed")
        pre = rcon_off - (sbox_off + 256)
        if 0 < pre:
            print(f"      {pre} bytes of constants sit between S-box and Rcon")
    else:
        print("  [-] no stock Rcon sequence in the cluster"
              " (computed schedule or non-standard constants?)")
    print()
    print("  candidates to chase in the disassembler: every aligned run of")
    print("  non-FF bytes between S-box and the cluster end. 16-byte runs are")
    print("  key-shaped; 4-byte runs are mask-shaped; a lone 32-bit value")
    print("  followed by an 8-byte value near a self-test routine is a")
    print("  known-answer pair - free verification for your reimplementation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
