#!/usr/bin/env python3
"""Hunt for known crypto tables in a firmware blob.

Slides a 256-byte window across the binary and scores each position
against the FIPS-197 AES S-box by Hamming distance. Distance 0 means
the stock table is embedded verbatim - the most common case in
automotive firmware. Small distances (a few bits) mean a tweaked
table, which some vendors use.

Usage:
    python3 01_hunt_sbox.py [firmware/tecu3_fw.bin]

Works on any binary - point it at whatever dump you are analysing.
"""
from __future__ import annotations

import sys

AES_SBOX = bytes.fromhex(
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
)

DEFAULT_BLOB = "firmware/tecu3_fw.bin"
BASE = 0x08000000          # flash base this image is linked at


def hamming_distance(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def scan(blob: bytes, table: bytes, max_report: int = 5):
    """Yield (offset, distance) for the best windows in the blob."""
    hits = []
    for off in range(0, len(blob) - len(table) + 1):
        dist = hamming_distance(blob[off:off + len(table)], table)
        if dist <= 128:                      # 256 bytes * 8 bits: 128 = coin flip
            hits.append((off, dist))
    hits.sort(key=lambda h: (h[1], h[0]))
    return hits[:max_report]


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BLOB
    blob = open(path, "rb").read()
    print(f"scanning {path} ({len(blob)} bytes) for the AES S-box ...")
    hits = scan(blob, AES_SBOX)
    if not hits:
        print("no plausible S-box candidate (closest window still > 128 bits away)")
        print("-> stock AES table not present; consider tweaked tables or")
        print("   computed S-boxes (some vendors generate the table at boot)")
        return 1
    for off, dist in hits:
        addr = BASE + off
        if dist == 0:
            verdict = "EXACT - stock FIPS-197 S-box embedded verbatim"
        else:
            verdict = f"near miss - possibly tweaked table ({dist} bits differ)"
        print(f"  candidate @ file 0x{off:04X} (addr 0x{addr:08X})"
              f"  distance {dist:4d} bits  {verdict}")
    print("\nnext: dump the bytes around the best hit - vendor keys and masks")
    print("often sit next to the tables they belong with")
    return 0


if __name__ == "__main__":
    sys.exit(main())
