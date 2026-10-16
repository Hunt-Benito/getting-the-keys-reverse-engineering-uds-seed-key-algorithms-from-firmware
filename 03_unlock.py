#!/usr/bin/env python3
"""End-to-end security access against the TECU-3 virtual ECU.

Plays the part of the tester that has just finished reverse engineering
the seed-key algorithm: request a seed, compute the key with the
reimplementation (tecu_algo.py), send it, and prove the unlock by
entering the developer session and reading a developer-gated DID.

Terminal 1:  python3 sim_tecu.py
Terminal 2:  python3 03_unlock.py
"""
from __future__ import annotations

import argparse
import sys

from udscope.transport import IsotpLink
from udscope.uds import NegativeResponseError, Session, UdsClient

from tecu_algo import tecu_compute_key_int


def quiet(direction, arb_id, data):
    pass


def request_seed(client: UdsClient) -> int:
    resp = client.request(bytes([0x27, 0x11]))          # SecurityAccess, odd sub
    if resp[0] != 0x67:
        raise ValueError(f"unexpected response {resp.hex()}")
    return int.from_bytes(resp[2:], "big")


def send_key(client: UdsClient, key: int) -> bytes:
    return client.request(bytes([0x27, 0x12]) + key.to_bytes(8, "big"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channel", default="vcan0")
    parser.add_argument("--bus", default="socketcan")
    args = parser.parse_args()

    link = IsotpLink(0x7E0, 0x7E8, channel=args.channel,
                     interface=args.bus, logger=quiet)
    link.start()
    client = UdsClient(link)

    try:
        print("[1] extended diagnostic session")
        print(f"    {client.set_session(Session.EXTENDED).hex(' ')}"
              f"  (0x50 = positive, session 0x03)")

        print("[2] seed request, then a key we KNOW is wrong (all zeros)")
        seed = request_seed(client)
        print(f"    seed: 0x{seed:08X}")
        try:
            send_key(client, 0)
        except NegativeResponseError as exc:
            print(f"    reply: NRC 0x{exc.nrc:02X} ({exc.description})")

        print("[3] fresh seed, key computed by our extracted algorithm")
        seed = request_seed(client)
        key = tecu_compute_key_int(seed)
        print(f"    seed: 0x{seed:08X}  ->  key: {key:016X}")
        resp = send_key(client, key)
        print(f"    reply: {resp.hex(' ')}  (0x67 0x12 = key accepted)")

        print("[4] proof of unlock: developer session + gated DID 0xF22C")
        print(f"    {client.set_session(Session.DEVELOPER).hex(' ')}"
              f"  (0x50 = positive, session 0x60)")
        did = client.read_did(0xF22C)
        print(f"    DID 0xF22C: {did[3:].hex(' ')} - readable only when unlocked")
        print("\nsecurity access: REVERSE ENGINEERED AND UNLOCKED")
        return 0
    except NegativeResponseError as exc:
        print(f"error: negative response {exc}", file=sys.stderr)
        return 1
    finally:
        link.stop()


if __name__ == "__main__":
    sys.exit(main())
