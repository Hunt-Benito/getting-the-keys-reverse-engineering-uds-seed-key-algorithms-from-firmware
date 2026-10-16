#!/usr/bin/env python3
"""Run the TECU-3 virtual ECU on vcan0.

This is udscope's simulator with one substitution: the demo seed-key
algorithm is replaced by the TECU-3 security module (tecu_algo.py) at
runtime, through udscope's public registry API. No udscope files are
modified - the plugin registers itself, then points the DemoEcu at the
registered name.

Terminal 1:  python3 sim_tecu.py
Terminal 2:  python3 03_unlock.py
"""
from __future__ import annotations

import sys

from udscope import __version__, security
from udscope.security import SeedKeyAlgorithm
from udscope.simulator import DemoEcu
from udscope.transport import IsotpLink
from udscope.vcan import ensure_vcan

from tecu_algo import tecu_compute_key_int

ALGO_NAME = "tecu_scramble"


def register_tecu_algorithm() -> None:
    security.register(SeedKeyAlgorithm(
        name=ALGO_NAME,
        seed_len=4,
        key_len=8,
        fn=lambda seed, level=0x11: tecu_compute_key_int(seed),
        description="modified AES (9 rounds) with output scramblers (synthetic)",
        origin="synthetic (TECU-3 training target)",
    ))


def main() -> int:
    if not ensure_vcan(channel="vcan0", interface="socketcan"):
        print("vcan0 unavailable - run `udscope setup` first", file=sys.stderr)
        return 2

    register_tecu_algorithm()

    # DemoEcu resolves its algorithm by name at reset; swap the default
    # for ours before the simulator instance is created.
    import udscope.simulator as sim
    sim.SECURITY_ALGORITHM = ALGO_NAME

    link = IsotpLink(0x7E8, 0x7E0, channel="vcan0", interface="socketcan")
    ecu = DemoEcu(link)
    print(f"udscope {__version__} - TECU-3 training ECU on socketcan:vcan0")
    print("(requests 0x7E0, responses 0x7E8)")
    print("Level 0x11 seed-key algorithm: modified AES + scramblers | Ctrl-C to stop")
    try:
        ecu.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping simulator")
    ecu.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
