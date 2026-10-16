# TECU-3: Reverse Engineering a UDS Seed-Key Algorithm from Firmware

Companion PoC for the Hunt-Benito article
**Getting the Keys: Reverse Engineering UDS Seed-Key Algorithms from Firmware**
(https://www.hunt-benito.com/blog/getting-the-keys-reverse-engineering-uds-seed-key-algorithms-from-firmware/).

Everything here is synthetic. The `tecu3_fw.bin` blob is a small ARM
Cortex-M3 training image built for this exercise: it contains a modified
AES core (nine rounds instead of the AES-128 standard ten) wrapped in two
bespoke output scramblers - the flavour of construction you meet in real
automotive security-access code, with every constant freshly generated.
No real vehicle, ECU, or vendor secret is involved.

## What is here

```
01_hunt_sbox.py        scan any binary for the AES S-box (Hamming distance)
02_map_blob.py         dump and annotate the table cluster behind the S-box
03_unlock.py           end-to-end security access against the virtual ECU
sim_tecu.py            the TECU-3 virtual ECU (udscope simulator + plugin)
tecu_algo.py           the reimplemented algorithm, pure Python, no deps
firmware/
  tecu3_fw.bin         the training blob (4 KB, flash base 0x08000000)
  Makefile, linker.ld, src/   full build so you can rebuild or fork it
```

## Setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install git+https://github.com/Hunt-Benito/udscope   # pulls python-can, can-isotp
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

(`udscope setup` does the vcan dance for you if the interface is missing.)

## The walkthrough

```bash
# 1. find the crypto in the blob
python3 01_hunt_sbox.py
python3 02_map_blob.py 520

# 2. sanity-check the reimplementation against the firmware self-test
python3 tecu_algo.py --selftest
python3 tecu_algo.py 1A2B3C4D

# 3. bring the virtual ECU up (terminal 1) ...
python3 sim_tecu.py

# 4. ... and unlock it (terminal 2)
python3 03_unlock.py
```

Rebuilding the firmware requires an `arm-none-eabi` GCC (`apt install
gcc-arm-none-eabi` or an xPack release): `cd firmware && make`.

## Reading the disassembly yourself

The blob is raw Thumb-2 at flash base `0x08000000`. In Ghidra: import
`firmware/tecu3_fw.bin`, language `ARM Cortex Little Endian (v7-M?)` /
Thumb, base address `0x08000000`, then find `tecu_compute_key` (file
offset `0x398`) and follow the literal pool at its tail. With plain
binutils: `arm-none-eabi-objdump -D -b binary -m arm -M force-thumb
--adjust-vma=0x08000000 firmware/tecu3_fw.bin`.

## Scope and ethics

This is a training exercise against a synthetic target. The techniques
(table fingerprinting, literal-pool reading, round counting) transfer to
real firmware you own or are authorised to test - your bench ECUs, your
own vehicle, engagement scope. Nothing here bypasses a security mechanism
on anyone else's property.
