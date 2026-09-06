#!/usr/bin/env python3
"""
C3 — AES Oracle Attacks: offline demo.

Runs padding-oracle, CBC bit-flip, and ECB-detection attacks against local,
controlled oracles. Bundled pure-python AES ensures it works with stdlib only.
Exits 0 on success.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from firmware import aes_attacks as aes


def main():
    print("C3 AES Oracle Attacks — offline demo (authorized lab only)")
    backend = "pycryptodome" if aes._HAS_PYCRYPTODOME else "pure-python"
    print(f"cipher backend: {backend}")
    results = [
        aes.demo_padding_oracle(),
        aes.demo_bitflip(),
        aes.ecb_detection_demo(),
    ]
    print("\n--- summary ---")
    for r in results:
        print(f"  {r['attack']}: recovered={r['recovered']}")
    aes.save_report(results, os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports"))
    assert all(r["recovered"] for r in results)
    print("\nAll offline demos PASSED: 3 AES oracle attacks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
