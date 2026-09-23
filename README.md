> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# C3 — AES Oracle Attacks

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/c3-aes-attacks)
![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/c3-aes-attacks)
![GitHub issues](https://img.shields.io/github/issues/5h4d0wn1k/c3-aes-attacks)

A real, offline suite of **AES cryptographic attack demos** — CBC padding-oracle, CBC bit-flip, and ECB-detection — against local, controlled oracles, with a bundled pure-Python AES (FIPS-197) so everything runs on the standard library alone.

## Why

Flawed AES modes predate real-world cryptanalysis: CBC padding oracles, bit-flips, and ECB block patterns are exactly what modern crypto auditing hunts for. This toolkit makes **cryptographic attacks** legible for authorized security testing and education — you watch a real PKCS#7 padding oracle recover a full CBC plaintext byte-by-byte, a bit-flip rewrite `Admin=0;role=user` into `Admin=1;role=user` in-place, and ECB detection pick out duplicated ciphertext blocks. Everything runs offline against **local, controlled oracle implementations**, deliberately: a lab design, not a deployable weapon. The bundled pure-python AES backend is verified byte-for-byte against FIPS-197 known-answer tests and `pycryptodome`.

## Features

- **Padding Oracle attack** — recovers full CBC plaintext byte-by-byte from a local PKCS#7 oracle with query counting.
- **CBC bit-flip attack** — edits ciphertext to flip controlled plaintext bytes in-place.
- **ECB detection** — identifies ECB by duplicate ciphertext blocks and distinguishes it from CBC.
- **Pure-python AES (FIPS-197)** — S-box, key expansion, ShiftRows, MixColumns; guarded `pycryptodome` acceleration (`C3_FORCE_PURE=1` forces stdlib).
- **JSON reports** under `reports/` (gitignored); exit `0` only if all attacks recovered/verified correctly.

## Quickstart

```bash
# Run all attacks against local oracles (offline demo)
python3 demo.py

# Individual attacks
python3 firmware/aes_attacks.py padding-oracle
python3 firmware/aes_attacks.py bitflip
python3 firmware/aes_attacks.py ecb-detect
python3 firmware/aes_attacks.py all

# Help
python3 firmware/aes_attacks.py --help
```

```bash
# Tests (FIPS-197 KAT, PKCS#7, each attack)
python3 -m unittest discover -s tests -v

# Force pure-python AES backend to prove stdlib-only operation
C3_FORCE_PURE=1 python3 -m unittest discover -s tests -v
```

Requirements: Python 3.8+ (standard library only); optional `pycryptodome` for a faster cipher backend.

## Project structure

```
c3-aes-attacks/
├── firmware/aes_attacks.py  # attacks + bundled AES (stdlib)
├── demo.py                  # offline demo (all 3 attacks, exit 0)
├── tests/                   # unittest suite
└── ETHICS.md, SCOPE.md      # authorized-use rules
```

## Documentation

- [ETHICS.md](ETHICS.md) — authorized-use policy
- [SCOPE.md](SCOPE.md) — lab scope
- [SECURITY.md](SECURITY.md) — security policy
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Never point these attacks at production systems or third-party data without written authorization.

## License

MIT. See [LICENSE](LICENSE).