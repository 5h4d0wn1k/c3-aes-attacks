# C3 — AES Oracle Attacks

A real, offline suite of AES oracle attacks for **authorized security testing
and education**. Includes a bundled pure-python AES (FIPS-197) so everything
works with the standard library alone.

## IMPORTANT: Read before use.

**For educational and authorized security testing purposes only.**

- Only run these attacks against your own systems or within a defined lab
  scope (lab-* hosts, 192.0.2.x ranges, example.com) that you are authorized
  to test.
- Exploiting cryptographic weaknesses (padding attacks, mode misuse) without
  authorization may violate the **Computer Fraud and Abuse Act (CFAA)** and
  related statutes. You are solely responsible for lawful use.
- Provided "AS IS", no warranty; the author is not liable for misuse or damage.

## What genuinely works (real mechanics)

- **Padding Oracle attack** — recovers a full CBC plaintext byte-by-byte from a
  local padding-validity oracle (real PKCS#7 oracle, counts queries).
- **CBC bit-flip attack** — edits ciphertext to flip controlled plaintext bytes
  in-place (e.g. changes `Admin=0;role=user` into `Admin=1;role=user`).
- **ECB detection** — identifies ECB mode by duplicate ciphertext blocks and
  distinguishes it from CBC.

Everything is fully offline against **local, controlled oracle
implementations** — this is a deliberate lab design, not a real vulnerability
you can deploy against third parties.

### Pure-python AES backend
A full AES-128/192/256 implementation (FIPS-197: S-box, key expansion,
ShiftRows, MixColumns, AddRoundKey and their inverses) is bundled, verified
byte-for-byte against `pycryptodome` and the FIPS-197 Appendix C known-answer
test. If `pycryptodome` is installed it is used automatically (guarded import);
set `C3_FORCE_PURE=1` to force the pure-python path.

## Requirements

- Python 3.8+ (standard library only).
- Optional: `pycryptodome` for a faster cipher backend (guarded, not required).

## Usage

```bash
python3 firmware/aes_attacks.py --help
python3 firmware/aes_attacks.py padding-oracle
python3 firmware/aes_attacks.py bitflip
python3 firmware/aes_attacks.py ecb-detect
python3 firmware/aes_attacks.py all
```

Exit code 0 only if every attack recovered/verified correctly.

## Demo (offline, deterministic)

```bash
python3 demo.py
```

## Tests

```bash
python3 -m unittest discover -s tests

# Force the pure-python AES backend to prove stdlib-only operation
C3_FORCE_PURE=1 python3 -m unittest discover -s tests
```

## Live Lab Test Plan

1. **Offline unit tests**: `python3 -m unittest discover -s tests` — verify AES
   correctness (FIPS-197 KAT + pycryptodome cross-check), PKCS#7, and each
   attack against local oracles.
2. **Pure-stdlib proof**: `C3_FORCE_PURE=1 python3 -m unittest discover -s tests`.
3. **Offline demo**: `python3 demo.py` — all 3 attacks, exit 0.
4. **Cross-check**: with pycryptodome installed, confirm the padding-oracle
   result and oracle-query count are stable.
5. **Lab scope only**: never point these attacks at real production systems or
   third-party data without written authorization.

## Metrics

- Attacks: **3** (padding-oracle, CBC bit-flip, ECB detection).
- AES backend: pure-python (stdlib) with optional pycryptodome speed-up.
- Padding oracle: full message recovery, query count reported (e.g. ~4.8k
  queries for a 2-block message).
- Determinism: fixed labs + stable backends produce reproducible results.
- Reports: JSON under `reports/`, gitignored.

## License

MIT
