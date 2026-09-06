#!/usr/bin/env python3
"""
C3 — AES Oracle Attacks
=======================

Real AES oracle attacks for AUTHORIZED security testing / education:

  * Padding Oracle attack  — recover plaintext from a CBC decrypt padding
                             oracle, byte by byte.
  * CBC bit-flip attack    — tamper with ciphertext to flip controlled bytes
                             of the decrypted plaintext.
  * ECB mode detection     — identify ECB by duplicate-ciphertext-blocks.

A pure-python AES (FIPS-197) is bundled so the attacks work with the standard
library alone. If the `pycryptodome` package is installed it may be used as a
drop-in cipher backend (guarded import); the attack code is identical either
way because every oracle is a local, controlled implementation.

All attacks run offline against local oracles. No network access is used.

IMPORTANT: Read before use. Educational / authorized use only.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import secrets
import sys
import time
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Pure-python AES (FIPS-197). Encrypt + decrypt, 128/192/256-bit keys.
# ---------------------------------------------------------------------------

_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

# Inverse S-box
_RSBOX = [0] * 256
for _i in range(256):
    _RSBOX[_SBOX[_i]] = _i

# Fixed round-constant word
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _xtime(a: int) -> int:
    a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF
    return a


def _xtimes(x, n):
    for _ in range(n):
        x = _xtime(x)
    return x


def _gmul(a: int, b: int) -> int:
    """Multiply in GF(2^8) using the standard reduction polynomial."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _rot_word(w):
    return w[1:] + w[:1]


def _sub_word(w):
    return [_SBOX[b] for b in w]


def _key_expansion(key: bytes) -> list:
    """Expand key into round keys (list of 4-word lists, each word 4 bytes)."""
    Nk = len(key) // 4
    Nr = Nk + 6
    w = [[key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]] for i in range(Nk)]
    for i in range(Nk, 4 * (Nr + 1)):
        temp = list(w[i - 1])
        if i % Nk == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= _RCON[i // Nk - 1]
        elif Nk > 6 and i % Nk == 4:
            temp = _sub_word(temp)
        w.append([w[i - Nk][j] ^ temp[j] for j in range(4)])
    # Reorganize into round keys of 16 bytes
    round_keys = []
    for r in range(Nr + 1):
        block = w[r * 4:r * 4 + 4]
        round_keys.append(bytes(b for word in block for b in word))
    return round_keys


def _to_state(block: bytes):
    # FIPS-197: state[r][c] = in[r + 4*c]  (column-major)
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def _from_state(st) -> bytes:
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = st[r][c]
    return bytes(out)


def _add_round_key(st, rk: bytes):
    # state column c XOR round-key word c (bytes 4c..4c+3)
    for c in range(4):
        for r in range(4):
            st[r][c] ^= rk[4 * c + r]


def _sub_bytes(st, table=_SBOX):
    for r in range(4):
        for c in range(4):
            st[r][c] = table[st[r][c]]


def _shift_rows(st):
    # row r shifted left by r
    return [st[0][:], st[1][1:] + st[1][:1], st[2][2:] + st[2][:2], st[3][3:] + st[3][:3]]


def _inv_shift_rows(st):
    return [st[0][:], st[1][3:] + st[1][:3], st[2][2:] + st[2][:2], st[3][1:] + st[3][:1]]


def _mix_columns(st):
    new = [[0] * 4 for _ in range(4)]
    for c in range(4):
        new[0][c] = _gmul(st[0][c], 2) ^ _gmul(st[1][c], 3) ^ st[2][c] ^ st[3][c]
        new[1][c] = st[0][c] ^ _gmul(st[1][c], 2) ^ _gmul(st[2][c], 3) ^ st[3][c]
        new[2][c] = st[0][c] ^ st[1][c] ^ _gmul(st[2][c], 2) ^ _gmul(st[3][c], 3)
        new[3][c] = _gmul(st[0][c], 3) ^ st[1][c] ^ st[2][c] ^ _gmul(st[3][c], 2)
    return new


def _inv_mix_columns(st):
    new = [[0] * 4 for _ in range(4)]
    for c in range(4):
        new[0][c] = (_gmul(st[0][c], 0x0e) ^ _gmul(st[1][c], 0x0b) ^
                     _gmul(st[2][c], 0x0d) ^ _gmul(st[3][c], 0x09))
        new[1][c] = (_gmul(st[0][c], 0x09) ^ _gmul(st[1][c], 0x0e) ^
                     _gmul(st[2][c], 0x0b) ^ _gmul(st[3][c], 0x0d))
        new[2][c] = (_gmul(st[0][c], 0x0d) ^ _gmul(st[1][c], 0x09) ^
                     _gmul(st[2][c], 0x0e) ^ _gmul(st[3][c], 0x0b))
        new[3][c] = (_gmul(st[0][c], 0x0b) ^ _gmul(st[1][c], 0x0d) ^
                     _gmul(st[2][c], 0x09) ^ _gmul(st[3][c], 0x0e))
    return new


class PureAES:
    """Pure-python AES (FIPS-197) block cipher (supports ECB/CBC)."""

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16/24/32 bytes")
        self.key = key
        self.round_keys = _key_expansion(key)
        self.Nr = len(key) // 4 + 6

    def encrypt_block(self, block: bytes) -> bytes:
        st = _to_state(block)
        _add_round_key(st, self.round_keys[0])
        for r in range(1, self.Nr):
            _sub_bytes(st)
            st = _shift_rows(st)
            st = _mix_columns(st)
            _add_round_key(st, self.round_keys[r])
        _sub_bytes(st)
        st = _shift_rows(st)
        _add_round_key(st, self.round_keys[self.Nr])
        return _from_state(st)

    def decrypt_block(self, block: bytes) -> bytes:
        st = _to_state(block)
        _add_round_key(st, self.round_keys[self.Nr])
        for r in range(self.Nr - 1, 0, -1):
            st = _inv_shift_rows(st)
            _sub_bytes(st, _RSBOX)
            _add_round_key(st, self.round_keys[r])
            st = _inv_mix_columns(st)
        st = _inv_shift_rows(st)
        _sub_bytes(st, _RSBOX)
        _add_round_key(st, self.round_keys[0])
        return _from_state(st)


# ---------------------------------------------------------------------------
# Cipher backend: prefer pycryptodome if present (guarded), else pure-python.
# ---------------------------------------------------------------------------

try:
    from Crypto.Cipher import AES as _PyAES
    from Crypto.Util.Padding import pad as _py_pad, unpad as _py_unpad

    _HAS_PYCRYPTODOME = True
except Exception:  # pragma: no cover - fallback path
    _PyAES = None
    _HAS_PYCRYPTODOME = False


def _backend_aes(key: bytes):
    if _HAS_PYCRYPTODOME and not os.environ.get("C3_FORCE_PURE"):
        return _PyAES.new(key, _PyAES.MODE_ECB)
    return PureAES(key)


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    n = block_size - (len(data) % block_size)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("Invalid padding")
    n = data[-1]
    if n < 1 or n > block_size:
        raise ValueError("Invalid padding")
    if data[-n:] != bytes([n]) * n:
        raise ValueError("Invalid padding")
    return data[:-n]


def aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    if _HAS_PYCRYPTODOME and not os.environ.get("C3_FORCE_PURE"):
        return _PyAES.new(key, _PyAES.MODE_ECB).encrypt(plaintext)
    aes = PureAES(key)
    return b"".join(aes.encrypt_block(plaintext[i:i + 16])
                    for i in range(0, len(plaintext), 16))


def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    if _HAS_PYCRYPTODOME and not os.environ.get("C3_FORCE_PURE"):
        return _PyAES.new(key, _PyAES.MODE_ECB).decrypt(ciphertext)
    aes = PureAES(key)
    return b"".join(aes.decrypt_block(ciphertext[i:i + 16])
                    for i in range(0, len(ciphertext), 16))


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    if _HAS_PYCRYPTODOME and not os.environ.get("C3_FORCE_PURE"):
        return _PyAES.new(key, _PyAES.MODE_CBC, iv).encrypt(plaintext)
    aes = PureAES(key)
    prev, out = iv, b""
    for i in range(0, len(plaintext), 16):
        block = bytes(a ^ b for a, b in zip(plaintext[i:i + 16], prev))
        prev = aes.encrypt_block(block)
        out += prev
    return out


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if _HAS_PYCRYPTODOME and not os.environ.get("C3_FORCE_PURE"):
        return _PyAES.new(key, _PyAES.MODE_CBC, iv).decrypt(ciphertext)
    aes = PureAES(key)
    prev, out = iv, b""
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        dec = aes.decrypt_block(block)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    return out


# ---------------------------------------------------------------------------
# Oracles (LOCAL, controlled implementations)
# ---------------------------------------------------------------------------

class PaddingOracle:
    """CBC encrypt + padding-validity oracle (the attacker interacts with this)."""

    def __init__(self, key: bytes):
        self.key = key
        self.calls = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = secrets.token_bytes(16)
        padded = pkcs7_pad(plaintext, 16)
        ct = aes_cbc_encrypt(self.key, iv, padded)
        return iv + ct

    def check_padding(self, iv_plus_ct: bytes) -> bool:
        self.calls += 1
        iv = iv_plus_ct[:16]
        ct = iv_plus_ct[16:]
        pt = aes_cbc_decrypt(self.key, iv, ct)
        try:
            pkcs7_unpad(pt, 16)
            return True
        except ValueError:
            return False

    def decrypt(self, iv_plus_ct: bytes) -> bytes:
        iv = iv_plus_ct[:16]
        ct = iv_plus_ct[16:]
        return pkcs7_unpad(aes_cbc_decrypt(self.key, iv, ct), 16)


class CBCOracle:
    """CBC encrypt/decrypt with PKCS7 used by the bit-flip demo."""

    def __init__(self, key: bytes):
        self.key = key
        self.iv = secrets.token_bytes(16)

    def encrypt(self, plaintext: bytes) -> bytes:
        return aes_cbc_encrypt(self.key, self.iv, pkcs7_pad(plaintext, 16))

    def decrypt(self, ciphertext: bytes) -> bytes:
        return pkcs7_unpad(aes_cbc_decrypt(self.key, self.iv, ciphertext), 16)


class ECBOracle:
    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        return aes_ecb_encrypt(self.key, pkcs7_pad(plaintext, 16))


# ---------------------------------------------------------------------------
# Attack 1: Padding Oracle (decrypt a full message)
# ---------------------------------------------------------------------------

def padding_oracle_attack(oracle: PaddingOracle, iv_plus_ct: bytes) -> bytes:
    """Recover plaintext (minus padding) using the CBC padding oracle."""
    if len(iv_plus_ct) % 16 != 0 or iv_plus_ct == b"":
        raise ValueError("Invalid ciphertext length")
    iv = iv_plus_ct[:16]
    blocks = [iv_plus_ct[i:i + 16] for i in range(16, len(iv_plus_ct), 16)]
    plaintext = b""

    for block in blocks:
        # We recover the intermediate state I (block ^ prev = D(block))
        intermediate = bytearray(16)
        for byte_pos in range(15, -1, -1):
            pad_len = 16 - byte_pos
            prefix = bytearray(16)
            for k in range(byte_pos + 1, 16):
                prefix[k] = intermediate[k] ^ pad_len
            found = False
            for guess in range(256):
                prefix[byte_pos] = guess
                if oracle.check_padding(bytes(prefix) + block):
                    # Anti false-positive: verifier snippet for pad_len==1
                    if byte_pos == 15:
                        verify = bytearray(prefix)
                        verify[14] ^= 1
                        if not oracle.check_padding(bytes(verify) + block):
                            continue
                    intermediate[byte_pos] = guess ^ pad_len
                    found = True
                    break
            if not found:
                raise RuntimeError(f"Could not recover byte {byte_pos}")
        # plaintext block = intermediate ^ prev block (or IV for first)
        prev = iv if block is blocks[0] else blocks[blocks.index(block) - 1]
        plaintext += bytes(a ^ b for a, b in zip(intermediate, prev))

    try:
        return pkcs7_unpad(plaintext, 16)
    except ValueError:
        return plaintext


# ---------------------------------------------------------------------------
# Attack 2: CBC bit-flip
# ---------------------------------------------------------------------------

def cbc_bitflip_byte(ct: bytes, prev_block_idx: int, pos_in_block: int,
                     original_val: int, new_val: int) -> bytes:
    """Flip one plaintext byte by XORing the ciphertext byte that controls it.

    The plaintext byte `pos_in_block` of the block AFTER `prev_block_idx` is
    P = D(C) ^ C_prev, so editing C_prev[pos] by `original_val ^ new_val`
    changes exactly that plaintext byte (in-place bit-flip).
    """
    ct = bytearray(ct)
    ct[prev_block_idx * 16 + pos_in_block] ^= original_val ^ new_val
    return bytes(ct)


def demo_bitflip():
    print("\n[CBC bit-flip]  (offsets: edit preceding ct block to control plaintext byte)")
    key = secrets.token_bytes(16)
    oracle = CBCOracle(key)
    # Block 1 bytes are controlled by ciphertext block 0 (ct[0:16]).
    # Flush block 0 with padding filler, put the flippable text in block 1.
    # '0' is at full-plaintext index 16+6 -> controlled by ct[6].
    plaintext = b"\x01" * 16 + b"Admin=0;role=user"
    ct = oracle.encrypt(plaintext)
    modified = cbc_bitflip_byte(ct, prev_block_idx=0, pos_in_block=6,
                                original_val=ord('0'), new_val=ord('1'))
    dec = oracle.decrypt(modified)
    ok = dec[22] == ord('1') and dec[:22] != plaintext[:22]
    print(f"  original block1='Admin=0;role=user'")
    print(f"  modified plaintext block1='{dec[16:]}'")
    assert ok, "bitflip failed"
    return {"attack": "cbc_bitflip", "recovered": ok,
            "modified_block1": dec[16:].decode(errors='replace')}


# ---------------------------------------------------------------------------
# Attack 3: ECB detection
# ---------------------------------------------------------------------------

def detect_ecb(ciphertext: bytes, block_size: int = 16) -> bool:
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    return len(blocks) != len(set(blocks))


def ecb_detection_demo() -> dict:
    print("\n[ECB detection]  (offsets: duplicate ciphertext blocks => ECB)")
    key = secrets.token_bytes(16)
    plaintext = b"A" * 64  # 4 identical blocks after padding
    ecb_ct = ECBOracle(key).encrypt(plaintext)
    cbc_ct = CBCOracle(key).encrypt(plaintext)
    ecb_det = detect_ecb(ecb_ct)
    cbc_det = detect_ecb(cbc_ct)
    print(f"  ECB ciphertext duplicate blocks detected: {ecb_det}")
    print(f"  CBC ciphertext duplicate blocks detected: {cbc_det}")
    assert ecb_det and not cbc_det, "ECB detection failed"
    return {"attack": "ecb_detect", "recovered": True,
            "ecb_detected": ecb_det, "cbc_detected": cbc_det}


def demo_padding_oracle() -> dict:
    print("\n[Padding Oracle]  (offsets: local CBC padding oracle)")
    key = secrets.token_bytes(16)
    oracle = PaddingOracle(key)
    secret = b"Top secret lab message!"
    ct = oracle.encrypt(secret)
    print(f"  oracle queries start=0, plaintext={secret!r}")
    recovered = padding_oracle_attack(oracle, ct)
    ok = recovered == secret
    print(f"  recovered={recovered!r}  queries={oracle.calls}")
    assert ok, "padding oracle attack failed"
    return {"attack": "padding_oracle", "recovered": ok, "oracle_queries": oracle.calls}


def save_report(data, report_dir: str) -> str:
    os.makedirs(report_dir, exist_ok=True)
    fname = os.path.join(report_dir, f"c3_report_{int(time.time()*1000)}.json")
    with open(fname, "w") as fh:
        json.dump(data, fh, indent=2)
    return fname


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="aes_attacks",
        description="C3 — AES Oracle Attacks (AUTHORIZED testing only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Attacks: padding-oracle | bitflip | ecb-detect | all",
    )
    parser.add_argument("attack", choices=["padding-oracle", "bitflip", "ecb-detect", "all"])
    parser.add_argument("--report-dir", default="reports")
    args = parser.parse_args(argv)

    print("=" * 60)
    print("C3 — AES Oracle Attacks")
    print("=" * 60)
    dispatch = {
        "padding-oracle": lambda: [demo_padding_oracle()],
        "bitflip": lambda: [demo_bitflip()],
        "ecb-detect": lambda: [ecb_detection_demo()],
        "all": lambda: [demo_padding_oracle(), demo_bitflip(), ecb_detection_demo()],
    }
    results = dispatch[args.attack]()
    print("\n" + "=" * 60)
    for r in results:
        print(f"  {r['attack']}: recovered={r['recovered']}")
    print("=" * 60)
    if args.report_dir:
        print(f"[*] Report written: {save_report(results, args.report_dir)}")
    return 0 if all(r["recovered"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
