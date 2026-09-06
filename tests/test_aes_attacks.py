#!/usr/bin/env python3
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from firmware import aes_attacks as aes


class TestPureAES(unittest.TestCase):
    """Pure-python AES must be byte-for-byte correct (matched vs pycryptodome)."""

    def test_fips197_aes128_kat(self):
        # FIPS-197 Appendix C.1: key=000102..0f, pt=001122..ff -> ct=69c4..
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(aes.aes_ecb_encrypt(key, pt), expected)
        self.assertEqual(aes.aes_ecb_decrypt(key, expected), pt)

    def test_roundtrip_all_keys(self):
        for klen in (16, 24, 32):
            key = bytes((i * 3) % 256 for i in range(klen))
            for msg in (b"", b"a", b"x" * 31, b"y" * 33):
                p = aes.pkcs7_pad(msg)
                iv = b"\x00" * 16
                ct = aes.aes_cbc_encrypt(key, iv, p)
                self.assertEqual(aes.aes_cbc_decrypt(key, iv, ct), p)

    def test_matches_pycryptodome_if_present(self):
        if not aes._HAS_PYCRYPTODOME:
            self.skipTest("pycryptodome not present")
        from Crypto.Cipher import AES as PA
        for klen in (16, 24, 32):
            key = bytes((i * 7) % 256 for i in range(klen))
            p = aes.pkcs7_pad(b"pure-vs-crypto-demo")
            self.assertEqual(aes.aes_ecb_encrypt(key, p),
                             PA.new(key, PA.MODE_ECB).encrypt(p))
            iv = b"\x00" * 16
            self.assertEqual(aes.aes_cbc_encrypt(key, iv, p),
                             PA.new(key, PA.MODE_CBC, iv).encrypt(p))


class TestPKCS7(unittest.TestCase):
    def test_pad_unpad(self):
        for n in range(0, 40):
            data = b"z" * n
            self.assertEqual(aes.pkcs7_unpad(aes.pkcs7_pad(data), 16), data)

    def test_invalid_padding(self):
        with self.assertRaises(ValueError):
            aes.pkcs7_unpad(b"\x00" * 15 + b"\x09", 16)


class TestPaddingOracle(unittest.TestCase):
    def _attack(self, secret):
        key = bytes(range(16))
        oracle = aes.PaddingOracle(key)
        ct = oracle.encrypt(secret)
        recovered = aes.padding_oracle_attack(oracle, ct)
        return recovered, oracle

    def test_short(self):
        secret = b"hello"
        recovered, oracle = self._attack(secret)
        self.assertEqual(recovered, secret)
        self.assertLess(oracle.calls, 4096)

    def test_ipad_one_block(self):
        secret = b"x" * 24
        recovered, oracle = self._attack(secret)
        self.assertEqual(recovered, secret)

    def test_multiple_blocks(self):
        secret = b"Top secret lab message! multi block"
        recovered, oracle = self._attack(secret)
        self.assertEqual(recovered, secret)


class TestBitflip(unittest.TestCase):
    def test_bitflip_byte(self):
        key = bytes(range(16))
        oracle = aes.CBCOracle(key)
        plaintext = b"\x01" * 16 + b"Admin=0;role=user"
        ct = oracle.encrypt(plaintext)
        modified = aes.cbc_bitflip_byte(ct, 0, 6, ord('0'), ord('1'))
        dec = oracle.decrypt(modified)
        self.assertEqual(dec[22], ord('1'))
        # other bytes in block1 unaffected
        self.assertEqual(dec[16:22], b"Admin=")
        self.assertEqual(dec[23:], b";role=user")


class TestECBDetect(unittest.TestCase):
    def test_detect_ecb(self):
        key = bytes(range(16))
        pt = b"A" * 64
        ecb_ct = aes.ECBOracle(key).encrypt(pt)
        cbc_ct = aes.CBCOracle(key).encrypt(pt)
        self.assertTrue(aes.detect_ecb(ecb_ct))
        self.assertFalse(aes.detect_ecb(cbc_ct))


class TestCLI(unittest.TestCase):
    def test_help(self):
        old = sys.argv
        sys.argv = ["aes_attacks", "--help"]
        try:
            with self.assertRaises(SystemExit):
                aes.main()
        finally:
            sys.argv = old

    def test_all_exit_zero(self):
        self.assertEqual(aes.main(["all"]), 0)


if __name__ == "__main__":
    unittest.main()
