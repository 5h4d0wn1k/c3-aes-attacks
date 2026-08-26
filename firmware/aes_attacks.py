#!/usr/bin/env python3
"""
C3 — AES Implementation + Attacks
Educational AES attack demonstrations for authorized security testing only.
"""

import argparse
import os
import secrets
import struct
import sys
from typing import Tuple, Optional, List
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad, PaddingError

# === AES Oracles for Attack Demonstrations ===

class PaddingOracle:
    """Simulates a padding oracle for CBC decryption attacks."""
    
    def __init__(self, key: bytes):
        self.key = key
        self.cipher = AES.new(key, AES.MODE_ECB)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt with random IV."""
        iv = os.urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, 16))
        return iv + ciphertext
    
    def check_padding(self, ciphertext: bytes) -> bool:
        """Check if padding is valid (the oracle)."""
        try:
            iv = ciphertext[:16]
            ct = ciphertext[16:]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ct)
            unpad(plaintext, 16)
            return True
        except PaddingError:
            return False
        except Exception:
            return False

class ECBOracle:
    """Simulates ECB mode for detection."""
    
    def __init__(self, key: bytes):
        self.key = key
    
    def encrypt(self, plaintext: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(pad(plaintext, 16))

class CBCOracle:
    """Simulates CBC mode for detection."""
    
    def __init__(self, key: bytes):
        self.key = key
    
    def encrypt(self, plaintext: bytes) -> bytes:
        iv = os.urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(pad(plaintext, 16))


# === Padding Oracle Attack ===

def padding_oracle_attack(oracle: PaddingOracle, ciphertext: bytes) -> bytes:
    """
    Perform padding oracle attack to decrypt ciphertext.
    Works byte by byte from the end of the message.
    """
    if len(ciphertext) % 16 != 0 or len(ciphertext) < 32:
        raise ValueError("Invalid ciphertext length")
    
    iv = ciphertext[:16]
    ct_blocks = [ciphertext[i:i+16] for i in range(16, len(ciphertext), 16)]
    
    plaintext = b""
    
    for block_idx in range(len(ct_blocks)):
        decrypted_block = bytearray(16)
        target_ct = ct_blocks[block_idx]
        
        for byte_idx in range(15, -1, -1):
            pad_value = 16 - byte_idx
            prefix = bytearray(16)
            
            # Set known bytes to produce correct padding
            for k in range(byte_idx + 1, 16):
                prefix[k] = decrypted_block[k] ^ pad_value
            
            found = False
            for guess in range(256):
                prefix[byte_idx] = guess
                test_ct = bytes(prefix) + target_ct
                
                if oracle.check_padding(test_ct):
                    # Verify it's not a false positive
                    if byte_idx == 15:
                        # Check if changing previous byte still works
                        verify = bytearray(prefix)
                        verify[byte_idx - 1] ^= 1
                        if not oracle.check_padding(bytes(verify) + target_ct):
                            continue
                    
                    decrypted_block[byte_idx] = guess ^ pad_value
                    found = True
                    break
            
            if not found:
                raise RuntimeError(f"Could not decrypt byte {byte_idx}")
        
        plaintext += bytes(decrypted_block)
    
    try:
        return unpad(plaintext, 16)
    except PaddingError:
        return plaintext

def demo_padding_oracle(bits: int = 128):
    """Demonstrate padding oracle attack."""
    print("\n[Padding Oracle Attack]")
    
    key = secrets.token_bytes(bits // 8)
    oracle = PaddingOracle(key)
    
    secret_message = b"Secret message!"
    print(f"Original plaintext: {secret_message}")
    
    ciphertext = oracle.encrypt(secret_message)
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    
    print("Attacking with padding oracle...")
    recovered = padding_oracle_attack(oracle, ciphertext)
    
    print(f"Recovered plaintext: {recovered}")
    if recovered == secret_message:
        print("Attack SUCCESSFUL!")
    else:
        print("Attack failed")


# === CBC Bitflip Attack ===

def cbc_bitflip_attack(ciphertext: bytes, target_changes: dict, block_size: int = 16) -> bytes:
    """
    Modify CBC ciphertext to change specific bytes in plaintext.
    
    target_changes: dict mapping (block_index, byte_position) to new_value
    """
    ct_list = bytearray(ciphertext)
    
    for (block_idx, byte_pos), new_value in target_changes.items():
        if block_idx == 0:
            # Modify IV
            ct_list[byte_pos] ^= new_value
        else:
            # Modify previous ciphertext block
            prev_block_start = (block_idx - 1) * block_size
            ct_list[prev_block_start + byte_pos] ^= new_value
    
    return bytes(ct_list)

def demo_bitflip(bits: int = 128):
    """Demonstrate CBC bitflip attack."""
    print("\n[CBC Bitflip Attack]")
    
    key = secrets.token_bytes(bits // 8)
    iv = os.urandom(16)
    
    # Original plaintext with role
    original = b"Admin=0;role=user"
    padded = pad(original, 16)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = iv + cipher.encrypt(padded)
    
    print(f"Original plaintext: {original}")
    print(f"Target: Admin=1;role=admin")
    
    # To change '0' at position 6 to '1', we need to flip the bit
    # in the IV (first block)
    changes = {
        (0, 6): ord('0') ^ ord('1')  # Flip '0' to '1'
    }
    
    modified = cbc_bitflip_attack(ciphertext, changes)
    
    # Decrypt to verify
    mod_iv = modified[:16]
    mod_ct = modified[16:]
    cipher = AES.new(key, AES.MODE_CBC, mod_iv)
    decrypted = unpad(cipher.decrypt(mod_ct), 16)
    
    print(f"Modified plaintext: {decrypted}")
    if b"Admin=1" in decrypted:
        print("Attack SUCCESSFUL!")
    else:
        print("Attack failed")


# === ECB Detection ===

def detect_ecb(ciphertext: bytes, block_size: int = 16) -> Tuple[bool, float]:
    """
    Detect if ECB mode is used by checking for duplicate blocks.
    Returns (is_ecb, duplicate_ratio).
    """
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    unique_blocks = set(blocks)
    
    if len(blocks) == 0:
        return False, 0.0
    
    duplicate_ratio = 1.0 - (len(unique_blocks) / len(blocks))
    
    # ECB mode produces identical blocks for identical plaintext
    return duplicate_ratio > 0.1, duplicate_ratio

def demo_ecb_detect():
    """Demonstrate ECB detection."""
    print("\n[ECB Detection]")
    
    key = secrets.token_bytes(16)
    
    # Create plaintext with repeated blocks
    block = b"YELLOW SUBMARINE"
    plaintext = block * 10  # 10 identical blocks
    
    # Test ECB
    ecb_cipher = AES.new(key, AES.MODE_ECB)
    ecb_ct = ecb_cipher.encrypt(pad(plaintext, 16))
    
    # Test CBC
    iv = os.urandom(16)
    cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
    cbc_ct = iv + cbc_cipher.encrypt(pad(plaintext, 16))
    
    print(f"Plaintext: {len(plaintext)} bytes ({len(plaintext)//16} blocks)")
    
    ecb_detected, ecb_ratio = detect_ecb(ecb_ct)
    print(f"ECB ciphertext: Detected={ecb_detected}, Duplicate ratio={ecb_ratio:.2%}")
    
    cbc_detected, cbc_ratio = detect_ecb(cbc_ct)
    print(f"CBC ciphertext: Detected={cbc_detected}, Duplicate ratio={cbc_ratio:.2%}")
    
    if ecb_detected and not cbc_detected:
        print("Detection SUCCESSFUL!")
    else:
        print("Detection failed")


# === Mode Analysis ===

def analyze_mode(ciphertext: bytes, block_size: int = 16) -> dict:
    """
    Analyze ciphertext to determine likely block cipher mode.
    """
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    unique_blocks = set(blocks)
    
    # Calculate entropy
    block_freq = {}
    for block in blocks:
        block_freq[block] = block_freq.get(block, 0) + 1
    
    import math
    entropy = 0
    total = len(blocks)
    for count in block_freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    
    max_entropy = math.log2(len(unique_blocks)) if unique_blocks else 0
    
    analysis = {
        "total_blocks": len(blocks),
        "unique_blocks": len(unique_blocks),
        "duplicate_ratio": 1.0 - (len(unique_blocks) / len(blocks)) if blocks else 0,
        "entropy": entropy,
        "max_entropy": max_entropy,
        "entropy_ratio": entropy / max_entropy if max_entropy > 0 else 0,
    }
    
    # Mode detection heuristics
    if analysis["duplicate_ratio"] > 0.3:
        analysis["likely_mode"] = "ECB"
        analysis["confidence"] = "High"
    elif analysis["duplicate_ratio"] < 0.05 and analysis["entropy_ratio"] > 0.9:
        analysis["likely_mode"] = "CTR/GCM"
        analysis["confidence"] = "Medium"
    else:
        analysis["likely_mode"] = "CBC"
        analysis["confidence"] = "Medium"
    
    return analysis

def demo_mode_analysis(bits: int = 128):
    """Demonstrate mode analysis."""
    print("\n[Mode Analysis]")
    
    key = secrets.token_bytes(bits // 8)
    plaintext = b"Test message for mode analysis!" * 10
    
    # Encrypt with different modes
    modes = {
        "ECB": AES.new(key, AES.MODE_ECB).encrypt(pad(plaintext, 16)),
        "CBC": os.urandom(16) + AES.new(key, AES.MODE_CBC, os.urandom(16)).encrypt(pad(plaintext, 16)),
        "CTR": AES.new(key, AES.MODE_CTR, nonce=os.urandom(8)).encrypt(plaintext),
    }
    
    for mode_name, ct in modes.items():
        print(f"\n--- {mode_name} Mode ---")
        analysis = analyze_mode(ct)
        print(f"Blocks: {analysis['total_blocks']}")
        print(f"Unique: {analysis['unique_blocks']}")
        print(f"Duplicate ratio: {analysis['duplicate_ratio']:.2%}")
        print(f"Entropy ratio: {analysis['entropy_ratio']:.2%}")
        print(f"Detected: {analysis['likely_mode']} (confidence: {analysis['confidence']})")


# === Main CLI ===

def main():
    parser = argparse.ArgumentParser(
        description="C3 — AES Implementation + Attacks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attacks:
  padding-oracle  Padding oracle attack on CBC mode
  bitflip         CBC bitflip attack
  ecb-detect      Detect ECB mode usage
  mode-analysis   Analyze ciphertext mode
  all             Run all demonstrations
        """
    )
    
    parser.add_argument("attack",
                       choices=["padding-oracle", "bitflip", "ecb-detect", "mode-analysis", "all"],
                       help="Attack to demonstrate")
    
    parser.add_argument("--bits", type=int, default=128,
                       help="AES key size in bits (default: 128)")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("C3 — AES Implementation + Attacks")
    print("=" * 60)
    
    if args.attack == "padding-oracle":
        demo_padding_oracle(args.bits)
    elif args.attack == "bitflip":
        demo_bitflip(args.bits)
    elif args.attack == "ecb-detect":
        demo_ecb_detect()
    elif args.attack == "mode-analysis":
        demo_mode_analysis(args.bits)
    elif args.attack == "all":
        demo_padding_oracle(args.bits)
        demo_bitflip(args.bits)
        demo_ecb_detect()
        demo_mode_analysis(args.bits)
    
    print("\n" + "=" * 60)
    print("Demonstration complete!")
    print("=" * 60)

if __name__ == "__main__":
    main()
