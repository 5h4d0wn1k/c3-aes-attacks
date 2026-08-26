# C3 — AES Implementation + Attacks

A comprehensive toolkit for demonstrating AES vulnerabilities and attack vectors in various modes of operation.

## Overview

This project implements various AES attacks to demonstrate cryptographic weaknesses when AES is improperly implemented or when vulnerable modes of operation are used.

## Features

- **Padding Oracle Attack**: Decrypts AES-CBC ciphertext without the key
- **CBC Bitflip Attack**: Modifies ciphertext to manipulate plaintext
- **ECB Detection**: Identifies if AES-ECB mode is being used
- **Mode Analysis**: Detects and analyzes block cipher modes

## Installation

```bash
pip install pycryptodome
```

## Usage

```bash
# Padding oracle attack demonstration
python3 aes_attacks.py padding-oracle --bits 128

# CBC bitflip attack
python3 aes_attacks.py bitflip --bits 128

# ECB detection
python3 aes_attacks.py ecb-detect

# Mode analysis
python3 aes_attacks.py mode-analysis --bits 128

# Run all demonstrations
python3 aes_attacks.py all
```

## Attack Descriptions

### Padding Oracle Attack
Exploits CBC mode padding to decrypt ciphertext without the key. By sending modified ciphertext to an oracle that reveals padding validity, each byte of plaintext can be recovered.

### CBC Bitflip Attack
Manipulates ciphertext bytes to produce predictable changes in plaintext. Flipping a ciphertext byte flips the corresponding plaintext byte in the next block.

### ECB Detection
Detects when AES-ECB mode is used by encrypting identical blocks and checking for identical ciphertext blocks. ECB is deterministic and leaks patterns.

### Mode Analysis
Analyzes encrypted data to determine which block cipher mode was used (ECB, CBC, CTR, etc.) based on statistical properties.

## Example Output

```
=== C3 — AES Implementation + Attacks ===

[Padding Oracle Attack]
Target ciphertext: 4f8392a...
Recovered plaintext: b'Secret message!'
Bytes recovered: 16/16
Attack SUCCESSFUL!

[CBC Bitflip Attack]
Original plaintext: b'Admin=0;role=user'
Modified plaintext: b'Admin=1;role=admin'
Attack SUCCESSFUL!

[ECB Detection]
Blocks analyzed: 100
Identical blocks found: 15
ECB mode detected: YES
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the system owner before using this tool
- Cryptanalysis of systems you do not own or have authorization to test is illegal
- This tool should ONLY be used on systems you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Digital Millennium Copyright Act (DMCA)**: Circumvention of technological protection measures may be illegal
- **State Laws**: Many states have additional computer crime statutes
- **Export Controls**: Cryptographic tools may be subject to export regulations

### Acceptable Use
- Testing security of your own cryptographic implementations
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training
- CTF competitions and challenges

### Prohibited Use
- Attacking systems you do not own or have authorization to test
- Breaking encryption for unauthorized access
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
