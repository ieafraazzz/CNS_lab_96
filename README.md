# AES ECB vs CBC — Security Analysis & Classical Cryptography Lab

Cryptography & Network Security (CNS) lab experiments implementing and analyzing
classical ciphers, modular arithmetic foundations, and AES block cipher modes in Python.

**Course:** Cryptography & Network Security
**Institute:** SIES Graduate School of Technology, Dept. of Computer Engineering

## Overview

This repo contains two experiments:

### 1. `experiment1_AES.py` — AES ECB vs CBC Security Analysis
Implements AES-128 encryption/decryption in **ECB** and **CBC** modes on a
plaintext with repeated blocks (`TEMP=30C;` x6), then analyzes ciphertext block
patterns to demonstrate:
- ECB's plaintext pattern leakage (identical plaintext blocks → identical ciphertext blocks)
- CBC's chaining + IV eliminating that leakage
- Correct round-trip decryption in both modes

### 2. `experiment2_cryptography.py` — Classical Cryptography, Modular Arithmetic & AES
A broader cryptographic toolkit covering:
- Caesar Cipher
- Euclidean Algorithm (GCD) & Extended Euclidean Algorithm (Modular Inverse)
- Affine Cipher
- Vigenère Cipher
- Congruence relations
- Fermat's Little Theorem
- Chinese Remainder Theorem (CRT)
- AES-CBC (modern symmetric encryption)

Each technique is implemented, run, and verified against the original plaintext.

## Requirements

- Python 3.x
- [PyCryptodome](https://pypi.org/project/pycryptodome/)

## Setup

```bash
git clone https://github.com/ieafraazzz/<repo-name>.git
cd <repo-name>
pip install -r requirements.txt
```

## Usage

```bash
python experiment1_AES.py
python experiment2_cryptography.py
```

## Sample Output (Experiment 1)

```
ECB Ciphertext Blocks:
Block 1: c33ddfbac0bbe30bcb1975923c0b8954
Block 2: 2c93034fb7bb0f1d901192127466987e
Block 3: f103aca876ca826ce5258e01e9bcd1a7
Block 4: 42efd404d4ce65447225b737b4e2d7e2

Total ECB Blocks: 4
Unique ECB Blocks: 4
```

> Note: in this particular plaintext the 16-byte block boundaries don't align
> exactly with the repeated `TEMP=30C;` substring, so no identical blocks
> appear — but ECB's block-independence is still demonstrable by aligning
> plaintext to the block size (see Conclusion in script output for discussion).

## Key Concepts Demonstrated

| Concept | Where |
|---|---|
| Block cipher modes (ECB vs CBC) | `experiment1_AES.py` |
| Initialization Vector (IV) & chaining | `experiment1_AES.py`, `experiment2_cryptography.py` |
| PKCS#7 padding | Both scripts |
| Modular inverse & gcd conditions | `experiment2_cryptography.py` |
| Poly-alphabetic substitution | `experiment2_cryptography.py` (Vigenère) |
| Number-theoretic proofs (Fermat, CRT) | `experiment2_cryptography.py` |

## License

MIT — see [LICENSE](LICENSE).

## Author

**Afraaz Shaikh**
[GitHub](https://github.com/ieafraazzz) · [LinkedIn](https://linkedin.com/in/afraaz-shaikh-4b268226b/)
