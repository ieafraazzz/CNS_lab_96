# ============================================================
# EXPERIMENT 1
# AES SECURITY ANALYSIS USING ECB AND CBC MODES
# ============================================================

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# ------------------------------------------------------------
# AES-ECB ENCRYPTION
# ------------------------------------------------------------

def aes_ecb_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return ciphertext


# ------------------------------------------------------------
# AES-ECB DECRYPTION
# ------------------------------------------------------------

def aes_ecb_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted, AES.block_size)
    return plaintext.decode()


# ------------------------------------------------------------
# AES-CBC ENCRYPTION
# ------------------------------------------------------------

def aes_cbc_encrypt(plaintext, key):
    # Generate a random 16-byte Initialization Vector
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return iv, ciphertext


# ------------------------------------------------------------
# AES-CBC DECRYPTION
# ------------------------------------------------------------

def aes_cbc_decrypt(iv, ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted, AES.block_size)
    return plaintext.decode()


# ------------------------------------------------------------
# DISPLAY CIPHERTEXT BLOCKS
# ------------------------------------------------------------

def display_blocks(ciphertext):
    blocks = []
    for i in range(0, len(ciphertext), AES.block_size):
        block = ciphertext[i:i + AES.block_size]
        blocks.append(block)
        print(f"Block {i // AES.block_size + 1}: {block.hex()}")
    return blocks


# ============================================================
# MAIN PROGRAM
# ============================================================

if __name__ == "__main__":
    print("=" * 70)
    print("      AES SECURITY ANALYSIS: ECB vs CBC")
    print("=" * 70)

    # AES-128 key (16 bytes)
    key = b"0123456789ABCDEF"

    # Repeated plaintext is deliberately used to demonstrate
    # the pattern leakage problem of ECB.
    plaintext = (
        "TEMP=30C;TEMP=30C;TEMP=30C;"
        "TEMP=30C;TEMP=30C;TEMP=30C;"
    )

    print("\nOriginal Plaintext:")
    print(plaintext)

    # ============================================================
    # AES-ECB
    # ============================================================
    print("\n" + "-" * 70)
    print("AES-ECB ENCRYPTION")
    print("-" * 70)

    ecb_ciphertext = aes_ecb_encrypt(plaintext, key)
    print("\nECB Ciphertext:")
    print(ecb_ciphertext.hex())

    ecb_decrypted = aes_ecb_decrypt(ecb_ciphertext, key)
    print("\nECB Decrypted Plaintext:")
    print(ecb_decrypted)

    print("\nECB Ciphertext Blocks:")
    ecb_blocks = display_blocks(ecb_ciphertext)

    print("\nTotal ECB Blocks:", len(ecb_blocks))
    print("Unique ECB Blocks:", len(set(ecb_blocks)))

    # ============================================================
    # AES-CBC
    # ============================================================
    print("\n" + "-" * 70)
    print("AES-CBC ENCRYPTION")
    print("-" * 70)

    cbc_iv, cbc_ciphertext = aes_cbc_encrypt(plaintext, key)
    print("\nCBC Initialization Vector (IV):")
    print(cbc_iv.hex())

    print("\nCBC Ciphertext:")
    print(cbc_ciphertext.hex())

    cbc_decrypted = aes_cbc_decrypt(cbc_iv, cbc_ciphertext, key)
    print("\nCBC Decrypted Plaintext:")
    print(cbc_decrypted)

    print("\nCBC Ciphertext Blocks:")
    cbc_blocks = display_blocks(cbc_ciphertext)

    print("\nTotal CBC Blocks:", len(cbc_blocks))
    print("Unique CBC Blocks:", len(set(cbc_blocks)))

    # ============================================================
    # SECURITY ANALYSIS
    # ============================================================
    print("\n" + "=" * 70)
    print("SECURITY ANALYSIS")
    print("=" * 70)

    if len(set(ecb_blocks)) < len(ecb_blocks):
        print("\nECB Observation:")
        print("Repeated ciphertext blocks are present.")
        print("This can reveal patterns in the plaintext.")
    else:
        print("\nECB Observation:")
        print("No repeated ciphertext blocks were observed.")

    if len(set(cbc_blocks)) == len(cbc_blocks):
        print("\nCBC Observation:")
        print("Ciphertext blocks are different.")
        print("The repeated plaintext pattern is hidden.")
    else:
        print("\nCBC Observation:")
        print("Repeated ciphertext blocks were observed.")

    # ============================================================
    # VERIFICATION
    # ============================================================
    print("\n" + "=" * 70)
    print("DECRYPTION VERIFICATION")
    print("=" * 70)

    if ecb_decrypted == plaintext:
        print("ECB: Decryption successful.")
    else:
        print("ECB: Decryption failed.")

    if cbc_decrypted == plaintext:
        print("CBC: Decryption successful.")
    else:
        print("CBC: Decryption failed.")

    # ============================================================
    # CONCLUSION
    # ============================================================
    print("\n" + "=" * 70)
    print("CONCLUSION")
    print("=" * 70)

    print("""
AES successfully encrypted and decrypted the given plaintext.

ECB mode can reveal patterns because identical plaintext
blocks are encrypted independently.

CBC mode uses an Initialization Vector (IV) and chaining,
which prevents the same plaintext pattern from directly
producing the same ciphertext pattern.

Therefore, the experiment demonstrates that the choice of
block cipher mode is an important part of cryptographic
system design.
""")
