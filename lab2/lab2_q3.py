from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify
import time


# Define the message
message = "Performance Testing of Encryption Algorithms"

# DES key (8 bytes / 16 hex characters)
des_key = b"12345678"

# AES-256 key (32 bytes / 64 hex characters)
aes_key_hex = "0123456789ABCDEF0123456789ABCDEF"
aes_key = unhexlify(aes_key_hex)

# Block size for AES and DES (obtained from respective classes)
aes_block_size = AES.block_size
des_block_size = DES.block_size


def measure_performance(cipher_type, message, key):
    """
    Measures encryption and decryption performance for a given cipher.

    Args:
        cipher_type (str): The type of cipher (e.g., "DES", "AES").
        message (str): The message to be encrypted.
        key (bytes): The key to be used for encryption/decryption.

    Returns:
        tuple: A tuple containing encryption time (ms), decryption time (ms),
               and the decrypted plaintext.
    """

    # Create a cipher object in CBC mode with the provided key
    cipher = getattr(Crypto.Cipher, cipher_type).new(key, DES.MODE_CBC)

    # Pad the message to a multiple of the block size
    padded_msg = pad(message.encode('utf-8'), cipher.block_size)

    # Start a timer for encryption
    start_time = time.perf_counter()

    # Encrypt the padded message
    ciphertext = cipher.encrypt(padded_msg)
    iv = cipher.iv  # Retrieve the initialization vector used

    # Stop the timer and calculate encryption time in milliseconds
    encryption_time_s = time.perf_counter() - start_time
    encryption_time_ms = encryption_time_s * 1000

    # Start a timer for decryption
    start_time = time.perf_counter()

    # Decrypt the ciphertext
    padded_plaintext = cipher.decrypt(ciphertext)

    # Remove padding and decode the decrypted message
    plaintext = unpad(padded_plaintext, cipher.block_size).decode('utf-8')

    # Stop the timer and calculate decryption time in milliseconds
    decryption_time_s = time.perf_counter() - start_time
    decryption_time_ms = decryption_time_s * 1000

    return encryption_time_ms, decryption_time_ms, plaintext


# Measure DES performance
des_enc_time_ms, des_dec_time_ms, des_plaintext = measure_performance("DES", message, des_key)
print(f"DES Encryption Time: {des_enc_time_ms:.6f} milliseconds")
print(f"DES Decryption Time: {des_dec_time_ms:.6f} milliseconds")
print(f"DES Plaintext: {des_plaintext}")

# Measure AES-256 performance
aes_enc_time_ms, aes_dec_time_ms, aes_plaintext = measure_performance("AES", message, aes_key)
print(f"AES-256 Encryption Time: {aes_enc_time_ms:.6f} milliseconds")
print(f"AES-256 Decryption Time: {aes_dec_time_ms:.6f} milliseconds")
print(f"AES-256 Plaintext: {aes_plaintext}")