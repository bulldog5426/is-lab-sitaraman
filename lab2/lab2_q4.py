from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import binascii

# Key as a hexadecimal string (24 bytes / 48 hex characters)
key_hex = "1234567890ABCDEFAAFFFFFFFFFFFFFF1234567890ABCDEF"
key = binascii.unhexlify(key_hex)

# Define the message
message = "Classified Text"

def encrypt(msg):
    """
    Encrypts the provided message using DES3 in CBC mode.

    Args:
        msg (str): The message to encrypt (assumed to be UTF-8 encoded).

    Returns:
        tuple: A tuple containing the initialization vector (IV) and ciphertext.
    """

    # Create a new DES3 cipher object in CBC mode
    cipher = DES3.new(key, DES3.MODE_CBC)

    # Pad the message to a multiple of the DES3 block size (8 bytes)
    padded_msg = pad(msg.encode('utf-8'), DES3.block_size)

    # Encrypt the padded message
    ciphertext = cipher.encrypt(padded_msg)

    # Retrieve the initialization vector (IV) used for encryption
    iv = cipher.iv

    # Return the IV and ciphertext for decryption
    return iv, ciphertext

def decrypt(iv, ciphertext):
    """
    Decrypts the provided ciphertext using DES3 in CBC mode.

    Args:
        iv (bytes): The initialization vector used for encryption.
        ciphertext (bytes): The encrypted message.

    Returns:
        str or bool: The decrypted plaintext (if successful) or False (if message is corrupted).
    """

    # Create a new DES3 cipher object in CBC mode with the provided IV
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)

    # Decrypt the ciphertext
    padded_plaintext = cipher.decrypt(ciphertext)

    try:
        # Remove padding from the decrypted message
        plaintext = unpad(padded_plaintext, DES3.block_size).decode('utf-8')

        # Return the decrypted plaintext
        return plaintext

    except ValueError:  # Handle potential decryption errors
        # Message is likely corrupted (decryption failed or invalid padding)
        return False

# Encrypt the message
iv, ciphertext = encrypt(message)
print(f'Ciphertext (hex): {ciphertext.hex()}')

# Decrypt the ciphertext to verify the original message
plaintext = decrypt(iv, ciphertext)
if not plaintext:
    print('Message is corrupted')
else:
    print(f'Plaintext: {plaintext}')