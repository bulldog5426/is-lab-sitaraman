from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify

# Key as a hexadecimal string (16 bytes / 32 hex characters)
key_hex = "0123456789ABCDEF0123456789ABCDEF"

# Convert the hexadecimal key to bytes
key = unhexlify(key_hex)

# Define the AES block size (16 bytes)
block_size = AES.block_size  # Access block size from imported AES class

def encrypt(msg):
    """
    Encrypts the provided message using AES in CBC mode.

    Args:
        msg (str): The message to encrypt (assumed to be UTF-8 encoded).

    Returns:
        tuple: A tuple containing the initialization vector (IV) and ciphertext.
    """

    # Create a new AES cipher object in CBC mode
    cipher = AES.new(key, AES.MODE_CBC)

    # Pad the message to a multiple of the AES block size (16 bytes)
    padded_msg = pad(msg.encode('utf-8'), block_size)
    # Padding adds extra bytes to ensure the message length is a multiple of block size

    # Encrypt the padded message
    ciphertext = cipher.encrypt(padded_msg)

    # Retrieve the initialization vector (IV) used for encryption
    iv = cipher.iv

    # Return the IV and ciphertext for decryption
    return iv, ciphertext

def decrypt(iv, ciphertext):
    """
    Decrypts the provided ciphertext using AES in CBC mode.

    Args:
        iv (bytes): The initialization vector used for encryption.
        ciphertext (bytes): The encrypted message.

    Returns:
        str or bool: The decrypted plaintext (if successful) or False (if message is corrupted).
    """

    # Create a new AES cipher object in CBC mode with the provided IV
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    # Decrypt the ciphertext
    padded_plaintext = cipher.decrypt(ciphertext)

    try:
        # Remove padding from the decrypted message
        plaintext = unpad(padded_plaintext, block_size).decode('utf-8')

        # Return the decrypted plaintext
        return plaintext

    except ValueError:  # Handle potential decryption errors
        # Message is likely corrupted (decryption failed or invalid padding)
        return False

# Encrypt the message "Sensitive Information"
iv, ciphertext = encrypt("Sensitive Information")
print(f'Ciphertext (hex): {ciphertext.hex()}')  # Print ciphertext in hex format

# Decrypt the ciphertext to verify the original message
plaintext = decrypt(iv, ciphertext)
if not plaintext:
    print('Message is corrupted')
else:
    print(f'Plaintext: {plaintext}')