from Crypto.Cipher import DES
from binascii import unhexlify

# Key as a hexadecimal string (Note: repeated twice for 8 bytes)
key_hex = "A1B2C3D4A1B2C3D4"

# Convert the hexadecimal key to bytes
key = unhexlify(key_hex)

def encrypt(msg):
    """
    Encrypts the provided message using DES with EAX mode.

    Args:
        msg (str): The message to encrypt (should be ASCII encoded).

    Returns:
        tuple: A tuple containing the nonce, ciphertext, and authentication tag.
    """

    # Create a new DES cipher object in EAX mode
    cipher = DES.new(key, DES.MODE_EAX)

    # Generate a random nonce for authentication
    nonce = cipher.nonce

    # Encrypt the message (assumed to be ASCII encoded) and generate an authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))

    # Return the nonce, ciphertext, and tag for decryption
    return nonce, ciphertext, tag

def decrypt(nonce, ciphertext, tag):
    """
    Decrypts the provided ciphertext using DES with EAX mode.

    Args:
        nonce (bytes): The nonce used for encryption.
        ciphertext (bytes): The encrypted message.
        tag (bytes): The authentication tag generated during encryption.

    Returns:
        str or bool: The decrypted plaintext (if successful) or False (if message is corrupted).
    """

    # Create a new DES cipher object in EAX mode and provide the nonce
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)

    # Try to decrypt the ciphertext
    try:
        plaintext = cipher.decrypt(ciphertext)

        # Verify the authentication tag to ensure message integrity
        cipher.verify(tag)

        # Decode the decrypted bytes back to ASCII string
        return plaintext.decode('ascii')

    except ValueError:  # Handle potential decryption errors
        # Message is likely corrupted
        return False

# Encrypt the message "Confidential Data"
nonce, ciphertext, tag = encrypt("Confidential Data")
print(f'Ciphertext: {ciphertext.hex()}')  # Print ciphertext in hex format

# Decrypt the ciphertext to verify the original message
plaintext = decrypt(nonce, ciphertext, tag)
if not plaintext:
    print('Message is corrupted')
else:
    print(f'Plaintext: {plaintext}')