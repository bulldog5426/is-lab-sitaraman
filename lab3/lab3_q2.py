from Crypto.PublicKey import ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from binascii import hexlify, unhexlify


# Generate ECC key pair (private and public keys)
private_key = ECC.generate(curve="P-256")
public_key = private_key.public_key()

# Message to encrypt (convert to bytes)
message = "Secure Transactions".encode()


# Function to encrypt a message using ECC (hybrid approach with AES)
def ecc_encrypt(message, public_key):
    """Encrypts a message using a combination of ECC and AES.

    1. Generates a random 16-byte AES session key for data encryption.
    2. Encrypts the session key using RSA-OAEP with the public key
       (ECC doesn't directly encrypt data but ensures secure key exchange).
    3. Encrypts the message content with AES in EAX mode (authenticated encryption).

    Args:
        message (bytes): The message to encrypt.
        public_key (ECC.EccKey): The public key of the recipient.

    Returns:
        str: The encrypted message in hexadecimal string format.
    """

    session_key = get_random_bytes(16)  # Generate random AES key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)  # Create AES cipher object

    # Encrypt message with AES and get authentication tag
    ciphertext, tag = cipher_aes.encrypt_and_digest(pad(message, AES.block_size))

    # Encrypt the session key using PKCS1_OAEP with the public key
    encrypted_session_key = PKCS1_OAEP.new(public_key).encrypt(session_key)

    # Combine encrypted session key, nonce, tag, and ciphertext for transmission
    combined_data = (
        encrypted_session_key
        + cipher_aes.nonce  # Include the nonce for decryption
        + tag
        + ciphertext
    )

    # Return the combined data in hexadecimal string format
    return hexlify(combined_data).decode()


# Function to decrypt a message using ECC (private key)
def ecc_decrypt(ciphertext, private_key):
    """Decrypts a message encrypted using the ECC public key.

    1. Extracts encrypted session key, nonce, tag, and ciphertext from the combined data.
    2. Decrypts the session key using PKCS1_OAEP with the private key.
    3. Decrypts the message content with AES in EAX mode using the recovered session key
       and verifies the authentication tag for integrity check.

    Args:
        ciphertext (str): The encrypted message in hexadecimal string format.
        private_key (ECC.EccKey): The private key of the recipient.

    Returns:
        str: The decrypted message.
    """

    data = unhexlify(ciphertext)  # Convert ciphertext from string to bytes

    # Extract encrypted session key, nonce, tag, and ciphertext
    (
        encrypted_session_key,
        nonce,
        tag,
        ciphertext,
    ) = data[:32], data[32:48], data[48:64], data[64:]

    # Decrypt the session key using PKCS1_OAEP with the private key
    session_key = PKCS1_OAEP.new(private_key).decrypt(encrypted_session_key)

    # Create a new AES cipher object with the decrypted session key and nonce
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)

    # Decrypt the ciphertext and verify the authentication tag
    plaintext = unpad(cipher_aes.decrypt_and_verify(ciphertext, tag), AES.block_size)

    return plaintext.decode()  # Decode decrypted message from bytes


# Perform encryption
encrypted_message = ecc_encrypt(message, public_key)
print(f"Encrypted message (hex): {encrypted_message}")

# Perform decryption
decrypted_message = ecc_decrypt(encrypted_message, private_key)
print(f"Decrypted message: {decrypted_message}")

# Verify the result
assert decrypted_message == message.decode()
print("Decryption successful!")