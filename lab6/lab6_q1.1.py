from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Util.number import GCD

# Key Generation
key = ElGamal.generate(256, get_random_bytes)  # Generate an ElGamal key pair
public_key = (int(key.p), int(key.g), int(key.y))  # Extract public key components as integers
private_key = int(key.x)  # Extract private key as an integer

# Encryption Function
def elgamal_encrypt(message, key):
    """Encrypts a message using ElGamal encryption.

    Args:
        message (int): The message to encrypt.
        key (ElGamal.PublicKey): The ElGamal public key.

    Returns:
        tuple: A tuple containing the encrypted ciphertext (c1, c2).
    """

    p, g, y = int(key.p), int(key.g), int(key.y)  # Convert key components to integers
    k = randint(1, p - 2)  # Generate a random integer for encryption

    # Ensure k is coprime with p-1
    while GCD(k, p - 1) != 1:
        k = randint(1, p - 2)

    c1 = pow(g, k, p)  # Compute the first ciphertext component
    c2 = (message * pow(y, k, p)) % p  # Compute the second ciphertext component
    return (c1, c2)

# Decryption Function
def elgamal_decrypt(cipher_text, key):
    """Decrypts a message using ElGamal decryption.

    Args:
        cipher_text (tuple): The encrypted message (c1, c2).
        key (ElGamal.PrivateKey): The ElGamal private key.

    Returns:
        int: The decrypted message.
    """

    c1, c2 = cipher_text
    p = int(key.p)  # Convert key component to integer
    s = pow(c1, int(key.x), p)  # Compute the shared secret
    s_inv = pow(s, p - 2, p)  # Compute the modular inverse of s using Fermat's Little Theorem
    return (c2 * s_inv) % p  # Decrypt the message

# Example usage
message = 4441
cipher_text = elgamal_encrypt(message, key)
decrypted_message = elgamal_decrypt(cipher_text, key)

print("Original message:", message)
print("Encrypted message:", cipher_text)
print("Decrypted message:", decrypted_message)