from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes, random
from Crypto.Util.number import GCD, bytes_to_long, long_to_bytes
from Crypto.Hash import SHA256


# Generate ElGamal keys (2048 bits)
def generate_elgamal_keys():
    """Generates an ElGamal key pair (private and public).

    Returns:
        tuple: A tuple containing the ElGamal key object and the public key.
    """

    key = ElGamal.generate(2048, random.StrongRandom().randint)
    public_key = key.publickey()
    return key, public_key


# ElGamal key components
key, public_key = generate_elgamal_keys()
p = public_key.p
g = public_key.g
h = public_key.y
x = key.x  # Private key component

# Message to encrypt
plain_text = "Confidential Data".encode()

# Hash the message for integrity check
hash_obj = SHA256.new(plain_text)
message_hash = bytes_to_long(hash_obj.digest())


# ElGamal encryption function
def elgamal_encrypt(message_hash, public_key):
    """Encrypts a message hash using the provided ElGamal public key.

    Args:
        message_hash (int): The message hash value.
        public_key (ElGamal.PublicKey): The ElGamal public key object.

    Returns:
        tuple: A tuple containing the ElGamal ciphertext components (c1, c2).
    """

    k = random.StrongRandom().randint(1, public_key.p - 2)
    while GCD(k, public_key.p - 1) != 1:
        k = random.StrongRandom().randint(1, public_key.p - 2)

    c1 = pow(public_key.g, k, public_key.p)
    s = pow(public_key.y, k, public_key.p)
    c2 = (message_hash * s) % public_key.p
    return c1, c2


# ElGamal decryption function
def elgamal_decrypt(c1, c2, private_key):
    """Decrypts an ElGamal ciphertext using the provided private key.

    Args:
        c1 (int): The first component of the ciphertext (c1).
        c2 (int): The second component of the ciphertext (c2).
        private_key (ElGamal.PrivateKey): The ElGamal private key object.

    Returns:
        int: The decrypted message hash value.
    """

    s = pow(c1, private_key.x, private_key.p)
    s_inv = pow(s, private_key.p - 2, private_key.p)
    decrypted_hash = (c2 * s_inv) % private_key.p
    return decrypted_hash


# Encrypt the message hash
c1, c2 = elgamal_encrypt(message_hash, public_key)
print(f"Ciphertext: (c1={c1}, c2={c2})")

# Decrypt the ciphertext
decrypted_hash = elgamal_decrypt(c1, c2, key)
decrypted_text = long_to_bytes(decrypted_hash)

# Verify the decrypted message hash
assert decrypted_hash == message_hash, "Decryption failed!"

print(f"Decrypted text: {decrypted_text}")