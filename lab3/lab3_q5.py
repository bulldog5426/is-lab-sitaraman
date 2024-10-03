import time
import random
from hashlib import sha256

# Prime number (p) and generator (g) for the Diffie-Hellman key exchange
p = 23  # Small prime number for demonstration (use a larger prime in practice)
g = 5  # Generator


def generate_private_key():
    """Generates a random private key in the range [1, p-1].

    Returns:
        int: The generated private key.
    """
    return random.randint(1, p - 1)


def generate_public_key(private_key):
    """Generates a public key based on the given private key.

    Args:
        private_key (int): The private key.

    Returns:
        int: The generated public key.
    """
    return pow(g, private_key, p)


def compute_shared_secret(private_key, other_public_key):
    """Computes the shared secret key using the Diffie-Hellman algorithm.

    Args:
        private_key (int): The private key of the current party.
        other_public_key (int): The public key of the other party.

    Returns:
        int: The computed shared secret.
    """
    return pow(other_public_key, private_key, p)


# Measure time taken for key generation and exchange
start_time = time.time()

# Peer 1 generates a private key and computes the public key
private_key_1 = generate_private_key()
public_key_1 = generate_public_key(private_key_1)

# Peer 2 generates a private key and computes the public key
private_key_2 = generate_private_key()
public_key_2 = generate_public_key(private_key_2)

# Key exchange: Peers exchange their public keys
# Each peer computes the shared secret using their private key and the other's public key
shared_secret_1 = compute_shared_secret(private_key_1, public_key_2)
shared_secret_2 = compute_shared_secret(private_key_2, public_key_1)

# Derive a shared key using SHA-256 for additional security
shared_key_1 = sha256(str(shared_secret_1).encode()).hexdigest()
shared_key_2 = sha256(str(shared_secret_2).encode()).hexdigest()

end_time = time.time()

# Check if both peers derived the same shared key
assert shared_key_1 == shared_key_2

# Output the results
print(f"Public Key 1: {public_key_1}")
print(f"Public Key 2: {public_key_2}")
print(f"Shared Key: {shared_key_1}")
print(f"Time taken: {end_time - start_time} seconds")