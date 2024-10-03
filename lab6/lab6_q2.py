import random
from sympy import isprime


def generate_large_prime(bits=256):
    """Generates a large prime number using a simple algorithm.

    Args:
        bits (int, optional): The desired number of bits for the prime (default: 256).

    Returns:
        int: A large prime number.
    """

    while True:
        n = random.getrandbits(bits)  # Generate a random number with the specified number of bits
        if isprime(n):  # Check if the number is prime
            return n

def dh_keygen(bits=256):
    """Generates a Diffie-Hellman key pair.

    Args:
        bits (int, optional): The desired number of bits for the prime modulus (default: 256).

    Returns:
        tuple: A tuple containing the public values (p, g, A, B) and the shared secret (shared_secret).
    """

    # Generate a large prime number for the modulus
    p = generate_large_prime(bits)

    # Generate a random generator element 'g' in the range [2, p-2]
    g = random.randint(2, p - 2)

    # Generate private keys for Alice and Bob
    a, b = random.randint(1, p - 2), random.randint(1, p - 2)

    # Calculate public values
    A = pow(g, a, p)
    B = pow(g, b, p)

    # Calculate the shared secret (using either A and b or B and a)
    shared_secret = pow(B, a, p)  # Or pow(A, b, p)

    return (p, g, A, B), shared_secret

# Example usage
(public_values, shared_secret) = dh_keygen()
print("Public values (p, g, A, B):", *public_values)
print("Shared secrets match?", shared_secret == pow(public_values[2], public_values[3], public_values[0]))