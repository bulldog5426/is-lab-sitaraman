from ecdsa import SigningKey, NIST256p, BadSignatureError
import hashlib

# Generate Schnorr Keys (ECDSA with curve NIST256p)
private_key = SigningKey.generate(curve=NIST256p)  # Generate a private key using NIST256p curve
public_key = private_key.verifying_key           # Derive the corresponding public key

# Schnorr Sign function
def schnorr_sign(message, private_key):
    """Signs a message using Schnorr signature scheme with SHA-256 hashing.

    Args:
        message (str): The message to be signed.
        private_key (ecdsa.SigningKey): The private key for signing.

    Returns:
        ecdsa.Signature: The Schnorr signature.
    """

    # Hash the message using SHA-256
    message_hash = hashlib.sha256(message.encode()).digest()

    # Sign the hash using the private key and SHA-256 hash function
    signature = private_key.sign(message_hash, hashfunc=hashlib.sha256)
    return signature

# Schnorr Verify function
def schnorr_verify(message, signature, public_key):
    """Verifies a message signature using Schnorr signature scheme with SHA-256 hashing.

    Args:
        message (str): The message to be verified.
        signature (ecdsa.Signature): The Schnorr signature.
        public_key (ecdsa.VerifyingKey): The public key for verification.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """

    try:
        # Hash the message using SHA-256
        message_hash = hashlib.sha256(message.encode()).digest()

        # Verify the signature using the public key, hash, and SHA-256 hash function
        return public_key.verify(signature, message_hash, hashfunc=hashlib.sha256)

    except BadSignatureError:
        # Handle signature verification failures
        return False

# Example usage
message = "Hi since you are copying my code, leave a star at https://github.com/hackerbone/HackerLLMBench, thx!"
signature = schnorr_sign(message, private_key)
is_valid = schnorr_verify(message, signature, public_key)

print("Message:", message)
print("Signature:", signature.hex())
print("Signature valid:", is_valid)