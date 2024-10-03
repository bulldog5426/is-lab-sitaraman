from Crypto.Util import number
import time


# Rabin Cryptosystem Class
class RabinCryptosystem:
    def __init__(self, key_size=1024):
        """Initializes the Rabin Cryptosystem with the specified key size."""
        self.key_size = key_size

    def generate_key_pair(self):
        """Generates a new RSA key pair (public and private).

        Returns:
            tuple: A tuple containing the public key (n) and private key (p, q).
        """

        p = number.getPrime(self.key_size // 2)  # Generate a prime number for the modulus
        q = number.getPrime(self.key_size // 2)  # Generate another prime number

        n = p * q  # Calculate the modulus (public key)
        return (n,), (p, q)  # Return public key (n) and private key (p, q)

    def encrypt(self, public_key, message):
        """Encrypts a message using the Rabin cryptosystem.

        Args:
            public_key (tuple): The public key (n).
            message (str): The message to encrypt.

        Returns:
            int: The encrypted ciphertext.
        """

        n = public_key[0]
        m = int.from_bytes(message.encode("utf-8"), "big")  # Convert message to integer
        return (m**2) % n  # Perform the Rabin encryption (square modulo n)

    def decrypt(self, private_key, ciphertext):
        """Decrypts a ciphertext using the Rabin cryptosystem.

        Args:
            private_key (tuple): The private key (p, q).
            ciphertext (int): The encrypted message.

        Returns:
            list: A list of possible decrypted messages (up to four).
        """

        p, q = private_key
        n = p * q

        # Calculate roots using the Chinese Remainder Theorem
        mp = pow(ciphertext, (p + 1) // 4, p)
        mq = pow(ciphertext, (q + 1) // 4, q)
        yp, yq = number.inverse(q, p), number.inverse(p, q)
        r1 = (yp * p * mq + yq * q * mp) % n
        r2 = (yp * p * mq - yq * q * mp) % n

        return [r1, n - r1, r2, n - r2]  # Return possible decrypted messages


# Key Management and Logging Class
class KeyManager:
    def __init__(self, key_size=1024):
        """Initializes the KeyManager for managing key generation, distribution, and logging.

        Args:
            key_size (int): The desired key size for Rabin cryptosystem.
        """

        self.keys = {}  # Dictionary to store generated keys
        self.logs = []  # List to store log entries
        self.rabin = RabinCryptosystem(key_size)  # Create a RabinCryptosystem instance

    def generate_keys(self, facility_id):
        """Generates a new key pair for a given facility ID.

        Args:
            facility_id (str): The unique identifier for the facility.

        Returns:
            int: The public key for the facility.
        """

        public_key, private_key = self.rabin.generate_key_pair()
        self.keys[facility_id] = {"public_key": public_key, "private_key": private_key}
        self.log(f"Keys generated for {facility_id}.")
        return public_key

    def distribute_keys(self, facility_id):
        """Distributes the public and private keys for a given facility ID.

        Args:
            facility_id (str): The unique identifier for the facility.

        Returns:
            tuple: A tuple containing the public key and private key, or None if not found.
        """

        keys = self.keys.get(facility_id)
        if keys:
            self.log(f"Keys distributed to {facility_id}.")
            return keys["public_key"], keys["private_key"]
        self.log(f"Keys not found for {facility_id}.")
        return None

    def log(self, message):
        """Logs a message with a timestamp.

        Args:
            message (str): The message to log.
        """

        entry = f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}"
        self.logs.append(entry)
        print(entry)


# Example Usage
km = KeyManager()
facility_id = "hospital1"

# Key Generation and Distribution
public_key = km.generate_keys(facility_id)
public_key, private_key = km.distribute_keys(facility_id)

# Encrypt and Decrypt Example
message = "datadatadatadatadata"
ciphertext = km.rabin.encrypt(public_key, message)
print(f"Encrypted: {ciphertext}")
possible_plaintexts = km.rabin.decrypt(private_key, ciphertext)

# Print Valid Decrypted Results
print("Possible decrypted messages:")
for i, pt in enumerate(possible_plaintexts):
    try:
        # Convert the decrypted integer to bytes
        decoded_bytes = int.to_bytes(pt, (pt.bit_length() + 7) // 8, "big")

        try:
            # Attempt to decode bytes to text
            decoded_message = decoded_bytes.decode("utf-8")
            print(f"Decrypted possibility {i+1}: {decoded_message}")
        except UnicodeDecodeError:
            # If decoding to text fails, print the hex representation
            print(f"Decrypted possibility {i+1}: (hex) {decoded_bytes.hex()}")
    except Exception as e:
        print(f"Decrypted possibility {i+1}: Unable to decode - {e}")