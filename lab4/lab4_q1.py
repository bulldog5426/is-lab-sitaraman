from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import os
import time


class DRMSystem:
    """A Digital Rights Management (DRM) system using ElGamal encryption."""

    def __init__(self, key_size=2048):
        """Initializes the DRM system with a specified key size.

        Args:
            key_size (int, optional): The desired key size for ElGamal keys (default: 2048).
        """

        self.key_size = key_size
        self.master_key_pair = None  # Stores the master public/private key pair
        self.content_keys = {}  # Dictionary to store encrypted content keys
        self.access_control = {}  # Dictionary to track access permissions (customer ID, content ID, expiration time)
        self.logs = []  # List to store log messages

    def generate_master_key(self):
        """Generates a new ElGamal key pair for the DRM system."""

        self.master_key_pair = ElGamal.generate(self.key_size, get_random_bytes)
        self.log("Master key pair generated.")

    def encrypt_content(self, content_id, content):
        """Encrypts a piece of content using the master public key.

        Args:
            content_id (str): Unique identifier for the content.
            content (bytes): The content to be encrypted.
        """

        # Hash the content for integrity and uniqueness
        content_hash = SHA256.new(content).digest()

        # Encrypt the content hash using ElGamal with the master public key
        encrypted_content = self.master_key_pair.encrypt(content_hash, get_random_bytes(16))

        # Store the encrypted content key with the content ID
        self.content_keys[content_id] = encrypted_content
        self.log(f"Content {content_id} encrypted.")

    def distribute_key(self, customer_id, content_id):
        """Grants temporary access to content for a customer.

        Args:
            customer_id (str): Unique identifier for the customer.
            content_id (str): Unique identifier for the content.

        This implementation demonstrates a simple example of limited-time access.
        You can replace this with a more robust access control mechanism.
        """

        # Set expiration time for access (e.g., 1 hour)
        self.access_control[(customer_id, content_id)] = time.time() + 3600
        self.log(f"Access granted to {customer_id} for content {content_id}.")

    def revoke_access(self, customer_id, content_id):
        """Revokes access to content for a customer.

        Args:
            customer_id (str): Unique identifier for the customer.
            content_id (str): Unique identifier for the content.
        """

        if (customer_id, content_id) in self.access_control:
            del self.access_control[(customer_id, content_id)]
            self.log(f"Access revoked for {customer_id} for content {content_id}.")

    def key_revocation(self):
        """Revokes the current master key and generates a new one.

        This is a critical security measure to prevent unauthorized access
        if the master key is compromised.
        """

        self.generate_master_key()
        self.log("Master key revoked and renewed.")

    def check_access(self, customer_id, content_id):
        """Checks if a customer has valid access to a piece of content.

        Args:
            customer_id (str): Unique identifier for the customer.
            content_id (str): Unique identifier for the content.

        Returns:
            bool: True if the customer has access, False otherwise.
        """

        if (customer_id, content_id) in self.access_control:
            access_time = self.access_control[(customer_id, content_id)]
            if time.time() <= access_time:
                return True
        return False

    def secure_store_key(self):
        """Stores the master private key securely (demonstration only).

        This is a simplified example. In practice, consider using a Hardware
        Security Module (HSM) for more robust key storage and management.
        """

        with open("private_key.pem", "wb") as f:
            f.write(self.master_key_pair.export_key())
        os.chmod("private_key.pem", 0o600)  # Set file permissions for restricted access
        self.log("Master private key securely stored.")

    def log(self, message):
        """Logs a message with a timestamp.

        Args:
            message (str): The message to log.
        """

        self.logs.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}")
        print(message)  # For demonstration purposes


# Example Usage:
drm = DRMSystem()
drm.generate_master_key()
drm.encrypt_content("content1", b"Some digital content")
drm.distribute_key("customer1", "content1")
drm.revoke_access("customer1", "content1")
drm.key_revocation()
drm.secure_store_key()