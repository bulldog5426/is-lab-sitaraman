import socket
import hashlib

def compute_hash(data):
    """Computes the SHA-256 hash of the given data."""
    return hashlib.sha256(data).hexdigest()

def start_client(server_host='127.0.0.1', server_port=65432):
    """Starts the client and sends data to the server for integrity verification."""

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_host, server_port))  # Connect to the server

    try:
        # Define the data to send (replace with your actual data)
        data = b"Your actual data here"  # Commented out the embedded message

        # Compute SHA-256 hash of the data before sending
        expected_hash = compute_hash(data)

        # Send data to the server
        client_socket.send(data)

        # Receive the hash from the server
        received_hash = client_socket.recv(64).decode()  # Maximum expected hash length (64 bytes)

        # Verify the hash for data integrity
        if expected_hash == received_hash:
            print("Data integrity verified. No corruption or tampering detected.")
        else:
            print("Data integrity check failed. Possible corruption or tampering.")

    finally:
        client_socket.close()  # Ensure socket is closed even on errors

if __name__ == "__main__":
    start_client()