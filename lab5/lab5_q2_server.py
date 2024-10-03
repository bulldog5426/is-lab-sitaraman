import socket
import hashlib

def compute_hash(data):
    """Computes the SHA-256 hash of the given data."""
    return hashlib.sha256(data).hexdigest()

def handle_client_connection(client_socket):
    """Handles an incoming client connection.

    Args:
        client_socket (socket.socket): The socket object representing the client connection.
    """

    try:
        # Receive data from the client (up to 1024 bytes)
        data = client_socket.recv(1024)

        # If no data is received, the connection is likely closed
        if not data:
            return

        # Compute the SHA-256 hash of the received data
        received_hash = compute_hash(data)

        # Send the computed hash back to the client
        client_socket.send(received_hash.encode())

    finally:
        # Ensure the socket is closed, even if an exception occurs
        client_socket.close()

def start_server(host='127.0.0.1', port=65432):
    """Starts a TCP server on the specified host and port.

    Args:
        host (str, optional): The hostname or IP address to bind to (default: '127.0.0.1').
        port (int, optional): The port number to listen on (default: 65432).
    """

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
    server_socket.bind((host, port))  # Bind the socket to the specified host and port
    server_socket.listen(1)  # Listen for incoming connections (max 1 at a time)
    print(f"Server listening on {host}:{port}")

    while True:
        client_socket, addr = server_socket.accept()  # Accept a new connection
        print(f"Accepted connection from {addr}")
        handle_client_connection(client_socket)  # Handle the client connection

if __name__ == "__main__":
    start_server()