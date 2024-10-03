from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii


def print_hex(data, label):
    """
    Prints the hexadecimal representation of the provided data with a label.

    Args:
        data (bytes): The data to be printed in hexadecimal format.
        label (str): A label to describe the data.
    """
    print(f"{label}: {binascii.hexlify(data).decode()}")


# Convert the key and plaintext to bytes
key = binascii.unhexlify("FEDCBA9876543210FEDCBA9876543210")
plain_text = "Top Secret Data".encode()

# Pad the plaintext to make it a multiple of the block size (16 bytes)
padded_plaintext = pad(plain_text, AES.block_size)

# Initialize AES cipher in ECB mode
cipher = AES.new(key, AES.MODE_ECB)

# Initial Round (using first 16 bytes of padded plaintext)
print_hex(padded_plaintext[:16], "Plaintext Block")  # Print the first block of plaintext
initial_round_state = cipher.encrypt(padded_plaintext[:16])
print_hex(initial_round_state, "After Initial Round")

# Loop through the remaining plaintext blocks (if any) for encryption
ciphertext_blocks = []
for i in range(0, len(padded_plaintext), AES.block_size):
    block = padded_plaintext[i:i + AES.block_size]
    encrypted_block = cipher.encrypt(block)
    ciphertext_blocks.append(encrypted_block)

# Concatenate the encrypted blocks to form the final ciphertext
ciphertext = b''.join(ciphertext_blocks)
print_hex(ciphertext, "Ciphertext")

# Decrypt the ciphertext (similar loop structure)
decrypted_blocks = []
for i in range(0, len(ciphertext), AES.block_size):
    block = ciphertext[i:i + AES.block_size]
    decrypted_block = cipher.decrypt(block)
    decrypted_blocks.append(decrypted_block)

# Combine the decrypted blocks and remove padding
decrypted_text = unpad(b''.join(decrypted_blocks), AES.block_size)
print_hex(decrypted_text, "Decrypted Text")

# Verify decryption matches the original plaintext
assert decrypted_text.decode() == "Top Secret Data"