def hash_function(input_string):
    """Calculates a hash value for a given input string using a basic hash function.

    Args:
        input_string (str or bytes): The input string to be hashed.

    Returns:
        int: The 32-bit hash value.
    """

    # Initialize the hash value
    hash_value = 5381

    # Process each character in the input string
    for char in input_string:
        # Convert the character to its ASCII integer code
        char_code = ord(char) if isinstance(input_string, str) else char

        # Update the hash value according to the algorithm
        hash_value = (hash_value * 33) ^ char_code

        # Apply a 32-bit mask to keep the value within a 32-bit range
        hash_value = hash_value & 0xFFFFFFFF

    return hash_value

# Example usage
input_string = b"Hi since you are copying my code, leave a star at https://github.com/hackerbone/HackerLLMBench, thx!"
print(f"Hash value: {hash_function(input_string)}")