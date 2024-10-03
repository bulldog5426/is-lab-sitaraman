import hashlib
import time
import random
import string
from collections import defaultdict

# Function to generate a random string of fixed length
def generate_random_string(length=10):
    """Generates a random string of the specified length.

    Args:
        length (int, optional): The desired length of the string (default: 10).

    Returns:
        str: The generated random string.
    """

    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Function to compute hash values for a list of strings using different hash algorithms
def compute_hashes(strings, hash_algo):
    """Computes hash values for a list of strings using a specified hash algorithm.

    Args:
        strings (list): A list of strings to be hashed.
        hash_algo (callable): The hash algorithm function (e.g., hashlib.md5, hashlib.sha1).

    Returns:
        dict: A dictionary mapping each string to its corresponding hash value.
    """

    hash_dict = {}
    for s in strings:
        hash_obj = hash_algo()  # Create a new hash object
        hash_obj.update(s.encode())  # Update the hash object with the string
        hash_value = hash_obj.hexdigest()  # Get the hexdigest of the hash
        hash_dict[s] = hash_value  # Store the hash value in the dictionary
    return hash_dict

# Function to detect collisions in a dictionary of hash values
def detect_collisions(hash_dict):
    """Detects collisions in a dictionary of hash values.

    Args:
        hash_dict (dict): A dictionary mapping strings to their hash values.

    Returns:
        list: A list of tuples containing the hash value and the colliding strings.
    """

    reverse_hashes = defaultdict(list)  # Create a reverse lookup dictionary
    collisions = []

    for s, h in hash_dict.items():
        reverse_hashes[h].append(s)  # Add the string to the list for its hash value

    for hash_value, strs in reverse_hashes.items():
        if len(strs) > 1:  # If there are multiple strings with the same hash
            collisions.append((hash_value, strs))

    return collisions

# Function to generate a dataset of random strings
def generate_dataset(num_strings=50, length=10):
    """Generates a dataset of random strings.

    Args:
        num_strings (int, optional): The number of strings to generate (default: 50).
        length (int, optional): The length of each string (default: 10).

    Returns:
        list: A list of random strings.
    """

    return [generate_random_string(length) for _ in range(num_strings)]

# Function to measure the time taken and collisions for different hash algorithms
def measure_time_and_collisions(strings, hash_algos):
    """Measures the time taken and detects collisions for different hash algorithms.

    Args:
        strings (list): A list of strings to be hashed.
        hash_algos (dict): A dictionary mapping hash algorithm names to their functions.

    Returns:
        dict: A dictionary containing the results for each hash algorithm, including time taken and collisions.
    """

    results = {}

    for algo_name, hash_algo in hash_algos.items():
        start_time = time.time()  # Start time measurement
        hashes = compute_hashes(strings, hash_algo)  # Compute hashes
        end_time = time.time()  # End time measurement

        collision_info = detect_collisions(hashes)  # Detect collisions

        results[algo_name] = {
            'time_taken': end_time - start_time,
            'collisions': collision_info
        }

    return results

# Main function
def main():
    # Define hash algorithms
    hash_algos = {
        'MD5': hashlib.md5,
        'SHA-1': hashlib.sha1,
        'SHA-256': hashlib.sha256
    }

    # Generate a dataset of random strings
    num_strings = 5000
    dataset = generate_dataset(num_strings)

    # Measure performance and collisions for each hash algorithm
    results = measure_time_and_collisions(dataset, hash_algos)

    # Print the results
    for algo_name, result in results.items():
        print(f"Algorithm: {algo_name}")
        print(f"Time taken: {result['time_taken']:.8f} seconds")
        print(f"Collisions detected: {len(result['collisions'])}")
        for collision in result['collisions']:
            print(f"Hash: {collision[0]} -> Strings: {collision[1]}")
        print()


if __name__ == '__main__':
    main()