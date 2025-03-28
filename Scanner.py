import os
import re
import sys

# Constant for the Base58 pattern
BASE58_PATTERN = r'[13][a-km-zA-HJ-NP-Z0-9]{52}'
BASE58_REGEX = re.compile(BASE58_PATTERN)


def validate_path(path):
    """
    Checks if the given path is a valid and existing directory on the current operating system.
    """
    return os.path.exists(path) and os.path.isdir(path)


def scan_directory_for_private_keys(start_path):
    """
    Recursively scans the specified directory for private keys
    in Base58 format using a predefined pattern.
    """
    found_keys = set()

    print(f"Scanning directory: {start_path}...")
    for root, dirs, files in os.walk(start_path, topdown=True):
        print(f"Directory: {root}")  # Debug output

        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    matches = BASE58_REGEX.findall(content.decode('utf-8', errors='ignore'))
                    if matches:
                        print(f"Key found in file: {file_path}")  # Debug output
                        found_keys.update(matches)
            except (PermissionError, FileNotFoundError) as e:
                # Skip files that cannot be accessed
                print(f"Skipping file {file_path} due to error: {e}.")
            except Exception as e:
                # Handle any other exceptions during file processing
                print(f"Error processing file {file_path}: {e}")

    return list(found_keys)


def convert_base58_to_wif(base58_key):
    """
    Converts a Base58 private key to WIF format.
    """
    prefix = '80' if len(base58_key) == 52 else '00'
    return f"{prefix}{base58_key}"


def main():
    start_path = input("Enter a valid directory path to start the search (e.g., 'C:\\Users\\User' or '/home/user'): ").strip()
    if not validate_path(start_path):
        print(f"Invalid path: {start_path}")
        sys.exit(1)

    private_keys = scan_directory_for_private_keys(start_path)
    if private_keys:
        print("\nFound private keys:")
        for key in private_keys:
            print(f"Key: {key}")
            wif_key = convert_base58_to_wif(key)
            print(f"WIF version of the key: {wif_key}")
            print("---")
    else:
        print("No private keys found.")


if __name__ == '__main__':
    main()
