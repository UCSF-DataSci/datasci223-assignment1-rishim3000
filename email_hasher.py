import sys
import hashlib

def hash_email(email):
    """
    Hash an email address using SHA-256 and return the hexadecimal digest.
    
    Args:
        email (str): The email address to hash
        
    Returns:
        str: The SHA-256 hash of the email in hexadecimal format
    """
    email_bytes = email.encode('utf-8')
    sha256_hash = hashlib.sha256(email_bytes)
    return sha256_hash.hexdigest()

def write_hash_to_file(hash_value, filename="hash.email"):
    """
    Write a hash value to a file.
    
    Args:
        hash_value (str): The hash value to write
        filename (str): The name of the file to write to (default: "hash.email")
    """
    with open(filename, 'w') as f:
        f.write(hash_value)

def main():
    """
    Main function to process command line arguments and execute the script.
    """
    if len(sys.argv) != 2:
        print("Usage: python email_hasher.py <email_address>")
        sys.exit(1)
    email = sys.argv[1]
    hash_value = hash_email(email)
    write_hash_to_file(hash_value)

if __name__ == "__main__":
    main()