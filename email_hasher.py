#!/usr/bin/env python3
"""
Email Hasher Script

This script takes an email address as a command line argument,
hashes it using the SHA-256 algorithm, and writes the hash to a file.

Usage:
    python email_hasher.py <email_address>

Example:
    python email_hasher.py example@email.com
"""

import sys
import hashlib

def hash_email(email):
    hash_object = hashlib.sha256()
    data = email.encode("utf-8")
    hash_object.update(data)
    return hash_object.hexdigest()

def write_hash_to_file(hash_value, filename="hash.email"):
    with open(filename, "w") as file:
        file.write(hash_value)


def main():
    if len(sys.argv) != 2:
        print("Usage: python email_hasher.py <email_address>")
        sys.exit(1)

    email = sys.argv[1] #email from command line argument
    if "@" not in email:
        print("Invalid email address!")
        sys.exit(1)
    if ".com" not in email:
        print("Invalid email address!")
        sys.exit(1)    
    hash_value = hash_email(email) #hash value of email input
    write_hash_to_file(hash_value) #write hash value to file

    print(f"Email hashed to hash.email")   

if __name__ == "__main__":
    main()
