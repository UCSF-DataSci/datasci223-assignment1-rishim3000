import sys
import hashlib
import re

def hash_email(email):
    hash_object = hashlib.sha256()
    data = email.encode("utf-8")
    hash_object.update(data)
    return hash_object.hexdigest()

def write_hash_to_file(hash_value, filename="hash.email"):
    with open(filename, "w") as file:
        file.write(hash_value)

def is_valid_email(email):
    #checking for valid email address
    email_regex = r"^[^@]+@[^@]+\.[a-zA-Z]{2,}$"
    return re.match(email_regex, email)       

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python email_hasher.py <email_address>")
        sys.exit(1)

    email = sys.argv[1] #email from command line argument
    
    if not is_valid_email(email):
        print("Invalid email address!")
        sys.exit(1)

    hash_value = hash_email(email) #hash value of email input
    write_hash_to_file(hash_value) #write hash value to file

    print(f"Email hashed to hash.email")   

if __name__ == "__main__":
    main()
