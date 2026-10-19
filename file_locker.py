
import os
import base64
import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SALT_FILE = "locker.salt"


def get_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )

    key = base64.urlsafe_b64encode(
        kdf.derive(password.encode())
    )
    return key


def encrypt_file():
    filename = input("Text file to encrypt: ").strip()
    password = getpass.getpass("Create a password: ")

    if not password:
        print("Password cannot be empty.")
        return

    if not os.path.isfile(filename):
        print("File not found.")
        return

    salt = os.urandom(16)
    key = get_key(password, salt)

    try:
        with open(filename, "rb") as file:
            content = file.read()

        encrypted = Fernet(key).encrypt(content)

        with open(filename + ".encrypted", "wb") as file:
            file.write(encrypted)

        with open(filename + ".salt", "wb") as file:
            file.write(salt)

        print("Encrypted file created successfully.")
        print("Original file has been kept unchanged.")

    except OSError as error:
        print(f"File error: {error}")


def decrypt_file():
    filename = input("Encrypted file path: ").strip()
    password = getpass.getpass("Enter password: ")
    salt_path = filename.removesuffix(".encrypted") + ".salt"

    try:
        with open(filename, "rb") as file:
            encrypted = file.read()

        with open(salt_path, "rb") as file:
            salt = file.read()

        key = get_key(password, salt)
        content = Fernet(key).decrypt(encrypted)

        output = filename.removesuffix(".encrypted") + ".decrypted"

        with open(output, "wb") as file:
            file.write(content)

        print(f"Decrypted file saved as: {output}")

    except InvalidToken:
        print("Wrong password or corrupted encrypted file.")
    except OSError:
        print("Could not read the file or its salt file.")


print("====== PASSWORD-PROTECTED FILE LOCKER ======")
print("1. Encrypt a file")
print("2. Decrypt a file")

choice = input("Choose an option: ").strip()

if choice == "1":
    encrypt_file()
elif choice == "2":
    decrypt_file()
else:
    print("Invalid choice.")
