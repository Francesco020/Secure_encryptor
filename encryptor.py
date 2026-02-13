from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os

def derive_key(password: str, salt: bytes): 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(input_file: str, key: bytes):
    with open(input_file, "rb") as f:
        data = f.read()
        
    fernet = Fernet(key)
    
    encrypted_data = fernet.encrypt(data)
    
    temp_file = input_file + ".enc"
    with open(temp_file, "wb") as f:
        f.write(encrypted_data)
        
    os.replace(temp_file, input_file)
        
    print(f"File encrypted successfully: {input_file}")
    
def decrypt_file(input_file: str, key: bytes):
    with open(input_file, "rb") as f:
        encrypted_data = f.read()
    
    fernet = Fernet(key)
    
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception:
        print("Invalid password or corrupted file")
        return
        
    with open(input_file, "wb") as f:
        f.write(decrypted_data)
        
    print(f"File decrypted successfuly: {input_file}")
    
def main():
    mode = input("Choose mode (encrypt/decrypt)")
    file = input("Insert file name:")
    password = input("Insert password: ")
    
    salt = b"1234567890123456"
    key = derive_key(password, salt)
    
    if mode == "encrypt":
        encrypt_file(file, key)
    elif mode == "decrypt":
        decrypt_file(file, key)
    else:
        print("Invalid mode")
        
if __name__ == "__main__":
    main()
    