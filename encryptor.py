from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
from cryptography.fernet import Fernet
import base64
import os

MAGIC = b"FER1"
SALT_LEN = 16
PBKDF2_ITERS = 300_000

def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERS) -> bytes: 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

def encrypt_file(input_path: str,output_path: str, password: str) -> None:
    with open(input_path, "rb") as f:
        data = f.read()
    
    salt = os.random(SALT_LEN)
    key = derive_key(password, salt)
    token = Fernet(key).encrypt(data)
    
    tmp = output_path + ".enc"
    with open(tmp, "wb") as f:
        f.write(MAGIC)
        f.write(salt)
        f.write(token)
        
    os.replace(tmp, output_path)
        
    print(f"File encrypted successfully: {output_path}")
    
def decrypt_file(input_file: str, key: bytes):
    with open(input_file, "rb") as f:
        encrypted_data = f.read()
    
    fernet = Fernet(key)
    
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except InvalidToken:
        print("Invalid password or corrupted file")
        return
        
    with open(input_file, "wb") as f:
        f.write(decrypted_data)
        
    print(f"File decrypted successfuly: {input_file}")  
    