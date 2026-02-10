from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

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
    
    output_file = input_file + ".enc"
    with open(output_file, "wb") as f:
        f.write(encrypted_data)
        
    print("File encrypted successfully: {output_file}")
    
