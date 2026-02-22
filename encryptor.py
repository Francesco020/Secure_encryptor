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
    
def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    with open(input_path, "rb") as f:
        blob = f.read()
    
    if len(blob) < len(MAGIC) + SALT_LEN or blob[:4] != MAGIC:
        raise ValueError("Formato file non riconosciuto (header MAGIC mancante).")
    
    salt = blob[4:4 + SALT_LEN]
    token = blob[4 + SALT_LEN:]
    
    key = derive_key(password, salt)
    
    try:
        data = Fernet(key).decrypt(token)
    except InvalidToken:
        raise ValueError("Password errata o file corrotto.") from None
        
    tmp = output_path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        
    os.replace(tmp, output_path)
    