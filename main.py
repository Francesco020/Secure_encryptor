import argparse
from getpass import getpass

from encryptor import encrypt_file, decrypt_file

def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypt/Decrypt con PBKDF2 + Fernet")
    parser.add_argument("mode", choices=["encrypt", "decrypt"])
    parser.add_argument("input", help="Percorso file input")
    parser.add_argument("-o", "--output", help="Percorso file output (opzionale)") 
    args = parser.parse_args()
    
    password = getpass("Password: ")
    
    try:
        if args.mode == "Encrypt":
            out = args.output or (args.input + ".enc")
            encrypt_file(args.input, out, password)
            print(f"Encrypted -> {out}")
        else:
            default_out = args.input[:-4] if args.input.endswith(".enc") else (args.input + ".dec")
            out = args.output or default_out
            decrypt_file(args.input, out, password)
            print(f"Decrypted -> {out}")
            
    except FileNotFoundError:
        print("Errore: file non trovato.")
    except PermissionError:
        print("Errore: permessi insufficienti.")
    except ValueError as e:
        print(f"Errore: {e}")
        
if __name__ == "__main__":
    main()