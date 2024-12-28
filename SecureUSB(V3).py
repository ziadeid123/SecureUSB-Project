import os
import re
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Define dynamic paths
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))  # Directory of the script
PASSWORD_FILE = os.path.join(CURRENT_DIR, "user_data.json")
PRIVATE_KEY_FILE = os.path.join(CURRENT_DIR, "private_key.pem")
PUBLIC_KEY_FILE = os.path.join(CURRENT_DIR, "public_key.pem")

# RSA Key Management
def generate_rsa_keys():
    """Generate RSA private and public keys."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_rsa_keys(private_key, public_key):
    """Save RSA keys to files."""
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(PRIVATE_KEY_FILE, "wb") as priv_file, open(PUBLIC_KEY_FILE, "wb") as pub_file:
        priv_file.write(private_pem)
        pub_file.write(public_pem)

def load_rsa_keys():
    """Load RSA keys from files."""
    with open(PRIVATE_KEY_FILE, "rb") as priv_file:
        private_key = serialization.load_pem_private_key(
            priv_file.read(),
            password=None
        )
    with open(PUBLIC_KEY_FILE, "rb") as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read())
    return private_key, public_key

# Password Management
def encrypt_password(password, public_key):
    """Encrypt the password using the public RSA key."""
    encrypted_password = public_key.encrypt(
        password.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_password).decode()

def decrypt_password(encrypted_password, private_key):
    """Decrypt the password using the private RSA key."""
    encrypted_password_bytes = base64.b64decode(encrypted_password)
    password = private_key.decrypt(
        encrypted_password_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return password.decode()

def save_password(encrypted_password):
    """Save the encrypted password to a file."""
    with open(PASSWORD_FILE, "w") as file:
        json.dump({"password": encrypted_password}, file)

def load_password():
    """Load the encrypted password from the file."""
    with open(PASSWORD_FILE, "r") as file:
        data = json.load(file)
    return data["password"]

def setup_password():
    """Set up a secure password for the first time."""
    print("Set up your password:")
    while True:
        password = input("Enter a strong password (8+ characters, 1 uppercase, 1 lowercase, 1 number, 1 special character): ")
        if validate_password(password):
            break
        print("Invalid password. Try again.")
    
    private_key, public_key = generate_rsa_keys()
    save_rsa_keys(private_key, public_key)
    
    encrypted_password = encrypt_password(password, public_key)
    save_password(encrypted_password)
    print("Password setup complete.")

def validate_password(password):
    """Validate the password against security requirements."""
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

# File Encryption and Decryption
def encrypt_file(file_path, key, algorithm="AES"):
    """Encrypt a file using AES or ChaCha20."""
    with open(file_path, "rb") as f:
        plaintext = f.read()

    if algorithm == "AES":
        iv = os.urandom(16)  # Generate a 16-byte IV
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    elif algorithm == "ChaCha20":
        nonce = os.urandom(16)  # Generate a 16-byte nonce
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    else:
        raise ValueError("Invalid encryption algorithm.")

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Save the IV or nonce along with the encrypted file
    encrypted_file = file_path + ".enc"
    with open(encrypted_file, "wb") as f:
        f.write(iv + ciphertext)  # Prefix IV or nonce to the ciphertext

    print(f"File encrypted: {encrypted_file}")

def decrypt_file(file_path, key, algorithm="AES"):
    """Decrypt a file using AES or ChaCha20."""
    with open(file_path, "rb") as f:
        file_data = f.read()

    if algorithm == "AES":
        iv = file_data[:16]  # Extract the first 16 bytes as IV
        ciphertext = file_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    elif algorithm == "ChaCha20":
        nonce = file_data[:16]  # Extract the first 16 bytes as nonce
        ciphertext = file_data[16:]
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    else:
        raise ValueError("Invalid decryption algorithm.")

    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    decrypted_file = file_path.replace(".enc", "")
    with open(decrypted_file, "wb") as f:
        f.write(plaintext)

    print(f"File decrypted: {decrypted_file}")

# Main Program
if __name__ == "__main__":
    if not os.path.exists(PASSWORD_FILE):
        print("No password found. Setting up SecureUSB for the first time.")
        setup_password()
    else:
        print("SecureUSB is already set up.")
        private_key, _ = load_rsa_keys()
        encrypted_password = load_password()
        user_password = input("Enter your password: ")
        
        try:
            stored_password = decrypt_password(encrypted_password, private_key)
            if user_password == stored_password:
                print("Access granted.")
                print("1. Encrypt a file")
                print("2. Decrypt a file")
                choice = input("Choose an option: ")
                
                key = b"ThisIsA32ByteKey1234567890ABCDEF"  # Replace with a secure key
                if choice == "1":
                    file_path = input("Enter the path of the file to encrypt: ")
                    algorithm = input("Choose encryption method (AES/ChaCha20): ").strip().lower()
                    if algorithm == "aes":
                        encrypt_file(file_path, key, algorithm="AES")
                    elif algorithm == "chacha20":
                        encrypt_file(file_path, key, algorithm="ChaCha20")
                    else:
                        print("Invalid encryption algorithm.")
                elif choice == "2":
                    file_path = input("Enter the path of the file to decrypt: ")
                    algorithm = input("Choose decryption method (AES/ChaCha20): ").strip().lower()
                    if algorithm == "aes":
                        decrypt_file(file_path, key, algorithm="AES")
                    elif algorithm == "chacha20":
                        decrypt_file(file_path, key, algorithm="ChaCha20")
                    else:
                        print("Invalid decryption algorithm.")
                else:
                    print("Invalid choice.")
            else:
                print("Invalid password.")
        except Exception as e:
            print(f"Error: {e}")
