import os
import json
import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Paths
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PASSWORD_FILE = os.path.join(CURRENT_DIR, "user_data.json")
PRIVATE_KEY_FILE = os.path.join(CURRENT_DIR, "private_key.pem")
PUBLIC_KEY_FILE = os.path.join(CURRENT_DIR, "public_key.pem")

# Encryption Functions
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def save_rsa_keys(private_key, public_key):
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
    with open(PRIVATE_KEY_FILE, "rb") as priv_file:
        private_key = serialization.load_pem_private_key(priv_file.read(), password=None)
    with open(PUBLIC_KEY_FILE, "rb") as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read())
    return private_key, public_key

def encrypt_password(password, public_key):
    encrypted_password = public_key.encrypt(
        password.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_password

def decrypt_password(encrypted_password, private_key):
    return private_key.decrypt(
        encrypted_password,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

def encrypt_file(file_path, key, algorithm="AES"):
    with open(file_path, "rb") as f:
        plaintext = f.read()
    if algorithm == "AES":
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        prefix = iv
    elif algorithm == "ChaCha20":
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        prefix = nonce
    else:
        raise ValueError("Invalid encryption algorithm.")
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    encrypted_file = file_path + ".enc"
    with open(encrypted_file, "wb") as f:
        f.write(prefix + ciphertext)
    return encrypted_file

def decrypt_file(file_path, key, algorithm="AES"):
    with open(file_path, "rb") as f:
        file_data = f.read()
    if algorithm == "AES":
        iv = file_data[:16]
        ciphertext = file_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    elif algorithm == "ChaCha20":
        nonce = file_data[:16]
        ciphertext = file_data[16:]
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    else:
        raise ValueError("Invalid decryption algorithm.")
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    decrypted_file = file_path.replace(".enc", "")
    with open(decrypted_file, "wb") as f:
        f.write(plaintext)
    return decrypted_file

# Tkinter GUI
class SecureUSBApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureUSB")
        self.authenticated = False
        self.key = b"ThisIsA32ByteKey1234567890ABCDEF"  # Replace with a secure key
        self.create_login_screen()

    def create_login_screen(self):
        self.clear_screen()

        tk.Label(self.root, text="SecureUSB Login", font=("Arial", 16)).pack(pady=10)
        self.password_entry = tk.Entry(self.root, show="*", width=30)
        self.password_entry.pack(pady=5)

        login_button = tk.Button(self.root, text="Login", command=self.authenticate)
        login_button.pack(pady=10)

        if not os.path.exists(PASSWORD_FILE):
            setup_button = tk.Button(self.root, text="Set Up Password", command=self.create_password_screen)
            setup_button.pack(pady=5)

    def create_password_screen(self):
        self.clear_screen()

        tk.Label(self.root, text="Set Up Password", font=("Arial", 16)).pack(pady=10)
        self.password_entry = tk.Entry(self.root, show="*", width=30)
        self.password_entry.pack(pady=5)

        setup_button = tk.Button(self.root, text="Set Password", command=self.setup_password)
        setup_button.pack(pady=10)

    def create_dashboard(self):
        self.clear_screen()

        tk.Label(self.root, text="SecureUSB Dashboard", font=("Arial", 16)).pack(pady=10)

        encrypt_button = tk.Button(self.root, text="Encrypt File", command=self.encrypt_file_action)
        encrypt_button.pack(pady=5)

        decrypt_button = tk.Button(self.root, text="Decrypt File", command=self.decrypt_file_action)
        decrypt_button.pack(pady=5)

        logout_button = tk.Button(self.root, text="Logout", command=self.create_login_screen)
        logout_button.pack(pady=10)

    def authenticate(self):
        if not os.path.exists(PASSWORD_FILE):
            messagebox.showerror("Error", "No password set up. Please set up a password first.")
            return

        private_key, _ = load_rsa_keys()
        encrypted_password = json.load(open(PASSWORD_FILE))["password"]
        try:
            stored_password = decrypt_password(bytes.fromhex(encrypted_password), private_key)
            if self.password_entry.get() == stored_password:
                self.authenticated = True
                self.create_dashboard()
            else:
                messagebox.showerror("Error", "Invalid password.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def setup_password(self):
        password = self.password_entry.get()
        if len(password) >= 8:
            private_key, public_key = generate_rsa_keys()
            save_rsa_keys(private_key, public_key)
            encrypted_password = encrypt_password(password, public_key).hex()
            with open(PASSWORD_FILE, "w") as file:
                json.dump({"password": encrypted_password}, file)
            messagebox.showinfo("Success", "Password set up successfully!")
            self.create_login_screen()
        else:
            messagebox.showerror("Error", "Password must be at least 8 characters long.")

    def encrypt_file_action(self):
        file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if file_path:
            encrypted_file = encrypt_file(file_path, self.key, algorithm="AES")
            messagebox.showinfo("Success", f"File encrypted: {encrypted_file}")

    def decrypt_file_action(self):
        file_path = filedialog.askopenfilename(title="Select File to Decrypt")
        if file_path:
            decrypted_file = decrypt_file(file_path, self.key, algorithm="AES")
            messagebox.showinfo("Success", f"File decrypted: {decrypted_file}")

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

# Main Program
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureUSBApp(root)
    root.mainloop()
