import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import secrets
import sympy
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64
from key import KeyManagementSystem
from check_password_strength import analyze_password

class KeyManagementGUI:
    def __init__(self, root):
        self.kms = KeyManagementSystem()
        self.root = root
        self.root.title("Key Management System")
        self.root.geometry("600x600")

        self.setup_gui()

    def setup_gui(self):
        tab_control = tk.ttk.Notebook(self.root)

        self.random_number_tab = tk.Frame(tab_control)
        self.large_prime_tab = tk.Frame(tab_control)
        self.password_strength_tab = tk.Frame(tab_control)
        self.encrypt_decrypt_tab = tk.Frame(tab_control)
        self.key_pair_tab = tk.Frame(tab_control)
        self.sign_verify_tab = tk.Frame(tab_control)

        tab_control.add(self.random_number_tab, text="Random Number")
        tab_control.add(self.large_prime_tab, text="Large Prime")
        tab_control.add(self.password_strength_tab, text="Password Strength")
        tab_control.add(self.encrypt_decrypt_tab, text="Encrypt/Decrypt Key")
        tab_control.add(self.key_pair_tab, text="Key Pair")
        tab_control.add(self.sign_verify_tab, text="Sign/Verify Key")

        tab_control.pack(expand=1, fill="both")

        self.create_random_number_tab()
        self.create_large_prime_tab()
        self.create_password_strength_tab()
        self.create_encrypt_decrypt_tab()
        self.create_key_pair_tab()
        self.create_sign_verify_tab()

    def create_random_number_tab(self):
            tk.Label(self.random_number_tab, text="Generate Random Number", font=("Arial", 14)).pack(pady=10)
            
            tk.Label(self.random_number_tab, text="Bit Length:").pack(pady=5)
            self.random_number_bit_length = tk.Entry(self.random_number_tab)
            # self.random_number_bit_length.insert(0, "Enter bit length (<= 256)")  # 默认提示文字
            self.random_number_bit_length.pack(pady=5)

            tk.Button(self.random_number_tab, text="Generate", command=self.generate_random_number).pack(pady=10)
            self.random_number_result = scrolledtext.ScrolledText(self.random_number_tab, width=50, height=5)
            self.random_number_result.pack(pady=10)

    def create_large_prime_tab(self):
        tk.Label(self.large_prime_tab, text="Generate Large Prime Number", font=("Arial", 14)).pack(pady=10)
        
        tk.Label(self.large_prime_tab, text="Bit Length:(<=1000)").pack(pady=5)
        self.large_prime_bit_length = tk.Entry(self.large_prime_tab)
        self.large_prime_bit_length.pack(pady=5)

        tk.Button(self.large_prime_tab, text="Generate", command=self.generate_large_prime).pack(pady=10)
        self.large_prime_result = scrolledtext.ScrolledText(self.large_prime_tab, width=50, height=5)
        self.large_prime_result.pack(pady=10)

    def create_password_strength_tab(self):
        tk.Label(self.password_strength_tab, text="Check Password Strength", font=("Arial", 14)).pack(pady=10)
        self.password_entry = tk.Entry(self.password_strength_tab, show='*', width=30)
        self.password_entry.pack(pady=10)
        tk.Button(self.password_strength_tab, text="Check", command=self.check_password_strength).pack(pady=10)
        self.password_strength_result = tk.Label(self.password_strength_tab, text="", font=("Arial", 12))
        self.password_strength_result.pack(pady=10)

    def create_encrypt_decrypt_tab(self):
        tk.Label(self.encrypt_decrypt_tab, text="Encrypt/Decrypt Key", font=("Arial", 14)).pack(pady=10)

        tk.Label(self.encrypt_decrypt_tab, text="Key").pack()
        self.key_entry = tk.Entry(self.encrypt_decrypt_tab, width=50)
        self.key_entry.pack(pady=5)

        tk.Label(self.encrypt_decrypt_tab, text="Password").pack()
        self.encrypt_password_entry = tk.Entry(self.encrypt_decrypt_tab, show='*', width=30)
        self.encrypt_password_entry.pack(pady=5)

        tk.Button(self.encrypt_decrypt_tab, text="Encrypt Key", command=self.encrypt_key).pack(pady=5)
        self.encrypted_key_result = scrolledtext.ScrolledText(self.encrypt_decrypt_tab, width=50, height=5)
        self.encrypted_key_result.pack(pady=5)

        tk.Label(self.encrypt_decrypt_tab, text="Encrypted Key").pack()
        self.encrypted_key_entry = scrolledtext.ScrolledText(self.encrypt_decrypt_tab, width=50, height=5)
        self.encrypted_key_entry.pack(pady=5)

        tk.Label(self.encrypt_decrypt_tab, text="Password").pack()
        self.decrypt_password_entry = tk.Entry(self.encrypt_decrypt_tab, show='*', width=30)
        self.decrypt_password_entry.pack(pady=5)

        tk.Button(self.encrypt_decrypt_tab, text="Decrypt Key", command=self.decrypt_key).pack(pady=5)
        self.decrypted_key_result = scrolledtext.ScrolledText(self.encrypt_decrypt_tab, width=50, height=5)
        self.decrypted_key_result.pack(pady=5)

    def create_key_pair_tab(self):
        tk.Label(self.key_pair_tab, text="Generate Key Pair", font=("Arial", 14)).pack(pady=10)
        tk.Button(self.key_pair_tab, text="Generate", command=self.generate_key_pair).pack(pady=10)
        self.private_key_result = scrolledtext.ScrolledText(self.key_pair_tab, width=50, height=10)
        self.private_key_result.pack(pady=5)
        self.public_key_result = scrolledtext.ScrolledText(self.key_pair_tab, width=50, height=10)
        self.public_key_result.pack(pady=5)

    def create_sign_verify_tab(self):
        tk.Label(self.sign_verify_tab, text="Sign/Verify Key", font=("Arial", 14)).pack(pady=10)

        tk.Label(self.sign_verify_tab, text="Private Key").pack()
        self.private_key_entry = scrolledtext.ScrolledText(self.sign_verify_tab, width=50, height=10)
        self.private_key_entry.pack(pady=5)

        tk.Label(self.sign_verify_tab, text="Message").pack()
        self.message_entry = tk.Entry(self.sign_verify_tab, width=50)
        self.message_entry.pack(pady=5)

        tk.Button(self.sign_verify_tab, text="Sign Key", command=self.sign_key).pack(pady=5)
        self.signature_result = scrolledtext.ScrolledText(self.sign_verify_tab, width=50, height=5)
        self.signature_result.pack(pady=5)

        tk.Label(self.sign_verify_tab, text="Public Key").pack()
        self.public_key_entry = scrolledtext.ScrolledText(self.sign_verify_tab, width=50, height=10)
        self.public_key_entry.pack(pady=5)

        tk.Label(self.sign_verify_tab, text="Signature").pack()
        self.signature_entry = scrolledtext.ScrolledText(self.sign_verify_tab, width=50, height=5)
        self.signature_entry.pack(pady=5)

        tk.Button(self.sign_verify_tab, text="Verify Signature", command=self.verify_signature).pack(pady=5)
        self.verification_result = tk.Label(self.sign_verify_tab, text="", font=("Arial", 12))
        self.verification_result.pack(pady=10)

    def generate_random_number(self):
        try:
            bit_length = int(self.random_number_bit_length.get())
        except ValueError:
            self.random_number_result.delete(1.0, tk.END)
            self.random_number_result.insert(tk.END, "Please enter a valid number for bit length.")
            return

        random_number = self.kms.generate_random_number(bit_length)
        self.random_number_result.delete(1.0, tk.END)
        self.random_number_result.insert(tk.END, str(random_number))

    def generate_large_prime(self):
        try:
            bit_length = int(self.large_prime_bit_length.get())
        except ValueError:
            self.large_prime_result.delete(1.0, tk.END)
            self.large_prime_result.insert(tk.END, "Please enter a valid number for bit length.")
            return

        large_prime = self.kms.generate_large_prime(bit_length)
        self.large_prime_result.delete(1.0, tk.END)
        self.large_prime_result.insert(tk.END, str(large_prime))

    def check_password_strength(self):
        password = self.password_entry.get()
        print(password)
        analysis = analyze_password(password)
        print(analysis)
        result_text = (
            f"Charset Length: {analysis['charset_length']}\n"
            f"Entropy: {analysis['entropy']:.2f} bits\n"
            f"Estimated Crack Time: {analysis['human_readable_crack_time']}\n"
            f"Strength Score: {analysis['strength_score']:.2f}"
        )
        
        self.password_strength_result.config(text=result_text)

    def encrypt_key(self):
        key = self.key_entry.get()
        password = self.encrypt_password_entry.get()
        encrypted_key = self.kms.encrypt_key(key, password)
        self.encrypted_key_result.delete('1.0', tk.END)
        self.encrypted_key_result.insert(tk.END, encrypted_key)

    def decrypt_key(self):
        encrypted_key = self.encrypted_key_entry.get('1.0', tk.END).strip()
        password = self.decrypt_password_entry.get()
        try:
            decrypted_key = self.kms.decrypt_key(encrypted_key, password)
            self.decrypted_key_result.delete('1.0', tk.END)
            self.decrypted_key_result.insert(tk.END, decrypted_key)
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed: " + str(e))

    def generate_key_pair(self):
        private_key, public_key = self.kms.generate_key_pair()
        self.private_key_result.delete('1.0', tk.END)
        self.private_key_result.insert(tk.END, private_key)
        self.public_key_result.delete('1.0', tk.END)
        self.public_key_result.insert(tk.END, public_key)

    def sign_key(self):
        private_key = self.private_key_entry.get('1.0', tk.END).strip()
        message = self.message_entry.get()
        try:
            signature = self.kms.sign_key(private_key, message)
            self.signature_result.delete('1.0', tk.END)
            self.signature_result.insert(tk.END, signature)
        except Exception as e:
            messagebox.showerror("Error", "Signing failed: " + str(e))

    def verify_signature(self):
        public_key = self.public_key_entry.get('1.0', tk.END).strip()
        message = self.message_entry.get()
        signature = self.signature_entry.get('1.0', tk.END).strip()
        is_valid = self.kms.verify_signature(public_key, message, signature)
        if is_valid:
            self.verification_result.config(text="Signature Valid", fg="green")
        else:
            self.verification_result.config(text="Signature Invalid", fg="red")

