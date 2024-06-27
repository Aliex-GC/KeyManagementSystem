import secrets
import base64
import sympy
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

class KeyManagementSystem:
    def __init__(self):
        self.keys = {}

    def generate_random_number(self, bit_length=256):
        return secrets.randbits(bit_length)

    def generate_large_prime(self, bit_length=256):
        return sympy.randprime(2**(bit_length-1), 2**bit_length)


    def encrypt_key(self, key, password):
        password_bytes = password.encode('utf-8')
        key_bytes = key.encode('utf-8')
        cipher = AES.new(password_bytes[:16], AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(key_bytes)
        return base64.b64encode(nonce + tag + ciphertext).decode('utf-8')

    def decrypt_key(self, encrypted_key, password):
        password_bytes = password.encode('utf-8')
        encrypted_key_bytes = base64.b64decode(encrypted_key.encode('utf-8'))
        nonce = encrypted_key_bytes[:16]
        tag = encrypted_key_bytes[16:32]
        ciphertext = encrypted_key_bytes[32:]
        cipher = AES.new(password_bytes[:16], AES.MODE_EAX, nonce=nonce)
        key_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        return key_bytes.decode('utf-8')

    def generate_key_pair(self, key_size=2048):
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key.decode('utf-8'), public_key.decode('utf-8')

    def sign_key(self, private_key_str, message):
        private_key = RSA.import_key(private_key_str.encode('utf-8'))
        h = SHA256.new(message.encode('utf-8'))
        signature = pkcs1_15.new(private_key).sign(h)
        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, public_key_str, message, signature_str):
        public_key = RSA.import_key(public_key_str.encode('utf-8'))
        h = SHA256.new(message.encode('utf-8'))
        signature = base64.b64decode(signature_str.encode('utf-8'))
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False