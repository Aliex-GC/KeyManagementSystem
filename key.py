import secrets
import base64
import sympy
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from sha256 import to_sha256, str_to_hash

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
        msg_bytes = message.encode('utf-8')
        sha256_string = to_sha256(msg_bytes)
        sha256_hash = str_to_hash(sha256_string)
        signature = pkcs1_15.new(private_key).sign(sha256_hash)
        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, public_key_str, message, signature_str):
        public_key = RSA.import_key(public_key_str.encode('utf-8'))
        msg_bytes = message.encode('utf-8')
        sha256_string = to_sha256(msg_bytes)
        h = str_to_hash(sha256_string)
        signature = base64.b64decode(signature_str.encode('utf-8'))
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
        


private_key_str = """
-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA3jfPpPS42Xqjto3x
CX34wz3cz4RRNA8fXl/LHCSLiEta1z5VO/KCF8Qc0GreX6OAybyu8nPupk0zvk1x
ymCQOQIDAQABAkBlp2pZr4mQE0YpEK2fBf1ycy47z+/FvNVAutmTOjSKV/P8qJBP
zzho4x9BpItSAqv3kN+UpEAdIV192N+n7AfBAiEA+TYFFlQMuqVu1PF6ZhFciTpU
QNsPBLTErMakisTeF6UCIQDkRYs/Cg7DuQGQGr+VlwNAtBWb2P4QOH8/nz5bUPaS
BQIhAKU7B8xyFa56mS1encSmpi/mGI6XrzFzmSLk4ZuQQ6BxAiBPSEAmsu2R2O3M
CR5FbF+611EyAdmr9JNtm3di6+nXqQIgf32HuMWFZq7S0CKhtJvHzSOP+/Uw+N+t
0erGDYfXTK4=
-----END PRIVATE KEY-----
"""

public_key_str = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Ih5p1JnO0lkDd
-----END PUBLIC KEY-----
"""

message = "This is a test message."

# 实例化类

# kms = KeyManagementSystem()

# # 签名示例
# signature = kms.sign_key(private_key_str, message)
# print("Signature:", signature)

# # 验证签名示例
# is_valid = kms.verify_signature(public_key_str, message, signature)
# print("Signature verification:", is_valid)