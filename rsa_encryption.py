from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class RSAEncryption:
    def __init__(self, key_size=2048):
        self.private_key = RSA.generate(key_size)
        self.public_key = self.private_key.publickey()

    def encrypt_key(self, aes_key):
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        encrypted_key = cipher_rsa.encrypt(aes_key)
        return encrypted_key

    def decrypt_key(self, encrypted_key):
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        decrypted_key = cipher_rsa.decrypt(encrypted_key)
        return decrypted_key
