from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

class ChaCha20Cipher:
    def __init__(self):
        self.key = get_random_bytes(32)  # 256-bit key

    def encrypt(self, data):
        cipher = ChaCha20.new(key=self.key)
        ciphertext = cipher.encrypt(data.encode('utf-8'))
        return cipher.nonce, ciphertext

    def decrypt(self, nonce, ciphertext):
        cipher = ChaCha20.new(key=self.key, nonce=nonce)
        decrypted_data = cipher.decrypt(ciphertext)
        return decrypted_data.decode('utf-8')
