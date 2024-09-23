from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

class ChaCha20Poly1305Cipher:
    def __init__(self):
        self.key = get_random_bytes(32)  # 256-bit key

    def encrypt(self, data):
        cipher = ChaCha20_Poly1305.new(key=self.key)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
        return nonce, ciphertext, tag

    def decrypt(self, nonce, ciphertext, tag):
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        try:
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted_data.decode('utf-8')
        except ValueError:
            return "Invalid decryption"
