class PaymentEncryptionSystem:
    def __init__(self):
        self.aes_cipher = AESCipher()
        self.rsa_encryption = RSAEncryption()
        self.hmac_signature = HMACSignature(self.aes_cipher.key)

    def encrypt_transaction(self, transaction_details):
        nonce, ciphertext, tag = self.aes_cipher.encrypt(transaction_details)
        encrypted_aes_key = self.rsa_encryption.encrypt_key(self.aes_cipher.key)
        signature = self.hmac_signature.sign_message(transaction_details)
        return {
            "encrypted_aes_key": encrypted_aes_key,
            "nonce": nonce,
            "ciphertext": ciphertext,
            "tag": tag,
            "signature": signature
        }

    def decrypt_transaction(self, encrypted_data):
        decrypted_aes_key = self.rsa_encryption.decrypt_key(encrypted_data['encrypted_aes_key'])
        self.aes_cipher.key = decrypted_aes_key  # Update AES key
        decrypted_transaction = self.aes_cipher.decrypt(encrypted_data['nonce'], encrypted_data['ciphertext'], encrypted_data['tag'])
        signature_valid = self.hmac_signature.verify_signature(decrypted_transaction, encrypted_data['signature'])
        return decrypted_transaction, signature_valid

# Example usage
payment_system = PaymentEncryptionSystem()
transaction = "Payment of $100 to merchant X"
encrypted_data = payment_system.encrypt_transaction(transaction)
print(f"Encrypted Transaction: {encrypted_data}")

decrypted_transaction, is_signature_valid = payment_system.decrypt_transaction(encrypted_data)
print(f"Decrypted Transaction: {decrypted_transaction}")
print(f"Signature Valid: {is_signature_valid}")
