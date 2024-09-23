import hmac
import hashlib

class HMACSignature:
    def __init__(self, key):
        self.key = key

    def sign_message(self, message):
        signature = hmac.new(self.key, message.encode('utf-8'), hashlib.sha256).hexdigest()
        return signature

    def verify_signature(self, message, signature):
        expected_signature = self.sign_message(message)
        return hmac.compare_digest(expected_signature, signature)
