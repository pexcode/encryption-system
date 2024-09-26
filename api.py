from flask import Flask, request, jsonify
from aes_cipher import AESCipher
from rsa_encryption import RSAEncryption
from hmac_signature import HMACSignature
import json

app = Flask(__name__)
aes_cipher = AESCipher()
rsa_encryption = RSAEncryption()
hmac_signature = HMACSignature(aes_cipher.key)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json  #  JSON data
    json_data = json.dumps(data)  # convert JSON
    nonce, ciphertext, tag = aes_cipher.encrypt(json_data)
    encrypted_aes_key = rsa_encryption.encrypt_key(aes_cipher.key)
    signature = hmac_signature.sign_message(json_data)
    return jsonify({
        'encrypted_aes_key': encrypted_aes_key.hex(),
        'nonce': nonce.hex(),
        'ciphertext': ciphertext.hex(),
        'tag': tag.hex(),
        'signature': signature
    })

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_data = request.json
    decrypted_aes_key = rsa_encryption.decrypt_key(bytes.fromhex(encrypted_data['encrypted_aes_key']))
    aes_cipher.key = decrypted_aes_key
    nonce = bytes.fromhex(encrypted_data['nonce'])
    ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
    tag = bytes.fromhex(encrypted_data['tag'])
    decrypted_json = aes_cipher.decrypt(nonce, ciphertext, tag)
    signature_valid = hmac_signature.verify_signature(decrypted_json, encrypted_data['signature'])
    return jsonify({
        'decrypted_data': json.loads(decrypted_json),  #  convert   JSON    
        'signature_valid': signature_valid
    })

if __name__ == '__main__':
    app.run(debug=True)
