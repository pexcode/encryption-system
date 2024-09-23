# Advanced Encryption System

This is an open-source project for developing a secure encryption system that relies on modern techniques to encrypt and decrypt objects and arrays. The system has been developed by Mussab Muhaimeed and Company https://pexcode.com with the assistance of artificial intelligence.

## Description

This system allows you to encrypt sensitive data such as payment transactions and emails, using advanced encryption algorithms like AES, RSA, and ChaCha20-Poly1305 to ensure security.

## Usage

### useing request encrypt
```bash
curl -X POST http://127.0.0.1:5000/encrypt \
-H "Content-Type: application/json" \
-d '{"transaction_id": "12345", "amount": 100.0, "currency": "USD", "merchant": "Merchant X"}'



### useing request decrypt
```bash
curl -X POST http://127.0.0.1:5000/decrypt \
-H "Content-Type: application/json" \
-d '{"encrypted_aes_key": "ENCRYPTED_KEY", "nonce": "NONCE", "ciphertext": "CIPHERTEXT", "tag": "TAG", "signature": "SIGNATURE"}'



### Requirements

Before getting started, ensure you have the required libraries installed:

```bash
pip install pycryptodome Flask




