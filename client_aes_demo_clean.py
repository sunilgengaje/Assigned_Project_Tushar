import requests
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

BASE_URL = "http://localhost:8000"

def login(username, password):
    payload = {"username": username, "password": password}
    url = f"{BASE_URL}/auth/login"
    resp = requests.post(url, json=payload)
    resp.raise_for_status()
    data = resp.json()
    return data["access_token"], data["aes_key"]

def encrypt_payload(aes_key_b64, payload):
    key = base64.b64decode(aes_key_b64)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {"data": base64.b64encode(nonce + ciphertext).decode(), "aad": None}

def decrypt_response(aes_key_b64, encrypted_json):
    key = base64.b64decode(aes_key_b64)
    aesgcm = AESGCM(key)
    data_b64 = encrypted_json["data"]
    combined = base64.b64decode(data_b64)
    nonce = combined[:12]
    ciphertext = combined[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))

if __name__ == "__main__":
    username = "tushar"
    password = "Tushar@123"

    # 1. Login and get tokens
    access_token, aes_key_b64 = login(username, password)
    print("Access Token:", access_token)
    print("AES Key (base64):", aes_key_b64)

    # 2. Encrypt your request payload
    payload = {"foo": "bar"}
    encrypted_payload = encrypt_payload(aes_key_b64, payload)

    # 3. Send encrypted request to a secure endpoint
    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"{BASE_URL}/secure/your-endpoint"
    resp = requests.post(url, json=encrypted_payload, headers=headers)
    resp.raise_for_status()

    # 4. Decrypt the encrypted response
    encrypted_response = resp.json()
    decrypted = decrypt_response(aes_key_b64, encrypted_response)
    print("Decrypted response:", decrypted)
