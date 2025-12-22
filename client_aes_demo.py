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
    return data["access_token"]

def encrypt_payload(aes_key_b64, payload):
    aesgcm = AESGCM(aes_key_b64)
    nonce = os.urandom(12)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {"data": base64.b64encode(nonce + ciphertext).decode(), "aad": None}

def decrypt_response(aes_key_b64, encrypted_json):
    aesgcm = AESGCM(aes_key_b64)
    data_b64 = encrypted_json["data"]
    combined = base64.b64decode(data_b64)
    nonce = combined[:12]
    ciphertext = combined[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))

# Example usage:

if __name__ == "__main__":
    # Step 1: Login and get access token
    username = "tushar"
    password = "Tushar@123"
    access_token = login(username, password)
    print("Access Token:", access_token)


    # Step 2: Write access_token to .env as AES_GCM_KEY
    with open(".env", "r") as f:
        lines = f.readlines()
    found = False
    for i, line in enumerate(lines):
        if line.startswith("AES_GCM_KEY="):
            lines[i] = f"AES_GCM_KEY={access_token}\n"
            found = True
    if not found:
        lines.append(f"AES_GCM_KEY={access_token}\n")
    with open(".env", "w") as f:
        f.writelines(lines)

    # Use access token as AES key (padded/truncated to 32 bytes)
    token_bytes = access_token.encode()
    if len(token_bytes) < 32:
        aes_key = token_bytes.ljust(32, b'0')
    elif len(token_bytes) > 32:
        aes_key = token_bytes[:32]
    else:
        aes_key = token_bytes
    print("AES Key (hex, 32 bytes):", aes_key.hex())

    # Step 3: Prepare registration payload
    reg_payload = {"username": "newuser", "email": "newuser@example.com", "password": "NewUser@123"}
    print("Plain registration payload:", reg_payload)
    encrypted_reg_payload = encrypt_payload(aes_key, reg_payload)
    print("Encrypted registration payload:", encrypted_reg_payload)

    # Step 4: Call /auth/register with encrypted payload
    url = f"{BASE_URL}/auth/register"
    resp = requests.post(url, json=encrypted_reg_payload)
    resp.raise_for_status()
    encrypted_response = resp.json()
    print("Encrypted server response:", encrypted_response)
    decrypted_response = decrypt_response(aes_key, encrypted_response)
    print("Decrypted server response:", decrypted_response)
