import os
import json
import base64
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

# Config
API_URL = os.getenv("API_URL_DEV", "http://localhost:8000")
LOGIN_ENDPOINT = f"{API_URL}/auth/login"
ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")

# Load .env
load_dotenv(dotenv_path=ENV_PATH)

# --- Minimal login and AES_GCM_KEY update script ---
def normalize_key(key_raw: str) -> bytes:
    key = key_raw.encode("utf-8")
    if len(key) < 32:
        return key.ljust(32, b"0")
    return key[:32]

def decrypt_server_response(data_b64: str, key_raw: str) -> dict:
    key = normalize_key(key_raw)
    raw = base64.b64decode(data_b64)
    nonce = raw[:12]
    ciphertext = raw[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode())

def update_env_aes_key(new_key: str):
    with open(ENV_PATH, "r") as f:
        lines = f.readlines()
    found = False
    for i, line in enumerate(lines):
        if line.startswith("AES_GCM_KEY="):
            lines[i] = f"AES_GCM_KEY={new_key}\n"
            found = True
    if not found:
        lines.append(f"AES_GCM_KEY={new_key}\n")
    with open(ENV_PATH, "w") as f:
        f.writelines(lines)
    print("[INFO] .env updated with new AES_GCM_KEY.")

def main():
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    # If captcha is required, add logic here
    payload = {"username": username, "password": password, "captcha": "bypass"}
    resp = requests.post(LOGIN_ENDPOINT, json=payload)
    if resp.status_code != 200:
        print(f"[LOGIN] Failed: {resp.status_code} {resp.text}")
        return
    data = resp.json()
    if "data" not in data:
        print("[LOGIN] No encrypted data in response.")
        return
    # Decrypt using password as key (or update logic as needed)
    try:
        decrypted = decrypt_server_response(data["data"], password)
        print("[LOGIN] Decrypted response:", json.dumps(decrypted, indent=2))
        access_token = decrypted.get("access_token")
        if not access_token:
            print("[LOGIN] No access_token in decrypted response.")
            return
        update_env_aes_key(access_token)
    except Exception as e:
        print("[ERROR] Failed to decrypt login response:", e)

if __name__ == "__main__":
    main()
