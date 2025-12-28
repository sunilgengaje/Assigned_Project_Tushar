import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

# Config
ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(dotenv_path=ENV_PATH)

def normalize_key(key_raw: str) -> bytes:
    key = key_raw.encode("utf-8")
    if len(key) < 32:
        return key.ljust(32, b"0")
    return key[:32]

def decrypt_login_response(data_b64: str, key_raw: str) -> dict:
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
    print("Paste the encrypted 'data' value from the login API response (Swagger):")
    encrypted_data = input().strip()
    print("Enter the password (or key) used for decryption:")
    key = input().strip()
    try:
        decrypted = decrypt_login_response(encrypted_data, key)
        print("[DECRYPTED LOGIN RESPONSE]:\n", json.dumps(decrypted, indent=2))
        access_token = decrypted.get("access_token")
        if not access_token:
            print("[ERROR] No access_token in decrypted response.")
            return
        update_env_aes_key(access_token)
    except Exception as e:
        print("[ERROR] Failed to decrypt login response:", e)

if __name__ == "__main__":
    main()
