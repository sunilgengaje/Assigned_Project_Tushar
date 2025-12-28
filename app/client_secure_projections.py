

import os
import json
import base64
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import argparse
from api_config import APIConfig

# Allow setting applicationId and aggregatorId via command line
parser = argparse.ArgumentParser(description="Dynamic projections client with login")
parser.add_argument("--application-id", type=str, default=os.getenv("APPLICATION_ID", "1"), help="Application ID")
parser.add_argument("--aggregator-id", type=str, default=os.getenv("AGGREGATOR_ID", "1"), help="Aggregator ID")
parser.add_argument("--username", type=str, default=os.getenv("LOGIN_USERNAME", "testuser@example.com"), help="Login username")
parser.add_argument("--password", type=str, default=os.getenv("LOGIN_PASSWORD", "testpass"), help="Login password")
args = parser.parse_args()
APPLICATION_ID = args.application_id
AGGREGATOR_ID = args.aggregator_id
LOGIN_USERNAME = args.username
LOGIN_PASSWORD = args.password

# Use APIConfig for base URL and endpoints
config = APIConfig()

# -------------------------------------------------
# AES helper
# -------------------------------------------------
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

# -------------------------------------------------
# Login and extract JWT/AES key
# -------------------------------------------------
def login_and_get_tokens():
    login_url = config.LOGIN
    payload = {
        "username": LOGIN_USERNAME,
        "password": LOGIN_PASSWORD,
        "captcha": "bypass"  # If captcha is required, handle accordingly
    }
    resp = requests.post(login_url, json=payload)
    if resp.status_code != 200:
        print(f"[LOGIN] Failed: {resp.status_code} {resp.text}")
        exit(1)
    data = resp.json()
    # Expecting base64 encoded JWT and AES_GCM_KEY in response
    jwt_b64 = data.get("jwt_token") or data.get("jwt") or data.get("token")
    aes_key = data.get("aes_gcm_key") or data.get("aes_key") or data.get("AES_GCM_KEY")
    if not jwt_b64 or not aes_key:
        print("[LOGIN] Missing jwt_token or AES_GCM_KEY in response.")
        print("Response:", data)
        exit(1)
    # Decode base64 JWT if needed
    try:
        jwt_token = base64.b64decode(jwt_b64).decode()
    except Exception:
        jwt_token = jwt_b64  # If not base64, use as is
    return jwt_token, aes_key

if __name__ == "__main__":
    print("[LOGIN] Logging in to fetch JWT and AES key...")
    jwt_token, aes_gcm_key = login_and_get_tokens()
    print("[LOGIN] JWT and AES key obtained.")

    url = config.PROJECTIONS(APPLICATION_ID, AGGREGATOR_ID)
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = requests.get(url, headers=headers)
    print(f"[HTTP] Status: {response.status_code}")
    if response.status_code != 200:
        print(response.text)
        exit(1)
    payload = response.json()
    print("[RAW RESPONSE]")
    print(json.dumps(payload, indent=2))
    # Decrypt if encrypted
    if "data" in payload:
        try:
            decrypted = decrypt_server_response(payload["data"], aes_gcm_key)
            print("\n[DECRYPTED RESPONSE]")
            print(json.dumps(decrypted, indent=2))
        except Exception as e:
            print("❌ Decryption failed:", e)
    else:
        print("\n[PLAIN RESPONSE]")
        print(json.dumps(payload, indent=2))

# -------------------------------------------------
# AES helper
# -------------------------------------------------
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


# -------------------------------------------------
# Call API
# -------------------------------------------------
url = f"{API_URL}/api/applications/{APPLICATION_ID}/aggregators/{AGGREGATOR_ID}/projections"

headers = {}
if JWT_TOKEN:
    headers["Authorization"] = f"Bearer {JWT_TOKEN}"

response = requests.get(url, headers=headers)

print(f"[HTTP] Status: {response.status_code}")

if response.status_code != 200:
    print(response.text)
    exit(1)

payload = response.json()
print("[RAW RESPONSE]")
print(json.dumps(payload, indent=2))

# -------------------------------------------------
# Decrypt if encrypted
# -------------------------------------------------
if "data" in payload:
    try:
        decrypted = decrypt_server_response(payload["data"], AES_GCM_KEY)
        print("\n[DECRYPTED RESPONSE]")
        print(json.dumps(decrypted, indent=2))
    except Exception as e:
        print("❌ Decryption failed:", e)
else:
    print("\n[PLAIN RESPONSE]")
    print(json.dumps(payload, indent=2))
