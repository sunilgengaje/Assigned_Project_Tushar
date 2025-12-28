
import os
import json
import base64
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
import hashlib

# --- Your aggregator payload ---
payload = {
    "aggregatorName": "Acme Aggregator",
    "contactPersonName": "John Doe",
    "email": "b28@example.com",
    "mobileNo": "9876543210",
    "location": "Mumbai",
    "services": "Logistics, Warehousing",
    "isDeleted": False,
    "status": "Created"
}

# --- Load .env and get JWT token (access token) ---
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
dotenv_path = os.path.join(project_root, ".env")
load_dotenv(dotenv_path=dotenv_path)
jwt_token = os.environ.get("JWT_TOKEN")
if not jwt_token:
    raise SystemExit("Set JWT_TOKEN in .env (client)")

# --- Derive AES key from access token (SHA-256) ---
key_bytes = hashlib.sha256(jwt_token.encode()).digest()  # 32 bytes for AES-256-GCM
aesgcm = AESGCM(key_bytes)

# --- Encrypt the payload ---
nonce = os.urandom(12)
plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
ciphertext = aesgcm.encrypt(nonce, plaintext, None)
data = base64.b64encode(nonce + ciphertext).decode()

# --- Send the request ---
url = "http://127.0.0.1:8000/api/manage-aggregator"
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {jwt_token}"
}
request_body = {"data": data}
response = requests.post(url, headers=headers, json=request_body)

# --- Decrypt the response ---
try:
    server_json = response.json()
    if "data" in server_json:
        combined = base64.b64decode(server_json["data"])
        nonce_resp, ct_resp = combined[:12], combined[12:]
        pt_resp = aesgcm.decrypt(nonce_resp, ct_resp, None)
        resp_obj = json.loads(pt_resp.decode("utf-8"))
        print("Response:", resp_obj)
    else:
        print("Non-encrypted response:", server_json)
except Exception as e:
    print("Decryption/parse error:", e)

# --- Secure projections endpoint call ---
def call_secure_projections():
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "accept": "application/json"
    }
    url = "http://127.0.0.1:8000/secure/api/applications/1/aggregators/1/projections"
    resp = requests.get(url, headers=headers)
    try:
        resp_json = resp.json()
        if "data" in resp_json:
            # Decrypt using the same AES key
            combined = base64.b64decode(resp_json["data"])
            nonce, ct = combined[:12], combined[12:]
            pt = aesgcm.decrypt(nonce, ct, None)
            print("Secure projections response:", json.loads(pt.decode("utf-8")))
    except Exception as e:
        print("Secure projections decrypt error:", e)

if __name__ == "__main__":
    call_secure_projections()
