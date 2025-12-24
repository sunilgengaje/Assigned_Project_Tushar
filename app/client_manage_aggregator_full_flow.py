from dotenv import load_dotenv
import os
import base64
import json
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Your aggregator payload
payload = {
    "aggregatorName": "Acme Aggregator",
    "contactPersonName": "John Doe",
    "email": "b1@example.com",
    "mobileNo": "9876543210",
    "location": "Mumbai",
    "services": "Logistics, Warehousing",
    "isDeleted": False,
    "status": "Created"
}

# Load .env and get AES key
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
dotenv_path = os.path.join(project_root, ".env")
load_dotenv(dotenv_path=dotenv_path)
aes_key_raw = os.environ.get("AES_GCM_KEY")
if not aes_key_raw:
    raise SystemExit("Set AES_GCM_KEY in .env (client)")
key_bytes = aes_key_raw.encode("utf-8")
if len(key_bytes) < 32:
    key_bytes = key_bytes.ljust(32, b'0')
elif len(key_bytes) > 32:
    key_bytes = key_bytes[:32]
AES = AESGCM(key_bytes)

# Encrypt the payload
nonce = os.urandom(12)
pt = json.dumps(payload, separators=(",", ":")).encode("utf-8")
ct = AES.encrypt(nonce, pt, None)
data = base64.b64encode(nonce + ct).decode()

# Send the request
url = "http://127.0.0.1:8000/api/manage-aggregator"
headers = {"Content-Type": "application/json"}
request_body = {"data": data}
response = requests.post(url, headers=headers, json=request_body)

print("HTTP status:", response.status_code)
print("Encrypted server response:", response.text)

# Decrypt the response
try:
    server_json = response.json()
    if "data" in server_json:
        combined = base64.b64decode(server_json["data"])
        nonce_resp, ct_resp = combined[:12], combined[12:]
        pt_resp = AES.decrypt(nonce_resp, ct_resp, None)
        resp_obj = json.loads(pt_resp.decode("utf-8"))
        print("Decrypted server response (JSON):", json.dumps(resp_obj, indent=2))
        # Print all aggregator fields clearly
        print("\n=== AGGREGATOR DETAILS ===")
        print("Aggregator ID:", resp_obj.get("aggregatorId"))
        print("Aggregator Name:", resp_obj.get("aggregatorName"))
        print("Contact Person Name:", resp_obj.get("contactPersonName"))
        print("Email:", resp_obj.get("email"))
        print("Mobile No:", resp_obj.get("mobileNo"))
        print("Location:", resp_obj.get("location"))
        print("Services:", resp_obj.get("services"))
        print("isDeleted:", resp_obj.get("isDeleted"))
        print("Status:", resp_obj.get("status"))
        print("==========================")
        # Print login credentials for user
        print("\n=== LOGIN CREDENTIALS ===")
        print("Username (for login):", resp_obj.get("email"))
        if "password" in resp_obj:
            print("Password (for login):", resp_obj["password"])
        else:
            print("Password (for login): [not returned in response]")
        print("=========================")
    else:
        print("Server did not return encrypted JSON; printed raw above.")
except Exception as e:
    print("Failed to decrypt server response:", repr(e))
