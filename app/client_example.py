from pathlib import Path
from dotenv import load_dotenv
import os, base64, json, requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---- deterministic .env load ----
project_root = Path(__file__).resolve().parents[1]
dotenv_path = project_root / ".env"
load_dotenv(dotenv_path=str(dotenv_path))
aes_key_raw = os.environ.get("AES_GCM_KEY")
if not aes_key_raw:
    raise SystemExit("Set AES_GCM_KEY in .env (client)")
# Pad or truncate to 32 bytes
key_bytes = aes_key_raw.encode("utf-8")
if len(key_bytes) < 32:
    key_bytes = key_bytes.ljust(32, b'0')
elif len(key_bytes) > 32:
    key_bytes = key_bytes[:32]
AES = AESGCM(key_bytes)
BASE = "http://127.0.0.1:8000"

def encrypt(obj):
    nonce = os.urandom(12)
    pt = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ct = AES.encrypt(nonce, pt, None)
    return {"data": base64.b64encode(nonce + ct).decode(), "aad": None}

def decrypt(blob):
    combined = base64.b64decode(blob["data"])
    nonce, ct = combined[:12], combined[12:]
    pt = AES.decrypt(nonce, ct, None)
    return json.loads(pt.decode("utf-8"))

if __name__ == "__main__":
    payload = {
        "username": "sand1",
        "email": "sand1@example.com",
        "full_name": "sand",
        "password": "Password@123"
    }
    blob = encrypt(payload)
    print("\n=== RAW ENCRYPTED PAYLOAD (FULL) ===")
    print(json.dumps(blob, indent=2))
    print("====================================\n")
    resp = requests.post(f"{BASE}/auth/register", json=blob)
    try:
        server_json = resp.json()
    except Exception:
        server_json = resp.text
    print("HTTP status:", resp.status_code)
    print("Server raw response:", server_json)
    if isinstance(server_json, dict) and "data" in server_json:
        try:
            plain = decrypt(server_json)
            print("Decrypted server response (JSON):", json.dumps(plain, indent=2, ensure_ascii=False))
        except Exception as e:
            print("Failed to decrypt server response:", repr(e))
    else:
        print("Server did not return encrypted JSON; printed raw above.")
    resp.raise_for_status()
