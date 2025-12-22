# app/client_example.py
from pathlib import Path
from dotenv import load_dotenv
import os, base64, json, requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---- deterministic .env load ----
project_root = Path(__file__).resolve().parents[1]
dotenv_path = project_root / ".env"

# Use correct env var name
print(f"[DEBUG] Loading .env from: {dotenv_path}")
load_dotenv(dotenv_path=str(dotenv_path))
aes_key_raw_debug = os.environ.get("AES_GCM_KEY")
print(f"[DEBUG] AES_GCM_KEY from os.environ: {aes_key_raw_debug}")

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
KEY = key_bytes
BASE = "http://127.0.0.1:8000"

def encrypt(obj):
    import os, json, base64
    nonce = os.urandom(12)
    pt = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ct = AES.encrypt(nonce, pt, None)
    return {"data": base64.b64encode(nonce + ct).decode(), "aad": None}

def decrypt(blob):
    import base64, json
    combined = base64.b64decode(blob["data"])
    nonce, ct = combined[:12], combined[12:]
    pt = AES.decrypt(nonce, ct, None)
    return json.loads(pt.decode("utf-8"))

if __name__ == "__main__":
    payload = {
  "username": "sunilnew123",
  "email": "sunilnew123@example.com",
  "full_name": "sunil",
  "password": "1234"
}


    blob = encrypt(payload)

    # PRINT THE FULL ENCRYPTED PAYLOAD (exact JSON sent to server)
    print("\n=== RAW ENCRYPTED PAYLOAD (FULL) ===")
    print(json.dumps(blob, indent=2))
    print("====================================\n")



    # debug before sending
    print("=== CLIENT DEBUG BEFORE SEND ===")
    print("AES key (masked):", aes_key_raw[:6] + "..." + aes_key_raw[-4:])
    print("AES key bytes length:", len(KEY))
    print("Outgoing blob keys:", list(blob.keys()))
    print("Outgoing data length (chars):", len(blob["data"]))
    print("Outgoing data prefix:", blob["data"][:80])
    print("================================")

    resp = requests.post(f"{BASE}/auth/register", json=blob)

    # always print server raw JSON if possible
    try:
        server_json = resp.json()
    except Exception:
        server_json = resp.text

    print("HTTP status:", resp.status_code)
    print("Server raw response:", server_json)

    # Attempt to decrypt server response if it looks like the encrypted shape
    if isinstance(server_json, dict) and "data" in server_json:
        try:
            plain = decrypt(server_json)
            print("Decrypted server response (JSON):", json.dumps(plain, indent=2, ensure_ascii=False))
        except Exception as e:
            print("Failed to decrypt server response:", repr(e))
            # show server blob details for diagnosis
            print("Server blob.data length (chars):", len(server_json.get("data","")))
            print("Server blob.data prefix:", server_json.get("data","")[:80])
    else:
        print("Server did not return encrypted JSON; printed raw above.")

    # Now raise for non-2xx if you want a hard failure
    try:
        resp.raise_for_status()
    except Exception as e:
        # re-raise with more context
        raise RuntimeError(f"Request failed: {e}. See decrypted server response (if any) above.") from e
