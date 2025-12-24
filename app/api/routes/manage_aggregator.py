from fastapi import APIRouter, Depends, status, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.models.user import User
from app.models.manage_aggregator import ManageAggregator
from app.core.security import hash_password
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64, json, string, secrets

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def generate_random_password(length=12):
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

@router.post('/api/manage-aggregator', status_code=status.HTTP_201_CREATED)
async def create_manageAggregator(request: Request, db: Session = Depends(get_db)):
    # Print login credentials only after new_agg and password are defined (inside try block)
    # Decrypt incoming payload
    body = await request.json()
    data_b64 = body.get("data")
    if not data_b64:
        raise HTTPException(status_code=400, detail="Missing encrypted data")
    aes_key_raw = os.getenv("AES_GCM_KEY")
    if not aes_key_raw:
        raise HTTPException(status_code=400, detail="AES_GCM_KEY not set in .env")
    key_bytes = aes_key_raw.encode()
    if len(key_bytes) < 32:
        key_bytes = key_bytes.ljust(32, b'0')
    elif len(key_bytes) > 32:
        key_bytes = key_bytes[:32]
    aesgcm = AESGCM(key_bytes)
    combined = base64.b64decode(data_b64)
    nonce = combined[:12]
    ciphertext = combined[12:]
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        agg_dict = json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        error_response = {
            "status": "error",
            "error_code": "DECRYPTION_FAILED",
            "message": f"Decryption failed: {e}",
            "details": {}
        }
        # Encrypt error response
        nonce_resp = os.urandom(12)
        plaintext_resp = json.dumps(error_response, separators=(",", ":")).encode("utf-8")
        ciphertext_resp = AESGCM(key_bytes).encrypt(nonce_resp, plaintext_resp, None)
        encrypted_response = {"data": base64.b64encode(nonce_resp + ciphertext_resp).decode()}
        print("[SERVER] Decrypted error response:", json.dumps(error_response, indent=2))
        return JSONResponse(content=encrypted_response, status_code=400)

    # Generate password, hash it, and encode in base64 for storage
    password = generate_random_password()
    hashed_password = hash_password(password)
    password_b64 = base64.b64encode(hashed_password.encode()).decode()
    print("[DEBUG][Aggregator Creation] Plain password:", password)
    print("[DEBUG][Aggregator Creation] Hashed password:", hashed_password)
    print("[DEBUG][Aggregator Creation] Base64-encoded password:", password_b64)

    try:
        # Add aggregator to DB
        new_agg = ManageAggregator(
            aggregatorName=agg_dict["aggregatorName"],
            contactPersonName=agg_dict["contactPersonName"],
            email=agg_dict["email"],
            mobileNo=agg_dict["mobileNo"],
            location=agg_dict["location"],
            services=agg_dict["services"],
            isDeleted=agg_dict.get("isDeleted", False),
            status=agg_dict.get("status", "Created")
        )

        # Try to add aggregator, handle duplicate
        try:
            db.add(new_agg)
            db.commit()
            db.refresh(new_agg)
        except Exception as e:
            db.rollback()
            if "Duplicate entry" in str(e):
                error_response = {
                    "status": "error",
                    "error_code": "DUPLICATE_AGGREGATOR",
                    "message": "Duplicate entry for aggregator email.",
                    "details": {}
                }
                nonce_resp = os.urandom(12)
                plaintext_resp = json.dumps(error_response, separators=(",", ":")).encode("utf-8")
                ciphertext_resp = AESGCM(key_bytes).encrypt(nonce_resp, plaintext_resp, None)
                encrypted_response = {"data": base64.b64encode(nonce_resp + ciphertext_resp).decode()}
                print("[SERVER] Duplicate aggregator error response:", json.dumps(error_response, indent=2))
                return JSONResponse(content=encrypted_response, status_code=409)
            else:
                raise

        # Try to add user, handle duplicate
        try:
            user = User(
                username=agg_dict["email"],
                email=agg_dict["email"],
                password=password_b64
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        except Exception as e:
            db.rollback()
            if "Duplicate entry" in str(e):
                error_response = {
                    "status": "error",
                    "error_code": "DUPLICATE_USER",
                    "message": "Duplicate entry for user email.",
                    "details": {}
                }
                nonce_resp = os.urandom(12)
                plaintext_resp = json.dumps(error_response, separators=(",", ":")).encode("utf-8")
                ciphertext_resp = AESGCM(key_bytes).encrypt(nonce_resp, plaintext_resp, None)
                encrypted_response = {"data": base64.b64encode(nonce_resp + ciphertext_resp).decode()}
                print("[SERVER] Duplicate user error response:", json.dumps(error_response, indent=2))
                return JSONResponse(content=encrypted_response, status_code=409)
            else:
                raise

        # Print login credentials after new_agg and password are defined
        print("[SERVER] LOGIN CREDENTIALS ===")
        print(f"Username (for login): {agg_dict['email']}")
        print(f"Password (for login): {password}")
        print("=============================")

        # Success response
        response_obj = {
            "message": "Aggregate added successfully",
            "status": "created",
            "data": {
                "temporary_password": password
            }
        }
        # Encrypt success response
        nonce_resp = os.urandom(12)
        plaintext_resp = json.dumps(response_obj, separators=(",", ":")).encode("utf-8")
        ciphertext_resp = AESGCM(key_bytes).encrypt(nonce_resp, plaintext_resp, None)
        encrypted_response = {"data": base64.b64encode(nonce_resp + ciphertext_resp).decode()}
        print("[SERVER] Decrypted success response:", json.dumps(response_obj, indent=2))
        return JSONResponse(content=encrypted_response, status_code=201)
    except Exception as e:
        error_response = {
            "status": "error",
            "error_code": "DB_ERROR",
            "message": f"Database error: {e}",
            "details": {}
        }
        # Encrypt error response
        nonce_resp = os.urandom(12)
        plaintext_resp = json.dumps(error_response, separators=(",", ":")).encode("utf-8")
        ciphertext_resp = AESGCM(key_bytes).encrypt(nonce_resp, plaintext_resp, None)
        encrypted_response = {"data": base64.b64encode(nonce_resp + ciphertext_resp).decode()}
        print("[SERVER] Decrypted error response:", json.dumps(error_response, indent=2))
        return JSONResponse(content=encrypted_response, status_code=400)
