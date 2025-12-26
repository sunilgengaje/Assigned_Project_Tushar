# All imports at the top
from fastapi import APIRouter, Depends, status, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from app.db.session import SessionLocal

from fastapi import APIRouter, Depends, status, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.models.manage_aggregator import ManageAggregator
from app.models.manage_aggregator_backup import ManageAggregatorBackup
from app.core.security import hash_password
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64, json, string, secrets
from datetime import datetime

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
    try:
        db.commit()
        db.refresh(agg)
        # Mirror to backup
        backup_agg = ManageAggregatorBackup(
            aggregatorId=agg.aggregatorId,
            aggregatorName=agg.aggregatorName,
            contactPersonName=agg.contactPersonName,
            email=agg.email,
            mobileNo=agg.mobileNo,
            location=agg.location,
            services=agg.services,
            isDeleted=agg.isDeleted,
            status=agg.status,
            password=agg.password,
            is_logged_in=agg.is_logged_in,
            password_history=agg.password_history,
            failed_login_attempts=agg.failed_login_attempts,
            lockout_until=agg.lockout_until,
            backup_timestamp=datetime.utcnow().isoformat()
        )
        db.add(backup_agg)
        db.commit()
        # Success response
        response_obj = {"message": "Aggregator updated successfully", "status": "updated"}
        nonce_resp = os.urandom(12)
        plaintext_resp = json.dumps(response_obj, separators=(",", ":")).encode("utf-8")
        ciphertext_resp = AESGCM(key_bytes).encrypt(nonce_resp, plaintext_resp, None)
        encrypted_response = {"data": base64.b64encode(nonce_resp + ciphertext_resp).decode()}
        print("[SERVER] Decrypted success response:", json.dumps(response_obj, indent=2))
        return JSONResponse(content=encrypted_response, status_code=200)
    except Exception as e:
        db.rollback()
        return generic_error_response(f"Database error: {e}", code="DB_ERROR", status_code=400)

# Delete aggregator endpoint
@router.delete('/api/manage-aggregator/{aggregator_id}', status_code=status.HTTP_200_OK)
async def delete_manageAggregator(aggregator_id: int, db: Session = Depends(get_db)):
    aes_key_raw = os.getenv("AES_GCM_KEY")
    def generic_error_response(message, code="GENERIC_ERROR", status_code=400, details=None):
        err = {
            "status": "error",
            "error_code": code,
            "message": message,
            "details": details or {}
        }
        nonce_resp = os.urandom(12)
        key_bytes = aes_key_raw.encode()
        if len(key_bytes) < 32:
            key_bytes = key_bytes.ljust(32, b'0')
        elif len(key_bytes) > 32:
            key_bytes = key_bytes[:32]
        ciphertext_resp = AESGCM(key_bytes).encrypt(nonce_resp, json.dumps(err, separators=(",", ":")).encode("utf-8"), None)
        encrypted_response = {"data": base64.b64encode(nonce_resp + ciphertext_resp).decode()}
        print(f"[SERVER] Encrypted error response: {json.dumps(err, indent=2)}")
        return JSONResponse(content=encrypted_response, status_code=status_code)
    if not aes_key_raw:
        return generic_error_response("AES_GCM_KEY not set in .env", code="MISSING_KEY", status_code=400)
    key_bytes = aes_key_raw.encode()
    if len(key_bytes) < 32:
        key_bytes = key_bytes.ljust(32, b'0')
    elif len(key_bytes) > 32:
        key_bytes = key_bytes[:32]
    agg = db.query(ManageAggregator).filter(ManageAggregator.aggregatorId == aggregator_id).first()
    if not agg:
        return generic_error_response("Aggregator not found", code="NOT_FOUND", status_code=404)
    try:
        # Mirror to backup before delete
        backup_agg = ManageAggregatorBackup(
            aggregatorId=agg.aggregatorId,
            aggregatorName=agg.aggregatorName,
            contactPersonName=agg.contactPersonName,
            email=agg.email,
            mobileNo=agg.mobileNo,
            location=agg.location,
            services=agg.services,
            isDeleted=agg.isDeleted,
            status=agg.status,
            password=agg.password,
            is_logged_in=agg.is_logged_in,
            password_history=agg.password_history,
            failed_login_attempts=agg.failed_login_attempts,
            lockout_until=agg.lockout_until,
            backup_timestamp=datetime.utcnow().isoformat()
        )
        db.add(backup_agg)
        db.delete(agg)
        db.commit()
        # Success response
        response_obj = {"message": "Aggregator deleted successfully", "status": "deleted"}
        nonce_resp = os.urandom(12)
        plaintext_resp = json.dumps(response_obj, separators=(",", ":")).encode("utf-8")
        ciphertext_resp = AESGCM(key_bytes).encrypt(nonce_resp, plaintext_resp, None)
        encrypted_response = {"data": base64.b64encode(nonce_resp + ciphertext_resp).decode()}
        print("[SERVER] Decrypted success response:", json.dumps(response_obj, indent=2))
        return JSONResponse(content=encrypted_response, status_code=200)
    except Exception as e:
        db.rollback()
        return generic_error_response(f"Database error: {e}", code="DB_ERROR", status_code=400)
from fastapi import APIRouter, Depends, status, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.models.manage_aggregator import ManageAggregator
from app.models.manage_aggregator_backup import ManageAggregatorBackup
from app.core.security import hash_password
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64, json, string, secrets


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

router = APIRouter()

def generate_random_password(length=12):
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

@router.post('/api/manage-aggregator', status_code=status.HTTP_201_CREATED)
async def create_manageAggregator(request: Request, db: Session = Depends(get_db)):
    # Print login credentials only after new_agg and password are defined (inside try block)
    # Decrypt incoming payload
    body = await request.json()
    data_b64 = body.get("data")
    aes_key_raw = os.getenv("AES_GCM_KEY")
    def generic_error_response(message, code="GENERIC_ERROR", status_code=400, details=None):
        err = {
            "status": "error",
            "error_code": code,
            "message": message,
            "details": details or {}
        }
        nonce_resp = os.urandom(12)
        plaintext_resp = json.dumps(err, separators=(",", ":")).encode("utf-8")
        ciphertext_resp = AESGCM(key_bytes).encrypt(nonce_resp, plaintext_resp, None)
        encrypted_response = {"data": base64.b64encode(nonce_resp + ciphertext_resp).decode()}
        print(f"[SERVER] Encrypted error response: {json.dumps(err, indent=2)}")
        return JSONResponse(content=encrypted_response, status_code=status_code)

    if not data_b64:
        return generic_error_response("Missing encrypted data", code="MISSING_DATA", status_code=400)
    if not aes_key_raw:
        return generic_error_response("AES_GCM_KEY not set in .env", code="MISSING_KEY", status_code=400)
    key_bytes = aes_key_raw.encode()
    if len(key_bytes) < 32:
        key_bytes = key_bytes.ljust(32, b'0')
    elif len(key_bytes) > 32:
        key_bytes = key_bytes[:32]
    aesgcm = AESGCM(key_bytes)
    try:
        combined = base64.b64decode(data_b64)
        nonce = combined[:12]
        ciphertext = combined[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        agg_dict = json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        return generic_error_response(f"Decryption failed: {e}", code="DECRYPTION_FAILED", status_code=400)

    # Generate password, hash it, and encode in base64 for storage
    password = generate_random_password()
    hashed_password = hash_password(password)
    password_b64 = base64.b64encode(hashed_password.encode()).decode()
    print("[DEBUG][Aggregator Creation] Plain password:", password)
    print("[DEBUG][Aggregator Creation] Hashed password:", hashed_password)
    print("[DEBUG][Aggregator Creation] Base64-encoded password:", password_b64)

    import datetime
    try:
        # Add aggregator/user to DB (single table)
        new_agg = ManageAggregator(
            aggregatorName=agg_dict["aggregatorName"],
            contactPersonName=agg_dict["contactPersonName"],
            email=agg_dict["email"],
            mobileNo=agg_dict["mobileNo"],
            location=agg_dict["location"],
            services=agg_dict["services"],
            isDeleted=agg_dict.get("isDeleted", False),
            status=agg_dict.get("status", "Created"),
            password=password_b64,
            is_logged_in='N',
            password_history=json.dumps([hashed_password]),
            failed_login_attempts=0,
            lockout_until=None
        )
        backup_agg = ManageAggregatorBackup(
            aggregatorName=agg_dict["aggregatorName"],
            contactPersonName=agg_dict["contactPersonName"],
            email=agg_dict["email"],
            mobileNo=agg_dict["mobileNo"],
            location=agg_dict["location"],
            services=agg_dict["services"],
            isDeleted=agg_dict.get("isDeleted", False),
            status=agg_dict.get("status", "Created"),
            password=password_b64,
            is_logged_in='N',
            password_history=json.dumps([hashed_password]),
            failed_login_attempts=0,
            lockout_until=None,
            backup_timestamp=datetime.datetime.utcnow().isoformat()
        )
        try:
            db.add(new_agg)
            db.add(backup_agg)
            db.commit()
            db.refresh(new_agg)
        except Exception as e:
            db.rollback()
            if "Duplicate entry" in str(e):
                return generic_error_response("Duplicate entry for email.", code="DUPLICATE_ENTRY", status_code=409)
            else:
                return generic_error_response(f"Database error: {e}", code="DB_ERROR", status_code=400)

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
        return generic_error_response(f"Database error: {e}", code="DB_ERROR", status_code=400)
