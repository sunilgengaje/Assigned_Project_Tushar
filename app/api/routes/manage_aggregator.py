
import os

import hashlib
import json
import base64
import string
import secrets
from datetime import datetime
from fastapi import APIRouter, Request, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.models.manage_aggregator import ManageAggregator
from app.models.manage_aggregator_backup import ManageAggregatorBackup
from app.core.security import hash_password
from app.db.session import SessionLocal  # Ensure SessionLocal is imported
from app.api_logger import APILogger
logger = APILogger()

router = APIRouter(prefix="/api")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def generate_random_password(length=12):
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

from app.email.common import send_password_email

# --- Helper functions for AES key normalization, encrypted response, and error ---
def normalize_aes_key(aes_key_raw):
    key_bytes = aes_key_raw.encode()
    if len(key_bytes) < 32:
        key_bytes = key_bytes.ljust(32, b'0')
    elif len(key_bytes) > 32:
        key_bytes = key_bytes[:32]
    return key_bytes

def encrypted_response(obj, key_bytes, status_code=200):
    nonce = os.urandom(12)
    plaintext = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key_bytes).encrypt(nonce, plaintext, None)
    encrypted = {"data": base64.b64encode(nonce + ciphertext).decode()}
    logger.log_decrypted_response(obj, endpoint="encrypted_response")
    logger.log_encrypted_response(encrypted, endpoint="encrypted_response")
    return JSONResponse(content=encrypted, status_code=status_code)

def generic_error(message, code, key_bytes, status_code=400, details=None):
    err = {
        "status": "error",
        "error_code": code,
        "message": message,
        "details": details or {}
    }
    return encrypted_response(err, key_bytes, status_code)



@router.post('/manage-aggregator', status_code=status.HTTP_201_CREATED)
async def create_manageAggregator(request: Request, db: Session = Depends(get_db)):
    agg_dict = None  # Ensure agg_dict is always defined
    key_bytes = None
    try:
        import sys, traceback
        body = await request.json()
        print("[DEBUG] Request body:", body, file=sys.stderr)
        data_b64 = body.get("data")
        # Extract access token from Authorization header
        auth_header = request.headers.get("authorization")
        if not auth_header or not auth_header.lower().startswith("bearer "):
            return JSONResponse({"error": "Missing or invalid Authorization header"}, 401)
        access_token = auth_header.split(" ", 1)[1]
        # Derive AES key from access token using SHA-256
        key_bytes = hashlib.sha256(access_token.encode()).digest()
        if not data_b64:
            return generic_error("Missing encrypted data", "MISSING_DATA", key_bytes)
        raw = base64.b64decode(data_b64)
        nonce, ciphertext = raw[:12], raw[12:]
        plaintext = AESGCM(key_bytes).decrypt(nonce, ciphertext, None)
        print("[DEBUG] Decrypted plaintext:", plaintext, file=sys.stderr)
        agg_dict = json.loads(plaintext.decode())
        print("[DEBUG] agg_dict:", agg_dict, file=sys.stderr)
        password = generate_random_password()
        hashed_password = hash_password(password)
        # Store the raw bcrypt hash in the password field (not base64-encoded)
        new_agg = ManageAggregator(
            aggregatorName=agg_dict["aggregatorName"],
            contactPersonName=agg_dict["contactPersonName"],
            email=agg_dict["email"],
            mobileNo=agg_dict["mobileNo"],
            location=agg_dict["location"],
            services=agg_dict["services"],
            status="Created",
            password=hashed_password,
            is_logged_in='N',
            password_history=json.dumps([hashed_password]),
            failed_login_attempts=0
        )
        db.add(new_agg)
        db.commit()
        db.refresh(new_agg)
        return encrypted_response(
            {
                "message": "Aggregator added successfully",
                "status": "created",
                "data": {"temporary_password": password}
            },
            key_bytes,
            201
        )
    except IntegrityError as e:
        db.rollback()
        # Debug logging for exception details
        import sys
        print("[DEBUG] IntegrityError:", str(e), file=sys.stderr)
        print("[DEBUG] IntegrityError repr:", repr(e), file=sys.stderr)
        if hasattr(e, 'orig'):
            print("[DEBUG] IntegrityError orig:", repr(e.orig), file=sys.stderr)
        error_str = str(e)
        orig_str = str(e.orig) if hasattr(e, 'orig') else ''
        email_val = agg_dict.get("email") if agg_dict else None
        if ("Duplicate entry" in error_str or "Duplicate entry" in orig_str or "1062" in error_str or "1062" in orig_str):
            return generic_error(
                "Email already exists. Please use a different email.",
                "DUPLICATE_EMAIL",
                key_bytes,
                400,
                {"error": "Duplicate email", "field": "email", "value": email_val}
            )
        else:
            return generic_error(
                "Database error",
                "DB_ERROR",
                key_bytes,
                500,
                {"error": error_str, "orig": orig_str}
            )
    except Exception as e:
        db.rollback()
        import sys, traceback
        print("[DEBUG] General Exception:", str(e), file=sys.stderr)
        print("[DEBUG] Exception type:", type(e), file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        print("[DEBUG] agg_dict in exception:", agg_dict, file=sys.stderr)
        return generic_error(
            "Database error",
            "DB_ERROR",
            key_bytes if key_bytes else b'0'*32,
            500,
            {"error": str(e), "type": str(type(e)), "traceback": traceback.format_exc()}
        )





# plain text api

@router.post('/manage-aggregator/plain', status_code=status.HTTP_201_CREATED)
async def create_manageAggregator_plain(request: Request, db: Session = Depends(get_db)):
    """
    Create a new aggregator without any encryption on request or response.
    Accepts a plain JSON body and returns a plain JSON response.
    """
    agg_dict = None
    try:
        body = await request.json()
        # Log the plain request body for debugging
        import sys
        print("[DEBUG] Plain request body:", body, file=sys.stderr)
        agg_dict = body
        password = generate_random_password()
        hashed_password = hash_password(password)
        new_agg = ManageAggregator(
            aggregatorName=agg_dict["aggregatorName"],
            contactPersonName=agg_dict["contactPersonName"],
            email=agg_dict["email"],
            mobileNo=agg_dict["mobileNo"],
            location=agg_dict["location"],
            services=agg_dict["services"],
            status="Created",
            password=hashed_password,
            is_logged_in='N',
            password_history=json.dumps([hashed_password]),
            failed_login_attempts=0
        )
        db.add(new_agg)
        db.commit()
        db.refresh(new_agg)
        # Send password email
        send_password_email(agg_dict["email"], password)
        return JSONResponse(
            status_code=201,
            content={
                "message": "Aggregator added successfully. Password sent to email.",
                "status": "created",
            }
        )
    except IntegrityError as e:
        db.rollback()
        import sys
        print("[DEBUG] IntegrityError:", str(e), file=sys.stderr)
        print("[DEBUG] IntegrityError repr:", repr(e), file=sys.stderr)
        if hasattr(e, 'orig'):
            print("[DEBUG] IntegrityError orig:", repr(e.orig), file=sys.stderr)
        error_str = str(e)
        orig_str = str(e.orig) if hasattr(e, 'orig') else ''
        email_val = agg_dict.get("email") if agg_dict else None
        if ("Duplicate entry" in error_str or "Duplicate entry" in orig_str or "1062" in error_str or "1062" in orig_str):
            return JSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "error_code": "DUPLICATE_EMAIL",
                    "message": "Email already exists. Please use a different email.",
                    "details": {"error": "Duplicate email", "field": "email", "value": email_val}
                }
            )
        else:
            return JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "error_code": "DB_ERROR",
                    "message": "Database error",
                    "details": {"error": error_str, "orig": orig_str}
                }
            )
    except Exception as e:
        db.rollback()
        import sys, traceback
        print("[DEBUG] General Exception:", str(e), file=sys.stderr)
        print("[DEBUG] Exception type:", type(e), file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        print("[DEBUG] agg_dict in exception:", agg_dict, file=sys.stderr)
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "error_code": "DB_ERROR",
                "message": "Database error",
                "details": {"error": str(e), "type": str(type(e)), "traceback": traceback.format_exc()}
            }
        )