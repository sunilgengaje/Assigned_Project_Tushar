import os
import hashlib
import json
import base64
import string
import secrets
import random
from fastapi import APIRouter, Request, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.models.manage_aggregator import ManageAggregator

from app.core.security import hash_password
from app.db.session import SessionLocal  # Ensure SessionLocal is imported
from app.api_logger import APILogger
from app.models.user import User
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
        import sys
        import traceback
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
        import sys
        import traceback
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
        return JSONResponse(
            status_code=201,
            content={
                "message": "Aggregator added successfully",
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
        import sys
        import traceback
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
    




    #without smtp api

    

@router.post('/manage-aggregator/validate-details', status_code=200, dependencies=[])
async def validate_aggregator_details(request: Request, db: Session = Depends(get_db)):
    """
    Accepts base64-encoded JSON: {"email": ..., "mobileNo": ..., "temporary_password": ...}
    Returns base64-encoded JSON: {"message": ..., "flag": "S"|"F"}
    """
    try:
        body = await request.json()
        encoded_data = body.get("data")
        if not encoded_data:
            return JSONResponse(status_code=400, content={"data": base64.b64encode(json.dumps({"message": "Missing data field", "flag": "F"}).encode()).decode()})
        try:
            decoded = base64.b64decode(encoded_data).decode()
            payload = json.loads(decoded)
        except Exception as e:
            return JSONResponse(status_code=400, content={"data": base64.b64encode(json.dumps({"message": "Invalid base64 or JSON", "flag": "F"}).encode()).decode()})

        email = payload.get("email")
        mobile_no = payload.get("mobileNo")
        temp_password = payload.get("temporary_password")
        if not (email and mobile_no and temp_password):
            return JSONResponse(status_code=400, content={"data": base64.b64encode(json.dumps({"message": "Missing required fields", "flag": "F"}).encode()).decode()})

        agg = db.query(ManageAggregator).filter(ManageAggregator.email == email, ManageAggregator.mobileNo == mobile_no).first()
        if not agg:
            resp = {"message": "Aggregator not found or mobile number mismatch", "flag": "F"}
            return JSONResponse(status_code=200, content={"data": base64.b64encode(json.dumps(resp).encode()).decode()})

        from app.core.security import verify_password
        if not verify_password(temp_password, agg.password):
            resp = {"message": "Temporary password incorrect", "flag": "F"}
            return JSONResponse(status_code=200, content={"data": base64.b64encode(json.dumps(resp).encode()).decode()})

        resp = {"message": "Validated success", "flag": "S", "email": email}
        return JSONResponse(status_code=200, content={"data": base64.b64encode(json.dumps(resp).encode()).decode()})
    except Exception as e:
        resp = {"message": "Internal server error", "flag": "F"}
        return JSONResponse(status_code=500, content={"data": base64.b64encode(json.dumps(resp).encode()).decode()})
    
# --- API: Reset aggregator password (after validation) ---
@router.post('/manage-aggregator/reset-password-plain', status_code=200, dependencies=[])
async def reset_aggregator_password_plain(request: Request, db: Session = Depends(get_db)):
    """
    Accepts base64-encoded JSON: {"email": ..., "flag": "S"|"F", "newpassword": ...}
    Returns base64-encoded JSON: {"message": ..., "flag": "S"|"F"}
    """
    import base64
    from app.core.security import hash_password
    try:
        body = await request.json()
        encoded_data = body.get("data")
        if not encoded_data:
            return JSONResponse(status_code=400, content={"data": base64.b64encode(json.dumps({"message": "Missing data field", "flag": "F"}).encode()).decode()})
        try:
            decoded = base64.b64decode(encoded_data).decode()
            payload = json.loads(decoded)
        except Exception as e:
            return JSONResponse(status_code=400, content={"data": base64.b64encode(json.dumps({"message": "Invalid base64 or JSON", "flag": "F"}).encode()).decode()})

        email = payload.get("email")
        flag = payload.get("flag")
        newpassword = payload.get("newpassword")
        if not (email and flag and newpassword):
            return JSONResponse(status_code=400, content={"data": base64.b64encode(json.dumps({"message": "Missing required fields", "flag": "F"}).encode()).decode()})
        if flag != "S":
            return JSONResponse(status_code=400, content={"data": base64.b64encode(json.dumps({"message": "Validation failed. Cannot reset password.", "flag": "F"}).encode()).decode()})

        agg = db.query(ManageAggregator).filter(ManageAggregator.email == email).first()
        if not agg:
            resp = {"message": "Aggregator not found", "flag": "F"}
            return JSONResponse(status_code=200, content={"data": base64.b64encode(json.dumps(resp).encode()).decode()})

        agg.password = hash_password(newpassword)
        # Optionally update password history
        try:
            history = json.loads(agg.password_history)
        except Exception:
            history = []
        history.append(agg.password)
        agg.password_history = json.dumps(history)
        db.commit()
        db.refresh(agg)
        resp = {"message": "Password reset successful", "flag": "S"}
        return JSONResponse(status_code=200, content={"data": base64.b64encode(json.dumps(resp).encode()).decode()})
    except Exception as e:
        resp = {"message": "Internal server error", "flag": "F"}
        return JSONResponse(status_code=500, content={"data": base64.b64encode(json.dumps(resp).encode()).decode()})
# --- API: Validate aggregator details (email, mobileNo, temporary password) ---



# --- Add Manage Aggregator with base64 encryption and temp password email ---
@router.post("/add-manage-aggregator-encrypted", status_code=201)
async def add_manage_aggregator_encrypted(request: Request, db: Session = Depends(get_db)):
    logger = APILogger()
    # Expecting {"data": <base64-encoded JSON payload>}
    payload = await request.json()
    data_b64 = payload.get("data")
    if not data_b64:
        resp = {"message": "Missing encoded data", "flag": "F"}
        return JSONResponse(status_code=400, content={"data": base64.b64encode(json.dumps(resp).encode()).decode()})
    try:
        decoded = base64.b64decode(data_b64).decode()
        user_dict = json.loads(decoded)
    except Exception as e:
        resp = {"message": f"Base64 decode failed: {e}", "flag": "F"}
        return JSONResponse(status_code=400, content={"data": base64.b64encode(json.dumps(resp).encode()).decode()})

    # Validate email
    email = user_dict.get("email")
    if not email:
        resp = {"message": "Email is required.", "flag": "F"}
        return JSONResponse(status_code=400, content={"data": base64.b64encode(json.dumps(resp).encode()).decode()})
    from app.models.manage_aggregator import ManageAggregator
    existing = db.query(ManageAggregator).filter(ManageAggregator.email == email).first()
    if existing:
        resp = {"message": "Email already exists.", "flag": "F"}
        return JSONResponse(status_code=409, content={"data": base64.b64encode(json.dumps(resp).encode()).decode()})
    # Optionally: validate email format
    import re
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        resp = {"message": "Invalid email format.", "flag": "F"}
        return JSONResponse(status_code=400, content={"data": base64.b64encode(json.dumps(resp).encode()).decode()})

    # Generate temp password
    temp_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    user_dict["password"] = hash_password(temp_password)
    # Save user
    user = ManageAggregator(
        aggregatorName=user_dict.get("aggregatorName"),
        contactPersonName=user_dict.get("contactPersonName"),
        email=email,
        password=user_dict.get("password"),
        password_history=json.dumps([user_dict.get("password")]),
        is_logged_in='N',
        failed_login_attempts=0,
        lockout_until=None,
        mobileNo=user_dict.get("mobileNo", ""),
        location=user_dict.get("location", ""),
        services=user_dict.get("services", ""),
        isDeleted=False,
        status='Created'
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    # Send email with temp password (pseudo-code, replace with your email logic)
    send_temp_password_email(user.email, temp_password)
    logger.log_decrypted_response({"email": user.email, "temp_password": temp_password}, endpoint="add_manage_aggregator_encrypted")
    resp = {"message": "User created and temp password sent via email.", "flag": "S"}
    return JSONResponse(status_code=201, content={"data": base64.b64encode(json.dumps(resp).encode()).decode()})

# Dummy email sender (replace with real implementation)
def send_temp_password_email(email, temp_password):
    from app.email.common import send_password_email
    result = send_password_email(email, temp_password)
    if not result.get("success"):
        # Log or handle email sending error as needed
        print(f"[EMAIL ERROR] Could not send to {email}: {result}")
    return result




@router.post('/unlock-user', status_code=200)
async def unlock_user(request: Request, db: Session = Depends(get_db)):
    body = await request.json()
    email = body.get("email")
    if not email:
        return JSONResponse(status_code=400, content={"data": base64.b64encode(b"Email is required").decode()})
    agg = db.query(ManageAggregator).filter(ManageAggregator.email == email).first()
    if not agg:
        return JSONResponse(status_code=404, content={"data": base64.b64encode(b"User not found").decode()})
    if not agg.lockout_until:
        return JSONResponse(status_code=200, content={"data": base64.b64encode(b"User is not locked").decode()})
    # Unlock logic
    agg.lockout_until = None
    agg.failed_login_attempts = 0
    db.commit()
    return JSONResponse(status_code=200, content={"data": base64.b64encode(b"User unlocked successfully").decode()})



@router.post('/forgot-password', status_code=200)
async def forgot_password(request: Request, db: Session = Depends(get_db)):
    """
    Accepts base64-encoded JSON: {"email": ..., "mobileNo": ...}
    Returns base64-encoded JSON: {"message": ..., "flag": "S"|"F"}
    """
    try:
        body = await request.json()
        data_b64 = body.get("data")
        if not data_b64:
            resp = {"message": "Missing encoded data", "flag": "F"}
            return JSONResponse(status_code=400, content={"data": base64.b64encode(json.dumps(resp).encode()).decode()})
        try:
            decoded = base64.b64decode(data_b64).decode()
            payload = json.loads(decoded)
        except Exception as e:
            resp = {"message": f"Base64 decode failed: {e}", "flag": "F"}
            return JSONResponse(status_code=400, content={"data": base64.b64encode(json.dumps(resp).encode()).decode()})

        email = payload.get("email")
        mobile_no = payload.get("mobileNo")
        if not email or not mobile_no:
            resp = {"message": "Email and mobile number are required.", "flag": "F"}
            return JSONResponse(status_code=400, content={"data": base64.b64encode(json.dumps(resp).encode()).decode()})


        agg = db.query(ManageAggregator).filter(ManageAggregator.email == email, ManageAggregator.mobileNo == mobile_no).first()
        if not agg:
            resp = {"message": "User not found or mobile number mismatch.", "flag": "F"}
            return JSONResponse(status_code=404, content={"data": base64.b64encode(json.dumps(resp).encode()).decode()})

        # Generate temp password
        temp_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        from app.core.security import hash_password
        agg.password = hash_password(temp_password)
        # Optionally update password history
        try:
            history = json.loads(agg.password_history)
        except Exception:
            history = []
        history.append(agg.password)
        agg.password_history = json.dumps(history)
        db.commit()
        # Send email with temp password
        send_temp_password_email(agg.email, temp_password)
        resp = {"message": "Temporary password sent to your email.", "flag": "S"}
        return JSONResponse(status_code=200, content={"data": base64.b64encode(json.dumps(resp).encode()).decode()})
    except Exception as e:
        resp = {"message": "Internal server error", "flag": "F"}
        return JSONResponse(status_code=500, content={"data": base64.b64encode(json.dumps(resp).encode()).decode()})


