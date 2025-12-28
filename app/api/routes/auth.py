
# --- Unified imports and logger setup ---
import os
import json
import base64
import string
import secrets
from datetime import datetime
from fastapi import APIRouter, Request, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.models.manage_aggregator import ManageAggregator
from app.models.manage_aggregator_backup import ManageAggregatorBackup
from app.core.security import hash_password
from app.db.session import SessionLocal
from app.api_logger import APILogger
logger = APILogger()

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


@router.delete('/api/manage-aggregator/{aggregator_id}', status_code=status.HTTP_200_OK)
async def delete_manageAggregator(aggregator_id: int, db: Session = Depends(get_db)):
    """
    Delete an aggregator by ID, mirror the deletion in the backup table, and return an encrypted response.
    All errors and success responses are encrypted using AES-GCM.
    """
    from app.services.api_log_service import log_api_entry
    aes_key_raw = os.getenv("AES_GCM_KEY")
    client_ip = None
    username = None
    if not aes_key_raw:
        log_api_entry(db, username, client_ip, f"/api/manage-aggregator/{aggregator_id}", "", None, 'F')
        return generic_error(
            "AES_GCM_KEY missing",
            "KEY_MISSING",
            b"",  # No key to encrypt, so send as plaintext
            500
        )

    key_bytes = normalize_aes_key(aes_key_raw)

    agg = db.query(ManageAggregator).filter(ManageAggregator.aggregatorId == aggregator_id).first()
    if not agg:
        log_api_entry(db, username, client_ip, f"/api/manage-aggregator/{aggregator_id}", "", key_bytes, 'F')
        return generic_error("Aggregator not found", "NOT_FOUND", key_bytes, 404)

    try:
        # Mirror to backup before deletion
        backup = ManageAggregatorBackup(
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
        db.add(backup)
        db.delete(agg)
        db.commit()
        log_api_entry(db, username, client_ip, f"/api/manage-aggregator/{aggregator_id}", "", key_bytes, 'S')
        return encrypted_response(
            {"message": "Aggregator deleted successfully", "status": "deleted"},
            key_bytes,
            200
        )
    except Exception as e:
        db.rollback()
        log_api_entry(db, username, client_ip, f"/api/manage-aggregator/{aggregator_id}", "", key_bytes, 'F')
        return generic_error(
            "Failed to delete aggregator",
            "DELETE_FAILED",
            key_bytes,
            500,
            {"error": str(e)}
        )

@router.get("/api/applications/{applicationId}/aggregators/{aggregatorId}/projections", tags=["Projections"])
def get_encrypted_projection_details(applicationId: int, aggregatorId: int, db: Session = Depends(get_db)):
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import base64, json
    # Load AES key from .env
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=".env")
    from app.services.api_log_service import log_api_entry
    aes_key_raw = os.getenv("AES_GCM_KEY")
    client_ip = None
    username = None
    if not aes_key_raw:
        log_api_entry(db, username, client_ip, f"/api/applications/{applicationId}/aggregators/{aggregatorId}/projections", "", None, 'F')
        err = {"status": "error", "error_code": "MISSING_KEY", "message": "AES_GCM_KEY not set in .env", "details": {}}
        print("[SERVER] Decrypted error:", err)
        return {"error": base64.b64encode(json.dumps(err).encode()).decode()}
    # Normalize key to 32 bytes
    key_bytes = aes_key_raw.encode()
    if len(key_bytes) < 32:
        key_bytes = key_bytes.ljust(32, b'0')
    elif len(key_bytes) > 32:
        key_bytes = key_bytes[:32]
    # Query projections
    projections = db.query(ProjectionDetailsInDB).filter(
        ProjectionDetailsInDB.isDeleted == False,
        ProjectionDetailsInDB.applicationId == applicationId,
        ProjectionDetailsInDB.aggregatorId == aggregatorId
    ).all()
    projections_data = []
    for p in projections:
        d = {c.name: getattr(p, c.name, None) for c in ProjectionDetailsInDB.__table__.columns}
        projections_data.append(d)
    logger.log_decrypted_response(projections_data, endpoint="get_encrypted_projection_details")
    log_api_entry(db, username, client_ip, f"/api/applications/{applicationId}/aggregators/{aggregatorId}/projections", str(projections_data), key_bytes, 'S')
    nonce = os.urandom(12)
    plaintext = json.dumps(projections_data, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key_bytes).encrypt(nonce, plaintext, None)
    encrypted_response = {"data": base64.b64encode(nonce + ciphertext).decode()}
    logger.log_encrypted_response(encrypted_response, endpoint="get_encrypted_projection_details")
    return JSONResponse(content=encrypted_response)
from app.models.manage_aggregator import ManageAggregator
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.schemas.user import PasswordReset
from pydantic import BaseModel
from app.services.auth_service import AuthService
auth_service = AuthService()
from app.api.deps import get_current_user
from app.core.captcha_store import captcha_store
from fastapi.responses import StreamingResponse
from io import BytesIO
import uuid
from captcha.image import ImageCaptcha
import os
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
from fastapi.responses import JSONResponse



# GET /auth/captcha: generate captcha image and ID
from app.core.captcha_store import captcha_store
from fastapi.responses import StreamingResponse
from io import BytesIO
import uuid
from captcha.image import ImageCaptcha


# Place captcha endpoint after router definition and before other endpoints

@router.get(
    "/captcha",
    summary="Get captcha image and ID (base64)",
    tags=["Auth"],
    response_description="JSON with base64 image and captcha_id."
)
def get_captcha():
    from app.api_logger import APILogger
    logger = APILogger()
    import random
    import string
    import base64
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    captcha_id = str(uuid.uuid4())
    captcha_store.set(captcha_id, captcha_text)
    image = ImageCaptcha(width=200, height=70)
    data = image.generate(captcha_text)
    img_bytes = BytesIO(data.read())
    img_b64 = base64.b64encode(img_bytes.getvalue()).decode()
    response = {"captcha_id": captcha_id, "image_b64": img_b64}
    logger.log_request_payload({}, endpoint="get_captcha")
    logger.log_decrypted_response(response, endpoint="get_captcha")
    return response

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/unlock-user", summary="Unlock user account", description="Manually unlock a user account after lockout. Requires username.")
def unlock_user(
    username: str,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    import base64
    import json
    from app.services.api_log_service import log_api_entry
    client_ip = None
    aes_key_bytes = None
    def generic_error(message, code="GENERIC_ERROR", status_code=400, details=None):
        err = {
            "status": "error",
            "error_code": code,
            "message": message,
            "details": details or {}
        }
        err_json = json.dumps(err, separators=(",", ":")).encode()
        err_b64 = base64.b64encode(err_json).decode()
        print("[SERVER] Decrypted error:", err)
        log_api_entry(db, username, client_ip, "/unlock-user", str(err), aes_key_bytes, 'F')
        return {"error": err_b64}
    try:
        auth_service.unlock_user(db, username)
        log_api_entry(db, username, client_ip, "/unlock-user", f"username={username}", aes_key_bytes, 'S')
    except Exception as e:
        return generic_error(str(e), code="UNLOCK_ERROR", status_code=400)
    return {"message": f"User '{username}' unlocked successfully."}




@router.post(
    "/logout",
    summary="Logout user session (POST)",
    description="Logs out the current user by invalidating their session (sets is_logged_in to 'N'). Requires a valid Authorization token.",
    response_description="Logout successful message"
)
@router.get(
    "/logout",
    summary="Logout user session (GET)",
    description="Logs out the current user by invalidating their session (sets is_logged_in to 'N'). Requires a valid Authorization token.",
    response_description="Logout successful message"
)
def logout(
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    """
    Logout the current user. Requires a valid Authorization token (Bearer).
    """
    import base64, json
    from app.services.api_log_service import log_api_entry
    client_ip = None
    aes_key_bytes = None
    def generic_error(message, code="GENERIC_ERROR", status_code=400, details=None):
        err = {
            "status": "error",
            "error_code": code,
            "message": message,
            "details": details or {}
        }
        err_json = json.dumps(err, separators=(",", ":")).encode()
        err_b64 = base64.b64encode(err_json).decode()
        log_api_entry(db, current_user, client_ip, "/logout", str(err), aes_key_bytes, 'F')
        return {"error": err_b64}
    try:
        auth_service.logout(db, current_user)
        log_api_entry(db, current_user, client_ip, "/logout", f"user={current_user}", aes_key_bytes, 'S')
    except Exception as e:
        return generic_error(str(e), code="LOGOUT_ERROR", status_code=400)
    return {"message": "Logout successful"}


from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from fastapi.responses import StreamingResponse
from io import BytesIO
import uuid
from captcha.image import ImageCaptcha
from app.core.captcha_store import captcha_store
from app.schemas.user import PasswordReset
from app.services.auth_service import AuthService
import os
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv



import os
import base64
from fastapi import Request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json

@router.post("/register")
async def register(request: Request, db: Session = Depends(get_db)):
    # Get AES key from .env (set to access token by client)

    from app.services.api_log_service import log_api_entry
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=".env")
    aes_key_raw = os.getenv("AES_GCM_KEY")
    client_ip = request.client.host if request and request.client else None
    username = None
    if not aes_key_raw:
        log_api_entry(db, username, client_ip, "/register", "", None, 'F')
        err = {"status": "error", "error_code": "MISSING_KEY", "message": "AES_GCM_KEY not set in .env", "details": {}}
        print("[SERVER] Decrypted error:", err)
        return {"error": base64.b64encode(json.dumps(err).encode()).decode()}
    token_bytes = aes_key_raw.encode()
    if len(token_bytes) < 32:
        aes_key = token_bytes.ljust(32, b'0')
    elif len(token_bytes) > 32:
        aes_key = token_bytes[:32]
    else:
        aes_key = token_bytes

    encrypted_payload = await request.json()
    logger.log_request_payload(encrypted_payload, endpoint="register")
    data_b64 = encrypted_payload.get("data")
    aad_b64 = encrypted_payload.get("aad")
    if not data_b64:
        log_api_entry(db, username, client_ip, "/register", str(encrypted_payload), aes_key, 'F')
        err = {"status": "error", "error_code": "MISSING_DATA", "message": "Missing encrypted data", "details": {}}
        logger.log_decrypted_response(err, endpoint="register")
        return {"error": base64.b64encode(json.dumps(err).encode()).decode()}
    try:
        combined = base64.b64decode(data_b64)
        nonce = combined[:12]
        ciphertext = combined[12:]
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        user_dict = json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        log_api_entry(db, username, client_ip, "/register", str(encrypted_payload), aes_key, 'F')
        err = {"status": "error", "error_code": "DECRYPTION_FAILED", "message": f"Decryption failed: {e}", "details": {}}
        logger.log_decrypted_response(err, endpoint="register")
        return {"error": base64.b64encode(json.dumps(err).encode()).decode()}
    logger.log_decrypted_response(user_dict, endpoint="register")
    try:
        auth_service.register(db, user_dict["username"], user_dict["email"], user_dict["password"])
        response_obj = {"message": "User registered successfully"}
        nonce = os.urandom(12)
        plaintext = json.dumps(response_obj, separators=(",", ":")).encode("utf-8")
        ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
        encrypted_response = {"data": base64.b64encode(nonce + ciphertext).decode(), "aad": None}
        logger.log_decrypted_response(response_obj, endpoint="register")
        logger.log_encrypted_response(encrypted_response, endpoint="register")
        log_api_entry(db, user_dict.get("username"), client_ip, "/register", str(user_dict), aes_key, 'S')
        return encrypted_response
    except Exception as e:
        log_api_entry(db, user_dict.get("username"), client_ip, "/register", str(user_dict), aes_key, 'F')
        err = {"status": "error", "error_code": "REGISTER_ERROR", "message": str(e), "details": {}}
        logger.log_decrypted_response(err, endpoint="register")
        return {"error": base64.b64encode(json.dumps(err).encode()).decode()}


# New login schema with captcha
class UserLoginWithCaptcha(BaseModel):
    username: str
    password: str
    captcha_id: str
    captcha_solution: str


# --- New login endpoint: base64-encoded JSON request/response, no AES ---
from fastapi import Body
@router.post("/login")
def login(data: dict = Body(...), db: Session = Depends(get_db), request: Request = None):
    from app.api_logger import APILogger
    logger = APILogger()
    import base64, json
    from app.core.captcha_store import captcha_store
    from app.services.api_log_service import log_api_entry
    # Expecting {"data": "<base64>"}
    client_ip = request.client.host if request and request.client else None
    username = None
    aes_key_bytes = None
    if "data" not in data:
        error_obj = {"error": "Missing data field"}
        logger.log_decrypted_response(error_obj, endpoint="login")
        error_b64 = base64.b64encode(json.dumps(error_obj, separators=(",", ":")).encode()).decode()
        logger.log_encrypted_response({"data": error_b64}, endpoint="login")
        log_api_entry(db, username, client_ip, "/auth/login", str(data), aes_key_bytes, 'F')
        return {"data": error_b64}
    try:
        decoded = base64.b64decode(data["data"]).decode()
        user_dict = json.loads(decoded)
        logger.log_decrypted_response(user_dict, endpoint="login")
        username = user_dict.get("username", "")
    except Exception as e:
        error_obj = {"error": f"Invalid base64 or JSON: {e}"}
        logger.log_decrypted_response(error_obj, endpoint="login")
        error_b64 = base64.b64encode(json.dumps(error_obj, separators=(",", ":")).encode()).decode()
        logger.log_encrypted_response({"data": error_b64}, endpoint="login")
        log_api_entry(db, username, client_ip, "/auth/login", str(data), aes_key_bytes, 'F')
        return {"data": error_b64}
    # Extract fields
    password = user_dict.get("password", "")
    captcha_id = user_dict.get("captcha_id", "")
    captcha_solution = user_dict.get("captcha_solution", "")
    # Validate captcha
    expected = captcha_store.get(captcha_id)
    def generic_login_error(message, code="LOGIN_ERROR", status_code=400, details=None):
        err = {
            "status": "error",
            "error_code": code,
            "message": message,
            "details": details or {}
        }
        logger.log_decrypted_response(err, endpoint="login")
        err_b64 = base64.b64encode(json.dumps(err, separators=(",", ":")).encode()).decode()
        logger.log_encrypted_response({"data": err_b64}, endpoint="login")
        log_api_entry(db, username, client_ip, "/auth/login", str(data), aes_key_bytes, 'F')
        return {"data": err_b64}
    if not expected:
        return generic_login_error("Invalid or expired captcha ID", code="INVALID_CAPTCHA", status_code=400)
    if captcha_solution.strip().upper() != expected.strip().upper():
        return generic_login_error("Captcha verification failed", code="CAPTCHA_FAILED", status_code=400)
    # Proceed with login
    try:
        login_result = auth_service.login(db, username, password)
        if isinstance(login_result, dict) and login_result.get("already_logged_in"):
            log_api_entry(db, username, client_ip, "/auth/login", str(data), aes_key_bytes, 'F')
            return generic_login_error(login_result["message"], code="ALREADY_LOGGED_IN", status_code=400)
        if isinstance(login_result, dict) and "access_token" in login_result:
            token = login_result["access_token"]
            # Set AES key in aes_key_store for this user (username/email)
            from app.core.aes_key_store import aes_key_store
            key_bytes = token.encode()
            if len(key_bytes) < 32:
                key_bytes = key_bytes.ljust(32, b'0')
            elif len(key_bytes) > 32:
                key_bytes = key_bytes[:32]
            aes_key_store.set_key(username, key_bytes)
            aes_key_bytes = key_bytes
            # Fetch user details for response
            user_obj = db.query(ManageAggregator).filter(ManageAggregator.email == username).first()
            user_data = None
            if user_obj:
                user_data = {
                    "aggregatorId": user_obj.aggregatorId,
                    "aggregatorName": user_obj.aggregatorName,
                    "contactPersonName": user_obj.contactPersonName,
                    "email": user_obj.email
                }
            response_obj = {
                "access_token": token,
                "message": "login successfully",
                "data": user_data
            }
            logger.log_decrypted_response(response_obj, endpoint="login")
            resp_b64 = base64.b64encode(json.dumps(response_obj, separators=(",", ":")).encode()).decode()
            logger.log_encrypted_response({"data": resp_b64}, endpoint="login")
            log_api_entry(db, username, client_ip, "/auth/login", str(data), aes_key_bytes, 'S')
            return {"data": resp_b64}
        else:
            token = str(login_result)
        response_obj = {"access_token": token, "message": "login successfully"}
        logger.log_decrypted_response(response_obj, endpoint="login")
        resp_b64 = base64.b64encode(json.dumps(response_obj, separators=(",", ":")).encode()).decode()
        logger.log_encrypted_response({"data": resp_b64}, endpoint="login")
        log_api_entry(db, username, client_ip, "/auth/login", str(data), aes_key_bytes, 'S')
        return {"data": resp_b64}
    except Exception as e:
        error_obj = {"error": str(e) if str(e) else "Invalid username or password"}
        logger.log_decrypted_response(error_obj, endpoint="login")
        log_api_entry(db, username, client_ip, "/auth/login", str(data), aes_key_bytes, 'F')
        return generic_login_error(str(e) if str(e) else "Invalid username or password", code="LOGIN_ERROR", status_code=400)


@router.post("/reset-password", summary="Reset user password", description="Reset the password for a user. Requires either username or email (one must be provided), and old_password, new_password, confirm_new_password. The new password must not match any of the last 3 passwords.")
async def reset_password(
    data: PasswordReset,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user),
):
    # Treat empty string as None for username/email
    username = data.username.strip() if data.username and data.username.strip() else None
    email = data.email.strip() if data.email and str(data.email).strip() else None
    if not username:
        username = None
    if not email:
        email = None
    import base64, json
    from app.services.api_log_service import log_api_entry
    client_ip = None
    aes_key_bytes = None
    def generic_error(message, code="GENERIC_ERROR", status_code=400, details=None):
        err = {
            "status": "error",
            "error_code": code,
            "message": message,
            "details": details or {}
        }
        err_json = json.dumps(err, separators=(",", ":")).encode()
        err_b64 = base64.b64encode(err_json).decode()
        print("[SERVER] Decrypted error:", err)
        log_api_entry(db, username or email, client_ip, "/reset-password", str(err), aes_key_bytes, 'F')
        return {"error": err_b64}
    if not (username or email):
        return generic_error("Either username or email is required.", code="RESET_MISSING_USER", status_code=400)
    if data.new_password != data.confirm_new_password:
        return generic_error("New password and confirm password do not match.", code="RESET_PASSWORD_MISMATCH", status_code=400)
    try:
        auth_service.reset_password(db, username, email, data.old_password, data.new_password)
        log_api_entry(db, username or email, client_ip, "/reset-password", f"user={username or email}", aes_key_bytes, 'S')
    except Exception as e:
        return generic_error(str(e), code="RESET_ERROR", status_code=400)
    return {"message": "Password reset successful"}

# --- Secure Projections Endpoint (duplicate of secure_projections.py for /auth router) ---
from app.core.aes_key_store import aes_key_store
from app.core.security import decode_token
from app.middleware.aes_gcm_middleware import encrypt_json_once
from app.models import ProjectionDetailsInDB

