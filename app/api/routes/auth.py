



import os
import uuid
import json
import base64
import hashlib
from io import BytesIO
from fastapi import APIRouter, Depends, Request, status, Body, FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import and_
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from captcha.image import ImageCaptcha
from app.api_logger import APILogger
from app.db.session import SessionLocal
from app.api.deps import get_current_user
from app.services.api_log_service import log_api_entry
from app.services.auth_service import AuthService
from app.core.captcha_store import captcha_store
from app.models.manage_aggregator import ManageAggregator
from app.models import ProjectionDetailsInDB
from app.models.payment_aggregator import PaymentAggregatorInDB
from app.schemas.payment_aggregator_update import PaymentAggregatorUpdate
from app.schemas.user import PasswordReset

logger = APILogger()
router = APIRouter()
auth_service = AuthService()



def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# New endpoint: Get payment aggregator by applicationId and aggregatorId
@router.get("/api/payment-aggregator/application/{applicationId}/aggregator/{aggregatorId}", tags=["PaymentAggregator"])
def get_payment_aggregator_by_ids(
    applicationId: int,
    aggregatorId: int,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Fetch a single payment aggregator by applicationId and aggregatorId, encrypted with per-user AES key derived from access token.
    """
    auth_header = request.headers.get("authorization")
    client_ip = None
    username = None
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return JSONResponse({"error": "Missing or invalid Authorization header"}, status_code=401)
    access_token = auth_header.split(" ", 1)[1]
    key_bytes = hashlib.sha256(access_token.encode()).digest()

    aggregator = db.query(PaymentAggregatorInDB).filter(
        PaymentAggregatorInDB.applicationId == applicationId,
        PaymentAggregatorInDB.aggregatorId == aggregatorId,
        PaymentAggregatorInDB.isDeleted == False
    ).first()
    if not aggregator:
        err = {"status": "error", "error_code": "NOT_FOUND", "message": "PaymentAggregator not found", "details": {}}
        logger.log_decrypted_response(err, endpoint="get_payment_aggregator_by_ids")
        log_api_entry(db, username, client_ip, f"/api/payment-aggregator/application/{applicationId}/aggregator/{aggregatorId}", str(err), key_bytes, 'F')
        return JSONResponse({"error": base64.b64encode(json.dumps(err).encode()).decode()}, status_code=404)

    data = {c.name: getattr(aggregator, c.name, None) for c in PaymentAggregatorInDB.__table__.columns}
    logger.log_decrypted_response(data, endpoint="get_payment_aggregator_by_ids")
    log_api_entry(db, username, client_ip, f"/api/payment-aggregator/application/{applicationId}/aggregator/{aggregatorId}", str(data), key_bytes, 'S')
    nonce = os.urandom(12)
    plaintext = json.dumps(data, separators=(',', ':')).encode("utf-8")
    ciphertext = AESGCM(key_bytes).encrypt(nonce, plaintext, None)
    encrypted_response = {"data": base64.b64encode(nonce + ciphertext).decode()}
    logger.log_encrypted_response(encrypted_response, endpoint="get_payment_aggregator_by_ids")
    return JSONResponse(content=encrypted_response)



def create_tables():
    # Ensure all tables for all models are created
    from app.models.manage_aggregator import Base as ManageAggregatorBase
    from app.models.payment_aggregator import Base as PaymentAggregatorBase
    from app.db.session import engine
    ManageAggregatorBase.metadata.create_all(bind=engine)
    PaymentAggregatorBase.metadata.create_all(bind=engine)
    # If you have other Bases, add them here as well




# PUT endpoint to update PaymentAggregator with per-user AES encryption
@router.put('/api/payment-aggregator/application/{applicationId}/aggregator/{aggregatorId}', tags=["PaymentAggregator"])
async def update_paymentAggregator(
    applicationId: int,
    aggregatorId: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    # Extract access token from Authorization header
    auth_header = request.headers.get("authorization")
    client_ip = request.client.host if request and request.client else None
    username = current_user if current_user else None
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return JSONResponse({"error": "Missing or invalid Authorization header"}, status_code=401)
    access_token = auth_header.split(" ", 1)[1]
    key_bytes = hashlib.sha256(access_token.encode()).digest()

    # Decrypt the payload
    try:
        encrypted_payload = await request.json()
        data_b64 = encrypted_payload.get("data")
        if not data_b64:
            err = {"status": "error", "error_code": "MISSING_DATA", "message": "Missing encrypted data", "details": {}}
            logger.log_decrypted_response(err, endpoint="update_paymentAggregator")
            log_api_entry(db, username, client_ip, request.url.path, str(encrypted_payload), key_bytes, 'F')
            return {"error": base64.b64encode(json.dumps(err).encode()).decode()}
        combined = base64.b64decode(data_b64)
        nonce = combined[:12]
        ciphertext = combined[12:]
        aesgcm = AESGCM(key_bytes)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        update_dict = json.loads(plaintext.decode("utf-8"))
        update_obj = PaymentAggregatorUpdate(**update_dict)
    except Exception as e:
        err = {"status": "error", "error_code": "DECRYPTION_FAILED", "message": f"Decryption failed: {e}", "details": {}}
        logger.log_decrypted_response(err, endpoint="update_paymentAggregator")
        log_api_entry(db, username, client_ip, request.url.path, str(e), key_bytes, 'F')
        return {"error": base64.b64encode(json.dumps(err).encode()).decode()}

    # Find and update the PaymentAggregator
    existing_PaymentAggregator = db.query(PaymentAggregatorInDB).filter(
        PaymentAggregatorInDB.applicationId == applicationId,
        PaymentAggregatorInDB.aggregatorId == aggregatorId,
        PaymentAggregatorInDB.isDeleted == False
    ).first()
    if not existing_PaymentAggregator:
        err = {"status": "error", "error_code": "NOT_FOUND", "message": "PaymentAggregator not found", "details": {}}
        logger.log_decrypted_response(err, endpoint="update_paymentAggregator")
        log_api_entry(db, username, client_ip, request.url.path, str(err), key_bytes, 'F')
        return JSONResponse({"error": base64.b64encode(json.dumps(err).encode()).decode()}, status_code=404)

    # Update the values from update_obj
    for key, value in update_obj.dict().items():
        if value is not None:
            setattr(existing_PaymentAggregator, key, value)

    db.commit()
    db.refresh(existing_PaymentAggregator)

    response_dict = {
        "aggregatorCode": existing_PaymentAggregator.id,
        "status": "Updated"
    }
    logger.log_decrypted_response(response_dict, endpoint="update_paymentAggregator")
    log_api_entry(db, username, client_ip, request.url.path, str(response_dict), key_bytes, 'S')
    # Encrypt response
    nonce = os.urandom(12)
    plaintext = json.dumps(response_dict, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key_bytes).encrypt(nonce, plaintext, None)
    encrypted_response = {"data": base64.b64encode(nonce + ciphertext).decode()}
    logger.log_encrypted_response(encrypted_response, endpoint="update_paymentAggregator")
    return JSONResponse(content=encrypted_response, status_code=200)



    nonce = combined[:12]
    ciphertext = combined[12:]
    try:
        plaintext = AESGCM(key_bytes).decrypt(nonce, ciphertext, None)
        aggregators = json.loads(plaintext.decode())
        print("[SERVER] Decrypted request payload:", json.dumps(aggregators, indent=2))
    except Exception as e:
        return JSONResponse({"error": "Decryption failed", "details": str(e)}, status_code=400)

    # Save aggregators to DB
    db_objects = []
    try:
        for agg in aggregators:
            db_obj = PaymentAggregatorInDB(**agg)
            db_objects.append(db_obj)
        db.add_all(db_objects)
        db.commit()
    except Exception as e:
        db.rollback()
        return JSONResponse({"error": "DB save failed", "details": str(e)}, status_code=400)

    # Prepare response (echo back for demo)
    response_data = {"status": "success", "count": len(aggregators)}
    print("[SERVER] Decrypted response payload:", json.dumps(response_data, indent=2))

    # Encrypt response
    resp_nonce = os.urandom(12)
    resp_plaintext = json.dumps(response_data, separators=(",", ":")).encode("utf-8")
    resp_ciphertext = AESGCM(key_bytes).encrypt(resp_nonce, resp_plaintext, None)
    encrypted_response = {"data": base64.b64encode(resp_nonce + resp_ciphertext).decode()}
    print("[SERVER] Encrypted response payload:", json.dumps(encrypted_response, indent=2))

    return JSONResponse(content=encrypted_response, status_code=201)


# New endpoint: Get payment aggregator by applicationId and aggregatorId
@router.get("/api/payment-aggregator/application/{applicationId}/aggregator/{aggregatorId}", tags=["PaymentAggregator"])
def get_payment_aggregator_by_ids(
    applicationId: int,
    aggregatorId: int,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Fetch a single payment aggregator by applicationId and aggregatorId, encrypted with per-user AES key derived from access token.
    """
    auth_header = request.headers.get("authorization")
    client_ip = None
    username = None
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return JSONResponse({"error": "Missing or invalid Authorization header"}, status_code=401)
    access_token = auth_header.split(" ", 1)[1]
    key_bytes = hashlib.sha256(access_token.encode()).digest()

    aggregator = db.query(PaymentAggregatorInDB).filter(
        ~PaymentAggregatorInDB.isDeleted,
        PaymentAggregatorInDB.applicationId == applicationId,
        PaymentAggregatorInDB.aggregatorId == aggregatorId
    ).first()
    if not aggregator:
        err = {"status": "error", "error_code": "NOT_FOUND", "message": "PaymentAggregator not found", "details": {}}
        logger.log_decrypted_response(err, endpoint="get_payment_aggregator_by_ids")
        log_api_entry(db, username, client_ip, f"/api/payment-aggregator/application/{applicationId}/aggregator/{aggregatorId}", str(err), key_bytes, 'F')
        return JSONResponse({"error": base64.b64encode(json.dumps(err).encode()).decode()}, status_code=404)

    data = {c.name: getattr(aggregator, c.name, None) for c in PaymentAggregatorInDB.__table__.columns}
    logger.log_decrypted_response(data, endpoint="get_payment_aggregator_by_ids")
    log_api_entry(db, username, client_ip, f"/api/payment-aggregator/application/{applicationId}/aggregator/{aggregatorId}", str(data), key_bytes, 'S')
    nonce = os.urandom(12)
    plaintext = json.dumps(data, separators=(',', ':')).encode("utf-8")
    ciphertext = AESGCM(key_bytes).encrypt(nonce, plaintext, None)
    encrypted_response = {"data": base64.b64encode(nonce + ciphertext).decode()}
    logger.log_encrypted_response(encrypted_response, endpoint="get_payment_aggregator_by_ids")
    return JSONResponse(content=encrypted_response)

# App startup logic
app = None
try:
    import app.main
    app = app.main.app
except Exception:
    pass
if app is not None and isinstance(app, FastAPI):
    @app.on_event("startup")
    def on_startup():
        create_tables()
else:
    # If not running as main FastAPI app, create tables immediately (safe, idempotent)
    create_tables()



@router.get("/api/all-payment-aggregator/{aggregatorId}", tags=["PaymentAggregator"])
def get_all_payment_aggregator_by_aggregatorId(aggregatorId: int, request: Request, db: Session = Depends(get_db)):
    """
    Returns all payment aggregators for a given aggregatorId, encrypted with per-user AES key derived from access token.
    """
    auth_header = request.headers.get("authorization")
    client_ip = None
    username = None
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return JSONResponse({"error": "Missing or invalid Authorization header"}, status_code=401)
    access_token = auth_header.split(" ", 1)[1]
    key_bytes = hashlib.sha256(access_token.encode()).digest()

    from datetime import datetime, timezone
    payment_aggregators = db.query(PaymentAggregatorInDB).filter(
        PaymentAggregatorInDB.aggregatorId == aggregatorId,
        PaymentAggregatorInDB.isDeleted == False
    ).all()
    # Update status to 'expired' if endDate is in the past and status is not 'submitted'
    for aggregator in payment_aggregators:
        dt1_str = getattr(aggregator, 'endDate', None)
        status_val = getattr(aggregator, 'status', None)
        if dt1_str:
            try:
                try:
                    dt1 = datetime.strptime(dt1_str, "%Y-%m-%dT%H:%M:%S.%fZ")
                except ValueError:
                    dt1 = datetime.strptime(dt1_str, "%Y-%m-%dT%H:%M:%SZ")
                dt1 = dt1.replace(tzinfo=timezone.utc)
                dt2 = datetime.now(timezone.utc)
                if dt1 < dt2 and status_val != 'submitted':
                    aggregator.status = "expired"
            except Exception:
                pass
    db.commit()
    # Re-fetch after possible updates
    payment_aggregators = db.query(PaymentAggregatorInDB).filter(
        PaymentAggregatorInDB.aggregatorId == aggregatorId,
        PaymentAggregatorInDB.isDeleted == False
    ).all()
    data = []
    for p in payment_aggregators:
        d = {c.name: getattr(p, c.name, None) for c in PaymentAggregatorInDB.__table__.columns}
        data.append(d)
    logger.log_decrypted_response(data, endpoint="get_all_payment_aggregator_by_aggregatorId")
    log_api_entry(db, username, client_ip, f"/api/all-payment-aggregator/{aggregatorId}", str(data), key_bytes, 'S')
    nonce = os.urandom(12)
    plaintext = json.dumps(data, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key_bytes).encrypt(nonce, plaintext, None)
    encrypted_response = {"data": base64.b64encode(nonce + ciphertext).decode()}
    logger.log_encrypted_response(encrypted_response, endpoint="get_all_payment_aggregator_by_aggregatorId")
    return JSONResponse(content=encrypted_response)


# get_db already defined above, remove duplicate


@router.get("/api/applications/{applicationId}/aggregators/{aggregatorId}/projections", tags=["Projections"])
def get_encrypted_projection_details(applicationId: int, aggregatorId: int, request: Request, db: Session = Depends(get_db)):
    # Extract access token from Authorization header
    auth_header = request.headers.get("authorization")
    client_ip = None
    username = None
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return JSONResponse({"error": "Missing or invalid Authorization header"}, status_code=401)
    access_token = auth_header.split(" ", 1)[1]
    key_bytes = hashlib.sha256(access_token.encode()).digest()
    projections = db.query(ProjectionDetailsInDB).filter(
        ~ProjectionDetailsInDB.isDeleted,
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


@router.post("/api/applications/{applicationId}/aggregators/{aggregatorId}/projections", tags=["Projections"], status_code=status.HTTP_201_CREATED)
def create_encrypted_projection_details(applicationId: int, aggregatorId: int, projectionDetails: list, request: Request, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    # Extract access token from Authorization header
    auth_header = request.headers.get("authorization")
    client_ip = None
    username = None
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return JSONResponse({"error": "Missing or invalid Authorization header"}, status_code=401)
    access_token = auth_header.split(" ", 1)[1]
    key_bytes = hashlib.sha256(access_token.encode()).digest()

    # Mark old projections as deleted
    projectionDetailsOld = db.query(ProjectionDetailsInDB).filter(
        ~ProjectionDetailsInDB.isDeleted,
        ProjectionDetailsInDB.applicationId == applicationId,
        ProjectionDetailsInDB.aggregatorId == aggregatorId
    ).all()
    for projectionDetail in projectionDetailsOld:
        projectionDetail.isDeleted = True
    db.commit()

    # Add new projections
    for projectionDetail in projectionDetails:
        new_projectionDetail = ProjectionDetailsInDB(**projectionDetail)
        db.add(new_projectionDetail)
    db.commit()

    # Fetch new projections
    projectionDetailsNew = db.query(ProjectionDetailsInDB).filter(
        ~ProjectionDetailsInDB.isDeleted,
        ProjectionDetailsInDB.applicationId == applicationId,
        ProjectionDetailsInDB.aggregatorId == aggregatorId
    ).all()
    projections_data = []
    for p in projectionDetailsNew:
        d = {c.name: getattr(p, c.name, None) for c in ProjectionDetailsInDB.__table__.columns}
        projections_data.append(d)
    logger.log_decrypted_response(projections_data, endpoint="create_encrypted_projection_details")
    log_api_entry(db, username, client_ip, f"/api/applications/{applicationId}/aggregators/{aggregatorId}/projections", str(projections_data), key_bytes, 'S')
    nonce = os.urandom(12)
    plaintext = json.dumps(projections_data, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key_bytes).encrypt(nonce, plaintext, None)
    encrypted_response = {"data": base64.b64encode(nonce + ciphertext).decode()}
    logger.log_encrypted_response(encrypted_response, endpoint="create_encrypted_projection_details")
    return JSONResponse(content=encrypted_response)




@router.post("/api/applications/payment-aggregators", tags=["PaymentAggregator"], status_code=status.HTTP_201_CREATED)
async def create_payment_aggregator(
    request: Request,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    """
    Bulk create payment aggregators. Request and response are encrypted with per-user AES key derived from access token.
    """
    auth_header = request.headers.get("authorization")
    client_ip = request.client.host if request and request.client else None
    username = current_user if current_user else None
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return JSONResponse({"error": "Missing or invalid Authorization header"}, status_code=401)
    access_token = auth_header.split(" ", 1)[1]
    key_bytes = hashlib.sha256(access_token.encode()).digest()

    try:
        encrypted_payload = await request.json()
        data_b64 = encrypted_payload.get("data")
        if not data_b64:
            err = {"status": "error", "error_code": "MISSING_DATA", "message": "Missing encrypted data", "details": {}}
            logger.log_decrypted_response(err, endpoint="create_payment_aggregator")
            log_api_entry(db, username, client_ip, "/api/applications/payment-aggregators", str(encrypted_payload), key_bytes, 'F')
            return {"error": base64.b64encode(json.dumps(err).encode()).decode()}
        combined = base64.b64decode(data_b64)
        nonce = combined[:12]
        ciphertext = combined[12:]
        aesgcm = AESGCM(key_bytes)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        aggregator_list = json.loads(plaintext.decode("utf-8"))
        if not isinstance(aggregator_list, list):
            aggregator_list = [aggregator_list]
    except Exception as e:
        err = {"status": "error", "error_code": "DECRYPTION_FAILED", "message": f"Decryption failed: {e}", "details": {}}
        logger.log_decrypted_response(err, endpoint="create_payment_aggregator")
        log_api_entry(db, username, client_ip, "/api/applications/payment-aggregators", str(e), key_bytes, 'F')
        return {"error": base64.b64encode(json.dumps(err).encode()).decode()}

    # Insert new aggregators using PaymentAggregatorInDB
    try:
        new_aggregators = []
        for aggregator_dict in aggregator_list:
            new_aggregator = PaymentAggregatorInDB(**aggregator_dict)
            db.add(new_aggregator)
            new_aggregators.append(new_aggregator)
        db.commit()
        for agg in new_aggregators:
            db.refresh(agg)
        response_data = [
            {c.name: getattr(agg, c.name, None) for c in PaymentAggregatorInDB.__table__.columns}
            for agg in new_aggregators
        ]
        logger.log_decrypted_response(response_data, endpoint="create_payment_aggregator")
        log_api_entry(db, username, client_ip, "/api/applications/payment-aggregators", str(response_data), key_bytes, 'S')
        nonce = os.urandom(12)
        plaintext = json.dumps(response_data, separators=(",", ":")).encode("utf-8")
        ciphertext = AESGCM(key_bytes).encrypt(nonce, plaintext, None)
        encrypted_response = {"data": base64.b64encode(nonce + ciphertext).decode()}
        logger.log_encrypted_response(encrypted_response, endpoint="create_payment_aggregator")
        return JSONResponse(content=encrypted_response, status_code=201)
    except Exception as e:
        db.rollback()
        err = {"status": "error", "error_code": "CREATE_ERROR", "message": str(e), "details": {}}
        logger.log_decrypted_response(err, endpoint="create_payment_aggregator")
        log_api_entry(db, username, client_ip, "/api/applications/payment-aggregators", str(e), key_bytes, 'F')
        return {"error": base64.b64encode(json.dumps(err).encode()).decode()}

auth_service = AuthService()






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
        log_api_entry(db, current_user, client_ip, "/logout", str(err), aes_key_bytes, 'F')
        return {"error": err_b64}
    try:
        auth_service.logout(db, current_user)
        log_api_entry(db, current_user, client_ip, "/logout", f"user={current_user}", aes_key_bytes, 'S')
    except Exception as e:
        return generic_error(str(e), code="LOGOUT_ERROR", status_code=400)
    return {"message": "Logout successful"}








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
    # aad_b64 = encrypted_payload.get("aad")  # Unused, removed for cleanliness
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



# Import UserLoginWithCaptcha schema from schemas


# --- New login endpoint: base64-encoded JSON request/response, no AES ---

@router.post("/login")
def login(data: dict = Body(...), db: Session = Depends(get_db), request: Request = None):
    from app.api_logger import APILogger
    logger = APILogger()
    import base64
    import json
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

