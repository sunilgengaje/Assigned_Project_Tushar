from fastapi import APIRouter, Depends, status, HTTPException, Request
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.schemas.user import UserRegister, UserLogin, PasswordReset
from app.services.auth_service import AuthService
from app.api.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Auth"])
auth_service = AuthService()

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
    try:
        auth_service.unlock_user(db, username)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
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
    try:
        auth_service.logout(db, current_user)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    return {"message": "Logout successful"}




import os
import base64
from fastapi import Request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json

@router.post("/register")
async def register(request: Request, db: Session = Depends(get_db)):
    # Get AES key from .env (set to access token by client)

    from dotenv import load_dotenv
    load_dotenv(dotenv_path=".env")
    aes_key_raw = os.getenv("AES_GCM_KEY")
    if not aes_key_raw:
        raise HTTPException(status_code=400, detail="AES_GCM_KEY not set in .env")
    # Use the raw value, pad/truncate to 32 bytes
    token_bytes = aes_key_raw.encode()
    if len(token_bytes) < 32:
        aes_key = token_bytes.ljust(32, b'0')
    elif len(token_bytes) > 32:
        aes_key = token_bytes[:32]
    else:
        aes_key = token_bytes

    # Read and print encrypted payload
    encrypted_payload = await request.json()
    print("[SERVER] Encrypted registration payload:", encrypted_payload)
    data_b64 = encrypted_payload.get("data")
    aad_b64 = encrypted_payload.get("aad")
    if not data_b64:
        raise HTTPException(status_code=400, detail="Missing encrypted data")
    # Decrypt
    try:
        combined = base64.b64decode(data_b64)
        nonce = combined[:12]
        ciphertext = combined[12:]
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        user_dict = json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {e}")
    print("[SERVER] Decrypted registration payload:", user_dict)

    # Register user
    auth_service.register(db, user_dict["username"], user_dict["email"], user_dict["password"])
    response_obj = {"message": "User registered successfully"}

    # Encrypt response
    nonce = os.urandom(12)
    plaintext = json.dumps(response_obj, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    encrypted_response = {"data": base64.b64encode(nonce + ciphertext).decode(), "aad": None}
    print("[SERVER] Encrypted response:", encrypted_response)
    return encrypted_response

@router.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    import os, base64
    from app.core.aes_key_store import aes_key_store
    try:
        token = auth_service.login(db, user.username, user.password)
        # Generate random AES key for this session/user
        aes_key = os.urandom(32)
        aes_key_store.set_key(user.username, aes_key)
        aes_key_b64 = base64.b64encode(aes_key).decode()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e) if str(e) else "Invalid username or password"
        )
    return {"access_token": token, "token_type": "bearer", "aes_key": aes_key_b64}


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
    if not (username or email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either username or email is required."
        )
    if data.new_password != data.confirm_new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password and confirm password do not match."
        )
    try:
        auth_service.reset_password(db, username, email, data.old_password, data.new_password)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    return {"message": "Password reset successful"}
