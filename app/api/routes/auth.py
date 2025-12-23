from fastapi import APIRouter, Depends, status, HTTPException, Request
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.schemas.user import UserRegister, UserLogin, PasswordReset
from pydantic import BaseModel
from app.services.auth_service import AuthService
from app.api.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Auth"])
auth_service = AuthService()

# ...existing code...

# GET /auth/captcha: generate captcha image and ID
from app.core.captcha_store import captcha_store
from fastapi.responses import StreamingResponse
from io import BytesIO
import uuid
from captcha.image import ImageCaptcha


# Place captcha endpoint after router definition and before other endpoints

@router.get(
    "/captcha",
    summary="Get captcha image and ID",
    tags=["Auth"],
    response_class=StreamingResponse,
    response_description="PNG image with captcha. Captcha ID in X-Captcha-Id header."
)
def get_captcha():
    import random, string
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    captcha_id = str(uuid.uuid4())
    captcha_store.set(captcha_id, captcha_text)
    image = ImageCaptcha(width=200, height=70)
    data = image.generate(captcha_text)
    img_bytes = BytesIO(data.read())
    return StreamingResponse(img_bytes, media_type="image/png", headers={"x-captcha-id": captcha_id})

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


# New login schema with captcha
class UserLoginWithCaptcha(BaseModel):
    username: str
    password: str
    captcha_id: str
    captcha_solution: str

@router.post("/login")
def login(user: UserLoginWithCaptcha, db: Session = Depends(get_db)):
    print("[DEBUG] Encoded login values:")
    print("  username (b64):", user.username)
    print("  password (b64):", user.password)
    print("  captcha_id (b64):", user.captcha_id)
    print("  captcha_solution (b64):", user.captcha_solution)
    import os, base64
    from app.core.aes_key_store import aes_key_store
    from app.core.captcha_store import captcha_store
    # Decode base64 fields
    def b64d(x):
        return base64.b64decode(x).decode() if x else ""
    username = b64d(user.username)
    password = b64d(user.password)
    captcha_id = b64d(user.captcha_id)
    captcha_solution = b64d(user.captcha_solution)
    print("[DEBUG] Decoded login values:")
    print("  username:", username)
    print("  password:", password)
    print("  captcha_id:", captcha_id)
    print("  captcha_solution:", captcha_solution)
    # Validate captcha
    expected = captcha_store.get(captcha_id)
    if not expected:
        raise HTTPException(status_code=400, detail="Invalid or expired captcha ID")
    if captcha_solution.strip().upper() != expected.strip().upper():
        raise HTTPException(status_code=400, detail="Captcha verification failed")
    # Optionally delete captcha after use
    captcha_store.delete(captcha_id)
    # Proceed with login
    try:
        token = auth_service.login(db, username, password)
        # Save plain token in .env as AES_GCM_KEY (for AES key usage)
        env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../../.env')
        print(f"[SERVER] Writing AES_GCM_KEY to: {env_path} with token: {token}")
        try:
            with open(env_path, 'r') as f:
                lines = f.readlines()
        except FileNotFoundError:
            lines = []
        found = False
        for i, line in enumerate(lines):
            if line.strip().startswith('AES_GCM_KEY='):
                lines[i] = f'AES_GCM_KEY={token}\n'
                found = True
        if not found:
            # Remove any lines with AES_GCM_KEY (including None or empty)
            lines = [l for l in lines if not l.strip().startswith('AES_GCM_KEY=')]
            lines.append(f'AES_GCM_KEY={token}\n')
        with open(env_path, 'w') as f:
            f.writelines(lines)
        print(f"[SERVER] .env file updated.")
        # Print .env file contents for debug
        try:
            with open(env_path, 'r') as f:
                print('[SERVER] .env contents after update:')
                print(f.read())
        except Exception as e:
            print(f"[SERVER] Failed to read .env after update: {e}")
        # Prepare response: access token (base64-encoded) and message (base64-encoded)
        access_token_b64 = base64.b64encode(token.encode()).decode()
        message = "login successfully"
        message_b64 = base64.b64encode(message.encode()).decode()
        plain_response = {"access_token": token, "message": message}
        print("[SERVER] Login response (plain):", plain_response)
        response_obj = {"access_token": access_token_b64, "message": message_b64}
        print("[SERVER] Login response (base64):", response_obj)
        return response_obj
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e) if str(e) else "Invalid username or password"
        )


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
