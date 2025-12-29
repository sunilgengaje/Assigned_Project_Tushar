
from fastapi import APIRouter, Depends, status
from app.api.deps import get_current_user
from app.core.response_utils import success_response

router = APIRouter(prefix="/api/secure", tags=["Secure"])

@router.post("/hello")
def secure_hello(current_user: str = Depends(get_current_user)):
    # This will be encrypted/decrypted by your AES-GCM middleware
    return success_response(
        message=f"Hello, {current_user}! This is a secure, encrypted endpoint.",
        data=None
    )
