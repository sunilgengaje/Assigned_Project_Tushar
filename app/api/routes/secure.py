from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from app.api.deps import get_current_user

router = APIRouter(prefix="/secure", tags=["Secure"])

@router.post("/hello")
def secure_hello(current_user: str = Depends(get_current_user)):
    # This will be encrypted/decrypted by your AES-GCM middleware
    return {"message": f"Hello, {current_user}! This is a secure, encrypted endpoint."}
