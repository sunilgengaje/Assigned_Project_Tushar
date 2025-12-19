
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



@router.post("/register")
def register(user: UserRegister, db: Session = Depends(get_db)):
    auth_service.register(db, user.username, user.email, user.password)
    return {"message": "User registered successfully"}

@router.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    try:
        token = auth_service.login(db, user.username, user.password)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e) if str(e) else "Invalid username or password"
        )
    return {"access_token": token, "token_type": "bearer"}


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
