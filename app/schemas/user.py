from pydantic import BaseModel, EmailStr


class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


from typing import Optional

from typing import Optional
from pydantic import Field

class PasswordReset(BaseModel):
    username: Optional[str] = Field(default=None, nullable=True, description="Username of the user (optional, but either username or email is required)")
    email: Optional[EmailStr] = Field(default=None, nullable=True, description="Email of the user (optional, but either username or email is required)")
    old_password: str = Field(..., description="Current password (required)")
    new_password: str = Field(..., description="New password (required, must not match any of the last 3 passwords)")
    confirm_new_password: str = Field(..., description="Confirm new password (must match new_password)")

    class Config:
        schema_extra = {
            "example": {
                "username": "user1",
                "email": None,
                "old_password": "oldpassword123",
                "new_password": "newpassword456",
                "confirm_new_password": "newpassword456"
            }
        }
