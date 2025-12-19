from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext

import os
from dotenv import load_dotenv
load_dotenv(dotenv_path=".env")
SECRET_KEY = os.getenv("SECRET_KEY", "SUPER_SECRET_KEY_CHANGE_ME")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")



# bcrypt expects a string, not bytes, and the 72-character limit is for characters, not bytes.
def _normalize_password(password: str) -> str:
    if len(password) > 72:
        # Optionally, raise an error or just truncate
        # raise ValueError("Password cannot be longer than 72 characters for bcrypt.")
        return password[:72]
    return password


def hash_password(password: str) -> str:
    return pwd_context.hash(_normalize_password(password))


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(_normalize_password(password), hashed)


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str):
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
