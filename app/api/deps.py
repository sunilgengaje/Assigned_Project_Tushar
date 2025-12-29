from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.core.security import decode_token
from app.core.jwt_blacklist import is_token_blacklisted

security = HTTPBearer()

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    try:
        print("[DEBUG] get_current_user: Incoming token:", credentials.credentials)
        payload = decode_token(credentials.credentials)
        print("[DEBUG] get_current_user: Decoded payload:", payload)
        jti = payload.get("jti")
        if jti:
            try:
                if is_token_blacklisted(jti):
                    print("[DEBUG] get_current_user: Token is blacklisted! jti:", jti)
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Token has been revoked. Please log in again."
                    )
            except Exception as redis_exc:
                print("[DEBUG] get_current_user: Redis unavailable:", redis_exc)
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Authentication service unavailable (Redis down). Please try again later."
                )
        return payload["sub"]
    except HTTPException:
        raise
    except Exception as e:
        print("[DEBUG] get_current_user: Exception:", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
