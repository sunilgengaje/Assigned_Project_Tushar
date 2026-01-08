from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import auth, secure, manage_aggregator
from app.db.base import Base
from app.db.session import engine
import os
from dotenv import load_dotenv
from app.middleware.aes_gcm_middleware import AESGCMMiddleware
import logging

load_dotenv(dotenv_path=".env")
API_ENV = os.getenv("API_ENV", "DEV").upper()

# Suppress SQLAlchemy engine logs in production
if API_ENV == "PROD":
	logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

Base.metadata.create_all(bind=engine)


# Global dependency: require authentication for all routes except login, register, captcha
from fastapi import Depends
from app.api.deps import get_current_user

from fastapi import Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

EXEMPT_PATHS = [
	"/api/login",
	"/api/register",
	"/api/captcha",
	"/api/manage-aggregator/plain",
	"/api/manage-aggregator/validate-details",
	"/api/manage-aggregator/reset-password-plain",
	"/api/unlock-user",
	"/add-manage-aggregator-encrypted",
	"/api/add-manage-aggregator-encrypted",
]

def global_auth_dependency(request: Request, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False))):
	for prefix in EXEMPT_PATHS:
		if request.url.path.startswith(prefix):
			return None
	# If not exempt, require authentication
	if not credentials or not credentials.credentials:
		from fastapi import HTTPException, status
		raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header")
	from app.api.deps import get_current_user
	return get_current_user(credentials)

app = FastAPI(title="FastAPI Clean Auth", dependencies=[Depends(global_auth_dependency)])
app.add_middleware(AESGCMMiddleware, secure_prefix="/secure")

# Dynamic CORS origins for DEV/UAT
def get_allowed_origins():
	if API_ENV == "DEV":
		return ["*"]
	elif API_ENV == "UAT":
		return [os.getenv("API_URL_UAT")]
	else:
		return []

app.add_middleware(
	CORSMiddleware,
	allow_origins=["*"],  # Allow all origins
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"],
	expose_headers=["x-captcha-id"],
)

app.include_router(auth.router)
app.include_router(secure.router)
app.include_router(manage_aggregator.router)
