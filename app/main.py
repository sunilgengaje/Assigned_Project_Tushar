from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import auth, secure, manage_aggregator
from app.db.base import Base
from app.db.session import engine
import os
from dotenv import load_dotenv
from app.middleware.aes_gcm_middleware import AESGCMMiddleware

load_dotenv(dotenv_path=".env")
API_ENV = os.getenv("API_ENV", "DEV").upper()

Base.metadata.create_all(bind=engine)

app = FastAPI(title="FastAPI Clean Auth")
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
