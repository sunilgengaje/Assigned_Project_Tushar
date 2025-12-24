from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import auth, secure, manage_aggregator
from app.db.base import Base
from app.db.session import engine

Base.metadata.create_all(bind=engine)

from app.middleware.aes_gcm_middleware import AESGCMMiddleware
app = FastAPI(title="FastAPI Clean Auth")
app.add_middleware(AESGCMMiddleware, secure_prefix="/secure")

# Enable CORS for all origins (for Swagger/browser testing)
app.add_middleware(
	CORSMiddleware,
	allow_origins=["*"],
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"],
	expose_headers=["x-captcha-id"],  # Expose captcha header for frontend
)

app.include_router(auth.router)
app.include_router(secure.router)
app.include_router(manage_aggregator.router)
