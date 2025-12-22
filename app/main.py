from fastapi import FastAPI
from app.api.routes import auth, secure
from app.db.base import Base
from app.db.session import engine

Base.metadata.create_all(bind=engine)


from app.middleware.aes_gcm_middleware import AESGCMMiddleware
app = FastAPI(title="FastAPI Clean Auth")
app.add_middleware(AESGCMMiddleware, secure_prefix="/secure")

app.include_router(auth.router)
app.include_router(secure.router)
