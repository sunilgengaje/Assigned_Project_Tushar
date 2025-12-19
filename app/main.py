from fastapi import FastAPI
from app.api.routes import auth
from app.db.base import Base
from app.db.session import engine

Base.metadata.create_all(bind=engine)

app = FastAPI(title="FastAPI Clean Auth")

app.include_router(auth.router)
