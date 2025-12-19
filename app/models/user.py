
from sqlalchemy import Column, Integer, String
from app.db.base import Base

from sqlalchemy import Text
import json

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    is_logged_in = Column(String(1), default='N', nullable=False)
    password_history = Column(Text, default='[]', nullable=False)  # JSON-encoded list of last 3 hashes
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    lockout_until = Column(String(25), nullable=True)  # ISO datetime string, nullable
