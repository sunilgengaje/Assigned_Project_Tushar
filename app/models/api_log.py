from sqlalchemy import Column, Integer, String, Text, DateTime
from app.db.base import Base
from datetime import datetime

class APILog(Base):
    __tablename__ = "api_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)

    username = Column(String(100), nullable=True)
    client_ip = Column(String(45), nullable=True)  # IPv6 compatible
    api_endpoint = Column(String(255), nullable=False)
    request_data = Column(Text, nullable=True)
    access_time = Column(DateTime, default=datetime.utcnow, nullable=False)
    accessed_key = Column(String(64), nullable=True)  # base64-encoded AES key
    status = Column(String(1), nullable=False, default='F')  # 'S' for success, 'F' for failure
    session_id = Column(String(255), nullable=True)  # Session or token identifier
