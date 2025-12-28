from sqlalchemy import Column, Integer, String, Boolean
from app.db.base import Base

class ManageAggregator(Base):
    __tablename__ = "manage_aggregator"

    aggregatorId = Column(Integer, primary_key=True, autoincrement=True)
    aggregatorName = Column(String(100), nullable=False)
    contactPersonName = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    mobileNo = Column(String(20), nullable=False)
    location = Column(String(100), nullable=False)
    services = Column(String(255), nullable=False)
    isDeleted = Column(Boolean, default=False, nullable=False)
    status = Column(String(32), default="Created", nullable=False)

    # User fields
    password = Column(String(255), nullable=False)
    is_logged_in = Column(String(1), default='N', nullable=False)
    password_history = Column(String(1024), default='[]', nullable=False)  # JSON-encoded list
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    lockout_until = Column(String(25), nullable=True)  # ISO datetime string, nullable

