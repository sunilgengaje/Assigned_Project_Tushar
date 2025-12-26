from sqlalchemy import Column, Integer, String, Boolean
from app.db.base import Base

class ManageAggregatorBackup(Base):
    __tablename__ = "manage_aggregator_backup"

    aggregatorId = Column(Integer, primary_key=True, autoincrement=True)
    aggregatorName = Column(String(100), nullable=False)
    contactPersonName = Column(String(100), nullable=False)
    email = Column(String(100), unique=False, nullable=False)
    mobileNo = Column(String(20), nullable=False)
    location = Column(String(100), nullable=False)
    services = Column(String(255), nullable=False)
    isDeleted = Column(Boolean, default=False, nullable=False)
    status = Column(String(32), default="Created", nullable=False)
    password = Column(String(255), nullable=False)
    is_logged_in = Column(String(1), default='N', nullable=False)
    password_history = Column(String(1024), default='[]', nullable=False)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    lockout_until = Column(String(25), nullable=True)
    # Add a timestamp for backup tracking
    backup_timestamp = Column(String(32), nullable=False)
