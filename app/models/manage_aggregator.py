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
