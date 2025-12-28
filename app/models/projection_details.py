from sqlalchemy import Column, Integer, String, Boolean, Float
from app.db.base import Base

class ProjectionDetailsInDB(Base):
    __tablename__ = 'projection_details'
    id = Column(Integer, primary_key=True, autoincrement=True)
    transactionCount = Column(String(255), nullable=True)
    transactionValue = Column(String(255), nullable=True)
    transactionType = Column(String(255), nullable=True)
    transactionTypePercent = Column(String(255), nullable=True)
    isIB = Column(Boolean, nullable=True)
    estimatedTransactions = Column(Float, nullable=True)
    aggregateAmount = Column(Float, nullable=True)
    rate = Column(Float, nullable=True)
    unit = Column(String(255), nullable=True)
    chargesProposed = Column(Float, nullable=True)
    grossAmount = Column(Float, nullable=True)
    vendorShare = Column(Float, nullable=True)
    expectedRevenue = Column(Float, nullable=True)
    isDeleted = Column(Boolean, nullable=True)
    applicationId = Column(Integer, nullable=True)
    aggregatorId = Column(Integer, nullable=True)
    order = Column(Integer, nullable=True)
    allow = Column(Boolean, nullable=True)
    bankUnit = Column(String(255), nullable=True)
