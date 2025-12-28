from sqlalchemy import Column, Integer, String, Float, Boolean, Sequence
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class PaymentAggregatorInDB(Base):
    __tablename__ = 'payment_aggregators'

    id = Column(Integer, Sequence('payment_aggregator_id_seq'), primary_key=True)
    aggregatorId = Column(Integer)
    aggregatorName = Column(String(255))
    createdAt = Column(String(255))
    endDate = Column(String(255))
    isDeleted = Column(Boolean, default=False)
    applicationId = Column(Integer)
    totalEstimatedTransactions = Column(Float)
    totalAggregateAmount = Column(Float)
    totalGrossAmount = Column(Float)
    totalVendorShare = Column(Float)
    totalExpectedRevenue = Column(Float)
    status = Column(String(255))
    quoteStatus = Column(String(255))
    sumOfRate = Column(Float, nullable=True)
    categories = Column(String(255), nullable=True)
    avg_no_of_transactions = Column(Float, nullable=True)
    avg_ticket_size = Column(Float, nullable=True)
        # applicationid = Column(Integer, nullable=True)
