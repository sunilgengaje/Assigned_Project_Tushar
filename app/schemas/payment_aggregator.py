from pydantic import BaseModel
from typing import Optional

class PaymentAggregator(BaseModel):
    aggregatorId: int
    aggregatorName: str
    createdAt: str
    endDate: str
    isDeleted: bool = False
    applicationId: int
    totalEstimatedTransactions: float
    totalAggregateAmount: float
    totalGrossAmount: float
    totalVendorShare: float
    totalExpectedRevenue: float
    status: str
    quoteStatus: str
    sumOfRate: Optional[float] = None
    categories: Optional[str] = None
    avg_no_of_transactions: Optional[float] = None
    avg_ticket_size: Optional[float] = None
