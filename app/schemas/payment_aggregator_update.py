from pydantic import BaseModel

class PaymentAggregatorUpdate(BaseModel):
    aggregatorName: str = None
    createdAt: str = None
    endDate: str = None
    isDeleted: bool = None
    applicationId: int = None
    totalEstimatedTransactions: float = None
    totalAggregateAmount: float = None
    totalGrossAmount: float = None
    totalVendorShare: float = None
    totalExpectedRevenue: float = None
    status: str = None
    quoteStatus: str = None
    sumOfRate: float = None
    categories: str = None
    avg_no_of_transactions: float = None
    avg_ticket_size: float = None
