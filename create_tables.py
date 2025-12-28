# Run this script once to auto-create all tables in your database using SQLAlchemy models.

from app.db.session import engine
from app.models.manage_aggregator import Base as ManageAggregatorBase
from app.models import ProjectionDetailsInDB

# If you have a central Base, import and use that instead.
# from app.models.base import Base

# Create all tables for imported models
ManageAggregatorBase.metadata.create_all(bind=engine)
print("All tables created successfully.")
