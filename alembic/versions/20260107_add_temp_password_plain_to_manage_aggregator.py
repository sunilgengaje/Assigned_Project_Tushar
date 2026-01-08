"""
Revision ID: add_temp_password_plain_to_manage_aggregator
Revises: 
Create Date: 2026-01-07

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_temp_password_plain_to_manage_aggregator'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('manage_aggregator', sa.Column('temp_password_plain', sa.String(length=255), nullable=True))

def downgrade():
    op.drop_column('manage_aggregator', 'temp_password_plain')
