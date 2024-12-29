"""Add expiration dates

Revision ID: a9ff3b1c03ad
Revises: 
Create Date: 2024-12-29 19:48:49.556553

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a9ff3b1c03ad'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('project', schema=None) as batch_op:
        batch_op.add_column(sa.Column('expires_at', sa.Date(), nullable=True))

    with op.batch_alter_table('proposal', schema=None) as batch_op:
        batch_op.add_column(sa.Column('expires_at', sa.Date(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('proposal', schema=None) as batch_op:
        batch_op.drop_column('expires_at')

    with op.batch_alter_table('project', schema=None) as batch_op:
        batch_op.drop_column('expires_at')

    # ### end Alembic commands ###