"""empty message

Revision ID: 35f454c70f28
Revises: c860c7ca9aa4
Create Date: 2021-08-24 14:18:41.804289

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '35f454c70f28'
down_revision = 'c860c7ca9aa4'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('superadmin', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'superadmin')
    # ### end Alembic commands ###
