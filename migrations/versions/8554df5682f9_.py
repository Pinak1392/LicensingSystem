"""empty message

Revision ID: 8554df5682f9
Revises: d771666e4b88
Create Date: 2021-08-06 09:59:49.877730

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8554df5682f9'
down_revision = 'd771666e4b88'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('key', sa.Column('accessAmount', sa.Integer(), nullable=True))
    op.add_column('license', sa.Column('owner_id', sa.Integer(), nullable=False))
    op.drop_constraint('license_owner_email_fkey', 'license', type_='foreignkey')
    op.create_foreign_key(None, 'license', 'user', ['owner_id'], ['id'], onupdate='cascade')
    op.drop_column('license', 'owner_email')
    op.add_column('user', sa.Column('id', sa.Integer(), nullable=False))
    op.create_unique_constraint(None, 'user', ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'user', type_='unique')
    op.drop_column('user', 'id')
    op.add_column('license', sa.Column('owner_email', sa.VARCHAR(length=40), autoincrement=False, nullable=False))
    op.drop_constraint(None, 'license', type_='foreignkey')
    op.create_foreign_key('license_owner_email_fkey', 'license', 'user', ['owner_email'], ['email'], onupdate='CASCADE')
    op.drop_column('license', 'owner_id')
    op.drop_column('key', 'accessAmount')
    # ### end Alembic commands ###
