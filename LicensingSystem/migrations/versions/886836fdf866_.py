"""empty message

Revision ID: 886836fdf866
Revises: 02afe1b57366
Create Date: 2021-07-07 14:42:48.898913

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '886836fdf866'
down_revision = '02afe1b57366'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('key', sa.Column('id', sa.Integer(), nullable=False))
    op.alter_column('key', 'keyId',
               existing_type=sa.VARCHAR(length=80),
               nullable=True)
    op.drop_constraint('key_owner_id_fkey', 'key', type_='foreignkey')
    op.create_foreign_key(None, 'key', 'license', ['owner_id'], ['getKey'])
    op.drop_column('key', 'key')
    op.drop_column('license', 'id')
    op.add_column('user', sa.Column('admin', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'admin')
    op.add_column('license', sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False))
    op.add_column('key', sa.Column('key', sa.VARCHAR(length=80), autoincrement=False, nullable=False))
    op.drop_constraint(None, 'key', type_='foreignkey')
    op.create_foreign_key('key_owner_id_fkey', 'key', 'license', ['owner_id'], ['id'])
    op.alter_column('key', 'keyId',
               existing_type=sa.VARCHAR(length=80),
               nullable=False)
    op.drop_column('key', 'id')
    # ### end Alembic commands ###