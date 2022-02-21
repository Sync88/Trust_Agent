"""Initial database migration

Revision ID: 8a44a4364f5a
Revises: None
Create Date: 2020-10-08 20:29:54.883816

"""
import sys

from alembic import op
import sqlalchemy as sa

import keylime
sys.path.append("..")


# revision identifiers, used by Alembic.
revision = '8a44a4364f5a'
down_revision = None
branch_labels = None
depends_on = None


def upgrade(engine_name):
    globals()["upgrade_%s" % engine_name]()


def downgrade(engine_name):
    globals()["downgrade_%s" % engine_name]()


def upgrade_registrar():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('registrarmain',
                    sa.Column('agent_id', sa.String(length=80), nullable=False),
                    sa.Column('key', sa.String(length=45), nullable=True),
                    sa.Column('aik', sa.String(length=500), nullable=True),
                    sa.Column('ek', sa.String(length=500), nullable=True),
                    sa.Column('ekcert', sa.String(length=2048), nullable=True),
                    sa.Column('virtual', sa.Integer(), nullable=True),
                    sa.Column('active', sa.Integer(), nullable=True),
                    sa.Column('physical_tpm', sa.Integer(), nullable=True),
                    sa.Column('provider_keys', keylime.db.registrar_db.JSONPickleType(), nullable=True),
                    sa.Column('regcount', sa.Integer(), nullable=True),
                    sa.PrimaryKeyConstraint('agent_id'))
                    #SILVIO
    # ### end Alembic commands ###


def downgrade_registrar():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('registrarmain')
    # ### end Alembic commands ###


def upgrade_cloud_verifier():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('verifiermain',
                    sa.Column('agent_id', sa.String(length=80), nullable=False),
                    sa.Column('v', sa.String(length=45), nullable=True),
                    sa.Column('ip', sa.String(length=15), nullable=True),
                    sa.Column('port', sa.Integer(), nullable=True),
                    sa.Column('operational_state', sa.Integer(), nullable=True),
                    sa.Column('public_key', sa.String(length=500), nullable=True),
                    sa.Column('tpm_policy', sa.String(length=1000), nullable=True),
                    sa.Column('vtpm_policy', sa.String(length=1000), nullable=True),
                    sa.Column('meta_data', sa.String(length=200), nullable=True),
                    sa.Column('ima_whitelist', sa.Text(length=429400000), nullable=True),
                    sa.Column('revocation_key', sa.String(length=2800), nullable=True),
                    sa.Column('tpm_version', sa.Integer(), nullable=True),
                    sa.Column('accept_tpm_hash_algs', keylime.db.verifier_db.JSONPickleType(), nullable=True),
                    sa.Column('accept_tpm_encryption_algs', keylime.db.verifier_db.JSONPickleType(), nullable=True),
                    sa.Column('accept_tpm_signing_algs', keylime.db.verifier_db.JSONPickleType(), nullable=True),
                    sa.Column('hash_alg', sa.String(length=10), nullable=True),
                    sa.Column('enc_alg', sa.String(length=10), nullable=True),
                    sa.Column('sign_alg', sa.String(length=10), nullable=True),
                    sa.PrimaryKeyConstraint('agent_id'))
    # ### end Alembic commands ###


def downgrade_cloud_verifier():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('verifiermain')
    # ### end Alembic commands ###
