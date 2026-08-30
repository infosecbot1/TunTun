from __future__ import annotations

from alembic import op
from tuntun_core.adapters.sqlcipher.foundation_0001 import FOUNDATION_0001_METADATA

revision = "0001_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    FOUNDATION_0001_METADATA.create_all(bind=bind)
    op.execute(
        "CREATE TRIGGER audit_receipts_no_update "
        "BEFORE UPDATE ON audit_receipts "
        "BEGIN SELECT RAISE(ABORT, 'audit receipts are append-only'); END"
    )
    op.execute(
        "CREATE TRIGGER audit_receipts_no_delete "
        "BEFORE DELETE ON audit_receipts "
        "BEGIN SELECT RAISE(ABORT, 'audit receipts are append-only'); END"
    )


def downgrade() -> None:
    bind = op.get_bind()
    FOUNDATION_0001_METADATA.drop_all(bind=bind)
