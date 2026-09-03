from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_biometric_template_enrollment_binding"
down_revision = "0002_profiles_consent_enrollment"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("enrollment_sessions") as batch_op:
        batch_op.add_column(sa.Column("synthetic_template_id", sa.String(36), nullable=True))
        batch_op.create_check_constraint(
            "ck_enrollment_sessions_synthetic_template_id_uuid",
            "synthetic_template_id IS NULL OR length(synthetic_template_id)=36",
        )
        batch_op.create_index(
            "ux_enrollment_sessions_synthetic_template_id",
            ["synthetic_template_id"],
            unique=True,
        )

    with op.batch_alter_table("biometric_templates") as batch_op:
        batch_op.add_column(
            sa.Column("enrollment_session_id", sa.String(36), nullable=True),
        )
        batch_op.create_foreign_key(
            "fk_biometric_templates_enrollment_session_id",
            "enrollment_sessions",
            ["enrollment_session_id"],
            ["id"],
        )
        batch_op.create_index(
            "ix_biometric_templates_enrollment_session",
            ["enrollment_session_id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("biometric_templates") as batch_op:
        batch_op.drop_index("ix_biometric_templates_enrollment_session")
        batch_op.drop_constraint(
            "fk_biometric_templates_enrollment_session_id",
            type_="foreignkey",
        )
        batch_op.drop_column("enrollment_session_id")

    with op.batch_alter_table("enrollment_sessions") as batch_op:
        batch_op.drop_index("ux_enrollment_sessions_synthetic_template_id")
        batch_op.drop_constraint(
            "ck_enrollment_sessions_synthetic_template_id_uuid",
            type_="check",
        )
        batch_op.drop_column("synthetic_template_id")
