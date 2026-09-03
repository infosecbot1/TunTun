from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_profiles_consent_enrollment"
down_revision = "0001_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    utc = "GLOB '????-??-??T??:??:??.??????Z'"
    op.create_table(
        "subjects",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("household_id", sa.String(36), sa.ForeignKey("households.id"), nullable=False),
        sa.Column("guardian_id", sa.String(36), sa.ForeignKey("subjects.id")),
        sa.Column("guardian_generation", sa.Integer, nullable=False),
        sa.Column("profile_class", sa.String(16), nullable=False),
        sa.Column("encrypted_display_label", sa.LargeBinary, nullable=False),
        sa.Column("encrypted_persona_traits", sa.LargeBinary),
        sa.Column("current_consent_receipt_ids", sa.LargeBinary, nullable=False),
        sa.Column("active", sa.Integer, nullable=False),
        sa.Column("authority_generation", sa.Integer, nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("next_reenrollment_reminder_at", sa.String(27)),
        sa.Column("created_at", sa.String(27), nullable=False),
        sa.Column("updated_at", sa.String(27), nullable=False),
        sa.Column("revoked_at", sa.String(27)),
        sa.CheckConstraint(
            "length(id)=36 AND length(household_id)=36 "
            "AND (guardian_id IS NULL OR length(guardian_id)=36)"
        ),
        sa.CheckConstraint("profile_class IN ('owner','adult','k2','n1')"),
        sa.CheckConstraint("active IN (0,1)"),
        sa.CheckConstraint("authority_generation >= 1"),
        sa.CheckConstraint("version >= 1"),
        sa.CheckConstraint(
            "typeof(encrypted_display_label)='blob' "
            "AND length(encrypted_display_label) BETWEEN 1 AND 1024"
        ),
        sa.CheckConstraint(
            "encrypted_persona_traits IS NULL OR "
            "(typeof(encrypted_persona_traits)='blob' "
            "AND length(encrypted_persona_traits) BETWEEN 1 AND 4096)"
        ),
        sa.CheckConstraint(
            "typeof(current_consent_receipt_ids)='blob' "
            "AND length(current_consent_receipt_ids) BETWEEN 2 AND 512"
        ),
        sa.CheckConstraint(f"created_at {utc} AND updated_at {utc}"),
        sa.CheckConstraint(
            f"next_reenrollment_reminder_at IS NULL OR next_reenrollment_reminder_at {utc}"
        ),
        sa.CheckConstraint(f"revoked_at IS NULL OR revoked_at {utc}"),
        sa.CheckConstraint(
            "(profile_class IN ('k2','n1') AND guardian_id IS NOT NULL "
            "AND guardian_generation >= 1) OR "
            "(profile_class IN ('owner','adult') AND guardian_id IS NULL "
            "AND guardian_generation = 0)"
        ),
        sa.CheckConstraint("(active=1 AND revoked_at IS NULL) OR active=0"),
    )
    op.create_table(
        "current_owner_authority",
        sa.Column("household_id", sa.String(36), sa.ForeignKey("households.id"), primary_key=True),
        sa.Column(
            "subject_id", sa.String(36), sa.ForeignKey("subjects.id"), nullable=False, unique=True
        ),
        sa.Column("owner_generation", sa.Integer, nullable=False),
        sa.Column("changed_at", sa.String(27), nullable=False),
        sa.CheckConstraint("owner_generation >= 1"),
        sa.CheckConstraint(f"changed_at {utc}"),
    )
    op.create_table(
        "consent_receipts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("household_id", sa.String(36), sa.ForeignKey("households.id"), nullable=False),
        sa.Column("subject_id", sa.String(36), sa.ForeignKey("subjects.id"), nullable=False),
        sa.Column("actor_id", sa.String(36), sa.ForeignKey("subjects.id"), nullable=False),
        sa.Column("guardian_id", sa.String(36), sa.ForeignKey("subjects.id")),
        sa.Column("guardian_generation", sa.Integer),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column("granted", sa.Integer, nullable=False),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("disclosure_version", sa.String(64), nullable=False),
        sa.Column("commitment_key_id", sa.String(128), nullable=False),
        sa.Column("receipt_hmac", sa.LargeBinary, nullable=False),
        sa.Column("created_at", sa.String(27), nullable=False),
        sa.Column("expires_at", sa.String(27)),
        sa.CheckConstraint(
            "length(id)=36 AND length(household_id)=36 AND length(subject_id)=36 "
            "AND length(actor_id)=36 AND (guardian_id IS NULL OR length(guardian_id)=36)"
        ),
        sa.CheckConstraint(
            "purpose IN "
            "('face','voice','personalization','cloud_stt','cloud_reasoning','cloud_tts',"
            "'web_search','child_durable_memory_v1')"
        ),
        sa.CheckConstraint(
            "purpose!='web_search' OR (actor_id=subject_id AND guardian_id IS NULL)"
        ),
        sa.CheckConstraint(
            "purpose!='web_search' OR "
            "(actor_id=subject_id AND guardian_id IS NULL AND guardian_generation IS NULL)"
        ),
        sa.CheckConstraint(
            "purpose!='child_durable_memory_v1' OR "
            "(guardian_id IS NOT NULL AND guardian_generation >= 1 AND actor_id=guardian_id)"
        ),
        sa.CheckConstraint(
            "purpose!='child_durable_memory_v1' OR "
            "(guardian_id IS NOT NULL AND guardian_generation >= 1 "
            "AND actor_id=guardian_id AND expires_at IS NOT NULL)"
        ),
        sa.CheckConstraint(
            "(guardian_id IS NULL AND guardian_generation IS NULL) OR "
            "(guardian_id IS NOT NULL AND guardian_generation >= 1)"
        ),
        sa.CheckConstraint("granted IN (0,1)"),
        sa.CheckConstraint("length(policy_version) BETWEEN 1 AND 64"),
        sa.CheckConstraint("length(disclosure_version) BETWEEN 1 AND 64"),
        sa.CheckConstraint("length(commitment_key_id) BETWEEN 1 AND 128"),
        sa.CheckConstraint("typeof(receipt_hmac)='blob' AND length(receipt_hmac)=32"),
        sa.CheckConstraint(f"created_at {utc} AND (expires_at IS NULL OR expires_at {utc})"),
        sa.UniqueConstraint("household_id", "subject_id", "purpose", "created_at"),
    )
    op.create_table(
        "guest_disclosure_challenges",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("household_id", sa.String(36), sa.ForeignKey("households.id"), nullable=False),
        sa.Column(
            "session_id",
            sa.String(36),
            sa.ForeignKey("sessions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column("disclosure_version", sa.String(64), nullable=False),
        sa.Column(
            "presentation_receipt_id",
            sa.String(36),
            sa.ForeignKey("event_receipts.id"),
            nullable=False,
        ),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("issued_at", sa.String(27), nullable=False),
        sa.Column("expires_at", sa.String(27), nullable=False),
        sa.Column("consumed_at", sa.String(27)),
        sa.Column("commitment_key_id", sa.String(128), nullable=False),
        sa.Column("challenge_hmac", sa.LargeBinary, nullable=False),
        sa.CheckConstraint(
            "length(id)=36 AND length(household_id)=36 AND length(session_id)=36 "
            "AND length(presentation_receipt_id)=36"
        ),
        sa.CheckConstraint("purpose IN ('cloud_stt','cloud_reasoning','cloud_tts')"),
        sa.CheckConstraint("state IN ('open','accepted','denied')"),
        sa.CheckConstraint("length(disclosure_version) BETWEEN 1 AND 64"),
        sa.CheckConstraint("length(commitment_key_id) BETWEEN 1 AND 128"),
        sa.CheckConstraint("typeof(challenge_hmac)='blob' AND length(challenge_hmac)=32"),
        sa.CheckConstraint(f"issued_at {utc} AND expires_at {utc}"),
        sa.CheckConstraint(f"consumed_at IS NULL OR consumed_at {utc}"),
        sa.CheckConstraint("expires_at > issued_at"),
        sa.CheckConstraint(
            "(state='open' AND consumed_at IS NULL) OR "
            "(state IN ('accepted','denied') AND consumed_at IS NOT NULL)"
        ),
        sa.UniqueConstraint("presentation_receipt_id"),
        sa.UniqueConstraint(
            "household_id",
            "session_id",
            "purpose",
            "disclosure_version",
            "issued_at",
        ),
    )
    op.create_table(
        "guest_session_consent_receipts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("household_id", sa.String(36), sa.ForeignKey("households.id"), nullable=False),
        sa.Column(
            "session_id",
            sa.String(36),
            sa.ForeignKey("sessions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column(
            "challenge_id",
            sa.String(36),
            sa.ForeignKey("guest_disclosure_challenges.id"),
            nullable=False,
        ),
        sa.Column(
            "presentation_receipt_id",
            sa.String(36),
            sa.ForeignKey("event_receipts.id"),
            nullable=False,
        ),
        sa.Column("disclosure_version", sa.String(64), nullable=False),
        sa.Column("granted", sa.Integer, nullable=False),
        sa.Column("issued_at", sa.String(27), nullable=False),
        sa.Column("expires_at", sa.String(27), nullable=False),
        sa.Column("revoked_at", sa.String(27)),
        sa.Column("commitment_key_id", sa.String(128), nullable=False),
        sa.Column("receipt_hmac", sa.LargeBinary, nullable=False),
        sa.CheckConstraint(
            "length(id)=36 AND length(household_id)=36 AND length(session_id)=36 "
            "AND length(challenge_id)=36 AND length(presentation_receipt_id)=36"
        ),
        sa.CheckConstraint("purpose IN ('cloud_stt','cloud_reasoning','cloud_tts')"),
        sa.CheckConstraint("granted IN (0,1)"),
        sa.CheckConstraint("length(disclosure_version) BETWEEN 1 AND 64"),
        sa.CheckConstraint("length(commitment_key_id) BETWEEN 1 AND 128"),
        sa.CheckConstraint("typeof(receipt_hmac)='blob' AND length(receipt_hmac)=32"),
        sa.CheckConstraint(f"issued_at {utc} AND expires_at {utc}"),
        sa.CheckConstraint(f"revoked_at IS NULL OR revoked_at {utc}"),
        sa.CheckConstraint("expires_at > issued_at"),
        sa.CheckConstraint("revoked_at IS NULL OR revoked_at >= issued_at"),
        sa.UniqueConstraint("household_id", "session_id", "purpose", "issued_at"),
    )
    op.create_table(
        "enrollment_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("subject_id", sa.String(36), sa.ForeignKey("subjects.id"), nullable=False),
        sa.Column("modality", sa.String(16), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("auth_receipt_id", sa.String(36), nullable=False),
        sa.Column(
            "consent_receipt_id",
            sa.String(36),
            sa.ForeignKey("consent_receipts.id"),
            nullable=False,
        ),
        sa.Column("reenrollment_days", sa.Integer, nullable=False),
        sa.Column("created_at", sa.String(27), nullable=False),
        sa.Column("expires_at", sa.String(27), nullable=False),
        sa.Column("closed_at", sa.String(27)),
        sa.CheckConstraint("modality IN ('face','voice')"),
        sa.CheckConstraint(
            "state IN ('requested','capturing','calibrating','approved','cancelled','expired')"
        ),
        sa.CheckConstraint("reenrollment_days BETWEEN 30 AND 365"),
        sa.CheckConstraint(f"created_at {utc} AND expires_at {utc}"),
        sa.CheckConstraint(f"closed_at IS NULL OR closed_at {utc}"),
    )
    op.create_table(
        "biometric_templates",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("subject_id", sa.String(36), sa.ForeignKey("subjects.id"), nullable=False),
        sa.Column("modality", sa.String(16), nullable=False),
        sa.Column("model_version", sa.String(128), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary, nullable=False),
        sa.Column("nonce", sa.LargeBinary, nullable=False),
        sa.Column("wrapped_dek", sa.LargeBinary, nullable=False),
        sa.Column("root_key_id", sa.String(128), nullable=False),
        sa.Column(
            "consent_receipt_id",
            sa.String(36),
            sa.ForeignKey("consent_receipts.id"),
            nullable=False,
        ),
        sa.Column("created_at", sa.String(27), nullable=False),
        sa.Column("expires_at", sa.String(27)),
        sa.Column("revoked_at", sa.String(27)),
        sa.CheckConstraint("modality IN ('face','voice')"),
        sa.CheckConstraint(f"created_at {utc}"),
        sa.CheckConstraint(f"expires_at IS NULL OR expires_at {utc}"),
        sa.CheckConstraint(f"revoked_at IS NULL OR revoked_at {utc}"),
        sa.CheckConstraint("revoked_at IS NULL OR expires_at IS NOT NULL"),
    )
    op.create_table(
        "subject_revocation_outbox",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("event_key", sa.String(160), nullable=False, unique=True),
        sa.Column("subject_id", sa.String(36), sa.ForeignKey("subjects.id"), nullable=False),
        sa.Column("new_authority_generation", sa.Integer, nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("occurred_at", sa.String(27), nullable=False),
        sa.Column("claimed_at", sa.String(27)),
        sa.Column("lease_owner", sa.String(36)),
        sa.Column("lease_expires_at", sa.String(27)),
        sa.Column("fencing_token", sa.Integer, nullable=False),
        sa.Column("completed_at", sa.String(27)),
        sa.Column("attempt_count", sa.Integer, nullable=False),
        sa.Column("last_error", sa.String(512)),
        sa.Column("reconciliation_receipt_id", sa.String(36), unique=True),
        sa.CheckConstraint("new_authority_generation >= 2"),
        sa.CheckConstraint("state IN ('pending','processing','completed')"),
        sa.CheckConstraint("attempt_count >= 0 AND fencing_token >= 0"),
        sa.CheckConstraint(f"occurred_at {utc}"),
        sa.CheckConstraint(f"claimed_at IS NULL OR claimed_at {utc}"),
        sa.CheckConstraint(f"lease_expires_at IS NULL OR lease_expires_at {utc}"),
        sa.CheckConstraint(f"completed_at IS NULL OR completed_at {utc}"),
        sa.CheckConstraint(
            "(state='pending' AND claimed_at IS NULL AND lease_owner IS NULL "
            "AND lease_expires_at IS NULL AND completed_at IS NULL) OR "
            "(state='processing' AND claimed_at IS NOT NULL AND lease_owner IS NOT NULL "
            "AND lease_expires_at IS NOT NULL AND completed_at IS NULL) OR "
            "(state='completed' AND claimed_at IS NOT NULL AND lease_owner IS NULL "
            "AND lease_expires_at IS NULL AND completed_at IS NOT NULL "
            "AND reconciliation_receipt_id IS NOT NULL)"
        ),
    )
    op.create_table(
        "subject_revocation_effects",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "event_id",
            sa.String(36),
            sa.ForeignKey("subject_revocation_outbox.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("family", sa.String(32), nullable=False),
        sa.Column("idempotency_key", sa.String(36), nullable=False, unique=True),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("lease_owner", sa.String(36)),
        sa.Column("leased_until", sa.String(27)),
        sa.Column("fencing_token", sa.Integer, nullable=False),
        sa.Column("attempt_count", sa.Integer, nullable=False),
        sa.Column("downstream_receipt_id", sa.String(36)),
        sa.Column("disposition", sa.String(32)),
        sa.Column("last_error", sa.String(128)),
        sa.Column("created_at", sa.String(27), nullable=False),
        sa.Column("completed_at", sa.String(27)),
        sa.UniqueConstraint("event_id", "family", name="uq_subject_revocation_effect_event_family"),
        sa.CheckConstraint(
            "family IN "
            "('provider_routes','search_capabilities','action_authorities','memory_authorities')"
        ),
        sa.CheckConstraint("state IN ('pending','applying','completed')"),
        sa.CheckConstraint("attempt_count >= 0 AND fencing_token >= 0"),
        sa.CheckConstraint(f"created_at {utc}"),
        sa.CheckConstraint(f"leased_until IS NULL OR leased_until {utc}"),
        sa.CheckConstraint(f"completed_at IS NULL OR completed_at {utc}"),
        sa.CheckConstraint(
            "(state='pending' AND lease_owner IS NULL AND leased_until IS NULL "
            "AND completed_at IS NULL) OR "
            "(state='applying' AND lease_owner IS NOT NULL AND leased_until IS NOT NULL "
            "AND completed_at IS NULL) OR "
            "(state='completed' AND lease_owner IS NULL AND leased_until IS NULL "
            "AND completed_at IS NOT NULL AND downstream_receipt_id IS NOT NULL "
            "AND disposition IS NOT NULL)"
        ),
    )
    op.create_index(
        "ux_subjects_one_owner",
        "subjects",
        ["household_id"],
        unique=True,
        sqlite_where=sa.text("profile_class='owner' AND active=1"),
    )
    op.create_index(
        "ix_consent_subject_purpose_time",
        "consent_receipts",
        ["subject_id", "purpose", "created_at"],
    )
    op.create_index(
        "ix_guest_disclosure_session_purpose_state",
        "guest_disclosure_challenges",
        ["household_id", "session_id", "purpose", "state", "expires_at"],
    )
    op.create_index(
        "ix_guest_consent_session_purpose_time",
        "guest_session_consent_receipts",
        ["household_id", "session_id", "purpose", "issued_at"],
    )
    op.create_index(
        "ux_guest_consent_one_grant_per_challenge",
        "guest_session_consent_receipts",
        ["challenge_id"],
        unique=True,
        sqlite_where=sa.text("granted=1"),
    )
    op.create_index(
        "ux_biometric_active_model",
        "biometric_templates",
        ["subject_id", "modality", "model_version"],
        unique=True,
        sqlite_where=sa.text("revoked_at IS NULL"),
    )
    op.create_index(
        "ix_subject_revocation_outbox_drain",
        "subject_revocation_outbox",
        ["state", "occurred_at", "id"],
    )
    op.create_index(
        "ix_subject_revocation_effect_lease",
        "subject_revocation_effects",
        ["state", "leased_until", "id"],
    )


def downgrade() -> None:
    op.drop_index("ix_subject_revocation_effect_lease", table_name="subject_revocation_effects")
    op.drop_table("subject_revocation_effects")
    op.drop_index("ix_subject_revocation_outbox_drain", table_name="subject_revocation_outbox")
    op.drop_table("subject_revocation_outbox")
    op.drop_index("ux_biometric_active_model", table_name="biometric_templates")
    op.drop_table("biometric_templates")
    op.drop_table("enrollment_sessions")
    op.drop_index(
        "ux_guest_consent_one_grant_per_challenge",
        table_name="guest_session_consent_receipts",
    )
    op.drop_index(
        "ix_guest_consent_session_purpose_time",
        table_name="guest_session_consent_receipts",
    )
    op.drop_table("guest_session_consent_receipts")
    op.drop_index(
        "ix_guest_disclosure_session_purpose_state",
        table_name="guest_disclosure_challenges",
    )
    op.drop_table("guest_disclosure_challenges")
    op.drop_index("ix_consent_subject_purpose_time", table_name="consent_receipts")
    op.drop_table("consent_receipts")
    op.drop_table("current_owner_authority")
    op.drop_index("ux_subjects_one_owner", table_name="subjects")
    op.drop_table("subjects")
