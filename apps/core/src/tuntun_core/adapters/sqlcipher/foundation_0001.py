from __future__ import annotations

from sqlalchemy import (
    CheckConstraint,
    Column,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    text,
)

MAX_BOUNDED_COUNT = 9_000_000_000_000_000
MAX_QUOTE_MICROS_SGD = 1_000_000_000_000
MAX_PROVIDER_RATE_MICRO_USD = 1_000_000_000
MAX_INPUT_TIER_TOKENS = 10_000_000

FOUNDATION_TABLE_NAMES: frozenset[str] = frozenset(
    {
        "households",
        "devices",
        "sessions",
        "event_receipts",
        "idempotency_receipts",
        "audit_receipts",
        "audit_segments",
        "redaction_receipts",
        "provider_calls",
        "provider_response_receipts",
        "provider_prices",
        "budget_reservations",
        "cost_ledger",
        "runtime_settings",
        "reachy_core_tx_sequences",
        "reachy_duplex_correlations",
    }
)
assert len(FOUNDATION_TABLE_NAMES) == 16

FOUNDATION_0001_METADATA = MetaData()
_metadata = FOUNDATION_0001_METADATA


def _uuid_pk(name: str = "id") -> Column[str]:
    return Column(name, String(36), primary_key=True)


def _utc_text(name: str, nullable: bool = False) -> Column[str]:
    return Column(name, String(27), nullable=nullable)


def _utc_constraint(name: str, nullable: bool = False) -> CheckConstraint:
    valid = (
        f"length({name}) = 27 AND "
        f"{name} GLOB "
        "'[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T"
        "[0-9][0-9]:[0-9][0-9]:[0-9][0-9]."
        "[0-9][0-9][0-9][0-9][0-9][0-9]Z'"
    )
    return CheckConstraint(f"{name} IS NULL OR ({valid})" if nullable else valid)


def _lower_sha256(column: str) -> str:
    return f"length({column}) = 64 AND {column} NOT GLOB '*[^0-9a-f]*'"


def _integer_storage_constraint(name: str, *, nullable: bool = False) -> CheckConstraint:
    exact = f"typeof({name}) = 'integer'"
    return CheckConstraint(f"{name} IS NULL OR ({exact})" if nullable else exact)


households = Table(
    "households",
    _metadata,
    _uuid_pk(),
    Column("display_label_ciphertext", LargeBinary, nullable=False),
    Column("timezone", String(32), nullable=False, server_default="Asia/Singapore"),
    _utc_text("created_at"),
    CheckConstraint("timezone = 'Asia/Singapore'"),
    _utc_constraint("created_at"),
)

devices = Table(
    "devices",
    _metadata,
    _uuid_pk(),
    Column(
        "household_id",
        String(36),
        ForeignKey("households.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("kind", String(32), nullable=False),
    Column("certificate_fingerprint", String(128), nullable=False, unique=True),
    Column("signing_public_key", LargeBinary, nullable=False),
    Column("signing_key_id", String(128), nullable=False),
    Column("last_sequence", Integer, nullable=False, server_default=text("0")),
    _utc_text("paired_at"),
    _utc_text("revoked_at", nullable=True),
    _integer_storage_constraint("last_sequence"),
    CheckConstraint(f"last_sequence BETWEEN 0 AND {MAX_BOUNDED_COUNT}"),
    _utc_constraint("paired_at"),
    _utc_constraint("revoked_at", nullable=True),
)

sessions = Table(
    "sessions",
    _metadata,
    _uuid_pk(),
    Column(
        "household_id",
        String(36),
        ForeignKey("households.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("device_id", String(36), ForeignKey("devices.id"), nullable=False),
    Column("state", String(32), nullable=False),
    Column("speaker_subject_id", String(36), nullable=True),
    _utc_text("opened_at"),
    _utc_text("last_activity_at"),
    _utc_text("closed_at", nullable=True),
    _utc_constraint("opened_at"),
    _utc_constraint("last_activity_at"),
    _utc_constraint("closed_at", nullable=True),
)
Index(
    "uq_sessions_one_active_household",
    sessions.c.household_id,
    unique=True,
    sqlite_where=sessions.c.closed_at.is_(None),
)

event_receipts = Table(
    "event_receipts",
    _metadata,
    _uuid_pk(),
    Column(
        "household_id",
        String(36),
        ForeignKey("households.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("device_id", String(36), ForeignKey("devices.id"), nullable=False),
    Column("event_type", String(128), nullable=False),
    Column("correlation_id", String(36), nullable=False),
    Column("device_sequence", Integer, nullable=False),
    Column("payload_hmac_key_id", String(128), nullable=False),
    Column("payload_hmac_b64", String(128), nullable=False),
    Column("decision", String(64), nullable=False),
    _utc_text("occurred_at"),
    _integer_storage_constraint("device_sequence"),
    CheckConstraint(f"device_sequence BETWEEN 0 AND {MAX_BOUNDED_COUNT}"),
    _utc_constraint("occurred_at"),
    UniqueConstraint("device_id", "device_sequence", name="uq_event_device_sequence"),
)

idempotency_receipts = Table(
    "idempotency_receipts",
    _metadata,
    _uuid_pk(),
    Column("operation", String(128), nullable=False),
    Column("scope", String(128), nullable=False),
    Column("idempotency_key", String(36), nullable=False),
    Column("state", String(32), nullable=False),
    Column("result_hmac_key_id", String(128), nullable=True),
    Column("result_hmac_b64", String(128), nullable=True),
    _utc_text("first_seen_at"),
    _utc_text("last_seen_at"),
    _utc_text("expires_at"),
    CheckConstraint("(result_hmac_key_id IS NULL) = (result_hmac_b64 IS NULL)"),
    _utc_constraint("first_seen_at"),
    _utc_constraint("last_seen_at"),
    _utc_constraint("expires_at"),
    UniqueConstraint(
        "operation",
        "scope",
        "idempotency_key",
        name="uq_idempotency_scope_key",
    ),
)

audit_receipts = Table(
    "audit_receipts",
    _metadata,
    _uuid_pk(),
    Column("ordinal", Integer, nullable=False, unique=True),
    Column("previous_public_hash_hex", String(64), nullable=True),
    Column("public_hash_hex", String(64), nullable=False),
    Column("hmac_key_id", String(128), nullable=False),
    Column("hmac_b64", String(128), nullable=False),
    Column("canonical_body_json", Text, nullable=False),
    _utc_text("occurred_at"),
    _integer_storage_constraint("ordinal"),
    CheckConstraint(f"ordinal BETWEEN 1 AND {MAX_BOUNDED_COUNT}"),
    CheckConstraint(_lower_sha256("public_hash_hex")),
    CheckConstraint(
        f"previous_public_hash_hex IS NULL OR ({_lower_sha256('previous_public_hash_hex')})"
    ),
    CheckConstraint("json_valid(canonical_body_json)"),
    _utc_constraint("occurred_at"),
)

audit_segments = Table(
    "audit_segments",
    _metadata,
    _uuid_pk(),
    Column("first_ordinal", Integer, nullable=False),
    Column("last_ordinal", Integer, nullable=False),
    Column("receipt_count", Integer, nullable=False),
    Column("terminal_public_hash_hex", String(64), nullable=False),
    Column("terminal_hmac_b64", String(128), nullable=False),
    Column("hmac_key_id", String(128), nullable=False),
    _utc_text("sealed_at"),
    _utc_text("exported_at", nullable=True),
    _integer_storage_constraint("first_ordinal"),
    _integer_storage_constraint("last_ordinal"),
    _integer_storage_constraint("receipt_count"),
    CheckConstraint(f"first_ordinal BETWEEN 1 AND {MAX_BOUNDED_COUNT}"),
    CheckConstraint(f"last_ordinal BETWEEN first_ordinal AND {MAX_BOUNDED_COUNT}"),
    CheckConstraint(f"receipt_count BETWEEN 1 AND {MAX_BOUNDED_COUNT}"),
    CheckConstraint(_lower_sha256("terminal_public_hash_hex")),
    _utc_constraint("sealed_at"),
    _utc_constraint("exported_at", nullable=True),
)

redaction_receipts = Table(
    "redaction_receipts",
    _metadata,
    _uuid_pk(),
    Column("purpose", String(64), nullable=False),
    Column("input_hmac_key_id", String(128), nullable=False),
    Column("input_hmac_b64", String(128), nullable=False),
    Column("output_hmac_key_id", String(128), nullable=False),
    Column("output_hmac_b64", String(128), nullable=False),
    Column("removed_categories_json", Text, nullable=False),
    Column("removed_count", Integer, nullable=False),
    Column("policy_version", String(128), nullable=False),
    Column("maximum_sensitivity", String(32), nullable=False),
    _utc_text("occurred_at"),
    _integer_storage_constraint("removed_count"),
    CheckConstraint(f"removed_count BETWEEN 0 AND {MAX_BOUNDED_COUNT}"),
    CheckConstraint("json_valid(removed_categories_json)"),
    _utc_constraint("occurred_at"),
)

provider_prices = Table(
    "provider_prices",
    _metadata,
    _uuid_pk(),
    Column("provider", String(32), nullable=False),
    Column("model", String(128), nullable=False),
    Column("category", String(32), nullable=False),
    Column("native_currency", String(3), nullable=False),
    Column("tier_basis", String(32), nullable=False),
    Column("tier_min_input_tokens", Integer, nullable=False),
    Column("tier_max_input_tokens", Integer, nullable=False),
    Column("input_micro_usd_per_million", Integer, nullable=False),
    Column("output_micro_usd_per_million", Integer, nullable=False),
    Column("audio_micro_usd_per_minute", Integer, nullable=False),
    Column("web_search_micro_usd_per_call", Integer, nullable=False),
    Column("primary_accounting_basis", String(48), nullable=False),
    Column("missing_evidence_policy", String(48), nullable=False),
    Column("fx_micros_sgd", Integer, nullable=False),
    Column("pricing_version", String(128), nullable=False),
    Column("price_source_url", String(512), nullable=False),
    Column("price_source_sha256", String(64), nullable=False),
    Column("fx_version", String(128), nullable=False),
    Column("fx_source_sha256", String(64), nullable=False),
    _utc_text("effective_at"),
    _utc_text("expires_at"),
    _integer_storage_constraint("tier_min_input_tokens"),
    _integer_storage_constraint("tier_max_input_tokens"),
    _integer_storage_constraint("input_micro_usd_per_million"),
    _integer_storage_constraint("output_micro_usd_per_million"),
    _integer_storage_constraint("audio_micro_usd_per_minute"),
    _integer_storage_constraint("web_search_micro_usd_per_call"),
    _integer_storage_constraint("fx_micros_sgd"),
    CheckConstraint("provider IN ('openai','qwen')"),
    CheckConstraint("category IN ('stt','llm','tts','web_search')"),
    CheckConstraint("native_currency GLOB '[A-Z][A-Z][A-Z]'"),
    CheckConstraint(
        "(tier_basis = 'flat' AND tier_min_input_tokens = 0 "
        "AND tier_max_input_tokens = 0) OR "
        "(tier_basis = 'llm_input_tokens' AND category = 'llm' "
        f"AND tier_min_input_tokens BETWEEN 0 AND {MAX_INPUT_TIER_TOKENS} "
        "AND tier_max_input_tokens BETWEEN tier_min_input_tokens "
        f"AND {MAX_INPUT_TIER_TOKENS})"
    ),
    CheckConstraint(f"input_micro_usd_per_million BETWEEN 0 AND {MAX_PROVIDER_RATE_MICRO_USD}"),
    CheckConstraint(f"output_micro_usd_per_million BETWEEN 0 AND {MAX_PROVIDER_RATE_MICRO_USD}"),
    CheckConstraint(f"audio_micro_usd_per_minute BETWEEN 0 AND {MAX_PROVIDER_RATE_MICRO_USD}"),
    CheckConstraint(f"web_search_micro_usd_per_call BETWEEN 0 AND {MAX_PROVIDER_RATE_MICRO_USD}"),
    CheckConstraint(
        "primary_accounting_basis IN ('provider_reported_exact','request_bound_exact')"
    ),
    CheckConstraint(
        "missing_evidence_policy IN ('freeze_unknown_overage','conservative_full_reservation')"
    ),
    CheckConstraint(
        "(category = 'tts' AND primary_accounting_basis = 'request_bound_exact' "
        "AND missing_evidence_policy = 'freeze_unknown_overage' "
        "AND input_micro_usd_per_million > 0 AND output_micro_usd_per_million = 0 "
        "AND audio_micro_usd_per_minute = 0 AND web_search_micro_usd_per_call = 0) OR "
        "(category = 'web_search' AND primary_accounting_basis = 'provider_reported_exact' "
        "AND missing_evidence_policy = 'conservative_full_reservation' "
        "AND input_micro_usd_per_million > 0 AND output_micro_usd_per_million > 0 "
        "AND audio_micro_usd_per_minute = 0 AND web_search_micro_usd_per_call > 0) OR "
        "(category = 'stt' AND primary_accounting_basis = 'provider_reported_exact' "
        "AND missing_evidence_policy = 'freeze_unknown_overage' "
        "AND input_micro_usd_per_million = 0 AND output_micro_usd_per_million = 0 "
        "AND audio_micro_usd_per_minute > 0 AND web_search_micro_usd_per_call = 0) OR "
        "(category = 'llm' AND primary_accounting_basis = 'provider_reported_exact' "
        "AND missing_evidence_policy = 'freeze_unknown_overage' "
        "AND input_micro_usd_per_million > 0 AND output_micro_usd_per_million > 0 "
        "AND audio_micro_usd_per_minute = 0 AND web_search_micro_usd_per_call = 0)"
    ),
    CheckConstraint("fx_micros_sgd BETWEEN 1 AND 10000000"),
    CheckConstraint(
        "length(price_source_url) BETWEEN 9 AND 512 AND price_source_url GLOB 'https://*'"
    ),
    CheckConstraint(_lower_sha256("price_source_sha256")),
    CheckConstraint(_lower_sha256("fx_source_sha256")),
    CheckConstraint("effective_at < expires_at"),
    _utc_constraint("effective_at"),
    _utc_constraint("expires_at"),
    UniqueConstraint(
        "provider",
        "model",
        "category",
        "pricing_version",
        "fx_version",
        "tier_basis",
        "tier_min_input_tokens",
        "tier_max_input_tokens",
        name="uq_provider_price_version_tier",
    ),
)

budget_reservations = Table(
    "budget_reservations",
    _metadata,
    _uuid_pk(),
    Column("request_id", String(36), nullable=False),
    Column("attempt_id", String(36), nullable=False, unique=True),
    Column("month_key", String(7), nullable=False),
    Column("category", String(32), nullable=False),
    Column("provider", String(32), nullable=False),
    Column("model", String(128), nullable=False),
    Column("outcome", String(32), nullable=False),
    Column("reserved_micros_sgd", Integer, nullable=False),
    Column("charged_micros_sgd", Integer, nullable=True),
    Column("usage_ceiling_json", Text, nullable=False),
    Column("price_snapshot_json", Text, nullable=True),
    Column("primary_accounting_basis", String(48), nullable=True),
    Column("missing_evidence_policy", String(48), nullable=True),
    Column("pricing_version", String(128), nullable=True),
    Column("price_source_sha256", String(64), nullable=True),
    Column("fx_version", String(128), nullable=True),
    Column("fx_source_sha256", String(64), nullable=True),
    Column("pricing_commitment_key_id", String(128), nullable=True),
    Column("pricing_commitment_hmac_b64", String(128), nullable=True),
    Column("estimate_overrun", Integer, nullable=False, server_default=text("0")),
    Column("state", String(32), nullable=False),
    Column("gateway_ordering_version", Integer, nullable=False),
    Column("transport_phase", String(32), nullable=False),
    _utc_text("created_at"),
    _utc_text("expires_at"),
    _utc_text("settled_at", nullable=True),
    _utc_text("reconciled_at", nullable=True),
    _integer_storage_constraint("reserved_micros_sgd"),
    _integer_storage_constraint("charged_micros_sgd", nullable=True),
    _integer_storage_constraint("estimate_overrun"),
    _integer_storage_constraint("gateway_ordering_version"),
    CheckConstraint(f"reserved_micros_sgd BETWEEN 0 AND {MAX_QUOTE_MICROS_SGD}"),
    CheckConstraint(
        f"charged_micros_sgd IS NULL OR charged_micros_sgd BETWEEN 0 AND {MAX_QUOTE_MICROS_SGD}"
    ),
    CheckConstraint("json_valid(usage_ceiling_json)"),
    CheckConstraint("price_snapshot_json IS NULL OR json_valid(price_snapshot_json)"),
    CheckConstraint(
        "primary_accounting_basis IS NULL OR primary_accounting_basis IN "
        "('provider_reported_exact','request_bound_exact')"
    ),
    CheckConstraint(
        "missing_evidence_policy IS NULL OR missing_evidence_policy IN "
        "('freeze_unknown_overage','conservative_full_reservation')"
    ),
    CheckConstraint(f"price_source_sha256 IS NULL OR ({_lower_sha256('price_source_sha256')})"),
    CheckConstraint(f"fx_source_sha256 IS NULL OR ({_lower_sha256('fx_source_sha256')})"),
    CheckConstraint(
        "(price_snapshot_json IS NULL AND primary_accounting_basis IS NULL "
        "AND missing_evidence_policy IS NULL AND pricing_version IS NULL "
        "AND price_source_sha256 IS NULL AND fx_version IS NULL "
        "AND fx_source_sha256 IS NULL AND pricing_commitment_key_id IS NULL "
        "AND pricing_commitment_hmac_b64 IS NULL) OR "
        "(price_snapshot_json IS NOT NULL AND primary_accounting_basis IS NOT NULL "
        "AND missing_evidence_policy IS NOT NULL AND pricing_version IS NOT NULL "
        "AND price_source_sha256 IS NOT NULL AND fx_version IS NOT NULL "
        "AND fx_source_sha256 IS NOT NULL AND pricing_commitment_key_id IS NOT NULL "
        "AND pricing_commitment_hmac_b64 IS NOT NULL)"
    ),
    CheckConstraint(
        "primary_accounting_basis IS NULL OR "
        "(category = 'tts' AND primary_accounting_basis = 'request_bound_exact' "
        "AND missing_evidence_policy = 'freeze_unknown_overage') OR "
        "(category = 'web_search' AND primary_accounting_basis = 'provider_reported_exact' "
        "AND missing_evidence_policy = 'conservative_full_reservation') OR "
        "(category IN ('stt','llm') "
        "AND primary_accounting_basis = 'provider_reported_exact' "
        "AND missing_evidence_policy = 'freeze_unknown_overage')"
    ),
    CheckConstraint(
        "length(month_key) = 7 "
        "AND month_key GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]' "
        "AND CAST(substr(month_key, 6, 2) AS INTEGER) BETWEEN 1 AND 12"
    ),
    CheckConstraint("provider IN ('openai','qwen')"),
    CheckConstraint("category IN ('stt','llm','tts','web_search')"),
    CheckConstraint("gateway_ordering_version = 1"),
    CheckConstraint(
        "transport_phase IN "
        "('not_claimed','claim_begun','marked_sent','network_invocation_starting','finished')"
    ),
    CheckConstraint(
        "outcome IN "
        "('allow','allow_soft_warning','deny_hard_limit','deny_unknown_price',"
        "'deny_cloud_egress_frozen')"
    ),
    CheckConstraint("state IN ('reserved','sent','settled','released','denied')"),
    CheckConstraint(
        "(outcome IN ('allow','allow_soft_warning') "
        f"AND reserved_micros_sgd BETWEEN 1 AND {MAX_QUOTE_MICROS_SGD} "
        "AND price_snapshot_json IS NOT NULL "
        "AND state IN ('reserved','sent','settled','released')) OR "
        "(outcome = 'deny_hard_limit' AND reserved_micros_sgd = 0 "
        "AND price_snapshot_json IS NOT NULL AND state = 'denied') OR "
        "(outcome IN ('deny_unknown_price','deny_cloud_egress_frozen') "
        "AND reserved_micros_sgd = 0 AND price_snapshot_json IS NULL "
        "AND state = 'denied')"
    ),
    CheckConstraint(
        "(state = 'settled' AND charged_micros_sgd IS NOT NULL "
        "AND settled_at IS NOT NULL) OR "
        "(state <> 'settled' AND charged_micros_sgd IS NULL AND settled_at IS NULL)"
    ),
    CheckConstraint(
        "estimate_overrun IN (0,1) AND estimate_overrun = CASE "
        "WHEN charged_micros_sgd IS NOT NULL "
        "AND charged_micros_sgd > reserved_micros_sgd THEN 1 ELSE 0 END"
    ),
    CheckConstraint("created_at < expires_at"),
    _utc_constraint("created_at"),
    _utc_constraint("expires_at"),
    _utc_constraint("settled_at", nullable=True),
    _utc_constraint("reconciled_at", nullable=True),
    UniqueConstraint("id", "attempt_id", name="uq_budget_reservation_attempt"),
    UniqueConstraint(
        "id",
        "request_id",
        "attempt_id",
        "provider",
        "model",
        "category",
        name="uq_budget_provider_call_evidence",
    ),
    UniqueConstraint(
        "id",
        "month_key",
        "reserved_micros_sgd",
        "charged_micros_sgd",
        "pricing_version",
        "price_source_sha256",
        "fx_version",
        "fx_source_sha256",
        "settled_at",
        name="uq_budget_ledger_evidence",
    ),
    UniqueConstraint(
        "id",
        "primary_accounting_basis",
        name="uq_budget_ledger_accounting_basis",
    ),
)
Index("ix_budget_request", budget_reservations.c.request_id)
Index(
    "ix_budget_month_state_cost",
    budget_reservations.c.month_key,
    budget_reservations.c.state,
    budget_reservations.c.reserved_micros_sgd,
    budget_reservations.c.charged_micros_sgd,
)

provider_calls = Table(
    "provider_calls",
    _metadata,
    _uuid_pk(),
    Column("request_id", String(36), nullable=False),
    Column("attempt_id", String(36), nullable=False, unique=True),
    Column("authorization_id", String(36), nullable=False, unique=True),
    Column("budget_reservation_id", String(36), nullable=False, unique=True),
    Column("purpose", String(64), nullable=False),
    Column("provider", String(32), nullable=False),
    Column("model", String(128), nullable=False),
    Column(
        "redaction_receipt_id",
        String(36),
        ForeignKey("redaction_receipts.id"),
        nullable=True,
    ),
    Column("request_hmac_key_id", String(128), nullable=False),
    Column("request_hmac_b64", String(128), nullable=False),
    Column("response_hmac_key_id", String(128), nullable=True),
    Column("response_hmac_b64", String(128), nullable=True),
    Column("category", String(32), nullable=False),
    Column("outcome", String(64), nullable=False),
    Column("gateway_ordering_version", Integer, nullable=False),
    Column("transport_phase", String(32), nullable=False),
    Column("provider_usage_json", Text, nullable=True),
    Column("provider_usage_receipt_key_id", String(128), nullable=True),
    Column("provider_usage_receipt_hmac_b64", String(128), nullable=True),
    _utc_text("started_at"),
    _utc_text("finished_at", nullable=True),
    ForeignKeyConstraint(
        [
            "budget_reservation_id",
            "request_id",
            "attempt_id",
            "provider",
            "model",
            "category",
        ],
        [
            "budget_reservations.id",
            "budget_reservations.request_id",
            "budget_reservations.attempt_id",
            "budget_reservations.provider",
            "budget_reservations.model",
            "budget_reservations.category",
        ],
        name="fk_provider_call_exact_reservation",
    ),
    _integer_storage_constraint("gateway_ordering_version"),
    CheckConstraint(
        "purpose IN "
        "('cloud_stt','cloud_reasoning','cloud_tts','web_search','experimental_web_search')"
    ),
    CheckConstraint("provider IN ('openai','qwen')"),
    CheckConstraint("category IN ('stt','llm','tts','web_search')"),
    CheckConstraint(
        "(purpose = 'cloud_stt' AND category = 'stt') OR "
        "(purpose = 'cloud_reasoning' AND category = 'llm') OR "
        "(purpose = 'cloud_tts' AND category = 'tts') OR "
        "(purpose IN ('web_search','experimental_web_search') "
        "AND category = 'web_search')"
    ),
    CheckConstraint("outcome IN ('started','succeeded','failed','cancelled','ambiguous')"),
    CheckConstraint("gateway_ordering_version = 1"),
    CheckConstraint(
        "transport_phase IN ('claim_begun','marked_sent','network_invocation_starting','finished')"
    ),
    CheckConstraint("(response_hmac_key_id IS NULL) = (response_hmac_b64 IS NULL)"),
    CheckConstraint(
        "(provider_usage_json IS NULL "
        "AND provider_usage_receipt_key_id IS NULL "
        "AND provider_usage_receipt_hmac_b64 IS NULL) OR "
        "(provider_usage_json IS NOT NULL "
        "AND provider_usage_receipt_key_id IS NOT NULL "
        "AND provider_usage_receipt_hmac_b64 IS NOT NULL "
        "AND json_valid(provider_usage_json))"
    ),
    _utc_constraint("started_at"),
    _utc_constraint("finished_at", nullable=True),
    UniqueConstraint(
        "request_id",
        "attempt_id",
        "authorization_id",
        "provider",
        "model",
        "response_hmac_key_id",
        "response_hmac_b64",
        name="uq_provider_call_response_evidence",
    ),
)
Index("ix_provider_calls_request", provider_calls.c.request_id)

provider_response_receipts = Table(
    "provider_response_receipts",
    _metadata,
    _uuid_pk(),
    Column("request_id", String(36), nullable=False),
    Column("attempt_id", String(36), nullable=False, unique=True),
    Column("authorization_id", String(36), nullable=False, unique=True),
    Column("household_id", String(36), ForeignKey("households.id"), nullable=False),
    Column("subject_id", String(36), nullable=True),
    Column("session_id", String(36), ForeignKey("sessions.id"), nullable=False),
    Column("turn_id", String(36), nullable=False),
    Column("provider", String(32), nullable=False),
    Column("model", String(128), nullable=False),
    Column("output_schema_version", String(64), nullable=False),
    Column("response_hmac_key_id", String(128), nullable=False),
    Column("response_hmac_b64", String(128), nullable=False),
    Column("receipt_hmac_key_id", String(128), nullable=False),
    Column("receipt_hmac_b64", String(128), nullable=False),
    _utc_text("produced_at"),
    ForeignKeyConstraint(
        [
            "request_id",
            "attempt_id",
            "authorization_id",
            "provider",
            "model",
            "response_hmac_key_id",
            "response_hmac_b64",
        ],
        [
            "provider_calls.request_id",
            "provider_calls.attempt_id",
            "provider_calls.authorization_id",
            "provider_calls.provider",
            "provider_calls.model",
            "provider_calls.response_hmac_key_id",
            "provider_calls.response_hmac_b64",
        ],
        name="fk_provider_response_exact_call",
    ),
    CheckConstraint("provider IN ('openai','qwen')"),
    CheckConstraint("output_schema_version = 'assistant-turn-v1'"),
    _utc_constraint("produced_at"),
)

cost_ledger = Table(
    "cost_ledger",
    _metadata,
    _uuid_pk(),
    Column("reservation_id", String(36), nullable=False, unique=True),
    Column("month_key", String(7), nullable=False),
    Column("reserved_micros_sgd", Integer, nullable=False),
    Column("charged_micros_sgd", Integer, nullable=False),
    Column("usage_json", Text, nullable=False),
    Column("provider_usage_receipt_json", Text, nullable=True),
    Column("provider_usage_receipt_key_id", String(128), nullable=True),
    Column("provider_usage_receipt_hmac_b64", String(128), nullable=True),
    Column("accounting_basis", String(48), nullable=True),
    Column("conservative_estimate_used", Integer, nullable=False),
    Column("estimate_overrun", Integer, nullable=False),
    Column("hard_cap_exceeded", Integer, nullable=False),
    Column("pricing_version", String(128), nullable=False),
    Column("price_source_sha256", String(64), nullable=False),
    Column("fx_version", String(128), nullable=False),
    Column("fx_source_sha256", String(64), nullable=False),
    _utc_text("settled_at"),
    ForeignKeyConstraint(
        [
            "reservation_id",
            "month_key",
            "reserved_micros_sgd",
            "charged_micros_sgd",
            "pricing_version",
            "price_source_sha256",
            "fx_version",
            "fx_source_sha256",
            "settled_at",
        ],
        [
            "budget_reservations.id",
            "budget_reservations.month_key",
            "budget_reservations.reserved_micros_sgd",
            "budget_reservations.charged_micros_sgd",
            "budget_reservations.pricing_version",
            "budget_reservations.price_source_sha256",
            "budget_reservations.fx_version",
            "budget_reservations.fx_source_sha256",
            "budget_reservations.settled_at",
        ],
        name="fk_cost_ledger_exact_reservation",
    ),
    ForeignKeyConstraint(
        ["reservation_id", "accounting_basis"],
        ["budget_reservations.id", "budget_reservations.primary_accounting_basis"],
        name="fk_cost_ledger_accounting_basis",
    ),
    _integer_storage_constraint("reserved_micros_sgd"),
    _integer_storage_constraint("charged_micros_sgd"),
    _integer_storage_constraint("conservative_estimate_used"),
    _integer_storage_constraint("estimate_overrun"),
    _integer_storage_constraint("hard_cap_exceeded"),
    CheckConstraint(
        "length(month_key) = 7 "
        "AND month_key GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]' "
        "AND CAST(substr(month_key, 6, 2) AS INTEGER) BETWEEN 1 AND 12"
    ),
    CheckConstraint(f"reserved_micros_sgd BETWEEN 1 AND {MAX_QUOTE_MICROS_SGD}"),
    CheckConstraint(f"charged_micros_sgd BETWEEN 0 AND {MAX_QUOTE_MICROS_SGD}"),
    CheckConstraint("json_valid(usage_json)"),
    CheckConstraint(
        "accounting_basis IS NULL OR accounting_basis IN "
        "('provider_reported_exact','request_bound_exact','conservative_full_reservation')"
    ),
    CheckConstraint(
        "(provider_usage_receipt_json IS NULL "
        "AND provider_usage_receipt_key_id IS NULL "
        "AND provider_usage_receipt_hmac_b64 IS NULL "
        "AND accounting_basis IS NULL AND conservative_estimate_used = 1) OR "
        "(provider_usage_receipt_json IS NOT NULL "
        "AND provider_usage_receipt_key_id IS NOT NULL "
        "AND provider_usage_receipt_hmac_b64 IS NOT NULL "
        "AND accounting_basis IS NOT NULL AND conservative_estimate_used = 0 "
        "AND json_valid(provider_usage_receipt_json))"
    ),
    CheckConstraint("conservative_estimate_used IN (0,1)"),
    CheckConstraint(
        "estimate_overrun IN (0,1) AND estimate_overrun = CASE "
        "WHEN charged_micros_sgd > reserved_micros_sgd THEN 1 ELSE 0 END"
    ),
    CheckConstraint("hard_cap_exceeded IN (0,1)"),
    CheckConstraint(_lower_sha256("price_source_sha256")),
    CheckConstraint(_lower_sha256("fx_source_sha256")),
    _utc_constraint("settled_at"),
)

runtime_settings = Table(
    "runtime_settings",
    _metadata,
    Column("key", String(128), primary_key=True),
    Column("value_json", Text, nullable=False),
    Column("version", Integer, nullable=False),
    _utc_text("updated_at"),
    _integer_storage_constraint("version"),
    CheckConstraint(f"version BETWEEN 1 AND {MAX_BOUNDED_COUNT}"),
    CheckConstraint("json_valid(value_json)"),
    _utc_constraint("updated_at"),
)

reachy_core_tx_sequences = Table(
    "reachy_core_tx_sequences",
    _metadata,
    Column("device_id", String(36), ForeignKey("devices.id"), primary_key=True),
    Column("last_sequence", Integer, nullable=False),
    _integer_storage_constraint("last_sequence"),
    CheckConstraint(f"last_sequence BETWEEN 0 AND {MAX_BOUNDED_COUNT}"),
)

reachy_duplex_correlations = Table(
    "reachy_duplex_correlations",
    _metadata,
    Column("device_id", String(36), ForeignKey("devices.id"), primary_key=True),
    Column("correlation_id", String(36), primary_key=True),
    Column("purpose", String(64), nullable=False),
    Column("request_direction", String(16), nullable=False),
    Column("state", String(16), nullable=False),
    Column("first_sequence", Integer, nullable=False),
    Column("last_sequence", Integer, nullable=False),
    _utc_text("created_at"),
    _utc_text("updated_at"),
    _integer_storage_constraint("first_sequence"),
    _integer_storage_constraint("last_sequence"),
    CheckConstraint("request_direction IN ('edge_to_core','core_to_edge')"),
    CheckConstraint("state IN ('pending','completed','abandoned')"),
    CheckConstraint(
        f"first_sequence BETWEEN 1 AND {MAX_BOUNDED_COUNT} "
        f"AND last_sequence BETWEEN first_sequence AND {MAX_BOUNDED_COUNT}"
    ),
    _utc_constraint("created_at"),
    _utc_constraint("updated_at"),
)

assert set(FOUNDATION_0001_METADATA.tables) == FOUNDATION_TABLE_NAMES
