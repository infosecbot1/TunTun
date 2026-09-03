# mypy: disable-error-code="no-untyped-def"
from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from tuntun_core.bootstrap.container import build_task1_sqlcipher_uow_factory
from tuntun_core.domain.profile import ConsentPurpose, ConsentReceipt, GuestConsentPurpose
from tuntun_core.services.identity.consent import ConsentDenied
from tuntun_core.services.storage_time import utc_storage
from tuntun_core.services.transactions.identity_uow import IdentityUnitOfWork

from tests.identity_support import task1_test_identity_keys


def _checks(sync_connection, table: str) -> tuple[str, ...]:
    return tuple(
        item["sqltext"] for item in sa.inspect(sync_connection).get_check_constraints(table)
    )


def _guest_disclosure_event_type(
    purpose: GuestConsentPurpose,
    disclosure_version: str,
) -> str:
    return f"guest_disclosure_presentation:{purpose}:{disclosure_version}"


def _insert_guest_disclosure_presentation(
    connection,
    *,
    household_id: UUID,
    device_id: UUID,
    session_id: UUID,
    presentation_receipt_id: UUID,
    purpose: GuestConsentPurpose,
    disclosure_version: str,
    occurred_at: datetime,
    decision: str = "accepted",
    event_type: str | None = None,
) -> None:
    connection.exec_driver_sql(
        "INSERT INTO households(id,display_label_ciphertext,timezone,created_at) VALUES (?,?,?,?)",
        (str(household_id), b"label", "Asia/Singapore", utc_storage(occurred_at)),
    )
    connection.exec_driver_sql(
        "INSERT INTO devices "
        "(id,household_id,kind,certificate_fingerprint,signing_public_key,signing_key_id,"
        "last_sequence,paired_at,revoked_at) VALUES (?,?,?,?,?,?,?,?,NULL)",
        (
            str(device_id),
            str(household_id),
            "simulated-guest",
            f"fixture-{device_id}",
            b"public-key",
            "guest-disclosure-test-key",
            1,
            utc_storage(occurred_at),
        ),
    )
    connection.exec_driver_sql(
        "INSERT INTO event_receipts "
        "(id,household_id,device_id,event_type,correlation_id,device_sequence,"
        "payload_hmac_key_id,payload_hmac_b64,decision,occurred_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            str(presentation_receipt_id),
            str(household_id),
            str(device_id),
            event_type
            or _guest_disclosure_event_type(
                purpose,
                disclosure_version,
            ),
            str(session_id),
            1,
            "guest-disclosure-test-key",
            base64.b64encode(b"presentation-payload-digest").decode("ascii"),
            decision,
            utc_storage(occurred_at),
        ),
    )


@pytest.mark.asyncio
async def test_migration_has_adult_search_but_exact_guest_cloud_purposes(
    migrated_sqlcipher_engine,
) -> None:
    async with migrated_sqlcipher_engine.connect() as connection:
        checks = await connection.run_sync(
            lambda sync: {
                table: _checks(sync, table)
                for table in (
                    "consent_receipts",
                    "guest_disclosure_challenges",
                    "guest_session_consent_receipts",
                )
            }
        )

    assert (
        "purpose IN "
        "('face','voice','personalization','cloud_stt','cloud_reasoning','cloud_tts',"
        "'web_search','child_durable_memory_v1')"
    ) in checks["consent_receipts"]
    assert (
        "purpose!='web_search' OR (actor_id=subject_id AND guardian_id IS NULL)"
        in checks["consent_receipts"]
    )
    assert (
        "purpose!='child_durable_memory_v1' OR "
        "(guardian_id IS NOT NULL AND guardian_generation >= 1 AND actor_id=guardian_id)"
    ) in checks["consent_receipts"]
    for table in ("guest_disclosure_challenges", "guest_session_consent_receipts"):
        assert "purpose IN ('cloud_stt','cloud_reasoning','cloud_tts')" in checks[table]
        assert all("web_search" not in constraint for constraint in checks[table])


@pytest.mark.asyncio
async def test_guest_disclosure_challenge_schema_has_exact_presentation_lineage(
    migrated_sqlcipher_engine,
) -> None:
    async with migrated_sqlcipher_engine.connect() as connection:
        columns = await connection.run_sync(
            lambda sync: [
                item["name"] for item in sa.inspect(sync).get_columns("guest_disclosure_challenges")
            ]
        )

    assert "challenge_id" not in columns
    assert columns.count("presentation_receipt_id") == 1


@pytest.mark.asyncio
async def test_guest_session_consent_receipts_bind_challenge_and_presentation_lineage(
    migrated_sqlcipher_engine,
) -> None:
    async with migrated_sqlcipher_engine.connect() as connection:
        columns, foreign_keys, indexes = await connection.run_sync(
            lambda sync: (
                {
                    item["name"]: item
                    for item in sa.inspect(sync).get_columns("guest_session_consent_receipts")
                },
                sa.inspect(sync).get_foreign_keys("guest_session_consent_receipts"),
                sa.inspect(sync).get_indexes("guest_session_consent_receipts"),
            )
        )

    assert columns["challenge_id"]["nullable"] is False
    assert columns["presentation_receipt_id"]["nullable"] is False
    assert any(item["constrained_columns"] == ["challenge_id"] for item in foreign_keys)
    assert any(item["constrained_columns"] == ["presentation_receipt_id"] for item in foreign_keys)
    assert any(
        item["name"] == "ux_guest_consent_one_grant_per_challenge"
        and item["column_names"] == ["challenge_id"]
        and item["unique"]
        for item in indexes
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("changed_field", "expected_error"),
    (
        ("session_id", "guest_disclosure_presentation_mismatch"),
        ("purpose", "guest_disclosure_presentation_mismatch"),
        ("disclosure_version", "guest_disclosure_presentation_mismatch"),
        ("future_occurred_at", "guest_disclosure_presentation_mismatch"),
        ("decision", "guest_disclosure_presentation_mismatch"),
        ("event_type", "guest_disclosure_presentation_mismatch"),
    ),
)
async def test_sql_guest_presentation_receipt_requires_exact_context_and_validity(
    migrated_sqlcipher_engine,
    clock,
    changed_field,
    expected_error,
) -> None:
    keys = task1_test_identity_keys()
    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )
    household_id = uuid4()
    device_id = uuid4()
    session_id = uuid4()
    presentation_receipt_id = uuid4()
    purpose: GuestConsentPurpose = "cloud_stt"
    disclosure_version = "phase1-disclosure-v1"
    presentation_time = clock.now()
    observed_now = presentation_time
    decision = "accepted"
    event_type: str | None = None
    if changed_field == "future_occurred_at":
        presentation_time = presentation_time + timedelta(seconds=1)
    if changed_field == "decision":
        decision = "denied"
    if changed_field == "event_type":
        event_type = "reachy.audio.finalized"
    with migrated_sqlcipher_engine.engine.begin() as connection:
        _insert_guest_disclosure_presentation(
            connection,
            household_id=household_id,
            device_id=device_id,
            session_id=session_id,
            presentation_receipt_id=presentation_receipt_id,
            purpose=purpose,
            disclosure_version=disclosure_version,
            occurred_at=presentation_time,
            decision=decision,
            event_type=event_type,
        )
    requested_session_id = uuid4() if changed_field == "session_id" else session_id
    requested_purpose: GuestConsentPurpose = "cloud_tts" if changed_field == "purpose" else purpose
    requested_disclosure_version = (
        "phase1-disclosure-v2" if changed_field == "disclosure_version" else disclosure_version
    )

    async with uow_factory() as uow:
        with pytest.raises(ConsentDenied, match=expected_error):
            await uow.event_receipts.require_exact_guest_disclosure(
                presentation_receipt_id,
                household_id=household_id,
                session_id=requested_session_id,
                purpose=requested_purpose,
                disclosure_version=requested_disclosure_version,
                now=observed_now,
            )
        await uow.rollback()


@pytest.mark.asyncio
async def test_sql_guest_presentation_receipt_accepts_exact_context(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    keys = task1_test_identity_keys()
    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )
    household_id = uuid4()
    device_id = uuid4()
    session_id = uuid4()
    presentation_receipt_id = uuid4()
    purpose: GuestConsentPurpose = "cloud_stt"
    disclosure_version = "phase1-disclosure-v1"
    now = clock.now()
    with migrated_sqlcipher_engine.engine.begin() as connection:
        _insert_guest_disclosure_presentation(
            connection,
            household_id=household_id,
            device_id=device_id,
            session_id=session_id,
            presentation_receipt_id=presentation_receipt_id,
            purpose=purpose,
            disclosure_version=disclosure_version,
            occurred_at=now,
        )

    async with uow_factory() as uow:
        await uow.event_receipts.require_exact_guest_disclosure(
            presentation_receipt_id,
            household_id=household_id,
            session_id=session_id,
            purpose=purpose,
            disclosure_version=disclosure_version,
            now=now,
        )
        await uow.rollback()


@pytest.mark.asyncio
async def test_subject_schema_has_encrypted_optimistic_persona_storage(
    migrated_sqlcipher_engine,
) -> None:
    async with migrated_sqlcipher_engine.connect() as connection:
        columns = await connection.run_sync(
            lambda sync: {item["name"]: item for item in sa.inspect(sync).get_columns("subjects")}
        )

    assert columns["encrypted_persona_traits"]["type"].python_type is bytes
    assert columns["encrypted_persona_traits"]["nullable"] is True
    assert columns["version"]["nullable"] is False


@pytest.mark.asyncio
async def test_revocation_outbox_is_durable_leased_and_idempotent(
    migrated_sqlcipher_engine,
) -> None:
    async with migrated_sqlcipher_engine.connect() as connection:
        columns, uniques, checks = await connection.run_sync(
            lambda sync: (
                {
                    item["name"]: item
                    for item in sa.inspect(sync).get_columns("subject_revocation_outbox")
                },
                sa.inspect(sync).get_unique_constraints("subject_revocation_outbox"),
                _checks(sync, "subject_revocation_outbox"),
            )
        )

    assert set(columns) == {
        "id",
        "event_key",
        "subject_id",
        "new_authority_generation",
        "state",
        "occurred_at",
        "claimed_at",
        "lease_owner",
        "lease_expires_at",
        "fencing_token",
        "completed_at",
        "attempt_count",
        "last_error",
        "reconciliation_receipt_id",
    }
    assert any(item["column_names"] == ["event_key"] for item in uniques)
    assert "state IN ('pending','processing','completed')" in checks
    assert "attempt_count >= 0 AND fencing_token >= 0" in checks


@pytest.mark.asyncio
async def test_revocation_effect_claims_are_durable_leased_and_idempotent(
    migrated_sqlcipher_engine,
) -> None:
    async with migrated_sqlcipher_engine.connect() as connection:
        columns, uniques, checks = await connection.run_sync(
            lambda sync: (
                {
                    item["name"]: item
                    for item in sa.inspect(sync).get_columns("subject_revocation_effects")
                },
                sa.inspect(sync).get_unique_constraints("subject_revocation_effects"),
                _checks(sync, "subject_revocation_effects"),
            )
        )

    assert set(columns) == {
        "id",
        "event_id",
        "family",
        "idempotency_key",
        "state",
        "lease_owner",
        "leased_until",
        "fencing_token",
        "attempt_count",
        "downstream_receipt_id",
        "disposition",
        "last_error",
        "created_at",
        "completed_at",
    }
    assert any(item["column_names"] == ["idempotency_key"] for item in uniques)
    assert any(item["column_names"] == ["event_id", "family"] for item in uniques)
    assert "state IN ('pending','applying','completed')" in checks
    assert "attempt_count >= 0 AND fencing_token >= 0" in checks


@pytest.mark.asyncio
async def test_current_owner_authority_has_one_generation_bound_subject_per_household(
    migrated_sqlcipher_engine,
) -> None:
    async with migrated_sqlcipher_engine.connect() as connection:
        columns, uniques = await connection.run_sync(
            lambda sync: (
                {
                    item["name"]: item
                    for item in sa.inspect(sync).get_columns("current_owner_authority")
                },
                sa.inspect(sync).get_unique_constraints("current_owner_authority"),
            )
        )

    assert set(columns) == {"household_id", "subject_id", "owner_generation", "changed_at"}
    assert any(item["column_names"] == ["subject_id"] for item in uniques)


@pytest.mark.asyncio
async def test_web_search_subject_receipt_invariant_survives_downgrade_reupgrade(
    migration_runner,
) -> None:
    await migration_runner.downgrade("0001")
    await migration_runner.upgrade("0002")
    checks = await migration_runner.check_constraints("consent_receipts")

    assert (
        "purpose!='web_search' OR "
        "(actor_id=subject_id AND guardian_id IS NULL AND guardian_generation IS NULL)"
    ) in checks


@pytest.mark.asyncio
async def test_subject_authority_generation_is_non_null_monotonic_state(
    migrated_sqlcipher_engine,
) -> None:
    async with migrated_sqlcipher_engine.connect() as connection:
        columns, checks = await connection.run_sync(
            lambda sync: (
                {item["name"]: item for item in sa.inspect(sync).get_columns("subjects")},
                _checks(sync, "subjects"),
            )
        )

    assert columns["authority_generation"]["nullable"] is False
    assert "authority_generation >= 1" in checks


@pytest.mark.asyncio
async def test_task1_profile_and_consent_schema_bounds_sensitive_blobs_and_time_fields(
    migrated_sqlcipher_engine,
) -> None:
    async with migrated_sqlcipher_engine.connect() as connection:
        checks = await connection.run_sync(
            lambda sync: {
                table: _checks(sync, table)
                for table in (
                    "subjects",
                    "consent_receipts",
                    "guest_disclosure_challenges",
                    "guest_session_consent_receipts",
                )
            }
        )

    assert (
        "typeof(encrypted_display_label)='blob' "
        "AND length(encrypted_display_label) BETWEEN 1 AND 1024"
    ) in checks["subjects"]
    assert (
        "encrypted_persona_traits IS NULL OR "
        "(typeof(encrypted_persona_traits)='blob' "
        "AND length(encrypted_persona_traits) BETWEEN 1 AND 4096)"
    ) in checks["subjects"]
    assert (
        "typeof(current_consent_receipt_ids)='blob' "
        "AND length(current_consent_receipt_ids) BETWEEN 2 AND 512"
    ) in checks["subjects"]
    reminder_check = (
        "next_reenrollment_reminder_at IS NULL OR "
        "next_reenrollment_reminder_at GLOB '????-??-??T??:??:??.??????Z'"
    )
    assert reminder_check in checks["subjects"]
    assert (
        "revoked_at IS NULL OR revoked_at GLOB '????-??-??T??:??:??.??????Z'" in checks["subjects"]
    )
    assert "typeof(receipt_hmac)='blob' AND length(receipt_hmac)=32" in checks["consent_receipts"]
    assert (
        "typeof(challenge_hmac)='blob' AND length(challenge_hmac)=32"
        in checks["guest_disclosure_challenges"]
    )
    assert (
        "typeof(receipt_hmac)='blob' AND length(receipt_hmac)=32"
        in checks["guest_session_consent_receipts"]
    )


def _insert_household(connection, household_id: UUID, now: datetime) -> None:
    connection.exec_driver_sql(
        "INSERT INTO households(id,display_label_ciphertext,timezone,created_at) VALUES (?,?,?,?)",
        (str(household_id), b"label", "Asia/Singapore", utc_storage(now)),
    )


def _insert_subject(
    connection,
    *,
    household_id: UUID,
    subject_id: UUID,
    now: datetime,
    encrypted_display_label: object = b"encrypted-label",
    encrypted_persona_traits: object | None = None,
    current_consent_receipt_ids: object = b"[]",
    revoked_at: str | None = None,
    next_reenrollment_reminder_at: str | None = None,
) -> None:
    connection.exec_driver_sql(
        "INSERT INTO subjects "
        "(id,household_id,guardian_id,guardian_generation,profile_class,"
        "encrypted_display_label,encrypted_persona_traits,current_consent_receipt_ids,"
        "active,authority_generation,version,next_reenrollment_reminder_at,"
        "created_at,updated_at,revoked_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            str(subject_id),
            str(household_id),
            None,
            0,
            "adult",
            encrypted_display_label,
            encrypted_persona_traits,
            current_consent_receipt_ids,
            0 if revoked_at is not None else 1,
            1,
            1,
            next_reenrollment_reminder_at,
            utc_storage(now),
            utc_storage(now),
            revoked_at,
        ),
    )


def _sql_consent_receipt(
    *,
    household_id: UUID,
    subject_id: UUID,
    purpose: ConsentPurpose,
    granted: bool = True,
    created_at: datetime,
) -> ConsentReceipt:
    return ConsentReceipt(
        id=uuid4(),
        household_id=household_id,
        subject_id=subject_id,
        actor_id=subject_id,
        guardian_id=None,
        guardian_generation=None,
        purpose=purpose,
        granted=granted,
        policy_version="phase1-v1",
        disclosure_version="phase1-disclosure-v1",
        commitment_key_id=task1_test_identity_keys().receipt.key_id,
        receipt_hmac=b"h" * 32,
        created_at=created_at,
        expires_at=None,
    )


def _current_consent_pointer(connection, subject_id: UUID) -> tuple[UUID, ...]:
    raw = connection.exec_driver_sql(
        "SELECT current_consent_receipt_ids FROM subjects WHERE id=?",
        (str(subject_id),),
    ).scalar_one()
    return tuple(UUID(item) for item in json.loads(bytes(raw).decode("ascii")))


@pytest.mark.asyncio
async def test_sql_consent_append_updates_current_pointer_and_preserves_other_purposes(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    now = clock.now()
    household_id = UUID("00000000-0000-4000-8000-000000000621")
    subject_id = UUID("00000000-0000-4000-8000-000000000622")
    with migrated_sqlcipher_engine.engine.begin() as connection:
        _insert_household(connection, household_id, now)
        _insert_subject(connection, household_id=household_id, subject_id=subject_id, now=now)

    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        task1_test_identity_keys(),
    )
    stt = _sql_consent_receipt(
        household_id=household_id,
        subject_id=subject_id,
        purpose=ConsentPurpose.CLOUD_STT,
        created_at=now,
    )
    reasoning = _sql_consent_receipt(
        household_id=household_id,
        subject_id=subject_id,
        purpose=ConsentPurpose.CLOUD_REASONING,
        created_at=now,
    )
    stt_revoked = _sql_consent_receipt(
        household_id=household_id,
        subject_id=subject_id,
        purpose=ConsentPurpose.CLOUD_STT,
        granted=False,
        created_at=now + timedelta(microseconds=1),
    )

    async with uow_factory() as uow:
        await uow.consent_receipts.append_replacing_current(
            stt,
            expected_latest_receipt_id=None,
            auth=object(),
        )
        await uow.commit()
    with migrated_sqlcipher_engine.engine.connect() as connection:
        assert _current_consent_pointer(connection, subject_id) == (stt.id,)

    async with uow_factory() as uow:
        await uow.consent_receipts.append_replacing_current(
            reasoning,
            expected_latest_receipt_id=None,
            auth=object(),
        )
        await uow.consent_receipts.append_replacing_current(
            stt_revoked,
            expected_latest_receipt_id=stt.id,
            auth=object(),
        )
        await uow.commit()

    with migrated_sqlcipher_engine.engine.connect() as connection:
        assert _current_consent_pointer(connection, subject_id) == (reasoning.id,)


@pytest.mark.asyncio
async def test_sql_consent_append_rolls_back_receipt_and_current_pointer_together(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    now = clock.now()
    household_id = UUID("00000000-0000-4000-8000-000000000631")
    subject_id = UUID("00000000-0000-4000-8000-000000000632")
    with migrated_sqlcipher_engine.engine.begin() as connection:
        _insert_household(connection, household_id, now)
        _insert_subject(connection, household_id=household_id, subject_id=subject_id, now=now)

    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        task1_test_identity_keys(),
    )
    receipt = _sql_consent_receipt(
        household_id=household_id,
        subject_id=subject_id,
        purpose=ConsentPurpose.CLOUD_TTS,
        created_at=now,
    )

    async with uow_factory() as uow:
        await uow.consent_receipts.append_replacing_current(
            receipt,
            expected_latest_receipt_id=None,
            auth=object(),
        )
        await uow.rollback()

    with migrated_sqlcipher_engine.engine.connect() as connection:
        assert (
            connection.exec_driver_sql(
                "SELECT count(*) FROM consent_receipts WHERE id=?",
                (str(receipt.id),),
            ).scalar_one()
            == 0
        )
        assert _current_consent_pointer(connection, subject_id) == ()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("encrypted_display_label", b"x" * 1025),
        ("encrypted_display_label", "text-not-blob"),
        ("encrypted_persona_traits", b"x" * 4097),
        ("current_consent_receipt_ids", b"x" * 513),
        ("current_consent_receipt_ids", "[]"),
        ("next_reenrollment_reminder_at", "not-utc"),
        ("revoked_at", "not-utc"),
    ),
)
async def test_task1_subject_schema_rejects_unbounded_or_wrong_storage_class_values(
    migrated_sqlcipher_engine,
    field,
    value,
) -> None:
    now = datetime(2026, 8, 27, 8, 0, tzinfo=UTC)
    household_id = UUID("00000000-0000-4000-8000-000000000601")
    subject_id = UUID("00000000-0000-4000-8000-000000000602")
    with migrated_sqlcipher_engine.engine.begin() as connection:
        _insert_household(connection, household_id, now)
        kwargs = {
            "household_id": household_id,
            "subject_id": subject_id,
            "now": now,
            field: value,
        }
        with pytest.raises(sa.exc.IntegrityError):
            _insert_subject(connection, **kwargs)


@pytest.mark.asyncio
async def test_task1_repository_bounds_restored_profile_receipt_json_before_decoding(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    now = clock.now()
    household_id = UUID("00000000-0000-4000-8000-000000000611")
    subject_id = UUID("00000000-0000-4000-8000-000000000612")
    with migrated_sqlcipher_engine.engine.begin() as connection:
        connection.exec_driver_sql("PRAGMA ignore_check_constraints=ON")
        _insert_household(connection, household_id, now)
        _insert_subject(
            connection,
            household_id=household_id,
            subject_id=subject_id,
            now=now,
            current_consent_receipt_ids=b"[" + (b" " * 4096),
        )
        connection.exec_driver_sql("PRAGMA ignore_check_constraints=OFF")

    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        task1_test_identity_keys(),
    )
    async with uow_factory() as uow:
        identity_uow = cast(IdentityUnitOfWork, uow)
        with pytest.raises(ValueError, match="current consent receipt ids corrupt"):
            await identity_uow.profiles.get(subject_id)
        await uow.rollback()
