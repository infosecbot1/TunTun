# mypy: disable-error-code="no-untyped-def"
from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from tuntun_core.adapters.sqlcipher.identity_repositories import _receipt_ids_blob
from tuntun_core.bootstrap.container import (
    build_task1_identity_container,
    build_task1_sqlcipher_uow_factory,
)
from tuntun_core.domain.profile import (
    ConsentPurpose,
    ConsentReceipt,
    GuestConsentPurpose,
    Profile,
    ProfileClass,
)
from tuntun_core.services.identity.consent import ConsentDenied
from tuntun_core.services.identity.runtime import HmacReceiptSigner
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


def _insert_active_session(
    connection,
    *,
    household_id: UUID,
    device_id: UUID,
    session_id: UUID,
    now: datetime,
    last_activity_at: datetime | None = None,
    closed_at: datetime | None = None,
) -> None:
    connection.exec_driver_sql(
        "INSERT INTO sessions "
        "(id,household_id,device_id,state,speaker_subject_id,opened_at,last_activity_at,closed_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (
            str(session_id),
            str(household_id),
            str(device_id),
            "active",
            None,
            utc_storage(now),
            utc_storage(last_activity_at or now),
            None if closed_at is None else utc_storage(closed_at),
        ),
    )


def _build_sql_uow_factory(migrated_sqlcipher_engine, clock, keys=None):
    return build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys or task1_test_identity_keys(),
    )


def _build_sql_identity_container(migrated_sqlcipher_engine, clock):
    keys = task1_test_identity_keys()
    uow_factory = _build_sql_uow_factory(migrated_sqlcipher_engine, clock, keys)
    return keys, uow_factory, build_task1_identity_container(uow_factory, clock, keys)


def _insert_guest_consent_context(
    connection,
    *,
    household_id: UUID,
    device_id: UUID,
    session_id: UUID,
    presentation_receipt_id: UUID,
    purpose: GuestConsentPurpose,
    disclosure_version: str,
    now: datetime,
) -> None:
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
    _insert_active_session(
        connection,
        household_id=household_id,
        device_id=device_id,
        session_id=session_id,
        now=now,
    )


def _restore_guest_challenge_expiry(
    connection,
    *,
    keys,
    challenge_id: UUID,
    household_id: UUID,
    session_id: UUID,
    purpose: GuestConsentPurpose,
    disclosure_version: str,
    presentation_receipt_id: UUID,
    issued_at: datetime,
    expires_at: datetime,
) -> str:
    signer = HmacReceiptSigner(keys.receipt.root_key, key_id=keys.receipt.key_id)
    key_id, challenge_hmac = signer.sign_fields(
        "guest_disclosure_challenge",
        (
            challenge_id,
            household_id,
            session_id,
            purpose,
            disclosure_version,
            presentation_receipt_id,
            issued_at,
            expires_at,
        ),
    )
    connection.exec_driver_sql(
        "UPDATE guest_disclosure_challenges SET expires_at=?,challenge_hmac=? WHERE id=?",
        (utc_storage(expires_at), challenge_hmac, str(challenge_id)),
    )
    return key_id


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
async def test_sql_guest_consent_roundtrip_revokes_current_receipt_and_records_guest_audits(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    _, uow_factory, container = _build_sql_identity_container(
        migrated_sqlcipher_engine,
        clock,
    )
    household_id = uuid4()
    device_id = uuid4()
    session_id = uuid4()
    presentation_receipt_id = uuid4()
    purpose: GuestConsentPurpose = "cloud_reasoning"
    disclosure_version = "phase1-disclosure-v1"
    now = clock.now()
    try:
        with migrated_sqlcipher_engine.engine.begin() as connection:
            _insert_guest_consent_context(
                connection,
                household_id=household_id,
                device_id=device_id,
                session_id=session_id,
                presentation_receipt_id=presentation_receipt_id,
                purpose=purpose,
                disclosure_version=disclosure_version,
                now=now,
            )

        guest_consents = container.identity_services.guest_consents
        challenge = await guest_consents.issue_challenge(
            household_id,
            session_id,
            ConsentPurpose.CLOUD_REASONING,
            disclosure_version,
            presentation_receipt_id,
            now,
        )
        granted = await guest_consents.accept_challenge(challenge.id, "haan", now)
        current = await guest_consents.require_current(
            household_id,
            session_id,
            ConsentPurpose.CLOUD_REASONING,
            now,
        )
        revoke_time = now + timedelta(seconds=1)
        revoked = await guest_consents.revoke(
            household_id,
            session_id,
            ConsentPurpose.CLOUD_REASONING,
            revoke_time,
        )

        assert current.id == granted.id
        assert revoked.granted is False
        assert revoked.revoked_at == revoke_time
        with pytest.raises(ConsentDenied, match="current_guest_session_consent_required"):
            await guest_consents.require_current(
                household_id,
                session_id,
                ConsentPurpose.CLOUD_REASONING,
                revoke_time,
            )

        with migrated_sqlcipher_engine.engine.connect() as connection:
            challenge_state = connection.exec_driver_sql(
                "SELECT state,consumed_at FROM guest_disclosure_challenges WHERE id=?",
                (str(challenge.id),),
            ).one()
            receipt_rows = connection.exec_driver_sql(
                "SELECT granted,revoked_at FROM guest_session_consent_receipts "
                "WHERE session_id=? ORDER BY issued_at,id",
                (str(session_id),),
            ).all()
            audit_actions = [
                json.loads(str(body))["action_code"]
                for (body,) in connection.exec_driver_sql(
                    "SELECT canonical_body_json FROM audit_receipts ORDER BY ordinal",
                ).all()
            ]

        assert tuple(challenge_state) == ("accepted", utc_storage(now))
        assert [tuple(row) for row in receipt_rows] == [
            (1, None),
            (0, utc_storage(revoke_time)),
        ]
        assert "guest.consent.granted" in audit_actions
        assert "guest.consent.revoked" in audit_actions
    finally:
        await uow_factory.aclose()


@pytest.mark.asyncio
async def test_sql_guest_challenge_decline_consumes_challenge_without_minting_receipt(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    _, uow_factory, container = _build_sql_identity_container(
        migrated_sqlcipher_engine,
        clock,
    )
    household_id = uuid4()
    device_id = uuid4()
    session_id = uuid4()
    presentation_receipt_id = uuid4()
    purpose: GuestConsentPurpose = "cloud_tts"
    disclosure_version = "phase1-disclosure-v1"
    now = clock.now()
    try:
        with migrated_sqlcipher_engine.engine.begin() as connection:
            _insert_guest_consent_context(
                connection,
                household_id=household_id,
                device_id=device_id,
                session_id=session_id,
                presentation_receipt_id=presentation_receipt_id,
                purpose=purpose,
                disclosure_version=disclosure_version,
                now=now,
            )

        challenge = await container.identity_services.guest_consents.issue_challenge(
            household_id,
            session_id,
            ConsentPurpose.CLOUD_TTS,
            disclosure_version,
            presentation_receipt_id,
            now,
        )
        with pytest.raises(ConsentDenied, match="guest_disclosure_declined"):
            await container.identity_services.guest_consents.accept_challenge(
                challenge.id,
                "no",
                now,
            )

        with migrated_sqlcipher_engine.engine.connect() as connection:
            challenge_state = connection.exec_driver_sql(
                "SELECT state,consumed_at FROM guest_disclosure_challenges WHERE id=?",
                (str(challenge.id),),
            ).one()
            receipt_count = connection.exec_driver_sql(
                "SELECT count(*) FROM guest_session_consent_receipts WHERE challenge_id=?",
                (str(challenge.id),),
            ).scalar_one()

        assert tuple(challenge_state) == ("denied", utc_storage(now))
        assert receipt_count == 0
    finally:
        await uow_factory.aclose()


@pytest.mark.asyncio
async def test_sql_guest_challenge_with_restored_within_session_expiry_accepts_hmac(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    keys, uow_factory, container = _build_sql_identity_container(
        migrated_sqlcipher_engine,
        clock,
    )
    household_id = uuid4()
    device_id = uuid4()
    session_id = uuid4()
    presentation_receipt_id = uuid4()
    purpose: GuestConsentPurpose = "cloud_stt"
    disclosure_version = "phase1-disclosure-v1"
    now = clock.now()
    try:
        with migrated_sqlcipher_engine.engine.begin() as connection:
            _insert_guest_consent_context(
                connection,
                household_id=household_id,
                device_id=device_id,
                session_id=session_id,
                presentation_receipt_id=presentation_receipt_id,
                purpose=purpose,
                disclosure_version=disclosure_version,
                now=now,
            )

        challenge = await container.identity_services.guest_consents.issue_challenge(
            household_id,
            session_id,
            ConsentPurpose.CLOUD_STT,
            disclosure_version,
            presentation_receipt_id,
            now,
        )
        restored_expires_at = now + timedelta(minutes=29)
        with migrated_sqlcipher_engine.engine.begin() as connection:
            key_id = _restore_guest_challenge_expiry(
                connection,
                keys=keys,
                challenge_id=challenge.id,
                household_id=household_id,
                session_id=session_id,
                purpose=purpose,
                disclosure_version=disclosure_version,
                presentation_receipt_id=presentation_receipt_id,
                issued_at=now,
                expires_at=restored_expires_at,
            )

        receipt = await container.identity_services.guest_consents.accept_challenge(
            challenge.id,
            "yes",
            now,
        )

        with migrated_sqlcipher_engine.engine.connect() as connection:
            challenge_state = connection.exec_driver_sql(
                "SELECT state,consumed_at FROM guest_disclosure_challenges WHERE id=?",
                (str(challenge.id),),
            ).one()
            persisted_receipt = connection.exec_driver_sql(
                "SELECT challenge_id,granted FROM guest_session_consent_receipts WHERE id=?",
                (str(receipt.id),),
            ).one()

        assert key_id == keys.receipt.key_id
        assert receipt.challenge_id == challenge.id
        assert tuple(challenge_state) == ("accepted", utc_storage(now))
        assert tuple(persisted_receipt) == (str(challenge.id), 1)
    finally:
        await uow_factory.aclose()


@pytest.mark.asyncio
async def test_sql_guest_challenge_with_restored_overlong_expiry_fails_before_receipt_insert(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    keys, uow_factory, container = _build_sql_identity_container(
        migrated_sqlcipher_engine,
        clock,
    )
    household_id = uuid4()
    device_id = uuid4()
    session_id = uuid4()
    presentation_receipt_id = uuid4()
    purpose: GuestConsentPurpose = "cloud_stt"
    disclosure_version = "phase1-disclosure-v1"
    now = clock.now()
    try:
        with migrated_sqlcipher_engine.engine.begin() as connection:
            _insert_guest_consent_context(
                connection,
                household_id=household_id,
                device_id=device_id,
                session_id=session_id,
                presentation_receipt_id=presentation_receipt_id,
                purpose=purpose,
                disclosure_version=disclosure_version,
                now=now,
            )

        challenge = await container.identity_services.guest_consents.issue_challenge(
            household_id,
            session_id,
            ConsentPurpose.CLOUD_STT,
            disclosure_version,
            presentation_receipt_id,
            now,
        )
        restored_expires_at = now + timedelta(minutes=31)
        with migrated_sqlcipher_engine.engine.begin() as connection:
            key_id = _restore_guest_challenge_expiry(
                connection,
                keys=keys,
                challenge_id=challenge.id,
                household_id=household_id,
                session_id=session_id,
                purpose=purpose,
                disclosure_version=disclosure_version,
                presentation_receipt_id=presentation_receipt_id,
                issued_at=now,
                expires_at=restored_expires_at,
            )

        with pytest.raises(ConsentDenied, match="active_guest_disclosure_challenge_required"):
            await container.identity_services.guest_consents.accept_challenge(
                challenge.id,
                "yes",
                now,
            )

        with migrated_sqlcipher_engine.engine.connect() as connection:
            state = connection.exec_driver_sql(
                "SELECT state FROM guest_disclosure_challenges WHERE id=?",
                (str(challenge.id),),
            ).scalar_one()
            receipt_count = connection.exec_driver_sql(
                "SELECT count(*) FROM guest_session_consent_receipts WHERE challenge_id=?",
                (str(challenge.id),),
            ).scalar_one()

        assert key_id == keys.receipt.key_id
        assert state == "open"
        assert receipt_count == 0
    finally:
        await uow_factory.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("last_activity_delta", "closed_delta"),
    (
        (timedelta(minutes=-31), None),
        (timedelta(), timedelta(seconds=1)),
    ),
)
async def test_sql_guest_session_repository_fails_closed_for_expired_or_closed_sessions(
    migrated_sqlcipher_engine,
    clock,
    last_activity_delta,
    closed_delta,
) -> None:
    uow_factory = _build_sql_uow_factory(migrated_sqlcipher_engine, clock)
    household_id = uuid4()
    device_id = uuid4()
    session_id = uuid4()
    now = clock.now()
    try:
        with migrated_sqlcipher_engine.engine.begin() as connection:
            _insert_household(connection, household_id, now)
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
                    "guest-session-test-key",
                    1,
                    utc_storage(now),
                ),
            )
            _insert_active_session(
                connection,
                household_id=household_id,
                device_id=device_id,
                session_id=session_id,
                now=now,
                last_activity_at=now + last_activity_delta,
                closed_at=None if closed_delta is None else now + closed_delta,
            )

        async with uow_factory() as uow:
            with pytest.raises(ConsentDenied, match="active_guest_session_required"):
                await uow.sessions.require_active(household_id, session_id, now)
            await uow.rollback()
    finally:
        await uow_factory.aclose()


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


def _insert_consent_receipt(connection, receipt: ConsentReceipt) -> None:
    connection.exec_driver_sql(
        "INSERT INTO consent_receipts "
        "(id,household_id,subject_id,actor_id,guardian_id,guardian_generation,purpose,"
        "granted,policy_version,disclosure_version,commitment_key_id,receipt_hmac,"
        "created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            str(receipt.id),
            str(receipt.household_id),
            str(receipt.subject_id),
            str(receipt.actor_id),
            None if receipt.guardian_id is None else str(receipt.guardian_id),
            receipt.guardian_generation,
            receipt.purpose.value,
            int(receipt.granted),
            receipt.policy_version,
            receipt.disclosure_version,
            receipt.commitment_key_id,
            receipt.receipt_hmac,
            utc_storage(receipt.created_at),
            None if receipt.expires_at is None else utc_storage(receipt.expires_at),
        ),
    )


def _current_consent_pointer(connection, subject_id: UUID) -> tuple[UUID, ...]:
    raw = connection.exec_driver_sql(
        "SELECT current_consent_receipt_ids FROM subjects WHERE id=?",
        (str(subject_id),),
    ).scalar_one()
    return tuple(UUID(item) for item in json.loads(bytes(raw).decode("ascii")))


@pytest.mark.asyncio
async def test_sql_profile_repository_roundtrips_private_fields_and_fails_closed_on_state_drift(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    now = clock.now()
    household_id = UUID("00000000-0000-4000-8000-000000000601")
    owner_id = UUID("00000000-0000-4000-8000-000000000602")
    adult_id = UUID("00000000-0000-4000-8000-000000000603")
    child_id = UUID("00000000-0000-4000-8000-000000000604")
    due_at = now - timedelta(seconds=1)
    adult_label = b"adult-label".ljust(28, b".")
    adult_persona = b"old-persona".ljust(28, b".")
    owner = Profile(
        id=owner_id,
        household_id=household_id,
        guardian_id=None,
        guardian_generation=0,
        profile_class=ProfileClass.OWNER,
        encrypted_display_label=b"owner-label".ljust(28, b"."),
        encrypted_persona_traits=None,
        current_consent_receipt_ids=(),
        active=True,
        authority_generation=1,
        version=1,
        next_reenrollment_reminder_at=None,
        created_at=now,
        updated_at=now,
    )
    adult = owner.model_copy(
        update={
            "id": adult_id,
            "profile_class": ProfileClass.ADULT,
            "encrypted_display_label": adult_label,
            "encrypted_persona_traits": adult_persona,
        }
    )
    child = owner.model_copy(
        update={
            "id": child_id,
            "guardian_id": owner_id,
            "guardian_generation": 1,
            "profile_class": ProfileClass.K2,
            "encrypted_display_label": b"child-label".ljust(28, b"."),
            "next_reenrollment_reminder_at": due_at,
        }
    )
    with migrated_sqlcipher_engine.engine.begin() as connection:
        _insert_household(connection, household_id, now)

    uow_factory = _build_sql_uow_factory(migrated_sqlcipher_engine, clock)
    try:
        async with uow_factory() as uow:
            await uow.profiles.insert(owner)
            await uow.profiles.insert(adult)
            await uow.profiles.insert(child)
            await uow.commit()

        with migrated_sqlcipher_engine.engine.begin() as connection:
            connection.exec_driver_sql(
                "INSERT INTO current_owner_authority "
                "(household_id,subject_id,owner_generation,changed_at) VALUES (?,?,?,?)",
                (str(household_id), str(owner_id), 1, utc_storage(now)),
            )

        async with uow_factory() as uow:
            reloaded = await uow.profiles.get(adult_id)
            assert reloaded.encrypted_display_label == adult_label
            assert reloaded.encrypted_persona_traits == adult_persona
            with pytest.raises(KeyError):
                await uow.profiles.get(uuid4())
            with pytest.raises(KeyError):
                await uow.profiles.get_scoped(uuid4(), adult_id)
            assert await uow.profiles.get_optional_scoped(uuid4(), adult_id) is None

            due = await uow.profiles.list_children_due_for_reenrollment_reminder(
                household_id,
                now,
            )
            assert tuple(profile.id for profile in due) == (child_id,)
            await uow.profiles.disable_biometric_identity(child_id, now)
            assert (
                await uow.profiles.require_current_owner_guardian_generation(
                    household_id,
                    owner_id,
                    now,
                )
                == 1
            )
            with pytest.raises(PermissionError, match="current_owner_guardian_required"):
                await uow.profiles.require_current_owner_guardian_generation(
                    household_id,
                    adult_id,
                    now,
                )

            updated = await uow.profiles.update_persona_expected_version(
                adult_id,
                1,
                b"new-persona".ljust(28, b"."),
                now + timedelta(microseconds=1),
            )
            with pytest.raises(RuntimeError, match="stale_profile_version"):
                await uow.profiles.update_persona_expected_version(
                    adult_id,
                    1,
                    b"stale-persona".ljust(28, b"."),
                    now + timedelta(microseconds=2),
                )
            revoked = await uow.profiles.revoke_and_advance_authority_generation_expected_version(
                adult_id,
                updated.version,
                updated.authority_generation,
                now + timedelta(microseconds=3),
            )
            with pytest.raises(RuntimeError, match="stale_profile_version"):
                await uow.profiles.revoke_and_advance_authority_generation_expected_version(
                    adult_id,
                    updated.version,
                    updated.authority_generation,
                    now + timedelta(microseconds=4),
                )
            await uow.commit()

        with migrated_sqlcipher_engine.engine.connect() as connection:
            reminder = connection.exec_driver_sql(
                "SELECT next_reenrollment_reminder_at FROM subjects WHERE id=?",
                (str(child_id),),
            ).scalar_one()
            adult_state = connection.exec_driver_sql(
                "SELECT active,authority_generation,version,revoked_at FROM subjects WHERE id=?",
                (str(adult_id),),
            ).one()

        assert reminder is None
        assert tuple(adult_state) == (
            0,
            revoked.authority_generation,
            revoked.version,
            utc_storage(now + timedelta(microseconds=3)),
        )
    finally:
        await uow_factory.aclose()


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

    uow_factory = _build_sql_uow_factory(migrated_sqlcipher_engine, clock)
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

    uow_factory = _build_sql_uow_factory(migrated_sqlcipher_engine, clock)
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
async def test_sql_consent_append_rejects_stale_latest_without_changing_pointer(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    now = clock.now()
    household_id = UUID("00000000-0000-4000-8000-000000000641")
    subject_id = UUID("00000000-0000-4000-8000-000000000642")
    with migrated_sqlcipher_engine.engine.begin() as connection:
        _insert_household(connection, household_id, now)
        _insert_subject(connection, household_id=household_id, subject_id=subject_id, now=now)

    uow_factory = _build_sql_uow_factory(migrated_sqlcipher_engine, clock)
    first = _sql_consent_receipt(
        household_id=household_id,
        subject_id=subject_id,
        purpose=ConsentPurpose.CLOUD_STT,
        created_at=now,
    )
    stale = _sql_consent_receipt(
        household_id=household_id,
        subject_id=subject_id,
        purpose=ConsentPurpose.CLOUD_STT,
        created_at=now + timedelta(microseconds=1),
    )
    async with uow_factory() as uow:
        await uow.consent_receipts.append_replacing_current(
            first,
            expected_latest_receipt_id=None,
            auth=object(),
        )
        await uow.commit()

    try:
        async with uow_factory() as uow:
            with pytest.raises(ConsentDenied, match="consent_state_changed"):
                await uow.consent_receipts.append_replacing_current(
                    stale,
                    expected_latest_receipt_id=None,
                    auth=object(),
                )
            await uow.rollback()

        with migrated_sqlcipher_engine.engine.connect() as connection:
            stale_count = connection.exec_driver_sql(
                "SELECT count(*) FROM consent_receipts WHERE id=?",
                (str(stale.id),),
            ).scalar_one()
            assert stale_count == 0
            assert _current_consent_pointer(connection, subject_id) == (first.id,)
    finally:
        await uow_factory.aclose()


@pytest.mark.asyncio
async def test_sql_consent_append_requires_active_subject_before_receipt_insert(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    now = clock.now()
    household_id = UUID("00000000-0000-4000-8000-000000000651")
    subject_id = UUID("00000000-0000-4000-8000-000000000652")
    with migrated_sqlcipher_engine.engine.begin() as connection:
        _insert_household(connection, household_id, now)
        _insert_subject(
            connection,
            household_id=household_id,
            subject_id=subject_id,
            now=now,
            revoked_at=utc_storage(now),
        )

    uow_factory = _build_sql_uow_factory(migrated_sqlcipher_engine, clock)
    receipt = _sql_consent_receipt(
        household_id=household_id,
        subject_id=subject_id,
        purpose=ConsentPurpose.CLOUD_TTS,
        created_at=now,
    )
    try:
        async with uow_factory() as uow:
            with pytest.raises(ConsentDenied, match="current_active_subject_required"):
                await uow.consent_receipts.append_replacing_current(
                    receipt,
                    expected_latest_receipt_id=None,
                    auth=object(),
                )
            await uow.rollback()

        with migrated_sqlcipher_engine.engine.connect() as connection:
            receipt_count = connection.exec_driver_sql(
                "SELECT count(*) FROM consent_receipts WHERE id=?",
                (str(receipt.id),),
            ).scalar_one()
        assert receipt_count == 0
    finally:
        await uow_factory.aclose()


@pytest.mark.asyncio
async def test_sql_consent_append_fails_closed_when_current_pointer_loses_latest_grant(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    now = clock.now()
    household_id = UUID("00000000-0000-4000-8000-000000000661")
    subject_id = UUID("00000000-0000-4000-8000-000000000662")
    with migrated_sqlcipher_engine.engine.begin() as connection:
        _insert_household(connection, household_id, now)
        _insert_subject(connection, household_id=household_id, subject_id=subject_id, now=now)
        first = _sql_consent_receipt(
            household_id=household_id,
            subject_id=subject_id,
            purpose=ConsentPurpose.CLOUD_STT,
            created_at=now,
        )
        _insert_consent_receipt(connection, first)

    uow_factory = _build_sql_uow_factory(migrated_sqlcipher_engine, clock)
    replacement = _sql_consent_receipt(
        household_id=household_id,
        subject_id=subject_id,
        purpose=ConsentPurpose.CLOUD_STT,
        created_at=now + timedelta(microseconds=1),
    )
    try:
        async with uow_factory() as uow:
            with pytest.raises(RuntimeError, match="current_consent_pointer_corrupt"):
                await uow.consent_receipts.append_replacing_current(
                    replacement,
                    expected_latest_receipt_id=first.id,
                    auth=object(),
                )
            await uow.rollback()

        with migrated_sqlcipher_engine.engine.connect() as connection:
            replacement_count = connection.exec_driver_sql(
                "SELECT count(*) FROM consent_receipts WHERE id=?",
                (str(replacement.id),),
            ).scalar_one()
        assert replacement_count == 0
    finally:
        await uow_factory.aclose()


@pytest.mark.asyncio
async def test_sql_consent_append_rejects_dangling_current_pointer_before_insert(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    now = clock.now()
    household_id = UUID("00000000-0000-4000-8000-000000000671")
    subject_id = UUID("00000000-0000-4000-8000-000000000672")
    with migrated_sqlcipher_engine.engine.begin() as connection:
        _insert_household(connection, household_id, now)
        _insert_subject(
            connection,
            household_id=household_id,
            subject_id=subject_id,
            now=now,
            current_consent_receipt_ids=_receipt_ids_blob((uuid4(),)),
        )

    uow_factory = _build_sql_uow_factory(migrated_sqlcipher_engine, clock)
    receipt = _sql_consent_receipt(
        household_id=household_id,
        subject_id=subject_id,
        purpose=ConsentPurpose.CLOUD_STT,
        created_at=now,
    )
    try:
        async with uow_factory() as uow:
            with pytest.raises(RuntimeError, match="current_consent_pointer_corrupt"):
                await uow.consent_receipts.append_replacing_current(
                    receipt,
                    expected_latest_receipt_id=None,
                    auth=object(),
                )
            await uow.rollback()

        with migrated_sqlcipher_engine.engine.connect() as connection:
            receipt_count = connection.exec_driver_sql(
                "SELECT count(*) FROM consent_receipts WHERE id=?",
                (str(receipt.id),),
            ).scalar_one()
        assert receipt_count == 0
    finally:
        await uow_factory.aclose()


@pytest.mark.asyncio
async def test_sql_consent_append_rejects_full_pointer_without_receipt_insert(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    now = clock.now()
    household_id = UUID("00000000-0000-4000-8000-000000000681")
    subject_id = UUID("00000000-0000-4000-8000-000000000682")
    other_subject_id = UUID("00000000-0000-4000-8000-000000000683")
    pointer_receipts = [
        _sql_consent_receipt(
            household_id=household_id,
            subject_id=subject_id if index < 7 else other_subject_id,
            purpose=ConsentPurpose.CLOUD_REASONING,
            created_at=now + timedelta(microseconds=index),
        )
        for index in range(8)
    ]
    with migrated_sqlcipher_engine.engine.begin() as connection:
        _insert_household(connection, household_id, now)
        _insert_subject(
            connection,
            household_id=household_id,
            subject_id=subject_id,
            now=now,
            current_consent_receipt_ids=_receipt_ids_blob(
                tuple(receipt.id for receipt in pointer_receipts)
            ),
        )
        _insert_subject(connection, household_id=household_id, subject_id=other_subject_id, now=now)
        for receipt in pointer_receipts:
            _insert_consent_receipt(connection, receipt)

    uow_factory = _build_sql_uow_factory(migrated_sqlcipher_engine, clock)
    receipt = _sql_consent_receipt(
        household_id=household_id,
        subject_id=subject_id,
        purpose=ConsentPurpose.CLOUD_STT,
        created_at=now + timedelta(seconds=1),
    )
    try:
        async with uow_factory() as uow:
            with pytest.raises(RuntimeError, match="current_consent_pointer_full"):
                await uow.consent_receipts.append_replacing_current(
                    receipt,
                    expected_latest_receipt_id=None,
                    auth=object(),
                )
            await uow.rollback()

        with migrated_sqlcipher_engine.engine.connect() as connection:
            receipt_count = connection.exec_driver_sql(
                "SELECT count(*) FROM consent_receipts WHERE id=?",
                (str(receipt.id),),
            ).scalar_one()
            assert receipt_count == 0
            assert _current_consent_pointer(connection, subject_id) == tuple(
                item.id for item in pointer_receipts
            )
    finally:
        await uow_factory.aclose()


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

    uow_factory = _build_sql_uow_factory(migrated_sqlcipher_engine, clock)
    async with uow_factory() as uow:
        identity_uow = cast(IdentityUnitOfWork, uow)
        with pytest.raises(ValueError, match="current consent receipt ids corrupt"):
            await identity_uow.profiles.get(subject_id)
        await uow.rollback()
