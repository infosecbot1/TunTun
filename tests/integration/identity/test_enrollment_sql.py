# mypy: disable-error-code="no-untyped-def"
from __future__ import annotations

from collections.abc import Mapping
from datetime import timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest
import rfc8785
from rfc8785._impl import _Value as Rfc8785Value
from tuntun_contracts.actions import ActionBinding
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.policy import AssuranceLevel, AuthContext
from tuntun_core.adapters.sqlcipher.identity_repositories import _receipt_ids_blob
from tuntun_core.bootstrap.container import (
    build_task1_identity_container,
    build_task1_sqlcipher_uow_factory,
)
from tuntun_core.domain.profile import ConsentPurpose, ConsentReceipt, Modality, RequestEnrollment
from tuntun_core.services.actions.parameter_binding import enrollment_request_parameters
from tuntun_core.services.identity.consent import _subject_consent_receipt_fields
from tuntun_core.services.identity.enrollment import EnrollmentDenied
from tuntun_core.services.identity.runtime import HmacReceiptSigner, Task1IdentityKeyBundle
from tuntun_core.services.storage_time import utc_storage
from tuntun_core.services.transactions.identity_uow import IdentityUnitOfWork

from tests.identity_support import task1_test_identity_keys

_POLICY_VERSION = "phase1-identity-test-v1"
_DISCLOSURE_VERSION = "phase1-biometric-disclosure-v1"


def _action_binding(
    keys: Task1IdentityKeyBundle,
    *,
    household_id: UUID,
    actor_id: UUID,
    child_id: UUID,
    consent_receipt_id: UUID,
) -> ActionBinding:
    parameters: Mapping[str, object] = {
        "expected_consent_receipt_id": str(consent_receipt_id),
        "expected_profile_version": 1,
        "modality": Modality.FACE.value,
        "reenrollment_days": 180,
        "subject_id": str(child_id),
    }
    commitment = commit_private(
        keys.action_parameters.root_key,
        keys.action_parameters.key_id,
        "action.parameters",
        rfc8785.dumps(cast(Rfc8785Value, dict(parameters))),
    )
    return ActionBinding(
        household_id=household_id,
        proposal_id=uuid4(),
        turn_id=uuid4(),
        idempotency_key=uuid4(),
        action_name="identity.enroll",
        resource_type="identity",
        resource_id=child_id,
        parameter_commitment=commitment,
        policy_version=_POLICY_VERSION,
        session_id=uuid4(),
        subject_id=actor_id,
    )


def _owner_passkey_auth(owner_id: UUID, binding: ActionBinding, now) -> AuthContext:
    return AuthContext(
        grant_id=uuid4(),
        subject_id=owner_id,
        binding=binding,
        assurance=AssuranceLevel.PASSKEY_VERIFIED,
        assurance_source="passkey",
        consumed_at=now,
    )


def _seed_child_face_consent(engine, keys: Task1IdentityKeyBundle, now):
    household_id = uuid4()
    owner_id = uuid4()
    child_id = uuid4()
    consent_id = uuid4()
    consent_expires_at = now + timedelta(days=30)
    signer = HmacReceiptSigner(
        keys.receipt.root_key,
        key_id=keys.receipt.key_id,
    )
    key_id, receipt_hmac = signer.sign_fields(
        "subject_consent_receipt",
        _subject_consent_receipt_fields(
            household_id=household_id,
            subject_id=child_id,
            purpose=ConsentPurpose.FACE,
            actor_id=owner_id,
            guardian_id=owner_id,
            guardian_generation=1,
            granted=True,
            policy_version=_POLICY_VERSION,
            disclosure_version=_DISCLOSURE_VERSION,
            created_at=now,
            expires_at=consent_expires_at,
        ),
    )
    consent = ConsentReceipt(
        id=consent_id,
        household_id=household_id,
        subject_id=child_id,
        actor_id=owner_id,
        guardian_id=owner_id,
        guardian_generation=1,
        purpose=ConsentPurpose.FACE,
        granted=True,
        policy_version=_POLICY_VERSION,
        disclosure_version=_DISCLOSURE_VERSION,
        commitment_key_id=key_id,
        receipt_hmac=receipt_hmac,
        created_at=now,
        expires_at=consent_expires_at,
    )
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "INSERT INTO households(id,display_label_ciphertext,timezone,created_at) "
            "VALUES(?,?,?,?)",
            (str(household_id), b"household-label", "Asia/Singapore", utc_storage(now)),
        )
        connection.exec_driver_sql(
            "INSERT INTO subjects "
            "(id,household_id,guardian_id,guardian_generation,profile_class,"
            "encrypted_display_label,encrypted_persona_traits,current_consent_receipt_ids,"
            "active,authority_generation,version,next_reenrollment_reminder_at,"
            "created_at,updated_at,revoked_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
            (
                str(owner_id),
                str(household_id),
                None,
                0,
                "owner",
                b"owner-label".ljust(28, b"."),
                None,
                _receipt_ids_blob(()),
                1,
                1,
                1,
                None,
                utc_storage(now),
                utc_storage(now),
            ),
        )
        connection.exec_driver_sql(
            "INSERT INTO current_owner_authority "
            "(household_id,subject_id,owner_generation,changed_at) VALUES (?,?,?,?)",
            (str(household_id), str(owner_id), 1, utc_storage(now)),
        )
        connection.exec_driver_sql(
            "INSERT INTO subjects "
            "(id,household_id,guardian_id,guardian_generation,profile_class,"
            "encrypted_display_label,encrypted_persona_traits,current_consent_receipt_ids,"
            "active,authority_generation,version,next_reenrollment_reminder_at,"
            "created_at,updated_at,revoked_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
            (
                str(child_id),
                str(household_id),
                str(owner_id),
                1,
                "k2",
                b"child-label".ljust(28, b"."),
                None,
                _receipt_ids_blob((consent_id,)),
                1,
                1,
                1,
                None,
                utc_storage(now),
                utc_storage(now),
            ),
        )
        connection.exec_driver_sql(
            "INSERT INTO consent_receipts "
            "(id,household_id,subject_id,actor_id,guardian_id,guardian_generation,"
            "purpose,granted,policy_version,disclosure_version,commitment_key_id,"
            "receipt_hmac,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(consent.id),
                str(consent.household_id),
                str(consent.subject_id),
                str(consent.actor_id),
                str(consent.guardian_id),
                consent.guardian_generation,
                consent.purpose.value,
                int(consent.granted),
                consent.policy_version,
                consent.disclosure_version,
                consent.commitment_key_id,
                consent.receipt_hmac,
                utc_storage(consent.created_at),
                utc_storage(consent.expires_at),
            ),
        )
    return household_id, owner_id, child_id, consent


def _enrollment_request(
    keys: Task1IdentityKeyBundle,
    household_id: UUID,
    owner_id: UUID,
    child_id: UUID,
    consent_id: UUID,
) -> RequestEnrollment:
    binding = _action_binding(
        keys,
        household_id=household_id,
        actor_id=owner_id,
        child_id=child_id,
        consent_receipt_id=consent_id,
    )
    command = RequestEnrollment(
        subject_id=child_id,
        modality=Modality.FACE,
        expected_profile_version=1,
        expected_consent_receipt_id=consent_id,
        reenrollment_days=180,
        action_binding=binding,
    )
    assert enrollment_request_parameters(command) == {
        "expected_consent_receipt_id": str(consent_id),
        "expected_profile_version": 1,
        "modality": "face",
        "reenrollment_days": 180,
        "subject_id": str(child_id),
    }
    return command


async def _insert_staged_template(
    uow: IdentityUnitOfWork,
    *,
    template_id: UUID,
    enrollment_session_id: UUID,
    subject_id: UUID,
    consent_id: UUID,
    created_at,
    expires_at=None,
) -> None:
    def insert_template(tx) -> None:
        tx.exec_driver_sql(
            "INSERT INTO biometric_templates "
            "(id,enrollment_session_id,subject_id,modality,model_version,ciphertext,nonce,wrapped_dek,"
            "root_key_id,consent_receipt_id,created_at,expires_at,revoked_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
            (
                str(template_id),
                str(enrollment_session_id),
                str(subject_id),
                Modality.FACE.value,
                "face-template-v1",
                b"encrypted-template-ciphertext",
                b"template-nonce",
                b"wrapped-template-dek",
                "template-root-key-v1",
                str(consent_id),
                utc_storage(created_at),
                None if expires_at is None else utc_storage(expires_at),
            ),
        )

    await uow.run_sync(insert_template)


@pytest.mark.asyncio
async def test_sql_enrollment_request_capture_calibrate_approval_roundtrip(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    keys = task1_test_identity_keys()
    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )
    container = build_task1_identity_container(uow_factory, clock, keys)
    try:
        household_id, owner_id, child_id, consent = _seed_child_face_consent(
            migrated_sqlcipher_engine.engine,
            keys,
            clock.now(),
        )
        command = _enrollment_request(keys, household_id, owner_id, child_id, consent.id)
        session = await container.identity_services.enrollments.request(
            command,
            _owner_passkey_auth(owner_id, command.action_binding, clock.now()),
        )
        template_id = session.synthetic_template_id
        assert template_id is not None

        async with container.identity_services.enrollment_mutations.mutation_scope.open() as uow:
            capturing = await container.identity_services.enrollments.begin_capture_in_uow(
                uow,
                session.id,
            )
            calibrating = await container.identity_services.enrollments.mark_calibrating_in_uow(
                uow,
                session.id,
            )
            await _insert_staged_template(
                uow,
                template_id=template_id,
                enrollment_session_id=session.id,
                subject_id=child_id,
                consent_id=consent.id,
                created_at=clock.now(),
            )
            approved = await container.identity_services.enrollments.complete_in_uow(
                uow,
                session.id,
                (template_id,),
                consent,
                clock.now(),
            )
            await uow.commit()

        assert capturing.state == "capturing"
        assert calibrating.state == "calibrating"
        assert approved.state == "approved"
        assert approved.next_reenrollment_reminder_at == clock.now() + timedelta(days=180)
        assert approved.biometric_hard_expires_at == clock.now() + timedelta(days=365)
        with migrated_sqlcipher_engine.engine.connect() as connection:
            enrollment_state = connection.exec_driver_sql(
                "SELECT state FROM enrollment_sessions WHERE id=?",
                (str(session.id),),
            ).scalar_one()
            template_expiry = connection.exec_driver_sql(
                "SELECT expires_at FROM biometric_templates WHERE id=?",
                (str(template_id),),
            ).scalar_one()
        assert enrollment_state == "approved"
        assert template_expiry == utc_storage(clock.now() + timedelta(days=365))
    finally:
        await uow_factory.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ("requested", "capturing"))
async def test_sql_enrollment_repository_approve_requires_calibrating_state(
    migrated_sqlcipher_engine,
    clock,
    state: str,
) -> None:
    keys = task1_test_identity_keys()
    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )
    container = build_task1_identity_container(uow_factory, clock, keys)
    try:
        household_id, owner_id, child_id, consent = _seed_child_face_consent(
            migrated_sqlcipher_engine.engine,
            keys,
            clock.now(),
        )
        command = _enrollment_request(keys, household_id, owner_id, child_id, consent.id)
        session = await container.identity_services.enrollments.request(
            command,
            _owner_passkey_auth(owner_id, command.action_binding, clock.now()),
        )
        if state == "capturing":
            with migrated_sqlcipher_engine.engine.begin() as connection:
                connection.exec_driver_sql(
                    "UPDATE enrollment_sessions SET state='capturing' WHERE id=?",
                    (str(session.id),),
                )
        template_id = session.synthetic_template_id
        assert template_id is not None

        async with uow_factory() as uow:
            await _insert_staged_template(
                uow,
                template_id=template_id,
                enrollment_session_id=session.id,
                subject_id=child_id,
                consent_id=consent.id,
                created_at=clock.now(),
            )
            with pytest.raises(RuntimeError, match="enrollment_approval_lost_ownership"):
                await uow.enrollments.approve(
                    session.id,
                    (template_id,),
                    None,
                    None,
                    clock.now(),
                )
            await uow.rollback()
    finally:
        await uow_factory.aclose()


@pytest.mark.asyncio
async def test_sql_enrollment_rejects_non_staged_expired_template(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    keys = task1_test_identity_keys()
    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )
    container = build_task1_identity_container(uow_factory, clock, keys)
    try:
        household_id, owner_id, child_id, consent = _seed_child_face_consent(
            migrated_sqlcipher_engine.engine,
            keys,
            clock.now(),
        )
        command = _enrollment_request(keys, household_id, owner_id, child_id, consent.id)
        session = await container.identity_services.enrollments.request(
            command,
            _owner_passkey_auth(owner_id, command.action_binding, clock.now()),
        )
        template_id = session.synthetic_template_id
        assert template_id is not None

        async with container.identity_services.enrollment_mutations.mutation_scope.open() as uow:
            await container.identity_services.enrollments.begin_capture_in_uow(uow, session.id)
            await container.identity_services.enrollments.mark_calibrating_in_uow(uow, session.id)
            await _insert_staged_template(
                uow,
                template_id=template_id,
                enrollment_session_id=session.id,
                subject_id=child_id,
                consent_id=consent.id,
                created_at=clock.now() - timedelta(minutes=1),
                expires_at=clock.now() - timedelta(seconds=1),
            )
            with pytest.raises(EnrollmentDenied, match="enrollment_template_scope_mismatch"):
                await container.identity_services.enrollments.complete_in_uow(
                    uow,
                    session.id,
                    (template_id,),
                    consent,
                    clock.now(),
                )
            await uow.rollback()
    finally:
        await uow_factory.aclose()


@pytest.mark.asyncio
async def test_sql_enrollment_expected_template_id_survives_reopened_factory_and_transitions(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    keys = task1_test_identity_keys()
    first_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )
    first_container = build_task1_identity_container(first_factory, clock, keys)
    try:
        household_id, owner_id, child_id, consent = _seed_child_face_consent(
            migrated_sqlcipher_engine.engine,
            keys,
            clock.now(),
        )
        command = _enrollment_request(keys, household_id, owner_id, child_id, consent.id)
        session = await first_container.identity_services.enrollments.request(
            command,
            _owner_passkey_auth(owner_id, command.action_binding, clock.now()),
        )
        expected_template_id = session.synthetic_template_id
        assert expected_template_id is not None
    finally:
        await first_factory.aclose()

    reopened_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )
    try:
        async with reopened_factory() as uow:
            reloaded = await uow.enrollments.require_for_update(session.id)
            capturing = await uow.enrollments.begin_capture(session.id, clock.now())
            calibrating = await uow.enrollments.mark_calibrating(session.id, clock.now())
            await uow.rollback()

        assert reloaded.synthetic_template_id == expected_template_id
        assert capturing.synthetic_template_id == expected_template_id
        assert calibrating.synthetic_template_id == expected_template_id
    finally:
        await reopened_factory.aclose()


@pytest.mark.asyncio
async def test_sql_null_expected_template_id_cannot_begin_capture(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    keys = task1_test_identity_keys()
    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )
    container = build_task1_identity_container(uow_factory, clock, keys)
    try:
        household_id, owner_id, child_id, consent = _seed_child_face_consent(
            migrated_sqlcipher_engine.engine,
            keys,
            clock.now(),
        )
        command = _enrollment_request(keys, household_id, owner_id, child_id, consent.id)
        session = await container.identity_services.enrollments.request(
            command,
            _owner_passkey_auth(owner_id, command.action_binding, clock.now()),
        )
        assert session.synthetic_template_id is not None
        with migrated_sqlcipher_engine.engine.begin() as connection:
            connection.exec_driver_sql(
                "UPDATE enrollment_sessions SET synthetic_template_id=NULL WHERE id=?",
                (str(session.id),),
            )

        async with container.identity_services.enrollment_mutations.mutation_scope.open() as uow:
            with pytest.raises(RuntimeError, match="enrollment_expected_template_required"):
                await container.identity_services.enrollments.begin_capture_in_uow(
                    uow,
                    session.id,
                )
            await uow.rollback()

        with migrated_sqlcipher_engine.engine.connect() as connection:
            persisted = connection.exec_driver_sql(
                "SELECT state FROM enrollment_sessions WHERE id=?",
                (str(session.id),),
            ).scalar_one()
        assert persisted == "requested"
    finally:
        await uow_factory.aclose()


@pytest.mark.asyncio
async def test_sql_null_expected_template_id_cannot_mark_calibrating(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    keys = task1_test_identity_keys()
    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )
    container = build_task1_identity_container(uow_factory, clock, keys)
    try:
        household_id, owner_id, child_id, consent = _seed_child_face_consent(
            migrated_sqlcipher_engine.engine,
            keys,
            clock.now(),
        )
        command = _enrollment_request(keys, household_id, owner_id, child_id, consent.id)
        session = await container.identity_services.enrollments.request(
            command,
            _owner_passkey_auth(owner_id, command.action_binding, clock.now()),
        )
        assert session.synthetic_template_id is not None
        with migrated_sqlcipher_engine.engine.begin() as connection:
            connection.exec_driver_sql(
                "UPDATE enrollment_sessions SET state='capturing', synthetic_template_id=NULL "
                "WHERE id=?",
                (str(session.id),),
            )

        async with container.identity_services.enrollment_mutations.mutation_scope.open() as uow:
            with pytest.raises(RuntimeError, match="enrollment_expected_template_required"):
                await container.identity_services.enrollments.mark_calibrating_in_uow(
                    uow,
                    session.id,
                )
            await uow.rollback()

        with migrated_sqlcipher_engine.engine.connect() as connection:
            persisted = connection.exec_driver_sql(
                "SELECT state FROM enrollment_sessions WHERE id=?",
                (str(session.id),),
            ).scalar_one()
        assert persisted == "capturing"
    finally:
        await uow_factory.aclose()


@pytest.mark.asyncio
async def test_sql_same_session_substituted_template_uuid_cannot_approve(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    keys = task1_test_identity_keys()
    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )
    container = build_task1_identity_container(uow_factory, clock, keys)
    try:
        household_id, owner_id, child_id, consent = _seed_child_face_consent(
            migrated_sqlcipher_engine.engine,
            keys,
            clock.now(),
        )
        command = _enrollment_request(keys, household_id, owner_id, child_id, consent.id)
        session = await container.identity_services.enrollments.request(
            command,
            _owner_passkey_auth(owner_id, command.action_binding, clock.now()),
        )
        expected_template_id = session.synthetic_template_id
        assert expected_template_id is not None
        wrong_template_id = uuid4()
        assert wrong_template_id != expected_template_id

        async with container.identity_services.enrollment_mutations.mutation_scope.open() as uow:
            await container.identity_services.enrollments.begin_capture_in_uow(uow, session.id)
            await container.identity_services.enrollments.mark_calibrating_in_uow(uow, session.id)
            await _insert_staged_template(
                uow,
                template_id=wrong_template_id,
                enrollment_session_id=session.id,
                subject_id=child_id,
                consent_id=consent.id,
                created_at=clock.now(),
            )
            with pytest.raises(EnrollmentDenied, match="enrollment_template_scope_mismatch"):
                await container.identity_services.enrollments.complete_in_uow(
                    uow,
                    session.id,
                    (wrong_template_id,),
                    consent,
                    clock.now(),
                )
            await uow.commit()

        with migrated_sqlcipher_engine.engine.connect() as connection:
            persisted = connection.exec_driver_sql(
                "SELECT state FROM enrollment_sessions WHERE id=?",
                (str(session.id),),
            ).scalar_one()
            wrong_template_expiry = connection.exec_driver_sql(
                "SELECT expires_at FROM biometric_templates WHERE id=?",
                (str(wrong_template_id),),
            ).scalar_one()
        assert persisted == "calibrating"
        assert wrong_template_expiry is None
    finally:
        await uow_factory.aclose()


@pytest.mark.asyncio
async def test_sql_enrollment_repository_approve_rejects_same_session_wrong_template_uuid(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    keys = task1_test_identity_keys()
    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )
    container = build_task1_identity_container(uow_factory, clock, keys)
    try:
        household_id, owner_id, child_id, consent = _seed_child_face_consent(
            migrated_sqlcipher_engine.engine,
            keys,
            clock.now(),
        )
        command = _enrollment_request(keys, household_id, owner_id, child_id, consent.id)
        session = await container.identity_services.enrollments.request(
            command,
            _owner_passkey_auth(owner_id, command.action_binding, clock.now()),
        )
        expected_template_id = session.synthetic_template_id
        assert expected_template_id is not None
        wrong_template_id = uuid4()
        assert wrong_template_id != expected_template_id

        async with uow_factory() as uow:
            await uow.enrollments.begin_capture(session.id, clock.now())
            await uow.enrollments.mark_calibrating(session.id, clock.now())
            await _insert_staged_template(
                uow,
                template_id=wrong_template_id,
                enrollment_session_id=session.id,
                subject_id=child_id,
                consent_id=consent.id,
                created_at=clock.now(),
            )
            with pytest.raises(RuntimeError, match="enrollment_approval_lost_ownership"):
                await uow.enrollments.approve(
                    session.id,
                    (wrong_template_id,),
                    None,
                    None,
                    clock.now(),
                )
            await uow.commit()

        with migrated_sqlcipher_engine.engine.connect() as connection:
            persisted = connection.exec_driver_sql(
                "SELECT state FROM enrollment_sessions WHERE id=?",
                (str(session.id),),
            ).scalar_one()
            wrong_template_expiry = connection.exec_driver_sql(
                "SELECT expires_at FROM biometric_templates WHERE id=?",
                (str(wrong_template_id),),
            ).scalar_one()
        assert persisted == "calibrating"
        assert wrong_template_expiry is None
    finally:
        await uow_factory.aclose()


@pytest.mark.asyncio
async def test_sql_enrollment_repository_approval_missing_template_is_atomic(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    keys = task1_test_identity_keys()
    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )
    container = build_task1_identity_container(uow_factory, clock, keys)
    try:
        household_id, owner_id, child_id, consent = _seed_child_face_consent(
            migrated_sqlcipher_engine.engine,
            keys,
            clock.now(),
        )
        command = _enrollment_request(keys, household_id, owner_id, child_id, consent.id)
        session = await container.identity_services.enrollments.request(
            command,
            _owner_passkey_auth(owner_id, command.action_binding, clock.now()),
        )
        expected_template_id = session.synthetic_template_id
        assert expected_template_id is not None

        async with uow_factory() as uow:
            await uow.enrollments.begin_capture(session.id, clock.now())
            await uow.enrollments.mark_calibrating(session.id, clock.now())
            with pytest.raises(RuntimeError):
                await uow.enrollments.approve(
                    session.id,
                    (expected_template_id,),
                    None,
                    None,
                    clock.now(),
                )
            await uow.commit()

        with migrated_sqlcipher_engine.engine.connect() as connection:
            persisted = connection.exec_driver_sql(
                "SELECT state FROM enrollment_sessions WHERE id=?",
                (str(session.id),),
            ).scalar_one()
        assert persisted == "calibrating"
    finally:
        await uow_factory.aclose()


@pytest.mark.asyncio
async def test_sql_legacy_null_expected_template_id_fails_closed(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    keys = task1_test_identity_keys()
    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )
    container = build_task1_identity_container(uow_factory, clock, keys)
    try:
        household_id, owner_id, child_id, consent = _seed_child_face_consent(
            migrated_sqlcipher_engine.engine,
            keys,
            clock.now(),
        )
        command = _enrollment_request(keys, household_id, owner_id, child_id, consent.id)
        session = await container.identity_services.enrollments.request(
            command,
            _owner_passkey_auth(owner_id, command.action_binding, clock.now()),
        )
        assert session.synthetic_template_id is not None
        with migrated_sqlcipher_engine.engine.begin() as connection:
            connection.exec_driver_sql(
                "UPDATE enrollment_sessions SET state='calibrating', synthetic_template_id=NULL "
                "WHERE id=?",
                (str(session.id),),
            )

        async with container.identity_services.enrollment_mutations.mutation_scope.open() as uow:
            await _insert_staged_template(
                uow,
                template_id=session.synthetic_template_id,
                enrollment_session_id=session.id,
                subject_id=child_id,
                consent_id=consent.id,
                created_at=clock.now(),
            )
            with pytest.raises(EnrollmentDenied, match="enrollment_template_scope_mismatch"):
                await container.identity_services.enrollments.complete_in_uow(
                    uow,
                    session.id,
                    (session.synthetic_template_id,),
                    consent,
                    clock.now(),
                )
            await uow.rollback()
    finally:
        await uow_factory.aclose()


@pytest.mark.asyncio
async def test_sql_template_from_prior_session_cannot_approve_reopened_enrollment(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    keys = task1_test_identity_keys()
    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )
    container = build_task1_identity_container(uow_factory, clock, keys)
    try:
        household_id, owner_id, child_id, consent = _seed_child_face_consent(
            migrated_sqlcipher_engine.engine,
            keys,
            clock.now(),
        )
        first_command = _enrollment_request(
            keys,
            household_id,
            owner_id,
            child_id,
            consent.id,
        )
        first_session = await container.identity_services.enrollments.request(
            first_command,
            _owner_passkey_auth(owner_id, first_command.action_binding, clock.now()),
        )
        first_template_id = first_session.synthetic_template_id
        assert first_template_id is not None

        async with container.identity_services.enrollment_mutations.mutation_scope.open() as uow:
            await container.identity_services.enrollments.begin_capture_in_uow(
                uow,
                first_session.id,
            )
            await container.identity_services.enrollments.mark_calibrating_in_uow(
                uow,
                first_session.id,
            )
            await _insert_staged_template(
                uow,
                template_id=first_template_id,
                enrollment_session_id=first_session.id,
                subject_id=child_id,
                consent_id=consent.id,
                created_at=clock.now(),
            )
            await uow.commit()

        second_command = _enrollment_request(
            keys,
            household_id,
            owner_id,
            child_id,
            consent.id,
        )
        second_session = await container.identity_services.enrollments.request(
            second_command,
            _owner_passkey_auth(owner_id, second_command.action_binding, clock.now()),
        )

        async with container.identity_services.enrollment_mutations.mutation_scope.open() as uow:
            await container.identity_services.enrollments.begin_capture_in_uow(
                uow,
                second_session.id,
            )
            await container.identity_services.enrollments.mark_calibrating_in_uow(
                uow,
                second_session.id,
            )
            with pytest.raises(EnrollmentDenied, match="enrollment_template_scope_mismatch"):
                await container.identity_services.enrollments.complete_in_uow(
                    uow,
                    second_session.id,
                    (first_template_id,),
                    consent,
                    clock.now(),
                )
            await uow.rollback()
    finally:
        await uow_factory.aclose()
