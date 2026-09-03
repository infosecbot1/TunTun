# mypy: disable-error-code="no-untyped-def"
from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4, uuid5

import pytest
import rfc8785
from rfc8785._impl import _Value as Rfc8785Value
from tuntun_contracts.actions import ActionBinding
from tuntun_contracts.base import Commitment, Sensitivity, canonical_bytes
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.policy import AssuranceLevel, AuthContext
from tuntun_contracts.provider import RouteAuthorization
from tuntun_core.adapters.keychain.provider import InMemorySecretProvider
from tuntun_core.adapters.sqlcipher.async_unit_of_work import AsyncUnitOfWorkFactory
from tuntun_core.adapters.sqlcipher.identity_repositories import (
    SqlProviderCallsRevocationPort,
    _receipt_ids_blob,
)
from tuntun_core.adapters.sqlcipher.subject_revocation_effect_repository import (
    DownstreamEffectReceipt,
)
from tuntun_core.bootstrap.container import (
    SEARCH_FEATURE_HEAD,
    Task1CapabilityStage,
    build_task1_identity_container,
    build_task1_sqlcipher_uow_factory,
)
from tuntun_core.domain.profile import (
    ConsentPurpose,
    ConsentReceipt,
    Profile,
    ProfileClass,
    RevokeConsent,
)
from tuntun_core.services.actions.parameter_binding import consent_parameters
from tuntun_core.services.audit.ledger import AsyncAuditLedger, AuditLedger
from tuntun_core.services.identity.consent import _subject_consent_receipt_fields
from tuntun_core.services.identity.runtime import (
    HmacReceiptSigner,
    IdentityAuditLedger,
    PrivateCommitmentService,
    Task1ConsentRevocationAuditMapper,
)
from tuntun_core.services.identity.subject_revocation import NotInstalledSubjectAuthorityHandler
from tuntun_core.services.identity.subject_revocation_handlers import (
    NotInstalledAuthorityRevocationHandler,
    ProviderRouteRevocationHandler,
    SearchAuthorityRevocationHandler,
    _OnceHandler,
)
from tuntun_core.services.providers.route_authorization import RouteAuthorizationEnvelopeV1
from tuntun_core.services.storage_time import utc_storage
from tuntun_core.services.transactions.identity_uow import (
    IdentityUnitOfWork,
    IdentityUnitOfWorkFactory,
)
from tuntun_core.services.transactions.protocols import UnitOfWorkProtocol

from tests.identity_support import FacadeFactory

EXPECTED_HANDLER_TYPES = {
    "provider_routes": ProviderRouteRevocationHandler,
    "search_capabilities": SearchAuthorityRevocationHandler,
    "action_authorities": NotInstalledAuthorityRevocationHandler,
    "memory_authorities": NotInstalledAuthorityRevocationHandler,
}


def _task1_test_root(seed: int) -> bytes:
    return bytes(((seed + index) % 251) + 1 for index in range(32))


def _task1_test_keys():
    from tuntun_core.services.identity.runtime import (
        Task1IdentityKeyBundle,
        Task1IdentityKeyMaterial,
    )

    return Task1IdentityKeyBundle(
        profile=Task1IdentityKeyMaterial(_task1_test_root(1), "task1-profile-test-v1"),
        receipt=Task1IdentityKeyMaterial(_task1_test_root(33), "task1-receipt-test-v1"),
        action_parameters=Task1IdentityKeyMaterial(
            _task1_test_root(65),
            "task1-action-parameters-test-v1",
        ),
        audit_chain=Task1IdentityKeyMaterial(
            _task1_test_root(97),
            "task1-audit-chain-test-v1",
        ),
        audit_payload=Task1IdentityKeyMaterial(
            _task1_test_root(129),
            "task1-audit-payload-test-v1",
        ),
    )


def test_task1_production_sources_do_not_embed_known_roots_or_zero_guest_bindings() -> None:
    repo = Path(__file__).resolve().parents[3]
    checked = (
        repo / "apps/core/src/tuntun_core/bootstrap/container.py",
        repo / "apps/core/src/tuntun_core/services/identity/runtime.py",
        repo / "apps/core/src/tuntun_core/adapters/sqlcipher/identity_repositories.py",
    )
    forbidden = (
        'b"p" * 32',
        "b'p' * 32",
        'b"r" * 32',
        "b'r' * 32",
        'b"a" * 32',
        "b'a' * 32",
        'b"l" * 32',
        "b'l' * 32",
        'b"u" * 32',
        "b'u' * 32",
        'b"i" * 32',
        "b'i' * 32",
        'b"\\0" * 32',
        "b'\\0' * 32",
        "_TASK1_PROFILE_ROOT_KEY",
        "_TASK1_RECEIPT_ROOT_KEY",
        "_TASK1_ACTION_PARAMETER_ROOT_KEY",
        "_TASK1_AUDIT_ROOT_KEY",
        "_AUDIT_PAYLOAD_ROOT",
        "_AUDIT_ROOT",
    )
    hits = [
        f"{path.relative_to(repo)}:{needle}"
        for path in checked
        for needle in forbidden
        if needle in path.read_text(encoding="utf-8")
    ]

    assert hits == []


@pytest.mark.asyncio
async def test_task1_identity_audit_rows_do_not_persist_raw_subject_identifiers(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    keys = _task1_test_keys()
    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )
    audit = IdentityAuditLedger(
        AsyncAuditLedger(AuditLedger(keys.audit_chain.key_id, keys.audit_chain.root_key, clock))
    )
    subject_id = UUID("00000000-0000-4000-8000-00000000a111")
    household_id = UUID("00000000-0000-4000-8000-00000000a112")
    binding = ActionBinding(
        household_id=household_id,
        proposal_id=uuid4(),
        turn_id=uuid4(),
        idempotency_key=uuid4(),
        action_name="profile.revoke",
        resource_type="profile",
        resource_id=subject_id,
        parameter_commitment=Commitment(
            algorithm="HMAC-SHA-256",
            key_id=keys.action_parameters.key_id,
            value_b64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
        policy_version="phase1-v1",
        session_id=uuid4(),
        subject_id=subject_id,
    )
    auth = AuthContext(
        grant_id=uuid4(),
        subject_id=subject_id,
        binding=binding,
        assurance=AssuranceLevel.PASSKEY_VERIFIED,
        assurance_source="passkey",
        consumed_at=clock.now(),
    )
    profile = Profile(
        id=subject_id,
        household_id=household_id,
        guardian_id=None,
        guardian_generation=0,
        profile_class=ProfileClass.ADULT,
        encrypted_display_label=b"x" * 28,
        encrypted_persona_traits=None,
        current_consent_receipt_ids=(),
        active=False,
        authority_generation=2,
        version=2,
        next_reenrollment_reminder_at=None,
        created_at=clock.now(),
        updated_at=clock.now(),
        revoked_at=clock.now(),
    )
    receipt = ConsentReceipt(
        id=UUID("00000000-0000-4000-8000-00000000a113"),
        household_id=household_id,
        subject_id=subject_id,
        actor_id=subject_id,
        guardian_id=None,
        guardian_generation=None,
        purpose=ConsentPurpose.CLOUD_STT,
        granted=False,
        policy_version="phase1-v1",
        disclosure_version="phase1-disclosure-v1",
        commitment_key_id=keys.receipt.key_id,
        receipt_hmac=b"h" * 32,
        created_at=clock.now(),
        expires_at=clock.now(),
    )

    async with uow_factory() as uow:
        await audit.append(uow, uow.profiles.created_audit(profile, auth))
        await audit.append(
            uow,
            uow.profiles.persona_changed_audit(profile, auth, operation="clear"),
        )
        await audit.append(uow, uow.profiles.revoked_audit(profile, auth))
        await audit.append(uow, uow.consent_receipts.audit_draft(receipt, auth))
        await audit.append(
            uow,
            Task1ConsentRevocationAuditMapper(PrivateCommitmentService(keys.audit_payload)).revoked(
                {"receipt_id": receipt.id}, auth
            ),
        )
        await uow.commit()

    with migrated_sqlcipher_engine.engine.connect() as connection:
        rows = connection.exec_driver_sql(
            "SELECT canonical_body_json FROM audit_receipts ORDER BY ordinal"
        ).all()
    persisted = "\n".join(str(row[0]) for row in rows)
    assert str(subject_id) not in persisted
    for body in (json.loads(str(row[0])) for row in rows):
        assert body["event_id"] != str(subject_id)
        assert body["correlation_id"] != str(subject_id)
        assert body["actor_pseudonym"].startswith("actor:pseudonym:v1:")


def test_task1_scope_does_not_export_future_action_or_memory_facades() -> None:
    repo = Path(__file__).resolve().parents[3]
    base_uow = repo / "apps/core/src/tuntun_core/services/transactions/identity_uow.py"
    handlers = repo / "apps/core/src/tuntun_core/services/identity/subject_revocation_handlers.py"

    assert "experimental_search_attempts:" not in base_uow.read_text(encoding="utf-8")
    assert "memory_proposals:" not in base_uow.read_text(encoding="utf-8")
    assert "class ActionAuthorityRevocationHandler" not in handlers.read_text(encoding="utf-8")
    assert "class MemoryAuthorityRevocationHandler" not in handlers.read_text(encoding="utf-8")


def test_task1_identity_keys_resolve_from_secret_provider_and_reject_known_roots() -> None:
    from tuntun_core.services.identity.runtime import SecretProviderTask1IdentityKeyProvider

    provider = InMemorySecretProvider()
    for service, seed, key_id in (
        ("tuntun.identity.profile", 1, "task1-profile-secret-v1"),
        ("tuntun.identity.receipts", 33, "task1-receipts-secret-v1"),
        ("tuntun.identity.action-parameters", 65, "task1-action-params-secret-v1"),
        ("tuntun.identity.audit-chain", 97, "task1-audit-chain-secret-v1"),
        ("tuntun.identity.audit-payload", 129, "task1-audit-payload-secret-v1"),
    ):
        provider.set(service, "root-v1", _task1_test_root(seed))
        provider.set(service, "key-id-v1", key_id.encode("ascii"))

    keys = SecretProviderTask1IdentityKeyProvider(provider).current_keys()

    assert keys.profile.key_id == "task1-profile-secret-v1"
    assert keys.receipt.root_key == _task1_test_root(33)

    provider.set("tuntun.identity.profile", "root-v1", b"p" * 32)
    with pytest.raises(RuntimeError, match="task1_identity_key_material_invalid"):
        SecretProviderTask1IdentityKeyProvider(provider).current_keys()


class _LeakTrackingUow:
    def __init__(self) -> None:
        self.closed = False


class _LeakTrackingUowContext:
    def __init__(self, uow: _LeakTrackingUow) -> None:
        self.uow = uow
        self.exits: list[tuple[type[BaseException] | None, str | None]] = []

    async def __aenter__(self) -> _LeakTrackingUow:
        return self.uow

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> bool:
        del traceback
        self.uow.closed = True
        self.exits.append((exc_type, None if exc is None else str(exc)))
        return False


class _LeakTrackingFactory:
    def __init__(self) -> None:
        self.contexts: list[_LeakTrackingUowContext] = []

    def __call__(self) -> _LeakTrackingUowContext:
        context = _LeakTrackingUowContext(_LeakTrackingUow())
        self.contexts.append(context)
        return context


class _PostOpenRejectingMutationScope:
    def __init__(self, delegate) -> None:
        self._delegate = delegate

    def open(self):
        return self._delegate.open()

    def require_active_uow(self):
        return self._delegate.require_active_uow()

    def _reject_nested_active(self) -> None:
        return None

    def _set_active(self, uow):
        return self._delegate._set_active(uow)

    def _clear_active(self, token) -> None:
        self._delegate._clear_active(token)

    def _open_uow(self):
        return self._delegate._open_uow()


@pytest.mark.asyncio
async def test_identity_mutation_scope_unwinds_uow_if_activation_rejects_nested_scope() -> None:
    from tuntun_core.services.identity.runtime import (
        SqlIdentityMutationScope,
        _SqlIdentityMutationContext,
    )

    factory = _LeakTrackingFactory()
    delegate = SqlIdentityMutationScope(cast(AsyncUnitOfWorkFactory, factory))
    scope = _PostOpenRejectingMutationScope(delegate)

    async with _SqlIdentityMutationContext(cast(SqlIdentityMutationScope, scope)) as outer_uow:
        assert scope.require_active_uow() is outer_uow
        with pytest.raises(RuntimeError, match="nested identity mutation scope"):
            async with _SqlIdentityMutationContext(cast(SqlIdentityMutationScope, scope)):
                pass

        assert len(factory.contexts) == 2
        assert factory.contexts[1].uow.closed is True
        assert factory.contexts[1].exits[0][0] is RuntimeError
        assert scope.require_active_uow() is outer_uow

    assert factory.contexts[0].uow.closed is True


def test_task1_sqlcipher_uow_factory_requires_application_clock(
    migrated_sqlcipher_engine,
) -> None:
    with pytest.raises(TypeError):
        build_task1_sqlcipher_uow_factory(migrated_sqlcipher_engine.engine)  # type: ignore[call-arg]


@pytest.mark.asyncio
async def test_identity_mutation_scope_is_task_local(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    from tuntun_core.services.identity.runtime import SqlIdentityMutationScope

    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        _task1_test_keys(),
    )
    scope = SqlIdentityMutationScope(uow_factory)

    async with scope.open() as parent_uow:
        assert scope.require_active_uow() is parent_uow

        async def inherited_context_probe() -> str:
            with pytest.raises(RuntimeError, match="no active atomic mutation scope"):
                scope.require_active_uow()
            return "isolated"

        task = asyncio.create_task(inherited_context_probe())
        assert await task == "isolated"
        with pytest.raises(RuntimeError, match="nested identity mutation scope"):
            async with scope.open():
                pass
        assert scope.require_active_uow() is parent_uow

    with pytest.raises(RuntimeError, match="no active atomic mutation scope"):
        scope.require_active_uow()


def _test_commitment() -> Commitment:
    return Commitment(
        algorithm="HMAC-SHA-256",
        key_id="route-test-key",
        value_b64="A" * 43 + "=",
    )


def _route_envelope(
    *,
    authorization_id: UUID,
    household_id: UUID,
    subject_id: UUID,
    consent_id: UUID,
    expires_at: datetime,
) -> RouteAuthorizationEnvelopeV1:
    route = RouteAuthorization(
        authorization_id=authorization_id,
        request_id=UUID("00000000-0000-4000-8000-000000000211"),
        attempt_id=UUID("00000000-0000-4000-8000-000000000212"),
        purpose="cloud_reasoning",
        household_id=household_id,
        subject_id=subject_id,
        session_id=UUID("00000000-0000-4000-8000-000000000213"),
        turn_id=UUID("00000000-0000-4000-8000-000000000214"),
        provider="openai",
        model="gpt-5.6-sol",
        request_commitment=_test_commitment(),
        max_input_bytes=8192,
        max_input_units=2048,
        privacy_receipt_id=UUID("00000000-0000-4000-8000-000000000215"),
        consent_receipt_ids=(consent_id,),
        budget_reservation_id=UUID("00000000-0000-4000-8000-000000000216"),
        maximum_sensitivity=Sensitivity.HOUSEHOLD,
        expires_at=expires_at.astimezone(UTC),
    )
    return RouteAuthorizationEnvelopeV1(route=route, subject_authority_generation=1)


def _insert_started_provider_call(
    tx: UnitOfWorkProtocol,
    *,
    call_id: UUID,
    reservation_id: UUID,
    request_id: UUID,
    attempt_id: UUID,
    authorization_id: UUID,
    transport_phase: str,
    now: datetime,
) -> None:
    tx.exec_driver_sql(
        "INSERT INTO budget_reservations "
        "(id,request_id,attempt_id,month_key,category,provider,model,outcome,"
        "reserved_micros_sgd,charged_micros_sgd,usage_ceiling_json,price_snapshot_json,"
        "primary_accounting_basis,missing_evidence_policy,pricing_version,price_source_sha256,"
        "fx_version,fx_source_sha256,pricing_commitment_key_id,pricing_commitment_hmac_b64,"
        "estimate_overrun,state,gateway_ordering_version,transport_phase,created_at,expires_at,"
        "settled_at,reconciled_at) VALUES "
        "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL)",
        (
            str(reservation_id),
            str(request_id),
            str(attempt_id),
            "2026-09",
            "llm",
            "openai",
            "gpt-5.6-sol",
            "allow",
            100,
            None,
            "{}",
            "{}",
            "provider_reported_exact",
            "freeze_unknown_overage",
            "test-price-v1",
            "a" * 64,
            "test-fx-v1",
            "b" * 64,
            "pricing-test-key",
            "A" * 43 + "=",
            0,
            "sent" if transport_phase != "claim_begun" else "reserved",
            1,
            transport_phase,
            utc_storage(now),
            utc_storage(now + timedelta(minutes=5)),
        ),
    )
    tx.exec_driver_sql(
        "INSERT INTO provider_calls "
        "(id,request_id,attempt_id,authorization_id,budget_reservation_id,purpose,"
        "provider,model,request_hmac_key_id,request_hmac_b64,category,outcome,"
        "gateway_ordering_version,transport_phase,started_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            str(call_id),
            str(request_id),
            str(attempt_id),
            str(authorization_id),
            str(reservation_id),
            "cloud_reasoning",
            "openai",
            "gpt-5.6-sol",
            "provider-request-v1",
            "A" * 43 + "=",
            "llm",
            "started",
            1,
            transport_phase,
            utc_storage(now),
        ),
    )


def _insert_route_authorization_setting(
    tx: UnitOfWorkProtocol,
    *,
    authorization_id: UUID,
    household_id: UUID,
    subject_id: UUID,
    consent_id: UUID,
    now: datetime,
    value_json: str | None = None,
) -> str:
    route_json = (
        canonical_bytes(
            _route_envelope(
                authorization_id=authorization_id,
                household_id=household_id,
                subject_id=subject_id,
                consent_id=consent_id,
                expires_at=now + timedelta(seconds=30),
            )
        ).decode("utf-8")
        if value_json is None
        else value_json
    )
    tx.exec_driver_sql(
        "INSERT INTO runtime_settings(key,value_json,version,updated_at) VALUES(?,?,1,?)",
        (
            f"route.authorization.{authorization_id}",
            route_json,
            utc_storage(now),
        ),
    )
    return route_json


def _provider_revocation_rows(engine, call_id: UUID, reservation_id: UUID):
    with engine.connect() as connection:
        call = connection.exec_driver_sql(
            "SELECT outcome,transport_phase,finished_at FROM provider_calls WHERE id=?",
            (str(call_id),),
        ).one()
        reservation = connection.exec_driver_sql(
            "SELECT state,transport_phase,charged_micros_sgd,settled_at "
            "FROM budget_reservations WHERE id=?",
            (str(reservation_id),),
        ).one()
    return tuple(call), tuple(reservation)


def test_task1_container_composes_exact_schema_stage_handlers(task1_identity_container) -> None:
    handlers = task1_identity_container.post_commit_revocation_handlers

    assert set(handlers) == set(EXPECTED_HANDLER_TYPES)
    assert all(type(handlers[name]) is kind for name, kind in EXPECTED_HANDLER_TYPES.items())
    assert handlers["action_authorities"].owning_revision == "0003_authentication"
    assert handlers["memory_authorities"].owning_revision == "0004_memory"
    assert task1_identity_container.revocation_processor.handlers is handlers


@pytest.mark.asyncio
async def test_live_worker_runs_task1_handlers_once_without_later_schema_access(
    task1_identity_runtime,
    subject_with_task1_started_authorities,
    revoke_profile_grant,
) -> None:
    runtime = await task1_identity_runtime.start()
    event = await runtime.revoke_profile(
        subject_with_task1_started_authorities, revoke_profile_grant
    )
    await runtime.revocation_worker.wait_until_idle()

    assert await runtime.revocation_outbox.state(event.id) == "completed"
    assert runtime.process_restart_count == 0
    assert runtime.revocation_effects.counts(event.id) == {
        "provider_routes": 1,
        "search_capabilities": 1,
        "action_authorities": 1,
        "memory_authorities": 1,
    }
    assert runtime.revocation_effects.dispositions(event.id) == {
        "provider_routes": "conservatively_settled",
        "search_capabilities": "cancelled",
        "action_authorities": "not_installed_no_authority",
        "memory_authorities": "not_installed_no_authority",
    }
    await runtime.revocation_worker.recover_and_drain_before_ready()
    assert all(value == 1 for value in runtime.revocation_effects.counts(event.id).values())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "crash_after",
    ("effect_claim_commit", "downstream_effect_commit", "effect_complete_commit"),
)
async def test_effect_crash_boundaries_reuse_one_key_receipt_and_side_effect(
    task1_file_backed_identity_runtime,
    subject_with_task1_started_authorities,
    revoke_profile_grant,
    revocation_effect_faults,
    clock,
    crash_after,
) -> None:
    runtime = await task1_file_backed_identity_runtime.start()
    revocation_effect_faults.crash_after(crash_after, family="provider_routes")
    event = await runtime.revoke_profile(
        subject_with_task1_started_authorities, revoke_profile_grant
    )

    with pytest.raises(BaseException, match="simulated_process_crash"):
        await runtime.revocation_worker.wait_for_crash()

    key = runtime.revocation_effects.fixed_key(event.id, "provider_routes")
    assert key == uuid5(event.id, "provider_routes")
    first_receipt = runtime.downstream_effects.receipt_for_key(key)
    clock.advance(seconds=31)
    restarted = await task1_file_backed_identity_runtime.restart()
    await restarted.revocation_worker.recover_and_drain_before_ready()
    completed = await restarted.revocation_effects.completed(key)

    assert completed is not None
    assert completed.idempotency_key == key
    assert restarted.downstream_effects.effect_count(key) == 1
    if first_receipt is not None:
        assert completed.id == first_receipt.id
        assert restarted.downstream_effects.receipt_for_key(key).id == first_receipt.id


@pytest.mark.asyncio
async def test_periodic_drain_takes_expired_effect_but_not_live_effect(
    task1_identity_runtime,
    stale_and_live_effect_claims,
    clock,
) -> None:
    runtime = await task1_identity_runtime.start_without_initial_drain()
    stale, live = stale_and_live_effect_claims

    await runtime.revocation_worker.run_one_periodic_drain()

    assert await runtime.revocation_effects.state(stale.id) == "completed"
    assert await runtime.revocation_effects.lease_owner(stale.id) != stale.lease_owner
    assert await runtime.revocation_effects.state(live.id) == "applying"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changed",
    ("idempotency_key", "event_id", "family", "subject_id", "through_generation"),
)
async def test_fenced_effect_completion_rejects_exact_scope_substitution(
    claimed_revocation_effect,
    revocation_effects,
    downstream_receipt_variant,
    changed,
) -> None:
    claim, receipt = claimed_revocation_effect

    with pytest.raises(RuntimeError, match="revocation_downstream_receipt_scope_mismatch"):
        await revocation_effects.complete(
            claim.idempotency_key,
            claim.lease_owner,
            claim.fencing_token,
            downstream_receipt_variant(receipt, changed),
            claim.now,
        )

    assert await revocation_effects.state(claim.id) == "applying"


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ("renew", "complete", "abandon"))
async def test_stale_effect_lease_cannot_be_renewed_completed_or_abandoned(
    claimed_revocation_effect,
    revocation_effects,
    clock,
    operation,
) -> None:
    claim, receipt = claimed_revocation_effect
    clock.advance(seconds=31)

    if operation == "renew":
        renewed = await revocation_effects.renew(
            claim.idempotency_key,
            claim.lease_owner,
            claim.fencing_token,
            clock.now(),
        )
        assert renewed is False
    elif operation == "complete":
        with pytest.raises(RuntimeError, match="revocation_effect_claim_lost"):
            await revocation_effects.complete(
                claim.idempotency_key,
                claim.lease_owner,
                claim.fencing_token,
                receipt,
                clock.now(),
            )
    else:
        with pytest.raises(RuntimeError, match="revocation_effect_claim_lost"):
            await revocation_effects.abandon(
                claim.idempotency_key,
                claim.lease_owner,
                claim.fencing_token,
                "handler_error:RuntimeError",
                clock.now(),
            )

    assert await revocation_effects.state(claim.id) == "applying"


@pytest.mark.asyncio
async def test_biometric_consent_revocation_handler_revokes_live_face_authority_rows(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    keys = _task1_test_keys()
    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )
    household_id = UUID("00000000-0000-4000-8000-00000000b001")
    subject_id = UUID("00000000-0000-4000-8000-00000000b002")
    device_id = UUID("00000000-0000-4000-8000-00000000b003")
    session_id = UUID("00000000-0000-4000-8000-00000000b004")
    face_consent_id = UUID("00000000-0000-4000-8000-00000000b005")
    face_enrollment_id = UUID("00000000-0000-4000-8000-00000000b006")
    face_template_id = UUID("00000000-0000-4000-8000-00000000b007")
    voice_template_id = UUID("00000000-0000-4000-8000-00000000b008")
    now = clock.now()
    later = now + timedelta(days=30)
    receipt_signer = HmacReceiptSigner(keys.receipt.root_key, key_id=keys.receipt.key_id)
    receipt_key_id, receipt_hmac = receipt_signer.sign_fields(
        "subject_consent_receipt",
        _subject_consent_receipt_fields(
            household_id=household_id,
            subject_id=subject_id,
            purpose=ConsentPurpose.FACE,
            actor_id=subject_id,
            guardian_id=None,
            guardian_generation=None,
            granted=True,
            policy_version="phase1-v1",
            disclosure_version="phase1-disclosure-v1",
            created_at=now,
            expires_at=None,
        ),
    )
    with migrated_sqlcipher_engine.engine.begin() as connection:
        connection.exec_driver_sql(
            "INSERT INTO households(id,display_label_ciphertext,timezone,created_at) "
            "VALUES (?,?,?,?)",
            (str(household_id), b"household-label", "Asia/Singapore", utc_storage(now)),
        )
        connection.exec_driver_sql(
            "INSERT INTO devices "
            "(id,household_id,kind,certificate_fingerprint,signing_public_key,signing_key_id,"
            "last_sequence,paired_at,revoked_at) VALUES (?,?,?,?,?,?,?,?,NULL)",
            (
                str(device_id),
                str(household_id),
                "reachy",
                "fixture-face-voice-handler",
                b"public-key",
                "fixture-signing-key",
                1,
                utc_storage(now),
            ),
        )
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
                b"profile-label-ciphertext-has-enough-bytes",
                None,
                _receipt_ids_blob((face_consent_id,)),
                1,
                1,
                1,
                None,
                utc_storage(now),
                utc_storage(now),
                None,
            ),
        )
        connection.exec_driver_sql(
            "INSERT INTO sessions "
            "(id,household_id,device_id,state,speaker_subject_id,opened_at,last_activity_at,"
            "closed_at) VALUES (?,?,?,?,?,?,?,NULL)",
            (
                str(session_id),
                str(household_id),
                str(device_id),
                "active",
                str(subject_id),
                utc_storage(now),
                utc_storage(now),
            ),
        )
        connection.exec_driver_sql(
            "INSERT INTO consent_receipts "
            "(id,household_id,subject_id,actor_id,guardian_id,guardian_generation,purpose,"
            "granted,policy_version,disclosure_version,commitment_key_id,receipt_hmac,"
            "created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
            (
                str(face_consent_id),
                str(household_id),
                str(subject_id),
                str(subject_id),
                None,
                None,
                "face",
                1,
                "phase1-v1",
                "phase1-disclosure-v1",
                receipt_key_id,
                receipt_hmac,
                utc_storage(now),
            ),
        )
        connection.exec_driver_sql(
            "INSERT INTO enrollment_sessions "
            "(id,subject_id,modality,state,auth_receipt_id,consent_receipt_id,"
            "reenrollment_days,created_at,expires_at,closed_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,NULL)",
            (
                str(face_enrollment_id),
                str(subject_id),
                "face",
                "capturing",
                str(uuid4()),
                str(face_consent_id),
                180,
                utc_storage(now),
                utc_storage(later),
            ),
        )
        for template_id, modality in (
            (face_template_id, "face"),
            (voice_template_id, "voice"),
        ):
            connection.exec_driver_sql(
                "INSERT INTO biometric_templates "
                "(id,enrollment_session_id,subject_id,modality,model_version,ciphertext,nonce,wrapped_dek,"
                "root_key_id,consent_receipt_id,created_at,expires_at,revoked_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
                (
                    str(template_id),
                    str(face_enrollment_id) if modality == "face" else None,
                    str(subject_id),
                    modality,
                    f"{modality}-model-v1",
                    b"template-ciphertext",
                    b"n" * 12,
                    b"wrapped-dek",
                    keys.profile.key_id,
                    str(face_consent_id),
                    utc_storage(now),
                    utc_storage(later),
                ),
            )
    binding = ActionBinding(
        household_id=household_id,
        proposal_id=uuid4(),
        turn_id=uuid4(),
        idempotency_key=uuid4(),
        action_name="consent.revoke",
        resource_type="consent",
        resource_id=subject_id,
        parameter_commitment=Commitment(
            algorithm="HMAC-SHA-256",
            key_id=keys.action_parameters.key_id,
            value_b64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
        policy_version="phase1-v1",
        session_id=session_id,
        subject_id=subject_id,
    )
    command = RevokeConsent(
        subject_id=subject_id,
        actor_id=subject_id,
        purpose=ConsentPurpose.FACE,
        expected_latest_receipt_id=face_consent_id,
        guardian_generation=None,
        policy_version="phase1-v1",
        disclosure_version="phase1-disclosure-v1",
        action_binding=binding,
    )
    bound_command = command.model_copy(
        update={
            "action_binding": binding.model_copy(
                update={
                    "parameter_commitment": commit_private(
                        keys.action_parameters.root_key,
                        keys.action_parameters.key_id,
                        "action.parameters",
                        rfc8785.dumps(cast(Rfc8785Value, consent_parameters(command))),
                    )
                }
            )
        }
    )
    auth = AuthContext(
        grant_id=uuid4(),
        subject_id=subject_id,
        binding=bound_command.action_binding,
        assurance=AssuranceLevel.PASSKEY_VERIFIED,
        assurance_source="passkey",
        consumed_at=now,
    )
    container = build_task1_identity_container(uow_factory, clock, keys)

    revoked = await container.identity_services.consents.revoke(bound_command, auth)
    revocation_time = revoked.created_at

    with migrated_sqlcipher_engine.engine.connect() as connection:
        speaker_subject_id, last_activity_at = connection.exec_driver_sql(
            "SELECT speaker_subject_id,last_activity_at FROM sessions WHERE id=?",
            (str(session_id),),
        ).one()
        face_state, face_closed_at = connection.exec_driver_sql(
            "SELECT state,closed_at FROM enrollment_sessions WHERE id=?",
            (str(face_enrollment_id),),
        ).one()
        face_template = connection.exec_driver_sql(
            "SELECT revoked_at,expires_at FROM biometric_templates WHERE id=?",
            (str(face_template_id),),
        ).one()
        voice_template = connection.exec_driver_sql(
            "SELECT revoked_at,expires_at FROM biometric_templates WHERE id=?",
            (str(voice_template_id),),
        ).one()
        erasure_audit_count = sum(
            json.loads(str(body))["action_code"] == "identity.biometric_template.erasure_requested"
            for (body,) in connection.exec_driver_sql(
                "SELECT canonical_body_json FROM audit_receipts",
            ).all()
        )

    assert speaker_subject_id is None
    assert last_activity_at == utc_storage(revocation_time)
    assert (face_state, face_closed_at) == ("cancelled", utc_storage(revocation_time))
    assert face_template == (utc_storage(revocation_time), utc_storage(revocation_time))
    assert voice_template == (None, utc_storage(later))
    assert erasure_audit_count == 1


def test_absent_search_build_uses_closed_concrete_no_authority_handler(
    absent_search_identity_container,
) -> None:
    handler = absent_search_identity_container.post_commit_revocation_handlers[
        "search_capabilities"
    ]

    assert type(handler) is SearchAuthorityRevocationHandler
    assert handler.feature_state == "absent"
    assert type(handler).__name__ != NotInstalledSubjectAuthorityHandler.__name__


@pytest.mark.asyncio
async def test_absent_search_stage_uses_future_feature_revision_and_verifies_schema_and_facade(
    migrated_sqlcipher_engine,
) -> None:
    stage = Task1CapabilityStage()
    uow_factory = AsyncUnitOfWorkFactory(migrated_sqlcipher_engine.engine)

    async with uow_factory() as uow:
        identity_uow = cast(IdentityUnitOfWork, uow)
        await stage.require_schema_and_facade_absent_in_uow(
            identity_uow,
            "search_capabilities",
            SEARCH_FEATURE_HEAD,
        )
        with pytest.raises(RuntimeError, match="capability_owning_revision_mismatch"):
            await stage.require_schema_and_facade_absent_in_uow(
                identity_uow,
                "search_capabilities",
                "0002_profiles_consent_enrollment",
            )
        await uow.rollback()

    with migrated_sqlcipher_engine.engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE alembic_version_experimental_search(version_num VARCHAR(64) NOT NULL)"
        )
        connection.exec_driver_sql(
            "INSERT INTO alembic_version_experimental_search(version_num) VALUES (?)",
            (SEARCH_FEATURE_HEAD,),
        )
    async with uow_factory() as uow:
        identity_uow = cast(IdentityUnitOfWork, uow)
        with pytest.raises(RuntimeError, match="not_installed_authority_handler_stale"):
            await stage.require_schema_and_facade_absent_in_uow(
                identity_uow,
                "search_capabilities",
                SEARCH_FEATURE_HEAD,
            )
        await uow.rollback()


@pytest.mark.asyncio
async def test_absent_search_stage_rejects_registered_facade_even_without_feature_table(
    migrated_sqlcipher_engine,
) -> None:
    stage = Task1CapabilityStage()
    uow_factory = AsyncUnitOfWorkFactory(
        migrated_sqlcipher_engine.engine,
        {"search_capabilities": FacadeFactory(object())},
    )

    async with uow_factory() as uow:
        identity_uow = cast(IdentityUnitOfWork, uow)
        with pytest.raises(RuntimeError, match="not_installed_authority_handler_stale"):
            await stage.require_schema_and_facade_absent_in_uow(
                identity_uow,
                "search_capabilities",
                SEARCH_FEATURE_HEAD,
            )
        await uow.rollback()


def test_task1_container_requires_sqlcipher_identity_facades(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    with pytest.raises(RuntimeError, match="task1_identity_repository_facades_required"):
        build_task1_identity_container(
            AsyncUnitOfWorkFactory(migrated_sqlcipher_engine.engine),
            clock,
            _task1_test_keys(),
        )


@pytest.mark.parametrize("future_revision", ["0003_authentication", "0004_memory"])
def test_task1_container_fails_stale_action_or_memory_placeholder_readiness(
    migrated_sqlcipher_engine,
    clock,
    future_revision,
) -> None:
    with migrated_sqlcipher_engine.engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS alembic_version(version_num VARCHAR(64) NOT NULL)"
        )
        connection.exec_driver_sql(
            "DELETE FROM alembic_version",
        )
        connection.exec_driver_sql(
            "INSERT INTO alembic_version(version_num) VALUES (?)",
            (future_revision,),
        )
    keys = _task1_test_keys()
    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )

    with pytest.raises(RuntimeError, match="not_installed_authority_handler_stale"):
        build_task1_identity_container(uow_factory, clock, keys)


@pytest.mark.asyncio
async def test_task1_sqlcipher_factory_exposes_required_identity_facades(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    keys = _task1_test_keys()
    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )
    container = build_task1_identity_container(uow_factory, clock, keys)

    async with uow_factory() as uow:
        for name in (
            "profiles",
            "consent_receipts",
            "guest_disclosure_challenges",
            "guest_session_consents",
            "sessions",
            "event_receipts",
            "provider_calls",
            "budget_reservations",
        ):
            assert hasattr(uow, name)
        await uow.rollback()

    assert set(container.post_commit_revocation_handlers) == set(EXPECTED_HANDLER_TYPES)
    assert container.identity_services.profiles is not None
    assert container.identity_services.consents is not None
    assert container.identity_services.guest_consents is not None
    assert container.identity_services.mutations is not None


@pytest.mark.asyncio
async def test_task1_production_identity_services_fail_closed_without_auth_schema(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    keys = _task1_test_keys()
    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )
    container = build_task1_identity_container(uow_factory, clock, keys)

    async with uow_factory() as uow:
        identity_uow = cast(IdentityUnitOfWork, uow)
        with pytest.raises(RuntimeError, match="task1_authentication_unavailable"):
            await container.identity_services.authentication.consume_in_uow(
                identity_uow,
                UUID("00000000-0000-4000-8000-000000000310"),
                object(),
            )
        await uow.rollback()


@pytest.mark.asyncio
async def test_sql_provider_revocation_closes_call_and_settles_budget_atomically(
    migrated_sqlcipher_engine,
    clock,
    monkeypatch,
) -> None:
    from tuntun_core.adapters.sqlcipher import identity_repositories

    engine = migrated_sqlcipher_engine.engine
    uow_factory = build_task1_sqlcipher_uow_factory(engine, clock, _task1_test_keys())
    subject_id = UUID("00000000-0000-4000-8000-000000000511")
    household_id = UUID("00000000-0000-4000-8000-000000000512")
    consent_id = UUID("00000000-0000-4000-8000-000000000513")
    call_id = UUID("00000000-0000-4000-8000-000000000514")
    reservation_id = UUID("00000000-0000-4000-8000-000000000515")
    request_id = UUID("00000000-0000-4000-8000-000000000516")
    attempt_id = UUID("00000000-0000-4000-8000-000000000517")
    authorization_id = UUID("00000000-0000-4000-8000-000000000518")
    now = clock.now()
    with engine.begin() as connection:
        _insert_started_provider_call(
            connection,
            call_id=call_id,
            reservation_id=reservation_id,
            request_id=request_id,
            attempt_id=attempt_id,
            authorization_id=authorization_id,
            transport_phase="marked_sent",
            now=now,
        )
        _insert_route_authorization_setting(
            connection,
            authorization_id=authorization_id,
            household_id=household_id,
            subject_id=subject_id,
            consent_id=consent_id,
            now=now,
        )

    original_settle = identity_repositories._settle_budget_reservation

    def fail_settle(
        tx: UnitOfWorkProtocol,
        item: UUID,
        settled_at: str,
    ) -> int:
        del tx, item, settled_at
        raise RuntimeError("injected_settlement_failure")

    monkeypatch.setattr(identity_repositories, "_settle_budget_reservation", fail_settle)
    port = SqlProviderCallsRevocationPort(
        cast(IdentityUnitOfWorkFactory, uow_factory),
        clock.now,
    )
    with pytest.raises(RuntimeError, match="injected_settlement_failure"):
        await port.reconcile_revoked_subject_once(
            event_id=UUID("00000000-0000-4000-8000-000000000519"),
            family="provider_routes",
            subject_id=subject_id,
            through_generation=2,
            idempotency_key=UUID("00000000-0000-4000-8000-00000000051a"),
        )

    assert _provider_revocation_rows(engine, call_id, reservation_id) == (
        ("started", "marked_sent", None),
        ("sent", "marked_sent", None, None),
    )

    monkeypatch.setattr(
        identity_repositories,
        "_settle_budget_reservation",
        original_settle,
    )
    restarted_port = SqlProviderCallsRevocationPort(
        cast(IdentityUnitOfWorkFactory, uow_factory),
        clock.now,
    )
    summary = await restarted_port.reconcile_revoked_subject_once(
        event_id=UUID("00000000-0000-4000-8000-000000000519"),
        family="provider_routes",
        subject_id=subject_id,
        through_generation=2,
        idempotency_key=UUID("00000000-0000-4000-8000-00000000051a"),
    )

    assert summary.network_started_reservation_ids == (reservation_id,)
    assert _provider_revocation_rows(engine, call_id, reservation_id) == (
        ("ambiguous", "finished", utc_storage(now)),
        ("settled", "finished", 100, utc_storage(now)),
    )
    replay = await restarted_port.reconcile_revoked_subject_once(
        event_id=UUID("00000000-0000-4000-8000-000000000519"),
        family="provider_routes",
        subject_id=subject_id,
        through_generation=2,
        idempotency_key=UUID("00000000-0000-4000-8000-00000000051a"),
    )
    assert replay.network_started_reservation_ids == ()
    assert _provider_revocation_rows(engine, call_id, reservation_id) == (
        ("ambiguous", "finished", utc_storage(now)),
        ("settled", "finished", 100, utc_storage(now)),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("reservation_state", "reservation_phase"),
    (("released", "finished"), ("settled", "finished")),
)
async def test_sql_provider_revocation_requires_proven_conservative_reservation_settlement(
    migrated_sqlcipher_engine,
    clock,
    reservation_state,
    reservation_phase,
) -> None:
    engine = migrated_sqlcipher_engine.engine
    uow_factory = build_task1_sqlcipher_uow_factory(engine, clock, _task1_test_keys())
    subject_id = UUID("00000000-0000-4000-8000-000000000531")
    household_id = UUID("00000000-0000-4000-8000-000000000532")
    consent_id = UUID("00000000-0000-4000-8000-000000000533")
    call_id = UUID("00000000-0000-4000-8000-000000000534")
    reservation_id = UUID("00000000-0000-4000-8000-000000000535")
    authorization_id = UUID("00000000-0000-4000-8000-000000000538")
    now = clock.now()
    with engine.begin() as connection:
        _insert_started_provider_call(
            connection,
            call_id=call_id,
            reservation_id=reservation_id,
            request_id=UUID("00000000-0000-4000-8000-000000000536"),
            attempt_id=UUID("00000000-0000-4000-8000-000000000537"),
            authorization_id=authorization_id,
            transport_phase="marked_sent",
            now=now,
        )
        _insert_route_authorization_setting(
            connection,
            authorization_id=authorization_id,
            household_id=household_id,
            subject_id=subject_id,
            consent_id=consent_id,
            now=now,
        )
        connection.exec_driver_sql(
            "UPDATE budget_reservations SET state=?,transport_phase=?,"
            "charged_micros_sgd=?,settled_at=? WHERE id=?",
            (
                reservation_state,
                reservation_phase,
                100 if reservation_state == "settled" else None,
                utc_storage(now) if reservation_state == "settled" else None,
                str(reservation_id),
            ),
        )

    port = SqlProviderCallsRevocationPort(cast(IdentityUnitOfWorkFactory, uow_factory), clock.now)
    if reservation_state == "released":
        with pytest.raises(RuntimeError, match="provider_budget_reservation_settlement_unproven"):
            await port.reconcile_revoked_subject_once(
                event_id=UUID("00000000-0000-4000-8000-000000000539"),
                family="provider_routes",
                subject_id=subject_id,
                through_generation=2,
                idempotency_key=UUID("00000000-0000-4000-8000-00000000053a"),
            )
        assert _provider_revocation_rows(engine, call_id, reservation_id) == (
            ("started", "marked_sent", None),
            ("released", "finished", None, None),
        )
        return

    summary = await port.reconcile_revoked_subject_once(
        event_id=UUID("00000000-0000-4000-8000-000000000539"),
        family="provider_routes",
        subject_id=subject_id,
        through_generation=2,
        idempotency_key=UUID("00000000-0000-4000-8000-00000000053a"),
    )

    assert summary.network_started_reservation_ids == (reservation_id,)
    assert _provider_revocation_rows(engine, call_id, reservation_id) == (
        ("ambiguous", "finished", utc_storage(now)),
        ("settled", "finished", 100, utc_storage(now)),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("corruption", "expected_error"),
    (
        ("missing_route", "provider_route_authority_metadata_corrupt"),
        ("non_text_route", "provider_route_authority_metadata_corrupt"),
        ("malformed_route", "provider_route_authority_metadata_corrupt"),
        ("unknown_transport_phase", "provider_call_transport_phase_unknown"),
    ),
)
async def test_sql_provider_revocation_fails_closed_on_hostile_started_call_metadata(
    migrated_sqlcipher_engine,
    clock,
    corruption,
    expected_error,
) -> None:
    engine = migrated_sqlcipher_engine.engine
    uow_factory = build_task1_sqlcipher_uow_factory(engine, clock, _task1_test_keys())
    subject_id = UUID("00000000-0000-4000-8000-000000000521")
    household_id = UUID("00000000-0000-4000-8000-000000000522")
    consent_id = UUID("00000000-0000-4000-8000-000000000523")
    call_id = UUID("00000000-0000-4000-8000-000000000524")
    reservation_id = UUID("00000000-0000-4000-8000-000000000525")
    authorization_id = UUID("00000000-0000-4000-8000-000000000528")
    now = clock.now()
    with engine.begin() as connection:
        _insert_started_provider_call(
            connection,
            call_id=call_id,
            reservation_id=reservation_id,
            request_id=UUID("00000000-0000-4000-8000-000000000526"),
            attempt_id=UUID("00000000-0000-4000-8000-000000000527"),
            authorization_id=authorization_id,
            transport_phase="marked_sent",
            now=now,
        )
        if corruption == "non_text_route":
            connection.exec_driver_sql("PRAGMA ignore_check_constraints=ON")
            connection.exec_driver_sql(
                "INSERT INTO runtime_settings(key,value_json,version,updated_at) VALUES(?,?,1,?)",
                (
                    f"route.authorization.{authorization_id}",
                    b"not-text",
                    utc_storage(now),
                ),
            )
            connection.exec_driver_sql("PRAGMA ignore_check_constraints=OFF")
        elif corruption == "malformed_route":
            _insert_route_authorization_setting(
                connection,
                authorization_id=authorization_id,
                household_id=household_id,
                subject_id=subject_id,
                consent_id=consent_id,
                now=now,
                value_json="{}",
            )
        elif corruption == "unknown_transport_phase":
            _insert_route_authorization_setting(
                connection,
                authorization_id=authorization_id,
                household_id=household_id,
                subject_id=subject_id,
                consent_id=consent_id,
                now=now,
            )
            connection.exec_driver_sql("PRAGMA ignore_check_constraints=ON")
            connection.exec_driver_sql(
                "UPDATE provider_calls SET transport_phase='transport_magic' WHERE id=?",
                (str(call_id),),
            )
            connection.exec_driver_sql("PRAGMA ignore_check_constraints=OFF")

    port = SqlProviderCallsRevocationPort(cast(IdentityUnitOfWorkFactory, uow_factory), clock.now)
    with pytest.raises(RuntimeError, match=expected_error):
        await port.reconcile_revoked_subject_once(
            event_id=UUID("00000000-0000-4000-8000-000000000529"),
            family="provider_routes",
            subject_id=subject_id,
            through_generation=2,
            idempotency_key=UUID("00000000-0000-4000-8000-00000000052a"),
        )

    assert _provider_revocation_rows(engine, call_id, reservation_id)[0][0] == "started"
    assert _provider_revocation_rows(engine, call_id, reservation_id)[1][0] in {
        "reserved",
        "sent",
    }


class InvalidDispositionHandler(_OnceHandler):
    family = "provider_routes"

    async def _apply(
        self,
        event_id: UUID,
        subject_id: UUID,
        through_generation: int,
        key: UUID,
    ) -> DownstreamEffectReceipt:
        return DownstreamEffectReceipt(
            uuid5(key, "invalid"),
            key,
            event_id,
            self.family,
            subject_id,
            through_generation,
            "corrupt_restored_disposition",
        )


@pytest.mark.asyncio
async def test_invalid_downstream_disposition_is_not_completed_or_retry_poisoned(
    task1_identity_runtime,
    clock,
) -> None:
    runtime = await task1_identity_runtime.start_without_initial_drain()
    event = await runtime.enqueue_event()
    handler = InvalidDispositionHandler(
        runtime.revocation_effects,
        runtime.clock.heartbeats,
    )

    with pytest.raises(RuntimeError, match="invalid_subject_revocation_disposition"):
        await handler.reconcile_started_once(
            event_id=event.id,
            subject_id=event.subject_id,
            through_generation=1,
            idempotency_key=uuid5(event.id, "provider_routes"),
            lease_owner=uuid5(event.id, "lease-owner"),
            now=clock.now(),
        )

    assert runtime.revocation_effects.dispositions(event.id) == {}


@pytest.mark.asyncio
async def test_transactional_revocation_handlers_mutate_real_authority_rows_and_rollback(
    migrated_sqlcipher_engine,
    clock,
) -> None:
    keys = _task1_test_keys()
    uow_factory = build_task1_sqlcipher_uow_factory(
        migrated_sqlcipher_engine.engine,
        clock,
        keys,
    )
    container = build_task1_identity_container(uow_factory, clock, keys)
    subject_id = UUID("00000000-0000-4000-8000-000000000111")
    household_id = UUID("00000000-0000-4000-8000-000000000112")
    consent_id = UUID("00000000-0000-4000-8000-000000000113")
    authorization_id = UUID("00000000-0000-4000-8000-000000000117")
    now = clock.now()
    expires = now + timedelta(days=90)
    route_key = f"route.authorization.{authorization_id}"
    route_json = canonical_bytes(
        _route_envelope(
            authorization_id=authorization_id,
            household_id=household_id,
            subject_id=subject_id,
            consent_id=consent_id,
            expires_at=now + timedelta(seconds=30),
        )
    ).decode("utf-8")

    with migrated_sqlcipher_engine.engine.begin() as connection:
        connection.exec_driver_sql(
            "INSERT INTO households(id,display_label_ciphertext,timezone,created_at) "
            "VALUES (?,?,?,?)",
            (str(household_id), b"label", "Asia/Singapore", utc_storage(now)),
        )
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
                b"profile-label-ciphertext-has-enough-bytes",
                None,
                b"[]",
                1,
                1,
                1,
                None,
                utc_storage(now),
                utc_storage(now),
                None,
            ),
        )
        connection.exec_driver_sql(
            "INSERT INTO consent_receipts "
            "(id,household_id,subject_id,actor_id,guardian_id,guardian_generation,purpose,"
            "granted,policy_version,disclosure_version,commitment_key_id,receipt_hmac,"
            "created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(consent_id),
                str(household_id),
                str(subject_id),
                str(subject_id),
                None,
                None,
                "face",
                1,
                "phase1-v1",
                "phase1-disclosure-v1",
                "test",
                b"h" * 32,
                utc_storage(now),
                None,
            ),
        )
        connection.exec_driver_sql(
            "INSERT INTO enrollment_sessions "
            "(id,subject_id,modality,state,auth_receipt_id,consent_receipt_id,"
            "reenrollment_days,created_at,expires_at,closed_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,NULL)",
            (
                str(UUID("00000000-0000-4000-8000-000000000114")),
                str(subject_id),
                "face",
                "capturing",
                str(UUID("00000000-0000-4000-8000-000000000115")),
                str(consent_id),
                180,
                utc_storage(now),
                utc_storage(expires),
            ),
        )
        connection.exec_driver_sql(
            "INSERT INTO biometric_templates "
            "(id,enrollment_session_id,subject_id,modality,model_version,ciphertext,nonce,"
            "wrapped_dek,root_key_id,consent_receipt_id,created_at,expires_at,revoked_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL,NULL)",
            (
                str(UUID("00000000-0000-4000-8000-000000000116")),
                str(UUID("00000000-0000-4000-8000-000000000114")),
                str(subject_id),
                "face",
                "face-v1",
                b"ciphertext",
                b"nonce",
                b"wrapped",
                "root-v1",
                str(consent_id),
                utc_storage(now),
            ),
        )
        connection.exec_driver_sql(
            "INSERT INTO runtime_settings(key,value_json,version,updated_at) VALUES(?,?,1,?)",
            (route_key, route_json, utc_storage(now)),
        )

    async with uow_factory() as uow:
        identity_uow = cast(IdentityUnitOfWork, uow)
        await container.transactional_subject_revocation_handlers["enrollments"].revoke_in_uow(
            identity_uow,
            household_id=household_id,
            subject_id=subject_id,
            through_generation=1,
            reason="test",
            now=now,
        )
        await container.transactional_subject_revocation_handlers[
            "biometric_templates"
        ].revoke_in_uow(
            identity_uow,
            household_id=household_id,
            subject_id=subject_id,
            through_generation=1,
            reason="test",
            now=now,
        )
        await container.transactional_subject_revocation_handlers["provider_routes"].revoke_in_uow(
            identity_uow,
            household_id=household_id,
            subject_id=subject_id,
            through_generation=1,
            reason="test",
            now=now,
        )

    with migrated_sqlcipher_engine.engine.connect() as connection:
        assert connection.exec_driver_sql(
            "SELECT state,closed_at FROM enrollment_sessions WHERE subject_id=?",
            (str(subject_id),),
        ).one() == ("capturing", None)
        assert connection.exec_driver_sql(
            "SELECT revoked_at,expires_at FROM biometric_templates WHERE subject_id=?",
            (str(subject_id),),
        ).one() == (None, None)
        assert (
            connection.exec_driver_sql(
                "SELECT value_json FROM runtime_settings WHERE key=?",
                (route_key,),
            ).scalar_one()
            == route_json
        )

    async with uow_factory() as uow:
        identity_uow = cast(IdentityUnitOfWork, uow)
        await container.transactional_subject_revocation_handlers["enrollments"].revoke_in_uow(
            identity_uow,
            household_id=household_id,
            subject_id=subject_id,
            through_generation=1,
            reason="test",
            now=now,
        )
        await container.transactional_subject_revocation_handlers[
            "biometric_templates"
        ].revoke_in_uow(
            identity_uow,
            household_id=household_id,
            subject_id=subject_id,
            through_generation=1,
            reason="test",
            now=now,
        )
        await container.transactional_subject_revocation_handlers["provider_routes"].revoke_in_uow(
            identity_uow,
            household_id=household_id,
            subject_id=subject_id,
            through_generation=1,
            reason="test",
            now=now,
        )
        await uow.commit()

    with migrated_sqlcipher_engine.engine.connect() as connection:
        assert connection.exec_driver_sql(
            "SELECT state,closed_at FROM enrollment_sessions WHERE subject_id=?",
            (str(subject_id),),
        ).one() == ("cancelled", utc_storage(now))
        assert connection.exec_driver_sql(
            "SELECT revoked_at,expires_at FROM biometric_templates WHERE subject_id=?",
            (str(subject_id),),
        ).one() == (utc_storage(now), utc_storage(now))
        assert (
            connection.exec_driver_sql(
                "SELECT count(*) FROM runtime_settings WHERE key=?",
                (route_key,),
            ).scalar_one()
            == 0
        )
