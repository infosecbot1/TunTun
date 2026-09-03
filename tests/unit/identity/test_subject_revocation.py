# mypy: disable-error-code="no-untyped-def"
from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4, uuid5

import pytest
from tuntun_core.domain.profile import ConsentPurpose, Profile, ProfileClass
from tuntun_core.services.identity.subject_revocation import (
    REQUIRED_SUBJECT_AUTHORITY_FAMILIES,
    BiometricTemplateSubjectAuthorityRevocationHandler,
    ConsentSubjectAuthorityRevocationHandler,
    EnrollmentSubjectAuthorityRevocationHandler,
    NotInstalledSubjectAuthorityHandler,
    ProviderRouteSubjectAuthorityRevocationHandler,
    SearchCapabilitySubjectAuthorityRevocationHandler,
    SessionSubjectAuthorityRevocationHandler,
    SqlProviderRouteAuthorityRevocation,
    SubjectAuthorityRevocationCascade,
    SubjectRevocationEvent,
)
from tuntun_core.services.identity.subject_revocation_handlers import (
    DeferredEffect,
    DownstreamEffectReceipt,
    EffectClaim,
    LeaseHeartbeatRunner,
    NotInstalledAuthorityRevocationHandler,
    SearchAuthorityRevocationHandler,
    _OnceHandler,
)
from tuntun_core.services.identity.subject_revocation_processor import (
    POST_COMMIT_FAMILIES,
    DeferredRevocationProcessing,
    SubjectRevocationProcessor,
)

NOW = datetime(2026, 8, 27, 8, 0, tzinfo=UTC)


def _profile(subject_id: UUID, *, authority_generation: int = 1) -> Profile:
    return Profile(
        id=subject_id,
        household_id=UUID("00000000-0000-4000-8000-000000000901"),
        guardian_id=None,
        guardian_generation=0,
        profile_class=ProfileClass.ADULT,
        encrypted_display_label=b"profile-label-ciphertext".ljust(28, b"."),
        encrypted_persona_traits=None,
        current_consent_receipt_ids=(),
        active=True,
        authority_generation=authority_generation,
        version=1,
        next_reenrollment_reminder_at=None,
        created_at=NOW,
        updated_at=NOW,
    )


class RecordingStage:
    def __init__(self) -> None:
        self.sync_calls: list[tuple[str, str]] = []
        self.async_calls: list[tuple[object, str, str]] = []

    def require_schema_and_facade_absent(self, family: str, owning_revision: str) -> None:
        self.sync_calls.append((family, owning_revision))

    async def require_schema_and_facade_absent_in_uow(
        self,
        uow: object,
        family: str,
        owning_revision: str,
    ) -> None:
        self.async_calls.append((uow, family, owning_revision))


class RecordingSessions:
    def __init__(self) -> None:
        self.calls: list[tuple[UUID, str, datetime]] = []

    async def invalidate_identity_subject(
        self,
        subject_id: UUID,
        reason: str,
        now: datetime,
    ) -> None:
        self.calls.append((subject_id, reason, now))


class RecordingConsentReceipts:
    def __init__(self) -> None:
        self.calls: list[tuple[UUID, int, str, datetime]] = []

    async def revoke_subject_authorities_in_uow(
        self,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: datetime,
    ) -> None:
        self.calls.append((subject_id, through_generation, reason, now))


class SqlResult:
    def __init__(
        self,
        *,
        rows: list[tuple[object, object]] | None = None,
        rowcount: int = 1,
        scalar: int = 0,
    ) -> None:
        self._rows = rows or []
        self.rowcount = rowcount
        self._scalar = scalar

    def fetchall(self) -> list[tuple[object, object]]:
        return self._rows

    def scalar_one(self) -> int:
        return self._scalar


class RecordingSqlTransaction:
    def __init__(
        self,
        *,
        route_rows: list[tuple[object, object]] | None = None,
        consumed_any: bool = False,
        consumed_exact: bool = False,
    ) -> None:
        self.route_rows = route_rows or []
        self.consumed_any = consumed_any
        self.consumed_exact = consumed_exact
        self.statements: list[tuple[str, tuple[object, ...]]] = []
        self.deleted_keys: list[object] = []

    def exec_driver_sql(
        self,
        statement: str,
        parameters: tuple[object, ...] = (),
    ) -> SqlResult:
        self.statements.append((statement, parameters))
        if "SELECT key,value_json FROM runtime_settings" in statement:
            return SqlResult(rows=self.route_rows)
        if "SELECT count(*) FROM idempotency_receipts" in statement:
            scalar = self.consumed_exact if "scope = ?" in statement else self.consumed_any
            return SqlResult(scalar=int(scalar))
        if statement.startswith("DELETE FROM runtime_settings"):
            self.deleted_keys.append(parameters[0])
            return SqlResult(rowcount=1)
        return SqlResult(rowcount=1)


class RecordingUow:
    def __init__(self, transaction: RecordingSqlTransaction | None = None) -> None:
        self.transaction = transaction or RecordingSqlTransaction()
        self.sessions = RecordingSessions()
        self.consent_receipts = RecordingConsentReceipts()
        self.signals: list[str] = []

    async def run_sync(self, operation):
        return operation(self.transaction)

    def signal_after_commit(self, name: str) -> None:
        self.signals.append(name)


class RecordingRoutes:
    def __init__(self) -> None:
        self.calls: list[tuple[object, UUID, str, datetime]] = []

    async def invalidate_subject_purpose_in_uow(
        self,
        uow: object,
        subject_id: UUID,
        purpose: str,
        now: datetime,
    ) -> tuple[UUID, ...]:
        self.calls.append((uow, subject_id, purpose, now))
        return ()


class RecordingSearchCapabilities:
    def __init__(self) -> None:
        self.calls: list[tuple[object, UUID, UUID, int, str, datetime]] = []

    async def revoke_subject_authorities_in_uow(
        self,
        uow: object,
        *,
        household_id: UUID,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: datetime,
    ) -> None:
        self.calls.append((uow, household_id, subject_id, through_generation, reason, now))


class RecordingCascadeHandler:
    def __init__(self, family: str) -> None:
        self.family = family
        self.calls: list[tuple[UUID, UUID, int, str, datetime]] = []

    async def revoke_in_uow(
        self,
        uow: object,
        *,
        household_id: UUID,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: datetime,
    ) -> None:
        del uow
        self.calls.append((household_id, subject_id, through_generation, reason, now))


class RecordingOutbox:
    def __init__(self) -> None:
        self.events: list[tuple[object, str, UUID, int, datetime]] = []

    async def enqueue_in_uow(
        self,
        uow: object,
        *,
        event_key: str,
        subject_id: UUID,
        new_authority_generation: int,
        occurred_at: datetime,
    ) -> None:
        self.events.append((uow, event_key, subject_id, new_authority_generation, occurred_at))


@pytest.mark.asyncio
async def test_not_installed_subject_authority_handler_requires_exact_absent_capability() -> None:
    stage = RecordingStage()
    uow = object()
    with pytest.raises(ValueError, match="closed not-installed authority family required"):
        NotInstalledSubjectAuthorityHandler(
            stage,
            family="sessions",
            owning_revision="0003_authentication",
        )

    handler = NotInstalledSubjectAuthorityHandler(
        stage,
        family="action_authorities",
        owning_revision="0003_authentication",
    )

    await handler.revoke_in_uow(
        uow,
        household_id=uuid4(),
        subject_id=uuid4(),
        through_generation=3,
        reason="profile_revoked",
        now=NOW,
    )

    assert stage.async_calls == [(uow, "action_authorities", "0003_authentication")]


@pytest.mark.asyncio
async def test_subject_revocation_transactional_handlers_delegate_exact_scope() -> None:
    uow = RecordingUow()
    subject_id = uuid4()
    household_id = uuid4()
    routes = RecordingRoutes()
    provider_handler = ProviderRouteSubjectAuthorityRevocationHandler(routes)

    await SessionSubjectAuthorityRevocationHandler().revoke_in_uow(
        uow,
        household_id=household_id,
        subject_id=subject_id,
        through_generation=4,
        reason="profile_revoked",
        now=NOW,
    )
    await ConsentSubjectAuthorityRevocationHandler().revoke_in_uow(
        uow,
        household_id=household_id,
        subject_id=subject_id,
        through_generation=4,
        reason="profile_revoked",
        now=NOW,
    )
    await EnrollmentSubjectAuthorityRevocationHandler().revoke_in_uow(
        uow,
        household_id=household_id,
        subject_id=subject_id,
        through_generation=4,
        reason="profile_revoked",
        now=NOW,
    )
    await BiometricTemplateSubjectAuthorityRevocationHandler().revoke_in_uow(
        uow,
        household_id=household_id,
        subject_id=subject_id,
        through_generation=4,
        reason="profile_revoked",
        now=NOW,
    )
    await provider_handler.revoke_in_uow(
        uow,
        household_id=household_id,
        subject_id=subject_id,
        through_generation=4,
        reason="profile_revoked",
        now=NOW,
    )

    assert uow.sessions.calls == [(subject_id, "profile_revoked", NOW)]
    assert uow.consent_receipts.calls == [(subject_id, 4, "profile_revoked", NOW)]
    assert [purpose for _, _, purpose, _ in routes.calls] == [
        ConsentPurpose.CLOUD_STT.value,
        ConsentPurpose.CLOUD_REASONING.value,
        ConsentPurpose.CLOUD_TTS.value,
    ]
    assert any(
        "UPDATE enrollment_sessions" in statement for statement, _ in uow.transaction.statements
    )
    assert any(
        "UPDATE biometric_templates" in statement for statement, _ in uow.transaction.statements
    )


@pytest.mark.asyncio
async def test_search_capability_revocation_honors_absent_and_present_feature_gates() -> None:
    uow = object()
    stage = RecordingStage()
    search_capabilities = RecordingSearchCapabilities()
    absent = SearchCapabilitySubjectAuthorityRevocationHandler(
        capability_stage=stage,
        feature_state="absent",
    )
    present = SearchCapabilitySubjectAuthorityRevocationHandler(
        search_capabilities=search_capabilities,
        feature_state="present",
    )
    with pytest.raises(RuntimeError, match="search_capability_absent_stage_required"):
        await SearchCapabilitySubjectAuthorityRevocationHandler().revoke_in_uow(
            uow,
            household_id=uuid4(),
            subject_id=uuid4(),
            through_generation=1,
            reason="profile_revoked",
            now=NOW,
        )
    with pytest.raises(RuntimeError, match="search_capability_revocation_repository_required"):
        SearchCapabilitySubjectAuthorityRevocationHandler(feature_state="present")

    await absent.revoke_in_uow(
        uow,
        household_id=uuid4(),
        subject_id=uuid4(),
        through_generation=1,
        reason="profile_revoked",
        now=NOW,
    )
    household_id = uuid4()
    subject_id = uuid4()
    await present.revoke_in_uow(
        uow,
        household_id=household_id,
        subject_id=subject_id,
        through_generation=5,
        reason="profile_revoked",
        now=NOW,
    )

    assert stage.async_calls[0][1:] == (
        "search_capabilities",
        "search_0001_experimental_search",
    )
    assert search_capabilities.calls == [(uow, household_id, subject_id, 5, "profile_revoked", NOW)]


@pytest.mark.asyncio
async def test_sql_provider_route_revocation_removes_unconsumed_restored_authorities() -> None:
    skipped_id = UUID("00000000-0000-4000-8000-000000000911")
    revoked_id = UUID("00000000-0000-4000-8000-000000000912")
    consumed_tx = RecordingSqlTransaction(
        route_rows=[(f"route.authorization.{skipped_id}", "{}")],
        consumed_any=True,
    )
    remove_tx = RecordingSqlTransaction(
        route_rows=[(f"route.authorization.{revoked_id}", "{}")],
        consumed_any=False,
    )
    with pytest.raises(TypeError, match="purpose must be an exact cloud route purpose"):
        await SqlProviderRouteAuthorityRevocation().invalidate_subject_purpose_in_uow(
            RecordingUow(),
            uuid4(),
            ConsentPurpose.FACE.value,
            NOW,
        )
    with pytest.raises(PermissionError, match="route_authorization_corrupt"):
        await SqlProviderRouteAuthorityRevocation().invalidate_subject_purpose_in_uow(
            RecordingUow(RecordingSqlTransaction(route_rows=[(b"bad-key", "{}")])),
            uuid4(),
            ConsentPurpose.CLOUD_REASONING.value,
            NOW,
        )

    skipped = await SqlProviderRouteAuthorityRevocation().invalidate_subject_purpose_in_uow(
        RecordingUow(consumed_tx),
        uuid4(),
        ConsentPurpose.CLOUD_REASONING.value,
        NOW,
    )
    revoked = await SqlProviderRouteAuthorityRevocation().invalidate_subject_purpose_in_uow(
        RecordingUow(remove_tx),
        uuid4(),
        ConsentPurpose.CLOUD_REASONING.value,
        NOW,
    )

    assert skipped == ()
    assert consumed_tx.deleted_keys == []
    assert revoked == (revoked_id,)
    assert remove_tx.deleted_keys == [f"route.authorization.{revoked_id}"]


@pytest.mark.asyncio
async def test_revocation_cascade_requires_complete_set_and_generation_advance() -> None:
    subject_id = uuid4()
    current = _profile(subject_id, authority_generation=2)
    revoked = current.model_copy(update={"active": False, "authority_generation": 3})
    handlers = {
        family: RecordingCascadeHandler(family) for family in REQUIRED_SUBJECT_AUTHORITY_FAMILIES
    }
    outbox = RecordingOutbox()
    uow = RecordingUow()
    with pytest.raises(RuntimeError, match="complete_subject_revocation_handlers_required"):
        SubjectAuthorityRevocationCascade(dict(tuple(handlers.items())[:-1]), outbox)
    with pytest.raises(RuntimeError, match="subject_authority_generation_not_advanced"):
        await SubjectAuthorityRevocationCascade(handlers, outbox).apply_in_uow(
            uow,
            current,
            revoked.model_copy(update={"authority_generation": 4}),
            object(),
            NOW,
        )

    await SubjectAuthorityRevocationCascade(handlers, outbox).apply_in_uow(
        uow,
        current,
        revoked,
        object(),
        NOW,
    )

    assert all(handler.calls for handler in handlers.values())
    assert outbox.events == [
        (
            uow,
            f"subject-revoked:{subject_id}:3",
            subject_id,
            3,
            NOW,
        )
    ]
    assert uow.signals == ["subject_revocation"]


class FakeEffects:
    def __init__(self, claim: EffectClaim | None = None) -> None:
        self.claim_result = claim
        self.completed_calls: list[DownstreamEffectReceipt] = []
        self.abandoned: list[str] = []

    async def claim(
        self,
        idempotency_key: UUID,
        *,
        event_id: UUID,
        family: str,
        subject_id: UUID,
        through_generation: int,
        lease_owner: UUID,
        now: datetime,
    ) -> EffectClaim:
        del event_id, family, subject_id, through_generation, lease_owner, now
        assert self.claim_result is not None
        assert self.claim_result.idempotency_key == idempotency_key
        return self.claim_result

    async def renew(
        self,
        idempotency_key: UUID,
        lease_owner: UUID,
        fencing_token: int,
        now: datetime,
    ) -> bool:
        del idempotency_key, lease_owner, fencing_token, now
        return True

    async def complete(
        self,
        idempotency_key: UUID,
        lease_owner: UUID,
        fencing_token: int,
        downstream: DownstreamEffectReceipt,
        now: datetime,
    ) -> None:
        del idempotency_key, lease_owner, fencing_token, now
        self.completed_calls.append(downstream)

    async def abandon(
        self,
        idempotency_key: UUID,
        lease_owner: UUID,
        fencing_token: int,
        reason_code: str,
        now: datetime,
    ) -> None:
        del idempotency_key, lease_owner, fencing_token, now
        self.abandoned.append(reason_code)

    async def recover_stale(self, now: datetime) -> int:
        del now
        return 7


class ImmediateClock:
    def now(self) -> datetime:
        return NOW

    async def sleep_until(self, deadline: datetime) -> None:
        del deadline


class ReceiptHandler(_OnceHandler):
    family = "provider_routes"

    def __init__(
        self,
        effects: FakeEffects,
        receipt: DownstreamEffectReceipt | None = None,
        error: BaseException | None = None,
    ) -> None:
        super().__init__(effects, LeaseHeartbeatRunner(ImmediateClock()))
        self.receipt = receipt
        self.error = error

    async def _apply(
        self,
        event_id: UUID,
        subject_id: UUID,
        through_generation: int,
        key: UUID,
    ) -> DownstreamEffectReceipt:
        if self.error is not None:
            raise self.error
        assert self.receipt is not None
        return self.receipt


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("claim", "expected_error"),
    [
        (
            EffectClaim("completed", uuid4(), UUID(int=0), None, None, None),
            "revocation_effect_completed_receipt_missing",
        ),
        (
            EffectClaim("busy", uuid4(), UUID(int=0), None, None),
            "revocation_effect_live_lease_missing",
        ),
        (
            EffectClaim("acquired", uuid4(), UUID(int=0), None, NOW + timedelta(seconds=30)),
            "revocation_effect_fence_missing",
        ),
    ],
)
async def test_once_handler_fails_closed_on_corrupt_effect_claims(
    claim,
    expected_error,
) -> None:
    event_id = uuid4()
    key = uuid5(event_id, "provider_routes")
    effects = FakeEffects(replace(claim, idempotency_key=key))
    handler = ReceiptHandler(effects)

    with pytest.raises(RuntimeError, match=expected_error):
        await handler.reconcile_started_once(
            event_id=event_id,
            subject_id=uuid4(),
            through_generation=1,
            idempotency_key=key,
            lease_owner=uuid4(),
            now=NOW,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("receipt_update", "expected_error"),
    [
        ({"subject_id": uuid4()}, "revocation_downstream_receipt_scope_mismatch"),
        ({"disposition": "surprise"}, "invalid_subject_revocation_disposition"),
    ],
)
async def test_once_handler_abandons_claim_when_downstream_receipt_is_out_of_scope_or_invalid(
    receipt_update,
    expected_error,
) -> None:
    event_id = uuid4()
    subject_id = uuid4()
    key = uuid5(event_id, "provider_routes")
    receipt = DownstreamEffectReceipt(
        uuid4(),
        key,
        event_id,
        "provider_routes",
        subject_id,
        1,
        "completed_once",
    )
    replacement = replace(receipt, **receipt_update)
    claim = EffectClaim("acquired", uuid4(), key, 9, NOW + timedelta(seconds=30))
    effects = FakeEffects(claim)
    handler = ReceiptHandler(effects, replacement)

    with pytest.raises(RuntimeError, match=expected_error):
        await handler.reconcile_started_once(
            event_id=event_id,
            subject_id=subject_id,
            through_generation=1,
            idempotency_key=key,
            lease_owner=uuid4(),
            now=NOW,
        )

    assert effects.abandoned == ["handler_error:RuntimeError"]
    assert effects.completed_calls == []


@pytest.mark.asyncio
async def test_not_installed_post_commit_handler_checks_absent_schema_before_receipt() -> None:
    stage = RecordingStage()
    event_id = uuid4()
    subject_id = uuid4()
    key = uuid5(event_id, "action_authorities")
    effects = FakeEffects(EffectClaim("acquired", uuid4(), key, 2, NOW + timedelta(seconds=30)))
    with pytest.raises(ValueError, match="closed not-installed revocation family required"):
        NotInstalledAuthorityRevocationHandler(
            effects,
            LeaseHeartbeatRunner(ImmediateClock()),
            stage,
            family="action_authorities",
            owning_revision="0004_memory",
        )
    handler = NotInstalledAuthorityRevocationHandler(
        effects,
        LeaseHeartbeatRunner(ImmediateClock()),
        stage,
        family="action_authorities",
        owning_revision="0003_authentication",
    )

    disposition = await handler.reconcile_started_once(
        event_id=event_id,
        subject_id=subject_id,
        through_generation=1,
        idempotency_key=key,
        lease_owner=uuid4(),
        now=NOW,
    )

    assert disposition == "not_installed_no_authority"
    assert stage.sync_calls == [("action_authorities", "0003_authentication")]
    assert effects.completed_calls[0].subject_id == subject_id


def test_absent_search_post_commit_handler_reports_stage_match_and_noop_receipt() -> None:
    stage = RecordingStage()
    handler = SearchAuthorityRevocationHandler(
        FakeEffects(),
        LeaseHeartbeatRunner(ImmediateClock()),
        lambda: None,
        feature_state="absent",
        capability_stage=stage,
    )

    handler.require_stage_match()

    assert stage.sync_calls == [("search_capabilities", "search_0001_experimental_search")]


class ProcessorHandler:
    def __init__(
        self,
        family: str,
        effects: FakeEffects,
        result: object = "completed_once",
    ) -> None:
        self.family = family
        self.effect_repository = effects
        self.result = result

    def require_stage_match(self) -> None:
        return None

    async def reconcile_started_once(
        self,
        *,
        event_id: UUID,
        subject_id: UUID,
        through_generation: int,
        idempotency_key: UUID,
        lease_owner: UUID,
        now: datetime,
    ) -> object:
        del event_id, subject_id, through_generation, idempotency_key, lease_owner, now
        return self.result


def _processor_handlers(
    effects: FakeEffects,
    *,
    first_result: object = "completed_once",
) -> dict[str, ProcessorHandler]:
    return {
        family: ProcessorHandler(
            family,
            effects,
            first_result if index == 0 else "completed_once",
        )
        for index, family in enumerate(POST_COMMIT_FAMILIES)
    }


@pytest.mark.asyncio
async def test_subject_revocation_processor_requires_complete_shared_effect_repository() -> None:
    shared_effects = FakeEffects()
    handlers = _processor_handlers(shared_effects)
    with pytest.raises(RuntimeError, match="complete_post_commit_revocation_handlers_required"):
        SubjectRevocationProcessor(dict(tuple(handlers.items())[:-1]))
    split_handlers = _processor_handlers(shared_effects)
    split_handlers["memory_authorities"] = ProcessorHandler(
        "memory_authorities",
        FakeEffects(),
    )
    with pytest.raises(RuntimeError, match="one_revocation_effect_repository_required"):
        SubjectRevocationProcessor(split_handlers)

    processor = SubjectRevocationProcessor(handlers)

    assert processor.available is True
    assert await processor.recover_stale_effect_claims(NOW) == 7


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("first_result", "expected"),
    [
        (DeferredEffect(NOW + timedelta(seconds=30)), DeferredRevocationProcessing),
        ("surprise", RuntimeError),
    ],
)
async def test_subject_revocation_processor_rejects_bad_idempotency_and_defers_or_fails(
    first_result,
    expected,
) -> None:
    effects = FakeEffects()
    processor = SubjectRevocationProcessor(_processor_handlers(effects, first_result=first_result))
    event = SubjectRevocationEvent(
        id=uuid4(),
        event_key="subject-revoked:test:2",
        subject_id=uuid4(),
        new_authority_generation=2,
        state="processing",
        occurred_at=NOW,
    )
    with pytest.raises(PermissionError, match="subject_revocation_idempotency_mismatch"):
        await processor.reconcile_once(event, idempotency_key=uuid4(), lease_owner=uuid4(), now=NOW)

    if expected is RuntimeError:
        with pytest.raises(RuntimeError, match="invalid_subject_revocation_disposition"):
            await processor.reconcile_once(
                event,
                idempotency_key=event.id,
                lease_owner=uuid4(),
                now=NOW,
            )
        return

    result = await processor.reconcile_once(
        event,
        idempotency_key=event.id,
        lease_owner=uuid4(),
        now=NOW,
    )

    assert isinstance(result, expected)
