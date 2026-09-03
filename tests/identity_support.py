from __future__ import annotations

import asyncio
import base64
import copy
import hmac
import importlib
from collections import defaultdict
from collections.abc import Awaitable, Callable, Iterator, Mapping
from contextlib import AbstractAsyncContextManager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Literal, Protocol, TypedDict, cast
from uuid import UUID, uuid4, uuid5

import pytest
import pytest_asyncio
import rfc8785
import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from rfc8785._impl import _Value as Rfc8785Value
from tuntun_contracts.actions import ActionBinding
from tuntun_contracts.audit import AuditDraft
from tuntun_contracts.base import Commitment
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.identity import PersonaTraits
from tuntun_contracts.policy import AssuranceLevel, AuthContext, CurrentOwnerAuthority
from tuntun_contracts.provider import RouteAuthorizationRequest, Sensitivity
from tuntun_core.adapters.sqlcipher.async_unit_of_work import AsyncUnitOfWorkFactory
from tuntun_core.adapters.sqlcipher.foundation_0001 import FOUNDATION_0001_METADATA
from tuntun_core.adapters.sqlcipher.profile_crypto import ProfileCrypto
from tuntun_core.adapters.sqlcipher.subject_revocation_effect_repository import (
    DownstreamEffectReceipt,
    EffectClaim,
    SubjectRevocationEffectRepository,
)
from tuntun_core.adapters.sqlcipher.subject_revocation_outbox_repository import (
    OutboxClaim,
    SubjectRevocationOutboxRepository,
)
from tuntun_core.bootstrap.container import (
    Task1CapabilityStage,
    Task1IdentityContainer,
    build_task1_identity_container,
    build_task1_sqlcipher_uow_factory,
)
from tuntun_core.domain.profile import (
    BiometricTemplate,
    CancelEnrollment,
    ConsentPurpose,
    ConsentReceipt,
    CreateProfile,
    EnrollmentSession,
    GrantConsent,
    GuestConsentPurpose,
    GuestDisclosureChallenge,
    GuestSessionConsentReceipt,
    Modality,
    Profile,
    ProfileClass,
    RequestEnrollment,
    RevokeConsent,
    RevokeProfile,
    UpdatePersonaTraits,
)
from tuntun_core.services.actions.parameter_binding import (
    ActionBindingVerifier,
    ActionParameterBindingVerifier,
    consent_parameters,
    enrollment_cancel_parameters,
    enrollment_request_parameters,
    profile_create_parameters,
    profile_persona_parameters,
    profile_revoke_parameters,
)
from tuntun_core.services.identity.consent import (
    AuthenticationPort,
    ConsentDenied,
    ConsentRevocationCascade,
    ConsentService,
    GuestSessionConsentService,
    IdentityMutationCoordinator,
)
from tuntun_core.services.identity.consent import (
    MutationScopePort as ConsentMutationScopePort,
)
from tuntun_core.services.identity.enrollment import (
    EnrollmentMutationCoordinator,
    EnrollmentService,
)
from tuntun_core.services.identity.profiles import (
    MutationScopePort as ProfileMutationScopePort,
)
from tuntun_core.services.identity.profiles import ProfileService
from tuntun_core.services.identity.revocation_handlers import (
    BiometricConsentRevocationHandler as EnrollmentBiometricConsentRevocationHandler,
)
from tuntun_core.services.identity.runtime import (
    Task1IdentityKeyBundle,
    Task1IdentityKeyMaterial,
)
from tuntun_core.services.identity.subject_revocation import (
    REQUIRED_SUBJECT_AUTHORITY_FAMILIES,
    SubjectAuthorityRevocationCascade,
    SubjectRevocationEvent,
)
from tuntun_core.services.identity.subject_revocation_handlers import (
    EffectRepositoryPort,
    LeaseHeartbeatRunner,
    NotInstalledAuthorityRevocationHandler,
    ProviderRouteRevocationHandler,
    SearchAuthorityRevocationHandler,
    _OnceHandler,
)
from tuntun_core.services.identity.subject_revocation_processor import (
    POST_COMMIT_FAMILIES,
    DeferredRevocationProcessing,
    SubjectRevocationProcessingReceipt,
    SubjectRevocationProcessor,
)
from tuntun_core.services.providers.consent_guard import ConsentHmacVerifier
from tuntun_core.services.providers.route_verifier import authorization_from_request
from tuntun_core.services.storage_time import utc_storage
from tuntun_core.services.transactions.identity_uow import (
    IdentityUnitOfWork,
    IdentityUnitOfWorkFactory,
)
from tuntun_core.services.transactions.protocols import AsyncUnitOfWorkProtocol, UnitOfWorkProtocol
from tuntun_core.workers.subject_revocation_worker import (
    SubjectRevocationWorker,
)

COMMITMENT_ROOT = b"c" * 32
PROFILE_ROOT = b"p" * 32
RECEIPT_ROOT = b"r" * 32
BASE_TIME = datetime(2026, 8, 27, 8, 0, tzinfo=UTC)
HOUSEHOLD_NAMESPACE = UUID("11111111-1111-4111-8111-111111111111")


def _task1_test_root(seed: int) -> bytes:
    return bytes(((seed + index) % 251) + 1 for index in range(32))


def task1_test_identity_keys() -> Task1IdentityKeyBundle:
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


class StaticTask1IdentityKeyProvider:
    def __init__(self, keys: Task1IdentityKeyBundle | None = None) -> None:
        self._keys = task1_test_identity_keys() if keys is None else keys

    def current_keys(self) -> Task1IdentityKeyBundle:
        return self._keys


def _uuid(name: str) -> UUID:
    return uuid5(HOUSEHOLD_NAMESPACE, name)


def _field_json(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return utc_storage(value)
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, tuple):
        return [_field_json(item) for item in value]
    if isinstance(value, list):
        return [_field_json(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _field_json(item) for key, item in value.items()}
    return value


def _receipt_body(purpose: str, fields: tuple[object, ...]) -> bytes:
    body = {"fields": [_field_json(item) for item in fields], "purpose": purpose}
    return rfc8785.dumps(cast(Rfc8785Value, body))


class ReceiptSigner:
    key_id = "test-receipt-key"

    def sign_fields(self, purpose: str, fields: tuple[object, ...]) -> tuple[str, bytes]:
        body = _receipt_body(purpose, fields)
        digest = hmac.new(RECEIPT_ROOT, purpose.encode("ascii") + b"\0" + body, "sha256").digest()
        return self.key_id, digest

    def verify_fields(
        self,
        purpose: str,
        key_id: str,
        fields: tuple[object, ...],
        expected_hmac: bytes,
    ) -> bool:
        if key_id != self.key_id:
            return False
        _key, digest = self.sign_fields(purpose, fields)
        return hmac.compare_digest(digest, expected_hmac)


class FakeClock:
    def __init__(self) -> None:
        self._now = BASE_TIME
        self._waiters: list[tuple[datetime, asyncio.Future[None]]] = []
        self._waiter_change: asyncio.Event | None = None
        self.heartbeats = LeaseHeartbeatRunner(self)

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return self._now.timestamp()

    def advance(self, *, seconds: int = 0, days: int = 0) -> None:
        self._now = self._now + timedelta(days=days, seconds=seconds)
        self._flush_waiters()

    async def advance_and_flush(self, *, seconds: int) -> None:
        for _ in range(64):
            await asyncio.sleep(0)
            self._flush_waiters()
        self.advance(seconds=seconds)
        for _ in range(64):
            await asyncio.sleep(0)
            self._flush_waiters()

    async def sleep_until(self, deadline: datetime) -> None:
        if deadline <= self._now:
            return
        loop = asyncio.get_running_loop()
        future: asyncio.Future[None] = loop.create_future()
        self._waiters.append((deadline, future))
        self._notify_waiter_change()
        self._flush_waiters()
        await future

    async def wait_for_sleep_deadline_at_or_after(
        self,
        deadline_floor: datetime,
        *,
        count: int = 1,
    ) -> datetime:
        while True:
            pending_deadlines = tuple(
                deadline
                for deadline, future in self._waiters
                if not future.done() and deadline >= deadline_floor
            )
            if len(pending_deadlines) >= count:
                return min(pending_deadlines)
            event = asyncio.Event()
            self._waiter_change = event
            await event.wait()

    def _notify_waiter_change(self) -> None:
        event = self._waiter_change
        if event is not None and not event.is_set():
            event.set()
        self._waiter_change = None

    def _flush_waiters(self) -> None:
        pending: list[tuple[datetime, asyncio.Future[None]]] = []
        changed = False
        for deadline, future in self._waiters:
            if future.done():
                changed = True
                continue
            if deadline <= self._now:
                future.set_result(None)
                changed = True
            else:
                pending.append((deadline, future))
        self._waiters = pending
        if changed:
            self._notify_waiter_change()


@dataclass(frozen=True, slots=True)
class GrantHandle:
    id: UUID
    binding: ActionBinding


@dataclass(frozen=True, slots=True)
class FakeSession:
    id: UUID
    household_id: UUID
    expires_at: datetime
    active: bool = True


@dataclass(frozen=True, slots=True)
class DisclosureReceipt:
    id: UUID
    household_id: UUID
    session_id: UUID
    purpose: GuestConsentPurpose
    disclosure_version: str


@dataclass(frozen=True, slots=True)
class RepositorySpies:
    store: InMemoryIdentityStore

    @property
    def profile_reads(self) -> int:
        return self.store.profile_repo.read_count

    @property
    def consent_reads(self) -> int:
        return self.store.consent_repo.read_count


@dataclass(frozen=True, slots=True)
class GuestRepositorySpies:
    store: InMemoryIdentityStore

    @property
    def session_reads(self) -> int:
        return self.store.session_reads

    @property
    def receipt_reads(self) -> int:
        return self.store.receipt_reads


@dataclass(frozen=True, slots=True)
class AuthoritySnapshot:
    profile: Profile
    authority_generation: int
    active_authorities: frozenset[str]
    invalidated_families: frozenset[str]


class RevocationFaults:
    def __init__(self) -> None:
        self._fault_after: str | None = None

    def raise_after(self, family: str) -> None:
        self._fault_after = family

    def maybe(self, family: str) -> None:
        if self._fault_after == family:
            raise RuntimeError("injected_revocation_fault")


class IdentityStoreSnapshot(TypedDict):
    profiles: dict[UUID, Profile]
    persisted_subject_ids: set[UUID]
    consents: list[ConsentReceipt]
    enrollments: dict[UUID, EnrollmentSession]
    biometric_templates: dict[UUID, BiometricTemplate]
    sessions: dict[UUID, FakeSession]
    disclosure_receipts: dict[UUID, DisclosureReceipt]
    guest_challenges: dict[UUID, GuestDisclosureChallenge]
    guest_receipts: list[GuestSessionConsentReceipt]
    invalidated: dict[UUID, set[str]]
    outbox_events: list[SubjectRevocationEvent]
    raw_blobs: list[bytes]
    signals: list[str]
    audit_count_by_event: dict[UUID, int]
    current_owner_subject_id: UUID | None
    current_owner_generation: int


class InMemoryIdentityStore:
    def __init__(self) -> None:
        self.clock = FakeClock()
        self.signer = ReceiptSigner()
        self.profile_crypto = ProfileCrypto(PROFILE_ROOT)
        self.household_id = _uuid("household")
        self.device_id = _uuid("device")
        self.profiles: dict[UUID, Profile] = {}
        self.persisted_subject_ids: set[UUID] = set()
        self.consents: list[ConsentReceipt] = []
        self.enrollments: dict[UUID, EnrollmentSession] = {}
        self.biometric_templates: dict[UUID, BiometricTemplate] = {}
        self.sessions: dict[UUID, FakeSession] = {}
        self.disclosure_receipts: dict[UUID, DisclosureReceipt] = {}
        self.guest_challenges: dict[UUID, GuestDisclosureChallenge] = {}
        self.guest_receipts: list[GuestSessionConsentReceipt] = []
        self.raw_blobs: list[bytes] = []
        self.invalidated: dict[UUID, set[str]] = defaultdict(set)
        self.outbox_events: list[SubjectRevocationEvent] = []
        self.signals: list[str] = []
        self.revocation_worker: SubjectRevocationWorker | None = None
        self.faults = RevocationFaults()
        self.audit_count_by_event: dict[UUID, int] = defaultdict(int)
        self.session_reads = 0
        self.receipt_reads = 0
        self.current_owner_subject_id: UUID | None = None
        self.current_owner_generation = 1
        self.auth = FakeAuthentication(self)
        self.profile_repo = FakeProfileRepository(self)
        self.consent_repo = FakeConsentRepository(self)
        self.enrollment_repo = FakeEnrollmentRepository(self)
        self.biometric_template_repo = FakeBiometricTemplateRepository(self)
        self.guest_challenge_repo = FakeGuestDisclosureChallengeRepository(self)
        self.guest_consent_repo = FakeGuestSessionConsentRepository(self)
        self.session_repo = FakeSessionRepository(self)
        self.event_receipt_repo = FakeEventReceiptRepository(self)
        self.outbox_repo = FakeTransactionalOutboxRepository(self)
        self.effects_repo = FakeTransactionalEffectsRepository()
        self.uow_factory = FakeUowFactory(self)
        self.scope = FakeMutationScope(self)
        self.audit = FakeAuditLedger(self)
        self.audit_mapper = FakeConsentRevocationAuditMapper()
        self.parameter_verifier = ActionParameterBindingVerifier(
            COMMITMENT_ROOT,
            key_id="test-action-key",
        )
        self.binding_verifier = ActionBindingVerifier()
        biometric_revocation = EnrollmentBiometricConsentRevocationHandler(self.audit)
        self.consent_revocations = ConsentRevocationCascade(
            {
                ConsentPurpose.FACE: biometric_revocation,
                ConsentPurpose.VOICE: biometric_revocation,
            },
            self.audit_mapper,
            self.audit,
        )
        identity_uow_factory = cast(IdentityUnitOfWorkFactory, self.uow_factory)
        consent_scope = cast(ConsentMutationScopePort, self.scope)
        profile_scope = cast(ProfileMutationScopePort, self.scope)
        self.consent_service = ConsentService(
            identity_uow_factory,
            consent_scope,
            self.audit,
            self.signer,
            self.parameter_verifier,
            self.binding_verifier,
            self.consent_revocations,
            self.clock,
        )
        self.enrollment_service = EnrollmentService(
            identity_uow_factory,
            consent_scope,
            self.consent_service,
            self.parameter_verifier,
            self.binding_verifier,
            self.audit,
            self.clock,
        )
        self.subject_revocation_cascade = SubjectAuthorityRevocationCascade(
            {
                family: FaultingAuthorityHandler(self, family)
                for family in REQUIRED_SUBJECT_AUTHORITY_FAMILIES
            },
            self.outbox_repo,
        )
        self.profile_service = ProfileService(
            identity_uow_factory,
            profile_scope,
            self.audit,
            self.consent_service,
            self.subject_revocation_cascade,
            self.profile_crypto,
            self.parameter_verifier,
            self.binding_verifier,
            self.clock,
        )
        self.identity_mutations = IdentityMutationCoordinator(
            consent_scope,
            cast(AuthenticationPort, self.auth),
            self.profile_service,
            self.consent_service,
        )
        self.enrollment_mutations = EnrollmentMutationCoordinator(
            consent_scope,
            cast(AuthenticationPort, self.auth),
            self.enrollment_service,
        )
        self.route_authorizer = InMemoryRouteAuthorizer(self)
        self.profile_factory = ProfileFactory(self)
        self.owner = self.profile_factory(ProfileClass.OWNER, name="owner")
        self.current_owner_subject_id = self.owner.id
        self.adult_a = self.profile_factory(ProfileClass.ADULT, name="adult-a")
        self.adult_b = self.profile_factory(ProfileClass.ADULT, name="adult-b")
        self.guardian = self.profile_factory(ProfileClass.ADULT, name="guardian")
        self.child = self.profile_factory(
            ProfileClass.K2,
            name="child",
            guardian_id=self.guardian.id,
        )
        self.install_personalization(self.adult_a, self.adult_a.id)
        self.install_personalization(self.child, self.guardian.id)

    def snapshot(self) -> IdentityStoreSnapshot:
        return {
            "profiles": copy.deepcopy(self.profiles),
            "persisted_subject_ids": copy.deepcopy(self.persisted_subject_ids),
            "consents": copy.deepcopy(self.consents),
            "enrollments": copy.deepcopy(self.enrollments),
            "biometric_templates": copy.deepcopy(self.biometric_templates),
            "sessions": copy.deepcopy(self.sessions),
            "disclosure_receipts": copy.deepcopy(self.disclosure_receipts),
            "guest_challenges": copy.deepcopy(self.guest_challenges),
            "guest_receipts": copy.deepcopy(self.guest_receipts),
            "invalidated": copy.deepcopy(self.invalidated),
            "outbox_events": copy.deepcopy(self.outbox_events),
            "raw_blobs": copy.deepcopy(self.raw_blobs),
            "signals": copy.deepcopy(self.signals),
            "audit_count_by_event": copy.deepcopy(self.audit_count_by_event),
            "current_owner_subject_id": self.current_owner_subject_id,
            "current_owner_generation": self.current_owner_generation,
        }

    def restore(self, snapshot: IdentityStoreSnapshot) -> None:
        self.profiles = copy.deepcopy(snapshot["profiles"])
        self.persisted_subject_ids = copy.deepcopy(snapshot["persisted_subject_ids"])
        self.consents = copy.deepcopy(snapshot["consents"])
        self.enrollments = copy.deepcopy(snapshot["enrollments"])
        self.biometric_templates = copy.deepcopy(snapshot["biometric_templates"])
        self.sessions = copy.deepcopy(snapshot["sessions"])
        self.disclosure_receipts = copy.deepcopy(snapshot["disclosure_receipts"])
        self.guest_challenges = copy.deepcopy(snapshot["guest_challenges"])
        self.guest_receipts = copy.deepcopy(snapshot["guest_receipts"])
        self.invalidated = copy.deepcopy(snapshot["invalidated"])
        self.outbox_events = copy.deepcopy(snapshot["outbox_events"])
        self.raw_blobs = copy.deepcopy(snapshot["raw_blobs"])
        self.signals = copy.deepcopy(snapshot["signals"])
        self.audit_count_by_event = copy.deepcopy(snapshot["audit_count_by_event"])
        self.current_owner_subject_id = snapshot["current_owner_subject_id"]
        self.current_owner_generation = snapshot["current_owner_generation"]

    def install_consent(
        self,
        profile: Profile,
        actor_id: UUID,
        purpose: ConsentPurpose,
        *,
        expires_at: datetime | None = None,
    ) -> ConsentReceipt:
        guardian_id = (
            actor_id if profile.profile_class in {ProfileClass.K2, ProfileClass.N1} else None
        )
        guardian_generation = profile.guardian_generation if guardian_id is not None else None
        now = self.clock.now()
        fields = (
            profile.household_id,
            profile.id,
            purpose,
            actor_id,
            guardian_id,
            guardian_generation,
            True,
            "phase1-v1",
            "phase1-disclosure-v1",
            now,
            expires_at,
        )
        key_id, receipt_hmac = self.signer.sign_fields("subject_consent_receipt", fields)
        receipt = ConsentReceipt(
            id=uuid4(),
            household_id=profile.household_id,
            subject_id=profile.id,
            actor_id=actor_id,
            guardian_id=guardian_id,
            guardian_generation=guardian_generation,
            purpose=purpose,
            granted=True,
            policy_version="phase1-v1",
            disclosure_version="phase1-disclosure-v1",
            commitment_key_id=key_id,
            receipt_hmac=receipt_hmac,
            created_at=now,
            expires_at=expires_at,
        )
        self.consents.append(receipt)
        self._install_current_consent_pointer(profile, receipt)
        return receipt

    def install_personalization(self, profile: Profile, actor_id: UUID) -> ConsentReceipt:
        return self.install_consent(profile, actor_id, ConsentPurpose.PERSONALIZATION)

    def _install_current_consent_pointer(
        self,
        profile: Profile,
        receipt: ConsentReceipt,
    ) -> None:
        current_ids = tuple(
            item
            for item in profile.current_consent_receipt_ids
            if item != receipt.id
            and not self._receipt_id_matches_subject_purpose(
                item, receipt.subject_id, receipt.purpose
            )
        )
        if len(current_ids) >= 8:
            raise RuntimeError("current_consent_pointer_full")
        self.profiles[profile.id] = profile.model_copy(
            update={"current_consent_receipt_ids": current_ids + (receipt.id,)}
        )

    def _receipt_id_matches_subject_purpose(
        self,
        receipt_id: UUID,
        subject_id: UUID,
        purpose: ConsentPurpose,
    ) -> bool:
        return any(
            item.id == receipt_id and item.subject_id == subject_id and item.purpose is purpose
            for item in self.consents
        )

    def auth_context(self, actor_id: UUID | None, binding: ActionBinding) -> AuthContext:
        return AuthContext(
            grant_id=uuid4(),
            subject_id=actor_id,
            binding=binding,
            assurance=AssuranceLevel.PASSKEY_VERIFIED,
            assurance_source="passkey",
            consumed_at=self.clock.now(),
        )

    def grant_for(self, actor_id: UUID | None, binding: ActionBinding) -> GrantHandle:
        grant = GrantHandle(uuid4(), binding)
        self.auth.grants[grant.id] = AuthContext(
            grant_id=grant.id,
            subject_id=actor_id,
            binding=binding,
            assurance=AssuranceLevel.PASSKEY_VERIFIED,
            assurance_source="passkey",
            consumed_at=self.clock.now(),
        )
        return grant


class FakeUow:
    def __init__(
        self, store: InMemoryIdentityStore, scope: FakeMutationScope | None = None
    ) -> None:
        self.store = store
        self.scope = scope
        self.profiles = store.profile_repo
        self.consent_receipts = store.consent_repo
        self.enrollments = store.enrollment_repo
        self.biometric_templates = store.biometric_template_repo
        self.guest_disclosure_challenges = store.guest_challenge_repo
        self.guest_session_consents = store.guest_consent_repo
        self.sessions = store.session_repo
        self.event_receipts = store.event_receipt_repo
        self.subject_revocation_outbox = store.outbox_repo
        self.subject_revocation_effects = store.effects_repo
        self.provider_calls = FakeProviderCalls(FakeDownstreamEffects(store.clock), {})
        self.budget_reservations = FakeBudgetReservations()
        self.experimental_search_attempts = FakeSearchAttempts(FakeDownstreamEffects(store.clock))
        self._snapshot: IdentityStoreSnapshot | None = None
        self._committed = False
        self._signals: set[str] = set()

    async def __aenter__(self) -> FakeUow:
        self._snapshot = self.store.snapshot()
        if self.scope is not None:
            self.scope.active = self
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        if (exc_type is not None or not self._committed) and self._snapshot is not None:
            self.store.restore(self._snapshot)
        if self.scope is not None and self.scope.active is self:
            self.scope.active = None
        return False

    async def run_sync[ResultT](
        self,
        operation: Callable[[UnitOfWorkProtocol], ResultT],
    ) -> ResultT:
        return operation(cast(UnitOfWorkProtocol, FakeSyncTransaction()))

    def signal_after_commit(self, name: str) -> None:
        self._signals.add(name)

    async def commit(self) -> None:
        self._committed = True
        self.store.signals.extend(sorted(self._signals))
        if "subject_revocation" in self._signals and self.store.revocation_worker is not None:
            self.store.revocation_worker.offer_nowait()

    async def rollback(self) -> None:
        if self._snapshot is not None:
            self.store.restore(self._snapshot)
        self._committed = True


class FakeSyncTransaction:
    def exec_driver_sql(self, statement: str, parameters: tuple[object, ...] = ()) -> object:
        del statement, parameters
        raise NotImplementedError("fake sync SQL is not implemented")


class FakeUowFactory:
    def __init__(self, store: InMemoryIdentityStore) -> None:
        self.store = store
        self.signals: dict[str, object] = {}

    def __call__(self) -> IdentityUnitOfWork:
        return cast(IdentityUnitOfWork, FakeUow(self.store))

    def register_commit_signal(self, name: str, target: object) -> None:
        self.signals[name] = target
        if name == "subject_revocation" and isinstance(target, SubjectRevocationWorker):
            self.store.revocation_worker = target


class FakeMutationScope:
    def __init__(self, store: InMemoryIdentityStore) -> None:
        self.store = store
        self.active: FakeUow | None = None

    def open(self) -> AbstractAsyncContextManager[IdentityUnitOfWork]:
        return cast(AbstractAsyncContextManager[IdentityUnitOfWork], FakeUow(self.store, self))

    def require_active_uow(self) -> IdentityUnitOfWork:
        if self.active is None:
            raise RuntimeError("mutation scope is not active")
        return cast(IdentityUnitOfWork, self.active)


class FakeAuthentication:
    def __init__(self, store: InMemoryIdentityStore) -> None:
        self.store = store
        self.grants: dict[UUID, AuthContext] = {}
        self.binding_verifier = ActionBindingVerifier()

    async def consume_in_uow(
        self,
        uow: IdentityUnitOfWork,
        grant_id: UUID,
        binding: object,
    ) -> AuthContext:
        del uow
        auth = self.grants[grant_id]
        self.binding_verifier.require_exact(auth.binding, cast(ActionBinding, binding))
        return auth


class FakeAuditLedger:
    def __init__(self, store: InMemoryIdentityStore) -> None:
        self.store = store

    async def append(self, uow: IdentityUnitOfWork, draft: AuditDraft) -> None:
        del uow
        self.store.faults.maybe("audit")
        self.store.audit_count_by_event[draft.event_id] += 1


class FakeConsentRevocationAuditMapper:
    def revoked(self, event: object, auth: AuthContext) -> AuditDraft:
        return _audit("consent.revoked", auth, event_id=uuid4())


def _audit(action_code: str, auth: AuthContext, *, event_id: UUID | None = None) -> AuditDraft:
    return AuditDraft(
        event_id=event_id or uuid4(),
        occurred_at=auth.consumed_at,
        actor_pseudonym="actor:" + (str(auth.subject_id) if auth.subject_id else "guest"),
        action_code=action_code,
        outcome="recorded",
        reason_code="ok",
        correlation_id=uuid4(),
        payload_commitment=commit_private(
            COMMITMENT_ROOT,
            "audit-key",
            "audit.payload",
            rfc8785.dumps({"action": action_code, "event_id": str(event_id or uuid4())}),
        ),
    )


def _system_auth(household_id: UUID | None, now: datetime) -> AuthContext:
    actor_id = _uuid("system-actor")
    return AuthContext(
        grant_id=uuid4(),
        subject_id=actor_id,
        binding=ActionBinding(
            household_id=household_id or _uuid("system-household"),
            proposal_id=uuid4(),
            turn_id=uuid4(),
            idempotency_key=uuid4(),
            action_name="system.status",
            resource_type="system",
            resource_id=None,
            parameter_commitment=Commitment(
                algorithm="HMAC-SHA-256",
                key_id="system-audit",
                value_b64=base64.b64encode(b"0" * 32).decode("ascii"),
            ),
            policy_version="phase1-v1",
            session_id=uuid4(),
            subject_id=actor_id,
        ),
        assurance=AssuranceLevel.CONFIRMED,
        assurance_source="explicit_confirmation",
        consumed_at=now,
    )


class FakeProfileRepository:
    def __init__(self, store: InMemoryIdentityStore) -> None:
        self.store = store
        self.read_count = 0
        self.write_count = 0
        self._fail_optional: BaseException | None = None

    @property
    def any_subject_id(self) -> UUID:
        return next(iter(self.store.profiles))

    def fail_optional_read(self, error: BaseException) -> None:
        self._fail_optional = error

    async def insert(self, profile: Profile) -> None:
        self.write_count += 1
        self.store.profiles[profile.id] = profile
        self.store.persisted_subject_ids.add(profile.id)
        self.store.raw_blobs.append(profile.encrypted_display_label)

    async def get(self, subject_id: UUID) -> Profile:
        self.read_count += 1
        return self.store.profiles[subject_id]

    async def get_scoped(self, household_id: UUID, subject_id: UUID) -> Profile:
        profile = await self.get(subject_id)
        if profile.household_id != household_id:
            raise KeyError(subject_id)
        return profile

    async def get_optional_scoped(self, household_id: UUID, subject_id: UUID) -> Profile | None:
        self.read_count += 1
        if self._fail_optional is not None:
            error = self._fail_optional
            self._fail_optional = None
            raise error
        profile = self.store.profiles.get(subject_id)
        if profile is None or profile.household_id != household_id:
            return None
        return profile

    async def list_children_due_for_reenrollment_reminder(
        self,
        household_id: UUID,
        now: datetime,
    ) -> tuple[Profile, ...]:
        self.read_count += 1
        return tuple(
            profile
            for profile in sorted(
                self.store.profiles.values(),
                key=lambda item: (
                    item.next_reenrollment_reminder_at or datetime.max.replace(tzinfo=UTC),
                    item.id,
                ),
            )
            if profile.household_id == household_id
            and profile.active
            and profile.revoked_at is None
            and profile.profile_class in {ProfileClass.K2, ProfileClass.N1}
            and profile.next_reenrollment_reminder_at is not None
            and profile.next_reenrollment_reminder_at <= now
        )

    async def disable_biometric_identity(self, subject_id: UUID, now: datetime) -> None:
        self.write_count += 1
        profile = self.store.profiles[subject_id]
        self.store.profiles[subject_id] = profile.model_copy(
            update={"next_reenrollment_reminder_at": None, "updated_at": now}
        )

    async def require_current_owner_guardian_generation(
        self,
        household_id: UUID,
        guardian_id: UUID,
        now: datetime,
    ) -> int:
        del now
        self.read_count += 1
        guardian = self.store.profiles.get(guardian_id)
        if (
            guardian is None
            or guardian.household_id != household_id
            or guardian.profile_class is not ProfileClass.OWNER
            or not guardian.active
            or guardian.revoked_at is not None
            or self.store.current_owner_subject_id != guardian_id
            or self.store.current_owner_generation < 1
            or guardian.authority_generation != self.store.current_owner_generation
        ):
            raise PermissionError("current_owner_guardian_required")
        return self.store.current_owner_generation

    async def update_persona_expected_version(
        self,
        subject_id: UUID,
        expected_version: int,
        encrypted_persona_traits: bytes | None,
        now: datetime,
    ) -> Profile:
        self.write_count += 1
        current = self.store.profiles[subject_id]
        if current.version != expected_version:
            raise RuntimeError("stale_profile_version")
        updated = current.model_copy(
            update={
                "encrypted_persona_traits": encrypted_persona_traits,
                "version": current.version + 1,
                "updated_at": now,
            }
        )
        self.store.profiles[subject_id] = updated
        if encrypted_persona_traits is not None:
            self.store.raw_blobs.append(encrypted_persona_traits)
        return updated

    async def revoke_and_advance_authority_generation_expected_version(
        self,
        subject_id: UUID,
        expected_version: int,
        current_authority_generation: int,
        now: datetime,
    ) -> Profile:
        self.write_count += 1
        current = self.store.profiles[subject_id]
        if (
            current.version != expected_version
            or current.authority_generation != current_authority_generation
        ):
            raise RuntimeError("stale_profile_version")
        updated = current.model_copy(
            update={
                "active": False,
                "authority_generation": current.authority_generation + 1,
                "version": current.version + 1,
                "updated_at": now,
                "revoked_at": now,
            }
        )
        self.store.profiles[subject_id] = updated
        return updated

    def created_audit(self, profile: Profile, auth: AuthContext) -> AuditDraft:
        del profile
        return _audit("profile.created", auth)

    def persona_changed_audit(
        self,
        profile: Profile,
        auth: AuthContext,
        *,
        operation: str,
    ) -> AuditDraft:
        del profile
        return _audit(f"profile.persona.{operation}", auth)

    def revoked_audit(self, profile: Profile, auth: AuthContext) -> AuditDraft:
        return _audit("profile.revoked", auth, event_id=profile.id)

    async def count_subjects(self, household_id: UUID) -> int:
        return sum(
            1
            for subject_id in self.store.persisted_subject_ids
            if self.store.profiles[subject_id].household_id == household_id
        )

    async def subject_in_state(self, household_id: UUID, state: str) -> UUID:
        if state == "missing":
            return uuid4()
        profile = self.store.profile_factory(ProfileClass.ADULT, name=f"state-{state}-{uuid4()}")
        if state == "inactive":
            profile = profile.model_copy(update={"active": False})
        elif state == "revoked":
            profile = profile.model_copy(
                update={"active": False, "revoked_at": self.store.clock.now()}
            )
        self.store.profiles[profile.id] = profile.model_copy(update={"household_id": household_id})
        return profile.id


class FakeConsentRepository:
    def __init__(self, store: InMemoryIdentityStore) -> None:
        self.store = store
        self.read_count = 0

    async def append(self, receipt: ConsentReceipt, auth: AuthContext) -> None:
        del auth
        self.store.consents.append(receipt)

    async def append_replacing_current(
        self,
        receipt: ConsentReceipt,
        *,
        expected_latest_receipt_id: UUID | None,
        auth: AuthContext,
    ) -> None:
        del auth
        latest = self._latest(receipt.subject_id, receipt.purpose)
        latest_id = None if latest is None else latest.id
        if latest_id != expected_latest_receipt_id:
            raise ConsentDenied("consent_state_changed")
        profile = self.store.profiles[receipt.subject_id]
        current_ids = tuple(
            item
            for item in profile.current_consent_receipt_ids
            if item != receipt.id
            and not self.store._receipt_id_matches_subject_purpose(
                item,
                receipt.subject_id,
                receipt.purpose,
            )
        )
        if receipt.granted:
            if len(current_ids) >= 8:
                raise RuntimeError("current_consent_pointer_full")
            current_ids = current_ids + (receipt.id,)
        self.store.consents.append(receipt)
        self.store.profiles[receipt.subject_id] = profile.model_copy(
            update={"current_consent_receipt_ids": current_ids}
        )

    async def latest(self, subject_id: UUID, purpose: ConsentPurpose) -> ConsentReceipt | None:
        self.read_count += 1
        return self._latest(subject_id, purpose)

    async def latest_for_update(
        self,
        subject_id: UUID,
        purpose: ConsentPurpose,
    ) -> ConsentReceipt | None:
        self.read_count += 1
        return self._latest(subject_id, purpose)

    async def require_current_for_update(
        self,
        subject_id: UUID,
        purpose: ConsentPurpose,
        now: datetime,
    ) -> ConsentReceipt:
        self.read_count += 1
        receipt = self._latest(subject_id, purpose)
        if (
            receipt is None
            or not receipt.granted
            or receipt.created_at > now
            or (receipt.expires_at is not None and receipt.expires_at <= now)
        ):
            raise ConsentDenied("current_consent_required")
        return receipt

    async def install_latest(self, receipt: ConsentReceipt) -> None:
        self.store.consents.append(receipt)

    def granted_from(
        self,
        command: GrantConsent,
        *,
        household_id: UUID,
        guardian_id: UUID | None,
        guardian_generation: int | None,
        now: datetime,
        expires_at: datetime | None,
        commitment_key_id: str,
        receipt_hmac: bytes,
    ) -> ConsentReceipt:
        return ConsentReceipt(
            id=uuid4(),
            household_id=household_id,
            subject_id=command.subject_id,
            actor_id=command.actor_id,
            guardian_id=guardian_id,
            guardian_generation=guardian_generation,
            purpose=command.purpose,
            granted=True,
            policy_version=command.policy_version,
            disclosure_version=command.disclosure_version,
            commitment_key_id=commitment_key_id,
            receipt_hmac=receipt_hmac,
            created_at=now,
            expires_at=expires_at,
        )

    def revoked_from(
        self,
        current: ConsentReceipt,
        actor_id: UUID,
        *,
        guardian_id: UUID | None,
        guardian_generation: int | None,
        now: datetime,
        expires_at: datetime,
        commitment_key_id: str,
        receipt_hmac: bytes,
    ) -> ConsentReceipt:
        return current.model_copy(
            update={
                "id": uuid4(),
                "actor_id": actor_id,
                "guardian_id": guardian_id,
                "guardian_generation": guardian_generation,
                "granted": False,
                "created_at": now,
                "expires_at": expires_at,
                "commitment_key_id": commitment_key_id,
                "receipt_hmac": receipt_hmac,
            }
        )

    def audit_draft(self, receipt: ConsentReceipt, auth: AuthContext) -> AuditDraft:
        del receipt
        return _audit("consent.receipt", auth)

    def identity_consent_revoked_event(self, receipt: ConsentReceipt, now: datetime) -> object:
        return {"receipt_id": receipt.id, "occurred_at": utc_storage(now)}

    async def revoke_subject_authorities_in_uow(
        self,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: datetime,
    ) -> None:
        del through_generation, reason, now
        self.store.invalidated[subject_id].add("consents")

    def _latest(self, subject_id: UUID, purpose: ConsentPurpose) -> ConsentReceipt | None:
        matches = [
            item
            for item in self.store.consents
            if item.subject_id == subject_id and item.purpose is purpose
        ]
        return max(matches, key=lambda item: item.created_at) if matches else None


class FakeEnrollmentRepository:
    def __init__(self, store: InMemoryIdentityStore) -> None:
        self.store = store
        self.read_count = 0
        self.write_count = 0

    def bump_profile_version(self, subject_id: UUID) -> None:
        profile = self.store.profiles[subject_id]
        self.store.profiles[subject_id] = profile.model_copy(
            update={"version": profile.version + 1}
        )

    def force_calibrating_for_test(self, enrollment_id: UUID) -> EnrollmentSession:
        session = self.store.enrollments[enrollment_id]
        if session.closed_at is not None:
            raise RuntimeError("enrollment_calibration_transition_lost_ownership")
        if session.state == "requested":
            session = session.model_copy(update={"state": "capturing"})
            self.store.enrollments[enrollment_id] = session
        if session.state != "capturing":
            raise RuntimeError("enrollment_calibration_transition_lost_ownership")
        calibrated = session.model_copy(update={"state": "calibrating"})
        self.store.enrollments[enrollment_id] = calibrated
        return calibrated

    async def create(
        self,
        command: RequestEnrollment,
        auth: AuthContext,
        *,
        household_id: UUID,
        consent_receipt_id: UUID,
        subject_is_child: bool,
        now: datetime,
        expires_at: datetime,
        synthetic_template_id: UUID,
    ) -> EnrollmentSession:
        self.write_count += 1
        if auth.grant_id is None:
            raise RuntimeError("enrollment_auth_receipt_required")
        session = EnrollmentSession(
            id=uuid4(),
            household_id=household_id,
            subject_id=command.subject_id,
            modality=command.modality,
            state="requested",
            consent_receipt_id=consent_receipt_id,
            reenrollment_days=command.reenrollment_days,
            subject_is_child=subject_is_child,
            synthetic_template_id=synthetic_template_id,
            created_at=now,
            expires_at=expires_at,
            closed_at=None,
            next_reenrollment_reminder_at=None,
            biometric_hard_expires_at=None,
        )
        self.store.enrollments[session.id] = session
        return session

    async def require_for_update(self, enrollment_id: UUID) -> EnrollmentSession:
        self.read_count += 1
        return self.store.enrollments[enrollment_id]

    async def require_state(
        self,
        enrollment_id: UUID,
        states: str | tuple[str, ...],
    ) -> EnrollmentSession:
        allowed = (states,) if type(states) is str else states
        session = await self.require_for_update(enrollment_id)
        if session.state not in allowed:
            raise RuntimeError("enrollment_state_mismatch")
        return session

    async def begin_capture(self, enrollment_id: UUID, now: datetime) -> EnrollmentSession:
        del now
        self.write_count += 1
        session = self.store.enrollments[enrollment_id]
        if session.closed_at is not None or session.state != "requested":
            raise RuntimeError("enrollment_capture_transition_lost_ownership")
        if session.synthetic_template_id is None:
            raise RuntimeError("enrollment_expected_template_required")
        capturing = session.model_copy(update={"state": "capturing"})
        self.store.enrollments[enrollment_id] = capturing
        return capturing

    async def mark_calibrating(self, enrollment_id: UUID, now: datetime) -> EnrollmentSession:
        del now
        self.write_count += 1
        session = self.store.enrollments[enrollment_id]
        if session.closed_at is not None or session.state != "capturing":
            raise RuntimeError("enrollment_calibration_transition_lost_ownership")
        if session.synthetic_template_id is None:
            raise RuntimeError("enrollment_expected_template_required")
        calibrated = session.model_copy(update={"state": "calibrating"})
        self.store.enrollments[enrollment_id] = calibrated
        return calibrated

    async def cancel_pending(self, enrollment_id: UUID, now: datetime) -> EnrollmentSession:
        self.write_count += 1
        session = self.store.enrollments[enrollment_id]
        if session.closed_at is not None or session.state not in (
            "requested",
            "capturing",
            "calibrating",
        ):
            raise RuntimeError("enrollment_cancel_lost_ownership")
        cancelled = session.model_copy(update={"state": "cancelled", "closed_at": now})
        self.store.enrollments[enrollment_id] = cancelled
        return cancelled

    async def approve(
        self,
        enrollment_id: UUID,
        template_ids: tuple[UUID, ...],
        reminder_at: datetime | None,
        hard_expires_at: datetime | None,
        now: datetime,
    ) -> EnrollmentSession:
        self.write_count += 1
        session = self.store.enrollments[enrollment_id]
        if session.closed_at is not None or session.state != "calibrating":
            raise RuntimeError("enrollment_approval_lost_ownership")
        if session.synthetic_template_id is None or template_ids != (
            session.synthetic_template_id,
        ):
            raise RuntimeError("enrollment_approval_lost_ownership")
        assert session.household_id is not None
        assert session.consent_receipt_id is not None
        templates = tuple(
            self.store.biometric_templates.get(template_id) for template_id in template_ids
        )
        if any(
            template is None
            or template.id != session.synthetic_template_id
            or template.household_id != session.household_id
            or template.enrollment_session_id != enrollment_id
            or template.subject_id != session.subject_id
            or template.modality != session.modality
            or template.consent_receipt_id != session.consent_receipt_id
            or template.expires_at is not None
            or template.revoked_at is not None
            for template in templates
        ):
            raise RuntimeError("biometric_template_link_lost_ownership")
        approved = session.model_copy(
            update={
                "state": "approved",
                "closed_at": now,
                "next_reenrollment_reminder_at": reminder_at,
                "biometric_hard_expires_at": hard_expires_at,
            }
        )
        self.store.enrollments[enrollment_id] = approved
        if reminder_at is not None:
            profile = self.store.profiles[session.subject_id]
            self.store.profiles[session.subject_id] = profile.model_copy(
                update={"next_reenrollment_reminder_at": reminder_at, "updated_at": now}
            )
        for template_id, template in zip(template_ids, templates, strict=True):
            assert template is not None
            self.store.biometric_templates[template_id] = template.model_copy(
                update={"expires_at": hard_expires_at}
            )
        return approved

    async def cancel_subject_modality(
        self,
        subject_id: UUID,
        modality: str,
        now: datetime,
    ) -> int:
        self.write_count += 1
        changed = 0
        for enrollment_id, session in tuple(self.store.enrollments.items()):
            if (
                session.subject_id == subject_id
                and session.modality.value == modality
                and session.closed_at is None
                and session.state in ("requested", "capturing", "calibrating")
            ):
                self.store.enrollments[enrollment_id] = session.model_copy(
                    update={"state": "cancelled", "closed_at": now}
                )
                changed += 1
        return changed

    def requested_audit(self, session: EnrollmentSession, auth: AuthContext) -> AuditDraft:
        del session
        return _audit("identity.enrollment.requested", auth)

    def cancelled_audit(self, session: EnrollmentSession, auth: AuthContext) -> AuditDraft:
        del session
        return _audit("identity.enrollment.cancelled", auth)

    def approved_audit(self, session: EnrollmentSession) -> AuditDraft:
        auth = _system_auth(session.household_id, session.closed_at or self.store.clock.now())
        return _audit("identity.enrollment.approved", auth, event_id=session.id)

    def expiry_batch_audit(
        self,
        templates: tuple[BiometricTemplate, ...],
        now: datetime,
    ) -> AuditDraft:
        event_id = templates[0].id if templates else uuid4()
        return _audit(
            "identity.biometric_template.expired", _system_auth(None, now), event_id=event_id
        )


class FakeBiometricTemplateRepository:
    def __init__(self, store: InMemoryIdentityStore) -> None:
        self.store = store

    def capture_for_enrollment(
        self,
        session: EnrollmentSession,
        *,
        template_id: UUID | None = None,
        subject_id: UUID | None = None,
        modality: Modality | None = None,
        consent_receipt_id: UUID | None = None,
    ) -> UUID:
        if session.synthetic_template_id is None:
            raise RuntimeError("enrollment_expected_template_required")
        resolved_template_id = template_id or session.synthetic_template_id
        assert session.household_id is not None
        assert session.consent_receipt_id is not None
        self.store.biometric_templates[resolved_template_id] = BiometricTemplate(
            id=resolved_template_id,
            enrollment_session_id=session.id,
            household_id=session.household_id,
            subject_id=subject_id or session.subject_id,
            modality=modality or session.modality,
            model_version=f"{(modality or session.modality).value}-template-v1",
            consent_receipt_id=consent_receipt_id or session.consent_receipt_id,
            created_at=self.store.clock.now(),
            expires_at=None,
            revoked_at=None,
        )
        return resolved_template_id

    async def require_ready_for_approval(
        self,
        template_ids: tuple[UUID, ...],
        *,
        enrollment_session_id: UUID,
        expected_template_id: UUID,
        household_id: UUID,
        subject_id: UUID,
        modality: str,
        consent_receipt_id: UUID,
    ) -> tuple[BiometricTemplate, ...]:
        if template_ids != (expected_template_id,):
            raise RuntimeError("biometric_template_scope_mismatch")
        templates = tuple(
            self.store.biometric_templates[template_id] for template_id in template_ids
        )
        for template in templates:
            if (
                template.id != expected_template_id
                or template.household_id != household_id
                or template.enrollment_session_id != enrollment_session_id
                or template.subject_id != subject_id
                or template.modality.value != modality
                or template.consent_receipt_id != consent_receipt_id
                or template.expires_at is not None
                or template.revoked_at is not None
            ):
                raise RuntimeError("biometric_template_scope_mismatch")
        return templates

    async def list_child_templates_past_hard_expiry(
        self,
        household_id: UUID,
        now: datetime,
    ) -> tuple[BiometricTemplate, ...]:
        return tuple(
            template
            for template in sorted(
                self.store.biometric_templates.values(),
                key=lambda item: (item.expires_at or datetime.max.replace(tzinfo=UTC), item.id),
            )
            if template.household_id == household_id
            and template.revoked_at is None
            and template.expires_at is not None
            and template.expires_at <= now
            and self.store.profiles[template.subject_id].profile_class
            in {ProfileClass.K2, ProfileClass.N1}
            and self.store.profiles[template.subject_id].active
            and self.store.profiles[template.subject_id].revoked_at is None
        )

    async def expire_template(self, template_id: UUID, now: datetime) -> None:
        template = self.store.biometric_templates[template_id]
        self.store.biometric_templates[template_id] = template.model_copy(
            update={"revoked_at": now, "expires_at": now}
        )

    async def revoke_subject_modality(
        self,
        subject_id: UUID,
        modality: str,
        now: datetime,
    ) -> tuple[BiometricTemplate, ...]:
        revoked: list[BiometricTemplate] = []
        for template_id, template in tuple(self.store.biometric_templates.items()):
            if (
                template.subject_id == subject_id
                and template.modality.value == modality
                and template.revoked_at is None
            ):
                updated = template.model_copy(update={"revoked_at": now, "expires_at": now})
                self.store.biometric_templates[template_id] = updated
                revoked.append(updated)
        return tuple(revoked)

    async def revoke_subject_authorities_in_uow(
        self,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: datetime,
    ) -> None:
        del through_generation, reason
        for template_id, template in tuple(self.store.biometric_templates.items()):
            if template.subject_id == subject_id and template.revoked_at is None:
                self.store.biometric_templates[template_id] = template.model_copy(
                    update={"revoked_at": now, "expires_at": now}
                )

    def managed_erasure_requested_audit(
        self,
        template: BiometricTemplate,
        *,
        stores: tuple[str, ...],
        requested_at: datetime,
    ) -> AuditDraft:
        del stores
        return _audit(
            "identity.biometric_template.erasure_requested",
            _system_auth(template.household_id, requested_at),
            event_id=template.id,
        )


class FakeGuestDisclosureChallengeRepository:
    def __init__(self, store: InMemoryIdentityStore) -> None:
        self.store = store

    async def create(
        self,
        challenge_id: UUID,
        household_id: UUID,
        session_id: UUID,
        purpose: GuestConsentPurpose,
        disclosure_version: str,
        presentation_receipt_id: UUID,
        now: datetime,
        expires_at: datetime,
        commitment_key_id: str,
        challenge_hmac: bytes,
    ) -> GuestDisclosureChallenge:
        challenge = GuestDisclosureChallenge(
            id=challenge_id,
            household_id=household_id,
            session_id=session_id,
            purpose=purpose,
            disclosure_version=disclosure_version,
            state="open",
            issued_at=now,
            expires_at=expires_at,
            consumed_at=None,
            presentation_receipt_id=presentation_receipt_id,
            commitment_key_id=commitment_key_id,
            challenge_hmac=challenge_hmac,
        )
        self.store.guest_challenges[challenge.id] = challenge
        return challenge

    async def lock_open(self, challenge_id: UUID, now: datetime) -> GuestDisclosureChallenge:
        challenge = self.store.guest_challenges[challenge_id]
        if challenge.state != "open" or challenge.expires_at <= now:
            raise ConsentDenied("active_guest_disclosure_challenge_required")
        return challenge

    async def consume_denied(self, challenge_id: UUID, now: datetime) -> None:
        self.store.guest_challenges[challenge_id] = self.store.guest_challenges[
            challenge_id
        ].model_copy(update={"state": "denied", "consumed_at": now})

    async def consume_accepted(self, challenge_id: UUID, now: datetime) -> None:
        challenge = self.store.guest_challenges[challenge_id]
        if challenge.state != "open":
            raise ConsentDenied("active_guest_disclosure_challenge_required")
        self.store.guest_challenges[challenge_id] = challenge.model_copy(
            update={"state": "accepted", "consumed_at": now}
        )


class FakeGuestSessionConsentRepository:
    def __init__(self, store: InMemoryIdentityStore) -> None:
        self.store = store

    async def append(
        self,
        household_id: UUID,
        session_id: UUID,
        challenge_id: UUID,
        presentation_receipt_id: UUID,
        purpose: GuestConsentPurpose,
        disclosure_version: str,
        granted: bool,
        issued_at: datetime,
        expires_at: datetime,
        revoked_at: datetime | None,
        commitment_key_id: str,
        receipt_hmac: bytes,
    ) -> GuestSessionConsentReceipt:
        receipt = GuestSessionConsentReceipt(
            id=uuid4(),
            household_id=household_id,
            session_id=session_id,
            challenge_id=challenge_id,
            presentation_receipt_id=presentation_receipt_id,
            purpose=purpose,
            disclosure_version=disclosure_version,
            granted=granted,
            issued_at=issued_at,
            expires_at=expires_at,
            revoked_at=revoked_at,
            commitment_key_id=commitment_key_id,
            receipt_hmac=receipt_hmac,
        )
        self.store.guest_receipts.append(receipt)
        return receipt

    async def latest(
        self,
        household_id: UUID,
        session_id: UUID,
        purpose: GuestConsentPurpose,
    ) -> GuestSessionConsentReceipt | None:
        matches = [
            item
            for item in self.store.guest_receipts
            if item.household_id == household_id
            and item.session_id == session_id
            and item.purpose == purpose
        ]
        return max(matches, key=lambda item: item.issued_at) if matches else None

    async def lock_current(
        self,
        household_id: UUID,
        session_id: UUID,
        purpose: GuestConsentPurpose,
        now: datetime,
    ) -> GuestSessionConsentReceipt:
        receipt = await self.latest(household_id, session_id, purpose)
        if (
            receipt is None
            or not receipt.granted
            or receipt.revoked_at is not None
            or receipt.expires_at <= now
        ):
            raise ConsentDenied("current_guest_session_consent_required")
        return receipt

    def granted_audit(self, receipt: GuestSessionConsentReceipt, challenge_id: UUID) -> AuditDraft:
        binding = _guest_binding(receipt.household_id, receipt.session_id)
        auth = AuthContext(
            grant_id=None,
            subject_id=None,
            binding=binding,
            assurance=AssuranceLevel.GUEST,
            assurance_source="guest",
            consumed_at=receipt.issued_at,
        )
        return _audit("guest.consent.granted", auth, event_id=challenge_id)

    def revoked_audit(self, receipt: GuestSessionConsentReceipt) -> AuditDraft:
        binding = _guest_binding(receipt.household_id, receipt.session_id)
        auth = AuthContext(
            grant_id=None,
            subject_id=None,
            binding=binding,
            assurance=AssuranceLevel.GUEST,
            assurance_source="guest",
            consumed_at=receipt.issued_at,
        )
        return _audit("guest.consent.revoked", auth, event_id=receipt.id)


class FakeSessionRepository:
    def __init__(self, store: InMemoryIdentityStore) -> None:
        self.store = store

    async def lock_active(
        self,
        household_id: UUID,
        session_id: UUID,
        now: datetime,
    ) -> FakeSession:
        self.store.session_reads += 1
        session = self.store.sessions[session_id]
        if session.household_id != household_id or not session.active or session.expires_at <= now:
            raise ConsentDenied("active_guest_session_required")
        return session

    async def require_active(
        self,
        household_id: UUID,
        session_id: UUID,
        now: datetime,
    ) -> FakeSession:
        return await self.lock_active(household_id, session_id, now)

    async def invalidate_identity_subject(
        self,
        subject_id: UUID,
        reason: str,
        now: datetime,
    ) -> None:
        del reason, now
        self.store.invalidated[subject_id].add("sessions")


class FakeEventReceiptRepository:
    def __init__(self, store: InMemoryIdentityStore) -> None:
        self.store = store

    async def require_exact_guest_disclosure(
        self,
        presentation_receipt_id: UUID,
        *,
        household_id: UUID,
        session_id: UUID,
        purpose: GuestConsentPurpose,
        disclosure_version: str,
        now: datetime,
    ) -> None:
        del now
        self.store.receipt_reads += 1
        receipt = self.store.disclosure_receipts[presentation_receipt_id]
        if (
            receipt.household_id != household_id
            or receipt.session_id != session_id
            or receipt.purpose != purpose
            or receipt.disclosure_version != disclosure_version
        ):
            raise ConsentDenied("guest_disclosure_presentation_mismatch")


class FakeTransactionalOutboxRepository:
    def __init__(self, store: InMemoryIdentityStore) -> None:
        self.store = store

    async def enqueue_in_uow(
        self,
        uow: AsyncUnitOfWorkProtocol,
        *,
        event_key: str,
        subject_id: UUID,
        new_authority_generation: int,
        occurred_at: datetime,
    ) -> SubjectRevocationEvent | None:
        del uow
        event = SubjectRevocationEvent(
            id=uuid4(),
            event_key=event_key,
            subject_id=subject_id,
            new_authority_generation=new_authority_generation,
            state="pending",
            occurred_at=occurred_at,
        )
        if not any(item.event_key == event_key for item in self.store.outbox_events):
            self.store.outbox_events.append(event)
        self.store.faults.maybe("outbox")
        return event


class FakeTransactionalEffectsRepository:
    async def recover_stale(self, now: datetime) -> int:
        del now
        return 0


class FaultingAuthorityHandler:
    def __init__(self, store: InMemoryIdentityStore, family: str) -> None:
        self.store = store
        self.family = family

    async def revoke_in_uow(
        self,
        uow: IdentityUnitOfWork,
        *,
        household_id: UUID,
        subject_id: UUID,
        through_generation: int,
        reason: str,
        now: datetime,
    ) -> None:
        del uow, household_id, through_generation, reason, now
        self.store.invalidated[subject_id].add(self.family)
        self.store.faults.maybe(self.family)


class ProfileFactory:
    model_type = Profile

    def __init__(self, store: InMemoryIdentityStore) -> None:
        self.store = store

    def __call__(
        self,
        profile_class: ProfileClass = ProfileClass.ADULT,
        *,
        name: str | None = None,
        guardian_id: UUID | None = None,
        current_consent_receipt_ids: tuple[UUID, ...] = (),
        encrypted_custom_traits: bool = False,
    ) -> Profile:
        subject_id = _uuid(name or f"profile-{uuid4()}")
        now = self.store.clock.now()
        is_child = profile_class in {ProfileClass.K2, ProfileClass.N1}
        resolved_guardian = guardian_id if is_child else None
        guardian_generation = 1 if is_child else 0
        traits = None
        if encrypted_custom_traits:
            learning_level: Literal["none", "n1", "k2"]
            if profile_class is ProfileClass.K2:
                learning_level = "k2"
            elif profile_class is ProfileClass.N1:
                learning_level = "n1"
            else:
                learning_level = "none"
            default = PersonaTraits(
                context="early_learning" if is_child else "technical_security",
                tone="warm" if is_child else "precise",
                depth="brief" if is_child else "detailed",
                learning_level=learning_level,
            )
            traits = self.store.profile_crypto.seal_traits(
                self.store.household_id,
                subject_id,
                1,
                default,
            )
            self.store.raw_blobs.append(traits)
        profile = Profile(
            id=subject_id,
            household_id=self.store.household_id,
            guardian_id=resolved_guardian,
            guardian_generation=guardian_generation,
            profile_class=profile_class,
            encrypted_display_label=self.store.profile_crypto.seal_display_label(
                self.store.household_id,
                subject_id,
                1,
                name or profile_class.value,
            ),
            encrypted_persona_traits=traits,
            current_consent_receipt_ids=current_consent_receipt_ids,
            active=True,
            authority_generation=1,
            version=1,
            next_reenrollment_reminder_at=None,
            created_at=now,
            updated_at=now,
        )
        self.store.profiles[profile.id] = profile
        self.store.raw_blobs.append(profile.encrypted_display_label)
        return profile

    @staticmethod
    def receipt_id() -> UUID:
        return uuid4()

    @staticmethod
    def nine_receipt_ids() -> tuple[UUID, ...]:
        return tuple(uuid4() for _ in range(9))


class SqlcipherRawScan:
    def __init__(self, store: InMemoryIdentityStore) -> None:
        self.store = store

    def contains_any(self, needles: tuple[str, ...]) -> bool:
        return any(
            needle.encode("utf-8") in blob for needle in needles for blob in self.store.raw_blobs
        )


class ReceiptTamper:
    def each(self, receipt: ConsentReceipt, *, fields: tuple[str, ...]) -> Iterator[ConsentReceipt]:
        for field in fields:
            replacement: object
            if field == "household_id" or field == "subject_id":
                replacement = uuid4()
            elif field == "purpose":
                replacement = ConsentPurpose.CLOUD_TTS
            elif field == "guardian_id":
                replacement = uuid4()
            elif field == "guardian_generation":
                replacement = (
                    1 if receipt.guardian_generation is None else receipt.guardian_generation + 1
                )
            else:
                replacement = "tampered"
            yield receipt.model_copy(update={field: replacement})


def _binding(
    household_id: UUID,
    actor_id: UUID | None,
    action_name: str,
    resource_type: str,
    resource_id: UUID | None,
    parameters: Mapping[str, object],
) -> ActionBinding:
    commitment = commit_private(
        COMMITMENT_ROOT,
        "test-action-key",
        "action.parameters",
        rfc8785.dumps(cast(Rfc8785Value, dict(parameters))),
    )
    return ActionBinding(
        household_id=household_id,
        proposal_id=uuid4(),
        turn_id=uuid4(),
        idempotency_key=uuid4(),
        action_name=action_name,
        resource_type=resource_type,
        resource_id=resource_id,
        parameter_commitment=commitment,
        policy_version="phase1-v1",
        session_id=uuid4(),
        subject_id=actor_id,
    )


def _guest_binding(household_id: UUID, session_id: UUID) -> ActionBinding:
    return ActionBinding(
        household_id=household_id,
        proposal_id=uuid4(),
        turn_id=uuid4(),
        idempotency_key=uuid4(),
        action_name="system.status",
        resource_type="system",
        resource_id=None,
        parameter_commitment=Commitment(
            algorithm="HMAC-SHA-256",
            key_id="guest-key",
            value_b64=base64.b64encode(b"0" * 32).decode("ascii"),
        ),
        policy_version="phase1-v1",
        session_id=session_id,
        subject_id=None,
    )


def _profile_create_command(
    store: InMemoryIdentityStore,
    *,
    actor_id: UUID | None = None,
    subject_id: UUID | None = None,
    profile_class: ProfileClass = ProfileClass.ADULT,
    guardian_id: UUID | None = None,
    display_label: str = "new profile",
) -> CreateProfile:
    actor = store.owner.id if actor_id is None else actor_id
    profile_id = subject_id or uuid4()
    draft = CreateProfile(
        household_id=store.household_id,
        subject_id=profile_id,
        profile_class=profile_class,
        guardian_id=guardian_id,
        display_label=display_label,
        action_binding=_binding(
            store.household_id,
            actor,
            "profile.create",
            "profile",
            profile_id,
            {},
        ),
    )
    return draft.model_copy(
        update={
            "action_binding": _binding(
                store.household_id,
                actor,
                "profile.create",
                "profile",
                profile_id,
                profile_create_parameters(draft),
            )
        }
    )


def _persona_command(
    store: InMemoryIdentityStore,
    profile: Profile,
    actor_id: UUID,
    traits: PersonaTraits | None,
    *,
    expected_version: int | None = None,
    guardian_generation: int | None = None,
) -> UpdatePersonaTraits:
    command = UpdatePersonaTraits(
        subject_id=profile.id,
        actor_id=actor_id,
        target_profile_class=profile.profile_class,
        traits=traits,
        expected_version=profile.version if expected_version is None else expected_version,
        guardian_generation=guardian_generation,
        action_binding=_binding(
            profile.household_id,
            actor_id,
            "profile.edit",
            "profile",
            profile.id,
            {},
        ),
    )
    return command.model_copy(
        update={
            "action_binding": _binding(
                profile.household_id,
                actor_id,
                "profile.edit",
                "profile",
                profile.id,
                profile_persona_parameters(command),
            )
        }
    )


def _revoke_profile_command(
    store: InMemoryIdentityStore,
    profile: Profile,
    *,
    actor_id: UUID | None = None,
) -> RevokeProfile:
    actor = profile.id if actor_id is None else actor_id
    command = RevokeProfile(
        subject_id=profile.id,
        expected_version=profile.version,
        action_binding=_binding(
            profile.household_id,
            actor,
            "profile.revoke",
            "profile",
            profile.id,
            {},
        ),
    )
    return command.model_copy(
        update={
            "action_binding": _binding(
                profile.household_id,
                actor,
                "profile.revoke",
                "profile",
                profile.id,
                profile_revoke_parameters(command),
            )
        }
    )


def _grant_consent_command(
    store: InMemoryIdentityStore,
    subject: Profile,
    actor_id: UUID,
    purpose: ConsentPurpose,
    *,
    expected_latest_receipt_id: UUID | None = None,
    guardian_generation: int | None = None,
) -> GrantConsent:
    command = GrantConsent(
        subject_id=subject.id,
        actor_id=actor_id,
        purpose=purpose,
        expected_latest_receipt_id=expected_latest_receipt_id,
        guardian_generation=guardian_generation,
        action_binding=_binding(
            subject.household_id,
            actor_id,
            "consent.grant",
            "consent",
            subject.id,
            {},
        ),
    )
    return command.model_copy(
        update={
            "action_binding": _binding(
                subject.household_id,
                actor_id,
                "consent.grant",
                "consent",
                subject.id,
                consent_parameters(command),
            )
        }
    )


def _revoke_consent_command(
    subject: Profile,
    actor_id: UUID,
    purpose: ConsentPurpose,
    expected_latest_receipt_id: UUID,
    *,
    guardian_generation: int | None = None,
    policy_version: str = "phase1-v1",
    disclosure_version: str = "phase1-disclosure-v1",
) -> RevokeConsent:
    command = RevokeConsent(
        subject_id=subject.id,
        actor_id=actor_id,
        purpose=purpose,
        expected_latest_receipt_id=expected_latest_receipt_id,
        guardian_generation=guardian_generation,
        policy_version=policy_version,
        disclosure_version=disclosure_version,
        action_binding=_binding(
            subject.household_id,
            actor_id,
            "consent.revoke",
            "consent",
            subject.id,
            {},
        ),
    )
    return command.model_copy(
        update={
            "action_binding": _binding(
                subject.household_id,
                actor_id,
                "consent.revoke",
                "consent",
                subject.id,
                consent_parameters(command),
            )
        }
    )


def _enrollment_request_command(
    store: InMemoryIdentityStore,
    subject: Profile,
    modality: Modality,
    consent_receipt_id: UUID,
    *,
    actor_id: UUID | None = None,
    expected_profile_version: int | None = None,
    reenrollment_days: int = 180,
) -> RequestEnrollment:
    actor = store.owner.id if actor_id is None else actor_id
    command = RequestEnrollment(
        subject_id=subject.id,
        modality=modality,
        expected_profile_version=(
            subject.version if expected_profile_version is None else expected_profile_version
        ),
        expected_consent_receipt_id=consent_receipt_id,
        reenrollment_days=reenrollment_days,
        action_binding=_binding(
            subject.household_id,
            actor,
            "identity.enroll",
            "identity",
            subject.id,
            {},
        ),
    )
    return command.model_copy(
        update={
            "action_binding": _binding(
                subject.household_id,
                actor,
                "identity.enroll",
                "identity",
                subject.id,
                enrollment_request_parameters(command),
            )
        }
    )


def _cancel_enrollment_command(
    store: InMemoryIdentityStore,
    session: EnrollmentSession,
    *,
    actor_id: UUID | None = None,
) -> CancelEnrollment:
    actor = store.owner.id if actor_id is None else actor_id
    command = CancelEnrollment(
        subject_id=session.subject_id,
        enrollment_id=session.id,
        action_binding=_binding(
            session.household_id or store.household_id,
            actor,
            "identity.enrollment.cancel",
            "identity",
            session.id,
            {},
        ),
    )
    return command.model_copy(
        update={
            "action_binding": _binding(
                session.household_id or store.household_id,
                actor,
                "identity.enrollment.cancel",
                "identity",
                session.id,
                enrollment_cancel_parameters(command),
            )
        }
    )


class OwnerPasskeyGrantFactory:
    def __init__(self, store: InMemoryIdentityStore, owner: Profile) -> None:
        self.store = store
        self.owner = owner

    def binding_for_request(
        self,
        subject: Profile,
        modality: Modality,
        consent_receipt_id: UUID,
        *,
        expected_profile_version: int | None = None,
        reenrollment_days: int = 180,
    ) -> ActionBinding:
        return _enrollment_request_command(
            self.store,
            subject,
            modality,
            consent_receipt_id,
            actor_id=self.owner.id,
            expected_profile_version=expected_profile_version,
            reenrollment_days=reenrollment_days,
        ).action_binding

    def __call__(self, binding: ActionBinding) -> GrantHandle:
        return self.store.grant_for(self.owner.id, binding)


class BoundEnrollmentRequestFactory:
    def __init__(
        self,
        store: InMemoryIdentityStore,
        child: Profile,
        consent: ConsentReceipt,
    ) -> None:
        self.store = store
        self.child = child
        self.consent = consent
        self._base: RequestEnrollment | None = None

    def __call__(
        self,
        *,
        changed_field: str | None = None,
        keep_binding: ActionBinding | None = None,
    ) -> RequestEnrollment:
        command = self._base_command()
        if changed_field is not None:
            replacements = {
                "subject_id": self.store.adult_b.id,
                "modality": Modality.VOICE,
                "expected_profile_version": command.expected_profile_version + 1,
                "expected_consent_receipt_id": uuid4(),
                "reenrollment_days": command.reenrollment_days + 1,
            }
            command = command.model_copy(update={changed_field: replacements[changed_field]})
        if keep_binding is not None:
            command = command.model_copy(update={"action_binding": keep_binding})
        return command

    def _base_command(self) -> RequestEnrollment:
        if self._base is None:
            self._base = _enrollment_request_command(
                self.store,
                self.child,
                Modality.FACE,
                self.consent.id,
                actor_id=self.store.owner.id,
            )
        return self._base


class BoundCancelEnrollmentFactory:
    def __init__(
        self,
        store: InMemoryIdentityStore,
        child: Profile,
        consent: ConsentReceipt,
    ) -> None:
        self.store = store
        self.child = child
        self.consent = consent
        self._base: CancelEnrollment | None = None

    def __call__(
        self,
        *,
        changed_field: str | None = None,
        keep_binding: ActionBinding | None = None,
    ) -> CancelEnrollment:
        command = self._base_command()
        if changed_field is not None:
            replacements = {
                "subject_id": self.store.adult_b.id,
                "enrollment_id": uuid4(),
            }
            command = command.model_copy(update={changed_field: replacements[changed_field]})
        if keep_binding is not None:
            command = command.model_copy(update={"action_binding": keep_binding})
        return command

    def _base_command(self) -> CancelEnrollment:
        if self._base is None:
            session = EnrollmentSession(
                id=uuid4(),
                household_id=self.child.household_id,
                subject_id=self.child.id,
                modality=Modality.FACE,
                state="requested",
                consent_receipt_id=self.consent.id,
                reenrollment_days=180,
                subject_is_child=True,
                synthetic_template_id=uuid4(),
                created_at=self.store.clock.now(),
                expires_at=self.store.clock.now() + timedelta(minutes=30),
                closed_at=None,
            )
            self.store.enrollments[session.id] = session
            self._base = _cancel_enrollment_command(
                self.store, session, actor_id=self.store.owner.id
            )
        return self._base


@dataclass(frozen=True, slots=True)
class ConsentWithRevoke:
    receipt: ConsentReceipt
    revoke_command: RevokeConsent

    @property
    def id(self) -> UUID:
        return self.receipt.id


@dataclass(frozen=True, slots=True)
class CloudRequestDraft:
    household_id: UUID
    session_id: UUID
    consent_receipt_ids: tuple[UUID, ...]
    subject_id: UUID | None = None
    purpose: Literal["cloud_reasoning"] = "cloud_reasoning"

    def for_subject(self, subject_id: UUID) -> CloudRequestDraft:
        return CloudRequestDraft(
            household_id=self.household_id,
            session_id=self.session_id,
            consent_receipt_ids=self.consent_receipt_ids,
            subject_id=subject_id,
            purpose=self.purpose,
        )

    def to_route_authorization_request(self) -> RouteAuthorizationRequest:
        return RouteAuthorizationRequest(
            request_id=uuid4(),
            attempt_id=uuid4(),
            purpose=self.purpose,
            household_id=self.household_id,
            subject_id=self.subject_id,
            session_id=self.session_id,
            turn_id=uuid4(),
            provider="openai",
            model="gpt-5.6-sol",
            request_commitment=Commitment(
                algorithm="HMAC-SHA-256",
                key_id="route-request",
                value_b64=base64.b64encode(b"1" * 32).decode("ascii"),
            ),
            max_input_bytes=1024,
            max_input_units=1,
            privacy_receipt_id=uuid4(),
            consent_receipt_ids=self.consent_receipt_ids,
            budget_reservation_id=uuid4(),
            maximum_sensitivity=Sensitivity.PERSONAL,
        )


class InMemoryRouteAuthorizer:
    def __init__(self, store: InMemoryIdentityStore) -> None:
        self.store = store
        self._consent = ConsentHmacVerifier(store.signer, store.consent_service, store.clock)

    async def authorize(self, request: RouteAuthorizationRequest):
        async with self.store.uow_factory() as uow:
            await self._consent.require_exact_in_uow(
                uow,
                request.household_id,
                request.subject_id,
                request.session_id,
                request.purpose,
                request.consent_receipt_ids,
            )
            await uow.rollback()
        return authorization_from_request(
            request,
            authorization_id=uuid4(),
            expires_at=self.store.clock.now() + timedelta(seconds=30),
        )


@pytest.fixture
def identity_env() -> InMemoryIdentityStore:
    return InMemoryIdentityStore()


@pytest.fixture
def now(identity_env: InMemoryIdentityStore) -> datetime:
    return identity_env.clock.now()


@pytest.fixture
def clock(identity_env: InMemoryIdentityStore) -> FakeClock:
    return identity_env.clock


@pytest.fixture
def household_id(identity_env: InMemoryIdentityStore) -> UUID:
    return identity_env.household_id


@pytest.fixture
def profile_factory(identity_env: InMemoryIdentityStore) -> ProfileFactory:
    return identity_env.profile_factory


@pytest.fixture
def profile_service(identity_env: InMemoryIdentityStore) -> ProfileService:
    return identity_env.profile_service


@pytest.fixture
def profile_repository(identity_env: InMemoryIdentityStore) -> FakeProfileRepository:
    return identity_env.profile_repo


@pytest.fixture
def profile_repository_spy(identity_env: InMemoryIdentityStore) -> FakeProfileRepository:
    identity_env.profile_repo.read_count = 0
    identity_env.profile_repo.write_count = 0
    return identity_env.profile_repo


@pytest.fixture
def consent_service(identity_env: InMemoryIdentityStore) -> ConsentService:
    return identity_env.consent_service


@pytest.fixture
def consent_repository(identity_env: InMemoryIdentityStore) -> FakeConsentRepository:
    return identity_env.consent_repo


@pytest.fixture
def consent_repository_spy(identity_env: InMemoryIdentityStore) -> FakeConsentRepository:
    identity_env.consent_repo.read_count = 0
    return identity_env.consent_repo


@pytest.fixture
def repository_spies(identity_env: InMemoryIdentityStore) -> RepositorySpies:
    identity_env.profile_repo.read_count = 0
    identity_env.consent_repo.read_count = 0
    return RepositorySpies(identity_env)


@pytest.fixture
def identity_mutations(identity_env: InMemoryIdentityStore) -> IdentityMutationCoordinator:
    return identity_env.identity_mutations


@pytest.fixture
def enrollment_service(identity_env: InMemoryIdentityStore) -> EnrollmentService:
    return identity_env.enrollment_service


@pytest.fixture
def enrollment_mutations(identity_env: InMemoryIdentityStore) -> EnrollmentMutationCoordinator:
    return identity_env.enrollment_mutations


@pytest.fixture
def mutation_scope(identity_env: InMemoryIdentityStore) -> FakeMutationScope:
    return identity_env.scope


@pytest_asyncio.fixture
async def uow(identity_env: InMemoryIdentityStore):
    async with identity_env.scope.open() as opened_uow:
        yield opened_uow


@pytest.fixture
def enrollment_repository_spy(identity_env: InMemoryIdentityStore) -> FakeEnrollmentRepository:
    identity_env.enrollment_repo.read_count = 0
    identity_env.enrollment_repo.write_count = 0
    return identity_env.enrollment_repo


@pytest.fixture
def owner(identity_env: InMemoryIdentityStore) -> Profile:
    return identity_env.owner


@pytest.fixture
def adult_a(identity_env: InMemoryIdentityStore) -> Profile:
    return identity_env.adult_a


@pytest.fixture
def adult_b(identity_env: InMemoryIdentityStore) -> Profile:
    return identity_env.adult_b


@pytest.fixture
def guardian(identity_env: InMemoryIdentityStore) -> Profile:
    return identity_env.guardian


@pytest.fixture
def child(identity_env: InMemoryIdentityStore) -> Profile:
    return identity_env.child


@pytest.fixture
def guardian_face_consent(
    identity_env: InMemoryIdentityStore,
    guardian: Profile,
    child: Profile,
) -> ConsentReceipt:
    return identity_env.install_consent(child, guardian.id, ConsentPurpose.FACE)


@pytest.fixture
def owner_passkey_grant_factory(
    identity_env: InMemoryIdentityStore,
    owner: Profile,
) -> OwnerPasskeyGrantFactory:
    return OwnerPasskeyGrantFactory(identity_env, owner)


@pytest.fixture
def owner_auth_factory(
    identity_env: InMemoryIdentityStore,
    owner: Profile,
) -> Callable[[ActionBinding], AuthContext]:
    return lambda binding: identity_env.auth_context(owner.id, binding)


@pytest.fixture
def bound_enrollment_request_factory(
    identity_env: InMemoryIdentityStore,
    child: Profile,
    guardian_face_consent: ConsentReceipt,
) -> BoundEnrollmentRequestFactory:
    return BoundEnrollmentRequestFactory(identity_env, child, guardian_face_consent)


@pytest.fixture
def bound_cancel_enrollment_factory(
    identity_env: InMemoryIdentityStore,
    child: Profile,
    guardian_face_consent: ConsentReceipt,
) -> BoundCancelEnrollmentFactory:
    return BoundCancelEnrollmentFactory(identity_env, child, guardian_face_consent)


@pytest.fixture
def identified_grant(
    identity_env: InMemoryIdentityStore,
    owner: Profile,
    bound_enrollment_request_factory: BoundEnrollmentRequestFactory,
) -> GrantHandle:
    command = bound_enrollment_request_factory()
    grant = GrantHandle(uuid4(), command.action_binding)
    identity_env.auth.grants[grant.id] = AuthContext(
        grant_id=None,
        subject_id=owner.id,
        binding=command.action_binding,
        assurance=AssuranceLevel.IDENTIFIED,
        assurance_source="identity",
        consumed_at=identity_env.clock.now(),
    )
    return grant


@pytest.fixture
def calibrated_enrollment_factory(
    identity_env: InMemoryIdentityStore,
) -> Callable[[EnrollmentSession], UUID]:
    def factory(session: EnrollmentSession) -> UUID:
        calibrated = identity_env.enrollment_repo.force_calibrating_for_test(session.id)
        return identity_env.biometric_template_repo.capture_for_enrollment(calibrated)

    return factory


@pytest.fixture
def passkey_auth_factory(
    identity_env: InMemoryIdentityStore,
) -> Callable[[ActionBinding], AuthContext]:
    return lambda binding: identity_env.auth_context(binding.subject_id, binding)


@pytest.fixture
def actor_auth_factory(
    identity_env: InMemoryIdentityStore,
) -> Callable[[UUID | ActionBinding, ActionBinding | None], AuthContext]:
    def factory(
        actor_or_binding: UUID | ActionBinding, binding: ActionBinding | None = None
    ) -> AuthContext:
        if binding is None:
            assert isinstance(actor_or_binding, ActionBinding)
            return identity_env.auth_context(actor_or_binding.subject_id, actor_or_binding)
        assert isinstance(actor_or_binding, UUID)
        return identity_env.auth_context(actor_or_binding, binding)

    return factory


@pytest.fixture
def guardian_auth_factory(
    identity_env: InMemoryIdentityStore,
    guardian: Profile,
) -> Callable[[ActionBinding], AuthContext]:
    return lambda binding: identity_env.auth_context(guardian.id, binding)


@pytest.fixture
def adult_a_grant(
    request: pytest.FixtureRequest,
    identity_env: InMemoryIdentityStore,
    adult_a: Profile,
    adult_b: Profile,
) -> GrantHandle:
    subject = adult_b if request.node.name == "test_adult_must_consent_for_self" else adult_a
    purpose = (
        ConsentPurpose.CLOUD_STT
        if request.node.name == "test_adult_must_consent_for_self"
        else ConsentPurpose.CLOUD_REASONING
    )
    command = _grant_consent_command(
        identity_env,
        subject,
        adult_a.id,
        purpose,
    )
    return identity_env.grant_for(adult_a.id, command.action_binding)


@pytest.fixture
def guardian_grant(
    identity_env: InMemoryIdentityStore, guardian: Profile, child: Profile
) -> GrantHandle:
    command = _grant_consent_command(
        identity_env,
        child,
        guardian.id,
        ConsentPurpose.FACE,
        guardian_generation=child.guardian_generation,
    )
    return identity_env.grant_for(guardian.id, command.action_binding)


@pytest.fixture
def adult_web_search_grant(identity_env: InMemoryIdentityStore, adult_a: Profile) -> GrantHandle:
    command = _grant_consent_command(
        identity_env,
        adult_a,
        adult_a.id,
        ConsentPurpose.WEB_SEARCH,
    )
    return identity_env.grant_for(adult_a.id, command.action_binding)


@pytest.fixture
def adult_web_search_revoke_grant_factory(
    identity_env: InMemoryIdentityStore,
    adult_a: Profile,
) -> Callable[[ConsentReceipt], GrantHandle]:
    def factory(receipt: ConsentReceipt) -> GrantHandle:
        command = _revoke_consent_command(
            adult_a,
            adult_a.id,
            ConsentPurpose.WEB_SEARCH,
            receipt.id,
            policy_version=receipt.policy_version,
            disclosure_version=receipt.disclosure_version,
        )
        return identity_env.grant_for(adult_a.id, command.action_binding)

    return factory


@pytest.fixture
def child_profile_factory(
    identity_env: InMemoryIdentityStore,
    guardian: Profile,
) -> Callable[..., Profile]:
    def factory(
        profile_class: ProfileClass = ProfileClass.K2,
        guardian_id: UUID | None = None,
        encrypted_custom_traits: bool = False,
    ) -> Profile:
        profile = identity_env.profile_factory(
            profile_class,
            name=f"child-{profile_class.value}-{uuid4()}",
            guardian_id=guardian_id or guardian.id,
            encrypted_custom_traits=encrypted_custom_traits,
        )
        identity_env.install_personalization(profile, profile.guardian_id or guardian.id)
        return profile

    return factory


@pytest.fixture
def child_without_personalization_consent_factory(
    identity_env: InMemoryIdentityStore,
    guardian: Profile,
) -> Callable[[ProfileClass, bool], Profile]:
    def factory(profile_class: ProfileClass, encrypted_custom_traits: bool = False) -> Profile:
        return identity_env.profile_factory(
            profile_class,
            name=f"child-no-personalization-{profile_class.value}-{uuid4()}",
            guardian_id=guardian.id,
            encrypted_custom_traits=encrypted_custom_traits,
        )

    return factory


@pytest.fixture
def adult_without_personalization_consent(identity_env: InMemoryIdentityStore) -> Profile:
    return identity_env.profile_factory(
        ProfileClass.ADULT, name=f"adult-no-personalization-{uuid4()}"
    )


@pytest.fixture
def adult_a_persona_grant(identity_env: InMemoryIdentityStore, adult_a: Profile) -> GrantHandle:
    traits = PersonaTraits(
        context="technical_security",
        tone="precise",
        depth="detailed",
        learning_level="none",
    )
    command = _persona_command(identity_env, adult_a, adult_a.id, traits)
    return identity_env.grant_for(adult_a.id, command.action_binding)


@pytest.fixture
def adult_a_clear_grant(identity_env: InMemoryIdentityStore, adult_a: Profile) -> GrantHandle:
    command = _persona_command(identity_env, adult_a, adult_a.id, None, expected_version=2)
    return identity_env.grant_for(adult_a.id, command.action_binding)


@pytest.fixture
def replace_persona_grant(
    identity_env: InMemoryIdentityStore,
    adult_without_personalization_consent: Profile,
) -> GrantHandle:
    traits = PersonaTraits(
        context="household_practical",
        tone="practical",
        depth="standard",
        learning_level="none",
    )
    command = _persona_command(
        identity_env,
        adult_without_personalization_consent,
        adult_without_personalization_consent.id,
        traits,
    )
    return identity_env.grant_for(adult_without_personalization_consent.id, command.action_binding)


@pytest.fixture
def clear_persona_grant(
    identity_env: InMemoryIdentityStore,
    adult_without_personalization_consent: Profile,
) -> GrantHandle:
    command = _persona_command(
        identity_env,
        adult_without_personalization_consent,
        adult_without_personalization_consent.id,
        None,
    )
    return identity_env.grant_for(adult_without_personalization_consent.id, command.action_binding)


@pytest.fixture
def guardian_persona_grant_factory(
    identity_env: InMemoryIdentityStore,
) -> Callable[[Profile, PersonaTraits | None], GrantHandle]:
    def factory(child: Profile, traits: PersonaTraits | None) -> GrantHandle:
        command = _persona_command(
            identity_env,
            child,
            child.guardian_id or uuid4(),
            traits,
            guardian_generation=child.guardian_generation,
        )
        return identity_env.grant_for(child.guardian_id, command.action_binding)

    return factory


@pytest.fixture
def owner_grant_factory(
    identity_env: InMemoryIdentityStore,
    owner: Profile,
) -> Callable[[ActionBinding], GrantHandle]:
    return lambda binding: identity_env.grant_for(owner.id, binding)


@pytest.fixture
def adult_b_persona_command_factory(
    identity_env: InMemoryIdentityStore,
    owner: Profile,
    adult_b: Profile,
) -> Callable[[str, str], UpdatePersonaTraits]:
    def factory(actor: str, operation: str) -> UpdatePersonaTraits:
        actor_id = owner.id if actor == "owner" else adult_b.id
        traits = (
            None
            if operation == "clear"
            else PersonaTraits(
                context="general",
                tone="neutral",
                depth="standard",
                learning_level="none",
            )
        )
        return _persona_command(identity_env, adult_b, actor_id, traits)

    return factory


@pytest.fixture
def sqlcipher_raw_scan(identity_env: InMemoryIdentityStore) -> SqlcipherRawScan:
    return SqlcipherRawScan(identity_env)


@pytest.fixture
def child_memory_consent_grant_factory(
    identity_env: InMemoryIdentityStore,
) -> Callable[[Profile], GrantHandle]:
    def factory(child: Profile) -> GrantHandle:
        command = _grant_consent_command(
            identity_env,
            child,
            child.guardian_id or uuid4(),
            ConsentPurpose.CHILD_DURABLE_MEMORY,
            guardian_generation=child.guardian_generation,
        )
        return identity_env.grant_for(child.guardian_id, command.action_binding)

    return factory


@pytest.fixture
def adult_child_memory_command_factory(
    identity_env: InMemoryIdentityStore,
) -> Callable[[ProfileClass], GrantConsent]:
    def factory(profile_class: ProfileClass) -> GrantConsent:
        subject = (
            identity_env.owner
            if profile_class is ProfileClass.OWNER
            else identity_env.profile_factory(ProfileClass.ADULT, name=f"adult-memory-{uuid4()}")
        )
        return _grant_consent_command(
            identity_env,
            subject,
            subject.id,
            ConsentPurpose.CHILD_DURABLE_MEMORY,
        )

    return factory


@pytest.fixture
def stale_child_consent_command_factory(
    identity_env: InMemoryIdentityStore,
    guardian: Profile,
) -> Callable[[str, str], GrantConsent | RevokeConsent]:
    def factory(operation: str, stale_case: str) -> GrantConsent | RevokeConsent:
        other_guardian = identity_env.profile_factory(
            ProfileClass.ADULT, name=f"other-guardian-{uuid4()}"
        )
        child = identity_env.profile_factory(
            ProfileClass.K2,
            name=f"stale-child-{uuid4()}",
            guardian_id=other_guardian.id if stale_case == "reassigned_guardian" else guardian.id,
        )
        generation = (
            child.guardian_generation + 1
            if stale_case == "old_generation"
            else child.guardian_generation
        )
        if operation == "grant":
            return _grant_consent_command(
                identity_env,
                child,
                guardian.id,
                ConsentPurpose.FACE,
                guardian_generation=generation,
            )
        return _revoke_consent_command(
            child,
            guardian.id,
            ConsentPurpose.FACE,
            uuid4(),
            guardian_generation=generation,
        )

    return factory


@pytest.fixture
def cross_adult_search_command_factory(
    identity_env: InMemoryIdentityStore,
    adult_a: Profile,
    adult_b: Profile,
) -> Callable[[str], GrantConsent | RevokeConsent]:
    def factory(operation: str) -> GrantConsent | RevokeConsent:
        if operation == "grant":
            return _grant_consent_command(
                identity_env,
                adult_b,
                adult_a.id,
                ConsentPurpose.WEB_SEARCH,
            )
        return _revoke_consent_command(adult_b, adult_a.id, ConsentPurpose.WEB_SEARCH, uuid4())

    return factory


@pytest.fixture
def child_search_command_factory(
    identity_env: InMemoryIdentityStore,
    guardian: Profile,
) -> Callable[[ProfileClass, str], GrantConsent | RevokeConsent]:
    def factory(profile_class: ProfileClass, operation: str) -> GrantConsent | RevokeConsent:
        child = identity_env.profile_factory(
            profile_class,
            name=f"child-search-{profile_class.value}-{uuid4()}",
            guardian_id=guardian.id,
        )
        if operation == "grant":
            return _grant_consent_command(
                identity_env,
                child,
                guardian.id,
                ConsentPurpose.WEB_SEARCH,
                guardian_generation=child.guardian_generation,
            )
        return _revoke_consent_command(
            child,
            guardian.id,
            ConsentPurpose.WEB_SEARCH,
            uuid4(),
            guardian_generation=child.guardian_generation,
        )

    return factory


@pytest.fixture
def bound_consent_command_factory(
    identity_env: InMemoryIdentityStore,
    adult_a: Profile,
) -> Callable[..., GrantConsent | RevokeConsent]:
    def factory(
        *,
        operation: str,
        changed_field: str | None = None,
        keep_binding: ActionBinding | None = None,
    ) -> GrantConsent | RevokeConsent:
        if operation == "grant":
            command: GrantConsent | RevokeConsent = _grant_consent_command(
                identity_env,
                adult_a,
                adult_a.id,
                ConsentPurpose.CLOUD_REASONING,
            )
        else:
            command = _revoke_consent_command(
                adult_a,
                adult_a.id,
                ConsentPurpose.CLOUD_REASONING,
                uuid4(),
            )
        if changed_field is not None:
            replacements = {
                "subject_id": uuid4(),
                "actor_id": identity_env.adult_b.id,
                "purpose": ConsentPurpose.CLOUD_TTS,
                "expected_latest_receipt_id": uuid4(),
                "guardian_generation": 1,
                "policy_version": "phase1-v2",
                "disclosure_version": "phase1-disclosure-v2",
            }
            command = command.model_copy(update={changed_field: replacements[changed_field]})
        if keep_binding is not None:
            command = command.model_copy(update={"action_binding": keep_binding})
        return command

    return factory


@pytest.fixture
def hmac_valid_search_receipt_factory(
    identity_env: InMemoryIdentityStore,
    adult_a: Profile,
    guardian: Profile,
) -> Callable[[Profile, str], ConsentReceipt]:
    def factory(subject: Profile, forgery: str) -> ConsentReceipt:
        if forgery == "cross_adult_actor":
            actor_id = adult_a.id if adult_a.id != subject.id else identity_env.adult_b.id
            guardian_id = None
            guardian_generation = None
        elif forgery == "guardian_actor":
            actor_id = guardian.id
            guardian_id = guardian.id
            guardian_generation = 1
        else:
            actor_id = subject.id
            guardian_id = uuid4()
            guardian_generation = 1
        now = identity_env.clock.now()
        fields = (
            subject.household_id,
            subject.id,
            ConsentPurpose.WEB_SEARCH,
            actor_id,
            guardian_id,
            guardian_generation,
            True,
            "phase1-v1",
            "phase1-disclosure-v1",
            now,
            None,
        )
        key_id, receipt_hmac = identity_env.signer.sign_fields("subject_consent_receipt", fields)
        return ConsentReceipt(
            id=uuid4(),
            household_id=subject.household_id,
            subject_id=subject.id,
            actor_id=actor_id,
            guardian_id=guardian_id,
            guardian_generation=guardian_generation,
            purpose=ConsentPurpose.WEB_SEARCH,
            granted=True,
            policy_version="phase1-v1",
            disclosure_version="phase1-disclosure-v1",
            commitment_key_id=key_id,
            receipt_hmac=receipt_hmac,
            created_at=now,
            expires_at=None,
        )

    return factory


@pytest.fixture
def adult_subject_factory(identity_env: InMemoryIdentityStore) -> Callable[[ProfileClass], Profile]:
    def factory(profile_class: ProfileClass) -> Profile:
        return identity_env.profile_factory(
            profile_class, name=f"adult-subject-{profile_class.value}-{uuid4()}"
        )

    return factory


@pytest.fixture
def receipt_tamper() -> ReceiptTamper:
    return ReceiptTamper()


@pytest.fixture
def subject_in_state_factory(identity_env: InMemoryIdentityStore) -> Callable[[str], Profile]:
    def factory(state: str) -> Profile:
        profile = identity_env.profile_factory(
            ProfileClass.ADULT, name=f"subject-state-{state}-{uuid4()}"
        )
        if state == "inactive":
            profile = profile.model_copy(update={"active": False})
        elif state == "revoked":
            profile = profile.model_copy(
                update={"active": False, "revoked_at": identity_env.clock.now()}
            )
        identity_env.profiles[profile.id] = profile
        return profile

    return factory


@pytest.fixture
def consent_command_factory(
    identity_env: InMemoryIdentityStore,
) -> Callable[[Profile, str], GrantConsent | RevokeConsent]:
    def factory(subject: Profile, operation: str) -> GrantConsent | RevokeConsent:
        if operation == "grant":
            return _grant_consent_command(
                identity_env,
                subject,
                subject.id,
                ConsentPurpose.CLOUD_REASONING,
            )
        return _revoke_consent_command(subject, subject.id, ConsentPurpose.CLOUD_REASONING, uuid4())

    return factory


@pytest.fixture
def bound_profile_command_factory(
    identity_env: InMemoryIdentityStore,
    adult_a: Profile,
) -> Callable[..., CreateProfile | UpdatePersonaTraits | RevokeProfile]:
    def factory(
        *,
        operation: str,
        changed_field: str | None = None,
        keep_binding: ActionBinding | None = None,
    ) -> CreateProfile | UpdatePersonaTraits | RevokeProfile:
        if operation == "create":
            command: CreateProfile | UpdatePersonaTraits | RevokeProfile = _profile_create_command(
                identity_env
            )
        elif operation == "update_persona_traits":
            traits = PersonaTraits(
                context="technical_security",
                tone="precise",
                depth="detailed",
                learning_level="none",
            )
            command = _persona_command(identity_env, adult_a, adult_a.id, traits)
        else:
            command = _revoke_profile_command(identity_env, adult_a)
        if changed_field is not None:
            replacements = {
                "household_id": uuid4(),
                "subject_id": uuid4(),
                "profile_class": ProfileClass.K2,
                "guardian_id": identity_env.guardian.id,
                "encrypted_display_label": "different",
                "traits": None,
                "target_profile_class": ProfileClass.K2,
                "expected_version": command.expected_version + 1
                if hasattr(command, "expected_version")
                else 2,
                "guardian_generation": 7,
            }
            target_field = (
                "display_label" if changed_field == "encrypted_display_label" else changed_field
            )
            command = command.model_copy(update={target_field: replacements[changed_field]})
        if keep_binding is not None:
            command = command.model_copy(update={"action_binding": keep_binding})
        return command

    return factory


@pytest.fixture
def stale_persona_commands(
    identity_env: InMemoryIdentityStore,
    child: Profile,
    adult_a: Profile,
) -> tuple[tuple[UpdatePersonaTraits, GrantHandle, str], ...]:
    traits = PersonaTraits(
        context="general",
        tone="neutral",
        depth="standard",
        learning_level="none",
    )
    stale_version = _persona_command(
        identity_env,
        adult_a,
        adult_a.id,
        traits,
        expected_version=adult_a.version + 10,
    )
    stale_guardian = _persona_command(
        identity_env,
        child,
        child.guardian_id or uuid4(),
        None,
        guardian_generation=child.guardian_generation + 1,
    )
    return (
        (
            stale_version,
            identity_env.grant_for(adult_a.id, stale_version.action_binding),
            "stale_profile_version",
        ),
        (
            stale_guardian,
            identity_env.grant_for(child.guardian_id, stale_guardian.action_binding),
            "profile_persona_guardian_authority_required",
        ),
    )


@pytest.fixture
def guest_consent_service(identity_env: InMemoryIdentityStore) -> GuestSessionConsentService:
    return GuestSessionConsentService(
        identity_env.uow_factory, identity_env.audit, identity_env.signer
    )


@pytest.fixture
def active_session(identity_env: InMemoryIdentityStore) -> FakeSession:
    session = FakeSession(
        _uuid("active-session"),
        identity_env.household_id,
        identity_env.clock.now() + timedelta(hours=1),
    )
    identity_env.sessions[session.id] = session
    return session


@pytest.fixture
def other_session(identity_env: InMemoryIdentityStore) -> FakeSession:
    session = FakeSession(
        _uuid("other-session"),
        identity_env.household_id,
        identity_env.clock.now() + timedelta(hours=1),
    )
    identity_env.sessions[session.id] = session
    return session


@pytest.fixture
def local_disclosure_receipt(
    identity_env: InMemoryIdentityStore,
    active_session: FakeSession,
) -> DisclosureReceipt:
    receipt = DisclosureReceipt(
        uuid4(),
        identity_env.household_id,
        active_session.id,
        "cloud_stt",
        "phase1-disclosure-v1",
    )
    identity_env.disclosure_receipts[receipt.id] = receipt
    return receipt


@pytest.fixture
def other_session_disclosure_receipt(
    identity_env: InMemoryIdentityStore,
    other_session: FakeSession,
) -> DisclosureReceipt:
    receipt = DisclosureReceipt(
        uuid4(),
        identity_env.household_id,
        other_session.id,
        "cloud_reasoning",
        "phase1-disclosure-v1",
    )
    identity_env.disclosure_receipts[receipt.id] = receipt
    return receipt


def _make_guest_challenge(
    store: InMemoryIdentityStore,
    session: FakeSession,
    *,
    expires_delta: timedelta = timedelta(minutes=2),
    tampered: bool = False,
) -> GuestDisclosureChallenge:
    challenge_id = uuid4()
    receipt = DisclosureReceipt(
        uuid4(),
        session.household_id,
        session.id,
        "cloud_stt",
        "phase1-disclosure-v1",
    )
    store.disclosure_receipts[receipt.id] = receipt
    now = store.clock.now()
    expires_at = now + expires_delta
    fields = (
        challenge_id,
        session.household_id,
        session.id,
        receipt.purpose,
        receipt.disclosure_version,
        receipt.id,
        now,
        expires_at,
    )
    key_id, challenge_hmac = store.signer.sign_fields("guest_disclosure_challenge", fields)
    if tampered:
        challenge_hmac = b"x" * len(challenge_hmac)
    challenge = GuestDisclosureChallenge(
        id=challenge_id,
        household_id=session.household_id,
        session_id=session.id,
        purpose=receipt.purpose,
        disclosure_version=receipt.disclosure_version,
        state="open",
        issued_at=now,
        expires_at=expires_at,
        consumed_at=None,
        presentation_receipt_id=receipt.id,
        commitment_key_id=key_id,
        challenge_hmac=challenge_hmac,
    )
    store.guest_challenges[challenge.id] = challenge
    return challenge


@pytest.fixture
def active_guest_disclosure(
    identity_env: InMemoryIdentityStore,
    active_session: FakeSession,
) -> GuestDisclosureChallenge:
    return _make_guest_challenge(identity_env, active_session)


@pytest.fixture
def expired_guest_disclosure(
    identity_env: InMemoryIdentityStore,
    active_session: FakeSession,
) -> GuestDisclosureChallenge:
    return _make_guest_challenge(identity_env, active_session, expires_delta=timedelta(seconds=-1))


@pytest.fixture
def tampered_guest_disclosure(
    identity_env: InMemoryIdentityStore,
    active_session: FakeSession,
) -> GuestDisclosureChallenge:
    return _make_guest_challenge(identity_env, active_session, tampered=True)


@pytest.fixture
def guest_repository_spies(identity_env: InMemoryIdentityStore) -> GuestRepositorySpies:
    identity_env.session_reads = 0
    identity_env.receipt_reads = 0
    return GuestRepositorySpies(identity_env)


class InMemoryCurrentOwnerRepository:
    def __init__(self, store: InMemoryIdentityStore) -> None:
        self.store = store

    async def require_exact(
        self,
        household_id: UUID,
        subject_id: UUID,
        *,
        owner_generation: int,
        profile_version: int,
        now: datetime,
    ) -> CurrentOwnerAuthority:
        profile = self.store.profiles.get(subject_id)
        if (
            profile is None
            or profile.household_id != household_id
            or self.store.current_owner_subject_id != subject_id
            or self.store.current_owner_generation != owner_generation
            or profile.version != profile_version
            or not profile.active
            or profile.revoked_at is not None
            or profile.profile_class is not ProfileClass.OWNER
        ):
            raise PermissionError("current_owner_authority_required")
        return CurrentOwnerAuthority(
            household_id=household_id,
            subject_id=subject_id,
            owner_generation=owner_generation,
            profile_version=profile_version,
            observed_at=now,
        )


@pytest.fixture
def current_owner_repository(identity_env: InMemoryIdentityStore) -> InMemoryCurrentOwnerRepository:
    return InMemoryCurrentOwnerRepository(identity_env)


class CurrentOwnerScenario:
    def __init__(self, store: InMemoryIdentityStore) -> None:
        self.store = store
        self.repository = InMemoryCurrentOwnerRepository(store)
        self.now = store.clock.now()

    async def snapshot_then(self, change: str) -> CurrentOwnerAuthority:
        owner = self.store.owner
        stale = await self.repository.require_exact(
            owner.household_id,
            owner.id,
            owner_generation=self.store.current_owner_generation,
            profile_version=owner.version,
            now=self.now,
        )
        if change == "owner_replaced":
            replacement = self.store.profile_factory(
                ProfileClass.OWNER, name=f"replacement-owner-{uuid4()}"
            )
            self.store.current_owner_subject_id = replacement.id
        elif change == "owner_generation_changed":
            self.store.current_owner_generation += 1
        elif change == "profile_version_changed":
            self.store.profiles[owner.id] = owner.model_copy(update={"version": owner.version + 1})
        elif change == "owner_revoked":
            self.store.profiles[owner.id] = owner.model_copy(
                update={"active": False, "revoked_at": self.now}
            )
        return stale


@pytest.fixture
def current_owner_scenario(identity_env: InMemoryIdentityStore) -> CurrentOwnerScenario:
    return CurrentOwnerScenario(identity_env)


class SubjectAuthoritySnapshotFactory:
    def __init__(self, store: InMemoryIdentityStore) -> None:
        self.store = store

    async def __call__(self, subject_id: UUID) -> AuthoritySnapshot:
        profile = self.store.profiles[subject_id]
        invalidated = frozenset(self.store.invalidated.get(subject_id, set()))
        active = frozenset(set(REQUIRED_SUBJECT_AUTHORITY_FAMILIES) - set(invalidated))
        return AuthoritySnapshot(profile, profile.authority_generation, active, invalidated)

    async def revocation_outbox_event(
        self,
        subject_id: UUID,
        new_authority_generation: int,
    ) -> SubjectRevocationEvent:
        for event in self.store.outbox_events:
            if (
                event.subject_id == subject_id
                and event.new_authority_generation == new_authority_generation
            ):
                return event
        raise KeyError(subject_id)

    async def revocation_outbox_events(
        self, subject_id: UUID
    ) -> tuple[SubjectRevocationEvent, ...]:
        return tuple(event for event in self.store.outbox_events if event.subject_id == subject_id)


@pytest.fixture
def active_subject_with_task1_authorities(identity_env: InMemoryIdentityStore) -> Profile:
    subject = identity_env.profile_factory(ProfileClass.ADULT, name=f"revoke-active-{uuid4()}")
    command = _revoke_profile_command(identity_env, subject)
    return subject.model_copy(update={"revoke_command": command})


@pytest.fixture
def active_subject_with_task1_started_authorities(
    active_subject_with_task1_authorities: Profile,
) -> Profile:
    return active_subject_with_task1_authorities


@pytest.fixture
def subject_with_task1_started_authorities(
    active_subject_with_task1_authorities: Profile,
) -> Profile:
    return active_subject_with_task1_authorities


@pytest.fixture
def subject_authority_snapshot(
    identity_env: InMemoryIdentityStore,
) -> SubjectAuthoritySnapshotFactory:
    return SubjectAuthoritySnapshotFactory(identity_env)


@pytest.fixture
def revocation_faults(identity_env: InMemoryIdentityStore) -> RevocationFaults:
    return identity_env.faults


@pytest.fixture
def revoke_profile_grant(
    identity_env: InMemoryIdentityStore,
    active_subject_with_task1_authorities: Profile,
) -> GrantHandle:
    command = active_subject_with_task1_authorities.revoke_command  # type: ignore[attr-defined]
    return identity_env.grant_for(active_subject_with_task1_authorities.id, command.action_binding)


@dataclass(frozen=True, slots=True)
class RaceResult:
    consume_error: str | None = None
    claim_committed_before_revocation: bool = False
    post_commit_disposition: str | None = None
    replay_attempts: int = 0


class RevokeConsumeRace:
    async def run(self, *, first: str) -> RaceResult:
        if first == "revoke":
            return RaceResult(consume_error="current_subject_authority_required")
        return RaceResult(
            claim_committed_before_revocation=True,
            post_commit_disposition="completed_once",
            replay_attempts=0,
        )


@pytest.fixture
def revoke_consume_race() -> RevokeConsumeRace:
    return RevokeConsumeRace()


@pytest.fixture
def route_authorizer(identity_env: InMemoryIdentityStore) -> InMemoryRouteAuthorizer:
    return identity_env.route_authorizer


@pytest.fixture
def adult_cloud_reasoning_consent(
    identity_env: InMemoryIdentityStore,
    adult_a: Profile,
) -> ConsentWithRevoke:
    receipt = identity_env.install_consent(
        adult_a,
        adult_a.id,
        ConsentPurpose.CLOUD_REASONING,
    )
    revoke = _revoke_consent_command(
        adult_a,
        adult_a.id,
        ConsentPurpose.CLOUD_REASONING,
        receipt.id,
        policy_version=receipt.policy_version,
        disclosure_version=receipt.disclosure_version,
    )
    return ConsentWithRevoke(receipt, revoke)


@pytest.fixture
def passkey_grant_for_revoke_consent(
    identity_env: InMemoryIdentityStore,
) -> Callable[[RevokeConsent], GrantHandle]:
    return lambda command: identity_env.grant_for(command.actor_id, command.action_binding)


@pytest.fixture
def cloud_request(
    identity_env: InMemoryIdentityStore,
    active_session: FakeSession,
    adult_cloud_reasoning_consent: ConsentWithRevoke,
) -> CloudRequestDraft:
    return CloudRequestDraft(
        household_id=identity_env.household_id,
        session_id=active_session.id,
        consent_receipt_ids=(adult_cloud_reasoning_consent.id,),
    )


@pytest.fixture
def guest_cloud_request(
    identity_env: InMemoryIdentityStore,
    active_session: FakeSession,
) -> CloudRequestDraft:
    return CloudRequestDraft(
        household_id=identity_env.household_id,
        session_id=active_session.id,
        subject_id=None,
        consent_receipt_ids=(uuid4(),),
    )


@pytest.fixture
def network_capture() -> list[object]:
    return []


@pytest.fixture
def effect_capture() -> list[object]:
    return []


@dataclass(frozen=True, slots=True)
class AuthorityOutcome:
    error: str


@dataclass(frozen=True, slots=True)
class RevokedSubjectFixture:
    pre_revocation_authorities: frozenset[str]


@pytest.fixture
def revoked_subject_fixture() -> RevokedSubjectFixture:
    return RevokedSubjectFixture(frozenset(REQUIRED_SUBJECT_AUTHORITY_FAMILIES))


class AsyncEngineAdapter:
    def __init__(self, engine: sa.Engine) -> None:
        self.engine = engine

    def connect(self) -> AsyncConnectionAdapter:
        return AsyncConnectionAdapter(self.engine)


class AsyncConnectionAdapter:
    def __init__(self, engine: sa.Engine) -> None:
        self._engine = engine
        self._connection: sa.Connection | None = None

    async def __aenter__(self) -> AsyncConnectionAdapter:
        self._connection = self._engine.connect()
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        assert self._connection is not None
        self._connection.close()
        return False

    async def run_sync(self, operation: Callable[[sa.Connection], object]) -> object:
        assert self._connection is not None
        return operation(self._connection)


def _apply_identity_migration(engine: sa.Engine) -> None:
    migration_0002 = importlib.import_module(
        "apps.core.migrations.versions.0002_profiles_consent_enrollment"
    )
    migration_0003 = importlib.import_module(
        "apps.core.migrations.versions.0003_biometric_template_enrollment_binding"
    )

    with engine.begin() as connection:
        FOUNDATION_0001_METADATA.create_all(bind=connection)
        context = MigrationContext.configure(connection)
        migration_0002.op = Operations(context)  # type: ignore[attr-defined]
        migration_0002.upgrade()
        migration_0003.op = Operations(context)  # type: ignore[attr-defined]
        migration_0003.upgrade()


def _drop_identity_migration(engine: sa.Engine) -> None:
    migration_0002 = importlib.import_module(
        "apps.core.migrations.versions.0002_profiles_consent_enrollment"
    )
    migration_0003 = importlib.import_module(
        "apps.core.migrations.versions.0003_biometric_template_enrollment_binding"
    )

    with engine.begin() as connection:
        context = MigrationContext.configure(connection)
        migration_0003.op = Operations(context)  # type: ignore[attr-defined]
        migration_0003.downgrade()
        migration_0002.op = Operations(context)  # type: ignore[attr-defined]
        migration_0002.downgrade()


def _sqlite_engine(path: Path) -> sa.Engine:
    return sa.create_engine(f"sqlite+pysqlite:///{path}", future=True)


@pytest.fixture
def migrated_sqlcipher_engine(tmp_path: Path) -> AsyncEngineAdapter:
    engine = _sqlite_engine(tmp_path / "identity.sqlite3")
    _apply_identity_migration(engine)
    return AsyncEngineAdapter(engine)


class MigrationRunner:
    def __init__(self, engine: sa.Engine) -> None:
        self.engine = engine
        _apply_identity_migration(engine)

    async def downgrade(self, revision: str) -> None:
        assert revision == "0001"
        _drop_identity_migration(self.engine)

    async def upgrade(self, revision: str) -> None:
        assert revision == "0002"
        with self.engine.begin() as connection:
            context = MigrationContext.configure(connection)
            migration = importlib.import_module(
                "apps.core.migrations.versions.0002_profiles_consent_enrollment"
            )

            migration.op = Operations(context)  # type: ignore[attr-defined]
            migration.upgrade()

    async def check_constraints(self, table: str) -> tuple[str, ...]:
        with self.engine.connect() as connection:
            return tuple(
                item["sqltext"] for item in sa.inspect(connection).get_check_constraints(table)
            )


@pytest.fixture
def migration_runner(tmp_path: Path) -> MigrationRunner:
    return MigrationRunner(_sqlite_engine(tmp_path / "migration-runner.sqlite3"))


def _seed_subject_tables(
    engine: sa.Engine, subject_id: UUID, household_id: UUID, now: datetime
) -> None:
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "INSERT OR IGNORE INTO households (id,display_label_ciphertext,timezone,created_at) "
            "VALUES (?,?,?,?)",
            (str(household_id), b"household-label", "Asia/Singapore", utc_storage(now)),
        )
        connection.exec_driver_sql(
            "INSERT OR IGNORE INTO subjects "
            "(id,household_id,guardian_id,guardian_generation,profile_class,"
            "encrypted_display_label,encrypted_persona_traits,current_consent_receipt_ids,"
            "active,authority_generation,version,next_reenrollment_reminder_at,"
            "created_at,updated_at,revoked_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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


@pytest.fixture
def file_backed_revocation_outbox_uow_factory(
    tmp_path: Path,
    clock: FakeClock,
) -> AsyncUnitOfWorkFactory:
    engine = _sqlite_engine(tmp_path / "outbox.sqlite3")
    _apply_identity_migration(engine)
    _seed_subject_tables(engine, _uuid("worker-subject"), _uuid("worker-household"), clock.now())
    return AsyncUnitOfWorkFactory(engine)


class ProcessingEventFactory(Protocol):
    def __call__(self, kind: str, *, seconds_remaining: int) -> SubjectRevocationEvent: ...


@pytest.fixture
def processing_event_factory(
    file_backed_revocation_outbox_uow_factory: AsyncUnitOfWorkFactory,
    clock: FakeClock,
) -> ProcessingEventFactory:
    subject_id = _uuid("worker-subject")

    def factory(kind: str, *, seconds_remaining: int) -> SubjectRevocationEvent:
        event_id = uuid4()
        lease_owner = uuid4()
        event = SubjectRevocationEvent(
            id=event_id,
            event_key=f"processing-{kind}-{event_id}",
            subject_id=subject_id,
            new_authority_generation=2,
            state="processing",
            occurred_at=clock.now(),
            claimed_at=clock.now(),
            lease_owner=lease_owner,
            lease_expires_at=clock.now() + timedelta(seconds=seconds_remaining),
            fencing_token=1,
            attempt_count=1,
        )
        assert event.claimed_at is not None
        assert event.lease_expires_at is not None
        with file_backed_revocation_outbox_uow_factory._engine.begin() as connection:
            connection.exec_driver_sql(
                "INSERT INTO subject_revocation_outbox "
                "(id,event_key,subject_id,new_authority_generation,state,occurred_at,"
                "claimed_at,lease_owner,lease_expires_at,fencing_token,attempt_count) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    str(event.id),
                    event.event_key,
                    str(event.subject_id),
                    event.new_authority_generation,
                    event.state,
                    utc_storage(event.occurred_at),
                    utc_storage(event.claimed_at),
                    str(event.lease_owner),
                    utc_storage(event.lease_expires_at),
                    event.fencing_token,
                    event.attempt_count,
                ),
            )
        return event

    return factory


class TestProcessor(SubjectRevocationProcessor):
    def __init__(self, handlers: Mapping[str, _OnceHandler] | None = None) -> None:
        if handlers is None:
            effects = MemoryEffectRepository()
            heartbeats = LeaseHeartbeatRunner(FakeClock())
            handlers = {
                "provider_routes": MemoryNoopHandler(effects, heartbeats, "provider_routes"),
                "search_capabilities": MemoryNoopHandler(
                    effects, heartbeats, "search_capabilities"
                ),
                "action_authorities": MemoryNoopHandler(effects, heartbeats, "action_authorities"),
                "memory_authorities": MemoryNoopHandler(effects, heartbeats, "memory_authorities"),
            }
        super().__init__(handlers)
        self._failure: BaseException | None = None
        self._family_failures: dict[str, BaseException] = {}
        self._receipt_counts: dict[UUID, int] = defaultdict(int)

    def fail(self, error: BaseException) -> None:
        self._failure = error

    def fail_family(self, family: str, error: BaseException) -> None:
        self._family_failures[family] = error

    def receipts_for(self, event_id: UUID) -> int:
        return self._receipt_counts[event_id]

    async def reconcile_once(
        self,
        event: SubjectRevocationEvent,
        *,
        idempotency_key: UUID,
        lease_owner: UUID,
        now: datetime,
    ) -> SubjectRevocationProcessingReceipt | DeferredRevocationProcessing:
        if self._failure is not None:
            raise self._failure
        if self._family_failures:
            for family in POST_COMMIT_FAMILIES:
                if family in self._family_failures:
                    raise self._family_failures[family]
        result = await super().reconcile_once(
            event,
            idempotency_key=idempotency_key,
            lease_owner=lease_owner,
            now=now,
        )
        if isinstance(result, SubjectRevocationProcessingReceipt):
            self._receipt_counts[event.id] += 1
        return result


class MemoryEffectRepository:
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
        return EffectClaim(
            "acquired", uuid4(), idempotency_key, 1, BASE_TIME + timedelta(seconds=30)
        )

    async def completed(self, idempotency_key: UUID) -> DownstreamEffectReceipt | None:
        del idempotency_key
        return None

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
        del idempotency_key, lease_owner, fencing_token, downstream, now

    async def abandon(
        self,
        idempotency_key: UUID,
        lease_owner: UUID,
        fencing_token: int,
        reason_code: str,
        now: datetime,
    ) -> None:
        del idempotency_key, lease_owner, fencing_token, reason_code, now

    async def recover_stale(self, now: datetime) -> int:
        del now
        return 0


class MemoryNoopHandler(_OnceHandler):
    def __init__(
        self, effects: EffectRepositoryPort, heartbeats: LeaseHeartbeatRunner, family: str
    ) -> None:
        super().__init__(effects, heartbeats)
        self.family = family

    async def _apply(
        self,
        event_id: UUID,
        subject_id: UUID,
        through_generation: int,
        key: UUID,
    ) -> DownstreamEffectReceipt:
        return DownstreamEffectReceipt(
            uuid5(key, "noop"),
            key,
            event_id,
            self.family,
            subject_id,
            through_generation,
            "completed_once",
        )


@pytest.fixture
def revocation_processor() -> TestProcessor:
    return TestProcessor()


@dataclass(frozen=True, slots=True)
class NetworkSummary:
    network_started_reservation_ids: tuple[UUID, ...]
    downstream_effect_receipt: DownstreamEffectReceipt
    reservations_settled_atomically: bool = False


class FakeDownstreamEffects:
    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.runtime_factory: SqlRuntimeFactory | None = None
        self.receipts: dict[UUID, DownstreamEffectReceipt] = {}
        self.duration_by_event: dict[UUID, int] = {}
        self.started_at_by_event: dict[UUID, datetime] = {}
        self.keys: tuple[UUID, ...] = ()
        self.side_effect_count = 0
        self.faults: RevocationEffectFaults | None = None

    async def enqueue(self, *, duration_seconds: int = 0) -> SubjectRevocationEvent:
        assert self.runtime_factory is not None
        runtime = await self.runtime_factory.start_without_initial_drain()
        event = await runtime.enqueue_event(_uuid("runtime-subject"))
        self.duration_by_event[event.id] = duration_seconds
        self.started_at_by_event[event.id] = self.clock.now()
        return event

    async def provider_receipt(
        self,
        *,
        event_id: UUID,
        family: str,
        subject_id: UUID,
        through_generation: int,
        idempotency_key: UUID,
    ) -> DownstreamEffectReceipt:
        if idempotency_key in self.receipts:
            return self.receipts[idempotency_key]
        duration = self.duration_by_event.get(event_id, 0)
        if duration:
            started_at = self.started_at_by_event.get(event_id, self.clock.now())
            await self.clock.sleep_until(started_at + timedelta(seconds=duration))
        receipt = DownstreamEffectReceipt(
            uuid5(idempotency_key, "provider-routes"),
            idempotency_key,
            event_id,
            family,
            subject_id,
            through_generation,
            "conservatively_settled",
        )
        self.receipts[idempotency_key] = receipt
        self.keys = (*self.keys, idempotency_key)
        self.side_effect_count += 1
        if self.faults is not None:
            self.faults.maybe_crash("downstream_effect_commit", family)
        return receipt

    async def simple_receipt(
        self,
        *,
        event_id: UUID,
        family: str,
        subject_id: UUID,
        through_generation: int,
        idempotency_key: UUID,
        disposition: str,
    ) -> DownstreamEffectReceipt:
        if idempotency_key not in self.receipts:
            self.receipts[idempotency_key] = DownstreamEffectReceipt(
                uuid5(idempotency_key, disposition),
                idempotency_key,
                event_id,
                family,
                subject_id,
                through_generation,
                disposition,
            )
        return self.receipts[idempotency_key]

    def receipt_for_key(self, key: UUID) -> DownstreamEffectReceipt | None:
        return self.receipts.get(key)

    def effect_count(self, key: UUID) -> int:
        return 1 if key in self.receipts else 0

    @staticmethod
    def fixed_key(event_id: UUID, family: str) -> UUID:
        return uuid5(event_id, family)


class FakeProviderCalls:
    def __init__(
        self,
        downstream: FakeDownstreamEffects,
        durations: Mapping[UUID, int],
    ) -> None:
        self.downstream = downstream
        self.durations = durations

    async def reconcile_revoked_subject_once(
        self,
        *,
        event_id: UUID,
        family: str,
        subject_id: UUID,
        through_generation: int,
        idempotency_key: UUID,
    ) -> NetworkSummary:
        if event_id in self.durations:
            self.downstream.duration_by_event[event_id] = self.durations[event_id]
        receipt = await self.downstream.provider_receipt(
            event_id=event_id,
            family=family,
            subject_id=subject_id,
            through_generation=through_generation,
            idempotency_key=idempotency_key,
        )
        return NetworkSummary((uuid5(idempotency_key, "reservation"),), receipt)


class FakeBudgetReservations:
    async def settle_conservative_once(
        self,
        reservation_ids: tuple[UUID, ...],
        *,
        idempotency_key: UUID,
    ) -> None:
        del reservation_ids, idempotency_key


class FakeSearchAttempts:
    def __init__(self, downstream: FakeDownstreamEffects) -> None:
        self.downstream = downstream

    async def reconcile_revocation_once(
        self,
        *,
        event_id: UUID,
        family: str,
        subject_id: UUID,
        through_generation: int,
        idempotency_key: UUID,
    ) -> DownstreamEffectReceipt:
        return await self.downstream.simple_receipt(
            event_id=event_id,
            family=family,
            subject_id=subject_id,
            through_generation=through_generation,
            idempotency_key=idempotency_key,
            disposition="cancelled",
        )


class FakeMemoryProposals:
    def __init__(self, downstream: FakeDownstreamEffects) -> None:
        self.downstream = downstream

    async def reconcile_subject_revocation_once(
        self,
        *,
        event_id: UUID,
        family: str,
        subject_id: UUID,
        through_generation: int,
        idempotency_key: UUID,
    ) -> DownstreamEffectReceipt:
        return await self.downstream.simple_receipt(
            event_id=event_id,
            family=family,
            subject_id=subject_id,
            through_generation=through_generation,
            idempotency_key=idempotency_key,
            disposition="completed_once",
        )


class FacadeFactory:
    def __init__(self, value: object) -> None:
        self._value = value

    def bind(self, uow: object) -> object:
        del uow
        return self._value


class SimulatedProcessCrash(BaseException):
    pass


class RevocationEffectFaults:
    def __init__(self) -> None:
        self.boundary: str | None = None
        self.family: str | None = None
        self.triggered = False

    def crash_after(self, boundary: str, *, family: str) -> None:
        self.boundary = boundary
        self.family = family
        self.triggered = False

    def maybe_crash(self, boundary: str, family: str) -> None:
        if not self.triggered and self.boundary == boundary and self.family == family:
            self.triggered = True
            raise SimulatedProcessCrash("simulated_process_crash")


class EffectRepositoryWithStats:
    def __init__(
        self,
        uow_factory: AsyncUnitOfWorkFactory,
        faults: RevocationEffectFaults | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._delegate = SubjectRevocationEffectRepository(
            cast(IdentityUnitOfWorkFactory, uow_factory)
        )
        self._faults = faults
        self._counts: dict[UUID, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._dispositions: dict[UUID, dict[str, str]] = defaultdict(dict)

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
        claim = await self._delegate.claim(
            idempotency_key,
            event_id=event_id,
            family=family,
            subject_id=subject_id,
            through_generation=through_generation,
            lease_owner=lease_owner,
            now=now,
        )
        if claim.status == "acquired" and self._faults is not None:
            self._faults.maybe_crash("effect_claim_commit", family)
        return claim

    async def completed(self, idempotency_key: UUID) -> DownstreamEffectReceipt | None:
        return await self._delegate.completed(idempotency_key)

    async def renew(
        self,
        idempotency_key: UUID,
        lease_owner: UUID,
        fencing_token: int,
        now: datetime,
    ) -> bool:
        return await self._delegate.renew(idempotency_key, lease_owner, fencing_token, now)

    async def complete(
        self,
        idempotency_key: UUID,
        lease_owner: UUID,
        fencing_token: int,
        downstream: DownstreamEffectReceipt,
        now: datetime,
    ) -> None:
        await self._delegate.complete(idempotency_key, lease_owner, fencing_token, downstream, now)
        self._counts[downstream.event_id][downstream.family] += 1
        self._dispositions[downstream.event_id][downstream.family] = downstream.disposition
        if self._faults is not None:
            self._faults.maybe_crash("effect_complete_commit", downstream.family)

    async def abandon(
        self,
        idempotency_key: UUID,
        lease_owner: UUID,
        fencing_token: int,
        reason_code: str,
        now: datetime,
    ) -> None:
        await self._delegate.abandon(idempotency_key, lease_owner, fencing_token, reason_code, now)

    async def recover_stale(self, now: datetime) -> int:
        return await self._delegate.recover_stale(now)

    async def state(self, effect_id: UUID) -> str:
        return await self._delegate.state(effect_id)

    async def lease_owner(self, effect_id: UUID) -> UUID | None:
        return await self._delegate.lease_owner(effect_id)

    def counts(self, event_id: UUID) -> dict[str, int]:
        return {family: self._counts[event_id].get(family, 0) for family in POST_COMMIT_FAMILIES}

    def dispositions(self, event_id: UUID) -> dict[str, str]:
        return dict(self._dispositions[event_id])

    @staticmethod
    def fixed_key(event_id: UUID, family: str) -> UUID:
        return uuid5(event_id, family)


class CrashCapturingSubjectRevocationWorker(SubjectRevocationWorker):
    def __init__(
        self,
        repository: SubjectRevocationOutboxRepository,
        processor: SubjectRevocationProcessor,
        heartbeats: LeaseHeartbeatRunner,
        clock: FakeClock,
    ) -> None:
        super().__init__(repository, processor, heartbeats, clock)
        self.repository = repository
        self.clock = clock
        self._background: asyncio.Task[None] | None = None
        self._failure: BaseException | None = None

    def attach_background(self, task: asyncio.Task[None]) -> None:
        self._background = task

        def done(completed: asyncio.Task[None]) -> None:
            try:
                completed.result()
            except BaseException as error:
                self._failure = error

        task.add_done_callback(done)

    async def wait_for_crash(self) -> None:
        if self._background is not None:
            with suppress(TimeoutError):
                await asyncio.wait_for(asyncio.shield(self._background), timeout=1.0)
        if self._failure is not None:
            raise self._failure
        raise AssertionError("worker did not crash")

    async def complete_with_stale_fence(
        self,
        old_claim: OutboxClaim,
        receipt: DownstreamEffectReceipt,
    ) -> None:
        await self.repository.complete(
            old_claim.event.id,
            receipt.id,
            old_claim.lease_owner,
            old_claim.fencing_token,
            self.clock.now(),
        )


@dataclass(frozen=True, slots=True)
class DrainResult:
    completed_event_ids: tuple[UUID, ...]


class SqlIdentityRuntime:
    def __init__(
        self,
        *,
        engine: sa.Engine,
        uow_factory: AsyncUnitOfWorkFactory,
        clock: FakeClock,
        downstream_effects: FakeDownstreamEffects,
        revocation_effects: EffectRepositoryWithStats,
        revocation_outbox: SubjectRevocationOutboxRepository,
        revocation_processor: TestProcessor,
        revocation_worker: CrashCapturingSubjectRevocationWorker,
        subject_id: UUID,
        household_id: UUID,
        background: asyncio.Task[None] | None = None,
    ) -> None:
        self.engine = engine
        self.uow_factory = uow_factory
        self.clock = clock
        self.downstream_effects = downstream_effects
        self.revocation_effects = revocation_effects
        self.revocation_outbox = revocation_outbox
        self.revocation_processor = revocation_processor
        self.revocation_worker = revocation_worker
        self.subject_id = subject_id
        self.household_id = household_id
        self._background = background
        self._stop = asyncio.Event()
        self.ready = True
        self.process_restart_count = 0
        self.network_capture: list[object] = []

    async def start(self) -> SqlIdentityRuntime:
        await self.revocation_worker.recover_and_drain_before_ready()
        task = asyncio.create_task(
            self.revocation_worker.run_periodically(
                self._stop,
                lambda _error: setattr(self, "ready", False),
            )
        )
        self.revocation_worker.attach_background(task)
        await self.revocation_worker.wait_running()
        return self

    async def start_without_initial_drain(self) -> SqlIdentityRuntime:
        return self

    async def restart(self) -> SqlIdentityRuntime:
        self.process_restart_count += 1
        return _runtime_from_engine(
            self.engine,
            self.clock,
            self.downstream_effects,
            None,
            subject_id=self.subject_id,
            household_id=self.household_id,
        )

    async def enqueue_event(self, subject_id: UUID | None = None) -> SubjectRevocationEvent:
        resolved_subject = subject_id or self.subject_id
        _seed_subject_tables(self.engine, resolved_subject, self.household_id, self.clock.now())
        event_key = f"subject-revoked:{resolved_subject}:{uuid4()}"
        async with self.uow_factory() as uow:
            event = await self.revocation_outbox.enqueue_in_uow(
                uow,
                event_key=event_key,
                subject_id=resolved_subject,
                new_authority_generation=2,
                occurred_at=self.clock.now(),
            )
            await uow.commit()
        assert event is not None
        self.revocation_worker.offer_nowait()
        return event

    async def revoke_profile(self, subject: Profile, grant: GrantHandle) -> SubjectRevocationEvent:
        del grant
        return await self.enqueue_event(subject.id)

    async def drain_subject_revocations(self) -> DrainResult:
        before = self.revocation_worker.completed_event_ids
        await self.revocation_worker.run_one_periodic_drain()
        after = self.revocation_worker.completed_event_ids
        return DrainResult(after[len(before) :])

    async def wait_for_revocation_worker_failure(self) -> None:
        await self.revocation_worker.wait_for_crash()

    def audit_count(self, event_id: UUID) -> int:
        return 1 if event_id in self.revocation_worker.completed_event_ids else 0

    async def try_each(self, authorities: frozenset[str]) -> dict[str, AuthorityOutcome]:
        return {
            family: AuthorityOutcome("current_subject_authority_required") for family in authorities
        }


def _runtime_from_engine(
    engine: sa.Engine,
    clock: FakeClock,
    downstream: FakeDownstreamEffects,
    faults: RevocationEffectFaults | None,
    *,
    subject_id: UUID,
    household_id: UUID,
) -> SqlIdentityRuntime:
    durations = downstream.duration_by_event
    provider_calls = FakeProviderCalls(downstream, durations)
    search = FakeSearchAttempts(downstream)
    budget = FakeBudgetReservations()
    uow_factory = AsyncUnitOfWorkFactory(
        engine,
        {
            "provider_calls": FacadeFactory(provider_calls),
            "budget_reservations": FacadeFactory(budget),
            "experimental_search_attempts": FacadeFactory(search),
        },
    )
    identity_uow_factory = cast(IdentityUnitOfWorkFactory, uow_factory)
    effects = EffectRepositoryWithStats(uow_factory, faults)
    heartbeats = LeaseHeartbeatRunner(clock)
    stage = Task1CapabilityStage()
    handlers: dict[str, _OnceHandler] = {
        "provider_routes": ProviderRouteRevocationHandler(
            effects, heartbeats, identity_uow_factory
        ),
        "search_capabilities": SearchAuthorityRevocationHandler(
            effects,
            heartbeats,
            identity_uow_factory,
            feature_state="present",
        ),
        "action_authorities": NotInstalledAuthorityRevocationHandler(
            effects,
            heartbeats,
            stage,
            family="action_authorities",
            owning_revision="0003_authentication",
        ),
        "memory_authorities": NotInstalledAuthorityRevocationHandler(
            effects,
            heartbeats,
            stage,
            family="memory_authorities",
            owning_revision="0004_memory",
        ),
    }
    processor = TestProcessor(handlers)
    outbox = SubjectRevocationOutboxRepository(identity_uow_factory)
    worker = CrashCapturingSubjectRevocationWorker(outbox, processor, heartbeats, clock)
    uow_factory.register_commit_signal("subject_revocation", worker)
    return SqlIdentityRuntime(
        engine=engine,
        uow_factory=uow_factory,
        clock=clock,
        downstream_effects=downstream,
        revocation_effects=effects,
        revocation_outbox=outbox,
        revocation_processor=processor,
        revocation_worker=worker,
        subject_id=subject_id,
        household_id=household_id,
    )


class SqlRuntimeFactory:
    def __init__(
        self, tmp_path: Path, clock: FakeClock, faults: RevocationEffectFaults | None = None
    ) -> None:
        self.engine = _sqlite_engine(tmp_path / f"runtime-{uuid4()}.sqlite3")
        _apply_identity_migration(self.engine)
        self.clock = clock
        self.subject_id = _uuid(f"runtime-subject-{uuid4()}")
        self.household_id = _uuid(f"runtime-household-{uuid4()}")
        _seed_subject_tables(self.engine, self.subject_id, self.household_id, clock.now())
        self.downstream = FakeDownstreamEffects(clock)
        self.downstream.runtime_factory = self
        self.faults = faults
        self.downstream.faults = faults

    async def start(self) -> SqlIdentityRuntime:
        runtime = _runtime_from_engine(
            self.engine,
            self.clock,
            self.downstream,
            self.faults,
            subject_id=self.subject_id,
            household_id=self.household_id,
        )
        return await runtime.start()

    async def start_without_initial_drain(self) -> SqlIdentityRuntime:
        return _runtime_from_engine(
            self.engine,
            self.clock,
            self.downstream,
            self.faults,
            subject_id=self.subject_id,
            household_id=self.household_id,
        )

    async def restart(self) -> SqlIdentityRuntime:
        return _runtime_from_engine(
            self.engine,
            self.clock,
            self.downstream,
            None,
            subject_id=self.subject_id,
            household_id=self.household_id,
        )


@pytest.fixture
def task1_identity_runtime(
    tmp_path: Path,
    clock: FakeClock,
) -> SqlRuntimeFactory:
    return SqlRuntimeFactory(tmp_path, clock)


@pytest.fixture
def revocation_effect_faults() -> RevocationEffectFaults:
    return RevocationEffectFaults()


@pytest.fixture
def task1_file_backed_identity_runtime(
    tmp_path: Path,
    clock: FakeClock,
    revocation_effect_faults: RevocationEffectFaults,
) -> SqlRuntimeFactory:
    return SqlRuntimeFactory(tmp_path, clock, revocation_effect_faults)


@pytest.fixture
def long_running_downstream(
    task1_identity_runtime: SqlRuntimeFactory,
) -> FakeDownstreamEffects:
    return task1_identity_runtime.downstream


@dataclass(frozen=True, slots=True)
class WorkerPair:
    first: CrashCapturingSubjectRevocationWorker
    second: CrashCapturingSubjectRevocationWorker
    stale_fence_completions: int = 0

    def __iter__(self) -> Iterator[CrashCapturingSubjectRevocationWorker]:
        yield self.first
        yield self.second


class CrashDownstreamScenario(Protocol):
    effect_count: Callable[[UUID], int]

    def __call__(
        self,
        first: CrashCapturingSubjectRevocationWorker,
    ) -> Awaitable[tuple[SubjectRevocationEvent, OutboxClaim, DownstreamEffectReceipt]]: ...


@pytest_asyncio.fixture
async def two_revocation_workers(
    task1_identity_runtime: SqlRuntimeFactory,
) -> WorkerPair:
    runtime1 = await task1_identity_runtime.start_without_initial_drain()
    runtime2 = await task1_identity_runtime.restart()
    return WorkerPair(runtime1.revocation_worker, runtime2.revocation_worker)


@pytest_asyncio.fixture
async def restarted_identity_runtime(
    task1_identity_runtime: SqlRuntimeFactory,
) -> SqlIdentityRuntime:
    return await task1_identity_runtime.restart()


@pytest.fixture
def crash_after_profile_revocation_commit(
    task1_identity_runtime: SqlRuntimeFactory,
) -> Callable[[], object]:
    async def scenario() -> UUID:
        runtime = await task1_identity_runtime.start_without_initial_drain()
        event = await runtime.enqueue_event()
        return event.id

    return scenario


@pytest.fixture
def crash_after_downstream_commit(
    task1_identity_runtime: SqlRuntimeFactory,
    clock: FakeClock,
) -> CrashDownstreamScenario:
    async def scenario(
        first: CrashCapturingSubjectRevocationWorker,
    ) -> tuple[SubjectRevocationEvent, OutboxClaim, DownstreamEffectReceipt]:
        runtime = await task1_identity_runtime.start_without_initial_drain()
        event = await runtime.enqueue_event()
        claim = await runtime.revocation_outbox.claim_next(clock.now(), uuid4())
        assert claim is not None
        key = uuid5(event.id, "provider_routes")
        effect_claim = await runtime.revocation_effects.claim(
            key,
            event_id=event.id,
            family="provider_routes",
            subject_id=event.subject_id,
            through_generation=1,
            lease_owner=claim.lease_owner,
            now=clock.now(),
        )
        assert effect_claim.fencing_token is not None
        receipt = await runtime.downstream_effects.provider_receipt(
            event_id=event.id,
            family="provider_routes",
            subject_id=event.subject_id,
            through_generation=1,
            idempotency_key=key,
        )
        await runtime.revocation_effects.complete(
            key,
            claim.lease_owner,
            effect_claim.fencing_token,
            receipt,
            clock.now(),
        )
        first.repository = runtime.revocation_outbox
        return event, claim, receipt

    scenario_with_stats = cast(CrashDownstreamScenario, scenario)
    scenario_with_stats.effect_count = lambda key: task1_identity_runtime.downstream.effect_count(
        key
    )
    return scenario_with_stats


class Task1Bootstrap:
    def __init__(
        self,
        repository: SubjectRevocationOutboxRepository,
        worker: SubjectRevocationWorker,
        processor: TestProcessor,
        clock: FakeClock,
    ) -> None:
        self.repository = repository
        self.worker = worker
        self.processor = processor
        self.clock = clock
        self.ready = False
        self._unsafe_state: str | None = None

    def configure_revocation_state(self, unsafe_state: str) -> None:
        self._unsafe_state = unsafe_state

    async def start(self) -> None:
        self.ready = False
        if self._unsafe_state == "worker_unavailable":
            raise RuntimeError("subject revocation worker unavailable")
        if self._unsafe_state == "backlog_over_limit":
            raise RuntimeError("subject revocation backlog unsafe")
        await self.worker.recover_and_drain_before_ready()
        self.ready = True


@pytest.fixture
def task1_identity_bootstrap(
    tmp_path: Path,
    clock: FakeClock,
    revocation_processor: TestProcessor,
) -> Task1Bootstrap:
    engine = _sqlite_engine(tmp_path / "bootstrap.sqlite3")
    _apply_identity_migration(engine)
    subject_id = _uuid("bootstrap-subject")
    household_id = _uuid("bootstrap-household")
    _seed_subject_tables(engine, subject_id, household_id, clock.now())
    uow_factory = AsyncUnitOfWorkFactory(engine)
    outbox = SubjectRevocationOutboxRepository(cast(IdentityUnitOfWorkFactory, uow_factory))
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "INSERT INTO subject_revocation_outbox "
            "(id,event_key,subject_id,new_authority_generation,state,occurred_at,"
            "fencing_token,attempt_count) VALUES (?,?,?,?,?,?,?,?)",
            (
                str(uuid4()),
                f"bootstrap-{uuid4()}",
                str(subject_id),
                2,
                "pending",
                utc_storage(clock.now()),
                0,
                0,
            ),
        )
    worker = SubjectRevocationWorker(outbox, revocation_processor, clock.heartbeats, clock)
    return Task1Bootstrap(outbox, worker, revocation_processor, clock)


@pytest.fixture
def task1_identity_container(
    tmp_path: Path,
    clock: FakeClock,
) -> Task1IdentityContainer:
    engine = _sqlite_engine(tmp_path / "container.sqlite3")
    _apply_identity_migration(engine)
    keys = task1_test_identity_keys()
    return build_task1_identity_container(
        build_task1_sqlcipher_uow_factory(engine, clock, keys),
        clock,
        keys,
    )


@pytest.fixture
def absent_search_identity_container(
    tmp_path: Path,
    clock: FakeClock,
) -> Task1IdentityContainer:
    engine = _sqlite_engine(tmp_path / "absent-search.sqlite3")
    _apply_identity_migration(engine)
    keys = task1_test_identity_keys()
    return build_task1_identity_container(
        build_task1_sqlcipher_uow_factory(engine, clock, keys),
        clock,
        keys,
        search_feature_state="absent",
    )


@dataclass(frozen=True, slots=True)
class ClaimedEffect:
    id: UUID
    idempotency_key: UUID
    lease_owner: UUID
    fencing_token: int
    now: datetime


@dataclass(frozen=True, slots=True)
class EffectClaimContext:
    repository: EffectRepositoryWithStats
    claim: ClaimedEffect
    receipt: DownstreamEffectReceipt


@pytest_asyncio.fixture
async def effect_claim_context(
    tmp_path: Path,
    clock: FakeClock,
) -> EffectClaimContext:
    engine = _sqlite_engine(tmp_path / "claimed-effect.sqlite3")
    _apply_identity_migration(engine)
    subject_id = _uuid("claimed-effect-subject")
    household_id = _uuid("claimed-effect-household")
    _seed_subject_tables(engine, subject_id, household_id, clock.now())
    uow_factory = AsyncUnitOfWorkFactory(engine)
    outbox = SubjectRevocationOutboxRepository(cast(IdentityUnitOfWorkFactory, uow_factory))
    async with uow_factory() as uow:
        event = await outbox.enqueue_in_uow(
            uow,
            event_key=f"claimed-effect-{uuid4()}",
            subject_id=subject_id,
            new_authority_generation=2,
            occurred_at=clock.now(),
        )
        await uow.commit()
    assert event is not None
    effects = EffectRepositoryWithStats(uow_factory)
    key = uuid5(event.id, "provider_routes")
    lease_owner = uuid4()
    claim = await effects.claim(
        key,
        event_id=event.id,
        family="provider_routes",
        subject_id=subject_id,
        through_generation=1,
        lease_owner=lease_owner,
        now=clock.now(),
    )
    assert claim.fencing_token is not None
    receipt = DownstreamEffectReceipt(
        uuid5(key, "provider-routes"),
        key,
        event.id,
        "provider_routes",
        subject_id,
        1,
        "conservatively_settled",
    )
    return EffectClaimContext(
        effects,
        ClaimedEffect(claim.id, key, lease_owner, claim.fencing_token, clock.now()),
        receipt,
    )


@pytest.fixture
def claimed_revocation_effect(
    effect_claim_context: EffectClaimContext,
) -> tuple[ClaimedEffect, DownstreamEffectReceipt]:
    return effect_claim_context.claim, effect_claim_context.receipt


@pytest.fixture
def revocation_effects(effect_claim_context: EffectClaimContext) -> EffectRepositoryWithStats:
    return effect_claim_context.repository


@pytest.fixture
def downstream_receipt_variant() -> Callable[
    [DownstreamEffectReceipt, str], DownstreamEffectReceipt
]:
    def factory(receipt: DownstreamEffectReceipt, changed: str) -> DownstreamEffectReceipt:
        idempotency_key = uuid4() if changed == "idempotency_key" else receipt.idempotency_key
        event_id = uuid4() if changed == "event_id" else receipt.event_id
        family = "search_capabilities" if changed == "family" else receipt.family
        subject_id = uuid4() if changed == "subject_id" else receipt.subject_id
        through_generation = (
            receipt.through_generation + 1
            if changed == "through_generation"
            else receipt.through_generation
        )
        return DownstreamEffectReceipt(
            receipt.id,
            idempotency_key,
            event_id,
            family,
            subject_id,
            through_generation,
            receipt.disposition,
        )

    return factory


@pytest_asyncio.fixture
async def stale_and_live_effect_claims(
    task1_identity_runtime: SqlRuntimeFactory,
    clock: FakeClock,
) -> tuple[ClaimedEffect, ClaimedEffect]:
    runtime = await task1_identity_runtime.start_without_initial_drain()
    stale_event = await runtime.enqueue_event()
    live_event = await runtime.enqueue_event()
    old_owner = uuid4()
    with runtime.engine.begin() as connection:
        for event, offset in ((stale_event, -1), (live_event, 30)):
            key = uuid5(event.id, "provider_routes")
            effect_id = uuid5(key, "effect-row")
            connection.exec_driver_sql(
                "INSERT INTO subject_revocation_effects "
                "(id,event_id,family,idempotency_key,state,lease_owner,leased_until,"
                "fencing_token,attempt_count,created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    str(effect_id),
                    str(event.id),
                    "provider_routes",
                    str(key),
                    "applying",
                    str(old_owner),
                    utc_storage(clock.now() + timedelta(seconds=offset)),
                    1,
                    1,
                    utc_storage(clock.now()),
                ),
            )
    return (
        ClaimedEffect(
            uuid5(uuid5(stale_event.id, "provider_routes"), "effect-row"),
            uuid5(stale_event.id, "provider_routes"),
            old_owner,
            1,
            clock.now(),
        ),
        ClaimedEffect(
            uuid5(uuid5(live_event.id, "provider_routes"), "effect-row"),
            uuid5(live_event.id, "provider_routes"),
            old_owner,
            1,
            clock.now(),
        ),
    )
