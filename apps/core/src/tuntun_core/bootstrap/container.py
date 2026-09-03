from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from uuid import UUID

from fastapi import FastAPI
from fastapi.routing import APIRoute
from sqlalchemy import Engine
from tuntun_contracts.ports import ClockPort, RouteAuthorizerPort
from tuntun_core.adapters.reachy.authenticated_control import AuthenticatedControlClient
from tuntun_core.adapters.reachy.current_session import (
    CoreDisconnectSafetyFacade,
    CurrentReachySessionChannel,
)
from tuntun_core.adapters.reachy.gateway import ReachyGateway
from tuntun_core.adapters.reachy.session import CoreReachySession, ReachyTransportSupervisorState
from tuntun_core.adapters.reachy.wss_server import (
    DeviceRegistry as ReachyDeviceRegistry,
)
from tuntun_core.adapters.reachy.wss_server import (
    DuplexState as ReachyDuplexState,
)
from tuntun_core.adapters.reachy.wss_server import (
    Endpoint as ReachyEndpoint,
)
from tuntun_core.adapters.reachy.wss_server import (
    Handler as ReachyHandler,
)
from tuntun_core.adapters.reachy.wss_server import (
    PairingKeys as ReachyPairingKeys,
)
from tuntun_core.adapters.reachy.wss_server import (
    ReachyWssServer,
)
from tuntun_core.adapters.reachy.wss_server import (
    SessionFactory as ReachySessionFactory,
)
from tuntun_core.adapters.reachy.wss_server import (
    TimeIssuer as ReachyTimeIssuer,
)
from tuntun_core.adapters.sqlcipher.async_unit_of_work import AsyncUnitOfWorkFactory
from tuntun_core.adapters.sqlcipher.identity_repositories import (
    SqlBudgetReservationsRevocationPort,
    SqlProviderCallsRevocationPort,
    task1_identity_repository_facades,
)
from tuntun_core.adapters.sqlcipher.subject_revocation_effect_repository import (
    SubjectRevocationEffectRepository,
)
from tuntun_core.adapters.sqlcipher.subject_revocation_outbox_repository import (
    SubjectRevocationOutboxRepository,
)
from tuntun_core.api.app import create_app
from tuntun_core.api.dependencies import ReadinessDependency, SimulatedGuestAppDependencies
from tuntun_core.bootstrap.lifecycle import (
    BudgetReconciliationSupervisor,
    CoreProcessLease,
    ProductionReachyLifecycle,
    StartupTurnRecovery,
    start_identity_runtime,
)
from tuntun_core.domain.profile import ConsentPurpose
from tuntun_core.services.actions.parameter_binding import (
    ActionBindingVerifier,
    ActionParameterBindingVerifier,
)
from tuntun_core.services.audit.ledger import AsyncAuditLedger, AuditLedger
from tuntun_core.services.budget.catalog import PriceCatalog
from tuntun_core.services.budget.evidence import BudgetEvidenceService
from tuntun_core.services.budget.guard import BudgetGuard
from tuntun_core.services.budget.reconciler import ExpiredBudgetReconciler
from tuntun_core.services.context_builder import ContextBuilder
from tuntun_core.services.identity.consent import (
    CloudRouteConsentRevocationHandler,
    ConsentRevocationCascade,
    ConsentService,
    GuestSessionConsentService,
    IdentityMutationCoordinator,
)
from tuntun_core.services.identity.enrollment import (
    EnrollmentMutationCoordinator,
    EnrollmentService,
)
from tuntun_core.services.identity.profiles import ProfileCrypto, ProfileService
from tuntun_core.services.identity.revocation_handlers import BiometricConsentRevocationHandler
from tuntun_core.services.identity.runtime import (
    HmacReceiptSigner,
    IdentityAuditLedger,
    IdentityUnitOfWorkContextFactory,
    PrivateCommitmentService,
    SqlIdentityMutationScope,
    Task1ConsentRevocationAuditMapper,
    Task1IdentityKeyBundle,
    Task1IdentityKeyProviderPort,
    Task1IdentityMutationServices,
    UnavailableTask1Authentication,
)
from tuntun_core.services.identity.subject_revocation import (
    BiometricTemplateSubjectAuthorityRevocationHandler,
    CapabilityStagePort,
    ConsentSubjectAuthorityRevocationHandler,
    EnrollmentSubjectAuthorityRevocationHandler,
    NotInstalledSubjectAuthorityHandler,
    ProviderRouteSubjectAuthorityRevocationHandler,
    SearchCapabilitySubjectAuthorityRevocationHandler,
    SessionSubjectAuthorityRevocationHandler,
    SqlProviderRouteAuthorityRevocation,
    SubjectAuthorityRevocationCascade,
    SubjectAuthorityRevocationHandler,
)
from tuntun_core.services.identity.subject_revocation_handlers import (
    BudgetReservationsRevocationPort,
    LeaseHeartbeatRunner,
    NotInstalledAuthorityRevocationHandler,
    ProviderCallsRevocationPort,
    ProviderRouteRevocationHandler,
    SearchAuthorityRevocationHandler,
    _OnceHandler,
)
from tuntun_core.services.identity.subject_revocation_handlers import (
    ClockPort as RevocationHandlerClockPort,
)
from tuntun_core.services.identity.subject_revocation_processor import SubjectRevocationProcessor
from tuntun_core.services.persona_builder import PersonaBuilder
from tuntun_core.services.personalized_turn_context import (
    IdentityContextPort,
    PersonalizedTurnContextProvider,
    ProfileProjectionPort,
    SessionLanguageRegistry,
)
from tuntun_core.services.providers.call_repository import ProviderCallRepository
from tuntun_core.services.providers.consent_guard import ConsentEvidenceService, ConsentHmacVerifier
from tuntun_core.services.providers.defaults import (
    ProviderDefaultsDocumentV1,
    load_provider_defaults,
)
from tuntun_core.services.providers.gateway import ProviderGateway
from tuntun_core.services.providers.redaction_repository import (
    RedactionReceiptRepository,
)
from tuntun_core.services.providers.review import (
    RuntimeProviderIdentityReader,
    SqlcipherCurrentProviderReviews,
)
from tuntun_core.services.sessions.manager import SessionManager
from tuntun_core.services.sessions.turn_coordinator import TurnCoordinator
from tuntun_core.services.transactions.identity_uow import (
    IdentityUnitOfWork,
    IdentityUnitOfWorkFactory,
)
from tuntun_core.services.transactions.protocols import UnitOfWorkProtocol
from tuntun_core.workers.subject_revocation_worker import (
    ClockPort as RevocationWorkerClockPort,
)
from tuntun_core.workers.subject_revocation_worker import SubjectRevocationWorker
from tuntun_core.workflows.contract_workflow import (
    CompletedTurnAudioPort,
    ContractConversationWorkflow,
    ConversationEngine,
)
from tuntun_core.workflows.conversation import (
    ContextWorkflowPorts,
    LinearConversationEngine,
    ProviderEgressAuthorizer,
    ProviderEgressBoundary,
    WorkflowPorts,
)
from tuntun_core.workflows.langgraph_adapter import LangGraphConversationEngine

_SIMULATED_GUEST_ROUTE_NAMES = frozenset(
    {"health.ready", "session.simulated_end", "session.simulated_turn"}
)
_LOOPBACK_LISTENER_BINDINGS = frozenset({"loopback"})
SEARCH_FEATURE_HEAD = "search_0001_experimental_search"
SEARCH_VERSION_TABLE = "alembic_version_experimental_search"
TASK1_REQUIRED_IDENTITY_REPOSITORY_FACADES = frozenset(
    {
        "profiles",
        "consent_receipts",
        "guest_disclosure_challenges",
        "guest_session_consents",
        "enrollments",
        "biometric_templates",
        "sessions",
        "event_receipts",
        "subject_revocation_outbox",
        "subject_revocation_effects",
        "provider_calls",
        "budget_reservations",
    }
)
_CAPABILITY_OWNER_REVISIONS = {
    "search_capabilities": SEARCH_FEATURE_HEAD,
    "action_authorities": "0003_authentication",
    "memory_authorities": "0004_memory",
}
_CAPABILITY_FACADE_NAMES = {
    "search_capabilities": ("search_capabilities", "experimental_search_attempts"),
    "action_authorities": (),
    "memory_authorities": (),
}
_CAPABILITY_SCHEMA_NAMES = {
    "search_capabilities": (
        SEARCH_VERSION_TABLE,
        "search_capabilities",
        "experimental_search_attempts",
    ),
    "action_authorities": ("action_authorities", "action_proposals", "action_claims"),
    "memory_authorities": ("memory_authorities", "memory_proposals"),
}


class CurrentProviderReviews(Protocol):
    def require_current(
        self,
        uow: UnitOfWorkProtocol,
        provider: str,
        model: str,
        purpose: str,
        now: datetime,
    ) -> object: ...


class CoreContainer:
    """Sole production provider stack after Task 05 activates live egress."""

    __slots__ = (
        "sqlcipher_uow_factory",
        "clock",
        "route_authorizer",
        "budget_evidence",
        "budget_guard",
        "redaction_receipt_repository",
        "provider_call_repository",
        "provider_gateway",
    )

    def __init__(
        self,
        *,
        sqlcipher_uow_factory: AsyncUnitOfWorkFactory,
        clock: ClockPort,
        route_authorizer: RouteAuthorizerPort,
        price_catalog: PriceCatalog,
        provider_reviews: CurrentProviderReviews,
        budget_evidence: BudgetEvidenceService,
        provider_defaults: ProviderDefaultsDocumentV1,
    ) -> None:
        if type(budget_evidence) is not BudgetEvidenceService:
            raise TypeError("production budget evidence service required")
        if type(provider_defaults) is not ProviderDefaultsDocumentV1:
            raise TypeError("validated provider defaults document required")
        self.sqlcipher_uow_factory = sqlcipher_uow_factory
        self.clock = clock
        self.route_authorizer = route_authorizer
        self.budget_evidence = budget_evidence
        self.redaction_receipt_repository = RedactionReceiptRepository(
            sqlcipher_uow_factory,
            clock,
        )
        self.budget_guard = BudgetGuard(
            sqlcipher_uow_factory,
            clock,
            price_catalog,
            provider_reviews,
            budget_evidence,
            hard_limit=provider_defaults.budget.hard_limit_micros_sgd,
            soft_limit=provider_defaults.budget.soft_limit_micros_sgd,
            reservation_expiry_seconds=provider_defaults.budget.reservation_expiry_seconds,
        )
        self.provider_call_repository = ProviderCallRepository(
            sqlcipher_uow_factory,
            clock,
            self.redaction_receipt_repository,
            budget_evidence,
        )
        self.provider_gateway = ProviderGateway(
            route_authorizer,
            self.budget_guard,
            self.provider_call_repository,
            budget_evidence,
            clock,
        )


@dataclass(frozen=True, slots=True)
class SimulatedGuestComposition:
    app: FastAPI
    workflow: ContractConversationWorkflow
    dependencies: SimulatedGuestAppDependencies
    linear_engine: LinearConversationEngine | None = None
    langgraph_engine: LangGraphConversationEngine | None = None
    context_provider: PersonalizedTurnContextProvider | None = None


@dataclass(frozen=True, slots=True)
class InstalledSimulatedGuestApp:
    composition: SimulatedGuestComposition
    coordinator: TurnCoordinator
    session_manager: SessionManager
    household_id: UUID
    device_id: UUID
    loopback_host: str
    readiness_dependencies: tuple[ReadinessDependency, ...]
    route_ids: set[str]
    duplicate_route_ids: tuple[str, ...]
    listener_bindings: frozenset[str]


class _IdentityRuntimeTaskRegistry:
    def __init__(self, observe_done: Callable[[asyncio.Task[None]], None]) -> None:
        self._observe_done = observe_done
        self._tasks: set[asyncio.Task[None]] = set()

    def create_task(
        self,
        coroutine: Coroutine[object, object, None],
    ) -> asyncio.Task[None]:
        task = asyncio.create_task(coroutine, name="subject-revocation-worker")
        self._tasks.add(task)
        task.add_done_callback(self._discard_task)
        task.add_done_callback(self._observe_done)
        return task

    def _discard_task(self, task: asyncio.Task[None]) -> None:
        self._tasks.discard(task)

    @property
    def tasks(self) -> tuple[asyncio.Task[None], ...]:
        return tuple(self._tasks)


class Task1IdentityRuntimeSupervisor:
    """Production readiness boundary for Task 1 subject-authority revocation."""

    __slots__ = ("identity", "_readiness", "_stop", "_tasks", "_started", "_failure_code")

    def __init__(self, identity: Task1IdentityContainer) -> None:
        self.identity = identity
        self._readiness = asyncio.Event()
        self._stop = asyncio.Event()
        self._tasks = _IdentityRuntimeTaskRegistry(self._observe_worker_done)
        self._started = False
        self._failure_code: str | None = "not_started"

    async def start(self) -> None:
        if self._started or self._tasks.tasks:
            raise RuntimeError("identity_revocation_runtime_already_started")
        self._stop = asyncio.Event()
        self._tasks = _IdentityRuntimeTaskRegistry(self._observe_worker_done)
        self._failure_code = "starting"
        try:
            await start_identity_runtime(
                self.identity.post_commit_revocation_handlers,
                self.identity.revocation_worker,
                self._readiness,
                self._tasks,
                self._stop,
            )
        except RuntimeError:
            await self._cleanup_failed_start()
            raise
        except BaseException as error:
            await self._cleanup_failed_start()
            raise RuntimeError("identity_revocation_runtime_unhealthy") from error
        if not self._readiness.is_set() or not self._tasks.tasks:
            await self._cleanup_failed_start()
            raise RuntimeError("identity_revocation_runtime_unhealthy")
        self._started = True
        self._failure_code = None

    async def _cleanup_failed_start(self) -> None:
        self._readiness.clear()
        self._stop.set()
        self.identity.revocation_worker.offer_nowait()
        try:
            await self._cancel_workers()
        finally:
            await self.identity.uow_factory.aclose()

    def _observe_worker_done(self, task: asyncio.Task[None]) -> None:
        self._readiness.clear()
        if self._stop.is_set():
            return
        try:
            task.result()
        except asyncio.CancelledError:
            self._failure_code = "worker:unexpected_cancel"
        except BaseException as error:
            self._failure_code = f"worker:{type(error).__name__}"
        else:
            self._failure_code = "worker:unexpected_exit"

    def require_ready(self) -> None:
        if (
            not self._started
            or not self._readiness.is_set()
            or self._failure_code is not None
            or not self._tasks.tasks
        ):
            raise RuntimeError("identity_revocation_runtime_unhealthy")
        for task in self._tasks.tasks:
            if task.done():
                self._observe_worker_done(task)
                raise RuntimeError("identity_revocation_runtime_unhealthy")

    async def _cancel_workers(self) -> None:
        tasks = self._tasks.tasks
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def stop(self, *, close_factory: bool = True) -> None:
        self._readiness.clear()
        self._stop.set()
        self.identity.revocation_worker.offer_nowait()
        primary: BaseException | None = None
        try:
            await self._cancel_workers()
        except BaseException as error:
            primary = error
        if close_factory:
            try:
                await self.identity.uow_factory.aclose()
            except BaseException as error:
                if primary is None:
                    primary = error
        self._started = False
        self._failure_code = "not_started"
        if primary is not None:
            raise primary


class ProductionContainer:
    """Process-lifetime composition root; exactly one supervised reconciler."""

    __slots__ = (
        "core",
        "turn_coordinator",
        "session_manager",
        "core_process_lease",
        "budget_reconciler",
        "startup_turn_recovery",
        "budget_lifecycle",
        "reachy_transport_supervisor",
        "disconnect_safety",
        "current_reachy_session",
        "authenticated_reachy_control",
        "reachy_gateway",
        "reachy_wss_server",
        "reachy_transport_lifecycle",
        "task1_identity",
        "identity_lifecycle",
        "readiness_dependencies",
        "simulated_guest_app",
    )

    def __init__(
        self,
        *,
        core: CoreContainer,
        core_process_lease: CoreProcessLease,
        budget_reconciler: ExpiredBudgetReconciler,
        startup_turn_recovery: StartupTurnRecovery,
        budget_lifecycle: BudgetReconciliationSupervisor,
        turn_coordinator: TurnCoordinator | None = None,
        session_manager: SessionManager | None = None,
        reachy_transport_supervisor: ReachyTransportSupervisorState | None = None,
        disconnect_safety: CoreDisconnectSafetyFacade | None = None,
        current_reachy_session: CurrentReachySessionChannel | None = None,
        authenticated_reachy_control: AuthenticatedControlClient | None = None,
        reachy_gateway: ReachyGateway | None = None,
        reachy_wss_server: ReachyWssServer | None = None,
        reachy_transport_lifecycle: ProductionReachyLifecycle | None = None,
        task1_identity: Task1IdentityContainer | None = None,
        identity_lifecycle: Task1IdentityRuntimeSupervisor | None = None,
    ) -> None:
        if budget_lifecycle.reconciler is not budget_reconciler:
            raise TypeError("production reconciler identity mismatch")
        if budget_lifecycle.startup_recovery is not startup_turn_recovery:
            raise TypeError("production startup recovery identity mismatch")
        if startup_turn_recovery.process_lease is not core_process_lease:
            raise TypeError("production process lease identity mismatch")
        self.core = core
        self.turn_coordinator = turn_coordinator
        self.session_manager = session_manager
        self.core_process_lease = core_process_lease
        self.budget_reconciler = budget_reconciler
        self.startup_turn_recovery = startup_turn_recovery
        self.budget_lifecycle = budget_lifecycle
        self.reachy_transport_supervisor = reachy_transport_supervisor
        self.disconnect_safety = disconnect_safety
        self.current_reachy_session = current_reachy_session
        self.authenticated_reachy_control = authenticated_reachy_control
        self.reachy_gateway = reachy_gateway
        self.reachy_wss_server = reachy_wss_server
        self.reachy_transport_lifecycle = reachy_transport_lifecycle
        self.task1_identity = task1_identity
        self.identity_lifecycle = identity_lifecycle
        if (task1_identity is None) != (identity_lifecycle is None):
            raise TypeError("production identity composition incomplete")
        if identity_lifecycle is not None and identity_lifecycle.identity is not task1_identity:
            raise TypeError("production identity lifecycle mismatch")
        reachy_components = (
            reachy_transport_supervisor,
            disconnect_safety,
            current_reachy_session,
            authenticated_reachy_control,
            reachy_gateway,
            reachy_wss_server,
            reachy_transport_lifecycle,
        )
        if any(component is not None for component in reachy_components):
            if not all(component is not None for component in reachy_components):
                raise TypeError("production reachy transport composition incomplete")
            if reachy_transport_supervisor is None or current_reachy_session is None:
                raise TypeError("production reachy readiness composition incomplete")
            readiness_dependencies: tuple[ReadinessDependency, ...] = (
                reachy_transport_supervisor,
                current_reachy_session,
                budget_lifecycle,
            )
        else:
            readiness_dependencies = (budget_lifecycle,)
        if identity_lifecycle is not None:
            readiness_dependencies = (identity_lifecycle, *readiness_dependencies)
        self.readiness_dependencies = readiness_dependencies
        self.simulated_guest_app: InstalledSimulatedGuestApp | None = None

    @classmethod
    def build(
        cls,
        *,
        configured_state_root: Path,
        reachy: Any,
        sqlcipher_uow_factory: AsyncUnitOfWorkFactory,
        task1_identity_key_provider: Task1IdentityKeyProviderPort,
        clock: ClockPort,
        route_authorizer: RouteAuthorizerPort,
        price_catalog: PriceCatalog,
        runtime_provider_identities: RuntimeProviderIdentityReader,
        budget_evidence: BudgetEvidenceService,
        provider_defaults_path: Path,
        task1_capability_stage: CapabilityStagePort | None = None,
        task1_search_feature_state: Literal["absent", "present"] = "absent",
        reachy_endpoint: Any | None = None,
        reachy_tls_context: object | None = None,
        reachy_device_registry: Any | None = None,
        reachy_pairing_keys: Any | None = None,
        reachy_duplex_state: Any | None = None,
        reachy_handler: Any | None = None,
        reachy_time_issuer: Any | None = None,
        reachy_serve_factory: Any | None = None,
        reachy_client_certificate_verifier: Any | None = None,
        reachy_session_ready_timeout: float = 2.0,
    ) -> ProductionContainer:
        if not configured_state_root.is_absolute():
            raise ValueError("production_state_root_requires_absolute_path")
        provider_defaults = load_provider_defaults(provider_defaults_path)
        lease = CoreProcessLease.acquire(
            configured_state_root / "core-process.lock",
        )
        try:
            required_reachy_transport_parts = (
                reachy_endpoint,
                reachy_tls_context,
                reachy_device_registry,
                reachy_pairing_keys,
                reachy_duplex_state,
                reachy_handler,
                reachy_time_issuer,
            )
            owns_reachy_transport = all(
                component is not None for component in required_reachy_transport_parts
            )
            if any(component is not None for component in required_reachy_transport_parts) and (
                not owns_reachy_transport
            ):
                raise TypeError("production reachy transport composition incomplete")
            task1_keys = task1_identity_key_provider.current_keys()
            install_task1_sqlcipher_repository_facades(
                sqlcipher_uow_factory,
                clock,
                task1_keys,
            )
            task1_identity = build_task1_identity_container(
                sqlcipher_uow_factory,
                clock,
                task1_keys,
                capability_stage=task1_capability_stage,
                search_feature_state=task1_search_feature_state,
            )
            identity_lifecycle = Task1IdentityRuntimeSupervisor(task1_identity)
            provider_reviews = SqlcipherCurrentProviderReviews(
                runtime_provider_identities,
            )
            core = CoreContainer(
                sqlcipher_uow_factory=sqlcipher_uow_factory,
                clock=clock,
                route_authorizer=route_authorizer,
                price_catalog=price_catalog,
                provider_reviews=provider_reviews,
                budget_evidence=budget_evidence,
                provider_defaults=provider_defaults,
            )
            turn_coordinator: TurnCoordinator | None = None
            if owns_reachy_transport:

                def active_turn_id() -> UUID | None:
                    if turn_coordinator is None:
                        return None
                    return turn_coordinator.active_turn_id()

                async def cancel_turn(turn_id: UUID, reason: str) -> None:
                    if turn_coordinator is None:
                        raise RuntimeError("production turn coordinator unavailable")
                    await turn_coordinator.cancel(turn_id, reason)

                reachy_transport_supervisor = ReachyTransportSupervisorState()
                disconnect_safety = CoreDisconnectSafetyFacade(
                    active_turn_id=active_turn_id,
                    cancel_turn=cancel_turn,
                )
                current_reachy_session = CurrentReachySessionChannel(safety=disconnect_safety)
                authenticated_reachy_control = AuthenticatedControlClient(current_reachy_session)
                reachy_gateway = ReachyGateway(authenticated_reachy_control, clock)
                reachy_runtime = reachy_gateway
            else:
                reachy_transport_supervisor = None
                disconnect_safety = None
                current_reachy_session = None
                authenticated_reachy_control = None
                reachy_gateway = None
                reachy_runtime = reachy
            reconciler = ExpiredBudgetReconciler(
                sqlcipher_uow_factory,
                clock,
                core.budget_guard,
            )
            startup_recovery = StartupTurnRecovery(
                reachy_runtime,
                reconciler,
                sqlcipher_uow_factory,
                clock,
                lease,
            )
            lifecycle = BudgetReconciliationSupervisor(
                reconciler,
                startup_recovery,
            )
            turn_coordinator = TurnCoordinator(
                core.budget_guard,
                reachy_runtime,
                clock,
            )
            if owns_reachy_transport:
                if (
                    reachy_endpoint is None
                    or reachy_tls_context is None
                    or reachy_device_registry is None
                    or reachy_pairing_keys is None
                    or reachy_duplex_state is None
                    or reachy_handler is None
                    or reachy_time_issuer is None
                    or reachy_transport_supervisor is None
                    or current_reachy_session is None
                    or disconnect_safety is None
                ):
                    raise TypeError("production reachy transport composition incomplete")
                reachy_wss_server = ReachyWssServer(
                    cast(ReachyEndpoint, reachy_endpoint),
                    tls_context=reachy_tls_context,
                    device_registry=cast(ReachyDeviceRegistry, reachy_device_registry),
                    pairing_keys=cast(ReachyPairingKeys, reachy_pairing_keys),
                    state=cast(ReachyDuplexState, reachy_duplex_state),
                    handler=cast(ReachyHandler, reachy_handler),
                    sessions=current_reachy_session,
                    readiness=reachy_transport_supervisor,
                    time_issuer=cast(ReachyTimeIssuer, reachy_time_issuer),
                    clock=clock,
                    session_factory=cast(ReachySessionFactory, CoreReachySession),
                    serve_factory=reachy_serve_factory,
                    client_certificate_verifier=reachy_client_certificate_verifier,
                )
                reachy_transport_lifecycle = ProductionReachyLifecycle(
                    wss_server=reachy_wss_server,
                    current_session=current_reachy_session,
                    disconnect_safety=disconnect_safety,
                    budget_lifecycle=lifecycle,
                    process_lease=lease,
                    session_ready_timeout=reachy_session_ready_timeout,
                )
            else:
                reachy_wss_server = None
                reachy_transport_lifecycle = None
            session_manager = SessionManager(turn_coordinator)
            return cls(
                core=core,
                turn_coordinator=turn_coordinator,
                session_manager=session_manager,
                core_process_lease=lease,
                budget_reconciler=reconciler,
                startup_turn_recovery=startup_recovery,
                budget_lifecycle=lifecycle,
                reachy_transport_supervisor=reachy_transport_supervisor,
                disconnect_safety=disconnect_safety,
                current_reachy_session=current_reachy_session,
                authenticated_reachy_control=authenticated_reachy_control,
                reachy_gateway=reachy_gateway,
                reachy_wss_server=reachy_wss_server,
                reachy_transport_lifecycle=reachy_transport_lifecycle,
                task1_identity=task1_identity,
                identity_lifecycle=identity_lifecycle,
            )
        except BaseException:
            lease.release_after_shutdown()
            raise

    async def start(self) -> None:
        if self.identity_lifecycle is not None:
            await self.identity_lifecycle.start()
        try:
            if self.reachy_transport_lifecycle is not None:
                await self.reachy_transport_lifecycle.start()
                return
            await self.budget_lifecycle.start()
        except BaseException:
            if self.identity_lifecycle is not None:
                await self.identity_lifecycle.stop(close_factory=False)
            raise

    async def stop(self) -> None:
        primary: BaseException | None = None
        if self.reachy_transport_lifecycle is not None:
            try:
                await self.reachy_transport_lifecycle.stop()
            except BaseException as error:
                primary = error
        else:
            try:
                await self.budget_lifecycle.stop()
            except BaseException as error:
                primary = error
        if self.identity_lifecycle is not None:
            try:
                await self.identity_lifecycle.stop()
            except BaseException as error:
                if primary is None:
                    primary = error
        if primary is not None:
            raise primary

    def install_simulated_guest_app(
        self,
        *,
        ports: WorkflowPorts | ContextWorkflowPorts,
        completed_audio: CompletedTurnAudioPort,
        household_id: UUID,
        device_id: UUID,
        loopback_host: str,
        identity: IdentityContextPort | None = None,
        profiles: ProfileProjectionPort | None = None,
        prompt_root: Path = Path("prompts"),
        context_provider: PersonalizedTurnContextProvider | None = None,
        provider_egress: ProviderEgressBoundary | None = None,
        workflow_name: Literal["linear", "langgraph"] = "linear",
    ) -> InstalledSimulatedGuestApp:
        if type(workflow_name) is not str or workflow_name not in {"linear", "langgraph"}:
            raise ValueError("unknown workflow")
        if self.simulated_guest_app is not None:
            raise RuntimeError("simulated_guest_app_already_installed")
        if self.turn_coordinator is None or self.session_manager is None:
            raise RuntimeError("simulated_guest_roots_unavailable")
        if type(provider_egress) is not ProviderEgressAuthorizer:
            raise TypeError("production provider egress authorizer required")
        if context_provider is None:
            if identity is None or profiles is None:
                raise TypeError("personalized identity and profile ports required")
            context_builder = ContextBuilder(PersonaBuilder.from_directory(prompt_root))
            context_provider = PersonalizedTurnContextProvider(
                self.session_manager,
                identity,
                profiles,
                SessionLanguageRegistry(),
                context_builder,
                self.core.clock,
            )
        self.session_manager.register_session_ended_handler(context_provider.on_session_ended)
        linear_engine: LinearConversationEngine | None = None
        langgraph_engine: LangGraphConversationEngine | None = None
        if workflow_name == "linear":
            linear_engine = LinearConversationEngine(
                ports,
                context_provider=context_provider,
                provider_egress=provider_egress,
                accepts_results=self.session_manager.accepts_results,
            )
            engine: ConversationEngine = linear_engine
        elif workflow_name == "langgraph":
            langgraph_engine = LangGraphConversationEngine(
                cast(WorkflowPorts, ports),
                context_provider=context_provider,
                provider_egress=provider_egress,
                accepts_results=self.session_manager.accepts_results,
            )
            engine = langgraph_engine
        else:
            raise ValueError("unknown workflow")
        workflow = build_workflow(
            ports,
            completed_audio,
            self.turn_coordinator,
            context_provider=context_provider,
            provider_egress=provider_egress,
            engine=engine,
            session_manager=self.session_manager,
            workflow_name=workflow_name,
        )
        dependencies = SimulatedGuestAppDependencies(
            session_manager=self.session_manager,
            workflow=workflow,
            household_id=household_id,
            device_id=device_id,
            loopback_host=loopback_host,
            readiness_dependencies=self.readiness_dependencies,
        )
        app = create_app(dependencies)
        route_id_sequence = tuple(
            route.name for route in app.router.routes if isinstance(route, APIRoute)
        )
        duplicate_route_ids = _duplicate_route_ids(route_id_sequence)
        route_ids = set(route_id_sequence)
        if frozenset(route_ids) != _SIMULATED_GUEST_ROUTE_NAMES or duplicate_route_ids:
            raise RuntimeError("simulated_guest_route_inventory_mismatch")
        installed = InstalledSimulatedGuestApp(
            composition=SimulatedGuestComposition(
                app=app,
                workflow=workflow,
                dependencies=dependencies,
                linear_engine=linear_engine,
                langgraph_engine=langgraph_engine,
                context_provider=context_provider,
            ),
            coordinator=self.turn_coordinator,
            session_manager=self.session_manager,
            household_id=household_id,
            device_id=device_id,
            loopback_host=loopback_host,
            readiness_dependencies=self.readiness_dependencies,
            route_ids=route_ids,
            duplicate_route_ids=duplicate_route_ids,
            listener_bindings=_LOOPBACK_LISTENER_BINDINGS,
        )
        self.simulated_guest_app = installed
        return installed


def build_workflow(
    ports: WorkflowPorts | ContextWorkflowPorts,
    completed_audio: CompletedTurnAudioPort,
    coordinator: TurnCoordinator,
    *,
    context_provider: PersonalizedTurnContextProvider | None = None,
    provider_egress: ProviderEgressBoundary | None = None,
    engine: ConversationEngine | None = None,
    session_manager: SessionManager | None = None,
    workflow_name: Literal["linear", "langgraph"] = "linear",
) -> ContractConversationWorkflow:
    if type(workflow_name) is not str or workflow_name not in {"linear", "langgraph"}:
        raise ValueError("unknown workflow")
    cleanup = coordinator if session_manager is None else session_manager
    if engine is None:
        if workflow_name == "linear":
            engine = LinearConversationEngine(
                ports,
                context_provider=context_provider,
                provider_egress=provider_egress,
                accepts_results=cleanup.accepts_results,
            )
        elif workflow_name == "langgraph":
            engine = LangGraphConversationEngine(
                cast(WorkflowPorts, ports),
                context_provider=context_provider,
                provider_egress=provider_egress,
                accepts_results=cleanup.accepts_results,
            )
        else:
            raise ValueError("unknown workflow")
    elif (workflow_name == "linear" and type(engine) is not LinearConversationEngine) or (
        workflow_name == "langgraph" and type(engine) is not LangGraphConversationEngine
    ):
        raise TypeError("workflow engine kind mismatch")
    if getattr(engine, "context_provider", None) is not context_provider:
        raise TypeError("workflow engine context provider mismatch")
    return ContractConversationWorkflow(completed_audio, engine, cleanup)


def _duplicate_route_ids(route_ids: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for route_id in route_ids:
        if route_id in seen:
            duplicates.add(route_id)
        seen.add(route_id)
    return tuple(sorted(duplicates))


class Task1CapabilityStage:
    def __init__(
        self,
        installed_revisions: frozenset[str] = frozenset(),
        *,
        installed_facades: frozenset[str] = frozenset(),
        installed_schema_names: frozenset[str] = frozenset(),
    ) -> None:
        self._installed_revisions = installed_revisions
        self._installed_facades = installed_facades
        self._installed_schema_names = installed_schema_names

    @classmethod
    def from_uow_factory(cls, async_uow_factory: AsyncUnitOfWorkFactory) -> Task1CapabilityStage:
        engine = getattr(async_uow_factory, "_engine", None)
        installed_revisions: set[str] = set()
        installed_schema_names: set[str] = set()
        if isinstance(engine, Engine):
            installed_schema_names.update(_sqlite_schema_names(engine))
            installed_revisions.update(_sqlite_revision_rows(engine, "alembic_version"))
            installed_revisions.update(_sqlite_revision_rows(engine, SEARCH_VERSION_TABLE))
        return cls(
            frozenset(installed_revisions),
            installed_facades=_repository_facade_names(async_uow_factory),
            installed_schema_names=frozenset(installed_schema_names),
        )

    def require_schema_and_facade_absent(self, family: str, owning_revision: str) -> None:
        if _CAPABILITY_OWNER_REVISIONS.get(family) != owning_revision:
            raise RuntimeError("capability_owning_revision_mismatch")
        if (
            owning_revision in self._installed_revisions
            or self._installed_facades.intersection(_CAPABILITY_FACADE_NAMES[family])
            or self._installed_schema_names.intersection(_CAPABILITY_SCHEMA_NAMES[family])
        ):
            raise RuntimeError("not_installed_authority_handler_stale")

    async def require_schema_and_facade_absent_in_uow(
        self,
        uow: IdentityUnitOfWork,
        family: str,
        owning_revision: str,
    ) -> None:
        self.require_schema_and_facade_absent(family, owning_revision)
        for facade_name in _CAPABILITY_FACADE_NAMES[family]:
            if hasattr(uow, facade_name):
                raise RuntimeError("not_installed_authority_handler_stale")
        schema_names = _CAPABILITY_SCHEMA_NAMES[family]
        placeholders = ",".join("?" for _ in schema_names)
        discovered = await uow.run_sync(
            lambda tx: tuple(
                row[0]
                for row in tx.exec_driver_sql(
                    "SELECT name FROM sqlite_master "
                    f"WHERE type IN ('table','view') AND name IN ({placeholders})",
                    schema_names,
                ).fetchall()
            )
        )
        if discovered:
            raise RuntimeError("not_installed_authority_handler_stale")


def _repository_facade_names(async_uow_factory: AsyncUnitOfWorkFactory) -> frozenset[str]:
    facades = getattr(async_uow_factory, "_repository_facades", None)
    if not isinstance(facades, dict):
        return frozenset()
    return frozenset(str(name) for name in facades)


def _sqlite_schema_names(engine: Engine) -> frozenset[str]:
    with engine.connect() as connection:
        return frozenset(
            str(row[0])
            for row in connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type IN ('table','view')"
            ).fetchall()
        )


def _sqlite_revision_rows(engine: Engine, table_name: str) -> frozenset[str]:
    if table_name not in _sqlite_schema_names(engine):
        return frozenset()
    with engine.connect() as connection:
        return frozenset(
            str(row[0])
            for row in connection.exec_driver_sql(
                f"SELECT version_num FROM {table_name}"
            ).fetchall()
        )


def _require_task1_identity_facades(async_uow_factory: AsyncUnitOfWorkFactory) -> None:
    missing = TASK1_REQUIRED_IDENTITY_REPOSITORY_FACADES - _repository_facade_names(
        async_uow_factory
    )
    if missing:
        raise RuntimeError("task1_identity_repository_facades_required")


def _sqlcipher_engine_from_factory(async_uow_factory: AsyncUnitOfWorkFactory) -> Engine:
    engine = getattr(async_uow_factory, "_engine", None)
    if not isinstance(engine, Engine):
        raise TypeError("sqlcipher_uow_factory_engine_required")
    return engine


def _require_task1_clock(clock: ClockPort) -> ClockPort:
    if not callable(getattr(clock, "now", None)) or not callable(getattr(clock, "monotonic", None)):
        raise TypeError("task1_identity_application_clock_required")
    return clock


class _Task1RuntimeClock:
    def __init__(self, clock: ClockPort) -> None:
        self._clock = _require_task1_clock(clock)
        sleep_until = getattr(clock, "sleep_until", None)
        self._sleep_until = (
            cast(Callable[[datetime], Awaitable[None]], sleep_until)
            if callable(sleep_until)
            else None
        )

    def now(self) -> datetime:
        return self._clock.now()

    def monotonic(self) -> float:
        return self._clock.monotonic()

    async def sleep_until(self, deadline: datetime) -> None:
        if self._sleep_until is not None:
            await self._sleep_until(deadline)
            return
        delay = (deadline - self.now()).total_seconds()
        if delay > 0:
            await asyncio.sleep(delay)


class _DiscardingCloudRouteRevocation:
    def __init__(self, delegate: SqlProviderRouteAuthorityRevocation) -> None:
        self._delegate = delegate

    async def invalidate_subject_purpose_in_uow(
        self,
        uow: IdentityUnitOfWork,
        subject_id: UUID,
        purpose: str,
        now: datetime,
    ) -> None:
        await self._delegate.invalidate_subject_purpose_in_uow(uow, subject_id, purpose, now)


def build_task1_sqlcipher_uow_factory(
    engine: Engine,
    clock: ClockPort,
    keys: Task1IdentityKeyBundle,
) -> AsyncUnitOfWorkFactory:
    factory = AsyncUnitOfWorkFactory(engine)
    install_task1_sqlcipher_repository_facades(factory, clock, keys)
    return factory


def install_task1_sqlcipher_repository_facades(
    async_uow_factory: AsyncUnitOfWorkFactory,
    clock: ClockPort,
    keys: Task1IdentityKeyBundle,
) -> None:
    _require_task1_clock(clock)
    audit_commitments = PrivateCommitmentService(keys.audit_payload)
    async_uow_factory.register_repository_facades(
        task1_identity_repository_facades(clock.now, audit_commitments)
    )


def _build_task1_identity_services(
    async_uow_factory: AsyncUnitOfWorkFactory,
    identity_uow_factory: IdentityUnitOfWorkFactory,
    subject_revocations: SubjectAuthorityRevocationCascade,
    clock: ClockPort,
    keys: Task1IdentityKeyBundle,
) -> Task1IdentityMutationServices:
    mutation_scope = SqlIdentityMutationScope(
        cast(IdentityUnitOfWorkContextFactory, async_uow_factory)
    )
    audit_ledger = AsyncAuditLedger(
        AuditLedger(keys.audit_chain.key_id, keys.audit_chain.root_key, clock)
    )
    identity_audit_ledger = IdentityAuditLedger(audit_ledger)
    receipt_signer = HmacReceiptSigner(
        keys.receipt.root_key,
        key_id=keys.receipt.key_id,
    )
    parameter_verifier = ActionParameterBindingVerifier(
        keys.action_parameters.root_key,
        key_id=keys.action_parameters.key_id,
    )
    binding_verifier = ActionBindingVerifier()
    audit_commitments = PrivateCommitmentService(keys.audit_payload)
    cloud_route_revocation = CloudRouteConsentRevocationHandler(
        _DiscardingCloudRouteRevocation(SqlProviderRouteAuthorityRevocation())
    )
    biometric_revocation = BiometricConsentRevocationHandler(identity_audit_ledger)
    consent_revocations = ConsentRevocationCascade(
        {
            ConsentPurpose.FACE: biometric_revocation,
            ConsentPurpose.VOICE: biometric_revocation,
            ConsentPurpose.CLOUD_STT: cloud_route_revocation,
            ConsentPurpose.CLOUD_REASONING: cloud_route_revocation,
            ConsentPurpose.CLOUD_TTS: cloud_route_revocation,
        },
        Task1ConsentRevocationAuditMapper(audit_commitments),
        identity_audit_ledger,
    )
    consents = ConsentService(
        identity_uow_factory,
        mutation_scope,
        identity_audit_ledger,
        receipt_signer,
        parameter_verifier,
        binding_verifier,
        consent_revocations,
        clock,
    )
    enrollments = EnrollmentService(
        identity_uow_factory,
        mutation_scope,
        consents,
        parameter_verifier,
        binding_verifier,
        identity_audit_ledger,
        clock,
    )
    profiles = ProfileService(
        identity_uow_factory,
        mutation_scope,
        identity_audit_ledger,
        consents,
        subject_revocations,
        ProfileCrypto(keys.profile.root_key, key_id=keys.profile.key_id),
        parameter_verifier,
        binding_verifier,
        clock,
    )
    authentication = UnavailableTask1Authentication()
    mutations = IdentityMutationCoordinator(
        mutation_scope,
        authentication,
        profiles,
        consents,
    )
    enrollment_mutations = EnrollmentMutationCoordinator(
        mutation_scope,
        authentication,
        enrollments,
    )
    guest_consents = GuestSessionConsentService(
        identity_uow_factory,
        identity_audit_ledger,
        receipt_signer,
    )
    consent_evidence = ConsentEvidenceService(consents, guest_consents)
    consent_hmac_verifier = ConsentHmacVerifier(receipt_signer, consents, clock)
    return Task1IdentityMutationServices(
        profiles=profiles,
        consents=consents,
        guest_consents=guest_consents,
        enrollments=enrollments,
        mutations=mutations,
        enrollment_mutations=enrollment_mutations,
        consent_evidence=consent_evidence,
        consent_hmac_verifier=consent_hmac_verifier,
        authentication=authentication,
        audit_ledger=identity_audit_ledger,
    )


@dataclass(frozen=True, slots=True)
class Task1IdentityContainer:
    uow_factory: AsyncUnitOfWorkFactory
    identity_services: Task1IdentityMutationServices
    revocation_outbox: SubjectRevocationOutboxRepository
    revocation_effects: SubjectRevocationEffectRepository
    revocation_heartbeats: LeaseHeartbeatRunner
    transactional_subject_revocation_handlers: Mapping[str, SubjectAuthorityRevocationHandler]
    subject_revocation_cascade: SubjectAuthorityRevocationCascade
    post_commit_revocation_handlers: Mapping[str, _OnceHandler]
    revocation_processor: SubjectRevocationProcessor
    revocation_worker: SubjectRevocationWorker


def build_task1_identity_container(
    async_uow_factory: AsyncUnitOfWorkFactory,
    clock: ClockPort,
    keys: Task1IdentityKeyBundle,
    *,
    capability_stage: CapabilityStagePort | None = None,
    search_feature_state: Literal["absent", "present"] = "absent",
) -> Task1IdentityContainer:
    _require_task1_identity_facades(async_uow_factory)
    stage = (
        Task1CapabilityStage.from_uow_factory(async_uow_factory)
        if capability_stage is None
        else capability_stage
    )
    runtime_clock = _Task1RuntimeClock(clock)
    identity_uow_factory = cast(IdentityUnitOfWorkFactory, async_uow_factory)
    revocation_clock = cast(RevocationHandlerClockPort, runtime_clock)
    worker_clock = cast(RevocationWorkerClockPort, runtime_clock)
    revocation_outbox = SubjectRevocationOutboxRepository(identity_uow_factory)
    revocation_effects = SubjectRevocationEffectRepository(identity_uow_factory)
    revocation_heartbeats = LeaseHeartbeatRunner(revocation_clock)
    transactional_subject_revocation_handlers: dict[str, SubjectAuthorityRevocationHandler] = {
        "sessions": SessionSubjectAuthorityRevocationHandler(),
        "consents": ConsentSubjectAuthorityRevocationHandler(),
        "enrollments": EnrollmentSubjectAuthorityRevocationHandler(),
        "biometric_templates": BiometricTemplateSubjectAuthorityRevocationHandler(),
        "provider_routes": ProviderRouteSubjectAuthorityRevocationHandler(),
        "search_capabilities": SearchCapabilitySubjectAuthorityRevocationHandler(
            stage,
            feature_state=search_feature_state,
        ),
        "action_authorities": NotInstalledSubjectAuthorityHandler(
            stage,
            family="action_authorities",
            owning_revision="0003_authentication",
        ),
        "memory_authorities": NotInstalledSubjectAuthorityHandler(
            stage,
            family="memory_authorities",
            owning_revision="0004_memory",
        ),
    }
    subject_revocation_cascade = SubjectAuthorityRevocationCascade(
        transactional_subject_revocation_handlers,
        revocation_outbox,
    )
    identity_services = _build_task1_identity_services(
        async_uow_factory,
        identity_uow_factory,
        subject_revocation_cascade,
        runtime_clock,
        keys,
    )
    post_commit_revocation_handlers: dict[str, _OnceHandler] = {
        "provider_routes": ProviderRouteRevocationHandler(
            revocation_effects,
            revocation_heartbeats,
            identity_uow_factory,
            provider_calls=cast(
                ProviderCallsRevocationPort,
                SqlProviderCallsRevocationPort(identity_uow_factory, clock.now),
            ),
            budget_reservations=cast(
                BudgetReservationsRevocationPort,
                SqlBudgetReservationsRevocationPort(
                    identity_uow_factory,
                    clock.now,
                ),
            ),
        ),
        "search_capabilities": SearchAuthorityRevocationHandler(
            revocation_effects,
            revocation_heartbeats,
            identity_uow_factory,
            feature_state=search_feature_state,
            capability_stage=stage,
            owning_revision=SEARCH_FEATURE_HEAD,
        ),
        "action_authorities": NotInstalledAuthorityRevocationHandler(
            revocation_effects,
            revocation_heartbeats,
            stage,
            family="action_authorities",
            owning_revision="0003_authentication",
        ),
        "memory_authorities": NotInstalledAuthorityRevocationHandler(
            revocation_effects,
            revocation_heartbeats,
            stage,
            family="memory_authorities",
            owning_revision="0004_memory",
        ),
    }
    revocation_processor = SubjectRevocationProcessor(post_commit_revocation_handlers)
    if not revocation_processor.available:
        raise RuntimeError("subject revocation processor unavailable")
    revocation_worker = SubjectRevocationWorker(
        revocation_outbox,
        revocation_processor,
        revocation_heartbeats,
        worker_clock,
    )
    async_uow_factory.register_commit_signal("subject_revocation", revocation_worker)
    return Task1IdentityContainer(
        uow_factory=async_uow_factory,
        identity_services=identity_services,
        revocation_outbox=revocation_outbox,
        revocation_effects=revocation_effects,
        revocation_heartbeats=revocation_heartbeats,
        transactional_subject_revocation_handlers=transactional_subject_revocation_handlers,
        subject_revocation_cascade=subject_revocation_cascade,
        post_commit_revocation_handlers=post_commit_revocation_handlers,
        revocation_processor=revocation_processor,
        revocation_worker=revocation_worker,
    )
