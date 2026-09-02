from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

from fastapi import FastAPI
from fastapi.routing import APIRoute
from tuntun_contracts.ports import ClockPort, RouteAuthorizerPort
from tuntun_core.adapters.sqlcipher.async_unit_of_work import AsyncUnitOfWorkFactory
from tuntun_core.api.app import create_app
from tuntun_core.api.dependencies import ReadinessDependency, SimulatedGuestAppDependencies
from tuntun_core.bootstrap.lifecycle import (
    BudgetReconciliationSupervisor,
    CoreProcessLease,
    StartupTurnRecovery,
)
from tuntun_core.services.budget.catalog import PriceCatalog
from tuntun_core.services.budget.evidence import BudgetEvidenceService
from tuntun_core.services.budget.guard import BudgetGuard
from tuntun_core.services.budget.reconciler import ExpiredBudgetReconciler
from tuntun_core.services.context_builder import ContextBuilder
from tuntun_core.services.persona_builder import PersonaBuilder
from tuntun_core.services.personalized_turn_context import (
    IdentityContextPort,
    PersonalizedTurnContextProvider,
    ProfileProjectionPort,
    SessionLanguageRegistry,
)
from tuntun_core.services.providers.call_repository import ProviderCallRepository
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
from tuntun_core.services.transactions.protocols import UnitOfWorkProtocol
from tuntun_core.workflows.contract_workflow import (
    CompletedTurnAudioPort,
    ContractConversationWorkflow,
)
from tuntun_core.workflows.conversation import (
    ContextWorkflowPorts,
    LinearConversationEngine,
    WorkflowPorts,
)

_SIMULATED_GUEST_ROUTE_NAMES = frozenset(
    {"health.ready", "session.simulated_end", "session.simulated_turn"}
)
_LOOPBACK_LISTENER_BINDINGS = frozenset({"loopback"})


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
        self.readiness_dependencies = (budget_lifecycle,)
        self.simulated_guest_app: InstalledSimulatedGuestApp | None = None

    @classmethod
    def build(
        cls,
        *,
        configured_state_root: Path,
        reachy: Any,
        sqlcipher_uow_factory: AsyncUnitOfWorkFactory,
        clock: ClockPort,
        route_authorizer: RouteAuthorizerPort,
        price_catalog: PriceCatalog,
        runtime_provider_identities: RuntimeProviderIdentityReader,
        budget_evidence: BudgetEvidenceService,
        provider_defaults_path: Path,
    ) -> ProductionContainer:
        if not configured_state_root.is_absolute():
            raise ValueError("production_state_root_requires_absolute_path")
        provider_defaults = load_provider_defaults(provider_defaults_path)
        lease = CoreProcessLease.acquire(
            configured_state_root / "core-process.lock",
        )
        try:
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
            reconciler = ExpiredBudgetReconciler(
                sqlcipher_uow_factory,
                clock,
                core.budget_guard,
            )
            startup_recovery = StartupTurnRecovery(
                reachy,
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
                reachy,
                clock,
            )
            session_manager = SessionManager(turn_coordinator)
            return cls(
                core=core,
                turn_coordinator=turn_coordinator,
                session_manager=session_manager,
                core_process_lease=lease,
                budget_reconciler=reconciler,
                startup_turn_recovery=startup_recovery,
                budget_lifecycle=lifecycle,
            )
        except BaseException:
            lease.release_after_shutdown()
            raise

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
    ) -> InstalledSimulatedGuestApp:
        if self.simulated_guest_app is not None:
            raise RuntimeError("simulated_guest_app_already_installed")
        if self.turn_coordinator is None or self.session_manager is None:
            raise RuntimeError("simulated_guest_roots_unavailable")
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
        linear_engine = LinearConversationEngine(
            ports,
            context_provider=context_provider,
            accepts_results=self.session_manager.accepts_results,
        )
        workflow = build_workflow(
            ports,
            completed_audio,
            self.turn_coordinator,
            context_provider=context_provider,
            engine=linear_engine,
            session_manager=self.session_manager,
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
    engine: LinearConversationEngine | None = None,
    session_manager: SessionManager | None = None,
) -> ContractConversationWorkflow:
    cleanup = coordinator if session_manager is None else session_manager
    if engine is None:
        engine = LinearConversationEngine(
            ports,
            context_provider=context_provider,
            accepts_results=cleanup.accepts_results,
        )
    elif engine.context_provider is not context_provider:
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
