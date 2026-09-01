from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from tuntun_contracts.ports import ClockPort, RouteAuthorizerPort
from tuntun_core.adapters.sqlcipher.async_unit_of_work import AsyncUnitOfWorkFactory
from tuntun_core.bootstrap.lifecycle import (
    BudgetReconciliationSupervisor,
    CoreProcessLease,
    StartupTurnRecovery,
)
from tuntun_core.services.budget.catalog import PriceCatalog
from tuntun_core.services.budget.evidence import BudgetEvidenceService
from tuntun_core.services.budget.guard import BudgetGuard
from tuntun_core.services.budget.reconciler import ExpiredBudgetReconciler
from tuntun_core.services.providers.call_repository import ProviderCallRepository
from tuntun_core.services.providers.gateway import ProviderGateway
from tuntun_core.services.providers.redaction_repository import (
    RedactionReceiptRepository,
)
from tuntun_core.services.providers.review import (
    RuntimeProviderIdentityReader,
    SqlcipherCurrentProviderReviews,
)
from tuntun_core.services.transactions.protocols import UnitOfWorkProtocol


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
        hard_limit: int = 150_000_000,
        soft_limit: int = 100_000_000,
    ) -> None:
        if type(budget_evidence) is not BudgetEvidenceService:
            raise TypeError("production budget evidence service required")
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
            hard_limit=hard_limit,
            soft_limit=soft_limit,
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


class ProductionContainer:
    """Process-lifetime composition root; exactly one supervised reconciler."""

    __slots__ = (
        "core",
        "core_process_lease",
        "budget_reconciler",
        "startup_turn_recovery",
        "budget_lifecycle",
        "readiness_dependencies",
    )

    def __init__(
        self,
        *,
        core: CoreContainer,
        core_process_lease: CoreProcessLease,
        budget_reconciler: ExpiredBudgetReconciler,
        startup_turn_recovery: StartupTurnRecovery,
        budget_lifecycle: BudgetReconciliationSupervisor,
    ) -> None:
        if budget_lifecycle.reconciler is not budget_reconciler:
            raise TypeError("production reconciler identity mismatch")
        if budget_lifecycle.startup_recovery is not startup_turn_recovery:
            raise TypeError("production startup recovery identity mismatch")
        if startup_turn_recovery.process_lease is not core_process_lease:
            raise TypeError("production process lease identity mismatch")
        self.core = core
        self.core_process_lease = core_process_lease
        self.budget_reconciler = budget_reconciler
        self.startup_turn_recovery = startup_turn_recovery
        self.budget_lifecycle = budget_lifecycle
        self.readiness_dependencies = (budget_lifecycle,)

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
        hard_limit: int = 150_000_000,
        soft_limit: int = 100_000_000,
    ) -> ProductionContainer:
        if not configured_state_root.is_absolute():
            raise ValueError("production_state_root_requires_absolute_path")
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
                hard_limit=hard_limit,
                soft_limit=soft_limit,
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
            return cls(
                core=core,
                core_process_lease=lease,
                budget_reconciler=reconciler,
                startup_turn_recovery=startup_recovery,
                budget_lifecycle=lifecycle,
            )
        except BaseException:
            lease.release_after_shutdown()
            raise
