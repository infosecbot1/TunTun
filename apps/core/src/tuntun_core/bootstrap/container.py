from __future__ import annotations

from tuntun_contracts.ports import BudgetPort, ClockPort, RouteAuthorizerPort
from tuntun_core.adapters.sqlcipher.async_unit_of_work import AsyncUnitOfWorkFactory
from tuntun_core.services.providers.call_repository import ProviderCallRepository
from tuntun_core.services.providers.gateway import ProviderGateway
from tuntun_core.services.providers.redaction_repository import (
    RedactionReceiptRepository,
)


class CoreContainer:
    """Task-04 composition root; live egress requires explicit budget injection."""

    __slots__ = (
        "sqlcipher_uow_factory",
        "clock",
        "route_authorizer",
        "redaction_receipt_repository",
        "provider_call_repository",
    )

    def __init__(
        self,
        *,
        sqlcipher_uow_factory: AsyncUnitOfWorkFactory,
        clock: ClockPort,
        route_authorizer: RouteAuthorizerPort,
    ) -> None:
        self.sqlcipher_uow_factory = sqlcipher_uow_factory
        self.clock = clock
        self.route_authorizer = route_authorizer
        self.redaction_receipt_repository = RedactionReceiptRepository(
            sqlcipher_uow_factory,
            clock,
        )
        self.provider_call_repository = ProviderCallRepository(
            sqlcipher_uow_factory,
            clock,
            self.redaction_receipt_repository,
        )

    def build_provider_gateway(self, budget: BudgetPort) -> ProviderGateway:
        return ProviderGateway(
            self.route_authorizer,
            budget,
            self.provider_call_repository,
        )
