from __future__ import annotations

import pytest


class ScopeProbeUnit:
    def __init__(self, factory: ScopeProbeFactory) -> None:
        self.factory = factory
        self.finished = False

    async def __aenter__(self) -> ScopeProbeUnit:
        self.factory.active += 1
        return self

    async def commit(self) -> None:
        if self.finished:
            raise RuntimeError("probe is not active")
        self.factory.persisted += 1
        self.finished = True

    async def rollback(self) -> None:
        if not self.finished:
            self.factory.rollbacks += 1
            self.finished = True

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> bool:
        del exc_type, exc, traceback
        if not self.finished:
            await self.rollback()
        self.factory.active -= 1
        return False


class ScopeProbeFactory:
    def __init__(self) -> None:
        self.active = 0
        self.persisted = 0
        self.rollbacks = 0

    def __call__(self) -> ScopeProbeUnit:
        return ScopeProbeUnit(self)

    async def persisted_probe_count(self) -> int:
        return self.persisted

    async def probe_scope_is_absent(self, scope: object) -> bool:
        try:
            scope.require_active_uow()  # type: ignore[attr-defined]
        except RuntimeError as error:
            return "no active atomic mutation scope" in str(error)
        return False


@pytest.fixture
def async_uow_factory() -> ScopeProbeFactory:
    return ScopeProbeFactory()
