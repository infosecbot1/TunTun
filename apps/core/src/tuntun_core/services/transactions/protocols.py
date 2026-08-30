from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Protocol, TypeVar, runtime_checkable

from sqlalchemy.engine import CursorResult
from sqlalchemy.sql import Executable

T = TypeVar("T")


@runtime_checkable
class UnitOfWorkProtocol(Protocol):
    def execute(
        self,
        statement: Executable,
        parameters: Mapping[str, object] | None = None,
    ) -> CursorResult[Any]: ...

    def exec_driver_sql(
        self,
        statement: str,
        parameters: tuple[object, ...] | Mapping[str, object] = (),
    ) -> CursorResult[Any]: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...


@runtime_checkable
class AsyncUnitOfWorkProtocol(Protocol):
    async def run_sync(self, operation: Callable[[UnitOfWorkProtocol], T]) -> T: ...

    def signal_after_commit(self, name: str) -> None: ...

    async def commit(self) -> None: ...

    async def rollback(self) -> None: ...
