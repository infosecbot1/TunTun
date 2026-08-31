from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from types import TracebackType
from typing import Protocol, Self

from .protocols import AsyncUnitOfWorkProtocol


class _AsyncContextUnitOfWork(AsyncUnitOfWorkProtocol, Protocol):
    async def __aenter__(self) -> Self: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class _MutationAuthority:
    uow: AsyncUnitOfWorkProtocol
    owner: asyncio.Task[object]


_CURRENT_MUTATION: ContextVar[_MutationAuthority | None] = ContextVar(
    "tuntun_current_atomic_mutation",
    default=None,
)


def _current_task() -> asyncio.Task[object]:
    task = asyncio.current_task()
    if task is None:
        raise RuntimeError("no active atomic mutation scope")
    return task


class AtomicMutationScope:
    def __init__(self, factory: Callable[[], _AsyncContextUnitOfWork]) -> None:
        self._factory = factory

    @asynccontextmanager
    async def open(self) -> AsyncIterator[AsyncUnitOfWorkProtocol]:
        owner = _current_task()
        authority = _CURRENT_MUTATION.get()
        if authority is not None:
            if authority.owner is owner:
                raise RuntimeError("nested atomic mutation scope")
            raise RuntimeError("copied atomic mutation scope authority")

        async with self._factory() as uow:
            token = _CURRENT_MUTATION.set(_MutationAuthority(uow, owner))
            try:
                yield uow
            finally:
                _CURRENT_MUTATION.reset(token)

    def require_active_uow(self) -> AsyncUnitOfWorkProtocol:
        authority = _CURRENT_MUTATION.get()
        try:
            owner = _current_task()
        except RuntimeError:
            raise RuntimeError("no active atomic mutation scope") from None
        if authority is None or authority.owner is not owner:
            raise RuntimeError("no active atomic mutation scope")
        return authority.uow
