from __future__ import annotations

import asyncio
from typing import Protocol

import pytest
from tuntun_core.services.transactions.mutation_scope import AtomicMutationScope


class _ScopeProbeUnit(Protocol):
    async def commit(self) -> None: ...

    async def rollback(self) -> None: ...


class ScopeProbeFactory(Protocol):
    active: int
    persisted: int
    rollbacks: int

    def __call__(self) -> _ScopeProbeUnit: ...

    async def persisted_probe_count(self) -> int: ...

    async def probe_scope_is_absent(self, scope: object) -> bool: ...


@pytest.mark.asyncio
async def test_scope_is_task_local_rejects_nesting_and_rolls_back_on_failure(
    async_uow_factory: ScopeProbeFactory,
) -> None:
    scope = AtomicMutationScope(async_uow_factory)
    with pytest.raises(RuntimeError, match="no active atomic mutation scope"):
        scope.require_active_uow()

    with pytest.raises(RuntimeError, match="nested atomic mutation scope"):
        async with scope.open():
            assert scope.require_active_uow() is not None
            assert await asyncio.create_task(async_uow_factory.probe_scope_is_absent(scope))
            async with scope.open():
                pass

    assert await async_uow_factory.persisted_probe_count() == 0
    assert async_uow_factory.rollbacks == 1
    assert await asyncio.create_task(async_uow_factory.probe_scope_is_absent(scope)) is True


@pytest.mark.asyncio
async def test_scope_rejects_nesting_across_scope_instances(
    async_uow_factory: ScopeProbeFactory,
) -> None:
    first = AtomicMutationScope(async_uow_factory)
    second = AtomicMutationScope(async_uow_factory)

    async with first.open() as uow:
        with pytest.raises(RuntimeError, match="nested atomic mutation scope"):
            async with second.open():
                pass
        await uow.rollback()

    assert async_uow_factory.active == 0


@pytest.mark.asyncio
async def test_copied_child_task_cannot_open_or_use_parent_scope(
    async_uow_factory: ScopeProbeFactory,
) -> None:
    scope = AtomicMutationScope(async_uow_factory)

    async def child() -> tuple[str, str]:
        with pytest.raises(RuntimeError) as use_error:
            scope.require_active_uow()
        with pytest.raises(RuntimeError) as open_error:
            async with scope.open():
                pass
        return str(use_error.value), str(open_error.value)

    async with scope.open() as uow:
        use_message, open_message = await asyncio.create_task(child())
        assert "no active atomic mutation scope" in use_message
        assert "copied atomic mutation scope authority" in open_message
        await uow.rollback()


@pytest.mark.asyncio
async def test_scope_commits_only_when_coordinator_explicitly_commits(
    async_uow_factory: ScopeProbeFactory,
) -> None:
    scope = AtomicMutationScope(async_uow_factory)

    async with scope.open():
        pass
    assert async_uow_factory.persisted == 0

    async with scope.open() as uow:
        await uow.commit()
    assert async_uow_factory.persisted == 1
    with pytest.raises(RuntimeError, match="no active atomic mutation scope"):
        scope.require_active_uow()


@pytest.mark.asyncio
async def test_cancellation_clears_scope_and_rolls_back(
    async_uow_factory: ScopeProbeFactory,
) -> None:
    scope = AtomicMutationScope(async_uow_factory)
    entered = asyncio.Event()

    async def mutation() -> None:
        async with scope.open():
            entered.set()
            await asyncio.Future()

    task = asyncio.create_task(mutation())
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert async_uow_factory.active == 0
    assert async_uow_factory.persisted == 0
    assert async_uow_factory.rollbacks == 1
    with pytest.raises(RuntimeError, match="no active atomic mutation scope"):
        scope.require_active_uow()
