from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Callable, Coroutine, Generator
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass
from enum import Enum
from threading import Event, get_ident
from typing import Protocol, cast

import pytest
from sqlalchemy import text
from tuntun_contracts.base import Commitment
from tuntun_contracts.events import EventType
from tuntun_core.adapters.sqlcipher.async_unit_of_work import AsyncUnitOfWorkFactory
from tuntun_core.adapters.sqlcipher.repository_facade import AsyncRepositoryFacade
from tuntun_core.adapters.sqlcipher.unit_of_work import UnitOfWork
from tuntun_core.services.transactions.protocols import (
    AsyncUnitOfWorkProtocol,
    UnitOfWorkProtocol,
)


class CommitSignalProbe(Protocol):
    offer_count: int

    def offer_nowait(self) -> None: ...


class HouseholdFacadeFactory(Protocol):
    def bind(self, uow: object) -> object: ...


HOUSEHOLD_INSERT = text(
    "INSERT INTO households(id,display_label_ciphertext,timezone,created_at) "
    "VALUES(:id,:label,'Asia/Singapore',:now)"
)


def _household(identifier: str) -> dict[str, object]:
    return {
        "id": identifier,
        "label": b"ciphertext",
        "now": "2026-08-27T01:02:03.000004Z",
    }


def _insert_household(transaction: UnitOfWorkProtocol, identifier: str) -> None:
    transaction.execute(HOUSEHOLD_INSERT, _household(identifier))


def _count_households(engine: object) -> int:
    with engine.connect() as connection:  # type: ignore[attr-defined]
        return int(connection.execute(text("SELECT count(*) FROM households")).scalar_one())


async def _start_lingering_task() -> tuple[asyncio.Task[None], asyncio.Event]:
    started = asyncio.Event()
    stopped = asyncio.Event()

    async def linger() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    task = asyncio.create_task(linger())
    await started.wait()
    return task, stopped


@pytest.mark.asyncio
async def test_async_facade_keeps_one_worker_and_commits(migrated_database: object) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    try:
        async with factory() as uow:
            assert isinstance(uow, AsyncUnitOfWorkProtocol)
            worker = await uow.run_sync(lambda tx: (get_ident(), id(tx.connection)))
            await uow.run_sync(
                lambda tx: _insert_household(
                    tx,
                    "00000000-0000-0000-0000-000000000611",
                )
            )
            assert await uow.run_sync(lambda tx: (get_ident(), id(tx.connection))) == worker
            await uow.commit()

        assert uow._sync is None
        assert not factory._transaction_lock.locked()
        assert _count_households(engine) == 1
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_cancelled_context_rolls_back_and_never_leaves_writer_lock(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    try:
        with pytest.raises(asyncio.CancelledError):
            async with factory() as uow:
                await uow.run_sync(
                    lambda tx: _insert_household(
                        tx,
                        "00000000-0000-0000-0000-000000000612",
                    )
                )
                raise asyncio.CancelledError

        async with factory() as next_uow:
            assert (
                await next_uow.run_sync(
                    lambda tx: tx.execute(text("SELECT count(*) FROM households")).scalar_one()
                )
                == 0
            )
            await next_uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("point", ("before_lock", "during_begin", "after_begin"))
async def test_cancelled_entry_is_terminal_before_application_lock_release(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
    point: str,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    created: list[UnitOfWork] = []
    original_enter = UnitOfWork.__enter__
    begin_started = Event()
    release_begin = Event()

    def controlled_enter(unit: UnitOfWork) -> UnitOfWork:
        created.append(unit)
        if point == "during_begin":
            begin_started.set()
            assert release_begin.wait(timeout=5)
        result = original_enter(unit)
        if point == "after_begin":
            begin_started.set()
            assert release_begin.wait(timeout=5)
        return result

    monkeypatch.setattr(UnitOfWork, "__enter__", controlled_enter)
    held_lock = False
    try:
        if point == "before_lock":
            await factory._transaction_lock.acquire()
            held_lock = True
        pending = factory()
        task = asyncio.create_task(pending.__aenter__())
        if point == "before_lock":
            await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            factory._transaction_lock.release()
            held_lock = False
        else:
            assert await asyncio.to_thread(begin_started.wait, 5)
            task.cancel()
            task.cancel()
            release_begin.set()
            with pytest.raises(asyncio.CancelledError):
                await task

        assert pending._sync is None
        assert not factory._transaction_lock.locked()
        assert all(unit.connection is None or unit.connection.closed for unit in created)
        async with factory() as next_uow:
            assert (
                await next_uow.run_sync(
                    lambda tx: tx.execute(text("SELECT count(*) FROM households")).scalar_one()
                )
                == 0
            )
            await next_uow.rollback()
    finally:
        release_begin.set()
        if held_lock:
            factory._transaction_lock.release()
        await factory.aclose()


@pytest.mark.asyncio
async def test_waiting_entry_is_owned_before_application_lock_acquisition(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    await factory._transaction_lock.acquire()
    held_lock = True
    pending = factory()
    entering = asyncio.create_task(pending.__aenter__())
    try:
        await asyncio.sleep(0)
        assert not entering.done()
        assert pending._task_owner is entering
        with pytest.raises(RuntimeError, match="owning task"):
            await pending.aclose()

        entering.cancel()
        with pytest.raises(asyncio.CancelledError):
            await entering
        assert pending._task_owner is None
        assert pending._terminal_closed
    finally:
        entering.cancel()
        with suppress(asyncio.CancelledError):
            await entering
        if held_lock:
            factory._transaction_lock.release()
            held_lock = False
        await factory.aclose()


@pytest.mark.asyncio
async def test_typed_repository_facade_stays_on_transaction_worker(
    migrated_database: object,
    household_repository_facade: HouseholdFacadeFactory,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(
        engine,
        {"households": household_repository_facade},
    )
    try:
        async with factory() as uow:
            worker = await uow.run_sync(lambda tx: get_ident())
            created = await uow.households.insert_synthetic("00000000-0000-0000-0000-000000000613")
            assert created.worker_ident == worker
            captured_facade = uow.households
            await uow.rollback()

        with pytest.raises(RuntimeError, match="not active"):
            await captured_facade.insert_synthetic("00000000-0000-0000-0000-000000000614")
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_concurrent_units_serialize_whole_transaction_lifetimes(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    first_entered = asyncio.Event()
    release_first = asyncio.Event()
    entered: list[str] = []

    async def writer(identifier: str, hold: bool) -> None:
        async with factory() as uow:
            entered.append(identifier)
            if hold:
                first_entered.set()
                await release_first.wait()
            await uow.run_sync(lambda tx: _insert_household(tx, identifier))
            await uow.commit()

    try:
        first = asyncio.create_task(writer("00000000-0000-0000-0000-000000000615", True))
        await first_entered.wait()
        second = asyncio.create_task(writer("00000000-0000-0000-0000-000000000616", False))
        await asyncio.sleep(0)
        assert entered == ["00000000-0000-0000-0000-000000000615"]
        release_first.set()
        await asyncio.gather(first, second)
        assert entered == [
            "00000000-0000-0000-0000-000000000615",
            "00000000-0000-0000-0000-000000000616",
        ]
        assert _count_households(engine) == 2
    finally:
        release_first.set()
        await factory.aclose()


@pytest.mark.asyncio
async def test_child_task_cannot_use_or_terminate_parent_transaction(
    migrated_database: object,
    household_repository_facade: HouseholdFacadeFactory,
    nonblocking_commit_signal: CommitSignalProbe,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(
        engine,
        {"households": household_repository_facade},
    )
    factory.register_commit_signal("subject_revocation", nonblocking_commit_signal)
    direct_effects: list[str] = []
    identifier = "00000000-0000-0000-0000-000000000619"

    try:
        async with factory() as uow:
            await uow.run_sync(lambda tx: _insert_household(tx, identifier))

            async def child_attempts() -> None:
                with pytest.raises(RuntimeError, match="owning task"):
                    await uow.run_sync(lambda _tx: direct_effects.append("run_sync executed"))
                with pytest.raises(RuntimeError, match="owning task"):
                    await uow.households.insert_synthetic("00000000-0000-0000-0000-000000000620")
                with pytest.raises(RuntimeError, match="owning task"):
                    uow.signal_after_commit("subject_revocation")
                with pytest.raises(RuntimeError, match="owning task"):
                    await uow.commit()
                with pytest.raises(RuntimeError, match="owning task"):
                    await uow.rollback()
                with pytest.raises(RuntimeError, match="owning task"):
                    await uow.aclose()
                with pytest.raises(RuntimeError, match="owning task"):
                    await uow.__aexit__(None, None, None)

            await asyncio.create_task(child_attempts())

            assert direct_effects == []
            assert uow._sync is not None and uow._sync.active
            assert factory._transaction_lock.locked()
            assert (
                await uow.run_sync(
                    lambda tx: tx.execute(text("SELECT count(*) FROM households")).scalar_one()
                )
                == 1
            )
            await uow.commit()

        assert _count_households(engine) == 1
        assert nonblocking_commit_signal.offer_count == 0
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_fixed_post_commit_signal_fires_only_after_successful_commit(
    migrated_database: object,
    nonblocking_commit_signal: CommitSignalProbe,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    factory.register_commit_signal("subject_revocation", nonblocking_commit_signal)
    try:
        async with factory() as committed:
            committed.signal_after_commit("subject_revocation")
            await committed.commit()
        assert nonblocking_commit_signal.offer_count == 1

        async with factory() as rolled_back:
            rolled_back.signal_after_commit("subject_revocation")
            await rolled_back.rollback()
        assert nonblocking_commit_signal.offer_count == 1
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_post_commit_signal_failure_never_changes_committed_result(
    migrated_database: object,
    failing_nonblocking_commit_signal: CommitSignalProbe,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    factory.register_commit_signal(
        "subject_revocation",
        failing_nonblocking_commit_signal,
    )
    try:
        async with factory() as uow:
            await uow.run_sync(
                lambda tx: _insert_household(
                    tx,
                    "00000000-0000-0000-0000-000000000617",
                )
            )
            uow.signal_after_commit("subject_revocation")
            await uow.commit()

        assert failing_nonblocking_commit_signal.offer_count == 1
        assert factory.failed_commit_signal_count("subject_revocation") == 1
        assert _count_households(engine) == 1
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_commit_failure_never_fires_signal_and_is_rolled_back(
    migrated_database: object,
    nonblocking_commit_signal: CommitSignalProbe,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    factory.register_commit_signal("subject_revocation", nonblocking_commit_signal)
    commit_failure = RuntimeError("synthetic commit failure")

    def fail_commit(unit: UnitOfWork) -> None:
        del unit
        raise commit_failure

    monkeypatch.setattr(UnitOfWork, "commit", fail_commit)
    try:
        with pytest.raises(RuntimeError) as raised:
            async with factory() as uow:
                await uow.run_sync(
                    lambda tx: _insert_household(
                        tx,
                        "00000000-0000-0000-0000-000000000620",
                    )
                )
                uow.signal_after_commit("subject_revocation")
                await uow.commit()

        assert raised.value is commit_failure
        assert nonblocking_commit_signal.offer_count == 0
        assert _count_households(engine) == 0
        assert not factory._transaction_lock.locked()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_commit_error_remains_primary_when_async_exit_cannot_close(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    commit_failure = RuntimeError("synthetic commit primary")
    close_failure = RuntimeError("synthetic preterminal cleanup failure")
    original_commit = UnitOfWork.commit
    original_exit = UnitOfWork.__exit__

    def fail_commit(unit: UnitOfWork) -> None:
        del unit
        raise commit_failure

    def fail_exit(
        unit: UnitOfWork,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> bool:
        del unit, exc_type, exc, traceback
        raise close_failure

    monkeypatch.setattr(UnitOfWork, "commit", fail_commit)
    monkeypatch.setattr(UnitOfWork, "__exit__", fail_exit)
    pending = factory()
    try:
        with pytest.raises(RuntimeError) as raised:
            async with pending as uow:
                await uow.commit()

        assert raised.value is commit_failure
        assert any(
            "preterminal cleanup failure" in note for note in getattr(raised.value, "__notes__", ())
        )
        assert pending._sync is not None
        assert pending._sync.active
        assert factory._transaction_lock.locked()

        monkeypatch.setattr(UnitOfWork, "commit", original_commit)
        monkeypatch.setattr(UnitOfWork, "__exit__", original_exit)
        await pending.aclose()
        assert pending._sync is None
        assert not factory._transaction_lock.locked()
    finally:
        monkeypatch.setattr(UnitOfWork, "commit", original_commit)
        monkeypatch.setattr(UnitOfWork, "__exit__", original_exit)
        if pending._sync is not None:
            await pending.aclose()
        await factory.aclose()


@pytest.mark.asyncio
async def test_cancellation_after_terminal_commit_still_delivers_fixed_signal(
    migrated_database: object,
    nonblocking_commit_signal: CommitSignalProbe,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    factory.register_commit_signal("subject_revocation", nonblocking_commit_signal)
    original_commit = UnitOfWork.commit
    commit_finished = Event()
    release_commit = Event()

    def commit_then_block(unit: UnitOfWork) -> None:
        original_commit(unit)
        commit_finished.set()
        assert release_commit.wait(timeout=5)

    monkeypatch.setattr(UnitOfWork, "commit", commit_then_block)

    async def mutation() -> None:
        async with factory() as uow:
            await uow.run_sync(
                lambda tx: _insert_household(
                    tx,
                    "00000000-0000-0000-0000-000000000621",
                )
            )
            uow.signal_after_commit("subject_revocation")
            await uow.commit()

    try:
        task = asyncio.create_task(mutation())
        assert await asyncio.to_thread(commit_finished.wait, 5)
        task.cancel()
        task.cancel()
        release_commit.set()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert nonblocking_commit_signal.offer_count == 1
        assert _count_households(engine) == 1
        assert not factory._transaction_lock.locked()
    finally:
        release_commit.set()
        await factory.aclose()


@pytest.mark.asyncio
async def test_signal_registration_is_fixed_before_first_unit_and_names_only(
    migrated_database: object,
    nonblocking_commit_signal: CommitSignalProbe,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    factory.register_commit_signal("subject_revocation", nonblocking_commit_signal)
    with pytest.raises(RuntimeError, match="registration"):
        factory.register_commit_signal("subject_revocation", nonblocking_commit_signal)
    pending = factory()
    with pytest.raises(RuntimeError, match="registration"):
        factory.register_commit_signal("late", nonblocking_commit_signal)
    try:
        async with pending as uow:
            with pytest.raises(RuntimeError, match="unregistered"):
                uow.signal_after_commit("dynamic")
            with pytest.raises(RuntimeError, match="unregistered"):
                uow.signal_after_commit(cast(str, lambda: None))
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_signal_registration_rejects_noncallable_and_async_targets(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)

    class NonCallableTarget:
        offer_nowait = 42

    class AsyncTarget:
        async def offer_nowait(self) -> None:
            await asyncio.sleep(0)

    try:
        with pytest.raises(RuntimeError, match="registration"):
            factory.register_commit_signal(
                "noncallable", cast(CommitSignalProbe, NonCallableTarget())
            )
        with pytest.raises(RuntimeError, match="registration"):
            factory.register_commit_signal("async_target", cast(CommitSignalProbe, AsyncTarget()))
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_signal_registration_remains_closed_after_factory_shutdown(
    migrated_database: object,
    nonblocking_commit_signal: CommitSignalProbe,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)

    await factory.aclose()
    with pytest.raises(RuntimeError, match="registration"):
        factory.register_commit_signal("late", nonblocking_commit_signal)


@pytest.mark.asyncio
async def test_signal_returning_awaitable_is_closed_and_counted_as_failure(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)

    class AwaitableTarget:
        def __init__(self) -> None:
            self.result: Coroutine[object, object, None] | None = None

        def offer_nowait(self) -> object:
            async def forbidden() -> None:
                await asyncio.sleep(0)

            self.result = forbidden()
            return self.result

    target = AwaitableTarget()
    factory.register_commit_signal("subject_revocation", cast(CommitSignalProbe, target))
    try:
        async with factory() as uow:
            uow.signal_after_commit("subject_revocation")
            await uow.commit()

        assert factory.failed_commit_signal_count("subject_revocation") == 1
        assert target.result is not None
        assert target.result.cr_frame is None
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_signal_returning_task_is_cancelled_terminally_before_commit_returns(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    task, stopped = await _start_lingering_task()

    class TaskTarget:
        def offer_nowait(self) -> object:
            return task

    factory.register_commit_signal(
        "subject_revocation",
        cast(CommitSignalProbe, TaskTarget()),
    )
    try:
        async with factory() as uow:
            uow.signal_after_commit("subject_revocation")
            await uow.commit()
            assert task.done()
            assert task.cancelled()
            assert stopped.is_set()

        assert factory.failed_commit_signal_count("subject_revocation") == 1
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        await factory.aclose()


@pytest.mark.asyncio
async def test_every_transaction_operation_uses_the_factory_worker(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    event_loop_ident = get_ident()
    calls: list[tuple[str, int]] = []
    original_enter = UnitOfWork.__enter__
    original_commit = UnitOfWork.commit
    original_rollback = UnitOfWork.rollback
    original_exit = UnitOfWork.__exit__

    def wrap(name: str, operation: Callable[..., object]) -> Callable[..., object]:
        def wrapped(*args: object, **kwargs: object) -> object:
            calls.append((name, get_ident()))
            return operation(*args, **kwargs)

        return wrapped

    monkeypatch.setattr(UnitOfWork, "__enter__", wrap("enter", original_enter))
    monkeypatch.setattr(UnitOfWork, "commit", wrap("commit", original_commit))
    monkeypatch.setattr(UnitOfWork, "rollback", wrap("rollback", original_rollback))
    monkeypatch.setattr(UnitOfWork, "__exit__", wrap("close", original_exit))
    factory = AsyncUnitOfWorkFactory(engine)
    try:
        async with factory() as committed:
            await committed.run_sync(lambda tx: calls.append(("run_sync", get_ident())))
            await committed.commit()
        async with factory() as rolled_back:
            await rolled_back.rollback()
    finally:
        await factory.aclose()

    worker_idents = {worker for _, worker in calls}
    assert worker_idents
    assert worker_idents == {calls[0][1]}
    assert event_loop_ident not in worker_idents
    assert {name for name, _ in calls} >= {
        "enter",
        "run_sync",
        "commit",
        "rollback",
        "close",
    }


@pytest.mark.asyncio
async def test_cancelled_run_sync_finishes_then_rolls_back_before_unlock(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    operation_started = Event()
    release_operation = Event()

    def blocking_insert(transaction: UnitOfWork) -> None:
        operation_started.set()
        assert release_operation.wait(timeout=5)
        transaction.execute(
            HOUSEHOLD_INSERT,
            _household("00000000-0000-0000-0000-000000000618"),
        )

    async def mutation() -> None:
        async with factory() as uow:
            await uow.run_sync(blocking_insert)

    try:
        task = asyncio.create_task(mutation())
        assert await asyncio.to_thread(operation_started.wait, 5)
        task.cancel()
        task.cancel()
        assert not task.done()
        release_operation.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not factory._transaction_lock.locked()
        assert _count_households(engine) == 0
    finally:
        release_operation.set()
        await factory.aclose()


@pytest.mark.asyncio
async def test_factory_shutdown_waits_for_live_unit_and_prevents_reopening(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    async with factory() as uow:
        shutdown = asyncio.create_task(factory.aclose())
        await asyncio.sleep(0)
        assert not shutdown.done()
        with pytest.raises(RuntimeError, match="shutting down"):
            factory()
        await uow.rollback()
    await shutdown
    await factory.aclose()
    with pytest.raises(RuntimeError, match="shut down"):
        factory()


@pytest.mark.asyncio
async def test_factory_shutdown_from_transaction_owner_fails_fast(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    pending = factory()
    await pending.__aenter__()

    async def rescue_current_implementation() -> None:
        await asyncio.sleep(0.05)
        if pending._sync is not None:
            await pending.rollback()
            await pending.__aexit__(None, None, None)

    rescue = asyncio.create_task(rescue_current_implementation())
    try:
        with pytest.raises(RuntimeError, match="active transaction"):
            await factory.aclose()
    finally:
        rescue.cancel()
        with suppress(asyncio.CancelledError):
            await rescue
        if pending._sync is not None:
            await pending.rollback()
            await pending.__aexit__(None, None, None)
        await factory.aclose()


@pytest.mark.asyncio
async def test_cancelled_factory_shutdown_is_terminal_before_propagation(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    async with factory() as uow:
        shutdown = asyncio.create_task(factory.aclose())
        await asyncio.sleep(0)
        shutdown.cancel()
        shutdown.cancel()
        assert not shutdown.done()
        await uow.rollback()

    with pytest.raises(asyncio.CancelledError):
        await shutdown
    await factory.aclose()
    with pytest.raises(RuntimeError, match="shut down"):
        factory()


@pytest.mark.asyncio
async def test_unit_constructed_before_shutdown_cannot_enter_dead_executor(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    pending = factory()

    await factory.aclose()
    with pytest.raises(RuntimeError, match="shut down"):
        await pending.__aenter__()

    assert pending._sync is None
    assert not factory._transaction_lock.locked()


@pytest.mark.asyncio
async def test_async_close_before_enter_permanently_rejects_later_entry(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    pending = factory()
    try:
        await pending.aclose()
        await pending.aclose()
        with pytest.raises(RuntimeError, match="closed"):
            await pending.__aenter__()
        assert pending._sync is None
        assert not factory._transaction_lock.locked()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_queued_pre_shutdown_unit_is_rejected_before_worker_submission(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    active = factory()
    await active.__aenter__()
    queued = factory()
    queued_entry = asyncio.create_task(queued.__aenter__())
    await asyncio.sleep(0)
    shutdown = asyncio.create_task(factory.aclose())
    await asyncio.sleep(0)

    assert not queued_entry.done()
    assert not shutdown.done()
    await active.rollback()
    await active.__aexit__(None, None, None)

    with pytest.raises(RuntimeError, match="shutting down"):
        await queued_entry
    await shutdown
    assert queued._sync is None
    assert not factory._transaction_lock.locked()


@pytest.mark.asyncio
async def test_async_close_failure_does_not_replace_body_error(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    original_exit = UnitOfWork.__exit__
    close_failure = RuntimeError("synthetic async close failure")

    def failing_exit(
        unit: UnitOfWork,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> bool:
        original_exit(unit, exc_type, exc, traceback)  # type: ignore[arg-type]
        raise close_failure

    monkeypatch.setattr(UnitOfWork, "__exit__", failing_exit)
    body_error = ValueError("async body remains primary")
    try:
        with pytest.raises(ValueError) as raised:
            async with factory():
                raise body_error
        assert raised.value is body_error
        assert any("close failure" in note for note in getattr(raised.value, "__notes__", ()))
        assert not factory._transaction_lock.locked()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_preterminal_close_failure_retains_sync_and_lock_until_async_retry(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    original_exit = UnitOfWork.__exit__
    close_failure = RuntimeError("synthetic preterminal close failure")
    attempts = 0

    def fail_once_before_close(
        unit: UnitOfWork,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> bool:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise close_failure
        return original_exit(unit, exc_type, exc, traceback)  # type: ignore[arg-type]

    monkeypatch.setattr(UnitOfWork, "__exit__", fail_once_before_close)
    pending = factory()
    try:
        with pytest.raises(RuntimeError) as raised:
            async with pending as uow:
                await uow.run_sync(
                    lambda tx: _insert_household(
                        tx,
                        "00000000-0000-0000-0000-000000000619",
                    )
                )

        assert raised.value is close_failure
        assert pending._sync is not None
        assert pending._sync.connection is not None
        assert not pending._sync.connection.closed
        assert factory._transaction_lock.locked()

        await pending.aclose()
        assert pending._sync is None
        assert not factory._transaction_lock.locked()
        assert _count_households(engine) == 0
    finally:
        if pending._sync is not None:
            await pending.aclose()
        await factory.aclose()


@pytest.mark.asyncio
async def test_entry_failure_retains_live_writer_when_cleanup_cannot_close(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    original_enter = UnitOfWork.__enter__
    original_exit = UnitOfWork.__exit__
    entry_failure = RuntimeError("synthetic failure immediately after begin")
    close_failure = RuntimeError("synthetic entry cleanup close failure")

    def enter_then_fail(unit: UnitOfWork) -> UnitOfWork:
        original_enter(unit)
        raise entry_failure

    def fail_before_close(
        unit: UnitOfWork,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> bool:
        del unit, exc_type, exc, traceback
        raise close_failure

    monkeypatch.setattr(UnitOfWork, "__enter__", enter_then_fail)
    monkeypatch.setattr(UnitOfWork, "__exit__", fail_before_close)
    pending = factory()
    try:
        with pytest.raises(RuntimeError) as raised:
            await pending.__aenter__()

        assert raised.value is entry_failure
        assert any(
            "entry cleanup close failure" in note for note in getattr(raised.value, "__notes__", ())
        )
        assert pending._sync is not None
        assert pending._sync.active
        assert factory._transaction_lock.locked()

        monkeypatch.setattr(UnitOfWork, "__exit__", original_exit)
        await pending.aclose()
        assert pending._sync is None
        assert not factory._transaction_lock.locked()
    finally:
        monkeypatch.setattr(UnitOfWork, "__exit__", original_exit)
        if pending._sync is not None:
            await pending.aclose()
        await factory.aclose()


@pytest.mark.asyncio
async def test_async_close_retry_keeps_lock_after_repeated_preterminal_failure(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    pending = factory()
    await pending.__aenter__()
    original_close = UnitOfWork.close
    close_failure = RuntimeError("synthetic explicit async close failure")
    close_attempts = 0

    def fail_once_before_close(unit: UnitOfWork) -> None:
        nonlocal close_attempts
        close_attempts += 1
        if close_attempts == 1:
            raise close_failure
        original_close(unit)

    monkeypatch.setattr(UnitOfWork, "close", fail_once_before_close)
    try:
        await pending.run_sync(
            lambda tx: _insert_household(
                tx,
                "00000000-0000-0000-0000-000000000622",
            )
        )
        with pytest.raises(RuntimeError) as raised:
            await pending.aclose()
        assert raised.value is close_failure
        assert pending._sync is not None
        assert pending._sync.active
        assert factory._transaction_lock.locked()

        await pending.aclose()
        assert pending._sync is None
        assert not factory._transaction_lock.locked()
        assert _count_households(engine) == 0
    finally:
        monkeypatch.setattr(UnitOfWork, "close", original_close)
        if pending._sync is not None:
            await pending.aclose()
        await factory.aclose()


@pytest.mark.asyncio
async def test_failed_owner_claim_never_releases_authority_it_did_not_claim(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    pending = factory()
    claim_failure = RuntimeError("synthetic owner claim failure")
    release_count = 0

    def fail_claim() -> None:
        raise claim_failure

    def record_release() -> None:
        nonlocal release_count
        release_count += 1

    pending._claim_owner = fail_claim
    pending._release_owner = record_release
    try:
        with pytest.raises(RuntimeError) as raised:
            await pending.__aenter__()

        assert raised.value is claim_failure
        assert release_count == 0
        assert pending._sync is None
        assert not factory._transaction_lock.locked()
    finally:
        if factory._transaction_lock.locked():
            factory._transaction_lock.release()
        await factory.aclose()


@pytest.mark.asyncio
async def test_owner_release_failure_retains_lock_until_explicit_close_retry(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    pending = factory()
    await pending.__aenter__()
    await pending.rollback()
    original_release = pending._release_owner
    release_failure = RuntimeError("synthetic owner release failure")
    release_count = 0

    def fail_once() -> None:
        nonlocal release_count
        release_count += 1
        if release_count == 1:
            raise release_failure
        original_release()

    pending._release_owner = fail_once
    try:
        with pytest.raises(RuntimeError) as raised:
            await pending.__aexit__(None, None, None)

        assert raised.value is release_failure
        assert factory._transaction_lock.locked()
        assert pending._owns_lock

        await pending.aclose()
        assert release_count == 2
        assert not factory._transaction_lock.locked()
        assert not pending._owns_lock
    finally:
        pending._release_owner = original_release
        if factory._transaction_lock.locked():
            original_release()
            factory._transaction_lock.release()
        await factory.aclose()


@pytest.mark.asyncio
async def test_body_error_survives_owner_release_failure_and_close_retry(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    pending = factory()
    original_release = pending._release_owner
    release_failure = RuntimeError("synthetic owner release cleanup failure")
    body_failure = ValueError("body remains primary")
    release_count = 0

    def fail_once() -> None:
        nonlocal release_count
        release_count += 1
        if release_count == 1:
            raise release_failure
        original_release()

    pending._release_owner = fail_once
    try:
        with pytest.raises(ValueError) as raised:
            async with pending:
                raise body_failure

        assert raised.value is body_failure
        assert any(
            "owner release cleanup failure" in note
            for note in getattr(raised.value, "__notes__", ())
        )
        assert factory._transaction_lock.locked()
        assert pending._owns_lock

        await pending.aclose()
        assert release_count == 2
        assert not factory._transaction_lock.locked()
    finally:
        pending._release_owner = original_release
        if factory._transaction_lock.locked():
            original_release()
            factory._transaction_lock.release()
        await factory.aclose()


@pytest.mark.asyncio
async def test_facade_binding_failure_rolls_back_closes_and_unlocks(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    bind_failure = RuntimeError("synthetic facade bind failure")

    class FailingFacadeFactory:
        def bind(self, uow: object) -> object:
            del uow
            raise bind_failure

    factory = AsyncUnitOfWorkFactory(engine, {"households": FailingFacadeFactory()})
    pending = factory()
    try:
        with pytest.raises(RuntimeError) as raised:
            await pending.__aenter__()
        assert raised.value is bind_failure
        assert pending._sync is None
        assert not factory._transaction_lock.locked()
    finally:
        await factory.aclose()


def test_repository_facade_registration_rejects_unsafe_or_untyped_names(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]

    class FacadeFactory:
        def bind(self, uow: object) -> object:
            return uow

    class NonCallableFacadeFactory:
        bind = 42

    class AsyncFacadeFactory:
        async def bind(self, uow: object) -> object:
            await asyncio.sleep(0)
            return uow

    for name in ("commit", "_sync", "not-an-identifier"):
        with pytest.raises(ValueError, match="invalid repository facade"):
            AsyncUnitOfWorkFactory(engine, {name: FacadeFactory()})
    with pytest.raises(ValueError, match="invalid repository facade"):
        AsyncUnitOfWorkFactory(
            engine,
            {"households": cast(HouseholdFacadeFactory, NonCallableFacadeFactory())},
        )
    with pytest.raises(ValueError, match="invalid repository facade"):
        AsyncUnitOfWorkFactory(
            engine,
            {"households": cast(HouseholdFacadeFactory, AsyncFacadeFactory())},
        )


@pytest.mark.asyncio
async def test_facade_bind_task_is_cancelled_before_failed_entry_releases_lock(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    task, stopped = await _start_lingering_task()

    class TaskFacadeFactory:
        def bind(self, uow: object) -> object:
            del uow
            return task

    factory = AsyncUnitOfWorkFactory(
        engine,
        {"households": cast(HouseholdFacadeFactory, TaskFacadeFactory())},
    )
    pending = factory()
    try:
        with pytest.raises(TypeError, match="synchronous"):
            await pending.__aenter__()

        assert task.done()
        assert task.cancelled()
        assert stopped.is_set()
        assert pending._sync is None
        assert not factory._transaction_lock.locked()
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        if pending._sync is not None:
            await pending.aclose()
        await factory.aclose()


@pytest.mark.asyncio
async def test_generic_repository_facade_rejects_awaitable_repository_operation(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)

    class Repository:
        def __init__(self, transaction: UnitOfWork) -> None:
            self.transaction = transaction

    async def forbidden_external_await() -> int:
        await asyncio.sleep(0)
        return 1

    try:
        async with factory() as uow:
            facade = AsyncRepositoryFacade(uow, Repository)
            with pytest.raises(TypeError, match="synchronous"):
                await facade.run(lambda _repository: forbidden_external_await())
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_repository_object_may_hold_transaction_only_inside_worker(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)

    @dataclass(frozen=True, slots=True)
    class Repository:
        transaction: UnitOfWorkProtocol

    try:
        async with factory() as uow:
            facade = AsyncRepositoryFacade(uow, Repository)
            assert (
                await facade.run(
                    lambda repository: repository.transaction.exec_driver_sql(
                        "SELECT 1"
                    ).scalar_one()
                )
                == 1
            )
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_repository_operation_task_is_cancelled_before_rejection_returns(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    task, stopped = await _start_lingering_task()

    class Repository:
        def __init__(self, transaction: UnitOfWork) -> None:
            self.transaction = transaction

    try:
        async with factory() as uow:
            facade = AsyncRepositoryFacade(uow, Repository)
            with pytest.raises(TypeError, match="synchronous"):
                await facade.run(lambda _repository: task)
            assert task.done()
            assert task.cancelled()
            assert stopped.is_set()
            await uow.rollback()
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        await factory.aclose()


@pytest.mark.asyncio
async def test_generic_repository_facade_rejects_async_repository_factory(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)

    async def forbidden_factory(transaction: object) -> object:
        await asyncio.sleep(0)
        return transaction

    try:
        async with factory() as uow:
            facade = AsyncRepositoryFacade(uow, forbidden_factory)  # type: ignore[arg-type]
            with pytest.raises(TypeError, match="synchronous"):
                await facade.run(lambda _repository: 1)
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_repository_factory_task_is_cancelled_before_rejection_returns(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    task, stopped = await _start_lingering_task()

    def forbidden_factory(transaction: object) -> object:
        del transaction
        return task

    try:
        async with factory() as uow:
            facade = AsyncRepositoryFacade(uow, forbidden_factory)  # type: ignore[arg-type]
            with pytest.raises(TypeError, match="synchronous"):
                await facade.run(lambda _repository: 1)
            assert task.done()
            assert task.cancelled()
            assert stopped.is_set()
            await uow.rollback()
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        await factory.aclose()


@pytest.mark.asyncio
async def test_run_sync_rejects_and_closes_awaitable_results(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)

    async def forbidden_external_await() -> int:
        await asyncio.sleep(0)
        return 1

    try:
        async with factory() as uow:
            coroutine = forbidden_external_await()
            with pytest.raises(TypeError, match="synchronous"):
                await uow.run_sync(lambda _transaction: coroutine)
            assert coroutine.cr_frame is None
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_run_sync_rejects_and_terminally_cancels_future_results(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    future = asyncio.get_running_loop().create_future()

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous"):
                await uow.run_sync(lambda _transaction: future)
            assert future.done()
            assert future.cancelled()
            await uow.rollback()
    finally:
        future.cancel()
        await factory.aclose()


@pytest.mark.asyncio
async def test_run_sync_rejects_and_terminally_cancels_task_results(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    task, stopped = await _start_lingering_task()

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous"):
                await uow.run_sync(lambda _transaction: task)
            assert task.done()
            assert task.cancelled()
            assert stopped.is_set()
            await uow.rollback()
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        await factory.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "result_kind",
    (
        "unit_of_work",
        "connection",
        "result",
        "generator",
        "async_generator",
        "callable",
        "nested_connection",
    ),
)
async def test_run_sync_rejects_live_or_deferred_database_capabilities(
    migrated_database: object,
    result_kind: str,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    produced: list[object] = []

    def make_result(transaction: UnitOfWork) -> object:
        def generator() -> object:
            yield 1

        async def async_generator() -> object:
            yield 1

        choices: dict[str, Callable[[], object]] = {
            "unit_of_work": lambda: transaction,
            "connection": lambda: transaction.connection,
            "result": lambda: transaction.execute(text("SELECT 1")),
            "generator": generator,
            "async_generator": async_generator,
            "callable": lambda: lambda: transaction,
            "nested_connection": lambda: {"connection": transaction.connection},
        }
        result = choices[result_kind]()
        produced.append(result)
        return result

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(make_result)

            assert produced
            if result_kind == "result":
                assert produced[0].closed  # type: ignore[attr-defined]
            elif result_kind == "generator":
                assert produced[0].gi_frame is None  # type: ignore[attr-defined]
            elif result_kind == "async_generator":
                assert produced[0].ag_frame is None  # type: ignore[attr-defined]
            assert await uow.run_sync(lambda tx: tx.exec_driver_sql("SELECT 1").scalar_one()) == 1
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_concurrent_future_result_finishes_before_rejection_returns(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    external_executor = ThreadPoolExecutor(max_workers=1)
    started = Event()
    release = Event()

    def blocking_result() -> int:
        started.set()
        assert release.wait(timeout=5)
        return 42

    external_future = external_executor.submit(blocking_result)
    try:
        async with factory() as uow:

            async def release_external_future() -> None:
                assert await asyncio.to_thread(started.wait, 5)
                await asyncio.sleep(0)
                assert factory._transaction_lock.locked()
                assert not external_future.done()
                release.set()

            releaser = asyncio.create_task(release_external_future())
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(lambda _transaction: external_future)
            await releaser
            assert external_future.done()
            assert external_future.result() == 42
            await uow.rollback()
    finally:
        release.set()
        external_executor.shutdown(wait=True, cancel_futures=True)
        await factory.aclose()


@pytest.mark.asyncio
async def test_cancellation_storm_waits_for_rejected_task_to_terminate_before_unlock(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    rejected_cancelled = asyncio.Event()
    release_rejected = asyncio.Event()
    rejected_stopped = asyncio.Event()

    async def stubborn_rejected_task() -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            rejected_cancelled.set()
            await release_rejected.wait()
            raise
        finally:
            rejected_stopped.set()

    rejected = asyncio.create_task(stubborn_rejected_task())
    await asyncio.sleep(0)

    async def mutation() -> None:
        async with factory() as uow:
            await uow.run_sync(lambda _transaction: rejected)

    mutation_task = asyncio.create_task(mutation())
    try:
        await rejected_cancelled.wait()
        mutation_task.cancel()
        mutation_task.cancel()
        await asyncio.sleep(0)
        assert not mutation_task.done()
        assert factory._transaction_lock.locked()

        release_rejected.set()
        with pytest.raises(asyncio.CancelledError):
            await mutation_task

        assert rejected.done()
        assert rejected.cancelled()
        assert rejected_stopped.is_set()
        assert not factory._transaction_lock.locked()
    finally:
        release_rejected.set()
        rejected.cancel()
        mutation_task.cancel()
        with suppress(asyncio.CancelledError, TypeError):
            await mutation_task
        with suppress(asyncio.CancelledError):
            await rejected
        await factory.aclose()


@pytest.mark.asyncio
async def test_run_sync_positive_data_boundary_rejects_opaque_capability_wrapper(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)

    class OpaqueCapabilityWrapper:
        def __init__(self, transaction: UnitOfWorkProtocol) -> None:
            self.transaction = transaction
            self.bound_execute = transaction.execute

    produced: list[OpaqueCapabilityWrapper] = []

    def wrap(transaction: UnitOfWorkProtocol) -> OpaqueCapabilityWrapper:
        wrapper = OpaqueCapabilityWrapper(transaction)
        produced.append(wrapper)
        return wrapper

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(wrap)

            assert produced
            assert produced[0].transaction is uow._sync
            assert await uow.run_sync(lambda tx: tx.exec_driver_sql("SELECT 1").scalar_one()) == 1
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_run_sync_rejects_frozen_record_with_custom_dunder_capability(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    produced: list[object] = []

    def make_record(transaction: UnitOfWorkProtocol) -> object:
        @dataclass(frozen=True, slots=True)
        class DunderCapabilityRecord:
            marker: str

            def __getstate__(self) -> object:
                return transaction

        record = DunderCapabilityRecord("unsafe")
        produced.append(record)
        return record

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(make_record)

            assert produced
            assert produced[0].__getstate__() is uow._sync  # type: ignore[attr-defined]
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_run_sync_rejects_frozen_record_with_custom_metaclass_capability(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    produced: list[object] = []

    def make_record(transaction: UnitOfWorkProtocol) -> object:
        class CapabilityMeta(type):
            @property
            def leak(cls) -> object:
                del cls
                return transaction

        @dataclass(frozen=True, slots=True)
        class MetaclassCapabilityRecord(metaclass=CapabilityMeta):
            marker: str

        record = MetaclassCapabilityRecord("unsafe")
        produced.append(record)
        return record

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(make_record)

            assert produced
            assert type(produced[0]).leak is uow._sync  # type: ignore[attr-defined]
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_run_sync_rejects_frozen_record_with_capability_in_field_metadata(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    produced: list[object] = []

    def make_record(transaction: UnitOfWorkProtocol) -> object:
        @dataclass(frozen=True, slots=True)
        class FieldCapabilityRecord:
            marker: str

        FieldCapabilityRecord.__dataclass_fields__["marker"].type = transaction
        record = FieldCapabilityRecord("unsafe")
        produced.append(record)
        return record

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(make_record)

            assert produced
            assert (
                type(produced[0]).__dataclass_fields__["marker"].type is uow._sync  # type: ignore[attr-defined]
            )
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_run_sync_rejects_enum_with_spoofed_contract_module(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)

    class SpoofedContractEnum(Enum):
        VALUE = "value"

    SpoofedContractEnum.__module__ = "tuntun_contracts.spoofed"

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(lambda _transaction: SpoofedContractEnum.VALUE)
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_run_sync_positive_data_boundary_allows_registered_contract_dto(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    commitment = Commitment(
        algorithm="HMAC-SHA-256",
        key_id="audit-v1",
        value_b64="A" * 43 + "=",
    )

    try:
        async with factory() as uow:
            assert await uow.run_sync(
                lambda _transaction: {"receipt": (commitment,), "event": EventType.WAKE_DETECTED},
            ) == {"receipt": (commitment,), "event": EventType.WAKE_DETECTED}
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_compound_rejected_tasks_are_all_terminal_and_deduplicated(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    first, first_stopped = await _start_lingering_task()
    second, second_stopped = await _start_lingering_task()

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(
                    lambda _transaction: {
                        "first": [first, {"duplicate": first}],
                        "second": (second,),
                    }
                )

            assert first.done() and first.cancelled() and first_stopped.is_set()
            assert second.done() and second.cancelled() and second_stopped.is_set()
            assert first.cancelling() == 1
            await uow.rollback()
    finally:
        for task in (first, second):
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        await factory.aclose()


@pytest.mark.asyncio
async def test_compound_concurrent_future_and_result_are_both_terminally_cleaned(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    external_executor = ThreadPoolExecutor(max_workers=1)
    started = Event()
    release = Event()
    produced_results: list[object] = []

    def blocking_result() -> int:
        started.set()
        assert release.wait(timeout=5)
        return 42

    external_future = external_executor.submit(blocking_result)

    def compound(transaction: UnitOfWorkProtocol) -> object:
        result = transaction.execute(text("SELECT 1"))
        produced_results.append(result)
        return {"future": external_future, "nested": [{"result": result}]}

    try:
        async with factory() as uow:

            async def release_external_future() -> None:
                assert await asyncio.to_thread(started.wait, 5)
                await asyncio.sleep(0)
                assert factory._transaction_lock.locked()
                assert not external_future.done()
                release.set()

            releaser = asyncio.create_task(release_external_future())
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(compound)
            await releaser

            assert external_future.done() and external_future.result() == 42
            assert produced_results and produced_results[0].closed  # type: ignore[attr-defined]
            await uow.rollback()
    finally:
        release.set()
        external_executor.shutdown(wait=True, cancel_futures=True)
        await factory.aclose()


@pytest.mark.asyncio
async def test_compound_cleanup_failure_keeps_rejection_primary_and_cleans_siblings(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    sibling, sibling_stopped = await _start_lingering_task()

    def failing_generator() -> Generator[object, None, None]:
        try:
            yield 1
        finally:
            raise RuntimeError("synthetic generator cleanup failure")

    generator = failing_generator()
    next(generator)

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value") as raised:
                await uow.run_sync(
                    lambda _transaction: {
                        "generator": generator,
                        "sibling": [sibling],
                    }
                )

            assert generator.gi_frame is None  # type: ignore[attr-defined]
            assert sibling.done() and sibling.cancelled() and sibling_stopped.is_set()
            assert any(
                "synthetic generator cleanup failure" in note
                for note in getattr(raised.value, "__notes__", ())
            )
            await uow.rollback()
    finally:
        generator.close()  # type: ignore[attr-defined]
        sibling.cancel()
        with suppress(asyncio.CancelledError):
            await sibling
        await factory.aclose()


@pytest.mark.asyncio
async def test_async_generator_cleanup_failure_is_not_allowed_to_replace_rejection(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)

    async def failing_async_generator() -> AsyncGenerator[object, None]:
        try:
            yield 1
        finally:
            raise RuntimeError("synthetic async generator cleanup failure")

    generator = failing_async_generator()
    assert await anext(generator) == 1

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value") as raised:
                await uow.run_sync(lambda _transaction: {"generator": generator})

            assert generator.ag_frame is None
            assert any(
                "synthetic async generator cleanup failure" in note
                for note in getattr(raised.value, "__notes__", ())
            )
            await uow.rollback()
    finally:
        with suppress(RuntimeError):
            await generator.aclose()
        await factory.aclose()


@pytest.mark.asyncio
async def test_compound_cancellation_storm_waits_for_every_rejected_task(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    first_cancelled = asyncio.Event()
    second_cancelled = asyncio.Event()
    release_rejected = asyncio.Event()
    first_stopped = asyncio.Event()
    second_stopped = asyncio.Event()

    async def stubborn_rejected_task(
        cancelled: asyncio.Event,
        stopped: asyncio.Event,
    ) -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            await release_rejected.wait()
            raise
        finally:
            stopped.set()

    first = asyncio.create_task(stubborn_rejected_task(first_cancelled, first_stopped))
    second = asyncio.create_task(stubborn_rejected_task(second_cancelled, second_stopped))
    await asyncio.sleep(0)

    async def mutation() -> None:
        async with factory() as uow:
            await uow.run_sync(lambda _transaction: ({"first": first}, [second, first]))

    mutation_task = asyncio.create_task(mutation())
    try:
        async with asyncio.timeout(2):
            await first_cancelled.wait()
            await second_cancelled.wait()
        mutation_task.cancel()
        mutation_task.cancel()
        await asyncio.sleep(0)
        assert not mutation_task.done()
        assert factory._transaction_lock.locked()

        release_rejected.set()
        with pytest.raises(asyncio.CancelledError) as raised:
            await mutation_task

        assert first.done() and first.cancelled() and first_stopped.is_set()
        assert second.done() and second.cancelled() and second_stopped.is_set()
        assert first.cancelling() == 1
        assert any(
            "synchronous data value" in note for note in getattr(raised.value, "__notes__", ())
        )
        assert not factory._transaction_lock.locked()
    finally:
        release_rejected.set()
        mutation_task.cancel()
        for task in (mutation_task, first, second):
            task.cancel()
            with suppress(asyncio.CancelledError, TypeError):
                await task
        await factory.aclose()
