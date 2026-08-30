from __future__ import annotations

import asyncio
import inspect
import weakref
from collections.abc import AsyncGenerator, Callable, Coroutine, Generator
from concurrent.futures import Future as ConcurrentFuture
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from threading import Barrier, Event, Lock, Thread, get_ident
from typing import Protocol, cast

import pytest
from sqlalchemy import text
from tuntun_contracts.base import Commitment
from tuntun_contracts.events import EventType
from tuntun_core.adapters.sqlcipher import repository_facade as repository_facade_module
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


def _run_in_fresh_event_loop(operation: Callable[[], Coroutine[object, object, None]]) -> None:
    asyncio.run(operation())


def _start_cleanup_watchdog(started: Event, release: Event) -> Thread:
    """Keep a regression probe bounded even when unsafe cleanup blocks a worker/loop."""

    def release_if_started() -> None:
        started.wait(timeout=0.25)
        release.set()

    watchdog = Thread(target=release_if_started, daemon=True)
    watchdog.start()
    return watchdog


def test_task_14_plan_does_not_overclaim_unowned_deferred_cleanup() -> None:
    plan = (
        Path(__file__).resolve().parents[3]
        / "docs/superpowers/plans/2026-08-27-tuntun-phase1-foundation-execution.md"
    ).read_text()
    task_14 = plan.split("### Task 14:", maxsplit=1)[1].split("### Task 15:", maxsplit=1)[0]

    assert (
        "cancels then awaits every rejected asyncio or concurrent `Future`/`Task` "
        "to terminal completion"
    ) not in task_14
    assert "fixed bounded event-loop-turn cleanup windows" not in task_14
    assert (
        "Rejected same-loop futures, tasks, and async generators receive cancellation"
        not in task_14
    )
    assert "factory-owned bounded strong quarantine" in task_14
    assert (
        "It never cancels, closes, awaits, calls, or otherwise runs arbitrary rejected" in task_14
    )
    assert "process-lifetime strong quarantine" in task_14


@pytest.mark.asyncio
async def test_factory_concurrent_first_use_binds_exactly_one_running_loop(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    start = Barrier(2)
    after_call = Barrier(2)
    selection_lock = Lock()
    selected = False
    begin_calls = 0
    original_enter = UnitOfWork.__enter__

    def counted_enter(unit: UnitOfWork) -> UnitOfWork:
        nonlocal begin_calls
        with selection_lock:
            begin_calls += 1
        return original_enter(unit)

    monkeypatch.setattr(UnitOfWork, "__enter__", counted_enter)

    def contender() -> tuple[str, str]:
        async def attempt() -> tuple[str, str]:
            nonlocal selected
            start.wait(timeout=5)
            try:
                pending = factory()
            except RuntimeError as error:
                outcome = ("rejected", str(error))
                after_call.wait(timeout=5)
                return outcome

            after_call.wait(timeout=5)
            with selection_lock:
                should_enter = not selected
                if should_enter:
                    selected = True
            if not should_enter:
                await pending.aclose()
                return ("constructed", "")
            try:
                async with pending as uow:
                    await uow.rollback()
                return ("entered", "")
            finally:
                await factory.aclose()

        return asyncio.run(attempt())

    executor = ThreadPoolExecutor(max_workers=2)
    try:
        first = asyncio.wrap_future(executor.submit(contender))
        second = asyncio.wrap_future(executor.submit(contender))
        results = await asyncio.gather(first, second)

        assert sorted(result[0] for result in results) == ["entered", "rejected"]
        assert next(message for status, message in results if status == "rejected") == (
            "async unit-of-work factory belongs to another event loop"
        )
        assert begin_calls == 1
    finally:
        executor.shutdown(wait=True, cancel_futures=True)


@pytest.mark.asyncio
async def test_preconstructed_uow_foreign_loop_entry_has_zero_state_or_sql_effects(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    pending = factory()
    begin_calls = 0
    original_enter = UnitOfWork.__enter__

    def counted_enter(unit: UnitOfWork) -> UnitOfWork:
        nonlocal begin_calls
        begin_calls += 1
        return original_enter(unit)

    async def foreign_entry() -> None:
        entered = await pending.__aenter__()
        await entered.rollback()
        await entered.__aexit__(None, None, None)

    monkeypatch.setattr(UnitOfWork, "__enter__", counted_enter)
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        foreign = asyncio.wrap_future(executor.submit(_run_in_fresh_event_loop, foreign_entry))
        with pytest.raises(
            RuntimeError,
            match="async unit-of-work factory belongs to another event loop",
        ):
            await foreign

        assert pending._entered is False
        assert pending._task_owner is None
        assert pending._sync is None
        assert factory._active_owner is None
        assert not factory._transaction_lock.locked()
        assert begin_calls == 0

        async with pending as uow:
            assert await uow.run_sync(lambda tx: tx.exec_driver_sql("SELECT 1").scalar_one()) == 1
            await uow.rollback()
        assert begin_calls == 1
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
        await factory.aclose()


@pytest.mark.asyncio
async def test_foreign_loop_factory_and_preconstructed_uow_close_have_zero_effects(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    pending = factory()

    async def foreign_factory_close() -> None:
        await factory.aclose()

    async def foreign_uow_close() -> None:
        await pending.aclose()

    executor = ThreadPoolExecutor(max_workers=1)
    try:
        for operation in (foreign_factory_close, foreign_uow_close):
            foreign = asyncio.wrap_future(executor.submit(_run_in_fresh_event_loop, operation))
            with pytest.raises(
                RuntimeError,
                match="async unit-of-work factory belongs to another event loop",
            ):
                await foreign

            assert factory._closing is False
            assert factory._closed is False
            assert factory._shutdown_task is None
            assert factory._active_owner is None
            assert pending._terminal_closed is False
            assert pending._entered is False
            assert pending._sync is None

        async with pending as uow:
            await uow.rollback()
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
        await factory.aclose()


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
async def test_signal_returning_awaitable_is_quarantined_and_counted_as_failure(
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
        assert target.result.cr_frame is not None
        assert factory.quarantined_result_count() == 1
        assert uow._sync is None
        assert not factory._transaction_lock.locked()
    finally:
        await factory.aclose()
        if target.result is not None:
            target.result.close()


@pytest.mark.asyncio
async def test_signal_returning_task_is_quarantined_before_commit_returns(
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
            assert not task.done()
            assert task.cancelling() == 0
            assert not stopped.is_set()

        assert factory.failed_commit_signal_count("subject_revocation") == 1
        assert factory.quarantined_result_count() == 1
        assert uow._sync is None
        assert not factory._transaction_lock.locked()
    finally:
        await factory.aclose()
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


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
async def test_facade_bind_task_is_quarantined_before_failed_entry_releases_lock(
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

        assert not task.done()
        assert task.cancelling() == 0
        assert not stopped.is_set()
        assert pending._sync is None
        assert not factory._transaction_lock.locked()
        assert factory.quarantined_result_count() == 1
    finally:
        if pending._sync is not None:
            await pending.aclose()
        await factory.aclose()
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_generic_repository_facade_rejects_awaitable_repository_operation(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)

    class Repository:
        def __init__(self, transaction: UnitOfWork) -> None:
            self.transaction = transaction

    produced: list[Coroutine[object, object, int]] = []

    async def forbidden_external_await() -> int:
        await asyncio.sleep(0)
        return 1

    def make_forbidden() -> Coroutine[object, object, int]:
        result = forbidden_external_await()
        produced.append(result)
        return result

    try:
        async with factory() as uow:
            facade = AsyncRepositoryFacade(uow, Repository)
            with pytest.raises(TypeError, match="synchronous"):
                await facade.run(lambda _repository: make_forbidden())
            assert uow._sync is None
            assert factory.quarantined_result_count() == 1
    finally:
        await factory.aclose()
        for coroutine in produced:
            coroutine.close()


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
async def test_repository_operation_task_is_quarantined_before_rejection_returns(
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
            assert not task.done()
            assert task.cancelling() == 0
            assert not stopped.is_set()
            assert uow._sync is None
    finally:
        await factory.aclose()
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_generic_repository_facade_rejects_async_repository_factory(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)

    produced: list[Coroutine[object, object, object]] = []

    async def forbidden_factory_async(transaction: object) -> object:
        await asyncio.sleep(0)
        return transaction

    def forbidden_factory(transaction: object) -> object:
        result = forbidden_factory_async(transaction)
        produced.append(result)
        return result

    try:
        async with factory() as uow:
            facade = AsyncRepositoryFacade(uow, forbidden_factory)  # type: ignore[arg-type]
            with pytest.raises(TypeError, match="synchronous"):
                await facade.run(lambda _repository: 1)
            assert uow._sync is None
    finally:
        await factory.aclose()
        for coroutine in produced:
            coroutine.close()


@pytest.mark.asyncio
async def test_repository_factory_task_is_quarantined_before_rejection_returns(
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
            assert not task.done()
            assert task.cancelling() == 0
            assert not stopped.is_set()
            assert uow._sync is None
    finally:
        await factory.aclose()
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_run_sync_quarantines_awaitable_results_without_closing_them(
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
            assert coroutine.cr_frame is not None
            assert uow._sync is None
    finally:
        await factory.aclose()
        coroutine.close()


@pytest.mark.asyncio
async def test_run_sync_quarantines_future_results_without_cancelling_them(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    future = asyncio.get_running_loop().create_future()

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous"):
                await uow.run_sync(lambda _transaction: future)
            assert not future.done()
            assert uow._sync is None
    finally:
        await factory.aclose()
        future.cancel()


@pytest.mark.asyncio
async def test_run_sync_quarantines_task_results_without_cancelling_them(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    task, stopped = await _start_lingering_task()

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous"):
                await uow.run_sync(lambda _transaction: task)
            assert not task.done()
            assert task.cancelling() == 0
            assert not stopped.is_set()
            assert uow._sync is None
    finally:
        await factory.aclose()
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_running_foreign_loop_future_is_rejected_without_wait_or_cancellation(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    published: ConcurrentFuture[asyncio.Future[None]] = ConcurrentFuture()
    stop_foreign_loop = Event()

    def run_foreign_loop() -> None:
        async def serve() -> None:
            published.set_result(asyncio.get_running_loop().create_future())
            while not stop_foreign_loop.is_set():
                await asyncio.sleep(0.001)

        asyncio.run(serve())

    executor = ThreadPoolExecutor(max_workers=1)
    foreign_runner = executor.submit(run_foreign_loop)
    foreign_future = await asyncio.to_thread(published.result, 5)
    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value") as raised:
                await uow.run_sync(lambda _transaction: foreign_future)

            assert not foreign_future.done()
            assert any(
                "strongly quarantined" in note for note in getattr(raised.value, "__notes__", ())
            )
            assert uow._sync is None

        async with factory() as next_uow:
            assert (
                await next_uow.run_sync(lambda tx: tx.exec_driver_sql("SELECT 1").scalar_one()) == 1
            )
            await next_uow.rollback()
    finally:
        stop_foreign_loop.set()
        await asyncio.wrap_future(foreign_runner)
        executor.shutdown(wait=True, cancel_futures=True)
        await factory.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("close_owner_loop", (False, True), ids=("stopped", "closed"))
async def test_stopped_or_closed_foreign_loop_future_is_rejected_without_touch(
    migrated_database: object,
    close_owner_loop: bool,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    foreign_loop = asyncio.new_event_loop()
    foreign_future = foreign_loop.create_future()
    if close_owner_loop:
        foreign_loop.close()

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value") as raised:
                await uow.run_sync(lambda _transaction: foreign_future)

            assert not foreign_future.done()
            assert any(
                "strongly quarantined" in note for note in getattr(raised.value, "__notes__", ())
            )
            assert uow._sync is None
    finally:
        if not foreign_loop.is_closed():
            foreign_loop.close()
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
                assert not produced[0].closed  # type: ignore[attr-defined]
            elif result_kind == "generator":
                assert produced[0].gi_frame is not None  # type: ignore[attr-defined]
            elif result_kind == "async_generator":
                assert produced[0].ag_frame is not None  # type: ignore[attr-defined]
            assert uow._sync is None

        async with factory() as next_uow:
            assert (
                await next_uow.run_sync(
                    lambda transaction: transaction.exec_driver_sql("SELECT 1").scalar_one()
                )
                == 1
            )
            await next_uow.rollback()
    finally:
        await factory.aclose()
        if produced and result_kind in ("result", "generator"):
            produced[0].close()  # type: ignore[attr-defined]
        elif produced and result_kind == "async_generator":
            await produced[0].aclose()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_running_concurrent_future_never_holds_transaction_cleanup_open(
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
    notes: tuple[str, ...] = ()

    async def mutation() -> None:
        nonlocal notes
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value") as raised:
                await uow.run_sync(lambda _transaction: external_future)
            notes = tuple(getattr(raised.value, "__notes__", ()))
            assert uow._sync is None

    mutation_task = asyncio.create_task(mutation())
    try:
        assert await asyncio.to_thread(started.wait, 5)
        done, _ = await asyncio.wait((mutation_task,), timeout=0.5)
        assert done == {mutation_task}
        await mutation_task
        assert not external_future.done()
        assert any("strongly quarantined" in note for note in notes)
        assert not factory._transaction_lock.locked()

        async with factory() as next_uow:
            assert (
                await next_uow.run_sync(lambda tx: tx.exec_driver_sql("SELECT 1").scalar_one()) == 1
            )
            await next_uow.rollback()
    finally:
        await factory.aclose()
        release.set()
        with suppress(TypeError):
            await mutation_task
        external_executor.shutdown(wait=True, cancel_futures=True)


@pytest.mark.asyncio
async def test_non_cooperative_local_task_never_holds_transaction_cleanup_open(
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

    notes: tuple[str, ...] = ()

    async def mutation() -> None:
        nonlocal notes
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value") as raised:
                await uow.run_sync(lambda _transaction: rejected)
            notes = tuple(getattr(raised.value, "__notes__", ()))
            assert uow._sync is None

    mutation_task = asyncio.create_task(mutation())
    try:
        done, _ = await asyncio.wait((mutation_task,), timeout=0.5)
        assert done == {mutation_task}
        await mutation_task
        assert not rejected_cancelled.is_set()
        assert not rejected.done()
        assert rejected.cancelling() == 0
        assert any("strongly quarantined" in note for note in notes)
        assert not factory._transaction_lock.locked()

        async with factory() as next_uow:
            assert (
                await next_uow.run_sync(lambda tx: tx.exec_driver_sql("SELECT 1").scalar_one()) == 1
            )
            await next_uow.rollback()
    finally:
        if not mutation_task.done():
            mutation_task.cancel()
        with suppress(asyncio.CancelledError, TypeError):
            await mutation_task
        await factory.aclose()
        rejected.cancel()
        await asyncio.sleep(0)
        assert rejected_cancelled.is_set()
        release_rejected.set()
        with suppress(asyncio.CancelledError):
            await rejected
        assert rejected_stopped.is_set()


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
            assert produced[0].transaction.closed  # type: ignore[attr-defined]
            assert uow._sync is None
            with pytest.raises(RuntimeError, match="poisoned"):
                await uow.run_sync(lambda transaction: transaction)

        async with factory() as next_uow:
            assert (
                await next_uow.run_sync(
                    lambda transaction: transaction.exec_driver_sql("SELECT 1").scalar_one()
                )
                == 1
            )
            await next_uow.rollback()
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
            escaped = produced[0].__getstate__()  # type: ignore[attr-defined]
            assert escaped.closed  # type: ignore[attr-defined]
            assert uow._sync is None
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
            escaped = type(produced[0]).leak  # type: ignore[attr-defined]
            assert escaped.closed  # type: ignore[attr-defined]
            assert uow._sync is None
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
                type(produced[0]).__dataclass_fields__["marker"].type.closed  # type: ignore[attr-defined]
            )
            assert uow._sync is None
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
            assert uow._sync is None
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
async def test_compound_rejected_tasks_are_strongly_quarantined_without_cleanup(
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

            assert not first.done() and not first_stopped.is_set()
            assert not second.done() and not second_stopped.is_set()
            assert first.cancelling() == 0
            assert second.cancelling() == 0
            assert factory.quarantined_result_count() == 3
            assert uow._sync is None
    finally:
        await factory.aclose()
        for task in (first, second):
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task


@pytest.mark.asyncio
async def test_compound_result_and_running_future_are_quarantined_without_cleanup(
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
    safety_release: asyncio.Task[None] | None = None

    def compound(transaction: UnitOfWorkProtocol) -> object:
        result = transaction.execute(text("SELECT 1"))
        produced_results.append(result)
        return {"future": external_future, "nested": [{"result": result}]}

    try:
        async with factory() as uow:

            async def release_if_cleanup_regresses() -> None:
                await asyncio.sleep(0.5)
                release.set()

            assert await asyncio.to_thread(started.wait, 5)
            safety_release = asyncio.create_task(release_if_cleanup_regresses())
            with pytest.raises(TypeError, match="synchronous data value") as raised:
                await uow.run_sync(compound)

            assert not release.is_set()
            assert not external_future.done()
            assert produced_results and not produced_results[0].closed  # type: ignore[attr-defined]
            assert any(
                "strongly quarantined" in note for note in getattr(raised.value, "__notes__", ())
            )
            assert uow._sync is None
    finally:
        if safety_release is not None:
            safety_release.cancel()
            with suppress(asyncio.CancelledError):
                await safety_release
        await factory.aclose()
        if produced_results:
            produced_results[0].close()  # type: ignore[attr-defined]
        release.set()
        external_executor.shutdown(wait=True, cancel_futures=True)


@pytest.mark.asyncio
async def test_compound_cleanup_failure_is_never_invoked_by_boundary_rejection(
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

            assert generator.gi_frame is not None  # type: ignore[attr-defined]
            assert not sibling.done() and not sibling_stopped.is_set()
            assert not any(
                "synthetic generator cleanup failure" in note
                for note in getattr(raised.value, "__notes__", ())
            )
            assert uow._sync is None
    finally:
        await factory.aclose()
        with suppress(RuntimeError):
            generator.close()  # type: ignore[attr-defined]
        sibling.cancel()
        with suppress(asyncio.CancelledError):
            await sibling


@pytest.mark.asyncio
async def test_async_generator_cleanup_failure_is_never_invoked_by_boundary_rejection(
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

            assert generator.ag_frame is not None
            assert not any(
                "synthetic async generator cleanup failure" in note
                for note in getattr(raised.value, "__notes__", ())
            )
            assert uow._sync is None
    finally:
        await factory.aclose()
        with suppress(RuntimeError):
            await generator.aclose()


@pytest.mark.asyncio
async def test_compound_cancellation_storm_preserves_rejection_and_releases_writer(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    release_rejected = asyncio.Event()
    first_stopped = asyncio.Event()
    second_stopped = asyncio.Event()
    close_started = Event()
    close_release = Event()
    original_exit = UnitOfWork.__exit__

    def blocking_exit(
        unit: UnitOfWork,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> bool:
        close_started.set()
        assert close_release.wait(timeout=5)
        return original_exit(unit, exc_type, exc, traceback)  # type: ignore[arg-type]

    monkeypatch.setattr(UnitOfWork, "__exit__", blocking_exit)

    async def stubborn_rejected_task(
        stopped: asyncio.Event,
    ) -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await release_rejected.wait()
            raise
        finally:
            stopped.set()

    first = asyncio.create_task(stubborn_rejected_task(first_stopped))
    second = asyncio.create_task(stubborn_rejected_task(second_stopped))
    await asyncio.sleep(0)

    async def mutation() -> None:
        async with factory() as uow:
            await uow.run_sync(lambda _transaction: ({"first": first}, [second, first]))

    mutation_task = asyncio.create_task(mutation())
    try:
        assert await asyncio.to_thread(close_started.wait, 5)
        mutation_task.cancel()
        mutation_task.cancel()
        close_release.set()
        done, _ = await asyncio.wait((mutation_task,), timeout=0.5)
        assert done == {mutation_task}
        with pytest.raises(TypeError, match="synchronous data value") as raised:
            await mutation_task

        assert not first.done() and not first_stopped.is_set()
        assert not second.done() and not second_stopped.is_set()
        assert first.cancelling() == 0
        assert second.cancelling() == 0
        assert any(
            "strongly quarantined" in note for note in getattr(raised.value, "__notes__", ())
        )
        assert any("CancelledError" in note for note in getattr(raised.value, "__notes__", ()))
        assert not factory._transaction_lock.locked()

        async with factory() as next_uow:
            assert (
                await next_uow.run_sync(lambda tx: tx.exec_driver_sql("SELECT 1").scalar_one()) == 1
            )
            await next_uow.rollback()
    finally:
        close_release.set()
        mutation_task.cancel()
        with suppress(asyncio.CancelledError, TypeError):
            await mutation_task
        await factory.aclose()
        release_rejected.set()
        for task in (first, second):
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task


@pytest.mark.asyncio
async def test_pending_concurrent_future_callback_never_runs_under_writer_ownership(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    pending = factory()
    uow = await pending.__aenter__()
    future: ConcurrentFuture[None] = ConcurrentFuture()
    boundary_returned = Event()
    callback_started = Event()
    callback_release = Event()
    observations: list[tuple[bool, bool]] = []

    def blocking_done_callback(_future: ConcurrentFuture[None]) -> None:
        observations.append((boundary_returned.is_set(), factory._transaction_lock.locked()))
        callback_started.set()
        assert callback_release.wait(timeout=5)

    future.add_done_callback(blocking_done_callback)
    watchdog = _start_cleanup_watchdog(callback_started, callback_release)
    try:
        try:
            with pytest.raises(TypeError, match="synchronous data value") as raised:
                await uow.run_sync(lambda _transaction: future)
        finally:
            boundary_returned.set()

        assert observations == []
        assert not future.done()
        assert any("quarantine" in note for note in getattr(raised.value, "__notes__", ()))
        assert uow._sync is None
        assert not factory._transaction_lock.locked()
        await uow.__aexit__(None, None, None)
        await uow.aclose()

        async with factory() as next_uow:
            assert (
                await next_uow.run_sync(
                    lambda transaction: transaction.exec_driver_sql("SELECT 1").scalar_one()
                )
                == 1
            )
            await next_uow.rollback()
    finally:
        boundary_returned.set()
        callback_release.set()
        if uow._sync is not None:
            await uow.aclose()
        await factory.aclose()
        future.cancel()
        await asyncio.to_thread(watchdog.join, 2)

    assert not watchdog.is_alive()
    assert observations == [(True, False)]


@pytest.mark.asyncio
async def test_same_loop_future_callback_never_runs_under_writer_ownership(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    uow = await factory().__aenter__()
    future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    boundary_returned = Event()
    callback_started = Event()
    callback_release = Event()
    observations: list[tuple[bool, bool]] = []

    def blocking_done_callback(_future: asyncio.Future[None]) -> None:
        observations.append((boundary_returned.is_set(), factory._transaction_lock.locked()))
        callback_started.set()
        assert callback_release.wait(timeout=5)

    future.add_done_callback(blocking_done_callback)
    watchdog = _start_cleanup_watchdog(callback_started, callback_release)
    try:
        try:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(lambda _transaction: future)
        finally:
            boundary_returned.set()

        assert observations == []
        assert not future.done()
        assert uow._sync is None
        assert not factory._transaction_lock.locked()
    finally:
        boundary_returned.set()
        callback_release.set()
        if uow._sync is not None:
            await uow.aclose()
        await factory.aclose()
        future.cancel()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await asyncio.to_thread(watchdog.join, 2)

    assert not watchdog.is_alive()
    assert observations == [(True, False)]


@pytest.mark.asyncio
async def test_task_cancellation_handler_never_runs_under_writer_ownership(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    uow = await factory().__aenter__()
    task_started = asyncio.Event()
    boundary_returned = Event()
    callback_started = Event()
    callback_release = Event()
    observations: list[tuple[bool, bool]] = []

    async def rejected_task() -> None:
        task_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            observations.append((boundary_returned.is_set(), factory._transaction_lock.locked()))
            callback_started.set()
            assert callback_release.wait(timeout=5)
            raise

    task = asyncio.create_task(rejected_task())
    await task_started.wait()
    watchdog = _start_cleanup_watchdog(callback_started, callback_release)
    try:
        try:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(lambda _transaction: task)
        finally:
            boundary_returned.set()

        assert observations == []
        assert not task.done()
        assert task.cancelling() == 0
        assert uow._sync is None
        assert not factory._transaction_lock.locked()
    finally:
        boundary_returned.set()
        callback_release.set()
        if uow._sync is not None:
            await uow.aclose()
        await factory.aclose()
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        await asyncio.to_thread(watchdog.join, 2)

    assert not watchdog.is_alive()
    assert observations == [(True, False)]


@pytest.mark.asyncio
async def test_primed_async_generator_finally_never_runs_under_writer_ownership(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    uow = await factory().__aenter__()
    boundary_returned = Event()
    finalizer_started = Event()
    finalizer_release = Event()
    observations: list[tuple[bool, bool]] = []

    async def rejected_generator() -> AsyncGenerator[object, None]:
        try:
            yield object()
        finally:
            observations.append((boundary_returned.is_set(), factory._transaction_lock.locked()))
            finalizer_started.set()
            assert finalizer_release.wait(timeout=5)

    generator = rejected_generator()
    await anext(generator)
    watchdog = _start_cleanup_watchdog(finalizer_started, finalizer_release)
    try:
        try:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(lambda _transaction: generator)
        finally:
            boundary_returned.set()

        assert observations == []
        assert generator.ag_frame is not None
        assert uow._sync is None
        assert not factory._transaction_lock.locked()
    finally:
        boundary_returned.set()
        finalizer_release.set()
        if uow._sync is not None:
            await uow.aclose()
        await factory.aclose()
        await generator.aclose()
        await asyncio.to_thread(watchdog.join, 2)

    assert not watchdog.is_alive()
    assert observations == [(True, False)]


@pytest.mark.asyncio
@pytest.mark.parametrize("deferred_kind", ("generator", "coroutine"))
async def test_sync_deferred_finalizer_never_runs_under_writer_ownership(
    migrated_database: object,
    deferred_kind: str,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    uow = await factory().__aenter__()
    boundary_returned = Event()
    finalizer_started = Event()
    finalizer_release = Event()
    observations: list[tuple[bool, bool]] = []

    def record_finalizer() -> None:
        observations.append((boundary_returned.is_set(), factory._transaction_lock.locked()))
        finalizer_started.set()
        assert finalizer_release.wait(timeout=5)

    def rejected_generator() -> Generator[object, None, None]:
        try:
            yield object()
        finally:
            record_finalizer()

    async def rejected_coroutine() -> None:
        try:
            await asyncio.sleep(0)
        finally:
            record_finalizer()

    if deferred_kind == "generator":
        deferred: object = rejected_generator()
        next(cast(Generator[object, None, None], deferred))
    else:
        deferred = rejected_coroutine()
        cast(Coroutine[object, object, None], deferred).send(None)

    watchdog = _start_cleanup_watchdog(finalizer_started, finalizer_release)
    try:
        try:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(lambda _transaction: deferred)
        finally:
            boundary_returned.set()

        assert observations == []
        assert uow._sync is None
        assert not factory._transaction_lock.locked()
    finally:
        boundary_returned.set()
        finalizer_release.set()
        if uow._sync is not None:
            await uow.aclose()
        await factory.aclose()
        deferred.close()  # type: ignore[union-attr]
        await asyncio.to_thread(watchdog.join, 2)

    assert not watchdog.is_alive()
    assert observations == [(True, False)]


@pytest.mark.asyncio
async def test_rejected_last_reference_is_strongly_quarantined_before_worker_unwinds(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    uow = await factory().__aenter__()
    boundary_returned = Event()
    observations: list[tuple[bool, bool]] = []

    class FinalizerProbe:
        def __del__(self) -> None:
            observations.append((boundary_returned.is_set(), factory._transaction_lock.locked()))

    try:
        try:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(lambda _transaction: FinalizerProbe())
        finally:
            boundary_returned.set()

        assert observations == []
        assert uow._sync is None
        assert not factory._transaction_lock.locked()
    finally:
        boundary_returned.set()
        if uow._sync is not None:
            await uow.aclose()
        await factory.aclose()

    assert observations == []


@pytest.mark.asyncio
async def test_quarantine_bound_is_observable_and_overflow_fails_later_entry_closed(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    rejected_graph = [object() for _ in range(64)]

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(lambda _transaction: rejected_graph)

            assert uow._sync is None
            assert factory.quarantined_result_count() == 65
            assert factory.quarantine_overflowed()

        with pytest.raises(RuntimeError, match="too many unsafe results"):
            factory()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_discovered_nested_generator_survives_concurrent_container_removal(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    boundary_returned = Event()
    discovered = Event()
    inspection_release = Event()
    observations: list[tuple[bool, bool]] = []

    def nested_generator() -> Generator[object, None, None]:
        try:
            yield object()
        finally:
            observations.append((boundary_returned.is_set(), factory._transaction_lock.locked()))

    generator = nested_generator()
    next(generator)
    generator_ref = weakref.ref(generator)
    shared: list[object] = [generator]
    entered_uow: list[object] = []
    del generator

    original_inspect = repository_facade_module._inspect_data_value

    def inspect_with_mutation_window(value: object, inspection: object) -> None:
        original_inspect(value, inspection)  # type: ignore[arg-type]
        if inspect.isgenerator(value):
            discovered.set()
            assert inspection_release.wait(timeout=5)

    monkeypatch.setattr(
        repository_facade_module,
        "_inspect_data_value",
        inspect_with_mutation_window,
    )

    async def reject_shared_result() -> None:
        async with factory() as uow:
            entered_uow.append(uow)
            try:
                with pytest.raises(TypeError, match="synchronous data value"):
                    await uow.run_sync(lambda _transaction: shared)
            finally:
                boundary_returned.set()

    rejection = asyncio.create_task(reject_shared_result())
    try:
        assert await asyncio.to_thread(discovered.wait, 5)
        shared.clear()
        inspection_release.set()
        await rejection

        assert observations == []
        assert generator_ref() is not None
        assert entered_uow and entered_uow[0]._sync is None  # type: ignore[attr-defined]
        assert not factory._transaction_lock.locked()
    finally:
        inspection_release.set()
        if not rejection.done():
            rejection.cancel()
        with suppress(asyncio.CancelledError, TypeError):
            await rejection
        await factory.aclose()
        retained_generator = generator_ref()
        if retained_generator is not None:
            retained_generator.close()

    assert observations == [(True, False)]
