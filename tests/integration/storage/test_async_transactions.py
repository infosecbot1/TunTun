from __future__ import annotations

import asyncio
import gc
import inspect
import weakref
from collections.abc import AsyncGenerator, Callable, Coroutine, Generator
from concurrent.futures import Future as ConcurrentFuture
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass, make_dataclass
from datetime import datetime, timedelta, tzinfo
from enum import Enum
from pathlib import Path
from threading import Barrier, Event, Lock, Thread, get_ident
from typing import Protocol, cast
from uuid import UUID, SafeUUID

import pytest
from pydantic_core import TzInfo
from sqlalchemy import text
from tuntun_contracts.base import Commitment, canonical_bytes
from tuntun_contracts.events import EventType
from tuntun_contracts.identity import IdentityDecision
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
    assert "owned recursive snapshot" in task_14
    assert "module-owned `_SynchronousDataRecord`" in task_14
    assert "64-source per-unit retention bound" in task_14
    assert "trusted in-process Enum singleton residual" in task_14
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
async def test_post_commit_signal_record_source_is_retained_until_context_unlock(
    migrated_database: object,
) -> None:
    @dataclass(frozen=True, slots=True)
    class Record:
        marker: str

    class RecordTarget:
        def offer_nowait(self) -> object:
            return Record("signal")

    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    observations: list[tuple[bool, bool]] = []
    factory.register_commit_signal(
        "subject_revocation",
        cast(CommitSignalProbe, RecordTarget()),
    )
    try:
        async with factory() as uow:
            uow.signal_after_commit("subject_revocation")
            await uow.commit()
            assert len(uow._result_sources_until_unlock) == 1

            def installed_finalizer(_value: object) -> None:
                observations.append((factory._transaction_lock.locked(), uow._sync is None))

            Record.__del__ = installed_finalizer  # type: ignore[attr-defined]
            assert observations == []

        assert observations == [(False, True)]
        assert factory.failed_commit_signal_count("subject_revocation") == 0
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
    source_observations: list[tuple[bool, bool]] = []

    @dataclass(frozen=True, slots=True)
    class Record:
        marker: str

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
        await pending.run_sync(lambda _transaction: Record("retained"))

        def installed_finalizer(_value: object) -> None:
            source_observations.append((factory._transaction_lock.locked(), pending._sync is None))

        Record.__del__ = installed_finalizer  # type: ignore[attr-defined]
        with pytest.raises(RuntimeError) as raised:
            await pending.aclose()
        assert raised.value is close_failure
        assert pending._sync is not None
        assert pending._sync.active
        assert factory._transaction_lock.locked()
        assert source_observations == []

        await pending.aclose()
        assert pending._sync is None
        assert not factory._transaction_lock.locked()
        assert source_observations == [(False, True)]
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
    original_release = pending._release_owner
    release_failure = RuntimeError("synthetic owner release failure")
    release_count = 0
    source_observations: list[tuple[bool, bool]] = []

    @dataclass(frozen=True, slots=True)
    class Record:
        marker: str

    def fail_once() -> None:
        nonlocal release_count
        release_count += 1
        if release_count == 1:
            raise release_failure
        original_release()

    pending._release_owner = fail_once
    try:
        await pending.run_sync(lambda _transaction: Record("retained"))
        await pending.rollback()

        def installed_finalizer(_value: object) -> None:
            source_observations.append((factory._transaction_lock.locked(), pending._sync is None))

        Record.__del__ = installed_finalizer  # type: ignore[attr-defined]
        with pytest.raises(RuntimeError) as raised:
            await pending.__aexit__(None, None, None)

        assert raised.value is release_failure
        assert factory._transaction_lock.locked()
        assert pending._owns_lock
        assert source_observations == []

        await pending.aclose()
        assert release_count == 2
        assert not factory._transaction_lock.locked()
        assert not pending._owns_lock
        assert source_observations == [(False, True)]
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

    def inspect_with_mutation_window(value: object, inspection: object) -> object:
        result = original_inspect(value, inspection)  # type: ignore[arg-type]
        if inspect.isgenerator(value):
            discovered.set()
            assert inspection_release.wait(timeout=5)
        return result

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


@pytest.mark.asyncio
async def test_run_sync_returns_owned_snapshot_before_alias_can_add_future(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    shared: list[object] = [1]
    validated = Event()
    inspection_release = Event()
    returned: list[object] = []
    entered_uow: list[object] = []
    future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    original_inspect = repository_facade_module._inspect_data_value

    def inspect_with_post_validation_window(value: object, inspection: object) -> object:
        result = original_inspect(value, inspection)  # type: ignore[arg-type]
        if value is shared:
            validated.set()
            assert inspection_release.wait(timeout=5)
        return result

    monkeypatch.setattr(
        repository_facade_module,
        "_inspect_data_value",
        inspect_with_post_validation_window,
    )

    async def return_shared_result() -> None:
        async with factory() as uow:
            entered_uow.append(uow)
            returned.append(await uow.run_sync(lambda _transaction: shared))
            await uow.rollback()

    operation = asyncio.create_task(return_shared_result())
    try:
        assert await asyncio.to_thread(validated.wait, 5)
        shared.append(future)
        inspection_release.set()
        await operation

        assert returned == [[1]]
        assert returned[0] is not shared
        assert not future.done()
        assert entered_uow and entered_uow[0]._sync is None  # type: ignore[attr-defined]
        assert not factory._transaction_lock.locked()
        assert factory.quarantined_result_count() == 0
    finally:
        inspection_release.set()
        if not operation.done():
            operation.cancel()
        with suppress(BaseException):
            await operation
        await factory.aclose()
        future.cancel()


@pytest.mark.asyncio
async def test_dict_mutation_after_discovery_is_terminally_quarantined(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    boundary_returned = Event()
    discovered = Event()
    inspection_release = Event()
    observations: list[tuple[bool, bool]] = []
    entered_uow: list[object] = []

    def nested_generator() -> Generator[object, None, None]:
        try:
            yield object()
        finally:
            observations.append((boundary_returned.is_set(), factory._transaction_lock.locked()))

    generator = nested_generator()
    next(generator)
    generator_ref = weakref.ref(generator)
    shared: dict[str, object] = {"unsafe": generator, "tail": 1}
    del generator

    original_inspect = repository_facade_module._inspect_data_value

    def inspect_with_mutation_window(value: object, inspection: object) -> object:
        result = original_inspect(value, inspection)  # type: ignore[arg-type]
        if inspect.isgenerator(value):
            discovered.set()
            assert inspection_release.wait(timeout=5)
        return result

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
        del shared["unsafe"]
        inspection_release.set()
        await rejection

        assert observations == []
        assert generator_ref() is not None
        assert factory.quarantined_result_count() == 2
        assert entered_uow and entered_uow[0]._sync is None  # type: ignore[attr-defined]
        assert not factory._transaction_lock.locked()

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
        inspection_release.set()
        if not rejection.done():
            rejection.cancel()
        with suppress(BaseException):
            await rejection
        await factory.aclose()
        retained_generator = generator_ref()
        if retained_generator is not None:
            retained_generator.close()

    assert observations == [(True, False)]


@pytest.mark.asyncio
async def test_snapshot_failure_after_discovery_is_terminally_quarantined(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    boundary_returned = Event()
    observations: list[tuple[bool, bool]] = []

    def nested_generator() -> Generator[object, None, None]:
        try:
            yield object()
        finally:
            observations.append((boundary_returned.is_set(), factory._transaction_lock.locked()))

    generator = nested_generator()
    next(generator)
    generator_ref = weakref.ref(generator)
    source: list[object] = [generator]
    del generator
    original_inspect = repository_facade_module._inspect_data_value

    def fail_after_discovery(value: object, inspection: object) -> object:
        result = original_inspect(value, inspection)  # type: ignore[arg-type]
        if inspect.isgenerator(value):
            raise RuntimeError("synthetic result snapshot failure")
        return result

    monkeypatch.setattr(repository_facade_module, "_inspect_data_value", fail_after_discovery)

    try:
        async with factory() as uow:
            try:
                with pytest.raises(TypeError, match="synchronous data value") as raised:
                    await uow.run_sync(lambda _transaction: source)
            finally:
                boundary_returned.set()

            assert raised.value.__cause__ is not None
            assert "synthetic result snapshot failure" in str(raised.value.__cause__)
            assert any("snapshot failed" in note for note in getattr(raised.value, "__notes__", ()))
            assert observations == []
            assert generator_ref() is not None
            assert factory.quarantined_result_count() == 2
            assert uow._sync is None
            assert not factory._transaction_lock.locked()

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
        await factory.aclose()
        retained_generator = generator_ref()
        if retained_generator is not None:
            retained_generator.close()

    assert observations == [(True, False)]


@pytest.mark.asyncio
async def test_snapshot_failure_transfers_nested_source_removed_by_concurrent_alias(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    boundary_returned = Event()
    nested_discovered = Event()
    traversal_release = Event()
    observations: list[tuple[bool, bool]] = []

    class FinalizableNestedSource:
        def __del__(self) -> None:
            observations.append((boundary_returned.is_set(), factory._transaction_lock.locked()))

    nested = FinalizableNestedSource()
    nested_identity = id(nested)
    nested_ref = weakref.ref(nested)
    source: dict[str, object] = {"nested": nested}
    del nested
    original_exact_type_in = repository_facade_module._exact_type_in

    def fail_after_source_discovery(
        value_type: type[object],
        candidates: tuple[type[object], ...],
    ) -> bool:
        if value_type is FinalizableNestedSource:
            nested_discovered.set()
            assert traversal_release.wait(timeout=5)
            raise RuntimeError("synthetic nested snapshot failure")
        return original_exact_type_in(value_type, candidates)

    monkeypatch.setattr(
        repository_facade_module,
        "_exact_type_in",
        fail_after_source_discovery,
    )

    async def reject_source() -> None:
        async with factory() as uow:
            try:
                with pytest.raises(TypeError, match="synchronous data value") as raised:
                    await uow.run_sync(lambda _transaction: source)
            finally:
                boundary_returned.set()

            retained = cast(tuple[object, ...], raised.value.values)  # type: ignore[attr-defined]
            assert any(id(value) == nested_identity for value in retained)
            assert raised.value.__cause__ is not None
            assert "synthetic nested snapshot failure" in str(raised.value.__cause__)
            assert observations == []
            assert nested_ref() is not None
            assert factory.quarantined_result_count() == 3
            assert uow._sync is None
            assert not factory._transaction_lock.locked()

    operation = asyncio.create_task(reject_source())
    try:
        assert await asyncio.to_thread(nested_discovered.wait, 5)
        del source["nested"]
        traversal_release.set()
        await operation

        assert observations == []
        assert nested_ref() is not None
    finally:
        boundary_returned.set()
        traversal_release.set()
        if not operation.done():
            operation.cancel()
        with suppress(BaseException):
            await operation
        await factory.aclose()


@pytest.mark.asyncio
async def test_supported_composites_are_rebuilt_with_owned_mutable_members(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    shared: list[object] = ["before"]

    @dataclass(frozen=True, slots=True)
    class MutableRecord:
        payload: object

    record = MutableRecord(shared)
    contract = Commitment(
        algorithm="HMAC-SHA-256",
        key_id="audit-v1",
        value_b64="A" * 43 + "=",
    )
    object.__setattr__(contract, "key_id", shared)
    source = {
        "record": record,
        "contract": contract,
        "aliases": [shared, shared],
    }

    try:
        async with factory() as uow:
            snapshot = await uow.run_sync(lambda _transaction: source)
            shared.append("after")

            assert snapshot is not source
            snapshot_record = cast(MutableRecord, snapshot["record"])
            snapshot_contract = cast(Commitment, snapshot["contract"])
            snapshot_aliases = cast(list[object], snapshot["aliases"])
            assert snapshot_record is not record
            assert type(snapshot_record) is not MutableRecord
            assert type(snapshot_record).__name__ == "_SynchronousDataRecord"
            assert snapshot_contract is not contract
            assert snapshot_record.payload == ["before"]
            assert snapshot_record.payload is snapshot_contract.key_id
            assert snapshot_record.payload is snapshot_aliases[0]
            assert snapshot_aliases[0] is snapshot_aliases[1]
            assert snapshot_record.payload is not shared
            second_record = await uow.run_sync(lambda _transaction: record)
            assert type(second_record) is type(snapshot_record)
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.parametrize(
    "expires_at",
    (
        "2026-08-27T00:00:00.000000Z",
        "2026-08-27T05:30:00.000000+05:30",
    ),
)
@pytest.mark.asyncio
async def test_pydantic_parsed_timezone_contract_is_snapshotted(
    migrated_database: object,
    expires_at: str,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    contract = IdentityDecision.model_validate_json(
        f'{{"status":"unknown","subject_id":null,"reason_code":"test","expires_at":"{expires_at}"}}'
    )
    expected_canonical = canonical_bytes(contract)

    assert type(contract.expires_at.tzinfo) is TzInfo

    try:
        async with factory() as uow:
            snapshot = await uow.run_sync(lambda _transaction: contract)

            assert snapshot is not contract
            assert type(snapshot) is IdentityDecision
            assert snapshot == contract
            assert type(snapshot.expires_at.tzinfo) is TzInfo
            assert canonical_bytes(snapshot) == expected_canonical
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_caller_defined_timezone_remains_rejected(
    migrated_database: object,
) -> None:
    class CallerTimezone(tzinfo):
        def utcoffset(self, value: datetime | None) -> timedelta:
            return timedelta(hours=5, minutes=30)

        def dst(self, value: datetime | None) -> timedelta:
            return timedelta(0)

    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    value = datetime(2026, 8, 27, tzinfo=CallerTimezone())

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(lambda _transaction: value)

            assert uow._sync is None
            assert not factory._transaction_lock.locked()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_result_classification_does_not_invoke_custom_metaclass(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    hook_started = Event()
    hook_release = Event()
    hooks_armed = Event()
    observations: list[tuple[str, bool, bool]] = []
    entered_uow: list[object] = []

    class BlockingMetaclass(type):
        def __getattribute__(cls, name: str) -> object:
            if hooks_armed.is_set():
                observations.append(
                    (
                        name,
                        factory._transaction_lock.locked(),
                        entered_uow[0]._sync is not None,  # type: ignore[attr-defined]
                    )
                )
                hook_started.set()
                assert hook_release.wait(timeout=5)
            return type.__getattribute__(cls, name)

    class CallerOwnedValue(metaclass=BlockingMetaclass):
        pass

    value = CallerOwnedValue()
    hooks_armed.set()
    watchdog = _start_cleanup_watchdog(hook_started, hook_release)
    try:
        async with factory() as uow:
            entered_uow.append(uow)
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(lambda _transaction: value)

            assert uow._sync is None
            assert not factory._transaction_lock.locked()
    finally:
        hooks_armed.clear()
        hook_release.set()
        watchdog.join(timeout=5)
        await factory.aclose()

    assert observations == []


@pytest.mark.asyncio
async def test_result_classification_does_not_invoke_instance_getattribute(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    hook_started = Event()
    hook_release = Event()
    hooks_armed = Event()
    observations: list[tuple[str, bool, bool]] = []
    entered_uow: list[object] = []

    class CallerOwnedValue:
        def __getattribute__(self, name: str) -> object:
            if hooks_armed.is_set():
                observations.append(
                    (
                        name,
                        factory._transaction_lock.locked(),
                        entered_uow[0]._sync is not None,  # type: ignore[attr-defined]
                    )
                )
                hook_started.set()
                assert hook_release.wait(timeout=5)
            return object.__getattribute__(self, name)

    value = CallerOwnedValue()
    hooks_armed.set()
    watchdog = _start_cleanup_watchdog(hook_started, hook_release)
    try:
        async with factory() as uow:
            entered_uow.append(uow)
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(lambda _transaction: value)

            assert uow._sync is None
            assert not factory._transaction_lock.locked()
    finally:
        hooks_armed.clear()
        hook_release.set()
        watchdog.join(timeout=5)
        await factory.aclose()

    assert observations == []


@pytest.mark.asyncio
async def test_registered_contract_hidden_state_is_terminally_quarantined(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    boundary_returned = Event()
    observations: list[tuple[bool, bool]] = []
    probe_refs: list[weakref.ReferenceType[object]] = []

    class Probe:
        def __del__(self) -> None:
            observations.append((boundary_returned.is_set(), factory._transaction_lock.locked()))

    def contract_with_hidden_state(_transaction: UnitOfWorkProtocol) -> Commitment:
        contract = Commitment(
            algorithm="HMAC-SHA-256",
            key_id="audit-v1",
            value_b64="A" * 43 + "=",
        )
        probe = Probe()
        probe_refs.append(weakref.ref(probe))
        contract.__dict__["hidden"] = probe
        return contract

    try:
        async with factory() as uow:
            try:
                with pytest.raises(TypeError, match="synchronous data value"):
                    await uow.run_sync(contract_with_hidden_state)
            finally:
                boundary_returned.set()

            assert observations == []
            assert probe_refs and probe_refs[0]() is not None
            assert uow._sync is None
            assert not factory._transaction_lock.locked()
    finally:
        boundary_returned.set()
        await factory.aclose()


@pytest.mark.parametrize("model_first", (True, False), ids=("model-first", "state-first"))
@pytest.mark.asyncio
async def test_registered_contract_snapshot_preserves_state_container_aliases(
    migrated_database: object,
    model_first: bool,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    contract = Commitment(
        algorithm="HMAC-SHA-256",
        key_id="audit-v1",
        value_b64="A" * 43 + "=",
    )
    source = (
        [contract, contract.__dict__, contract.__pydantic_fields_set__]
        if model_first
        else [contract.__dict__, contract.__pydantic_fields_set__, contract]
    )

    try:
        async with factory() as uow:
            snapshot = await uow.run_sync(lambda _transaction: source)
            snapshot_contract = cast(Commitment, snapshot[0 if model_first else 2])
            snapshot_dict = cast(dict[str, object], snapshot[1 if model_first else 0])
            snapshot_fields_set = cast(set[str], snapshot[2 if model_first else 1])

            assert snapshot_contract is not contract
            assert snapshot_contract.__dict__ is snapshot_dict
            assert snapshot_contract.__pydantic_fields_set__ is snapshot_fields_set
            assert snapshot_dict is not contract.__dict__
            assert snapshot_fields_set is not contract.__pydantic_fields_set__
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_exported_enum_state_drift_is_terminally_quarantined(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    member = EventType.WAKE_DETECTED
    future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    member.__dict__["hidden"] = future

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(lambda _transaction: member)

            assert not future.done()
            assert uow._sync is None
            assert not factory._transaction_lock.locked()
    finally:
        member.__dict__.pop("hidden", None)
        await factory.aclose()
        future.cancel()


@pytest.mark.asyncio
async def test_clean_exported_enum_preserves_singleton_identity(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)

    try:
        async with factory() as uow:
            assert (
                await uow.run_sync(lambda _transaction: EventType.WAKE_DETECTED)
                is EventType.WAKE_DETECTED
            )
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_uuid_is_rebuilt_with_exact_safe_state_and_aliases(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    value = UUID("00000000-0000-0000-0000-000000000001", is_safe=SafeUUID.safe)

    try:
        async with factory() as uow:
            snapshot = await uow.run_sync(lambda _transaction: [value, value])

            assert snapshot[0] is snapshot[1]
            assert snapshot[0] is not value
            assert type(snapshot[0]) is UUID
            assert snapshot[0] == value
            assert hash(snapshot[0]) == hash(value)
            assert str(snapshot[0]) == str(value)
            assert snapshot[0].is_safe is SafeUUID.safe
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.parametrize("slot_name", ("int", "is_safe"))
@pytest.mark.asyncio
async def test_uuid_state_drift_is_terminally_quarantined(
    migrated_database: object,
    slot_name: str,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    value = UUID(int=1)
    future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    object.__setattr__(value, slot_name, future)

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(lambda _transaction: value)

            assert not future.done()
            assert uow._sync is None
            assert not factory._transaction_lock.locked()
    finally:
        await factory.aclose()
        future.cancel()


@pytest.mark.parametrize(
    "mutation_kind",
    ("function-slot", "match-args", "field-flag", "annotation-key"),
)
@pytest.mark.asyncio
async def test_generated_record_shape_check_does_not_invoke_mutated_metadata(
    migrated_database: object,
    mutation_kind: str,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    hooks_armed = Event()
    observations: list[str] = []

    class Hook:
        def __getattribute__(self, name: str) -> object:
            if hooks_armed.is_set():
                observations.append(f"getattribute:{name}")
            return object.__getattribute__(self, name)

        def __hash__(self) -> int:
            if hooks_armed.is_set():
                observations.append("hash")
            return hash("marker")

        def __eq__(self, other: object) -> bool:
            if hooks_armed.is_set():
                observations.append("eq")
            return False

    @dataclass(frozen=True, slots=True)
    class Record:
        marker: str

    value = Record("safe")
    hook = Hook()
    if mutation_kind == "function-slot":
        Record.__repr__ = hook  # type: ignore[assignment]
    elif mutation_kind == "match-args":
        Record.__match_args__ = (hook,)  # type: ignore[assignment]
    elif mutation_kind == "field-flag":
        Record.__dataclass_fields__["marker"].init = hook  # type: ignore[assignment]
    else:
        Record.__init__.__annotations__[hook] = str  # type: ignore[index]
    hooks_armed.set()

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(lambda _transaction: value)

            assert uow._sync is None
            assert not factory._transaction_lock.locked()
    finally:
        hooks_armed.clear()
        await factory.aclose()

    assert observations == []


@pytest.mark.asyncio
async def test_generated_record_classification_does_not_hash_or_compare_namespace_keys(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    hooks_armed = Event()
    observations: list[str] = []

    class HookKey(str):
        def __hash__(self) -> int:
            if hooks_armed.is_set():
                observations.append("hash")
            return hash("__dataclass_fields__")

        def __eq__(self, other: object) -> bool:
            if hooks_armed.is_set():
                observations.append("eq")
            return str.__eq__(self, other)

    key = HookKey("hostile_metadata")
    future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    record_type = dataclass(frozen=True, slots=True)(
        type(
            "Record",
            (),
            {
                "__annotations__": {"marker": "str"},
                key: future,
            },
        )
    )
    assert any(type(name) is HookKey for name in vars(record_type))
    hooks_armed.set()
    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(lambda _transaction: record_type("safe"))

            assert uow._sync is None
            assert not factory._transaction_lock.locked()
    finally:
        hooks_armed.clear()
        await factory.aclose()
        future.cancel()

    assert observations == []


@pytest.mark.asyncio
async def test_repository_awaitable_check_does_not_invoke_instance_getattribute(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    hooks_armed = Event()
    observations: list[str] = []

    class Repository:
        def __getattribute__(self, name: str) -> object:
            if hooks_armed.is_set():
                observations.append(name)
            return object.__getattribute__(self, name)

    repository = Repository()
    hooks_armed.set()
    try:
        async with factory() as uow:
            facade = AsyncRepositoryFacade(uow, lambda _transaction: repository)
            assert await facade.run(lambda _repository: 1) == 1
            await uow.rollback()
    finally:
        hooks_armed.clear()
        await factory.aclose()

    assert observations == []


@pytest.mark.asyncio
async def test_repository_awaitable_check_does_not_compare_custom_class_keys(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    hooks_armed = Event()
    observations: list[str] = []

    class HookKey(str):
        def __hash__(self) -> int:
            if hooks_armed.is_set():
                observations.append("hash")
            return hash("__await__")

        def __eq__(self, other: object) -> bool:
            if hooks_armed.is_set():
                observations.append("eq")
            return str.__eq__(self, other)

    future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    repository_type = type(
        "Repository",
        (),
        {HookKey("hostile_metadata"): future},
    )
    assert any(type(name) is HookKey for name in vars(repository_type))
    hooks_armed.set()
    try:
        async with factory() as uow:
            facade = AsyncRepositoryFacade(uow, lambda _transaction: repository_type())
            with pytest.raises(TypeError, match="synchronous"):
                await facade.run(lambda _repository: 1)

            assert uow._sync is None
            assert not factory._transaction_lock.locked()
    finally:
        hooks_armed.clear()
        await factory.aclose()
        future.cancel()

    assert observations == []


@pytest.mark.asyncio
async def test_repository_facade_defers_the_single_result_snapshot_to_uow(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    duplicate_snapshot_calls: list[object] = []

    def reject_duplicate_snapshot(value: object) -> object:
        duplicate_snapshot_calls.append(value)
        raise AssertionError("repository facade attempted a duplicate result snapshot")

    monkeypatch.setattr(
        repository_facade_module,
        "_reject_worker_result",
        reject_duplicate_snapshot,
    )

    class Repository:
        pass

    try:
        async with factory() as uow:
            facade = AsyncRepositoryFacade(uow, lambda _transaction: Repository())
            assert await facade.run(lambda _repository: {"values": [1]}) == {"values": [1]}
            assert duplicate_snapshot_calls == []
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.parametrize(
    "state_name",
    ("__pydantic_extra__", "__pydantic_private__"),
)
@pytest.mark.asyncio
async def test_registered_contract_hidden_state_channels_are_fully_traversed(
    migrated_database: object,
    state_name: str,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    contract = Commitment(
        algorithm="HMAC-SHA-256",
        key_id="audit-v1",
        value_b64="A" * 43 + "=",
    )
    object.__setattr__(contract, state_name, {"hidden": [future]})

    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(lambda _transaction: contract)

            cast(dict[str, list[object]], object.__getattribute__(contract, state_name)).clear()
            assert not future.done()
            assert uow._sync is None
            assert not factory._transaction_lock.locked()
    finally:
        await factory.aclose()
        future.cancel()


@pytest.mark.asyncio
async def test_owned_snapshot_rebuilds_all_container_kinds_and_key_aliases(
    migrated_database: object,
) -> None:
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    shared: list[object] = ["shared"]
    tuple_key = ("key",)
    frozen_element = frozenset({"element"})
    source = {
        "aliases": (shared, shared),
        "mapping": {tuple_key: tuple_key},
        "set": {frozen_element},
        "frozenset": frozenset({("nested",)}),
    }

    try:
        async with factory() as uow:
            snapshot = await uow.run_sync(lambda _transaction: source)
            snapshot_aliases = cast(tuple[list[object], list[object]], snapshot["aliases"])
            snapshot_mapping = cast(dict[tuple[str], tuple[str]], snapshot["mapping"])
            snapshot_key = next(iter(snapshot_mapping))
            snapshot_set = cast(set[frozenset[str]], snapshot["set"])
            snapshot_frozen = cast(frozenset[tuple[str]], snapshot["frozenset"])

            assert snapshot is not source
            assert snapshot_aliases is not source["aliases"]
            assert snapshot_aliases[0] is snapshot_aliases[1]
            assert snapshot_aliases[0] is not shared
            assert snapshot_key is snapshot_mapping[snapshot_key]
            assert snapshot_key is not tuple_key
            assert next(iter(snapshot_set)) is not frozen_element
            assert snapshot_frozen is not source["frozenset"]
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.parametrize(
    "cycle_kind",
    ("list", "dict", "tuple-list", "record-list"),
)
@pytest.mark.asyncio
async def test_owned_snapshot_rejects_every_supported_cycle(
    migrated_database: object,
    cycle_kind: str,
) -> None:
    @dataclass(frozen=True, slots=True)
    class Record:
        payload: object

    if cycle_kind == "list":
        root: object = []
        cast(list[object], root).append(root)
    elif cycle_kind == "dict":
        root = {}
        cast(dict[str, object], root)["self"] = root
    elif cycle_kind == "tuple-list":
        member: list[object] = []
        root = (member,)
        member.append(root)
    else:
        member = []
        root = Record(member)
        member.append(root)

    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(lambda _transaction: root)

            assert uow._sync is None
            assert not factory._transaction_lock.locked()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_snapshot_identity_memo_keeps_strong_source_references(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @dataclass(frozen=True, slots=True)
    class Record:
        first: object
        second: object

    old_holder: dict[str, list[object]] = {"old": []}
    later: list[object] = []
    root = Record(old_holder["old"], later)
    old_identity = id(old_holder["old"])
    candidate_reused_identity: list[bool] = []
    mutated = False
    original_inspect = repository_facade_module._inspect_data_value

    def inspect_with_identity_reuse_window(value: object, inspection: object) -> object:
        nonlocal mutated
        was_old = not mutated and id(value) == old_identity
        result = original_inspect(value, inspection)  # type: ignore[arg-type]
        if was_old:
            mutated = True
            object.__setattr__(root, "first", None)
            old_holder.clear()
            value = None
            candidate: list[object] = ["NEW"]
            candidate_reused_identity.append(id(candidate) == old_identity)
            later.append(candidate)
        return result

    monkeypatch.setattr(
        repository_facade_module,
        "_inspect_data_value",
        inspect_with_identity_reuse_window,
    )
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    try:
        async with factory() as uow:
            snapshot = await uow.run_sync(lambda _transaction: root)
            assert snapshot.first == []
            assert snapshot.second == [["NEW"]]
            assert snapshot.first is not snapshot.second[0]
            assert candidate_reused_identity == [False]
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_record_class_mutation_after_validation_cannot_run_hash_hook(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @dataclass(frozen=True, slots=True)
    class RecordKey:
        marker: str

    key = RecordKey("key")
    source = {key: "value"}
    validated = Event()
    validation_release = Event()
    observations: list[tuple[bool, bool]] = []
    entered_uow: list[object] = []
    original_shape_check = repository_facade_module._has_exact_generated_record_shape

    def shape_check_with_mutation_window(
        record_type: type[object],
        field_names: tuple[str, ...],
        namespace: dict[str, object],
        inspection: object,
    ) -> bool:
        result = original_shape_check(
            record_type,
            field_names,
            namespace,
            inspection,  # type: ignore[arg-type]
        )
        if record_type is RecordKey:
            validated.set()
            assert validation_release.wait(timeout=5)
        return result

    monkeypatch.setattr(
        repository_facade_module,
        "_has_exact_generated_record_shape",
        shape_check_with_mutation_window,
    )
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)

    async def snapshot_mapping() -> None:
        async with factory() as uow:
            entered_uow.append(uow)
            snapshot = await uow.run_sync(lambda _transaction: source)
            assert type(next(iter(snapshot))) is not RecordKey
            await uow.rollback()

    operation = asyncio.create_task(snapshot_mapping())
    try:
        assert await asyncio.to_thread(validated.wait, 5)

        def mutated_hash(_value: object) -> int:
            observations.append(
                (
                    factory._transaction_lock.locked(),
                    entered_uow[0]._sync is not None,  # type: ignore[attr-defined]
                )
            )
            return 1

        RecordKey.__hash__ = mutated_hash  # type: ignore[assignment]
        validation_release.set()
        await operation

        assert observations == []
        assert not factory._transaction_lock.locked()
    finally:
        validation_release.set()
        if not operation.done():
            operation.cancel()
        with suppress(BaseException):
            await operation
        await factory.aclose()


@pytest.mark.asyncio
async def test_module_owned_record_type_is_sealed_and_resnapshots_idempotently(
    migrated_database: object,
) -> None:
    @dataclass(frozen=True, slots=True)
    class Record:
        marker: str

    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    try:
        async with factory() as uow:
            first = await uow.run_sync(lambda _transaction: Record("safe"))
            owned_type = type(first)

            def replacement(*_args: object) -> object:
                raise AssertionError("sealed record method replacement ran")

            for name in ("__hash__", "__eq__", "__repr__", "__del__"):
                with pytest.raises(TypeError, match="record type is sealed"):
                    setattr(owned_type, name, replacement)
            for name in ("__hash__", "__eq__", "__repr__"):
                with pytest.raises(TypeError, match="record type is sealed"):
                    delattr(owned_type, name)

            second = await uow.run_sync(lambda _transaction: first)
            assert second is not first
            assert type(second) is owned_type
            assert second == first
            assert hash(second) == hash(first)
            assert repr(second) == repr(first)
            await uow.rollback()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_owned_record_classifier_does_not_compare_hostile_namespace_keys(
    migrated_database: object,
) -> None:
    hooks_armed = Event()
    observations: list[str] = []

    class HookKey(str):
        def __hash__(self) -> int:
            if hooks_armed.is_set():
                observations.append("hash")
            return hash(repository_facade_module._OWNED_RECORD_SEAL_ATTRIBUTE)

        def __eq__(self, other: object) -> bool:
            if hooks_armed.is_set():
                observations.append("eq")
            return str.__eq__(self, other)

    future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    hostile_type = repository_facade_module._SealedOwnedRecordMeta(
        "HostileOwnedRecord",
        (),
        {HookKey("hostile_metadata"): future},
    )
    assert any(type(name) is HookKey for name in vars(hostile_type))
    hooks_armed.set()
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(lambda _transaction: hostile_type())

            assert observations == []
            assert uow._sync is None
            assert not factory._transaction_lock.locked()
    finally:
        hooks_armed.clear()
        await factory.aclose()
        future.cancel()


@pytest.mark.parametrize("container_kind", ("dict", "set"))
@pytest.mark.asyncio
async def test_sealed_owned_record_methods_cannot_change_during_later_key_snapshot(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
    container_kind: str,
) -> None:
    @dataclass(frozen=True, slots=True)
    class Record:
        marker: str

    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    async with factory() as first_uow:
        first = await first_uow.run_sync(lambda _transaction: Record("first"))
        await first_uow.rollback()
    owned_type = type(first)
    record_snapshotted = Event()
    snapshot_release = Event()
    hooks_called: list[str] = []
    original_inspect_record = repository_facade_module._inspect_frozen_record

    def inspect_record_with_mutation_window(
        value: object,
        inspection: object,
    ) -> object:
        snapshot = original_inspect_record(value, inspection)  # type: ignore[arg-type]
        if type(value) is Record:
            record_snapshotted.set()
            assert snapshot_release.wait(timeout=5)
        return snapshot

    monkeypatch.setattr(
        repository_facade_module,
        "_inspect_frozen_record",
        inspect_record_with_mutation_window,
    )

    def make_key_container(_transaction: object) -> object:
        key = Record("key")
        if container_kind == "dict":
            return {key: "value"}
        return {key}

    async def snapshot_key_container() -> object:
        async with factory() as uow:
            result = await uow.run_sync(make_key_container)
            await uow.rollback()
            return result

    operation = asyncio.create_task(snapshot_key_container())
    try:
        assert await asyncio.to_thread(record_snapshotted.wait, 5)
        assert factory._transaction_lock.locked()

        def replacement_hash(_value: object) -> int:
            hooks_called.append("hash")
            return 1

        def replacement_eq(_value: object, _other: object) -> bool:
            hooks_called.append("eq")
            return True

        def replacement_finalizer(_value: object) -> None:
            hooks_called.append("del")

        for name, replacement in (
            ("__hash__", replacement_hash),
            ("__eq__", replacement_eq),
            ("__del__", replacement_finalizer),
        ):
            with pytest.raises(TypeError, match="record type is sealed"):
                setattr(owned_type, name, replacement)
        with pytest.raises(TypeError, match="record type is sealed"):
            delattr(owned_type, "__repr__")

        snapshot_release.set()
        snapshot = await operation
        key = next(iter(snapshot))
        assert type(key) is owned_type
        assert len(snapshot) == 1
        assert hooks_called == []
        assert not factory._transaction_lock.locked()
    finally:
        snapshot_release.set()
        if not operation.done():
            operation.cancel()
        with suppress(BaseException):
            await operation
        await factory.aclose()


@pytest.mark.parametrize("container_kind", ("dict", "set"))
@pytest.mark.asyncio
async def test_normalized_record_keys_cannot_silently_collapse(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
    container_kind: str,
) -> None:
    @dataclass(frozen=True, slots=True)
    class LeftRecord:
        marker: str

    @dataclass(frozen=True, slots=True)
    class RightRecord:
        marker: str

    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    both_snapshotted = Event()
    snapshot_release = Event()
    boundary_returned = Event()
    entered_uow: list[object] = []
    source_ids: list[int] = []
    observations: list[tuple[bool, bool, bool]] = []
    inspected_records = 0
    original_inspect_record = repository_facade_module._inspect_frozen_record

    def inspect_record_with_finalizer_window(
        value: object,
        inspection: object,
    ) -> object:
        nonlocal inspected_records
        snapshot = original_inspect_record(value, inspection)  # type: ignore[arg-type]
        if type(value) is LeftRecord or type(value) is RightRecord:
            inspected_records += 1
            if inspected_records == 2:
                both_snapshotted.set()
                assert snapshot_release.wait(timeout=5)
        return snapshot

    monkeypatch.setattr(
        repository_facade_module,
        "_inspect_frozen_record",
        inspect_record_with_finalizer_window,
    )

    def make_colliding_source(_transaction: object) -> object:
        left = LeftRecord("same")
        right = RightRecord("same")
        source_ids.extend((id(left), id(right)))
        if container_kind == "dict":
            return {left: "left", right: "right"}
        return {left, right}

    async def reject_collision() -> None:
        async with factory() as uow:
            entered_uow.append(uow)
            try:
                with pytest.raises(TypeError, match="synchronous data value"):
                    await uow.run_sync(make_colliding_source)
            finally:
                boundary_returned.set()

            assert observations == []
            retained_ids = {id(value) for value in factory._quarantined_results}
            assert set(source_ids) <= retained_ids
            assert uow._sync is None
            assert not factory._transaction_lock.locked()

    operation = asyncio.create_task(reject_collision())
    try:
        assert await asyncio.to_thread(both_snapshotted.wait, 5)

        def installed_finalizer(_value: object) -> None:
            observations.append(
                (
                    boundary_returned.is_set(),
                    factory._transaction_lock.locked(),
                    entered_uow[0]._sync is None,  # type: ignore[attr-defined]
                )
            )

        LeftRecord.__del__ = installed_finalizer  # type: ignore[attr-defined]
        RightRecord.__del__ = installed_finalizer  # type: ignore[attr-defined]
        snapshot_release.set()
        await operation

        assert observations == []
        retained_ids = {id(value) for value in factory._quarantined_results}
        assert set(source_ids) <= retained_ids
        assert factory.quarantined_result_count() >= 3
    finally:
        boundary_returned.set()
        snapshot_release.set()
        if not operation.done():
            operation.cancel()
        with suppress(BaseException):
            await operation
        await factory.aclose()


@pytest.mark.asyncio
async def test_removed_record_metadata_finalizer_is_retained_until_boundary(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @dataclass(frozen=True, slots=True)
    class Record:
        marker: str

    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    boundary_returned = Event()
    metadata_discovered = Event()
    validation_release = Event()
    observations: list[tuple[bool, bool]] = []

    class FinalizableMetadata:
        def __del__(self) -> None:
            observations.append((boundary_returned.is_set(), factory._transaction_lock.locked()))

    metadata = FinalizableMetadata()
    metadata_identity = id(metadata)
    metadata_ref = weakref.ref(metadata)
    Record.__repr__ = metadata  # type: ignore[assignment]
    del metadata
    original_reject_metadata = repository_facade_module._reject_metadata_value

    def reject_metadata_with_removal_window(
        value: object,
        inspection: object,
    ) -> None:
        original_reject_metadata(value, inspection)  # type: ignore[arg-type]
        if id(value) == metadata_identity:
            metadata_discovered.set()
            assert validation_release.wait(timeout=5)

    monkeypatch.setattr(
        repository_facade_module,
        "_reject_metadata_value",
        reject_metadata_with_removal_window,
    )

    async def reject_record() -> None:
        async with factory() as uow:
            try:
                with pytest.raises(TypeError, match="synchronous data value"):
                    await uow.run_sync(lambda _transaction: Record("safe"))
            finally:
                boundary_returned.set()

            assert observations == []
            assert metadata_ref() is not None
            assert uow._sync is None
            assert not factory._transaction_lock.locked()

    operation = asyncio.create_task(reject_record())
    try:
        assert await asyncio.to_thread(metadata_discovered.wait, 5)
        Record.__repr__ = lambda _self: "changed"  # type: ignore[assignment]
        assert observations == []
        validation_release.set()
        await operation

        assert observations == []
        assert metadata_ref() is not None
        assert not factory._transaction_lock.locked()
    finally:
        validation_release.set()
        if not operation.done():
            operation.cancel()
        with suppress(BaseException):
            await operation
        await factory.aclose()


@pytest.mark.parametrize("cycle_kind", ("self-wrapped-function", "metadata-dict"))
@pytest.mark.asyncio
async def test_cyclic_record_function_metadata_is_rejected_without_recursion_leak(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
    cycle_kind: str,
) -> None:
    @dataclass(frozen=True, slots=True)
    class Record:
        marker: str

    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    boundary_returned = Event()
    payload_discovered = Event()
    inspection_release = Event()
    observations: list[tuple[bool, bool]] = []

    class FinalizableMetadata:
        def __del__(self) -> None:
            observations.append((boundary_returned.is_set(), factory._transaction_lock.locked()))

    payload = FinalizableMetadata()
    payload_identity = id(payload)
    payload_ref = weakref.ref(payload)
    function = Record.__repr__
    if cycle_kind == "self-wrapped-function":
        function.__dict__["__wrapped__"] = function
        function.__dict__["payload"] = payload
    else:
        cyclic_metadata: dict[str, object] = {}
        cyclic_metadata["self"] = cyclic_metadata
        cyclic_metadata["payload"] = payload
        function.__dict__["cyclic_metadata"] = cyclic_metadata
        del cyclic_metadata
    del payload
    original_reject_metadata = repository_facade_module._reject_metadata_value

    def reject_metadata_with_removal_window(
        value: object,
        inspection: object,
    ) -> None:
        original_reject_metadata(value, inspection)  # type: ignore[arg-type]
        if id(value) == payload_identity:
            payload_discovered.set()
            assert inspection_release.wait(timeout=5)

    monkeypatch.setattr(
        repository_facade_module,
        "_reject_metadata_value",
        reject_metadata_with_removal_window,
    )

    async def reject_record() -> None:
        async with factory() as uow:
            try:
                with pytest.raises(TypeError, match="synchronous data value") as raised:
                    await uow.run_sync(lambda _transaction: Record("safe"))
            finally:
                boundary_returned.set()

            assert not isinstance(raised.value.__cause__, RecursionError)
            assert observations == []
            assert payload_ref() is not None
            assert uow._sync is None
            assert not factory._transaction_lock.locked()

    operation = asyncio.create_task(reject_record())
    try:
        assert await asyncio.to_thread(payload_discovered.wait, 5)
        function.__dict__.clear()
        inspection_release.set()
        await operation

        assert observations == []
        assert payload_ref() is not None
        assert not factory._transaction_lock.locked()
    finally:
        boundary_returned.set()
        inspection_release.set()
        if not operation.done():
            operation.cancel()
        with suppress(BaseException):
            await operation
        await factory.aclose()


@pytest.mark.parametrize(
    "exit_kind",
    ("normal", "rollback-aclose", "base-exception", "cancellation"),
)
@pytest.mark.asyncio
async def test_operation_local_record_finalizer_runs_only_after_terminal_unlock(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
    exit_kind: str,
) -> None:
    class BodyFailure(BaseException):
        pass

    @dataclass(frozen=True, slots=True)
    class Record:
        marker: str

    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    shape_validated = Event()
    validation_release = Event()
    run_returned = Event()
    source_ids: list[int] = []
    entered_uow: list[object] = []
    observations: list[tuple[bool, bool, bool]] = []
    original_shape_check = repository_facade_module._has_exact_generated_record_shape

    def shape_check_with_finalizer_window(
        record_type: type[object],
        field_names: tuple[str, ...],
        namespace: dict[str, object],
        inspection: object,
    ) -> bool:
        result = original_shape_check(
            record_type,
            field_names,
            namespace,
            inspection,  # type: ignore[arg-type]
        )
        if record_type is Record:
            shape_validated.set()
            assert validation_release.wait(timeout=5)
        return result

    monkeypatch.setattr(
        repository_facade_module,
        "_has_exact_generated_record_shape",
        shape_check_with_finalizer_window,
    )

    def make_operation_local_record(_transaction: object) -> object:
        value = Record("safe")
        source_ids.append(id(value))
        return value

    async def own_transaction() -> None:
        async with factory() as uow:
            entered_uow.append(uow)
            await uow.run_sync(make_operation_local_record)
            run_returned.set()
            assert any(id(value) == source_ids[0] for value in uow._result_sources_until_unlock)
            assert observations == []
            if exit_kind == "base-exception":
                raise BodyFailure("body failed")
            if exit_kind == "rollback-aclose":
                await uow.rollback()
                await uow.aclose()

    operation: asyncio.Task[None] | None = asyncio.create_task(own_transaction())
    try:
        assert await asyncio.to_thread(shape_validated.wait, 5)
        assert operation is not None
        if exit_kind == "cancellation":
            operation.cancel()

        def installed_finalizer(_value: object) -> None:
            observations.append(
                (
                    factory._transaction_lock.locked(),
                    entered_uow[0]._sync is None,  # type: ignore[attr-defined]
                    run_returned.is_set(),
                )
            )

        Record.__del__ = installed_finalizer  # type: ignore[attr-defined]
        validation_release.set()
        if exit_kind == "base-exception":
            with pytest.raises(BodyFailure, match="body failed"):
                await operation
        elif exit_kind == "cancellation":
            with pytest.raises(asyncio.CancelledError):
                await operation
        else:
            await operation

        completed_operation = operation
        operation = None
        del completed_operation
        gc.collect()
        assert observations == [
            (False, True, exit_kind != "cancellation"),
        ]
        assert not factory._transaction_lock.locked()

        async with factory() as next_uow:
            assert await next_uow.run_sync(lambda _transaction: 1) == 1
            await next_uow.rollback()
    finally:
        validation_release.set()
        if operation is not None and not operation.done():
            operation.cancel()
        if operation is not None:
            with suppress(BaseException):
                await operation
        await factory.aclose()


@pytest.mark.asyncio
async def test_record_source_retention_dedupes_across_calls_and_fails_closed_at_bound(
    migrated_database: object,
) -> None:
    @dataclass(frozen=True, slots=True)
    class Record:
        marker: int

    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    shared = Record(-1)
    source_ids: list[int] = []

    def make_record(_transaction: object, marker: int) -> object:
        value = Record(marker)
        source_ids.append(id(value))
        return value

    try:
        async with factory() as uow:
            for _ in range(3):
                await uow.run_sync(lambda _transaction: shared)
            assert len(uow._result_sources_until_unlock) == 1

            for marker in range(63):
                await uow.run_sync(
                    lambda transaction, marker=marker: make_record(transaction, marker)
                )
            assert len(uow._result_sources_until_unlock) == 64
            retained_ids = {id(value) for value in uow._result_sources_until_unlock}
            assert set(source_ids) <= retained_ids

            with pytest.raises(TypeError, match="record retention bound exceeded"):
                await uow.run_sync(lambda transaction: make_record(transaction, 64))

            assert uow._sync is None
            assert uow._result_sources_until_unlock == []
            assert not factory._transaction_lock.locked()

        assert factory.quarantined_result_count() == 1
    finally:
        await factory.aclose()


@pytest.mark.parametrize(
    "field_names",
    (
        tuple(f"field_{index}" for index in range(65)),
        ("x" * 129,),
    ),
)
@pytest.mark.asyncio
async def test_generated_record_shape_bounds_precede_internal_class_generation(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
    field_names: tuple[str, ...],
) -> None:
    record_type = make_dataclass(
        "CallerRecord",
        [(name, object) for name in field_names],
        frozen=True,
        slots=True,
    )
    record = record_type(*range(len(field_names)))
    internal_generation_calls: list[tuple[object, ...]] = []
    original_make_dataclass = repository_facade_module.make_dataclass

    def observe_internal_generation(*args: object, **kwargs: object) -> type[object]:
        internal_generation_calls.append(args)
        return original_make_dataclass(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        repository_facade_module,
        "make_dataclass",
        observe_internal_generation,
    )
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value"):
                await uow.run_sync(lambda _transaction: record)

            assert internal_generation_calls == []
            assert uow._sync is None
            assert not factory._transaction_lock.locked()
    finally:
        await factory.aclose()


@pytest.mark.asyncio
async def test_owned_record_shape_cache_exhaustion_fails_before_class_generation(
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @dataclass(frozen=True, slots=True)
    class Record:
        marker: str

    field_names = ("marker",)
    repository_facade_module._reference_record_type(field_names)
    full_cache = {
        (f"cached_shape_{index}",): object
        for index in range(repository_facade_module._MAX_SYNCHRONOUS_RECORD_SHAPES)
    }
    monkeypatch.setattr(repository_facade_module, "_OWNED_RECORD_TYPES", full_cache)
    generation_calls: list[tuple[object, ...]] = []
    original_make_dataclass = repository_facade_module.make_dataclass

    def observe_generation(*args: object, **kwargs: object) -> type[object]:
        generation_calls.append(args)
        return original_make_dataclass(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(repository_facade_module, "make_dataclass", observe_generation)
    engine = migrated_database.engine  # type: ignore[attr-defined]
    factory = AsyncUnitOfWorkFactory(engine)
    try:
        async with factory() as uow:
            with pytest.raises(TypeError, match="synchronous data value") as raised:
                await uow.run_sync(lambda _transaction: Record("safe"))

            assert raised.value.__cause__ is not None
            assert "shape cache is exhausted" in str(raised.value.__cause__)
            assert generation_calls == []
            assert uow._sync is None
            assert not factory._transaction_lock.locked()
    finally:
        await factory.aclose()
