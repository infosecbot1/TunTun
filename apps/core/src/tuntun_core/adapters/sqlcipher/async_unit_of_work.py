from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from types import TracebackType
from typing import Protocol, TypeVar, cast, runtime_checkable

from sqlalchemy import Engine
from tuntun_core.services.transactions.protocols import UnitOfWorkProtocol

from .repository_facade import (
    _OwnedResultEnvelope,
    _reject_awaitable,
    _reject_worker_result,
    _RejectedDeferredResult,
)
from .unit_of_work import UnitOfWork

ResultT = TypeVar("ResultT")
_ASYNC_CLEANUP_NOTE = "additional async unit-of-work cleanup failure"
_FACTORY_QUARANTINE_LIMIT = 64
_RESULT_SOURCE_RETENTION_LIMIT = 64
_CAPTURED_RESULT_SOURCE_RETENTION_LIMIT = 4096
_PROCESS_LIFETIME_REJECTED_VALUES: list[object] = []
_PROCESS_LIFETIME_QUARANTINE_LOCK = Lock()


def _retain_for_process_lifetime(values: tuple[object, ...]) -> None:
    """Retain trusted-code invariant violations without invoking their cleanup."""

    with _PROCESS_LIFETIME_QUARANTINE_LOCK:
        _PROCESS_LIFETIME_REJECTED_VALUES.extend(values)


def _record_cleanup_failure(
    primary: BaseException,
    action: str,
    cleanup_error: BaseException,
) -> None:
    primary.add_note(
        f"{_ASYNC_CLEANUP_NOTE} ({action}): {type(cleanup_error).__name__}: {cleanup_error}"
    )


@runtime_checkable
class _CommitSignal(Protocol):
    def offer_nowait(self) -> object | None: ...


@runtime_checkable
class _RepositoryFacadeFactory(Protocol):
    def bind(self, uow: AsyncUnitOfWork) -> object: ...


def _valid_repository_facade_factory(value: object) -> bool:
    if not isinstance(value, _RepositoryFacadeFactory):
        return False
    return callable(value.bind) and not inspect.iscoroutinefunction(value.bind)


def _invalid_repository_facade_names(
    repository_facades: Mapping[str, _RepositoryFacadeFactory],
    *,
    existing: set[str] | None = None,
) -> set[str]:
    reserved = set(dir(AsyncUnitOfWork))
    occupied = set() if existing is None else existing
    return {
        name
        for name, facade in repository_facades.items()
        if type(name) is not str
        or not name.isidentifier()
        or name.startswith("_")
        or name in reserved
        or name in occupied
        or not _valid_repository_facade_factory(facade)
    }


class AsyncUnitOfWork:
    def __init__(
        self,
        engine: Engine,
        executor: ThreadPoolExecutor,
        transaction_lock: asyncio.Lock,
        repository_facades: Mapping[str, _RepositoryFacadeFactory],
        commit_signals: Mapping[str, _CommitSignal],
        signal_failures: dict[str, int],
        require_loop: Callable[[], None],
        entry_guard: Callable[[], None],
        claim_owner: Callable[[], None],
        release_owner: Callable[[], None],
        quarantine_rejected: Callable[[tuple[object, ...]], None],
    ) -> None:
        self._engine = engine
        self._executor = executor
        self._transaction_lock = transaction_lock
        self._repository_facades = repository_facades
        self._commit_signals = commit_signals
        self._signal_failures = signal_failures
        self._require_loop = require_loop
        self._entry_guard = entry_guard
        self._claim_owner = claim_owner
        self._release_owner = release_owner
        self._quarantine_rejected = quarantine_rejected
        self._signals_after_commit: set[str] = set()
        self._sync: UnitOfWork | None = None
        self._entered = False
        self._terminal_closed = False
        self._owns_lock = False
        self._owner_claimed = False
        self._task_owner: asyncio.Task[object] | None = None
        self._poisoned = False
        self._result_sources_until_unlock: list[object] = []
        self._result_source_ids: set[int] = set()
        self._captured_sources_until_unlock: list[object] = []
        self._captured_source_ids: set[int] = set()

    async def _call(self, operation: Callable[[], ResultT]) -> ResultT:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, operation)

    def _quarantine_boundary_rejection(self, error: _RejectedDeferredResult) -> None:
        # This method deliberately performs only identity/list bookkeeping. It
        # must retain the root and every discovered unsafe object before any
        # worker frame can release a last reference, and must never call
        # user-controlled cleanup code.
        self._quarantine_rejected(error.values)
        self._poisoned = True
        self._signals_after_commit.clear()
        error.add_note(
            "rejected transaction result is strongly quarantined; no cancellation, "
            "close, callback, or finalizer was invoked by the unit of work"
        )

    async def _finish_boundary_rejection(
        self,
        error: _RejectedDeferredResult,
    ) -> BaseException:
        self._quarantine_boundary_rejection(error)
        primary = await self._finish_exit(type(error), error, error.__traceback__)
        return error if primary is None else primary

    async def _terminal_call(self, operation: Callable[[], ResultT]) -> ResultT:
        worker_call = asyncio.create_task(self._call(operation))
        cancellation: asyncio.CancelledError | None = None
        while not worker_call.done():
            try:
                await asyncio.shield(worker_call)
            except asyncio.CancelledError as error:
                if cancellation is None:
                    cancellation = error
            except BaseException:
                pass
        try:
            result = worker_call.result()
        except _RejectedDeferredResult as operation_error:
            if cancellation is not None:
                _record_cleanup_failure(
                    operation_error,
                    "cancellation deferred behind boundary rejection",
                    cancellation,
                )
            raise
        except BaseException as operation_error:
            if cancellation is not None:
                _record_cleanup_failure(cancellation, "worker operation", operation_error)
                raise cancellation from None
            raise
        if type(result) is _OwnedResultEnvelope:
            try:
                envelope = cast(_OwnedResultEnvelope[object], result)
                result = cast(ResultT, self._adopt_result_envelope(envelope))
                del envelope
            except _RejectedDeferredResult as adoption_error:
                if cancellation is not None:
                    _record_cleanup_failure(
                        adoption_error,
                        "cancellation deferred behind result-source retention",
                        cancellation,
                    )
                raise
        if cancellation is not None:
            # A completed worker task owns its exact result envelope. Drop it
            # after its record sources have moved into UOW retention so the
            # cancellation traceback cannot extend source lifetime.
            del worker_call
            raise cancellation
        return result

    def _active_sync(self) -> UnitOfWork:
        if self._poisoned:
            raise RuntimeError("async unit of work is poisoned by a rejected result")
        if self._sync is None or not self._sync.active:
            raise RuntimeError("async unit of work is not active")
        self._require_task_owner()
        return self._sync

    def _require_task_owner(self) -> None:
        try:
            current = asyncio.current_task()
        except RuntimeError:
            current = None
        if self._task_owner is None or current is not self._task_owner:
            raise RuntimeError("async unit of work belongs to another owning task")

    def _adopt_result_envelope[EnvelopeResultT](
        self,
        envelope: _OwnedResultEnvelope[EnvelopeResultT],
    ) -> EnvelopeResultT:
        record_additions: list[object] = []
        record_addition_ids: set[int] = set()
        for value in envelope.record_sources:
            identity = id(value)
            if identity not in self._result_source_ids and identity not in record_addition_ids:
                record_addition_ids.add(identity)
                record_additions.append(value)
        captured_additions: list[object] = []
        captured_addition_ids: set[int] = set()
        for value in envelope.captured_sources:
            identity = id(value)
            if identity not in self._captured_source_ids and identity not in captured_addition_ids:
                captured_addition_ids.add(identity)
                captured_additions.append(value)
        if (
            len(self._result_sources_until_unlock) + len(record_additions)
            > _RESULT_SOURCE_RETENTION_LIMIT
        ):
            raise _RejectedDeferredResult(
                tuple(captured_additions),
                "unit-of-work operations must return a synchronous data value; "
                "record retention bound exceeded",
            )
        if (
            len(self._captured_sources_until_unlock) + len(captured_additions)
            > _CAPTURED_RESULT_SOURCE_RETENTION_LIMIT
        ):
            raise _RejectedDeferredResult(
                tuple(captured_additions),
                "unit-of-work operations must return a synchronous data value; "
                "captured source retention bound exceeded",
            )
        self._result_source_ids.update(record_addition_ids)
        self._result_sources_until_unlock.extend(record_additions)
        self._captured_source_ids.update(captured_addition_ids)
        self._captured_sources_until_unlock.extend(captured_additions)
        return envelope.snapshot

    def _release_result_sources_after_unlock(self) -> None:
        self._result_source_ids.clear()
        self._result_sources_until_unlock.clear()
        self._captured_source_ids.clear()
        self._captured_sources_until_unlock.clear()

    def _release_terminal_ownership(self) -> None:
        sync = self._sync
        if sync is not None and not sync.closed:
            return
        self._signals_after_commit.clear()
        self._sync = None
        self._terminal_closed = True
        if self._owns_lock:
            if self._owner_claimed:
                self._release_owner()
                self._owner_claimed = False
            self._transaction_lock.release()
            self._owns_lock = False
            self._task_owner = None
            # Caller record sources can acquire Python-level finalizers after
            # validation. Drop their last component-owned references only
            # after both SQL close and writer-lock release.
            self._release_result_sources_after_unlock()

    async def _finish_exit(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> BaseException | None:
        sync = self._sync
        primary = exc
        if sync is not None:
            try:
                await self._terminal_call(lambda: sync.__exit__(exc_type, exc, traceback))
            except BaseException as close_error:
                if primary is None:
                    primary = close_error
                elif close_error is not primary:
                    _record_cleanup_failure(primary, "close", close_error)
        try:
            self._release_terminal_ownership()
        except BaseException as release_error:
            if primary is None:
                primary = release_error
            else:
                _record_cleanup_failure(primary, "ownership release", release_error)
        return primary

    async def __aenter__(self) -> AsyncUnitOfWork:
        self._require_loop()
        if self._terminal_closed:
            raise RuntimeError("async unit of work is closed")
        if self._entered:
            raise RuntimeError("async unit of work cannot be reused")
        self._entered = True
        owner = asyncio.current_task()
        if owner is None:
            self._terminal_closed = True
            raise RuntimeError("unit-of-work task ownership invariant failed")
        self._task_owner = owner
        try:
            self._entry_guard()
            await self._transaction_lock.acquire()
        except BaseException:
            self._task_owner = None
            self._terminal_closed = True
            raise
        self._owns_lock = True
        try:
            self._claim_owner()
            self._owner_claimed = True
            self._entry_guard()
            self._sync = UnitOfWork(self._engine)
            await self._terminal_call(self._sync.__enter__)
            for name, facade_factory in self._repository_facades.items():
                facade = _reject_awaitable(
                    facade_factory.bind(self),
                    "repository facade binding must be synchronous",
                )
                setattr(self, name, facade)
            return self
        except BaseException as error:
            primary: BaseException | None
            if isinstance(error, _RejectedDeferredResult):
                primary = await self._finish_boundary_rejection(error)
            else:
                primary = await self._finish_exit(type(error), error, error.__traceback__)
            if primary is not None and primary is not error:
                raise primary from error
            raise error

    async def run_sync(
        self,
        operation: Callable[[UnitOfWorkProtocol], ResultT],
    ) -> ResultT:
        sync = self._active_sync()

        def invoke() -> _OwnedResultEnvelope[ResultT]:
            return _reject_worker_result(
                operation(sync),
                "unit-of-work operations must return a synchronous data value",
            )

        try:
            return cast(ResultT, await self._terminal_call(invoke))
        except _RejectedDeferredResult as error:
            primary = await self._finish_boundary_rejection(error)
            if primary is not error:
                raise primary from error
            raise

    def signal_after_commit(self, name: str) -> None:
        self._active_sync()
        if type(name) is not str or name not in self._commit_signals:
            raise RuntimeError("unregistered post-commit signal")
        self._signals_after_commit.add(name)

    async def _deliver_commit_signals(self) -> None:
        names = tuple(sorted(self._signals_after_commit))
        self._signals_after_commit.clear()
        for name in names:
            try:
                envelope = _reject_worker_result(
                    self._commit_signals[name].offer_nowait(),
                    "post-commit signals must be synchronous",
                )
                self._adopt_result_envelope(envelope)
            except _RejectedDeferredResult as error:
                self._signal_failures[name] = self._signal_failures.get(name, 0) + 1
                primary = await self._finish_boundary_rejection(error)
                if self._owns_lock:
                    raise primary from None
                break
            except BaseException:
                self._signal_failures[name] = self._signal_failures.get(name, 0) + 1

    async def commit(self) -> None:
        sync = self._active_sync()
        cancellation: asyncio.CancelledError | None = None
        try:
            await self._terminal_call(sync.commit)
        except asyncio.CancelledError as error:
            cancellation = error
        if sync.active:
            if cancellation is not None:
                raise cancellation
            return
        await self._deliver_commit_signals()
        if cancellation is not None:
            raise cancellation

    async def rollback(self) -> None:
        sync = self._active_sync()
        self._signals_after_commit.clear()
        await self._terminal_call(sync.rollback)

    async def aclose(self) -> None:
        self._require_loop()
        if self._task_owner is not None:
            self._require_task_owner()
        sync = self._sync
        if sync is None:
            self._release_terminal_ownership()
            return
        primary: BaseException | None = None
        try:
            await self._terminal_call(sync.close)
        except BaseException as close_error:
            primary = close_error
        try:
            self._release_terminal_ownership()
        except BaseException as release_error:
            if primary is None:
                primary = release_error
            else:
                _record_cleanup_failure(primary, "ownership release", release_error)
        if primary is not None:
            raise primary

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        self._require_loop()
        if self._task_owner is not None:
            self._require_task_owner()
        primary = await self._finish_exit(exc_type, exc, traceback)
        if primary is not None and primary is not exc:
            raise primary
        return False


class AsyncUnitOfWorkFactory:
    def __init__(
        self,
        engine: Engine,
        repository_facades: Mapping[str, _RepositoryFacadeFactory] | None = None,
    ) -> None:
        self._engine = engine
        self._repository_facades = dict(repository_facades or {})
        invalid = _invalid_repository_facade_names(self._repository_facades)
        if invalid:
            raise ValueError("invalid repository facade registration")
        self._commit_signals: dict[str, _CommitSignal] = {}
        self._signal_failures: dict[str, int] = {}
        self._registration_closed = False
        self._closing = False
        self._closed = False
        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="tuntun-sqlcipher",
        )
        self._loop_guard = Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._transaction_lock = asyncio.Lock()
        self._shutdown_task: asyncio.Task[None] | None = None
        self._active_owner: asyncio.Task[object] | None = None
        self._quarantined_results: list[object] = []
        self._quarantined_result_ids: set[int] = set()
        self._quarantined_result_total = 0
        self._quarantine_overflowed = False

    def register_repository_facades(
        self,
        repository_facades: Mapping[str, _RepositoryFacadeFactory],
    ) -> None:
        if (
            self._registration_closed
            or self._closing
            or self._closed
            or self._active_owner is not None
        ):
            raise RuntimeError("repository facade registration closed")
        additions = dict(repository_facades)
        invalid = _invalid_repository_facade_names(
            additions,
            existing=set(self._repository_facades),
        )
        if invalid:
            raise ValueError("invalid repository facade registration")
        self._repository_facades.update(additions)

    def register_commit_signal(self, name: str, target: _CommitSignal) -> None:
        if (
            self._registration_closed
            or self._closing
            or self._closed
            or self._active_owner is not None
        ):
            raise RuntimeError("post-commit signal registration closed")
        offer_nowait = target.offer_nowait if isinstance(target, _CommitSignal) else None
        if (
            type(name) is not str
            or not name.isidentifier()
            or name.startswith("_")
            or name in self._commit_signals
            or offer_nowait is None
            or not callable(offer_nowait)
            or inspect.iscoroutinefunction(offer_nowait)
        ):
            raise RuntimeError("post-commit signal registration closed")
        self._commit_signals[name] = target

    def failed_commit_signal_count(self, name: str) -> int:
        return self._signal_failures.get(name, 0)

    def quarantined_result_count(self) -> int:
        """Return the number of distinct rejected objects retained by this factory."""

        return self._quarantined_result_total

    def quarantine_overflowed(self) -> bool:
        """Report whether repeated trusted-code violations exhausted the local bound."""

        return self._quarantine_overflowed

    def _quarantine_rejected_results(self, values: tuple[object, ...]) -> None:
        overflow: list[object] = []
        for value in values:
            identity = id(value)
            if identity in self._quarantined_result_ids:
                continue
            self._quarantined_result_ids.add(identity)
            self._quarantined_result_total += 1
            if len(self._quarantined_results) < _FACTORY_QUARANTINE_LIMIT:
                self._quarantined_results.append(value)
            else:
                overflow.append(value)
                self._quarantine_overflowed = True
        if overflow:
            _retain_for_process_lifetime(tuple(overflow))

    def _transfer_quarantine_to_process_lifetime(self) -> None:
        if not self._quarantined_results:
            return
        retained = tuple(self._quarantined_results)
        _retain_for_process_lifetime(retained)
        self._quarantined_results.clear()

    def _ensure_entry_allowed(self) -> None:
        if self._closed:
            raise RuntimeError("unit-of-work factory is shut down")
        if self._closing:
            raise RuntimeError("unit-of-work factory is shutting down")
        if self._quarantine_overflowed:
            raise RuntimeError("unit-of-work factory rejected too many unsafe results")

    def _require_loop(self) -> None:
        current_loop = asyncio.get_running_loop()
        with self._loop_guard:
            owner_loop = self._loop
            if owner_loop is None:
                self._loop = current_loop
                return
            if owner_loop is not current_loop:
                raise RuntimeError("async unit-of-work factory belongs to another event loop")

    def _claim_transaction_owner(self) -> None:
        owner = asyncio.current_task()
        if owner is None or self._active_owner is not None:
            raise RuntimeError("unit-of-work transaction ownership invariant failed")
        self._active_owner = owner

    def _release_transaction_owner(self) -> None:
        self._active_owner = None

    def __call__(self) -> AsyncUnitOfWork:
        self._require_loop()
        self._ensure_entry_allowed()
        self._registration_closed = True
        return AsyncUnitOfWork(
            self._engine,
            self._executor,
            self._transaction_lock,
            self._repository_facades,
            self._commit_signals,
            self._signal_failures,
            self._require_loop,
            self._ensure_entry_allowed,
            self._claim_transaction_owner,
            self._release_transaction_owner,
            self._quarantine_rejected_results,
        )

    async def _shutdown(self) -> None:
        await self._transaction_lock.acquire()
        try:
            self._executor.shutdown(wait=True, cancel_futures=False)
            self._transfer_quarantine_to_process_lifetime()
            self._closed = True
        finally:
            self._transaction_lock.release()

    async def aclose(self) -> None:
        self._require_loop()
        if self._closed:
            return
        if self._active_owner is asyncio.current_task():
            raise RuntimeError("cannot shut down factory from its active transaction")
        self._registration_closed = True
        self._closing = True
        if self._shutdown_task is None:
            self._shutdown_task = asyncio.create_task(self._shutdown())
        cancellation: asyncio.CancelledError | None = None
        while not self._shutdown_task.done():
            try:
                await asyncio.shield(self._shutdown_task)
            except asyncio.CancelledError as error:
                if cancellation is None:
                    cancellation = error
        self._shutdown_task.result()
        if cancellation is not None:
            raise cancellation
