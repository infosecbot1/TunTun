from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable, Mapping
from concurrent.futures import Future as ConcurrentFuture
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from types import TracebackType
from typing import Protocol, TypeVar, runtime_checkable

from sqlalchemy import Engine
from tuntun_core.services.transactions.protocols import UnitOfWorkProtocol

from .repository_facade import (
    _reject_awaitable,
    _reject_worker_result,
    _RejectedDeferredResult,
)
from .unit_of_work import UnitOfWork

ResultT = TypeVar("ResultT")
_ASYNC_CLEANUP_NOTE = "additional async unit-of-work cleanup failure"


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


class AsyncUnitOfWork:
    def __init__(
        self,
        engine: Engine,
        executor: ThreadPoolExecutor,
        transaction_lock: asyncio.Lock,
        repository_facades: Mapping[str, _RepositoryFacadeFactory],
        commit_signals: Mapping[str, _CommitSignal],
        signal_failures: dict[str, int],
        entry_guard: Callable[[], None],
        claim_owner: Callable[[], None],
        release_owner: Callable[[], None],
    ) -> None:
        self._engine = engine
        self._executor = executor
        self._transaction_lock = transaction_lock
        self._repository_facades = repository_facades
        self._commit_signals = commit_signals
        self._signal_failures = signal_failures
        self._entry_guard = entry_guard
        self._claim_owner = claim_owner
        self._release_owner = release_owner
        self._signals_after_commit: set[str] = set()
        self._sync: UnitOfWork | None = None
        self._entered = False
        self._terminal_closed = False
        self._owns_lock = False
        self._owner_claimed = False
        self._task_owner: asyncio.Task[object] | None = None

    async def _call(self, operation: Callable[[], ResultT]) -> ResultT:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, operation)

    async def _await_terminal_cleanup(
        self,
        cleanup_task: asyncio.Task[None],
    ) -> asyncio.CancelledError | None:
        cancellation: asyncio.CancelledError | None = None
        while not cleanup_task.done():
            try:
                await asyncio.shield(cleanup_task)
            except asyncio.CancelledError as cleanup_cancellation:
                if cancellation is None:
                    cancellation = cleanup_cancellation
        cleanup_task.result()
        return cancellation

    async def _terminate_one_rejected_deferred_result(
        self,
        value: object,
    ) -> None:
        if isinstance(value, asyncio.Future):
            if value is asyncio.current_task():
                raise RuntimeError("owning task cannot be returned as transaction data")

            async def cancel_and_wait() -> None:
                value.cancel()
                with suppress(BaseException):
                    await value

            owner_loop = value.get_loop()
            current_loop = asyncio.get_running_loop()
            if owner_loop is current_loop:
                cleanup_task = asyncio.create_task(cancel_and_wait())
            elif owner_loop.is_running():

                async def cancel_cross_loop() -> None:
                    transfer = asyncio.run_coroutine_threadsafe(
                        cancel_and_wait(),
                        owner_loop,
                    )
                    await asyncio.wrap_future(transfer)

                cleanup_task = asyncio.create_task(cancel_cross_loop())
            else:
                value.cancel()
                if not value.done():
                    raise RuntimeError("rejected task belongs to a stopped foreign event loop")
                return
        elif isinstance(value, ConcurrentFuture):

            async def cancel_concurrent_future() -> None:
                value.cancel()
                with suppress(BaseException):
                    await asyncio.wrap_future(value)

            cleanup_task = asyncio.create_task(cancel_concurrent_future())
        elif inspect.isasyncgen(value):

            async def close_async_generator() -> None:
                await value.aclose()

            cleanup_task = asyncio.create_task(close_async_generator())
        else:
            raise AssertionError("unsupported deferred result")
        await cleanup_task

    async def _terminate_rejected_deferred_result(
        self,
        error: _RejectedDeferredResult,
    ) -> asyncio.CancelledError | None:
        if not error.values:
            return None

        async def cleanup_all() -> None:
            cleanup_tasks = tuple(
                asyncio.create_task(self._terminate_one_rejected_deferred_result(value))
                for value in error.values
            )
            results = await asyncio.gather(*cleanup_tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, BaseException):
                    _record_cleanup_failure(error, "rejected value", result)

        cleanup_task = asyncio.create_task(cleanup_all())
        return await self._await_terminal_cleanup(cleanup_task)

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
            cleanup_cancellation = await self._terminate_rejected_deferred_result(operation_error)
            if cancellation is None:
                cancellation = cleanup_cancellation
            if cancellation is not None:
                _record_cleanup_failure(
                    cancellation,
                    "rejected scheduled awaitable",
                    operation_error,
                )
                raise cancellation from None
            raise
        except BaseException as operation_error:
            if cancellation is not None:
                _record_cleanup_failure(cancellation, "worker operation", operation_error)
                raise cancellation from None
            raise
        if cancellation is not None:
            raise cancellation
        return result

    def _active_sync(self) -> UnitOfWork:
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
            if isinstance(error, _RejectedDeferredResult):
                cleanup_cancellation = await self._terminate_rejected_deferred_result(error)
                if cleanup_cancellation is not None:
                    _record_cleanup_failure(
                        cleanup_cancellation,
                        "rejected scheduled awaitable",
                        error,
                    )
                    error = cleanup_cancellation
            primary = await self._finish_exit(type(error), error, error.__traceback__)
            if primary is not None and primary is not error:
                raise primary from error
            raise error

    async def run_sync(
        self,
        operation: Callable[[UnitOfWorkProtocol], ResultT],
    ) -> ResultT:
        sync = self._active_sync()

        def invoke() -> ResultT:
            return _reject_worker_result(
                operation(sync),
                "unit-of-work operations must return a synchronous data value",
            )

        return await self._terminal_call(invoke)

    def signal_after_commit(self, name: str) -> None:
        self._active_sync()
        if type(name) is not str or name not in self._commit_signals:
            raise RuntimeError("unregistered post-commit signal")
        self._signals_after_commit.add(name)

    async def _deliver_commit_signals(self) -> asyncio.CancelledError | None:
        names = tuple(sorted(self._signals_after_commit))
        self._signals_after_commit.clear()
        cancellation: asyncio.CancelledError | None = None
        for name in names:
            try:
                _reject_worker_result(
                    self._commit_signals[name].offer_nowait(),
                    "post-commit signals must be synchronous",
                )
            except _RejectedDeferredResult as error:
                cleanup_cancellation = await self._terminate_rejected_deferred_result(error)
                if cancellation is None:
                    cancellation = cleanup_cancellation
                self._signal_failures[name] = self._signal_failures.get(name, 0) + 1
            except BaseException:
                self._signal_failures[name] = self._signal_failures.get(name, 0) + 1
        return cancellation

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
        signal_cancellation = await self._deliver_commit_signals()
        if cancellation is None:
            cancellation = signal_cancellation
        if cancellation is not None:
            raise cancellation

    async def rollback(self) -> None:
        sync = self._active_sync()
        self._signals_after_commit.clear()
        await self._terminal_call(sync.rollback)

    async def aclose(self) -> None:
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
        reserved = set(dir(AsyncUnitOfWork))
        invalid = {
            name
            for name, facade in self._repository_facades.items()
            if type(name) is not str
            or not name.isidentifier()
            or name.startswith("_")
            or name in reserved
            or not _valid_repository_facade_factory(facade)
        }
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
        self._transaction_lock = asyncio.Lock()
        self._shutdown_task: asyncio.Task[None] | None = None
        self._active_owner: asyncio.Task[object] | None = None

    def register_commit_signal(self, name: str, target: _CommitSignal) -> None:
        if self._registration_closed or self._closing or self._closed:
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

    def _ensure_entry_allowed(self) -> None:
        if self._closed:
            raise RuntimeError("unit-of-work factory is shut down")
        if self._closing:
            raise RuntimeError("unit-of-work factory is shutting down")

    def _claim_transaction_owner(self) -> None:
        owner = asyncio.current_task()
        if owner is None or self._active_owner is not None:
            raise RuntimeError("unit-of-work transaction ownership invariant failed")
        self._active_owner = owner

    def _release_transaction_owner(self) -> None:
        self._active_owner = None

    def __call__(self) -> AsyncUnitOfWork:
        self._ensure_entry_allowed()
        self._registration_closed = True
        return AsyncUnitOfWork(
            self._engine,
            self._executor,
            self._transaction_lock,
            self._repository_facades,
            self._commit_signals,
            self._signal_failures,
            self._ensure_entry_allowed,
            self._claim_transaction_owner,
            self._release_transaction_owner,
        )

    async def _shutdown(self) -> None:
        await self._transaction_lock.acquire()
        try:
            self._executor.shutdown(wait=True, cancel_futures=False)
            self._closed = True
        finally:
            self._transaction_lock.release()

    async def aclose(self) -> None:
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
