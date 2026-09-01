from __future__ import annotations

import asyncio
import fcntl
import os
import stat
from collections.abc import Callable, Coroutine
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from tuntun_contracts.reachy import SafetyReceipt
from tuntun_core.services.budget.reconciler import ExpiredBudgetReconciler
from tuntun_core.services.sessions.turn_coordinator import TurnCoordinator
from tuntun_core.services.storage_time import utc_storage


async def shutdown(coordinator: TurnCoordinator) -> None:
    """Preserve the Task-02 full owned safety barrier."""

    if type(coordinator) is not TurnCoordinator:
        raise TypeError("coordinator must be an exact TurnCoordinator")
    active = coordinator.active_turn_id()
    if active is not None:
        await coordinator.cancel(active, "shutdown")


class CoreProcessLease:
    """Lifetime-held single-core lease in the owner-only SQLCipher state root."""

    def __init__(self, path: Path, descriptor: int) -> None:
        self.path = path
        self._descriptor = descriptor
        self._held = True

    @classmethod
    def acquire(cls, path: Path) -> CoreProcessLease:
        if not path.is_absolute():
            raise ValueError("core_process_lease_requires_absolute_path")
        parent = path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) != 0o700
        ):
            raise PermissionError("core_process_lease_directory_not_owner_only")
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags | os.O_EXCL, 0o600)
        except FileExistsError:
            descriptor = os.open(path, flags, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise PermissionError("core_process_lease_file_not_owner_only")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise RuntimeError("core_process_lease_held") from error
            return cls(path, descriptor)
        except BaseException:
            os.close(descriptor)
            raise

    def require_held(self) -> None:
        if not self._held:
            raise RuntimeError("core_process_lease_not_held")
        try:
            os.fstat(self._descriptor)
        except OSError as error:
            self._held = False
            raise RuntimeError("core_process_lease_not_held") from error

    def release_after_shutdown(self) -> None:
        """Called only after traffic/readiness/workers have stopped."""

        if self._held:
            self._held = False
            fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            os.close(self._descriptor)


class StartupTurnRecovery:
    """Mandatory after authenticated Reachy connect and before any traffic/readiness."""

    def __init__(
        self,
        reachy: Any,
        reconciler: ExpiredBudgetReconciler,
        uow_factory: Any,
        clock: Any,
        process_lease: CoreProcessLease,
        retry_limit: int = 3,
        attempt_timeout: float = 0.250,
    ) -> None:
        self._reachy = reachy
        self._reconciler = reconciler
        self._uow_factory = uow_factory
        self._clock = clock
        self._retry_limit = retry_limit
        self._attempt_timeout = attempt_timeout
        self.process_lease = process_lease
        self._ready = False
        self._background: set[asyncio.Task[Any]] = set()

    def _retain(self, task: asyncio.Task[Any]) -> None:
        self._background.add(task)

        def observed(completed: asyncio.Task[Any]) -> None:
            self._background.discard(completed)
            with suppress(BaseException):
                completed.result()

        task.add_done_callback(observed)

    @staticmethod
    def _spawn_owned(
        factory: Callable[[], Coroutine[Any, Any, Any]],
        name: str,
    ) -> asyncio.Task[Any]:
        coroutine = factory()
        try:
            return asyncio.create_task(coroutine, name=name)
        except BaseException:
            with suppress(BaseException):
                coroutine.close()
            fallback = factory()
            try:
                return asyncio.Task(
                    fallback,
                    loop=asyncio.get_running_loop(),
                    name=name,
                )
            except BaseException:
                with suppress(BaseException):
                    fallback.close()
                raise

    async def _verify_global_safety(self) -> None:
        for _attempt in range(self._retry_limit):
            try:
                operation = self._spawn_owned(
                    lambda: self._reachy.stop_all(None),
                    "startup-reachy-stop-all",
                )
            except BaseException:
                continue
            done, pending = await asyncio.wait({operation}, timeout=self._attempt_timeout)
            for task in pending:
                task.cancel()
                self._retain(task)
            if operation not in done:
                continue
            try:
                receipt = operation.result()
            except BaseException:
                continue
            if type(receipt) is SafetyReceipt and receipt == SafetyReceipt(
                turn_id=None,
                playback_stopped=True,
                motion_stopped=True,
                buffers_cleared=True,
            ):
                return
        raise RuntimeError("startup_global_reachy_safety_unverified")

    async def recover_before_ready(self) -> None:
        self._ready = False
        try:
            self.process_lease.require_held()
        except BaseException as error:
            raise RuntimeError("startup_turn_recovery_unhealthy") from error
        cutoff = self._clock.now()
        tasks = []
        failures = []
        for factory, name in (
            (self._verify_global_safety, "startup-global-reachy-safety"),
            (
                lambda: self._reconciler.drain_restart_open_attempts(cutoff),
                "startup-orphan-budget-reconciliation",
            ),
        ):
            try:
                tasks.append(self._spawn_owned(factory, name))
            except BaseException as error:
                failures.append(error)
        results = await asyncio.gather(*tasks, return_exceptions=True)
        failures.extend(result for result in results if isinstance(result, BaseException))
        if failures:
            raise RuntimeError("startup_turn_recovery_unhealthy") from BaseExceptionGroup(
                "startup turn recovery effects degraded",
                failures,
            )
        try:
            async with self._uow_factory() as uow:

                def abandon(db: Any) -> None:
                    db.exec_driver_sql(
                        "UPDATE sessions SET state='cancelled',closed_at=?,last_activity_at=? "
                        "WHERE closed_at IS NULL AND opened_at<=?",
                        (utc_storage(cutoff), utc_storage(cutoff), utc_storage(cutoff)),
                    )

                await uow.run_sync(abandon)
                await uow.commit()
        except BaseException as error:
            raise RuntimeError("startup_turn_recovery_unhealthy") from error
        self._ready = True

    def require_ready(self) -> None:
        if not self._ready:
            raise RuntimeError("startup_turn_recovery_unhealthy")


class BudgetReconciliationSupervisor:
    """One required worker; failure withdraws readiness until process restart."""

    def __init__(
        self,
        reconciler: ExpiredBudgetReconciler,
        startup_recovery: StartupTurnRecovery,
    ) -> None:
        self.reconciler = reconciler
        self.startup_recovery = startup_recovery
        self._stop = asyncio.Event()
        self._worker: asyncio.Task[None] | None = None
        self._ready = False
        self._failure_code: str | None = "not_started"
        self.worker_stopped = asyncio.Event()

    async def start(self) -> None:
        if self._worker is not None:
            raise RuntimeError("budget_reconciliation_already_started")
        try:
            await self.startup_recovery.recover_before_ready()
        except BaseException as error:
            self._failure_code = f"startup_turn:{type(error).__name__}"
            if isinstance(error, RuntimeError):
                raise
            raise RuntimeError("startup_turn_recovery_unhealthy") from error
        try:
            await self.reconciler.drain_before_ready()
        except BaseException as error:
            self._failure_code = f"startup:{type(error).__name__}"
            raise RuntimeError("budget_reconciliation_unhealthy") from error
        self._failure_code = None
        try:
            self._worker = cast(
                asyncio.Task[None],
                self.startup_recovery._spawn_owned(
                    self._run_required_worker,
                    "expired-budget-reconciler",
                ),
            )
        except BaseException as error:
            self._failure_code = f"worker_factory:{type(error).__name__}"
            raise RuntimeError("budget_reconciliation_unhealthy") from error
        self._worker.add_done_callback(self._observe_worker_done)
        await asyncio.sleep(0)
        if self._worker.done():
            try:
                self._worker.result()
            except BaseException as error:
                raise RuntimeError("budget_reconciliation_unhealthy") from error
        self._ready = True

    def _observe_worker_done(self, task: asyncio.Task[None]) -> None:
        self._ready = False
        try:
            task.result()
        except asyncio.CancelledError:
            if not self._stop.is_set():
                self._failure_code = "worker:unexpected_cancel"
        except BaseException as error:
            if self._failure_code is None:
                self._failure_code = f"worker:{type(error).__name__}"
        else:
            if not self._stop.is_set():
                self._failure_code = "worker:unexpected_exit"

    async def _run_required_worker(self) -> None:
        try:
            await self.reconciler.run_periodically(self._stop)
        except asyncio.CancelledError:
            if not self._stop.is_set():
                self._failure_code = "worker:unexpected_cancel"
                raise
        except BaseException as error:
            self._failure_code = f"worker:{type(error).__name__}"
            raise
        finally:
            self._ready = False
            self.worker_stopped.set()

    def require_ready(self) -> None:
        try:
            self.startup_recovery.require_ready()
        except BaseException as error:
            raise RuntimeError("budget_reconciliation_unhealthy") from error
        if (
            not self._ready
            or self._failure_code is not None
            or self._worker is None
            or self._worker.done()
        ):
            raise RuntimeError("budget_reconciliation_unhealthy")

    async def stop(self) -> None:
        self._ready = False
        self._stop.set()
        try:
            if self._worker is not None:
                with suppress(asyncio.CancelledError):
                    await self._worker
        finally:
            self.startup_recovery.process_lease.release_after_shutdown()
