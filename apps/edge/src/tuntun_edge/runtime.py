from __future__ import annotations

import asyncio
import contextlib
import inspect
from collections.abc import Callable, Coroutine
from typing import Any, Protocol, TypeVar

from tuntun_contracts.reachy import SafetyReceipt

_ResultT = TypeVar("_ResultT")


class AsyncGate(Protocol):
    async def require(self) -> None: ...


class ControllerGuard(Protocol):
    async def poll(self) -> bool: ...


class StartupSafety(Protocol):
    async def close_media_stop_playback_motion_and_forget_turn(self) -> Any: ...


class ReachyWssClient(Protocol):
    async def run(self, stop: asyncio.Event) -> None: ...


class Readiness(Protocol):
    def latch_disconnect_degraded(
        self,
        codes: tuple[str, ...],
        *,
        restart_required: bool = False,
    ) -> None: ...


class ManagedEdgeRuntime:
    def __init__(
        self,
        *,
        active_release_gate: AsyncGate,
        firewall_baseline: AsyncGate,
        boot_gate: AsyncGate,
        commissioning_gate: AsyncGate,
        secure_time_gate: AsyncGate,
        controller_guard: ControllerGuard,
        startup_safety: StartupSafety,
        reachy_wss_client: ReachyWssClient,
        readiness: Readiness,
        cleanup_timeout: float = 1.0,
    ) -> None:
        if type(cleanup_timeout) not in {int, float} or cleanup_timeout <= 0:
            raise ValueError("managed edge cleanup timeout invalid")
        self._active_release_gate = active_release_gate
        self._firewall_baseline = firewall_baseline
        self._boot_gate = boot_gate
        self._commissioning_gate = commissioning_gate
        self._secure_time_gate = secure_time_gate
        self._controller_guard = controller_guard
        self._startup_safety = startup_safety
        self._reachy_wss_client = reachy_wss_client
        self._readiness = readiness
        self._cleanup_timeout = float(cleanup_timeout)
        self._cleanup_abandon_timeout = min(max(self._cleanup_timeout, 0.001), 1.0)
        self._background: set[asyncio.Task[Any]] = set()

    async def run(self, stop: asyncio.Event) -> None:
        primary: BaseException | None = None
        cleanup_cancellations = 0
        try:
            await _call_required_gate(self._active_release_gate)
            await _call_required_gate(self._firewall_baseline)
            await _call_required_gate(self._boot_gate)
            await _call_required_gate(self._commissioning_gate)
            await _call_required_gate(self._secure_time_gate)
            controller_ready = await self._controller_guard.poll()
            controller_failure = _controller_failure_code(
                self._controller_guard,
                controller_ready=controller_ready,
            )
            if controller_failure is not None:
                self._readiness.latch_disconnect_degraded(
                    (controller_failure,),
                    restart_required=True,
                )
                raise PermissionError(controller_failure)
            startup_receipt = (
                await self._startup_safety.close_media_stop_playback_motion_and_forget_turn()
            )
            startup_failure = _safety_receipt_failure_code(
                startup_receipt,
                prefix="managed_edge_startup_safety",
            )
            if startup_failure is None and _safety_restart_required(self._startup_safety):
                startup_failure = "managed_edge_startup_safety_restart_required"
            if startup_failure is not None:
                self._readiness.latch_disconnect_degraded(
                    (startup_failure,),
                    restart_required=_safety_restart_required(self._startup_safety),
                )
                raise PermissionError(startup_failure)
            await self._reachy_wss_client.run(stop)
        except BaseException as error:
            primary = error
        cleanup_error: BaseException | None = None
        try:
            cleanup_cancellations = await self._complete_cleanup_barrier()
        except BaseException as error:
            cleanup_error = error
            self._readiness.latch_disconnect_degraded(
                (f"managed_edge_cleanup:{type(error).__name__}",),
                restart_required=True,
            )
        self._readiness.latch_disconnect_degraded(("managed_edge_runtime_exited",))
        if isinstance(primary, asyncio.CancelledError) or cleanup_cancellations:
            raise asyncio.CancelledError from cleanup_error
        if primary is not None:
            raise primary
        if cleanup_error is not None:
            raise RuntimeError("managed_edge_cleanup_failed") from cleanup_error

    async def _complete_cleanup_barrier(self) -> int:
        cleanup_task = _spawn_owned_task(
            self._startup_safety.close_media_stop_playback_motion_and_forget_turn,
            name="managed-edge-cleanup",
        )
        self._retain_background(cleanup_task)
        caller_cancellations = 0
        deadline = asyncio.get_running_loop().time() + self._cleanup_timeout
        while not cleanup_task.done():
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                cleanup_task.cancel()
                await _cancel_and_observe(
                    cleanup_task,
                    timeout=self._cleanup_abandon_timeout,
                )
                raise TimeoutError("managed_edge_cleanup_timeout")
            try:
                await asyncio.wait_for(asyncio.shield(cleanup_task), timeout=remaining)
            except TimeoutError:
                continue
            except asyncio.CancelledError:
                caller_cancellations += 1
                caller_cancellations = _preserved_cancellation_count(caller_cancellations)
                continue
        cleanup_receipt = cleanup_task.result()
        cleanup_failure = _safety_receipt_failure_code(
            cleanup_receipt,
            prefix="managed_edge_cleanup_safety",
        )
        if cleanup_failure is None and _safety_restart_required(self._startup_safety):
            cleanup_failure = "managed_edge_cleanup_restart_required"
        if cleanup_failure is not None:
            self._readiness.latch_disconnect_degraded(
                (cleanup_failure,),
                restart_required=True,
            )
            raise RuntimeError(cleanup_failure)
        return caller_cancellations

    def _retain_background(self, task: asyncio.Task[Any]) -> None:
        self._background.add(task)

        def observed(completed: asyncio.Task[Any]) -> None:
            self._background.discard(completed)
            with contextlib.suppress(BaseException):
                completed.result()

        task.add_done_callback(observed)


async def _call_required_gate(gate: AsyncGate) -> None:
    result = gate.require()
    if inspect.isawaitable(result):
        await result


class CallableGate:
    def __init__(self, callback: Any) -> None:
        self._callback = callback

    async def require(self) -> None:
        result = self._callback()
        if inspect.isawaitable(result):
            await result


class UnavailableGate:
    def __init__(self, label: str) -> None:
        self._label = label

    async def require(self) -> None:
        raise RuntimeError(f"{self._label}_gate_not_configured")


class _TaskFactoryUnavailable(RuntimeError):
    pass


def _spawn_owned_task(  # noqa: UP047 - Edge package keeps its Python 3.11 floor.
    factory: Callable[[], Coroutine[Any, Any, _ResultT]],
    *,
    name: str,
) -> asyncio.Task[_ResultT]:
    coroutine = factory()
    try:
        return asyncio.create_task(coroutine, name=name)
    except BaseException as error:
        _close_unstarted(coroutine)
        if not isinstance(error, Exception):
            raise
    fallback = factory()
    try:
        return asyncio.Task(fallback, loop=asyncio.get_running_loop(), name=name)
    except BaseException as error:
        _close_unstarted(fallback)
        if not isinstance(error, Exception):
            raise
        raise _TaskFactoryUnavailable(f"{name}:factory_unavailable") from error


def _close_unstarted(awaitable: object) -> None:
    close = getattr(awaitable, "close", None)
    if callable(close):
        with contextlib.suppress(BaseException):
            close()


async def _cancel_and_observe(task: asyncio.Task[Any], *, timeout: float) -> bool:
    if not task.done():
        task.cancel()
    done, _pending = await asyncio.wait({task}, timeout=timeout)
    if task not in done:
        return False
    with contextlib.suppress(BaseException):
        task.result()
    return True


def _preserved_cancellation_count(observed: int) -> int:
    current = asyncio.current_task()
    if current is None:
        return observed
    return max(observed, current.cancelling())


def _safety_receipt_failure_code(receipt: object, *, prefix: str) -> str | None:
    if type(receipt) is not SafetyReceipt:
        return f"{prefix}_contract_mismatch"
    if receipt.playback_stopped and receipt.motion_stopped and receipt.buffers_cleared:
        return None
    return f"{prefix}_incomplete"


def _safety_restart_required(safety: object) -> bool:
    return getattr(safety, "process_restart_required", False) is True


def _controller_failure_code(controller_guard: object, *, controller_ready: bool) -> str | None:
    if getattr(controller_guard, "process_restart_required", False) is True:
        return "managed_edge_controller_restart_required"
    if getattr(controller_guard, "error_safe_latched", False) is True:
        return "managed_edge_controller_error_safe"
    if controller_ready is not True:
        return "competing_controller_fail_safe"
    return None
