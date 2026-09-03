from __future__ import annotations

import asyncio
import contextlib
import signal
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from tuntun_edge.reachy.client import DaemonMotion, MediaBuffers, ReachyClient
from tuntun_edge.runtime import ManagedEdgeRuntime, UnavailableGate
from tuntun_edge.transport.websocket import EdgeTransportSupervisorState, ReachyWssClient


class WssClientFactory(Protocol):
    def __call__(self, **kwargs: Any) -> Any: ...


@dataclass(frozen=True, slots=True)
class ManagedEdgeComposition:
    reachy_transport_supervisor: EdgeTransportSupervisorState
    disconnect_safety: EdgeDisconnectSafety
    reachy_client: ReachyClient
    reachy_wss_client: Any
    runtime: ManagedEdgeRuntime
    readiness_dependencies: tuple[EdgeTransportSupervisorState, ...]

    @classmethod
    def build(
        cls,
        *,
        endpoint: Any,
        tls_context: object,
        pairing_keys: Any,
        duplex_state: Any,
        daemon: DaemonMotion,
        buffers: MediaBuffers,
        clock: Any,
        reachy_wss_client_factory: WssClientFactory | None = None,
        active_release_gate: Any | None = None,
        firewall_baseline: Any | None = None,
        boot_gate: Any | None = None,
        commissioning_gate: Any | None = None,
        secure_time_gate: Any | None = None,
        controller_guard: Any | None = None,
    ) -> ManagedEdgeComposition:
        supervisor = EdgeTransportSupervisorState()
        reachy_client = ReachyClient(daemon, buffers, clock)
        disconnect_safety = EdgeDisconnectSafety(reachy_client)
        factory = reachy_wss_client_factory or ReachyWssClient
        wss_client = factory(
            endpoint=endpoint,
            tls_context=tls_context,
            pairing_keys=pairing_keys,
            state=duplex_state,
            safety=disconnect_safety,
            handler=reachy_client,
            readiness=supervisor,
            clock=clock,
        )
        runtime = ManagedEdgeRuntime(
            active_release_gate=active_release_gate or UnavailableGate("active_release"),
            firewall_baseline=firewall_baseline or UnavailableGate("firewall_baseline"),
            boot_gate=boot_gate or UnavailableGate("boot"),
            commissioning_gate=commissioning_gate or UnavailableGate("commissioning"),
            secure_time_gate=secure_time_gate or UnavailableGate("secure_time"),
            controller_guard=controller_guard or _UnavailableControllerGuard(),
            startup_safety=disconnect_safety,
            reachy_wss_client=wss_client,
            readiness=supervisor,
        )
        return cls(
            reachy_transport_supervisor=supervisor,
            disconnect_safety=disconnect_safety,
            reachy_client=reachy_client,
            reachy_wss_client=wss_client,
            runtime=runtime,
            readiness_dependencies=(supervisor,),
        )


class EdgeDisconnectSafety:
    def __init__(self, reachy_client: ReachyClient) -> None:
        self._reachy_client = reachy_client

    @property
    def process_restart_required(self) -> bool:
        return self._reachy_client.process_restart_required

    @property
    def last_failure_codes(self) -> tuple[str, ...]:
        return self._reachy_client.last_safety_failure_codes

    def latch_error_safe(self, reason: str) -> None:
        self._reachy_client.latch_error_safe(reason)

    async def close_media_stop_playback_motion_and_forget_turn(self) -> Any:
        try:
            return await self._reachy_client.stop_all(None)
        finally:
            self._reachy_client.latch_error_safe("disconnect_cleanup_complete")


class _UnavailableControllerGuard:
    async def poll(self) -> bool:
        raise RuntimeError("controller_guard_not_configured")


def build_production_managed_edge() -> ManagedEdgeComposition:
    raise RuntimeError("production managed Edge dependencies are installed by release packaging")


async def run_managed_edge(
    composition: Any,
    *,
    install_signal_handlers: Callable[[asyncio.Event], Callable[[], None]] | None = None,
) -> None:
    stop = asyncio.Event()
    remove_signal_handlers = (install_signal_handlers or install_stop_signal_handlers)(stop)
    try:
        await composition.runtime.run(stop)
    finally:
        remove_signal_handlers()


def install_stop_signal_handlers(stop: asyncio.Event) -> Callable[[], None]:
    loop = asyncio.get_running_loop()
    installed_loop_handlers: list[signal.Signals] = []
    previous_signal_handlers: list[tuple[signal.Signals, Any]] = []

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(signum, stop.set)
            except (NotImplementedError, RuntimeError):
                previous = signal.getsignal(signum)

                def set_stop(_signum: int, _frame: object, *, event: asyncio.Event = stop) -> None:
                    loop.call_soon_threadsafe(event.set)

                signal.signal(signum, set_stop)
                previous_signal_handlers.append((signum, previous))
            else:
                installed_loop_handlers.append(signum)
    except BaseException:
        _remove_stop_signal_handlers(loop, installed_loop_handlers, previous_signal_handlers)
        raise

    removed = False

    def remove() -> None:
        nonlocal removed
        if removed:
            return
        removed = True
        _remove_stop_signal_handlers(loop, installed_loop_handlers, previous_signal_handlers)

    return remove


def _remove_stop_signal_handlers(
    loop: Any,
    installed_loop_handlers: list[signal.Signals],
    previous_signal_handlers: list[tuple[signal.Signals, Any]],
) -> None:
    while installed_loop_handlers:
        signum = installed_loop_handlers.pop()
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.remove_signal_handler(signum)
    while previous_signal_handlers:
        signum, previous = previous_signal_handlers.pop()
        with contextlib.suppress(ValueError):
            signal.signal(signum, previous)


async def run_production_managed_edge() -> None:
    await run_managed_edge(build_production_managed_edge())
