from __future__ import annotations

import asyncio
import contextlib
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tuntun_contracts.base import canonical_bytes, parse_contract_json
from tuntun_contracts.ports import TurnInput, TurnOutput
from tuntun_contracts.reachy import (
    ReachyCommand,
    ReachyReceipt,
    SafetyReceipt,
    StopAllReceiptBundleV1,
)
from tuntun_core.api.app import create_app
from tuntun_core.api.dependencies import SimulatedGuestAppDependencies
from tuntun_core.bootstrap.lifecycle import CoreProcessLease

from tests.identity_support import StaticTask1IdentityKeyProvider

pytest_plugins = ("tests.fixtures.provider_egress",)

PROJECT_ROOT = Path(__file__).parents[3]
NOW = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)
DEVICE_ID = UUID("00000000-0000-0000-0000-00000000c010")
_PRODUCTION_START_DIAGNOSTIC_TIMEOUT_SECONDS = 10.0
_PRODUCTION_START_CLEANUP_TIMEOUT_SECONDS = 1.0


async def _await_successful_production_start(
    start_task: asyncio.Task[None],
    production: Any,
    events: list[str],
    *,
    diagnostic_timeout: float = _PRODUCTION_START_DIAGNOSTIC_TIMEOUT_SECONDS,
) -> None:
    try:
        await asyncio.wait_for(
            asyncio.shield(start_task),
            timeout=diagnostic_timeout,
        )
    except TimeoutError as error:
        pytest.fail(
            "production.start() did not finish after authenticated session publication "
            f"within {diagnostic_timeout:.3f}s; "
            f"diagnostics={_production_start_timeout_diagnostics(production, events)}"
        )
        raise AssertionError("unreachable") from error


async def _await_production_start_or_cleanup(
    start_task: asyncio.Task[None],
    production: Any,
    events: list[str],
    *,
    diagnostic_timeout: float = _PRODUCTION_START_DIAGNOSTIC_TIMEOUT_SECONDS,
) -> None:
    try:
        await _await_successful_production_start(
            start_task,
            production,
            events,
            diagnostic_timeout=diagnostic_timeout,
        )
    except BaseException as primary:
        await _cleanup_production_after_start_failure(start_task, production, primary)
        raise


async def _cleanup_production_after_start_failure(
    start_task: asyncio.Task[None],
    production: Any,
    primary: BaseException,
) -> None:
    cleanup_error = await _cancel_unfinished_start_then_stop(start_task, production)
    if cleanup_error is not None:
        primary.add_note(
            "production.start() cleanup after primary failure raised "
            f"{type(cleanup_error).__name__}: {cleanup_error}"
        )


async def _cancel_unfinished_start_then_stop(
    start_task: asyncio.Task[None],
    production: Any,
    *,
    cleanup_timeout: float = _PRODUCTION_START_CLEANUP_TIMEOUT_SECONDS,
) -> BaseException | None:
    cleanup_errors: list[BaseException] = []
    if not start_task.done():
        start_task.cancel()
        try:
            await asyncio.wait_for(start_task, timeout=cleanup_timeout)
        except asyncio.CancelledError:
            pass
        except BaseException as error:
            cleanup_errors.append(error)

    try:
        await asyncio.wait_for(production.stop(), timeout=cleanup_timeout)
    except BaseException as error:
        cleanup_errors.append(error)

    if not cleanup_errors:
        return None
    if len(cleanup_errors) == 1:
        return cleanup_errors[0]
    return ExceptionGroup("production_start_cleanup_failed", cleanup_errors)


def _production_start_timeout_diagnostics(production: Any, events: list[str]) -> dict[str, object]:
    lifecycle = production.reachy_transport_lifecycle
    current = production.current_reachy_session
    transport = production.reachy_transport_supervisor
    wss_server = production.reachy_wss_server
    current_ready = True
    current_error: str | None
    try:
        current.require_ready()
    except BaseException as error:
        current_ready = False
        current_error = f"{type(error).__name__}:{error}"
    else:
        current_error = None
    return {
        "events": tuple(events),
        "start_task_done": lifecycle._start_task.done()
        if lifecycle._start_task is not None
        else None,
        "lifecycle_started": lifecycle._started,
        "lifecycle_stopping": lifecycle._stopping,
        "lifecycle_cleanup_pending": lifecycle._cleanup_pending,
        "current_ready": current_ready,
        "current_error": current_error,
        "transport_ready": transport.ready,
        "transport_degraded_codes": transport.disconnect_degraded_codes,
        "transport_restart_required": transport.restart_required,
        "wss_server_retained": wss_server._server is not None,
        "process_lease_path": str(production.core_process_lease.path),
    }


@dataclass(frozen=True, slots=True)
class _Endpoint:
    core_ipv4: str = "192.168.50.10"
    port: int = 7443
    generation: int = 1
    client_certificate_sha256: str = "1" * 64
    server_key_id: str = "ed25519:reachy-core:v1"
    server_public_key_sha256: str = "2" * 64
    device_signing_key_id: str = "ed25519:reachy-edge:v1"
    hmac_key_id: str = "reachy-frame-hmac:v1"


class _Clock:
    def now(self) -> datetime:
        return NOW


class _RouteAuthorizer:
    async def authorize(self, request: object) -> Any:
        raise AssertionError(f"unexpected provider authorization: {request!r}")

    async def consume(self, authorization_id: object, consumption: object) -> None:
        raise AssertionError((authorization_id, consumption))


class _DuplexState:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def abandon_connection(self, reason: str) -> None:
        self.events.append(f"duplex:{reason}")


class _Handler:
    async def control(self, purpose: str, payload: bytes) -> bytes:
        raise AssertionError((purpose, payload))

    async def media(self, frame: bytes) -> None:
        raise AssertionError(frame)


class _DeviceRegistry:
    async def require_current_client_certificate(
        self,
        observed_sha256: str,
        expected_sha256: str,
        endpoint_generation: int,
    ) -> object:
        raise AssertionError((observed_sha256, expected_sha256, endpoint_generation))


class _PairingKeys:
    async def current_outbound(self, **kwargs: object) -> object:
        raise AssertionError(kwargs)

    async def resolve_inbound(self, **kwargs: object) -> object:
        raise AssertionError(kwargs)


class _TimeIssuer:
    async def issue(self, nonce: bytes, *, client_certificate_sha256: str) -> object:
        raise AssertionError((nonce, client_certificate_sha256))


class _StartedServer:
    def __init__(self, events: list[str], *, close_raises: bool = False) -> None:
        self.events = events
        self.close_raises = close_raises
        self.closed = 0
        self.waited = 0

    def close(self) -> None:
        self.events.append("wss.close")
        self.closed += 1
        if self.close_raises:
            raise RuntimeError("synthetic_wss_close_failed")

    async def wait_closed(self) -> None:
        self.events.append("wss.wait_closed")
        self.waited += 1


class _ServeFactory:
    def __init__(self, events: list[str], *, start_raises: bool = False) -> None:
        self.events = events
        self.start_raises = start_raises
        self.started = asyncio.Event()
        self.calls: list[dict[str, object]] = []
        self.server = _StartedServer(events)

    async def __call__(self, handler: object, **kwargs: object) -> _StartedServer:
        self.events.append("wss.start")
        self.calls.append({"handler": handler, **kwargs})
        self.started.set()
        if self.start_raises:
            raise RuntimeError("synthetic_wss_start_failed")
        return self.server


class _StopAllSession:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.requests: list[tuple[str, UUID | None]] = []

    async def exchange_signed(self, *, purpose: str, payload: bytes) -> bytes:
        command = parse_contract_json(
            ReachyCommand,
            payload,
            max_bytes=131_072,
            require_canonical=True,
        )
        self.events.append(f"session.exchange:{purpose}:{command.turn_id}")
        self.requests.append((purpose, command.turn_id))
        if purpose != "reachy.stop_all.v1" or command.kind != "stop_all":
            raise AssertionError((purpose, command))
        return canonical_bytes(
            StopAllReceiptBundleV1(
                command_receipt=ReachyReceipt(
                    command_id=command.command_id,
                    accepted=True,
                    reason_code="accepted",
                ),
                safety_receipt=SafetyReceipt(
                    turn_id=command.turn_id,
                    playback_stopped=True,
                    motion_stopped=True,
                    buffers_cleared=True,
                ),
            )
        )

    async def serve(self) -> None:
        raise AssertionError("the current-session channel should not serve")


class _ScriptedExchangeSession:
    def __init__(self, events: list[str], *, response: bytes = b"ok") -> None:
        self.events = events
        self.response = response
        self.requests: list[tuple[str, bytes]] = []

    async def exchange_signed(self, *, purpose: str, payload: bytes) -> bytes:
        self.events.append(f"session.exchange:{purpose}")
        self.requests.append((purpose, payload))
        return self.response


class _BlockingExchangeSession:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.started = asyncio.Event()
        self.response: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    async def exchange_signed(self, *, purpose: str, payload: bytes) -> bytes:
        self.events.append(f"session.exchange:{purpose}")
        self.started.set()
        return await self.response


class _Workflow:
    async def run(self, turn: TurnInput) -> TurnOutput:
        return TurnOutput(turn_id=turn.turn_id, outcome="completed")


class _SessionManager:
    async def open(
        self,
        household_id: UUID,
        turn_id: UUID,
        *,
        context_session_id: UUID | None = None,
    ) -> Any:
        raise AssertionError((household_id, turn_id, context_session_id))

    async def end_context_session(self, context_session_id: UUID) -> bool:
        raise AssertionError(context_session_id)


class _LifecycleProcessLease:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.held = True

    def require_held(self) -> None:
        self.events.append("lease.require")
        if not self.held:
            raise RuntimeError("core_process_lease_not_held")

    def release_after_shutdown(self) -> None:
        self.events.append("lease.release")
        self.held = False


class _LifecycleStartupRecovery:
    def __init__(self, lease: _LifecycleProcessLease) -> None:
        self.process_lease = lease

    @staticmethod
    def _spawn_owned(factory: object, name: str) -> asyncio.Task[object]:
        assert type(name) is str and name
        return asyncio.create_task(factory(), name=name)  # type: ignore[operator]


class _LifecycleBudget:
    def __init__(
        self,
        events: list[str],
        lease: _LifecycleProcessLease,
        *,
        start_error: BaseException | None = None,
    ) -> None:
        self.events = events
        self.start_error = start_error
        self.startup_recovery = _LifecycleStartupRecovery(lease)

    async def start(self) -> None:
        self.events.append("budget.start")
        if self.start_error is not None:
            raise self.start_error

    async def stop(self) -> None:
        self.events.append("budget.stop")
        self.startup_recovery.process_lease.release_after_shutdown()


class _LifecycleCurrentSession:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def open_publication_generation(self) -> None:
        self.events.append("current.open_publication")

    async def begin_shutdown_drain(self) -> None:
        self.events.append("current.begin_shutdown_drain")

    def withdraw_readiness(self) -> None:
        self.events.append("current.withdraw_readiness")

    async def withdraw_authority(self) -> None:
        self.events.append("current.withdraw_authority")

    async def wait_authenticated(self, timeout: float) -> None:
        self.events.append(f"current.wait:{timeout}")


class _BlockingLifecycleCurrentSession(_LifecycleCurrentSession):
    def __init__(self, events: list[str]) -> None:
        super().__init__(events)
        self.wait_started = asyncio.Event()
        self.cancel_seen = asyncio.Event()
        self.release = asyncio.Event()

    async def wait_authenticated(self, timeout: float) -> None:
        self.events.append(f"current.wait:{timeout}")
        self.wait_started.set()
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancel_seen.set()
            await self.release.wait()
            raise


class _LifecycleSafety:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def close_media_stop_playback_motion_and_forget_turn(self) -> None:
        self.events.append("safety.close")


class _LifecycleWss:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def start(self) -> None:
        self.events.append("wss.start")

    async def close(self) -> None:
        self.events.append("wss.close")


class _BlockingLifecycleWss(_LifecycleWss):
    def __init__(self, events: list[str], *, close_error: BaseException | None = None) -> None:
        super().__init__(events)
        self.close_started = asyncio.Event()
        self.release_close = asyncio.Event()
        self.close_error = close_error

    async def close(self) -> None:
        self.events.append("wss.close")
        self.close_started.set()
        await self.release_close.wait()
        if self.close_error is not None:
            raise self.close_error


def test_wss_uses_the_session_owned_transport_supervisor_definition() -> None:
    from tuntun_core.adapters.reachy import session as session_module
    from tuntun_core.adapters.reachy import wss_server

    assert wss_server.ReachyTransportSupervisorState is (
        session_module.ReachyTransportSupervisorState
    )


@pytest.mark.asyncio
async def test_current_authenticated_session_channel_is_exact_and_fail_closed() -> None:
    from tuntun_core.adapters.reachy.current_session import (
        CoreDisconnectSafetyFacade,
        CurrentReachySessionChannel,
    )

    safety = CoreDisconnectSafetyFacade(active_turn_id=lambda: None, cancel_turn=_no_active_turn)
    channel = CurrentReachySessionChannel(safety=safety)

    with pytest.raises(RuntimeError, match="reachy_authenticated_session_unavailable"):
        channel.require_ready()
    with pytest.raises(RuntimeError, match="reachy_authenticated_session_unavailable"):
        await channel.exchange_signed(purpose="reachy.health.v1", payload=b"{}")

    session = _StopAllSession([])
    replacement = _StopAllSession([])
    await channel.publish(DEVICE_ID, session)
    channel.require_ready()
    assert channel.safety is safety
    assert await channel.current_session() is session

    await channel.exchange_signed(purpose="reachy.stop_all.v1", payload=_stop_all_payload(None))

    with pytest.raises(RuntimeError, match="reachy_authenticated_session_already_published"):
        await channel.publish(DEVICE_ID, replacement)
    with pytest.raises(RuntimeError, match="reachy_authenticated_session_identity_mismatch"):
        await channel.clear(DEVICE_ID, replacement)
    assert await channel.current_session() is session

    await channel.clear(DEVICE_ID, session)
    assert await channel.current_session() is None
    with pytest.raises(RuntimeError, match="reachy_authenticated_session_unavailable"):
        await channel.exchange_signed(purpose="reachy.stop_all.v1", payload=_stop_all_payload(None))


@pytest.mark.asyncio
async def test_current_session_channel_shutdown_drain_blocks_ordinary_exchange_and_publish() -> (
    None
):
    from tuntun_core.adapters.reachy.current_session import (
        CoreDisconnectSafetyFacade,
        CurrentReachySessionChannel,
    )

    events: list[str] = []
    safety = CoreDisconnectSafetyFacade(active_turn_id=lambda: None, cancel_turn=_no_active_turn)
    channel = CurrentReachySessionChannel(safety=safety)
    await channel.open_publication_generation()
    session = _ScriptedExchangeSession(events)
    await channel.publish(DEVICE_ID, session)

    await channel.begin_shutdown_drain()

    with pytest.raises(RuntimeError, match="reachy_authenticated_session_unavailable"):
        channel.require_ready()
    assert await channel.current_session() is None
    with pytest.raises(RuntimeError, match="reachy_authenticated_session_unavailable"):
        await channel.exchange_signed(purpose="reachy.health.v1", payload=b"{}")
    with pytest.raises(RuntimeError, match="reachy_session_publication_closed"):
        await channel.publish(DEVICE_ID, session)

    assert (
        await channel.exchange_signed(
            purpose="reachy.stop_all.v1",
            payload=_stop_all_payload(None),
        )
        == b"ok"
    )
    assert events == ["session.exchange:reachy.stop_all.v1"]

    await channel.withdraw_authority()
    with pytest.raises(RuntimeError, match="reachy_authenticated_session_unavailable"):
        await channel.exchange_signed(purpose="reachy.stop_all.v1", payload=_stop_all_payload(None))

    await channel.open_publication_generation()
    replacement = _ScriptedExchangeSession(events)
    await channel.publish(DEVICE_ID, replacement)
    channel.require_ready()
    assert await channel.current_session() is replacement


@pytest.mark.asyncio
async def test_current_session_channel_rejects_stale_exchange_result_after_shutdown_drain() -> None:
    from tuntun_core.adapters.reachy.current_session import (
        CoreDisconnectSafetyFacade,
        CurrentReachySessionChannel,
    )

    events: list[str] = []
    safety = CoreDisconnectSafetyFacade(active_turn_id=lambda: None, cancel_turn=_no_active_turn)
    channel = CurrentReachySessionChannel(safety=safety)
    await channel.open_publication_generation()
    session = _BlockingExchangeSession(events)
    await channel.publish(DEVICE_ID, session)

    exchange = asyncio.create_task(
        channel.exchange_signed(purpose="reachy.health.v1", payload=b"{}")
    )
    await asyncio.wait_for(session.started.wait(), timeout=1)
    await channel.begin_shutdown_drain()
    session.response.set_result(b"stale")

    with pytest.raises(RuntimeError, match="reachy_authenticated_session_unavailable"):
        await exchange
    assert events == ["session.exchange:reachy.health.v1"]


@pytest.mark.asyncio
async def test_current_session_channel_allows_in_flight_stop_all_to_finish_after_drain() -> None:
    from tuntun_core.adapters.reachy.current_session import (
        CoreDisconnectSafetyFacade,
        CurrentReachySessionChannel,
    )

    events: list[str] = []
    safety = CoreDisconnectSafetyFacade(active_turn_id=lambda: None, cancel_turn=_no_active_turn)
    channel = CurrentReachySessionChannel(safety=safety)
    await channel.open_publication_generation()
    session = _BlockingExchangeSession(events)
    await channel.publish(DEVICE_ID, session)

    exchange = asyncio.create_task(
        channel.exchange_signed(
            purpose="reachy.stop_all.v1",
            payload=_stop_all_payload(None),
        )
    )
    await asyncio.wait_for(session.started.wait(), timeout=1)
    await channel.begin_shutdown_drain()
    session.response.set_result(b"safe")

    assert await exchange == b"safe"
    assert events == ["session.exchange:reachy.stop_all.v1"]


@pytest.mark.asyncio
async def test_current_session_invalidates_in_flight_stop_after_authority_withdrawal() -> None:
    from tuntun_core.adapters.reachy.current_session import (
        CoreDisconnectSafetyFacade,
        CurrentReachySessionChannel,
    )

    events: list[str] = []
    safety = CoreDisconnectSafetyFacade(active_turn_id=lambda: None, cancel_turn=_no_active_turn)
    channel = CurrentReachySessionChannel(safety=safety)
    await channel.open_publication_generation()
    session = _BlockingExchangeSession(events)
    await channel.publish(DEVICE_ID, session)

    exchange = asyncio.create_task(
        channel.exchange_signed(
            purpose="reachy.stop_all.v1",
            payload=_stop_all_payload(None),
        )
    )
    await asyncio.wait_for(session.started.wait(), timeout=1)
    await channel.withdraw_authority()
    session.response.set_result(b"stale")

    with pytest.raises(RuntimeError, match="reachy_authenticated_session_unavailable"):
        await exchange
    assert events == ["session.exchange:reachy.stop_all.v1"]


@pytest.mark.asyncio
async def test_current_session_invalidates_in_flight_stop_after_session_replacement() -> None:
    from tuntun_core.adapters.reachy.current_session import (
        CoreDisconnectSafetyFacade,
        CurrentReachySessionChannel,
    )

    events: list[str] = []
    safety = CoreDisconnectSafetyFacade(active_turn_id=lambda: None, cancel_turn=_no_active_turn)
    channel = CurrentReachySessionChannel(safety=safety)
    await channel.open_publication_generation()
    session = _BlockingExchangeSession(events)
    await channel.publish(DEVICE_ID, session)

    exchange = asyncio.create_task(
        channel.exchange_signed(
            purpose="reachy.stop_all.v1",
            payload=_stop_all_payload(None),
        )
    )
    await asyncio.wait_for(session.started.wait(), timeout=1)
    await channel.withdraw_authority()
    await channel.open_publication_generation()
    replacement = _ScriptedExchangeSession(events)
    await channel.publish(DEVICE_ID, replacement)
    session.response.set_result(b"stale")

    with pytest.raises(RuntimeError, match="reachy_authenticated_session_unavailable"):
        await exchange
    assert await channel.current_session() is replacement
    assert events == ["session.exchange:reachy.stop_all.v1"]


def test_production_container_builds_one_shared_core_transport_composition(
    async_uow_factory: object,
    clock: object,
    catalog: object,
    runtime_provider_identities: object,
    budget_evidence: object,
    tmp_path: Path,
) -> None:
    from tuntun_core.adapters.reachy.authenticated_control import AuthenticatedControlClient
    from tuntun_core.adapters.reachy.gateway import ReachyGateway
    from tuntun_core.adapters.reachy.session import CoreReachySession

    production = _build_production_container(
        tmp_path,
        async_uow_factory=async_uow_factory,
        clock=clock,
        catalog=catalog,
        runtime_provider_identities=runtime_provider_identities,
        budget_evidence=budget_evidence,
    )
    try:
        state = production.reachy_transport_supervisor
        safety = production.disconnect_safety
        current = production.current_reachy_session

        assert production.readiness_dependencies.count(state) == 1
        assert production.readiness_dependencies.count(current) == 1
        assert production.readiness_dependencies.count(production.budget_lifecycle) == 1
        assert production.reachy_wss_server._readiness is state
        assert production.reachy_wss_server._sessions is current
        assert current.safety is safety
        assert type(production.authenticated_reachy_control) is AuthenticatedControlClient
        assert production.authenticated_reachy_control._channel is current
        assert type(production.reachy_gateway) is ReachyGateway
        assert production.reachy_gateway._control is production.authenticated_reachy_control
        assert production.startup_turn_recovery._reachy is production.reachy_gateway
        assert production.turn_coordinator._reachy is production.reachy_gateway

        session = production.reachy_wss_server._session_factory(
            socket=_Socket(),
            connection_nonce=b"n" * 32,
            outbound_keys=_Keys(),
            inbound_key_resolver=_PairingKeys(),
            tls_peer_sha256="1" * 64,
            device_id=DEVICE_ID,
            state=_DuplexState([]),
            handler=_Handler(),
            safety=safety,
            readiness=state,
            clock=_Clock(),
        )
        assert type(session) is CoreReachySession
        assert session._readiness is state
        assert session._safety is safety
    finally:
        production.core_process_lease.release_after_shutdown()


@pytest.mark.asyncio
async def test_production_start_waits_for_authenticated_session_before_startup_recovery(
    async_uow_factory: object,
    clock: object,
    catalog: object,
    runtime_provider_identities: object,
    budget_evidence: object,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    serve_factory = _ServeFactory(events)
    production = _build_production_container(
        tmp_path,
        async_uow_factory=async_uow_factory,
        clock=clock,
        catalog=catalog,
        runtime_provider_identities=runtime_provider_identities,
        budget_evidence=budget_evidence,
        events=events,
        serve_factory=serve_factory,
        session_ready_timeout=0.5,
    )
    dependencies = SimulatedGuestAppDependencies(
        session_manager=_SessionManager(),
        workflow=_Workflow(),
        household_id=uuid4(),
        device_id=uuid4(),
        loopback_host="127.0.0.1",
        readiness_dependencies=production.readiness_dependencies,
    )
    app = create_app(dependencies)
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 42_000))

    start_task = asyncio.create_task(production.start())
    try:
        await asyncio.wait_for(serve_factory.started.wait(), timeout=0.5)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            ready = await client.get("/health/ready")
            turn = await client.post("/session/simulated-turn", json={})
        assert ready.status_code == 503
        assert turn.status_code == 503
        assert events == ["duplex:restart_recovery", "wss.start"]

        session = _StopAllSession(events)
        await production.current_reachy_session.publish(DEVICE_ID, session)
        await _await_production_start_or_cleanup(start_task, production, events)

        assert session.requests == [("reachy.stop_all.v1", None)]
        assert events.index("wss.start") < events.index("session.exchange:reachy.stop_all.v1:None")
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            ready = await client.get("/health/ready")
        assert ready.status_code == 200
        assert serve_factory.calls[0]["subprotocols"] == [
            "tuntun.reachy.time.v1",
            "tuntun.reachy.v1",
        ]
    except BaseException as primary:
        await _cleanup_production_after_start_failure(start_task, production, primary)
        raise
    else:
        await production.stop()


@pytest.mark.asyncio
async def test_production_listener_start_failure_releases_lease_and_stays_unready(
    async_uow_factory: object,
    clock: object,
    catalog: object,
    runtime_provider_identities: object,
    budget_evidence: object,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    production = _build_production_container(
        tmp_path,
        async_uow_factory=async_uow_factory,
        clock=clock,
        catalog=catalog,
        runtime_provider_identities=runtime_provider_identities,
        budget_evidence=budget_evidence,
        events=events,
        serve_factory=_ServeFactory(events, start_raises=True),
    )
    lock_path = production.core_process_lease.path

    with pytest.raises(RuntimeError, match="synthetic_wss_start_failed"):
        await production.start()

    with pytest.raises(RuntimeError, match="reachy_authenticated_session_unavailable"):
        production.current_reachy_session.require_ready()
    _assert_lease_released(lock_path)


@pytest.mark.asyncio
async def test_production_start_cancellation_closes_wss_and_releases_lease(
    async_uow_factory: object,
    clock: object,
    catalog: object,
    runtime_provider_identities: object,
    budget_evidence: object,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    serve_factory = _ServeFactory(events)
    production = _build_production_container(
        tmp_path,
        async_uow_factory=async_uow_factory,
        clock=clock,
        catalog=catalog,
        runtime_provider_identities=runtime_provider_identities,
        budget_evidence=budget_evidence,
        events=events,
        serve_factory=serve_factory,
        session_ready_timeout=0.5,
    )
    lock_path = production.core_process_lease.path

    start_task = asyncio.create_task(production.start())
    await asyncio.wait_for(serve_factory.started.wait(), timeout=0.5)
    start_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await start_task
    await production.stop()

    with pytest.raises(RuntimeError, match="reachy_authenticated_session_unavailable"):
        production.current_reachy_session.require_ready()
    assert events == [
        "duplex:restart_recovery",
        "wss.start",
        "wss.close",
        "wss.wait_closed",
    ]
    _assert_lease_released(lock_path)


@pytest.mark.asyncio
async def test_production_start_helper_timeout_cancels_start_and_stops_production(
    async_uow_factory: object,
    clock: object,
    catalog: object,
    runtime_provider_identities: object,
    budget_evidence: object,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    serve_factory = _ServeFactory(events)
    production = _build_production_container(
        tmp_path,
        async_uow_factory=async_uow_factory,
        clock=clock,
        catalog=catalog,
        runtime_provider_identities=runtime_provider_identities,
        budget_evidence=budget_evidence,
        events=events,
        serve_factory=serve_factory,
        session_ready_timeout=0.5,
    )
    lock_path = production.core_process_lease.path

    start_task = asyncio.create_task(production.start())
    await asyncio.wait_for(serve_factory.started.wait(), timeout=0.5)
    session = _BlockingExchangeSession(events)
    await production.current_reachy_session.publish(DEVICE_ID, session)
    await asyncio.wait_for(session.started.wait(), timeout=0.5)

    with pytest.raises(pytest.fail.Exception, match="production.start\\(\\) did not finish"):
        await _await_production_start_or_cleanup(
            start_task,
            production,
            events,
            diagnostic_timeout=0.001,
        )

    assert start_task.done()
    assert production.reachy_wss_server._server is None
    assert "wss.close" in events
    assert "wss.wait_closed" in events
    _assert_lease_released(lock_path)


@pytest.mark.asyncio
async def test_production_failed_start_runs_physical_safety_before_authority_loss() -> None:
    from tuntun_core.bootstrap.lifecycle import ProductionReachyLifecycle

    events: list[str] = []
    lease = _LifecycleProcessLease(events)
    lifecycle = ProductionReachyLifecycle(
        wss_server=_LifecycleWss(events),
        current_session=_LifecycleCurrentSession(events),
        disconnect_safety=_LifecycleSafety(events),
        budget_lifecycle=_LifecycleBudget(
            events,
            lease,
            start_error=RuntimeError("budget start failed"),
        ),
        process_lease=lease,
        session_ready_timeout=0.05,
    )

    with pytest.raises(RuntimeError, match="budget start failed"):
        await lifecycle.start()

    assert events.index("safety.close") < events.index("current.withdraw_authority")
    assert events.index("wss.close") < events.index("current.withdraw_authority")
    assert events[-2:] == ["budget.stop", "lease.release"]


@pytest.mark.asyncio
async def test_production_start_is_rejected_while_older_stop_cleanup_is_active() -> None:
    from tuntun_core.bootstrap.lifecycle import ProductionReachyLifecycle

    events: list[str] = []
    lease = _LifecycleProcessLease(events)
    wss = _BlockingLifecycleWss(events)
    lifecycle = ProductionReachyLifecycle(
        wss_server=wss,
        current_session=_LifecycleCurrentSession(events),
        disconnect_safety=_LifecycleSafety(events),
        budget_lifecycle=_LifecycleBudget(events, lease),
        process_lease=lease,
        session_ready_timeout=0.05,
    )

    stop_task = asyncio.create_task(lifecycle.stop())
    await asyncio.wait_for(wss.close_started.wait(), timeout=1)
    try:
        with pytest.raises(RuntimeError, match="reachy_production_lifecycle_stop_in_progress"):
            await lifecycle.start()
        assert "wss.start" not in events
    finally:
        wss.release_close.set()
        await asyncio.wait_for(stop_task, timeout=1)


@pytest.mark.asyncio
async def test_failed_start_caller_cancellation_with_cleanup_error_blocks_retry() -> None:
    from tuntun_core.bootstrap.lifecycle import ProductionReachyLifecycle

    events: list[str] = []
    lease = _LifecycleProcessLease(events)
    wss = _BlockingLifecycleWss(events, close_error=RuntimeError("synthetic_wss_close_failed"))
    lifecycle = ProductionReachyLifecycle(
        wss_server=wss,
        current_session=_LifecycleCurrentSession(events),
        disconnect_safety=_LifecycleSafety(events),
        budget_lifecycle=_LifecycleBudget(
            events,
            lease,
            start_error=RuntimeError("budget start failed"),
        ),
        process_lease=lease,
        session_ready_timeout=0.05,
    )

    start_task = asyncio.create_task(lifecycle.start())
    await asyncio.wait_for(wss.close_started.wait(), timeout=1)
    start_task.cancel()
    wss.release_close.set()
    with pytest.raises(asyncio.CancelledError) as cancelled:
        await asyncio.wait_for(start_task, timeout=1)

    assert cancelled.value.__cause__ is not None
    assert _exception_tree_contains(cancelled.value.__cause__, "budget start failed")
    assert _exception_tree_contains(cancelled.value.__cause__, "synthetic_wss_close_failed")
    assert "lease.release" not in events
    with pytest.raises(RuntimeError, match="reachy_production_lifecycle_cleanup_pending"):
        await lifecycle.start()

    wss.close_error = None
    await lifecycle.stop()
    assert "lease.release" in events


@pytest.mark.asyncio
async def test_stop_caller_cancellation_with_cleanup_error_blocks_retry_until_cleanup() -> None:
    from tuntun_core.bootstrap.lifecycle import ProductionReachyLifecycle

    events: list[str] = []
    lease = _LifecycleProcessLease(events)
    wss = _BlockingLifecycleWss(events, close_error=RuntimeError("synthetic_wss_close_failed"))
    lifecycle = ProductionReachyLifecycle(
        wss_server=wss,
        current_session=_LifecycleCurrentSession(events),
        disconnect_safety=_LifecycleSafety(events),
        budget_lifecycle=_LifecycleBudget(events, lease),
        process_lease=lease,
        session_ready_timeout=0.05,
    )
    await lifecycle.start()

    stop_task = asyncio.create_task(lifecycle.stop())
    await asyncio.wait_for(wss.close_started.wait(), timeout=1)
    stop_task.cancel()
    wss.release_close.set()
    with pytest.raises(asyncio.CancelledError) as cancelled:
        await asyncio.wait_for(stop_task, timeout=1)

    assert cancelled.value.__cause__ is not None
    assert _exception_tree_contains(cancelled.value.__cause__, "synthetic_wss_close_failed")
    assert "lease.release" not in events
    with pytest.raises(RuntimeError, match="reachy_production_lifecycle_cleanup_pending"):
        await lifecycle.start()

    wss.close_error = None
    await lifecycle.stop()
    assert "lease.release" in events


@pytest.mark.asyncio
async def test_production_stop_bounds_in_flight_start_observation() -> None:
    from tuntun_core.bootstrap.lifecycle import ProductionReachyLifecycle

    events: list[str] = []
    lease = _LifecycleProcessLease(events)
    current = _BlockingLifecycleCurrentSession(events)
    lifecycle = ProductionReachyLifecycle(
        wss_server=_LifecycleWss(events),
        current_session=current,
        disconnect_safety=_LifecycleSafety(events),
        budget_lifecycle=_LifecycleBudget(events, lease),
        process_lease=lease,
        session_ready_timeout=0.01,
    )
    start = asyncio.create_task(lifecycle.start())
    await asyncio.wait_for(current.wait_started.wait(), timeout=1)

    try:
        with pytest.raises(RuntimeError, match="reachy_production_start_stop_unobserved"):
            await asyncio.wait_for(lifecycle.stop(), timeout=0.1)
        assert current.cancel_seen.is_set()
        assert "safety.close" in events
        assert "wss.close" in events
    finally:
        current.release.set()
        with contextlib.suppress(BaseException):
            await asyncio.wait_for(start, timeout=0.2)
        with contextlib.suppress(BaseException):
            await asyncio.wait_for(lifecycle.stop(), timeout=0.2)


@pytest.mark.asyncio
async def test_production_partial_start_timeout_closes_wss_and_releases_lease(
    async_uow_factory: object,
    clock: object,
    catalog: object,
    runtime_provider_identities: object,
    budget_evidence: object,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    serve_factory = _ServeFactory(events)
    production = _build_production_container(
        tmp_path,
        async_uow_factory=async_uow_factory,
        clock=clock,
        catalog=catalog,
        runtime_provider_identities=runtime_provider_identities,
        budget_evidence=budget_evidence,
        events=events,
        serve_factory=serve_factory,
        session_ready_timeout=0.01,
    )
    lock_path = production.core_process_lease.path

    with pytest.raises(RuntimeError, match="reachy_authenticated_session_unavailable"):
        await production.start()
    await production.stop()

    with pytest.raises(RuntimeError, match="reachy_authenticated_session_unavailable"):
        production.current_reachy_session.require_ready()
    assert events == [
        "duplex:restart_recovery",
        "wss.start",
        "wss.close",
        "wss.wait_closed",
    ]
    _assert_lease_released(lock_path)


@pytest.mark.asyncio
async def test_production_failed_start_unproven_close_surfaces_both_causes_and_blocks_retry(
    async_uow_factory: object,
    clock: object,
    catalog: object,
    runtime_provider_identities: object,
    budget_evidence: object,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    serve_factory = _ServeFactory(events)
    serve_factory.server = _StartedServer(events, close_raises=True)
    production = _build_production_container(
        tmp_path,
        async_uow_factory=async_uow_factory,
        clock=clock,
        catalog=catalog,
        runtime_provider_identities=runtime_provider_identities,
        budget_evidence=budget_evidence,
        events=events,
        serve_factory=serve_factory,
        session_ready_timeout=0.01,
    )
    lock_path = production.core_process_lease.path

    try:
        with pytest.raises(RuntimeError, match="reachy_production_start_failed") as raised:
            await production.start()

        assert _exception_tree_contains(
            raised.value,
            "reachy_authenticated_session_unavailable",
        )
        assert _exception_tree_contains(raised.value, "reachy_server_close_unproven")
        assert production.reachy_wss_server._server is serve_factory.server
        _assert_lease_held(lock_path)

        with pytest.raises(
            RuntimeError,
            match="reachy_production_lifecycle_cleanup_pending",
        ):
            await production.start()
        assert len(serve_factory.calls) == 1

        serve_factory.server.close_raises = False
        await production.stop()
        assert production.reachy_wss_server._server is None
        _assert_lease_released(lock_path)
    finally:
        serve_factory.server.close_raises = False
        if production.reachy_wss_server._server is not None:
            with contextlib.suppress(BaseException):
                await production.stop()


@pytest.mark.asyncio
async def test_production_shutdown_withdraws_readiness_runs_safety_closes_wss_then_releases_lease(
    async_uow_factory: object,
    clock: object,
    catalog: object,
    runtime_provider_identities: object,
    budget_evidence: object,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    serve_factory = _ServeFactory(events)
    production = _build_production_container(
        tmp_path,
        async_uow_factory=async_uow_factory,
        clock=clock,
        catalog=catalog,
        runtime_provider_identities=runtime_provider_identities,
        budget_evidence=budget_evidence,
        events=events,
        serve_factory=serve_factory,
        session_ready_timeout=0.5,
    )
    start_task = asyncio.create_task(production.start())
    try:
        await asyncio.wait_for(serve_factory.started.wait(), timeout=0.5)
        session = _StopAllSession(events)
        await production.current_reachy_session.publish(DEVICE_ID, session)
        await _await_production_start_or_cleanup(start_task, production, events)
        turn_id = uuid4()
        await production.turn_coordinator.start(turn_id)
        lock_path = production.core_process_lease.path

        await production.stop()
        await production.stop()

        with pytest.raises(RuntimeError, match="reachy_authenticated_session_unavailable"):
            production.current_reachy_session.require_ready()
        assert ("reachy.stop_all.v1", turn_id) in session.requests
        assert events.index(f"session.exchange:reachy.stop_all.v1:{turn_id}") < events.index(
            "wss.close"
        )
        assert events.index("wss.wait_closed") > events.index("wss.close")
        _assert_lease_released(lock_path)
    except BaseException as primary:
        await _cleanup_production_after_start_failure(start_task, production, primary)
        raise


@pytest.mark.asyncio
async def test_production_shutdown_close_failure_retains_listener_and_lease_until_retry(
    async_uow_factory: object,
    clock: object,
    catalog: object,
    runtime_provider_identities: object,
    budget_evidence: object,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    serve_factory = _ServeFactory(events)
    serve_factory.server = _StartedServer(events, close_raises=True)
    production = _build_production_container(
        tmp_path,
        async_uow_factory=async_uow_factory,
        clock=clock,
        catalog=catalog,
        runtime_provider_identities=runtime_provider_identities,
        budget_evidence=budget_evidence,
        events=events,
        serve_factory=serve_factory,
        session_ready_timeout=0.5,
    )
    start_task = asyncio.create_task(production.start())
    try:
        await asyncio.wait_for(serve_factory.started.wait(), timeout=0.5)
        await production.current_reachy_session.publish(DEVICE_ID, _StopAllSession(events))
        await _await_production_start_or_cleanup(start_task, production, events)
        lock_path = production.core_process_lease.path

        with pytest.raises(RuntimeError, match="reachy_server_close_unproven"):
            await production.stop()

        assert "reachy_server_close:RuntimeError" in (
            production.reachy_transport_supervisor.disconnect_degraded_codes
        )
        assert production.reachy_wss_server._server is serve_factory.server
        _assert_lease_held(lock_path)

        serve_factory.server.close_raises = False
        await production.stop()

        assert production.reachy_wss_server._server is None
        _assert_lease_released(lock_path)
    except BaseException as primary:
        serve_factory.server.close_raises = False
        await _cleanup_production_after_start_failure(start_task, production, primary)
        raise


async def _no_active_turn(turn_id: UUID, reason: str) -> None:
    raise AssertionError((turn_id, reason))


def _stop_all_payload(turn_id: UUID | None) -> bytes:
    return canonical_bytes(
        ReachyCommand(
            command_id=uuid4(),
            turn_id=turn_id,
            kind="stop_all",
            state=None,
            media_stream_id=None,
            gesture_id=None,
            expires_at=NOW,
        )
    )


class _Keys:
    signer = Ed25519PrivateKey.generate()
    signing_key_id = "ed25519:reachy-core:v1"
    hmac_root = b"h" * 32
    hmac_key_id = "reachy-frame-hmac:v1"


class _Socket:
    async def send(self, message: str | bytes) -> None:
        raise AssertionError(message)

    async def close(self, *, code: int = 1000, reason: str = "") -> None:
        raise AssertionError((code, reason))

    def ping(self, payload: bytes) -> object:
        raise AssertionError(payload)

    def __aiter__(self) -> object:
        raise AssertionError("not used")


def _build_production_container(
    tmp_path: Path,
    *,
    async_uow_factory: object,
    clock: object,
    catalog: object,
    runtime_provider_identities: object,
    budget_evidence: object,
    events: list[str] | None = None,
    serve_factory: _ServeFactory | None = None,
    session_ready_timeout: float = 0.05,
) -> Any:
    from tuntun_core.bootstrap.container import ProductionContainer

    state_root = tmp_path / f"production-state-{uuid4()}"
    state_root.mkdir(mode=0o700)
    state_root.chmod(0o700)
    provider_defaults_path = tmp_path / f"provider-defaults-{uuid4()}.yaml"
    shutil.copyfile(PROJECT_ROOT / "config/providers/default.yaml", provider_defaults_path)
    provider_defaults_path.chmod(0o600)
    log = [] if events is None else events
    return ProductionContainer.build(
        configured_state_root=state_root,
        reachy=object(),
        sqlcipher_uow_factory=async_uow_factory,  # type: ignore[arg-type]
        task1_identity_key_provider=StaticTask1IdentityKeyProvider(),
        clock=clock,  # type: ignore[arg-type]
        route_authorizer=_RouteAuthorizer(),
        price_catalog=catalog,  # type: ignore[arg-type]
        runtime_provider_identities=runtime_provider_identities,  # type: ignore[arg-type]
        budget_evidence=budget_evidence,  # type: ignore[arg-type]
        provider_defaults_path=provider_defaults_path,
        reachy_endpoint=_Endpoint(),
        reachy_tls_context=object(),
        reachy_device_registry=_DeviceRegistry(),
        reachy_pairing_keys=_PairingKeys(),
        reachy_duplex_state=_DuplexState(log),
        reachy_handler=_Handler(),
        reachy_time_issuer=_TimeIssuer(),
        reachy_serve_factory=serve_factory or _ServeFactory(log),
        reachy_session_ready_timeout=session_ready_timeout,
    )


def _assert_lease_released(lock_path: Path) -> None:
    lease = CoreProcessLease.acquire(lock_path)
    lease.release_after_shutdown()


def _assert_lease_held(lock_path: Path) -> None:
    with pytest.raises(RuntimeError, match="core_process_lease_held"):
        CoreProcessLease.acquire(lock_path)


def _exception_tree_contains(error: BaseException, expected: str) -> bool:
    seen: set[int] = set()
    stack: list[BaseException] = [error]
    while stack:
        current = stack.pop()
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        if expected in str(current):
            return True
        if isinstance(current, BaseExceptionGroup):
            stack.extend(current.exceptions)
        if current.__cause__ is not None:
            stack.append(current.__cause__)
        context = current.__context__ if not current.__suppress_context__ else None
        if context is not None:
            stack.append(context)
    return False
