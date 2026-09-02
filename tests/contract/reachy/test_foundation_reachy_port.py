from __future__ import annotations

import asyncio
import base64
import contextlib
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, cast
from uuid import UUID, uuid4

import pytest
import tuntun_core.adapters.reachy.session as reachy_session_module
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from tuntun_contracts.base import (
    Commitment,
    ContractParseError,
    canonical_bytes,
    canonical_mapping_bytes,
    parse_contract_json,
)
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.ports import ReachyPort
from tuntun_contracts.reachy import (
    CameraWindowGrant,
    ReachyCommand,
    ReachyHealth,
    ReachyReceipt,
    ReachyState,
    SafetyReceipt,
    StopAllReceiptBundleV1,
)
from tuntun_contracts.reachy_wire import (
    MAX_CONTROL_FRAME_JSON_BYTES,
    MAX_CONTROL_PAYLOAD_BYTES,
    FrameKind,
    FramePurpose,
    SignedControlFrameV1,
    authenticate_control_frame,
    sign_control_frame,
)
from tuntun_core.adapters.reachy.authenticated_control import AuthenticatedControlClient
from tuntun_core.adapters.reachy.gateway import ReachyGateway
from tuntun_core.adapters.reachy.session import (
    CoreReachySession,
    PersistentCameraGrantClaims,
    ReachySession,
    ReachyTransportSupervisorState,
)

NOW = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)
DEVICE_ID = UUID("00000000-0000-0000-0000-00000000b001")
TLS_PEER_SHA256 = "1" * 64
CORE_SIGNING_KEY_ID = "ed25519:reachy-core:v1"
EDGE_SIGNING_KEY_ID = "ed25519:reachy-edge:v1"
HMAC_KEY_ID = "reachy-frame-hmac:v1"
HMAC_ROOT = bytes(range(32))
CONNECTION_NONCE = bytes(range(32, 64))


class Clock:
    def now(self) -> datetime:
        return NOW

    def monotonic(self) -> float:
        return 12.0


@dataclass(frozen=True, slots=True)
class KeyBundle:
    signer: Ed25519PrivateKey
    hmac_root: bytes
    signing_key_id: str
    hmac_key_id: str

    @property
    def public_key(self) -> Any:
        return self.signer.public_key()


@dataclass(slots=True)
class MutableKeyBundle:
    signer: Ed25519PrivateKey
    hmac_root: bytes
    signing_key_id: str
    hmac_key_id: str


class MutableRawEd25519PrivateKey(Ed25519PrivateKey):
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self.private_key = private_key

    def sign(self, data: bytes) -> bytes:
        return bytes(64)

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: object,
    ) -> bytes:
        return self.private_key.private_bytes(encoding, format, encryption_algorithm)

    def private_bytes_raw(self) -> bytes:
        return self.private_key.private_bytes_raw()

    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def __copy__(self) -> Ed25519PrivateKey:
        return self


class InboundKeyResolver:
    def __init__(self, inbound: KeyBundle) -> None:
        self._inbound = inbound
        self.calls: list[tuple[UUID, str, str, str, datetime]] = []

    async def resolve_inbound(
        self,
        *,
        device_id: UUID,
        tls_peer_sha256: str,
        signing_key_id: str,
        hmac_key_id: str,
        now: datetime,
    ) -> KeyBundle:
        self.calls.append((device_id, tls_peer_sha256, signing_key_id, hmac_key_id, now))
        if (
            device_id != DEVICE_ID
            or tls_peer_sha256 != TLS_PEER_SHA256
            or signing_key_id != self._inbound.signing_key_id
            or hmac_key_id != self._inbound.hmac_key_id
        ):
            raise PermissionError("pairing_key_binding")
        return self._inbound


class RecordingState:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.reserved: list[tuple[UUID, str, str]] = []
        self.accepted: list[tuple[int, UUID, str, str]] = []
        self.completed: list[UUID] = []
        self.abandoned: list[tuple[UUID | None, str]] = []

    async def reserve_outbound(self, correlation_id: UUID, purpose: str, kind: str) -> int:
        self.events.append(f"reserve:{kind}:{purpose}")
        self.reserved.append((correlation_id, purpose, kind))
        return len(self.reserved)

    async def accept_inbound(
        self,
        sequence: int,
        correlation_id: UUID,
        purpose: str,
        kind: str,
    ) -> None:
        self.events.append(f"accept:{kind}:{purpose}")
        self.accepted.append((sequence, correlation_id, purpose, kind))

    async def accept_response(self, correlation_id: UUID, purpose: str, payload: bytes) -> None:
        if not any(
            pending_id == correlation_id
            and pending_purpose == purpose
            and pending_kind == "request"
            for pending_id, pending_purpose, pending_kind in self.reserved
        ):
            raise PermissionError("correlation_not_pending")
        if type(payload) is not bytes:
            raise TypeError("control response payload must be bytes")

    async def complete(self, correlation_id: UUID) -> None:
        self.events.append(f"complete:{correlation_id}")
        self.completed.append(correlation_id)

    async def abandon_correlation(self, correlation_id: UUID, reason: str) -> None:
        self.events.append(f"abandon:{reason}")
        self.abandoned.append((correlation_id, reason))

    async def abandon_connection(self, reason: str) -> None:
        self.events.append(f"tombstone:{reason}")
        self.abandoned.append((None, reason))


class RecordingHandler:
    def __init__(self, events: list[str], response: bytes = b'{"ok":true}') -> None:
        self.events = events
        self.response = response
        self.control_calls: list[tuple[str, bytes]] = []
        self.media_calls: list[bytes] = []

    async def control(self, purpose: str, payload: bytes) -> bytes:
        self.events.append(f"control:{purpose}:{len(payload)}")
        self.control_calls.append((purpose, payload))
        return self.response

    async def media(self, frame: bytes) -> None:
        self.events.append(f"media:{len(frame)}")
        self.media_calls.append(frame)


class RecordingSafety:
    def __init__(
        self,
        events: list[str],
        *,
        pending_count: Callable[[], int] | None = None,
        failure: str | None = None,
        release: asyncio.Event | None = None,
    ) -> None:
        self.events = events
        self.pending_count = pending_count or (lambda: 0)
        self.failure = failure
        self.release = release
        self.latched: list[tuple[str, int]] = []
        self.closed = 0
        self.entered = asyncio.Event()

    def latch_error_safe(self, reason: str) -> None:
        self.events.append(f"latch:{reason}:{self.pending_count()}")
        self.latched.append((reason, self.pending_count()))

    async def close_media_stop_playback_motion_and_forget_turn(self) -> None:
        self.events.append("safety:start")
        self.entered.set()
        if self.failure == "raise":
            raise RuntimeError("safety boom")
        if self.release is not None:
            await self.release.wait()
        self.closed += 1
        self.events.append("safety:done")


class RecordingReadiness:
    def __init__(self) -> None:
        self.disconnect_degraded_codes: tuple[str, ...] = ()
        self.restart_required = False

    @property
    def ready(self) -> bool:
        return not self.disconnect_degraded_codes and not self.restart_required

    def latch_disconnect_degraded(
        self,
        codes: tuple[str, ...],
        *,
        restart_required: bool = False,
    ) -> None:
        self.disconnect_degraded_codes = tuple(
            dict.fromkeys((*self.disconnect_degraded_codes, *codes))
        )
        self.restart_required = self.restart_required or restart_required


class ScriptedSocket:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.sent: list[str] = []
        self.closed: list[tuple[int, str]] = []
        self._incoming: asyncio.Queue[str | bytes | BaseException | None] = asyncio.Queue()

    async def send(self, message: str | bytes) -> None:
        self.events.append("send")
        if isinstance(message, bytes):
            message = message.decode("utf-8")
        self.sent.append(message)

    def ping(self, payload: bytes) -> asyncio.Future[None]:
        if type(payload) is not bytes or len(payload) != 8:
            raise AssertionError("heartbeat ping must be exactly eight bytes")
        return asyncio.get_running_loop().create_future()

    async def close(self, *, code: int = 1000, reason: str = "") -> None:
        self.closed.append((code, reason))

    async def push(self, value: str | bytes | BaseException | None) -> None:
        await self._incoming.put(value)

    def __aiter__(self) -> ScriptedSocket:
        return self

    async def __anext__(self) -> str | bytes:
        value = await self._incoming.get()
        if value is None:
            raise StopAsyncIteration
        if isinstance(value, BaseException):
            raise value
        return value


class ResponsiveSocket(ScriptedSocket):
    def __init__(
        self,
        events: list[str],
        *,
        signer: Ed25519PrivateKey,
        response_purpose: FramePurpose,
        response_kind: FrameKind,
        response_payload: bytes = b"{}",
    ) -> None:
        super().__init__(events)
        self._signer = signer
        self._response_purpose = response_purpose
        self._response_kind = response_kind
        self._response_payload = response_payload

    async def send(self, message: str | bytes) -> None:
        await super().send(message)
        frame = parse_contract_json(
            SignedControlFrameV1,
            self.sent[-1].encode("utf-8"),
            max_bytes=MAX_CONTROL_FRAME_JSON_BYTES,
            require_canonical=True,
        )
        response = sign_control_frame(
            self._signer,
            HMAC_ROOT,
            signing_key_id=EDGE_SIGNING_KEY_ID,
            hmac_key_id=HMAC_KEY_ID,
            direction="edge_to_core",
            kind=self._response_kind,
            connection_nonce=CONNECTION_NONCE,
            sequence=1,
            correlation_id=frame.correlation_id,
            purpose=self._response_purpose,
            payload=self._response_payload,
        )
        await self.push(canonical_bytes(response).decode("utf-8"))


class HangingTombstoneState(RecordingState):
    def __init__(self, events: list[str], release: asyncio.Event) -> None:
        super().__init__(events)
        self.release = release
        self.entered = asyncio.Event()

    async def abandon_connection(self, reason: str) -> None:
        self.events.append(f"tombstone:start:{reason}")
        self.entered.set()
        await self.release.wait()
        await super().abandon_connection(reason)


def _core_session(
    *,
    socket: ScriptedSocket,
    state: RecordingState,
    handler: RecordingHandler,
    edge_signer: Ed25519PrivateKey | None = None,
    safety: RecordingSafety | None = None,
    readiness: RecordingReadiness | None = None,
    request_timeout: float = 0.05,
    cleanup_timeout: float = 0.05,
    heartbeat_interval: float = 1.0,
    heartbeat_timeout: float = 0.9,
) -> CoreReachySession:
    core_signer = Ed25519PrivateKey.generate()
    outbound = KeyBundle(
        signer=core_signer,
        hmac_root=HMAC_ROOT,
        signing_key_id=CORE_SIGNING_KEY_ID,
        hmac_key_id=HMAC_KEY_ID,
    )
    inbound = KeyBundle(
        signer=edge_signer or Ed25519PrivateKey.generate(),
        hmac_root=HMAC_ROOT,
        signing_key_id=EDGE_SIGNING_KEY_ID,
        hmac_key_id=HMAC_KEY_ID,
    )
    return CoreReachySession(
        socket=socket,
        connection_nonce=CONNECTION_NONCE,
        outbound_keys=outbound,
        inbound_key_resolver=InboundKeyResolver(inbound),
        tls_peer_sha256=TLS_PEER_SHA256,
        device_id=DEVICE_ID,
        state=state,
        handler=handler,
        safety=safety or RecordingSafety(state.events),
        readiness=readiness or RecordingReadiness(),
        clock=Clock(),
        request_timeout=request_timeout,
        cleanup_timeout=cleanup_timeout,
        heartbeat_interval=heartbeat_interval,
        heartbeat_timeout=heartbeat_timeout,
    )


def _command(kind: str = "state", *, turn_id: UUID | None = None) -> ReachyCommand:
    return ReachyCommand(
        command_id=uuid4(),
        turn_id=turn_id,
        kind=cast(Any, kind),
        state=ReachyState.IDLE if kind == "state" else None,
        media_stream_id=uuid4() if kind == "playback" else None,
        gesture_id="wave" if kind == "gesture" else None,
        expires_at=NOW + timedelta(seconds=2),
    )


def _stop_command(turn_id: UUID | None) -> ReachyCommand:
    return ReachyCommand(
        command_id=uuid4(),
        turn_id=turn_id,
        kind="stop_all",
        state=None,
        media_stream_id=None,
        gesture_id=None,
        expires_at=NOW + timedelta(seconds=2),
    )


class PayloadChannel:
    def __init__(self) -> None:
        self.payloads: list[bytes] = []
        self.requests: list[tuple[str, bytes]] = []

    async def exchange_signed(self, *, purpose: str, payload: bytes) -> bytes:
        self.requests.append((purpose, payload))
        if not self.payloads:
            raise AssertionError("test channel exhausted")
        return self.payloads.pop(0)


@pytest.mark.asyncio
async def test_authenticated_control_client_requires_canonical_bound_command_receipts() -> None:
    command = _command()
    receipt = ReachyReceipt(command_id=command.command_id, accepted=True, reason_code="accepted")
    channel = PayloadChannel()
    channel.payloads.append(canonical_bytes(receipt))

    client = AuthenticatedControlClient(channel)

    assert await client.request_signed(command) == receipt
    assert channel.requests == [("reachy.command.v1", canonical_bytes(command))]

    channel.payloads.append(b" " + canonical_bytes(receipt))
    with pytest.raises(ContractParseError):
        await client.request_signed(command)

    channel.payloads.append(
        canonical_bytes(ReachyReceipt(command_id=uuid4(), accepted=True, reason_code="accepted"))
    )
    with pytest.raises(PermissionError, match="reachy_control_response_binding_mismatch"):
        await client.request_signed(command)


@pytest.mark.asyncio
async def test_authenticated_stop_all_uses_canonical_bundle_and_exact_binding() -> None:
    turn_id = uuid4()
    command = _stop_command(turn_id)
    channel = PayloadChannel()
    receipt = ReachyReceipt(command_id=command.command_id, accepted=True, reason_code="accepted")
    safety = SafetyReceipt(
        turn_id=turn_id,
        playback_stopped=True,
        motion_stopped=True,
        buffers_cleared=True,
    )
    channel.payloads.append(
        canonical_bytes(StopAllReceiptBundleV1(command_receipt=receipt, safety_receipt=safety))
    )

    assert await AuthenticatedControlClient(channel).request_stop_all_signed(command) == (
        receipt,
        safety,
    )
    assert channel.requests == [("reachy.stop_all.v1", canonical_bytes(command))]

    channel.payloads.append(
        canonical_bytes(
            StopAllReceiptBundleV1(
                command_receipt=receipt,
                safety_receipt=safety.model_copy(update={"turn_id": uuid4()}),
            )
        )
    )
    with pytest.raises(PermissionError, match="reachy_stop_response_binding_mismatch"):
        await AuthenticatedControlClient(channel).request_stop_all_signed(command)


class GatewayControl:
    def __init__(self) -> None:
        self.stop_receipts: list[tuple[ReachyReceipt, SafetyReceipt]] = []

    async def request_signed(self, command: ReachyCommand) -> ReachyReceipt:
        return ReachyReceipt(command_id=command.command_id, accepted=True, reason_code="accepted")

    async def request_health_signed(self) -> ReachyHealth:
        return ReachyHealth(state=ReachyState.IDLE, daemon_connected=True, queue_depth=0)

    async def request_stop_all_signed(
        self,
        command: ReachyCommand,
    ) -> tuple[ReachyReceipt, SafetyReceipt]:
        if self.stop_receipts:
            return self.stop_receipts.pop(0)
        return (
            ReachyReceipt(command_id=command.command_id, accepted=True, reason_code="accepted"),
            SafetyReceipt(
                turn_id=command.turn_id,
                playback_stopped=True,
                motion_stopped=True,
                buffers_cleared=True,
            ),
        )


@pytest.mark.asyncio
async def test_gateway_implements_reachy_port_and_returns_exact_receipts() -> None:
    gateway = ReachyGateway(GatewayControl(), Clock())
    turn_id = uuid4()

    assert isinstance(gateway, ReachyPort)
    assert type(await gateway.send(_command())) is ReachyReceipt
    assert await gateway.health() == ReachyHealth(
        state=ReachyState.IDLE,
        daemon_connected=True,
        queue_depth=0,
    )
    assert await gateway.stop_all(turn_id) == SafetyReceipt(
        turn_id=turn_id,
        playback_stopped=True,
        motion_stopped=True,
        buffers_cleared=True,
    )


@pytest.mark.asyncio
async def test_gateway_rejects_private_or_contradictory_stop_receipts() -> None:
    class PrivateSafetyReceipt(SafetyReceipt):
        private_ack: bool = True

    turn_id = uuid4()
    private_control = type(
        "PrivateStopControl",
        (),
        {
            "request_signed": GatewayControl.request_signed,
            "request_health_signed": GatewayControl.request_health_signed,
            "request_stop_all_signed": lambda self, command: _async_return(
                (
                    ReachyReceipt(
                        command_id=command.command_id,
                        accepted=True,
                        reason_code="accepted",
                    ),
                    PrivateSafetyReceipt(
                        turn_id=command.turn_id,
                        playback_stopped=True,
                        motion_stopped=True,
                        buffers_cleared=True,
                    ),
                )
            ),
        },
    )()
    with pytest.raises(RuntimeError, match="reachy_safety_receipt_contract_mismatch"):
        await ReachyGateway(private_control, Clock()).stop_all(turn_id)

    command_id = uuid4()
    control = GatewayControl()
    control.stop_receipts.append(
        (
            ReachyReceipt(command_id=command_id, accepted=True, reason_code="accepted"),
            SafetyReceipt(
                turn_id=turn_id,
                playback_stopped=True,
                motion_stopped=True,
                buffers_cleared=True,
            ),
        )
    )
    with pytest.raises(RuntimeError, match="reachy_receipt_binding_mismatch"):
        await ReachyGateway(control, Clock()).stop_all(turn_id)

    control = GatewayControl()
    control.stop_receipts.append(
        (
            ReachyReceipt(command_id=uuid4(), accepted=True, reason_code="accepted"),
            SafetyReceipt(
                turn_id=turn_id,
                playback_stopped=True,
                motion_stopped=True,
                buffers_cleared=True,
            ),
        )
    )
    with pytest.raises(RuntimeError, match="reachy_receipt_binding_mismatch"):
        await ReachyGateway(control, Clock()).stop_all(turn_id)

    control = type(
        "ContradictoryStopControl",
        (),
        {
            "request_signed": GatewayControl.request_signed,
            "request_health_signed": GatewayControl.request_health_signed,
            "request_stop_all_signed": lambda self, command: _async_return(
                (
                    ReachyReceipt(
                        command_id=command.command_id,
                        accepted=False,
                        reason_code="edge_failed",
                    ),
                    SafetyReceipt(
                        turn_id=command.turn_id,
                        playback_stopped=True,
                        motion_stopped=True,
                        buffers_cleared=True,
                    ),
                )
            ),
        },
    )()
    with pytest.raises(RuntimeError, match="reachy_command_and_safety_receipt_mismatch"):
        await ReachyGateway(control, Clock()).stop_all(turn_id)


async def _async_return(value: object) -> object:
    return value


@pytest.mark.asyncio
async def test_core_session_reserves_durable_sequence_before_send_and_abandons_timeout() -> None:
    events: list[str] = []
    state = RecordingState(events)
    socket = ScriptedSocket(events)
    session = _core_session(socket=socket, state=state, handler=RecordingHandler(events))

    with pytest.raises(TimeoutError):
        await session.exchange_signed(purpose="reachy.health.v1", payload=b'{"request":"health"}')

    assert events[:2] == ["reserve:request:reachy.health.v1", "send"]
    assert state.abandoned == [(state.reserved[0][0], "exchange_failed")]
    assert session.pending_count == 0
    sent = parse_contract_json(
        SignedControlFrameV1,
        socket.sent[0].encode("utf-8"),
        max_bytes=MAX_CONTROL_FRAME_JSON_BYTES,
        require_canonical=True,
    )
    assert sent.sequence == 1
    assert sent.correlation_id == state.reserved[0][0]
    assert sent.purpose == "reachy.health.v1"
    assert sent.kind == "request"


@pytest.mark.asyncio
async def test_core_session_abandons_reserved_correlation_when_signing_setup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    state = RecordingState(events)
    socket = ScriptedSocket(events)
    session = _core_session(socket=socket, state=state, handler=RecordingHandler(events))

    def fail_signing(*_args: object, **_kwargs: object) -> SignedControlFrameV1:
        raise RuntimeError("signing offline")

    monkeypatch.setattr(reachy_session_module, "sign_control_frame", fail_signing)

    with pytest.raises(RuntimeError, match="signing offline"):
        await session.exchange_signed(purpose="reachy.command.v1", payload=b"{}")

    assert socket.sent == []
    assert session.pending_count == 0
    assert state.abandoned == [(state.reserved[0][0], "exchange_failed")]


@pytest.mark.asyncio
async def test_core_session_abandons_reserved_correlation_when_pending_setup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    state = RecordingState(events)
    socket = ScriptedSocket(events)
    session = _core_session(socket=socket, state=state, handler=RecordingHandler(events))

    class FailingLoop:
        def create_future(self) -> asyncio.Future[bytes]:
            raise RuntimeError("future allocation unavailable")

    monkeypatch.setattr(
        reachy_session_module.asyncio,
        "get_running_loop",
        lambda: FailingLoop(),
    )

    with pytest.raises(RuntimeError, match="future allocation unavailable"):
        await session.exchange_signed(purpose="reachy.command.v1", payload=b"{}")

    assert socket.sent == []
    assert session.pending_count == 0
    assert state.abandoned == [(state.reserved[0][0], "exchange_failed")]


@pytest.mark.asyncio
async def test_core_session_freezes_outbound_signing_metadata_at_construction() -> None:
    events: list[str] = []
    original_signer = Ed25519PrivateKey.generate()
    mutated_signer = Ed25519PrivateKey.generate()
    outbound = MutableKeyBundle(
        signer=original_signer,
        hmac_root=HMAC_ROOT,
        signing_key_id=CORE_SIGNING_KEY_ID,
        hmac_key_id=HMAC_KEY_ID,
    )
    inbound = KeyBundle(
        signer=Ed25519PrivateKey.generate(),
        hmac_root=HMAC_ROOT,
        signing_key_id=EDGE_SIGNING_KEY_ID,
        hmac_key_id=HMAC_KEY_ID,
    )
    socket = ScriptedSocket(events)
    state = RecordingState(events)
    session = CoreReachySession(
        socket=socket,
        connection_nonce=CONNECTION_NONCE,
        outbound_keys=outbound,
        inbound_key_resolver=InboundKeyResolver(inbound),
        tls_peer_sha256=TLS_PEER_SHA256,
        device_id=DEVICE_ID,
        state=state,
        handler=RecordingHandler(events),
        safety=RecordingSafety(events),
        readiness=RecordingReadiness(),
        clock=Clock(),
        request_timeout=0.01,
    )
    outbound.signer = mutated_signer
    outbound.hmac_root = b"\xff" * 32
    outbound.signing_key_id = "ed25519:reachy-core:rotated"
    outbound.hmac_key_id = "reachy-frame-hmac:rotated"

    with pytest.raises(TimeoutError):
        await session.exchange_signed(purpose="reachy.command.v1", payload=b"{}")

    sent = parse_contract_json(
        SignedControlFrameV1,
        socket.sent[0].encode("utf-8"),
        max_bytes=MAX_CONTROL_FRAME_JSON_BYTES,
        require_canonical=True,
    )
    assert sent.signing_key_id == CORE_SIGNING_KEY_ID
    assert sent.payload_commitment.key_id == HMAC_KEY_ID
    authenticate_control_frame(
        original_signer.public_key(),
        HMAC_ROOT,
        sent,
        expected_signing_key_id=CORE_SIGNING_KEY_ID,
        expected_hmac_key_id=HMAC_KEY_ID,
        expected_direction="core_to_edge",
        expected_nonce=CONNECTION_NONCE,
    )


@pytest.mark.asyncio
async def test_core_session_snapshots_outbound_signer_from_raw_private_bytes_at_construction() -> (
    None
):
    events: list[str] = []
    original_signer = Ed25519PrivateKey.generate()
    mutated_signer = Ed25519PrivateKey.generate()
    signer = MutableRawEd25519PrivateKey(original_signer)
    outbound = MutableKeyBundle(
        signer=signer,
        hmac_root=HMAC_ROOT,
        signing_key_id=CORE_SIGNING_KEY_ID,
        hmac_key_id=HMAC_KEY_ID,
    )
    inbound = KeyBundle(
        signer=Ed25519PrivateKey.generate(),
        hmac_root=HMAC_ROOT,
        signing_key_id=EDGE_SIGNING_KEY_ID,
        hmac_key_id=HMAC_KEY_ID,
    )
    socket = ScriptedSocket(events)
    state = RecordingState(events)
    session = CoreReachySession(
        socket=socket,
        connection_nonce=CONNECTION_NONCE,
        outbound_keys=outbound,
        inbound_key_resolver=InboundKeyResolver(inbound),
        tls_peer_sha256=TLS_PEER_SHA256,
        device_id=DEVICE_ID,
        state=state,
        handler=RecordingHandler(events),
        safety=RecordingSafety(events),
        readiness=RecordingReadiness(),
        clock=Clock(),
        request_timeout=0.01,
    )
    signer.private_key = mutated_signer

    with pytest.raises(TimeoutError):
        await session.exchange_signed(purpose="reachy.command.v1", payload=b"{}")

    sent = parse_contract_json(
        SignedControlFrameV1,
        socket.sent[0].encode("utf-8"),
        max_bytes=MAX_CONTROL_FRAME_JSON_BYTES,
        require_canonical=True,
    )
    authenticate_control_frame(
        original_signer.public_key(),
        HMAC_ROOT,
        sent,
        expected_signing_key_id=CORE_SIGNING_KEY_ID,
        expected_hmac_key_id=HMAC_KEY_ID,
        expected_direction="core_to_edge",
        expected_nonce=CONNECTION_NONCE,
    )


def test_core_session_rejects_non_exact_outbound_key_material_at_construction() -> None:
    events: list[str] = []
    signer = Ed25519PrivateKey.generate()
    valid = {
        "signer": signer,
        "hmac_root": HMAC_ROOT,
        "signing_key_id": CORE_SIGNING_KEY_ID,
        "hmac_key_id": HMAC_KEY_ID,
    }
    invalid_values: tuple[tuple[str, object], ...] = (
        ("signer", object()),
        ("hmac_root", bytearray(HMAC_ROOT)),
        ("hmac_root", b"x" * 31),
        ("signing_key_id", object()),
        ("hmac_key_id", 123),
    )

    for field, value in invalid_values:
        outbound = MutableKeyBundle(**(valid | {field: value}))  # type: ignore[arg-type]
        with pytest.raises((TypeError, ValueError), match="reachy_outbound_"):
            CoreReachySession(
                socket=ScriptedSocket(events),
                connection_nonce=CONNECTION_NONCE,
                outbound_keys=outbound,
                inbound_key_resolver=InboundKeyResolver(
                    KeyBundle(
                        signer=Ed25519PrivateKey.generate(),
                        hmac_root=HMAC_ROOT,
                        signing_key_id=EDGE_SIGNING_KEY_ID,
                        hmac_key_id=HMAC_KEY_ID,
                    )
                ),
                tls_peer_sha256=TLS_PEER_SHA256,
                device_id=DEVICE_ID,
                state=RecordingState(events),
                handler=RecordingHandler(events),
                safety=RecordingSafety(events),
                readiness=RecordingReadiness(),
                clock=Clock(),
            )


@pytest.mark.asyncio
async def test_core_session_accepts_max_shared_frame_size_before_decoding_or_dispatch() -> None:
    events: list[str] = []
    edge_signer = Ed25519PrivateKey.generate()
    state = RecordingState(events)
    socket = ScriptedSocket(events)
    handler = RecordingHandler(events)
    frame = sign_control_frame(
        edge_signer,
        HMAC_ROOT,
        signing_key_id=EDGE_SIGNING_KEY_ID,
        hmac_key_id=HMAC_KEY_ID,
        direction="edge_to_core",
        kind="request",
        connection_nonce=CONNECTION_NONCE,
        sequence=1,
        correlation_id=uuid4(),
        purpose="reachy.media_control.v1",
        payload=b"x" * MAX_CONTROL_PAYLOAD_BYTES,
    )
    raw = canonical_bytes(frame)
    assert len(raw) <= MAX_CONTROL_FRAME_JSON_BYTES
    await socket.push(raw.decode("utf-8"))
    await socket.push(None)
    session = _core_session(
        socket=socket,
        state=state,
        handler=handler,
        edge_signer=edge_signer,
    )

    with pytest.raises(ConnectionError, match="reachy websocket closed"):
        await session._receive_loop()

    assert events[:5] == [
        "accept:request:reachy.media_control.v1",
        f"control:reachy.media_control.v1:{MAX_CONTROL_PAYLOAD_BYTES}",
        "reserve:response:reachy.media_control.v1",
        "send",
        f"complete:{frame.correlation_id}",
    ]
    assert handler.control_calls == [("reachy.media_control.v1", b"x" * MAX_CONTROL_PAYLOAD_BYTES)]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kind", "purpose", "message"),
    (
        ("event", "reachy.command.v1", "unsupported_inbound_control_frame"),
        ("request", "reachy.event.v1", "unsupported_inbound_control_frame"),
        ("response", "reachy.command.v1", "correlation_not_pending"),
    ),
)
async def test_core_session_rejects_signed_illegal_inbound_kind_purpose_before_state_or_handler(
    kind: FrameKind,
    purpose: FramePurpose,
    message: str,
) -> None:
    events: list[str] = []
    edge_signer = Ed25519PrivateKey.generate()
    state = RecordingState(events)
    socket = ScriptedSocket(events)
    handler = RecordingHandler(events)
    frame = sign_control_frame(
        edge_signer,
        HMAC_ROOT,
        signing_key_id=EDGE_SIGNING_KEY_ID,
        hmac_key_id=HMAC_KEY_ID,
        direction="edge_to_core",
        kind=kind,
        connection_nonce=CONNECTION_NONCE,
        sequence=1,
        correlation_id=uuid4(),
        purpose=purpose,
        payload=b"{}",
    )
    await socket.push(canonical_bytes(frame).decode("utf-8"))
    await socket.push(None)
    session = _core_session(
        socket=socket,
        state=state,
        handler=handler,
        edge_signer=edge_signer,
    )

    with pytest.raises(PermissionError, match=message):
        await session._receive_loop()

    assert state.accepted == []
    assert state.completed == []
    assert handler.control_calls == []
    assert socket.sent == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response_purpose", "response_kind"),
    (("reachy.health.v1", "response"), ("reachy.command.v1", "event")),
)
async def test_core_session_requires_exact_pending_response_purpose_and_kind(
    response_purpose: FramePurpose,
    response_kind: FrameKind,
) -> None:
    events: list[str] = []
    edge_signer = Ed25519PrivateKey.generate()
    state = RecordingState(events)
    socket = ResponsiveSocket(
        events,
        signer=edge_signer,
        response_purpose=response_purpose,
        response_kind=response_kind,
    )
    handler = RecordingHandler(events)
    session = _core_session(
        socket=socket,
        state=state,
        handler=handler,
        edge_signer=edge_signer,
    )
    receiver = asyncio.create_task(session._receive_loop())
    exchange = asyncio.create_task(
        session.exchange_signed(purpose="reachy.command.v1", payload=b"{}")
    )

    with pytest.raises(PermissionError, match="correlation_not_pending"):
        await receiver
    with pytest.raises(TimeoutError):
        await exchange

    assert handler.control_calls == []
    assert state.completed == []
    assert state.abandoned[-1] == (state.reserved[0][0], "exchange_failed")


@pytest.mark.asyncio
async def test_core_disconnect_cleanup_fails_pending_before_safety_and_tombstones() -> None:
    events: list[str] = []
    state = RecordingState(events)
    socket = ScriptedSocket(events)
    readiness = RecordingReadiness()
    safety = RecordingSafety(events, failure="raise")
    session = _core_session(
        socket=socket,
        state=state,
        handler=RecordingHandler(events),
        safety=safety,
        readiness=readiness,
        request_timeout=30,
        cleanup_timeout=0.01,
    )
    safety.pending_count = lambda: session.pending_count
    pending = [
        asyncio.create_task(session.exchange_signed(purpose="reachy.command.v1", payload=b"{}"))
        for _ in range(3)
    ]
    while len(socket.sent) < 3:
        await asyncio.sleep(0)

    failures, cancellations = await session._complete_disconnect_cleanup()

    assert cancellations == 0
    assert tuple(type(error) for error in failures) == (RuntimeError,)
    assert "physical_media_safety:RuntimeError" in session.last_disconnect_failure_codes
    assert safety.latched == [("transport_disconnect", 0)]
    assert session.pending_count == 0
    assert state.abandoned[-1] == (None, "disconnect")
    assert readiness.ready is False
    for task in pending:
        with pytest.raises(ConnectionError, match="reachy disconnected"):
            await task


@pytest.mark.asyncio
async def test_core_serve_failure_cleanup_leaves_socket_close_to_wss_owner_without_leak() -> None:
    events: list[str] = []
    state = RecordingState(events)
    socket = ScriptedSocket(events)
    safety = RecordingSafety(events)
    session = _core_session(
        socket=socket,
        state=state,
        handler=RecordingHandler(events),
        safety=safety,
        heartbeat_interval=10.0,
    )
    runner = asyncio.create_task(session.serve())
    await socket.push(RuntimeError("transport exploded"))

    with pytest.raises(BaseExceptionGroup) as exc_info:
        await runner
    await asyncio.sleep(0)

    assert any(
        isinstance(error, RuntimeError) and str(error) == "transport exploded"
        for error in exc_info.value.exceptions
    )
    assert socket.closed == []
    assert session.pending_count == 0
    assert session._cleanup_background == set()
    assert safety.latched == [("transport_disconnect", 0)]
    assert state.abandoned == [(None, "disconnect")]


@pytest.mark.asyncio
async def test_disconnect_cleanup_defers_cancellation_until_owned_cleanup_finishes() -> None:
    events: list[str] = []
    release = asyncio.Event()
    state = HangingTombstoneState(events, release)
    socket = ScriptedSocket(events)
    session = _core_session(
        socket=socket,
        state=state,
        handler=RecordingHandler(events),
        cleanup_timeout=0.5,
    )
    runner = asyncio.create_task(session._complete_disconnect_cleanup())
    await state.entered.wait()

    for _ in range(3):
        runner.cancel()
        await asyncio.sleep(0)
    assert runner.done() is False

    release.set()
    failures, cancellations = await runner

    assert failures == ()
    assert cancellations >= 3
    assert session.last_disconnect_failure_codes == ()
    await asyncio.sleep(0)
    assert session._cleanup_background == set()


@pytest.mark.asyncio
async def test_core_disconnect_task_factory_failure_uses_fresh_owned_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    state = RecordingState(events)
    socket = ScriptedSocket(events)
    session = _core_session(
        socket=socket,
        state=state,
        handler=RecordingHandler(events),
    )
    original_create_task = asyncio.create_task
    failed = False

    def fail_once(
        coroutine: Any,
        *,
        name: str | None = None,
        context: object | None = None,
    ) -> asyncio.Task[Any]:
        nonlocal failed
        del context
        if name == "core_physical_media_safety" and not failed:
            failed = True
            raise RuntimeError("synthetic task factory failure")
        return original_create_task(cast(Any, coroutine), name=name)

    monkeypatch.setattr(asyncio, "create_task", fail_once)

    failures, cancellations = await session._complete_disconnect_cleanup()

    assert failures == ()
    assert cancellations == 0
    assert "core_physical_media_safety" in session.task_factory_failure_points
    assert events.count("safety:start") == 1
    assert state.abandoned == [(None, "disconnect")]
    await asyncio.sleep(0)
    assert session._cleanup_background == set()


@pytest.mark.asyncio
async def test_core_serve_task_factory_total_failure_withdraws_readiness_and_cleans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    state = RecordingState(events)
    socket = ScriptedSocket(events)
    safety = RecordingSafety(events)
    readiness = RecordingReadiness()
    session = _core_session(
        socket=socket,
        state=state,
        handler=RecordingHandler(events),
        safety=safety,
        readiness=readiness,
    )
    original_direct_task = asyncio.Task

    def taskgroup_create_task_fail(
        self: asyncio.TaskGroup,
        coroutine: Any,
        *,
        name: str | None = None,
        context: object | None = None,
    ) -> asyncio.Task[Any]:
        del self, context
        if name == "core_receive_loop":
            raise RuntimeError("synthetic taskgroup task failure")
        return original_direct_task(cast(Any, coroutine), name=name)

    def direct_task_fail(
        coroutine: Any,
        *,
        loop: asyncio.AbstractEventLoop | None = None,
        name: str | None = None,
        context: object | None = None,
    ) -> asyncio.Task[Any]:
        del loop, context
        if name == "core_receive_loop":
            raise RuntimeError("synthetic direct task failure")
        return original_direct_task(cast(Any, coroutine), name=name)

    monkeypatch.setattr(asyncio.TaskGroup, "create_task", taskgroup_create_task_fail)
    monkeypatch.setattr(reachy_session_module.asyncio, "Task", direct_task_fail)

    with pytest.raises(RuntimeError, match="core_receive_loop:factory_unavailable"):
        await session.serve()

    assert safety.latched[0] == ("transport_task_factory_failure", 0)
    assert safety.latched[-1] == ("transport_disconnect", 0)
    assert readiness.ready is False
    assert "core_receive_loop:factory_unavailable" in readiness.disconnect_degraded_codes
    assert state.abandoned == [(None, "disconnect")]
    await asyncio.sleep(0)
    assert session._cleanup_background == set()


def _grant(root: bytes = HMAC_ROOT) -> CameraWindowGrant:
    draft = CameraWindowGrant(
        grant_id=uuid4(),
        household_id=uuid4(),
        device_id=uuid4(),
        session_id=uuid4(),
        turn_id=uuid4(),
        subject_id=uuid4(),
        action_name="identity.enroll",
        purpose="explicit_enrollment",
        max_frames=20,
        max_frame_bytes=1_000_000,
        max_total_bytes=10_000_000,
        max_frames_per_second=2,
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=10),
        grant_commitment=Commitment(
            algorithm="HMAC-SHA-256",
            key_id="camera-hmac-v1",
            value_b64="A" * 43 + "=",
        ),
    )
    return draft.model_copy(
        update={
            "grant_commitment": commit_private(
                root,
                "camera-hmac-v1",
                "reachy.camera.grant",
                canonical_mapping_bytes(
                    draft.model_dump(mode="python", exclude={"grant_commitment"})
                ),
            )
        }
    )


class SqliteTransaction:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def exec_driver_sql(
        self,
        statement: str,
        parameters: tuple[object, ...] = (),
    ) -> sqlite3.Cursor:
        return self._connection.execute(statement, parameters)


class SqliteUnitOfWork:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._connection: sqlite3.Connection | None = None

    async def __aenter__(self) -> SqliteUnitOfWork:
        self._connection = sqlite3.connect(self._path)
        self._connection.execute("BEGIN IMMEDIATE")
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        del exc_type, exc, traceback
        if self._connection is not None:
            with contextlib.suppress(sqlite3.Error):
                self._connection.rollback()
            self._connection.close()
            self._connection = None

    async def run_sync(self, callback: Callable[[SqliteTransaction], Any]) -> Any:
        if self._connection is None:
            raise RuntimeError("unit of work not entered")
        return callback(SqliteTransaction(self._connection))

    async def commit(self) -> None:
        if self._connection is None:
            raise RuntimeError("unit of work not entered")
        self._connection.commit()

    async def rollback(self) -> None:
        if self._connection is None:
            raise RuntimeError("unit of work not entered")
        self._connection.rollback()


class SqliteUnitOfWorkFactory(Protocol):
    def __call__(self) -> SqliteUnitOfWork: ...


def _camera_claim_factory(tmp_path: Path) -> tuple[SqliteUnitOfWorkFactory, Path]:
    path = tmp_path / "claims.sqlite3"
    with sqlite3.connect(path) as database:
        database.execute(
            "CREATE TABLE idempotency_receipts("
            "id TEXT PRIMARY KEY,"
            "operation TEXT NOT NULL,"
            "scope TEXT NOT NULL,"
            "idempotency_key TEXT NOT NULL,"
            "state TEXT NOT NULL,"
            "first_seen_at TEXT NOT NULL,"
            "last_seen_at TEXT NOT NULL,"
            "expires_at TEXT NOT NULL,"
            "UNIQUE(operation,scope,idempotency_key)"
            ")"
        )

    def factory() -> SqliteUnitOfWork:
        return SqliteUnitOfWork(path)

    return factory, path


@pytest.mark.asyncio
async def test_camera_grant_claim_is_persistent_exact_and_single_use(tmp_path: Path) -> None:
    factory, path = _camera_claim_factory(tmp_path)
    claims = PersistentCameraGrantClaims(factory, Clock())
    grant = _grant()

    assert await claims.claim(grant) is True
    assert await claims.claim(grant) is False
    with sqlite3.connect(path) as database:
        rows = database.execute(
            "SELECT operation,scope,idempotency_key,state,first_seen_at,last_seen_at,expires_at "
            "FROM idempotency_receipts"
        ).fetchall()

    assert rows == [
        (
            "reachy.camera.grant",
            str(grant.device_id),
            str(grant.grant_id),
            "claimed",
            "2026-09-03T12:00:00.000000Z",
            "2026-09-03T12:00:00.000000Z",
            "2026-09-03T12:00:10.000000Z",
        )
    ]
    assert str(grant.subject_id).encode() not in path.read_bytes()


@pytest.mark.asyncio
async def test_reachy_session_validates_camera_grant_before_persistent_claim() -> None:
    grant = _grant()
    claim_calls: list[UUID] = []

    async def claim_once(candidate: CameraWindowGrant) -> bool:
        claim_calls.append(candidate.grant_id)
        return len(claim_calls) == 1

    session = ReachySession(claim_grant=claim_once, hmac_root=HMAC_ROOT, clock=Clock())
    invalid = grant.model_copy(
        update={
            "grant_commitment": grant.grant_commitment.model_copy(
                update={"value_b64": base64.b64encode(b"bad").decode("ascii")}
            )
        }
    )

    with pytest.raises(PermissionError, match="camera_grant_commitment_invalid"):
        await session.grant_camera(invalid)
    assert claim_calls == []

    window = await session.grant_camera(grant)
    assert window.grant.grant_id == grant.grant_id
    with pytest.raises(PermissionError, match="camera_grant_already_used"):
        await session.grant_camera(grant)


@pytest.mark.asyncio
async def test_reachy_session_does_not_install_camera_after_privacy_during_claim() -> None:
    grant = _grant()
    claim_entered = asyncio.Event()
    release_claim = asyncio.Event()

    async def claim_after_privacy(candidate: CameraWindowGrant) -> bool:
        assert candidate.grant_id == grant.grant_id
        claim_entered.set()
        await release_claim.wait()
        return True

    session = ReachySession(
        claim_grant=claim_after_privacy,
        hmac_root=HMAC_ROOT,
        clock=Clock(),
    )
    task = asyncio.create_task(session.grant_camera(grant))
    await claim_entered.wait()

    session.on_privacy()
    release_claim.set()

    with pytest.raises(PermissionError, match="camera_grant_window_invalidated"):
        await task
    assert session.active_camera is None


@pytest.mark.asyncio
async def test_reachy_session_later_accepted_camera_grant_wins_over_delayed_older_claim() -> None:
    older = _grant()
    newer = _grant()
    older_claim_entered = asyncio.Event()
    release_older_claim = asyncio.Event()

    async def claim_with_delayed_older(candidate: CameraWindowGrant) -> bool:
        if candidate.grant_id == older.grant_id:
            older_claim_entered.set()
            await release_older_claim.wait()
        return True

    session = ReachySession(
        claim_grant=claim_with_delayed_older,
        hmac_root=HMAC_ROOT,
        clock=Clock(),
    )
    older_task = asyncio.create_task(session.grant_camera(older))
    await older_claim_entered.wait()

    newer_window = await session.grant_camera(newer)
    assert session.active_camera is newer_window
    assert newer_window.grant.grant_id == newer.grant_id

    release_older_claim.set()
    with pytest.raises(PermissionError, match="camera_grant_window_invalidated"):
        await older_task

    assert session.active_camera is newer_window
    assert newer_window.closed is False


def test_reachy_transport_supervisor_state_deduplicates_degradation_and_restart() -> None:
    state = ReachyTransportSupervisorState()

    state.latch_disconnect_degraded(("physical_media_safety:RuntimeError",))
    state.latch_disconnect_degraded(
        ("physical_media_safety:RuntimeError", "correlation_tombstone:timeout"),
        restart_required=True,
    )

    assert state.ready is False
    assert state.disconnect_degraded_codes == (
        "physical_media_safety:RuntimeError",
        "correlation_tombstone:timeout",
    )
    assert state.restart_required is True
