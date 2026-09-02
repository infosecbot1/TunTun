from __future__ import annotations

import asyncio
import contextlib
import math
from collections import deque
from collections.abc import Callable, Coroutine
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import datetime
from threading import Lock
from typing import Any, Protocol, TypeVar, get_args
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from tuntun_contracts.base import canonical_bytes, parse_contract_json
from tuntun_contracts.reachy import CameraWindowGrant
from tuntun_contracts.reachy_media import MAX_CAMERA_PAYLOAD, MAX_HEADER, PREFIX, CameraWindow
from tuntun_contracts.reachy_wire import (
    MAX_CONTROL_FRAME_JSON_BYTES,
    MAX_CONTROL_PAYLOAD_BYTES,
    FrameKind,
    FramePurpose,
    SignedControlFrameV1,
    authenticate_control_frame,
    decode_control_payload,
    sign_control_frame,
)
from tuntun_core.services.storage_time import utc_storage
from tuntun_core.services.transactions.protocols import AsyncUnitOfWorkProtocol, UnitOfWorkProtocol

MAX_REQUEST_TIMEOUT_SECONDS = 30.0
MAX_HEARTBEAT_SECONDS = 60.0
MAX_SOCKET_CLOSE_SECONDS = 2.0
MAX_MEDIA_FRAME_BYTES = PREFIX.size + MAX_HEADER + MAX_CAMERA_PAYLOAD
CAMERA_CLAIM_OPERATION = "reachy.camera.grant"
_CleanupResult = TypeVar("_CleanupResult")
_PURPOSES: frozenset[str] = frozenset(get_args(FramePurpose))
_KINDS: frozenset[str] = frozenset(get_args(FrameKind))
_INBOUND_REQUEST_PURPOSES: frozenset[FramePurpose] = frozenset({"reachy.media_control.v1"})
_INBOUND_EVENT_PURPOSES: frozenset[FramePurpose] = frozenset({"reachy.event.v1"})


class Clock(Protocol):
    def now(self) -> datetime: ...


class OutboundKeys(Protocol):
    @property
    def signer(self) -> Ed25519PrivateKey: ...

    @property
    def signing_key_id(self) -> str: ...

    @property
    def hmac_root(self) -> bytes: ...

    @property
    def hmac_key_id(self) -> str: ...


class InboundKeys(Protocol):
    @property
    def public_key(self) -> Any: ...

    @property
    def signing_key_id(self) -> str: ...

    @property
    def hmac_root(self) -> bytes: ...

    @property
    def hmac_key_id(self) -> str: ...


class InboundKeyResolver(Protocol):
    async def resolve_inbound(
        self,
        *,
        device_id: UUID,
        tls_peer_sha256: str,
        signing_key_id: str,
        hmac_key_id: str,
        now: datetime,
    ) -> InboundKeys: ...


class DuplexState(Protocol):
    async def reserve_outbound(
        self,
        correlation_id: UUID,
        purpose: FramePurpose,
        kind: FrameKind,
    ) -> int: ...

    async def accept_inbound(
        self,
        sequence: int,
        correlation_id: UUID,
        purpose: FramePurpose,
        kind: FrameKind,
    ) -> None: ...

    async def accept_response(
        self,
        correlation_id: UUID,
        purpose: FramePurpose,
        payload: bytes,
    ) -> None: ...

    async def complete(self, correlation_id: UUID) -> None: ...

    async def abandon_correlation(self, correlation_id: UUID, reason: str) -> None: ...

    async def abandon_connection(self, reason: str) -> None: ...


class ControlHandler(Protocol):
    async def control(self, purpose: FramePurpose, payload: bytes) -> bytes: ...

    async def media(self, frame: bytes) -> None: ...


class DisconnectSafety(Protocol):
    def latch_error_safe(self, reason: str) -> None: ...

    async def close_media_stop_playback_motion_and_forget_turn(self) -> None: ...


class TransportReadiness(Protocol):
    def latch_disconnect_degraded(
        self,
        codes: tuple[str, ...],
        *,
        restart_required: bool = False,
    ) -> None: ...


class WebSocketLike(Protocol):
    async def send(self, message: str | bytes) -> None: ...

    async def close(self, *, code: int = 1000, reason: str = "") -> None: ...

    def ping(self, payload: bytes) -> Any: ...

    def __aiter__(self) -> Any: ...


class UnitOfWorkFactory(Protocol):
    def __call__(self) -> AbstractAsyncContextManager[AsyncUnitOfWorkProtocol]: ...


@dataclass(frozen=True, slots=True)
class _PendingExchange:
    purpose: FramePurpose
    expected_kind: FrameKind
    future: asyncio.Future[bytes]


class ReachyTransportSupervisorState:
    """Shared synchronous readiness latch observed by the process supervisor."""

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
        if codes:
            self.disconnect_degraded_codes = tuple(
                dict.fromkeys((*self.disconnect_degraded_codes, *codes))
            )
        self.restart_required = self.restart_required or restart_required


class PersistentCameraGrantClaims:
    def __init__(self, uow_factory: UnitOfWorkFactory, clock: Clock) -> None:
        self._uow_factory = uow_factory
        self._clock = clock

    async def claim(self, grant: CameraWindowGrant) -> bool:
        if type(grant) is not CameraWindowGrant:
            raise TypeError("camera grant must be exactly CameraWindowGrant")
        observed = self._clock.now()
        now = utc_storage(observed)
        expires_at = utc_storage(grant.expires_at)

        def insert_claim(transaction: UnitOfWorkProtocol) -> int:
            rowcount = transaction.exec_driver_sql(
                "INSERT INTO idempotency_receipts("
                "id,operation,scope,idempotency_key,state,"
                "first_seen_at,last_seen_at,expires_at"
                ") VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(operation,scope,idempotency_key) DO NOTHING",
                (
                    str(uuid4()),
                    CAMERA_CLAIM_OPERATION,
                    str(grant.device_id),
                    str(grant.grant_id),
                    "claimed",
                    now,
                    now,
                    expires_at,
                ),
            ).rowcount
            if type(rowcount) is not int:
                raise RuntimeError("camera_grant_claim_rowcount_unavailable")
            return rowcount

        async with self._uow_factory() as uow:
            inserted = await uow.run_sync(insert_claim)
            if inserted == 1:
                await uow.commit()
                return True
            await uow.rollback()
            return False


class ReachySession:
    def __init__(
        self,
        *,
        claim_grant: Callable[[CameraWindowGrant], Any],
        hmac_root: bytes,
        clock: Clock,
    ) -> None:
        self._camera: CameraWindow | None = None
        self._claim_grant = claim_grant
        self._hmac_root = hmac_root
        self._clock = clock
        self._camera_install_lock = asyncio.Lock()
        self._camera_generation = 0
        self._camera_grant_ticket = 0
        self._camera_installed_ticket = 0

    @property
    def active_camera(self) -> CameraWindow | None:
        return self._camera

    async def grant_camera(self, grant: CameraWindowGrant) -> CameraWindow:
        async with self._camera_install_lock:
            self._camera_grant_ticket += 1
            grant_ticket = self._camera_grant_ticket
            generation = self._camera_generation
        window = CameraWindow.open(grant, self._hmac_root, self._clock.now())
        claimed = await self._claim_grant(grant)
        if type(claimed) is not bool:
            window.close("cancel")
            raise TypeError("camera grant claim result must be a bool")
        if not claimed:
            window.close("cancel")
            raise PermissionError("camera_grant_already_used")
        async with self._camera_install_lock:
            if (
                self._camera_generation != generation
                or grant_ticket < self._camera_installed_ticket
            ):
                window.close("cancel")
                raise PermissionError("camera_grant_window_invalidated")
            self._close_camera("cancel", invalidate=False)
            self._camera = window
            self._camera_installed_ticket = grant_ticket
            return window

    def close_camera(self, reason: str) -> None:
        self._close_camera(reason, invalidate=True)

    def _close_camera(self, reason: str, *, invalidate: bool) -> None:
        if invalidate:
            self._camera_generation += 1
        camera = self._camera
        self._camera = None
        if camera is not None and not camera.closed:
            camera.close(reason)

    def on_privacy(self) -> None:
        self.close_camera("privacy")

    def on_cancel(self) -> None:
        self.close_camera("cancel")

    def on_identity_complete(self) -> None:
        self.close_camera("identity_completion")

    def on_expiry(self) -> None:
        self.close_camera("expiry")

    def on_disconnect(self) -> None:
        self.close_camera("disconnect")


class PriorityControlQueues:
    def __init__(
        self,
        *,
        safety_max: int = 16,
        control_max: int = 64,
        media_max: int = 50,
        max_frame_bytes: int | None = None,
        max_control_frame_bytes: int = MAX_CONTROL_FRAME_JSON_BYTES,
        max_media_frame_bytes: int = MAX_MEDIA_FRAME_BYTES,
    ) -> None:
        self._safety_max = _positive_int(safety_max, "safety queue bound")
        self._control_max = _positive_int(control_max, "control queue bound")
        self._media_max = _positive_int(media_max, "media queue bound")
        if max_frame_bytes is not None:
            max_control_frame_bytes = max_frame_bytes
            max_media_frame_bytes = max_frame_bytes
        self._max_control_frame_bytes = _positive_int(
            max_control_frame_bytes,
            "control queue frame byte bound",
        )
        self._max_media_frame_bytes = _positive_int(
            max_media_frame_bytes,
            "media queue frame byte bound",
        )
        self._lock = Lock()
        self._available = asyncio.Event()
        self._safety: deque[bytes] = deque()
        self._control: deque[bytes] = deque()
        self._media: deque[bytes] = deque()

    @property
    def depths(self) -> dict[str, int]:
        with self._lock:
            return {
                "safety": len(self._safety),
                "control": len(self._control),
                "media": len(self._media),
            }

    def put_safety_nowait(self, frame: bytes) -> bool:
        self._put_strict(self._safety, self._safety_max, frame)
        return True

    def put_control_nowait(self, frame: bytes) -> bool:
        self._put_strict(self._control, self._control_max, frame)
        return True

    def put_media_nowait(self, frame: bytes) -> bool:
        checked = self._require_frame(frame, max_bytes=self._max_media_frame_bytes)
        with self._lock:
            if len(self._media) >= self._media_max:
                self._media.popleft()
            self._media.append(checked)
            self._available.set()
        return True

    async def get(self) -> tuple[str, bytes]:
        while True:
            with self._lock:
                for name, queue in (
                    ("safety", self._safety),
                    ("control", self._control),
                    ("media", self._media),
                ):
                    if queue:
                        item = queue.popleft()
                        if not self._safety and not self._control and not self._media:
                            self._available.clear()
                        return name, item
                self._available.clear()
            await self._available.wait()

    def _put_strict(self, queue: deque[bytes], limit: int, frame: bytes) -> None:
        checked = self._require_frame(frame, max_bytes=self._max_control_frame_bytes)
        with self._lock:
            if len(queue) >= limit:
                raise asyncio.QueueFull
            queue.append(checked)
            self._available.set()

    def _require_frame(self, frame: bytes, *, max_bytes: int) -> bytes:
        if type(frame) is not bytes:
            raise TypeError("queued frame must be bytes")
        if not 1 <= len(frame) <= max_bytes:
            raise ValueError("queued frame outside byte bound")
        return bytes(frame)


class _TaskGroupCreateTaskFailure(RuntimeError):
    def __init__(self, task_name: str) -> None:
        super().__init__(f"{task_name}:taskgroup_factory_unavailable")
        self.task_name = task_name


class CoreReachySession:
    def __init__(
        self,
        *,
        socket: WebSocketLike,
        connection_nonce: bytes,
        outbound_keys: OutboundKeys,
        inbound_key_resolver: InboundKeyResolver,
        tls_peer_sha256: str,
        device_id: UUID,
        state: DuplexState,
        handler: ControlHandler,
        safety: DisconnectSafety,
        readiness: TransportReadiness,
        clock: Clock,
        request_timeout: float = 2.0,
        cleanup_timeout: float = 0.250,
        heartbeat_interval: float = 1.0,
        heartbeat_timeout: float = 0.9,
        socket_close_timeout: float = 2.0,
    ) -> None:
        if type(connection_nonce) is not bytes or len(connection_nonce) != 32:
            raise ValueError("connection_nonce_or_sequence")
        if type(device_id) is not UUID:
            raise TypeError("device_id must be an exact UUID")
        self._socket = socket
        self._nonce = bytes(connection_nonce)
        self._outbound_signer = _snapshot_outbound_signer(outbound_keys.signer)
        self._outbound_hmac_root = _require_exact_hmac_root(
            outbound_keys.hmac_root,
            "reachy_outbound_hmac_root_invalid",
        )
        self._outbound_signing_key_id = _require_exact_key_id(
            outbound_keys.signing_key_id,
            "reachy_outbound_signing_key_id_invalid",
        )
        self._outbound_hmac_key_id = _require_exact_key_id(
            outbound_keys.hmac_key_id,
            "reachy_outbound_hmac_key_id_invalid",
        )
        self._inbound_keys = inbound_key_resolver
        self._tls_peer_sha256 = tls_peer_sha256
        self._device_id = device_id
        self._state = state
        self._handler = handler
        self._safety = safety
        self._readiness = readiness
        self._clock = clock
        self._request_timeout = _bounded_positive_float(
            request_timeout,
            "request_timeout",
            MAX_REQUEST_TIMEOUT_SECONDS,
        )
        self._cleanup_timeout = _bounded_positive_float(
            cleanup_timeout,
            "cleanup_timeout",
            MAX_SOCKET_CLOSE_SECONDS,
        )
        self._heartbeat_interval = _bounded_positive_float(
            heartbeat_interval,
            "heartbeat_interval",
            MAX_HEARTBEAT_SECONDS,
        )
        self._heartbeat_timeout = _bounded_positive_float(
            heartbeat_timeout,
            "heartbeat_timeout",
            self._heartbeat_interval,
        )
        self._socket_close_timeout = _bounded_positive_float(
            socket_close_timeout,
            "socket_close_timeout",
            MAX_SOCKET_CLOSE_SECONDS,
        )
        self._pending: dict[UUID, _PendingExchange] = {}
        self._cleanup_background: set[asyncio.Task[Any]] = set()
        self.last_disconnect_failure_codes: tuple[str, ...] = ()
        self.task_factory_failure_points: tuple[str, ...] = ()

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    async def exchange_signed(self, *, purpose: FramePurpose, payload: bytes) -> bytes:
        _require_purpose(purpose)
        _require_payload_bytes(payload)
        correlation_id = uuid4()
        sequence = await self._state.reserve_outbound(correlation_id, purpose, "request")
        try:
            frame = sign_control_frame(
                self._outbound_signer,
                self._outbound_hmac_root,
                signing_key_id=self._outbound_signing_key_id,
                hmac_key_id=self._outbound_hmac_key_id,
                direction="core_to_edge",
                kind="request",
                connection_nonce=self._nonce,
                sequence=sequence,
                correlation_id=correlation_id,
                purpose=purpose,
                payload=payload,
            )
            future: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()
            self._pending[correlation_id] = _PendingExchange(
                purpose=purpose,
                expected_kind="response",
                future=future,
            )
            await self._socket.send(canonical_bytes(frame).decode("utf-8"))
            return await asyncio.wait_for(future, timeout=self._request_timeout)
        except BaseException:
            with contextlib.suppress(BaseException):
                await self._state.abandon_correlation(correlation_id, "exchange_failed")
            raise
        finally:
            self._pending.pop(correlation_id, None)

    async def _receive_loop(self) -> None:
        async for raw in self._socket:
            if isinstance(raw, bytes):
                await self._handler.media(raw)
                continue
            if type(raw) is not str:
                raise PermissionError("reachy_control_frame_text_required")
            frame = parse_contract_json(
                SignedControlFrameV1,
                raw.encode("utf-8"),
                max_bytes=MAX_CONTROL_FRAME_JSON_BYTES,
                require_canonical=True,
            )
            keys = await self._inbound_keys.resolve_inbound(
                device_id=self._device_id,
                tls_peer_sha256=self._tls_peer_sha256,
                signing_key_id=frame.signing_key_id,
                hmac_key_id=frame.payload_commitment.key_id,
                now=self._clock.now(),
            )
            authenticate_control_frame(
                keys.public_key,
                keys.hmac_root,
                frame,
                expected_signing_key_id=keys.signing_key_id,
                expected_hmac_key_id=keys.hmac_key_id,
                expected_direction="edge_to_core",
                expected_nonce=self._nonce,
            )
            self._require_legal_inbound(frame)
            await self._state.accept_inbound(
                frame.sequence,
                frame.correlation_id,
                frame.purpose,
                frame.kind,
            )
            payload = decode_control_payload(frame)
            if frame.kind == "response":
                await self._handle_response(frame, payload)
                continue
            response = await self._handler.control(frame.purpose, payload)
            if frame.kind == "request":
                await self._send_response(frame, response)
            await self._state.complete(frame.correlation_id)
        raise ConnectionError("reachy websocket closed")

    def _require_legal_inbound(self, frame: SignedControlFrameV1) -> None:
        if frame.kind == "response":
            pending = self._pending.get(frame.correlation_id)
            if (
                pending is None
                or pending.purpose != frame.purpose
                or pending.expected_kind != frame.kind
            ):
                raise PermissionError("correlation_not_pending")
            return
        if frame.correlation_id in self._pending:
            raise PermissionError("correlation_not_pending")
        if frame.kind == "request" and frame.purpose in _INBOUND_REQUEST_PURPOSES:
            return
        if frame.kind == "event" and frame.purpose in _INBOUND_EVENT_PURPOSES:
            return
        raise PermissionError("unsupported_inbound_control_frame")

    async def _handle_response(self, frame: SignedControlFrameV1, payload: bytes) -> None:
        pending = self._pending.get(frame.correlation_id)
        if (
            pending is None
            or pending.purpose != frame.purpose
            or pending.expected_kind != frame.kind
        ):
            raise PermissionError("correlation_not_pending")
        await self._state.accept_response(frame.correlation_id, frame.purpose, payload)
        await self._state.complete(frame.correlation_id)
        if not pending.future.done():
            pending.future.set_result(payload)

    async def _send_response(self, frame: SignedControlFrameV1, response: bytes) -> None:
        _require_payload_bytes(response)
        sequence = await self._state.reserve_outbound(
            frame.correlation_id,
            frame.purpose,
            "response",
        )
        reply = sign_control_frame(
            self._outbound_signer,
            self._outbound_hmac_root,
            signing_key_id=self._outbound_signing_key_id,
            hmac_key_id=self._outbound_hmac_key_id,
            direction="core_to_edge",
            kind="response",
            connection_nonce=self._nonce,
            sequence=sequence,
            correlation_id=frame.correlation_id,
            purpose=frame.purpose,
            payload=response,
        )
        await self._socket.send(canonical_bytes(reply).decode("utf-8"))

    async def _heartbeat_loop(self) -> None:
        misses = 0
        loop = asyncio.get_running_loop()
        deadline = loop.time()
        while True:
            deadline += self._heartbeat_interval
            await asyncio.sleep(max(0.0, deadline - loop.time()))
            pong = self._socket.ping(uuid4().bytes[:8])
            try:
                await asyncio.wait_for(pong, timeout=self._heartbeat_timeout)
                misses = 0
            except TimeoutError as error:
                misses += 1
                if misses >= 2:
                    await _close_bounded_suppressing_errors(
                        self._socket,
                        code=1011,
                        reason="heartbeat_lost",
                        timeout=self._socket_close_timeout,
                    )
                    raise ConnectionError("two consecutive heartbeats missed") from error

    async def serve(self) -> None:
        primary: BaseException | None = None
        try:
            try:
                await self._serve_with_task_group()
            except _TaskGroupCreateTaskFailure:
                await self._serve_with_direct_tasks()
        except BaseException as error:
            primary = error
        if primary is not None and _is_runtime_task_factory_unavailable(primary):
            self._withdraw_readiness_for_runtime_task_factory(primary)
        # The WSS adapter owns the close handshake for ordinary transport failure.
        # Core only forces a bounded close on heartbeat loss, then always performs
        # local fail-pending/safety/tombstone cleanup so session state cannot leak.
        failures, cancellations = await self._complete_disconnect_cleanup()
        if isinstance(primary, asyncio.CancelledError) or cancellations:
            raise asyncio.CancelledError
        if primary is not None:
            raise primary
        if failures:
            raise RuntimeError("reachy_disconnect_cleanup_degraded") from BaseExceptionGroup(
                "reachy disconnect cleanup effects degraded",
                list(failures),
            )

    async def _serve_with_task_group(self) -> None:
        try:
            async with asyncio.TaskGroup() as tasks:
                self._task_group_create_task(tasks, self._receive_loop, name="core_receive_loop")
                self._task_group_create_task(
                    tasks,
                    self._heartbeat_loop,
                    name="core_heartbeat_loop",
                )
        except* _TaskGroupCreateTaskFailure as group:
            failure = group.exceptions[0]
            if type(failure) is _TaskGroupCreateTaskFailure:
                raise failure from None
            raise

    def _task_group_create_task(
        self,
        tasks: asyncio.TaskGroup,
        factory: Callable[[], Coroutine[Any, Any, Any]],
        *,
        name: str,
    ) -> None:
        coroutine = factory()
        try:
            tasks.create_task(coroutine, name=name)
        except BaseException as error:
            self.task_factory_failure_points = tuple(
                dict.fromkeys((*self.task_factory_failure_points, name))
            )
            with contextlib.suppress(BaseException):
                coroutine.close()
            raise _TaskGroupCreateTaskFailure(name) from error

    async def _serve_with_direct_tasks(self) -> None:
        tasks: list[asyncio.Task[Any]] = []
        try:
            tasks.append(
                self._spawn_direct_runtime_task(self._receive_loop, name="core_receive_loop")
            )
            tasks.append(
                self._spawn_direct_runtime_task(self._heartbeat_loop, name="core_heartbeat_loop")
            )
            done, pending = await asyncio.wait(set(tasks), return_when=asyncio.FIRST_EXCEPTION)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                task.result()
        except BaseException:
            for task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            raise

    def _spawn_direct_runtime_task(
        self,
        factory: Callable[[], Coroutine[Any, Any, Any]],
        *,
        name: str,
    ) -> asyncio.Task[Any]:
        coroutine = factory()
        try:
            return asyncio.Task(coroutine, loop=asyncio.get_running_loop(), name=name)
        except BaseException as error:
            self.task_factory_failure_points = tuple(
                dict.fromkeys((*self.task_factory_failure_points, name))
            )
            with contextlib.suppress(BaseException):
                coroutine.close()
            raise RuntimeError(f"{name}:factory_unavailable") from error

    def _withdraw_readiness_for_runtime_task_factory(self, primary: BaseException) -> None:
        code = str(primary)
        with contextlib.suppress(BaseException):
            self._readiness.latch_disconnect_degraded((code,), restart_required=True)
        try:
            self._safety.latch_error_safe("transport_task_factory_failure")
        except BaseException as error:
            with contextlib.suppress(BaseException):
                self._readiness.latch_disconnect_degraded(
                    (f"runtime_task_factory_latch:{type(error).__name__}",),
                    restart_required=True,
                )

    def _retain_cleanup(self, task: asyncio.Task[Any]) -> None:
        self._cleanup_background.add(task)

        def observed(completed: asyncio.Task[Any]) -> None:
            self._cleanup_background.discard(completed)
            with contextlib.suppress(BaseException):
                completed.result()

        task.add_done_callback(observed)

    def _spawn_cleanup_owned(
        self,
        factory: Callable[[], Coroutine[Any, Any, _CleanupResult]],
        *,
        name: str,
    ) -> asyncio.Task[_CleanupResult]:
        coroutine = factory()
        try:
            return asyncio.create_task(coroutine, name=name)
        except BaseException:
            self.task_factory_failure_points = tuple(
                dict.fromkeys((*self.task_factory_failure_points, name))
            )
            with contextlib.suppress(BaseException):
                coroutine.close()
            fallback = factory()
            try:
                return asyncio.Task(fallback, loop=asyncio.get_running_loop(), name=name)
            except BaseException:
                with contextlib.suppress(BaseException):
                    fallback.close()
                raise

    def _prepare_disconnect_synchronously(self) -> tuple[BaseException, ...]:
        failures: list[BaseException] = []
        for pending in tuple(self._pending.values()):
            if pending.future.done():
                continue
            try:
                pending.future.set_exception(ConnectionError("reachy disconnected"))
            except BaseException as error:
                failures.append(RuntimeError(f"pending_future_failure:{type(error).__name__}"))
                with contextlib.suppress(BaseException):
                    pending.future.cancel()
        self._pending.clear()
        try:
            self._safety.latch_error_safe("transport_disconnect")
        except BaseException as error:
            failures.append(RuntimeError(f"local_error_safe_latch:{type(error).__name__}"))
        if failures:
            self._readiness.latch_disconnect_degraded(
                tuple(str(item) for item in failures),
                restart_required=True,
            )
        return tuple(failures)

    async def _disconnect_cleanup_once(self) -> tuple[BaseException, ...]:
        operations: dict[str, asyncio.Task[Any]] = {}
        failures: list[BaseException] = []
        for name, factory in (
            (
                "physical_media_safety",
                self._safety.close_media_stop_playback_motion_and_forget_turn,
            ),
            ("correlation_tombstone", lambda: self._state.abandon_connection("disconnect")),
        ):
            try:
                cleanup_task = self._spawn_cleanup_owned(factory, name=f"core_{name}")
            except BaseException:
                failures.append(RuntimeError(f"{name}:factory_unavailable"))
                self._readiness.latch_disconnect_degraded(
                    (f"{name}:factory_unavailable",),
                    restart_required=True,
                )
            else:
                operations[name] = cleanup_task
                self._retain_cleanup(cleanup_task)
        done: set[asyncio.Task[Any]] = set()
        pending: set[asyncio.Task[Any]] = set()
        if operations:
            done, pending = await asyncio.wait(
                set(operations.values()),
                timeout=self._cleanup_timeout,
            )
        for pending_task in pending:
            pending_task.cancel()
            self._retain_cleanup(pending_task)
        for name, operation_task in operations.items():
            if operation_task not in done:
                failures.append(RuntimeError(f"{name}:timeout"))
                continue
            try:
                operation_task.result()
            except BaseException as error:
                failures.append(RuntimeError(f"{name}:{type(error).__name__}"))
        self.last_disconnect_failure_codes = tuple(str(error) for error in failures)
        if failures:
            self._readiness.latch_disconnect_degraded(self.last_disconnect_failure_codes)
        return tuple(failures)

    async def _complete_disconnect_cleanup(self) -> tuple[tuple[BaseException, ...], int]:
        preparation_failures = self._prepare_disconnect_synchronously()
        try:
            owned = self._spawn_cleanup_owned(
                self._disconnect_cleanup_once,
                name="core_outer_cleanup",
            )
        except BaseException:
            failure = RuntimeError("disconnect_cleanup_owner:factory_unavailable")
            failures = (*preparation_failures, failure)
            self.last_disconnect_failure_codes = tuple(str(item) for item in failures)
            self._readiness.latch_disconnect_degraded(
                self.last_disconnect_failure_codes,
                restart_required=True,
            )
            return failures, 0
        self._retain_cleanup(owned)
        cancellations = 0
        while not owned.done():
            try:
                await asyncio.shield(owned)
            except asyncio.CancelledError:
                cancellations += 1
        try:
            cleanup_failures = owned.result()
        except BaseException as error:
            cleanup_failures = (RuntimeError(f"disconnect_cleanup_owner:{type(error).__name__}"),)
            self._readiness.latch_disconnect_degraded(
                tuple(str(item) for item in cleanup_failures),
                restart_required=True,
            )
        failures = (*preparation_failures, *cleanup_failures)
        self.last_disconnect_failure_codes = tuple(str(item) for item in failures)
        if failures:
            self._readiness.latch_disconnect_degraded(self.last_disconnect_failure_codes)
        return failures, cancellations


def _snapshot_outbound_signer(value: object) -> Ed25519PrivateKey:
    if not isinstance(value, Ed25519PrivateKey):
        raise TypeError("reachy_outbound_ed25519_signer_required")
    try:
        raw_private = value.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    except (TypeError, ValueError) as error:
        raise TypeError("reachy_outbound_ed25519_signer_required") from error
    if type(raw_private) is not bytes or len(raw_private) != 32:
        raise TypeError("reachy_outbound_ed25519_signer_required")
    return Ed25519PrivateKey.from_private_bytes(raw_private)


def _require_exact_hmac_root(value: object, error: str) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise ValueError(error)
    return bytes(value)


def _require_exact_key_id(value: object, error: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(error)
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exception:
        raise ValueError(error) from exception
    return value


def _is_runtime_task_factory_unavailable(error: BaseException) -> bool:
    return type(error) is RuntimeError and str(error).endswith(":factory_unavailable")


def _require_purpose(value: str) -> None:
    if type(value) is not str or value not in _PURPOSES:
        raise ValueError("unsupported control frame purpose")


def _require_payload_bytes(value: bytes) -> None:
    if type(value) is not bytes:
        raise TypeError("control frame payload must be bytes")
    if len(value) > MAX_CONTROL_PAYLOAD_BYTES:
        raise ValueError("control frame payload too large")


def _positive_int(value: int, label: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{label} positive required")
    return value


def _bounded_positive_float(value: float, label: str, maximum: float) -> float:
    if type(value) not in {int, float} or not math.isfinite(value) or value <= 0 or value > maximum:
        raise ValueError(f"{label}_positive_required")
    return float(value)


async def _close_bounded_suppressing_errors(
    socket: WebSocketLike,
    *,
    code: int,
    reason: str,
    timeout: float,
) -> None:
    try:
        await asyncio.wait_for(socket.close(code=code, reason=reason), timeout=timeout)
    except asyncio.CancelledError:
        raise
    except BaseException:
        pass


__all__ = (
    "CAMERA_CLAIM_OPERATION",
    "CoreReachySession",
    "DisconnectSafety",
    "PersistentCameraGrantClaims",
    "PriorityControlQueues",
    "ReachySession",
    "ReachyTransportSupervisorState",
)
