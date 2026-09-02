from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import importlib
import math
import secrets
from collections.abc import Awaitable, Callable, Coroutine
from dataclasses import dataclass
from typing import Any, Final, Protocol, cast
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tuntun_contracts.base import canonical_bytes, canonical_mapping_bytes, parse_contract_json
from tuntun_contracts.reachy_time import CoreTimeRequestV1
from tuntun_contracts.reachy_wire import (
    ChallengeAcceptedV1,
    DeviceChallengeV1,
    DeviceProofV1,
)
from tuntun_core.adapters.reachy.tls import require_client_certificate_sha256

APP_PATH = "/v1/reachy"
APP_SUBPROTOCOL = "tuntun.reachy.v1"
TIME_PATH = "/v1/reachy/time"
TIME_SUBPROTOCOL = "tuntun.reachy.time.v1"
MAX_WSS_MESSAGE_BYTES = 1_052_684
MAX_SOCKET_CLOSE_SECONDS = 2.0
DEVICE_PROOF_SCHEMA: Final = "tuntun.reachy-device-proof.v1"
CHALLENGE_ACCEPTED_SCHEMA: Final = "tuntun.reachy-challenge-accepted.v1"
HANDSHAKE_SIGNATURE_PAYLOAD_SCHEMA: Final = "tuntun.reachy-device-challenge-signing-payload.v1"
HANDSHAKE_SIGNATURE_DOMAIN: Final = "tuntun.reachy.wss.device-challenge-signature.v1"


class _TaskFactoryUnavailable(RuntimeError):
    pass


class Endpoint(Protocol):
    @property
    def core_ipv4(self) -> str: ...

    @property
    def port(self) -> int: ...

    @property
    def generation(self) -> int: ...

    @property
    def client_certificate_sha256(self) -> str: ...

    @property
    def device_signing_key_id(self) -> str: ...

    @property
    def hmac_key_id(self) -> str: ...


class Device(Protocol):
    @property
    def device_id(self) -> UUID: ...


class DeviceRegistry(Protocol):
    async def require_current_client_certificate(
        self,
        observed_sha256: str,
        expected_sha256: str,
        endpoint_generation: int,
    ) -> Device: ...


class PairingKeys(Protocol):
    async def current_outbound(
        self,
        *,
        device_id: UUID,
        tls_peer_sha256: str,
        now: Any,
    ) -> Any: ...

    async def resolve_inbound(
        self,
        *,
        device_id: UUID,
        tls_peer_sha256: str,
        signing_key_id: str,
        hmac_key_id: str,
        now: Any,
    ) -> Any: ...


class DuplexState(Protocol):
    async def abandon_connection(self, reason: str) -> None: ...


class Handler(Protocol):
    async def control(self, purpose: str, payload: bytes) -> bytes: ...

    async def media(self, frame: bytes) -> None: ...


class Session(Protocol):
    async def serve(self) -> None: ...


class SessionFactory(Protocol):
    def __call__(self, **kwargs: object) -> Session: ...


class SessionPublisher(Protocol):
    @property
    def safety(self) -> Any: ...

    async def publish(self, device_id: UUID, session: Session) -> None: ...

    async def clear(self, device_id: UUID, session: Session) -> None: ...


class Readiness(Protocol):
    def latch_disconnect_degraded(
        self,
        codes: tuple[str, ...],
        *,
        restart_required: bool = False,
    ) -> None: ...


class TimeIssuer(Protocol):
    async def issue(self, nonce: bytes, *, client_certificate_sha256: str) -> Any: ...


class Clock(Protocol):
    def now(self) -> Any: ...


class SocketLike(Protocol):
    @property
    def subprotocol(self) -> str | None: ...

    @property
    def transport(self) -> Any: ...

    @property
    def request(self) -> Any: ...

    async def recv(self) -> str | bytes: ...

    async def send(self, message: str | bytes) -> None: ...

    async def close(self, *, code: int = 1000, reason: str = "") -> None: ...


class ServeFactory(Protocol):
    async def __call__(
        self,
        handler: Callable[[SocketLike], Awaitable[None]],
        **kwargs: object,
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class _EndpointSnapshot:
    core_ipv4: str
    port: int
    generation: int
    client_certificate_sha256: str
    device_signing_key_id: str
    hmac_key_id: str


@dataclass(frozen=True, slots=True)
class _DeviceSnapshot:
    device_id: UUID


@dataclass(frozen=True, slots=True)
class _OutboundKeysSnapshot:
    signer: Ed25519PrivateKey
    signing_key_id: str
    hmac_root: bytes
    hmac_key_id: str


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


class ReachyWssServer:
    def __init__(
        self,
        endpoint: Endpoint,
        *,
        tls_context: object,
        device_registry: DeviceRegistry,
        pairing_keys: PairingKeys,
        state: DuplexState,
        handler: Handler,
        sessions: SessionPublisher,
        readiness: Readiness,
        time_issuer: TimeIssuer,
        clock: Clock,
        session_factory: SessionFactory,
        serve_factory: ServeFactory | None = None,
        client_certificate_verifier: Callable[[SocketLike, str], tuple[str, bytes]] | None = None,
        nonce_factory: Callable[[int], bytes] = secrets.token_bytes,
        handshake_timeout: float = 2.0,
        socket_close_timeout: float = 2.0,
        pre_session_cleanup_timeout: float = 0.250,
    ) -> None:
        self._endpoint = endpoint
        self._tls_context = tls_context
        self._devices = device_registry
        self._pairing_keys = pairing_keys
        self._state = state
        self._handler = handler
        self._sessions = sessions
        self._readiness = readiness
        self._time_issuer = time_issuer
        self._clock = clock
        self._session_factory = session_factory
        self._serve_factory = serve_factory or _serve_with_websockets
        self._client_certificate_verifier = (
            client_certificate_verifier or _default_client_certificate_verifier
        )
        self._nonce_factory = nonce_factory
        self._handshake_timeout = _bounded_positive_float(
            handshake_timeout,
            "handshake_timeout",
            MAX_SOCKET_CLOSE_SECONDS,
        )
        self._socket_close_timeout = _bounded_positive_float(
            socket_close_timeout,
            "socket_close_timeout",
            MAX_SOCKET_CLOSE_SECONDS,
        )
        self._pre_session_cleanup_timeout = _bounded_positive_float(
            pre_session_cleanup_timeout,
            "pre_session_cleanup_timeout",
            MAX_SOCKET_CLOSE_SECONDS,
        )
        self._client_lock = asyncio.Lock()
        self._server: object | None = None
        self._background_cleanup_tasks: set[asyncio.Task[Any]] = set()

    def with_endpoint(self, endpoint: Endpoint) -> ReachyWssServer:
        return ReachyWssServer(
            endpoint,
            tls_context=self._tls_context,
            device_registry=self._devices,
            pairing_keys=self._pairing_keys,
            state=self._state,
            handler=self._handler,
            sessions=self._sessions,
            readiness=self._readiness,
            time_issuer=self._time_issuer,
            clock=self._clock,
            session_factory=self._session_factory,
            serve_factory=self._serve_factory,
            client_certificate_verifier=self._client_certificate_verifier,
            nonce_factory=self._nonce_factory,
            handshake_timeout=self._handshake_timeout,
            socket_close_timeout=self._socket_close_timeout,
            pre_session_cleanup_timeout=self._pre_session_cleanup_timeout,
        )

    def _capture_endpoint(self) -> _EndpointSnapshot:
        return _EndpointSnapshot(
            core_ipv4=_require_numeric_rfc1918_ipv4(self._endpoint.core_ipv4),
            port=_require_port(self._endpoint.port),
            generation=_require_generation(self._endpoint.generation),
            client_certificate_sha256=_require_sha256(
                self._endpoint.client_certificate_sha256,
                "reachy_client_certificate_sha256_invalid",
            ),
            device_signing_key_id=_require_key_id(
                self._endpoint.device_signing_key_id,
                "reachy_device_signing_key_id_invalid",
            ),
            hmac_key_id=_require_key_id(
                self._endpoint.hmac_key_id,
                "reachy_hmac_key_id_invalid",
            ),
        )

    def _require_unchanged_endpoint(self, snapshot: _EndpointSnapshot) -> None:
        if self._capture_endpoint() != snapshot:
            raise PermissionError("reachy_endpoint_changed")

    @staticmethod
    def _capture_device(device: Device) -> _DeviceSnapshot:
        device_id = device.device_id
        if type(device_id) is not UUID:
            raise PermissionError("reachy_device_id_invalid")
        return _DeviceSnapshot(device_id=device_id)

    def _require_unchanged_device(
        self,
        device: Device,
        snapshot: _DeviceSnapshot,
    ) -> None:
        if self._capture_device(device) != snapshot:
            raise PermissionError("reachy_device_changed")

    @staticmethod
    def _capture_outbound_keys(keys: Any) -> _OutboundKeysSnapshot:
        signer = keys.signer
        if not isinstance(signer, Ed25519PrivateKey):
            raise TypeError("reachy_outbound_signer_invalid")
        hmac_root = keys.hmac_root
        if type(hmac_root) is not bytes:
            raise TypeError("reachy_outbound_hmac_root_invalid")
        return _OutboundKeysSnapshot(
            signer=signer,
            signing_key_id=_require_key_id(keys.signing_key_id, "reachy_signing_key_id_invalid"),
            hmac_root=bytes(hmac_root),
            hmac_key_id=_require_key_id(keys.hmac_key_id, "reachy_hmac_key_id_invalid"),
        )

    async def start(self) -> None:
        endpoint = self._capture_endpoint()
        await self._state.abandon_connection("restart_recovery")
        server: object | None = None
        try:
            server = await self._serve_factory(
                self.accept,
                host=endpoint.core_ipv4,
                port=endpoint.port,
                ssl=self._tls_context,
                subprotocols=[TIME_SUBPROTOCOL, APP_SUBPROTOCOL],
                compression=None,
                ping_interval=None,
                max_size=MAX_WSS_MESSAGE_BYTES,
                max_queue=16,
                open_timeout=5,
                close_timeout=2,
            )
            self._server = server
            self._require_unchanged_endpoint(endpoint)
        except BaseException as error:
            if server is not None:
                cancellations = await self._close_bound_server(
                    server,
                    failure_prefix="reachy_server_start_close",
                    timeout_code="reachy_server_start_close:timeout",
                    clear_state_on_timeout=True,
                )
                if cancellations:
                    raise asyncio.CancelledError from error
            raise

    async def close(self) -> None:
        if self._server is None:
            return
        server = self._server
        cancellations = await self._close_bound_server(
            server,
            failure_prefix="reachy_server_close",
            timeout_code="reachy_server_close:timeout",
            clear_state_on_timeout=False,
        )
        if cancellations:
            raise asyncio.CancelledError

    async def _close_bound_server(
        self,
        server: object,
        *,
        failure_prefix: str,
        timeout_code: str,
        clear_state_on_timeout: bool,
    ) -> int:
        close = getattr(server, "close", None)
        wait_closed = getattr(server, "wait_closed", None)
        if callable(close):
            close()
        cancellations = 0
        wait_completed = True
        if callable(wait_closed):
            wait_task: asyncio.Task[Any] | None = None
            try:
                wait_task = _spawn_task_with_direct_fallback(
                    lambda: _await_once(wait_closed),
                    name="reachy_server_wait_closed",
                    on_factory_unavailable=lambda code: self._readiness.latch_disconnect_degraded(
                        (code,),
                        restart_required=True,
                    ),
                )
                await asyncio.wait_for(
                    asyncio.shield(wait_task),
                    timeout=self._socket_close_timeout,
                )
            except _TaskFactoryUnavailable:
                wait_completed = False
            except TimeoutError:
                wait_completed = False
                if wait_task is not None:
                    wait_task.cancel()
                    self._retain_background_task(
                        wait_task,
                        failure_prefix=failure_prefix,
                    )
                self._readiness.latch_disconnect_degraded(
                    (timeout_code,),
                    restart_required=True,
                )
            except asyncio.CancelledError:
                wait_completed = False
                if wait_task is not None:
                    wait_task.cancel()
                    self._retain_background_task(
                        wait_task,
                        failure_prefix=failure_prefix,
                    )
                cancellations += 1
            except Exception as error:
                wait_completed = False
                self._readiness.latch_disconnect_degraded(
                    (f"{failure_prefix}:{type(error).__name__}",),
                    restart_required=True,
                )
            if wait_task is not None and wait_task.done():
                try:
                    wait_task.result()
                except asyncio.CancelledError:
                    cancellations += 1
                except Exception as error:
                    wait_completed = False
                    self._readiness.latch_disconnect_degraded(
                        (f"{failure_prefix}:{type(error).__name__}",),
                        restart_required=True,
                    )
        if self._server is server and (wait_completed or clear_state_on_timeout):
            self._server = None
        return cancellations

    async def accept(self, socket: SocketLike) -> None:
        try:
            path = _request_path(socket)
        except PermissionError as error:
            cancellations = await _close_socket_observing_cancellation(
                socket,
                code=1008,
                reason="reachy_path_or_subprotocol",
                timeout=self._socket_close_timeout,
                readiness=self._readiness,
            )
            if cancellations:
                raise asyncio.CancelledError from error
            raise
        route = (path, socket.subprotocol)
        if route not in {
            (TIME_PATH, TIME_SUBPROTOCOL),
            (APP_PATH, APP_SUBPROTOCOL),
        }:
            cancellations = await _close_socket_observing_cancellation(
                socket,
                code=1008,
                reason="reachy_path_or_subprotocol",
                timeout=self._socket_close_timeout,
                readiness=self._readiness,
            )
            if cancellations:
                raise asyncio.CancelledError
            return
        if self._client_lock.locked():
            cancellations = await _close_socket_observing_cancellation(
                socket,
                code=1013,
                reason="commissioned_reachy_already_connected",
                timeout=self._socket_close_timeout,
                readiness=self._readiness,
            )
            if cancellations:
                raise asyncio.CancelledError
            return
        async with self._client_lock:
            endpoint = self._capture_endpoint()
            try:
                negotiated_tls_version, client_der = self._client_certificate_verifier(
                    socket,
                    endpoint.client_certificate_sha256,
                )
                self._require_unchanged_endpoint(endpoint)
                if negotiated_tls_version != "TLSv1.3":
                    raise PermissionError("reachy_tls13_required")
                client_sha256 = _verified_leaf_sha256(
                    client_der,
                    endpoint.client_certificate_sha256,
                    invalid_error="reachy_client_certificate_invalid",
                    mismatch_error="reachy_client_certificate_mismatch",
                )
                device = await self._devices.require_current_client_certificate(
                    client_sha256,
                    endpoint.client_certificate_sha256,
                    endpoint.generation,
                )
                self._require_unchanged_endpoint(endpoint)
                if route == (TIME_PATH, TIME_SUBPROTOCOL):
                    await self._serve_time_bootstrap(socket, client_sha256, endpoint)
                    return
                device_id, session = await self._open_application_session(
                    socket,
                    device,
                    client_sha256,
                    endpoint,
                )
            except asyncio.CancelledError as error:
                cancellations = await self._handle_pre_session_failure(
                    socket,
                    code=1011,
                    reason="reachy_accept_cancelled",
                    readiness_code="reachy_pre_session_cancelled",
                )
                if cancellations:
                    raise asyncio.CancelledError from error
                raise
            except BaseException as error:
                close_code = 1008 if isinstance(error, PermissionError) else 1011
                close_reason = (
                    "reachy_handshake_failed"
                    if isinstance(error, PermissionError)
                    else "reachy_accept_failed"
                )
                cancellations = await self._handle_pre_session_failure(
                    socket,
                    code=close_code,
                    reason=close_reason,
                    readiness_code=f"reachy_pre_session_failed:{type(error).__name__}",
                )
                if cancellations:
                    raise asyncio.CancelledError from error
                raise
            await self._serve_published_session(device_id, session)

    async def _handle_pre_session_failure(
        self,
        socket: SocketLike,
        *,
        code: int,
        reason: str,
        readiness_code: str,
    ) -> int:
        close_cancellations = await _close_socket_observing_cancellation(
            socket,
            code=code,
            reason=reason,
            timeout=self._socket_close_timeout,
            readiness=self._readiness,
        )
        self._readiness.latch_disconnect_degraded((readiness_code,))
        cleanup_cancellations = await self._observe_pre_session_cleanup()
        return close_cancellations + cleanup_cancellations

    async def _observe_pre_session_cleanup(self) -> int:
        cleanup_task, _failure = self._spawn_cleanup_task(
            lambda: self._state.abandon_connection("pre_session_failure"),
            name="reachy_pre_session_cleanup",
            failure_prefix="reachy_pre_session_cleanup",
            factory_unavailable_code="reachy_pre_session_cleanup:factory_unavailable",
        )
        if cleanup_task is None:
            return 0
        cancellations, _failures, _timed_out = await self._observe_cleanup_task(
            cleanup_task,
            timeout_code="reachy_pre_session_cleanup:timeout",
            failure_prefix="reachy_pre_session_cleanup",
        )
        return cancellations

    async def _clear_session_observing_cancellation(
        self,
        device_id: UUID,
        session: Session,
    ) -> tuple[int, tuple[BaseException, ...], bool]:
        clear_task, failure = self._spawn_cleanup_task(
            lambda: self._sessions.clear(device_id, session),
            name="reachy_session_clear",
            failure_prefix="reachy_session_clear",
            factory_unavailable_code="reachy_session_clear:factory_unavailable",
        )
        if clear_task is None:
            return 0, (failure,) if failure is not None else (), False
        return await self._observe_cleanup_task(
            clear_task,
            timeout_code="reachy_session_clear:timeout",
            failure_prefix="reachy_session_clear",
        )

    def _spawn_cleanup_task(
        self,
        awaitable_factory: Callable[[], Coroutine[Any, Any, Any]],
        *,
        name: str,
        failure_prefix: str,
        factory_unavailable_code: str,
    ) -> tuple[asyncio.Task[Any] | None, BaseException | None]:
        awaitable, failure = self._call_cleanup_awaitable_factory(
            awaitable_factory,
            failure_prefix=failure_prefix,
        )
        if failure is not None or awaitable is None:
            return None, failure
        try:
            return asyncio.create_task(awaitable, name=name), None
        except BaseException as error:
            _close_unstarted_awaitable(awaitable)
            if not isinstance(error, Exception):
                raise
        fallback_awaitable, failure = self._call_cleanup_awaitable_factory(
            awaitable_factory,
            failure_prefix=failure_prefix,
        )
        if failure is not None or fallback_awaitable is None:
            return None, failure
        try:
            return asyncio.Task(fallback_awaitable, name=name), None
        except BaseException as error:
            _close_unstarted_awaitable(fallback_awaitable)
            if not isinstance(error, Exception):
                raise
            self._readiness.latch_disconnect_degraded(
                (factory_unavailable_code,),
                restart_required=True,
            )
            return None, error

    def _call_cleanup_awaitable_factory(
        self,
        awaitable_factory: Callable[[], Coroutine[Any, Any, Any]],
        *,
        failure_prefix: str,
    ) -> tuple[Coroutine[Any, Any, Any] | None, BaseException | None]:
        try:
            return awaitable_factory(), None
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            self._readiness.latch_disconnect_degraded(
                (f"{failure_prefix}:{type(error).__name__}",),
                restart_required=True,
            )
            return None, error

    async def _observe_cleanup_task(
        self,
        task: asyncio.Task[Any],
        *,
        timeout_code: str,
        failure_prefix: str,
    ) -> tuple[int, tuple[BaseException, ...], bool]:
        cancellations = 0
        timed_out = False
        failures: list[BaseException] = []
        while not task.done():
            try:
                await asyncio.wait_for(
                    asyncio.shield(task),
                    timeout=self._pre_session_cleanup_timeout,
                )
            except TimeoutError:
                if task.done():
                    break
                timed_out = True
                task.cancel()
                self._readiness.latch_disconnect_degraded(
                    (timeout_code,),
                    restart_required=True,
                )
                while not task.done():
                    try:
                        await asyncio.wait_for(
                            asyncio.shield(task),
                            timeout=self._pre_session_cleanup_timeout,
                        )
                    except TimeoutError:
                        if task.done():
                            break
                        self._retain_background_task(
                            task,
                            failure_prefix=failure_prefix,
                        )
                        return cancellations, (), timed_out
                    except asyncio.CancelledError:
                        if task.done():
                            break
                        cancellations += 1
                    except Exception as error:
                        failures.append(error)
                        self._readiness.latch_disconnect_degraded(
                            (f"{failure_prefix}:{type(error).__name__}",),
                            restart_required=True,
                        )
                        return cancellations, tuple(failures), timed_out
                break
            except asyncio.CancelledError:
                if task.done():
                    break
                cancellations += 1
            except Exception as error:
                failures.append(error)
                self._readiness.latch_disconnect_degraded(
                    (f"{failure_prefix}:{type(error).__name__}",),
                    restart_required=True,
                )
                return cancellations, tuple(failures), timed_out
        if task.done():
            try:
                task.result()
            except asyncio.CancelledError:
                if not timed_out:
                    cancellations += 1
            except Exception as error:
                failures.append(error)
                self._readiness.latch_disconnect_degraded(
                    (f"{failure_prefix}:{type(error).__name__}",),
                    restart_required=True,
                )
        return cancellations, tuple(failures), timed_out

    def _retain_background_task(
        self,
        task: asyncio.Task[Any],
        *,
        failure_prefix: str | None,
    ) -> None:
        self._background_cleanup_tasks.add(task)

        def observe(completed: asyncio.Future[Any]) -> None:
            self._background_cleanup_tasks.discard(cast(asyncio.Task[Any], completed))
            try:
                completed.result()
            except asyncio.CancelledError:
                pass
            except BaseException as error:
                if failure_prefix is not None:
                    self._readiness.latch_disconnect_degraded(
                        (f"{failure_prefix}:{type(error).__name__}",),
                        restart_required=True,
                    )

        task.add_done_callback(observe)

    async def _serve_time_bootstrap(
        self,
        socket: SocketLike,
        client_sha256: str,
        endpoint: _EndpointSnapshot,
    ) -> None:
        raw = await asyncio.wait_for(socket.recv(), timeout=self._handshake_timeout)
        self._require_unchanged_endpoint(endpoint)
        request = _parse_handshake_text(CoreTimeRequestV1, raw)
        nonce = base64.b64decode(request.request_nonce_b64, validate=True)
        proof = await self._time_issuer.issue(nonce, client_certificate_sha256=client_sha256)
        self._require_unchanged_endpoint(endpoint)
        await asyncio.wait_for(
            socket.send(canonical_bytes(proof).decode("utf-8")),
            timeout=self._handshake_timeout,
        )
        self._require_unchanged_endpoint(endpoint)
        cancellations = await _close_socket_observing_cancellation(
            socket,
            code=1000,
            reason="secure_time_complete",
            timeout=self._socket_close_timeout,
            readiness=self._readiness,
        )
        if cancellations:
            raise asyncio.CancelledError

    async def _open_application_session(
        self,
        socket: SocketLike,
        device: Device,
        client_sha256: str,
        endpoint: _EndpointSnapshot,
    ) -> tuple[UUID, Session]:
        device_snapshot = self._capture_device(device)
        outbound_keys = self._capture_outbound_keys(
            await self._pairing_keys.current_outbound(
                device_id=device_snapshot.device_id,
                tls_peer_sha256=client_sha256,
                now=self._clock.now(),
            )
        )
        self._require_unchanged_endpoint(endpoint)
        self._require_unchanged_device(device, device_snapshot)
        challenge_nonce = _fresh_nonce(self._nonce_factory, 32)
        server_nonce = _fresh_nonce(self._nonce_factory, 32)
        challenge = DeviceChallengeV1(
            schema_version="tuntun.reachy-device-challenge.v1",
            challenge_b64=base64.b64encode(challenge_nonce).decode("ascii"),
            server_nonce_b64=base64.b64encode(server_nonce).decode("ascii"),
            endpoint_generation=endpoint.generation,
        )
        await asyncio.wait_for(
            socket.send(canonical_bytes(challenge).decode("utf-8")),
            timeout=self._handshake_timeout,
        )
        self._require_unchanged_endpoint(endpoint)
        self._require_unchanged_device(device, device_snapshot)
        raw_proof = await asyncio.wait_for(socket.recv(), timeout=self._handshake_timeout)
        self._require_unchanged_endpoint(endpoint)
        self._require_unchanged_device(device, device_snapshot)
        proof = _parse_handshake_text(DeviceProofV1, raw_proof)
        try:
            _strict_b64_32(proof.client_nonce_b64, "connection_nonce_or_sequence")
        except ValueError as error:
            raise PermissionError("connection_nonce_or_sequence") from error
        inbound_keys = await self._pairing_keys.resolve_inbound(
            device_id=device_snapshot.device_id,
            tls_peer_sha256=client_sha256,
            signing_key_id=endpoint.device_signing_key_id,
            hmac_key_id=endpoint.hmac_key_id,
            now=self._clock.now(),
        )
        self._require_unchanged_endpoint(endpoint)
        self._require_unchanged_device(device, device_snapshot)
        try:
            inbound_keys.public_key.verify(
                base64.b64decode(proof.signature_b64, validate=True),
                device_challenge_signing_payload(
                    challenge,
                    proof.client_nonce_b64,
                    proof_schema_version=proof.schema_version,
                ),
            )
        except (InvalidSignature, ValueError, TypeError) as error:
            raise PermissionError("device_challenge") from error
        try:
            connection_nonce = _expected_connection_nonce(
                challenge,
                proof.client_nonce_b64,
                proof_schema_version=proof.schema_version,
            )
        except ValueError as error:
            raise PermissionError("connection_nonce_or_sequence") from error
        accepted = ChallengeAcceptedV1(
            schema_version=CHALLENGE_ACCEPTED_SCHEMA,
            connection_nonce_b64=base64.b64encode(connection_nonce).decode("ascii"),
        )
        await asyncio.wait_for(
            socket.send(canonical_bytes(accepted).decode("utf-8")),
            timeout=self._handshake_timeout,
        )
        self._require_unchanged_endpoint(endpoint)
        self._require_unchanged_device(device, device_snapshot)
        session = self._session_factory(
            socket=socket,
            connection_nonce=connection_nonce,
            outbound_keys=outbound_keys,
            inbound_key_resolver=self._pairing_keys,
            tls_peer_sha256=client_sha256,
            device_id=device_snapshot.device_id,
            state=self._state,
            handler=self._handler,
            safety=self._sessions.safety,
            readiness=self._readiness,
            clock=self._clock,
        )
        try:
            await self._sessions.publish(device_snapshot.device_id, session)
            self._require_unchanged_endpoint(endpoint)
            self._require_unchanged_device(device, device_snapshot)
        except BaseException as error:
            (
                clear_cancellations,
                clear_failures,
                clear_timed_out,
            ) = await self._clear_session_observing_cancellation(
                device_snapshot.device_id,
                session,
            )
            _raise_after_session_clear(
                primary=error,
                clear_cancellations=clear_cancellations,
                clear_failures=clear_failures,
                clear_timed_out=clear_timed_out,
            )
        return device_snapshot.device_id, session

    async def _serve_published_session(self, device_id: UUID, session: Session) -> None:
        primary: BaseException | None = None
        try:
            await session.serve()
        except BaseException as error:
            primary = error
        (
            clear_cancellations,
            clear_failures,
            clear_timed_out,
        ) = await self._clear_session_observing_cancellation(device_id, session)
        _raise_after_session_clear(
            primary=primary,
            clear_cancellations=clear_cancellations,
            clear_failures=clear_failures,
            clear_timed_out=clear_timed_out,
        )


def _raise_after_session_clear(
    *,
    primary: BaseException | None,
    clear_cancellations: int,
    clear_failures: tuple[BaseException, ...],
    clear_timed_out: bool,
) -> None:
    if clear_cancellations:
        if primary is not None:
            raise asyncio.CancelledError from primary
        raise asyncio.CancelledError
    if primary is not None:
        raise primary
    if clear_failures:
        raise RuntimeError("reachy_session_clear_degraded") from ExceptionGroup(
            "reachy_session_clear_degraded",
            [error for error in clear_failures if isinstance(error, Exception)],
        )
    if clear_timed_out:
        raise RuntimeError("reachy_session_clear_degraded")


def _close_unstarted_awaitable(awaitable: Awaitable[Any]) -> None:
    close = getattr(awaitable, "close", None)
    if callable(close):
        close()


async def _await_once(awaitable_factory: Callable[[], Awaitable[Any]]) -> None:
    await awaitable_factory()


def _spawn_task_with_direct_fallback(
    awaitable_factory: Callable[[], Coroutine[Any, Any, Any]],
    *,
    name: str,
    on_factory_unavailable: Callable[[str], None] | None = None,
) -> asyncio.Task[Any]:
    awaitable = awaitable_factory()
    try:
        return asyncio.create_task(awaitable, name=name)
    except BaseException as error:
        _close_unstarted_awaitable(awaitable)
        if not isinstance(error, Exception):
            raise
    fallback = awaitable_factory()
    try:
        return asyncio.Task(fallback, name=name)
    except BaseException as error:
        _close_unstarted_awaitable(fallback)
        if not isinstance(error, Exception):
            raise
        code = f"{name}:factory_unavailable"
        if on_factory_unavailable is not None:
            on_factory_unavailable(code)
        raise _TaskFactoryUnavailable(code) from error


async def _serve_with_websockets(
    handler: Callable[[SocketLike], Awaitable[None]],
    **kwargs: object,
) -> object:
    try:
        module = importlib.import_module("websockets.asyncio.server")
    except ModuleNotFoundError as error:
        raise RuntimeError("websockets==15.0.1 is required for Reachy WSS transport") from error
    serve = cast(Callable[..., Awaitable[object]], cast(Any, module).serve)
    return await serve(handler, **kwargs)


def _default_client_certificate_verifier(
    socket: SocketLike,
    expected_sha256: str,
) -> tuple[str, bytes]:
    return require_client_certificate_sha256(_ssl_object(socket), expected_sha256)


def _ssl_object(socket: SocketLike) -> Any:
    transport = getattr(socket, "transport", None)
    getter = getattr(transport, "get_extra_info", None)
    if not callable(getter):
        raise PermissionError("reachy_tls_peer_unavailable")
    tls_connection = getter("ssl_object")
    if tls_connection is None:
        raise PermissionError("reachy_tls_peer_unavailable")
    return tls_connection


def _request_path(socket: SocketLike) -> str:
    request = getattr(socket, "request", None)
    path = getattr(request, "path", None)
    if type(path) is not str:
        raise PermissionError("reachy_path_or_subprotocol")
    return path


def _parse_handshake_text(model_type: type[Any], raw: str | bytes) -> Any:
    if type(raw) is not str:
        raise PermissionError("reachy_handshake_text_json_required")
    try:
        return parse_contract_json(
            model_type,
            raw.encode("utf-8"),
            max_bytes=8_192,
            require_canonical=True,
        )
    except (TypeError, ValueError) as error:
        raise PermissionError("reachy_handshake_json_invalid") from error


def device_challenge_signing_payload(
    challenge: DeviceChallengeV1,
    client_nonce_b64: str,
    *,
    proof_schema_version: str = DEVICE_PROOF_SCHEMA,
) -> bytes:
    return canonical_mapping_bytes(
        {
            "schema_version": HANDSHAKE_SIGNATURE_PAYLOAD_SCHEMA,
            "domain": HANDSHAKE_SIGNATURE_DOMAIN,
            "route": APP_PATH,
            "subprotocol": APP_SUBPROTOCOL,
            "challenge_schema_version": challenge.schema_version,
            "proof_schema_version": proof_schema_version,
            "challenge_b64": challenge.challenge_b64,
            "server_nonce_b64": challenge.server_nonce_b64,
            "client_nonce_b64": client_nonce_b64,
            "endpoint_generation": challenge.endpoint_generation,
        }
    )


def _expected_connection_nonce(
    challenge: DeviceChallengeV1,
    client_nonce_b64: str,
    *,
    proof_schema_version: str = DEVICE_PROOF_SCHEMA,
    accepted_schema_version: str = CHALLENGE_ACCEPTED_SCHEMA,
) -> bytes:
    del proof_schema_version, accepted_schema_version
    challenge_nonce = _strict_b64_32(challenge.challenge_b64, "connection_nonce_or_sequence")
    server_nonce = _strict_b64_32(challenge.server_nonce_b64, "connection_nonce_or_sequence")
    client_nonce = _strict_b64_32(client_nonce_b64, "connection_nonce_or_sequence")
    return hashlib.sha256(challenge_nonce + server_nonce + client_nonce).digest()


def _strict_b64_32(value: object, error: str) -> bytes:
    if type(value) is not str:
        raise ValueError(error)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as decode_error:
        raise ValueError(error) from decode_error
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(error)
    return decoded


def _fresh_nonce(factory: Callable[[int], bytes], size: int) -> bytes:
    value = factory(size)
    if type(value) is not bytes or len(value) != size:
        raise ValueError("reachy_nonce_size")
    return bytes(value)


def _verified_leaf_sha256(
    leaf_der: bytes,
    expected_sha256: str,
    *,
    invalid_error: str,
    mismatch_error: str,
) -> str:
    expected = _require_sha256(expected_sha256, invalid_error)
    if type(leaf_der) is not bytes or not leaf_der:
        raise PermissionError(invalid_error)
    observed = hashlib.sha256(leaf_der).hexdigest()
    if not hmac.compare_digest(observed, expected):
        raise PermissionError(mismatch_error)
    return observed


def _require_sha256(value: object, error: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(error)
    return value


def _require_numeric_rfc1918_ipv4(value: object) -> str:
    if type(value) is not str:
        raise ValueError("reachy_core_endpoint_numeric_rfc1918_ipv4_required")
    pieces = value.split(".")
    if len(pieces) != 4:
        raise ValueError("reachy_core_endpoint_numeric_rfc1918_ipv4_required")
    octets: list[int] = []
    for piece in pieces:
        if not piece.isdecimal() or (len(piece) > 1 and piece.startswith("0")):
            raise ValueError("reachy_core_endpoint_numeric_rfc1918_ipv4_required")
        number = int(piece)
        if number > 255 or str(number) != piece:
            raise ValueError("reachy_core_endpoint_numeric_rfc1918_ipv4_required")
        octets.append(number)
    first, second = octets[0], octets[1]
    if first == 10 or (first == 172 and 16 <= second <= 31) or (first == 192 and second == 168):
        return value
    raise ValueError("reachy_core_endpoint_numeric_rfc1918_ipv4_required")


def _require_port(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("reachy_core_endpoint_port_required")
    return value


def _require_generation(value: object) -> int:
    if type(value) is not int or value < 1:
        raise ValueError("reachy_endpoint_generation_invalid")
    return value


def _require_key_id(value: object, error: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(error)
    return value


def _bounded_positive_float(value: float, label: str, maximum: float) -> float:
    if type(value) not in {int, float} or not math.isfinite(value) or value <= 0 or value > maximum:
        raise ValueError(f"{label}_positive_required")
    return float(value)


async def _close_bounded_suppressing_errors(
    socket: SocketLike,
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


async def _close_socket_observing_cancellation(
    socket: SocketLike,
    *,
    code: int,
    reason: str,
    timeout: float,
    readiness: Readiness | None = None,
) -> int:
    try:
        close_task = _spawn_task_with_direct_fallback(
            lambda: _close_bounded_suppressing_errors(
                socket,
                code=code,
                reason=reason,
                timeout=timeout,
            ),
            name="reachy_pre_session_socket_close",
            on_factory_unavailable=(
                lambda code: (
                    readiness.latch_disconnect_degraded(
                        (code,),
                        restart_required=True,
                    )
                    if readiness is not None
                    else None
                )
            ),
        )
    except _TaskFactoryUnavailable:
        return 0
    cancellations = 0
    while not close_task.done():
        try:
            await asyncio.shield(close_task)
        except asyncio.CancelledError:
            cancellations += 1
    try:
        close_task.result()
    except asyncio.CancelledError:
        cancellations += 1
    return cancellations


__all__ = (
    "APP_PATH",
    "APP_SUBPROTOCOL",
    "ReachyTransportSupervisorState",
    "ReachyWssServer",
    "TIME_PATH",
    "TIME_SUBPROTOCOL",
)
