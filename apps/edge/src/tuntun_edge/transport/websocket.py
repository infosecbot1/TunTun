from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hashlib
import hmac
import importlib
import inspect
import math
import secrets
import ssl
from collections.abc import Awaitable, Callable, Coroutine, Iterator
from dataclasses import dataclass
from typing import Any, Final, Protocol, TypeVar, cast
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tuntun_contracts.base import canonical_bytes, canonical_mapping_bytes, parse_contract_json
from tuntun_contracts.reachy_wire import (
    MAX_CONTROL_FRAME_JSON_BYTES,
    ChallengeAcceptedV1,
    DeviceChallengeV1,
    DeviceProofV1,
    SignedControlFrameV1,
    authenticate_control_frame,
    decode_control_payload,
    sign_control_frame,
)

from tuntun_edge.transport.tls import require_server_leaf_sha256

APP_PATH = "/v1/reachy"
APP_SUBPROTOCOL = "tuntun.reachy.v1"
MAX_WSS_MESSAGE_BYTES = 1_052_684
RECONNECT_DELAYS = (0.25, 0.5, 1.0, 2.0, 5.0)
MAX_HEARTBEAT_SECONDS = 60.0
MAX_HANDSHAKE_SECONDS = 2.0
MAX_SOCKET_CLOSE_SECONDS = 2.0
DEVICE_PROOF_SCHEMA: Final = "tuntun.reachy-device-proof.v1"
CHALLENGE_ACCEPTED_SCHEMA: Final = "tuntun.reachy-challenge-accepted.v1"
HANDSHAKE_SIGNATURE_PAYLOAD_SCHEMA: Final = "tuntun.reachy-device-challenge-signing-payload.v1"
HANDSHAKE_SIGNATURE_DOMAIN: Final = "tuntun.reachy.wss.device-challenge-signature.v1"
_TERMINAL_TLS_AUTH_REASONS: Final[frozenset[str]] = frozenset(
    {
        "CERTIFICATE_VERIFY_FAILED",
        "CERTIFICATE_REQUIRED",
        "PEER_DID_NOT_RETURN_A_CERTIFICATE",
        "SSLV3_ALERT_BAD_CERTIFICATE",
        "SSLV3_ALERT_CERTIFICATE_EXPIRED",
        "SSLV3_ALERT_CERTIFICATE_REVOKED",
        "SSLV3_ALERT_CERTIFICATE_UNKNOWN",
        "SSLV3_ALERT_HANDSHAKE_FAILURE",
        "SSLV3_ALERT_UNSUPPORTED_CERTIFICATE",
        "TLSV1_ALERT_ACCESS_DENIED",
        "TLSV1_ALERT_BAD_CERTIFICATE",
        "TLSV1_ALERT_CERTIFICATE_EXPIRED",
        "TLSV1_ALERT_CERTIFICATE_REQUIRED",
        "TLSV1_ALERT_CERTIFICATE_REVOKED",
        "TLSV1_ALERT_CERTIFICATE_UNKNOWN",
        "TLSV1_ALERT_DECRYPT_ERROR",
        "TLSV1_ALERT_HANDSHAKE_FAILURE",
        "TLSV1_ALERT_INSUFFICIENT_SECURITY",
        "TLSV1_ALERT_PROTOCOL_VERSION",
        "TLSV1_ALERT_UNKNOWN_CA",
        "TLSV1_ALERT_UNSUPPORTED_CERTIFICATE",
        "TLSV13_ALERT_CERTIFICATE_REQUIRED",
        "WRONG_VERSION_NUMBER",
    }
)
_CleanupResult = TypeVar("_CleanupResult")


class _TerminalCommissioningError(PermissionError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.readiness_code = f"reachy_recommission_required:{code}"


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
    def server_leaf_sha256(self) -> str: ...

    @property
    def client_certificate_sha256(self) -> str: ...


class Clock(Protocol):
    def now(self) -> Any: ...


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


class EdgePairingKeyResolver(Protocol):
    async def current_outbound(self, *, tls_peer_sha256: str, now: Any) -> OutboundKeys: ...

    async def resolve_frame(
        self,
        frame: SignedControlFrameV1,
        *,
        tls_peer_sha256: str,
        now: Any,
    ) -> InboundKeys: ...


class EdgeDuplexState(Protocol):
    async def reserve_outbound(self, correlation_id: UUID, purpose: str, kind: str) -> int: ...

    async def accept_inbound(
        self,
        sequence: int,
        correlation_id: UUID,
        purpose: str,
        kind: str,
    ) -> None: ...

    async def accept_response(self, correlation_id: UUID, purpose: str, payload: bytes) -> None: ...

    async def complete(self, correlation_id: UUID) -> None: ...

    async def abandon_connection(self, reason: str) -> None: ...


class EdgeHandler(Protocol):
    async def control(self, purpose: str, payload: bytes) -> bytes: ...

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
    @property
    def subprotocol(self) -> str | None: ...

    @property
    def transport(self) -> Any: ...

    async def recv(self) -> str | bytes: ...

    async def send(self, message: str | bytes) -> None: ...

    async def close(self, *, code: int = 1000, reason: str = "") -> None: ...

    def ping(self, payload: bytes) -> Awaitable[Any]: ...

    def __aiter__(self) -> Any: ...


class ConnectFactory(Protocol):
    async def __call__(self, uri: str, **kwargs: object) -> WebSocketLike: ...


@dataclass(frozen=True, slots=True)
class _EndpointSnapshot:
    core_ipv4: str
    port: int
    generation: int
    server_leaf_sha256: str
    client_certificate_sha256: str


@dataclass(frozen=True, slots=True)
class _OutboundKeysSnapshot:
    signer: Ed25519PrivateKey
    signing_key_id: str
    hmac_root: bytes
    hmac_key_id: str


class EdgeTransportSupervisorState:
    """Synchronous edge readiness/restart latch; contains no turn content."""

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


class EdgeReachyConnection:
    def __init__(
        self,
        *,
        socket: WebSocketLike,
        connection_nonce: bytes,
        outbound_keys: OutboundKeys,
        inbound_key_resolver: EdgePairingKeyResolver,
        state: EdgeDuplexState,
        handler: EdgeHandler,
        negotiated_tls_version: str,
        peer_leaf_sha256: str,
        client_certificate_sha256: str,
        clock: Clock,
        heartbeat_interval: float = 1.0,
        heartbeat_timeout: float = 0.9,
        socket_close_timeout: float = 2.0,
        readiness: TransportReadiness | None = None,
    ) -> None:
        if type(connection_nonce) is not bytes or len(connection_nonce) != 32:
            raise ValueError("connection_nonce_or_sequence")
        self._socket = socket
        self._nonce = bytes(connection_nonce)
        self._outbound_keys = outbound_keys
        self._inbound_keys = inbound_key_resolver
        self._state = state
        self._handler = handler
        self._clock = clock
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
        self._readiness = readiness
        self.negotiated_tls_version = negotiated_tls_version
        self.peer_leaf_sha256 = peer_leaf_sha256
        self.client_certificate_sha256 = client_certificate_sha256
        self.device_challenge_verified = True
        self._close_requested = False

    @property
    def connection_nonce(self) -> bytes:
        return self._nonce

    async def close(self, *, code: int = 1000, reason: str = "") -> None:
        if self._close_requested:
            return
        self._close_requested = True
        await _close_bounded_suppressing_errors(
            self._socket,
            code=code,
            reason=reason,
            timeout=self._socket_close_timeout,
        )

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
            keys = await self._inbound_keys.resolve_frame(
                frame,
                tls_peer_sha256=self.peer_leaf_sha256,
                now=self._clock.now(),
            )
            authenticate_control_frame(
                keys.public_key,
                keys.hmac_root,
                frame,
                expected_signing_key_id=keys.signing_key_id,
                expected_hmac_key_id=keys.hmac_key_id,
                expected_direction="core_to_edge",
                expected_nonce=self._nonce,
            )
            await self._state.accept_inbound(
                frame.sequence,
                frame.correlation_id,
                frame.purpose,
                frame.kind,
            )
            payload = decode_control_payload(frame)
            if frame.kind == "response":
                await self._state.accept_response(frame.correlation_id, frame.purpose, payload)
                await self._state.complete(frame.correlation_id)
                continue
            response = await self._handler.control(frame.purpose, payload)
            if frame.kind == "request":
                sequence = await self._state.reserve_outbound(
                    frame.correlation_id,
                    frame.purpose,
                    "response",
                )
                signed = sign_control_frame(
                    self._outbound_keys.signer,
                    self._outbound_keys.hmac_root,
                    signing_key_id=self._outbound_keys.signing_key_id,
                    hmac_key_id=self._outbound_keys.hmac_key_id,
                    direction="edge_to_core",
                    kind="response",
                    connection_nonce=self._nonce,
                    sequence=sequence,
                    correlation_id=frame.correlation_id,
                    purpose=frame.purpose,
                    payload=response,
                )
                await asyncio.wait_for(
                    self._socket.send(canonical_bytes(signed).decode("utf-8")),
                    timeout=self._socket_close_timeout,
                )
            await self._state.complete(frame.correlation_id)
        raise ConnectionError("reachy websocket closed")

    async def _heartbeat_loop(self) -> None:
        misses = 0
        loop = asyncio.get_running_loop()
        deadline = loop.time()
        while True:
            deadline += self._heartbeat_interval
            await asyncio.sleep(max(0.0, deadline - loop.time()))
            pong = self._socket.ping(secrets.token_bytes(8))
            try:
                await asyncio.wait_for(pong, timeout=self._heartbeat_timeout)
                misses = 0
            except TimeoutError as error:
                misses += 1
                if misses >= 2:
                    await self.close(code=1011, reason="heartbeat_lost")
                    raise ConnectionError("two consecutive heartbeats missed") from error

    async def serve(self) -> None:
        receive_task = self._spawn_owned_task(
            self._receive_loop,
            name="edge_connection_receive",
        )
        heartbeat_task: asyncio.Task[Any] | None = None
        try:
            heartbeat_task = self._spawn_owned_task(
                self._heartbeat_loop,
                name="edge_connection_heartbeat",
            )
            done, pending = await asyncio.wait(
                {receive_task, heartbeat_task},
                return_when=asyncio.FIRST_EXCEPTION,
            )
            for task in pending:
                task.cancel()
            for task in pending:
                await _cancel_and_observe(task)
            for task in done:
                try:
                    task.result()
                except BaseException as error:
                    if isinstance(error, Exception):
                        raise
                    raise BaseExceptionGroup("edge_connection_serve_failed", [error]) from error
        finally:
            if not receive_task.done():
                receive_task.cancel()
                await _cancel_and_observe(receive_task)
            if heartbeat_task is not None and not heartbeat_task.done():
                heartbeat_task.cancel()
                await _cancel_and_observe(heartbeat_task)

    def _spawn_owned_task(
        self,
        awaitable_factory: Callable[[], Coroutine[Any, Any, Any]],
        *,
        name: str,
    ) -> asyncio.Task[Any]:
        return _spawn_task_with_direct_fallback(
            awaitable_factory,
            name=name,
            on_factory_unavailable=(
                lambda code: (
                    self._readiness.latch_disconnect_degraded(
                        (code,),
                        restart_required=True,
                    )
                    if self._readiness is not None
                    else None
                )
            ),
        )


class ReachyWssClient:
    """Reachy edge transport. The edge is always the TCP/WSS initiator."""

    def __init__(
        self,
        endpoint: Endpoint,
        *,
        tls_context: object,
        pairing_keys: EdgePairingKeyResolver,
        state: EdgeDuplexState,
        safety: DisconnectSafety,
        handler: EdgeHandler,
        readiness: TransportReadiness,
        clock: Clock,
        connect_factory: ConnectFactory | None = None,
        tls_peer_verifier: Callable[[WebSocketLike, str], tuple[str, bytes]] | None = None,
        client_certificate_sha256: Callable[[WebSocketLike], str] | None = None,
        nonce_factory: Callable[[int], bytes] = secrets.token_bytes,
        sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep,
        cleanup_timeout: float = 0.250,
        heartbeat_interval: float = 1.0,
        heartbeat_timeout: float = 0.9,
        handshake_timeout: float = 2.0,
        socket_close_timeout: float = 2.0,
    ) -> None:
        self._endpoint = endpoint
        self._tls_context = tls_context
        self._pairing_keys = pairing_keys
        self._state = state
        self._safety = safety
        self._handler = handler
        self._readiness = readiness
        self._clock = clock
        self._connect_factory = connect_factory or _connect_with_websockets
        self._tls_peer_verifier = tls_peer_verifier or _default_server_leaf_verifier
        self._client_certificate_sha256 = client_certificate_sha256 or (
            lambda _socket: self._endpoint.client_certificate_sha256
        )
        self._nonce_factory = nonce_factory
        self._sleeper = sleeper
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
        self._handshake_timeout = _bounded_positive_float(
            handshake_timeout,
            "handshake_timeout",
            MAX_HANDSHAKE_SECONDS,
        )
        self._socket_close_timeout = _bounded_positive_float(
            socket_close_timeout,
            "socket_close_timeout",
            MAX_SOCKET_CLOSE_SECONDS,
        )
        self._cleanup_background: set[asyncio.Task[Any]] = set()
        self.last_disconnect_failure_codes: tuple[str, ...] = ()
        self.task_factory_failure_points: tuple[str, ...] = ()
        self.connection_history: list[bytes] = []

    def _capture_endpoint(self) -> _EndpointSnapshot:
        return _EndpointSnapshot(
            core_ipv4=_require_numeric_rfc1918_ipv4(self._endpoint.core_ipv4),
            port=_require_port(self._endpoint.port),
            generation=_require_generation(self._endpoint.generation),
            server_leaf_sha256=_require_sha256(
                self._endpoint.server_leaf_sha256,
                "reachy_server_leaf_invalid",
            ),
            client_certificate_sha256=_require_sha256(
                self._endpoint.client_certificate_sha256,
                "reachy_client_certificate_sha256_invalid",
            ),
        )

    def _require_unchanged_endpoint(self, snapshot: _EndpointSnapshot) -> None:
        if self._capture_endpoint() != snapshot:
            raise _TerminalCommissioningError("reachy_endpoint_changed")

    @staticmethod
    def _capture_outbound_keys(keys: OutboundKeys) -> _OutboundKeysSnapshot:
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

    def endpoint_url(self) -> str:
        endpoint = self._capture_endpoint()
        return f"wss://{endpoint.core_ipv4}:{endpoint.port}{APP_PATH}"

    @staticmethod
    def device_challenge_signing_payload(
        challenge: DeviceChallengeV1,
        client_nonce_b64: str,
    ) -> bytes:
        return _device_challenge_signing_payload(challenge, client_nonce_b64)

    async def connect_once(self) -> EdgeReachyConnection:
        endpoint = self._capture_endpoint()
        uri = f"wss://{endpoint.core_ipv4}:{endpoint.port}{APP_PATH}"
        socket = await self._connect_factory(
            uri,
            ssl=self._tls_context,
            server_hostname=endpoint.core_ipv4,
            subprotocols=[APP_SUBPROTOCOL],
            compression=None,
            ping_interval=None,
            proxy=None,
            open_timeout=5,
            close_timeout=2,
            max_size=MAX_WSS_MESSAGE_BYTES,
            max_queue=16,
        )
        try:
            self._require_unchanged_endpoint(endpoint)
            if socket.subprotocol != APP_SUBPROTOCOL:
                raise _TerminalCommissioningError("reachy_path_or_subprotocol")
            negotiated_tls_version, leaf_der = self._tls_peer_verifier(
                socket,
                endpoint.server_leaf_sha256,
            )
            self._require_unchanged_endpoint(endpoint)
            if negotiated_tls_version != "TLSv1.3":
                raise _TerminalCommissioningError("reachy_tls13_required")
            try:
                peer_leaf_sha256 = _verified_leaf_sha256(
                    leaf_der,
                    endpoint.server_leaf_sha256,
                    invalid_error="reachy_server_leaf_invalid",
                    mismatch_error="reachy_server_leaf_mismatch",
                )
                outbound_keys = self._capture_outbound_keys(
                    await self._pairing_keys.current_outbound(
                        tls_peer_sha256=peer_leaf_sha256,
                        now=self._clock.now(),
                    )
                )
            except PermissionError as error:
                raise _terminal_commissioning_from(error) from error
            self._require_unchanged_endpoint(endpoint)
            try:
                challenge = _parse_handshake_text(
                    DeviceChallengeV1,
                    await asyncio.wait_for(socket.recv(), timeout=self._handshake_timeout),
                )
            except PermissionError as error:
                raise _terminal_commissioning_from(error) from error
            self._require_unchanged_endpoint(endpoint)
            if challenge.endpoint_generation != endpoint.generation:
                raise _TerminalCommissioningError("device_challenge_generation")
            client_nonce = _fresh_nonce(self._nonce_factory, 32)
            client_nonce_b64 = base64.b64encode(client_nonce).decode("ascii")
            signature = outbound_keys.signer.sign(
                _device_challenge_signing_payload(challenge, client_nonce_b64)
            )
            proof = DeviceProofV1(
                schema_version="tuntun.reachy-device-proof.v1",
                client_nonce_b64=client_nonce_b64,
                signature_b64=base64.b64encode(signature).decode("ascii"),
            )
            await asyncio.wait_for(
                socket.send(canonical_bytes(proof).decode("utf-8")),
                timeout=self._handshake_timeout,
            )
            self._require_unchanged_endpoint(endpoint)
            try:
                accepted = _parse_handshake_text(
                    ChallengeAcceptedV1,
                    await asyncio.wait_for(socket.recv(), timeout=self._handshake_timeout),
                )
            except PermissionError as error:
                raise _terminal_commissioning_from(error) from error
            self._require_unchanged_endpoint(endpoint)
            try:
                connection_nonce = _expected_connection_nonce(
                    challenge,
                    client_nonce_b64,
                    proof_schema_version=proof.schema_version,
                    accepted_schema_version=accepted.schema_version,
                )
            except ValueError as error:
                raise _TerminalCommissioningError("connection_nonce_or_sequence") from error
            try:
                accepted_nonce = _strict_b64_32(
                    accepted.connection_nonce_b64,
                    "connection_nonce_or_sequence",
                )
            except ValueError as error:
                raise _TerminalCommissioningError("connection_nonce_or_sequence") from error
            if accepted_nonce != connection_nonce:
                raise _TerminalCommissioningError("connection_nonce_or_sequence")
            client_certificate_sha256 = _require_sha256(
                self._client_certificate_sha256(socket),
                "reachy_client_certificate_sha256_invalid",
            )
            self._require_unchanged_endpoint(endpoint)
            if not hmac.compare_digest(
                client_certificate_sha256, endpoint.client_certificate_sha256
            ):
                raise _TerminalCommissioningError("reachy_client_certificate_binding")
            return EdgeReachyConnection(
                socket=socket,
                connection_nonce=connection_nonce,
                outbound_keys=outbound_keys,
                inbound_key_resolver=self._pairing_keys,
                state=self._state,
                handler=self._handler,
                negotiated_tls_version=negotiated_tls_version,
                peer_leaf_sha256=peer_leaf_sha256,
                client_certificate_sha256=client_certificate_sha256,
                clock=self._clock,
                heartbeat_interval=self._heartbeat_interval,
                heartbeat_timeout=self._heartbeat_timeout,
                socket_close_timeout=self._socket_close_timeout,
                readiness=self._readiness,
            )
        except BaseException:
            await _close_bounded_suppressing_errors(
                socket,
                code=1008,
                reason="reachy_handshake_failed",
                timeout=self._socket_close_timeout,
            )
            raise

    async def run(
        self,
        stop: asyncio.Event,
        *,
        after_connect: Callable[[EdgeReachyConnection], object] | None = None,
    ) -> None:
        attempt = 0
        while not stop.is_set():
            connection: EdgeReachyConnection | None = None
            setup_complete = False
            try:
                connection = await self.connect_once()
                self.connection_history.append(connection.connection_nonce)
                if after_connect is not None:
                    maybe_awaitable = after_connect(connection)
                    if inspect.isawaitable(maybe_awaitable):
                        await maybe_awaitable
                setup_complete = True
                attempt = 0
                stopped = await self._serve_until_stop(connection, stop)
            except asyncio.CancelledError as error:
                cancel_close_failure: BaseException | None = None
                if connection is not None:
                    try:
                        close_cancellations = await _close_connection_observing_cancellation(
                            connection,
                            code=1011,
                            reason="edge_supervisor_cancelled",
                            on_factory_failure=self._record_task_factory_failure,
                            on_factory_unavailable=self._latch_task_factory_unavailable,
                        )
                    except _TaskFactoryUnavailable as close_error:
                        cancel_close_failure = close_error
                        close_cancellations = 0
                else:
                    close_cancellations = 0
                _failures, cleanup_cancellations = await self._complete_disconnect_cleanup()
                if cancel_close_failure is not None:
                    raise asyncio.CancelledError from cancel_close_failure
                if close_cancellations or cleanup_cancellations:
                    raise asyncio.CancelledError from error
                raise
            except _TerminalCommissioningError as error:
                _failures, cancellations = await self._complete_disconnect_cleanup()
                self._readiness.latch_disconnect_degraded(
                    (error.readiness_code,),
                    restart_required=True,
                )
                if cancellations:
                    raise asyncio.CancelledError from error
                raise
            except BaseException as error:
                close_cancellations = 0
                run_close_failure: BaseException | None = None
                if connection is not None:
                    try:
                        close_cancellations = await _close_connection_observing_cancellation(
                            connection,
                            code=1011,
                            reason=(
                                "edge_connection_failed"
                                if setup_complete
                                else "edge_connection_setup_failed"
                            ),
                            on_factory_failure=self._record_task_factory_failure,
                            on_factory_unavailable=self._latch_task_factory_unavailable,
                        )
                    except _TaskFactoryUnavailable as close_error:
                        run_close_failure = close_error
                _failures, cancellations = await self._complete_disconnect_cleanup()
                if run_close_failure is not None:
                    raise run_close_failure from error
                if close_cancellations or cancellations:
                    raise asyncio.CancelledError from error
                if not isinstance(error, Exception):
                    raise
                terminal_tls_code = _terminal_tls_commissioning_code(error)
                if terminal_tls_code is not None:
                    self._readiness.latch_disconnect_degraded(
                        (f"reachy_recommission_required:{terminal_tls_code}",),
                        restart_required=True,
                    )
                    raise
                if not _is_transient_reconnect_error(error, setup_complete=setup_complete):
                    raise
                if stop.is_set():
                    return
                delay = RECONNECT_DELAYS[min(attempt, len(RECONNECT_DELAYS) - 1)]
                attempt += 1
                await self._sleeper(delay)
                continue
            if stopped:
                _failures, cancellations = await self._complete_disconnect_cleanup()
                if cancellations:
                    raise asyncio.CancelledError
                return

    async def _serve_until_stop(
        self, connection: EdgeReachyConnection, stop: asyncio.Event
    ) -> bool:
        serve_task = self._spawn_supervisor_task(
            lambda: connection.serve(),
            name="edge_connection_serve",
        )
        try:
            stop_task = self._spawn_supervisor_task(
                stop.wait,
                name="edge_connection_stop_wait",
            )
        except BaseException:
            if not serve_task.done():
                serve_task.cancel()
                await _cancel_and_observe(serve_task)
            raise
        try:
            done, pending = await asyncio.wait(
                {serve_task, stop_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            if stop_task in done:
                await _cancel_and_observe(serve_task)
                await connection.close(code=1000, reason="edge_stopped")
                return True
            await _cancel_and_observe(stop_task)
            await serve_task
            return False
        finally:
            for task in (serve_task, stop_task):
                if not task.done():
                    task.cancel()
                    await _cancel_and_observe(task)

    def _record_task_factory_failure(self, name: str) -> None:
        self.task_factory_failure_points = tuple(
            dict.fromkeys((*self.task_factory_failure_points, name))
        )

    def _latch_task_factory_unavailable(self, code: str) -> None:
        self._readiness.latch_disconnect_degraded((code,), restart_required=True)

    def _spawn_supervisor_task(
        self,
        awaitable_factory: Callable[[], Coroutine[Any, Any, Any]],
        *,
        name: str,
    ) -> asyncio.Task[Any]:
        return _spawn_task_with_direct_fallback(
            awaitable_factory,
            name=name,
            on_factory_failure=self._record_task_factory_failure,
            on_factory_unavailable=self._latch_task_factory_unavailable,
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
        try:
            self._safety.latch_error_safe("transport_disconnect")
        except BaseException as error:
            failure = RuntimeError(f"local_error_safe_latch:{type(error).__name__}")
            self._readiness.latch_disconnect_degraded((str(failure),), restart_required=True)
            return (failure,)
        return ()

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
                cleanup_task = self._spawn_cleanup_owned(factory, name=f"edge_{name}")
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
                name="edge_outer_cleanup",
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


async def _connect_with_websockets(uri: str, **kwargs: object) -> WebSocketLike:
    try:
        module = importlib.import_module("websockets.asyncio.client")
    except ModuleNotFoundError as error:
        raise RuntimeError("websockets==15.0.1 is required for Reachy WSS transport") from error
    connect = cast(Callable[..., Awaitable[WebSocketLike]], cast(Any, module).connect)
    return await connect(uri, **kwargs)


def _default_server_leaf_verifier(
    socket: WebSocketLike,
    expected_sha256: str,
) -> tuple[str, bytes]:
    return require_server_leaf_sha256(_ssl_object(socket), expected_sha256)


def _ssl_object(socket: WebSocketLike) -> Any:
    transport = getattr(socket, "transport", None)
    getter = getattr(transport, "get_extra_info", None)
    if not callable(getter):
        raise PermissionError("reachy_tls_peer_unavailable")
    tls_connection = getter("ssl_object")
    if tls_connection is None:
        raise PermissionError("reachy_tls_peer_unavailable")
    return tls_connection


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


def _device_challenge_signing_payload(
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


def _terminal_commissioning_from(error: PermissionError) -> _TerminalCommissioningError:
    code = error.args[0] if error.args and type(error.args[0]) is str else type(error).__name__
    return _TerminalCommissioningError(code)


def _terminal_tls_commissioning_code(error: Exception) -> str | None:
    for candidate in _iter_exception_chain(error):
        if isinstance(candidate, ssl.SSLCertVerificationError):
            return "reachy_tls_certificate_verification"
        if isinstance(candidate, ssl.SSLError) and _is_terminal_tls_auth_error(candidate):
            return "reachy_tls_authentication"
    return None


def _iter_exception_chain(error: BaseException) -> Iterator[BaseException]:
    seen: set[int] = set()
    stack: list[BaseException] = [error]
    while stack:
        current = stack.pop()
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        yield current
        context = current.__context__ if not current.__suppress_context__ else None
        if context is not None:
            stack.append(context)
        if current.__cause__ is not None:
            stack.append(current.__cause__)


def _is_terminal_tls_auth_error(error: ssl.SSLError) -> bool:
    reason = getattr(error, "reason", None)
    return type(reason) is str and reason in _TERMINAL_TLS_AUTH_REASONS


def _is_transient_reconnect_error(error: Exception, *, setup_complete: bool) -> bool:
    if setup_complete:
        return not isinstance(error, _TaskFactoryUnavailable)
    if isinstance(error, PermissionError):
        return False
    return isinstance(error, (ConnectionError, TimeoutError, OSError))


def _fresh_nonce(factory: Callable[[int], bytes], size: int) -> bytes:
    value = factory(size)
    if type(value) is not bytes or len(value) != size:
        raise ValueError("reachy_nonce_size")
    return bytes(value)


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


def _close_unstarted_awaitable(awaitable: Awaitable[Any]) -> None:
    close = getattr(awaitable, "close", None)
    if callable(close):
        close()


def _spawn_task_with_direct_fallback(
    awaitable_factory: Callable[[], Coroutine[Any, Any, Any]],
    *,
    name: str,
    on_factory_failure: Callable[[str], None] | None = None,
    on_factory_unavailable: Callable[[str], None] | None = None,
) -> asyncio.Task[Any]:
    awaitable = awaitable_factory()
    try:
        return asyncio.create_task(awaitable, name=name)
    except BaseException as error:
        _close_unstarted_awaitable(awaitable)
        if not isinstance(error, Exception):
            raise
        if on_factory_failure is not None:
            on_factory_failure(name)
    fallback = awaitable_factory()
    try:
        return asyncio.Task(fallback, loop=asyncio.get_running_loop(), name=name)
    except BaseException as error:
        _close_unstarted_awaitable(fallback)
        if not isinstance(error, Exception):
            raise
        code = f"{name}:factory_unavailable"
        if on_factory_unavailable is not None:
            on_factory_unavailable(code)
        raise _TaskFactoryUnavailable(code) from error


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


async def _close_connection_observing_cancellation(
    connection: EdgeReachyConnection,
    *,
    code: int,
    reason: str,
    on_factory_failure: Callable[[str], None] | None = None,
    on_factory_unavailable: Callable[[str], None] | None = None,
) -> int:
    close_task = _spawn_task_with_direct_fallback(
        lambda: connection.close(code=code, reason=reason),
        name="edge_connection_close",
        on_factory_failure=on_factory_failure,
        on_factory_unavailable=on_factory_unavailable,
    )
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


async def _cancel_and_observe(task: asyncio.Task[object]) -> None:
    if not task.done():
        task.cancel()
    with contextlib.suppress(BaseException):
        await task


__all__ = (
    "APP_PATH",
    "APP_SUBPROTOCOL",
    "EdgeReachyConnection",
    "EdgeTransportSupervisorState",
    "MAX_CONTROL_FRAME_JSON_BYTES",
    "RECONNECT_DELAYS",
    "ReachyWssClient",
)
