from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from tuntun_contracts.base import canonical_bytes, canonical_mapping_bytes, parse_contract_json
from tuntun_contracts.reachy_time import CoreTimeProofV1, CoreTimeRequestV1
from tuntun_contracts.reachy_wire import (
    ChallengeAcceptedV1,
    DeviceChallengeV1,
    DeviceProofV1,
    sign_control_frame,
)

NOW = datetime(2026, 8, 27, 1, 2, 3, 4, tzinfo=UTC)
DEVICE_ID = UUID("00000000-0000-0000-0000-00000000a010")
OTHER_DEVICE_ID = UUID("00000000-0000-0000-0000-00000000a020")
SERVER_KEY_ID = "ed25519:reachy-core:v1"
DEVICE_SIGNING_KEY_ID = "ed25519:reachy-edge:v1"
HMAC_KEY_ID = "reachy-frame-hmac:v1"
SERVER_LEAF_DER = b"server-leaf"
CLIENT_CERTIFICATE_DER = b"client-leaf"
SERVER_LEAF_SHA256 = hashlib.sha256(SERVER_LEAF_DER).hexdigest()
CLIENT_CERTIFICATE_SHA256 = hashlib.sha256(CLIENT_CERTIFICATE_DER).hexdigest()
SERVER_PUBLIC_KEY_SHA256 = "3" * 64
DEVICE_PUBLIC_KEY_SHA256 = "4" * 64
HMAC_SHA256 = "5" * 64
HOUSEHOLD_CA_SHA256 = "6" * 64
DEVICE_PROOF_SCHEMA = "tuntun.reachy-device-proof.v1"
CHALLENGE_ACCEPTED_SCHEMA = "tuntun.reachy-challenge-accepted.v1"
HANDSHAKE_SIGNATURE_PAYLOAD_SCHEMA = "tuntun.reachy-device-challenge-signing-payload.v1"
HANDSHAKE_SIGNATURE_DOMAIN = "tuntun.reachy.wss.device-challenge-signature.v1"


@dataclass(frozen=True, slots=True)
class Endpoint:
    core_ipv4: str = "192.168.50.10"
    port: int = 7443
    generation: int = 1
    certificate_generation: int = 1
    server_key_generation: int = 1
    trust_digest_generation: int = 1
    client_tls_key_generation: int = 1
    device_signing_key_generation: int = 1
    hmac_key_generation: int = 1
    server_leaf_sha256: str = SERVER_LEAF_SHA256
    client_certificate_sha256: str = CLIENT_CERTIFICATE_SHA256
    server_key_id: str = SERVER_KEY_ID
    server_public_key_sha256: str = SERVER_PUBLIC_KEY_SHA256
    client_tls_key_id: str = "reachy-client-tls:v1"
    device_signing_key_id: str = DEVICE_SIGNING_KEY_ID
    device_signing_public_key_sha256: str = DEVICE_PUBLIC_KEY_SHA256
    hmac_key_id: str = HMAC_KEY_ID
    hmac_key_sha256: str = HMAC_SHA256
    household_ca_sha256: str = HOUSEHOLD_CA_SHA256


class MutableEndpoint:
    def __init__(self) -> None:
        self.core_ipv4 = "192.168.50.10"
        self.port = 7443
        self.generation = 1
        self.server_leaf_sha256 = SERVER_LEAF_SHA256
        self.client_certificate_sha256 = CLIENT_CERTIFICATE_SHA256
        self.device_signing_key_id = DEVICE_SIGNING_KEY_ID
        self.hmac_key_id = HMAC_KEY_ID


class Clock:
    def now(self) -> datetime:
        return NOW


class OutboundKeys:
    def __init__(self, signer: Ed25519PrivateKey, hmac_root: bytes) -> None:
        self.signer = signer
        self.signing_key_id = DEVICE_SIGNING_KEY_ID
        self.hmac_root = hmac_root
        self.hmac_key_id = HMAC_KEY_ID


class CoreOutboundKeys:
    def __init__(self, signer: Ed25519PrivateKey, hmac_root: bytes) -> None:
        self.signer = signer
        self.signing_key_id = SERVER_KEY_ID
        self.hmac_root = hmac_root
        self.hmac_key_id = HMAC_KEY_ID


class EdgePairingKeys:
    def __init__(self, signer: Ed25519PrivateKey, *, hmac_root: bytes = b"h" * 32) -> None:
        self.signer = signer
        self.hmac_root = hmac_root
        self.tls_peers: list[str] = []

    async def current_outbound(self, *, tls_peer_sha256: str, now: datetime) -> OutboundKeys:
        assert now == NOW
        self.tls_peers.append(tls_peer_sha256)
        if tls_peer_sha256 != SERVER_LEAF_SHA256:
            raise PermissionError("pairing_key_binding")
        return OutboundKeys(self.signer, self.hmac_root)

    async def resolve_frame(
        self,
        _frame: object,
        *,
        tls_peer_sha256: str,
        now: datetime,
    ) -> Any:
        assert tls_peer_sha256 == SERVER_LEAF_SHA256
        assert now == NOW
        return type(
            "InboundKeys",
            (),
            {
                "public_key": self.signer.public_key(),
                "signing_key_id": SERVER_KEY_ID,
                "hmac_key_id": HMAC_KEY_ID,
                "hmac_root": self.hmac_root,
            },
        )()


class CorePairingKeys:
    def __init__(self, device_signer: Ed25519PrivateKey, server_signer: Ed25519PrivateKey) -> None:
        self.device_signer = device_signer
        self.server_signer = server_signer
        self.hmac_root = b"h" * 32
        self.inbound_resolutions = 0
        self.outbound_resolutions = 0

    async def current_outbound(
        self,
        *,
        device_id: UUID,
        tls_peer_sha256: str,
        now: datetime,
    ) -> CoreOutboundKeys:
        assert device_id == DEVICE_ID
        assert tls_peer_sha256 == CLIENT_CERTIFICATE_SHA256
        assert now == NOW
        self.outbound_resolutions += 1
        return CoreOutboundKeys(self.server_signer, self.hmac_root)

    async def resolve_inbound(
        self,
        *,
        device_id: UUID,
        tls_peer_sha256: str,
        signing_key_id: str,
        hmac_key_id: str,
        now: datetime,
    ) -> Any:
        assert device_id == DEVICE_ID
        assert tls_peer_sha256 == CLIENT_CERTIFICATE_SHA256
        assert signing_key_id == DEVICE_SIGNING_KEY_ID
        assert hmac_key_id == HMAC_KEY_ID
        assert now == NOW
        self.inbound_resolutions += 1
        return type(
            "InboundKeys",
            (),
            {
                "public_key": self.device_signer.public_key(),
                "signing_key_id": DEVICE_SIGNING_KEY_ID,
                "hmac_key_id": HMAC_KEY_ID,
                "hmac_root": self.hmac_root,
            },
        )()


class PermissiveCorePairingKeys(CorePairingKeys):
    def __init__(self, device_signer: Ed25519PrivateKey, server_signer: Ed25519PrivateKey) -> None:
        super().__init__(device_signer, server_signer)
        self.inbound_arguments: list[tuple[str, str]] = []

    async def resolve_inbound(
        self,
        *,
        device_id: UUID,
        tls_peer_sha256: str,
        signing_key_id: str,
        hmac_key_id: str,
        now: datetime,
    ) -> Any:
        assert device_id == DEVICE_ID
        assert tls_peer_sha256 == CLIENT_CERTIFICATE_SHA256
        assert now == NOW
        self.inbound_resolutions += 1
        self.inbound_arguments.append((signing_key_id, hmac_key_id))
        return type(
            "InboundKeys",
            (),
            {
                "public_key": self.device_signer.public_key(),
                "signing_key_id": signing_key_id,
                "hmac_key_id": hmac_key_id,
                "hmac_root": self.hmac_root,
            },
        )()


class DeviceMutatingPairingKeys(CorePairingKeys):
    def __init__(
        self,
        device: MutableDevice,
        device_signer: Ed25519PrivateKey,
        server_signer: Ed25519PrivateKey,
    ) -> None:
        super().__init__(device_signer, server_signer)
        self.device = device

    async def current_outbound(
        self,
        *,
        device_id: UUID,
        tls_peer_sha256: str,
        now: datetime,
    ) -> CoreOutboundKeys:
        outbound = await super().current_outbound(
            device_id=device_id,
            tls_peer_sha256=tls_peer_sha256,
            now=now,
        )
        self.device.device_id = OTHER_DEVICE_ID
        return outbound


class OutboundMutatingPairingKeys(CorePairingKeys):
    def __init__(self, device_signer: Ed25519PrivateKey, server_signer: Ed25519PrivateKey) -> None:
        super().__init__(device_signer, server_signer)
        self.outbound = CoreOutboundKeys(server_signer, b"h" * 32)

    async def current_outbound(
        self,
        *,
        device_id: UUID,
        tls_peer_sha256: str,
        now: datetime,
    ) -> CoreOutboundKeys:
        assert device_id == DEVICE_ID
        assert tls_peer_sha256 == CLIENT_CERTIFICATE_SHA256
        assert now == NOW
        self.outbound_resolutions += 1
        return self.outbound


class FakeState:
    def __init__(self) -> None:
        self.abandoned: list[str] = []

    async def reserve_outbound(self, _correlation_id: UUID, _purpose: str, _kind: str) -> int:
        return 1

    async def accept_inbound(
        self,
        _sequence: int,
        _correlation_id: UUID,
        _purpose: str,
        _kind: str,
    ) -> None:
        return None

    async def accept_response(
        self,
        _correlation_id: UUID,
        _purpose: str,
        _payload: bytes,
    ) -> None:
        return None

    async def complete(self, _correlation_id: UUID) -> None:
        return None

    async def abandon_connection(self, reason: str) -> None:
        self.abandoned.append(reason)


class HangingAbandonState(FakeState):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()

    async def abandon_connection(self, reason: str) -> None:
        self.abandoned.append(reason)
        self.started.set()
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            self.cancelled.set()
            raise


class FakeSafety:
    def __init__(self) -> None:
        self.latched: list[str] = []
        self.closed = 0

    def latch_error_safe(self, reason: str) -> None:
        self.latched.append(reason)

    async def close_media_stop_playback_motion_and_forget_turn(self) -> None:
        self.closed += 1


class FakeHandler:
    def __init__(self) -> None:
        self.control_calls: list[tuple[str, bytes]] = []
        self.media_calls: list[bytes] = []

    async def control(self, purpose: str, payload: bytes) -> bytes:
        self.control_calls.append((purpose, payload))
        return b'{"accepted":true}'

    async def media(self, frame: bytes) -> None:
        self.media_calls.append(frame)


class FakeReadiness:
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
        self.disconnect_degraded_codes = (*self.disconnect_degraded_codes, *codes)
        self.restart_required = self.restart_required or restart_required


class FakeConnector:
    def __init__(self, sockets: list[ClientSocket]) -> None:
        self.sockets = sockets
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def __call__(self, uri: str, **kwargs: object) -> ClientSocket:
        self.calls.append((uri, kwargs))
        if not self.sockets:
            raise AssertionError("unexpected extra connect")
        return self.sockets.pop(0)


class ScriptedConnector:
    def __init__(self, steps: list[ClientSocket | Exception]) -> None:
        self.steps = steps
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def __call__(self, uri: str, **kwargs: object) -> ClientSocket:
        self.calls.append((uri, kwargs))
        if not self.steps:
            raise AssertionError("unexpected extra connect")
        step = self.steps.pop(0)
        if isinstance(step, Exception):
            raise step
        return step


class MutatingConnector(FakeConnector):
    def __init__(self, endpoint: MutableEndpoint, sockets: list[ClientSocket]) -> None:
        super().__init__(sockets)
        self.endpoint = endpoint

    async def __call__(self, uri: str, **kwargs: object) -> ClientSocket:
        socket = await super().__call__(uri, **kwargs)
        self.endpoint.generation = 2
        return socket


class ClientSocket:
    def __init__(self, challenge: DeviceChallengeV1, accepted: ChallengeAcceptedV1) -> None:
        self.challenge = challenge
        self.accepted = accepted
        self.sent: list[str] = []
        self.closed: list[tuple[int, str]] = []
        self.subprotocol: str | None = "tuntun.reachy.v1"
        self.transport: object = object()
        self.ping_count = 0

    async def recv(self) -> str:
        if not self.sent:
            return canonical_bytes(self.challenge).decode("utf-8")
        return canonical_bytes(self.accepted).decode("utf-8")

    async def send(self, message: str | bytes) -> None:
        if isinstance(message, bytes):
            message = message.decode("utf-8")
        self.sent.append(message)

    def ping(self, payload: bytes) -> Awaitable[None]:
        assert len(payload) == 8
        self.ping_count += 1
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        return future

    async def close(self, *, code: int = 1000, reason: str = "") -> None:
        self.closed.append((code, reason))

    def __aiter__(self) -> ClientSocket:
        return self

    async def __anext__(self) -> str:
        await asyncio.sleep(3600)
        raise StopAsyncIteration


class HangingHandshakeSocket(ClientSocket):
    def __init__(self, challenge: DeviceChallengeV1, accepted: ChallengeAcceptedV1) -> None:
        super().__init__(challenge, accepted)
        self.close_started = asyncio.Event()

    async def recv(self) -> str:
        await asyncio.sleep(3600)
        raise AssertionError("unreachable")

    async def close(self, *, code: int = 1000, reason: str = "") -> None:
        self.close_started.set()
        await asyncio.sleep(3600)


class HangingClientSendSocket(ClientSocket):
    def __init__(self, challenge: DeviceChallengeV1, accepted: ChallengeAcceptedV1) -> None:
        super().__init__(challenge, accepted)
        self.send_started = asyncio.Event()

    async def send(self, message: str | bytes) -> None:
        assert message
        self.send_started.set()
        await asyncio.sleep(3600)


class ScriptedApplicationSocket(ClientSocket):
    def __init__(
        self,
        challenge: DeviceChallengeV1,
        accepted: ChallengeAcceptedV1,
        incoming: list[str | bytes | BaseException],
    ) -> None:
        super().__init__(challenge, accepted)
        self.incoming = incoming

    async def __anext__(self) -> str | bytes:
        if not self.incoming:
            await asyncio.sleep(3600)
            raise StopAsyncIteration
        item = self.incoming.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


class HangingApplicationSendSocket(ScriptedApplicationSocket):
    def __init__(
        self,
        challenge: DeviceChallengeV1,
        accepted: ChallengeAcceptedV1,
        incoming: list[str | bytes | BaseException],
        *,
        hang_on_send: int,
    ) -> None:
        super().__init__(challenge, accepted, incoming)
        self.hang_on_send = hang_on_send
        self.send_attempts = 0
        self.hanging_send_started = asyncio.Event()

    async def send(self, message: str | bytes) -> None:
        assert message
        self.send_attempts += 1
        if self.send_attempts == self.hang_on_send:
            self.hanging_send_started.set()
            await asyncio.sleep(3600)
        await super().send(message)


def _accepted_for(
    challenge: DeviceChallengeV1,
    *,
    client_nonce: bytes,
) -> ChallengeAcceptedV1:
    client_nonce_b64 = base64.b64encode(client_nonce).decode("ascii")
    connection_nonce = _expected_raw_connection_nonce(challenge, client_nonce_b64)
    return ChallengeAcceptedV1(
        schema_version=CHALLENGE_ACCEPTED_SCHEMA,
        connection_nonce_b64=base64.b64encode(connection_nonce).decode("ascii"),
    )


def _challenge(*, generation: int = 1, marker: bytes = b"a") -> DeviceChallengeV1:
    return DeviceChallengeV1(
        schema_version="tuntun.reachy-device-challenge.v1",
        challenge_b64=base64.b64encode(marker * 32).decode("ascii"),
        server_nonce_b64=base64.b64encode(bytes(reversed(marker * 32))).decode("ascii"),
        endpoint_generation=generation,
    )


def _expected_bound_device_challenge_payload(
    challenge: DeviceChallengeV1,
    client_nonce_b64: str,
    *,
    route: str = "/v1/reachy",
    subprotocol: str = "tuntun.reachy.v1",
    proof_schema_version: str = DEVICE_PROOF_SCHEMA,
) -> bytes:
    return canonical_mapping_bytes(
        {
            "schema_version": HANDSHAKE_SIGNATURE_PAYLOAD_SCHEMA,
            "domain": HANDSHAKE_SIGNATURE_DOMAIN,
            "route": route,
            "subprotocol": subprotocol,
            "challenge_schema_version": challenge.schema_version,
            "proof_schema_version": proof_schema_version,
            "challenge_b64": challenge.challenge_b64,
            "server_nonce_b64": challenge.server_nonce_b64,
            "client_nonce_b64": client_nonce_b64,
            "endpoint_generation": challenge.endpoint_generation,
        }
    )


def _expected_raw_connection_nonce(
    challenge: DeviceChallengeV1,
    client_nonce_b64: str,
) -> bytes:
    challenge_nonce = base64.b64decode(challenge.challenge_b64, validate=True)
    server_nonce = base64.b64decode(challenge.server_nonce_b64, validate=True)
    client_nonce = base64.b64decode(client_nonce_b64, validate=True)
    if len(challenge_nonce) != 32 or len(server_nonce) != 32 or len(client_nonce) != 32:
        raise ValueError("connection_nonce_or_sequence")
    return hashlib.sha256(challenge_nonce + server_nonce + client_nonce).digest()


def _legacy_device_challenge_payload(
    challenge: DeviceChallengeV1,
    client_nonce_b64: str,
) -> bytes:
    return canonical_mapping_bytes(
        {
            "challenge_b64": challenge.challenge_b64,
            "server_nonce_b64": challenge.server_nonce_b64,
            "client_nonce_b64": client_nonce_b64,
            "endpoint_generation": challenge.endpoint_generation,
        }
    )


def _signed_core_request(
    signer: Ed25519PrivateKey,
    *,
    connection_nonce: bytes,
    payload: bytes = b'{"request":true}',
) -> str:
    frame = sign_control_frame(
        signer,
        b"h" * 32,
        signing_key_id=SERVER_KEY_ID,
        hmac_key_id=HMAC_KEY_ID,
        direction="core_to_edge",
        kind="request",
        connection_nonce=connection_nonce,
        sequence=1,
        correlation_id=UUID("00000000-0000-0000-0000-00000000a011"),
        purpose="reachy.command.v1",
        payload=payload,
    )
    return canonical_bytes(frame).decode("utf-8")


def test_client_rejects_non_numeric_or_non_rfc1918_endpoints_before_connect() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    rejected = (
        "reachy-mini.local",
        "localhost",
        "127.0.0.1",
        "8.8.8.8",
        "192.168.050.10",
        "::1",
    )
    for host in rejected:
        client = ReachyWssClient(
            Endpoint(core_ipv4=host),
            tls_context=object(),
            pairing_keys=EdgePairingKeys(Ed25519PrivateKey.generate()),
            state=FakeState(),
            safety=FakeSafety(),
            handler=FakeHandler(),
            readiness=FakeReadiness(),
            clock=Clock(),
            connect_factory=FakeConnector([]),
        )
        with pytest.raises(ValueError, match="reachy_core_endpoint_numeric_rfc1918_ipv4_required"):
            client.endpoint_url()


@pytest.mark.asyncio
async def test_connect_once_dials_exact_numeric_wss_and_disables_proxy_env() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    signer = Ed25519PrivateKey.generate()
    client_nonce = b"c" * 32
    challenge = _challenge(marker=b"d")
    socket = ClientSocket(challenge, _accepted_for(challenge, client_nonce=client_nonce))
    connector = FakeConnector([socket])
    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(signer),
        state=FakeState(),
        safety=FakeSafety(),
        handler=FakeHandler(),
        readiness=FakeReadiness(),
        clock=Clock(),
        connect_factory=connector,
        tls_peer_verifier=lambda _socket, expected: ("TLSv1.3", SERVER_LEAF_DER),
        client_certificate_sha256=lambda _socket: CLIENT_CERTIFICATE_SHA256,
        nonce_factory=lambda size: client_nonce if size == 32 else b"",
    )

    connection = await client.connect_once()

    assert connector.calls == [
        (
            "wss://192.168.50.10:7443/v1/reachy",
            {
                "ssl": client._tls_context,
                "server_hostname": "192.168.50.10",
                "subprotocols": ["tuntun.reachy.v1"],
                "compression": None,
                "ping_interval": None,
                "proxy": None,
                "open_timeout": 5,
                "close_timeout": 2,
                "max_size": 1052684,
                "max_queue": 16,
            },
        )
    ]
    assert connection.connection_nonce == base64.b64decode(
        socket.accepted.connection_nonce_b64,
        validate=True,
    )
    assert connection.negotiated_tls_version == "TLSv1.3"
    assert connection.peer_leaf_sha256 == SERVER_LEAF_SHA256
    assert connection.client_certificate_sha256 == CLIENT_CERTIFICATE_SHA256
    proof = parse_contract_json(
        DeviceProofV1,
        socket.sent[0].encode("utf-8"),
        max_bytes=8_192,
        require_canonical=True,
    )
    signer.public_key().verify(
        base64.b64decode(proof.signature_b64, validate=True),
        client.device_challenge_signing_payload(challenge, proof.client_nonce_b64),
    )


@pytest.mark.asyncio
async def test_connect_once_rejects_endpoint_mutation_after_connect_before_proof() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    signer = Ed25519PrivateKey.generate()
    client_nonce = b"u" * 32
    challenge = _challenge(generation=2, marker=b"u")
    socket = ClientSocket(challenge, _accepted_for(challenge, client_nonce=client_nonce))
    endpoint = MutableEndpoint()
    client = ReachyWssClient(
        endpoint,
        tls_context=object(),
        pairing_keys=EdgePairingKeys(signer),
        state=FakeState(),
        safety=FakeSafety(),
        handler=FakeHandler(),
        readiness=FakeReadiness(),
        clock=Clock(),
        connect_factory=MutatingConnector(endpoint, [socket]),
        tls_peer_verifier=lambda _socket, expected: ("TLSv1.3", SERVER_LEAF_DER),
        client_certificate_sha256=lambda _socket: CLIENT_CERTIFICATE_SHA256,
        nonce_factory=lambda size: client_nonce if size == 32 else b"",
    )

    with pytest.raises(PermissionError, match="reachy_endpoint_changed"):
        await client.connect_once()

    assert socket.sent == []
    assert socket.closed == [(1008, "reachy_handshake_failed")]


@pytest.mark.asyncio
async def test_connect_once_bounds_device_proof_send_and_closes_socket() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    signer = Ed25519PrivateKey.generate()
    client_nonce = b"b" * 32
    challenge = _challenge(marker=b"b")
    socket = HangingClientSendSocket(
        challenge,
        _accepted_for(challenge, client_nonce=client_nonce),
    )
    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(signer),
        state=FakeState(),
        safety=FakeSafety(),
        handler=FakeHandler(),
        readiness=FakeReadiness(),
        clock=Clock(),
        connect_factory=FakeConnector([socket]),
        tls_peer_verifier=lambda _socket, expected: ("TLSv1.3", SERVER_LEAF_DER),
        client_certificate_sha256=lambda _socket: CLIENT_CERTIFICATE_SHA256,
        nonce_factory=lambda size: client_nonce if size == 32 else b"",
        handshake_timeout=0.001,
    )

    started = asyncio.get_running_loop().time()
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(client.connect_once(), timeout=0.2)

    assert asyncio.get_running_loop().time() - started < 0.1
    assert socket.send_started.is_set()
    assert socket.closed == [(1008, "reachy_handshake_failed")]


def test_device_challenge_signing_payload_binds_schema_domain_route_and_subprotocol() -> None:
    import tuntun_core.adapters.reachy.wss_server as core_wss
    from tuntun_edge.transport.websocket import ReachyWssClient

    challenge = _challenge(marker=b"p")
    client_nonce_b64 = base64.b64encode(b"p" * 32).decode("ascii")

    edge_payload = ReachyWssClient.device_challenge_signing_payload(
        challenge,
        client_nonce_b64,
    )
    core_payload = core_wss.device_challenge_signing_payload(challenge, client_nonce_b64)

    assert edge_payload == core_payload
    payload = json.loads(edge_payload)
    assert payload == {
        "schema_version": HANDSHAKE_SIGNATURE_PAYLOAD_SCHEMA,
        "domain": HANDSHAKE_SIGNATURE_DOMAIN,
        "route": core_wss.APP_PATH,
        "subprotocol": core_wss.APP_SUBPROTOCOL,
        "challenge_schema_version": challenge.schema_version,
        "proof_schema_version": DEVICE_PROOF_SCHEMA,
        "challenge_b64": challenge.challenge_b64,
        "server_nonce_b64": challenge.server_nonce_b64,
        "client_nonce_b64": client_nonce_b64,
        "endpoint_generation": challenge.endpoint_generation,
    }


def test_wss_max_message_bytes_covers_largest_binary_media_frame() -> None:
    import tuntun_core.adapters.reachy.wss_server as core_wss
    import tuntun_edge.transport.websocket as edge_wss
    from tuntun_contracts.reachy_media import MAX_CAMERA_PAYLOAD, MAX_HEADER, PREFIX

    expected = PREFIX.size + MAX_HEADER + MAX_CAMERA_PAYLOAD

    assert expected == 1_052_684
    assert expected == core_wss.MAX_WSS_MESSAGE_BYTES
    assert expected == edge_wss.MAX_WSS_MESSAGE_BYTES


@pytest.mark.asyncio
async def test_connect_once_times_out_handshake_and_bounds_failed_close() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    signer = Ed25519PrivateKey.generate()
    client_nonce = b"c" * 32
    challenge = _challenge(marker=b"t")
    socket = HangingHandshakeSocket(
        challenge,
        _accepted_for(challenge, client_nonce=client_nonce),
    )
    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(signer),
        state=FakeState(),
        safety=FakeSafety(),
        handler=FakeHandler(),
        readiness=FakeReadiness(),
        clock=Clock(),
        connect_factory=FakeConnector([socket]),
        tls_peer_verifier=lambda _socket, expected: ("TLSv1.3", SERVER_LEAF_DER),
        client_certificate_sha256=lambda _socket: CLIENT_CERTIFICATE_SHA256,
        nonce_factory=lambda size: client_nonce if size == 32 else b"",
        handshake_timeout=0.001,
        socket_close_timeout=0.001,
    )

    with pytest.raises(TimeoutError):
        await client.connect_once()

    assert socket.close_started.is_set()
    assert socket.sent == []


@pytest.mark.asyncio
async def test_connect_once_rejects_mismatched_server_leaf_der_from_verifier() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    signer = Ed25519PrivateKey.generate()
    client_nonce = b"c" * 32
    challenge = _challenge(marker=b"v")
    socket = ClientSocket(challenge, _accepted_for(challenge, client_nonce=client_nonce))
    pairing_keys = EdgePairingKeys(signer)
    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=pairing_keys,
        state=FakeState(),
        safety=FakeSafety(),
        handler=FakeHandler(),
        readiness=FakeReadiness(),
        clock=Clock(),
        connect_factory=FakeConnector([socket]),
        tls_peer_verifier=lambda _socket, expected: ("TLSv1.3", b"wrong-server-leaf"),
        client_certificate_sha256=lambda _socket: CLIENT_CERTIFICATE_SHA256,
        nonce_factory=lambda size: client_nonce if size == 32 else b"",
    )

    with pytest.raises(PermissionError, match="reachy_server_leaf_mismatch"):
        await client.connect_once()

    assert pairing_keys.tls_peers == []
    assert socket.sent == []
    assert socket.closed == [(1008, "reachy_handshake_failed")]


def test_client_rejects_non_finite_or_unbounded_timing_config() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    for kwargs in (
        {"heartbeat_interval": True},
        {"heartbeat_timeout": float("nan")},
        {"heartbeat_interval": 0.001, "heartbeat_timeout": 0.002},
        {"heartbeat_interval": 61.0},
        {"handshake_timeout": 2.1},
        {"socket_close_timeout": float("inf")},
    ):
        with pytest.raises(ValueError):
            ReachyWssClient(
                Endpoint(),
                tls_context=object(),
                pairing_keys=EdgePairingKeys(Ed25519PrivateKey.generate()),
                state=FakeState(),
                safety=FakeSafety(),
                handler=FakeHandler(),
                readiness=FakeReadiness(),
                clock=Clock(),
                connect_factory=FakeConnector([]),
                **kwargs,
            )


@pytest.mark.asyncio
async def test_run_treats_generation_mismatch_as_terminal_recommission() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    signer = Ed25519PrivateKey.generate()
    client_nonce = b"r" * 32
    stale = ClientSocket(
        _challenge(generation=99, marker=b"x"),
        _accepted_for(_challenge(marker=b"x"), client_nonce=client_nonce),
    )
    state = FakeState()
    safety = FakeSafety()
    readiness = FakeReadiness()
    sleeps: list[float] = []
    stop = asyncio.Event()
    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(signer),
        state=state,
        safety=safety,
        handler=FakeHandler(),
        readiness=readiness,
        clock=Clock(),
        connect_factory=FakeConnector([stale]),
        tls_peer_verifier=lambda _socket, expected: ("TLSv1.3", SERVER_LEAF_DER),
        client_certificate_sha256=lambda _socket: CLIENT_CERTIFICATE_SHA256,
        nonce_factory=lambda size: client_nonce if size == 32 else b"",
        sleeper=lambda delay: _record_sleep(sleeps, delay),
    )

    with pytest.raises(PermissionError, match="device_challenge_generation"):
        await asyncio.wait_for(
            client.run(stop, after_connect=lambda _connection: stop.set()),
            timeout=0.1,
        )

    assert stale.closed == [(1008, "reachy_handshake_failed")]
    assert safety.latched == ["transport_disconnect"]
    assert state.abandoned == ["disconnect"]
    assert sleeps == []
    assert client.connection_history == []
    assert readiness.disconnect_degraded_codes == (
        "reachy_recommission_required:device_challenge_generation",
    )
    assert readiness.restart_required is True


@pytest.mark.asyncio
async def test_run_closes_live_connection_and_propagates_callback_failure() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    signer = Ed25519PrivateKey.generate()
    first_nonce = b"q" * 32
    first_challenge = _challenge(marker=b"q")
    first = ClientSocket(first_challenge, _accepted_for(first_challenge, client_nonce=first_nonce))
    state = FakeState()
    safety = FakeSafety()
    sleeps: list[float] = []
    stop = asyncio.Event()

    def callback(_connection: object) -> None:
        raise RuntimeError("callback failed")

    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(signer),
        state=state,
        safety=safety,
        handler=FakeHandler(),
        readiness=FakeReadiness(),
        clock=Clock(),
        connect_factory=FakeConnector([first]),
        tls_peer_verifier=lambda _socket, expected: ("TLSv1.3", SERVER_LEAF_DER),
        client_certificate_sha256=lambda _socket: CLIENT_CERTIFICATE_SHA256,
        nonce_factory=lambda size: first_nonce if size == 32 else b"",
        sleeper=lambda delay: _record_sleep(sleeps, delay),
    )

    with pytest.raises(RuntimeError, match="callback failed"):
        await asyncio.wait_for(client.run(stop, after_connect=callback), timeout=0.1)

    assert first.closed == [(1011, "edge_connection_setup_failed")]
    assert safety.latched == ["transport_disconnect"]
    assert state.abandoned == ["disconnect"]
    assert sleeps == []
    assert len(client.connection_history) == 1


@pytest.mark.asyncio
async def test_run_clean_stop_performs_disconnect_cleanup_before_return() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    signer = Ed25519PrivateKey.generate()
    client_nonce = b"k" * 32
    challenge = _challenge(marker=b"k")
    socket = ClientSocket(challenge, _accepted_for(challenge, client_nonce=client_nonce))
    state = FakeState()
    safety = FakeSafety()
    stop = asyncio.Event()
    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(signer),
        state=state,
        safety=safety,
        handler=FakeHandler(),
        readiness=FakeReadiness(),
        clock=Clock(),
        connect_factory=FakeConnector([socket]),
        tls_peer_verifier=lambda _socket, expected: ("TLSv1.3", SERVER_LEAF_DER),
        client_certificate_sha256=lambda _socket: CLIENT_CERTIFICATE_SHA256,
        nonce_factory=lambda size: client_nonce if size == 32 else b"",
    )

    await asyncio.wait_for(
        client.run(stop, after_connect=lambda _connection: stop.set()),
        timeout=0.1,
    )

    assert socket.closed == [(1000, "edge_stopped")]
    assert safety.latched == ["transport_disconnect"]
    assert safety.closed == 1
    assert state.abandoned == ["disconnect"]


class FatalTransportExit(BaseException):
    pass


class FatalConnector:
    async def __call__(self, uri: str, **_kwargs: object) -> ClientSocket:
        assert uri
        raise FatalTransportExit


class ReasonedTlsAuthError(ssl.SSLError):
    @property
    def reason(self) -> str:
        return "TLSV1_ALERT_UNKNOWN_CA"


@pytest.mark.asyncio
async def test_run_re_raises_fatal_base_exception_after_cleanup() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    state = FakeState()
    safety = FakeSafety()
    sleeps: list[float] = []
    stop = asyncio.Event()

    async def stop_if_fatal_is_swallowed(delay: float) -> None:
        sleeps.append(delay)
        stop.set()

    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(Ed25519PrivateKey.generate()),
        state=state,
        safety=safety,
        handler=FakeHandler(),
        readiness=FakeReadiness(),
        clock=Clock(),
        connect_factory=FatalConnector(),
        sleeper=stop_if_fatal_is_swallowed,
    )

    with pytest.raises(FatalTransportExit):
        await client.run(stop)

    assert safety.latched == ["transport_disconnect"]
    assert state.abandoned == ["disconnect"]
    assert sleeps == []


@pytest.mark.asyncio
async def test_run_treats_presocket_certificate_verification_as_terminal_recommission() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    state = FakeState()
    safety = FakeSafety()
    readiness = FakeReadiness()
    sleeps: list[float] = []
    stop = asyncio.Event()
    certificate_error = ssl.SSLCertVerificationError(1, "certificate verify failed")
    connector = ScriptedConnector([certificate_error])

    async def fail_if_retried(delay: float) -> None:
        sleeps.append(delay)
        raise AssertionError("terminal TLS certificate verification failure retried")

    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(Ed25519PrivateKey.generate()),
        state=state,
        safety=safety,
        handler=FakeHandler(),
        readiness=readiness,
        clock=Clock(),
        connect_factory=connector,
        sleeper=fail_if_retried,
    )

    with pytest.raises(ssl.SSLCertVerificationError):
        await client.run(stop)

    assert len(connector.calls) == 1
    assert safety.latched == ["transport_disconnect"]
    assert state.abandoned == ["disconnect"]
    assert sleeps == []
    assert readiness.disconnect_degraded_codes == (
        "reachy_recommission_required:reachy_tls_certificate_verification",
    )
    assert readiness.restart_required is True


@pytest.mark.asyncio
async def test_run_treats_presocket_tls_auth_protocol_error_as_terminal_recommission() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    state = FakeState()
    safety = FakeSafety()
    readiness = FakeReadiness()
    sleeps: list[float] = []
    stop = asyncio.Event()
    connector = ScriptedConnector(
        [ReasonedTlsAuthError(ssl.SSL_ERROR_SSL, "peer rejected TLS client auth")]
    )

    async def fail_if_retried(delay: float) -> None:
        sleeps.append(delay)
        raise AssertionError("terminal TLS auth/protocol failure retried")

    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(Ed25519PrivateKey.generate()),
        state=state,
        safety=safety,
        handler=FakeHandler(),
        readiness=readiness,
        clock=Clock(),
        connect_factory=connector,
        sleeper=fail_if_retried,
    )

    with pytest.raises(ReasonedTlsAuthError):
        await client.run(stop)

    assert len(connector.calls) == 1
    assert safety.latched == ["transport_disconnect"]
    assert state.abandoned == ["disconnect"]
    assert sleeps == []
    assert readiness.disconnect_degraded_codes == (
        "reachy_recommission_required:reachy_tls_authentication",
    )
    assert readiness.restart_required is True


@pytest.mark.asyncio
async def test_run_treats_wrapped_tls_certificate_error_as_terminal_recommission() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    state = FakeState()
    safety = FakeSafety()
    readiness = FakeReadiness()
    sleeps: list[float] = []
    stop = asyncio.Event()
    wrapped_error = ConnectionError("websockets connect failed")
    wrapped_error.__cause__ = ssl.SSLCertVerificationError(1, "certificate verify failed")
    connector = ScriptedConnector([wrapped_error])

    async def fail_if_retried(delay: float) -> None:
        sleeps.append(delay)
        raise AssertionError("wrapped terminal TLS certificate failure retried")

    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(Ed25519PrivateKey.generate()),
        state=state,
        safety=safety,
        handler=FakeHandler(),
        readiness=readiness,
        clock=Clock(),
        connect_factory=connector,
        sleeper=fail_if_retried,
    )

    with pytest.raises(ConnectionError, match="websockets connect failed") as raised:
        await client.run(stop)

    assert isinstance(raised.value.__cause__, ssl.SSLCertVerificationError)
    assert len(connector.calls) == 1
    assert safety.latched == ["transport_disconnect"]
    assert state.abandoned == ["disconnect"]
    assert sleeps == []
    assert readiness.disconnect_degraded_codes == (
        "reachy_recommission_required:reachy_tls_certificate_verification",
    )
    assert readiness.restart_required is True


@pytest.mark.asyncio
async def test_run_resets_backoff_after_genuinely_successful_connection() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    signer = Ed25519PrivateKey.generate()
    heartbeat_nonce = b"h" * 32
    stop_nonce = b"p" * 32
    heartbeat_challenge = _challenge(marker=b"h")
    stop_challenge = _challenge(marker=b"p")
    heartbeat_socket = ClientSocket(
        heartbeat_challenge,
        _accepted_for(heartbeat_challenge, client_nonce=heartbeat_nonce),
    )
    stop_socket = ClientSocket(
        stop_challenge, _accepted_for(stop_challenge, client_nonce=stop_nonce)
    )
    sleeps: list[float] = []
    stop = asyncio.Event()
    nonces = [heartbeat_nonce, stop_nonce]
    successful_connections = 0

    def after_connect(_connection: object) -> None:
        nonlocal successful_connections
        successful_connections += 1
        if successful_connections == 2:
            stop.set()

    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(signer),
        state=FakeState(),
        safety=FakeSafety(),
        handler=FakeHandler(),
        readiness=FakeReadiness(),
        clock=Clock(),
        connect_factory=ScriptedConnector(
            [
                ConnectionError("offline"),
                TimeoutError("open timed out"),
                heartbeat_socket,
                stop_socket,
            ]
        ),
        tls_peer_verifier=lambda _socket, expected: ("TLSv1.3", SERVER_LEAF_DER),
        client_certificate_sha256=lambda _socket: CLIENT_CERTIFICATE_SHA256,
        nonce_factory=lambda size: nonces.pop(0) if size == 32 else b"",
        sleeper=lambda delay: _record_sleep(sleeps, delay),
        heartbeat_interval=0.001,
        heartbeat_timeout=0.001,
    )

    await asyncio.wait_for(client.run(stop, after_connect=after_connect), timeout=0.2)

    assert sleeps == [0.25, 0.5, 0.25]
    assert heartbeat_socket.closed == [(1011, "heartbeat_lost")]
    assert stop_socket.closed == [(1000, "edge_stopped")]


@pytest.mark.asyncio
async def test_two_missed_heartbeats_latch_error_safe_cleanup_and_reconnect() -> None:
    from tuntun_edge.transport.websocket import RECONNECT_DELAYS, ReachyWssClient

    signer = Ed25519PrivateKey.generate()
    first_client_nonce = b"1" * 32
    second_client_nonce = b"2" * 32
    first_challenge = _challenge(marker=b"f")
    second_challenge = _challenge(marker=b"g")
    first = ClientSocket(
        first_challenge,
        _accepted_for(first_challenge, client_nonce=first_client_nonce),
    )
    second = ClientSocket(
        second_challenge,
        _accepted_for(second_challenge, client_nonce=second_client_nonce),
    )
    state = FakeState()
    safety = FakeSafety()
    readiness = FakeReadiness()
    sleeps: list[float] = []
    client_nonces = [first_client_nonce, second_client_nonce]
    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(signer),
        state=state,
        safety=safety,
        handler=FakeHandler(),
        readiness=readiness,
        clock=Clock(),
        connect_factory=FakeConnector([first, second]),
        tls_peer_verifier=lambda _socket, expected: ("TLSv1.3", SERVER_LEAF_DER),
        client_certificate_sha256=lambda _socket: CLIENT_CERTIFICATE_SHA256,
        nonce_factory=lambda size: client_nonces.pop(0) if size == 32 else b"",
        sleeper=lambda delay: _record_sleep(sleeps, delay),
        heartbeat_interval=0.001,
        heartbeat_timeout=0.001,
    )
    stop = asyncio.Event()
    second_connection = asyncio.Event()
    connected_count = 0

    def mark_connected(_connection: object) -> None:
        nonlocal connected_count
        connected_count += 1
        if connected_count == 2:
            second_connection.set()

    runner = asyncio.create_task(client.run(stop, after_connect=mark_connected))
    await asyncio.wait_for(second_connection.wait(), timeout=1)
    stop.set()
    await runner

    assert first.closed == [(1011, "heartbeat_lost")]
    assert safety.latched == ["transport_disconnect", "transport_disconnect"]
    assert safety.closed == 2
    assert state.abandoned == ["disconnect", "disconnect"]
    assert readiness.ready is True
    assert sleeps[0] == RECONNECT_DELAYS[0]
    assert second.closed == [(1000, "edge_stopped")]
    assert client.connection_history[0] != client.connection_history[1]


@pytest.mark.asyncio
async def test_run_closes_live_socket_before_reconnect_after_malformed_control_frame() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    signer = Ed25519PrivateKey.generate()
    first_nonce = b"m" * 32
    second_nonce = b"n" * 32
    first_challenge = _challenge(marker=b"m")
    second_challenge = _challenge(marker=b"n")
    first = ScriptedApplicationSocket(
        first_challenge,
        _accepted_for(first_challenge, client_nonce=first_nonce),
        ["not-json"],
    )
    second = ClientSocket(
        second_challenge, _accepted_for(second_challenge, client_nonce=second_nonce)
    )
    state = FakeState()
    safety = FakeSafety()
    sleeps: list[float] = []
    nonces = [first_nonce, second_nonce]
    stop = asyncio.Event()
    connections = 0

    def stop_after_second_connection(_connection: object) -> None:
        nonlocal connections
        connections += 1
        if connections == 2:
            stop.set()

    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(signer),
        state=state,
        safety=safety,
        handler=FakeHandler(),
        readiness=FakeReadiness(),
        clock=Clock(),
        connect_factory=FakeConnector([first, second]),
        tls_peer_verifier=lambda _socket, expected: ("TLSv1.3", SERVER_LEAF_DER),
        client_certificate_sha256=lambda _socket: CLIENT_CERTIFICATE_SHA256,
        nonce_factory=lambda size: nonces.pop(0) if size == 32 else b"",
        sleeper=lambda delay: _record_sleep(sleeps, delay),
    )

    await client.run(stop, after_connect=stop_after_second_connection)

    assert first.closed == [(1011, "edge_connection_failed")]
    assert second.closed == [(1000, "edge_stopped")]
    assert safety.latched == ["transport_disconnect", "transport_disconnect"]
    assert state.abandoned == ["disconnect", "disconnect"]
    assert sleeps == [0.25]


@pytest.mark.asyncio
async def test_run_bounds_application_response_send_and_reconnects() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    signer = Ed25519PrivateKey.generate()
    first_nonce = b"s" * 32
    second_nonce = b"t" * 32
    first_challenge = _challenge(marker=b"s")
    second_challenge = _challenge(marker=b"t")
    connection_nonce = base64.b64decode(
        _accepted_for(first_challenge, client_nonce=first_nonce).connection_nonce_b64,
        validate=True,
    )
    first = HangingApplicationSendSocket(
        first_challenge,
        _accepted_for(first_challenge, client_nonce=first_nonce),
        [_signed_core_request(signer, connection_nonce=connection_nonce)],
        hang_on_send=2,
    )
    second = ClientSocket(
        second_challenge, _accepted_for(second_challenge, client_nonce=second_nonce)
    )
    state = FakeState()
    safety = FakeSafety()
    sleeps: list[float] = []
    nonces = [first_nonce, second_nonce]
    stop = asyncio.Event()
    connections = 0

    def stop_after_second_connection(_connection: object) -> None:
        nonlocal connections
        connections += 1
        if connections == 2:
            stop.set()

    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(signer),
        state=state,
        safety=safety,
        handler=FakeHandler(),
        readiness=FakeReadiness(),
        clock=Clock(),
        connect_factory=FakeConnector([first, second]),
        tls_peer_verifier=lambda _socket, expected: ("TLSv1.3", SERVER_LEAF_DER),
        client_certificate_sha256=lambda _socket: CLIENT_CERTIFICATE_SHA256,
        nonce_factory=lambda size: nonces.pop(0) if size == 32 else b"",
        sleeper=lambda delay: _record_sleep(sleeps, delay),
        socket_close_timeout=0.001,
    )

    await asyncio.wait_for(
        client.run(stop, after_connect=stop_after_second_connection),
        timeout=0.1,
    )

    assert first.hanging_send_started.is_set()
    assert first.closed == [(1011, "edge_connection_failed")]
    assert second.closed == [(1000, "edge_stopped")]
    assert safety.latched == ["transport_disconnect", "transport_disconnect"]
    assert state.abandoned == ["disconnect", "disconnect"]
    assert sleeps == [0.25]


@pytest.mark.asyncio
async def test_run_closes_live_socket_before_reconnect_after_dispatch_failure() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    class FailingControlHandler(FakeHandler):
        async def control(self, purpose: str, payload: bytes) -> bytes:
            await super().control(purpose, payload)
            raise RuntimeError("dispatch failed")

    signer = Ed25519PrivateKey.generate()
    first_nonce = b"d" * 32
    second_nonce = b"e" * 32
    first_challenge = _challenge(marker=b"d")
    second_challenge = _challenge(marker=b"e")
    connection_nonce = base64.b64decode(
        _accepted_for(first_challenge, client_nonce=first_nonce).connection_nonce_b64,
        validate=True,
    )
    first = ScriptedApplicationSocket(
        first_challenge,
        _accepted_for(first_challenge, client_nonce=first_nonce),
        [_signed_core_request(signer, connection_nonce=connection_nonce)],
    )
    second = ClientSocket(
        second_challenge, _accepted_for(second_challenge, client_nonce=second_nonce)
    )
    state = FakeState()
    safety = FakeSafety()
    sleeps: list[float] = []
    nonces = [first_nonce, second_nonce]
    stop = asyncio.Event()
    connections = 0

    def stop_after_second_connection(_connection: object) -> None:
        nonlocal connections
        connections += 1
        if connections == 2:
            stop.set()

    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(signer),
        state=state,
        safety=safety,
        handler=FailingControlHandler(),
        readiness=FakeReadiness(),
        clock=Clock(),
        connect_factory=FakeConnector([first, second]),
        tls_peer_verifier=lambda _socket, expected: ("TLSv1.3", SERVER_LEAF_DER),
        client_certificate_sha256=lambda _socket: CLIENT_CERTIFICATE_SHA256,
        nonce_factory=lambda size: nonces.pop(0) if size == 32 else b"",
        sleeper=lambda delay: _record_sleep(sleeps, delay),
    )

    await client.run(stop, after_connect=stop_after_second_connection)

    assert first.closed == [(1011, "edge_connection_failed")]
    assert second.closed == [(1000, "edge_stopped")]
    assert safety.latched == ["transport_disconnect", "transport_disconnect"]
    assert state.abandoned == ["disconnect", "disconnect"]
    assert sleeps == [0.25]


@pytest.mark.asyncio
async def test_edge_connection_serve_uses_direct_task_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tuntun_edge.transport.websocket as edge_wss
    from tuntun_edge.transport.websocket import ReachyWssClient

    signer = Ed25519PrivateKey.generate()
    client_nonce = b"f" * 32
    challenge = _challenge(marker=b"f")
    socket = ScriptedApplicationSocket(
        challenge,
        _accepted_for(challenge, client_nonce=client_nonce),
        [ConnectionError("receive failed")],
    )
    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(signer),
        state=FakeState(),
        safety=FakeSafety(),
        handler=FakeHandler(),
        readiness=FakeReadiness(),
        clock=Clock(),
        connect_factory=FakeConnector([socket]),
        tls_peer_verifier=lambda _socket, expected: ("TLSv1.3", SERVER_LEAF_DER),
        client_certificate_sha256=lambda _socket: CLIENT_CERTIFICATE_SHA256,
        nonce_factory=lambda size: client_nonce if size == 32 else b"",
    )
    connection = await client.connect_once()
    real_create_task = asyncio.create_task

    def create_task_or_fail(coro: Awaitable[object], *, name: str | None = None) -> Any:
        if name == "edge_connection_receive":
            close = getattr(coro, "close", None)
            if callable(close):
                close()
            raise RuntimeError("task factory unavailable")
        return real_create_task(coro, name=name)

    def task_group_create_task_or_fail(
        self: asyncio.TaskGroup,
        coro: Awaitable[object],
        *,
        name: str | None = None,
        **kwargs: object,
    ) -> Any:
        assert self
        assert name is None
        assert kwargs == {}
        close = getattr(coro, "close", None)
        if callable(close):
            close()
        raise RuntimeError("task factory unavailable")

    monkeypatch.setattr(edge_wss.asyncio, "create_task", create_task_or_fail)
    monkeypatch.setattr(edge_wss.asyncio.TaskGroup, "create_task", task_group_create_task_or_fail)

    with pytest.raises(ConnectionError, match="receive failed"):
        await connection.serve()


@pytest.mark.asyncio
async def test_run_stop_wait_uses_direct_task_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    import tuntun_edge.transport.websocket as edge_wss
    from tuntun_edge.transport.websocket import ReachyWssClient

    signer = Ed25519PrivateKey.generate()
    client_nonce = b"w" * 32
    challenge = _challenge(marker=b"w")
    socket = ClientSocket(challenge, _accepted_for(challenge, client_nonce=client_nonce))
    real_create_task = asyncio.create_task

    def create_task_or_fail(coro: Awaitable[object], *, name: str | None = None) -> Any:
        if name == "edge_connection_stop_wait":
            close = getattr(coro, "close", None)
            if callable(close):
                close()
            raise RuntimeError("task factory unavailable")
        return real_create_task(coro, name=name)

    monkeypatch.setattr(edge_wss.asyncio, "create_task", create_task_or_fail)
    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(signer),
        state=FakeState(),
        safety=FakeSafety(),
        handler=FakeHandler(),
        readiness=FakeReadiness(),
        clock=Clock(),
        connect_factory=FakeConnector([socket]),
        tls_peer_verifier=lambda _socket, expected: ("TLSv1.3", SERVER_LEAF_DER),
        client_certificate_sha256=lambda _socket: CLIENT_CERTIFICATE_SHA256,
        nonce_factory=lambda size: client_nonce if size == 32 else b"",
    )
    stop = asyncio.Event()

    await asyncio.wait_for(
        client.run(stop, after_connect=lambda _connection: stop.set()),
        timeout=0.1,
    )

    assert socket.closed == [(1000, "edge_stopped")]
    assert client.task_factory_failure_points == ("edge_connection_stop_wait",)


@pytest.mark.asyncio
async def test_run_connection_close_uses_direct_task_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tuntun_edge.transport.websocket as edge_wss
    from tuntun_edge.transport.websocket import ReachyWssClient

    signer = Ed25519PrivateKey.generate()
    first_nonce = b"l" * 32
    second_nonce = b"r" * 32
    first_challenge = _challenge(marker=b"l")
    second_challenge = _challenge(marker=b"r")
    first = ScriptedApplicationSocket(
        first_challenge,
        _accepted_for(first_challenge, client_nonce=first_nonce),
        [ConnectionError("receive failed")],
    )
    second = ClientSocket(
        second_challenge, _accepted_for(second_challenge, client_nonce=second_nonce)
    )
    real_create_task = asyncio.create_task

    def create_task_or_fail(coro: Awaitable[object], *, name: str | None = None) -> Any:
        if name == "edge_connection_close":
            close = getattr(coro, "close", None)
            if callable(close):
                close()
            raise RuntimeError("task factory unavailable")
        return real_create_task(coro, name=name)

    monkeypatch.setattr(edge_wss.asyncio, "create_task", create_task_or_fail)
    sleeps: list[float] = []
    nonces = [first_nonce, second_nonce]
    stop = asyncio.Event()
    connections = 0

    def stop_after_second_connection(_connection: object) -> None:
        nonlocal connections
        connections += 1
        if connections == 2:
            stop.set()

    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(signer),
        state=FakeState(),
        safety=FakeSafety(),
        handler=FakeHandler(),
        readiness=FakeReadiness(),
        clock=Clock(),
        connect_factory=FakeConnector([first, second]),
        tls_peer_verifier=lambda _socket, expected: ("TLSv1.3", SERVER_LEAF_DER),
        client_certificate_sha256=lambda _socket: CLIENT_CERTIFICATE_SHA256,
        nonce_factory=lambda size: nonces.pop(0) if size == 32 else b"",
        sleeper=lambda delay: _record_sleep(sleeps, delay),
    )

    await client.run(stop, after_connect=stop_after_second_connection)

    assert first.closed == [(1011, "edge_connection_failed")]
    assert second.closed == [(1000, "edge_stopped")]
    assert sleeps == [0.25]


@pytest.mark.asyncio
async def test_run_closes_live_socket_and_propagates_fatal_receive_exception() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    signer = Ed25519PrivateKey.generate()
    client_nonce = b"b" * 32
    challenge = _challenge(marker=b"b")
    socket = ScriptedApplicationSocket(
        challenge,
        _accepted_for(challenge, client_nonce=client_nonce),
        [FatalTransportExit()],
    )
    state = FakeState()
    safety = FakeSafety()
    sleeps: list[float] = []
    stop = asyncio.Event()
    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(signer),
        state=state,
        safety=safety,
        handler=FakeHandler(),
        readiness=FakeReadiness(),
        clock=Clock(),
        connect_factory=FakeConnector([socket]),
        tls_peer_verifier=lambda _socket, expected: ("TLSv1.3", SERVER_LEAF_DER),
        client_certificate_sha256=lambda _socket: CLIENT_CERTIFICATE_SHA256,
        nonce_factory=lambda size: client_nonce if size == 32 else b"",
        sleeper=lambda delay: _record_sleep(sleeps, delay),
    )

    with pytest.raises(BaseExceptionGroup) as error:
        await client.run(stop)

    assert _exception_group_contains(error.value, FatalTransportExit)
    assert socket.closed == [(1011, "edge_connection_failed")]
    assert safety.latched == ["transport_disconnect"]
    assert state.abandoned == ["disconnect"]
    assert sleeps == []


@pytest.mark.asyncio
async def test_run_cancellation_closes_live_socket_and_cleanup_before_reraising() -> None:
    from tuntun_edge.transport.websocket import ReachyWssClient

    signer = Ed25519PrivateKey.generate()
    client_nonce = b"x" * 32
    challenge = _challenge(marker=b"x")
    socket = ScriptedApplicationSocket(
        challenge,
        _accepted_for(challenge, client_nonce=client_nonce),
        [],
    )
    state = FakeState()
    safety = FakeSafety()
    connected = asyncio.Event()
    stop = asyncio.Event()
    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(signer),
        state=state,
        safety=safety,
        handler=FakeHandler(),
        readiness=FakeReadiness(),
        clock=Clock(),
        connect_factory=FakeConnector([socket]),
        tls_peer_verifier=lambda _socket, expected: ("TLSv1.3", SERVER_LEAF_DER),
        client_certificate_sha256=lambda _socket: CLIENT_CERTIFICATE_SHA256,
        nonce_factory=lambda size: client_nonce if size == 32 else b"",
    )

    runner = asyncio.create_task(
        client.run(stop, after_connect=lambda _connection: connected.set())
    )
    await asyncio.wait_for(connected.wait(), timeout=1)
    runner.cancel()
    with pytest.raises(asyncio.CancelledError):
        await runner

    assert socket.closed == [(1011, "edge_supervisor_cancelled")]
    assert safety.latched == ["transport_disconnect"]
    assert state.abandoned == ["disconnect"]


def _exception_group_contains(error: BaseException, expected_type: type[BaseException]) -> bool:
    if isinstance(error, BaseExceptionGroup):
        return any(_exception_group_contains(item, expected_type) for item in error.exceptions)
    return isinstance(error, expected_type)


def _assert_pre_session_failure_observed(
    state: FakeState,
    readiness: FakeReadiness,
    expected_code: str,
) -> None:
    assert state.abandoned == ["pre_session_failure"]
    assert readiness.disconnect_degraded_codes == (expected_code,)


async def _record_sleep(record: list[float], delay: float) -> None:
    record.append(delay)


@pytest.mark.asyncio
async def test_time_issuer_signs_current_endpoint_cert_bound_nonce_once_per_sequence() -> None:
    from tuntun_core.adapters.reachy.time_issuer import CoreTimeProofIssuer

    signer = Ed25519PrivateKey.generate()
    endpoint = Endpoint(
        server_public_key_sha256=hashlib.sha256(
            signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).hexdigest()
    )
    sequences = SequenceStore()
    issuer = CoreTimeProofIssuer(
        authority=AuthorityHealth(),
        sequences=sequences,
        signer=signer,
        endpoint=endpoint,
        clock=Clock(),
    )

    first = await issuer.issue(b"a" * 32, client_certificate_sha256=CLIENT_CERTIFICATE_SHA256)
    second = await issuer.issue(b"b" * 32, client_certificate_sha256=CLIENT_CERTIFICATE_SHA256)

    assert first.time_sequence == 1
    assert second.time_sequence == 2
    assert sequences.keys == [
        (1, 9, CLIENT_CERTIFICATE_SHA256, SERVER_KEY_ID),
        (1, 9, CLIENT_CERTIFICATE_SHA256, SERVER_KEY_ID),
    ]
    signer.public_key().verify(
        base64.b64decode(first.signature_b64, validate=True),
        first.signing_payload(),
    )
    with pytest.raises(PermissionError, match="secure_time_client_certificate_binding"):
        await issuer.issue(b"c" * 32, client_certificate_sha256="0" * 64)
    with pytest.raises(ValueError, match="secure_time_nonce_size"):
        await issuer.issue(b"short", client_certificate_sha256=CLIENT_CERTIFICATE_SHA256)


class AuthorityHealth:
    generation = 9

    async def require_synchronized_no_step(self) -> AuthorityHealth:
        return self


class SequenceStore:
    def __init__(self) -> None:
        self.value = 0
        self.keys: list[tuple[int, int, str, str]] = []

    async def reserve_next(
        self,
        endpoint_generation: int,
        authority_generation: int,
        client_certificate_sha256: str,
        signing_key_id: str,
    ) -> int:
        self.keys.append(
            (
                endpoint_generation,
                authority_generation,
                client_certificate_sha256,
                signing_key_id,
            )
        )
        self.value += 1
        return self.value


class MutableTimeEndpoint:
    def __init__(self, *, server_public_key_sha256: str) -> None:
        self.generation = 1
        self.client_certificate_sha256 = CLIENT_CERTIFICATE_SHA256
        self.server_key_id = SERVER_KEY_ID
        self.server_public_key_sha256 = server_public_key_sha256


class MutatingAuthority:
    generation = 9

    def __init__(self, endpoint: MutableTimeEndpoint) -> None:
        self.endpoint = endpoint

    async def require_synchronized_no_step(self) -> MutatingAuthority:
        self.endpoint.generation = 2
        return self


class MutatingSequenceStore:
    def __init__(self, endpoint: MutableTimeEndpoint) -> None:
        self.endpoint = endpoint

    async def reserve_next(
        self,
        _endpoint_generation: int,
        _authority_generation: int,
        _client_certificate_sha256: str,
        _signing_key_id: str,
    ) -> int:
        self.endpoint.server_key_id = "ed25519:reachy-core:v2"
        return 1


class DateTimeSubclass(datetime):
    pass


class SubclassClock:
    def now(self) -> datetime:
        return DateTimeSubclass(2026, 8, 27, 1, 2, 3, 4, tzinfo=UTC)


@pytest.mark.asyncio
async def test_time_issuer_rejects_endpoint_mutation_across_authority_await() -> None:
    from tuntun_core.adapters.reachy.time_issuer import CoreTimeProofIssuer

    signer = Ed25519PrivateKey.generate()
    endpoint = MutableTimeEndpoint(
        server_public_key_sha256=hashlib.sha256(
            signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).hexdigest()
    )
    sequences = SequenceStore()
    issuer = CoreTimeProofIssuer(
        authority=MutatingAuthority(endpoint),
        sequences=sequences,
        signer=signer,
        endpoint=endpoint,
        clock=Clock(),
    )

    with pytest.raises(PermissionError, match="secure_time_endpoint_changed"):
        await issuer.issue(b"m" * 32, client_certificate_sha256=CLIENT_CERTIFICATE_SHA256)

    assert sequences.keys == []


@pytest.mark.asyncio
async def test_time_issuer_rejects_endpoint_mutation_across_sequence_await() -> None:
    from tuntun_core.adapters.reachy.time_issuer import CoreTimeProofIssuer

    signer = Ed25519PrivateKey.generate()
    endpoint = MutableTimeEndpoint(
        server_public_key_sha256=hashlib.sha256(
            signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).hexdigest()
    )
    issuer = CoreTimeProofIssuer(
        authority=AuthorityHealth(),
        sequences=MutatingSequenceStore(endpoint),
        signer=signer,
        endpoint=endpoint,
        clock=Clock(),
    )

    with pytest.raises(PermissionError, match="secure_time_endpoint_changed"):
        await issuer.issue(b"s" * 32, client_certificate_sha256=CLIENT_CERTIFICATE_SHA256)


@pytest.mark.asyncio
async def test_time_issuer_requires_exact_aware_datetime() -> None:
    from tuntun_core.adapters.reachy.time_issuer import CoreTimeProofIssuer

    signer = Ed25519PrivateKey.generate()
    endpoint = Endpoint(
        server_public_key_sha256=hashlib.sha256(
            signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).hexdigest()
    )
    issuer = CoreTimeProofIssuer(
        authority=AuthorityHealth(),
        sequences=SequenceStore(),
        signer=signer,
        endpoint=endpoint,
        clock=SubclassClock(),
    )

    with pytest.raises(ValueError, match="secure_time_clock_utc_required"):
        await issuer.issue(b"d" * 32, client_certificate_sha256=CLIENT_CERTIFICATE_SHA256)


@pytest.mark.asyncio
async def test_server_time_bootstrap_one_proof_then_close_without_dispatch() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    device_signer = Ed25519PrivateKey.generate()
    request_nonce = b"n" * 32
    socket = ServerSocket(
        "/v1/reachy/time",
        "tuntun.reachy.time.v1",
        [
            canonical_bytes(
                CoreTimeRequestV1(
                    schema_version="tuntun.core-time-request.v1",
                    request_nonce_b64=base64.b64encode(request_nonce).decode("ascii"),
                )
            ).decode("utf-8")
        ],
    )
    issuer = TimeIssuer()
    sessions = SessionPublisher()
    registry = DeviceRegistry()
    tls_results = [
        ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        ("TLSv1.2", b"stale-leaf"),
        ("TLSv1.3", CLIENT_CERTIFICATE_DER),
    ]
    tls_verifications: list[tuple[str, str]] = []

    def verify_client_certificate(socket_arg: Any, expected: str) -> tuple[str, bytes]:
        tls_verifications.append((socket_arg.request.path, expected))
        return tls_results.pop(0)

    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=registry,
        pairing_keys=CorePairingKeys(device_signer, Ed25519PrivateKey.generate()),
        state=FakeState(),
        handler=FakeHandler(),
        sessions=sessions,
        readiness=FakeReadiness(),
        time_issuer=issuer,
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=verify_client_certificate,
    )

    await server.accept(socket)

    assert issuer.requests == [(request_nonce, CLIENT_CERTIFICATE_SHA256)]
    assert sessions.published == []
    assert socket.closed == [(1000, "secure_time_complete")]
    assert tls_verifications == [("/v1/reachy/time", CLIENT_CERTIFICATE_SHA256)]
    proof = parse_contract_json(
        CoreTimeProofV1,
        socket.sent[0].encode("utf-8"),
        max_bytes=8_192,
        require_canonical=True,
    )
    assert proof.endpoint_generation == 1
    stale_app_socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=device_signer,
    )

    with pytest.raises(PermissionError, match="reachy_tls13_required"):
        await server.accept(stale_app_socket)

    assert sessions.published == []
    assert stale_app_socket.sent == []
    fresh_app_socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=device_signer,
    )

    await server.accept(fresh_app_socket)

    assert socket.closed == [(1000, "secure_time_complete")]
    assert sessions.published == [DEVICE_ID]
    assert fresh_app_socket.sent
    assert tls_verifications == [
        ("/v1/reachy/time", CLIENT_CERTIFICATE_SHA256),
        ("/v1/reachy", CLIENT_CERTIFICATE_SHA256),
        ("/v1/reachy", CLIENT_CERTIFICATE_SHA256),
    ]
    assert registry.calls == [
        (CLIENT_CERTIFICATE_SHA256, CLIENT_CERTIFICATE_SHA256, 1),
        (CLIENT_CERTIFICATE_SHA256, CLIENT_CERTIFICATE_SHA256, 1),
    ]


@pytest.mark.asyncio
async def test_server_time_bootstrap_success_close_is_bounded() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    request_nonce = b"n" * 32
    socket = HangingCloseServerSocket(
        "/v1/reachy/time",
        "tuntun.reachy.time.v1",
        [
            canonical_bytes(
                CoreTimeRequestV1(
                    schema_version="tuntun.core-time-request.v1",
                    request_nonce_b64=base64.b64encode(request_nonce).decode("ascii"),
                )
            ).decode("utf-8")
        ],
    )
    issuer = TimeIssuer()
    readiness = FakeReadiness()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=FakeState(),
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=issuer,
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        socket_close_timeout=0.001,
    )

    await asyncio.wait_for(server.accept(socket), timeout=0.05)

    assert socket.close_started.is_set()
    assert issuer.requests == [(request_nonce, CLIENT_CERTIFICATE_SHA256)]
    assert readiness.disconnect_degraded_codes == ()


@pytest.mark.asyncio
async def test_server_rejects_wrong_path_or_subprotocol_before_identity_lookup() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    registry = DeviceRegistry()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=registry,
        pairing_keys=CorePairingKeys(Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()),
        state=FakeState(),
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=FakeReadiness(),
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
    )

    await server.accept(ServerSocket("/v1/reachy/extra", "tuntun.reachy.v1", []))
    await server.accept(ServerSocket("/v1/reachy", "tuntun.reachy.time.v1", []))

    assert registry.calls == []


@pytest.mark.asyncio
async def test_server_rejects_wrong_path_with_bounded_close_before_identity_lookup() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    registry = DeviceRegistry()
    socket = HangingCloseServerSocket("/v1/reachy/extra", "tuntun.reachy.v1", [])
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=registry,
        pairing_keys=CorePairingKeys(Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()),
        state=FakeState(),
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=FakeReadiness(),
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        socket_close_timeout=0.001,
    )

    await asyncio.wait_for(server.accept(socket), timeout=0.05)

    assert socket.close_started.is_set()
    assert registry.calls == []


@pytest.mark.asyncio
async def test_server_rejects_malformed_request_path_with_bounded_close() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    registry = DeviceRegistry()
    socket = ServerSocket("/v1/reachy", "tuntun.reachy.v1", [])
    socket.request.path = object()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=registry,
        pairing_keys=CorePairingKeys(Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()),
        state=FakeState(),
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=FakeReadiness(),
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        socket_close_timeout=0.001,
    )

    with pytest.raises(PermissionError, match="reachy_path_or_subprotocol"):
        await asyncio.wait_for(server.accept(socket), timeout=0.05)

    assert socket.closed == [(1008, "reachy_path_or_subprotocol")]
    assert registry.calls == []


@pytest.mark.asyncio
async def test_server_pre_session_socket_close_uses_direct_task_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tuntun_core.adapters.reachy.wss_server as core_wss
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    registry = DeviceRegistry()
    socket = ServerSocket("/v1/reachy", "tuntun.reachy.v1", [])
    socket.request.path = object()
    real_create_task = asyncio.create_task

    def create_task_or_fail(coro: Awaitable[object], *, name: str | None = None) -> Any:
        if name == "reachy_pre_session_socket_close":
            close = getattr(coro, "close", None)
            if callable(close):
                close()
            raise RuntimeError("task factory unavailable")
        return real_create_task(coro, name=name)

    monkeypatch.setattr(core_wss.asyncio, "create_task", create_task_or_fail)
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=registry,
        pairing_keys=CorePairingKeys(Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()),
        state=FakeState(),
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=FakeReadiness(),
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        socket_close_timeout=0.001,
    )

    with pytest.raises(PermissionError, match="reachy_path_or_subprotocol"):
        await server.accept(socket)

    assert socket.closed == [(1008, "reachy_path_or_subprotocol")]
    assert registry.calls == []


@pytest.mark.asyncio
async def test_server_rejects_cloned_certificate_without_device_signing_key_before_session() -> (
    None
):
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    true_device_signer = Ed25519PrivateKey.generate()
    clone_signer = Ed25519PrivateKey.generate()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=clone_signer,
    )
    state = FakeState()
    readiness = FakeReadiness()
    factory = SessionFactory()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(true_device_signer, Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=factory,
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        nonce_factory=lambda size: b"s" * size,
    )

    with pytest.raises(PermissionError, match="device_challenge"):
        await server.accept(socket)

    assert factory.created == 0
    assert socket.sent
    assert socket.closed == [(1008, "reachy_handshake_failed")]
    _assert_pre_session_failure_observed(
        state,
        readiness,
        "reachy_pre_session_failed:PermissionError",
    )


@pytest.mark.asyncio
async def test_server_rejects_mismatched_client_der_from_verifier_before_challenge() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    registry = DeviceRegistry()
    state = FakeState()
    readiness = FakeReadiness()
    factory = SessionFactory()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=registry,
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=factory,
        client_certificate_verifier=lambda _socket, expected: (
            "TLSv1.3",
            b"wrong-client-leaf",
        ),
    )

    with pytest.raises(PermissionError, match="reachy_client_certificate_mismatch"):
        await server.accept(socket)

    assert registry.calls == []
    assert factory.created == 0
    assert socket.sent == []
    assert socket.closed == [(1008, "reachy_handshake_failed")]
    _assert_pre_session_failure_observed(
        state,
        readiness,
        "reachy_pre_session_failed:PermissionError",
    )


@pytest.mark.asyncio
async def test_server_tls_rejection_starts_bounded_close_and_observes_cleanup() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = HangingCloseServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    state = FakeState()
    readiness = FakeReadiness()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.2", CLIENT_CERTIFICATE_DER),
        socket_close_timeout=0.001,
    )

    with pytest.raises(PermissionError, match="reachy_tls13_required"):
        await asyncio.wait_for(server.accept(socket), timeout=0.05)

    assert socket.close_started.is_set()
    _assert_pre_session_failure_observed(
        state,
        readiness,
        "reachy_pre_session_failed:PermissionError",
    )


@pytest.mark.asyncio
async def test_server_registry_rejection_closes_and_observes_pre_session_failure() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    state = FakeState()
    readiness = FakeReadiness()
    factory = SessionFactory()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(accept=False),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=factory,
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
    )

    with pytest.raises(PermissionError, match="revoked_or_stale_pairing_key"):
        await server.accept(socket)

    assert factory.created == 0
    assert socket.sent == []
    assert socket.closed == [(1008, "reachy_handshake_failed")]
    _assert_pre_session_failure_observed(
        state,
        readiness,
        "reachy_pre_session_failed:PermissionError",
    )


@pytest.mark.asyncio
async def test_server_time_handshake_failure_closes_and_observes_pre_session_failure() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = ServerSocket("/v1/reachy/time", "tuntun.reachy.time.v1", ["not-json"])
    state = FakeState()
    readiness = FakeReadiness()
    issuer = TimeIssuer()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=issuer,
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
    )

    with pytest.raises(PermissionError, match="reachy_handshake_json_invalid"):
        await server.accept(socket)

    assert issuer.requests == []
    assert socket.sent == []
    assert socket.closed == [(1008, "reachy_handshake_failed")]
    _assert_pre_session_failure_observed(
        state,
        readiness,
        "reachy_pre_session_failed:PermissionError",
    )


@pytest.mark.asyncio
async def test_server_send_failure_closes_and_observes_pre_session_failure() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = FailingSendServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    state = FakeState()
    readiness = FakeReadiness()
    factory = SessionFactory()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=factory,
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
    )

    with pytest.raises(RuntimeError, match="send failed"):
        await server.accept(socket)

    assert factory.created == 0
    assert socket.closed == [(1011, "reachy_accept_failed")]
    _assert_pre_session_failure_observed(
        state,
        readiness,
        "reachy_pre_session_failed:RuntimeError",
    )


@pytest.mark.asyncio
async def test_server_time_proof_send_timeout_closes_and_observes_pre_session_failure() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    request_nonce = b"t" * 32
    socket = HangingSendServerSocket(
        "/v1/reachy/time",
        "tuntun.reachy.time.v1",
        [
            canonical_bytes(
                CoreTimeRequestV1(
                    schema_version="tuntun.core-time-request.v1",
                    request_nonce_b64=base64.b64encode(request_nonce).decode("ascii"),
                )
            ).decode("utf-8")
        ],
        hang_on_send=1,
    )
    state = FakeState()
    readiness = FakeReadiness()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
    )
    server._handshake_timeout = 0.001

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(server.accept(socket), timeout=0.05)

    assert socket.hanging_send_started.is_set()
    assert socket.closed == [(1011, "reachy_accept_failed")]
    _assert_pre_session_failure_observed(
        state,
        readiness,
        "reachy_pre_session_failed:TimeoutError",
    )


@pytest.mark.asyncio
async def test_server_challenge_send_timeout_closes_and_observes_pre_session_failure() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = HangingSendServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        hang_on_send=1,
        proof_signer=signer,
    )
    state = FakeState()
    readiness = FakeReadiness()
    factory = SessionFactory()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=factory,
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
    )
    server._handshake_timeout = 0.001

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(server.accept(socket), timeout=0.05)

    assert factory.created == 0
    assert socket.hanging_send_started.is_set()
    assert socket.closed == [(1011, "reachy_accept_failed")]
    _assert_pre_session_failure_observed(
        state,
        readiness,
        "reachy_pre_session_failed:TimeoutError",
    )


@pytest.mark.asyncio
async def test_server_accepted_send_timeout_closes_and_observes_pre_session_failure() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = HangingSendServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        hang_on_send=2,
        proof_signer=signer,
    )
    state = FakeState()
    readiness = FakeReadiness()
    factory = SessionFactory()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=factory,
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
    )
    server._handshake_timeout = 0.001

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(server.accept(socket), timeout=0.05)

    assert factory.created == 0
    assert socket.send_attempts == 2
    assert socket.hanging_send_started.is_set()
    assert socket.closed == [(1011, "reachy_accept_failed")]
    _assert_pre_session_failure_observed(
        state,
        readiness,
        "reachy_pre_session_failed:TimeoutError",
    )


@pytest.mark.asyncio
async def test_server_publish_failure_closes_and_observes_pre_session_failure() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    state = FakeState()
    readiness = FakeReadiness()
    sessions = FailingSessionPublisher()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=sessions,
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        nonce_factory=lambda size: b"s" * size,
    )

    with pytest.raises(RuntimeError, match="publish failed"):
        await server.accept(socket)

    assert sessions.published == []
    assert sessions.cleared == [DEVICE_ID]
    assert socket.closed == [(1011, "reachy_accept_failed")]
    _assert_pre_session_failure_observed(
        state,
        readiness,
        "reachy_pre_session_failed:RuntimeError",
    )


@pytest.mark.asyncio
async def test_server_clears_published_session_when_endpoint_mutates_after_publish() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    endpoint = MutableEndpoint()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    state = FakeState()
    readiness = FakeReadiness()
    sessions = MutatingAfterPublishSessionPublisher(endpoint)
    server = ReachyWssServer(
        endpoint,
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=sessions,
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        nonce_factory=lambda size: b"s" * size,
    )

    with pytest.raises(PermissionError, match="reachy_endpoint_changed"):
        await server.accept(socket)

    assert sessions.published == [DEVICE_ID]
    assert sessions.cleared == [DEVICE_ID]
    assert socket.closed == [(1008, "reachy_handshake_failed")]
    _assert_pre_session_failure_observed(
        state,
        readiness,
        "reachy_pre_session_failed:PermissionError",
    )


@pytest.mark.asyncio
async def test_server_clears_session_when_publish_succeeds_then_raises() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    state = FakeState()
    readiness = FakeReadiness()
    sessions = AmbiguousPublishSessionPublisher()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=sessions,
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        nonce_factory=lambda size: b"s" * size,
    )

    with pytest.raises(RuntimeError, match="ambiguous publish failed"):
        await server.accept(socket)

    assert sessions.published == [DEVICE_ID]
    assert sessions.cleared == [DEVICE_ID]
    assert socket.closed == [(1011, "reachy_accept_failed")]
    _assert_pre_session_failure_observed(
        state,
        readiness,
        "reachy_pre_session_failed:RuntimeError",
    )


@pytest.mark.asyncio
async def test_server_fatal_pre_session_exception_closes_and_propagates() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    state = FakeState()
    readiness = FakeReadiness()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=FatalDeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
    )

    with pytest.raises(FatalTransportExit):
        await server.accept(socket)

    assert socket.sent == []
    assert socket.closed == [(1011, "reachy_accept_failed")]
    _assert_pre_session_failure_observed(
        state,
        readiness,
        "reachy_pre_session_failed:FatalTransportExit",
    )


@pytest.mark.asyncio
async def test_server_pre_session_cancellation_closes_and_observes_cleanup() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    request_nonce = b"q" * 32
    socket = ServerSocket(
        "/v1/reachy/time",
        "tuntun.reachy.time.v1",
        [
            canonical_bytes(
                CoreTimeRequestV1(
                    schema_version="tuntun.core-time-request.v1",
                    request_nonce_b64=base64.b64encode(request_nonce).decode("ascii"),
                )
            ).decode("utf-8")
        ],
    )
    state = FakeState()
    readiness = FakeReadiness()
    issuer = BlockingTimeIssuer()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=issuer,
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
    )

    task = asyncio.create_task(server.accept(socket))
    await asyncio.wait_for(issuer.started.wait(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert socket.closed == [(1011, "reachy_accept_cancelled")]
    _assert_pre_session_failure_observed(
        state,
        readiness,
        "reachy_pre_session_cancelled",
    )


@pytest.mark.asyncio
async def test_server_pre_session_cleanup_uses_direct_task_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tuntun_core.adapters.reachy.wss_server as core_wss
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    state = FakeState()
    readiness = FakeReadiness()
    real_create_task = asyncio.create_task

    def create_task_or_fail(coro: Awaitable[object], *, name: str | None = None) -> Any:
        if name == "reachy_pre_session_cleanup":
            close = getattr(coro, "close", None)
            if callable(close):
                close()
            raise RuntimeError("task factory unavailable")
        return real_create_task(coro, name=name)

    monkeypatch.setattr(core_wss.asyncio, "create_task", create_task_or_fail)
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(accept=False),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
    )

    with pytest.raises(PermissionError, match="revoked_or_stale_pairing_key"):
        await server.accept(socket)

    assert socket.closed == [(1008, "reachy_handshake_failed")]
    assert state.abandoned == ["pre_session_failure"]
    assert readiness.disconnect_degraded_codes == ("reachy_pre_session_failed:PermissionError",)
    assert readiness.restart_required is False


@pytest.mark.asyncio
async def test_server_pre_session_cleanup_latches_when_both_task_factories_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tuntun_core.adapters.reachy.wss_server as core_wss
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    state = FakeState()
    readiness = FakeReadiness()
    real_create_task = asyncio.create_task
    real_task = asyncio.Task

    def create_task_or_fail(coro: Awaitable[object], *, name: str | None = None) -> Any:
        if name == "reachy_pre_session_cleanup":
            close = getattr(coro, "close", None)
            if callable(close):
                close()
            raise RuntimeError("task factory unavailable")
        return real_create_task(coro, name=name)

    def task_or_fail(coro: Awaitable[object], *, name: str | None = None, **kwargs: object) -> Any:
        if name == "reachy_pre_session_cleanup":
            close = getattr(coro, "close", None)
            if callable(close):
                close()
            raise RuntimeError("direct task unavailable")
        return real_task(coro, name=name, **kwargs)

    monkeypatch.setattr(core_wss.asyncio, "create_task", create_task_or_fail)
    monkeypatch.setattr(core_wss.asyncio, "Task", task_or_fail)
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(accept=False),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
    )

    with pytest.raises(PermissionError, match="revoked_or_stale_pairing_key"):
        await server.accept(socket)

    assert socket.closed == [(1008, "reachy_handshake_failed")]
    assert state.abandoned == []
    assert readiness.disconnect_degraded_codes == (
        "reachy_pre_session_failed:PermissionError",
        "reachy_pre_session_cleanup:factory_unavailable",
    )
    assert readiness.restart_required is True


@pytest.mark.asyncio
async def test_server_pre_session_cleanup_timeout_observes_cancelled_task() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    state = HangingAbandonState()
    readiness = FakeReadiness()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(accept=False),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        pre_session_cleanup_timeout=0.001,
    )

    with pytest.raises(PermissionError, match="revoked_or_stale_pairing_key"):
        await asyncio.wait_for(server.accept(socket), timeout=0.05)

    assert state.abandoned == ["pre_session_failure"]
    assert state.cancelled.is_set()
    assert readiness.disconnect_degraded_codes == (
        "reachy_pre_session_failed:PermissionError",
        "reachy_pre_session_cleanup:timeout",
    )
    assert readiness.restart_required is True


@pytest.mark.asyncio
async def test_server_rejects_endpoint_mutation_after_registry_before_challenge() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    endpoint = MutableEndpoint()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    state = FakeState()
    readiness = FakeReadiness()
    factory = SessionFactory()
    server = ReachyWssServer(
        endpoint,
        tls_context=object(),
        device_registry=MutatingDeviceRegistry(endpoint),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=factory,
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
    )

    with pytest.raises(PermissionError, match="reachy_endpoint_changed"):
        await server.accept(socket)

    assert factory.created == 0
    assert socket.sent == []
    assert socket.closed == [(1008, "reachy_handshake_failed")]
    _assert_pre_session_failure_observed(
        state,
        readiness,
        "reachy_pre_session_failed:PermissionError",
    )


@pytest.mark.asyncio
async def test_server_rejects_endpoint_mutation_after_challenge_before_proof_resolution() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    endpoint = MutableEndpoint()
    socket = MutatingProofServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        endpoint=endpoint,
        proof_signer=signer,
    )
    state = FakeState()
    readiness = FakeReadiness()
    factory = SessionFactory()
    pairing_keys = PermissiveCorePairingKeys(signer, Ed25519PrivateKey.generate())
    server = ReachyWssServer(
        endpoint,
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=pairing_keys,
        state=state,
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=factory,
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        nonce_factory=lambda size: b"s" * size,
    )

    with pytest.raises(PermissionError, match="reachy_endpoint_changed"):
        await server.accept(socket)

    assert factory.created == 0
    assert pairing_keys.inbound_arguments == []
    assert len(socket.sent) == 1
    assert socket.closed == [(1008, "reachy_handshake_failed")]
    _assert_pre_session_failure_observed(
        state,
        readiness,
        "reachy_pre_session_failed:PermissionError",
    )


@pytest.mark.asyncio
async def test_server_rejects_device_id_mutation_after_registry_before_resolution() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    device = MutableDevice()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    state = FakeState()
    readiness = FakeReadiness()
    factory = SessionFactory()
    pairing_keys = DeviceMutatingPairingKeys(
        device,
        signer,
        Ed25519PrivateKey.generate(),
    )
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=MutableDeviceRegistry(device),
        pairing_keys=pairing_keys,
        state=state,
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=factory,
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        nonce_factory=lambda size: b"s" * size,
    )

    with pytest.raises(PermissionError, match="reachy_device_changed"):
        await server.accept(socket)

    assert factory.created == 0
    assert pairing_keys.inbound_resolutions == 0
    assert socket.closed == [(1008, "reachy_handshake_failed")]
    _assert_pre_session_failure_observed(
        state,
        readiness,
        "reachy_pre_session_failed:PermissionError",
    )


@pytest.mark.asyncio
async def test_server_session_uses_frozen_outbound_keys_after_later_mutation() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    pairing_keys = OutboundMutatingPairingKeys(signer, Ed25519PrivateKey.generate())
    socket = MutatingOutboundKeysServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        outbound_keys=pairing_keys.outbound,
        proof_signer=signer,
    )
    factory = RecordingSessionFactory()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=pairing_keys,
        state=FakeState(),
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=FakeReadiness(),
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=factory,
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        nonce_factory=lambda size: b"s" * size,
    )

    await server.accept(socket)

    assert factory.outbound_signing_key_ids == [SERVER_KEY_ID]
    assert factory.outbound_hmac_roots == [b"h" * 32]


@pytest.mark.asyncio
async def test_server_rejects_legacy_unbound_device_proof_before_session() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = LegacyProofServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    state = FakeState()
    readiness = FakeReadiness()
    factory = SessionFactory()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=factory,
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        nonce_factory=lambda size: b"s" * size,
    )

    with pytest.raises(PermissionError, match="device_challenge"):
        await server.accept(socket)

    assert factory.created == 0
    assert socket.closed == [(1008, "reachy_handshake_failed")]
    _assert_pre_session_failure_observed(
        state,
        readiness,
        "reachy_pre_session_failed:PermissionError",
    )


@pytest.mark.asyncio
async def test_connection_nonce_matches_frozen_raw_nonce_interop_vector() -> None:
    import tuntun_core.adapters.reachy.wss_server as core_wss
    import tuntun_edge.transport.websocket as edge_wss

    challenge = DeviceChallengeV1(
        schema_version="tuntun.reachy-device-challenge.v1",
        challenge_b64=base64.b64encode(b"a" * 32).decode("ascii"),
        server_nonce_b64=base64.b64encode(b"b" * 32).decode("ascii"),
        endpoint_generation=7,
    )
    client_nonce_b64 = base64.b64encode(b"c" * 32).decode("ascii")
    expected = bytes.fromhex("a0072c38c4ca385fcfada6fbb8d31e72ffb8cd037662b0c6ac7e05b44f8738d1")

    assert expected == _expected_raw_connection_nonce(challenge, client_nonce_b64)
    assert expected == core_wss._expected_connection_nonce(challenge, client_nonce_b64)
    assert expected == edge_wss._expected_connection_nonce(challenge, client_nonce_b64)


def test_connection_nonce_rejects_noncanonical_nonce_base64() -> None:
    import tuntun_core.adapters.reachy.wss_server as core_wss
    import tuntun_edge.transport.websocket as edge_wss

    challenge = DeviceChallengeV1(
        schema_version="tuntun.reachy-device-challenge.v1",
        challenge_b64=base64.b64encode(b"a" * 32).decode("ascii"),
        server_nonce_b64=base64.b64encode(b"b" * 32).decode("ascii"),
        endpoint_generation=7,
    )
    noncanonical_client_nonce_b64 = base64.b64encode(b"c" * 32).decode("ascii").rstrip("=")

    with pytest.raises(ValueError, match="connection_nonce_or_sequence"):
        core_wss._expected_connection_nonce(challenge, noncanonical_client_nonce_b64)
    with pytest.raises(ValueError, match="connection_nonce_or_sequence"):
        edge_wss._expected_connection_nonce(challenge, noncanonical_client_nonce_b64)


@pytest.mark.asyncio
async def test_server_connection_nonce_uses_raw_nonce_concatenation() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=FakeState(),
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=FakeReadiness(),
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        nonce_factory=lambda size: b"s" * size,
    )

    await server.accept(socket)

    challenge = parse_contract_json(
        DeviceChallengeV1,
        socket.sent[0].encode("utf-8"),
        max_bytes=8_192,
        require_canonical=True,
    )
    accepted = parse_contract_json(
        ChallengeAcceptedV1,
        socket.sent[-1].encode("utf-8"),
        max_bytes=8_192,
        require_canonical=True,
    )
    client_nonce_b64 = base64.b64encode(b"c" * 32).decode("ascii")
    accepted_nonce = base64.b64decode(accepted.connection_nonce_b64, validate=True)
    raw_nonce = hashlib.sha256(
        base64.b64decode(challenge.challenge_b64, validate=True)
        + base64.b64decode(challenge.server_nonce_b64, validate=True)
        + b"c" * 32
    ).digest()

    assert accepted_nonce == _expected_raw_connection_nonce(
        challenge,
        client_nonce_b64,
    )
    assert accepted_nonce == raw_nonce


@pytest.mark.asyncio
async def test_server_accepts_one_current_application_client_and_publishes_session() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    release_first_session = asyncio.Event()
    sessions = SessionPublisher()
    factory = SessionFactory(release=release_first_session)
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=FakeState(),
        handler=FakeHandler(),
        sessions=sessions,
        readiness=FakeReadiness(),
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=factory,
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        nonce_factory=lambda size: b"s" * size,
    )

    first = asyncio.create_task(server.accept(socket))
    await factory.created_event.wait()
    competing = ServerSocket("/v1/reachy", "tuntun.reachy.v1", [])

    await server.accept(competing)

    accepted = parse_contract_json(
        ChallengeAcceptedV1,
        socket.sent[-1].encode("utf-8"),
        max_bytes=8_192,
        require_canonical=True,
    )
    assert len(base64.b64decode(accepted.connection_nonce_b64, validate=True)) == 32
    assert factory.created == 1
    assert sessions.published == [DEVICE_ID]
    assert competing.closed == [(1013, "commissioned_reachy_already_connected")]
    assert competing.sent == []
    release_first_session.set()
    await first
    assert sessions.cleared == [DEVICE_ID]

    replacement = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    await server.accept(replacement)
    assert factory.created == 2
    assert sessions.published == [DEVICE_ID, DEVICE_ID]
    assert sessions.cleared == [DEVICE_ID, DEVICE_ID]


@pytest.mark.asyncio
async def test_server_busy_client_rejection_close_is_bounded() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    release_first_session = asyncio.Event()
    factory = SessionFactory(release=release_first_session)
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=FakeState(),
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=FakeReadiness(),
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=factory,
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        nonce_factory=lambda size: b"s" * size,
        socket_close_timeout=0.001,
    )

    first = asyncio.create_task(server.accept(socket))
    await asyncio.wait_for(factory.created_event.wait(), timeout=1)
    competing = HangingCloseServerSocket("/v1/reachy", "tuntun.reachy.v1", [])
    try:
        await asyncio.wait_for(server.accept(competing), timeout=0.05)
    finally:
        release_first_session.set()
        await first

    assert competing.close_started.is_set()


@pytest.mark.asyncio
async def test_server_session_clear_failure_is_latched_and_raised() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    readiness = FakeReadiness()
    sessions = FailingClearSessionPublisher()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=FakeState(),
        handler=FakeHandler(),
        sessions=sessions,
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        nonce_factory=lambda size: b"s" * size,
    )

    with pytest.raises(RuntimeError, match="reachy_session_clear_degraded"):
        await server.accept(socket)

    assert sessions.published == [DEVICE_ID]
    assert readiness.disconnect_degraded_codes == ("reachy_session_clear:RuntimeError",)
    assert readiness.restart_required is True


@pytest.mark.asyncio
async def test_server_session_clear_timeout_is_bounded_latched_and_raised() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    readiness = FakeReadiness()
    sessions = HangingClearSessionPublisher()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=FakeState(),
        handler=FakeHandler(),
        sessions=sessions,
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        nonce_factory=lambda size: b"s" * size,
        pre_session_cleanup_timeout=0.001,
    )

    with pytest.raises(RuntimeError, match="reachy_session_clear_degraded"):
        await asyncio.wait_for(server.accept(socket), timeout=0.05)

    assert sessions.published == [DEVICE_ID]
    assert sessions.clear_started.is_set()
    assert sessions.clear_cancelled.is_set()
    assert readiness.disconnect_degraded_codes == ("reachy_session_clear:timeout",)
    assert readiness.restart_required is True


@pytest.mark.asyncio
async def test_server_session_clear_cancellation_observed_before_reraising() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    readiness = FakeReadiness()
    sessions = HangingClearSessionPublisher()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=FakeState(),
        handler=FakeHandler(),
        sessions=sessions,
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        nonce_factory=lambda size: b"s" * size,
        pre_session_cleanup_timeout=0.001,
    )

    task = asyncio.create_task(server.accept(socket))
    await asyncio.wait_for(sessions.clear_started.wait(), timeout=1)
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=0.05)

    assert sessions.clear_cancelled.is_set()
    assert readiness.disconnect_degraded_codes == ("reachy_session_clear:timeout",)
    assert readiness.restart_required is True


@pytest.mark.asyncio
async def test_server_session_clear_uses_direct_task_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tuntun_core.adapters.reachy.wss_server as core_wss
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    readiness = FakeReadiness()
    sessions = SessionPublisher()
    real_create_task = asyncio.create_task

    def create_task_or_fail(coro: Awaitable[object], *, name: str | None = None) -> Any:
        if name == "reachy_session_clear":
            close = getattr(coro, "close", None)
            if callable(close):
                close()
            raise RuntimeError("task factory unavailable")
        return real_create_task(coro, name=name)

    monkeypatch.setattr(core_wss.asyncio, "create_task", create_task_or_fail)
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=FakeState(),
        handler=FakeHandler(),
        sessions=sessions,
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        nonce_factory=lambda size: b"s" * size,
    )

    await server.accept(socket)

    assert sessions.published == [DEVICE_ID]
    assert sessions.cleared == [DEVICE_ID]
    assert readiness.disconnect_degraded_codes == ()


@pytest.mark.asyncio
async def test_server_session_clear_latches_when_both_task_factories_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tuntun_core.adapters.reachy.wss_server as core_wss
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    signer = Ed25519PrivateKey.generate()
    socket = ServerSocket(
        "/v1/reachy",
        "tuntun.reachy.v1",
        [],
        proof_signer=signer,
    )
    readiness = FakeReadiness()
    sessions = SessionPublisher()
    real_create_task = asyncio.create_task
    real_task = asyncio.Task

    def create_task_or_fail(coro: Awaitable[object], *, name: str | None = None) -> Any:
        if name == "reachy_session_clear":
            close = getattr(coro, "close", None)
            if callable(close):
                close()
            raise RuntimeError("task factory unavailable")
        return real_create_task(coro, name=name)

    def task_or_fail(coro: Awaitable[object], *, name: str | None = None, **kwargs: object) -> Any:
        if name == "reachy_session_clear":
            close = getattr(coro, "close", None)
            if callable(close):
                close()
            raise RuntimeError("direct task unavailable")
        return real_task(coro, name=name, **kwargs)

    monkeypatch.setattr(core_wss.asyncio, "create_task", create_task_or_fail)
    monkeypatch.setattr(core_wss.asyncio, "Task", task_or_fail)
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(signer, Ed25519PrivateKey.generate()),
        state=FakeState(),
        handler=FakeHandler(),
        sessions=sessions,
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        client_certificate_verifier=lambda _socket, expected: ("TLSv1.3", CLIENT_CERTIFICATE_DER),
        nonce_factory=lambda size: b"s" * size,
    )

    with pytest.raises(RuntimeError, match="reachy_session_clear_degraded"):
        await server.accept(socket)

    assert sessions.published == [DEVICE_ID]
    assert sessions.cleared == []
    assert readiness.disconnect_degraded_codes == ("reachy_session_clear:factory_unavailable",)
    assert readiness.restart_required is True


@pytest.mark.asyncio
async def test_server_close_wait_closed_is_bounded() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    hanging_server = HangingServer()
    readiness = FakeReadiness()

    async def serve_factory(
        handler: Callable[[Any], Awaitable[None]],
        **kwargs: object,
    ) -> object:
        assert callable(handler)
        assert kwargs["host"] == "192.168.50.10"
        return hanging_server

    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()),
        state=FakeState(),
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        serve_factory=serve_factory,
        socket_close_timeout=0.001,
    )

    await server.start()
    await asyncio.wait_for(server.close(), timeout=0.05)

    assert hanging_server.close_called is True
    assert hanging_server.wait_started.is_set()
    assert server._server is hanging_server
    assert readiness.disconnect_degraded_codes == ("reachy_server_close:timeout",)
    assert readiness.restart_required is True


@pytest.mark.asyncio
async def test_server_close_wait_closed_uses_direct_task_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tuntun_core.adapters.reachy.wss_server as core_wss
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    class BoundServer:
        def __init__(self) -> None:
            self.close_called = False
            self.wait_closed_called = False

        def close(self) -> None:
            self.close_called = True

        async def wait_closed(self) -> None:
            self.wait_closed_called = True

    bound_server = BoundServer()

    async def serve_factory(
        handler: Callable[[Any], Awaitable[None]],
        **kwargs: object,
    ) -> object:
        assert callable(handler)
        assert kwargs["host"] == "192.168.50.10"
        return bound_server

    real_create_task = asyncio.create_task

    def create_task_or_fail(coro: Awaitable[object], *, name: str | None = None) -> Any:
        if name == "reachy_server_wait_closed":
            close = getattr(coro, "close", None)
            if callable(close):
                close()
            raise RuntimeError("task factory unavailable")
        return real_create_task(coro, name=name)

    monkeypatch.setattr(core_wss.asyncio, "create_task", create_task_or_fail)
    readiness = FakeReadiness()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()),
        state=FakeState(),
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        serve_factory=serve_factory,
    )

    await server.start()
    await server.close()

    assert bound_server.close_called is True
    assert bound_server.wait_closed_called is True
    assert server._server is None
    assert readiness.disconnect_degraded_codes == ()


@pytest.mark.asyncio
async def test_server_start_closes_bound_server_when_endpoint_mutates_after_bind() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    endpoint = MutableEndpoint()
    readiness = FakeReadiness()

    class BoundServer:
        def __init__(self) -> None:
            self.close_called = False
            self.wait_closed_called = False

        def close(self) -> None:
            self.close_called = True

        async def wait_closed(self) -> None:
            self.wait_closed_called = True

    bound_server = BoundServer()

    async def serve_factory(
        handler: Callable[[Any], Awaitable[None]],
        **kwargs: object,
    ) -> object:
        assert callable(handler)
        assert kwargs["host"] == "192.168.50.10"
        endpoint.generation = 2
        return bound_server

    server = ReachyWssServer(
        endpoint,
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()),
        state=FakeState(),
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=readiness,
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        serve_factory=serve_factory,
        socket_close_timeout=0.001,
    )

    with pytest.raises(PermissionError, match="reachy_endpoint_changed"):
        await server.start()

    assert bound_server.close_called is True
    assert bound_server.wait_closed_called is True
    assert server._server is None


def test_server_start_binds_exact_numeric_ipv4_and_closed_protocol_options() -> None:
    from tuntun_core.adapters.reachy.wss_server import ReachyWssServer

    factory = ServeFactory()
    state = FakeState()
    server = ReachyWssServer(
        Endpoint(),
        tls_context=object(),
        device_registry=DeviceRegistry(),
        pairing_keys=CorePairingKeys(Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()),
        state=state,
        handler=FakeHandler(),
        sessions=SessionPublisher(),
        readiness=FakeReadiness(),
        time_issuer=TimeIssuer(),
        clock=Clock(),
        session_factory=SessionFactory(),
        serve_factory=factory,
    )

    asyncio.run(server.start())

    assert state.abandoned == ["restart_recovery"]
    assert factory.calls == [
        {
            "host": "192.168.50.10",
            "port": 7443,
            "ssl": server._tls_context,
            "subprotocols": ["tuntun.reachy.time.v1", "tuntun.reachy.v1"],
            "compression": None,
            "ping_interval": None,
            "max_size": 1052684,
            "max_queue": 16,
            "open_timeout": 5,
            "close_timeout": 2,
        }
    ]
    for rejected in ("0.0.0.0", "::", "127.0.0.1", "reachy-mini.local", "8.8.8.8"):
        bad_server = server.with_endpoint(Endpoint(core_ipv4=rejected))
        with pytest.raises(ValueError, match="reachy_core_endpoint_numeric_rfc1918_ipv4_required"):
            asyncio.run(bad_server.start())


class ServerSocket:
    def __init__(
        self,
        path: str,
        subprotocol: str,
        received: list[str],
        *,
        proof_signer: Ed25519PrivateKey | None = None,
    ) -> None:
        self.request = type("Request", (), {"path": path})()
        self.subprotocol: str | None = subprotocol
        self.received = received
        self.proof_signer = proof_signer
        self.sent: list[str] = []
        self.closed: list[tuple[int, str]] = []
        self.transport: object = object()

    async def send(self, message: str | bytes) -> None:
        if isinstance(message, bytes):
            message = message.decode("utf-8")
        self.sent.append(message)

    async def recv(self) -> str:
        if self.received:
            return self.received.pop(0)
        challenge = parse_contract_json(
            DeviceChallengeV1,
            self.sent[-1].encode("utf-8"),
            max_bytes=8_192,
            require_canonical=True,
        )
        client_nonce_b64 = base64.b64encode(b"c" * 32).decode("ascii")
        payload = {
            "schema_version": HANDSHAKE_SIGNATURE_PAYLOAD_SCHEMA,
            "domain": HANDSHAKE_SIGNATURE_DOMAIN,
            "route": "/v1/reachy",
            "subprotocol": "tuntun.reachy.v1",
            "challenge_schema_version": challenge.schema_version,
            "proof_schema_version": DEVICE_PROOF_SCHEMA,
            "challenge_b64": challenge.challenge_b64,
            "server_nonce_b64": challenge.server_nonce_b64,
            "client_nonce_b64": client_nonce_b64,
            "endpoint_generation": challenge.endpoint_generation,
        }
        if self.proof_signer is None:
            raise AssertionError("proof signer required")
        signature = self.proof_signer.sign(canonical_mapping_bytes(payload))
        return canonical_bytes(
            DeviceProofV1(
                schema_version=DEVICE_PROOF_SCHEMA,
                client_nonce_b64=client_nonce_b64,
                signature_b64=base64.b64encode(signature).decode("ascii"),
            )
        ).decode("utf-8")

    async def close(self, *, code: int = 1000, reason: str = "") -> None:
        self.closed.append((code, reason))


class LegacyProofServerSocket(ServerSocket):
    async def recv(self) -> str:
        if self.received:
            return self.received.pop(0)
        challenge = parse_contract_json(
            DeviceChallengeV1,
            self.sent[-1].encode("utf-8"),
            max_bytes=8_192,
            require_canonical=True,
        )
        client_nonce_b64 = base64.b64encode(b"c" * 32).decode("ascii")
        if self.proof_signer is None:
            raise AssertionError("proof signer required")
        signature = self.proof_signer.sign(
            _legacy_device_challenge_payload(challenge, client_nonce_b64)
        )
        return canonical_bytes(
            DeviceProofV1(
                schema_version=DEVICE_PROOF_SCHEMA,
                client_nonce_b64=client_nonce_b64,
                signature_b64=base64.b64encode(signature).decode("ascii"),
            )
        ).decode("utf-8")


class MutatingProofServerSocket(ServerSocket):
    def __init__(
        self,
        path: str,
        subprotocol: str,
        received: list[str],
        *,
        endpoint: MutableEndpoint,
        proof_signer: Ed25519PrivateKey,
    ) -> None:
        super().__init__(path, subprotocol, received, proof_signer=proof_signer)
        self.endpoint = endpoint

    async def recv(self) -> str:
        self.endpoint.hmac_key_id = "reachy-frame-hmac:v2"
        return await super().recv()


class MutatingOutboundKeysServerSocket(ServerSocket):
    def __init__(
        self,
        path: str,
        subprotocol: str,
        received: list[str],
        *,
        outbound_keys: CoreOutboundKeys,
        proof_signer: Ed25519PrivateKey,
    ) -> None:
        super().__init__(path, subprotocol, received, proof_signer=proof_signer)
        self.outbound_keys = outbound_keys

    async def recv(self) -> str:
        self.outbound_keys.signing_key_id = "ed25519:reachy-core:v2"
        self.outbound_keys.hmac_root = b"i" * 32
        return await super().recv()


class FailingSendServerSocket(ServerSocket):
    async def send(self, message: str | bytes) -> None:
        assert message
        raise RuntimeError("send failed")


class HangingSendServerSocket(ServerSocket):
    def __init__(
        self,
        path: str,
        subprotocol: str,
        received: list[str],
        *,
        hang_on_send: int,
        proof_signer: Ed25519PrivateKey | None = None,
    ) -> None:
        super().__init__(path, subprotocol, received, proof_signer=proof_signer)
        self.hang_on_send = hang_on_send
        self.send_attempts = 0
        self.hanging_send_started = asyncio.Event()

    async def send(self, message: str | bytes) -> None:
        assert message
        self.send_attempts += 1
        if self.send_attempts == self.hang_on_send:
            self.hanging_send_started.set()
            await asyncio.sleep(3600)
        await super().send(message)


class HangingCloseServerSocket(ServerSocket):
    def __init__(
        self,
        path: str,
        subprotocol: str,
        received: list[str],
        *,
        proof_signer: Ed25519PrivateKey | None = None,
    ) -> None:
        super().__init__(path, subprotocol, received, proof_signer=proof_signer)
        self.close_started = asyncio.Event()

    async def close(self, *, code: int = 1000, reason: str = "") -> None:
        assert code
        assert reason
        self.close_started.set()
        await asyncio.sleep(3600)


class Device:
    device_id = DEVICE_ID


class MutableDevice:
    def __init__(self) -> None:
        self.device_id = DEVICE_ID


class DeviceRegistry:
    def __init__(self, *, accept: bool = True) -> None:
        self.accept = accept
        self.calls: list[tuple[str, str, int]] = []

    async def require_current_client_certificate(
        self,
        observed_sha256: str,
        expected_sha256: str,
        endpoint_generation: int,
    ) -> Device:
        self.calls.append((observed_sha256, expected_sha256, endpoint_generation))
        if not self.accept:
            raise PermissionError("revoked_or_stale_pairing_key")
        assert observed_sha256 == CLIENT_CERTIFICATE_SHA256
        assert expected_sha256 == CLIENT_CERTIFICATE_SHA256
        assert endpoint_generation == 1
        return Device()


class MutatingDeviceRegistry(DeviceRegistry):
    def __init__(self, endpoint: MutableEndpoint) -> None:
        super().__init__()
        self.endpoint = endpoint

    async def require_current_client_certificate(
        self,
        observed_sha256: str,
        expected_sha256: str,
        endpoint_generation: int,
    ) -> Device:
        device = await super().require_current_client_certificate(
            observed_sha256,
            expected_sha256,
            endpoint_generation,
        )
        self.endpoint.generation = 2
        return device


class MutableDeviceRegistry(DeviceRegistry):
    def __init__(self, device: MutableDevice) -> None:
        super().__init__()
        self.device = device

    async def require_current_client_certificate(
        self,
        observed_sha256: str,
        expected_sha256: str,
        endpoint_generation: int,
    ) -> MutableDevice:
        await super().require_current_client_certificate(
            observed_sha256,
            expected_sha256,
            endpoint_generation,
        )
        return self.device


class FatalDeviceRegistry(DeviceRegistry):
    async def require_current_client_certificate(
        self,
        observed_sha256: str,
        expected_sha256: str,
        endpoint_generation: int,
    ) -> Device:
        await super().require_current_client_certificate(
            observed_sha256,
            expected_sha256,
            endpoint_generation,
        )
        raise FatalTransportExit


class TimeIssuer:
    def __init__(self) -> None:
        self.requests: list[tuple[bytes, str]] = []

    async def issue(self, nonce: bytes, *, client_certificate_sha256: str) -> CoreTimeProofV1:
        self.requests.append((nonce, client_certificate_sha256))
        signer = Ed25519PrivateKey.generate()
        unsigned = CoreTimeProofV1(
            schema_version="tuntun.core-time-proof.v1",
            endpoint_generation=1,
            time_sequence=1,
            request_nonce_b64=base64.b64encode(nonce).decode("ascii"),
            core_utc=NOW,
            authority_health_generation=9,
            signing_key_id=SERVER_KEY_ID,
            signature_b64=base64.b64encode(bytes(64)).decode("ascii"),
        )
        return unsigned.model_copy(
            update={
                "signature_b64": base64.b64encode(signer.sign(unsigned.signing_payload())).decode(
                    "ascii"
                )
            }
        )


class BlockingTimeIssuer(TimeIssuer):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()

    async def issue(self, nonce: bytes, *, client_certificate_sha256: str) -> CoreTimeProofV1:
        self.requests.append((nonce, client_certificate_sha256))
        self.started.set()
        await asyncio.sleep(3600)
        raise AssertionError("unreachable")


class SessionPublisher:
    def __init__(self) -> None:
        self.safety = FakeSafety()
        self.published: list[UUID] = []
        self.cleared: list[UUID] = []

    async def publish(self, device_id: UUID, session: object) -> None:
        assert isinstance(session, Session)
        self.published.append(device_id)

    async def clear(self, device_id: UUID, session: object) -> None:
        assert isinstance(session, Session)
        self.cleared.append(device_id)


class FailingSessionPublisher(SessionPublisher):
    async def publish(self, device_id: UUID, session: object) -> None:
        assert device_id == DEVICE_ID
        assert isinstance(session, Session)
        raise RuntimeError("publish failed")


class MutatingAfterPublishSessionPublisher(SessionPublisher):
    def __init__(self, endpoint: MutableEndpoint) -> None:
        super().__init__()
        self.endpoint = endpoint

    async def publish(self, device_id: UUID, session: object) -> None:
        await super().publish(device_id, session)
        self.endpoint.generation = 2


class AmbiguousPublishSessionPublisher(SessionPublisher):
    async def publish(self, device_id: UUID, session: object) -> None:
        await super().publish(device_id, session)
        raise RuntimeError("ambiguous publish failed")


class HangingClearSessionPublisher(SessionPublisher):
    def __init__(self) -> None:
        super().__init__()
        self.clear_started = asyncio.Event()
        self.clear_cancelled = asyncio.Event()

    async def clear(self, device_id: UUID, session: object) -> None:
        assert device_id == DEVICE_ID
        assert isinstance(session, Session)
        self.clear_started.set()
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            self.clear_cancelled.set()
            raise


class FailingClearSessionPublisher(SessionPublisher):
    async def clear(self, device_id: UUID, session: object) -> None:
        assert device_id == DEVICE_ID
        assert isinstance(session, Session)
        raise RuntimeError("clear failed")


class Session:
    def __init__(self, release: asyncio.Event | None = None) -> None:
        self.served = False
        self._release = release

    async def serve(self) -> None:
        self.served = True
        if self._release is not None:
            await self._release.wait()


class SessionFactory:
    def __init__(self, release: asyncio.Event | None = None) -> None:
        self.created = 0
        self.release = release
        self.created_event = asyncio.Event()

    def __call__(self, **kwargs: object) -> Session:
        self.created += 1
        assert kwargs["connection_nonce"]
        assert kwargs["tls_peer_sha256"] == CLIENT_CERTIFICATE_SHA256
        self.created_event.set()
        return Session(self.release)


class RecordingSessionFactory(SessionFactory):
    def __init__(self) -> None:
        super().__init__()
        self.outbound_signing_key_ids: list[str] = []
        self.outbound_hmac_roots: list[bytes] = []

    def __call__(self, **kwargs: object) -> Session:
        outbound_keys = kwargs["outbound_keys"]
        self.outbound_signing_key_ids.append(outbound_keys.signing_key_id)
        self.outbound_hmac_roots.append(outbound_keys.hmac_root)
        return super().__call__(**kwargs)


class HangingServer:
    def __init__(self) -> None:
        self.close_called = False
        self.wait_started = asyncio.Event()

    def close(self) -> None:
        self.close_called = True

    async def wait_closed(self) -> None:
        self.wait_started.set()
        await asyncio.sleep(3600)


class ServeFactory:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def __call__(
        self,
        handler: Callable[[Any], Awaitable[None]],
        **kwargs: object,
    ) -> object:
        assert callable(handler)
        self.calls.append(kwargs)
        return object()


@dataclass(frozen=True, slots=True)
class TlsMaterials:
    server_context: ssl.SSLContext
    client_context: ssl.SSLContext
    ca_path: Path
    server_der_sha256: str
    client_der_sha256: str


@pytest.mark.asyncio
async def test_websockets_dependency_pin_for_live_wss(tmp_path: Path) -> None:
    import tuntun_core.adapters.reachy.wss_server as core_wss
    from websockets.asyncio import client as ws_client
    from websockets.asyncio import server as ws_server

    materials = _write_ed25519_mtls_materials(tmp_path)
    observed: dict[str, object] = {}

    async def echo_handler(socket: Any) -> None:
        ssl_object = socket.transport.get_extra_info("ssl_object")
        client_der = ssl_object.getpeercert(binary_form=True)
        observed["path"] = socket.request.path
        observed["subprotocol"] = socket.subprotocol
        observed["tls_version"] = ssl_object.version()
        observed["client_der_sha256"] = hashlib.sha256(client_der).hexdigest()
        message = await socket.recv()
        await socket.send(f"echo:{message}")

    server = await ws_server.serve(
        echo_handler,
        host="127.0.0.1",
        port=0,
        ssl=materials.server_context,
        subprotocols=[core_wss.APP_SUBPROTOCOL],
        compression=None,
        ping_interval=None,
        max_size=core_wss.MAX_WSS_MESSAGE_BYTES,
        max_queue=16,
        open_timeout=5,
        close_timeout=2,
    )
    try:
        sockets = getattr(server, "sockets", None)
        assert sockets
        port = sockets[0].getsockname()[1]
        connection = await ws_client.connect(
            f"wss://127.0.0.1:{port}{core_wss.APP_PATH}",
            ssl=materials.client_context,
            server_hostname="127.0.0.1",
            subprotocols=[core_wss.APP_SUBPROTOCOL],
            compression=None,
            ping_interval=None,
            proxy=None,
            open_timeout=5,
            close_timeout=2,
            max_size=core_wss.MAX_WSS_MESSAGE_BYTES,
            max_queue=16,
        )
        try:
            ssl_object = connection.transport.get_extra_info("ssl_object")
            server_der = ssl_object.getpeercert(binary_form=True)
            assert connection.subprotocol == core_wss.APP_SUBPROTOCOL
            assert ssl_object.version() == "TLSv1.3"
            assert hashlib.sha256(server_der).hexdigest() == materials.server_der_sha256
            await connection.send("ping")
            assert await connection.recv() == "echo:ping"
        finally:
            await connection.close()
    finally:
        server.close()
        await server.wait_closed()

    assert observed == {
        "path": core_wss.APP_PATH,
        "subprotocol": core_wss.APP_SUBPROTOCOL,
        "tls_version": "TLSv1.3",
        "client_der_sha256": materials.client_der_sha256,
    }


@pytest.mark.parametrize(
    "client_auth_failure",
    ("missing_client_certificate", "wrong_client_ca"),
)
@pytest.mark.asyncio
async def test_reachy_client_run_latches_live_websockets_client_auth_failure(
    tmp_path: Path,
    client_auth_failure: str,
) -> None:
    from tuntun_edge.transport.websocket import (
        APP_PATH,
        APP_SUBPROTOCOL,
        MAX_WSS_MESSAGE_BYTES,
        ReachyWssClient,
    )
    from websockets import exceptions as ws_exceptions
    from websockets.asyncio import client as ws_client
    from websockets.asyncio import server as ws_server

    materials = _write_ed25519_mtls_materials(tmp_path)
    if client_auth_failure == "missing_client_certificate":
        client_context = _client_context_without_certificate(materials.ca_path)
    else:
        client_context = _client_context_with_wrong_client_ca_certificate(
            tmp_path,
            materials.ca_path,
        )
    application_dispatches = 0

    async def fail_if_application_dispatches(socket: Any) -> None:
        nonlocal application_dispatches
        application_dispatches += 1
        await socket.close(code=1011, reason="unexpected_application_dispatch")

    server = await ws_server.serve(
        fail_if_application_dispatches,
        host="127.0.0.1",
        port=0,
        ssl=materials.server_context,
        subprotocols=[APP_SUBPROTOCOL],
        compression=None,
        ping_interval=None,
        max_size=MAX_WSS_MESSAGE_BYTES,
        max_queue=16,
        open_timeout=5,
        close_timeout=2,
    )
    sockets = getattr(server, "sockets", None)
    assert sockets
    port = sockets[0].getsockname()[1]
    state = FakeState()
    safety = FakeSafety()
    readiness = FakeReadiness()
    handler = FakeHandler()
    sleeps: list[float] = []
    stop = asyncio.Event()
    connect_attempts = 0

    async def connect_factory(_uri: str, **kwargs: object) -> Any:
        nonlocal connect_attempts
        connect_attempts += 1
        return await ws_client.connect(
            f"wss://127.0.0.1:{port}{APP_PATH}",
            ssl=client_context,
            server_hostname="127.0.0.1",
            subprotocols=kwargs["subprotocols"],
            compression=kwargs["compression"],
            ping_interval=kwargs["ping_interval"],
            proxy=kwargs["proxy"],
            open_timeout=kwargs["open_timeout"],
            close_timeout=kwargs["close_timeout"],
            max_size=kwargs["max_size"],
            max_queue=kwargs["max_queue"],
        )

    async def fail_if_retried(delay: float) -> None:
        sleeps.append(delay)
        raise AssertionError("terminal live WebSockets mTLS failure retried")

    client = ReachyWssClient(
        Endpoint(),
        tls_context=object(),
        pairing_keys=EdgePairingKeys(Ed25519PrivateKey.generate()),
        state=state,
        safety=safety,
        handler=handler,
        readiness=readiness,
        clock=Clock(),
        connect_factory=connect_factory,
        sleeper=fail_if_retried,
    )

    try:
        with pytest.raises(ws_exceptions.InvalidMessage) as raised:
            await asyncio.wait_for(client.run(stop), timeout=2.0)
    finally:
        server.close()
        await server.wait_closed()

    assert any(isinstance(error, EOFError) for error in _test_exception_chain(raised.value))
    assert application_dispatches == 0
    assert handler.control_calls == []
    assert handler.media_calls == []
    assert connect_attempts == 1
    assert safety.latched == ["transport_disconnect"]
    assert state.abandoned == ["disconnect"]
    assert sleeps == []
    assert readiness.disconnect_degraded_codes == (
        "reachy_recommission_required:reachy_wss_commissioning_protocol_mismatch",
    )
    assert readiness.restart_required is True


def _write_ed25519_mtls_materials(tmp_path: Path) -> TlsMaterials:
    ca_key = Ed25519PrivateKey.generate()
    server_key = Ed25519PrivateKey.generate()
    client_key = Ed25519PrivateKey.generate()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TunTun Reachy Test CA")])
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TunTun Reachy Test Server")])
    client_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TunTun Reachy Test Client")])
    now = datetime.now(UTC)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, algorithm=None)
    )
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, algorithm=None)
    )
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_name)
        .issuer_name(ca_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, algorithm=None)
    )
    ca_path = tmp_path / "ca.pem"
    server_cert_path = tmp_path / "server.pem"
    server_key_path = tmp_path / "server-key.pem"
    client_cert_path = tmp_path / "client.pem"
    client_key_path = tmp_path / "client-key.pem"
    ca_path.write_bytes(ca_cert.public_bytes(Encoding.PEM))
    server_cert_path.write_bytes(server_cert.public_bytes(Encoding.PEM))
    server_key_path.write_bytes(
        server_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    client_cert_path.write_bytes(client_cert.public_bytes(Encoding.PEM))
    client_key_path.write_bytes(
        client_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_3
    server_context.maximum_version = ssl.TLSVersion.TLSv1_3
    server_context.load_cert_chain(str(server_cert_path), str(server_key_path))
    server_context.load_verify_locations(cafile=str(ca_path))
    server_context.verify_mode = ssl.CERT_REQUIRED
    client_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_path))
    client_context.minimum_version = ssl.TLSVersion.TLSv1_3
    client_context.maximum_version = ssl.TLSVersion.TLSv1_3
    client_context.load_cert_chain(str(client_cert_path), str(client_key_path))
    return TlsMaterials(
        server_context=server_context,
        client_context=client_context,
        ca_path=ca_path,
        server_der_sha256=hashlib.sha256(server_cert.public_bytes(Encoding.DER)).hexdigest(),
        client_der_sha256=hashlib.sha256(client_cert.public_bytes(Encoding.DER)).hexdigest(),
    )


def _client_context_without_certificate(ca_path: Path) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_path))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    return context


def _client_context_with_wrong_client_ca_certificate(
    tmp_path: Path,
    trusted_server_ca_path: Path,
) -> ssl.SSLContext:
    ca_key = Ed25519PrivateKey.generate()
    client_key = Ed25519PrivateKey.generate()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue Reachy Test CA")])
    client_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue Reachy Test Client")])
    now = datetime.now(UTC)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, algorithm=None)
    )
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_name)
        .issuer_name(ca_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, algorithm=None)
    )
    ca_path = tmp_path / "rogue-ca.pem"
    client_cert_path = tmp_path / "rogue-client.pem"
    client_key_path = tmp_path / "rogue-client-key.pem"
    ca_path.write_bytes(ca_cert.public_bytes(Encoding.PEM))
    client_cert_path.write_bytes(client_cert.public_bytes(Encoding.PEM))
    client_key_path.write_bytes(
        client_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    context = _client_context_without_certificate(trusted_server_ca_path)
    context.load_cert_chain(str(client_cert_path), str(client_key_path))
    return context


def _test_exception_chain(error: BaseException) -> list[BaseException]:
    chain: list[BaseException] = []
    seen: set[int] = set()
    stack: list[BaseException] = [error]
    while stack:
        current = stack.pop()
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        chain.append(current)
        context = current.__context__ if not current.__suppress_context__ else None
        if context is not None:
            stack.append(context)
        if current.__cause__ is not None:
            stack.append(current.__cause__)
    return chain
