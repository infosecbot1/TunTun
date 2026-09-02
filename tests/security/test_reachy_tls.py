from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import ssl
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

HOST = "127.0.0.1"
OTHER_HOST = "127.0.0.2"
PASSWORDLESS_PRIVATE_KEY = serialization.NoEncryption()


@dataclass(frozen=True, slots=True)
class TlsMaterial:
    ca_pem: Path
    alternate_ca_pem: Path
    server_cert_pem: Path
    server_key_pem: Path
    server_wrong_ip_cert_pem: Path
    server_wrong_ip_key_pem: Path
    client_cert_pem: Path
    client_key_pem: Path
    alternate_client_cert_pem: Path
    alternate_client_key_pem: Path
    server_leaf_der: bytes
    client_leaf_der: bytes

    @property
    def server_leaf_sha256(self) -> str:
        return hashlib.sha256(self.server_leaf_der).hexdigest()

    @property
    def client_leaf_sha256(self) -> str:
        return hashlib.sha256(self.client_leaf_der).hexdigest()


@dataclass(slots=True)
class HandshakeResult:
    client_version: str
    server_version: str
    client_peer_der: bytes
    server_peer_der: bytes
    client_reply: bytes
    server_received: list[bytes]


class HandshakeFailure(Exception):
    def __init__(
        self,
        *,
        client_error: BaseException | None,
        server_error: BaseException | None,
        server_received: tuple[bytes, ...],
    ) -> None:
        messages = tuple(
            str(error) for error in (client_error, server_error) if error is not None and str(error)
        )
        super().__init__("; ".join(messages) or "tls_handshake_failed")
        self.client_error = client_error
        self.server_error = server_error
        self.server_received = server_received


@pytest.fixture()
def tls_material(tmp_path: Path) -> TlsMaterial:
    primary_ca_key, primary_ca_cert = _new_ca("tuntun-household-ca")
    alternate_ca_key, alternate_ca_cert = _new_ca("wrong-household-ca")
    server_key, server_cert = _new_leaf(
        primary_ca_key,
        primary_ca_cert,
        common_name="tuntun-core",
        ip_san=HOST,
        usage=ExtendedKeyUsageOID.SERVER_AUTH,
    )
    wrong_ip_server_key, wrong_ip_server_cert = _new_leaf(
        primary_ca_key,
        primary_ca_cert,
        common_name="tuntun-core-wrong-ip",
        ip_san=OTHER_HOST,
        usage=ExtendedKeyUsageOID.SERVER_AUTH,
    )
    client_key, client_cert = _new_leaf(
        primary_ca_key,
        primary_ca_cert,
        common_name="reachy-edge",
        ip_san=HOST,
        usage=ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    alternate_client_key, alternate_client_cert = _new_leaf(
        alternate_ca_key,
        alternate_ca_cert,
        common_name="untrusted-reachy-edge",
        ip_san=HOST,
        usage=ExtendedKeyUsageOID.CLIENT_AUTH,
    )

    return TlsMaterial(
        ca_pem=_write_cert(tmp_path / "household-ca.pem", primary_ca_cert),
        alternate_ca_pem=_write_cert(tmp_path / "alternate-ca.pem", alternate_ca_cert),
        server_cert_pem=_write_cert(tmp_path / "core-server.pem", server_cert),
        server_key_pem=_write_key(tmp_path / "core-server.key", server_key),
        server_wrong_ip_cert_pem=_write_cert(
            tmp_path / "core-server-wrong-ip.pem",
            wrong_ip_server_cert,
        ),
        server_wrong_ip_key_pem=_write_key(
            tmp_path / "core-server-wrong-ip.key", wrong_ip_server_key
        ),
        client_cert_pem=_write_cert(tmp_path / "reachy-client.pem", client_cert),
        client_key_pem=_write_key(tmp_path / "reachy-client.key", client_key),
        alternate_client_cert_pem=_write_cert(
            tmp_path / "alternate-reachy-client.pem",
            alternate_client_cert,
        ),
        alternate_client_key_pem=_write_key(
            tmp_path / "alternate-reachy-client.key",
            alternate_client_key,
        ),
        server_leaf_der=server_cert.public_bytes(serialization.Encoding.DER),
        client_leaf_der=client_cert.public_bytes(serialization.Encoding.DER),
    )


def test_contexts_require_tls13_mutual_certificates_hostname_checks_and_no_tickets(
    tls_material: TlsMaterial,
) -> None:
    from tuntun_core.adapters.reachy.tls import build_server_tls_context
    from tuntun_edge.transport.tls import build_client_tls_context

    client = build_client_tls_context(
        tls_material.ca_pem,
        tls_material.client_cert_pem,
        tls_material.client_key_pem,
    )
    server = build_server_tls_context(
        tls_material.ca_pem,
        tls_material.server_cert_pem,
        tls_material.server_key_pem,
    )

    assert client.minimum_version == ssl.TLSVersion.TLSv1_3
    assert client.maximum_version == ssl.TLSVersion.TLSv1_3
    assert server.minimum_version == ssl.TLSVersion.TLSv1_3
    assert server.maximum_version == ssl.TLSVersion.TLSv1_3
    assert client.verify_mode == ssl.CERT_REQUIRED
    assert server.verify_mode == ssl.CERT_REQUIRED
    assert client.check_hostname is True
    assert server.check_hostname is False
    assert client.options & ssl.OP_NO_TICKET
    assert server.options & ssl.OP_NO_TICKET
    assert client.options & ssl.OP_NO_COMPRESSION
    assert server.options & ssl.OP_NO_COMPRESSION
    assert server.num_tickets == 0


@pytest.mark.parametrize(
    ("builder_module", "builder_name"),
    (
        ("tuntun_edge.transport.tls", "build_client_tls_context"),
        ("tuntun_core.adapters.reachy.tls", "build_server_tls_context"),
    ),
)
def test_context_builders_reject_unsafe_path_shapes_before_ssl_fallbacks(
    tls_material: TlsMaterial,
    builder_module: str,
    builder_name: str,
    tmp_path: Path,
) -> None:
    module = __import__(builder_module, fromlist=[builder_name])
    builder = getattr(module, builder_name)

    with pytest.raises(TypeError, match="reachy_tls_ca_pem_path_invalid"):
        builder(
            str(tls_material.ca_pem),
            tls_material.client_cert_pem,
            tls_material.client_key_pem,
        )

    deceptive_path_type = type("DeceptivePath", (type(tls_material.ca_pem),), {})

    with pytest.raises(TypeError, match="reachy_tls_ca_pem_path_invalid"):
        builder(
            deceptive_path_type(tls_material.ca_pem),
            tls_material.client_cert_pem,
            tls_material.client_key_pem,
        )

    with pytest.raises(FileNotFoundError, match="reachy_tls_certificate_pem_not_found"):
        builder(
            tls_material.ca_pem,
            tmp_path / "missing-leaf.pem",
            tls_material.client_key_pem,
        )

    with pytest.raises(ValueError, match="reachy_tls_key_pem_not_file"):
        builder(
            tls_material.ca_pem,
            tls_material.client_cert_pem,
            tmp_path,
        )

    symlink_ca = tmp_path / "symlink-ca.pem"
    symlink_ca.symlink_to(tls_material.ca_pem)
    with pytest.raises(ValueError, match="reachy_tls_ca_pem_not_file"):
        builder(
            symlink_ca,
            tls_material.client_cert_pem,
            tls_material.client_key_pem,
        )

    fifo_key = tmp_path / "key-fifo.pem"
    os.mkfifo(fifo_key)
    with pytest.raises(ValueError, match="reachy_tls_key_pem_not_file"):
        builder(
            tls_material.ca_pem,
            tls_material.client_cert_pem,
            fifo_key,
        )


def test_real_loopback_handshake_negotiates_mtls_tls13_and_ip_san(
    tls_material: TlsMaterial,
) -> None:
    from tuntun_core.adapters.reachy.tls import (
        build_server_tls_context,
        require_client_certificate_sha256,
    )
    from tuntun_edge.transport.tls import build_client_tls_context, require_server_leaf_sha256

    client_context = build_client_tls_context(
        tls_material.ca_pem,
        tls_material.client_cert_pem,
        tls_material.client_key_pem,
    )
    server_context = build_server_tls_context(
        tls_material.ca_pem,
        tls_material.server_cert_pem,
        tls_material.server_key_pem,
    )

    result = _handshake(client_context, server_context)

    assert result.client_version == "TLSv1.3"
    assert result.server_version == "TLSv1.3"
    assert result.client_peer_der == tls_material.server_leaf_der
    assert result.server_peer_der == tls_material.client_leaf_der
    assert result.client_reply == b"ok"
    assert result.server_received == [b"x"]

    with _connected_tls_pair(client_context, server_context) as pair:
        assert require_server_leaf_sha256(pair.client, tls_material.server_leaf_sha256) == (
            "TLSv1.3",
            tls_material.server_leaf_der,
        )
        assert require_client_certificate_sha256(pair.server, tls_material.client_leaf_sha256) == (
            "TLSv1.3",
            tls_material.client_leaf_der,
        )


@pytest.mark.parametrize(
    "failure_kind",
    ("wrong_ca", "missing_client_cert", "wrong_client_ca", "wrong_ip_san"),
)
def test_tls_identity_failures_happen_before_application_data(
    tls_material: TlsMaterial,
    failure_kind: str,
) -> None:
    from tuntun_core.adapters.reachy.tls import build_server_tls_context
    from tuntun_edge.transport.tls import build_client_tls_context

    if failure_kind == "wrong_ca":
        client_context = build_client_tls_context(
            tls_material.alternate_ca_pem,
            tls_material.client_cert_pem,
            tls_material.client_key_pem,
        )
        server_context = build_server_tls_context(
            tls_material.ca_pem,
            tls_material.server_cert_pem,
            tls_material.server_key_pem,
        )
    elif failure_kind == "missing_client_cert":
        client_context = _client_context_without_certificate(tls_material.ca_pem)
        server_context = build_server_tls_context(
            tls_material.ca_pem,
            tls_material.server_cert_pem,
            tls_material.server_key_pem,
        )
    elif failure_kind == "wrong_client_ca":
        client_context = build_client_tls_context(
            tls_material.ca_pem,
            tls_material.alternate_client_cert_pem,
            tls_material.alternate_client_key_pem,
        )
        server_context = build_server_tls_context(
            tls_material.ca_pem,
            tls_material.server_cert_pem,
            tls_material.server_key_pem,
        )
    else:
        client_context = build_client_tls_context(
            tls_material.ca_pem,
            tls_material.client_cert_pem,
            tls_material.client_key_pem,
        )
        server_context = build_server_tls_context(
            tls_material.ca_pem,
            tls_material.server_wrong_ip_cert_pem,
            tls_material.server_wrong_ip_key_pem,
        )

    with pytest.raises(HandshakeFailure) as failure_context:
        _handshake(client_context, server_context)
    failure = failure_context.value
    assert failure.server_received == ()
    assert isinstance(failure.client_error, (ssl.SSLError, OSError)) or isinstance(
        failure.server_error,
        (ssl.SSLError, OSError),
    )


def test_wrong_leaf_pin_is_permission_error_before_application_data(
    tls_material: TlsMaterial,
) -> None:
    from tuntun_core.adapters.reachy.tls import build_server_tls_context
    from tuntun_edge.transport.tls import build_client_tls_context, require_server_leaf_sha256

    client_context = build_client_tls_context(
        tls_material.ca_pem,
        tls_material.client_cert_pem,
        tls_material.client_key_pem,
    )
    server_context = build_server_tls_context(
        tls_material.ca_pem,
        tls_material.server_cert_pem,
        tls_material.server_key_pem,
    )

    wrong_but_well_formed_digest = "0" * 64
    with pytest.raises(HandshakeFailure, match="reachy_server_leaf_mismatch") as failure_context:
        _handshake(
            client_context,
            server_context,
            before_client_app_data=lambda tls_socket: require_server_leaf_sha256(
                tls_socket,
                wrong_but_well_formed_digest,
            ),
        )
    failure = failure_context.value
    assert failure.server_received == ()
    assert isinstance(failure.client_error, PermissionError)


def test_server_pin_helper_rejects_unverified_tls_context(tls_material: TlsMaterial) -> None:
    from tuntun_core.adapters.reachy.tls import build_server_tls_context
    from tuntun_edge.transport.tls import require_server_leaf_sha256

    client_context = _unverified_client_context(
        tls_material.client_cert_pem,
        tls_material.client_key_pem,
    )
    server_context = build_server_tls_context(
        tls_material.ca_pem,
        tls_material.server_cert_pem,
        tls_material.server_key_pem,
    )

    with (
        _connected_tls_pair(client_context, server_context) as pair,
        pytest.raises(PermissionError, match="reachy_tls_peer_verification_required"),
    ):
        require_server_leaf_sha256(pair.client, tls_material.server_leaf_sha256)


def test_server_pin_helper_requires_hostname_checked_tls_context(
    tls_material: TlsMaterial,
) -> None:
    from tuntun_core.adapters.reachy.tls import build_server_tls_context
    from tuntun_edge.transport.tls import require_server_leaf_sha256

    client_context = _manual_no_hostname_client_context(
        tls_material.ca_pem,
        tls_material.client_cert_pem,
        tls_material.client_key_pem,
    )
    server_context = build_server_tls_context(
        tls_material.ca_pem,
        tls_material.server_cert_pem,
        tls_material.server_key_pem,
    )

    with (
        _connected_tls_pair(client_context, server_context) as pair,
        pytest.raises(PermissionError, match="reachy_tls_hostname_verification_required"),
    ):
        require_server_leaf_sha256(pair.client, tls_material.server_leaf_sha256)


def test_client_pin_helper_requires_mtls_cert_required_context(tls_material: TlsMaterial) -> None:
    from tuntun_core.adapters.reachy.tls import require_client_certificate_sha256
    from tuntun_edge.transport.tls import build_client_tls_context

    client_context = build_client_tls_context(
        tls_material.ca_pem,
        tls_material.client_cert_pem,
        tls_material.client_key_pem,
    )
    server_context = _manual_optional_client_auth_server_context(
        tls_material.ca_pem,
        tls_material.server_cert_pem,
        tls_material.server_key_pem,
    )

    with (
        _connected_tls_pair(client_context, server_context) as pair,
        pytest.raises(PermissionError, match="reachy_tls_peer_verification_required"),
    ):
        require_client_certificate_sha256(pair.server, tls_material.client_leaf_sha256)


def test_tls12_only_peer_fails_before_application_data(tls_material: TlsMaterial) -> None:
    from tuntun_core.adapters.reachy.tls import build_server_tls_context
    from tuntun_edge.transport.tls import build_client_tls_context

    client_context = build_client_tls_context(
        tls_material.ca_pem,
        tls_material.client_cert_pem,
        tls_material.client_key_pem,
    )
    server_context = build_server_tls_context(
        tls_material.ca_pem,
        tls_material.server_cert_pem,
        tls_material.server_key_pem,
    )
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.maximum_version = ssl.TLSVersion.TLSv1_2

    with pytest.raises(HandshakeFailure) as failure_context:
        _handshake(client_context, server_context)
    failure = failure_context.value
    assert failure.server_received == ()
    assert isinstance(failure.client_error, (ssl.SSLError, OSError)) or isinstance(
        failure.server_error,
        (ssl.SSLError, OSError),
    )


@pytest.mark.parametrize(
    ("side_module", "helper_name", "expected_digest"),
    (
        ("tuntun_edge.transport.tls", "require_server_leaf_sha256", "server_leaf_sha256"),
        (
            "tuntun_core.adapters.reachy.tls",
            "require_client_certificate_sha256",
            "client_leaf_sha256",
        ),
    ),
)
def test_peer_pin_helpers_reject_tls12_live_peers_and_caller_provided_der(
    tls_material: TlsMaterial,
    side_module: str,
    helper_name: str,
    expected_digest: str,
) -> None:
    module = __import__(side_module, fromlist=[helper_name])
    helper = getattr(module, helper_name)
    client_context = _manual_tls12_client_context(
        tls_material.ca_pem,
        tls_material.client_cert_pem,
        tls_material.client_key_pem,
    )
    server_context = _manual_tls12_server_context(
        tls_material.ca_pem,
        tls_material.server_cert_pem,
        tls_material.server_key_pem,
    )

    with _connected_tls_pair(client_context, server_context) as pair:
        peer = pair.client if "server" in helper_name else pair.server
        with pytest.raises(PermissionError, match="reachy_tls13_required"):
            helper(peer, getattr(tls_material, expected_digest))

    with pytest.raises(TypeError, match="reachy_tls_connection_invalid"):
        helper(tls_material.server_leaf_der, getattr(tls_material, expected_digest))

    with pytest.raises(ValueError, match="reachy_expected_leaf_sha256_invalid"):
        helper(object(), getattr(tls_material, expected_digest).upper())


@dataclass(slots=True)
class ConnectedTlsPair:
    client: ssl.SSLSocket
    server: ssl.SSLSocket
    raw_listener: socket.socket
    raw_client: socket.socket | None = None
    raw_server: socket.socket | None = None

    def __enter__(self) -> ConnectedTlsPair:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.client.close()
        self.server.close()
        self.raw_listener.close()


def _new_ca(common_name: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(tz=UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _new_leaf(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    *,
    common_name: str,
    ip_san: str,
    usage: ObjectIdentifier,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(tz=UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip_san))]),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return key, certificate


def _write_cert(path: Path, certificate: x509.Certificate) -> Path:
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return path


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> Path:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            PASSWORDLESS_PRIVATE_KEY,
        )
    )
    return path


def _handshake(
    client_context: ssl.SSLContext,
    server_context: ssl.SSLContext,
    *,
    before_client_app_data: Callable[[ssl.SSLSocket], object] | None = None,
) -> HandshakeResult:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((HOST, 0))
    listener.listen(1)
    listener.settimeout(5.0)
    port = listener.getsockname()[1]
    server_received: list[bytes] = []
    server_state: dict[str, Any] = {}

    def serve_once() -> None:
        try:
            raw_connection, _ = listener.accept()
            with (
                raw_connection,
                server_context.wrap_socket(raw_connection, server_side=True) as server_tls,
            ):
                server_state["version"] = server_tls.version()
                server_state["peer_der"] = server_tls.getpeercert(binary_form=True)
                payload = server_tls.recv(1)
                if payload:
                    server_received.append(payload)
                    server_tls.sendall(b"ok")
        except BaseException as error:
            server_state["error"] = error

    thread = threading.Thread(target=serve_once)
    thread.start()
    client_state: dict[str, Any] = {}
    try:
        try:
            with (
                socket.create_connection((HOST, port), timeout=5.0) as raw_client,
                client_context.wrap_socket(raw_client, server_hostname=HOST) as client_tls,
            ):
                client_state["version"] = client_tls.version()
                client_state["peer_der"] = client_tls.getpeercert(binary_form=True)
                if before_client_app_data is not None:
                    before_client_app_data(client_tls)
                client_tls.sendall(b"x")
                client_state["reply"] = client_tls.recv(2)
        except BaseException as error:
            client_state["error"] = error
    finally:
        listener.close()
        thread.join(timeout=5.0)

    client_error = client_state.get("error")
    server_error = server_state.get("error")
    if client_error is not None or server_error is not None:
        raise HandshakeFailure(
            client_error=client_error,
            server_error=server_error,
            server_received=tuple(server_received),
        )
    return HandshakeResult(
        client_version=client_state["version"],
        server_version=server_state["version"],
        client_peer_der=client_state["peer_der"],
        server_peer_der=server_state["peer_der"],
        client_reply=client_state["reply"],
        server_received=server_received,
    )


def _connected_tls_pair(
    client_context: ssl.SSLContext,
    server_context: ssl.SSLContext,
) -> ConnectedTlsPair:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((HOST, 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    raw_client = socket.create_connection((HOST, port), timeout=5.0)
    raw_server, _ = listener.accept()
    pair: dict[str, ssl.SSLSocket] = {}
    server_error: list[BaseException] = []

    def wrap_server() -> None:
        try:
            pair["server"] = server_context.wrap_socket(raw_server, server_side=True)
        except BaseException as error:
            server_error.append(error)

    thread = threading.Thread(target=wrap_server)
    thread.start()
    try:
        pair["client"] = client_context.wrap_socket(raw_client, server_hostname=HOST)
    except BaseException:
        raw_client.close()
        raw_server.close()
        listener.close()
        thread.join(timeout=5.0)
        raise
    thread.join(timeout=5.0)
    if server_error:
        pair["client"].close()
        listener.close()
        raise server_error[0]
    return ConnectedTlsPair(client=pair["client"], server=pair["server"], raw_listener=listener)


def _client_context_without_certificate(ca_pem: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.options |= ssl.OP_NO_TICKET | ssl.OP_NO_COMPRESSION
    context.load_verify_locations(cafile=ca_pem)
    return context


def _manual_tls12_client_context(
    ca_pem: Path,
    certificate_pem: Path,
    key_pem: Path,
) -> ssl.SSLContext:
    context = _client_context_without_certificate(ca_pem)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=certificate_pem, keyfile=key_pem)
    return context


def _unverified_client_context(certificate_pem: Path, key_pem: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.options |= ssl.OP_NO_TICKET | ssl.OP_NO_COMPRESSION
    context.load_cert_chain(certfile=certificate_pem, keyfile=key_pem)
    return context


def _manual_no_hostname_client_context(
    ca_pem: Path,
    certificate_pem: Path,
    key_pem: Path,
) -> ssl.SSLContext:
    context = _client_context_without_certificate(ca_pem)
    context.check_hostname = False
    context.load_cert_chain(certfile=certificate_pem, keyfile=key_pem)
    return context


def _manual_optional_client_auth_server_context(
    ca_pem: Path,
    certificate_pem: Path,
    key_pem: Path,
) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_OPTIONAL
    context.options |= ssl.OP_NO_TICKET | ssl.OP_NO_COMPRESSION
    context.num_tickets = 0
    context.load_verify_locations(cafile=ca_pem)
    context.load_cert_chain(certfile=certificate_pem, keyfile=key_pem)
    return context


def _manual_tls12_server_context(
    ca_pem: Path,
    certificate_pem: Path,
    key_pem: Path,
) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.options |= ssl.OP_NO_TICKET | ssl.OP_NO_COMPRESSION
    context.load_verify_locations(cafile=ca_pem)
    context.load_cert_chain(certfile=certificate_pem, keyfile=key_pem)
    return context
