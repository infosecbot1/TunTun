from __future__ import annotations

import hashlib
import hmac
import re
import ssl
import stat
from pathlib import Path

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_PATH_TYPE = type(Path())


def build_client_tls_context(ca_pem: Path, certificate_pem: Path, key_pem: Path) -> ssl.SSLContext:
    ca_path = _require_existing_file(ca_pem, "ca_pem")
    certificate_path = _require_existing_file(certificate_pem, "certificate_pem")
    key_path = _require_existing_file(key_pem, "key_pem")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.options |= ssl.OP_NO_TICKET | ssl.OP_NO_COMPRESSION
    context.load_verify_locations(cafile=str(ca_path))
    context.load_cert_chain(certfile=str(certificate_path), keyfile=str(key_path))
    return context


def peer_leaf_der(tls_connection: ssl.SSLSocket | ssl.SSLObject) -> bytes:
    return _require_peer_leaf_der(tls_connection)


def peer_leaf_sha256(tls_connection: ssl.SSLSocket | ssl.SSLObject) -> str:
    return hashlib.sha256(_require_peer_leaf_der(tls_connection)).hexdigest()


def require_server_leaf_sha256(
    tls_connection: ssl.SSLSocket | ssl.SSLObject,
    expected_sha256: str,
) -> tuple[str, bytes]:
    return _require_peer_leaf_sha256(
        tls_connection,
        expected_sha256,
        mismatch_error="reachy_server_leaf_mismatch",
    )


def _require_existing_file(value: Path, name: str) -> Path:
    if type(value) is not _PATH_TYPE:
        raise TypeError(f"reachy_tls_{name}_path_invalid")
    try:
        metadata = value.stat(follow_symlinks=False)
    except FileNotFoundError:
        raise FileNotFoundError(f"reachy_tls_{name}_not_found") from None
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"reachy_tls_{name}_not_file")
    return value


def _require_peer_leaf_sha256(
    tls_connection: ssl.SSLSocket | ssl.SSLObject,
    expected_sha256: str,
    *,
    mismatch_error: str,
) -> tuple[str, bytes]:
    _require_sha256(expected_sha256)
    certificate = _require_peer_leaf_der(tls_connection)
    observed = hashlib.sha256(certificate).hexdigest()
    if not hmac.compare_digest(observed, expected_sha256):
        raise PermissionError(mismatch_error)
    return "TLSv1.3", certificate


def _require_peer_leaf_der(tls_connection: ssl.SSLSocket | ssl.SSLObject) -> bytes:
    if not isinstance(tls_connection, (ssl.SSLSocket, ssl.SSLObject)):
        raise TypeError("reachy_tls_connection_invalid")
    if tls_connection.version() != "TLSv1.3":
        raise PermissionError("reachy_tls13_required")
    if tls_connection.context.verify_mode != ssl.CERT_REQUIRED:
        raise PermissionError("reachy_tls_peer_verification_required")
    if tls_connection.context.check_hostname is not True:
        raise PermissionError("reachy_tls_hostname_verification_required")
    certificate = tls_connection.getpeercert(binary_form=True)
    if type(certificate) is not bytes or not certificate:
        raise PermissionError("reachy_peer_leaf_unavailable")
    return certificate


def _require_sha256(value: str) -> None:
    if type(value) is not str or _SHA256_HEX.fullmatch(value) is None:
        raise ValueError("reachy_expected_leaf_sha256_invalid")


__all__ = [
    "build_client_tls_context",
    "peer_leaf_der",
    "peer_leaf_sha256",
    "require_server_leaf_sha256",
]
