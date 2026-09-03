from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import hmac
import json
import os
import socket
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field
from tuntun_contracts.base import (
    ContractModel,
    canonical_bytes,
    canonical_mapping_bytes,
    parse_contract_json,
)

Digest = str
RECEIPT_MAX_BYTES = 16_384


class FirewallBootReceiptV1(ContractModel):
    schema_version: Literal["tuntun.firewall-boot-receipt.v1"]
    boot_id: UUID
    candidate_commit: str = Field(pattern=r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
    endpoint_generation: int = Field(ge=1)
    network_generation: int = Field(ge=1)
    endpoint_payload_sha256: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    network_payload_sha256: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    capability_payload_sha256: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    daemon_ports_sha256: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    neighbor_binding_sha256: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    expected_rules_sha256: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    observed_rules_sha256: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: AwareDatetime
    signing_key_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    signature_b64: str = Field(min_length=44, max_length=44, pattern=r"^[A-Za-z0-9+/]{43}=$")

    def signing_payload(self) -> bytes:
        return canonical_mapping_bytes(self.model_dump(mode="python", exclude={"signature_b64"}))


class FirewallDegradedReceiptV1(ContractModel):
    schema_version: Literal["tuntun.firewall-degraded-receipt.v1"]
    state: Literal["degraded"]
    boot_id: UUID
    reason_code: Literal[
        "preflight_failed",
        "neighbor_binding_failed",
        "apply_failed",
        "observation_failed",
        "semantic_mismatch",
        "attestation_failed",
        "start_gate_failed",
    ]
    emergency_rules_sha256: Digest = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: AwareDatetime
    signing_key_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    signature_b64: str = Field(min_length=44, max_length=44, pattern=r"^[A-Za-z0-9+/]{43}=$")

    def signing_payload(self) -> bytes:
        return canonical_mapping_bytes(self.model_dump(mode="python", exclude={"signature_b64"}))


class ReceiptSigner(Protocol):
    key_id: str

    def sign(self, payload: bytes) -> str: ...

    def verify(self, payload: bytes, signature_b64: str) -> None: ...


class LocalReceiptSigner:
    def __init__(self, key_id: str, key: bytes) -> None:
        if type(key_id) is not str or not key_id:
            raise ValueError("firewall receipt key id invalid")
        if type(key) is not bytes or len(key) < 32:
            raise ValueError("firewall receipt key too short")
        self.key_id = key_id
        self._key = bytes(key)

    def sign(self, payload: bytes) -> str:
        return base64.b64encode(hmac.digest(self._key, payload, "sha256")).decode("ascii")

    def verify(self, payload: bytes, signature_b64: str) -> None:
        if not hmac.compare_digest(self.sign(payload), signature_b64):
            raise PermissionError("firewall_boot_gate_signature_invalid")


class FirewallReceiptRepository:
    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise TypeError("receipt path must be a Path")
        _validate_receipt_path(path)
        self.path = path

    def require(self) -> FirewallBootReceiptV1:
        parent_fd = self._open_parent_fd(create=False)
        descriptor: int | None = None
        try:
            self._require_no_publication_marker(parent_fd)
            descriptor = os.open(
                self.path.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise PermissionError("firewall_boot_gate_receipt_permissions")
            payload = _read_at_most(descriptor, RECEIPT_MAX_BYTES)
            if not payload:
                raise PermissionError("firewall_boot_gate_receipt_size")
            receipt = parse_contract_json(
                FirewallBootReceiptV1,
                payload,
                max_bytes=RECEIPT_MAX_BYTES,
                require_canonical=True,
            )
            self._require_no_publication_marker(parent_fd)
            return receipt
        except PermissionError:
            raise
        except OSError as error:
            raise PermissionError("firewall_boot_gate_receipt_permissions") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent_fd)

    def replace_atomic(self, receipt: FirewallBootReceiptV1 | FirewallDegradedReceiptV1) -> None:
        payload = canonical_bytes(receipt)
        if len(payload) > RECEIPT_MAX_BYTES:
            raise ValueError("firewall receipt too large")
        parent_fd = self._open_parent_fd(create=True)
        descriptor: int | None = None
        marker_descriptor: int | None = None
        temporary_name = f".{self.path.name}.{uuid4().hex}.tmp"
        marker_name = _receipt_publication_marker_name(self.path.name)
        marker_committed = False
        marker_created = False
        committed = False
        try:
            metadata = os.fstat(parent_fd)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
                raise PermissionError("firewall_boot_gate_directory_permissions")
            if stat.S_IMODE(metadata.st_mode) != 0o700:
                os.fchmod(parent_fd, 0o700)
                os.fsync(parent_fd)
            self._require_no_publication_marker(parent_fd)
            self._require_replace_target_safe(parent_fd)
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_fd,
            )
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, payload)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            marker_descriptor = os.open(
                marker_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_fd,
            )
            marker_created = True
            os.fchmod(marker_descriptor, 0o600)
            _write_all(marker_descriptor, b"tuntun-firewall-receipt-publication-v1\n")
            os.fsync(marker_descriptor)
            os.close(marker_descriptor)
            marker_descriptor = None
            os.fsync(parent_fd)
            marker_committed = True
            self._require_replace_target_safe(parent_fd)
            os.replace(
                temporary_name,
                self.path.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            os.fsync(parent_fd)
            self._remove_publication_marker_or_quarantine(parent_fd, marker_name, self.path.name)
            committed = True
        except PermissionError:
            raise
        except OSError as error:
            if marker_created:
                raise PermissionError("firewall_boot_gate_receipt_uncommitted") from error
            raise PermissionError("firewall_boot_gate_directory_permissions") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if marker_descriptor is not None:
                os.close(marker_descriptor)
            if not committed:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=parent_fd)
                if not marker_committed and marker_created:
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(marker_name, dir_fd=parent_fd)
                with contextlib.suppress(OSError):
                    os.fsync(parent_fd)
            os.close(parent_fd)

    def _open_parent_fd(self, *, create: bool) -> int:
        current_fd: int | None = None
        try:
            current_fd = os.open(self.path.anchor, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            parent_parts = [part for part in self.path.parent.parts if part != self.path.anchor]
            if not parent_parts:
                raise PermissionError("firewall_boot_gate_path_unsafe")
            for index, part in enumerate(parent_parts):
                is_final_parent = index == len(parent_parts) - 1
                if create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=current_fd)
                        os.fsync(current_fd)
                    except FileExistsError:
                        pass
                    except OSError as error:
                        raise PermissionError("firewall_boot_gate_directory_permissions") from error
                try:
                    next_fd = os.open(
                        part,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=current_fd,
                    )
                except OSError as error:
                    raise PermissionError("firewall_boot_gate_directory_permissions") from error
                os.close(current_fd)
                current_fd = next_fd
                metadata = os.fstat(current_fd)
                if not stat.S_ISDIR(metadata.st_mode):
                    raise PermissionError("firewall_boot_gate_directory_permissions")
                if is_final_parent and metadata.st_uid != os.geteuid():
                    raise PermissionError("firewall_boot_gate_directory_permissions")
            return current_fd
        except BaseException:
            if current_fd is not None:
                os.close(current_fd)
            raise

    def _require_replace_target_safe(self, parent_fd: int) -> None:
        try:
            metadata = os.stat(self.path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise PermissionError("firewall_boot_gate_receipt_permissions")

    def _require_no_publication_marker(self, parent_fd: int) -> None:
        marker_name = _receipt_publication_marker_name(self.path.name)
        for blocker_name in (marker_name, _receipt_quarantine_marker_name(marker_name)):
            try:
                os.stat(
                    blocker_name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                continue
            raise PermissionError("firewall_boot_gate_receipt_uncommitted")
        return

    def _remove_publication_marker_or_quarantine(
        self,
        parent_fd: int,
        marker_name: str,
        receipt_name: str,
    ) -> None:
        try:
            os.unlink(marker_name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except OSError:
            self._fail_closed_uncommitted_publication(parent_fd, marker_name, receipt_name)
            raise PermissionError("firewall_boot_gate_receipt_uncommitted") from None

    def _fail_closed_uncommitted_publication(
        self,
        parent_fd: int,
        marker_name: str,
        receipt_name: str,
    ) -> None:
        if self._try_restore_publication_marker(parent_fd, marker_name):
            return
        if self._try_restore_publication_marker(
            parent_fd,
            _receipt_quarantine_marker_name(marker_name),
        ):
            return
        self._make_receipt_name_unclaimable(parent_fd, receipt_name)

    def _try_restore_publication_marker(self, parent_fd: int, marker_name: str) -> bool:
        try:
            self._restore_publication_marker(parent_fd, marker_name)
        except OSError:
            return False
        return True

    @staticmethod
    def _make_receipt_name_unclaimable(parent_fd: int, receipt_name: str) -> None:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                receipt_name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
            os.fchmod(descriptor, 0)
            os.fsync(descriptor)
        except OSError:
            pass
        finally:
            if descriptor is not None:
                os.close(descriptor)
        with contextlib.suppress(OSError):
            os.unlink(receipt_name, dir_fd=parent_fd)
        with contextlib.suppress(OSError):
            os.fsync(parent_fd)

    @staticmethod
    def _restore_publication_marker(parent_fd: int, marker_name: str) -> None:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                marker_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_fd,
            )
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, b"tuntun-firewall-receipt-publication-v1\n")
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
        except FileExistsError:
            pass
        finally:
            if descriptor is not None:
                os.close(descriptor)
        os.fsync(parent_fd)


def issue_current_boot_receipt(
    *,
    inputs: Any,
    ruleset: dict[str, Any],
    observed_table: dict[str, Any],
    neighbor_binding_sha256: str,
    boot_id: UUID,
    candidate_commit: str,
    clock: Any,
    signer: ReceiptSigner,
    repository: FirewallReceiptRepository,
) -> FirewallBootReceiptV1:
    expected_sha256 = _rules_sha256(ruleset)
    observed_sha256 = _rules_sha256(observed_table)
    if expected_sha256 != observed_sha256:
        raise PermissionError("firewall_boot_gate_semantic_mismatch")
    fields = {
        "schema_version": "tuntun.firewall-boot-receipt.v1",
        "boot_id": boot_id,
        "candidate_commit": candidate_commit,
        "endpoint_generation": inputs.endpoint.generation,
        "network_generation": inputs.network.generation,
        "endpoint_payload_sha256": inputs.endpoint_payload_sha256,
        "network_payload_sha256": inputs.network_payload_sha256,
        "capability_payload_sha256": inputs.capability_payload_sha256,
        "daemon_ports_sha256": _ports_sha256(inputs.daemon_ports),
        "neighbor_binding_sha256": neighbor_binding_sha256,
        "expected_rules_sha256": expected_sha256,
        "observed_rules_sha256": observed_sha256,
        "issued_at": clock.now(),
        "signing_key_id": signer.key_id,
    }
    unsigned = FirewallBootReceiptV1(**fields, signature_b64="A" * 43 + "=")
    receipt = unsigned.model_copy(update={"signature_b64": signer.sign(unsigned.signing_payload())})
    repository.replace_atomic(receipt)
    return receipt


def issue_degraded_firewall_receipt(
    *,
    reason_code: str,
    emergency_rules_sha256: str,
    boot_id: UUID,
    clock: Any,
    signer: ReceiptSigner,
    repository: FirewallReceiptRepository,
) -> FirewallDegradedReceiptV1:
    fields = {
        "schema_version": "tuntun.firewall-degraded-receipt.v1",
        "state": "degraded",
        "boot_id": boot_id,
        "reason_code": reason_code,
        "emergency_rules_sha256": emergency_rules_sha256,
        "issued_at": clock.now(),
        "signing_key_id": signer.key_id,
    }
    unsigned = FirewallDegradedReceiptV1(**fields, signature_b64="A" * 43 + "=")
    receipt = unsigned.model_copy(update={"signature_b64": signer.sign(unsigned.signing_payload())})
    repository.replace_atomic(receipt)
    return receipt


def require_current_boot_receipt(
    *,
    repository: FirewallReceiptRepository,
    signer: ReceiptSigner,
    endpoint_json: bytes,
    network_json: bytes,
    capability_json: bytes,
    available_interfaces: set[str],
    boot_id: UUID,
    candidate_commit: str,
    observed_table: dict[str, Any],
    observed_neighbor_binding_sha256: str,
) -> FirewallBootReceiptV1:
    from deploy.reachy.render_firewall import build_nftables_ruleset, restore_firewall_inputs

    receipt = repository.require()
    if receipt.signing_key_id != signer.key_id:
        raise PermissionError("firewall_boot_gate_signing_key_mismatch")
    signer.verify(receipt.signing_payload(), receipt.signature_b64)
    inputs = restore_firewall_inputs(
        endpoint_json,
        network_json,
        capability_json,
        available_interfaces=available_interfaces,
    )
    expected_sha256 = _rules_sha256(build_nftables_ruleset(inputs))
    observed_sha256 = _rules_sha256(observed_table)
    expected = {
        "boot_id": boot_id,
        "candidate_commit": candidate_commit,
        "endpoint_generation": inputs.endpoint.generation,
        "network_generation": inputs.network.generation,
        "endpoint_payload_sha256": inputs.endpoint_payload_sha256,
        "network_payload_sha256": inputs.network_payload_sha256,
        "capability_payload_sha256": inputs.capability_payload_sha256,
        "daemon_ports_sha256": _ports_sha256(inputs.daemon_ports),
        "neighbor_binding_sha256": observed_neighbor_binding_sha256,
        "expected_rules_sha256": expected_sha256,
        "observed_rules_sha256": observed_sha256,
    }
    if expected_sha256 != observed_sha256 or any(
        getattr(receipt, key) != value for key, value in expected.items()
    ):
        raise PermissionError("firewall_boot_gate_binding_mismatch")
    return receipt


def gate_current_boot() -> None:
    from tuntun_edge.security.key_store import EdgeKeyStore

    from deploy.reachy.apply_firewall import (
        BOOT_ID_PATH,
        CAPABILITY_PATH,
        DEGRADED_RECEIPT_PATH,
        ENDPOINT_PATH,
        KEY_ROOT,
        NETWORK_PATH,
        RECEIPT_KEY_ID,
        RECEIPT_PATH,
        _parse_nft_json,
        _run_nft,
        install_emergency_table,
        read_candidate_commit,
        read_fixed_owner_file,
        require_neighbor_binding,
    )
    from deploy.reachy.render_firewall import restore_firewall_inputs

    signer = None
    boot_id = None
    try:
        signer = LocalReceiptSigner(RECEIPT_KEY_ID, EdgeKeyStore(KEY_ROOT).read(RECEIPT_KEY_ID))
        boot_id = UUID(read_fixed_owner_file(BOOT_ID_PATH, 64, exact_mode=None).decode().strip())
        if _path_exists_no_follow(DEGRADED_RECEIPT_PATH):
            raise PermissionError("firewall_degraded_receipt_blocks_edge")
        endpoint_json = read_fixed_owner_file(ENDPOINT_PATH, 65_536)
        network_json = read_fixed_owner_file(NETWORK_PATH, 65_536)
        capability_json = read_fixed_owner_file(CAPABILITY_PATH, 65_536)
        available_interfaces = {name for _, name in socket.if_nameindex()}
        inputs = restore_firewall_inputs(
            endpoint_json,
            network_json,
            capability_json,
            available_interfaces=available_interfaces,
        )
        neighbor_sha256 = require_neighbor_binding(inputs)
        observed = _parse_nft_json(_run_nft(["--json", "list", "table", "inet", "tuntun"]))
        require_current_boot_receipt(
            repository=FirewallReceiptRepository(RECEIPT_PATH),
            signer=signer,
            endpoint_json=endpoint_json,
            network_json=network_json,
            capability_json=capability_json,
            available_interfaces=available_interfaces,
            boot_id=boot_id,
            candidate_commit=read_candidate_commit(),
            observed_table=observed,
            observed_neighbor_binding_sha256=neighbor_sha256,
        )
    except BaseException as error:
        emergency_sha256 = install_emergency_table()
        if signer is not None and boot_id is not None and not _is_existing_degraded_marker(error):
            issue_degraded_firewall_receipt(
                reason_code="start_gate_failed",
                emergency_rules_sha256=emergency_sha256,
                boot_id=boot_id,
                clock=SystemClock(),
                signer=signer,
                repository=FirewallReceiptRepository(DEGRADED_RECEIPT_PATH),
            )
        raise PermissionError("firewall_start_gate_failed") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-current-boot-receipt", action="store_true", required=True)
    parser.parse_args(argv)
    gate_current_boot()
    return 0


def _sha256(value: bytes) -> Digest:
    return hashlib.sha256(value).hexdigest()


def _ports_sha256(ports: tuple[int, ...]) -> Digest:
    return _sha256(json.dumps(ports, separators=(",", ":")).encode("ascii"))


def _rules_sha256(document: dict[str, Any]) -> Digest:
    from deploy.reachy.apply_firewall import canonical_tuntun_table_semantics

    return _sha256(canonical_tuntun_table_semantics(document))


def _write_all(descriptor: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        written = os.write(descriptor, value[offset:])
        if written <= 0:
            raise OSError("firewall_receipt_write_incomplete")
        offset += written


def _read_at_most(descriptor: int, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(65_536, max_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            raise PermissionError("firewall_boot_gate_receipt_size")
    return b"".join(chunks)


def _validate_receipt_path(path: Path) -> None:
    parts = tuple(path.parts)
    leaf_parts = tuple(part for part in parts if part != path.anchor)
    if (
        not path.is_absolute()
        or len(leaf_parts) < 2
        or path.name in {"", ".", ".."}
        or any(part in {"", ".", ".."} or "\x00" in part for part in parts)
    ):
        raise PermissionError("firewall_boot_gate_path_unsafe")


def _receipt_publication_marker_name(receipt_name: str) -> str:
    return f".{receipt_name}.publish"


def _receipt_quarantine_marker_name(marker_name: str) -> str:
    return f"{marker_name}.quarantine"


def _path_exists_no_follow(path: Path) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise PermissionError("firewall_degraded_receipt_status_unreadable") from error
    return True


def _is_existing_degraded_marker(error: BaseException) -> bool:
    return (
        isinstance(error, PermissionError)
        and bool(error.args)
        and error.args[0] == "firewall_degraded_receipt_blocks_edge"
    )


class contextlib_suppress_file_not_found:
    def __enter__(self) -> None:
        return None

    def __exit__(self, error_type: object, error: object, traceback: object) -> bool:
        return isinstance(error, FileNotFoundError)


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


if __name__ == "__main__":
    raise SystemExit(main())
