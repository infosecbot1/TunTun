from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Annotated, Final, Literal, Self
from uuid import uuid4

from pydantic import Field, StringConstraints, field_validator, model_validator
from tuntun_contracts.base import (
    ContractModel,
    ContractParseError,
    canonical_bytes,
    canonical_mapping_bytes,
    parse_contract_json,
)
from tuntun_contracts.reachy_operator import ReachyAcceptedCapabilityV1

from .commissioning import (
    CommissioningStateV1,
    LocalPhysicalProof,
    LocalPhysicalProofVerifierPort,
    ReachyCommissioningRequestV1,
    ReachyCoreEndpointV1,
    _canonical_rfc1918_ipv4,
    _canonical_unicast_mac,
    _SyntheticLocalPhysicalEvidence,
    _SyntheticLocalPhysicalProofIssuer,
)

SHA256_PATTERN: Final = r"^[0-9a-f]{64}$"
_USERNAME_PATTERN: Final = (
    r"^(?:"
    r"[a-z_][a-z0-9_-]{0,2}"
    r"|[a-qs-z_][a-z0-9_-]{3}"
    r"|r[a-np-z0-9_-][a-z0-9_-]{2}"
    r"|ro[a-np-z0-9_-][a-z0-9_-]"
    r"|roo[a-su-z0-9_-]"
    r"|[a-z_][a-z0-9_-]{4,31}"
    r")$"
)
_INTERFACE_PATTERN: Final = r"^[A-Za-z0-9_.:-]{1,32}$"
_TAG_PATTERN: Final = r"^[A-Za-z0-9_.-]{1,128}$"
_SEMVER_PATTERN: Final = r"^(?:0|[1-9][0-9]*)[.](?:0|[1-9][0-9]*)[.](?:0|[1-9][0-9]*)$"
_PACKAGE_NAME_PATTERN: Final = r"^[a-z0-9][a-z0-9_.-]{0,63}$"
_LOCAL_CEREMONY_ERROR: Final = "unsafe Reachy local ceremony"
_EXPECTED_RUNTIME_PACKAGE_NAMES: Final = ("python", "reachy-mini", "websockets")
_EXPECTED_PROJECT_WHEELS: Final = ("tuntun-contracts", "tuntun-edge")
_EXPECTED_IMPORT_CLOSURE: Final = (
    "tuntun_contracts",
    "tuntun_edge",
    "tuntun_edge.cli.main",
    "tuntun_edge.transport.commissioning",
)
_MAX_DESCRIPTOR_BYTES: Final = 32_768
_MAX_DHCP_BYTES: Final = 16_384
_MAX_PINNED_HOST_KEY_BYTES: Final = 128
_MAX_ONE_TIME_CODE_RECEIPT_BYTES: Final = 512
_READ_CHUNK_BYTES: Final = 4096
_CLOEXEC: Final = getattr(os, "O_CLOEXEC", 0)
_NOFOLLOW: Final = getattr(os, "O_NOFOLLOW", 0)
_NONBLOCK: Final = getattr(os, "O_NONBLOCK", 0)
_DIRECTORY: Final = getattr(os, "O_DIRECTORY", 0)
_READ_FLAGS: Final = os.O_RDONLY | _CLOEXEC | _NOFOLLOW | _NONBLOCK
_DIRECTORY_FLAGS: Final = os.O_RDONLY | _DIRECTORY | _CLOEXEC | _NOFOLLOW
_WRITE_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _CLOEXEC | _NOFOLLOW
OS_MODULE: Final = os

Sha256Hex = Annotated[str, Field(pattern=SHA256_PATTERN)]
Username = Annotated[str, Field(pattern=_USERNAME_PATTERN)]
InterfaceName = Annotated[str, StringConstraints(strict=True, pattern=_INTERFACE_PATTERN)]
TagName = Annotated[str, StringConstraints(strict=True, pattern=_TAG_PATTERN)]
PackageName = Annotated[str, StringConstraints(strict=True, pattern=_PACKAGE_NAME_PATTERN)]
StableSemver = Annotated[str, Field(min_length=5, max_length=32, pattern=_SEMVER_PATTERN)]


class ReachyLocalCeremonyError(PermissionError):
    """The local physical ceremony inputs are absent, hostile, stale, or incomplete."""


@dataclass(frozen=True, slots=True)
class ReachyLocalCeremonyInputPaths:
    descriptor_path: Path
    pinned_host_key_path: Path
    dhcp_reservations_path: Path


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    nlink: int
    size: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> Self:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            mode=stat.S_IMODE(value.st_mode),
            uid=value.st_uid,
            nlink=value.st_nlink,
            size=value.st_size,
        )

    def same_file_and_size(self, value: os.stat_result) -> bool:
        return self == type(self).from_stat(value)


@dataclass(frozen=True, slots=True)
class _DirectoryIdentity:
    device: int
    inode: int
    uid: int
    mode: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> Self:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            uid=value.st_uid,
            mode=stat.S_IMODE(value.st_mode),
        )


class _OpenedInputDirectory:
    def __init__(self, path: Path, *, expected_owner_uid: int) -> None:
        self.path = _absolute_lexical_path(path)
        self.expected_owner_uid = expected_owner_uid
        self._fd = _open_private_directory(self.path, expected_owner_uid=expected_owner_uid)
        self.identity = _DirectoryIdentity.from_stat(OS_MODULE.fstat(self._fd))

    @property
    def fd(self) -> int:
        if self._fd < 0:
            raise OSError("closed Reachy local ceremony input directory")
        return self._fd

    def close(self) -> None:
        descriptor = self._fd
        self._fd = -1
        if descriptor >= 0:
            OS_MODULE.close(descriptor)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        _error_type: type[BaseException] | None,
        _error: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()


class RuntimePackageEvidence(ContractModel):
    name: PackageName
    version: Annotated[str, Field(min_length=1, max_length=64)]


class ScratchVenvEvidence(ContractModel):
    python_executable: Literal["/venvs/apps_venv/bin/python3"]
    system_site_packages: Literal[True]
    offline: Literal[True]
    no_deps: Literal[True]
    installed_wheels: Annotated[
        tuple[Literal["tuntun-contracts", "tuntun-edge"], ...],
        Field(min_length=2, max_length=2),
    ]
    imported_modules: Annotated[tuple[str, ...], Field(min_length=4, max_length=16)]
    removed: Literal[True]

    @field_validator("imported_modules")
    @classmethod
    def complete_edge_import_closure(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != _EXPECTED_IMPORT_CLOSURE:
            raise ValueError("scratch venv must import the complete Edge closure")
        return value

    @field_validator("installed_wheels")
    @classmethod
    def only_project_wheels(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != _EXPECTED_PROJECT_WHEELS:
            raise ValueError("scratch venv must install only the two Tuntun wheels")
        return value


class RuntimeEvidence(ContractModel):
    python_executable: Literal["/venvs/apps_venv/bin/python3"]
    python_version: Literal["3.11", "3.12"]
    python_abi: Literal["cp311", "cp312"]
    sys_tags: Annotated[tuple[TagName, ...], Field(min_length=1, max_length=4096)]
    edge_wheel_tags: Annotated[tuple[TagName, ...], Field(min_length=1, max_length=8)]
    contracts_wheel_tags: Annotated[tuple[TagName, ...], Field(min_length=1, max_length=8)]
    runtime_packages: Annotated[
        tuple[RuntimePackageEvidence, ...], Field(min_length=3, max_length=3)
    ]
    scratch_venv: ScratchVenvEvidence

    @model_validator(mode="after")
    def exact_interpreter_wheel_and_runtime_closure(self) -> Self:
        if (self.python_version, self.python_abi) not in {
            ("3.11", "cp311"),
            ("3.12", "cp312"),
        }:
            raise ValueError("unsupported Reachy interpreter ABI pair")
        if len(set(self.sys_tags)) != len(self.sys_tags):
            raise ValueError("Reachy target tag set must be duplicate-free")
        if "py3-none-any" not in self.sys_tags:
            raise ValueError("Reachy target tag set must include py3-none-any")
        if self.edge_wheel_tags != ("py3-none-any",) or self.contracts_wheel_tags != (
            "py3-none-any",
        ):
            raise ValueError("Tuntun project wheels must be pure py3-none-any")
        names = tuple(package.name for package in self.runtime_packages)
        if names != _EXPECTED_RUNTIME_PACKAGE_NAMES:
            raise ValueError("Reachy runtime inventory must be exact and closed")
        versions = {package.name: package.version for package in self.runtime_packages}
        if versions["websockets"] != "15.0.1":
            raise ValueError("Reachy runtime requires websockets==15.0.1")
        if self.scratch_venv.python_executable != self.python_executable:
            raise ValueError("scratch venv must use the accepted interpreter")
        return self

    def target_tag_set_sha256(self) -> str:
        return hashlib.sha256(canonical_mapping_bytes({"sys_tags": self.sys_tags})).hexdigest()

    def runtime_inventory_sha256(self) -> str:
        return hashlib.sha256(
            canonical_mapping_bytes(
                {
                    "runtime_packages": tuple(
                        package.model_dump(mode="json") for package in self.runtime_packages
                    )
                }
            )
        ).hexdigest()


class CapabilityEvidence(ContractModel):
    capability_report_sha256: Sha256Hex
    acceptance_receipt_sha256: Sha256Hex
    sdk_version: StableSemver
    daemon_version: StableSemver
    sdk_metadata_accepted: Literal[True]


class SshLocalCeremonyEvidence(ContractModel):
    ssh_username: Username
    local_account_username: Username
    remote_id_username: Username
    key_only_reopen_username: Username
    observed_ssh_host_key_sha256: Sha256Hex
    password_login_rejected: Literal[True]
    default_password_login_rejected: Literal[True]
    installer_privileges_bounded: Literal[True]
    managed_app_privileges_bounded: Literal[True]

    @field_validator(
        "ssh_username",
        "local_account_username",
        "remote_id_username",
        "key_only_reopen_username",
    )
    @classmethod
    def no_root_principal(cls, value: str) -> str:
        if value == "root":
            raise ValueError("Reachy local ceremony username must be non-root")
        return value

    @model_validator(mode="after")
    def same_principal_owns_every_ssh_fact(self) -> Self:
        if (
            len(
                {
                    self.ssh_username,
                    self.local_account_username,
                    self.remote_id_username,
                    self.key_only_reopen_username,
                }
            )
            != 1
        ):
            raise ValueError("Reachy SSH principal evidence must bind one user")
        return self


class RouteEvidence(ContractModel):
    binary: Literal["/sbin/ip", "/usr/sbin/ip"]
    interface: InterfaceName
    source_ipv4: Annotated[str, Field(min_length=7, max_length=15)]
    destination_ipv4: Annotated[str, Field(min_length=7, max_length=15)]
    prefix_length: Annotated[int, Field(ge=1, le=32)]
    scope: Literal["link"]
    gateway_ipv4: None
    peer_link_address: Annotated[
        str,
        StringConstraints(strict=True, pattern=r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$"),
    ]

    @field_validator("source_ipv4", "destination_ipv4")
    @classmethod
    def canonical_rfc1918_route_ip(cls, value: str) -> str:
        return _canonical_rfc1918_ipv4(value, label="route endpoint")

    @field_validator("peer_link_address")
    @classmethod
    def canonical_peer_mac(cls, value: str) -> str:
        return _canonical_unicast_mac(value, label="route peer link address")


class TopologyEvidence(ContractModel):
    core_inventory_id: Annotated[str, Field(min_length=8, max_length=128)]
    office_laptop_inventory_id: Annotated[str, Field(min_length=8, max_length=128)]
    accepted_mac_inventory_count: Literal[1]
    route_bearing_user_lan_interfaces: Annotated[
        tuple[InterfaceName, ...],
        Field(min_length=1, max_length=1),
    ]
    asus_mesh_user_lan_interface: InterfaceName
    reachy_ipv4: Annotated[str, Field(min_length=7, max_length=15)]
    reachy_link_address: Annotated[
        str,
        StringConstraints(strict=True, pattern=r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$"),
    ]
    core_ipv4: Annotated[str, Field(min_length=7, max_length=15)]
    core_link_address: Annotated[
        str,
        StringConstraints(strict=True, pattern=r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$"),
    ]
    same_l2_prefix_length: Annotated[int, Field(ge=24, le=30)]
    direct_same_l2: Literal[True]
    be800_direct_attachment_disconnected: Literal[True]
    ip_forwarding_enabled: Literal[False]
    internet_sharing_enabled: Literal[False]
    bridge_enabled: Literal[False]
    secondary_listener_reachable: Literal[False]
    gateway_bearing_routes: Literal[False]
    dual_homed: Literal[False]

    @field_validator("reachy_ipv4", "core_ipv4")
    @classmethod
    def canonical_rfc1918_topology_ip(cls, value: str) -> str:
        return _canonical_rfc1918_ipv4(value, label="topology endpoint")

    @field_validator("reachy_link_address", "core_link_address")
    @classmethod
    def canonical_topology_mac(cls, value: str) -> str:
        return _canonical_unicast_mac(value, label="topology link address")

    @model_validator(mode="after")
    def single_owner_mac_direct_l2_topology(self) -> Self:
        if self.core_inventory_id != self.office_laptop_inventory_id:
            raise ValueError("Core and office laptop must be one accepted Mac inventory")
        if self.route_bearing_user_lan_interfaces != (self.asus_mesh_user_lan_interface,):
            raise ValueError("one ASUS mesh user-LAN interface must carry the route")
        if self.reachy_ipv4 == self.core_ipv4:
            raise ValueError("Reachy and Core must be distinct RFC1918 hosts")
        if not _same_subnet(self.core_ipv4, self.reachy_ipv4, self.same_l2_prefix_length):
            raise ValueError("Reachy and Core must be direct same-L2 peers")
        return self


class DhcpReservation(ContractModel):
    role: Literal["core", "reachy"]
    ipv4: Annotated[str, Field(min_length=7, max_length=15)]
    link_address: Annotated[
        str,
        StringConstraints(strict=True, pattern=r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$"),
    ]

    @field_validator("ipv4")
    @classmethod
    def canonical_rfc1918_reservation_ip(cls, value: str) -> str:
        return _canonical_rfc1918_ipv4(value, label="DHCP reservation")

    @field_validator("link_address")
    @classmethod
    def canonical_reservation_mac(cls, value: str) -> str:
        return _canonical_unicast_mac(value, label="DHCP reservation link address")


class ReachyDhcpReservationsV1(ContractModel):
    schema_version: Literal["tuntun.reachy-dhcp-reservations.v1"]
    reservations: Annotated[tuple[DhcpReservation, ...], Field(min_length=2, max_length=2)]

    @field_validator("reservations")
    @classmethod
    def exact_reservation_roles(
        cls,
        value: tuple[DhcpReservation, ...],
    ) -> tuple[DhcpReservation, ...]:
        if tuple(item.role for item in value) != ("core", "reachy"):
            raise ValueError("Reachy DHCP reservations must bind core and reachy exactly")
        return value

    def reservation(self, role: Literal["core", "reachy"]) -> DhcpReservation:
        for item in self.reservations:
            if item.role == role:
                return item
        raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)


class ReachyLocalCeremonyDescriptor(ContractModel):
    schema_version: Literal["tuntun.reachy-local-ceremony.v1"]
    request: ReachyCommissioningRequestV1
    one_time_code_sha256: Sha256Hex
    ssh: SshLocalCeremonyEvidence
    capability: CapabilityEvidence
    runtime: RuntimeEvidence
    topology: TopologyEvidence
    route: RouteEvidence

    @model_validator(mode="after")
    def endpoint_facts_are_numeric_and_exact(self) -> Self:
        if self.request.core_ipv4 != self.topology.core_ipv4:
            raise ValueError("local ceremony request must bind exact numeric Core endpoint")
        if self.request.core_link_address != self.topology.core_link_address:
            raise ValueError("local ceremony request must bind exact Core link address")
        if self.route.source_ipv4 != self.request.core_ipv4:
            raise ValueError("route evidence must originate at the commissioned Core endpoint")
        if self.route.destination_ipv4 != self.topology.reachy_ipv4:
            raise ValueError("route evidence must target the numeric Reachy endpoint")
        if self.route.interface != self.topology.asus_mesh_user_lan_interface:
            raise ValueError("route evidence must use the accepted user-LAN interface")
        if self.route.prefix_length != self.topology.same_l2_prefix_length:
            raise ValueError("route evidence must bind the same direct-L2 prefix")
        if self.route.peer_link_address != self.topology.reachy_link_address:
            raise ValueError("route evidence must bind the commissioned Reachy MAC")
        return self


class ReachyLocalProofAuthority:
    def __init__(self) -> None:
        self._issuer = _SyntheticLocalPhysicalProofIssuer()

    @property
    def verifier(self) -> LocalPhysicalProofVerifierPort:
        return self._issuer.consumer

    def issue(
        self,
        evidence: _SyntheticLocalPhysicalEvidence,
        *,
        operation: Literal["commission", "recommission", "revoke"],
        request: ReachyCommissioningRequestV1 | None,
        current: CommissioningStateV1 | None,
    ) -> LocalPhysicalProof:
        return self._issuer.issue(
            evidence,
            operation=operation,
            request=request,
            current=current,
        )


class OneTimeCodeConsumptionReceiptV1(ContractModel):
    schema_version: Literal["tuntun.reachy-one-time-code-consumption.v1"]
    receipt_id: Sha256Hex


class ReachyOneTimeCodeReceiptRepository:
    def __init__(self, root: Path, *, expected_owner_uid: int) -> None:
        self.root = _absolute_lexical_path(root)
        self.expected_owner_uid = expected_owner_uid
        self._fd = _open_or_create_private_directory(
            self.root,
            expected_owner_uid=expected_owner_uid,
        )
        self.identity = _DirectoryIdentity.from_stat(OS_MODULE.fstat(self._fd))

    @property
    def fd(self) -> int:
        if self._fd < 0:
            raise OSError("closed Reachy local ceremony one-time-code receipt directory")
        return self._fd

    def close(self) -> None:
        descriptor = self._fd
        self._fd = -1
        if descriptor >= 0:
            OS_MODULE.close(descriptor)

    def consume_once(self, one_time_code_sha256: str) -> None:
        os_failure = False
        try:
            self._consume_once(one_time_code_sha256)
        except ReachyLocalCeremonyError:
            raise
        except OSError:
            os_failure = True
        if os_failure:
            raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)

    def _consume_once(self, one_time_code_sha256: str) -> None:
        receipt_id = _one_time_code_receipt_id(one_time_code_sha256)
        target_name = f"receipt-{receipt_id}.json"
        if not _safe_receipt_name(target_name):
            raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
        payload = canonical_bytes(
            OneTimeCodeConsumptionReceiptV1(
                schema_version="tuntun.reachy-one-time-code-consumption.v1",
                receipt_id=receipt_id,
            )
        )
        temp_name = f".one-time-code-receipt.{OS_MODULE.getpid()}.{uuid4().hex}.tmp"
        descriptor = -1
        temp_identity: _FileIdentity | None = None
        published = False
        try:
            descriptor = OS_MODULE.open(temp_name, _WRITE_FLAGS, 0o600, dir_fd=self.fd)
            OS_MODULE.fchmod(descriptor, 0o600)
            _write_all(descriptor, payload)
            written = OS_MODULE.fstat(descriptor)
            _require_owner_regular(
                written,
                expected_owner_uid=self.expected_owner_uid,
                expected_mode=0o600,
                max_bytes=_MAX_ONE_TIME_CODE_RECEIPT_BYTES,
                directory_device=self.identity.device,
            )
            if written.st_size != len(payload):
                raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
            OS_MODULE.fsync(descriptor)
            temp_identity = _FileIdentity.from_stat(written)
            OS_MODULE.close(descriptor)
            descriptor = -1
            named_temp = OS_MODULE.stat(temp_name, dir_fd=self.fd, follow_symlinks=False)
            if not temp_identity.same_file_and_size(named_temp):
                raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
            receipt_exists = False
            try:
                OS_MODULE.link(temp_name, target_name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            except FileExistsError:
                receipt_exists = True
            if receipt_exists:
                raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
            published = True
            OS_MODULE.fsync(self.fd)
        finally:
            primary_failure = sys.exception()
            cleanup_failure: OSError | None = None
            if descriptor >= 0 and temp_identity is None:
                try:
                    temp_identity = _FileIdentity.from_stat(OS_MODULE.fstat(descriptor))
                except OSError as error:
                    cleanup_failure = error
            if descriptor >= 0:
                try:
                    OS_MODULE.close(descriptor)
                except OSError as error:
                    if cleanup_failure is None:
                        cleanup_failure = error
            if temp_identity is not None:
                try:
                    OS_MODULE.unlink(temp_name, dir_fd=self.fd)
                except OSError as error:
                    cleanup_failure = error
                if published:
                    try:
                        OS_MODULE.fsync(self.fd)
                    except OSError as error:
                        if cleanup_failure is None:
                            cleanup_failure = error
            if cleanup_failure is not None and primary_failure is None:
                raise cleanup_failure
        if published:
            published_identity = OS_MODULE.stat(
                target_name,
                dir_fd=self.fd,
                follow_symlinks=False,
            )
            _require_owner_regular(
                published_identity,
                expected_owner_uid=self.expected_owner_uid,
                expected_mode=0o600,
                max_bytes=_MAX_ONE_TIME_CODE_RECEIPT_BYTES,
                directory_device=self.identity.device,
            )
            if (
                _read_owner_file(
                    self.root / target_name,
                    expected_owner_uid=self.expected_owner_uid,
                    max_bytes=_MAX_ONE_TIME_CODE_RECEIPT_BYTES,
                )
                != payload
            ):
                raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)


class ReachyLocalCeremony:
    def __init__(
        self,
        *,
        descriptor: ReachyLocalCeremonyDescriptor,
        pinned_host_key_sha256: str,
        dhcp_reservations: ReachyDhcpReservationsV1,
        one_time_code_receipts: ReachyOneTimeCodeReceiptRepository,
        proof_authority: ReachyLocalProofAuthority | None = None,
    ) -> None:
        self._descriptor = descriptor
        self._pinned_host_key_sha256 = pinned_host_key_sha256
        self._dhcp_reservations = dhcp_reservations
        self._one_time_code_receipts = one_time_code_receipts
        self._proof_authority = (
            ReachyLocalProofAuthority() if proof_authority is None else proof_authority
        )

    @property
    def proof_verifier(self) -> LocalPhysicalProofVerifierPort:
        return self._proof_authority.verifier

    def current_rfc1918_request(self) -> ReachyCommissioningRequestV1:
        return self._descriptor.request

    def accepted_capability(self) -> ReachyAcceptedCapabilityV1:
        self._verify_static_evidence()
        return ReachyAcceptedCapabilityV1(
            capability_report_sha256=self._descriptor.capability.capability_report_sha256,
            acceptance_receipt_sha256=self._descriptor.capability.acceptance_receipt_sha256,
            sdk_version=self._descriptor.capability.sdk_version,
            daemon_version=self._descriptor.capability.daemon_version,
            ssh_username=self._descriptor.ssh.ssh_username,
            python_executable=self._descriptor.runtime.python_executable,
            python_version=self._descriptor.runtime.python_version,
            python_abi=self._descriptor.runtime.python_abi,
            selected_wheel_tag="py3-none-any",
            target_tag_set_sha256=self._descriptor.runtime.target_tag_set_sha256(),
            runtime_inventory_sha256=self._descriptor.runtime.runtime_inventory_sha256(),
        )

    def issue_proof(
        self,
        *,
        operation: Literal["commission", "recommission", "revoke"],
        request: ReachyCommissioningRequestV1 | None,
        current: CommissioningStateV1 | None,
        one_time_code: str,
    ) -> LocalPhysicalProof:
        os_failure = False
        try:
            evidence = self._verified_evidence(one_time_code)
            return self._proof_authority.issue(
                evidence,
                operation=operation,
                request=request,
                current=current,
            )
        except ReachyLocalCeremonyError:
            raise
        except OSError:
            os_failure = True
        except (ValueError, ContractParseError) as error:
            raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR) from error
        if os_failure:
            raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
        raise AssertionError("unreachable")

    def _verified_evidence(self, one_time_code: str) -> _SyntheticLocalPhysicalEvidence:
        self._verify_static_evidence()
        if type(one_time_code) is not str or not hmac.compare_digest(
            hashlib.sha256(one_time_code.encode("utf-8")).hexdigest(),
            self._descriptor.one_time_code_sha256,
        ):
            raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
        self._one_time_code_receipts.consume_once(self._descriptor.one_time_code_sha256)
        return _SyntheticLocalPhysicalEvidence(
            local_tty=True,
            ssh_host_key_verified=True,
            one_time_code_verified=True,
            dhcp_reservations_verified=True,
        )

    def _verify_static_evidence(self) -> None:
        descriptor = self._descriptor
        if not commissioning_key_identity_contract_supports_required_ed25519_ids():
            raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
        if not hmac.compare_digest(
            descriptor.ssh.observed_ssh_host_key_sha256,
            self._pinned_host_key_sha256,
        ):
            raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
        if descriptor.capability.sdk_metadata_accepted is not True:
            raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
        self._verify_dhcp_reservations()
        self.accepted_capability_without_revalidating()

    def accepted_capability_without_revalidating(self) -> ReachyAcceptedCapabilityV1:
        descriptor = self._descriptor
        return ReachyAcceptedCapabilityV1(
            capability_report_sha256=descriptor.capability.capability_report_sha256,
            acceptance_receipt_sha256=descriptor.capability.acceptance_receipt_sha256,
            sdk_version=descriptor.capability.sdk_version,
            daemon_version=descriptor.capability.daemon_version,
            ssh_username=descriptor.ssh.ssh_username,
            python_executable=descriptor.runtime.python_executable,
            python_version=descriptor.runtime.python_version,
            python_abi=descriptor.runtime.python_abi,
            selected_wheel_tag="py3-none-any",
            target_tag_set_sha256=descriptor.runtime.target_tag_set_sha256(),
            runtime_inventory_sha256=descriptor.runtime.runtime_inventory_sha256(),
        )

    def _verify_dhcp_reservations(self) -> None:
        core = self._dhcp_reservations.reservation("core")
        reachy = self._dhcp_reservations.reservation("reachy")
        expected_digest = hashlib.sha256(canonical_bytes(self._dhcp_reservations)).hexdigest()
        if not hmac.compare_digest(
            expected_digest,
            self._descriptor.request.dhcp_reservation_receipt_sha256,
        ):
            raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
        if (
            core.ipv4 != self._descriptor.request.core_ipv4
            or core.link_address != self._descriptor.request.core_link_address
        ):
            raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
        if (
            reachy.ipv4 != self._descriptor.topology.reachy_ipv4
            or reachy.link_address != self._descriptor.topology.reachy_link_address
        ):
            raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)


def load_reachy_local_ceremony(
    paths: ReachyLocalCeremonyInputPaths,
    *,
    expected_owner_uid: int,
    one_time_code_receipts: ReachyOneTimeCodeReceiptRepository,
    proof_authority: ReachyLocalProofAuthority | None = None,
) -> ReachyLocalCeremony:
    try:
        _require_input_flags()
        descriptor = parse_contract_json(
            ReachyLocalCeremonyDescriptor,
            _read_owner_file(
                paths.descriptor_path,
                expected_owner_uid=expected_owner_uid,
                max_bytes=_MAX_DESCRIPTOR_BYTES,
            ),
            max_bytes=_MAX_DESCRIPTOR_BYTES,
            require_canonical=True,
        )
        pinned_host_key_sha256 = _parse_pinned_host_key(
            _read_owner_file(
                paths.pinned_host_key_path,
                expected_owner_uid=expected_owner_uid,
                max_bytes=_MAX_PINNED_HOST_KEY_BYTES,
            )
        )
        dhcp_reservations = parse_contract_json(
            ReachyDhcpReservationsV1,
            _read_owner_file(
                paths.dhcp_reservations_path,
                expected_owner_uid=expected_owner_uid,
                max_bytes=_MAX_DHCP_BYTES,
            ),
            max_bytes=_MAX_DHCP_BYTES,
            require_canonical=True,
        )
        ceremony = ReachyLocalCeremony(
            descriptor=descriptor,
            pinned_host_key_sha256=pinned_host_key_sha256,
            dhcp_reservations=dhcp_reservations,
            one_time_code_receipts=one_time_code_receipts,
            proof_authority=proof_authority,
        )
        return ceremony
    except ReachyLocalCeremonyError:
        raise
    except (OSError, PermissionError, ValueError, ContractParseError) as error:
        raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR) from error


def _parse_pinned_host_key(raw: bytes) -> str:
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR) from error
    if value.endswith("\n"):
        value = value[:-1]
    if re.fullmatch(SHA256_PATTERN, value) is None:
        raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
    return value


def _require_input_flags() -> None:
    if _CLOEXEC == 0 or _NOFOLLOW == 0 or _DIRECTORY == 0:
        raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)


def _read_owner_file(path: Path, *, expected_owner_uid: int, max_bytes: int) -> bytes:
    absolute = _absolute_lexical_path(path)
    if absolute.name == "":
        raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
    with _OpenedInputDirectory(absolute.parent, expected_owner_uid=expected_owner_uid) as directory:
        before = OS_MODULE.stat(absolute.name, dir_fd=directory.fd, follow_symlinks=False)
        _require_owner_regular(
            before,
            expected_owner_uid=expected_owner_uid,
            expected_mode=0o600,
            max_bytes=max_bytes,
            directory_device=directory.identity.device,
        )
        expected = _FileIdentity.from_stat(before)
        descriptor = OS_MODULE.open(absolute.name, _READ_FLAGS, dir_fd=directory.fd)
        try:
            opened = OS_MODULE.fstat(descriptor)
            _require_owner_regular(
                opened,
                expected_owner_uid=expected_owner_uid,
                expected_mode=0o600,
                max_bytes=max_bytes,
                directory_device=directory.identity.device,
            )
            if not expected.same_file_and_size(opened):
                raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
            chunks: list[bytes] = []
            remaining = opened.st_size
            while remaining > 0:
                chunk = OS_MODULE.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
                if not chunk:
                    raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
                chunks.append(chunk)
                remaining -= len(chunk)
            if OS_MODULE.read(descriptor, 1):
                raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
            after = OS_MODULE.fstat(descriptor)
            named_after = OS_MODULE.stat(
                absolute.name,
                dir_fd=directory.fd,
                follow_symlinks=False,
            )
            for candidate in (after, named_after):
                _require_owner_regular(
                    candidate,
                    expected_owner_uid=expected_owner_uid,
                    expected_mode=0o600,
                    max_bytes=max_bytes,
                    directory_device=directory.identity.device,
                )
            if not expected.same_file_and_size(after) or not expected.same_file_and_size(
                named_after
            ):
                raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
            return b"".join(chunks)
        finally:
            OS_MODULE.close(descriptor)


def _absolute_lexical_path(path: Path) -> Path:
    raw = os.fspath(path)
    if (
        type(raw) is not str
        or raw == ""
        or "\x00" in raw
        or not raw.startswith(os.sep)
        or raw.startswith(os.sep * 2)
        or os.sep * 2 in raw
    ):
        raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
    if any(part in {"", ".", ".."} for part in raw.split(os.sep)[1:]):
        raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
    absolute = Path(os.path.abspath(raw))
    if absolute == Path("/") or any(part in {".", ".."} for part in absolute.parts):
        raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
    return absolute


def _open_or_create_private_directory(path: Path, *, expected_owner_uid: int) -> int:
    absolute = _absolute_lexical_path(path)
    parts = absolute.parts
    descriptor = OS_MODULE.open("/", _DIRECTORY_FLAGS & ~_NOFOLLOW)
    try:
        for index, component in enumerate(parts[1:]):
            if not _safe_component(component):
                raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
            final = index == len(parts[1:]) - 1
            if final:
                with contextlib.suppress(FileExistsError):
                    OS_MODULE.mkdir(component, 0o700, dir_fd=descriptor)
            named = OS_MODULE.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(named.st_mode):
                raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
            child = OS_MODULE.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                opened = OS_MODULE.fstat(child)
                if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                    raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
                if final:
                    _require_private_directory(opened, expected_owner_uid=expected_owner_uid)
            except BaseException:
                OS_MODULE.close(child)
                raise
            OS_MODULE.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        with contextlib.suppress(OSError):
            OS_MODULE.close(descriptor)
        raise


def _open_private_directory(path: Path, *, expected_owner_uid: int) -> int:
    absolute = _absolute_lexical_path(path)
    parts = absolute.parts
    descriptor = OS_MODULE.open("/", _DIRECTORY_FLAGS & ~_NOFOLLOW)
    try:
        for index, component in enumerate(parts[1:]):
            if not _safe_component(component):
                raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
            final = index == len(parts[1:]) - 1
            named = OS_MODULE.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(named.st_mode):
                raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
            child = OS_MODULE.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                opened = OS_MODULE.fstat(child)
                if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                    raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
                if final:
                    _require_private_directory(opened, expected_owner_uid=expected_owner_uid)
            except BaseException:
                OS_MODULE.close(child)
                raise
            OS_MODULE.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        with contextlib.suppress(OSError):
            OS_MODULE.close(descriptor)
        raise


def _safe_component(value: str) -> bool:
    return (
        type(value) is str
        and value not in {"", ".", ".."}
        and "/" not in value
        and "\x00" not in value
    )


def _require_private_directory(
    identity: os.stat_result,
    *,
    expected_owner_uid: int,
) -> None:
    if (
        not stat.S_ISDIR(identity.st_mode)
        or identity.st_uid != expected_owner_uid
        or stat.S_IMODE(identity.st_mode) != 0o700
    ):
        raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)


def _require_owner_regular(
    identity: os.stat_result,
    *,
    expected_owner_uid: int,
    expected_mode: int,
    max_bytes: int,
    directory_device: int,
) -> None:
    if not stat.S_ISREG(identity.st_mode):
        raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
    if identity.st_uid != expected_owner_uid or stat.S_IMODE(identity.st_mode) != expected_mode:
        raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
    if identity.st_nlink != 1 or identity.st_dev != directory_device:
        raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
    if not 1 <= identity.st_size <= max_bytes:
        raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)


def _one_time_code_receipt_id(one_time_code_sha256: str) -> str:
    if (
        type(one_time_code_sha256) is not str
        or re.fullmatch(
            SHA256_PATTERN,
            one_time_code_sha256,
        )
        is None
    ):
        raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
    return hashlib.sha256(
        canonical_mapping_bytes(
            {
                "one_time_code_sha256": one_time_code_sha256,
                "schema_version": "tuntun.reachy-one-time-code-consumption-key.v1",
            }
        )
    ).hexdigest()


def _safe_receipt_name(value: str) -> bool:
    return re.fullmatch(r"receipt-[0-9a-f]{64}[.]json", value) is not None


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = OS_MODULE.write(descriptor, remaining)
        if written <= 0:
            raise ReachyLocalCeremonyError(_LOCAL_CEREMONY_ERROR)
        remaining = remaining[written:]


def _same_subnet(left: str, right: str, prefix_length: int) -> bool:
    mask = (0xFFFFFFFF << (32 - prefix_length)) & 0xFFFFFFFF
    return (_ipv4_to_int(left) & mask) == (_ipv4_to_int(right) & mask)


def _ipv4_to_int(value: str) -> int:
    canonical = _canonical_rfc1918_ipv4(value, label="local ceremony endpoint")
    pieces = canonical.split(".")
    result = 0
    for piece in pieces:
        result = (result << 8) | int(piece)
    return result


def commissioning_key_identity_contract_supports_required_ed25519_ids() -> bool:
    try:
        ReachyCoreEndpointV1(
            schema_version="tuntun.reachy-core-endpoint.v1",
            commissioning_uuid="00000000-0000-4000-8000-000000000001",
            generation=1,
            certificate_generation=1,
            server_key_generation=1,
            trust_digest_generation=1,
            client_tls_key_generation=1,
            device_signing_key_generation=1,
            hmac_key_generation=1,
            core_ipv4="192.168.50.10",
            core_link_address="02:00:5e:00:53:01",
            port=7443,
            household_ca_sha256=hashlib.sha256(b"ca").hexdigest(),
            server_leaf_sha256=hashlib.sha256(b"server-leaf").hexdigest(),
            server_key_id="ed25519:reachy-server:v1",
            server_public_key_sha256=hashlib.sha256(b"server-public").hexdigest(),
            server_ip_sans=("192.168.50.10",),
            client_certificate_sha256=hashlib.sha256(b"client-cert").hexdigest(),
            client_tls_key_id="reachy-client-tls-v1",
            client_tls_public_key_sha256=hashlib.sha256(b"client-public").hexdigest(),
            device_signing_key_id="ed25519:reachy-device-sign:v1",
            device_signing_public_key_sha256=hashlib.sha256(b"device-public").hexdigest(),
            hmac_key_id="reachy-frame-hmac-v1",
            hmac_key_sha256=hashlib.sha256(b"hmac-root").hexdigest(),
            hmac_agreement_public_key_sha256=hashlib.sha256(b"hmac-public").hexdigest(),
            dhcp_reservation_receipt_sha256=hashlib.sha256(b"dhcp").hexdigest(),
            boot_identity_sha256=hashlib.sha256(b"boot").hexdigest(),
            capability_evidence_sha256=hashlib.sha256(b"capability").hexdigest(),
        )
    except ValueError:
        return False
    return True
