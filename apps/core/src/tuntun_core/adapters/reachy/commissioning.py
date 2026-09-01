from __future__ import annotations

import base64
import binascii
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import pwd
import re
import secrets
import stat
import struct
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from ipaddress import AddressValueError, IPv4Address, IPv4Network
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal, SupportsIndex, cast
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import (
    AfterValidator,
    AwareDatetime,
    BeforeValidator,
    Field,
    TypeAdapter,
    model_validator,
)
from tuntun_contracts.base import (
    JCS_MAX_SAFE_INTEGER,
    ContractModel,
    ContractParseError,
    canonical_bytes,
    parse_bounded_json_value,
    parse_contract_json,
)
from tuntun_contracts.poc.framing import PttInputMode
from tuntun_contracts.python_runtime import (
    CanonicalPythonVersion,
    parse_canonical_python_version,
)
from tuntun_core.config.secure_paths import (
    OwnedDirectory,
    absolute_lexical_path,
    open_owned_directory,
    require_no_unsafe_acl,
)

Sha256 = Annotated[
    str,
    Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
]


def _sanitized_version_token(value: str) -> str:
    if "xn--" in value.casefold():
        raise ValueError("version token contains a private A-label marker")
    return value


VersionToken = Annotated[
    str,
    Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._+!-]{0,63}$",
        json_schema_extra={
            "not": {
                "anyOf": [
                    {"pattern": r"[Xx][Nn]--"},
                    {"pattern": r"[\r\n]"},
                ]
            }
        },
    ),
    AfterValidator(_sanitized_version_token),
]


def _canonical_absolute_posix_path(value: str) -> str:
    parsed = PurePosixPath(value)
    if (
        not parsed.is_absolute()
        or parsed == PurePosixPath("/")
        or str(parsed) != value
        or any(part in {".", ".."} for part in parsed.parts)
    ):
        raise ValueError("path must be canonical, absolute, and non-root")
    return value


AbsolutePosixPath = Annotated[
    str,
    Field(
        min_length=2,
        max_length=512,
        pattern=r"^/[^\x00\r\n]*$",
        json_schema_extra={
            "not": {
                "anyOf": [
                    {"pattern": r"//"},
                    {"pattern": r"(?:^|/)[.]{1,2}(?:/|$)"},
                    {"pattern": r"/$"},
                    {"pattern": r"[\r\n]"},
                ]
            }
        },
    ),
    AfterValidator(_canonical_absolute_posix_path),
]


CommandPosixPath = Annotated[
    str,
    Field(
        min_length=2,
        max_length=512,
        pattern=r"^/(?:[A-Za-z0-9._+-]+/)*[A-Za-z0-9._+-]+$",
        json_schema_extra={
            "not": {
                "anyOf": [
                    {"pattern": r"//"},
                    {"pattern": r"(?:^|/)[.]{1,2}(?:/|$)"},
                    {"pattern": r"/$"},
                    {"pattern": r"[\r\n]"},
                ]
            }
        },
    ),
    AfterValidator(_canonical_absolute_posix_path),
]


def _non_root_principal(value: str) -> str:
    if value == "root":
        raise ValueError("Reachy SSH principal must be non-root")
    return value


PosixPrincipal = Annotated[
    str,
    Field(
        min_length=1,
        max_length=32,
        pattern=r"^[a-z_][a-z0-9_-]{0,31}$",
        json_schema_extra={
            "not": {
                "anyOf": [
                    {"const": "root"},
                    {"pattern": r"[\r\n]"},
                ]
            }
        },
    ),
    AfterValidator(_non_root_principal),
]
_RFC1918_NETWORKS = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
)
_IPV4_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_RFC1918_PATTERN = (
    rf"^(?:10(?:[.]{_IPV4_OCTET}){{3}}|"
    rf"172[.](?:1[6-9]|2[0-9]|3[01])(?:[.]{_IPV4_OCTET}){{2}}|"
    rf"192[.]168(?:[.]{_IPV4_OCTET}){{2}})$"
)
_OPERATOR_STATE_SCHEMA_ID = (
    "https://tuntun.local/schemas/evidence/reachy-a05-operator-state.schema.json"
)
_REMOTE_STATE_SCHEMA_ID = (
    "https://tuntun.local/schemas/evidence/reachy-a05-remote-state.schema.json"
)
_STATE_FILENAME = "operator-state.json"
_LOCK_FILENAME = "operator-state.lock"
_MAX_STATE_BYTES = 32_768
_MAX_ARTIFACT_BYTES = 1_048_576
_PRIVATE_FILE_MODE = 0o600
_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_LOCK_FLAGS = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_CREATE_FLAGS = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_DIRECTORY_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
_SPAWN_SNAPSHOT_PREFIX = ".spawn-lease."
_SPAWN_SNAPSHOT_PATTERN = re.compile(r"^[.]spawn-lease[.][0-9a-f]{32}$")
_MAX_RESERVED_SPAWN_SNAPSHOTS = 8
_DARWIN_RENAME_EXCL = 0x4
_DARWIN_RENAME_SWAP = 0x2
_LINUX_RENAME_NOREPLACE = 1
_LINUX_RENAME_EXCHANGE = 2


def _openssh_config_option(keyword: str, path: str) -> str:
    """Encode one absolute path as a single OpenSSH ``-o`` argument."""

    if (
        keyword not in {"IdentityFile", "UserKnownHostsFile"}
        or type(path) is not str
        or not path.startswith("/")
        or "$" in path
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in path)
    ):
        raise ValueError("OpenSSH path is invalid")
    escaped = path.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    return f'{keyword}="{escaped}"'


def _rename_with_atomic_flag(
    directory_descriptor: int,
    source: str,
    destination: str,
    *,
    darwin_flag: int,
    linux_flag: int,
) -> None:
    if (
        type(directory_descriptor) is not int
        or type(source) is not str
        or type(destination) is not str
        or not source
        or not destination
        or "/" in source
        or "/" in destination
        or "\x00" in source
        or "\x00" in destination
    ):
        raise ValueError("atomic rename arguments are invalid")
    library = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin":
        try:
            renamer = library.renameatx_np
        except AttributeError:
            raise OSError(errno.ENOTSUP, "atomic rename primitive is unavailable") from None
        renamer.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renamer.restype = ctypes.c_int
        arguments = (
            directory_descriptor,
            source_bytes,
            directory_descriptor,
            destination_bytes,
            darwin_flag,
        )
    elif sys.platform.startswith("linux"):
        try:
            renamer = library.renameat2
        except AttributeError:
            raise OSError(errno.ENOTSUP, "atomic rename primitive is unavailable") from None
        renamer.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renamer.restype = ctypes.c_int
        arguments = (
            directory_descriptor,
            source_bytes,
            directory_descriptor,
            destination_bytes,
            linux_flag,
        )
    else:
        raise OSError(errno.ENOTSUP, "atomic rename primitive is unsupported")
    ctypes.set_errno(0)
    if renamer(*arguments) != 0:
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise FileExistsError(error_number, os.strerror(error_number), destination)
        raise OSError(error_number, os.strerror(error_number), source, destination)


def _rename_noreplace(
    directory_descriptor: int,
    source: str,
    destination: str,
) -> None:
    _rename_with_atomic_flag(
        directory_descriptor,
        source,
        destination,
        darwin_flag=_DARWIN_RENAME_EXCL,
        linux_flag=_LINUX_RENAME_NOREPLACE,
    )


def _rename_exchange(
    directory_descriptor: int,
    source: str,
    destination: str,
) -> None:
    _rename_with_atomic_flag(
        directory_descriptor,
        source,
        destination,
        darwin_flag=_DARWIN_RENAME_SWAP,
        linux_flag=_LINUX_RENAME_EXCHANGE,
    )


def _system_utc_now() -> datetime:
    return datetime.now(UTC)


def _address_text(value: object) -> str:
    if not isinstance(value, IPv4Address) and type(value) is not str:
        raise ValueError("Reachy address must be a numeric IPv4 string")
    try:
        address = value if isinstance(value, IPv4Address) else IPv4Address(value)
    except (AddressValueError, TypeError):
        raise ValueError("Reachy address must be a numeric IPv4 string") from None
    if not any(address in network for network in _RFC1918_NETWORKS):
        raise ValueError("Reachy address must be RFC1918")
    return str(address)


ReachyIPv4 = Annotated[
    str,
    Field(
        min_length=7,
        max_length=15,
        pattern=_RFC1918_PATTERN,
        json_schema_extra={"not": {"pattern": r"[\r\n]"}},
    ),
    BeforeValidator(_address_text),
]


class ReachyA05StateStatus(StrEnum):
    COMMISSIONED = "commissioned"
    STAGED = "staged"
    ACTIVE = "active"
    REMOVED = "removed"
    REVOKED = "revoked"


ReachyA05LiveStatus = Literal[
    ReachyA05StateStatus.COMMISSIONED,
    ReachyA05StateStatus.STAGED,
    ReachyA05StateStatus.ACTIVE,
    ReachyA05StateStatus.REMOVED,
]


class _CurrentStateUse(StrEnum):
    ORDINARY_AUTHORITY = "ordinary_authority"
    EXPIRED_TERMINAL_RECOVERY = "expired_terminal_recovery"


class ReachyA05RuntimeBinding(ContractModel):
    python_executable: CommandPosixPath
    python_version: CanonicalPythonVersion
    python_abi: Literal["cp311", "cp312"]
    selected_wheel_tag: Literal["py3-none-any"]
    target_tag_set_sha256: Sha256
    sdk_version: VersionToken
    sdk_artifact_sha256: Sha256
    daemon_version: VersionToken
    daemon_artifact_sha256: Sha256
    runtime_inventory_sha256: Sha256

    @model_validator(mode="after")
    def supported_interpreter_pair(self) -> ReachyA05RuntimeBinding:
        major, minor, _ = parse_canonical_python_version(self.python_version)
        if (major, minor, self.python_abi) not in {
            (3, 11, "cp311"),
            (3, 12, "cp312"),
        }:
            raise ValueError("unsupported Python version and ABI pair")
        return self


class ReachyA05DeploymentBinding(ContractModel):
    commissioning_id: UUID
    state_generation: Annotated[int, Field(ge=1, le=JCS_MAX_SAFE_INTEGER)]
    status: ReachyA05LiveStatus
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    boot_identity_sha256: Sha256
    capability_report_sha256: Sha256
    ptt_input_mode: PttInputMode
    runtime: ReachyA05RuntimeBinding
    ssh_principal: PosixPrincipal
    remote_home: CommandPosixPath
    remote_root: CommandPosixPath
    dispatcher_path: CommandPosixPath
    dispatcher_protocol_version: Literal["tuntun.reachy-a05-dispatcher.v1"]
    dispatcher_sha256: Sha256
    authorized_key_line_sha256: Sha256
    staged_bundle_sha256: Sha256 | None
    active_bundle_sha256: Sha256 | None

    @model_validator(mode="after")
    def fixed_remote_layout(self) -> ReachyA05DeploymentBinding:
        expected_root = f"{self.remote_home}/.local/share/tuntun/reachy-a05"
        expected_dispatcher = f"{expected_root}/bootstrap/reachy_a05_forced_dispatcher.py"
        if self.remote_root != expected_root or self.dispatcher_path != expected_dispatcher:
            raise ValueError("remote root or dispatcher path is not fixed")
        return self

    @model_validator(mode="after")
    def bounded_freshness(self) -> ReachyA05DeploymentBinding:
        freshness = self.expires_at - self.issued_at
        if not timedelta(0) < freshness <= timedelta(hours=24):
            raise ValueError("state freshness must be in (0, 24 hours]")
        return self

    @model_validator(mode="after")
    def exact_content_address_for_status(self) -> ReachyA05DeploymentBinding:
        if self.status is ReachyA05StateStatus.STAGED:
            valid = self.staged_bundle_sha256 is not None and self.active_bundle_sha256 is None
        elif self.status is ReachyA05StateStatus.ACTIVE:
            valid = self.staged_bundle_sha256 is None and self.active_bundle_sha256 is not None
        else:
            valid = self.staged_bundle_sha256 is None and self.active_bundle_sha256 is None
        if not valid:
            raise ValueError("status does not match staged and active content addresses")
        return self


class ReachyA05CommissioningStateV1(ContractModel):
    schema_version: Literal["tuntun.reachy-a05-operator-state.v1"]
    record_kind: Literal["bound"]
    deployment: ReachyA05DeploymentBinding
    reachy_ipv4: ReachyIPv4
    ssh_port: Literal[22]
    identity_path: AbsolutePosixPath
    known_hosts_path: AbsolutePosixPath
    identity_public_key_type: Literal["ssh-ed25519"]
    pinned_host_key_type: Literal["ssh-ed25519"]
    identity_public_key_sha256: Sha256
    pinned_host_key_sha256: Sha256
    identity_file_sha256: Sha256
    known_hosts_file_sha256: Sha256

    @model_validator(mode="after")
    def distinct_local_artifact_paths(self) -> ReachyA05CommissioningStateV1:
        if self.identity_path == self.known_hosts_path:
            raise ValueError("identity and known-hosts paths must be distinct")
        if self.identity_public_key_sha256 == self.pinned_host_key_sha256:
            raise ValueError("identity and host public keys must be distinct")
        return self


class ReachyA05RemoteStateV1(ContractModel):
    schema_version: Literal["tuntun.reachy-a05-remote-state.v1"]
    deployment: ReachyA05DeploymentBinding


class ReachyA05RevokedTombstoneV1(ContractModel):
    """Content-minimized local record after remote and credential removal."""

    schema_version: Literal["tuntun.reachy-a05-operator-state.v1"]
    record_kind: Literal["revoked"]
    commissioning_id: UUID
    state_generation: Annotated[int, Field(ge=2, le=JCS_MAX_SAFE_INTEGER)]
    status: Literal[ReachyA05StateStatus.REVOKED]
    revoked_at: AwareDatetime
    prior_deployment_sha256: Sha256
    revocation_proof_sha256: Sha256


ReachyA05OperatorStateV1 = Annotated[
    ReachyA05CommissioningStateV1 | ReachyA05RevokedTombstoneV1,
    Field(discriminator="record_kind"),
]


class ReachyA05StateExpectation(ContractModel):
    commissioning_id: UUID
    state_generation: Annotated[int, Field(ge=1, le=JCS_MAX_SAFE_INTEGER)]
    boot_identity_sha256: Sha256
    capability_report_sha256: Sha256
    runtime_inventory_sha256: Sha256
    dispatcher_sha256: Sha256
    authorized_key_line_sha256: Sha256
    state_sha256: Sha256


class ReachyA05RevokedStateExpectation(ContractModel):
    commissioning_id: UUID
    state_generation: Annotated[int, Field(ge=2, le=JCS_MAX_SAFE_INTEGER)]
    prior_deployment_sha256: Sha256
    revocation_proof_sha256: Sha256
    state_sha256: Sha256


ReachyA05AnyStateExpectation = ReachyA05StateExpectation | ReachyA05RevokedStateExpectation


def _state_generation(state: ReachyA05OperatorStateV1) -> int:
    if type(state) is ReachyA05CommissioningStateV1:
        return state.deployment.state_generation
    return cast(ReachyA05RevokedTombstoneV1, state).state_generation


def _state_commissioning_id(state: ReachyA05OperatorStateV1) -> UUID:
    if type(state) is ReachyA05CommissioningStateV1:
        return state.deployment.commissioning_id
    return cast(ReachyA05RevokedTombstoneV1, state).commissioning_id


class ReachyA05RepositoryError(ValueError):
    """The private state is absent, stale, drifted, or fails CAS."""


class ReachyA05CommitUnknown(ReachyA05RepositoryError):
    """Namespace publication happened, but durable candidate truth is not proved."""

    def __init__(
        self,
        *,
        candidate_generation: int,
        candidate_state_sha256: str,
    ) -> None:
        if (
            type(candidate_generation) is not int
            or not 1 <= candidate_generation <= JCS_MAX_SAFE_INTEGER
            or len(candidate_state_sha256) != 64
            or any(character not in "0123456789abcdef" for character in candidate_state_sha256)
        ):
            raise ValueError("candidate commitment is invalid")
        self.candidate_generation = candidate_generation
        self.candidate_state_sha256 = candidate_state_sha256
        super().__init__(
            "Reachy commissioning commit is unknown "
            f"(generation={candidate_generation}, sha256={candidate_state_sha256})"
        )


class ReachyA05PostCommitError(ReachyA05RepositoryError):
    """The candidate is durably committed, but bounded cleanup did not complete."""

    def __init__(
        self,
        *,
        candidate_generation: int,
        candidate_state_sha256: str,
    ) -> None:
        if (
            type(candidate_generation) is not int
            or not 1 <= candidate_generation <= JCS_MAX_SAFE_INTEGER
            or len(candidate_state_sha256) != 64
            or any(character not in "0123456789abcdef" for character in candidate_state_sha256)
        ):
            raise ValueError("candidate commitment is invalid")
        self.candidate_generation = candidate_generation
        self.candidate_state_sha256 = candidate_state_sha256
        super().__init__(
            "Reachy commissioning commit succeeded but cleanup is uncertain "
            f"(generation={candidate_generation}, sha256={candidate_state_sha256})"
        )


class ReachyA05CommitReconciliation(StrEnum):
    COMMITTED = "committed"
    NOT_COMMITTED = "not_committed"
    INDETERMINATE_OWNER_RECOVERY = "indeterminate_owner_recovery"


@dataclass(slots=True)
class _CommitWitness:
    candidate_generation: int
    candidate_state_sha256: str
    namespace_mutated: bool = False
    commit_proven: bool = False

    def commit_unknown(self) -> ReachyA05CommitUnknown:
        return ReachyA05CommitUnknown(
            candidate_generation=self.candidate_generation,
            candidate_state_sha256=self.candidate_state_sha256,
        )

    def post_commit_error(self) -> ReachyA05PostCommitError:
        return ReachyA05PostCommitError(
            candidate_generation=self.candidate_generation,
            candidate_state_sha256=self.candidate_state_sha256,
        )


def _require_private_regular_file(
    descriptor: int,
    *,
    name: str,
    parent_descriptor: int,
    expected_uid: int,
) -> os.stat_result:
    try:
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError:
        raise PermissionError("unsafe Reachy commissioning state file") from None
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or opened.st_uid != expected_uid
        or named.st_uid != expected_uid
        or stat.S_IMODE(opened.st_mode) != _PRIVATE_FILE_MODE
        or stat.S_IMODE(named.st_mode) != _PRIVATE_FILE_MODE
        or opened.st_nlink != 1
        or named.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise PermissionError("unsafe Reachy commissioning state file")
    require_no_unsafe_acl(descriptor, "unsafe Reachy commissioning state file")
    return opened


def _require_private_directory(
    descriptor: int,
    *,
    name: str,
    parent_descriptor: int,
    expected_uid: int,
) -> os.stat_result:
    try:
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError:
        raise PermissionError("unsafe Reachy spawn authority snapshot") from None
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or opened.st_uid != expected_uid
        or named.st_uid != expected_uid
        or stat.S_IMODE(opened.st_mode) != 0o700
        or stat.S_IMODE(named.st_mode) != 0o700
        or opened.st_nlink < 2
        or named.st_nlink < 2
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise PermissionError("unsafe Reachy spawn authority snapshot")
    require_no_unsafe_acl(descriptor, "unsafe Reachy spawn authority snapshot")
    return opened


def _require_exact_spawn_snapshot_namespace(
    root: OwnedDirectory,
    *,
    snapshot_name: str,
    snapshot_descriptor: int,
    expected_uid: int,
) -> None:
    if _SPAWN_SNAPSHOT_PATTERN.fullmatch(snapshot_name) is None:
        raise PermissionError("unsafe Reachy spawn authority snapshot")
    try:
        reserved_names = tuple(
            sorted(name for name in os.listdir(root.fd) if name.startswith(_SPAWN_SNAPSHOT_PREFIX))
        )
        snapshot_entries = frozenset(os.listdir(snapshot_descriptor))
    except OSError:
        raise PermissionError("unsafe Reachy spawn authority snapshot") from None
    if reserved_names != (snapshot_name,) or snapshot_entries != {"identity", "known_hosts"}:
        raise PermissionError("unsafe Reachy spawn authority snapshot")
    _require_private_directory(
        snapshot_descriptor,
        name=snapshot_name,
        parent_descriptor=root.fd,
        expected_uid=expected_uid,
    )


def _same_file_observation(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _read_stable_private_file(
    descriptor: int,
    *,
    name: str,
    parent_descriptor: int,
    expected_uid: int,
    maximum: int,
) -> bytes:
    before = _require_private_regular_file(
        descriptor,
        name=name,
        parent_descriptor=parent_descriptor,
        expected_uid=expected_uid,
    )
    if not 1 <= before.st_size <= maximum:
        raise ReachyA05RepositoryError("Reachy spawn authority artifact size is invalid")
    chunks: list[bytes] = []
    offset = 0
    limit = before.st_size + 1
    try:
        while offset < limit:
            chunk = os.pread(descriptor, min(65_536, limit - offset), offset)
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
    except OSError:
        raise PermissionError("unsafe Reachy spawn authority descriptor") from None
    raw = b"".join(chunks)
    after = _require_private_regular_file(
        descriptor,
        name=name,
        parent_descriptor=parent_descriptor,
        expected_uid=expected_uid,
    )
    if (
        not _same_file_observation(before, after)
        or len(raw) != before.st_size
        or after.st_size != before.st_size
    ):
        raise PermissionError("Reachy spawn authority artifact changed")
    return raw


def _read_ssh_string(
    value: bytes,
    offset: int,
    *,
    maximum: int,
) -> tuple[bytes, int]:
    if offset < 0 or offset + 4 > len(value):
        raise ValueError("truncated SSH string")
    length = struct.unpack_from(">I", value, offset)[0]
    offset += 4
    if length > maximum or offset + length > len(value):
        raise ValueError("invalid SSH string length")
    return value[offset : offset + length], offset + length


def _parse_ed25519_public_blob(value: bytes) -> tuple[str, bytes]:
    key_type_raw, offset = _read_ssh_string(value, 0, maximum=64)
    public_key, offset = _read_ssh_string(value, offset, maximum=64)
    if offset != len(value) or key_type_raw != b"ssh-ed25519" or len(public_key) != 32:
        raise ValueError("invalid Ed25519 public key blob")
    return key_type_raw.decode("ascii"), public_key


def _parse_openssh_ed25519_identity(value: bytes) -> tuple[str, str]:
    header = b"".join((b"-----BEGIN OPENSSH PRIVATE ", b"KEY-----\n"))
    footer = b"".join((b"-----END OPENSSH PRIVATE ", b"KEY-----\n"))
    if not value.startswith(header) or not value.endswith(footer) or b"\r" in value:
        raise ValueError("identity is not a canonical OpenSSH private key")
    encoded = value[len(header) : -len(footer)]
    if not encoded.endswith(b"\n"):
        raise ValueError("identity PEM body is invalid")
    encoded = encoded[:-1]
    lines = encoded.split(b"\n")
    if (
        not lines
        or any(not 1 <= len(line) <= 70 for line in lines)
        or any(re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", line) is None for line in lines)
    ):
        raise ValueError("identity PEM body is invalid")
    try:
        payload = base64.b64decode(b"".join(lines), validate=True)
    except binascii.Error:
        raise ValueError("identity PEM body is invalid") from None
    magic = b"openssh-key-v1\x00"
    if not payload.startswith(magic):
        raise ValueError("identity payload is not OpenSSH key v1")
    offset = len(magic)
    cipher_name, offset = _read_ssh_string(payload, offset, maximum=64)
    kdf_name, offset = _read_ssh_string(payload, offset, maximum=64)
    kdf_options, offset = _read_ssh_string(payload, offset, maximum=1_024)
    if (
        cipher_name != b"none"
        or kdf_name != b"none"
        or kdf_options
        or offset + 4 > len(payload)
        or struct.unpack_from(">I", payload, offset)[0] != 1
    ):
        raise ValueError("identity must contain one unencrypted OpenSSH key")
    offset += 4
    public_blob, offset = _read_ssh_string(payload, offset, maximum=16_384)
    private_block, offset = _read_ssh_string(payload, offset, maximum=_MAX_ARTIFACT_BYTES)
    if offset != len(payload) or len(private_block) < 8:
        raise ValueError("identity key payload is invalid")
    key_type, public_key = _parse_ed25519_public_blob(public_blob)
    private_offset = 0
    if private_offset + 8 > len(private_block):
        raise ValueError("identity private payload is truncated")
    first_check, second_check = struct.unpack_from(">II", private_block, private_offset)
    private_offset += 8
    private_key_type, private_offset = _read_ssh_string(
        private_block,
        private_offset,
        maximum=64,
    )
    private_public, private_offset = _read_ssh_string(
        private_block,
        private_offset,
        maximum=64,
    )
    private_key, private_offset = _read_ssh_string(
        private_block,
        private_offset,
        maximum=128,
    )
    derived_public = (
        Ed25519PrivateKey.from_private_bytes(private_key[:32])
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
        if len(private_key) == 64
        else b""
    )
    comment, private_offset = _read_ssh_string(
        private_block,
        private_offset,
        maximum=1_024,
    )
    padding = private_block[private_offset:]
    if (
        first_check != second_check
        or private_key_type != b"ssh-ed25519"
        or private_public != public_key
        or len(private_key) != 64
        or derived_public != public_key
        or private_key[-32:] != public_key
        or b"\x00" in comment
        or b"\r" in comment
        or b"\n" in comment
        or not 1 <= len(padding) <= 8
        or padding != bytes(range(1, len(padding) + 1))
    ):
        raise ValueError("identity private key semantics are invalid")
    return key_type, hashlib.sha256(public_blob).hexdigest()


def _parse_known_hosts_pin(
    value: bytes,
    *,
    expected_ipv4: str,
) -> tuple[str, str]:
    if not value.endswith(b"\n") or value.count(b"\n") != 1 or b"\r" in value:
        raise ValueError("known_hosts must contain one canonical line")
    try:
        line = value[:-1].decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("known_hosts line is not ASCII") from None
    parts = line.split(" ")
    if len(parts) != 3 or parts[0] != expected_ipv4 or any(not part for part in parts):
        raise ValueError("known_hosts target is not the commissioned numeric address")
    key_type, encoded = parts[1:]
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9@._+-]{0,63}", key_type) is None:
        raise ValueError("known_hosts key type is invalid")
    try:
        public_blob = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("known_hosts key blob is invalid") from None
    if base64.b64encode(public_blob).decode("ascii") != encoded:
        raise ValueError("known_hosts key blob is not canonical")
    embedded_type, offset = _read_ssh_string(public_blob, 0, maximum=64)
    try:
        embedded_type_text = embedded_type.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("known_hosts key type is invalid") from None
    if embedded_type_text != key_type or offset >= len(public_blob) or len(public_blob) > 16_384:
        raise ValueError("known_hosts key blob semantics are invalid")
    _parse_ed25519_public_blob(public_blob)
    return key_type, hashlib.sha256(public_blob).hexdigest()


@dataclass(frozen=True, slots=True)
class _StateObservation:
    state: ReachyA05OperatorStateV1
    device: int
    inode: int


def _close_spawn_descriptor(descriptor: int) -> bool:
    """Attempt one close; never retry an fd whose close outcome is ambiguous."""

    try:
        os.close(descriptor)
    except BaseException:
        # POSIX close errors leave descriptor state unspecified. Retrying the same
        # integer could close an unrelated descriptor that another handler reopened.
        return True
    return False


class _OwnedSpawnDescriptor:
    __slots__ = ("_descriptor",)

    def __init__(self, descriptor: int) -> None:
        if type(descriptor) is not int or descriptor < 0:
            raise TypeError("spawn descriptor is invalid")
        self._descriptor: int | None = descriptor

    def __del__(self) -> None:
        descriptor = getattr(self, "_descriptor", None)
        if descriptor is not None:
            self._descriptor = None
            _close_spawn_descriptor(descriptor)

    def borrow(self) -> int:
        if self._descriptor is None:
            raise RuntimeError("spawn descriptor is closed")
        return self._descriptor

    def close(self) -> bool:
        descriptor = self._descriptor
        if descriptor is None:
            return False
        self._descriptor = None
        return _close_spawn_descriptor(descriptor)


def _acquire_spawn_descriptor(opener: Callable[[], int]) -> _OwnedSpawnDescriptor:
    descriptor = opener()
    try:
        return _OwnedSpawnDescriptor(descriptor)
    except BaseException as error:
        if _close_spawn_descriptor(descriptor):
            error.add_note("additional spawn authority cleanup failure")
        raise


def _create_private_descriptor(
    opener: Callable[[], int],
    *,
    mode: int,
) -> _OwnedSpawnDescriptor:
    """Create, normalize, and own one O_EXCL descriptor before returning it."""

    def open_normalized() -> int:
        descriptor: int | None = None
        try:
            descriptor = opener()
            os.fchmod(descriptor, mode)
            return descriptor
        except BaseException as error:
            if descriptor is not None:
                cleanup_failed = False
                try:
                    os.fchmod(descriptor, mode)
                except BaseException:
                    cleanup_failed = True
                if _close_spawn_descriptor(descriptor):
                    cleanup_failed = True
                if cleanup_failed:
                    error.add_note("additional private descriptor cleanup failure")
            raise

    return _acquire_spawn_descriptor(open_normalized)


class _OwnedSpawnSnapshot:
    __slots__ = (
        "_closed",
        "_closing",
        "_creator_pid",
        "_directory",
        "_identity",
        "_known_hosts",
        "_owner_uid",
        "_root",
        "name",
    )

    def __init__(
        self,
        *,
        root: OwnedDirectory,
        owner_uid: int,
        name: str,
        directory: _OwnedSpawnDescriptor,
    ) -> None:
        if _SPAWN_SNAPSHOT_PATTERN.fullmatch(name) is None:
            raise TypeError("spawn snapshot name is invalid")
        self._root = root
        self._owner_uid = owner_uid
        self._creator_pid = os.getpid()
        self.name = name
        self._directory = directory
        self._identity: _OwnedSpawnDescriptor | None = None
        self._known_hosts: _OwnedSpawnDescriptor | None = None
        self._closed = False
        self._closing = False

    def __del__(self) -> None:
        with suppress(BaseException):
            self.close(primary_error=None, suppress=True)

    @property
    def directory_descriptor(self) -> int:
        return self._directory.borrow()

    @property
    def identity_descriptor(self) -> int:
        if self._identity is None:
            raise RuntimeError("spawn snapshot identity is absent")
        return self._identity.borrow()

    @property
    def known_hosts_descriptor(self) -> int:
        if self._known_hosts is None:
            raise RuntimeError("spawn snapshot known-hosts is absent")
        return self._known_hosts.borrow()

    def bind_identity(self, descriptor: _OwnedSpawnDescriptor) -> None:
        if self._identity is not None:
            raise RuntimeError("spawn snapshot identity is already bound")
        self._identity = descriptor

    def bind_known_hosts(self, descriptor: _OwnedSpawnDescriptor) -> None:
        if self._known_hosts is not None:
            raise RuntimeError("spawn snapshot known-hosts is already bound")
        self._known_hosts = descriptor

    def close(
        self,
        *,
        primary_error: BaseException | None,
        suppress: bool = False,
    ) -> None:
        if self._closed:
            return
        if self._closing:
            return
        completed = False
        try:
            self._closing = True
            cleanup_error: BaseException | None = None
            if os.getpid() == self._creator_pid:
                snapshot_exists = True
                try:
                    os.stat(self.name, dir_fd=self._root.fd, follow_symlinks=False)
                except FileNotFoundError:
                    snapshot_exists = False
                except OSError:
                    cleanup_error = PermissionError(
                        "unsafe Reachy spawn authority snapshot cleanup"
                    )
                if snapshot_exists and cleanup_error is None:
                    for attempt in range(2):
                        try:
                            ReachyA05CommissioningRepository._remove_spawn_snapshot(
                                self._root,
                                name=self.name,
                                owner_uid=self._owner_uid,
                                directory_descriptor=self._directory.borrow(),
                                identity_descriptor=(
                                    None if self._identity is None else self._identity.borrow()
                                ),
                                known_hosts_descriptor=(
                                    None
                                    if self._known_hosts is None
                                    else self._known_hosts.borrow()
                                ),
                            )
                            break
                        except BaseException as error:
                            if cleanup_error is None:
                                cleanup_error = error
                            else:
                                cleanup_error.add_note("additional spawn authority cleanup failure")
                        if attempt == 1:
                            break
                        try:
                            _require_private_directory(
                                self._directory.borrow(),
                                name=self.name,
                                parent_descriptor=self._root.fd,
                                expected_uid=self._owner_uid,
                            )
                        except FileNotFoundError:
                            break
                        except BaseException:
                            # The exact named directory cannot be proven safe for a retry.
                            cleanup_error.add_note("additional spawn authority cleanup failure")
                            break
            descriptor_cleanup_failed = False
            for owner in (self._identity, self._known_hosts, self._directory):
                if owner is not None and owner.close():
                    descriptor_cleanup_failed = True
            completed = True
            if primary_error is not None and (
                cleanup_error is not None or descriptor_cleanup_failed
            ):
                primary_error.add_note("additional spawn authority cleanup failure")
                return
            if suppress:
                return
            if cleanup_error is not None:
                if descriptor_cleanup_failed:
                    cleanup_error.add_note("additional spawn authority cleanup failure")
                raise cleanup_error
            if descriptor_cleanup_failed:
                raise PermissionError("unsafe Reachy spawn authority snapshot cleanup") from None
        finally:
            self._closing = False
            if completed:
                self._closed = True


_SPAWN_AUTHORITY_LEASE_TOKEN = object()


class ReachyA05SpawnLease:
    """Lock-held, snapshot-path authority for one SSH process lifetime.

    The repository creates this noncopyable lease only after validating the exact
    canonical state and its committed local artifacts. The ordinary file paths are
    required because macOS OpenSSH closes inherited non-stdio descriptors before it
    opens identity and known-host files. Call :meth:`revalidate` immediately before
    creating the SSH process and keep the context open through authenticated startup
    (or, more simply, through process exit). The repository lock, source descriptors,
    snapshot descriptors, and private snapshot names remain owned for that lifetime.

    This boundary detects cooperating races. An arbitrary, continuously malicious
    same-UID process can still race path lookup on platforms without an OpenSSH
    descriptor API and is outside the repository threat model.
    """

    __slots__ = (
        "_clock",
        "_closed",
        "_closing",
        "_creator_pid",
        "_identity_owner",
        "_known_hosts_owner",
        "_lock_descriptor",
        "_owner_uid",
        "_poisoned",
        "_root",
        "_snapshot",
        "_state",
        "_state_owner",
        "_state_raw",
    )

    def __init__(
        self,
        *,
        token: object,
        root: OwnedDirectory,
        owner_uid: int,
        clock: Callable[[], datetime],
        state: ReachyA05CommissioningStateV1,
        lock_descriptor: int,
        state_owner: _OwnedSpawnDescriptor,
        identity_owner: _OwnedSpawnDescriptor,
        known_hosts_owner: _OwnedSpawnDescriptor,
        snapshot: _OwnedSpawnSnapshot,
    ) -> None:
        if token is not _SPAWN_AUTHORITY_LEASE_TOKEN:
            raise TypeError("spawn authority leases are repository-owned")
        descriptors = (
            lock_descriptor,
            state_owner.borrow(),
            identity_owner.borrow(),
            known_hosts_owner.borrow(),
            snapshot.directory_descriptor,
            snapshot.identity_descriptor,
            snapshot.known_hosts_descriptor,
        )
        if (
            type(owner_uid) is not int
            or not callable(clock)
            or type(state) is not ReachyA05CommissioningStateV1
            or any(type(descriptor) is not int or descriptor < 0 for descriptor in descriptors)
            or len(set(descriptors)) != len(descriptors)
        ):
            raise TypeError("spawn authority lease inputs are invalid")
        self._root = root
        self._owner_uid = owner_uid
        self._creator_pid = os.getpid()
        self._clock = clock
        self._state = state
        self._state_raw = canonical_bytes(state)
        self._lock_descriptor = lock_descriptor
        self._state_owner = state_owner
        self._identity_owner = identity_owner
        self._known_hosts_owner = known_hosts_owner
        self._snapshot = snapshot
        self._closed = False
        self._closing = False
        self._poisoned = False

    def __repr__(self) -> str:
        return "ReachyA05SpawnLease(<opaque>)"

    def __del__(self) -> None:
        with suppress(BaseException):
            self._close(primary_error=None, suppress=True)

    def __copy__(self) -> ReachyA05SpawnLease:
        raise TypeError("spawn authority leases are noncopyable")

    def __deepcopy__(self, memo: object) -> ReachyA05SpawnLease:
        del memo
        raise TypeError("spawn authority leases are noncopyable")

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("spawn authority leases are noncopyable")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        del protocol
        raise TypeError("spawn authority leases are noncopyable")

    def _require_open(self) -> None:
        if os.getpid() != self._creator_pid:
            raise ReachyA05RepositoryError("spawn authority lease is invalid")
        if self._closed:
            raise RuntimeError("spawn authority lease is closed")
        if self._poisoned:
            raise ReachyA05RepositoryError("spawn authority lease is invalid")

    @property
    def state(self) -> ReachyA05CommissioningStateV1:
        self._require_open()
        return self._state

    @property
    def identity_path(self) -> str:
        self._require_open()
        return str(self._root.path / self._snapshot.name / "identity")

    @property
    def known_hosts_path(self) -> str:
        self._require_open()
        return str(self._root.path / self._snapshot.name / "known_hosts")

    @property
    def identity_config_option(self) -> str:
        return _openssh_config_option("IdentityFile", self.identity_path)

    @property
    def known_hosts_config_option(self) -> str:
        return _openssh_config_option("UserKnownHostsFile", self.known_hosts_path)

    def _read_stable_named_file(
        self,
        *,
        descriptor: int,
        name: str,
        parent_descriptor: int,
        maximum: int,
    ) -> bytes:
        return _read_stable_private_file(
            descriptor,
            name=name,
            parent_descriptor=parent_descriptor,
            expected_uid=self._owner_uid,
            maximum=maximum,
        )

    def revalidate(self) -> ReachyA05CommissioningStateV1:
        self._require_open()
        try:
            self._root.revalidate()
            _require_private_regular_file(
                self._lock_descriptor,
                name=_LOCK_FILENAME,
                parent_descriptor=self._root.fd,
                expected_uid=self._owner_uid,
            )
            _require_private_directory(
                self._snapshot.directory_descriptor,
                name=self._snapshot.name,
                parent_descriptor=self._root.fd,
                expected_uid=self._owner_uid,
            )
            _require_exact_spawn_snapshot_namespace(
                self._root,
                snapshot_name=self._snapshot.name,
                snapshot_descriptor=self._snapshot.directory_descriptor,
                expected_uid=self._owner_uid,
            )
            state_raw = self._read_stable_named_file(
                descriptor=self._state_owner.borrow(),
                name=_STATE_FILENAME,
                parent_descriptor=self._root.fd,
                maximum=_MAX_STATE_BYTES,
            )
            identity_raw = self._read_stable_named_file(
                descriptor=self._identity_owner.borrow(),
                name="identity",
                parent_descriptor=self._root.fd,
                maximum=_MAX_ARTIFACT_BYTES,
            )
            known_hosts_raw = self._read_stable_named_file(
                descriptor=self._known_hosts_owner.borrow(),
                name="known_hosts",
                parent_descriptor=self._root.fd,
                maximum=_MAX_ARTIFACT_BYTES,
            )
            snapshot_identity_raw = self._read_stable_named_file(
                descriptor=self._snapshot.identity_descriptor,
                name="identity",
                parent_descriptor=self._snapshot.directory_descriptor,
                maximum=_MAX_ARTIFACT_BYTES,
            )
            snapshot_known_hosts_raw = self._read_stable_named_file(
                descriptor=self._snapshot.known_hosts_descriptor,
                name="known_hosts",
                parent_descriptor=self._snapshot.directory_descriptor,
                maximum=_MAX_ARTIFACT_BYTES,
            )
            if (
                state_raw != self._state_raw
                or snapshot_identity_raw != identity_raw
                or snapshot_known_hosts_raw != known_hosts_raw
                or hashlib.sha256(identity_raw).hexdigest() != self._state.identity_file_sha256
                or hashlib.sha256(known_hosts_raw).hexdigest()
                != self._state.known_hosts_file_sha256
            ):
                raise ReachyA05RepositoryError("Reachy spawn authority commitment mismatch")
            ReachyA05CommissioningRepository._require_no_reserved_temporary_state(self._root)
            ReachyA05CommissioningRepository._require_fresh(
                self._state,
                now=self._clock(),
            )
            _require_private_regular_file(
                self._lock_descriptor,
                name=_LOCK_FILENAME,
                parent_descriptor=self._root.fd,
                expected_uid=self._owner_uid,
            )
            _require_private_directory(
                self._snapshot.directory_descriptor,
                name=self._snapshot.name,
                parent_descriptor=self._root.fd,
                expected_uid=self._owner_uid,
            )
            _require_exact_spawn_snapshot_namespace(
                self._root,
                snapshot_name=self._snapshot.name,
                snapshot_descriptor=self._snapshot.directory_descriptor,
                expected_uid=self._owner_uid,
            )
            self._root.revalidate()
        except BaseException:
            self._poisoned = True
            raise
        return self._state

    def _close(
        self,
        *,
        primary_error: BaseException | None,
        suppress: bool = False,
    ) -> None:
        if self._closed:
            return
        if self._closing:
            return
        completed = False
        try:
            self._closing = True
            cleanup_error: BaseException | None = None
            try:
                self._snapshot.close(primary_error=primary_error, suppress=suppress)
            except BaseException as error:
                cleanup_error = error
            descriptor_cleanup_failed = False
            for owner in (
                self._state_owner,
                self._identity_owner,
                self._known_hosts_owner,
            ):
                if owner.close():
                    descriptor_cleanup_failed = True
            completed = True
            if primary_error is not None and (
                cleanup_error is not None or descriptor_cleanup_failed
            ):
                primary_error.add_note("additional spawn authority cleanup failure")
                return
            if suppress:
                return
            if cleanup_error is not None:
                if descriptor_cleanup_failed:
                    cleanup_error.add_note("additional spawn authority cleanup failure")
                raise cleanup_error
            if descriptor_cleanup_failed:
                raise PermissionError("unsafe Reachy spawn authority descriptor cleanup") from None
        finally:
            self._closing = False
            if completed:
                self._closed = True


class ReachyA05CommissioningRepository:
    """Descriptor-safe state store for detected or cooperating races.

    Arbitrary, continuously malicious same-UID mutation is outside this file-integrity
    boundary; every race this store detects fails closed.

    ``require_current`` is state validation, not SSH-spawn authority. The deploy adapter must
    use ``acquire_spawn_lease`` so the exact state and artifact descriptors, plus
    the exclusive repository lock, remain bound through process creation. This repository
    deliberately exposes no spawn operation itself.
    """

    def __init__(
        self,
        root: Path,
        *,
        clock: Callable[[], datetime] = _system_utc_now,
    ) -> None:
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._root = absolute_lexical_path(root)
        self._owner_uid = os.geteuid()
        self._clock = clock

    @classmethod
    def from_login_home(cls) -> ReachyA05CommissioningRepository:
        login = pwd.getpwuid(os.geteuid())
        return cls(
            Path(login.pw_dir) / ".local/share/tuntun/reachy-a05",
            clock=_system_utc_now,
        )

    @property
    def root(self) -> Path:
        return self._root

    def _current_time(self) -> datetime:
        current = self._clock()
        if (
            type(current) is not datetime
            or current.tzinfo is None
            or current.utcoffset() != timedelta(0)
        ):
            raise TypeError("clock must return a timezone-aware UTC datetime")
        return current

    def _require_fixed_local_paths(
        self,
        state: ReachyA05CommissioningStateV1,
    ) -> None:
        expected = (
            str(self._root / "identity"),
            str(self._root / "known_hosts"),
        )
        if (state.identity_path, state.known_hosts_path) != expected:
            raise ReachyA05RepositoryError(
                "Reachy commissioning state has invalid local artifact paths"
            )

    def _require_bound_artifacts(
        self,
        root: OwnedDirectory,
        state: ReachyA05CommissioningStateV1,
    ) -> None:
        observed: dict[str, bytes] = {}
        for name, expected_sha256 in (
            ("identity", state.identity_file_sha256),
            ("known_hosts", state.known_hosts_file_sha256),
        ):
            try:
                descriptor = os.open(name, _READ_FLAGS, dir_fd=root.fd)
            except OSError:
                raise ReachyA05RepositoryError(
                    "Reachy commissioning artifact is unavailable"
                ) from None
            try:
                before = _require_private_regular_file(
                    descriptor,
                    name=name,
                    parent_descriptor=root.fd,
                    expected_uid=self._owner_uid,
                )
                if not 1 <= before.st_size <= _MAX_ARTIFACT_BYTES:
                    raise ReachyA05RepositoryError("Reachy commissioning artifact size is invalid")
                chunks: list[bytes] = []
                remaining = _MAX_ARTIFACT_BYTES + 1
                while remaining:
                    chunk = os.read(descriptor, remaining)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw = b"".join(chunks)
                after = _require_private_regular_file(
                    descriptor,
                    name=name,
                    parent_descriptor=root.fd,
                    expected_uid=self._owner_uid,
                )
                if (
                    not _same_file_observation(before, after)
                    or len(raw) != before.st_size
                    or hashlib.sha256(raw).hexdigest() != expected_sha256
                ):
                    raise ReachyA05RepositoryError(
                        "Reachy commissioning artifact commitment mismatch"
                    )
                observed[name] = raw
                root.revalidate()
            finally:
                try:
                    os.close(descriptor)
                except OSError:
                    raise PermissionError("unsafe Reachy commissioning artifact") from None
        try:
            identity_type, identity_sha256 = _parse_openssh_ed25519_identity(observed["identity"])
            host_key_type, host_key_sha256 = _parse_known_hosts_pin(
                observed["known_hosts"],
                expected_ipv4=state.reachy_ipv4,
            )
        except (KeyError, ValueError):
            raise ReachyA05RepositoryError(
                "Reachy commissioning artifact semantics are invalid"
            ) from None
        if (
            identity_type != state.identity_public_key_type
            or identity_sha256 != state.identity_public_key_sha256
            or host_key_type != state.pinned_host_key_type
            or host_key_sha256 != state.pinned_host_key_sha256
            or identity_sha256 == host_key_sha256
            or state.identity_public_key_sha256 == state.pinned_host_key_sha256
        ):
            raise ReachyA05RepositoryError(
                "Reachy commissioning artifact semantic commitment mismatch"
            )

    @contextmanager
    def _locked_root(
        self,
        *,
        commit_witness: _CommitWitness | None = None,
        lock_descriptor_observer: Callable[[int], None] | None = None,
    ) -> Iterator[OwnedDirectory]:
        try:
            with open_owned_directory(self._root) as root:
                lock_owner: _OwnedSpawnDescriptor | None = None
                lock_owner_pid: int | None = None
                primary_error: BaseException | None = None
                try:
                    try:
                        try:
                            lock_owner = _create_private_descriptor(
                                lambda: os.open(
                                    _LOCK_FILENAME,
                                    _LOCK_FLAGS | os.O_EXCL,
                                    _PRIVATE_FILE_MODE,
                                    dir_fd=root.fd,
                                ),
                                mode=_PRIVATE_FILE_MODE,
                            )
                        except FileExistsError:
                            lock_owner = _acquire_spawn_descriptor(
                                lambda: os.open(
                                    _LOCK_FILENAME,
                                    _LOCK_FLAGS & ~os.O_CREAT,
                                    dir_fd=root.fd,
                                )
                            )
                    except OSError:
                        raise PermissionError("unsafe Reachy commissioning lock") from None
                    lock_descriptor = lock_owner.borrow()
                    lock_owner_pid = os.getpid()
                    _require_private_regular_file(
                        lock_descriptor,
                        name=_LOCK_FILENAME,
                        parent_descriptor=root.fd,
                        expected_uid=self._owner_uid,
                    )
                    fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
                    _require_private_regular_file(
                        lock_descriptor,
                        name=_LOCK_FILENAME,
                        parent_descriptor=root.fd,
                        expected_uid=self._owner_uid,
                    )
                    root.revalidate()
                    if lock_descriptor_observer is not None:
                        lock_descriptor_observer(lock_descriptor)
                    yield root
                    _require_private_regular_file(
                        lock_descriptor,
                        name=_LOCK_FILENAME,
                        parent_descriptor=root.fd,
                        expected_uid=self._owner_uid,
                    )
                    root.revalidate()
                except BaseException as error:
                    primary_error = error
                    raise
                finally:
                    cleanup_failed = False
                    if lock_owner is not None and os.getpid() == lock_owner_pid:
                        try:
                            fcntl.flock(lock_owner.borrow(), fcntl.LOCK_UN)
                        except BaseException:
                            cleanup_failed = True
                    if lock_owner is not None and lock_owner.close():
                        cleanup_failed = True
                    if cleanup_failed:
                        if primary_error is None:
                            raise PermissionError("unsafe Reachy commissioning lock") from None
                        primary_error.add_note("additional commissioning lock cleanup failure")
        except (ReachyA05CommitUnknown, ReachyA05PostCommitError):
            raise
        except BaseException:
            if commit_witness is not None:
                if commit_witness.commit_proven:
                    raise commit_witness.post_commit_error() from None
                if commit_witness.namespace_mutated:
                    raise commit_witness.commit_unknown() from None
            raise

    def _read_named_state(
        self,
        root: OwnedDirectory,
        *,
        name: str,
        required: bool,
    ) -> _StateObservation | None:
        try:
            descriptor = os.open(name, _READ_FLAGS, dir_fd=root.fd)
        except FileNotFoundError:
            if required:
                raise ReachyA05RepositoryError("Reachy commissioning state is absent") from None
            return None
        except OSError:
            raise PermissionError("unsafe Reachy commissioning state file") from None
        try:
            before = _require_private_regular_file(
                descriptor,
                name=name,
                parent_descriptor=root.fd,
                expected_uid=self._owner_uid,
            )
            if not 1 <= before.st_size <= _MAX_STATE_BYTES:
                raise ReachyA05RepositoryError("Reachy commissioning state size is invalid")
            chunks: list[bytes] = []
            remaining = _MAX_STATE_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = _require_private_regular_file(
                descriptor,
                name=name,
                parent_descriptor=root.fd,
                expected_uid=self._owner_uid,
            )
            if (
                not _same_file_observation(before, after)
                or len(raw) != before.st_size
                or not 1 <= len(raw) <= _MAX_STATE_BYTES
            ):
                raise PermissionError("Reachy commissioning state changed during read")
            root.revalidate()
        finally:
            os.close(descriptor)
        try:
            decoded = parse_bounded_json_value(raw, max_bytes=_MAX_STATE_BYTES)
            if type(decoded) is not dict:
                raise ContractParseError("state must be an object")
            record_kind = decoded.get("record_kind")
            if record_kind == "bound":
                state: ReachyA05OperatorStateV1 = parse_contract_json(
                    ReachyA05CommissioningStateV1,
                    raw,
                    max_bytes=_MAX_STATE_BYTES,
                    require_canonical=True,
                )
            elif record_kind == "revoked":
                state = parse_contract_json(
                    ReachyA05RevokedTombstoneV1,
                    raw,
                    max_bytes=_MAX_STATE_BYTES,
                    require_canonical=True,
                )
            else:
                raise ContractParseError("state kind is invalid")
        except ContractParseError:
            raise ReachyA05RepositoryError("Reachy commissioning state is invalid") from None
        if type(state) is ReachyA05CommissioningStateV1:
            self._require_fixed_local_paths(state)
        return _StateObservation(state, before.st_dev, before.st_ino)

    def _read_state(
        self,
        root: OwnedDirectory,
        *,
        required: bool,
    ) -> _StateObservation | None:
        return self._read_named_state(
            root,
            name=_STATE_FILENAME,
            required=required,
        )

    @staticmethod
    def _reserved_temporary_names(root: OwnedDirectory) -> tuple[str, ...]:
        try:
            names = os.listdir(root.fd)
        except OSError:
            raise PermissionError("unsafe Reachy commissioning temp inventory") from None
        root.revalidate()
        return tuple(
            sorted(
                name
                for name in names
                if type(name) is str
                and name.startswith(".operator-state.")
                and name.endswith(".tmp")
            )
        )

    @staticmethod
    def _require_no_reserved_temporary_state(root: OwnedDirectory) -> None:
        if ReachyA05CommissioningRepository._reserved_temporary_names(root):
            raise ReachyA05RepositoryError(
                "Reachy reserved temp evidence requires exact reconciliation"
            )

    def _require_exact_named_bytes(
        self,
        root: OwnedDirectory,
        *,
        descriptor: int,
        name: str,
        expected: bytes,
    ) -> tuple[int, int]:
        before = _require_private_regular_file(
            descriptor,
            name=name,
            parent_descriptor=root.fd,
            expected_uid=self._owner_uid,
        )
        if before.st_size != len(expected):
            raise ReachyA05RepositoryError("Reachy commissioning state publication mismatch")
        raw = os.pread(descriptor, len(expected) + 1, 0)
        after = _require_private_regular_file(
            descriptor,
            name=name,
            parent_descriptor=root.fd,
            expected_uid=self._owner_uid,
        )
        if (
            raw != expected
            or not _same_file_observation(before, after)
            or after.st_size != len(expected)
        ):
            raise ReachyA05RepositoryError("Reachy commissioning state publication mismatch")
        return (after.st_dev, after.st_ino)

    @staticmethod
    def _require_fresh(
        state: ReachyA05CommissioningStateV1,
        *,
        now: datetime,
    ) -> None:
        if now.tzinfo is None:
            raise TypeError("current time must be timezone-aware")
        if not state.deployment.issued_at <= now < state.deployment.expires_at:
            raise ReachyA05RepositoryError("Reachy commissioning state is stale")

    @staticmethod
    def _require_expired(
        state: ReachyA05CommissioningStateV1,
        *,
        now: datetime,
    ) -> None:
        if now.tzinfo is None:
            raise TypeError("current time must be timezone-aware")
        if now < state.deployment.expires_at:
            raise ReachyA05RepositoryError("Reachy commissioning state is not expired")

    @staticmethod
    def _require_recent_revocation(
        state: ReachyA05RevokedTombstoneV1,
        *,
        now: datetime,
    ) -> None:
        if now.tzinfo is None:
            raise TypeError("current time must be timezone-aware")
        if not now - timedelta(hours=24) <= state.revoked_at <= now:
            raise ReachyA05RepositoryError("Reachy revocation proof is stale or future-dated")

    @staticmethod
    def _require_local_artifacts_absent(root: OwnedDirectory) -> None:
        for name in ("identity", "known_hosts"):
            try:
                os.stat(name, dir_fd=root.fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError:
                raise PermissionError("Reachy commissioning artifact absence is unsafe") from None
            raise ReachyA05RepositoryError(
                "Reachy commissioning artifacts must be removed before revocation"
            )
        root.revalidate()

    @staticmethod
    def _bound_state_bindings(state: ReachyA05CommissioningStateV1) -> tuple[object, ...]:
        deployment = state.deployment
        return (
            deployment.commissioning_id,
            deployment.boot_identity_sha256,
            deployment.capability_report_sha256,
            deployment.ptt_input_mode,
            deployment.runtime,
            deployment.ssh_principal,
            deployment.remote_home,
            deployment.remote_root,
            deployment.dispatcher_path,
            deployment.dispatcher_protocol_version,
            deployment.dispatcher_sha256,
            deployment.authorized_key_line_sha256,
            state.reachy_ipv4,
            state.ssh_port,
            state.identity_path,
            state.known_hosts_path,
            state.identity_public_key_type,
            state.pinned_host_key_type,
            state.identity_public_key_sha256,
            state.pinned_host_key_sha256,
            state.identity_file_sha256,
            state.known_hosts_file_sha256,
        )

    @staticmethod
    def _require_terminal_recovery_transition(
        current: ReachyA05CommissioningStateV1,
        candidate: ReachyA05OperatorStateV1,
    ) -> None:
        current_deployment = current.deployment
        if type(candidate) is ReachyA05RevokedTombstoneV1:
            revoked_candidate = candidate
            if (
                revoked_candidate.commissioning_id != current_deployment.commissioning_id
                or revoked_candidate.state_generation != current_deployment.state_generation + 1
                or revoked_candidate.prior_deployment_sha256
                != hashlib.sha256(canonical_bytes(current_deployment)).hexdigest()
            ):
                raise ReachyA05RepositoryError("Reachy terminal recovery binding drift")
            if revoked_candidate.revoked_at < current_deployment.issued_at:
                raise ReachyA05RepositoryError(
                    "Reachy terminal recovery revoked_at precedes the deployment"
                )
            return
        bound_candidate = cast(ReachyA05CommissioningStateV1, candidate)
        candidate_deployment = bound_candidate.deployment
        if (
            current_deployment.status is ReachyA05StateStatus.REMOVED
            or candidate_deployment.status is not ReachyA05StateStatus.REMOVED
            or candidate_deployment.staged_bundle_sha256 is not None
            or candidate_deployment.active_bundle_sha256 is not None
        ):
            raise ReachyA05RepositoryError("Reachy terminal recovery transition is invalid")
        if ReachyA05CommissioningRepository._bound_state_bindings(
            current
        ) != ReachyA05CommissioningRepository._bound_state_bindings(bound_candidate):
            raise ReachyA05RepositoryError("Reachy terminal recovery binding drift")
        if candidate_deployment.issued_at < current_deployment.issued_at:
            raise ReachyA05RepositoryError(
                "Reachy terminal recovery candidate issued_at precedes current state"
            )

    @staticmethod
    def _require_ordinary_transition(
        current: ReachyA05OperatorStateV1 | None,
        candidate: ReachyA05OperatorStateV1,
    ) -> None:
        if current is None:
            if type(candidate) is not ReachyA05CommissioningStateV1:
                raise ReachyA05RepositoryError("Reachy ordinary lifecycle transition is invalid")
            candidate_deployment = candidate.deployment
            if (
                candidate_deployment.state_generation != 1
                or candidate_deployment.status is not ReachyA05StateStatus.COMMISSIONED
            ):
                raise ReachyA05RepositoryError("Reachy ordinary lifecycle transition is invalid")
            return
        if type(current) is ReachyA05RevokedTombstoneV1:
            raise ReachyA05RepositoryError("Reachy ordinary lifecycle transition is invalid")
        bound_current = cast(ReachyA05CommissioningStateV1, current)
        current_deployment = bound_current.deployment
        if type(candidate) is ReachyA05RevokedTombstoneV1:
            revoked_candidate = candidate
            if (
                current_deployment.status is not ReachyA05StateStatus.REMOVED
                or revoked_candidate.commissioning_id != current_deployment.commissioning_id
                or revoked_candidate.state_generation != current_deployment.state_generation + 1
                or revoked_candidate.prior_deployment_sha256
                != hashlib.sha256(canonical_bytes(current_deployment)).hexdigest()
            ):
                raise ReachyA05RepositoryError("Reachy ordinary lifecycle transition is invalid")
            if revoked_candidate.revoked_at < current_deployment.issued_at:
                raise ReachyA05RepositoryError(
                    "Reachy ordinary revocation revoked_at precedes the deployment"
                )
            return
        bound_candidate = cast(ReachyA05CommissioningStateV1, candidate)
        candidate_deployment = bound_candidate.deployment
        successor = {
            ReachyA05StateStatus.COMMISSIONED: ReachyA05StateStatus.STAGED,
            ReachyA05StateStatus.STAGED: ReachyA05StateStatus.ACTIVE,
            ReachyA05StateStatus.ACTIVE: ReachyA05StateStatus.REMOVED,
            ReachyA05StateStatus.REMOVED: None,
        }[current_deployment.status]
        if candidate_deployment.status is not successor:
            raise ReachyA05RepositoryError("Reachy ordinary lifecycle transition is invalid")
        if ReachyA05CommissioningRepository._bound_state_bindings(
            bound_current
        ) != ReachyA05CommissioningRepository._bound_state_bindings(bound_candidate):
            raise ReachyA05RepositoryError("Reachy ordinary lifecycle binding drift")
        if candidate_deployment.issued_at < current_deployment.issued_at:
            raise ReachyA05RepositoryError(
                "Reachy ordinary successor issued_at precedes current state"
            )
        if (
            current_deployment.status is ReachyA05StateStatus.STAGED
            and candidate_deployment.status is ReachyA05StateStatus.ACTIVE
            and candidate_deployment.active_bundle_sha256 != current_deployment.staged_bundle_sha256
        ):
            raise ReachyA05RepositoryError(
                "Reachy staged content address was not transferred exactly"
            )

    @staticmethod
    def _require_expectation(
        state: ReachyA05OperatorStateV1,
        expectation: ReachyA05AnyStateExpectation,
    ) -> None:
        if (
            type(state) is ReachyA05CommissioningStateV1
            and type(expectation) is ReachyA05StateExpectation
        ):
            bound_state = state
            bound_expectation = expectation
            deployment = bound_state.deployment
            observed = (
                deployment.commissioning_id,
                deployment.state_generation,
                deployment.boot_identity_sha256,
                deployment.capability_report_sha256,
                deployment.runtime.runtime_inventory_sha256,
                deployment.dispatcher_sha256,
                deployment.authorized_key_line_sha256,
                hashlib.sha256(canonical_bytes(bound_state)).hexdigest(),
            )
            expected = (
                bound_expectation.commissioning_id,
                bound_expectation.state_generation,
                bound_expectation.boot_identity_sha256,
                bound_expectation.capability_report_sha256,
                bound_expectation.runtime_inventory_sha256,
                bound_expectation.dispatcher_sha256,
                bound_expectation.authorized_key_line_sha256,
                bound_expectation.state_sha256,
            )
            if observed != expected:
                raise ReachyA05RepositoryError("Reachy commissioning state commitment mismatch")
            return
        elif (
            type(state) is ReachyA05RevokedTombstoneV1
            and type(expectation) is ReachyA05RevokedStateExpectation
        ):
            revoked_state = state
            revoked_expectation = expectation
            revoked_observed = (
                revoked_state.commissioning_id,
                revoked_state.state_generation,
                revoked_state.prior_deployment_sha256,
                revoked_state.revocation_proof_sha256,
                hashlib.sha256(canonical_bytes(revoked_state)).hexdigest(),
            )
            revoked_expected = (
                revoked_expectation.commissioning_id,
                revoked_expectation.state_generation,
                revoked_expectation.prior_deployment_sha256,
                revoked_expectation.revocation_proof_sha256,
                revoked_expectation.state_sha256,
            )
            if revoked_observed != revoked_expected:
                raise ReachyA05RepositoryError("Reachy commissioning state commitment mismatch")
            return
        raise ReachyA05RepositoryError("Reachy commissioning state commitment mismatch")

    def require_current(
        self,
        *,
        expectation: ReachyA05AnyStateExpectation,
    ) -> ReachyA05OperatorStateV1:
        with self._locked_root() as root:
            self._require_no_reserved_temporary_state(root)
            observation = self._read_state(root, required=True)
            if observation is None:
                raise AssertionError("required state read returned absent")
            state = observation.state
            if type(state) is ReachyA05CommissioningStateV1:
                self._require_fresh(state, now=self._current_time())
            self._require_expectation(state, expectation)
            if type(state) is ReachyA05CommissioningStateV1:
                self._require_bound_artifacts(root, state)
            else:
                self._require_local_artifacts_absent(root)
            self._require_no_reserved_temporary_state(root)
            return state

    @staticmethod
    def _remove_spawn_snapshot(
        root: OwnedDirectory,
        *,
        name: str,
        owner_uid: int,
        directory_descriptor: int | None = None,
        identity_descriptor: int | None = None,
        known_hosts_descriptor: int | None = None,
    ) -> None:
        """Remove one fully validated reserved snapshot without following names."""

        if _SPAWN_SNAPSHOT_PATTERN.fullmatch(name) is None:
            raise PermissionError("unsafe Reachy spawn authority snapshot")
        local_directory: _OwnedSpawnDescriptor | None = None
        local_identity: _OwnedSpawnDescriptor | None = None
        local_known_hosts: _OwnedSpawnDescriptor | None = None
        primary_error: BaseException | None = None
        cleanup_failed = False
        try:
            if directory_descriptor is None:
                try:
                    local_directory = _acquire_spawn_descriptor(
                        lambda: os.open(name, _DIRECTORY_READ_FLAGS, dir_fd=root.fd)
                    )
                except OSError:
                    raise PermissionError("unsafe Reachy spawn authority snapshot") from None
                directory_descriptor = local_directory.borrow()
            _require_private_directory(
                directory_descriptor,
                name=name,
                parent_descriptor=root.fd,
                expected_uid=owner_uid,
            )
            try:
                entries = frozenset(os.listdir(directory_descriptor))
            except OSError:
                raise PermissionError("unsafe Reachy spawn authority snapshot") from None
            if not entries <= {"identity", "known_hosts"}:
                raise PermissionError("unsafe Reachy spawn authority snapshot")
            if "identity" in entries:
                if identity_descriptor is None:
                    try:
                        local_identity = _acquire_spawn_descriptor(
                            lambda: os.open("identity", _READ_FLAGS, dir_fd=directory_descriptor)
                        )
                    except OSError:
                        raise PermissionError("unsafe Reachy spawn authority snapshot") from None
                    identity_descriptor = local_identity.borrow()
                _require_private_regular_file(
                    identity_descriptor,
                    name="identity",
                    parent_descriptor=directory_descriptor,
                    expected_uid=owner_uid,
                )
            if "known_hosts" in entries:
                if known_hosts_descriptor is None:
                    try:
                        local_known_hosts = _acquire_spawn_descriptor(
                            lambda: os.open("known_hosts", _READ_FLAGS, dir_fd=directory_descriptor)
                        )
                    except OSError:
                        raise PermissionError("unsafe Reachy spawn authority snapshot") from None
                    known_hosts_descriptor = local_known_hosts.borrow()
                _require_private_regular_file(
                    known_hosts_descriptor,
                    name="known_hosts",
                    parent_descriptor=directory_descriptor,
                    expected_uid=owner_uid,
                )

            interrupted_cleanup: BaseException | None = None

            def remember_cleanup_error(error: BaseException) -> None:
                nonlocal interrupted_cleanup
                recorded = (
                    PermissionError("unsafe Reachy spawn authority snapshot cleanup")
                    if isinstance(error, OSError)
                    else error
                )
                if interrupted_cleanup is None:
                    interrupted_cleanup = recorded
                else:
                    interrupted_cleanup.add_note("additional spawn authority cleanup failure")

            descriptors_by_leaf = {
                "identity": identity_descriptor,
                "known_hosts": known_hosts_descriptor,
            }
            for leaf in ("identity", "known_hosts"):
                if leaf not in entries:
                    continue
                removed = False
                for _ in range(2):
                    try:
                        os.unlink(leaf, dir_fd=directory_descriptor)
                        removed = True
                        break
                    except BaseException as error:
                        remember_cleanup_error(error)
                    try:
                        os.stat(leaf, dir_fd=directory_descriptor, follow_symlinks=False)
                    except FileNotFoundError:
                        removed = True
                        break
                    except BaseException as error:
                        remember_cleanup_error(error)
                        break
                    descriptor = descriptors_by_leaf[leaf]
                    if descriptor is None:
                        remember_cleanup_error(
                            PermissionError("unsafe Reachy spawn authority snapshot cleanup")
                        )
                        break
                    try:
                        _require_private_regular_file(
                            descriptor,
                            name=leaf,
                            parent_descriptor=directory_descriptor,
                            expected_uid=owner_uid,
                        )
                    except BaseException as error:
                        remember_cleanup_error(error)
                        break
                if not removed:
                    remember_cleanup_error(
                        PermissionError("unsafe Reachy spawn authority snapshot cleanup")
                    )
            try:
                os.fsync(directory_descriptor)
                _require_private_directory(
                    directory_descriptor,
                    name=name,
                    parent_descriptor=root.fd,
                    expected_uid=owner_uid,
                )
                os.rmdir(name, dir_fd=root.fd)
                os.fsync(root.fd)
            except BaseException as error:
                if interrupted_cleanup is not None:
                    remember_cleanup_error(error)
                    raise interrupted_cleanup from None
                if isinstance(error, OSError):
                    raise PermissionError(
                        "unsafe Reachy spawn authority snapshot cleanup"
                    ) from None
                raise
            try:
                os.stat(name, dir_fd=root.fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError:
                raise PermissionError("unsafe Reachy spawn authority snapshot cleanup") from None
            else:
                raise PermissionError("unsafe Reachy spawn authority snapshot cleanup")
            if interrupted_cleanup is not None:
                raise interrupted_cleanup
        except BaseException as error:
            primary_error = error
            raise
        finally:
            for owner in (local_identity, local_known_hosts, local_directory):
                if owner is not None and owner.close():
                    cleanup_failed = True
            if cleanup_failed:
                if primary_error is None:
                    raise PermissionError(
                        "unsafe Reachy spawn authority snapshot cleanup"
                    ) from None
                primary_error.add_note("additional spawn authority cleanup failure")

    @staticmethod
    def _remove_created_spawn_snapshot(
        root: OwnedDirectory,
        *,
        name: str,
        owner_uid: int,
    ) -> None:
        """Normalize and remove only a snapshot candidate created by this operation."""

        if _SPAWN_SNAPSHOT_PATTERN.fullmatch(name) is None:
            raise PermissionError("unsafe Reachy spawn authority snapshot")
        directory: _OwnedSpawnDescriptor | None = None
        identity: _OwnedSpawnDescriptor | None = None
        known_hosts: _OwnedSpawnDescriptor | None = None
        pending_leaf: _OwnedSpawnDescriptor | None = None
        primary_error: BaseException | None = None
        cleanup_failed = False
        try:
            try:
                named_directory = os.stat(name, dir_fd=root.fd, follow_symlinks=False)
            except OSError:
                raise PermissionError("unsafe Reachy spawn authority snapshot") from None
            if (
                not stat.S_ISDIR(named_directory.st_mode)
                or named_directory.st_uid != owner_uid
                or named_directory.st_nlink < 2
            ):
                raise PermissionError("unsafe Reachy spawn authority snapshot")
            # mkdirat is umask-filtered. The unpredictable candidate name and held
            # repository lock exclude cooperating replacement; O_NOFOLLOW plus the
            # descriptor/name identity check below detects any observed replacement.
            os.chmod(name, 0o700, dir_fd=root.fd)
            directory = _acquire_spawn_descriptor(
                lambda: os.open(name, _DIRECTORY_READ_FLAGS, dir_fd=root.fd)
            )
            os.fchmod(directory.borrow(), 0o700)
            _require_private_directory(
                directory.borrow(),
                name=name,
                parent_descriptor=root.fd,
                expected_uid=owner_uid,
            )
            try:
                entries = frozenset(os.listdir(directory.borrow()))
            except OSError:
                raise PermissionError("unsafe Reachy spawn authority snapshot") from None
            if not entries <= {"identity", "known_hosts"}:
                raise PermissionError("unsafe Reachy spawn authority snapshot")

            def acquire_leaf(leaf_name: str) -> _OwnedSpawnDescriptor:
                def open_leaf() -> int:
                    return os.open(
                        leaf_name,
                        _READ_FLAGS,
                        dir_fd=directory.borrow(),
                    )

                return _acquire_spawn_descriptor(open_leaf)

            for leaf in sorted(entries):
                try:
                    named_leaf = os.stat(
                        leaf,
                        dir_fd=directory.borrow(),
                        follow_symlinks=False,
                    )
                except OSError:
                    raise PermissionError("unsafe Reachy spawn authority snapshot") from None
                if (
                    not stat.S_ISREG(named_leaf.st_mode)
                    or named_leaf.st_uid != owner_uid
                    or named_leaf.st_nlink != 1
                ):
                    raise PermissionError("unsafe Reachy spawn authority snapshot")
                os.chmod(leaf, _PRIVATE_FILE_MODE, dir_fd=directory.borrow())
                pending_leaf = acquire_leaf(leaf)
                os.fchmod(pending_leaf.borrow(), _PRIVATE_FILE_MODE)
                _require_private_regular_file(
                    pending_leaf.borrow(),
                    name=leaf,
                    parent_descriptor=directory.borrow(),
                    expected_uid=owner_uid,
                )
                if leaf == "identity":
                    identity = pending_leaf
                else:
                    known_hosts = pending_leaf
                pending_leaf = None
            ReachyA05CommissioningRepository._remove_spawn_snapshot(
                root,
                name=name,
                owner_uid=owner_uid,
                directory_descriptor=directory.borrow(),
                identity_descriptor=None if identity is None else identity.borrow(),
                known_hosts_descriptor=None if known_hosts is None else known_hosts.borrow(),
            )
        except BaseException as error:
            primary_error = error
            raise
        finally:
            for owned_descriptor in (pending_leaf, identity, known_hosts, directory):
                if owned_descriptor is not None and owned_descriptor.close():
                    cleanup_failed = True
            if cleanup_failed:
                if primary_error is None:
                    raise PermissionError(
                        "unsafe Reachy spawn authority snapshot cleanup"
                    ) from None
                primary_error.add_note("additional spawn authority cleanup failure")

    def _reconcile_spawn_snapshots(self, root: OwnedDirectory) -> None:
        try:
            names = tuple(
                sorted(
                    name for name in os.listdir(root.fd) if name.startswith(_SPAWN_SNAPSHOT_PREFIX)
                )
            )
        except OSError:
            raise PermissionError("unsafe Reachy spawn authority snapshot") from None
        if len(names) > _MAX_RESERVED_SPAWN_SNAPSHOTS:
            raise PermissionError("unsafe Reachy spawn authority snapshot inventory")
        if any(_SPAWN_SNAPSHOT_PATTERN.fullmatch(name) is None for name in names):
            raise PermissionError("unsafe Reachy spawn authority snapshot")
        for name in names:
            self._remove_spawn_snapshot(root, name=name, owner_uid=self._owner_uid)

    def _create_spawn_snapshot(
        self,
        root: OwnedDirectory,
        *,
        identity_source_descriptor: int,
        known_hosts_source_descriptor: int,
    ) -> _OwnedSpawnSnapshot:
        identity_raw = _read_stable_private_file(
            identity_source_descriptor,
            name="identity",
            parent_descriptor=root.fd,
            expected_uid=self._owner_uid,
            maximum=_MAX_ARTIFACT_BYTES,
        )
        known_hosts_raw = _read_stable_private_file(
            known_hosts_source_descriptor,
            name="known_hosts",
            parent_descriptor=root.fd,
            expected_uid=self._owner_uid,
            maximum=_MAX_ARTIFACT_BYTES,
        )
        snapshot_name: str | None = None
        snapshot: _OwnedSpawnSnapshot | None = None

        def create_copy(name: str, raw: bytes) -> _OwnedSpawnDescriptor:
            writer: _OwnedSpawnDescriptor | None = None
            reader: _OwnedSpawnDescriptor | None = None
            primary_error: BaseException | None = None
            try:
                if snapshot is None:
                    raise AssertionError("spawn snapshot directory is absent")
                active_snapshot = snapshot
                writer = _acquire_spawn_descriptor(
                    lambda: os.open(
                        name,
                        _CREATE_FLAGS,
                        _PRIVATE_FILE_MODE,
                        dir_fd=active_snapshot.directory_descriptor,
                    )
                )
                os.fchmod(writer.borrow(), _PRIVATE_FILE_MODE)
                offset = 0
                while offset < len(raw):
                    written = os.write(writer.borrow(), raw[offset:])
                    if written <= 0:
                        raise OSError(errno.EIO, "short spawn snapshot write")
                    offset += written
                os.fsync(writer.borrow())
                _require_private_regular_file(
                    writer.borrow(),
                    name=name,
                    parent_descriptor=active_snapshot.directory_descriptor,
                    expected_uid=self._owner_uid,
                )
                if writer.close():
                    raise PermissionError("unsafe Reachy spawn authority snapshot cleanup")
                writer = None
                reader = _acquire_spawn_descriptor(
                    lambda: os.open(name, _READ_FLAGS, dir_fd=active_snapshot.directory_descriptor)
                )
                observed = _read_stable_private_file(
                    reader.borrow(),
                    name=name,
                    parent_descriptor=active_snapshot.directory_descriptor,
                    expected_uid=self._owner_uid,
                    maximum=_MAX_ARTIFACT_BYTES,
                )
                if observed != raw:
                    raise ReachyA05RepositoryError(
                        "Reachy spawn authority snapshot commitment mismatch"
                    )
                result = reader
                reader = None
                return result
            except BaseException as caught:
                primary_error = caught
                raise
            finally:
                cleanup_failed = False
                if writer is not None:
                    try:
                        os.fchmod(writer.borrow(), _PRIVATE_FILE_MODE)
                    except BaseException:
                        cleanup_failed = True
                for owner in (writer, reader):
                    if owner is not None and owner.close():
                        cleanup_failed = True
                if cleanup_failed:
                    if primary_error is None:
                        raise PermissionError(
                            "unsafe Reachy spawn authority snapshot cleanup"
                        ) from None
                    primary_error.add_note("additional spawn authority cleanup failure")

        try:
            for _ in range(8):
                candidate = f"{_SPAWN_SNAPSHOT_PREFIX}{secrets.token_hex(16)}"
                snapshot_name = candidate
                try:
                    os.mkdir(candidate, 0o700, dir_fd=root.fd)
                except FileExistsError:
                    snapshot_name = None
                    continue
                except OSError:
                    raise PermissionError("unsafe Reachy spawn authority snapshot") from None
                try:
                    os.chmod(
                        candidate,
                        0o700,
                        dir_fd=root.fd,
                    )
                except OSError:
                    raise PermissionError("unsafe Reachy spawn authority snapshot") from None
                break
            if snapshot_name is None:
                raise ReachyA05RepositoryError("Reachy spawn authority snapshot is unavailable")
            try:
                directory = _acquire_spawn_descriptor(
                    lambda: os.open(
                        snapshot_name,
                        _DIRECTORY_READ_FLAGS,
                        dir_fd=root.fd,
                    )
                )
            except OSError:
                raise PermissionError("unsafe Reachy spawn authority snapshot") from None
            os.fchmod(directory.borrow(), 0o700)
            _require_private_directory(
                directory.borrow(),
                name=snapshot_name,
                parent_descriptor=root.fd,
                expected_uid=self._owner_uid,
            )
            snapshot = _OwnedSpawnSnapshot(
                root=root,
                owner_uid=self._owner_uid,
                name=snapshot_name,
                directory=directory,
            )
            snapshot.bind_identity(create_copy("identity", identity_raw))
            snapshot.bind_known_hosts(create_copy("known_hosts", known_hosts_raw))
            os.fsync(snapshot.directory_descriptor)
            os.fsync(root.fd)
            if (
                _read_stable_private_file(
                    identity_source_descriptor,
                    name="identity",
                    parent_descriptor=root.fd,
                    expected_uid=self._owner_uid,
                    maximum=_MAX_ARTIFACT_BYTES,
                )
                != identity_raw
                or _read_stable_private_file(
                    known_hosts_source_descriptor,
                    name="known_hosts",
                    parent_descriptor=root.fd,
                    expected_uid=self._owner_uid,
                    maximum=_MAX_ARTIFACT_BYTES,
                )
                != known_hosts_raw
            ):
                raise ReachyA05RepositoryError("Reachy spawn authority source changed")
            result = snapshot
            snapshot = None
            return result
        except BaseException as error:
            if snapshot is not None:
                try:
                    snapshot.close(primary_error=error)
                except BaseException:
                    error.add_note("additional spawn authority cleanup failure")
            elif snapshot_name is not None:
                try:
                    self._remove_created_spawn_snapshot(
                        root,
                        name=snapshot_name,
                        owner_uid=self._owner_uid,
                    )
                except BaseException:
                    error.add_note("additional spawn authority cleanup failure")
            raise

    @contextmanager
    def acquire_spawn_lease(
        self,
        *,
        expectation: ReachyA05StateExpectation,
    ) -> Iterator[ReachyA05SpawnLease]:
        """Retain one exact live state and its artifact authority through SSH spawn.

        The yielded lease owns private OpenSSH-compatible snapshot paths plus all source and
        snapshot descriptors while this context retains the exclusive repository lock. The
        lease is validated before yield and again on a clean context exit; callers must call
        ``revalidate`` immediately before process creation and retain the context until SSH
        has authenticated (or exited), because OpenSSH opens these paths after ``Popen``.
        """

        if type(expectation) is not ReachyA05StateExpectation:
            raise TypeError("spawn authority requires a bound-state expectation")
        lock_descriptor: int | None = None

        def observe_lock(descriptor: int) -> None:
            nonlocal lock_descriptor
            if lock_descriptor is not None:
                raise AssertionError("spawn authority lock was observed more than once")
            lock_descriptor = descriptor

        with self._locked_root(lock_descriptor_observer=observe_lock) as root:
            self._require_no_reserved_temporary_state(root)
            self._reconcile_spawn_snapshots(root)
            observation = self._read_state(root, required=True)
            if observation is None or type(observation.state) is not ReachyA05CommissioningStateV1:
                raise ReachyA05RepositoryError("spawn authority requires a bound state")
            state = observation.state
            self._require_fresh(state, now=self._current_time())
            self._require_expectation(state, expectation)
            self._require_bound_artifacts(root, state)
            if lock_descriptor is None:
                raise AssertionError("spawn authority lock descriptor is absent")

            state_owner: _OwnedSpawnDescriptor | None = None
            identity_owner: _OwnedSpawnDescriptor | None = None
            known_hosts_owner: _OwnedSpawnDescriptor | None = None
            snapshot: _OwnedSpawnSnapshot | None = None
            lease: ReachyA05SpawnLease | None = None
            primary_error: BaseException | None = None
            try:
                try:
                    state_owner = _acquire_spawn_descriptor(
                        lambda: os.open(_STATE_FILENAME, _READ_FLAGS, dir_fd=root.fd)
                    )
                    identity_owner = _acquire_spawn_descriptor(
                        lambda: os.open("identity", _READ_FLAGS, dir_fd=root.fd)
                    )
                    known_hosts_owner = _acquire_spawn_descriptor(
                        lambda: os.open("known_hosts", _READ_FLAGS, dir_fd=root.fd)
                    )
                except OSError:
                    raise ReachyA05RepositoryError(
                        "Reachy spawn authority artifact is unavailable"
                    ) from None
                snapshot = self._create_spawn_snapshot(
                    root,
                    identity_source_descriptor=identity_owner.borrow(),
                    known_hosts_source_descriptor=known_hosts_owner.borrow(),
                )
                lease = ReachyA05SpawnLease(
                    token=_SPAWN_AUTHORITY_LEASE_TOKEN,
                    root=root,
                    owner_uid=self._owner_uid,
                    clock=self._current_time,
                    state=state,
                    lock_descriptor=lock_descriptor,
                    state_owner=state_owner,
                    identity_owner=identity_owner,
                    known_hosts_owner=known_hosts_owner,
                    snapshot=snapshot,
                )
                state_owner = None
                identity_owner = None
                known_hosts_owner = None
                snapshot = None
                lease.revalidate()
                yield lease
                lease.revalidate()
            except BaseException as error:
                primary_error = error
                raise
            finally:
                if lease is not None:
                    lease._close(primary_error=primary_error)
                else:
                    cleanup_failed = False
                    if snapshot is not None:
                        try:
                            snapshot.close(primary_error=primary_error)
                        except BaseException:
                            cleanup_failed = True
                    for owner in (
                        state_owner,
                        identity_owner,
                        known_hosts_owner,
                    ):
                        if owner is not None and owner.close():
                            cleanup_failed = True
                    if cleanup_failed:
                        if primary_error is None:
                            raise PermissionError(
                                "unsafe Reachy spawn authority descriptor cleanup"
                            ) from None
                        primary_error.add_note("additional spawn authority cleanup failure")

    def _write_atomic(
        self,
        root: OwnedDirectory,
        state: ReachyA05OperatorStateV1,
        *,
        expected_state_identity: tuple[int, int] | None,
        expected_generation: int,
        expected_current: ReachyA05AnyStateExpectation | None,
        commit_witness: _CommitWitness,
        current_state_use: _CurrentStateUse,
    ) -> tuple[int, int]:
        raw = canonical_bytes(state)
        if not 1 <= len(raw) <= _MAX_STATE_BYTES:
            raise ReachyA05RepositoryError("Reachy commissioning state size is invalid")
        if (
            _state_generation(state) != commit_witness.candidate_generation
            or hashlib.sha256(raw).hexdigest() != commit_witness.candidate_state_sha256
        ):
            raise AssertionError("candidate commit witness does not match state")
        temporary_name = (
            f".operator-state.g{commit_witness.candidate_generation}."
            f"{commit_witness.candidate_state_sha256}.tmp"
        )
        descriptor: int | None = None
        creating_candidate = True
        temporary_present = False
        cleanup_temporary_on_failure = False
        primary_error: BaseException | None = None

        def displaced_predecessor_matches() -> bool:
            if expected_current is None or expected_state_identity is None:
                return False
            try:
                displaced = self._read_named_state(
                    root,
                    name=temporary_name,
                    required=True,
                )
                if (
                    displaced is None
                    or (
                        displaced.device,
                        displaced.inode,
                    )
                    != expected_state_identity
                ):
                    return False
                self._require_expectation(displaced.state, expected_current)
            except (PermissionError, ReachyA05RepositoryError, OSError):
                return False
            return True

        try:
            try:
                descriptor = os.open(
                    temporary_name,
                    _CREATE_FLAGS,
                    _PRIVATE_FILE_MODE,
                    dir_fd=root.fd,
                )
                cleanup_temporary_on_failure = True
                os.fchmod(descriptor, _PRIVATE_FILE_MODE)
            except FileExistsError:
                creating_candidate = False
                if expected_generation != 0:
                    raise ReachyA05RepositoryError(
                        "Reachy commissioning candidate temp already exists"
                    ) from None
                try:
                    descriptor = os.open(temporary_name, _READ_FLAGS, dir_fd=root.fd)
                except OSError:
                    raise ReachyA05RepositoryError(
                        "Reachy commissioning candidate temp is unsafe"
                    ) from None
                before = _require_private_regular_file(
                    descriptor,
                    name=temporary_name,
                    parent_descriptor=root.fd,
                    expected_uid=self._owner_uid,
                )
                existing = os.pread(descriptor, len(raw) + 1, 0)
                after = _require_private_regular_file(
                    descriptor,
                    name=temporary_name,
                    parent_descriptor=root.fd,
                    expected_uid=self._owner_uid,
                )
                if (
                    existing != raw
                    or before.st_size != len(raw)
                    or not _same_file_observation(before, after)
                ):
                    raise ReachyA05RepositoryError(
                        "Reachy commissioning candidate temp commitment mismatch"
                    ) from None
            temporary_present = True
            if cleanup_temporary_on_failure:
                _require_private_regular_file(
                    descriptor,
                    name=temporary_name,
                    parent_descriptor=root.fd,
                    expected_uid=self._owner_uid,
                )
                view = memoryview(raw)
                offset = 0
                while offset < len(view):
                    written = os.write(descriptor, view[offset:])
                    if written <= 0:
                        raise OSError("short Reachy commissioning state write")
                    offset += written
            os.fsync(descriptor)
            published_identity = self._require_exact_named_bytes(
                root,
                descriptor=descriptor,
                name=temporary_name,
                expected=raw,
            )
            root.revalidate()
            revalidated_current = self._read_state(
                root,
                required=expected_generation > 0,
            )
            publish_time = self._current_time()
            if type(state) is ReachyA05CommissioningStateV1:
                self._require_fresh(state, now=publish_time)
            else:
                self._require_recent_revocation(
                    cast(ReachyA05RevokedTombstoneV1, state), now=publish_time
                )
            self._require_cas(
                revalidated_current,
                expected_generation=expected_generation,
                expected_current=expected_current,
            )
            if current_state_use is _CurrentStateUse.ORDINARY_AUTHORITY:
                self._require_ordinary_transition(
                    None if revalidated_current is None else revalidated_current.state,
                    state,
                )
            if revalidated_current is not None:
                if current_state_use is _CurrentStateUse.ORDINARY_AUTHORITY:
                    if type(revalidated_current.state) is not ReachyA05CommissioningStateV1:
                        raise ReachyA05RepositoryError(
                            "Reachy ordinary lifecycle transition is invalid"
                        )
                    self._require_fresh(revalidated_current.state, now=publish_time)
                else:
                    if type(revalidated_current.state) is not ReachyA05CommissioningStateV1:
                        raise ReachyA05RepositoryError(
                            "Reachy terminal recovery transition is invalid"
                        )
                    self._require_expired(revalidated_current.state, now=publish_time)
            self._require_state_identity(root, expected_state_identity)
            if type(state) is ReachyA05CommissioningStateV1:
                self._require_bound_artifacts(root, state)
            else:
                self._require_local_artifacts_absent(root)
            os.fsync(root.fd)
            if (
                self._require_exact_named_bytes(
                    root,
                    descriptor=descriptor,
                    name=temporary_name,
                    expected=raw,
                )
                != published_identity
            ):
                raise ReachyA05RepositoryError(
                    "Reachy commissioning candidate changed before publication"
                )
            if expected_generation == 0:
                try:
                    _rename_noreplace(root.fd, temporary_name, _STATE_FILENAME)
                except FileExistsError:
                    raise ReachyA05RepositoryError(
                        "Reachy commissioning state CAS mismatch"
                    ) from None
                temporary_present = False
                commit_witness.namespace_mutated = True
            else:
                if expected_current is None or expected_state_identity is None:
                    raise AssertionError("validated update publication expectation is absent")
                _rename_exchange(root.fd, temporary_name, _STATE_FILENAME)
                commit_witness.namespace_mutated = True
                try:
                    candidate_matches = (
                        self._require_exact_named_bytes(
                            root,
                            descriptor=descriptor,
                            name=_STATE_FILENAME,
                            expected=raw,
                        )
                        == published_identity
                    )
                except (PermissionError, ReachyA05RepositoryError, OSError):
                    candidate_matches = False
                if not candidate_matches or not displaced_predecessor_matches():
                    _rename_exchange(root.fd, temporary_name, _STATE_FILENAME)
                    os.fsync(root.fd)
                    commit_witness.namespace_mutated = False
                    raise ReachyA05RepositoryError(
                        "Reachy commissioning state publication predecessor mismatch"
                    )
            if (
                self._require_exact_named_bytes(
                    root,
                    descriptor=descriptor,
                    name=_STATE_FILENAME,
                    expected=raw,
                )
                != published_identity
            ):
                raise ReachyA05RepositoryError("Reachy commissioning state publication mismatch")
            os.fsync(root.fd)
            if (
                self._require_exact_named_bytes(
                    root,
                    descriptor=descriptor,
                    name=_STATE_FILENAME,
                    expected=raw,
                )
                != published_identity
            ):
                raise ReachyA05RepositoryError("Reachy commissioning state publication mismatch")
            if expected_generation > 0 and not displaced_predecessor_matches():
                raise ReachyA05RepositoryError(
                    "Reachy commissioning state publication predecessor mismatch"
                )
            commit_witness.commit_proven = True
            if expected_generation > 0:
                os.unlink(temporary_name, dir_fd=root.fd)
                temporary_present = False
                os.fsync(root.fd)
            return published_identity
        except BaseException as error:
            primary_error = error
            raise
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    if primary_error is None:
                        raise
            if (
                (temporary_present and cleanup_temporary_on_failure)
                or (creating_candidate and descriptor is not None)
            ) and not commit_witness.namespace_mutated:
                try:
                    os.unlink(temporary_name, dir_fd=root.fd)
                except FileNotFoundError:
                    pass
                except OSError:
                    if primary_error is None:
                        raise

    def _require_state_identity(
        self,
        root: OwnedDirectory,
        expected: tuple[int, int] | None,
    ) -> None:
        try:
            named = os.stat(_STATE_FILENAME, dir_fd=root.fd, follow_symlinks=False)
        except FileNotFoundError:
            if expected is None:
                return
            raise PermissionError("Reachy commissioning state path changed") from None
        except OSError:
            raise PermissionError("Reachy commissioning state path changed") from None
        observed = (named.st_dev, named.st_ino)
        if (
            expected is None
            or observed != expected
            or not stat.S_ISREG(named.st_mode)
            or named.st_uid != self._owner_uid
            or stat.S_IMODE(named.st_mode) != _PRIVATE_FILE_MODE
            or named.st_nlink != 1
        ):
            raise PermissionError("Reachy commissioning state path changed")

    def _require_cas(
        self,
        observation: _StateObservation | None,
        *,
        expected_generation: int,
        expected_current: ReachyA05AnyStateExpectation | None,
    ) -> None:
        if expected_generation == 0:
            if observation is not None:
                raise ReachyA05RepositoryError("Reachy commissioning state CAS mismatch")
            return
        if observation is None or _state_generation(observation.state) != expected_generation:
            raise ReachyA05RepositoryError("Reachy commissioning state CAS mismatch")
        if expected_current is None:
            raise AssertionError("validated update CAS expectation is absent")
        self._require_expectation(observation.state, expected_current)

    def replace_atomic(
        self,
        state: ReachyA05CommissioningStateV1,
        *,
        expected_generation: int,
        expected_current: ReachyA05AnyStateExpectation | None = None,
        matching_remote_state: ReachyA05RemoteStateV1,
    ) -> None:
        if (
            type(expected_generation) is not int
            or not 0 <= expected_generation < JCS_MAX_SAFE_INTEGER
        ):
            raise ValueError("expected generation is invalid")
        if state.deployment != matching_remote_state.deployment:
            raise ReachyA05RepositoryError("local and remote commissioning state differ")
        if state.deployment.state_generation != expected_generation + 1:
            raise ReachyA05RepositoryError("Reachy commissioning state CAS mismatch")
        if expected_generation == 0:
            if expected_current is not None:
                raise ValueError("initial commissioning must not have a prior-state expectation")
        elif expected_current is None:
            raise ValueError("commissioning update requires a prior-state expectation")
        elif (
            expected_current.state_generation != expected_generation
            or state.deployment.commissioning_id != expected_current.commissioning_id
        ):
            raise ReachyA05RepositoryError("Reachy commissioning state CAS mismatch")
        self._require_fixed_local_paths(state)
        state_sha256 = hashlib.sha256(canonical_bytes(state)).hexdigest()
        commit_witness = _CommitWitness(
            candidate_generation=state.deployment.state_generation,
            candidate_state_sha256=state_sha256,
        )
        with self._locked_root(commit_witness=commit_witness) as root:
            candidate_temporary_name = (
                f".operator-state.g{commit_witness.candidate_generation}."
                f"{commit_witness.candidate_state_sha256}.tmp"
            )
            reserved_temporary_names = self._reserved_temporary_names(root)
            if reserved_temporary_names and not (
                expected_generation == 0 and reserved_temporary_names == (candidate_temporary_name,)
            ):
                raise ReachyA05RepositoryError(
                    "Reachy reserved temp evidence requires exact reconciliation"
                )
            current_observation = self._read_state(root, required=False)
            self._require_cas(
                current_observation,
                expected_generation=expected_generation,
                expected_current=expected_current,
            )
            self._require_ordinary_transition(
                None if current_observation is None else current_observation.state,
                state,
            )
            observed_time = self._current_time()
            self._require_fresh(state, now=observed_time)
            if current_observation is not None:
                self._require_fresh(
                    cast(ReachyA05CommissioningStateV1, current_observation.state),
                    now=observed_time,
                )
            self._require_bound_artifacts(root, state)
            expected_identity = (
                None
                if current_observation is None
                else (current_observation.device, current_observation.inode)
            )
            published_identity = self._write_atomic(
                root,
                state,
                expected_state_identity=expected_identity,
                expected_generation=expected_generation,
                expected_current=expected_current,
                commit_witness=commit_witness,
                current_state_use=_CurrentStateUse.ORDINARY_AUTHORITY,
            )
            restored = self._read_state(root, required=True)
            if (
                restored is None
                or restored.state != state
                or (restored.device, restored.inode) != published_identity
            ):
                raise ReachyA05RepositoryError("Reachy commissioning state publication mismatch")
            self._require_no_reserved_temporary_state(root)

    def publish_revoked_tombstone(
        self,
        state: ReachyA05RevokedTombstoneV1,
        *,
        expected_current: ReachyA05StateExpectation,
        remote_absence_proof_sha256: str,
    ) -> None:
        """Publish the local tombstone after an attended remover proved remote absence.

        This store verifies and binds the supplied proof commitment; the later attended deploy
        adapter owns the actual remote absence ceremony and must not call this method before it.
        """

        if (
            type(state) is not ReachyA05RevokedTombstoneV1
            or type(expected_current) is not ReachyA05StateExpectation
            or type(remote_absence_proof_sha256) is not str
            or len(remote_absence_proof_sha256) != 64
            or any(character not in "0123456789abcdef" for character in remote_absence_proof_sha256)
        ):
            raise ValueError("Reachy revocation inputs are invalid")
        if (
            state.commissioning_id != expected_current.commissioning_id
            or state.state_generation != expected_current.state_generation + 1
            or state.revocation_proof_sha256 != remote_absence_proof_sha256
        ):
            raise ReachyA05RepositoryError("Reachy revocation proof commitment mismatch")
        state_sha256 = hashlib.sha256(canonical_bytes(state)).hexdigest()
        commit_witness = _CommitWitness(
            candidate_generation=state.state_generation,
            candidate_state_sha256=state_sha256,
        )
        with self._locked_root(commit_witness=commit_witness) as root:
            self._require_no_reserved_temporary_state(root)
            current_observation = self._read_state(root, required=True)
            if (
                current_observation is None
                or type(current_observation.state) is not ReachyA05CommissioningStateV1
            ):
                raise ReachyA05RepositoryError("Reachy ordinary lifecycle transition is invalid")
            self._require_cas(
                current_observation,
                expected_generation=expected_current.state_generation,
                expected_current=expected_current,
            )
            self._require_ordinary_transition(current_observation.state, state)
            observed_time = self._current_time()
            self._require_fresh(current_observation.state, now=observed_time)
            self._require_recent_revocation(state, now=observed_time)
            self._require_local_artifacts_absent(root)
            expected_identity = (
                current_observation.device,
                current_observation.inode,
            )
            published_identity = self._write_atomic(
                root,
                state,
                expected_state_identity=expected_identity,
                expected_generation=expected_current.state_generation,
                expected_current=expected_current,
                commit_witness=commit_witness,
                current_state_use=_CurrentStateUse.ORDINARY_AUTHORITY,
            )
            restored = self._read_state(root, required=True)
            if (
                restored is None
                or restored.state != state
                or (restored.device, restored.inode) != published_identity
            ):
                raise ReachyA05RepositoryError("Reachy revocation publication mismatch")
            self._require_no_reserved_temporary_state(root)

    def recover_stale_terminal(
        self,
        state: ReachyA05OperatorStateV1,
        *,
        expected_current: ReachyA05StateExpectation,
        matching_recovery_remote_state: ReachyA05RemoteStateV1 | None,
        remote_absence_proof_sha256: str | None = None,
    ) -> None:
        expected_generation = expected_current.state_generation
        if (
            _state_generation(state) != expected_generation + 1
            or _state_commissioning_id(state) != expected_current.commissioning_id
        ):
            raise ReachyA05RepositoryError("Reachy terminal recovery CAS mismatch")
        if type(state) is ReachyA05CommissioningStateV1:
            bound_state = state
            if (
                matching_recovery_remote_state is None
                or bound_state.deployment != matching_recovery_remote_state.deployment
                or bound_state.deployment.status is not ReachyA05StateStatus.REMOVED
                or remote_absence_proof_sha256 is not None
            ):
                raise ReachyA05RepositoryError("Reachy terminal recovery evidence differs")
            self._require_fixed_local_paths(bound_state)
        else:
            revoked_state = cast(ReachyA05RevokedTombstoneV1, state)
            if (
                matching_recovery_remote_state is not None
                or type(remote_absence_proof_sha256) is not str
                or remote_absence_proof_sha256 != revoked_state.revocation_proof_sha256
            ):
                raise ReachyA05RepositoryError("Reachy terminal recovery evidence differs")
        state_sha256 = hashlib.sha256(canonical_bytes(state)).hexdigest()
        commit_witness = _CommitWitness(
            candidate_generation=_state_generation(state),
            candidate_state_sha256=state_sha256,
        )
        with self._locked_root(commit_witness=commit_witness) as root:
            self._require_no_reserved_temporary_state(root)
            current_observation = self._read_state(root, required=True)
            if current_observation is None:
                raise AssertionError("required terminal recovery state is absent")
            if type(current_observation.state) is not ReachyA05CommissioningStateV1:
                raise ReachyA05RepositoryError("Reachy terminal recovery transition is invalid")
            current_state = current_observation.state
            self._require_cas(
                current_observation,
                expected_generation=expected_generation,
                expected_current=expected_current,
            )
            observed_time = self._current_time()
            self._require_expired(current_state, now=observed_time)
            self._require_terminal_recovery_transition(current_state, state)
            if type(state) is ReachyA05CommissioningStateV1:
                bound_state = state
                self._require_fresh(bound_state, now=observed_time)
                self._require_bound_artifacts(root, bound_state)
            else:
                self._require_recent_revocation(
                    cast(ReachyA05RevokedTombstoneV1, state), now=observed_time
                )
                self._require_local_artifacts_absent(root)
            expected_identity = (
                current_observation.device,
                current_observation.inode,
            )
            published_identity = self._write_atomic(
                root,
                state,
                expected_state_identity=expected_identity,
                expected_generation=expected_generation,
                expected_current=expected_current,
                commit_witness=commit_witness,
                current_state_use=_CurrentStateUse.EXPIRED_TERMINAL_RECOVERY,
            )
            restored = self._read_state(root, required=True)
            if (
                restored is None
                or restored.state != state
                or (restored.device, restored.inode) != published_identity
            ):
                raise ReachyA05RepositoryError("Reachy terminal recovery publication mismatch")
            self._require_no_reserved_temporary_state(root)

    def reconcile_commit_unknown(
        self,
        uncertainty: ReachyA05CommitUnknown | ReachyA05PostCommitError,
        *,
        candidate: ReachyA05OperatorStateV1,
        expected_current: ReachyA05AnyStateExpectation | None = None,
    ) -> ReachyA05CommitReconciliation:
        candidate_raw = canonical_bytes(candidate)
        candidate_generation = _state_generation(candidate)
        candidate_sha256 = hashlib.sha256(candidate_raw).hexdigest()
        if (
            type(uncertainty) not in {ReachyA05CommitUnknown, ReachyA05PostCommitError}
            or uncertainty.candidate_generation != candidate_generation
            or uncertainty.candidate_state_sha256 != candidate_sha256
        ):
            raise ValueError("commit uncertainty does not match candidate")
        if candidate_generation == 1:
            if expected_current is not None:
                raise ValueError("initial reconciliation must not have a prior expectation")
        elif (
            expected_current is None
            or expected_current.state_generation != candidate_generation - 1
            or expected_current.commissioning_id != _state_commissioning_id(candidate)
        ):
            raise ValueError("update reconciliation requires the exact prior expectation")
        if type(candidate) is ReachyA05CommissioningStateV1:
            self._require_fixed_local_paths(candidate)
        return self._reconcile_exact_candidate(
            candidate=candidate,
            expected_current=expected_current,
            require_candidate_temp=False,
        )

    def recover_exact_candidate_update_temp(
        self,
        *,
        candidate: ReachyA05OperatorStateV1,
        expected_current: ReachyA05AnyStateExpectation,
    ) -> ReachyA05CommitReconciliation:
        """Idempotently remove one verified update temp; this does not publish the candidate."""

        candidate_generation = _state_generation(candidate)
        if (
            candidate_generation <= 1
            or expected_current.state_generation != candidate_generation - 1
            or expected_current.commissioning_id != _state_commissioning_id(candidate)
        ):
            raise ValueError("update temp recovery requires the exact prior expectation")
        if type(candidate) is ReachyA05CommissioningStateV1:
            self._require_fixed_local_paths(candidate)
        return self._reconcile_exact_candidate(
            candidate=candidate,
            expected_current=expected_current,
            require_candidate_temp=True,
        )

    def recover_exact_candidate_initial_temp(
        self,
        *,
        candidate: ReachyA05CommissioningStateV1,
    ) -> ReachyA05CommitReconciliation:
        """Idempotently remove one verified initial temp; this does not publish the candidate."""

        if (
            type(candidate) is not ReachyA05CommissioningStateV1
            or candidate.deployment.state_generation != 1
            or candidate.deployment.status is not ReachyA05StateStatus.COMMISSIONED
        ):
            raise ValueError(
                "initial temp recovery requires a generation-one commissioned candidate"
            )
        self._require_fixed_local_paths(candidate)
        candidate_raw = canonical_bytes(candidate)
        candidate_sha256 = hashlib.sha256(candidate_raw).hexdigest()
        temporary_name = f".operator-state.g1.{candidate_sha256}.tmp"
        with self._locked_root() as root:
            try:
                if self._read_state(root, required=False) is not None:
                    return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
                temporary_names = self._reserved_temporary_names(root)
                if not temporary_names:
                    os.fsync(root.fd)
                    if self._read_state(
                        root, required=False
                    ) is not None or self._reserved_temporary_names(root):
                        return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
                    return ReachyA05CommitReconciliation.NOT_COMMITTED
                if temporary_names != (temporary_name,):
                    return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
                evidence = self._read_named_state(
                    root,
                    name=temporary_name,
                    required=True,
                )
                if evidence is None or evidence.state != candidate:
                    return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
                evidence_identity = (evidence.device, evidence.inode)
                if self._read_state(
                    root, required=False
                ) is not None or self._reserved_temporary_names(root) != (temporary_name,):
                    return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
                os.fsync(root.fd)
                confirmed_evidence = self._read_named_state(
                    root,
                    name=temporary_name,
                    required=True,
                )
                if (
                    confirmed_evidence is None
                    or confirmed_evidence.state != candidate
                    or (confirmed_evidence.device, confirmed_evidence.inode) != evidence_identity
                    or self._read_state(root, required=False) is not None
                    or self._reserved_temporary_names(root) != (temporary_name,)
                ):
                    return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
                os.unlink(temporary_name, dir_fd=root.fd)
                os.fsync(root.fd)
                if self._read_state(
                    root, required=False
                ) is not None or self._reserved_temporary_names(root):
                    return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
            except (PermissionError, ReachyA05RepositoryError, OSError):
                return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
            return ReachyA05CommitReconciliation.NOT_COMMITTED

    def _reconcile_exact_candidate(
        self,
        *,
        candidate: ReachyA05OperatorStateV1,
        expected_current: ReachyA05AnyStateExpectation | None,
        require_candidate_temp: bool,
    ) -> ReachyA05CommitReconciliation:
        candidate_generation = _state_generation(candidate)
        candidate_sha256 = hashlib.sha256(canonical_bytes(candidate)).hexdigest()
        temporary_name = f".operator-state.g{candidate_generation}.{candidate_sha256}.tmp"
        with self._locked_root() as root:
            try:
                observation = self._read_state(root, required=False)
            except (PermissionError, ReachyA05RepositoryError, OSError):
                return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
            if observation is None:
                return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
            if observation.state == candidate:
                try:
                    temporary_names = self._reserved_temporary_names(root)
                    if temporary_names not in {(), (temporary_name,)}:
                        return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
                    if require_candidate_temp:
                        return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
                    os.fsync(root.fd)
                    if temporary_names:
                        if expected_current is None:
                            return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
                        evidence = self._read_named_state(
                            root,
                            name=temporary_name,
                            required=True,
                        )
                        if evidence is None:
                            return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
                        self._require_expectation(evidence.state, expected_current)
                        if self._reserved_temporary_names(root) != (temporary_name,):
                            return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
                        os.unlink(temporary_name, dir_fd=root.fd)
                        os.fsync(root.fd)
                    if self._reserved_temporary_names(root):
                        return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
                except (PermissionError, ReachyA05RepositoryError, OSError):
                    return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
                return ReachyA05CommitReconciliation.COMMITTED
            if expected_current is None:
                return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
            try:
                self._require_expectation(observation.state, expected_current)
                temporary_names = self._reserved_temporary_names(root)
                if not temporary_names:
                    if require_candidate_temp:
                        os.fsync(root.fd)
                        confirmed = self._read_state(root, required=True)
                        if confirmed is None:
                            return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
                        self._require_expectation(confirmed.state, expected_current)
                        if self._reserved_temporary_names(root):
                            return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
                    return ReachyA05CommitReconciliation.NOT_COMMITTED
                if temporary_names != (temporary_name,):
                    return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
                evidence = self._read_named_state(
                    root,
                    name=temporary_name,
                    required=True,
                )
                if evidence is None or evidence.state != candidate:
                    return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
                if self._reserved_temporary_names(root) != (temporary_name,):
                    return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
                os.unlink(temporary_name, dir_fd=root.fd)
                os.fsync(root.fd)
                if self._reserved_temporary_names(root):
                    return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
            except (PermissionError, ReachyA05RepositoryError, OSError):
                return ReachyA05CommitReconciliation.INDETERMINATE_OWNER_RECOVERY
            return ReachyA05CommitReconciliation.NOT_COMMITTED


def _harden_state_schema(schema: dict[str, object]) -> None:
    definitions = schema["$defs"]
    if not isinstance(definitions, dict):
        raise TypeError("generated state schema definitions are not an object")
    runtime = definitions["ReachyA05RuntimeBinding"]
    deployment = definitions["ReachyA05DeploymentBinding"]
    if not isinstance(runtime, dict) or not isinstance(deployment, dict):
        raise TypeError("generated state schema models are not objects")
    runtime["allOf"] = [
        {
            "if": {
                "properties": {"python_abi": {"const": "cp311"}},
                "required": ["python_abi"],
            },
            "then": {
                "properties": {
                    "python_version": {
                        "pattern": r"^3[.]11[.](?:0|[1-9][0-9]{0,2})$",
                        "not": {"pattern": r"[\r\n]"},
                    }
                }
            },
        },
        {
            "if": {
                "properties": {"python_abi": {"const": "cp312"}},
                "required": ["python_abi"],
            },
            "then": {
                "properties": {
                    "python_version": {
                        "pattern": r"^3[.]12[.](?:0|[1-9][0-9]{0,2})$",
                        "not": {"pattern": r"[\r\n]"},
                    }
                }
            },
        },
    ]
    sha256 = {
        "maxLength": 64,
        "minLength": 64,
        "pattern": r"^[0-9a-f]{64}$",
        "type": "string",
    }
    null = {"type": "null"}
    deployment["allOf"] = [
        {
            "if": {
                "properties": {"status": {"const": "staged"}},
                "required": ["status"],
            },
            "then": {
                "properties": {
                    "staged_bundle_sha256": sha256,
                    "active_bundle_sha256": null,
                }
            },
        },
        {
            "if": {
                "properties": {"status": {"const": "active"}},
                "required": ["status"],
            },
            "then": {
                "properties": {
                    "staged_bundle_sha256": null,
                    "active_bundle_sha256": sha256,
                }
            },
        },
        {
            "if": {
                "properties": {"status": {"enum": ["commissioned", "removed"]}},
                "required": ["status"],
            },
            "then": {
                "properties": {
                    "staged_bundle_sha256": null,
                    "active_bundle_sha256": null,
                }
            },
        },
    ]


def _render_schema(schema: dict[str, object], *, schema_id: str) -> bytes:
    _harden_state_schema(schema)
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = schema_id
    schema["description"] = (
        "Structural private-state schema; runtime model parsing is required for freshness, "
        "fixed-path, distinctness, lifecycle, and repository semantics."
    )
    schema["x-tuntun-validation-scope"] = "structural"
    schema["x-tuntun-runtime-semantic-validation-required"] = True
    return (
        json.dumps(
            schema,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def render_operator_state_schema() -> bytes:
    schema = TypeAdapter(ReachyA05OperatorStateV1).json_schema(
        mode="validation",
        ref_template="#/$defs/{model}",
    )
    return _render_schema(
        schema,
        schema_id=_OPERATOR_STATE_SCHEMA_ID,
    )


def render_remote_state_schema() -> bytes:
    schema = ReachyA05RemoteStateV1.model_json_schema(
        mode="validation",
        ref_template="#/$defs/{model}",
    )
    return _render_schema(
        schema,
        schema_id=_REMOTE_STATE_SCHEMA_ID,
    )
