"""Host-key-pinned OpenSSH stdio bridge for the Reachy A0.5 dispatcher."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import os
import re
import signal
import stat
import subprocess
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from struct import Struct
from typing import Annotated, Any, Final, Literal, Protocol, Self, cast
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from tuntun_contracts.base import (
    ContractModel,
    ContractParseError,
    canonical_bytes,
    canonical_mapping_bytes,
    parse_contract_json,
)
from tuntun_contracts.poc.framing import PttInputMode

from .commissioning import (
    ReachyA05CommissioningRepository,
    ReachyA05CommissioningStateV1,
    ReachyA05RepositoryError,
    ReachyA05SpawnLease,
    ReachyA05StateExpectation,
    ReachyA05StateStatus,
)

SSH_BINARY: Final = "/usr/bin/ssh"
MAX_IDENTITY_FILE_BYTES: Final = 16_384
MAX_KNOWN_HOSTS_BYTES: Final = 65_536
MAX_DISPATCH_REQUEST_BYTES: Final = 65_536
MAX_DISPATCH_RESPONSE_BYTES: Final = 4_096
DISPATCH_PREFIX: Final = Struct(">I")
CLOSED_SSH_ENV: Final = {"LANG": "C", "LC_ALL": "C"}
SSH_IO_TIMEOUT_SECONDS: Final = 5.0
SSH_STDIN_CLOSE_SECONDS: Final = 1.0
SSH_TERM_SECONDS: Final = 1.0
SSH_KILL_SECONDS: Final = 1.0
STDERR_CLASSIFIER_BYTES: Final = 4096
ACCEPTED_HOST_KEY_ALGORITHMS: Final = "ssh-ed25519"
_RFC1918_NETWORKS: Final = tuple(
    IPv4Network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_SHA256_PATTERN: Final = r"^[0-9a-f]{64}$"
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
_READ_CHUNK_BYTES: Final = 8192
_STATUS_RECONCILIATION_NAMESPACE: Final = UUID("7e3f0d4a-6cdd-5ec6-9c87-b9ff11d5a05c")


class SshBridgeErrorCode(StrEnum):
    CLOSED = "closed"
    UNSAFE_STATE = "unsafe_state"
    UNSAFE_ARGV = "unsafe_argv"
    DISPATCH_PROTOCOL = "dispatch_protocol"
    UNCERTAIN_DISPATCH = "uncertain_dispatch"
    PROCESS_FAILED = "process_failed"
    IO_TIMEOUT = "io_timeout"


class SshDispatchReconciliationResult(StrEnum):
    COMMITTED = "committed"
    NOT_COMMITTED = "not_committed"
    INDETERMINATE = "indeterminate"
    NOT_RESUMABLE = "not_resumable"


@dataclass(frozen=True, slots=True)
class SshDispatchReconciliation:
    status_operation_id: UUID
    result: SshDispatchReconciliationResult
    state_generation: int | None = None
    status: ReachyA05StateStatus | None = None


class SshBridgeError(PermissionError):
    """Content-free SSH bridge failure."""

    def __init__(
        self,
        code: SshBridgeErrorCode,
        *,
        reconciliation: SshDispatchReconciliation | None = None,
    ) -> None:
        if type(code) is not SshBridgeErrorCode:
            raise TypeError("invalid SSH bridge error code")
        if reconciliation is not None and type(reconciliation) is not SshDispatchReconciliation:
            raise TypeError("invalid SSH bridge reconciliation result")
        self.code = code
        self.reconciliation = reconciliation
        super().__init__("ssh-bridge-rejected")

    def __repr__(self) -> str:
        return f"SshBridgeError(code={self.code.value!r})"


class DispatchVerb(StrEnum):
    STATUS = "status"
    STAGE = "stage"
    ACTIVATE = "activate"
    RUN_PTT = "run_ptt"
    REMOVE = "remove"
    VERIFY_ABSENT = "verify_absent"


MUTATING_DISPATCH_VERBS: Final = frozenset(
    {
        DispatchVerb.STAGE,
        DispatchVerb.ACTIVATE,
        DispatchVerb.RUN_PTT,
        DispatchVerb.REMOVE,
    }
)


class _ProcessProtocol(Protocol):
    stdin: Any
    stdout: Any
    stderr: Any
    pid: int
    returncode: int | None

    async def wait(self) -> int: ...


ProcessFactory = Callable[..., Awaitable[_ProcessProtocol]]


@dataclass(frozen=True, slots=True)
class FileIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> Self:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            mode=stat.S_IMODE(value.st_mode),
            uid=value.st_uid,
            links=value.st_nlink,
            size=value.st_size,
            modified_ns=value.st_mtime_ns,
            changed_ns=value.st_ctime_ns,
        )


@dataclass(frozen=True, slots=True)
class ValidatedSshTarget:
    host: str
    user: str
    port: int
    identity_file: Path
    known_hosts_file: Path
    identity_config_option: str
    known_hosts_config_option: str
    commissioning_id: UUID
    state_generation: int
    status: ReachyA05StateStatus
    ptt_input_mode: PttInputMode
    boot_identity_sha256: str
    capability_report_sha256: str
    runtime_inventory_sha256: str
    dispatcher_sha256: str
    dispatcher_protocol_version: str
    authorized_key_line_sha256: str
    staged_bundle_sha256: str | None
    active_bundle_sha256: str | None
    identity_file_sha256: str
    known_hosts_file_sha256: str
    identity_file_identity: FileIdentity | None = None
    known_hosts_identity: FileIdentity | None = None


class SshLoopbackContractTarget(BaseModel):
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    user: str
    port: Annotated[int, Field(ge=1024, le=65535)]
    identity_file: Path
    known_hosts_file: Path
    commissioning_id: UUID
    state_generation: Annotated[int, Field(ge=1)]
    file_commitments: Mapping[str, str]

    @property
    def host(self) -> str:
        return "127.0.0.1"

    def to_validated_target(self) -> ValidatedSshTarget:
        identity_raw, identity = _read_absolute_owner_file(
            self.identity_file,
            max_bytes=MAX_IDENTITY_FILE_BYTES,
            expected_mode=0o600,
        )
        known_hosts_raw, known_hosts = _read_absolute_owner_file(
            self.known_hosts_file,
            max_bytes=MAX_KNOWN_HOSTS_BYTES,
            expected_mode=0o600,
        )
        if not hmac.compare_digest(
            hashlib.sha256(identity_raw).hexdigest(),
            self.file_commitments.get("identity_file_sha256", ""),
        ):
            raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)
        if not hmac.compare_digest(
            hashlib.sha256(known_hosts_raw).hexdigest(),
            self.file_commitments.get("known_hosts_file_sha256", ""),
        ):
            raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)
        identity_path = _absolute_lexical_path(self.identity_file)
        known_hosts_path = _absolute_lexical_path(self.known_hosts_file)
        return ValidatedSshTarget(
            host=self.host,
            user=self.user,
            port=self.port,
            identity_file=identity_path,
            known_hosts_file=known_hosts_path,
            identity_config_option=_canonical_ssh_config_path_option(
                keyword="IdentityFile",
                path=identity_path,
            ),
            known_hosts_config_option=_canonical_ssh_config_path_option(
                keyword="UserKnownHostsFile",
                path=known_hosts_path,
            ),
            commissioning_id=self.commissioning_id,
            state_generation=self.state_generation,
            status=ReachyA05StateStatus.ACTIVE,
            ptt_input_mode=PttInputMode.REACHY_LOCAL,
            boot_identity_sha256="0" * 64,
            capability_report_sha256="1" * 64,
            runtime_inventory_sha256="2" * 64,
            dispatcher_sha256="3" * 64,
            dispatcher_protocol_version="tuntun.reachy-a05-dispatcher.v1",
            authorized_key_line_sha256="4" * 64,
            staged_bundle_sha256=None,
            active_bundle_sha256="5" * 64,
            identity_file_sha256=hashlib.sha256(identity_raw).hexdigest(),
            known_hosts_file_sha256=hashlib.sha256(known_hosts_raw).hexdigest(),
            identity_file_identity=identity,
            known_hosts_identity=known_hosts,
        )


class SshDispatcherRequest(ContractModel):
    version: Literal[1]
    operation_id: UUID
    verb: DispatchVerb
    commissioning_id: UUID
    expected_state_generation: Annotated[int, Field(ge=1)]
    payload: dict[str, Any]

    @field_validator("payload")
    @classmethod
    def canonical_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        canonical_mapping_bytes(value)
        return value


class SshDispatcherResponse(ContractModel):
    version: Literal[1]
    operation_id: UUID
    ok: bool
    state_generation: Annotated[int, Field(ge=1)]
    status: Literal["commissioned", "staged", "active", "removed", "revoked"]
    payload: dict[str, Any]

    @field_validator("payload")
    @classmethod
    def canonical_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        canonical_mapping_bytes(value)
        return value

    def to_wire_bytes(self) -> bytes:
        payload = canonical_bytes(self)
        if not 1 <= len(payload) <= MAX_DISPATCH_RESPONSE_BYTES:
            raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
        return DISPATCH_PREFIX.pack(len(payload)) + payload


class SshDispatcherStatusPayload(ContractModel):
    boot_identity_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    capability_report_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    runtime_inventory_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    dispatcher_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    dispatcher_protocol_version: Literal["tuntun.reachy-a05-dispatcher.v1"]
    authorized_key_line_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    staged_bundle_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)] | None
    active_bundle_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)] | None


@dataclass(frozen=True, slots=True, repr=False)
class SshStderrSummary:
    classification: Literal["empty", "present", "truncated"]
    byte_count: int

    def __repr__(self) -> str:
        return (
            f"SshStderrSummary(classification={self.classification!r}, "
            f"byte_count={self.byte_count})"
        )


SSH_OPTION_VALUES: Final = (
    "BatchMode=yes",
    "IdentitiesOnly=yes",
    "{target.identity_config_option}",
    "IdentityAgent=none",
    "StrictHostKeyChecking=yes",
    "{target.known_hosts_config_option}",
    "GlobalKnownHostsFile=/dev/null",
    "UpdateHostKeys=no",
    "VerifyHostKeyDNS=no",
    f"HostKeyAlgorithms={ACCEPTED_HOST_KEY_ALGORITHMS}",
    "PasswordAuthentication=no",
    "KbdInteractiveAuthentication=no",
    "NumberOfPasswordPrompts=0",
    "PreferredAuthentications=publickey",
    "ProxyCommand=none",
    "ProxyJump=none",
    "ClearAllForwardings=yes",
    "ForwardAgent=no",
    "ForwardX11=no",
    "PermitLocalCommand=no",
    "ControlMaster=no",
    "RequestTTY=no",
    "Tunnel=no",
    "ConnectTimeout=5",
    "ServerAliveInterval=2",
    "ServerAliveCountMax=2",
    "TCPKeepAlive=no",
    "LogLevel=ERROR",
)


def build_pinned_ssh_argv(target: ValidatedSshTarget) -> tuple[str, ...]:
    _validate_target_for_argv(target)
    options: list[str] = []
    for option in SSH_OPTION_VALUES:
        value = option.format(target=target)
        if "\x00" in value or "\n" in value or "\r" in value:
            raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)
        options.extend(("-o", value))
    return (
        SSH_BINARY,
        "-4",
        "-T",
        "-F",
        "/dev/null",
        "-p",
        str(target.port),
        *options,
        "--",
        f"{target.user}@{target.host}",
    )


def derive_status_reconciliation_operation_id(
    operation_id: UUID,
    verb: DispatchVerb,
) -> UUID:
    if type(operation_id) is not UUID or type(verb) is not DispatchVerb:
        raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
    if verb is DispatchVerb.STATUS:
        raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
    return uuid5(
        _STATUS_RECONCILIATION_NAMESPACE,
        f"tuntun.reachy-a05.ssh-reconciliation.v1:{verb.value}:{operation_id}",
    )


def derive_verify_absent_reconciliation_operation_id(
    operation_id: UUID,
    verb: DispatchVerb,
    bundle_sha256: str,
) -> UUID:
    if (
        type(operation_id) is not UUID
        or type(verb) is not DispatchVerb
        or not _is_sha256(bundle_sha256)
    ):
        raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
    if verb is not DispatchVerb.REMOVE:
        raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
    return uuid5(
        _STATUS_RECONCILIATION_NAMESPACE,
        (
            "tuntun.reachy-a05.ssh-reconciliation.verify-absent.v1:"
            f"{verb.value}:{operation_id}:{bundle_sha256}"
        ),
    )


def _target_from_spawn_lease(lease: ReachyA05SpawnLease) -> ValidatedSshTarget:
    if type(lease) is not ReachyA05SpawnLease:
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)
    state = lease.revalidate()
    if type(state) is not ReachyA05CommissioningStateV1:
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)
    deployment = state.deployment
    identity_path = _absolute_lexical_path(Path(lease.identity_path))
    known_hosts_path = _absolute_lexical_path(Path(lease.known_hosts_path))
    try:
        status = ReachyA05StateStatus(deployment.status)
    except ValueError:
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE) from None
    return ValidatedSshTarget(
        host=state.reachy_ipv4,
        user=deployment.ssh_principal,
        port=state.ssh_port,
        identity_file=identity_path,
        known_hosts_file=known_hosts_path,
        identity_config_option=lease.identity_config_option,
        known_hosts_config_option=lease.known_hosts_config_option,
        commissioning_id=deployment.commissioning_id,
        state_generation=deployment.state_generation,
        status=status,
        ptt_input_mode=deployment.ptt_input_mode,
        boot_identity_sha256=deployment.boot_identity_sha256,
        capability_report_sha256=deployment.capability_report_sha256,
        runtime_inventory_sha256=deployment.runtime.runtime_inventory_sha256,
        dispatcher_sha256=deployment.dispatcher_sha256,
        dispatcher_protocol_version=deployment.dispatcher_protocol_version,
        authorized_key_line_sha256=deployment.authorized_key_line_sha256,
        staged_bundle_sha256=deployment.staged_bundle_sha256,
        active_bundle_sha256=deployment.active_bundle_sha256,
        identity_file_sha256=state.identity_file_sha256,
        known_hosts_file_sha256=state.known_hosts_file_sha256,
    )


def encode_dispatcher_request(
    *,
    verb: DispatchVerb,
    operation_id: UUID,
    commissioning_id: UUID,
    expected_generation: int,
    payload: Mapping[str, Any],
) -> bytes:
    if type(verb) is not DispatchVerb:
        raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
    request = SshDispatcherRequest(
        version=1,
        operation_id=operation_id,
        verb=verb,
        commissioning_id=commissioning_id,
        expected_state_generation=expected_generation,
        payload=dict(payload),
    )
    body = canonical_bytes(request)
    if not 1 <= len(body) <= MAX_DISPATCH_REQUEST_BYTES:
        raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
    return DISPATCH_PREFIX.pack(len(body)) + body


def _encode_dispatcher_exchange(
    *,
    verb: DispatchVerb,
    operation_id: UUID,
    commissioning_id: UUID,
    expected_generation: int,
    payload: Mapping[str, Any],
    artifact_bytes: bytes = b"",
) -> bytes:
    request = encode_dispatcher_request(
        verb=verb,
        operation_id=operation_id,
        commissioning_id=commissioning_id,
        expected_generation=expected_generation,
        payload=payload,
    )
    return request + _validated_dispatch_artifact_bytes(
        verb=verb,
        payload=payload,
        artifact_bytes=artifact_bytes,
    )


def _validated_dispatch_artifact_bytes(
    *,
    verb: DispatchVerb,
    payload: Mapping[str, Any],
    artifact_bytes: bytes,
) -> bytes:
    if type(artifact_bytes) is not bytes:
        raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
    if verb is not DispatchVerb.STAGE:
        if artifact_bytes:
            raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
        return b""

    artifact_records = payload.get("artifacts")
    if type(artifact_records) is not list:
        raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
    offset = 0
    for record in artifact_records:
        if not isinstance(record, Mapping):
            raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
        size = record.get("size")
        sha256 = record.get("sha256")
        if type(size) is not int or size < 0:
            raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
        if type(sha256) is not str or not _is_sha256(sha256):
            raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
        end = offset + size
        raw = artifact_bytes[offset:end]
        if len(raw) != size:
            raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), sha256):
            raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
        offset = end
    if offset != len(artifact_bytes):
        raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
    return artifact_bytes


def decode_dispatcher_response(
    raw: bytes,
    *,
    operation_id: UUID,
    expected_generation: int,
    verb: DispatchVerb | None = None,
    request_payload: Mapping[str, Any] | None = None,
    accepted_generations: frozenset[int] | None = None,
) -> SshDispatcherResponse:
    if type(raw) is not bytes or len(raw) < DISPATCH_PREFIX.size:
        raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
    (declared_length,) = DISPATCH_PREFIX.unpack(raw[: DISPATCH_PREFIX.size])
    body = raw[DISPATCH_PREFIX.size :]
    if not 1 <= declared_length <= MAX_DISPATCH_RESPONSE_BYTES or declared_length != len(body):
        raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
    try:
        response = parse_contract_json(
            SshDispatcherResponse,
            body,
            max_bytes=MAX_DISPATCH_RESPONSE_BYTES,
            require_canonical=True,
        )
    except ContractParseError as error:
        raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL) from error
    if response.operation_id != operation_id or not response.ok:
        raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
    if accepted_generations is not None:
        if (
            type(accepted_generations) is not frozenset
            or not accepted_generations
            or any(type(value) is not int or value < 1 for value in accepted_generations)
        ):
            raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
        if response.state_generation not in accepted_generations:
            raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
        return response
    if verb is None:
        if response.state_generation != expected_generation:
            raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
        return response
    if request_payload is None or not _response_matches_requested_dispatch(
        verb=verb,
        expected_generation=expected_generation,
        request_payload=request_payload,
        response=response,
    ):
        raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
    return response


def _response_matches_requested_dispatch(
    *,
    verb: DispatchVerb,
    expected_generation: int,
    request_payload: Mapping[str, Any],
    response: SshDispatcherResponse,
) -> bool:
    if type(verb) is not DispatchVerb or type(expected_generation) is not int:
        return False
    if expected_generation < 1 or not isinstance(request_payload, Mapping):
        return False
    if verb is DispatchVerb.STATUS:
        return response.state_generation == expected_generation and not request_payload
    if verb is DispatchVerb.RUN_PTT:
        return (
            response.state_generation == expected_generation
            and response.status == ReachyA05StateStatus.ACTIVE.value
            and response.payload
            == {
                "input_mode": request_payload.get("input_mode"),
                "ready": True,
            }
        )
    if verb is DispatchVerb.VERIFY_ABSENT:
        return response.state_generation == expected_generation and _response_verifies_absent(
            response,
            _payload_sha256(
                request_payload,
                preferred="bundle_sha256",
                fallback="bundle_sha256",
            ),
        )
    if response.state_generation not in {expected_generation, expected_generation + 1}:
        return False
    if verb is DispatchVerb.STAGE:
        return _response_reflects_staged_or_active_bundle(
            response,
            _payload_sha256(
                request_payload,
                preferred="bundle_sha256",
                fallback="staged_bundle_sha256",
            ),
        )
    if verb is DispatchVerb.ACTIVATE:
        return _response_reflects_active_bundle(
            response,
            _payload_sha256(
                request_payload,
                preferred="bundle_sha256",
                fallback="active_bundle_sha256",
            ),
        )
    if verb is DispatchVerb.REMOVE:
        return _response_verifies_absent(
            response,
            _payload_sha256(
                request_payload,
                preferred="bundle_sha256",
                fallback="removed_bundle_sha256",
            ),
        )
    return False


def _response_reflects_staged_or_active_bundle(
    response: SshDispatcherResponse,
    bundle_sha256: str | None,
) -> bool:
    if bundle_sha256 is None or set(response.payload) != {
        "active_bundle_sha256",
        "staged_bundle_sha256",
    }:
        return False
    active_bundle = response.payload.get("active_bundle_sha256")
    staged_bundle = response.payload.get("staged_bundle_sha256")
    if response.status == ReachyA05StateStatus.STAGED.value:
        return active_bundle is None and staged_bundle == bundle_sha256
    if response.status == ReachyA05StateStatus.ACTIVE.value:
        return staged_bundle is None and active_bundle == bundle_sha256
    return False


def _response_reflects_active_bundle(
    response: SshDispatcherResponse,
    bundle_sha256: str | None,
) -> bool:
    return (
        bundle_sha256 is not None
        and response.status == ReachyA05StateStatus.ACTIVE.value
        and set(response.payload) == {"active_bundle_sha256", "staged_bundle_sha256"}
        and response.payload.get("active_bundle_sha256") == bundle_sha256
        and response.payload.get("staged_bundle_sha256") is None
    )


def _response_verifies_absent(
    response: SshDispatcherResponse,
    bundle_sha256: str | None,
) -> bool:
    if (
        bundle_sha256 is None
        or set(response.payload)
        != {"active_bundle_sha256", "staged_bundle_sha256", "verified_absent"}
        or response.payload.get("verified_absent") != bundle_sha256
    ):
        return False
    active_bundle = response.payload.get("active_bundle_sha256")
    staged_bundle = response.payload.get("staged_bundle_sha256")
    if active_bundle == bundle_sha256 or staged_bundle == bundle_sha256:
        return False
    if response.status == ReachyA05StateStatus.REMOVED.value:
        return active_bundle is None and staged_bundle is None
    if response.status == ReachyA05StateStatus.ACTIVE.value:
        return _is_sha256(active_bundle) and staged_bundle is None
    if response.status == ReachyA05StateStatus.STAGED.value:
        return active_bundle is None and _is_sha256(staged_bundle)
    return False


class SshForcedCommandProcess:
    def __init__(
        self,
        *,
        target: ValidatedSshTarget,
        process: _ProcessProtocol,
        process_factory: ProcessFactory | None = None,
        spawn_lease_context: contextlib.AbstractContextManager[ReachyA05SpawnLease] | None = None,
        spawn_lease: ReachyA05SpawnLease | None = None,
    ) -> None:
        self.target = target
        self._process = process
        self._process_factory = process_factory
        self._spawn_lease_context = spawn_lease_context
        self._spawn_lease = spawn_lease
        self._stderr_task: asyncio.Task[SshStderrSummary] | None = asyncio.create_task(
            _drain_stderr(process.stderr)
        )
        self._stderr_summary = SshStderrSummary("empty", 0)
        self._closed = False
        self._stdin_closed = False
        self._close_lock = asyncio.Lock()

    @classmethod
    async def spawn(
        cls,
        repository: ReachyA05CommissioningRepository,
        *,
        expectation: ReachyA05StateExpectation,
        process_factory: ProcessFactory | None = None,
    ) -> Self:
        if (
            type(repository) is not ReachyA05CommissioningRepository
            or type(expectation) is not ReachyA05StateExpectation
        ):
            raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)
        lease_context = repository.acquire_spawn_lease(expectation=expectation)
        entered = False
        try:
            lease = lease_context.__enter__()
            entered = True
            target = _target_from_spawn_lease(lease)
            return await cls._spawn_validated_target(
                target,
                process_factory=process_factory,
                revalidate_files=False,
                spawn_lease_context=lease_context,
                spawn_lease=lease,
            )
        except SshBridgeError as error:
            if entered:
                _exit_spawn_lease_context(lease_context, primary_error=error)
            raise
        except (
            OSError,
            PermissionError,
            ReachyA05RepositoryError,
            RecursionError,
            RuntimeError,
            TypeError,
            ValueError,
            ValidationError,
        ):
            bridge_error = SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)
            if entered:
                _exit_spawn_lease_context(lease_context, primary_error=bridge_error)
            raise bridge_error from None

    @classmethod
    async def spawn_target(
        cls,
        target: ValidatedSshTarget,
        *,
        process_factory: ProcessFactory | None = None,
    ) -> Self:
        return await cls._spawn_validated_target(
            target,
            process_factory=process_factory,
            revalidate_files=True,
            spawn_lease_context=None,
            spawn_lease=None,
        )

    @classmethod
    async def _spawn_validated_target(
        cls,
        target: ValidatedSshTarget,
        *,
        process_factory: ProcessFactory | None,
        revalidate_files: bool,
        spawn_lease_context: contextlib.AbstractContextManager[ReachyA05SpawnLease] | None,
        spawn_lease: ReachyA05SpawnLease | None,
    ) -> Self:
        if revalidate_files:
            _revalidate_target_files_for_spawn(target)
        else:
            _validate_target_for_argv(target)
        argv = build_pinned_ssh_argv(target)
        raw_process: object
        try:
            if process_factory is None:
                raw_process = await asyncio.create_subprocess_exec(
                    *argv,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                    env=CLOSED_SSH_ENV,
                )
            else:
                raw_process = await process_factory(
                    *argv,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                    env=CLOSED_SSH_ENV,
                )
        except (OSError, RuntimeError, ValueError):
            raise SshBridgeError(SshBridgeErrorCode.PROCESS_FAILED) from None
        process = cast(_ProcessProtocol, raw_process)
        return cls(
            target=target,
            process=process,
            process_factory=process_factory,
            spawn_lease_context=spawn_lease_context,
            spawn_lease=spawn_lease,
        )

    @classmethod
    async def spawn_target_for_loopback_contract(
        cls,
        target: SshLoopbackContractTarget,
        *,
        process_factory: ProcessFactory | None = None,
    ) -> Self:
        return await cls.spawn_target(
            target.to_validated_target(),
            process_factory=process_factory,
        )

    @property
    def stderr_summary(self) -> SshStderrSummary:
        task = self._stderr_task
        if task is not None and task.done():
            with contextlib.suppress(asyncio.CancelledError, Exception):
                self._stderr_summary = task.result()
        return self._stderr_summary

    @property
    def returncode(self) -> int | None:
        return self._process.returncode

    async def dispatch(
        self,
        verb: DispatchVerb,
        *,
        operation_id: UUID,
        expected_generation: int,
        payload: Mapping[str, Any],
        artifact_bytes: bytes = b"",
    ) -> SshDispatcherResponse:
        self._require_open()
        wire_request = _encode_dispatcher_exchange(
            verb=verb,
            operation_id=operation_id,
            commissioning_id=self.target.commissioning_id,
            expected_generation=expected_generation,
            payload=payload,
            artifact_bytes=artifact_bytes,
        )
        try:
            return await self._dispatch_wire_request(
                verb,
                wire_request,
                operation_id=operation_id,
                expected_generation=expected_generation,
                request_payload=payload,
            )
        except SshBridgeError as error:
            if verb in MUTATING_DISPATCH_VERBS:
                reconciliation = await self._attempt_status_reconciliation(
                    verb=verb,
                    operation_id=operation_id,
                    expected_generation=expected_generation,
                    payload=payload,
                )
                raise SshBridgeError(
                    SshBridgeErrorCode.UNCERTAIN_DISPATCH,
                    reconciliation=reconciliation,
                ) from error
            raise

    async def _dispatch_once(
        self,
        verb: DispatchVerb,
        *,
        operation_id: UUID,
        expected_generation: int,
        payload: Mapping[str, Any],
        artifact_bytes: bytes = b"",
        accepted_generations: frozenset[int] | None = None,
    ) -> SshDispatcherResponse:
        wire_request = _encode_dispatcher_exchange(
            verb=verb,
            operation_id=operation_id,
            commissioning_id=self.target.commissioning_id,
            expected_generation=expected_generation,
            payload=payload,
            artifact_bytes=artifact_bytes,
        )
        return await self._dispatch_wire_request(
            verb,
            wire_request,
            operation_id=operation_id,
            expected_generation=expected_generation,
            request_payload=payload,
            accepted_generations=accepted_generations,
        )

    async def _dispatch_wire_request(
        self,
        verb: DispatchVerb,
        wire_request: bytes,
        *,
        operation_id: UUID,
        expected_generation: int,
        request_payload: Mapping[str, Any],
        accepted_generations: frozenset[int] | None = None,
    ) -> SshDispatcherResponse:
        await self.write(wire_request)
        if verb is not DispatchVerb.RUN_PTT:
            await self._half_close_stdin_after_dispatch()
        raw = await self.read_dispatcher_response()
        return decode_dispatcher_response(
            raw,
            operation_id=operation_id,
            expected_generation=expected_generation,
            verb=verb,
            request_payload=request_payload,
            accepted_generations=accepted_generations,
        )

    async def write(self, data: bytes) -> None:
        self._require_open()
        if self._stdin_closed:
            raise SshBridgeError(SshBridgeErrorCode.CLOSED)
        if type(data) is not bytes or not data:
            raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
        stdin = self._process.stdin
        if stdin is None:
            raise SshBridgeError(SshBridgeErrorCode.PROCESS_FAILED)
        try:
            stdin.write(data)
            await asyncio.wait_for(stdin.drain(), timeout=SSH_IO_TIMEOUT_SECONDS)
        except (TimeoutError, BrokenPipeError, ConnectionError, OSError, RuntimeError):
            raise SshBridgeError(SshBridgeErrorCode.IO_TIMEOUT) from None

    async def _half_close_stdin_after_dispatch(self) -> None:
        stdin = self._process.stdin
        if stdin is None:
            raise SshBridgeError(SshBridgeErrorCode.PROCESS_FAILED)
        if self._stdin_closed:
            return
        try:
            stdin.close()
            self._stdin_closed = True
            wait_closed = getattr(stdin, "wait_closed", None)
            if wait_closed is not None:
                await asyncio.wait_for(wait_closed(), timeout=SSH_STDIN_CLOSE_SECONDS)
        except (TimeoutError, BrokenPipeError, ConnectionError, OSError, RuntimeError):
            self._stdin_closed = True
            raise SshBridgeError(SshBridgeErrorCode.IO_TIMEOUT) from None

    async def read(self, max_bytes: int) -> bytes:
        self._require_open()
        if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_DISPATCH_REQUEST_BYTES:
            raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
        stdout = self._process.stdout
        if stdout is None:
            raise SshBridgeError(SshBridgeErrorCode.PROCESS_FAILED)
        try:
            raw = await asyncio.wait_for(stdout.read(max_bytes), timeout=SSH_IO_TIMEOUT_SECONDS)
            if type(raw) is not bytes:
                raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
            return raw
        except (TimeoutError, OSError, RuntimeError):
            raise SshBridgeError(SshBridgeErrorCode.IO_TIMEOUT) from None

    async def read_dispatcher_response(self) -> bytes:
        self._require_open()
        stdout = self._process.stdout
        if stdout is None:
            raise SshBridgeError(SshBridgeErrorCode.PROCESS_FAILED)
        try:
            header = await asyncio.wait_for(
                stdout.readexactly(DISPATCH_PREFIX.size),
                timeout=SSH_IO_TIMEOUT_SECONDS,
            )
            if type(header) is not bytes:
                raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
            (declared_length,) = DISPATCH_PREFIX.unpack(header)
            if not 1 <= declared_length <= MAX_DISPATCH_RESPONSE_BYTES:
                raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
            body = await asyncio.wait_for(
                stdout.readexactly(declared_length),
                timeout=SSH_IO_TIMEOUT_SECONDS,
            )
            if type(body) is not bytes:
                raise SshBridgeError(SshBridgeErrorCode.DISPATCH_PROTOCOL)
            return header + body
        except SshBridgeError:
            raise
        except (TimeoutError, asyncio.IncompleteReadError, OSError, RuntimeError):
            raise SshBridgeError(SshBridgeErrorCode.IO_TIMEOUT) from None

    async def close(self) -> None:
        async with self._close_lock:
            if self._closed:
                return
            self._closed = True
            close_error: BaseException | None = None
            try:
                await self._close_stdin_then_process()
            except BaseException as error:
                close_error = error
            finally:
                await self._finish_stderr_drain()
                if self._spawn_lease_context is not None:
                    try:
                        _exit_spawn_lease_context(
                            self._spawn_lease_context,
                            primary_error=close_error,
                        )
                    except SshBridgeError as error:
                        if close_error is None:
                            close_error = error
                        else:
                            close_error.add_note("additional spawn authority cleanup failure")
                    finally:
                        self._spawn_lease_context = None
                        self._spawn_lease = None
            if close_error is not None:
                raise close_error

    def _require_open(self) -> None:
        if self._closed or self._process.returncode is not None:
            raise SshBridgeError(SshBridgeErrorCode.CLOSED)

    async def _attempt_status_reconciliation(
        self,
        *,
        verb: DispatchVerb,
        operation_id: UUID,
        expected_generation: int,
        payload: Mapping[str, Any],
    ) -> SshDispatchReconciliation:
        status_operation_id = derive_status_reconciliation_operation_id(operation_id, verb)
        if verb is DispatchVerb.RUN_PTT:
            fallback_result = SshDispatchReconciliationResult.NOT_RESUMABLE
        else:
            fallback_result = SshDispatchReconciliationResult.INDETERMINATE
        status_process: SshForcedCommandProcess | None = None
        try:
            if self._spawn_lease is not None:
                _target_from_spawn_lease(self._spawn_lease)
            status_process = await type(self)._spawn_validated_target(
                self.target,
                process_factory=self._process_factory,
                revalidate_files=self._spawn_lease is None,
                spawn_lease_context=None,
                spawn_lease=None,
            )
            response = await status_process._dispatch_once(
                DispatchVerb.STATUS,
                operation_id=status_operation_id,
                expected_generation=expected_generation,
                payload={},
                accepted_generations=frozenset({expected_generation, expected_generation + 1}),
            )
            reconciliation = _reconcile_status_response(
                target=self.target,
                verb=verb,
                expected_generation=expected_generation,
                mutating_payload=payload,
                status_operation_id=status_operation_id,
                response=response,
            )
            if verb is DispatchVerb.REMOVE:
                verified_reconciliation = await self._attempt_remove_verify_absent_reconciliation(
                    operation_id=operation_id,
                    status_operation_id=status_operation_id,
                    expected_generation=expected_generation,
                    mutating_payload=payload,
                    status_response=response,
                )
                if verified_reconciliation is not None:
                    return verified_reconciliation
            return reconciliation
        except SshBridgeError:
            return SshDispatchReconciliation(status_operation_id, fallback_result)
        except (
            OSError,
            PermissionError,
            ReachyA05RepositoryError,
            RecursionError,
            RuntimeError,
            TypeError,
            ValueError,
            ValidationError,
        ):
            return SshDispatchReconciliation(status_operation_id, fallback_result)
        finally:
            if status_process is not None:
                with contextlib.suppress(SshBridgeError):
                    await status_process.close()

    async def _attempt_remove_verify_absent_reconciliation(
        self,
        *,
        operation_id: UUID,
        status_operation_id: UUID,
        expected_generation: int,
        mutating_payload: Mapping[str, Any],
        status_response: SshDispatcherResponse,
    ) -> SshDispatchReconciliation | None:
        bundle_sha256 = _payload_sha256(
            mutating_payload,
            preferred="bundle_sha256",
            fallback="removed_bundle_sha256",
        )
        if bundle_sha256 is None:
            return None
        try:
            status = ReachyA05StateStatus(status_response.status)
            status_payload = SshDispatcherStatusPayload.model_validate(status_response.payload)
        except (TypeError, ValueError, ValidationError):
            return None
        if (
            status_response.state_generation not in {expected_generation, expected_generation + 1}
            or not _status_payload_is_self_consistent(status, status_payload)
            or not _status_payload_matches_target_identity(self.target, status_payload)
            or _status_observes_original_target(
                target=self.target,
                response=status_response,
                status=status,
                payload=status_payload,
            )
            or not _status_observes_removed_null_state(
                status=status,
                payload=status_payload,
            )
        ):
            return None

        verify_operation_id = derive_verify_absent_reconciliation_operation_id(
            operation_id,
            DispatchVerb.REMOVE,
            bundle_sha256,
        )
        verify_process: SshForcedCommandProcess | None = None
        try:
            if self._spawn_lease is not None:
                _target_from_spawn_lease(self._spawn_lease)
            verify_process = await type(self)._spawn_validated_target(
                self.target,
                process_factory=self._process_factory,
                revalidate_files=self._spawn_lease is None,
                spawn_lease_context=None,
                spawn_lease=None,
            )
            verify_response = await verify_process._dispatch_once(
                DispatchVerb.VERIFY_ABSENT,
                operation_id=verify_operation_id,
                expected_generation=status_response.state_generation,
                payload={"bundle_sha256": bundle_sha256},
            )
            if _verify_absent_confirms_removed_null_state(
                status_response=status_response,
                verify_response=verify_response,
                bundle_sha256=bundle_sha256,
            ):
                return SshDispatchReconciliation(
                    status_operation_id,
                    SshDispatchReconciliationResult.COMMITTED,
                    state_generation=status_response.state_generation,
                    status=status,
                )
            return SshDispatchReconciliation(
                status_operation_id,
                SshDispatchReconciliationResult.INDETERMINATE,
                state_generation=status_response.state_generation,
                status=status,
            )
        except SshBridgeError:
            return SshDispatchReconciliation(
                status_operation_id,
                SshDispatchReconciliationResult.INDETERMINATE,
                state_generation=status_response.state_generation,
                status=status,
            )
        except (
            OSError,
            PermissionError,
            ReachyA05RepositoryError,
            RecursionError,
            RuntimeError,
            TypeError,
            ValueError,
            ValidationError,
        ):
            return SshDispatchReconciliation(
                status_operation_id,
                SshDispatchReconciliationResult.INDETERMINATE,
                state_generation=status_response.state_generation,
                status=status,
            )
        finally:
            if verify_process is not None:
                with contextlib.suppress(SshBridgeError):
                    await verify_process.close()

    async def _close_stdin_then_process(self) -> None:
        stdin = self._process.stdin
        if stdin is not None and not self._stdin_closed:
            with contextlib.suppress(BrokenPipeError, ConnectionError, OSError, RuntimeError):
                stdin.close()
                self._stdin_closed = True
            wait_closed = getattr(stdin, "wait_closed", None)
            if wait_closed is not None:
                with contextlib.suppress(
                    TimeoutError,
                    BrokenPipeError,
                    ConnectionError,
                    OSError,
                    RuntimeError,
                ):
                    await asyncio.wait_for(wait_closed(), timeout=SSH_STDIN_CLOSE_SECONDS)
        if await _wait_process(self._process, SSH_STDIN_CLOSE_SECONDS):
            return
        if not _validated_process_group_leader(self._process.pid):
            raise SshBridgeError(SshBridgeErrorCode.PROCESS_FAILED)
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(self._process.pid, signal.SIGTERM)
        if await _wait_process(self._process, SSH_TERM_SECONDS):
            return
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(self._process.pid, signal.SIGKILL)
        if not await _wait_process(self._process, SSH_KILL_SECONDS):
            raise SshBridgeError(SshBridgeErrorCode.PROCESS_FAILED)

    async def _finish_stderr_drain(self) -> None:
        task = self._stderr_task
        if task is None:
            return
        try:
            self._stderr_summary = await asyncio.wait_for(task, timeout=SSH_KILL_SECONDS)
        except (TimeoutError, asyncio.CancelledError):
            task.cancel()
            self._stderr_summary = SshStderrSummary("truncated", STDERR_CLASSIFIER_BYTES)
        except Exception:
            self._stderr_summary = SshStderrSummary("present", 1)


def _exit_spawn_lease_context(
    lease_context: contextlib.AbstractContextManager[ReachyA05SpawnLease],
    *,
    primary_error: BaseException | None,
) -> None:
    try:
        suppressed = lease_context.__exit__(
            None if primary_error is None else type(primary_error),
            primary_error,
            None if primary_error is None else primary_error.__traceback__,
        )
    except BaseException:
        if primary_error is not None:
            primary_error.add_note("additional spawn authority cleanup failure")
            return
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE) from None
    if suppressed and primary_error is not None:
        primary_error.add_note("additional spawn authority cleanup failure")


def _reconcile_status_response(
    *,
    target: ValidatedSshTarget,
    verb: DispatchVerb,
    expected_generation: int,
    mutating_payload: Mapping[str, Any],
    status_operation_id: UUID,
    response: SshDispatcherResponse,
) -> SshDispatchReconciliation:
    fallback = (
        SshDispatchReconciliationResult.NOT_RESUMABLE
        if verb is DispatchVerb.RUN_PTT
        else SshDispatchReconciliationResult.INDETERMINATE
    )
    try:
        status = ReachyA05StateStatus(response.status)
        status_payload = SshDispatcherStatusPayload.model_validate(response.payload)
    except (TypeError, ValueError, ValidationError):
        return SshDispatchReconciliation(status_operation_id, fallback)
    if not _status_payload_is_self_consistent(status, status_payload):
        return SshDispatchReconciliation(status_operation_id, fallback)
    if not _status_payload_matches_target_identity(target, status_payload):
        return SshDispatchReconciliation(status_operation_id, fallback)
    if verb is DispatchVerb.RUN_PTT:
        return SshDispatchReconciliation(
            status_operation_id,
            SshDispatchReconciliationResult.NOT_RESUMABLE,
            state_generation=response.state_generation,
            status=status,
        )
    if _status_observes_original_target(
        target=target,
        response=response,
        status=status,
        payload=status_payload,
    ):
        return SshDispatchReconciliation(
            status_operation_id,
            SshDispatchReconciliationResult.NOT_COMMITTED,
            state_generation=response.state_generation,
            status=status,
        )
    if _status_observes_committed_mutation(
        target=target,
        verb=verb,
        expected_generation=expected_generation,
        mutating_payload=mutating_payload,
        response=response,
        status=status,
        payload=status_payload,
    ):
        return SshDispatchReconciliation(
            status_operation_id,
            SshDispatchReconciliationResult.COMMITTED,
            state_generation=response.state_generation,
            status=status,
        )
    return SshDispatchReconciliation(
        status_operation_id,
        SshDispatchReconciliationResult.INDETERMINATE,
        state_generation=response.state_generation,
        status=status,
    )


def _status_payload_is_self_consistent(
    status: ReachyA05StateStatus,
    payload: SshDispatcherStatusPayload,
) -> bool:
    if status is ReachyA05StateStatus.STAGED:
        return payload.staged_bundle_sha256 is not None and payload.active_bundle_sha256 is None
    if status is ReachyA05StateStatus.ACTIVE:
        return payload.staged_bundle_sha256 is None and payload.active_bundle_sha256 is not None
    return payload.staged_bundle_sha256 is None and payload.active_bundle_sha256 is None


def _status_payload_matches_target_identity(
    target: ValidatedSshTarget,
    payload: SshDispatcherStatusPayload,
) -> bool:
    if payload.dispatcher_protocol_version != target.dispatcher_protocol_version:
        return False
    return all(
        hmac.compare_digest(observed, expected)
        for observed, expected in (
            (payload.boot_identity_sha256, target.boot_identity_sha256),
            (payload.capability_report_sha256, target.capability_report_sha256),
            (payload.runtime_inventory_sha256, target.runtime_inventory_sha256),
            (payload.dispatcher_sha256, target.dispatcher_sha256),
            (payload.authorized_key_line_sha256, target.authorized_key_line_sha256),
        )
    )


def _status_observes_removed_null_state(
    *,
    status: ReachyA05StateStatus,
    payload: SshDispatcherStatusPayload,
) -> bool:
    return (
        status is ReachyA05StateStatus.REMOVED
        and payload.staged_bundle_sha256 is None
        and payload.active_bundle_sha256 is None
    )


def _verify_absent_confirms_removed_null_state(
    *,
    status_response: SshDispatcherResponse,
    verify_response: SshDispatcherResponse,
    bundle_sha256: str,
) -> bool:
    return (
        verify_response.state_generation == status_response.state_generation
        and verify_response.status == ReachyA05StateStatus.REMOVED.value
        and _response_verifies_absent(verify_response, bundle_sha256)
        and verify_response.payload.get("active_bundle_sha256") is None
        and verify_response.payload.get("staged_bundle_sha256") is None
    )


def _status_observes_original_target(
    *,
    target: ValidatedSshTarget,
    response: SshDispatcherResponse,
    status: ReachyA05StateStatus,
    payload: SshDispatcherStatusPayload,
) -> bool:
    return (
        response.state_generation == target.state_generation
        and status is target.status
        and payload.staged_bundle_sha256 == target.staged_bundle_sha256
        and payload.active_bundle_sha256 == target.active_bundle_sha256
    )


def _status_observes_committed_mutation(
    *,
    target: ValidatedSshTarget,
    verb: DispatchVerb,
    expected_generation: int,
    mutating_payload: Mapping[str, Any],
    response: SshDispatcherResponse,
    status: ReachyA05StateStatus,
    payload: SshDispatcherStatusPayload,
) -> bool:
    if response.state_generation != expected_generation + 1:
        return False
    if verb is DispatchVerb.STAGE:
        staged_bundle = _payload_sha256(
            mutating_payload,
            preferred="staged_bundle_sha256",
            fallback="bundle_sha256",
        )
        return (
            staged_bundle is not None
            and status is ReachyA05StateStatus.STAGED
            and payload.staged_bundle_sha256 == staged_bundle
            and payload.active_bundle_sha256 is None
        )
    if verb is DispatchVerb.ACTIVATE:
        active_bundle = (
            _payload_sha256(
                mutating_payload,
                preferred="active_bundle_sha256",
                fallback="bundle_sha256",
            )
            or target.staged_bundle_sha256
        )
        return (
            active_bundle is not None
            and status is ReachyA05StateStatus.ACTIVE
            and payload.staged_bundle_sha256 is None
            and payload.active_bundle_sha256 == active_bundle
        )
    if verb is DispatchVerb.REMOVE:
        return False
    return False


def _payload_sha256(
    payload: Mapping[str, Any],
    *,
    preferred: str,
    fallback: str,
) -> str | None:
    for key in (preferred, fallback):
        value = payload.get(key)
        if (
            type(value) is str
            and len(value) == 64
            and all(character in "0123456789abcdef" for character in value)
        ):
            return value
    return None


def _absolute_lexical_path(path: Path) -> Path:
    try:
        raw = os.fspath(path)
    except TypeError as error:
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE) from error
    if (
        type(raw) is not str
        or not raw
        or "\x00" in raw
        or not os.path.isabs(raw)
        or raw.startswith(os.sep * 2)
    ):
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)
    normalized = os.path.normpath(raw)
    if normalized != raw or any(part in {"", ".", ".."} for part in raw.split(os.sep)[1:]):
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)
    return Path(raw)


def _required_flag(name: str) -> int:
    value = getattr(os, name, 0)
    if type(value) is not int or value == 0:
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)
    return value


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | _required_flag("O_CLOEXEC")
        | _required_flag("O_DIRECTORY")
        | _required_flag("O_NOFOLLOW")
    )


def _open_private_directory_ancestry(path: Path) -> int:
    absolute = _absolute_lexical_path(path)
    parts = absolute.parts
    if len(parts) < 2:
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)
    current_fd = os.open(os.sep, _directory_open_flags())
    try:
        _require_safe_ancestor_directory(os.fstat(current_fd))
        for index, component in enumerate(parts[1:], start=1):
            next_fd = os.open(component, _directory_open_flags(), dir_fd=current_fd)
            try:
                component_stat = os.fstat(next_fd)
                if index == len(parts) - 1:
                    _require_private_directory(component_stat)
                else:
                    _require_safe_ancestor_directory(component_stat)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.close(next_fd)
                raise
            with contextlib.suppress(OSError):
                os.close(current_fd)
            current_fd = next_fd
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(current_fd)
        raise
    return current_fd


def _require_safe_ancestor_directory(value: os.stat_result) -> None:
    mode = stat.S_IMODE(value.st_mode)
    is_root_owned_sticky = value.st_uid == 0 and bool(mode & stat.S_ISVTX)
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid not in {0, os.geteuid()}
        or ((mode & 0o022) != 0 and not is_root_owned_sticky)
    ):
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)


def _require_private_directory(value: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != os.geteuid()
        or stat.S_IMODE(value.st_mode) != 0o700
    ):
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)


def _require_owner_regular(
    value: os.stat_result,
    *,
    expected_mode: int,
    max_bytes: int,
    directory_device: int,
    allow_empty: bool = False,
) -> FileIdentity:
    identity = FileIdentity.from_stat(value)
    lower_bound = 0 if allow_empty else 1
    if (
        not stat.S_ISREG(value.st_mode)
        or identity.uid != os.geteuid()
        or identity.mode != expected_mode
        or identity.links != 1
        or identity.device != directory_device
        or not lower_bound <= identity.size <= max_bytes
    ):
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)
    return identity


def _read_owner_file_at(
    directory_fd: int,
    name: str,
    *,
    max_bytes: int,
    expected_mode: int,
) -> tuple[bytes, FileIdentity]:
    descriptor = -1
    try:
        directory_stat = os.fstat(directory_fd)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        identity = _require_owner_regular(
            named,
            expected_mode=expected_mode,
            max_bytes=max_bytes,
            directory_device=directory_stat.st_dev,
        )
        descriptor = os.open(
            name,
            os.O_RDONLY | _required_flag("O_CLOEXEC") | _required_flag("O_NOFOLLOW"),
            dir_fd=directory_fd,
        )
        opened = os.fstat(descriptor)
        if FileIdentity.from_stat(opened) != identity:
            raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)
        raw = _read_exact_regular_file(descriptor, identity.size)
        after = os.fstat(descriptor)
        named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            FileIdentity.from_stat(after) != identity
            or FileIdentity.from_stat(named_after) != identity
        ):
            raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)
        return raw, identity
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)


def _read_absolute_owner_file(
    path: Path,
    *,
    max_bytes: int,
    expected_mode: int,
) -> tuple[bytes, FileIdentity]:
    absolute = _absolute_lexical_path(path)
    parent = absolute.parent
    name = absolute.name
    directory_fd = -1
    try:
        directory_fd = _open_private_directory_ancestry(parent)
        return _read_owner_file_at(
            directory_fd,
            name,
            max_bytes=max_bytes,
            expected_mode=expected_mode,
        )
    finally:
        if directory_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(directory_fd)


def _read_exact_regular_file(descriptor: int, size: int) -> bytes:
    remaining = size
    chunks: list[bytes] = []
    while remaining:
        chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
        if not chunk:
            raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)
    return b"".join(chunks)


def _revalidate_target_files_for_spawn(target: ValidatedSshTarget) -> None:
    _validate_target_for_argv(target)
    if target.identity_file_identity is None or target.known_hosts_identity is None:
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)
    _revalidate_loopback_target_files(target)


def _revalidate_loopback_target_files(target: ValidatedSshTarget) -> None:
    identity_raw, identity = _read_absolute_owner_file(
        target.identity_file,
        max_bytes=MAX_IDENTITY_FILE_BYTES,
        expected_mode=0o600,
    )
    known_hosts_raw, known_hosts = _read_absolute_owner_file(
        target.known_hosts_file,
        max_bytes=MAX_KNOWN_HOSTS_BYTES,
        expected_mode=0o600,
    )
    if identity != target.identity_file_identity or known_hosts != target.known_hosts_identity:
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)
    if not hmac.compare_digest(
        hashlib.sha256(identity_raw).hexdigest(),
        target.identity_file_sha256,
    ):
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)
    if not hmac.compare_digest(
        hashlib.sha256(known_hosts_raw).hexdigest(),
        target.known_hosts_file_sha256,
    ):
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_STATE)


def _validate_target_for_argv(target: ValidatedSshTarget) -> None:
    if type(target) is not ValidatedSshTarget:
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)
    if type(target.commissioning_id) is not UUID or target.state_generation < 1:
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)
    if type(target.status) is not ReachyA05StateStatus:
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)
    if type(target.ptt_input_mode) is not PttInputMode:
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)
    if target.identity_file != _absolute_lexical_path(target.identity_file):
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)
    if target.known_hosts_file != _absolute_lexical_path(target.known_hosts_file):
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)
    if not _safe_ssh_config_path_option(
        target.identity_config_option,
        keyword="IdentityFile",
    ) or not _safe_ssh_config_path_option(
        target.known_hosts_config_option,
        keyword="UserKnownHostsFile",
    ):
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)
    if target.identity_config_option != _canonical_ssh_config_path_option(
        keyword="IdentityFile",
        path=target.identity_file,
    ):
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)
    if target.known_hosts_config_option != _canonical_ssh_config_path_option(
        keyword="UserKnownHostsFile",
        path=target.known_hosts_file,
    ):
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)
    if target.dispatcher_protocol_version != "tuntun.reachy-a05-dispatcher.v1":
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)
    for digest in (
        target.boot_identity_sha256,
        target.capability_report_sha256,
        target.runtime_inventory_sha256,
        target.dispatcher_sha256,
        target.authorized_key_line_sha256,
        target.identity_file_sha256,
        target.known_hosts_file_sha256,
    ):
        if not _is_sha256(digest):
            raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)
    for optional_digest in (target.staged_bundle_sha256, target.active_bundle_sha256):
        if optional_digest is not None and not _is_sha256(optional_digest):
            raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)
    if target.status is ReachyA05StateStatus.STAGED:
        if target.staged_bundle_sha256 is None or target.active_bundle_sha256 is not None:
            raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)
    elif target.status is ReachyA05StateStatus.ACTIVE:
        if target.staged_bundle_sha256 is not None or target.active_bundle_sha256 is None:
            raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)
    elif target.staged_bundle_sha256 is not None or target.active_bundle_sha256 is not None:
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)
    if re.fullmatch(_USERNAME_PATTERN, target.user) is None or target.user == "root":
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)
    if target.host != "127.0.0.1":
        try:
            address = IPv4Address(target.host)
        except ValueError as error:
            raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV) from error
        is_private_reachy_address = any(address in network for network in _RFC1918_NETWORKS)
        if str(address) != target.host or not is_private_reachy_address:
            raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)
        if target.port != 22:
            raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)
    elif not 1024 <= target.port <= 65535:
        raise SshBridgeError(SshBridgeErrorCode.UNSAFE_ARGV)


def _safe_ssh_config_path_option(value: str, *, keyword: str) -> bool:
    prefix = f"{keyword}="
    return (
        type(value) is str
        and value.startswith(prefix)
        and len(value) > len(prefix)
        and "\x00" not in value
        and "\r" not in value
        and "\n" not in value
    )


def _canonical_ssh_config_path_option(*, keyword: str, path: Path) -> str:
    absolute = os.fspath(_absolute_lexical_path(path))
    escaped = absolute.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    return f'{keyword}="{escaped}"'


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


async def _drain_stderr(stderr: Any) -> SshStderrSummary:
    if stderr is None:
        return SshStderrSummary("empty", 0)
    observed = 0
    truncated = False
    while True:
        try:
            chunk = await stderr.read(1024)
        except (OSError, RuntimeError, ValueError):
            if truncated:
                return SshStderrSummary("truncated", STDERR_CLASSIFIER_BYTES)
            return SshStderrSummary("present", max(observed, 1))
        if not chunk:
            break
        if observed >= STDERR_CLASSIFIER_BYTES:
            truncated = True
            continue
        if observed + len(chunk) > STDERR_CLASSIFIER_BYTES:
            observed = STDERR_CLASSIFIER_BYTES
            truncated = True
        else:
            observed += len(chunk)
    if truncated:
        return SshStderrSummary("truncated", STDERR_CLASSIFIER_BYTES)
    if observed:
        return SshStderrSummary("present", observed)
    return SshStderrSummary("empty", 0)


async def _wait_process(process: _ProcessProtocol, timeout: float) -> bool:
    if process.returncode is not None:
        return True
    try:
        await asyncio.wait_for(process.wait(), timeout=timeout)
    except TimeoutError:
        return process.returncode is not None
    except (OSError, RuntimeError):
        return False
    return True


def _validated_process_group_leader(pid: int) -> bool:
    if type(pid) is not int or pid <= 1:
        return False
    try:
        return os.getpgid(pid) == pid
    except (ProcessLookupError, PermissionError, OSError):
        return False
