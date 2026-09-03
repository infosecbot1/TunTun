from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import re
import socket
import sys
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any, Literal, Protocol, Self

from pydantic import Field, field_validator, model_validator
from tuntun_contracts.base import (
    ContractModel,
    canonical_mapping_bytes,
    parse_bounded_json_value,
)
from tuntun_contracts.poc.framing import TRANSPORT_AUDIO_FORMAT as TUNTUN_TRANSPORT_AUDIO_FORMAT

from tuntun_edge.config import load_edge_config
from tuntun_edge.reachy.native_media import REACHY_SDK_DECLARED_NATIVE_AUDIO_FORMAT

_STABLE_SEMVER_PATTERN = r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$"
_STABLE_SEMVER_MAX_LENGTH = 32
_PROBE_VERSION = "0.1.0"
_SYNTHETIC_VERSION = "0.0.0"
_REACHY_HARDWARE_FLAG = "TUNTUN_ALLOW_REACHY_HARDWARE"
_RUNTIME_ERROR_MESSAGE = "unsafe Reachy runtime compatibility"
_DAEMON_STATUS_HOST = "127.0.0.1"
_DAEMON_STATUS_PORT = 8000
_DAEMON_STATUS_PATH = "/api/daemon/status"
_DAEMON_STATUS_ENDPOINT = "http://127.0.0.1:8000/api/daemon/status"
_DAEMON_STATUS_REQUEST = (
    b"GET /api/daemon/status HTTP/1.1\r\n"
    b"Host: 127.0.0.1:8000\r\n"
    b"Accept: application/json\r\n"
    b"Connection: close\r\n\r\n"
)
_DAEMON_STATUS_MAX_HEADER_BYTES = 4096
_DAEMON_STATUS_MAX_BODY_BYTES = 256
_DAEMON_STATUS_HEADER_SEPARATOR = b"\r\n\r\n"
_DAEMON_STATUS_JSON_DEPTH = 4
_DAEMON_STATUS_JSON_CONTAINERS = 16
_DAEMON_STATUS_JSON_STRUCTURE_TOKENS = 128
_READ_CHUNK_BYTES = 4096
_PYTHON_EXECUTABLE = "/venvs/apps_venv/bin/python3"
_SELECTED_WHEEL_TAG = "py3-none-any"
_MAX_TARGET_TAGS = 4096
_TARGET_TAG_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_REQUIRED_WEBSOCKETS_VERSION = "15.0.1"
_EXPECTED_RUNTIME_PACKAGE_NAMES = ("python", "reachy-mini", "websockets")
_PACKAGING_DISTRIBUTION = "packaging"
_PACKAGING_MAJOR_VERSION = 26
_PACKAGING_VERSION_PATTERN = re.compile(r"^(0|[1-9]\d*)(?:\.(0|[1-9]\d*))*(?:\.post[0-9]+)?$")
REQUIRED_RUNTIME_IMPORTS = (
    "reachy_mini",
    "websockets",
    "websockets.asyncio.client",
    "numpy",
    "gi",
    "tuntun_contracts",
    "tuntun_edge",
    "tuntun_edge.cli.main",
    "tuntun_edge.transport.commissioning",
)

StableSemver = Annotated[
    str,
    Field(pattern=_STABLE_SEMVER_PATTERN, max_length=_STABLE_SEMVER_MAX_LENGTH),
]
NetworkPort = Annotated[int, Field(ge=1, le=65535)]


class ReachyHardwareNotAllowedError(PermissionError):
    pass


class ReachyHardwareProbeUnavailableError(RuntimeError):
    pass


class ReachyRuntimeCompatibilityError(RuntimeError):
    """The local Reachy runtime is absent, unsupported, or drifted."""


class ReachyRuntimeCompatibilityUnavailable(PermissionError):
    """The local Reachy runtime compatibility boundary is absent or unsafe."""


@dataclass(frozen=True, slots=True)
class LocalRuntimeCompatibility:
    sdk: str
    daemon: str
    python_executable: str
    python_version: str
    python_abi: str
    selected_wheel_tag: str
    target_tag_set_sha256: str
    runtime_inventory_sha256: str


@dataclass(frozen=True, slots=True)
class _ObservedPythonRuntime:
    executable: str
    version: str
    implementation_cache_tag: str
    package_version: str


@dataclass(frozen=True, slots=True)
class _RuntimeInventoryObservation:
    sdk: str
    websockets: str
    sha256: str


@dataclass(frozen=True, slots=True)
class _QualifiedPackagingApis:
    requirement: Callable[[str], Any]
    version: Callable[[str], Any]
    canonicalize_name: Callable[[str], str]
    sys_tags: Callable[[], Iterable[Any]]


class _DaemonVersionReaderPort(Protocol):
    def read_version(self, *, deadline: float, max_bytes: int) -> str: ...


class _RuntimeMetadataReaderPort(Protocol):
    def version(self, distribution_name: str, *, deadline: float) -> str: ...

    def requires(self, distribution_name: str, *, deadline: float) -> tuple[Any, ...]: ...


class _RuntimeImporterPort(Protocol):
    def import_module(self, module_name: str, *, deadline: float) -> object: ...


class _SocketLike(Protocol):
    def settimeout(self, timeout: float) -> None: ...

    def connect(self, address: tuple[str, int]) -> None: ...

    def sendall(self, payload: bytes) -> None: ...

    def recv(self, size: int) -> bytes: ...

    def close(self) -> None: ...


class _SocketFactory(Protocol):
    def __call__(self, family: int, socket_type: int) -> _SocketLike: ...


def _open_tcp_stream_socket(family: int, socket_type: int) -> _SocketLike:
    return socket.socket(family, socket_type)


class _LoopbackDaemonStatusReader:
    __slots__ = ("_socket_factory", "endpoint", "host", "path", "port")

    def __init__(
        self,
        *,
        host: str,
        port: int,
        path: str,
        socket_factory: _SocketFactory = _open_tcp_stream_socket,
    ) -> None:
        self.host = host
        self.port = port
        self.path = path
        self.endpoint = f"http://{host}:{port}{path}"
        self._socket_factory = socket_factory

    @classmethod
    def from_fixed_loopback_daemon_status(cls) -> Self:
        return cls(
            host=_DAEMON_STATUS_HOST,
            port=_DAEMON_STATUS_PORT,
            path=_DAEMON_STATUS_PATH,
        )

    def read_version(
        self,
        *,
        deadline: float,
        max_bytes: int,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> str:
        descriptor: _SocketLike | None = None
        try:
            if (
                self.host != _DAEMON_STATUS_HOST
                or self.port != _DAEMON_STATUS_PORT
                or self.path != _DAEMON_STATUS_PATH
                or self.endpoint != _DAEMON_STATUS_ENDPOINT
                or type(max_bytes) is not int
                or max_bytes != _DAEMON_STATUS_MAX_BODY_BYTES
            ):
                raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
            _require_not_expired(deadline, monotonic=monotonic)
            descriptor = self._socket_factory(socket.AF_INET, socket.SOCK_STREAM)
            descriptor.settimeout(_remaining_timeout(deadline, monotonic=monotonic))
            descriptor.connect((_DAEMON_STATUS_HOST, _DAEMON_STATUS_PORT))
            _require_not_expired(deadline, monotonic=monotonic)
            descriptor.settimeout(_remaining_timeout(deadline, monotonic=monotonic))
            descriptor.sendall(_DAEMON_STATUS_REQUEST)
            raw = _read_daemon_status_response(
                descriptor,
                deadline=deadline,
                max_body_bytes=max_bytes,
                monotonic=monotonic,
            )
            return _daemon_status_version(raw, max_body_bytes=max_bytes)
        except TimeoutError as error:
            if str(error) != _RUNTIME_ERROR_MESSAGE:
                raise TimeoutError(_RUNTIME_ERROR_MESSAGE) from None
            raise
        except (
            ReachyRuntimeCompatibilityError,
            ReachyRuntimeCompatibilityUnavailable,
        ):
            raise
        except Exception:
            raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE) from None
        finally:
            if descriptor is not None:
                primary_failure = sys.exception()
                try:
                    descriptor.close()
                except Exception:
                    if primary_failure is None:
                        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE) from None


class _ImportlibMetadataReader:
    def version(self, distribution_name: str, *, deadline: float) -> str:
        del deadline
        return importlib.metadata.version(distribution_name)

    def requires(self, distribution_name: str, *, deadline: float) -> tuple[str, ...]:
        del deadline
        requirements = importlib.metadata.requires(distribution_name)
        if requirements is None:
            return ()
        return tuple(requirements)


class _ImportlibRuntimeImporter:
    def import_module(self, module_name: str, *, deadline: float) -> object:
        del deadline
        return importlib.import_module(module_name)


def probe_local_runtime_compatibility(
    *,
    timeout_seconds: int,
    network: Literal[False],
) -> LocalRuntimeCompatibility:
    return _probe_local_runtime_compatibility(
        timeout_seconds=timeout_seconds,
        network=network,
        daemon_reader=_LoopbackDaemonStatusReader.from_fixed_loopback_daemon_status(),
        metadata=_ImportlibMetadataReader(),
        importer=_ImportlibRuntimeImporter(),
        observed_runtime=_observe_python_runtime(),
        sys_tags=None,
        monotonic=time.monotonic,
    )


def _probe_local_runtime_compatibility(
    *,
    timeout_seconds: int,
    network: Literal[False],
    daemon_reader: _DaemonVersionReaderPort,
    metadata: _RuntimeMetadataReaderPort,
    importer: _RuntimeImporterPort,
    observed_runtime: _ObservedPythonRuntime,
    sys_tags: Callable[[], Iterable[Any]] | None,
    monotonic: Callable[[], float],
) -> LocalRuntimeCompatibility:
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 5 or network is not False:
        raise ValueError(_RUNTIME_ERROR_MESSAGE)
    start = monotonic()
    deadline = start + timeout_seconds
    try:
        _require_not_expired(deadline, monotonic=monotonic)
        observed_abi = _require_observed_python_runtime(observed_runtime)
        packaging_apis = _load_qualified_packaging_apis(
            metadata=metadata,
            deadline=deadline,
            monotonic=monotonic,
        )
        target_tag_set_sha256 = canonical_target_tag_set_sha256(
            packaging_apis.sys_tags() if sys_tags is None else sys_tags()
        )
        _require_not_expired(deadline, monotonic=monotonic)
        runtime_inventory = _probe_required_runtime_inventory(
            deadline=deadline,
            python_package_version=observed_runtime.package_version,
            required_websockets=_REQUIRED_WEBSOCKETS_VERSION,
            metadata=metadata,
            importer=importer,
            packaging_apis=packaging_apis,
            monotonic=monotonic,
        )
        _require_not_expired(deadline, monotonic=monotonic)
        daemon = daemon_reader.read_version(
            deadline=deadline,
            max_bytes=_DAEMON_STATUS_MAX_BODY_BYTES,
        )
        _require_not_expired(deadline, monotonic=monotonic)
        _require_exact_stable_semver(runtime_inventory.sdk)
        _require_exact_stable_semver(daemon)
        return LocalRuntimeCompatibility(
            sdk=runtime_inventory.sdk,
            daemon=daemon,
            python_executable=observed_runtime.executable,
            python_version=observed_runtime.version,
            python_abi=observed_abi,
            selected_wheel_tag=_SELECTED_WHEEL_TAG,
            target_tag_set_sha256=target_tag_set_sha256,
            runtime_inventory_sha256=runtime_inventory.sha256,
        )
    except TimeoutError as error:
        if str(error) != _RUNTIME_ERROR_MESSAGE:
            raise TimeoutError(_RUNTIME_ERROR_MESSAGE) from None
        raise
    except ValueError as error:
        if str(error) != _RUNTIME_ERROR_MESSAGE:
            raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE) from None
        raise
    except (ReachyRuntimeCompatibilityError, ReachyRuntimeCompatibilityUnavailable):
        raise
    except Exception:
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE) from None


def _observe_python_runtime() -> _ObservedPythonRuntime:
    return _ObservedPythonRuntime(
        executable=sys.executable,
        version=f"{sys.version_info.major}.{sys.version_info.minor}",
        implementation_cache_tag=sys.implementation.cache_tag or "",
        package_version=(
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        ),
    )


def canonical_target_tag_set_sha256(tags: Iterable[Any]) -> str:
    tag_names: list[str] = []
    seen_tags: set[str] = set()
    for tag in tags:
        tag_name = str(tag)
        if (
            len(tag_names) >= _MAX_TARGET_TAGS
            or _TARGET_TAG_PATTERN.fullmatch(tag_name) is None
            or tag_name in seen_tags
        ):
            raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
        tag_names.append(tag_name)
        seen_tags.add(tag_name)
    if not tag_names or _SELECTED_WHEEL_TAG not in seen_tags:
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
    return hashlib.sha256(canonical_mapping_bytes({"sys_tags": tuple(tag_names)})).hexdigest()


def probe_required_runtime_inventory_sha256(
    *,
    deadline: float,
    python_package_version: str,
    required_websockets: str,
    metadata: _RuntimeMetadataReaderPort | None = None,
    importer: _RuntimeImporterPort | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> str:
    return _probe_required_runtime_inventory(
        deadline=deadline,
        python_package_version=python_package_version,
        required_websockets=required_websockets,
        metadata=metadata,
        importer=importer,
        monotonic=monotonic,
    ).sha256


def _probe_required_runtime_inventory(
    *,
    deadline: float,
    python_package_version: str,
    required_websockets: str,
    metadata: _RuntimeMetadataReaderPort | None = None,
    importer: _RuntimeImporterPort | None = None,
    packaging_apis: _QualifiedPackagingApis | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> _RuntimeInventoryObservation:
    metadata_reader = _ImportlibMetadataReader() if metadata is None else metadata
    runtime_importer = _ImportlibRuntimeImporter() if importer is None else importer
    qualified_packaging = (
        _load_qualified_packaging_apis(
            metadata=metadata_reader,
            deadline=deadline,
            monotonic=monotonic,
        )
        if packaging_apis is None
        else packaging_apis
    )
    _require_not_expired(deadline, monotonic=monotonic)
    sdk = metadata_reader.version("reachy-mini", deadline=deadline)
    _require_not_expired(deadline, monotonic=monotonic)
    websockets = metadata_reader.version("websockets", deadline=deadline)
    _require_not_expired(deadline, monotonic=monotonic)
    requirements = metadata_reader.requires("reachy-mini", deadline=deadline)
    _require_websockets_constraint(
        requirements,
        installed_websockets=websockets,
        required_websockets=required_websockets,
        packaging_apis=qualified_packaging,
    )
    for module_name in REQUIRED_RUNTIME_IMPORTS:
        _require_not_expired(deadline, monotonic=monotonic)
        runtime_importer.import_module(module_name, deadline=deadline)
        _require_not_expired(deadline, monotonic=monotonic)
    _require_exact_stable_semver(sdk)
    if websockets != required_websockets:
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
    return _RuntimeInventoryObservation(
        sdk=sdk,
        websockets=websockets,
        sha256=_required_runtime_inventory_sha256(
            python_package_version=python_package_version,
            sdk=sdk,
            websockets=websockets,
        ),
    )


def _required_runtime_inventory_sha256(
    *,
    python_package_version: str,
    sdk: str,
    websockets: str,
) -> str:
    packages = (
        {"name": "python", "version": python_package_version},
        {"name": "reachy-mini", "version": sdk},
        {"name": "websockets", "version": websockets},
    )
    if tuple(package["name"] for package in packages) != _EXPECTED_RUNTIME_PACKAGE_NAMES:
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
    return hashlib.sha256(canonical_mapping_bytes({"runtime_packages": packages})).hexdigest()


def _load_qualified_packaging_apis(
    *,
    metadata: _RuntimeMetadataReaderPort,
    deadline: float,
    monotonic: Callable[[], float],
) -> _QualifiedPackagingApis:
    try:
        _require_not_expired(deadline, monotonic=monotonic)
        version = metadata.version(_PACKAGING_DISTRIBUTION, deadline=deadline)
        _require_packaging_support_version(version)
        _require_not_expired(deadline, monotonic=monotonic)
        requirements_module: Any = importlib.import_module("packaging.requirements")
        tags_module: Any = importlib.import_module("packaging.tags")
        utils_module: Any = importlib.import_module("packaging.utils")
        version_module: Any = importlib.import_module("packaging.version")
        requirement = requirements_module.Requirement
        sys_tags = tags_module.sys_tags
        canonicalize_name = utils_module.canonicalize_name
        version_class = version_module.Version
        if not (
            callable(requirement)
            and callable(sys_tags)
            and callable(canonicalize_name)
            and callable(version_class)
        ):
            raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
        return _QualifiedPackagingApis(
            requirement=requirement,
            version=version_class,
            canonicalize_name=canonicalize_name,
            sys_tags=sys_tags,
        )
    except TimeoutError:
        raise
    except ReachyRuntimeCompatibilityError:
        raise
    except Exception:
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE) from None


def _require_packaging_support_version(value: str) -> None:
    if (
        type(value) is not str
        or len(value) > _STABLE_SEMVER_MAX_LENGTH
        or (match := _PACKAGING_VERSION_PATTERN.fullmatch(value)) is None
        or int(match.group(1)) != _PACKAGING_MAJOR_VERSION
    ):
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)


def _require_websockets_constraint(
    requirements: tuple[Any, ...],
    *,
    installed_websockets: str,
    required_websockets: str,
    packaging_apis: _QualifiedPackagingApis,
) -> None:
    if installed_websockets != required_websockets:
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
    try:
        installed = packaging_apis.version(installed_websockets)
        active_constraints: list[Any] = []
        for raw_requirement in requirements:
            requirement = _parse_requirement(raw_requirement, packaging_apis=packaging_apis)
            if packaging_apis.canonicalize_name(requirement.name) != "websockets":
                continue
            if requirement.marker is None or requirement.marker.evaluate():
                active_constraints.append(requirement)
        if len(active_constraints) != 1 or not active_constraints[0].specifier.contains(
            installed,
            prereleases=True,
        ):
            raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
    except ReachyRuntimeCompatibilityError:
        raise
    except Exception:
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE) from None


def _parse_requirement(requirement: Any, *, packaging_apis: _QualifiedPackagingApis) -> Any:
    if isinstance(requirement, str):
        try:
            return packaging_apis.requirement(requirement)
        except Exception:
            raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE) from None
    return requirement


def _require_observed_python_runtime(observed_runtime: _ObservedPythonRuntime) -> str:
    observed_abi = _python_abi(observed_runtime)
    if observed_runtime.executable != _PYTHON_EXECUTABLE or (
        observed_runtime.version,
        observed_abi,
    ) not in {("3.11", "cp311"), ("3.12", "cp312")}:
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
    return observed_abi


def _python_abi(observed_runtime: _ObservedPythonRuntime) -> str:
    values = {"cpython-311": "cp311", "cpython-312": "cp312"}
    try:
        return values[observed_runtime.implementation_cache_tag]
    except KeyError:
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE) from None


def _require_exact_stable_semver(value: str) -> None:
    if (
        type(value) is not str
        or len(value) > _STABLE_SEMVER_MAX_LENGTH
        or re.fullmatch(_STABLE_SEMVER_PATTERN, value) is None
    ):
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)


def _require_not_expired(
    deadline: float, *, monotonic: Callable[[], float] = time.monotonic
) -> None:
    if monotonic() >= deadline:
        raise TimeoutError(_RUNTIME_ERROR_MESSAGE)


def _remaining_timeout(
    deadline: float, *, monotonic: Callable[[], float] = time.monotonic
) -> float:
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise TimeoutError(_RUNTIME_ERROR_MESSAGE)
    return min(remaining, 5.0)


def _read_daemon_status_response(
    descriptor: _SocketLike,
    *,
    deadline: float,
    max_body_bytes: int,
    monotonic: Callable[[], float],
) -> bytes:
    raw = bytearray()
    expected_response_bytes: int | None = None
    while True:
        _require_not_expired(deadline, monotonic=monotonic)
        if expected_response_bytes is None:
            if len(raw) >= _DAEMON_STATUS_MAX_HEADER_BYTES + max_body_bytes:
                raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
            read_size = min(
                _READ_CHUNK_BYTES,
                _DAEMON_STATUS_MAX_HEADER_BYTES + max_body_bytes - len(raw),
            )
        elif len(raw) == expected_response_bytes:
            read_size = 1
        elif len(raw) < expected_response_bytes:
            read_size = min(_READ_CHUNK_BYTES, expected_response_bytes - len(raw))
        else:
            raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
        descriptor.settimeout(_remaining_timeout(deadline, monotonic=monotonic))
        chunk = descriptor.recv(read_size)
        _require_not_expired(deadline, monotonic=monotonic)
        if not chunk:
            if expected_response_bytes is not None and len(raw) == expected_response_bytes:
                return bytes(raw)
            raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
        raw.extend(chunk)
        if expected_response_bytes is not None:
            if len(raw) > expected_response_bytes:
                raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
            continue
        if _DAEMON_STATUS_HEADER_SEPARATOR not in raw:
            if len(raw) > _DAEMON_STATUS_MAX_HEADER_BYTES:
                raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
            continue
        header_block, _separator, _body = bytes(raw).partition(_DAEMON_STATUS_HEADER_SEPARATOR)
        if len(header_block) > _DAEMON_STATUS_MAX_HEADER_BYTES:
            raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
        _status_code, headers = _parse_daemon_status_headers(header_block)
        content_length = _daemon_status_content_length(headers)
        if not 1 <= content_length <= max_body_bytes:
            raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
        expected_response_bytes = (
            len(header_block) + len(_DAEMON_STATUS_HEADER_SEPARATOR) + content_length
        )
        if len(raw) > expected_response_bytes:
            raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)


def _daemon_status_version(raw: bytes, *, max_body_bytes: int) -> str:
    header_block, separator, body = raw.partition(_DAEMON_STATUS_HEADER_SEPARATOR)
    if separator != _DAEMON_STATUS_HEADER_SEPARATOR:
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
    status_code, headers = _parse_daemon_status_headers(header_block)
    if status_code != 200:
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
    content_type = headers.get("content-type")
    if content_type is None or content_type.split(";", 1)[0].strip().lower() != "application/json":
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
    content_length = _daemon_status_content_length(headers)
    if len(body) != content_length or not 1 <= content_length <= max_body_bytes:
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
    value = parse_bounded_json_value(
        body,
        max_bytes=max_body_bytes,
        max_depth=_DAEMON_STATUS_JSON_DEPTH,
        max_containers=_DAEMON_STATUS_JSON_CONTAINERS,
        max_structure_tokens=_DAEMON_STATUS_JSON_STRUCTURE_TOKENS,
    )
    if not isinstance(value, Mapping):
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
    version = value.get("version")
    if type(version) is not str:
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
    _require_exact_stable_semver(version)
    return version


def _parse_daemon_status_headers(header_block: bytes) -> tuple[int, dict[str, str]]:
    try:
        text = header_block.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE) from None
    lines = text.split("\r\n")
    if len(lines) < 2:
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
    status_parts = lines[0].split(" ", 2)
    if (
        len(status_parts) < 2
        or status_parts[0] != "HTTP/1.1"
        or len(status_parts[1]) != 3
        or not status_parts[1].isdigit()
    ):
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
    status_code = int(status_parts[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        normalized = name.lower()
        if (
            separator != ":"
            or not name
            or not value
            or normalized in headers
            or any(not 33 <= ord(character) <= 126 or character == ":" for character in name)
        ):
            raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
        headers[normalized] = value.strip(" \t")
    if "transfer-encoding" in headers:
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
    return status_code, headers


def _daemon_status_content_length(headers: Mapping[str, str]) -> int:
    value = headers.get("content-length")
    if value is None or not value.isdecimal():
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
    try:
        length = int(value)
    except ValueError:
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE) from None
    if str(length) != value:
        raise ReachyRuntimeCompatibilityError(_RUNTIME_ERROR_MESSAGE)
    return length


class ReachyMediaFacts(ContractModel):
    sample_format: Literal["float32_le"] | None = None
    sample_rate_hz: Literal[16000] | None = None
    channels: Literal[2] | None = None
    interleaved: Literal[True] | None = None
    channel_layout: Literal["stereo"] | None = None
    evidence_basis: Literal["sdk_declared", "physical_observed", "unknown"]

    @model_validator(mode="after")
    def require_known_basis_to_carry_exact_native_format(self) -> Self:
        fields = (
            self.sample_format,
            self.sample_rate_hz,
            self.channels,
            self.interleaved,
            self.channel_layout,
        )
        if self.evidence_basis == "unknown":
            if any(value is not None for value in fields):
                raise ValueError("unknown native media evidence cannot carry format facts")
            return self
        if fields != ("float32_le", 16000, 2, True, "stereo"):
            raise ValueError("known native media evidence must match the SDK-declared format")
        return self


class TuntunTransportMediaFacts(ContractModel):
    sample_format: Literal["s16le"]
    sample_rate_hz: Literal[16000]
    channels: Literal[1]
    interleaved: Literal[False]
    channel_layout: Literal["mono"]


class ReachyRtcFacts(ContractModel):
    rtc_available: bool
    unplugged_cold_boot_retained: bool
    real_drift_measurement_days: Annotated[int, Field(ge=0, le=30)]
    max_observed_drift_seconds: Annotated[float, Field(ge=0, le=86_400)] | None
    rtc_qualified: bool

    @model_validator(mode="after")
    def require_consistent_rtc_facts(self) -> Self:
        has_drift_evidence = (
            self.real_drift_measurement_days > 0 or self.max_observed_drift_seconds is not None
        )
        if not self.rtc_available and self.unplugged_cold_boot_retained:
            raise ValueError("RTC cold-boot retention requires RTC availability")
        if has_drift_evidence and (not self.rtc_available or not self.unplugged_cold_boot_retained):
            raise ValueError("RTC drift evidence requires available retained RTC")
        if self.real_drift_measurement_days == 0 and self.max_observed_drift_seconds is not None:
            raise ValueError("RTC drift requires a real measurement interval")
        if self.real_drift_measurement_days > 0 and self.max_observed_drift_seconds is None:
            raise ValueError("RTC drift seconds are required for measured intervals")
        computed = (
            self.rtc_available
            and self.unplugged_cold_boot_retained
            and self.real_drift_measurement_days == 30
            and self.max_observed_drift_seconds is not None
            and self.max_observed_drift_seconds <= 5.0
        )
        if self.rtc_qualified is not computed:
            raise ValueError("RTC qualification must match retained 30-day drift facts")
        return self


class ReachyCapabilityReportV1(ContractModel):
    schema_version: Literal["tuntun.reachy-capability-report.v1"]
    source: Literal["synthetic", "hardware"]
    probe_version: StableSemver
    sdk_version: StableSemver
    daemon_version: StableSemver
    input_rate_hz: Literal[16000]
    input_channels: Literal[1]
    output_rate_hz: Literal[16000]
    output_channels: Literal[1]
    aec_available: bool
    doa_available: bool
    daemon_ports: Annotated[tuple[NetworkPort, ...], Field(min_length=1, max_length=16)]
    secure_key_storage_available: bool
    managed_app_lock_available: bool
    competing_controller_detectable: bool
    stop_during_playback_tested: bool
    rtc_available: bool
    rtc_cold_boot_retains_utc: bool
    rtc_max_drift_seconds_30d: Annotated[float, Field(ge=0, le=86_400)] | None
    rtc_qualified: bool

    @property
    def reachy_sdk_version(self) -> str:
        return self.sdk_version

    @property
    def microphone(self) -> TuntunTransportMediaFacts:
        return _tuntun_transport_media()

    @property
    def speaker(self) -> TuntunTransportMediaFacts:
        return _tuntun_transport_media()

    @property
    def observed_ports(self) -> tuple[int, ...]:
        return self.daemon_ports

    @property
    def rtc(self) -> ReachyRtcFacts:
        return ReachyRtcFacts(
            rtc_available=self.rtc_available,
            unplugged_cold_boot_retained=self.rtc_cold_boot_retains_utc,
            real_drift_measurement_days=30 if self.rtc_max_drift_seconds_30d is not None else 0,
            max_observed_drift_seconds=self.rtc_max_drift_seconds_30d,
            rtc_qualified=self.rtc_qualified,
        )

    @field_validator(
        "input_rate_hz", "input_channels", "output_rate_hz", "output_channels", mode="before"
    )
    @classmethod
    def require_strict_media_integer(cls, value: int) -> int:
        if type(value) is not int:
            raise ValueError("media rate and channel facts must be strict integers")
        return value

    @field_validator("daemon_ports")
    @classmethod
    def require_unique_sorted_ports(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if any(type(port) is not int for port in value):
            raise ValueError("daemon ports must be strict integers")
        if tuple(sorted(value)) != value:
            raise ValueError("daemon ports must be sorted")
        if len(set(value)) != len(value):
            raise ValueError("daemon ports must be unique")
        return value

    @model_validator(mode="after")
    def require_consistent_rtc_facts(self) -> Self:
        if not self.rtc_available and self.rtc_cold_boot_retains_utc:
            raise ValueError("RTC cold-boot retention requires RTC availability")
        if self.rtc_max_drift_seconds_30d is not None and (
            not self.rtc_available or not self.rtc_cold_boot_retains_utc
        ):
            raise ValueError("RTC drift evidence requires available retained RTC")
        computed = (
            self.rtc_available
            and self.rtc_cold_boot_retains_utc
            and self.rtc_max_drift_seconds_30d is not None
            and self.rtc_max_drift_seconds_30d <= 5.0
        )
        if self.rtc_qualified is not computed:
            raise ValueError("RTC qualification must match explicit 30-day facts")
        return self


class CapabilityReport(ContractModel):
    schema_version: Literal["tuntun.reachy-capability-report.v2"]
    source: Literal["synthetic", "hardware"]
    probe_version: StableSemver
    sdk_version: StableSemver
    daemon_version: StableSemver
    native_capture_media: ReachyMediaFacts
    native_playback_media: ReachyMediaFacts
    tuntun_transport_media: TuntunTransportMediaFacts
    aec_available: bool
    doa_available: bool
    daemon_ports: Annotated[tuple[NetworkPort, ...], Field(min_length=1, max_length=16)]
    secure_key_storage_available: bool
    managed_app_lock_available: bool
    competing_controller_detectable: bool
    stop_during_playback_tested: bool
    rtc_available: bool
    rtc_cold_boot_retains_utc: bool
    rtc_max_drift_seconds_30d: Annotated[float, Field(ge=0, le=86_400)] | None
    rtc_qualified: bool

    @property
    def reachy_sdk_version(self) -> str:
        return self.sdk_version

    @property
    def microphone(self) -> ReachyMediaFacts:
        return self.native_capture_media

    @property
    def speaker(self) -> ReachyMediaFacts:
        return self.native_playback_media

    @property
    def observed_ports(self) -> tuple[int, ...]:
        return self.daemon_ports

    @property
    def rtc(self) -> ReachyRtcFacts:
        return ReachyRtcFacts(
            rtc_available=self.rtc_available,
            unplugged_cold_boot_retained=self.rtc_cold_boot_retains_utc,
            real_drift_measurement_days=30 if self.rtc_max_drift_seconds_30d is not None else 0,
            max_observed_drift_seconds=self.rtc_max_drift_seconds_30d,
            rtc_qualified=self.rtc_qualified,
        )

    @field_validator("daemon_ports")
    @classmethod
    def require_unique_sorted_ports(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if any(type(port) is not int for port in value):
            raise ValueError("daemon ports must be strict integers")
        if tuple(sorted(value)) != value:
            raise ValueError("daemon ports must be sorted")
        if len(set(value)) != len(value):
            raise ValueError("daemon ports must be unique")
        return value

    @model_validator(mode="after")
    def require_consistent_sanitized_facts(self) -> Self:
        if self.source == "synthetic" and (
            self.native_capture_media.evidence_basis == "physical_observed"
            or self.native_playback_media.evidence_basis == "physical_observed"
        ):
            raise ValueError("synthetic Reachy reports cannot claim physical media observations")
        if not self.rtc_available and self.rtc_cold_boot_retains_utc:
            raise ValueError("RTC cold-boot retention requires RTC availability")
        if self.rtc_max_drift_seconds_30d is not None and (
            not self.rtc_available or not self.rtc_cold_boot_retains_utc
        ):
            raise ValueError("RTC drift evidence requires available retained RTC")
        computed = (
            self.rtc_available
            and self.rtc_cold_boot_retains_utc
            and self.rtc_max_drift_seconds_30d is not None
            and self.rtc_max_drift_seconds_30d <= 5.0
        )
        if self.rtc_qualified is not computed:
            raise ValueError("RTC qualification must match explicit 30-day facts")
        return self


class ProbeSource(Protocol):
    sdk_version: str
    daemon_version: str
    native_capture_media: ReachyMediaFacts
    native_playback_media: ReachyMediaFacts
    aec_available: bool
    doa_available: bool
    daemon_ports: tuple[int, ...]
    secure_key_storage_available: bool
    managed_app_lock_available: bool
    competing_controller_detectable: bool
    stop_during_playback_tested: bool
    rtc_available: bool
    rtc_cold_boot_retains_utc: bool
    rtc_max_drift_seconds_30d: float | None


ReachyCapabilityEvidenceV1 = ReachyCapabilityReportV1
ReachyCapabilityEvidenceV2 = CapabilityReport


def _sdk_declared_native_media() -> ReachyMediaFacts:
    return ReachyMediaFacts(
        **REACHY_SDK_DECLARED_NATIVE_AUDIO_FORMAT.model_dump(),
        evidence_basis="sdk_declared",
    )


def _tuntun_transport_media() -> TuntunTransportMediaFacts:
    return TuntunTransportMediaFacts.model_validate(TUNTUN_TRANSPORT_AUDIO_FORMAT.model_dump())


def _build_capability_report(
    source: ProbeSource,
    *,
    report_source: Literal["synthetic", "hardware"],
) -> CapabilityReport:
    rtc_qualified = (
        source.rtc_available
        and source.rtc_cold_boot_retains_utc
        and source.rtc_max_drift_seconds_30d is not None
        and source.rtc_max_drift_seconds_30d <= 5.0
    )
    return CapabilityReport.model_validate(
        {
            "schema_version": "tuntun.reachy-capability-report.v2",
            "source": report_source,
            "probe_version": _PROBE_VERSION,
            "sdk_version": source.sdk_version,
            "daemon_version": source.daemon_version,
            "native_capture_media": source.native_capture_media,
            "native_playback_media": source.native_playback_media,
            "tuntun_transport_media": _tuntun_transport_media(),
            "aec_available": source.aec_available,
            "doa_available": source.doa_available,
            "daemon_ports": source.daemon_ports,
            "secure_key_storage_available": source.secure_key_storage_available,
            "managed_app_lock_available": source.managed_app_lock_available,
            "competing_controller_detectable": source.competing_controller_detectable,
            "stop_during_playback_tested": source.stop_during_playback_tested,
            "rtc_available": source.rtc_available,
            "rtc_cold_boot_retains_utc": source.rtc_cold_boot_retains_utc,
            "rtc_max_drift_seconds_30d": source.rtc_max_drift_seconds_30d,
            "rtc_qualified": rtc_qualified,
        }
    )


def probe(source: ProbeSource) -> CapabilityReport:
    return _build_capability_report(source, report_source="hardware")


class _SyntheticProbeSource:
    sdk_version = _SYNTHETIC_VERSION
    daemon_version = _SYNTHETIC_VERSION
    native_capture_media = _sdk_declared_native_media()
    native_playback_media = _sdk_declared_native_media()
    aec_available = False
    doa_available = False
    daemon_ports: tuple[int, ...] = (8000, 8001)
    secure_key_storage_available = False
    managed_app_lock_available = False
    competing_controller_detectable = False
    stop_during_playback_tested = False
    rtc_available = False
    rtc_cold_boot_retains_utc = False
    rtc_max_drift_seconds_30d: float | None = None


def synthetic_reachy_capabilities() -> CapabilityReport:
    return _build_capability_report(_SyntheticProbeSource(), report_source="synthetic")


def probe_reachy_capabilities(
    *,
    mode: Literal["synthetic", "hardware"] = "synthetic",
    environ: Mapping[str, str] | None = None,
) -> CapabilityReport:
    if mode == "synthetic":
        return synthetic_reachy_capabilities()
    if mode == "hardware":
        return probe_reachy_hardware_capabilities(environ=environ)
    raise ValueError("unsupported Reachy capability probe mode")


def _load_reachy_sdk() -> Any:
    try:
        return importlib.import_module("reachy_mini")
    except ImportError as error:
        raise ReachyHardwareProbeUnavailableError("Reachy hardware SDK is unavailable") from error


def probe_reachy_hardware_capabilities(
    *,
    environ: Mapping[str, str] | None = None,
) -> CapabilityReport:
    if not load_edge_config(environ).reachy.allow_hardware:
        raise ReachyHardwareNotAllowedError(
            f"{_REACHY_HARDWARE_FLAG}=1 is required for Reachy hardware probing"
        )
    _load_reachy_sdk()
    raise ReachyHardwareProbeUnavailableError(
        "Reachy hardware capability probing needs the future supervised physical procedure"
    )


__all__ = [
    "CapabilityReport",
    "LocalRuntimeCompatibility",
    "ProbeSource",
    "REACHY_SDK_DECLARED_NATIVE_AUDIO_FORMAT",
    "REQUIRED_RUNTIME_IMPORTS",
    "TUNTUN_TRANSPORT_AUDIO_FORMAT",
    "ReachyCapabilityEvidenceV1",
    "ReachyCapabilityEvidenceV2",
    "ReachyCapabilityReportV1",
    "ReachyHardwareNotAllowedError",
    "ReachyHardwareProbeUnavailableError",
    "ReachyMediaFacts",
    "ReachyRtcFacts",
    "ReachyRuntimeCompatibilityError",
    "ReachyRuntimeCompatibilityUnavailable",
    "TuntunTransportMediaFacts",
    "canonical_target_tag_set_sha256",
    "probe",
    "probe_local_runtime_compatibility",
    "probe_reachy_capabilities",
    "probe_reachy_hardware_capabilities",
    "synthetic_reachy_capabilities",
]
