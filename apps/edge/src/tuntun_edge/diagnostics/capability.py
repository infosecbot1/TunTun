from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import unicodedata
import zlib
from contextlib import suppress
from dataclasses import dataclass, fields
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, field_validator, model_validator
from tuntun_contracts.base import ContractModel, canonical_bytes
from tuntun_contracts.poc.framing import PttInputMode
from tuntun_contracts.python_runtime import (
    CanonicalPythonVersion,
    parse_canonical_python_version,
)
from tuntun_contracts.speech import AudioFormat

Sha256 = Annotated[
    str,
    Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
]
_SYNTACTIC_DOTTED_QUAD_PATTERN = r"^(?:[0-9]{1,3}[.]){3}[0-9]{1,3}$"
_SYNTACTIC_DOTTED_QUAD = re.compile(_SYNTACTIC_DOTTED_QUAD_PATTERN)
_PRIVATE_IDENTIFIER_JSON_SCHEMA = {
    "not": {
        "anyOf": [
            {"pattern": _SYNTACTIC_DOTTED_QUAD_PATTERN},
            {"pattern": r"[.][Ll][Oo][Cc][Aa][Ll]$"},
            {"pattern": (r"(?:^|[-_.+!])[Hh][Oo][Ss][Tt][Nn][Aa][Mm][Ee](?:$|[-_.+!])")},
            {
                "pattern": (
                    r"(?:^|[-_.+!])[Pp][Rr][Ii][Nn][Cc][Ii][Pp][Aa][Ll]"
                    r"(?:$|[-_.+!])"
                )
            },
            {"pattern": r"(?:^|[-_.+!])[Ss][Ee][Rr][Ii][Aa][Ll](?:$|[-_.+!])"},
            {"pattern": r"(?:^|[-_.+!])[Ss][Ss][Ii][Dd](?:$|[-_.+!])"},
            {"pattern": (r"(?:^|[-_.+!])[Uu][Ss][Ee][Rr][Nn][Aa][Mm][Ee](?:$|[-_.+!])")},
            {"pattern": r"[Xx][Nn]--"},
            {"pattern": r"[\r\n]"},
        ]
    }
}
VersionToken = Annotated[
    str,
    Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._+!-]{0,63}$",
        json_schema_extra=_PRIVATE_IDENTIFIER_JSON_SCHEMA,
    ),
]
DistributionName = Annotated[
    str,
    Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$",
        json_schema_extra=_PRIVATE_IDENTIFIER_JSON_SCHEMA,
    ),
]
_MAX_RUNTIME_DEPENDENCIES = 128

_CAPABILITY_SCHEMA_ID = "https://tuntun.local/schemas/evidence/reachy-a05-capability.schema.json"
_PEP503_SEPARATOR = re.compile(r"[-_.]+")
_PRIVATE_COMPONENT = re.compile(
    r"(?:^|[-_.+!])(?:hostname|principal|serial|ssid|username)(?:$|[-_.+!])"
)
_DOTTED_QUAD_LEXEME = re.compile(r"(?<![0-9])(?:[0-9]{1,3}[.]){3}[0-9]{1,3}(?![0-9])")
_LOCAL_NAME_LEXEME = re.compile(r"(?:^|[-_.+!])[a-z0-9-]+[.]local(?:$|[-_.+!])")
_IP_ADDRESS_TEXT_RUN = re.compile(r"[0-9A-Fa-f:.]+")


def _sanitized_public_token(value: str) -> str:
    if _SYNTACTIC_DOTTED_QUAD.fullmatch(value) is not None:
        raise ValueError("token contains an address-like identifier")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("token contains an address")
    lowered = value.casefold()
    if "xn--" in lowered or lowered.endswith(".local") or _PRIVATE_COMPONENT.search(lowered):
        raise ValueError("token contains a private identifier")
    return value


class CheckStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    UNKNOWN = "unknown"


class CapabilityStatus(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class CapabilityOutcome(StrEnum):
    ACCEPTED = "accepted"
    CONDITIONAL_MAC_KEY = "conditional_mac_key"
    REJECTED = "rejected"


class LimitationCode(StrEnum):
    AEC_UNAVAILABLE = "aec_unavailable"
    DOA_UNAVAILABLE = "doa_unavailable"
    LOCAL_INPUT_UNAVAILABLE = "local_input_unavailable"
    RTC_UNQUALIFIED = "rtc_unqualified"


class RejectionReason(StrEnum):
    NETWORK_TOPOLOGY_FAILED = "network_topology_failed"
    DAEMON_UNAVAILABLE = "daemon_unavailable"
    SDK_DAEMON_MISMATCH = "sdk_daemon_mismatch"
    UNSUPPORTED_INTERPRETER = "unsupported_interpreter"
    MEDIA_CAPTURE_FAILED = "media_capture_failed"
    MEDIA_PLAYBACK_FAILED = "media_playback_failed"
    PLAYBACK_STOP_FAILED = "playback_stop_failed"
    MOTION_STOP_UNAVAILABLE = "motion_stop_unavailable"
    CONTROLLER_DETECTION_UNAVAILABLE = "controller_detection_unavailable"
    CONTROLLER_COLLISION = "controller_collision"
    UNSAFE_BIND_SURFACE = "unsafe_bind_surface"
    SSH_BOUNDARY_FAILED = "ssh_boundary_failed"
    RESOURCE_LIMIT_FAILED = "resource_limit_failed"
    REPORT_PRIVACY_FAILED = "report_privacy_failed"


class CapabilityFact(StrEnum):
    AEC = "aec"
    DOA = "doa"
    LOCAL_CAPTURE_INPUT = "local_capture_input"
    LOCAL_STOP_INPUT = "local_stop_input"
    RTC = "rtc"


class UnobservedReason(StrEnum):
    NOT_ATTEMPTED = "not_attempted"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    PERMISSION_DENIED = "permission_denied"
    PROBE_ERROR = "probe_error"


class ObservedEvidence(ContractModel):
    observation: Literal["observed"]


class UnobservedEvidence(ContractModel):
    observation: Literal["unobserved"]
    reason: UnobservedReason


EvidenceObservation = Annotated[
    ObservedEvidence | UnobservedEvidence,
    Field(discriminator="observation"),
]


def _require_evidence_shape(
    evidence: EvidenceObservation,
    values: tuple[object | None, ...],
    *,
    label: str,
) -> bool:
    complete = all(value is not None for value in values)
    empty = all(value is None for value in values)
    if not complete and not empty:
        raise ValueError(f"{label} evidence must be complete or unobserved")
    observed = type(evidence) is ObservedEvidence
    if observed != complete:
        raise ValueError(f"{label} evidence discriminator contradicts its values")
    return observed


class RuntimeDependency(ContractModel):
    distribution: DistributionName
    version: VersionToken
    artifact_sha256: Sha256

    @field_validator("distribution", "version")
    @classmethod
    def sanitized_tokens(cls, value: str) -> str:
        return _sanitized_public_token(value)

    @field_validator("distribution")
    @classmethod
    def normalized_distribution(cls, value: str) -> str:
        if _PEP503_SEPARATOR.sub("-", value).lower() != value:
            raise ValueError("distribution must use its PEP-503 normalized name")
        return value


class RuntimeObservation(ContractModel):
    daemon_evidence: EvidenceObservation
    sdk_evidence: EvidenceObservation
    interpreter_evidence: EvidenceObservation
    sdk_version: VersionToken | None = None
    daemon_version: VersionToken | None = None
    python_version: CanonicalPythonVersion | None = None
    python_abi: (
        Annotated[
            str,
            Field(
                pattern=r"^cp[0-9]{3}$",
                json_schema_extra={"not": {"pattern": r"[\r\n]"}},
            ),
        ]
        | None
    ) = None
    sdk_artifact_sha256: Sha256 | None = None
    daemon_artifact_sha256: Sha256 | None = None
    runtime_inventory_sha256: Sha256 | None = None
    dependencies: (
        Annotated[
            tuple[RuntimeDependency, ...],
            Field(max_length=_MAX_RUNTIME_DEPENDENCIES, json_schema_extra={"uniqueItems": True}),
        ]
        | None
    ) = None
    daemon_available: CheckStatus
    sdk_daemon_match: CheckStatus
    interpreter_supported: CheckStatus

    @field_validator("sdk_version", "daemon_version")
    @classmethod
    def sanitized_versions(cls, value: str | None) -> str | None:
        return None if value is None else _sanitized_public_token(value)

    @model_validator(mode="after")
    def canonical_dependencies(self) -> RuntimeObservation:
        daemon_values = (self.daemon_version, self.daemon_artifact_sha256)
        sdk_values = (
            self.sdk_version,
            self.sdk_artifact_sha256,
            self.runtime_inventory_sha256,
            self.dependencies,
        )
        interpreter_values = (self.python_version, self.python_abi)
        daemon_observed = _require_evidence_shape(
            self.daemon_evidence,
            daemon_values,
            label="daemon",
        )
        sdk_observed = _require_evidence_shape(
            self.sdk_evidence,
            sdk_values,
            label="SDK",
        )
        interpreter_observed = _require_evidence_shape(
            self.interpreter_evidence,
            interpreter_values,
            label="interpreter",
        )
        if self.daemon_available is CheckStatus.PASSED and not daemon_observed:
            raise ValueError("passed daemon check requires exact observed evidence")
        if self.sdk_daemon_match is CheckStatus.PASSED and not (daemon_observed and sdk_observed):
            raise ValueError("passed SDK/daemon check requires exact observed evidence")
        if self.daemon_available is not CheckStatus.PASSED and (
            self.sdk_daemon_match is not CheckStatus.UNKNOWN
        ):
            raise ValueError("SDK/daemon compatibility is unknown without the daemon")
        if self.interpreter_supported is CheckStatus.PASSED and not interpreter_observed:
            raise ValueError("passed interpreter check requires exact observed evidence")
        if self.dependencies is None:
            keys: tuple[tuple[str, str, str], ...] = ()
        else:
            keys = tuple(
                (dependency.distribution, dependency.version, dependency.artifact_sha256)
                for dependency in self.dependencies
            )
        distributions = tuple(key[0] for key in keys)
        if len(distributions) != len(set(distributions)):
            raise ValueError("dependency distributions must be unique")
        if keys != tuple(sorted(keys)):
            raise ValueError("dependencies must use canonical tuple order")
        supported_interpreter = False
        if self.python_version is not None and self.python_abi is not None:
            major, minor, _ = parse_canonical_python_version(self.python_version)
            supported_interpreter = (major, minor, self.python_abi) in {
                (3, 11, "cp311"),
                (3, 12, "cp312"),
            }
        if self.interpreter_supported is CheckStatus.PASSED and not supported_interpreter:
            raise ValueError("passed interpreter check requires a supported Python and ABI pair")
        return self


class MediaObservation(ContractModel):
    native_input_evidence: EvidenceObservation
    native_output_evidence: EvidenceObservation
    native_input_format: AudioFormat | None = None
    native_output_format: AudioFormat | None = None
    microphone_capture: CheckStatus
    speaker_playback: CheckStatus
    camera_frame_observed: CheckStatus
    playback_stop: CheckStatus
    aec: CapabilityStatus
    doa: CapabilityStatus

    @model_validator(mode="after")
    def truthful_observed_formats(self) -> MediaObservation:
        input_observed = _require_evidence_shape(
            self.native_input_evidence,
            (self.native_input_format,),
            label="native input",
        )
        output_observed = _require_evidence_shape(
            self.native_output_evidence,
            (self.native_output_format,),
            label="native output",
        )
        if self.microphone_capture is CheckStatus.PASSED and not input_observed:
            raise ValueError("passed microphone check requires an observed native format")
        if self.speaker_playback is CheckStatus.PASSED and not output_observed:
            raise ValueError("passed speaker check requires an observed native format")
        if self.playback_stop is CheckStatus.PASSED and not output_observed:
            raise ValueError("passed playback-stop check requires an observed native format")
        if not input_observed and (
            self.aec is CapabilityStatus.AVAILABLE or self.doa is CapabilityStatus.AVAILABLE
        ):
            raise ValueError("input-derived capability requires an observed native format")
        return self


class SafetyObservation(ContractModel):
    movement_enumerated: CheckStatus
    motion_stop: CheckStatus
    app_lock: CheckStatus
    controller_detection: CheckStatus
    controller_collision_clear: CheckStatus
    local_capture_input: CapabilityStatus
    local_stop_input: CapabilityStatus


class HostObservation(ContractModel):
    resource_evidence: EvidenceObservation
    network_topology: CheckStatus
    bind_surface: CheckStatus
    ssh_boundary: CheckStatus
    resource_limits: CheckStatus
    report_privacy: Annotated[
        CheckStatus,
        Field(
            description=(
                "Probe hard check for exact known private values and private-value provenance; "
                "the model token checks are lexical guardrails only."
            )
        ),
    ]
    rtc: CapabilityStatus
    logical_cpu_count: Annotated[int, Field(ge=1, le=1_024)] | None = None
    memory_bytes: Annotated[int, Field(ge=1, le=1_099_511_627_776)] | None = None
    temperature_millicelsius: Annotated[int, Field(ge=-100_000, le=200_000)] | None = None

    @model_validator(mode="after")
    def truthful_resource_observation(self) -> HostObservation:
        values = (
            self.logical_cpu_count,
            self.memory_bytes,
            self.temperature_millicelsius,
        )
        observed = _require_evidence_shape(
            self.resource_evidence,
            values,
            label="resource",
        )
        if self.resource_limits is CheckStatus.PASSED and not observed:
            raise ValueError("passed resource check requires exact observed evidence")
        return self


class ReachyCapabilityReportV1(ContractModel):
    schema_version: Literal["tuntun.reachy-a05-capability.v1"]
    observed_at: AwareDatetime
    runtime: RuntimeObservation
    media: MediaObservation
    safety: SafetyObservation
    host: HostObservation


_MAX_RUNTIME_ARTIFACT_BYTES = 67_108_864
_MAX_RUNTIME_ARTIFACT_TOTAL_BYTES = 268_435_456
_COMPOSITION_ROOT_CONSTRUCTOR = object()


class RuntimeVersionSource(StrEnum):
    PACKAGE_METADATA = "package_metadata"
    DAEMON_PROTOCOL = "daemon_protocol"


class RuntimeVersionObservation:
    """Canonical one-line version read from one approved concrete source."""

    __slots__ = ("_source", "_value")

    def __init__(
        self,
        *,
        source: RuntimeVersionSource,
        raw: bytes,
        constructor: object,
    ) -> None:
        if constructor is not _COMPOSITION_ROOT_CONSTRUCTOR:
            raise TypeError("runtime version observations are composition-root-created")
        if type(source) is not RuntimeVersionSource or type(raw) is not bytes:
            raise TypeError("runtime version source is invalid")
        if not raw.endswith(b"\n") or raw.count(b"\n") != 1 or b"\r" in raw:
            raise ValueError("runtime version observation is not canonical")
        try:
            value = raw[:-1].decode("ascii")
        except UnicodeDecodeError:
            raise ValueError("runtime version observation is not ASCII") from None
        RuntimeDependency(
            distribution="observed-runtime",
            version=value,
            artifact_sha256="0" * 64,
        )
        self._source = source
        self._value = value

    @property
    def value(self) -> str:
        return self._value

    @property
    def source(self) -> RuntimeVersionSource:
        return self._source

    def __repr__(self) -> str:
        return "RuntimeVersionObservation(<redacted>)"


class InterpreterVersionObservation:
    """Interpreter version produced from the runtime's numeric version tuple."""

    __slots__ = ("_abi", "_version")

    def __init__(
        self,
        *,
        version: tuple[int, int, int],
        abi: str,
        constructor: object,
    ) -> None:
        if constructor is not _COMPOSITION_ROOT_CONSTRUCTOR:
            raise TypeError("interpreter observations are composition-root-created")
        if (
            type(version) is not tuple
            or len(version) != 3
            or any(type(component) is not int or not 0 <= component <= 999 for component in version)
            or type(abi) is not str
        ):
            raise TypeError("interpreter observation is invalid")
        rendered = ".".join(str(component) for component in version)
        parse_canonical_python_version(rendered)
        if re.fullmatch(r"cp[0-9]{3}", abi) is None or abi != f"cp{version[0]}{version[1]}":
            raise ValueError("interpreter observation ABI is invalid")
        self._version = rendered
        self._abi = abi

    @property
    def version(self) -> str:
        return self._version

    @property
    def abi(self) -> str:
        return self._abi

    def __repr__(self) -> str:
        return "InterpreterVersionObservation(<redacted>)"


class RuntimeArtifactObservation:
    """One composition-root runtime artifact; its digest is never caller-supplied."""

    __slots__ = ("_artifact", "_distribution", "_source", "_version")

    def __init__(
        self,
        *,
        distribution: str,
        version: RuntimeVersionObservation,
        artifact: bytes,
        constructor: object,
    ) -> None:
        if constructor is not _COMPOSITION_ROOT_CONSTRUCTOR:
            raise TypeError("runtime artifacts are composition-root-created")
        if (
            type(distribution) is not str
            or type(version) is not RuntimeVersionObservation
            or type(artifact) is not bytes
            or not 1 <= len(artifact) <= _MAX_RUNTIME_ARTIFACT_BYTES
        ):
            raise ValueError("runtime artifact observation is invalid")
        RuntimeDependency(
            distribution=distribution,
            version=version.value,
            artifact_sha256="0" * 64,
        )
        self._distribution = distribution
        self._source = version.source
        self._version = version.value
        self._artifact = artifact

    @property
    def distribution(self) -> str:
        return self._distribution

    @property
    def version(self) -> str:
        return self._version

    @property
    def artifact(self) -> bytes:
        return self._artifact

    @property
    def source(self) -> RuntimeVersionSource:
        return self._source

    def __repr__(self) -> str:
        return "RuntimeArtifactObservation(<redacted>)"


def _runtime_inventory_sha256(dependencies: tuple[RuntimeDependency, ...]) -> str:
    digest = hashlib.sha256(b"tuntun.runtime-inventory.v1\x00")
    for dependency in dependencies:
        raw = canonical_bytes(dependency)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


class RuntimeObservationBuilder:
    """Build bounded runtime evidence; eventual collectors stream artifact hashes."""

    __slots__ = ("_commitment", "_raw")

    def __init__(
        self,
        *,
        constructor: object,
        daemon_evidence: EvidenceObservation,
        sdk_evidence: EvidenceObservation,
        interpreter_evidence: EvidenceObservation,
        sdk_artifact: RuntimeArtifactObservation | None,
        daemon_artifact: RuntimeArtifactObservation | None,
        interpreter: InterpreterVersionObservation | None,
        dependencies: tuple[RuntimeArtifactObservation, ...] | None,
        daemon_available: CheckStatus,
        sdk_daemon_match: CheckStatus,
        interpreter_supported: CheckStatus,
    ) -> None:
        if constructor is not _COMPOSITION_ROOT_CONSTRUCTOR:
            raise TypeError("runtime builders are composition-root-created")
        if (
            type(daemon_evidence) not in {ObservedEvidence, UnobservedEvidence}
            or type(sdk_evidence) not in {ObservedEvidence, UnobservedEvidence}
            or type(interpreter_evidence) not in {ObservedEvidence, UnobservedEvidence}
            or (sdk_artifact is not None and type(sdk_artifact) is not RuntimeArtifactObservation)
            or (
                daemon_artifact is not None
                and type(daemon_artifact) is not RuntimeArtifactObservation
            )
            or (interpreter is not None and type(interpreter) is not InterpreterVersionObservation)
            or (
                dependencies is not None
                and (
                    type(dependencies) is not tuple
                    or any(type(item) is not RuntimeArtifactObservation for item in dependencies)
                )
            )
        ):
            raise TypeError("runtime observation builder inputs are not trusted typed values")
        if dependencies is not None and len(dependencies) > _MAX_RUNTIME_DEPENDENCIES:
            raise ValueError("runtime dependency count exceeds its contract bound")
        artifact_total_bytes = (
            (0 if sdk_artifact is None else len(sdk_artifact.artifact))
            + (0 if daemon_artifact is None else len(daemon_artifact.artifact))
            + sum(len(item.artifact) for item in dependencies or ())
        )
        if artifact_total_bytes > _MAX_RUNTIME_ARTIFACT_TOTAL_BYTES:
            raise ValueError("runtime aggregate artifact byte bound exceeded")
        if (
            (
                sdk_artifact is not None
                and sdk_artifact.source is not RuntimeVersionSource.PACKAGE_METADATA
            )
            or (
                daemon_artifact is not None
                and daemon_artifact.source is not RuntimeVersionSource.DAEMON_PROTOCOL
            )
            or (
                dependencies is not None
                and any(
                    item.source is not RuntimeVersionSource.PACKAGE_METADATA
                    for item in dependencies
                )
            )
        ):
            raise ValueError("runtime artifact version source does not match its observation role")
        built_dependencies = (
            None
            if dependencies is None
            else tuple(
                RuntimeDependency(
                    distribution=item.distribution,
                    version=item.version,
                    artifact_sha256=hashlib.sha256(item.artifact).hexdigest(),
                )
                for item in dependencies
            )
        )
        observation = RuntimeObservation(
            daemon_evidence=daemon_evidence,
            sdk_evidence=sdk_evidence,
            interpreter_evidence=interpreter_evidence,
            sdk_version=None if sdk_artifact is None else sdk_artifact.version,
            daemon_version=None if daemon_artifact is None else daemon_artifact.version,
            python_version=None if interpreter is None else interpreter.version,
            python_abi=None if interpreter is None else interpreter.abi,
            sdk_artifact_sha256=(
                None if sdk_artifact is None else hashlib.sha256(sdk_artifact.artifact).hexdigest()
            ),
            daemon_artifact_sha256=(
                None
                if daemon_artifact is None
                else hashlib.sha256(daemon_artifact.artifact).hexdigest()
            ),
            runtime_inventory_sha256=(
                None
                if built_dependencies is None
                else _runtime_inventory_sha256(built_dependencies)
            ),
            dependencies=built_dependencies,
            daemon_available=daemon_available,
            sdk_daemon_match=sdk_daemon_match,
            interpreter_supported=interpreter_supported,
        )
        self._raw = canonical_bytes(observation)
        commitment = hashlib.sha256(b"tuntun.runtime-observation-sources.v1\x00")
        artifacts: tuple[tuple[bytes, RuntimeArtifactObservation | None], ...] = (
            (b"sdk", sdk_artifact),
            (b"daemon", daemon_artifact),
        ) + tuple((b"dependency", item) for item in (() if dependencies is None else dependencies))
        for role, artifact in artifacts:
            commitment.update(len(role).to_bytes(2, "big"))
            commitment.update(role)
            if artifact is None:
                commitment.update(b"\x00")
                continue
            commitment.update(b"\x01")
            for value in (
                artifact.source.value.encode("ascii"),
                artifact.distribution.encode("ascii"),
                artifact.version.encode("ascii"),
                hashlib.sha256(artifact.artifact).digest(),
            ):
                commitment.update(len(value).to_bytes(8, "big"))
                commitment.update(value)
        if interpreter is None:
            commitment.update(b"interpreter\x00")
        else:
            commitment.update(b"interpreter\x01")
            for value in (interpreter.version.encode("ascii"), interpreter.abi.encode("ascii")):
                commitment.update(len(value).to_bytes(2, "big"))
                commitment.update(value)
        commitment.update(len(self._raw).to_bytes(8, "big"))
        commitment.update(self._raw)
        self._commitment = commitment.digest()

    @property
    def observation(self) -> RuntimeObservation:
        return RuntimeObservation.model_validate_json(self._raw)


class MediaObservationBuilder:
    __slots__ = ("_commitment", "_raw")

    def __init__(self, observation: MediaObservation, *, constructor: object) -> None:
        if constructor is not _COMPOSITION_ROOT_CONSTRUCTOR:
            raise TypeError("media builders are composition-root-created")
        if type(observation) is not MediaObservation:
            raise TypeError("media builder requires a typed observation")
        self._raw = canonical_bytes(observation)
        self._commitment = hashlib.sha256(b"media\x00" + self._raw).digest()

    @property
    def observation(self) -> MediaObservation:
        return MediaObservation.model_validate_json(self._raw)


class SafetyObservationBuilder:
    __slots__ = ("_commitment", "_raw")

    def __init__(self, observation: SafetyObservation, *, constructor: object) -> None:
        if constructor is not _COMPOSITION_ROOT_CONSTRUCTOR:
            raise TypeError("safety builders are composition-root-created")
        if type(observation) is not SafetyObservation:
            raise TypeError("safety builder requires a typed observation")
        self._raw = canonical_bytes(observation)
        self._commitment = hashlib.sha256(b"safety\x00" + self._raw).digest()

    @property
    def observation(self) -> SafetyObservation:
        return SafetyObservation.model_validate_json(self._raw)


class HostObservationBuilder:
    __slots__ = ("_commitment", "_raw")

    def __init__(self, observation: HostObservation, *, constructor: object) -> None:
        if constructor is not _COMPOSITION_ROOT_CONSTRUCTOR:
            raise TypeError("host builders are composition-root-created")
        if type(observation) is not HostObservation:
            raise TypeError("host builder requires a typed observation")
        self._raw = canonical_bytes(observation)
        self._commitment = hashlib.sha256(b"host\x00" + self._raw).digest()

    @property
    def observation(self) -> HostObservation:
        return HostObservation.model_validate_json(self._raw)


class PrivacyScanRejected(ValueError):
    """Known private material was found in the sanitized capability report."""


class PrivacyScanUnavailable(ValueError):
    """Complete trusted private-value evidence was unavailable."""


_PRIVACY_PROVENANCE = "delivered_reachy_probe_v1"
_MAX_PRIVACY_VALUES_PER_CLASS = 128
_MAX_PRIVACY_TEXT_VALUE_BYTES = 4_096
_MAX_PRIVACY_BINARY_VALUE_BYTES = 8_388_608
_MAX_PRIVACY_TOTAL_VALUES = 256
_MAX_PRIVACY_TOTAL_BYTES = 16_777_216
_MAX_PRIVACY_DERIVED_VALUES = 640
_MIN_PRIVACY_KEY_MATERIAL_BYTES = 16
_MIN_PRIVACY_CONTENT_BUFFER_BYTES = 16
_MAX_PRIVACY_PUBLIC_TEXT_VALUE_BYTES = 64
_MAX_PRIVACY_BINARY_REPRESENTATIONS_PER_VALUE = 10
_MAX_PRIVACY_REPRESENTATION_SOURCES = 2 * _MAX_PRIVACY_DERIVED_VALUES
_MAX_PRIVACY_SCAN_PRIVATE_VALUES = (
    _MAX_PRIVACY_DERIVED_VALUES
    + _MAX_PRIVACY_REPRESENTATION_SOURCES * _MAX_PRIVACY_BINARY_REPRESENTATIONS_PER_VALUE
)
_MAX_PRIVACY_TRANSFORMED_VALUE_BYTES = (
    _MAX_PRIVACY_REPRESENTATION_SOURCES
    * _MAX_PRIVACY_BINARY_REPRESENTATIONS_PER_VALUE
    * _MAX_PRIVACY_PUBLIC_TEXT_VALUE_BYTES
)
_MAX_PRIVACY_REPORT_TEXT_VALUES = 7 + 2 * _MAX_RUNTIME_DEPENDENCIES
_MAX_PRIVACY_SCAN_COMPARISONS = _MAX_PRIVACY_SCAN_PRIVATE_VALUES * _MAX_PRIVACY_REPORT_TEXT_VALUES
_MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES = _MAX_PRIVACY_BINARY_VALUE_BYTES
_MAX_PRIVACY_DECOMPRESSED_TOTAL_BYTES = _MAX_PRIVACY_TOTAL_BYTES
_MAX_PRIVACY_RECOVERED_SEARCH_BYTES = 4 * _MAX_PRIVACY_TOTAL_BYTES
_MAX_PRIVACY_RECOVERED_REPRESENTATION_BYTES = 4 * _MAX_PRIVACY_TOTAL_BYTES
_MAX_PRIVACY_COMPRESSION_LAYERS = 1
_MAX_PRIVACY_RECOVERED_BYTE_VARIANTS = 2
_MAX_PRIVACY_UTF8_REPAIR_VARIANTS = 16
_MAX_PRIVACY_UTF8_REPAIR_BYTES = 65_536
_MAX_PRIVACY_UTF8_REPAIR_DELETIONS = 4
_MAX_PRIVACY_NESTED_SEARCH_BYTES = 8 * _MAX_PRIVACY_TOTAL_BYTES
_MAX_PRIVACY_ZLIB_OFFSET_ATTEMPTS = 3 * _MAX_PRIVACY_PUBLIC_TEXT_VALUE_BYTES // 4
_MAX_PRIVACY_NESTED_DECODE_ATTEMPTS = 4_096
_MAX_PRIVACY_NESTED_DECODED_BYTES = 262_144
_MAX_PRIVACY_NESTED_LEXICAL_VALUE_BYTES = _MAX_PRIVACY_NESTED_DECODED_BYTES
_MAX_PRIVACY_NESTED_RECOVERY_ATTEMPTS = 48
_MAX_PRIVACY_NESTED_RECOVERY_BYTES = _MAX_PRIVACY_TOTAL_BYTES
_MIN_PRIVACY_FDICT_FRAME_BYTES = 12
_PRIVACY_DECOMPRESSION_STEP_BYTES = 4_096
_PRIVACY_STRUCTURAL_DICTIONARY = bytes(32_768)
_MIN_PRIVACY_SUBSTRING_TEXT_CHARACTERS = 4
_TRUSTED_CAPTURE_CONSTRUCTOR = object()
_PROBED_CAPABILITY_CONSTRUCTOR = object()


class PrivacyEvidenceClass(StrEnum):
    HOSTNAME = "hostname"
    FQDN = "fqdn"
    IP_ADDRESS = "ip_address"
    MAC_ADDRESS = "mac_address"
    PRINCIPAL = "principal"
    HOME_PATH = "home_path"
    SERIAL = "serial"
    SSID = "ssid"
    KEY_MATERIAL = "key_material"
    FINGERPRINT = "fingerprint"
    CONTENT_BUFFER = "content_buffer"


class PrivacyAcquisitionSource(StrEnum):
    SOCKET_IDENTITY = "socket_identity"
    NETWORK_INTERFACES = "network_interfaces"
    LOGIN_ACCOUNT = "login_account"
    DEVICE_METADATA = "device_metadata"
    NETWORK_CONFIGURATION = "network_configuration"
    COMMISSIONING_CREDENTIALS = "commissioning_credentials"
    BOUNDED_PROBE_BUFFERS = "bounded_probe_buffers"


class PrivacyCollectionStatus(StrEnum):
    COMPLETE_WITH_VALUES = "complete_with_values"
    COMPLETE_EMPTY = "complete_empty"
    NOT_ACCESSED = "not_accessed"
    NOT_APPLICABLE = "not_applicable"
    PARTIAL = "partial"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class PrivacyEvidenceCoverage:
    evidence_class: PrivacyEvidenceClass
    acquisition_source: PrivacyAcquisitionSource
    status: PrivacyCollectionStatus

    def __post_init__(self) -> None:
        if (
            type(self.evidence_class) is not PrivacyEvidenceClass
            or type(self.acquisition_source) is not PrivacyAcquisitionSource
            or type(self.status) is not PrivacyCollectionStatus
        ):
            raise ValueError("privacy evidence coverage is invalid")


_PRIVACY_COVERAGE = (
    (PrivacyEvidenceClass.HOSTNAME, PrivacyAcquisitionSource.SOCKET_IDENTITY, "hostnames"),
    (PrivacyEvidenceClass.FQDN, PrivacyAcquisitionSource.SOCKET_IDENTITY, "fqdns"),
    (
        PrivacyEvidenceClass.IP_ADDRESS,
        PrivacyAcquisitionSource.NETWORK_INTERFACES,
        "ip_addresses",
    ),
    (
        PrivacyEvidenceClass.MAC_ADDRESS,
        PrivacyAcquisitionSource.NETWORK_INTERFACES,
        "mac_addresses",
    ),
    (PrivacyEvidenceClass.PRINCIPAL, PrivacyAcquisitionSource.LOGIN_ACCOUNT, "principals"),
    (PrivacyEvidenceClass.HOME_PATH, PrivacyAcquisitionSource.LOGIN_ACCOUNT, "home_paths"),
    (PrivacyEvidenceClass.SERIAL, PrivacyAcquisitionSource.DEVICE_METADATA, "serials"),
    (PrivacyEvidenceClass.SSID, PrivacyAcquisitionSource.NETWORK_CONFIGURATION, "ssids"),
    (
        PrivacyEvidenceClass.KEY_MATERIAL,
        PrivacyAcquisitionSource.COMMISSIONING_CREDENTIALS,
        "key_material",
    ),
    (
        PrivacyEvidenceClass.FINGERPRINT,
        PrivacyAcquisitionSource.COMMISSIONING_CREDENTIALS,
        "fingerprints",
    ),
    (
        PrivacyEvidenceClass.CONTENT_BUFFER,
        PrivacyAcquisitionSource.BOUNDED_PROBE_BUFFERS,
        "content_buffers",
    ),
)


@dataclass(frozen=True, slots=True, repr=False)
class PrivacyScanEvidence:
    """Complete private acquisition snapshot supplied by the trusted probe producer."""

    provenance: str
    coverage: tuple[PrivacyEvidenceCoverage, ...]
    hostnames: tuple[str, ...]
    fqdns: tuple[str, ...]
    ip_addresses: tuple[str, ...]
    mac_addresses: tuple[str, ...]
    principals: tuple[str, ...]
    home_paths: tuple[str, ...]
    serials: tuple[str, ...]
    ssids: tuple[str, ...]
    key_material: tuple[bytes, ...]
    fingerprints: tuple[str, ...]
    content_buffers: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if type(self.provenance) is not str or self.provenance != _PRIVACY_PROVENANCE:
            raise ValueError("privacy evidence provenance is unavailable")
        if type(self.coverage) is not tuple or tuple(
            (item.evidence_class, item.acquisition_source)
            for item in self.coverage
            if type(item) is PrivacyEvidenceCoverage
        ) != tuple((private_class, source) for private_class, source, _ in _PRIVACY_COVERAGE):
            raise ValueError("privacy evidence source coverage is incomplete")
        total_values = 0
        total_bytes = 0
        derived_values = 0
        for field in fields(self):
            if field.name in {"provenance", "coverage"}:
                continue
            values = getattr(self, field.name)
            if type(values) is not tuple or len(values) > _MAX_PRIVACY_VALUES_PER_CLASS:
                raise ValueError("privacy evidence class is incomplete")
            total_values += len(values)
            derived_values += len(values)
            if field.name == "ip_addresses":
                derived_values += 6 * len(values)
            elif field.name == "mac_addresses":
                derived_values += 9 * len(values)
            if (
                total_values > _MAX_PRIVACY_TOTAL_VALUES
                or derived_values > _MAX_PRIVACY_DERIVED_VALUES
            ):
                raise ValueError("privacy evidence aggregate bound exceeded")
            expected_type = bytes if field.name in {"key_material", "content_buffers"} else str
            maximum = (
                _MAX_PRIVACY_BINARY_VALUE_BYTES
                if expected_type is bytes
                else _MAX_PRIVACY_TEXT_VALUE_BYTES
            )
            for value in values:
                if type(value) is not expected_type or not value:
                    raise ValueError("privacy evidence value is invalid")
                value_size = len(value if isinstance(value, bytes) else value.encode("utf-8"))
                minimum = (
                    _MIN_PRIVACY_KEY_MATERIAL_BYTES
                    if field.name == "key_material"
                    else (
                        _MIN_PRIVACY_CONTENT_BUFFER_BYTES if field.name == "content_buffers" else 1
                    )
                )
                if value_size < minimum:
                    raise ValueError("privacy evidence value is below its class minimum")
                if value_size > maximum:
                    raise ValueError("privacy evidence value is invalid")
                total_bytes += value_size
                if total_bytes > _MAX_PRIVACY_TOTAL_BYTES:
                    raise ValueError("privacy evidence aggregate bound exceeded")
            if len(values) != len(set(values)):
                raise ValueError("privacy evidence values must be unique")
        for item, (_, _, value_field) in zip(self.coverage, _PRIVACY_COVERAGE, strict=True):
            values = getattr(self, value_field)
            if item.status is PrivacyCollectionStatus.COMPLETE_WITH_VALUES and not values:
                raise ValueError("privacy coverage contradicts an empty value class")
            if item.status is PrivacyCollectionStatus.COMPLETE_EMPTY and values:
                raise ValueError("privacy coverage contradicts an observed value class")

    def __repr__(self) -> str:
        return "PrivacyScanEvidence(<redacted>)"


def _clone_privacy_evidence(evidence: PrivacyScanEvidence) -> PrivacyScanEvidence:
    if type(evidence) is not PrivacyScanEvidence:
        raise TypeError("privacy evidence builder requires a typed snapshot")
    return PrivacyScanEvidence(
        provenance=evidence.provenance,
        coverage=tuple(
            PrivacyEvidenceCoverage(
                evidence_class=item.evidence_class,
                acquisition_source=item.acquisition_source,
                status=item.status,
            )
            for item in evidence.coverage
        ),
        hostnames=tuple(evidence.hostnames),
        fqdns=tuple(evidence.fqdns),
        ip_addresses=tuple(evidence.ip_addresses),
        mac_addresses=tuple(evidence.mac_addresses),
        principals=tuple(evidence.principals),
        home_paths=tuple(evidence.home_paths),
        serials=tuple(evidence.serials),
        ssids=tuple(evidence.ssids),
        key_material=tuple(bytes(value) for value in evidence.key_material),
        fingerprints=tuple(evidence.fingerprints),
        content_buffers=tuple(bytes(value) for value in evidence.content_buffers),
    )


def _privacy_evidence_commitment(evidence: PrivacyScanEvidence) -> bytes:
    digest = hashlib.sha256(b"tuntun.privacy-evidence.v1\x00")
    provenance = evidence.provenance.encode("ascii")
    digest.update(len(provenance).to_bytes(2, "big"))
    digest.update(provenance)
    for item in evidence.coverage:
        for value in (
            item.evidence_class.value,
            item.acquisition_source.value,
            item.status.value,
        ):
            raw = value.encode("ascii")
            digest.update(len(raw).to_bytes(4, "big"))
            digest.update(raw)
    for field in fields(evidence):
        if field.name in {"provenance", "coverage"}:
            continue
        name = field.name.encode("ascii")
        digest.update(len(name).to_bytes(2, "big"))
        digest.update(name)
        values = getattr(evidence, field.name)
        digest.update(len(values).to_bytes(4, "big"))
        for value in values:
            raw = value if isinstance(value, bytes) else value.encode("utf-8")
            digest.update(len(raw).to_bytes(8, "big"))
            digest.update(raw)
    return digest.digest()


class PrivacyEvidenceBuilder:
    __slots__ = ("_commitment", "_evidence")

    def __init__(self, evidence: PrivacyScanEvidence, *, constructor: object) -> None:
        if constructor is not _COMPOSITION_ROOT_CONSTRUCTOR:
            raise TypeError("privacy evidence builders are composition-root-created")
        self._evidence = _clone_privacy_evidence(evidence)
        self._commitment = _privacy_evidence_commitment(self._evidence)


@dataclass(frozen=True, slots=True, repr=False)
class _TrustedCapabilitySnapshot:
    producer_identity: object
    sequence: int
    snapshot_identity: object
    report: ReachyCapabilityReportV1
    evidence: PrivacyScanEvidence
    report_commitment: bytes
    evidence_commitment: bytes
    sanctioned_commitment: bytes
    source_commitment: bytes

    def __repr__(self) -> str:
        return "_TrustedCapabilitySnapshot(<opaque>)"


class TrustedCapabilityProducer:
    """Concrete process-local producer instantiated only by the delivered composition root."""

    __slots__ = (
        "_evidence",
        "_evidence_commitment",
        "_identity",
        "_last_consumed_sequence",
        "_next_sequence",
        "_outstanding",
        "_report_raw",
        "_sanctioned_commitment",
        "_source_commitment",
    )

    def __init__(
        self,
        *,
        observed_at: datetime,
        runtime: RuntimeObservationBuilder,
        media: MediaObservationBuilder,
        safety: SafetyObservationBuilder,
        host: HostObservationBuilder,
        privacy: PrivacyEvidenceBuilder,
        constructor: object,
    ) -> None:
        if constructor is not _COMPOSITION_ROOT_CONSTRUCTOR:
            raise TypeError("trusted producers are composition-root-created")
        if (
            type(runtime) is not RuntimeObservationBuilder
            or type(media) is not MediaObservationBuilder
            or type(safety) is not SafetyObservationBuilder
            or type(host) is not HostObservationBuilder
            or type(privacy) is not PrivacyEvidenceBuilder
        ):
            raise TypeError("trusted producer requires exact delivered builders")
        report = ReachyCapabilityReportV1(
            schema_version="tuntun.reachy-a05-capability.v1",
            observed_at=observed_at,
            runtime=runtime.observation,
            media=media.observation,
            safety=safety.observation,
            host=host.observation,
        )
        self._report_raw = canonical_bytes(report)
        self._evidence = _clone_privacy_evidence(privacy._evidence)
        self._evidence_commitment = _privacy_evidence_commitment(self._evidence)
        sanctioned = hashlib.sha256(b"tuntun.sanctioned-capability-leaves.v1\x00")
        for commitment in (
            runtime._commitment,
            media._commitment,
            safety._commitment,
            host._commitment,
        ):
            sanctioned.update(commitment)
        self._sanctioned_commitment = sanctioned.digest()
        self._source_commitment = self._current_source_commitment()
        self._identity = object()
        self._next_sequence = 1
        self._last_consumed_sequence = 0
        self._outstanding: dict[object, int] = {}

    def _current_source_commitment(self) -> bytes:
        digest = hashlib.sha256(b"tuntun.trusted-capability-source.v1\x00")
        digest.update(hashlib.sha256(self._report_raw).digest())
        digest.update(self._evidence_commitment)
        digest.update(self._sanctioned_commitment)
        return digest.digest()

    @property
    def runtime_observation(self) -> RuntimeObservation:
        return ReachyCapabilityReportV1.model_validate_json(self._report_raw).runtime

    @property
    def outstanding_snapshot_count(self) -> int:
        return len(self._outstanding)

    @property
    def last_consumed_sequence(self) -> int:
        return self._last_consumed_sequence

    def _capture(self, constructor: object) -> _TrustedCapabilitySnapshot:
        if constructor is not _TRUSTED_CAPTURE_CONSTRUCTOR:
            raise TypeError("trusted snapshots are producer-private")
        if self._current_source_commitment() != self._source_commitment:
            raise PrivacyScanUnavailable("trusted capability source drift")
        if not 1 <= self._next_sequence < 1 << 64:
            raise PrivacyScanUnavailable("trusted capability snapshot sequence exhausted")
        report = ReachyCapabilityReportV1.model_validate_json(self._report_raw)
        evidence = _clone_privacy_evidence(self._evidence)
        report_commitment = hashlib.sha256(canonical_bytes(report)).digest()
        evidence_commitment = _privacy_evidence_commitment(evidence)
        snapshot_identity = object()
        sequence = self._next_sequence
        self._next_sequence += 1
        self._outstanding[snapshot_identity] = sequence
        return _TrustedCapabilitySnapshot(
            producer_identity=self._identity,
            sequence=sequence,
            snapshot_identity=snapshot_identity,
            report=report,
            evidence=evidence,
            report_commitment=report_commitment,
            evidence_commitment=evidence_commitment,
            sanctioned_commitment=self._sanctioned_commitment,
            source_commitment=self._source_commitment,
        )

    def _accepts_snapshot(self, snapshot: _TrustedCapabilitySnapshot) -> bool:
        try:
            return (
                type(snapshot) is _TrustedCapabilitySnapshot
                and snapshot.producer_identity is self._identity
                and self._outstanding.get(snapshot.snapshot_identity) == snapshot.sequence
                and snapshot.report_commitment
                == hashlib.sha256(canonical_bytes(snapshot.report)).digest()
                and snapshot.evidence_commitment == _privacy_evidence_commitment(snapshot.evidence)
                and snapshot.sanctioned_commitment == self._sanctioned_commitment
                and snapshot.source_commitment == self._source_commitment
                and self._current_source_commitment() == self._source_commitment
            )
        except Exception:
            return False

    def _consume(self, snapshot: _TrustedCapabilitySnapshot, constructor: object) -> None:
        if constructor is not _TRUSTED_CAPTURE_CONSTRUCTOR:
            raise TypeError("trusted snapshots are producer-private")
        if (
            type(snapshot) is _TrustedCapabilitySnapshot
            and snapshot.producer_identity is self._identity
            and self._outstanding.get(snapshot.snapshot_identity) == snapshot.sequence
        ):
            del self._outstanding[snapshot.snapshot_identity]
            self._last_consumed_sequence = max(
                self._last_consumed_sequence,
                snapshot.sequence,
            )


def _normalized_private_text(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def _report_privacy_values(report: ReachyCapabilityReportV1) -> tuple[str, ...]:
    """Return only probe-controlled leaves that can carry arbitrary public values.

    Schema keys, enum/literal vocabulary, timestamps, and one-way commitments are not
    caller-controlled privacy channels. Free-form runtime tokens and numeric host
    observations are. Keeping this path-based avoids both fixed-vocabulary false
    positives and value-based allowlisting of an attacker-controlled token.
    """

    runtime = report.runtime
    values = [
        value
        for value in (
            runtime.sdk_version,
            runtime.daemon_version,
            runtime.python_version,
            runtime.python_abi,
        )
        if value is not None
    ]
    if runtime.dependencies is not None:
        values.extend(
            value
            for dependency in runtime.dependencies
            for value in (dependency.distribution, dependency.version)
        )
    values.extend(
        str(value)
        for value in (
            report.host.logical_cpu_count,
            report.host.memory_bytes,
            report.host.temperature_millicelsius,
        )
        if value is not None
    )
    if len(values) > _MAX_PRIVACY_REPORT_TEXT_VALUES:
        raise PrivacyScanUnavailable("privacy report leaf bound exceeded")
    return tuple(values)


def _reversible_binary_representations(value: bytes) -> tuple[str, ...]:
    casefold_variants, exact_variants = _reversible_binary_representation_sets(value)
    return tuple(sorted((*casefold_variants, *exact_variants)))


def _reversible_binary_representation_sets(
    value: bytes,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    casefold_variants: set[str] = set()
    exact_variants: set[str] = set()

    def add_casefold(encoded: bytes) -> None:
        if len(encoded) <= _MAX_PRIVACY_PUBLIC_TEXT_VALUE_BYTES:
            casefold_variants.add(encoded.decode("ascii"))

    def add_exact(encoded: bytes) -> None:
        if len(encoded) <= _MAX_PRIVACY_PUBLIC_TEXT_VALUE_BYTES:
            exact_variants.add(encoded.decode("ascii"))

    if len(value) * 2 <= _MAX_PRIVACY_PUBLIC_TEXT_VALUE_BYTES:
        hexadecimal = value.hex().encode("ascii")
        add_casefold(hexadecimal)
        add_casefold(hexadecimal.upper())
    if 4 * ((len(value) + 2) // 3) <= _MAX_PRIVACY_PUBLIC_TEXT_VALUE_BYTES:
        for encoder in (base64.b64encode, base64.urlsafe_b64encode):
            encoded = encoder(value)
            add_exact(encoded)
            add_exact(encoded.rstrip(b"="))
    if 8 * ((len(value) + 4) // 5) <= _MAX_PRIVACY_PUBLIC_TEXT_VALUE_BYTES:
        encoded = base64.b32encode(value)
        add_casefold(encoded)
        add_casefold(encoded.rstrip(b"="))
        add_casefold(encoded.lower())
        add_casefold(encoded.rstrip(b"=").lower())
    if len(casefold_variants) + len(exact_variants) > _MAX_PRIVACY_BINARY_REPRESENTATIONS_PER_VALUE:
        raise PrivacyScanUnavailable("privacy representation bound exceeded")
    return tuple(sorted(casefold_variants)), tuple(sorted(exact_variants))


def _require_privacy_decompression_budget(
    *,
    token_output_bytes: int,
    total_output_bytes: int,
) -> None:
    if (
        type(token_output_bytes) is not int
        or type(total_output_bytes) is not int
        or token_output_bytes < 0
        or total_output_bytes < 0
        or token_output_bytes > _MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES
        or total_output_bytes > _MAX_PRIVACY_DECOMPRESSED_TOTAL_BYTES
    ):
        raise PrivacyScanUnavailable("privacy decompression bound exceeded")


def _decode_canonical_zlib_base64url(
    token: str,
    *,
    max_output_bytes: int,
) -> bytes | None:
    decoded, _, _ = _decode_canonical_zlib_base64url_with_work(
        token,
        max_output_bytes=max_output_bytes,
    )
    return decoded


def _decode_canonical_zlib_base64url_with_work(
    token: str,
    *,
    max_output_bytes: int,
) -> tuple[bytes | None, tuple[bytes, ...], int]:
    if (
        type(token) is not str
        or type(max_output_bytes) is not int
        or max_output_bytes < 0
        or not token
        or len(token) > _MAX_PRIVACY_PUBLIC_TEXT_VALUE_BYTES
        or "=" in token
        or len(token) % 4 == 1
        or re.fullmatch(r"[A-Za-z0-9_-]+", token) is None
    ):
        return None, (), 0
    padding = "=" * (-len(token) % 4)
    try:
        compressed = base64.b64decode(
            token + padding,
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error):
        return None, (), 0
    if base64.urlsafe_b64encode(compressed).rstrip(b"=").decode("ascii") != token:
        return None, (), 0
    candidate_offsets = tuple(
        offset
        for offset in range(len(compressed) - 1)
        if _has_bounded_zlib_header_candidate(compressed[offset:])
    )
    if len(candidate_offsets) > _MAX_PRIVACY_ZLIB_OFFSET_ATTEMPTS:
        raise PrivacyScanUnavailable("privacy zlib offset bound exceeded")
    recovered_candidates: dict[bytes, None] = {}
    canonical_payload: bytes | None = None
    total_work = 0
    for offset in candidate_offsets:
        body_offset = offset + 2
        remaining_output_bytes = max_output_bytes - total_work
        if remaining_output_bytes < 0:
            raise PrivacyScanUnavailable("privacy decompression bound exceeded")
        payload, reached_eof, trailing, work, _ = _recover_raw_deflate(
            compressed[body_offset:],
            max_output_bytes=remaining_output_bytes,
        )
        total_work += work
        if total_work > max_output_bytes:
            raise PrivacyScanUnavailable("privacy decompression bound exceeded")
        if payload is not None:
            recovered_candidates[payload] = None
        ordinary_complete = (
            payload is not None
            and reached_eof
            and len(trailing) >= 4
            and zlib.adler32(payload) == int.from_bytes(trailing[:4], "big")
        )
        if not ordinary_complete or _could_be_single_bit_fdict_header(compressed[offset:]):
            remaining_output_bytes = max_output_bytes - total_work
            if remaining_output_bytes < 0:
                raise PrivacyScanUnavailable("privacy decompression bound exceeded")
            preset_dictionary_candidate, dictionary_work = _inspect_preset_dictionary_frame(
                compressed[offset:],
                max_output_bytes=remaining_output_bytes,
            )
            total_work += dictionary_work
            if total_work > max_output_bytes:
                raise PrivacyScanUnavailable("privacy decompression bound exceeded")
            if preset_dictionary_candidate:
                raise PrivacyScanUnavailable("privacy preset dictionary is unsupported")
        if (
            offset == 0
            and _has_supported_zlib_header(compressed)
            and ordinary_complete
            and len(trailing) == 4
        ):
            canonical_payload = payload
    return canonical_payload, tuple(recovered_candidates), total_work


def _recover_raw_deflate(
    compressed_body_and_trailer: bytes,
    *,
    max_output_bytes: int,
) -> tuple[bytes | None, bool, bytes, int, int]:
    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
    output = bytearray()
    trailing = b""
    for index, compressed_byte in enumerate(compressed_body_and_trailer):
        pending = bytes((compressed_byte,))
        while pending:
            remaining = max_output_bytes + 1 - len(output)
            if remaining <= 0:
                raise PrivacyScanUnavailable("privacy decompression bound exceeded")
            step_bytes = min(_PRIVACY_DECOMPRESSION_STEP_BYTES, remaining)
            try:
                chunk = decompressor.decompress(pending, step_bytes)
            except zlib.error:
                recovered = bytes(output) if output else None
                return recovered, False, b"", len(output), index + 1
            output.extend(chunk)
            if len(output) > max_output_bytes:
                raise PrivacyScanUnavailable("privacy decompression bound exceeded")
            unconsumed = decompressor.unconsumed_tail
            if not unconsumed:
                pending = b""
            elif unconsumed == pending and not chunk:
                recovered = bytes(output) if output else None
                return recovered, False, b"", len(output), index + 1
            else:
                pending = unconsumed
        if decompressor.eof:
            trailing = decompressor.unused_data + compressed_body_and_trailer[index + 1 :]
            break
    payload = bytes(output)
    return (
        payload if payload or decompressor.eof else None,
        decompressor.eof and not decompressor.unconsumed_tail,
        trailing,
        len(output),
        len(compressed_body_and_trailer) - len(trailing),
    )


def _has_supported_zlib_header(value: bytes) -> bool:
    return (
        _has_plausible_zlib_cmf(value)
        and (value[0] << 8 | value[1]) % 31 == 0
        and not value[1] & 0x20
    )


def _has_preset_dictionary_zlib_header(value: bytes) -> bool:
    return (
        _has_plausible_zlib_cmf(value)
        and (value[0] << 8 | value[1]) % 31 == 0
        and bool(value[1] & 0x20)
    )


def _inspect_preset_dictionary_frame(
    value: bytes,
    *,
    max_output_bytes: int,
) -> tuple[bool, int]:
    """Validate FDICT framing without needing or guessing the private dictionary.

    A fixed 32-KiB synthetic history lets zlib parse every legal distance while
    keeping output bounded. For a one-bit-neighbor header, DEFLATE EOF plus at
    least four trailer bytes is required. An exact valid FDICT header plus bounded
    structural progress is sufficient to fail closed on body/trailer truncation.
    The trailer checksum is not compared because synthetic plaintext differs.
    """

    if (
        len(value) < _MIN_PRIVACY_FDICT_FRAME_BYTES
        or not _could_be_single_bit_fdict_header(value)
        or type(max_output_bytes) is not int
        or max_output_bytes < 0
    ):
        return False, 0
    reached_eof, trailing, work = _recover_structural_dictionary_deflate(
        value[6:],
        max_output_bytes=max_output_bytes,
    )
    exact_fdict_header = _is_valid_zlib_header(value[0] << 8 | value[1]) and bool(value[1] & 0x20)
    structurally_private = (reached_eof and len(trailing) >= 4) or (
        exact_fdict_header and (reached_eof or work > 0)
    )
    return structurally_private, work


def _recover_structural_dictionary_deflate(
    body_and_trailer: bytes,
    *,
    max_output_bytes: int,
) -> tuple[bool, bytes, int]:
    """Parse one FDICT body incrementally so corrupt-stream work is never lost."""

    decompressor = zlib.decompressobj(
        -zlib.MAX_WBITS,
        zdict=_PRIVACY_STRUCTURAL_DICTIONARY,
    )
    output_bytes = 0
    trailing = b""
    for index, compressed_byte in enumerate(body_and_trailer):
        pending = bytes((compressed_byte,))
        while pending:
            remaining = max_output_bytes + 1 - output_bytes
            if remaining <= 0:
                raise PrivacyScanUnavailable("privacy decompression bound exceeded")
            try:
                chunk = decompressor.decompress(
                    pending,
                    min(_PRIVACY_DECOMPRESSION_STEP_BYTES, remaining),
                )
            except zlib.error:
                return False, b"", output_bytes
            output_bytes += len(chunk)
            if output_bytes > max_output_bytes:
                raise PrivacyScanUnavailable("privacy decompression bound exceeded")
            unconsumed = decompressor.unconsumed_tail
            if not unconsumed:
                pending = b""
            elif unconsumed == pending and not chunk:
                return False, b"", output_bytes
            else:
                pending = unconsumed
        if decompressor.eof:
            trailing = decompressor.unused_data + body_and_trailer[index + 1 :]
            break
    return decompressor.eof and not decompressor.unconsumed_tail, trailing, output_bytes


def _has_plausible_preset_dictionary_frame(value: bytes) -> bool:
    plausible, _ = _inspect_preset_dictionary_frame(
        value,
        max_output_bytes=_MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES,
    )
    return plausible


def _has_bounded_zlib_header_candidate(value: bytes) -> bool:
    """Admit exact zlib headers and any single-bit CMF/FLG corruption."""

    if len(value) < 2:
        return False
    header = value[0] << 8 | value[1]
    return _is_valid_zlib_header(header) or any(
        _is_valid_zlib_header(header ^ (1 << bit)) for bit in range(16)
    )


def _could_be_single_bit_fdict_header(value: bytes) -> bool:
    if len(value) < 2:
        return False
    header = value[0] << 8 | value[1]
    return any(
        _is_valid_zlib_header(candidate) and bool(candidate & 0x20)
        for candidate in (header, *(header ^ (1 << bit) for bit in range(16)))
    )


def _is_valid_zlib_header(header: int) -> bool:
    encoded = header.to_bytes(2, "big")
    return _has_plausible_zlib_cmf(encoded) and header % 31 == 0


def _has_plausible_zlib_cmf(value: bytes) -> bool:
    return len(value) >= 2 and value[0] & 0x0F == 8 and value[0] >> 4 <= 7


def _has_plausible_raw_deflate_prefix(value: bytes) -> bool:
    if not value:
        return False
    block_type = (value[0] >> 1) & 0x03
    if block_type == 0x03:
        return False
    if block_type != 0:
        return True
    if len(value) < 5:
        return False
    stored_length = int.from_bytes(value[1:3], "little")
    stored_complement = int.from_bytes(value[3:5], "little")
    return stored_length ^ stored_complement == 0xFFFF


_SUPPORTED_ZLIB_HEADERS = tuple(
    bytes((cmf, flg))
    for cmf in range(256)
    for flg in range(256)
    if _has_supported_zlib_header(bytes((cmf, flg)))
)


def _require_privacy_recovered_search_budget(comparison_bytes: int) -> None:
    if (
        type(comparison_bytes) is not int
        or comparison_bytes < 0
        or comparison_bytes > _MAX_PRIVACY_RECOVERED_SEARCH_BYTES
    ):
        raise PrivacyScanUnavailable("privacy recovered search bound exceeded")


def _utf8_repair_text_variants(value: bytes) -> tuple[str, ...]:
    """Boundedly repair only bytes adjacent to a concrete UTF-8 decode failure."""

    try:
        return (value.decode("utf-8"),)
    except UnicodeDecodeError:
        pass
    if len(value) > _MAX_PRIVACY_UTF8_REPAIR_BYTES:
        raise PrivacyScanUnavailable("privacy UTF-8 repair bound exceeded")
    frontier: tuple[bytes, ...] = (value,)
    seen = {value}
    for deletions in range(_MAX_PRIVACY_UTF8_REPAIR_DELETIONS + 1):
        repaired: dict[str, None] = {}
        failures: list[tuple[bytes, int, int]] = []
        for candidate in frontier:
            try:
                repaired[candidate.decode("utf-8")] = None
            except UnicodeDecodeError as error:
                failures.append((candidate, error.start, error.end))
        if repaired:
            return tuple(repaired)
        if deletions == _MAX_PRIVACY_UTF8_REPAIR_DELETIONS:
            break
        next_frontier: dict[bytes, None] = {}
        for candidate, error_start, error_end in failures:
            start = max(0, error_start - 1)
            stop = min(len(candidate), error_end + 1)
            for index in range(start, stop):
                if candidate[index] < 0x80:
                    continue
                variant = candidate[:index] + candidate[index + 1 :]
                if variant in seen:
                    continue
                if len(seen) >= _MAX_PRIVACY_UTF8_REPAIR_VARIANTS:
                    raise PrivacyScanUnavailable("privacy UTF-8 repair variant bound exceeded")
                seen.add(variant)
                next_frontier[variant] = None
        frontier = tuple(next_frontier)
        if not frontier:
            break
    raise PrivacyScanUnavailable("privacy UTF-8 repair frontier exhausted")


def _contains_static_private_lexeme(value: str) -> bool:
    normalized = _normalized_private_text(value)
    return (
        "xn--" in normalized
        or _DOTTED_QUAD_LEXEME.search(normalized) is not None
        or _LOCAL_NAME_LEXEME.search(normalized) is not None
        or _PRIVATE_COMPONENT.search(normalized) is not None
    )


@dataclass(slots=True)
class _RecoveredScanBudget:
    comparison_bytes: int = 0
    representation_bytes: int = 0


def _require_privacy_recovered_representation_budget(representation_bytes: int) -> None:
    if (
        type(representation_bytes) is not int
        or representation_bytes < 0
        or representation_bytes > _MAX_PRIVACY_RECOVERED_REPRESENTATION_BYTES
    ):
        raise PrivacyScanUnavailable("privacy recovered representation bound exceeded")


def _scan_long_reversible_representations(
    recovered: bytes,
    representation_sources: tuple[bytes, ...],
    *,
    budget: _RecoveredScanBudget,
) -> None:
    """Scan >64-byte reversible forms one at a time under an aggregate byte budget."""

    recovered_casefold: bytes | None = None

    def scan(encoded: bytes, *, case_insensitive: bool) -> None:
        nonlocal recovered_casefold
        if len(encoded) <= _MAX_PRIVACY_PUBLIC_TEXT_VALUE_BYTES or len(encoded) > len(recovered):
            return
        budget.representation_bytes += len(encoded)
        _require_privacy_recovered_representation_budget(budget.representation_bytes)
        haystack = recovered
        needle = encoded
        if case_insensitive:
            if recovered_casefold is None:
                budget.representation_bytes += len(recovered)
                _require_privacy_recovered_representation_budget(budget.representation_bytes)
                recovered_casefold = recovered.lower()
            haystack = recovered_casefold
            needle = encoded.lower()
        budget.comparison_bytes += len(haystack)
        _require_privacy_recovered_search_budget(budget.comparison_bytes)
        if needle in haystack:
            raise PrivacyScanRejected("sanitized capability report contains private text")

    for source in representation_sources:
        hexadecimal_length = len(source) * 2
        if _MAX_PRIVACY_PUBLIC_TEXT_VALUE_BYTES < hexadecimal_length <= len(recovered):
            scan(binascii.hexlify(source), case_insensitive=True)

        base64_length = 4 * ((len(source) + 2) // 3)
        if base64_length - 2 <= len(recovered) and base64_length > 0:
            standard = base64.b64encode(source)
            standard_unpadded = standard.rstrip(b"=")
            scan(standard, case_insensitive=False)
            if standard_unpadded != standard:
                scan(standard_unpadded, case_insensitive=False)
            urlsafe = base64.urlsafe_b64encode(source)
            urlsafe_unpadded = urlsafe.rstrip(b"=")
            if urlsafe != standard:
                scan(urlsafe, case_insensitive=False)
            if urlsafe_unpadded not in {standard, standard_unpadded, urlsafe}:
                scan(urlsafe_unpadded, case_insensitive=False)

        base32_length = 8 * ((len(source) + 4) // 5)
        if base32_length - 6 <= len(recovered) and base32_length > 0:
            base32 = base64.b32encode(source)
            base32_unpadded = base32.rstrip(b"=")
            scan(base32, case_insensitive=True)
            if base32_unpadded != base32:
                scan(base32_unpadded, case_insensitive=True)


def _contains_equivalent_private_ip(
    recovered_text: str,
    packed_network_identifiers: frozenset[bytes],
) -> bool:
    for match in _IP_ADDRESS_TEXT_RUN.finditer(recovered_text):
        token = match.group()
        if ":" not in token or len(token) > 45:
            continue
        try:
            packed = ipaddress.ip_address(token).packed
        except ValueError:
            continue
        if packed in packed_network_identifiers:
            return True
    return False


def _scan_recovered_private_values(
    recovered: bytes,
    private_buffers: tuple[bytes, ...],
    representation_sources: tuple[bytes, ...],
    packed_network_identifiers: frozenset[bytes],
    normalized_private_values: tuple[str, ...],
    exact_private_values: tuple[str, ...],
    *,
    budget: _RecoveredScanBudget,
) -> None:
    for private_bytes in private_buffers:
        if len(private_bytes) > len(recovered):
            continue
        budget.comparison_bytes += len(recovered)
        _require_privacy_recovered_search_budget(budget.comparison_bytes)
        if private_bytes in recovered:
            raise PrivacyScanRejected("sanitized capability report contains private bytes")
    _scan_long_reversible_representations(
        recovered,
        representation_sources,
        budget=budget,
    )
    recovered_byte_variants = tuple(
        dict.fromkeys((recovered, bytes(byte for byte in recovered if byte < 0x80)))
    )
    if len(recovered_byte_variants) > _MAX_PRIVACY_RECOVERED_BYTE_VARIANTS:
        raise PrivacyScanUnavailable("privacy recovered byte variant bound exceeded")
    for recovered_byte_variant in recovered_byte_variants:
        for private_value in exact_private_values:
            encoded_private = private_value.encode("ascii")
            if len(encoded_private) > len(recovered_byte_variant):
                continue
            budget.comparison_bytes += len(recovered_byte_variant)
            _require_privacy_recovered_search_budget(budget.comparison_bytes)
            matches = (
                recovered_byte_variant == encoded_private
                if len(private_value) < _MIN_PRIVACY_SUBSTRING_TEXT_CHARACTERS
                else encoded_private in recovered_byte_variant
            )
            if matches:
                raise PrivacyScanRejected("sanitized capability report contains private text")
    recovered_text = recovered.decode("utf-8", errors="surrogateescape")
    normalized_recovered_text = _normalized_private_text(recovered_text)
    compact_recovered_text = "".join(
        character
        for character in normalized_recovered_text
        if not 0xDC80 <= ord(character) <= 0xDCFF
    )
    repaired_text_variants = (
        tuple(_normalized_private_text(value) for value in _utf8_repair_text_variants(recovered))
        if any(not value.isascii() for value in normalized_private_values)
        else ()
    )
    recovered_text_variants = tuple(
        dict.fromkeys(
            (
                normalized_recovered_text,
                compact_recovered_text,
                *repaired_text_variants,
            )
        )
    )
    if len(recovered_text_variants) > _MAX_PRIVACY_UTF8_REPAIR_VARIANTS + 2:
        raise PrivacyScanUnavailable("privacy recovered text variant bound exceeded")
    for recovered_text_variant in recovered_text_variants:
        recovered_text_bytes = len(recovered_text_variant.encode("utf-8", errors="surrogateescape"))
        budget.comparison_bytes += recovered_text_bytes
        _require_privacy_recovered_search_budget(budget.comparison_bytes)
        if _contains_static_private_lexeme(
            recovered_text_variant
        ) or _contains_equivalent_private_ip(
            recovered_text_variant,
            packed_network_identifiers,
        ):
            raise PrivacyScanRejected("sanitized capability report contains private text")
        for private_value in normalized_private_values:
            if len(private_value) > len(recovered_text_variant):
                continue
            budget.comparison_bytes += recovered_text_bytes
            _require_privacy_recovered_search_budget(budget.comparison_bytes)
            if _private_text_matches_report(private_value, recovered_text_variant):
                raise PrivacyScanRejected("sanitized capability report contains private text")


@dataclass(slots=True)
class _NestedScanBudget:
    search_bytes: int = 0
    decode_attempts: int = 0
    decoded_bytes: int = 0
    recovery_attempts: int = 0
    recovery_bytes: int = 0


def _require_privacy_nested_search_budget(search_bytes: int) -> None:
    if (
        type(search_bytes) is not int
        or search_bytes < 0
        or search_bytes > _MAX_PRIVACY_NESTED_SEARCH_BYTES
    ):
        raise PrivacyScanUnavailable("privacy nested search bound exceeded")


def _require_privacy_nested_budget(budget: _NestedScanBudget) -> None:
    _require_privacy_nested_search_budget(budget.search_bytes)
    if (
        budget.decode_attempts > _MAX_PRIVACY_NESTED_DECODE_ATTEMPTS
        or budget.decoded_bytes > _MAX_PRIVACY_NESTED_DECODED_BYTES
        or budget.recovery_attempts > _MAX_PRIVACY_NESTED_RECOVERY_ATTEMPTS
        or budget.recovery_bytes > _MAX_PRIVACY_NESTED_RECOVERY_BYTES
    ):
        raise PrivacyScanUnavailable("privacy nested transform bound exceeded")


def _canonical_reversible_decodes(value: bytes) -> tuple[bytes, ...]:
    if len(value) > _MAX_PRIVACY_NESTED_LEXICAL_VALUE_BYTES:
        raise PrivacyScanUnavailable("privacy nested lexical value bound exceeded")
    if len(value) < 3:
        return ()
    try:
        value.decode("ascii")
    except UnicodeDecodeError:
        return ()
    decoded_values: dict[bytes, None] = {}
    if len(value) % 2 == 0 and re.fullmatch(rb"[0-9A-Fa-f]+", value) is not None:
        with suppress(binascii.Error):
            decoded_values[binascii.unhexlify(value)] = None
    if len(value) % 4 != 1:
        padded = value + b"=" * (-len(value) % 4)
        for altchars in (None, b"-_"):
            with suppress(ValueError, binascii.Error):
                decoded_values[base64.b64decode(padded, altchars=altchars, validate=True)] = None
    padded_base32 = value + b"=" * (-len(value) % 8)
    with suppress(ValueError, binascii.Error):
        decoded_values[base64.b32decode(padded_base32, casefold=True)] = None
    canonical: list[bytes] = []
    for decoded in decoded_values:
        hexadecimal = binascii.hexlify(decoded)
        standard = base64.b64encode(decoded)
        urlsafe = base64.urlsafe_b64encode(decoded)
        base32 = base64.b32encode(decoded)
        if (
            value.lower() == hexadecimal
            or value in {standard, standard.rstrip(b"="), urlsafe, urlsafe.rstrip(b"=")}
            or value.upper() in {base32, base32.rstrip(b"=")}
        ):
            canonical.append(decoded)
    return tuple(canonical)


def _lexical_zlib_prefix(value: bytes, *, budget: _NestedScanBudget) -> bool:
    for prefix_bytes in (3, 4, 8):
        if len(value) < prefix_bytes:
            continue
        budget.decode_attempts += 1
        _require_privacy_nested_budget(budget)
        if any(
            len(decoded) >= 2 and _has_bounded_zlib_header_candidate(decoded)
            for decoded in _canonical_reversible_decodes(value[:prefix_bytes])
        ):
            return True
    return False


def _scan_nested_raw_candidate(
    value: bytes,
    *,
    budget: _NestedScanBudget,
    recovered_payloads: list[bytes],
) -> bool:
    budget.search_bytes += len(value)
    _require_privacy_nested_budget(budget)
    for offset in range(len(value) - 1):
        if not _has_bounded_zlib_header_candidate(value[offset:]):
            continue
        if not _has_plausible_raw_deflate_prefix(value[offset + 2 :]):
            remaining_output = _MAX_PRIVACY_NESTED_RECOVERY_BYTES - budget.recovery_bytes
            budget.recovery_attempts += 1
            _require_privacy_nested_budget(budget)
            preset_dictionary_candidate, dictionary_work = _inspect_preset_dictionary_frame(
                value[offset:],
                max_output_bytes=max(remaining_output, 0),
            )
            budget.recovery_bytes += dictionary_work
            _require_privacy_nested_budget(budget)
            if preset_dictionary_candidate:
                raise PrivacyScanUnavailable("privacy preset dictionary is unsupported")
            continue
        budget.recovery_attempts += 1
        _require_privacy_nested_budget(budget)
        remaining_output = _MAX_PRIVACY_NESTED_RECOVERY_BYTES - budget.recovery_bytes
        payload, reached_eof, trailing, output_work, input_work = _recover_raw_deflate(
            value[offset + 2 :],
            max_output_bytes=max(remaining_output, 0),
        )
        budget.recovery_bytes += output_work
        budget.search_bytes += input_work
        _require_privacy_nested_budget(budget)
        if payload is not None and payload not in recovered_payloads:
            recovered_payloads.append(payload)
        ordinary_complete = (
            payload is not None
            and reached_eof
            and len(trailing) >= 4
            and zlib.adler32(payload) == int.from_bytes(trailing[:4], "big")
        )
        if not ordinary_complete or _could_be_single_bit_fdict_header(value[offset:]):
            remaining_output = _MAX_PRIVACY_NESTED_RECOVERY_BYTES - budget.recovery_bytes
            budget.recovery_attempts += 1
            _require_privacy_nested_budget(budget)
            preset_dictionary_candidate, dictionary_work = _inspect_preset_dictionary_frame(
                value[offset:],
                max_output_bytes=max(remaining_output, 0),
            )
            budget.recovery_bytes += dictionary_work
            _require_privacy_nested_budget(budget)
            if preset_dictionary_candidate:
                raise PrivacyScanUnavailable("privacy preset dictionary is unsupported")
        if ordinary_complete:
            return True
    return False


def _contains_nested_zlib(
    value: bytes,
    *,
    search_bytes: int,
    budget: _NestedScanBudget | None = None,
    recovered_payloads: list[bytes] | None = None,
) -> tuple[bool, int]:
    """Recognize a finite transform grammar without treating signatures as proof.

    Grammar: raw bytes, or one canonical hex/base64/base64url/base32 lexical decode,
    followed by one zlib frame at any byte offset. Every candidate must reach DEFLATE
    EOF; FDICT is unavailable because the producer does not own its dictionary.
    Attempt, decoded-byte, input-search, and output budgets are aggregate and strict.
    """

    active_budget = budget or _NestedScanBudget(search_bytes=search_bytes)
    if active_budget.search_bytes < search_bytes:
        raise PrivacyScanUnavailable("privacy nested search state is invalid")
    recovered = recovered_payloads if recovered_payloads is not None else []
    compact_ascii = bytes(byte for byte in value if byte < 0x80)
    lexical_values = tuple(dict.fromkeys((value, compact_ascii)))
    if len(lexical_values) > _MAX_PRIVACY_RECOVERED_BYTE_VARIANTS:
        raise PrivacyScanUnavailable("privacy nested decode variant bound exceeded")
    for lexical_value in lexical_values:
        active_budget.search_bytes += len(lexical_value)
        _require_privacy_nested_budget(active_budget)
        for start in range(len(lexical_value)):
            suffix = lexical_value[start : start + _MAX_PRIVACY_NESTED_LEXICAL_VALUE_BYTES + 1]
            if not _lexical_zlib_prefix(suffix, budget=active_budget):
                continue
            for length_index in range(-1, len(suffix) - 2):
                length = len(suffix) if length_index == -1 else length_index + 3
                if length_index >= 0 and length == len(suffix):
                    continue
                active_budget.decode_attempts += 1
                _require_privacy_nested_budget(active_budget)
                for decoded in _canonical_reversible_decodes(suffix[:length]):
                    if len(decoded) < 2 or not _has_bounded_zlib_header_candidate(decoded):
                        continue
                    active_budget.decoded_bytes += len(decoded)
                    _require_privacy_nested_budget(active_budget)
                    if _scan_nested_raw_candidate(
                        decoded,
                        budget=active_budget,
                        recovered_payloads=recovered,
                    ):
                        return True, active_budget.search_bytes
    if _scan_nested_raw_candidate(value, budget=active_budget, recovered_payloads=recovered):
        return True, active_budget.search_bytes
    return False, active_budget.search_bytes


def _private_text_matches_report(private_value: str, report_value: str) -> bool:
    if len(private_value) < _MIN_PRIVACY_SUBSTRING_TEXT_CHARACTERS:
        return private_value == report_value
    return private_value in report_value


def _require_privacy_scan_budget(
    *,
    report_value_count: int,
    private_value_count: int,
    transformed_value_bytes: int,
) -> None:
    if transformed_value_bytes > _MAX_PRIVACY_TRANSFORMED_VALUE_BYTES:
        raise PrivacyScanUnavailable("privacy scan memory bound exceeded")
    if (
        report_value_count > _MAX_PRIVACY_REPORT_TEXT_VALUES
        or private_value_count > _MAX_PRIVACY_SCAN_PRIVATE_VALUES
        or private_value_count * report_value_count > _MAX_PRIVACY_SCAN_COMPARISONS
    ):
        raise PrivacyScanUnavailable("privacy scan work bound exceeded")


def _ip_representations(value: str) -> tuple[str, ...]:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise PrivacyScanUnavailable("private IP evidence is invalid") from None
    variants = {
        str(address),
        address.compressed,
        address.exploded,
        str(int(address)),
        address.packed.hex(),
        f"0x{int(address):x}",
    }
    return tuple(sorted(variants))


def _mac_representations(value: str) -> tuple[str, ...]:
    compact = re.sub(r"[:.\-]", "", value)
    if re.fullmatch(r"[0-9A-Fa-f]{12}", compact) is None:
        raise PrivacyScanUnavailable("private MAC evidence is invalid")
    compact = compact.lower()
    octets = tuple(compact[index : index + 2] for index in range(0, 12, 2))
    numeric = int(compact, 16)
    variants = {
        compact,
        compact.upper(),
        str(numeric),
        f"0x{numeric:x}",
        ":".join(octets),
        ":".join(octets).upper(),
        "-".join(octets),
        "-".join(octets).upper(),
        ".".join((compact[:4], compact[4:8], compact[8:])),
        ".".join((compact[:4], compact[4:8], compact[8:])).upper(),
    }
    return tuple(sorted(variants))


def _packed_network_identifiers(evidence: PrivacyScanEvidence) -> tuple[bytes, ...]:
    packed: dict[bytes, None] = {}
    for value in evidence.ip_addresses:
        try:
            packed[ipaddress.ip_address(value).packed] = None
        except ValueError:
            raise PrivacyScanUnavailable("private IP evidence is invalid") from None
    for value in evidence.mac_addresses:
        compact = re.sub(r"[:.\-]", "", value)
        if re.fullmatch(r"[0-9A-Fa-f]{12}", compact) is None:
            raise PrivacyScanUnavailable("private MAC evidence is invalid")
        packed[bytes.fromhex(compact)] = None
    return tuple(packed)


def _scan_privacy_snapshot(
    report: ReachyCapabilityReportV1,
    evidence: PrivacyScanEvidence,
) -> None:
    if type(report) is not ReachyCapabilityReportV1 or type(evidence) is not PrivacyScanEvidence:
        raise PrivacyScanUnavailable("trusted privacy snapshot is invalid")
    if any(
        item.status
        not in {
            PrivacyCollectionStatus.COMPLETE_WITH_VALUES,
            PrivacyCollectionStatus.COMPLETE_EMPTY,
        }
        for item in evidence.coverage
    ):
        raise PrivacyScanUnavailable("privacy evidence acquisition is incomplete")
    report_text_values = _report_privacy_values(report)
    normalized_report_values = tuple(
        _normalized_private_text(value) for value in report_text_values
    )
    text_evidence = tuple(
        value
        for name in (
            "hostnames",
            "fqdns",
            "principals",
            "home_paths",
            "serials",
            "ssids",
            "fingerprints",
        )
        for value in getattr(evidence, name)
    )
    derived_evidence = tuple(
        variant for value in evidence.ip_addresses for variant in _ip_representations(value)
    ) + tuple(
        variant for value in evidence.mac_addresses for variant in _mac_representations(value)
    )
    normalized_private_values = {
        _normalized_private_text(value) for value in (*text_evidence, *derived_evidence)
    }
    exact_private_values: set[str] = set()
    transformed_value_bytes = 0
    private_buffers = (*evidence.key_material, *evidence.content_buffers)
    packed_network_identifiers = frozenset(_packed_network_identifiers(evidence))
    private_binary_values = tuple(dict.fromkeys((*private_buffers, *packed_network_identifiers)))
    representation_sources = dict.fromkeys(
        (
            *(value.encode("utf-8") for value in (*text_evidence, *derived_evidence)),
            *(value.encode("utf-8") for value in sorted(normalized_private_values)),
            *private_binary_values,
        )
    )
    if len(representation_sources) > _MAX_PRIVACY_REPRESENTATION_SOURCES:
        raise PrivacyScanUnavailable("privacy representation source bound exceeded")
    ordered_representation_sources = tuple(representation_sources)
    for private_bytes in private_binary_values:
        if any(private_bytes in value.encode("utf-8") for value in report_text_values):
            raise PrivacyScanRejected("sanitized capability report contains private bytes")
    for private_bytes in representation_sources:
        casefold_representations, exact_representations = _reversible_binary_representation_sets(
            private_bytes
        )
        transformed_value_bytes += sum(
            len(value.encode("ascii"))
            for value in (*casefold_representations, *exact_representations)
        )
        normalized_private_values.update(
            _normalized_private_text(value) for value in casefold_representations
        )
        exact_private_values.update(exact_representations)
    _require_privacy_scan_budget(
        report_value_count=len(normalized_report_values),
        private_value_count=len(normalized_private_values) + len(exact_private_values),
        transformed_value_bytes=transformed_value_bytes,
    )
    ordered_private_values = tuple(sorted(normalized_private_values))
    ordered_exact_private_values = tuple(sorted(exact_private_values))
    private_buffer_commitments = {
        (len(private_bytes), hashlib.sha256(private_bytes).digest())
        for private_bytes in private_binary_values
    }
    total_decompressed_bytes = 0
    recovered_budget = _RecoveredScanBudget()
    nested_budget = _NestedScanBudget()
    for report_value in report_text_values:
        remaining_decompression_bytes = (
            _MAX_PRIVACY_DECOMPRESSED_TOTAL_BYTES - total_decompressed_bytes
        )
        decoded_payload, recovered_payloads, decompressed_work = (
            _decode_canonical_zlib_base64url_with_work(
                report_value,
                max_output_bytes=min(
                    _MAX_PRIVACY_DECOMPRESSED_TOKEN_BYTES,
                    max(remaining_decompression_bytes, 0),
                ),
            )
        )
        total_decompressed_bytes += decompressed_work
        _require_privacy_decompression_budget(
            token_output_bytes=decompressed_work,
            total_output_bytes=total_decompressed_bytes,
        )
        candidate_payloads = tuple(
            dict.fromkeys(
                (
                    *((decoded_payload,) if decoded_payload is not None else ()),
                    *recovered_payloads,
                )
            )
        )
        for candidate_payload in candidate_payloads:
            if (
                len(candidate_payload),
                hashlib.sha256(candidate_payload).digest(),
            ) in private_buffer_commitments:
                raise PrivacyScanRejected("sanitized capability report contains private bytes")
            _scan_recovered_private_values(
                candidate_payload,
                private_binary_values,
                ordered_representation_sources,
                packed_network_identifiers,
                ordered_private_values,
                ordered_exact_private_values,
                budget=recovered_budget,
            )
            nested_recovered_payloads: list[bytes] = []
            contains_nested_zlib, _ = _contains_nested_zlib(
                candidate_payload,
                search_bytes=nested_budget.search_bytes,
                budget=nested_budget,
                recovered_payloads=nested_recovered_payloads,
            )
            if contains_nested_zlib:
                raise PrivacyScanUnavailable("privacy nested compression is unsupported")
            for nested_recovered_payload in nested_recovered_payloads:
                _scan_recovered_private_values(
                    nested_recovered_payload,
                    private_binary_values,
                    ordered_representation_sources,
                    packed_network_identifiers,
                    ordered_private_values,
                    ordered_exact_private_values,
                    budget=recovered_budget,
                )
    if any(
        _private_text_matches_report(private_value, report_value)
        for private_value in ordered_private_values
        for report_value in normalized_report_values
    ) or any(
        _private_text_matches_report(private_value, report_value)
        for private_value in ordered_exact_private_values
        for report_value in report_text_values
    ):
        raise PrivacyScanRejected("sanitized capability report contains private text")


class _CapabilityProvenance:
    __slots__ = (
        "capability_identity",
        "evidence_commitment",
        "producer_identity",
        "proof_tag",
        "report_commitment",
        "sanctioned_commitment",
        "sequence",
        "service_identity",
        "snapshot_identity",
        "source_commitment",
    )

    def __init__(
        self,
        *,
        capability_identity: object,
        snapshot: _TrustedCapabilitySnapshot,
        service_identity: object,
        proof_tag: bytes,
        constructor: object,
    ) -> None:
        if constructor is not _PROBED_CAPABILITY_CONSTRUCTOR:
            raise TypeError("capability provenance is service-created")
        self.capability_identity = capability_identity
        self.service_identity = service_identity
        self.producer_identity = snapshot.producer_identity
        self.sequence = snapshot.sequence
        self.snapshot_identity = snapshot.snapshot_identity
        self.report_commitment = snapshot.report_commitment
        self.evidence_commitment = snapshot.evidence_commitment
        self.sanctioned_commitment = snapshot.sanctioned_commitment
        self.source_commitment = snapshot.source_commitment
        self.proof_tag = proof_tag

    def __repr__(self) -> str:
        return "_CapabilityProvenance(<opaque>)"


class ProbedCapability:
    """Opaque exact snapshot minted by the trusted zero-argument probe service."""

    __slots__ = ("_capability_identity", "_provenance", "_report_raw", "_service")

    def __init__(
        self,
        *,
        report_raw: bytes,
        service: CapabilityProbeService,
        provenance: _CapabilityProvenance,
        capability_identity: object,
        constructor: object,
    ) -> None:
        if constructor is not _PROBED_CAPABILITY_CONSTRUCTOR:
            raise TypeError("probed capabilities are service-created")
        self._report_raw = bytes(report_raw)
        self._service = service
        self._provenance = provenance
        self._capability_identity = capability_identity

    @property
    def report(self) -> ReachyCapabilityReportV1:
        return ReachyCapabilityReportV1.model_validate_json(self._report_raw)

    def _privacy_is_proved(self) -> bool:
        try:
            return self._service._accepts(
                report_raw=self._report_raw,
                provenance=self._provenance,
                capability_identity=self._capability_identity,
            )
        except Exception:
            return False

    def __repr__(self) -> str:
        return "ProbedCapability(<opaque>)"


class CapabilityProbeService:
    """Composition-root-owned issuer with no caller-supplied report or evidence input."""

    __slots__ = ("_producer", "_proof_key", "_service_identity")

    def __init__(self, producer: TrustedCapabilityProducer, *, constructor: object) -> None:
        if constructor is not _COMPOSITION_ROOT_CONSTRUCTOR:
            raise TypeError("probe services are composition-root-created")
        if type(producer) is not TrustedCapabilityProducer:
            raise TypeError("probe service requires the concrete trusted producer")
        self._producer = producer
        self._service_identity = object()
        self._proof_key = secrets.token_bytes(32)

    def _provenance_tag(
        self,
        *,
        capability_identity: object,
        snapshot_identity: object,
        sequence: int,
        report_commitment: bytes,
        evidence_commitment: bytes,
        sanctioned_commitment: bytes,
        source_commitment: bytes,
    ) -> bytes:
        digest = hmac.new(self._proof_key, b"tuntun.capability-provenance.v1\x00", hashlib.sha256)
        for identity in (
            self._service_identity,
            self._producer._identity,
            capability_identity,
            snapshot_identity,
        ):
            digest.update(id(identity).to_bytes(16, "big"))
        digest.update(sequence.to_bytes(8, "big"))
        for commitment in (
            report_commitment,
            evidence_commitment,
            sanctioned_commitment,
            source_commitment,
        ):
            digest.update(commitment)
        return digest.digest()

    def probe(self) -> ProbedCapability:
        snapshot = self._producer._capture(_TRUSTED_CAPTURE_CONSTRUCTOR)
        try:
            if not self._producer._accepts_snapshot(snapshot):
                raise PrivacyScanUnavailable("trusted capability snapshot is invalid")
            report_raw = canonical_bytes(snapshot.report)
            evidence_commitment = _privacy_evidence_commitment(snapshot.evidence)
            if snapshot.report.host.report_privacy is not CheckStatus.PASSED:
                raise PrivacyScanRejected("probe did not pass its report privacy check")
            _scan_privacy_snapshot(snapshot.report, snapshot.evidence)
            if (
                not self._producer._accepts_snapshot(snapshot)
                or canonical_bytes(snapshot.report) != report_raw
                or _privacy_evidence_commitment(snapshot.evidence) != evidence_commitment
            ):
                raise PrivacyScanUnavailable("trusted capability source drift")
            capability_identity = object()
            provenance = _CapabilityProvenance(
                capability_identity=capability_identity,
                snapshot=snapshot,
                service_identity=self._service_identity,
                proof_tag=self._provenance_tag(
                    capability_identity=capability_identity,
                    snapshot_identity=snapshot.snapshot_identity,
                    sequence=snapshot.sequence,
                    report_commitment=snapshot.report_commitment,
                    evidence_commitment=snapshot.evidence_commitment,
                    sanctioned_commitment=snapshot.sanctioned_commitment,
                    source_commitment=snapshot.source_commitment,
                ),
                constructor=_PROBED_CAPABILITY_CONSTRUCTOR,
            )
            return ProbedCapability(
                report_raw=report_raw,
                service=self,
                provenance=provenance,
                capability_identity=capability_identity,
                constructor=_PROBED_CAPABILITY_CONSTRUCTOR,
            )
        finally:
            self._producer._consume(snapshot, _TRUSTED_CAPTURE_CONSTRUCTOR)

    def _accepts(
        self,
        *,
        report_raw: bytes,
        provenance: _CapabilityProvenance,
        capability_identity: object,
    ) -> bool:
        return (
            type(provenance) is _CapabilityProvenance
            and type(report_raw) is bytes
            and provenance.capability_identity is capability_identity
            and provenance.service_identity is self._service_identity
            and provenance.producer_identity is self._producer._identity
            and provenance.sequence >= 1
            and provenance.report_commitment == hashlib.sha256(report_raw).digest()
            and provenance.sanctioned_commitment == self._producer._sanctioned_commitment
            and provenance.source_commitment == self._producer._source_commitment
            and provenance.evidence_commitment == self._producer._evidence_commitment
            and hmac.compare_digest(
                provenance.proof_tag,
                self._provenance_tag(
                    capability_identity=capability_identity,
                    snapshot_identity=provenance.snapshot_identity,
                    sequence=provenance.sequence,
                    report_commitment=provenance.report_commitment,
                    evidence_commitment=provenance.evidence_commitment,
                    sanctioned_commitment=provenance.sanctioned_commitment,
                    source_commitment=provenance.source_commitment,
                ),
            )
        )


class CapabilityDecision(ContractModel):
    outcome: CapabilityOutcome
    input_mode: PttInputMode | None
    limitations: Annotated[tuple[LimitationCode, ...], Field(max_length=4)] = ()
    rejection_reasons: Annotated[tuple[RejectionReason, ...], Field(max_length=14)] = ()
    unknown_facts: Annotated[tuple[CapabilityFact, ...], Field(max_length=5)] = ()

    @model_validator(mode="after")
    def truthful_closed_decision(self) -> CapabilityDecision:
        ordered_fields: tuple[
            tuple[tuple[StrEnum, ...], tuple[StrEnum, ...]],
            ...,
        ] = (
            (self.limitations, tuple(LimitationCode)),
            (self.rejection_reasons, tuple(RejectionReason)),
            (self.unknown_facts, tuple(CapabilityFact)),
        )
        if any(
            len(values) != len(set(values))
            or tuple(sorted(values, key=canonical_order.index)) != values
            for values, canonical_order in ordered_fields
        ):
            raise ValueError("decision facts must be unique and in canonical enum order")
        if self.outcome is CapabilityOutcome.ACCEPTED:
            truthful = (
                self.input_mode is PttInputMode.REACHY_LOCAL
                and not self.rejection_reasons
                and not self.unknown_facts
                and LimitationCode.LOCAL_INPUT_UNAVAILABLE not in self.limitations
            )
        elif self.outcome is CapabilityOutcome.CONDITIONAL_MAC_KEY:
            truthful = (
                self.input_mode is PttInputMode.CORE_TERMINAL_TOGGLE
                and LimitationCode.LOCAL_INPUT_UNAVAILABLE in self.limitations
                and not self.rejection_reasons
                and not self.unknown_facts
            )
        else:
            truthful = (
                self.input_mode is None
                and not self.limitations
                and bool(self.rejection_reasons or self.unknown_facts)
            )
        if not truthful:
            raise ValueError("decision outcome and evidence are inconsistent")
        return self


def render_capability_schema() -> bytes:
    schema = ReachyCapabilityReportV1.model_json_schema(
        mode="validation",
        ref_template="#/$defs/{model}",
    )
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = _CAPABILITY_SCHEMA_ID
    definitions = schema["$defs"]
    if not isinstance(definitions, dict):
        raise TypeError("generated capability definitions are not an object")
    runtime = definitions["RuntimeObservation"]
    media = definitions["MediaObservation"]
    host = definitions["HostObservation"]
    if not all(isinstance(value, dict) for value in (runtime, media, host)):
        raise TypeError("generated capability observation schema is not an object")
    nonnull = {"not": {"type": "null"}}
    runtime["dependentRequired"] = {
        "daemon_version": ["daemon_artifact_sha256"],
        "daemon_artifact_sha256": ["daemon_version"],
        "sdk_version": [
            "sdk_artifact_sha256",
            "runtime_inventory_sha256",
            "dependencies",
        ],
        "sdk_artifact_sha256": [
            "sdk_version",
            "runtime_inventory_sha256",
            "dependencies",
        ],
        "runtime_inventory_sha256": [
            "sdk_version",
            "sdk_artifact_sha256",
            "dependencies",
        ],
        "dependencies": [
            "sdk_version",
            "sdk_artifact_sha256",
            "runtime_inventory_sha256",
        ],
        "python_version": ["python_abi"],
        "python_abi": ["python_version"],
    }
    runtime["allOf"] = [
        {
            "if": {
                "properties": {"daemon_available": {"const": "passed"}},
                "required": ["daemon_available"],
            },
            "then": {
                "properties": {
                    "daemon_version": nonnull,
                    "daemon_artifact_sha256": nonnull,
                },
                "required": ["daemon_version", "daemon_artifact_sha256"],
            },
        },
        {
            "if": {
                "properties": {"sdk_daemon_match": {"const": "passed"}},
                "required": ["sdk_daemon_match"],
            },
            "then": {
                "properties": {
                    "sdk_version": nonnull,
                    "sdk_artifact_sha256": nonnull,
                    "runtime_inventory_sha256": nonnull,
                    "dependencies": nonnull,
                    "daemon_version": nonnull,
                    "daemon_artifact_sha256": nonnull,
                },
                "required": [
                    "sdk_version",
                    "sdk_artifact_sha256",
                    "runtime_inventory_sha256",
                    "dependencies",
                    "daemon_version",
                    "daemon_artifact_sha256",
                ],
            },
        },
        {
            "if": {
                "properties": {"interpreter_supported": {"const": "passed"}},
                "required": ["interpreter_supported"],
            },
            "then": {
                "oneOf": [
                    {
                        "properties": {
                            "python_version": {
                                "pattern": r"^3[.]11[.](?:0|[1-9][0-9]{0,2})$",
                                "not": {"pattern": r"[\r\n]"},
                            },
                            "python_abi": {"const": "cp311"},
                        }
                    },
                    {
                        "properties": {
                            "python_version": {
                                "pattern": r"^3[.]12[.](?:0|[1-9][0-9]{0,2})$",
                                "not": {"pattern": r"[\r\n]"},
                            },
                            "python_abi": {"const": "cp312"},
                        }
                    },
                ],
                "required": ["python_version", "python_abi"],
            },
        },
    ]
    media["allOf"] = [
        {
            "if": {
                "properties": {field: {"const": "passed"}},
                "required": [field],
            },
            "then": {
                "properties": {format_field: nonnull},
                "required": [format_field],
            },
        }
        for field, format_field in (
            ("microphone_capture", "native_input_format"),
            ("speaker_playback", "native_output_format"),
            ("playback_stop", "native_output_format"),
        )
    ]
    resource_fields = [
        "logical_cpu_count",
        "memory_bytes",
        "temperature_millicelsius",
    ]
    host["dependentRequired"] = {field: resource_fields for field in resource_fields}
    host["allOf"] = [
        {
            "if": {
                "properties": {"resource_limits": {"const": "passed"}},
                "required": ["resource_limits"],
            },
            "then": {
                "properties": {field: nonnull for field in resource_fields},
                "required": resource_fields,
            },
        }
    ]
    schema["description"] = (
        "Structural sanitized capability schema; runtime model parsing and a trusted in-memory "
        "privacy authority are required for cross-field and private-provenance semantics."
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
    ).encode()


def decide_capability(
    capability: ReachyCapabilityReportV1 | ProbedCapability,
) -> CapabilityDecision:
    if type(capability) is ProbedCapability:
        privacy_proved = capability._privacy_is_proved()
        try:
            report = capability.report
        except Exception:
            return CapabilityDecision(
                outcome=CapabilityOutcome.REJECTED,
                input_mode=None,
                rejection_reasons=(RejectionReason.REPORT_PRIVACY_FAILED,),
            )
    elif type(capability) is ReachyCapabilityReportV1:
        report = capability
        privacy_proved = False
    else:
        raise TypeError("capability decision requires a report or probed capability")
    runtime = report.runtime
    media = report.media
    safety = report.safety
    host = report.host
    privacy_proved = host.report_privacy is CheckStatus.PASSED and privacy_proved
    hard_requirements = (
        (RejectionReason.NETWORK_TOPOLOGY_FAILED, (host.network_topology,)),
        (RejectionReason.DAEMON_UNAVAILABLE, (runtime.daemon_available,)),
        (RejectionReason.SDK_DAEMON_MISMATCH, (runtime.sdk_daemon_match,)),
        (RejectionReason.UNSUPPORTED_INTERPRETER, (runtime.interpreter_supported,)),
        (
            RejectionReason.MEDIA_CAPTURE_FAILED,
            (media.microphone_capture, media.camera_frame_observed),
        ),
        (RejectionReason.MEDIA_PLAYBACK_FAILED, (media.speaker_playback,)),
        (RejectionReason.PLAYBACK_STOP_FAILED, (media.playback_stop,)),
        (
            RejectionReason.MOTION_STOP_UNAVAILABLE,
            (safety.movement_enumerated, safety.motion_stop),
        ),
        (
            RejectionReason.CONTROLLER_DETECTION_UNAVAILABLE,
            (safety.app_lock, safety.controller_detection),
        ),
        (RejectionReason.CONTROLLER_COLLISION, (safety.controller_collision_clear,)),
        (RejectionReason.UNSAFE_BIND_SURFACE, (host.bind_surface,)),
        (RejectionReason.SSH_BOUNDARY_FAILED, (host.ssh_boundary,)),
        (RejectionReason.RESOURCE_LIMIT_FAILED, (host.resource_limits,)),
        (
            RejectionReason.REPORT_PRIVACY_FAILED,
            (CheckStatus.PASSED if privacy_proved else CheckStatus.FAILED,),
        ),
    )
    rejections = tuple(
        reason
        for reason, checks in hard_requirements
        if any(check is not CheckStatus.PASSED for check in checks)
    )
    optional_facts = (
        (CapabilityFact.AEC, media.aec),
        (CapabilityFact.DOA, media.doa),
        (CapabilityFact.LOCAL_CAPTURE_INPUT, safety.local_capture_input),
        (CapabilityFact.LOCAL_STOP_INPUT, safety.local_stop_input),
        (CapabilityFact.RTC, host.rtc),
    )
    unknown_facts = tuple(
        fact for fact, status in optional_facts if status is CapabilityStatus.UNKNOWN
    )
    if rejections or unknown_facts:
        return CapabilityDecision(
            outcome=CapabilityOutcome.REJECTED,
            input_mode=None,
            rejection_reasons=rejections,
            unknown_facts=unknown_facts,
        )
    limitations: list[LimitationCode] = []
    if media.aec is CapabilityStatus.UNAVAILABLE:
        limitations.append(LimitationCode.AEC_UNAVAILABLE)
    if media.doa is CapabilityStatus.UNAVAILABLE:
        limitations.append(LimitationCode.DOA_UNAVAILABLE)
    local_input_available = (
        safety.local_capture_input is CapabilityStatus.AVAILABLE
        and safety.local_stop_input is CapabilityStatus.AVAILABLE
    )
    if not local_input_available:
        limitations.append(LimitationCode.LOCAL_INPUT_UNAVAILABLE)
    if host.rtc is CapabilityStatus.UNAVAILABLE:
        limitations.append(LimitationCode.RTC_UNQUALIFIED)
    return CapabilityDecision(
        outcome=(
            CapabilityOutcome.ACCEPTED
            if local_input_available
            else CapabilityOutcome.CONDITIONAL_MAC_KEY
        ),
        input_mode=(
            PttInputMode.REACHY_LOCAL
            if local_input_available
            else PttInputMode.CORE_TERMINAL_TOGGLE
        ),
        limitations=tuple(limitations),
    )
