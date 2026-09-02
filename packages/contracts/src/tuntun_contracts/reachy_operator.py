from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network
from typing import Annotated, Any, Final, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from .base import ContractModel

_RFC1918_CIDRS: Final = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
)
_RFC1918_NETWORKS: Final = tuple(IPv4Network(cidr) for cidr in _RFC1918_CIDRS)
_SHA256_PATTERN: Final = r"^[0-9a-f]{64}$"
_STABLE_SEMVER_PATTERN: Final = (
    r"^(?:0|[1-9][0-9]*)[.](?:0|[1-9][0-9]*)[.](?:0|[1-9][0-9]*)$"
)
_STABLE_SEMVER_MIN_LENGTH: Final = 5
_STABLE_SEMVER_MAX_LENGTH: Final = 32
_POSIX_NON_ROOT_USERNAME_PATTERN: Final = (
    r"^(?:"
    r"[a-z_][a-z0-9_-]{0,2}"
    r"|[a-qs-z_][a-z0-9_-]{3}"
    r"|r[a-np-z0-9_-][a-z0-9_-]{2}"
    r"|ro[a-np-z0-9_-][a-z0-9_-]"
    r"|roo[a-su-z0-9_-]"
    r"|[a-z_][a-z0-9_-]{4,31}"
    r")$"
)
_IPV4_OCTET_PATTERN: Final = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])"
_CANONICAL_RFC1918_IPV4_PATTERN: Final = (
    r"^(?:"
    rf"10[.]{_IPV4_OCTET_PATTERN}[.]{_IPV4_OCTET_PATTERN}[.]{_IPV4_OCTET_PATTERN}"
    rf"|172[.](?:1[6-9]|2[0-9]|3[0-1])[.]{_IPV4_OCTET_PATTERN}"
    rf"[.]{_IPV4_OCTET_PATTERN}"
    rf"|192[.]168[.]{_IPV4_OCTET_PATTERN}[.]{_IPV4_OCTET_PATTERN}"
    r")$"
)
_FIELD_SAFETY_EXTENSION_KEY: Final = "x-tuntun-field-safety"
_CROSS_FIELD_INVARIANTS_EXTENSION_KEY: Final = "x-tuntun-cross-field-invariants"
_NON_ROOT_USERNAME_SCHEMA_EXTRA: Final[dict[str, Any]] = {
    _FIELD_SAFETY_EXTENSION_KEY: {
        "constraint": "non-root-posix-username",
        "forbidden_values": ["root"],
        "runtime_authoritative": True,
    }
}
_RFC1918_IPV4_SCHEMA_EXTRA: Final[dict[str, Any]] = {
    _FIELD_SAFETY_EXTENSION_KEY: {
        "allowed_cidrs": list(_RFC1918_CIDRS),
        "constraint": "canonical-explicit-rfc1918-ipv4",
        "runtime_authoritative": True,
    }
}
_OPERATOR_STATE_SCHEMA_EXTRA: Final[dict[str, Any]] = {
    _CROSS_FIELD_INVARIANTS_EXTENSION_KEY: [
        {
            "constraint": "distinct-rfc1918-operator-endpoints",
            "fields": ["reachy_ipv4", "core_ipv4"],
            "relation": "not_equal",
            "runtime_authoritative": True,
        },
        {
            "constraint": "accepted-capability-username-match",
            "fields": ["ssh_username", "accepted_capability.ssh_username"],
            "relation": "equal_when_present",
            "runtime_authoritative": True,
        },
    ]
}
_ACCEPTED_CAPABILITY_SCHEMA_EXTRA: Final[dict[str, Any]] = {
    _CROSS_FIELD_INVARIANTS_EXTENSION_KEY: [
        {
            "allowed_pairs": [["3.11", "cp311"], ["3.12", "cp312"]],
            "constraint": "supported-reachy-interpreter-abi-pair",
            "fields": ["python_version", "python_abi"],
            "runtime_authoritative": True,
        }
    ]
}


class ReachyAcceptedCapabilityV1(ContractModel):
    model_config = ConfigDict(json_schema_extra=_ACCEPTED_CAPABILITY_SCHEMA_EXTRA)

    capability_report_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    acceptance_receipt_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    sdk_version: Annotated[
        str,
        Field(
            min_length=_STABLE_SEMVER_MIN_LENGTH,
            max_length=_STABLE_SEMVER_MAX_LENGTH,
            pattern=_STABLE_SEMVER_PATTERN,
        ),
    ]
    daemon_version: Annotated[
        str,
        Field(
            min_length=_STABLE_SEMVER_MIN_LENGTH,
            max_length=_STABLE_SEMVER_MAX_LENGTH,
            pattern=_STABLE_SEMVER_PATTERN,
        ),
    ]
    ssh_username: Annotated[
        str,
        Field(
            pattern=_POSIX_NON_ROOT_USERNAME_PATTERN,
            json_schema_extra=_NON_ROOT_USERNAME_SCHEMA_EXTRA,
        ),
    ]
    python_executable: Literal["/venvs/apps_venv/bin/python3"]
    python_version: Literal["3.11", "3.12"]
    python_abi: Literal["cp311", "cp312"]
    selected_wheel_tag: Literal["py3-none-any"]
    target_tag_set_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    runtime_inventory_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]

    @field_validator("ssh_username")
    @classmethod
    def non_root_username(cls, value: str) -> str:
        if value == "root":
            raise ValueError("Reachy SSH username must be non-root")
        return value

    @model_validator(mode="after")
    def supported_interpreter_pair(self) -> Self:
        if (self.python_version, self.python_abi) not in {
            ("3.11", "cp311"),
            ("3.12", "cp312"),
        }:
            raise ValueError("unsupported Reachy interpreter pair")
        return self


class ReachyOperatorStateV1(ContractModel):
    model_config = ConfigDict(json_schema_extra=_OPERATOR_STATE_SCHEMA_EXTRA)

    schema_version: Literal["tuntun.reachy-operator-state.v1"]
    commissioning_generation: Annotated[int, Field(ge=1)]
    commissioning_state_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    ssh_username: Annotated[
        str,
        Field(
            pattern=_POSIX_NON_ROOT_USERNAME_PATTERN,
            json_schema_extra=_NON_ROOT_USERNAME_SCHEMA_EXTRA,
        ),
    ]
    reachy_ipv4: Annotated[
        str,
        Field(
            pattern=_CANONICAL_RFC1918_IPV4_PATTERN,
            json_schema_extra=_RFC1918_IPV4_SCHEMA_EXTRA,
        ),
    ]
    core_ipv4: Annotated[
        str,
        Field(
            pattern=_CANONICAL_RFC1918_IPV4_PATTERN,
            json_schema_extra=_RFC1918_IPV4_SCHEMA_EXTRA,
        ),
    ]
    pinned_ssh_host_key_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    dhcp_receipt_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    accepted_capability: ReachyAcceptedCapabilityV1 | None

    @field_validator("ssh_username")
    @classmethod
    def non_root_username(cls, value: str) -> str:
        if value == "root":
            raise ValueError("Reachy SSH username must be non-root")
        return value

    @field_validator("reachy_ipv4", "core_ipv4")
    @classmethod
    def explicit_canonical_rfc1918(cls, value: str) -> str:
        try:
            address = IPv4Address(value)
        except ValueError as error:
            raise ValueError("operator IPv4 must be canonical RFC1918") from error
        if str(address) != value or not any(address in network for network in _RFC1918_NETWORKS):
            raise ValueError("operator IPv4 must be canonical RFC1918")
        return value

    @model_validator(mode="after")
    def exact_distinct_rfc1918_hosts_and_capability_user(self) -> Self:
        if self.reachy_ipv4 == self.core_ipv4:
            raise ValueError("operator endpoints must be distinct RFC1918 hosts")
        if (
            self.accepted_capability is not None
            and self.ssh_username != self.accepted_capability.ssh_username
        ):
            raise ValueError("accepted capability username mismatch")
        return self
