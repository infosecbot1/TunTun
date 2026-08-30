from __future__ import annotations

import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Protocol

SecretId = tuple[str, str]

MAX_SECRET_BYTES = 16_384
_SECRET_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")

SECRET_IDS: Mapping[str, SecretId] = MappingProxyType(
    {
        "database": ("tuntun.database", "root-v1"),
        "audit": ("tuntun.audit", "hmac-v1"),
        "backup": ("tuntun.backup", "slot-v1"),
        "records": ("tuntun.records", "root-v1"),
        "openai": ("tuntun.provider.openai", "api-v1"),
        "qwen": ("tuntun.provider.qwen", "api-v1"),
        "edge_ca": ("tuntun.edge.ca", "signing-v1"),
        "device_signing": ("tuntun.edge.device", "signing-v1"),
    }
)

REQUIRED_SECRET_LENGTHS: Mapping[SecretId, int] = MappingProxyType(
    {
        SECRET_IDS["database"]: 32,
        SECRET_IDS["audit"]: 32,
        SECRET_IDS["backup"]: 32,
        SECRET_IDS["records"]: 32,
    }
)
REQUIRED_SECRETS = tuple(REQUIRED_SECRET_LENGTHS)

if len(set(SECRET_IDS.values())) != len(SECRET_IDS):
    raise RuntimeError("secret identifiers must be unique")


def validate_secret_identifier(service: str, account: str) -> SecretId:
    if (
        type(service) is not str
        or type(account) is not str
        or _SECRET_IDENTIFIER.fullmatch(service) is None
        or _SECRET_IDENTIFIER.fullmatch(account) is None
    ):
        raise ValueError("invalid secret identifier")
    return service, account


def validate_secret_value(value: bytes) -> bytes:
    if type(value) is not bytes or not 1 <= len(value) <= MAX_SECRET_BYTES:
        raise ValueError("secret value must be nonempty bounded bytes")
    return value


class SecretProvider(Protocol):
    def get(self, service: str, account: str) -> bytes: ...

    def set(self, service: str, account: str, value: bytes) -> None: ...

    def delete(self, service: str, account: str) -> None: ...

    def exists(self, service: str, account: str) -> bool: ...


class InMemorySecretProvider:
    def __init__(self) -> None:
        self._values: dict[SecretId, bytes] = {}

    def get(self, service: str, account: str) -> bytes:
        key = validate_secret_identifier(service, account)
        try:
            return self._values[key]
        except KeyError as error:
            raise RuntimeError(f"missing secret: {service}/{account}") from error

    def set(self, service: str, account: str, value: bytes) -> None:
        key = validate_secret_identifier(service, account)
        self._values[key] = validate_secret_value(value)

    def delete(self, service: str, account: str) -> None:
        key = validate_secret_identifier(service, account)
        self._values.pop(key, None)

    def exists(self, service: str, account: str) -> bool:
        key = validate_secret_identifier(service, account)
        return key in self._values

    def __repr__(self) -> str:
        return f"InMemorySecretProvider(entries={len(self._values)})"


def validate_production_secrets(provider: SecretProvider) -> None:
    for (service, account), required_length in REQUIRED_SECRET_LENGTHS.items():
        try:
            value = validate_secret_value(provider.get(service, account))
        except (RuntimeError, ValueError) as error:
            raise RuntimeError(
                f"missing or invalid required secret: {service}/{account}"
            ) from error
        if len(value) != required_length:
            raise RuntimeError(f"invalid required secret length: {service}/{account}")
