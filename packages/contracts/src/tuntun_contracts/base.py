from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum, StrEnum
from typing import Any, Literal, NoReturn, TypeAlias, TypeVar, cast
from unicodedata import normalize
from uuid import UUID

import rfc8785
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

JCS_MAX_SAFE_INTEGER = 2**53 - 1
JCS_MIN_SAFE_INTEGER = -JCS_MAX_SAFE_INTEGER

JSONValue: TypeAlias = (  # noqa: UP040 -- contracts remain Python 3.11 compatible.
    str | int | Decimal | bool | None | list["JSONValue"] | dict[str, "JSONValue"]
)
ContractT = TypeVar("ContractT", bound="ContractModel")


class ContractParseError(ValueError):
    """Untrusted contract input or canonicalization failed closed."""


class _HostileJSONError(Exception):
    pass


def _is_jcs_safe_integer(value: int) -> bool:
    return JCS_MIN_SAFE_INTEGER <= value <= JCS_MAX_SAFE_INTEGER


def _normalize_contract_input(value: Any) -> Any:
    if isinstance(value, Enum):
        return value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("datetime must be timezone-aware")
        return value
    if type(value) is int and not _is_jcs_safe_integer(value):
        raise ValueError("integer must be in the RFC 8785 safe integer domain")
    if isinstance(value, str):
        return normalize("NFC", value)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("contract mapping keys must be strings")
            normalized_key = normalize("NFC", key)
            if normalized_key in result:
                raise ValueError("contract mapping keys collide after NFC")
            result[normalized_key] = _normalize_contract_input(item)
        return result
    if isinstance(value, tuple):
        return tuple(_normalize_contract_input(item) for item in value)
    if isinstance(value, list):
        return [_normalize_contract_input(item) for item in value]
    if isinstance(value, frozenset):
        frozen_normalized = frozenset(_normalize_contract_input(item) for item in value)
        if len(frozen_normalized) != len(value):
            raise ValueError("contract set values collide after NFC")
        return frozen_normalized
    if isinstance(value, set):
        mutable_normalized = {_normalize_contract_input(item) for item in value}
        if len(mutable_normalized) != len(value):
            raise ValueError("contract set values collide after NFC")
        return mutable_normalized
    return value


class ContractModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        allow_inf_nan=False,
        validate_assignment=True,
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_and_validate_contract_value(
        cls,
        value: Any,
        info: ValidationInfo,
    ) -> Any:
        normalized = _normalize_contract_input(value)
        if info.mode != "json" or not isinstance(normalized, Mapping):
            return normalized
        result = dict(normalized)
        for field_name, field in cls.model_fields.items():
            input_name = field.alias or field_name
            if input_name not in result:
                continue
            field_json = json.dumps(
                result[input_name],
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
            )
            result[input_name] = TypeAdapter(field.rebuild_annotation()).validate_json(
                field_json,
                strict=True,
                context=info.context,
            )
        return result


def registered_contract_models() -> tuple[type[ContractModel], ...]:
    # Import after package initialization so Task 5 can replace the one closed,
    # package-owned tuple while preserving this already-frozen import path.
    from . import _REGISTERED_CONTRACT_MODELS

    return _REGISTERED_CONTRACT_MODELS


def _unique_json_object(
    pairs: list[tuple[str, JSONValue]],
) -> dict[str, JSONValue]:
    result: dict[str, JSONValue] = {}
    for key, value in pairs:
        if key in result:
            raise _HostileJSONError("duplicate JSON key")
        result[key] = value
    return result


def _bounded_json_int(value: str) -> int:
    if len(value.removeprefix("-")) > 16:
        raise _HostileJSONError("JSON integer outside JCS safe domain")
    parsed = int(value)
    if not _is_jcs_safe_integer(parsed):
        raise _HostileJSONError("JSON integer outside JCS safe domain")
    return parsed


def _bounded_json_decimal(value: str) -> Decimal:
    if len(value) > 64:
        raise _HostileJSONError("JSON decimal too large")
    result = Decimal(value)
    if not result.is_finite():
        raise _HostileJSONError("non-finite JSON number")
    if len(result.as_tuple().digits) > 64 or not -308 <= result.adjusted() <= 308:
        raise _HostileJSONError("JSON decimal range exceeded")
    return result


def _reject_json_constant(value: str) -> NoReturn:
    raise _HostileJSONError(f"non-finite JSON number: {value}")


def _require_bounded_json_shape(
    text: str,
    *,
    max_depth: int,
    max_containers: int,
    max_structure_tokens: int,
) -> None:
    depth = 0
    containers = 0
    structure_tokens = 1
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            containers += 1
            if depth > max_depth or containers > max_containers:
                raise _HostileJSONError("contract JSON shape limit exceeded")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise _HostileJSONError("contract JSON shape invalid")
        elif character in ",:":
            structure_tokens += 1
            if structure_tokens > max_structure_tokens:
                raise _HostileJSONError("contract JSON shape limit exceeded")
    if in_string or depth != 0:
        raise _HostileJSONError("contract JSON shape invalid")


def parse_bounded_json_value(
    raw: bytes,
    *,
    max_bytes: int,
    max_depth: int = 32,
    max_containers: int = 4_096,
    max_structure_tokens: int = 16_384,
) -> JSONValue:
    limits = (max_bytes, max_depth, max_containers, max_structure_tokens)
    ceilings = (8_388_608, 32, 4_096, 16_384)
    if type(raw) is not bytes:
        raise TypeError("contract JSON raw input must be bytes")
    if any(type(value) is not int for value in limits) or any(
        not 1 <= value <= ceiling for value, ceiling in zip(limits, ceilings, strict=True)
    ):
        raise ValueError("invalid contract JSON parser configuration")
    if not 1 <= len(raw) <= max_bytes:
        raise ContractParseError("contract JSON size invalid")
    try:
        text = raw.decode("utf-8", errors="strict")
        _require_bounded_json_shape(
            text,
            max_depth=max_depth,
            max_containers=max_containers,
            max_structure_tokens=max_structure_tokens,
        )
        return cast(
            JSONValue,
            json.loads(
                text,
                object_pairs_hook=_unique_json_object,
                parse_int=_bounded_json_int,
                parse_float=_bounded_json_decimal,
                parse_constant=_reject_json_constant,
            ),
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, _HostileJSONError) as error:
        raise ContractParseError("contract JSON ingress rejected") from error


def parse_contract_json(  # noqa: UP047 -- contracts remain Python 3.11 compatible.
    model_type: type[ContractT],
    raw: bytes,
    *,
    max_bytes: int,
    require_canonical: bool = False,
) -> ContractT:
    if not isinstance(model_type, type) or not issubclass(model_type, ContractModel):
        raise TypeError("model_type must be a ContractModel subclass")
    parse_bounded_json_value(raw, max_bytes=max_bytes)
    try:
        model = model_type.model_validate_json(raw, strict=True)
    except (ValidationError, RecursionError) as error:
        raise ContractParseError("contract JSON schema rejected") from error
    if require_canonical and canonical_bytes(model) != raw:
        raise ContractParseError("contract JSON is not canonical JCS")
    return model


class Sensitivity(StrEnum):
    PUBLIC = "public"
    HOUSEHOLD = "household"
    PERSONAL = "personal"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"


def validate_canonical_base64(
    value: str,
    *,
    expected_bytes: int,
    label: str,
) -> str:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError(f"{label} must be canonical base64") from error
    if len(decoded) != expected_bytes or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{label} must encode exactly {expected_bytes} bytes canonically")
    return value


class Commitment(ContractModel):
    algorithm: Literal["HMAC-SHA-256"]
    key_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9_.:-]+$",
    )
    value_b64: str = Field(
        min_length=44,
        max_length=44,
        pattern=r"^[A-Za-z0-9+/]{43}=$",
    )

    @field_validator("value_b64")
    @classmethod
    def canonical_hmac_sha256(cls, value: str) -> str:
        return validate_canonical_base64(
            value,
            expected_bytes=32,
            label="commitment",
        )


def _canonical_value(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("datetime must be timezone-aware")
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(value, str):
        return normalize("NFC", value)
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Enum):
        return _canonical_value(value.value)
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if type(value) is int:
        if not _is_jcs_safe_integer(value):
            raise rfc8785.IntegerDomainError(value)
        return value
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("canonical JSON mapping keys must be strings")
            normalized_key = normalize("NFC", key)
            if normalized_key in result:
                raise ValueError("canonical JSON mapping keys collide after NFC")
            result[normalized_key] = _canonical_value(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    return value


def canonical_mapping_bytes(value: Mapping[str, Any]) -> bytes:
    if not isinstance(value, Mapping):
        raise TypeError("canonical JSON root must be a mapping")
    try:
        return rfc8785.dumps(_canonical_value(value))
    except rfc8785.CanonicalizationError as error:
        raise ContractParseError("contract canonicalization rejected") from error


def canonical_bytes(model: ContractModel) -> bytes:
    if not isinstance(model, ContractModel):
        raise TypeError("canonical_bytes requires a ContractModel")
    return canonical_mapping_bytes(model.model_dump(mode="python"))
