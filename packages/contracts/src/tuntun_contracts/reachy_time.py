from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Any, Final, Literal

from pydantic import AwareDatetime, Field, field_validator

from .base import ContractModel, canonical_mapping_bytes, validate_canonical_base64

_FIELD_SAFETY_EXTENSION_KEY: Final = "x-tuntun-field-safety"
_UTC_DATETIME_SCHEMA_EXTRA: Final[dict[str, Any]] = {
    _FIELD_SAFETY_EXTENSION_KEY: {
        "canonical_serialization_offset": "Z",
        "constraint": "utc-offset-zero-datetime",
        "required_utc_offset_seconds": 0,
        "runtime_authoritative": True,
    }
}


class CoreTimeRequestV1(ContractModel):
    schema_version: Literal["tuntun.core-time-request.v1"]
    request_nonce_b64: Annotated[
        str,
        Field(
            min_length=44,
            max_length=44,
            pattern=r"^[A-Za-z0-9+/]{43}=$",
        ),
    ]

    @field_validator("request_nonce_b64")
    @classmethod
    def canonical_nonce(cls, value: str) -> str:
        return validate_canonical_base64(
            value,
            expected_bytes=32,
            label="nonce",
        )


class CoreTimeProofV1(ContractModel):
    schema_version: Literal["tuntun.core-time-proof.v1"]
    endpoint_generation: Annotated[int, Field(ge=1)]
    time_sequence: Annotated[int, Field(ge=1)]
    request_nonce_b64: Annotated[
        str,
        Field(
            min_length=44,
            max_length=44,
            pattern=r"^[A-Za-z0-9+/]{43}=$",
        ),
    ]
    core_utc: Annotated[
        AwareDatetime,
        Field(json_schema_extra=_UTC_DATETIME_SCHEMA_EXTRA),
    ]
    authority_health_generation: Annotated[int, Field(ge=1)]
    signing_key_id: Annotated[
        str,
        Field(
            min_length=12,
            max_length=83,
            pattern=r"^ed25519:[a-z0-9][a-z0-9._-]{0,63}:v[1-9][0-9]{0,8}$",
        ),
    ]
    signature_b64: Annotated[
        str,
        Field(
            min_length=88,
            max_length=88,
            pattern=r"^[A-Za-z0-9+/]{86}==$",
        ),
    ]

    @field_validator("request_nonce_b64")
    @classmethod
    def canonical_nonce(cls, value: str) -> str:
        return validate_canonical_base64(
            value,
            expected_bytes=32,
            label="nonce",
        )

    @field_validator("signature_b64")
    @classmethod
    def canonical_ed25519_signature(cls, value: str) -> str:
        return validate_canonical_base64(
            value,
            expected_bytes=64,
            label="signature",
        )

    @field_validator("core_utc")
    @classmethod
    def utc_offset_zero(cls, value: datetime) -> datetime:
        if value.utcoffset() != timedelta(0):
            raise ValueError("core_utc must use UTC offset zero")
        return value

    def signing_payload(self) -> bytes:
        return canonical_mapping_bytes(self.model_dump(mode="python", exclude={"signature_b64"}))
