from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from enum import StrEnum
from typing import cast
from uuid import UUID

import pytest
import tuntun_contracts
from pydantic import AwareDatetime, Field, ValidationError
from tuntun_contracts.base import (
    JCS_MAX_SAFE_INTEGER,
    JCS_MIN_SAFE_INTEGER,
    Commitment,
    ContractModel,
    ContractParseError,
    Sensitivity,
    canonical_bytes,
    canonical_mapping_bytes,
    parse_bounded_json_value,
    parse_contract_json,
)
from tuntun_contracts.events import EventEnvelope, EventType, WakeDetectedPayload


def valid_python_event() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "event_id": UUID(int=1),
        "event_type": EventType.WAKE_DETECTED,
        "household_id": UUID(int=2),
        "device_id": UUID(int=3),
        "session_id": None,
        "correlation_id": UUID(int=4),
        "causation_id": None,
        "device_sequence": 1,
        "occurred_at": datetime(2026, 8, 27, 1, 2, 3, tzinfo=UTC),
        "sensitivity": Sensitivity.HOUSEHOLD,
        "payload_commitment": Commitment(
            algorithm="HMAC-SHA-256",
            key_id="audit-v1",
            value_b64="A" * 43 + "=",
        ),
        "payload": WakeDetectedPayload(
            kind="speech.wake_detected",
            turn_id=UUID(int=5),
            score_micros=900_000,
        ),
    }


def test_task1_version_and_task4_event_exports_are_preserved() -> None:
    assert tuntun_contracts.__version__ == "0.1.0.dev0"
    assert tuntun_contracts.EventEnvelope is EventEnvelope
    assert tuntun_contracts.WakeDetectedPayload is WakeDetectedPayload


def test_contracts_reject_extra_fields_and_naive_time() -> None:
    with pytest.raises(ValidationError):
        Commitment.model_validate(
            {
                "algorithm": "HMAC-SHA-256",
                "key_id": "audit-v1",
                "value_b64": "A" * 43 + "=",
                "extra": True,
            }
        )
    with pytest.raises(ValidationError, match="timezone"):
        EventEnvelope.model_validate(
            {
                **valid_python_event(),
                "occurred_at": datetime(2026, 8, 27, 1, 2, 3),
            }
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("device_sequence", "1"),
        ("device_sequence", True),
        ("schema_version", 1),
        ("event_id", str(UUID(int=1))),
        ("occurred_at", "2026-08-27T01:02:03Z"),
        ("event_type", "speech.wake_detected"),
    ),
)
def test_python_contract_path_rejects_all_coercion(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        EventEnvelope.model_validate({**valid_python_event(), field: value})


class _StringProbe(ContractModel):
    value: str


@pytest.mark.parametrize("value", (1, True, b"text", ["text"]))
def test_string_fields_never_coerce_non_strings(value: object) -> None:
    with pytest.raises(ValidationError):
        _StringProbe(value=value)  # type: ignore[arg-type]


def test_strict_json_path_accepts_only_json_native_uuid_and_time_strings() -> None:
    valid_wake_json = json.loads(
        canonical_bytes(EventEnvelope.model_validate(valid_python_event()))
    )
    parsed = EventEnvelope.model_validate_json(json.dumps(valid_wake_json), strict=True)
    assert parsed.event_id == UUID(valid_wake_json["event_id"])
    for field, value in (
        ("device_sequence", "1"),
        ("device_sequence", True),
        ("schema_version", 1),
    ):
        with pytest.raises(ValidationError):
            EventEnvelope.model_validate_json(
                json.dumps({**valid_wake_json, field: value}),
                strict=True,
            )


@pytest.mark.parametrize(
    "value",
    (
        "A" * 44,
        "A" * 42 + "==",
        "A" * 43,
        "A" * 43 + "==",
        "_" * 43 + "=",
        "A" * 42 + "B=",
    ),
)
def test_commitment_requires_canonical_base64_of_exactly_32_bytes(value: str) -> None:
    with pytest.raises(ValidationError):
        Commitment(
            algorithm="HMAC-SHA-256",
            key_id="audit-v1",
            value_b64=value,
        )


def test_contract_json_ingress_rejects_duplicates_nonfinite_size_and_noncanonical() -> None:
    commitment = Commitment(
        algorithm="HMAC-SHA-256",
        key_id="audit-v1",
        value_b64="A" * 43 + "=",
    )
    canonical = canonical_bytes(commitment)
    assert (
        parse_contract_json(
            Commitment,
            canonical,
            max_bytes=1_024,
            require_canonical=True,
        )
        == commitment
    )
    duplicate = (
        b'{"algorithm":"HMAC-SHA-256","algorithm":"HMAC-SHA-256",'
        b'"key_id":"audit-v1","value_b64":"' + b"A" * 43 + b'="}'
    )
    giant_decimal = b'{"x":0.' + b"1" * 65 + b"}"
    too_deep = b"[" * 33 + b"0" + b"]" * 33
    too_many = b"[" + b",".join((b"[]",) * 4_097) + b"]"
    too_flat = b"[" + b",".join((b"0",) * 16_385) + b"]"
    for raw in (
        duplicate,
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":-Infinity}',
        giant_decimal,
        b'{"x":1e999999}',
        b'{"x":1e-999999}',
        too_deep,
        too_many,
        too_flat,
    ):
        with pytest.raises(ContractParseError):
            parse_contract_json(
                Commitment,
                raw,
                max_bytes=32_000,
                require_canonical=False,
            )
    with pytest.raises(ContractParseError):
        parse_contract_json(
            Commitment,
            canonical,
            max_bytes=len(canonical) - 1,
            require_canonical=False,
        )
    noncanonical = json.dumps(
        commitment.model_dump(mode="json"),
        sort_keys=False,
    ).encode("utf-8")
    with pytest.raises(ContractParseError, match="not canonical"):
        parse_contract_json(
            Commitment,
            noncanonical,
            max_bytes=1_024,
            require_canonical=True,
        )
    assert (
        parse_contract_json(
            Commitment,
            noncanonical,
            max_bytes=1_024,
            require_canonical=False,
        )
        == commitment
    )


def test_bounded_json_value_is_reusable_without_a_contract_model() -> None:
    assert parse_bounded_json_value(
        b'{"vendor":true,"ports":[443,8443]}',
        max_bytes=64,
    ) == {"vendor": True, "ports": [443, 8443]}
    at_limit = b"[" + b",".join((b"0",) * 16_384) + b"]"
    parsed_at_limit = parse_bounded_json_value(at_limit, max_bytes=65_536)
    assert isinstance(parsed_at_limit, list)
    assert len(parsed_at_limit) == 16_384
    flat = b"[" + b",".join((b"0",) * 16_385) + b"]"
    with pytest.raises(ContractParseError, match="ingress rejected"):
        parse_bounded_json_value(flat, max_bytes=65_536)
    for raw in (b'{"x":1e999999}', b'{"x":1e-999999}'):
        with pytest.raises(ContractParseError, match="ingress rejected"):
            parse_bounded_json_value(raw, max_bytes=64)


@pytest.mark.parametrize("value", (JCS_MIN_SAFE_INTEGER, JCS_MAX_SAFE_INTEGER))
def test_jcs_safe_integer_boundaries_are_recursive_and_inclusive(value: int) -> None:
    raw = f'{{"nested":[{{"value":{value}}}]}}'.encode()
    assert parse_bounded_json_value(raw, max_bytes=128) == {"nested": [{"value": value}]}
    assert canonical_mapping_bytes({"nested": [{"value": value}]}) == raw


@pytest.mark.parametrize(
    "value",
    (JCS_MIN_SAFE_INTEGER - 1, JCS_MAX_SAFE_INTEGER + 1),
)
def test_jcs_unsafe_integers_fail_at_parse_model_and_canonical_boundaries(value: int) -> None:
    raw = f'{{"nested":[{{"value":{value}}}]}}'.encode()
    with pytest.raises(ContractParseError, match="ingress rejected"):
        parse_bounded_json_value(raw, max_bytes=128)
    with pytest.raises(ValidationError, match="safe integer"):
        _IntegerProbe(value={"nested": [value]})
    with pytest.raises(ContractParseError, match="canonicalization rejected"):
        canonical_mapping_bytes({"nested": [{"value": value}]})


class _CanonicalKind(StrEnum):
    SAMPLE = "sample"


class _NFCProbe(ContractModel):
    text: str
    nested: dict[str, tuple[str, ...]]


class _IntegerProbe(ContractModel):
    value: dict[str, list[int]]


class _NFCMaxLengthProbe(ContractModel):
    value: str = Field(max_length=1)


class _NFCMinLengthProbe(ContractModel):
    value: str = Field(min_length=2)


class _StrictJSONModeProbe(ContractModel):
    identifier: UUID
    occurred_at: AwareDatetime
    labels: tuple[str, ...]


def test_before_normalization_preserves_strict_json_native_conversions() -> None:
    parsed = _StrictJSONModeProbe.model_validate_json(
        b'{"identifier":"00000000-0000-0000-0000-000000000001",'
        b'"occurred_at":"2026-08-27T01:02:03Z","labels":["e\\u0301"]}',
        strict=True,
    )
    assert parsed.identifier == UUID(int=1)
    assert parsed.occurred_at == datetime(2026, 8, 27, 1, 2, 3, tzinfo=UTC)
    assert parsed.labels == ("\u00e9",)


def test_nfc_expansion_is_validated_before_max_length_in_python_and_json_modes() -> None:
    assert len("\u0344") == 1
    assert len("\u0308\u0301") == 2
    with pytest.raises(ValidationError):
        _NFCMaxLengthProbe(value="\u0344")
    with pytest.raises(ValidationError):
        _NFCMaxLengthProbe.model_validate_json(
            b'{"value":"\\u0344"}',
            strict=True,
        )


def test_nfc_contraction_is_validated_before_min_length_in_python_and_json_modes() -> None:
    assert len("e\u0301") == 2
    assert len("\u00e9") == 1
    with pytest.raises(ValidationError):
        _NFCMinLengthProbe(value="e\u0301")
    with pytest.raises(ValidationError):
        _NFCMinLengthProbe.model_validate_json(
            b'{"value":"e\\u0301"}',
            strict=True,
        )


def test_contract_ingress_normalizes_nfc_recursively_in_python_and_json_modes() -> None:
    python_value = _NFCProbe(text="e\u0301", nested={"a\u030a": ("n\u0303",)})
    json_value = _NFCProbe.model_validate_json(
        b'{"text":"e\\u0301","nested":{"a\\u030a":["n\\u0303"]}}',
        strict=True,
    )
    expected = _NFCProbe(text="\u00e9", nested={"\u00e5": ("\u00f1",)})
    assert python_value == json_value == expected
    with pytest.raises(ValidationError, match="collide after NFC"):
        _NFCProbe(
            text="ok",
            nested={"e\u0301": ("one",), "\u00e9": ("two",)},
        )


def test_shared_canonical_mapping_has_one_cross_phase_golden_encoding() -> None:
    value = {
        "text": "e\u0301",
        "time": datetime(
            2026,
            8,
            27,
            9,
            2,
            3,
            4,
            tzinfo=timezone(timedelta(hours=8)),
        ),
        "id": UUID(int=1),
        "kind": _CanonicalKind.SAMPLE,
        "blob": b"\x00\xff",
    }
    assert canonical_mapping_bytes(value) == (
        b'{"blob":"AP8=","id":"00000000-0000-0000-0000-000000000001",'
        b'"kind":"sample","text":"\xc3\xa9","time":"2026-08-27T01:02:03.000004Z"}'
    )


@pytest.mark.parametrize(
    "value",
    (
        {1: "non-string-key"},
        {"e\u0301": 1, "\u00e9": 2},
    ),
)
def test_shared_canonical_mapping_rejects_key_coercion_or_nfc_collision(
    value: object,
) -> None:
    mapping = cast(dict[str, object], value)
    with pytest.raises((TypeError, ValueError)):
        canonical_mapping_bytes(mapping)


def test_rfc8785_canonicalizer_faults_normalize_to_contract_parse_error() -> None:
    with pytest.raises(ContractParseError, match="canonicalization rejected"):
        canonical_mapping_bytes({"nested": [float("inf")]})
    with pytest.raises(ContractParseError, match="canonicalization rejected"):
        canonical_mapping_bytes({"nested": [chr(0xD800)]})


def test_model_type_is_validated_before_hostile_bytes() -> None:
    non_contract_type = cast(type[ContractModel], dict)
    with pytest.raises(TypeError, match="ContractModel"):
        parse_contract_json(non_contract_type, b"\xff", max_bytes=1)


def test_hostile_parse_faults_normalize_but_programmer_faults_propagate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ContractParseError):
        parse_bounded_json_value(b"\xff", max_bytes=64)
    with pytest.raises(ContractParseError):
        parse_contract_json(Commitment, b"{}", max_bytes=64)
    with pytest.raises(TypeError):
        parse_bounded_json_value("{}", max_bytes=64)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="configuration"):
        parse_bounded_json_value(b"{}", max_bytes=0)

    def unexpected_programmer_failure(*args: object, **kwargs: object) -> object:
        raise ValueError("injected programmer failure")

    monkeypatch.setattr(
        "tuntun_contracts.base.json.loads",
        unexpected_programmer_failure,
    )
    with pytest.raises(ValueError, match="injected programmer failure") as raised:
        parse_bounded_json_value(b"{}", max_bytes=64)
    assert type(raised.value) is ValueError
