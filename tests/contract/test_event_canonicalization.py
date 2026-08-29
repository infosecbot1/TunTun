from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError
from tuntun_contracts.base import (
    Commitment,
    Sensitivity,
    canonical_bytes,
    parse_contract_json,
)
from tuntun_contracts.events import (
    EventEnvelope,
    EventType,
    SignedEventEnvelope,
    WakeDetectedPayload,
)

VALID_SIGNATURE = base64.b64encode(bytes(range(64))).decode("ascii")
VALID_WAKE: dict[str, object] = {
    "schema_version": "1.0",
    "event_id": str(UUID(int=1)),
    "event_type": "speech.wake_detected",
    "household_id": str(UUID(int=2)),
    "device_id": str(UUID(int=3)),
    "session_id": None,
    "correlation_id": str(UUID(int=4)),
    "causation_id": None,
    "device_sequence": 1,
    "occurred_at": "2026-08-27T01:02:03.000004Z",
    "sensitivity": "household",
    "payload_commitment": {
        "algorithm": "HMAC-SHA-256",
        "key_id": "audit-v1",
        "value_b64": "A" * 43 + "=",
    },
    "payload": {
        "kind": "speech.wake_detected",
        "turn_id": str(UUID(int=5)),
        "score_micros": 900_000,
    },
}


def make_envelope() -> EventEnvelope:
    return EventEnvelope(
        schema_version="1.0",
        event_id=UUID(int=1),
        event_type=EventType.WAKE_DETECTED,
        household_id=UUID(int=2),
        device_id=UUID(int=3),
        session_id=None,
        correlation_id=UUID(int=4),
        causation_id=None,
        device_sequence=7,
        occurred_at=datetime(2026, 8, 27, 1, 2, 3, 4, UTC),
        sensitivity=Sensitivity.HOUSEHOLD,
        payload_commitment=Commitment(
            algorithm="HMAC-SHA-256",
            key_id="audit-v1",
            value_b64="A" * 43 + "=",
        ),
        payload=WakeDetectedPayload(
            kind="speech.wake_detected",
            turn_id=UUID(int=5),
            score_micros=900_000,
        ),
    )


def test_event_canonical_bytes_use_nfc_and_six_utc_digits() -> None:
    envelope = make_envelope()
    encoded = canonical_bytes(envelope)
    assert b'"occurred_at":"2026-08-27T01:02:03.000004Z"' in encoded
    assert encoded == canonical_bytes(envelope)


def test_event_type_must_equal_payload_kind() -> None:
    data = EventEnvelope.model_json_schema()
    assert data["title"] == "EventEnvelope"
    with pytest.raises(ValidationError, match="event_type must equal payload.kind"):
        EventEnvelope.model_validate_json(
            json.dumps({**VALID_WAKE, "event_type": "safety.stop_requested"}),
            strict=True,
        )


def test_signed_event_signing_input_is_exactly_the_canonical_envelope() -> None:
    envelope = make_envelope()
    first = SignedEventEnvelope(
        envelope=envelope,
        signing_key_id="ed25519:reachy-edge-01:v1",
        signature_b64=VALID_SIGNATURE,
    )
    second = SignedEventEnvelope(
        envelope=envelope,
        signing_key_id="ed25519:reachy-edge-02:v2",
        signature_b64=base64.b64encode(bytes(reversed(range(64)))).decode("ascii"),
    )
    expected = canonical_bytes(envelope)
    assert first.signing_bytes() == second.signing_bytes() == expected
    assert b"signing_key_id" not in expected
    assert b"signature_b64" not in expected


def test_signed_event_accepts_one_canonical_64_byte_ed25519_signature() -> None:
    signed = SignedEventEnvelope(
        envelope=make_envelope(),
        signing_key_id="ed25519:reachy-edge-01:v1",
        signature_b64=VALID_SIGNATURE,
    )
    assert len(signed.signature_b64) == 88
    assert len(base64.b64decode(signed.signature_b64, validate=True)) == 64
    encoded = canonical_bytes(signed)
    assert (
        parse_contract_json(
            SignedEventEnvelope,
            encoded,
            max_bytes=8_192,
            require_canonical=True,
        )
        == signed
    )


@pytest.mark.parametrize(
    "signature",
    (
        base64.b64encode(bytes(63)).decode("ascii"),
        base64.b64encode(bytes(65)).decode("ascii"),
        VALID_SIGNATURE.rstrip("="),
        base64.urlsafe_b64encode(bytes([255]) * 64).decode("ascii"),
        "A" * 86 + "=A",
        "!" + VALID_SIGNATURE[1:],
    ),
)
def test_signed_event_rejects_wrong_length_alphabet_padding_or_noncanonical_base64(
    signature: str,
) -> None:
    with pytest.raises(ValidationError, match="signature"):
        SignedEventEnvelope(
            envelope=make_envelope(),
            signing_key_id="ed25519:reachy-edge-01:v1",
            signature_b64=signature,
        )


@pytest.mark.parametrize(
    "key_id",
    (
        "ED25519:reachy-edge-01:v1",
        "ed25519:-reachy:v1",
        "ed25519:reachy edge:v1",
        "ed25519:reachy:v0",
        "ed25519:reachy:v01",
        "ed25519:reachy:extra:v1",
        "ed25519:" + "a" * 65 + ":v1",
    ),
)
def test_signed_event_rejects_every_key_id_outside_the_closed_grammar(
    key_id: str,
) -> None:
    with pytest.raises(ValidationError, match="signing_key_id"):
        SignedEventEnvelope(
            envelope=make_envelope(),
            signing_key_id=key_id,
            signature_b64=VALID_SIGNATURE,
        )
