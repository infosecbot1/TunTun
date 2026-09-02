from __future__ import annotations

import base64
import hashlib
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from tuntun_contracts.base import ContractModel, Sensitivity, canonical_bytes
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.events import (
    EventEnvelope,
    EventType,
    SignedEventEnvelope,
    StopRequestedPayload,
)
from tuntun_contracts.reachy_control import (
    HmacKeyEpoch,
    PairingMaterial,
    RotationKeyring,
    sign_envelope,
    verify_envelope,
)
from tuntun_edge.transport.protocol import (
    sign_envelope as edge_sign_envelope,
)
from tuntun_edge.transport.protocol import (
    verify_envelope as edge_verify_envelope,
)

HOUSEHOLD_ID = UUID("00000000-0000-0000-0000-000000000901")
DEVICE_ID = UUID("00000000-0000-0000-0000-000000000902")
OTHER_ID = UUID("00000000-0000-0000-0000-000000000903")
EVENT_ID = UUID("00000000-0000-0000-0000-000000000904")
CORRELATION_ID = UUID("00000000-0000-0000-0000-000000000905")
NOW = datetime(2026, 8, 27, 1, 2, 3, 4, tzinfo=UTC)
SINGAPORE_NOW = NOW.astimezone(timezone(timedelta(hours=8)))
SIGNING_KEY_ID = "ed25519:reachy-edge:v1"
OTHER_SIGNING_KEY_ID = "ed25519:reachy-edge:v2"
HMAC_KEY_ID = "hmac:reachy-edge:v1"
OTHER_HMAC_KEY_ID = "hmac:reachy-edge:v2"
HMAC_ROOT = bytes(range(32))
OTHER_HMAC_ROOT = bytes(reversed(range(32)))


class AcceptAllPrivateKey:
    def sign(self, data: bytes) -> bytes:
        return bytes(64)


class AcceptAllPublicKey:
    def verify(self, signature: bytes, data: bytes) -> None:
        return None


class ForgingEd25519PrivateKey(Ed25519PrivateKey):
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    def sign(self, data: bytes) -> bytes:
        return bytes(64)

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: object,
    ) -> bytes:
        return self._private_key.private_bytes(
            encoding,
            format,
            encryption_algorithm,
        )

    def private_bytes_raw(self) -> bytes:
        return self._private_key.private_bytes_raw()

    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def __copy__(self) -> Ed25519PrivateKey:
        return self


class AcceptAllEd25519PublicKey(Ed25519PublicKey):
    def __init__(self, public_key: Ed25519PublicKey) -> None:
        self._public_key = public_key

    def verify(self, signature: bytes, data: bytes) -> None:
        return None

    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:
        return self._public_key.public_bytes(encoding, format)

    def public_bytes_raw(self) -> bytes:
        return self._public_key.public_bytes_raw()

    def __eq__(self, other: object) -> bool:
        return self is other

    def __copy__(self) -> Ed25519PublicKey:
        return self


class ShortExportEd25519PrivateKey(ForgingEd25519PrivateKey):
    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: object,
    ) -> bytes:
        return b"short"

    def private_bytes_raw(self) -> bytes:
        return b"short"


class ShortExportEd25519PublicKey(AcceptAllEd25519PublicKey):
    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:
        return b"short"

    def public_bytes_raw(self) -> bytes:
        return b"short"


class CallerControlledSignedEnvelope:
    def __init__(
        self,
        *,
        envelope: EventEnvelope,
        signing_key_id: str,
        signature_b64: str,
        signing_bytes: bytes,
    ) -> None:
        self.envelope = envelope
        self.signing_key_id = signing_key_id
        self.signature_b64 = signature_b64
        self._signing_bytes = signing_bytes

    def signing_bytes(self) -> bytes:
        return self._signing_bytes


class EventEnvelopeSubclass(EventEnvelope):
    pass


class StatefulHmacKeyEpoch(HmacKeyEpoch):
    __slots__ = ("_value_reads",)

    def __init__(self) -> None:
        super().__init__(
            key_id=HMAC_KEY_ID,
            generation=1,
            sha256=hashlib.sha256(HMAC_ROOT).hexdigest(),
            value=HMAC_ROOT,
            active_from=NOW - timedelta(seconds=30),
            accept_until=NOW + timedelta(seconds=30),
        )
        object.__setattr__(self, "_value_reads", 0)

    @property
    def value(self) -> bytes:
        value_reads = self._value_reads
        object.__setattr__(self, "_value_reads", value_reads + 1)
        if value_reads == 0:
            return HMAC_ROOT
        return OTHER_HMAC_ROOT


def _payload(source: str = "edge_keyword") -> StopRequestedPayload:
    return StopRequestedPayload(
        kind="safety.stop_requested",
        turn_id=None,
        source=source,  # type: ignore[arg-type]
    )


def _event(
    *,
    root: bytes = HMAC_ROOT,
    hmac_key_id: str = HMAC_KEY_ID,
    occurred_at: datetime = NOW,
    purpose: str | None = None,
    payload: StopRequestedPayload | None = None,
) -> EventEnvelope:
    concrete_payload = payload or _payload()
    event_type = EventType.STOP_REQUESTED
    return EventEnvelope(
        schema_version="1.0",
        event_id=EVENT_ID,
        event_type=event_type,
        household_id=HOUSEHOLD_ID,
        device_id=DEVICE_ID,
        session_id=None,
        correlation_id=CORRELATION_ID,
        causation_id=None,
        device_sequence=7,
        occurred_at=occurred_at,
        sensitivity=Sensitivity.HOUSEHOLD,
        payload_commitment=commit_private(
            root,
            hmac_key_id,
            purpose or event_type.value,
            canonical_bytes(concrete_payload),
        ),
        payload=concrete_payload,
    )


def _sign_direct(
    private_key: Ed25519PrivateKey,
    envelope: EventEnvelope,
    *,
    signing_key_id: str = SIGNING_KEY_ID,
) -> SignedEventEnvelope:
    signature_b64 = base64.b64encode(private_key.sign(canonical_bytes(envelope))).decode("ascii")
    return SignedEventEnvelope(
        envelope=envelope,
        signing_key_id=signing_key_id,
        signature_b64=signature_b64,
    )


def _verify(
    public_key,
    signed: SignedEventEnvelope,
    *,
    hmac_keys: dict[str, bytes] | None = None,
    signing_key_id: str = SIGNING_KEY_ID,
    household_id: UUID = HOUSEHOLD_ID,
    device_id: UUID = DEVICE_ID,
    now: datetime = NOW,
) -> EventEnvelope:
    return verify_envelope(
        public_key,
        signing_key_id,
        hmac_keys or {HMAC_KEY_ID: HMAC_ROOT},
        signed,
        household_id,
        device_id,
        now,
    )


def test_sign_envelope_rejects_mismatched_payload_commitment_before_signing() -> None:
    private_key = Ed25519PrivateKey.generate()
    tampered = _event().model_copy(update={"payload": _payload(source="owner_console")})

    with pytest.raises(ValueError, match="invalid payload commitment"):
        sign_envelope(private_key, SIGNING_KEY_ID, HMAC_ROOT, tampered)


def test_sign_envelope_rejects_duck_typed_private_key() -> None:
    with pytest.raises(TypeError, match="Ed25519 private key required"):
        sign_envelope(AcceptAllPrivateKey(), SIGNING_KEY_ID, HMAC_ROOT, _event())  # type: ignore[arg-type]


def test_sign_envelope_reconstructs_trusted_private_key_before_signing() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = sign_envelope(
        ForgingEd25519PrivateKey(private_key),
        SIGNING_KEY_ID,
        HMAC_ROOT,
        _event(),
    )
    signature = base64.b64decode(signed.signature_b64, validate=True)

    assert signature != bytes(64)
    private_key.public_key().verify(signature, signed.signing_bytes())


def test_sign_envelope_rejects_malformed_private_key_raw_export() -> None:
    private_key = Ed25519PrivateKey.generate()

    with pytest.raises(ValueError, match="invalid Ed25519 private key"):
        sign_envelope(
            ShortExportEd25519PrivateKey(private_key),
            SIGNING_KEY_ID,
            HMAC_ROOT,
            _event(),
        )


def test_verify_accepts_current_server_resolved_keys() -> None:
    private_key = Ed25519PrivateKey.generate()
    event = _event()
    signed = sign_envelope(private_key, SIGNING_KEY_ID, HMAC_ROOT, event)

    assert _verify(private_key.public_key(), signed) == event


def test_verify_rejects_duck_typed_public_key_that_accepts_all_signatures() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = sign_envelope(private_key, SIGNING_KEY_ID, HMAC_ROOT, _event())
    forged = signed.model_copy(
        update={"signature_b64": base64.b64encode(bytes(64)).decode("ascii")},
    )

    with pytest.raises(TypeError, match="Ed25519 public key required"):
        _verify(AcceptAllPublicKey(), forged)


def test_verify_reconstructs_trusted_public_key_before_verifying() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = sign_envelope(private_key, SIGNING_KEY_ID, HMAC_ROOT, _event())
    forged = signed.model_copy(
        update={"signature_b64": base64.b64encode(bytes(64)).decode("ascii")},
    )

    with pytest.raises(ValueError, match="invalid envelope signature"):
        _verify(AcceptAllEd25519PublicKey(private_key.public_key()), forged)


def test_verify_rejects_malformed_public_key_raw_export() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = sign_envelope(private_key, SIGNING_KEY_ID, HMAC_ROOT, _event())

    with pytest.raises(ValueError, match="invalid Ed25519 public key"):
        _verify(ShortExportEd25519PublicKey(private_key.public_key()), signed)


def test_verify_rejects_caller_controlled_signed_envelope_signing_bytes() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = sign_envelope(private_key, SIGNING_KEY_ID, HMAC_ROOT, _event())
    tampered_envelope = _event(payload=_payload(source="owner_console"))
    forged = CallerControlledSignedEnvelope(
        envelope=tampered_envelope,
        signing_key_id=signed.signing_key_id,
        signature_b64=signed.signature_b64,
        signing_bytes=signed.signing_bytes(),
    )

    with pytest.raises(TypeError, match="signed event envelope required"):
        _verify(private_key.public_key(), forged)  # type: ignore[arg-type]


def test_verify_rejects_non_exact_event_envelope() -> None:
    private_key = Ed25519PrivateKey.generate()
    event = _event()
    subclass_event = EventEnvelopeSubclass.model_validate(event.model_dump())
    signature_b64 = base64.b64encode(private_key.sign(canonical_bytes(subclass_event))).decode(
        "ascii",
    )
    signed = SignedEventEnvelope(
        envelope=event,
        signing_key_id=SIGNING_KEY_ID,
        signature_b64=signature_b64,
    )
    object.__setattr__(signed, "envelope", subclass_event)

    with pytest.raises(TypeError, match="event envelope required"):
        _verify(private_key.public_key(), signed)


def test_verify_rejects_wrong_hmac_purpose() -> None:
    private_key = Ed25519PrivateKey.generate()
    event = _event(purpose="safety.wrong_purpose")
    signed = _sign_direct(private_key, event)

    with pytest.raises(ValueError, match="invalid payload commitment"):
        _verify(private_key.public_key(), signed)


def test_verify_rejects_wrong_hmac_key_id() -> None:
    private_key = Ed25519PrivateKey.generate()
    event = _event(hmac_key_id=OTHER_HMAC_KEY_ID)
    signed = sign_envelope(private_key, SIGNING_KEY_ID, HMAC_ROOT, event)

    with pytest.raises(ValueError, match="unknown or revoked HMAC key"):
        _verify(private_key.public_key(), signed)


def test_verify_rejects_wrong_signing_key_id() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = sign_envelope(private_key, SIGNING_KEY_ID, HMAC_ROOT, _event())
    wrong_key_id = SignedEventEnvelope(
        envelope=signed.envelope,
        signing_key_id=OTHER_SIGNING_KEY_ID,
        signature_b64=signed.signature_b64,
    )

    with pytest.raises(ValueError, match="unknown or revoked signing key"):
        _verify(private_key.public_key(), wrong_key_id)


@pytest.mark.parametrize(
    ("household_id", "device_id"),
    ((OTHER_ID, DEVICE_ID), (HOUSEHOLD_ID, OTHER_ID)),
)
def test_verify_rejects_household_or_device_scope_mismatch(
    household_id: UUID,
    device_id: UUID,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = sign_envelope(private_key, SIGNING_KEY_ID, HMAC_ROOT, _event())

    with pytest.raises(ValueError, match="event scope mismatch"):
        _verify(
            private_key.public_key(),
            signed,
            household_id=household_id,
            device_id=device_id,
        )


def test_verify_accepts_timestamps_exactly_thirty_seconds_from_utc_normalized_event() -> None:
    private_key = Ed25519PrivateKey.generate()
    event = _event(occurred_at=SINGAPORE_NOW)
    signed = sign_envelope(private_key, SIGNING_KEY_ID, HMAC_ROOT, event)

    assert _verify(private_key.public_key(), signed, now=NOW - timedelta(seconds=30)) == event
    assert _verify(private_key.public_key(), signed, now=NOW + timedelta(seconds=30)) == event


@pytest.mark.parametrize("offset", (-31, 31))
def test_verify_rejects_timestamps_just_outside_thirty_second_window(offset: int) -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = sign_envelope(private_key, SIGNING_KEY_ID, HMAC_ROOT, _event())

    with pytest.raises(ValueError, match="stale event timestamp"):
        _verify(private_key.public_key(), signed, now=NOW + timedelta(seconds=offset))


def test_verify_rejects_naive_now_or_event_timestamp() -> None:
    private_key = Ed25519PrivateKey.generate()
    event = _event()
    signed = sign_envelope(private_key, SIGNING_KEY_ID, HMAC_ROOT, event)

    with pytest.raises(ValueError, match="timestamp must be timezone-aware"):
        _verify(private_key.public_key(), signed, now=NOW.replace(tzinfo=None))

    naive_event = event.model_copy(update={"occurred_at": NOW.replace(tzinfo=None)})
    naive_signed = signed.model_copy(update={"envelope": naive_event})

    with pytest.raises(ValueError, match="timestamp must be timezone-aware"):
        _verify(private_key.public_key(), naive_signed)


def test_verify_rejects_invalid_ed25519_signature() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = sign_envelope(private_key, SIGNING_KEY_ID, HMAC_ROOT, _event())
    invalid = SignedEventEnvelope(
        envelope=signed.envelope,
        signing_key_id=signed.signing_key_id,
        signature_b64=base64.b64encode(bytes(64)).decode("ascii"),
    )

    with pytest.raises(ValueError, match="invalid envelope signature"):
        _verify(private_key.public_key(), invalid)


def test_signed_event_uses_existing_contract_signing_bytes() -> None:
    private_key = Ed25519PrivateKey.generate()
    event = _event()
    signed = sign_envelope(private_key, SIGNING_KEY_ID, HMAC_ROOT, event)
    signature = base64.b64decode(signed.signature_b64, validate=True)

    assert signed.signing_bytes() == canonical_bytes(event)
    private_key.public_key().verify(signature, signed.signing_bytes())
    with pytest.raises(InvalidSignature):
        private_key.public_key().verify(signature, canonical_bytes(signed))


def test_sign_and_verify_reject_wrong_hmac_root_length() -> None:
    private_key = Ed25519PrivateKey.generate()
    event = _event()

    with pytest.raises(ValueError, match="HMAC root must be 32 bytes"):
        sign_envelope(private_key, SIGNING_KEY_ID, b"short", event)

    signed = sign_envelope(private_key, SIGNING_KEY_ID, HMAC_ROOT, event)
    with pytest.raises(ValueError, match="HMAC root must be 32 bytes"):
        _verify(private_key.public_key(), signed, hmac_keys={HMAC_KEY_ID: b"short"})


def test_payload_commitment_comparison_uses_constant_time_compare(monkeypatch) -> None:
    import tuntun_contracts.reachy_control as reachy_control

    calls: list[tuple[object, object]] = []
    original = reachy_control.hmac.compare_digest

    def spy(left: object, right: object) -> bool:
        calls.append((left, right))
        return original(left, right)

    monkeypatch.setattr(reachy_control.hmac, "compare_digest", spy)
    private_key = Ed25519PrivateKey.generate()
    event = _event()
    signed = sign_envelope(private_key, SIGNING_KEY_ID, HMAC_ROOT, event)

    assert _verify(private_key.public_key(), signed) == event
    expected = commit_private(
        HMAC_ROOT,
        HMAC_KEY_ID,
        event.event_type.value,
        canonical_bytes(event.payload),
    ).value_b64
    assert (expected, event.payload_commitment.value_b64) in calls


def test_edge_protocol_reexports_shared_contract_implementation() -> None:
    assert edge_sign_envelope is sign_envelope
    assert edge_verify_envelope is verify_envelope


def _digest(label: bytes) -> str:
    return hashlib.sha256(label).hexdigest()


def _pairing_material(**updates: object) -> PairingMaterial:
    values = {
        "server_key_id": "ed25519:reachy-server:v1",
        "server_public_key_sha256": _digest(b"server-public"),
        "tls_key_id": "tls:reachy-edge:v1",
        "tls_key_generation": 1,
        "signing_key_id": SIGNING_KEY_ID,
        "signing_key_generation": 1,
        "signing_public_key_sha256": _digest(b"signing-public"),
        "hmac_key_id": HMAC_KEY_ID,
        "hmac_key_generation": 1,
        "hmac_key_sha256": hashlib.sha256(HMAC_ROOT).hexdigest(),
        "endpoint_generation": 1,
        "certificate_generation": 1,
        "server_key_generation": 1,
        "trust_digest_generation": 1,
        "household_ca_sha256": _digest(b"household-ca"),
        "server_leaf_sha256": _digest(b"server-leaf"),
        "client_certificate_sha256": _digest(b"client-certificate"),
    }
    values.update(updates)
    return PairingMaterial(**values)


def test_pairing_material_accepts_public_binding_metadata_without_raw_roots() -> None:
    material = _pairing_material()

    assert not isinstance(material, ContractModel)
    assert not hasattr(material, "model_dump")
    assert material.server_public_key_sha256 == _digest(b"server-public")
    assert material.hmac_key_sha256 == hashlib.sha256(HMAC_ROOT).hexdigest()
    assert not hasattr(material, "hmac_root")
    assert not hasattr(material, "private_key")


@pytest.mark.parametrize(
    "field",
    (
        "server_public_key_sha256",
        "signing_public_key_sha256",
        "hmac_key_sha256",
        "household_ca_sha256",
        "server_leaf_sha256",
        "client_certificate_sha256",
    ),
)
def test_pairing_material_rejects_non_lower_case_sha256_digests(field: str) -> None:
    with pytest.raises(ValueError, match="pairing digest must be lower-case SHA-256"):
        _pairing_material(**{field: "A" * 64})

    with pytest.raises(ValueError, match="pairing digest must be lower-case SHA-256"):
        _pairing_material(**{field: "0" * 63})


@pytest.mark.parametrize(
    "field",
    (
        "tls_key_generation",
        "signing_key_generation",
        "hmac_key_generation",
        "endpoint_generation",
        "certificate_generation",
        "server_key_generation",
        "trust_digest_generation",
    ),
)
def test_pairing_material_rejects_non_positive_generations(field: str) -> None:
    with pytest.raises(ValueError, match="pairing generations must be positive"):
        _pairing_material(**{field: 0})


def test_pairing_material_rejects_duplicate_or_blank_identifiers() -> None:
    with pytest.raises(ValueError, match="pairing identifiers must be distinct"):
        _pairing_material(hmac_key_id=SIGNING_KEY_ID)

    with pytest.raises(ValueError, match="pairing identifiers must be non-empty strings"):
        _pairing_material(tls_key_id="")

    with pytest.raises(ValueError, match="pairing identifiers must use closed grammar"):
        _pairing_material(tls_key_id="tls reachy edge")

    with pytest.raises(ValueError, match="pairing identifiers must use closed grammar"):
        _pairing_material(signing_key_id="reachy-device-sign-v1")


def _epoch(
    *,
    key_id: str = HMAC_KEY_ID,
    root: bytes = HMAC_ROOT,
    generation: int = 1,
    sha256: str | None = None,
    active_from: datetime = NOW - timedelta(seconds=30),
    accept_until: datetime = NOW + timedelta(seconds=30),
) -> HmacKeyEpoch:
    return HmacKeyEpoch(
        key_id=key_id,
        generation=generation,
        sha256=sha256 or hashlib.sha256(root).hexdigest(),
        value=root,
        active_from=active_from,
        accept_until=accept_until,
    )


def test_rotation_keyring_accepts_only_inclusive_aware_utc_epoch_boundaries() -> None:
    epoch = _epoch(active_from=NOW, accept_until=NOW + timedelta(seconds=30))
    keyring = RotationKeyring((epoch,))

    assert keyring.accepted(NOW) == {HMAC_KEY_ID: HMAC_ROOT}
    assert keyring.accepted(NOW + timedelta(seconds=30)) == {HMAC_KEY_ID: HMAC_ROOT}
    assert keyring.accepted(NOW - timedelta(microseconds=1)) == {}
    assert keyring.accepted(NOW + timedelta(seconds=30, microseconds=1)) == {}

    with pytest.raises(ValueError, match="timestamp must be timezone-aware"):
        keyring.accepted(NOW.replace(tzinfo=None))


def test_rotation_keyring_normalizes_epoch_bounds_to_utc() -> None:
    epoch = _epoch(
        active_from=SINGAPORE_NOW,
        accept_until=SINGAPORE_NOW + timedelta(seconds=30),
    )
    keyring = RotationKeyring((epoch,))

    assert keyring.accepted(NOW) == {HMAC_KEY_ID: HMAC_ROOT}


def test_rotation_keyring_rejects_duplicate_key_ids_without_overwrite() -> None:
    current = _epoch()
    duplicate = _epoch(generation=2, root=OTHER_HMAC_ROOT)

    with pytest.raises(ValueError, match="duplicate HMAC key epoch id"):
        RotationKeyring((current, duplicate))


def test_rotation_keyring_verifies_digest_before_exposing_root() -> None:
    wrong_digest = hashlib.sha256(OTHER_HMAC_ROOT).hexdigest()

    with pytest.raises(PermissionError, match="pairing_key_digest_mismatch"):
        RotationKeyring((_epoch(sha256=wrong_digest),))


def test_rotation_keyring_rejects_epoch_reassignment_after_validation() -> None:
    keyring = RotationKeyring((_epoch(),))

    with pytest.raises(AttributeError, match="RotationKeyring is immutable"):
        keyring._epochs = (_epoch(key_id=OTHER_HMAC_KEY_ID, root=OTHER_HMAC_ROOT),)  # type: ignore[attr-defined]


def test_rotation_keyring_revalidates_epochs_before_exposing_roots() -> None:
    keyring = RotationKeyring((_epoch(),))
    bypassed_epoch = _epoch(
        key_id=OTHER_HMAC_KEY_ID,
        root=OTHER_HMAC_ROOT,
        sha256=hashlib.sha256(HMAC_ROOT).hexdigest(),
    )

    object.__setattr__(keyring, "_epochs", (bypassed_epoch,))

    with pytest.raises(PermissionError, match="pairing_key_digest_mismatch"):
        keyring.accepted(NOW)


def test_rotation_keyring_rejects_stateful_epoch_subclass_before_exposing_root() -> None:
    keyring = RotationKeyring((_epoch(),))
    object.__setattr__(keyring, "_epochs", (StatefulHmacKeyEpoch(),))

    with pytest.raises(TypeError, match="HMAC key epoch required"):
        keyring.accepted(NOW)


def test_hmac_key_epoch_keeps_raw_root_runtime_only_and_immutable() -> None:
    epoch = _epoch()

    assert epoch.value == HMAC_ROOT
    assert not is_dataclass(epoch)
    with pytest.raises(TypeError, match="dataclass"):
        asdict(epoch)
    with pytest.raises(TypeError, match="__dict__"):
        vars(epoch)

    rendered = repr(epoch)
    assert repr(HMAC_ROOT) not in rendered
    assert "value=" not in rendered

    with pytest.raises(AttributeError, match="HMAC key epoch is immutable"):
        epoch.value = OTHER_HMAC_ROOT  # type: ignore[misc]
    with pytest.raises(AttributeError, match="HMAC key epoch is immutable"):
        epoch.key_id = OTHER_HMAC_KEY_ID  # type: ignore[misc]


def test_hmac_key_epoch_repr_does_not_include_raw_root() -> None:
    epoch = _epoch()

    assert repr(HMAC_ROOT) not in repr(epoch)
    assert "value=" not in repr(epoch)


@pytest.mark.parametrize(
    ("updates", "message"),
    (
        ({"root": b"short"}, "HMAC root must be 32 bytes"),
        ({"generation": 0}, "HMAC key generation must be positive"),
        ({"key_id": "bad key id"}, "HMAC key id must use closed grammar"),
        ({"sha256": "A" * 64}, "HMAC key digest must be lower-case SHA-256"),
        (
            {"active_from": NOW.replace(tzinfo=None)},
            "HMAC key epoch bounds must be timezone-aware",
        ),
        (
            {"accept_until": NOW - timedelta(seconds=31)},
            "HMAC key epoch accept_until before active_from",
        ),
    ),
)
def test_hmac_key_epoch_rejects_invalid_rotation_metadata(
    updates: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _epoch(**updates)
