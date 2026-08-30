from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from threading import Event, Lock, local
from typing import Any, cast
from uuid import UUID

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import ValidationError
from tuntun_core.adapters.sqlcipher import crypto
from tuntun_core.adapters.sqlcipher.crypto import EncryptedRecord, RecordCipher, RecordContext

ROOT_KEY = bytes(range(32))
CTX = RecordContext(
    household_id=UUID(int=1),
    table="biometric_templates",
    row_id=UUID(int=2),
    purpose="voice-template",
    schema_version="1.0",
)


class _ScriptedNonces:
    def __init__(self, *values: bytes) -> None:
        self._values = iter(values)
        self._lock = Lock()
        self.calls = 0

    def __call__(self) -> bytes:
        with self._lock:
            self.calls += 1
            return next(self._values)


class _DerivedUUID(UUID):
    pass


class _PausingConcurrentNonces:
    def __init__(self) -> None:
        self.first_entered = Event()
        self.release_first = Event()
        self.second_entered = Event()
        self._caller = local()

    def bind_caller(self, name: str) -> None:
        self._caller.name = name
        self._caller.index = 0

    def __call__(self) -> bytes:
        name = cast(str, self._caller.name)
        index = cast(int, self._caller.index) + 1
        self._caller.index = index
        if name == "first" and index == 1:
            self.first_entered.set()
            if not self.release_first.wait(timeout=5):
                raise AssertionError("first nonce source was not released")
        elif name == "second" and index == 1:
            self.second_entered.set()
        return {
            ("first", 1): b"A" * 12,
            ("first", 2): b"B" * 12,
            ("second", 1): b"C" * 12,
            ("second", 2): b"D" * 12,
        }[(name, index)]


def test_record_round_trip_and_every_context_identity_is_authenticated() -> None:
    cipher = RecordCipher(ROOT_KEY)
    plaintext = b"private-template-sentinel"

    encrypted = cipher.encrypt(plaintext, CTX)

    assert plaintext not in encrypted.ciphertext
    assert cipher.decrypt(encrypted, CTX) == plaintext
    other_contexts = (
        RecordContext.model_validate(CTX.model_dump() | {"household_id": UUID(int=9)}),
        RecordContext.model_validate(CTX.model_dump() | {"row_id": UUID(int=3)}),
        RecordContext.model_validate(CTX.model_dump() | {"purpose": "face-template"}),
        RecordContext(
            household_id=UUID(int=1),
            table="memory_embeddings",
            row_id=UUID(int=2),
            purpose="memory-embedding",
            schema_version="1.0",
        ),
    )
    for other in other_contexts:
        with pytest.raises(InvalidTag):
            cipher.decrypt(encrypted, other)


def test_record_context_is_closed_frozen_nfc_normalized_and_canonical() -> None:
    assert CTX.associated_data("record-data") == (
        b'{"domain":"record-data","household_id":"00000000-0000-0000-0000-000000000001",'
        b'"purpose":"voice-template","row_id":"00000000-0000-0000-0000-000000000002",'
        b'"schema_version":"1.0","table":"biometric_templates"}'
    )
    assert CTX.associated_data("dek-wrap") == (
        b'{"domain":"dek-wrap","household_id":"00000000-0000-0000-0000-000000000001",'
        b'"purpose":"voice-template","row_id":"00000000-0000-0000-0000-000000000002",'
        b'"schema_version":"1.0","table":"biometric_templates"}'
    )
    with pytest.raises(ValueError, match="associated-data domain"):
        CTX.associated_data(cast(Any, "caller-authored"))
    with pytest.raises(TypeError, match="associated-data domain"):
        CTX.associated_data(cast(Any, type("Domain", (str,), {})("record-data")))
    for hostile in (
        {"purpose": "voice-te\u0301mplate"},
        {"purpose": "status"},
        {"table": "biometric_templates-extra"},
        {"schema_version": "1.1"},
        {"extra": "caller-authored-aad"},
        {"table": "memory_embeddings", "purpose": "voice-template"},
        {"household_id": _DerivedUUID(int=1)},
    ):
        with pytest.raises(ValidationError):
            RecordContext.model_validate(CTX.model_dump() | hostile)
    with pytest.raises(ValidationError, match="frozen"):
        CTX.row_id = UUID(int=99)  # type: ignore[misc]


class _HostileBytes(bytes):
    def __len__(self) -> int:
        raise AssertionError("bytes-subclass-length-hook")


class _HostileStr(str):
    def __eq__(self, other: object) -> bool:
        del other
        raise AssertionError("str-subclass-equality-hook")


@pytest.mark.parametrize(
    ("root_key", "error"),
    (
        (bytearray(32), TypeError),
        (memoryview(bytes(32)), TypeError),
        (_HostileBytes(bytes(32)), TypeError),
        (b"short", ValueError),
        (bytes(33), ValueError),
    ),
)
def test_record_cipher_rejects_non_exact_or_wrong_length_root_keys(
    root_key: object,
    error: type[Exception],
) -> None:
    with pytest.raises(error, match="root key"):
        RecordCipher(cast(Any, root_key))


@pytest.mark.parametrize(
    "root_key_id",
    (
        "",
        "x" * 129,
        "records v1",
        "records/v1",
        "r\u00e9cords-v1",
        _HostileStr("records-v1"),
    ),
)
def test_record_cipher_rejects_noncanonical_root_key_ids(root_key_id: object) -> None:
    error = TypeError if type(root_key_id) is not str else ValueError
    with pytest.raises(error, match="root key id"):
        RecordCipher(ROOT_KEY, cast(Any, root_key_id))


def test_record_cipher_rejects_noncallable_nonce_source() -> None:
    with pytest.raises(TypeError, match="nonce source"):
        RecordCipher(ROOT_KEY, nonce_source=cast(Any, True))


def test_encrypted_record_has_an_immutable_exact_validated_shape() -> None:
    valid: dict[str, object] = {
        "ciphertext": bytes(16),
        "nonce": b"D" * 12,
        "wrapped_dek": bytes(48),
        "wrap_nonce": b"W" * 12,
        "root_key_id": "records-v1",
    }
    record = EncryptedRecord(**cast(Any, valid))
    with pytest.raises(FrozenInstanceError):
        record.nonce = b"N" * 12  # type: ignore[misc]
    malformed = (
        {"ciphertext": bytearray(16)},
        {"ciphertext": bytes(15)},
        {"nonce": bytes(11)},
        {"wrapped_dek": bytes(47)},
        {"wrap_nonce": bytes(13)},
        {"wrap_nonce": b"D" * 12},
        {"root_key_id": "invalid key id"},
    )
    for change in malformed:
        with pytest.raises((TypeError, ValueError)):
            EncryptedRecord(**cast(Any, valid | change))


def test_encrypt_snapshots_exact_bytes_and_valid_context_before_randomness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    random_calls: list[int] = []
    nonces = _ScriptedNonces(b"D" * 12, b"W" * 12)

    def tracking_random(size: int) -> bytes:
        random_calls.append(size)
        return bytes(size)

    monkeypatch.setattr(crypto.os, "urandom", tracking_random)
    cipher = RecordCipher(ROOT_KEY, nonce_source=nonces)
    for plaintext in (bytearray(b"mutable"), memoryview(b"view"), _HostileBytes(b"subclass")):
        with pytest.raises(TypeError, match="plaintext"):
            cipher.encrypt(cast(Any, plaintext), CTX)

    class DerivedContext(RecordContext):
        pass

    derived = DerivedContext.model_validate(CTX.model_dump())
    with pytest.raises(TypeError, match="context"):
        cipher.encrypt(b"data", derived)
    invalid = RecordContext.model_validate(CTX.model_dump())
    object.__setattr__(invalid, "purpose", "memory-embedding")
    with pytest.raises(ValidationError):
        cipher.encrypt(b"data", invalid)
    assert random_calls == []
    assert nonces.calls == 0


@pytest.mark.parametrize(
    "script",
    (
        (b"D" * 12, b"W" * 12, b"D" * 12, b"X" * 12),
        (b"D" * 12, b"W" * 12, b"W" * 12, b"X" * 12),
        (b"D" * 12, b"W" * 12, b"X" * 12, b"W" * 12),
    ),
)
def test_cross_domain_nonce_reuse_is_rejected_before_second_record_encryption(
    monkeypatch: pytest.MonkeyPatch,
    script: tuple[bytes, ...],
) -> None:
    encrypt_calls: list[bytes] = []
    original = AESGCM.encrypt

    def tracking_encrypt(
        self: AESGCM,
        nonce: bytes,
        data: bytes,
        associated_data: bytes | None,
    ) -> bytes:
        encrypt_calls.append(nonce)
        return original(self, nonce, data, associated_data)

    monkeypatch.setattr(AESGCM, "encrypt", tracking_encrypt)
    cipher = RecordCipher(ROOT_KEY, nonce_source=_ScriptedNonces(*script))
    cipher.encrypt(b"first", CTX)
    with pytest.raises(RuntimeError, match="nonce reuse detected"):
        cipher.encrypt(b"second", CTX)
    assert encrypt_calls == [b"D" * 12, b"W" * 12]


def test_same_record_nonce_collision_and_invalid_nonce_outputs_fail_before_aes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_encrypt(*args: object, **kwargs: object) -> bytes:
        del args, kwargs
        pytest.fail("AES-GCM must not run before both nonces are reserved")

    monkeypatch.setattr(AESGCM, "encrypt", unexpected_encrypt)
    with pytest.raises(RuntimeError, match="nonce reuse detected"):
        RecordCipher(
            ROOT_KEY,
            nonce_source=_ScriptedNonces(b"D" * 12, b"D" * 12),
        ).encrypt(b"data", CTX)
    for invalid in (bytes(11), bytes(13), bytearray(12), _HostileBytes(bytes(12))):
        with pytest.raises((TypeError, ValueError), match="nonce"):
            RecordCipher(
                ROOT_KEY,
                nonce_source=cast(Any, lambda value=invalid: value),
            ).encrypt(b"data", CTX)


def test_each_record_uses_a_fresh_32_byte_dek_and_dek_failure_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_dek = bytes(range(32))
    second_dek = bytes(reversed(range(32)))
    deks = iter((first_dek, second_dek))
    requested_sizes: list[int] = []

    def scripted_random(size: int) -> bytes:
        requested_sizes.append(size)
        return next(deks)

    monkeypatch.setattr(crypto.os, "urandom", scripted_random)
    cipher = RecordCipher(
        ROOT_KEY,
        nonce_source=_ScriptedNonces(b"A" * 12, b"B" * 12, b"C" * 12, b"D" * 12),
    )
    records = (cipher.encrypt(b"same", CTX), cipher.encrypt(b"same", CTX))
    root = AESGCM(ROOT_KEY)
    unwrapped = tuple(
        root.decrypt(record.wrap_nonce, record.wrapped_dek, CTX.associated_data("dek-wrap"))
        for record in records
    )
    assert requested_sizes == [32, 32]
    assert unwrapped == (first_dek, second_dek)

    nonce_calls: list[str] = []

    def failed_random(size: int) -> bytes:
        assert size == 32
        raise OSError("synthetic entropy failure")

    monkeypatch.setattr(crypto.os, "urandom", failed_random)
    with pytest.raises(OSError, match="entropy failure"):
        RecordCipher(
            ROOT_KEY,
            nonce_source=lambda: nonce_calls.append("nonce") or bytes(12),
        ).encrypt(b"data", CTX)
    assert nonce_calls == []


def test_both_nonces_stay_reserved_when_the_first_aes_call_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[bytes] = []

    class SyntheticEncryptionFailure(Exception):
        pass

    def failed_encrypt(
        self: AESGCM,
        nonce: bytes,
        data: bytes,
        associated_data: bytes | None,
    ) -> bytes:
        del self, data, associated_data
        calls.append(nonce)
        raise SyntheticEncryptionFailure

    monkeypatch.setattr(AESGCM, "encrypt", failed_encrypt)
    cipher = RecordCipher(
        ROOT_KEY,
        nonce_source=_ScriptedNonces(b"D" * 12, b"W" * 12, b"W" * 12, b"X" * 12),
    )
    with pytest.raises(SyntheticEncryptionFailure):
        cipher.encrypt(b"first", CTX)
    with pytest.raises(RuntimeError, match="nonce reuse detected"):
        cipher.encrypt(b"second", CTX)
    assert calls == [b"D" * 12]


def test_nonce_reservation_critical_section_serializes_concurrent_sources() -> None:
    nonces = _PausingConcurrentNonces()
    second_started = Event()
    cipher = RecordCipher(ROOT_KEY, nonce_source=nonces)

    def encrypt_as(name: str, plaintext: bytes) -> EncryptedRecord:
        nonces.bind_caller(name)
        if name == "second":
            second_started.set()
        return cipher.encrypt(plaintext, CTX)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(encrypt_as, "first", b"one")
        second = None
        try:
            assert nonces.first_entered.wait(timeout=2)
            second = executor.submit(encrypt_as, "second", b"two")
            assert second_started.wait(timeout=2)
            assert not nonces.second_entered.wait(timeout=1)
        finally:
            nonces.release_first.set()
        first_record = first.result(timeout=2)
        assert second is not None
        second_record = second.result(timeout=2)

    assert nonces.second_entered.is_set()
    assert cipher.decrypt(first_record, CTX) == b"one"
    assert cipher.decrypt(second_record, CTX) == b"two"


def test_root_aead_serializes_two_successful_concurrent_round_trips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_root_entered = Event()
    release_first_root = Event()
    second_data_entered = Event()
    second_root_entered = Event()
    original_encrypt = AESGCM.encrypt

    def scheduled_encrypt(
        self: AESGCM,
        nonce: bytes,
        data: bytes,
        associated_data: bytes | None,
    ) -> bytes:
        if nonce == b"B" * 12:
            first_root_entered.set()
            if not release_first_root.wait(timeout=5):
                raise AssertionError("first root encryption was not released")
        elif nonce == b"C" * 12:
            second_data_entered.set()
        elif nonce == b"D" * 12:
            second_root_entered.set()
        return original_encrypt(self, nonce, data, associated_data)

    monkeypatch.setattr(AESGCM, "encrypt", scheduled_encrypt)
    cipher = RecordCipher(
        ROOT_KEY,
        nonce_source=_ScriptedNonces(b"A" * 12, b"B" * 12, b"C" * 12, b"D" * 12),
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(cipher.encrypt, b"one", CTX)
        second = None
        try:
            assert first_root_entered.wait(timeout=2)
            second = executor.submit(cipher.encrypt, b"two", CTX)
            assert second_data_entered.wait(timeout=2)
            assert not second_root_entered.wait(timeout=1)
        finally:
            release_first_root.set()
        first_record = first.result(timeout=2)
        assert second is not None
        second_record = second.result(timeout=2)

    assert second_root_entered.is_set()
    assert cipher.decrypt(first_record, CTX) == b"one"
    assert cipher.decrypt(second_record, CTX) == b"two"


def test_nonce_history_capacity_fails_closed_without_growing_forever(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(crypto, "_MAX_TRACKED_NONCES", 2)
    nonces = _ScriptedNonces(b"D" * 12, b"W" * 12, b"X" * 12, b"Y" * 12)
    cipher = RecordCipher(ROOT_KEY, nonce_source=nonces)
    cipher.encrypt(b"first", CTX)
    with pytest.raises(RuntimeError, match="nonce tracking capacity exhausted"):
        cipher.encrypt(b"second", CTX)
    assert nonces.calls == 2


def test_decrypt_revalidates_record_shape_context_and_authentication() -> None:
    cipher = RecordCipher(
        ROOT_KEY,
        nonce_source=_ScriptedNonces(b"D" * 12, b"W" * 12),
    )
    record = cipher.encrypt(b"private", CTX)
    tampered = (
        replace(record, ciphertext=record.ciphertext[:-1] + bytes([record.ciphertext[-1] ^ 1])),
        replace(record, nonce=b"N" * 12),
        replace(record, wrapped_dek=record.wrapped_dek[:-1] + bytes([record.wrapped_dek[-1] ^ 1])),
        replace(record, wrap_nonce=b"Q" * 12),
    )
    for candidate in tampered:
        with pytest.raises(InvalidTag):
            cipher.decrypt(candidate, CTX)
    with pytest.raises(ValueError, match="root key id mismatch"):
        cipher.decrypt(replace(record, root_key_id="records-v2"), CTX)
    with pytest.raises(InvalidTag):
        RecordCipher(bytes(reversed(ROOT_KEY))).decrypt(record, CTX)

    mutated_record = replace(record)
    object.__setattr__(mutated_record, "nonce", bytes(11))
    with pytest.raises(ValueError, match="nonce"):
        cipher.decrypt(mutated_record, CTX)
    mutated_context = RecordContext.model_validate(CTX.model_dump())
    object.__setattr__(mutated_context, "purpose", "memory-embedding")
    with pytest.raises(ValidationError):
        cipher.decrypt(record, mutated_context)
    with pytest.raises(TypeError, match="encrypted record"):
        cipher.decrypt(cast(Any, object()), CTX)
