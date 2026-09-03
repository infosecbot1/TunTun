from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from typing import Annotated, Literal, Self
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import Field, field_validator, model_validator
from tuntun_contracts.base import ContractModel, canonical_mapping_bytes

_DEK_BYTES = 32
_GCM_TAG_BYTES = 16
_NONCE_BYTES = 12
_WRAPPED_DEK_BYTES = _DEK_BYTES + _GCM_TAG_BYTES
_MAX_TRACKED_NONCES = 1_000_000
_ROOT_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$", flags=re.ASCII)


def _validate_root_key_id(value: object) -> str:
    if type(value) is not str:
        raise TypeError("record root key id must be an exact string")
    result = value
    if _ROOT_KEY_ID.fullmatch(result) is None:
        raise ValueError("record root key id must be bounded canonical ASCII")
    return result


def _exact_bytes(value: object, *, label: str) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{label} must be exact bytes")
    return value


class RecordContext(ContractModel):
    household_id: UUID
    table: Literal[
        "subjects",
        "biometric_templates",
        "memory_embeddings",
        "recovery_sensitive_values",
    ]
    row_id: UUID
    purpose: Literal[
        "profile-display-label",
        "profile-persona-traits",
        "face-template",
        "voice-template",
        "memory-embedding",
        "recovery-sensitive",
    ]
    schema_version: Literal["1.0"]
    profile_version: Annotated[int | None, Field(default=None, ge=1)] = None

    @field_validator("household_id", "row_id")
    @classmethod
    def exact_uuid_type(cls, value: UUID) -> UUID:
        if type(value) is not UUID:
            raise ValueError("record context identifiers must be exact UUID values")
        return value

    @model_validator(mode="after")
    def exact_table_purpose(self) -> Self:
        valid = (
            (
                self.table == "subjects"
                and self.purpose in {"profile-display-label", "profile-persona-traits"}
                and self.profile_version is not None
            )
            or (
                self.table == "biometric_templates"
                and self.purpose in {"face-template", "voice-template"}
                and self.profile_version is None
            )
            or (
                self.table == "memory_embeddings"
                and self.purpose == "memory-embedding"
                and self.profile_version is None
            )
            or (
                self.table == "recovery_sensitive_values"
                and self.purpose == "recovery-sensitive"
                and self.profile_version is None
            )
        )
        if not valid:
            raise ValueError("record table/purpose mismatch")
        return self

    def associated_data(self, domain: Literal["record-data", "dek-wrap"]) -> bytes:
        if type(domain) is not str:
            raise TypeError("associated-data domain must be an exact string")
        if domain not in {"record-data", "dek-wrap"}:
            raise ValueError("unknown associated-data domain")
        fields: dict[str, object] = {
            "domain": domain,
            "household_id": self.household_id,
            "purpose": self.purpose,
            "row_id": self.row_id,
            "schema_version": self.schema_version,
            "table": self.table,
        }
        if self.profile_version is not None:
            fields["profile_version"] = self.profile_version
        return canonical_mapping_bytes(fields)


@dataclass(frozen=True, slots=True)
class EncryptedRecord:
    ciphertext: bytes
    nonce: bytes
    wrapped_dek: bytes
    wrap_nonce: bytes
    root_key_id: str

    def __post_init__(self) -> None:
        ciphertext = _exact_bytes(self.ciphertext, label="record ciphertext")
        nonce = _exact_bytes(self.nonce, label="record nonce")
        wrapped_dek = _exact_bytes(self.wrapped_dek, label="wrapped DEK")
        wrap_nonce = _exact_bytes(self.wrap_nonce, label="DEK-wrap nonce")
        _validate_root_key_id(self.root_key_id)
        if len(ciphertext) < _GCM_TAG_BYTES:
            raise ValueError("record ciphertext is shorter than an AES-GCM tag")
        if len(nonce) != _NONCE_BYTES:
            raise ValueError("record nonce must be 12 bytes")
        if len(wrapped_dek) != _WRAPPED_DEK_BYTES:
            raise ValueError("wrapped DEK must be 48 bytes")
        if len(wrap_nonce) != _NONCE_BYTES:
            raise ValueError("DEK-wrap nonce must be 12 bytes")
        if nonce == wrap_nonce:
            raise ValueError("record data and DEK-wrap nonces must be distinct")


class RecordCipher:
    __slots__ = (
        "_nonce_lock",
        "_nonce_source",
        "_root",
        "_root_key_id",
        "_root_lock",
        "_used_nonces",
    )

    def __init__(
        self,
        root_key: bytes,
        root_key_id: str = "records-v1",
        nonce_source: Callable[[], bytes] | None = None,
    ) -> None:
        exact_root_key = _exact_bytes(root_key, label="record root key")
        if len(exact_root_key) != _DEK_BYTES:
            raise ValueError("record root key must be 32 bytes")
        validated_key_id = _validate_root_key_id(root_key_id)
        if nonce_source is not None and not callable(nonce_source):
            raise TypeError("record nonce source must be callable")
        self._root = AESGCM(exact_root_key)
        self._root_key_id = validated_key_id
        self._nonce_source = nonce_source if nonce_source is not None else self._random_nonce
        self._used_nonces: set[bytes] = set()
        self._nonce_lock = Lock()
        self._root_lock = Lock()

    @staticmethod
    def _random_nonce() -> bytes:
        return os.urandom(_NONCE_BYTES)

    @staticmethod
    def _validated_context(context: RecordContext) -> RecordContext:
        if type(context) is not RecordContext:
            raise TypeError("record context must be an exact RecordContext")
        return RecordContext(
            household_id=context.household_id,
            table=context.table,
            row_id=context.row_id,
            purpose=context.purpose,
            schema_version=context.schema_version,
            profile_version=context.profile_version,
        )

    @staticmethod
    def _validated_record(record: EncryptedRecord) -> EncryptedRecord:
        if type(record) is not EncryptedRecord:
            raise TypeError("encrypted record must be an exact EncryptedRecord")
        return EncryptedRecord(
            ciphertext=record.ciphertext,
            nonce=record.nonce,
            wrapped_dek=record.wrapped_dek,
            wrap_nonce=record.wrap_nonce,
            root_key_id=record.root_key_id,
        )

    def _next_nonce(self) -> bytes:
        nonce = _exact_bytes(self._nonce_source(), label="AES-GCM nonce")
        if len(nonce) != _NONCE_BYTES:
            raise ValueError("AES-GCM nonce must be 12 bytes")
        return nonce

    def _reserve_nonce_pair(self) -> tuple[bytes, bytes]:
        with self._nonce_lock:
            if len(self._used_nonces) + 2 > _MAX_TRACKED_NONCES:
                raise RuntimeError("nonce tracking capacity exhausted")
            nonce = self._next_nonce()
            wrap_nonce = self._next_nonce()
            if nonce == wrap_nonce or nonce in self._used_nonces or wrap_nonce in self._used_nonces:
                raise RuntimeError("nonce reuse detected")
            self._used_nonces.update((nonce, wrap_nonce))
            return nonce, wrap_nonce

    def encrypt(self, plaintext: bytes, context: RecordContext) -> EncryptedRecord:
        exact_plaintext = _exact_bytes(plaintext, label="record plaintext")
        validated_context = self._validated_context(context)
        data_aad = validated_context.associated_data("record-data")
        wrap_aad = validated_context.associated_data("dek-wrap")
        dek = os.urandom(_DEK_BYTES)
        if type(dek) is not bytes or len(dek) != _DEK_BYTES:
            raise RuntimeError("record DEK generation failed")
        nonce, wrap_nonce = self._reserve_nonce_pair()
        ciphertext = AESGCM(dek).encrypt(nonce, exact_plaintext, data_aad)
        with self._root_lock:
            wrapped_dek = self._root.encrypt(wrap_nonce, dek, wrap_aad)
        return EncryptedRecord(
            ciphertext=ciphertext,
            nonce=nonce,
            wrapped_dek=wrapped_dek,
            wrap_nonce=wrap_nonce,
            root_key_id=self._root_key_id,
        )

    def decrypt(self, record: EncryptedRecord, context: RecordContext) -> bytes:
        validated_record = self._validated_record(record)
        validated_context = self._validated_context(context)
        if validated_record.root_key_id != self._root_key_id:
            raise ValueError("record root key id mismatch")
        wrap_aad = validated_context.associated_data("dek-wrap")
        data_aad = validated_context.associated_data("record-data")
        with self._root_lock:
            dek = self._root.decrypt(
                validated_record.wrap_nonce,
                validated_record.wrapped_dek,
                wrap_aad,
            )
        if type(dek) is not bytes or len(dek) != _DEK_BYTES:
            raise InvalidTag
        return AESGCM(dek).decrypt(
            validated_record.nonce,
            validated_record.ciphertext,
            data_aad,
        )
