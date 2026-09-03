from __future__ import annotations

from typing import Literal
from uuid import UUID

from cryptography.exceptions import InvalidTag
from tuntun_contracts.identity import PersonaTraits
from tuntun_core.adapters.sqlcipher.crypto import EncryptedRecord, RecordCipher, RecordContext


class ProfileCrypto:
    """SQLCipher-adjacent AEAD adapter for encrypted profile fields."""

    _DISPLAY_MAGIC = b"TTPROF-DISPLAY-V1\0"
    _TRAITS_MAGIC = b"TTPROF-TRAITS-V1\0"
    _SCHEMA_VERSION_BYTE = 1
    _NONCE_BYTES = 12
    _WRAPPED_DEK_BYTES = 48
    _GCM_TAG_BYTES = 16

    def __init__(self, root_key: bytes, *, key_id: str = "profile-aead-v1") -> None:
        if type(key_id) is not str or not key_id:
            raise ValueError("profile crypto key id required")
        self._cipher = RecordCipher(root_key, key_id)
        self.key_id = key_id

    def seal_display_label(
        self,
        household_id: UUID,
        subject_id: UUID,
        profile_version: int,
        display_label: str,
    ) -> bytes:
        return self._seal(
            self._DISPLAY_MAGIC,
            household_id,
            subject_id,
            profile_version,
            "profile-display-label",
            display_label.encode("utf-8"),
        )

    def seal_traits(
        self,
        household_id: UUID,
        subject_id: UUID,
        profile_version: int,
        traits: PersonaTraits,
    ) -> bytes:
        return self._seal(
            self._TRAITS_MAGIC,
            household_id,
            subject_id,
            profile_version,
            "profile-persona-traits",
            traits.model_dump_json().encode("utf-8"),
        )

    def open_traits(
        self,
        household_id: UUID,
        subject_id: UUID,
        profile_version: int,
        encrypted_persona_traits: bytes,
    ) -> PersonaTraits:
        payload = self._open(
            self._TRAITS_MAGIC,
            household_id,
            subject_id,
            profile_version,
            "profile-persona-traits",
            encrypted_persona_traits,
        )
        try:
            return PersonaTraits.model_validate_json(payload)
        except ValueError as error:
            raise PermissionError("encrypted_persona_traits_invalid") from error

    def _seal(
        self,
        magic: bytes,
        household_id: UUID,
        subject_id: UUID,
        profile_version: int,
        purpose: Literal["profile-display-label", "profile-persona-traits"],
        plaintext: bytes,
    ) -> bytes:
        record = self._cipher.encrypt(
            plaintext,
            self._context(household_id, subject_id, profile_version, purpose),
        )
        key_id_bytes = record.root_key_id.encode("ascii")
        if len(key_id_bytes) > 255:
            raise RuntimeError("profile crypto key id unexpectedly long")
        return (
            magic
            + bytes((self._SCHEMA_VERSION_BYTE, len(key_id_bytes)))
            + key_id_bytes
            + record.nonce
            + record.wrap_nonce
            + record.wrapped_dek
            + record.ciphertext
        )

    def _open(
        self,
        magic: bytes,
        household_id: UUID,
        subject_id: UUID,
        profile_version: int,
        purpose: Literal["profile-display-label", "profile-persona-traits"],
        envelope: bytes,
    ) -> bytes:
        if not envelope.startswith(magic):
            raise PermissionError("encrypted_persona_traits_invalid")
        offset = len(magic)
        if len(envelope) < offset + 2:
            raise PermissionError("encrypted_persona_traits_invalid")
        schema_version = envelope[offset]
        if schema_version != self._SCHEMA_VERSION_BYTE:
            raise PermissionError("encrypted_persona_traits_invalid")
        key_id_length = envelope[offset + 1]
        key_id_start = offset + 2
        key_id_end = key_id_start + key_id_length
        nonce_start = key_id_end
        nonce_end = nonce_start + self._NONCE_BYTES
        wrap_nonce_start = nonce_end
        wrap_nonce_end = wrap_nonce_start + self._NONCE_BYTES
        wrapped_dek_start = wrap_nonce_end
        wrapped_dek_end = wrapped_dek_start + self._WRAPPED_DEK_BYTES
        ciphertext_start = wrapped_dek_end
        if key_id_length == 0 or len(envelope) < ciphertext_start + self._GCM_TAG_BYTES:
            raise PermissionError("encrypted_persona_traits_invalid")
        try:
            key_id = envelope[key_id_start:key_id_end].decode("ascii")
        except UnicodeDecodeError as error:
            raise PermissionError("encrypted_persona_traits_invalid") from error
        if key_id != self.key_id:
            raise PermissionError("encrypted_persona_traits_invalid")
        record = EncryptedRecord(
            ciphertext=envelope[ciphertext_start:],
            nonce=envelope[nonce_start:nonce_end],
            wrapped_dek=envelope[wrapped_dek_start:wrapped_dek_end],
            wrap_nonce=envelope[wrap_nonce_start:wrap_nonce_end],
            root_key_id=key_id,
        )
        try:
            return self._cipher.decrypt(
                record,
                self._context(household_id, subject_id, profile_version, purpose),
            )
        except (InvalidTag, ValueError) as error:
            raise PermissionError("encrypted_persona_traits_invalid") from error

    @staticmethod
    def _context(
        household_id: UUID,
        subject_id: UUID,
        profile_version: int,
        purpose: Literal["profile-display-label", "profile-persona-traits"],
    ) -> RecordContext:
        return RecordContext(
            household_id=household_id,
            table="subjects",
            row_id=subject_id,
            purpose=purpose,
            schema_version="1.0",
            profile_version=profile_version,
        )
