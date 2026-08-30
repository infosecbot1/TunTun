from __future__ import annotations

import base64
import binascii
import hmac
import math
import platform

import keyring
from keyring.backend import KeyringBackend

from .provider import (
    MAX_SECRET_BYTES,
    SecretProvider,
    validate_secret_identifier,
    validate_secret_value,
)

MAX_ENCODED_SECRET_CHARS = ((MAX_SECRET_BYTES + 2) // 3) * 4


def _load_macos_keyring_type() -> type[KeyringBackend]:
    try:
        from keyring.backends.macOS import Keyring
    except (ImportError, RuntimeError) as error:
        raise RuntimeError("macOS Keychain backend is unavailable") from error
    return Keyring


def _bind_macos_backend(
    system_name: str,
    backend: KeyringBackend,
    expected_type: type[KeyringBackend],
) -> KeyringBackend:
    if system_name != "Darwin" or type(backend) is not expected_type:
        raise RuntimeError("production secret backend must be macOS Keychain")
    try:
        raw_priority = expected_type.priority
        if type(raw_priority) not in {int, float}:
            raise ValueError("macOS Keychain priority must be numeric")
        priority = float(raw_priority)
    except (AttributeError, RuntimeError, TypeError, ValueError) as error:
        raise RuntimeError("macOS Keychain backend is unavailable") from error
    if not math.isfinite(priority) or priority < 1:
        raise RuntimeError("macOS Keychain backend is unavailable")
    return backend


class MacOSKeychainSecretProvider(SecretProvider):
    def __init__(self) -> None:
        system_name = platform.system()
        if system_name != "Darwin":
            raise RuntimeError("production secret backend must be macOS Keychain")
        expected_type = _load_macos_keyring_type()
        try:
            backend = keyring.get_keyring()
        except (keyring.errors.KeyringError, RuntimeError) as error:
            raise RuntimeError("macOS Keychain backend is unavailable") from error
        self._backend = _bind_macos_backend(system_name, backend, expected_type)

    def _read_encoded(self, service: str, account: str) -> str | None:
        try:
            encoded = self._backend.get_password(service, account)
        except keyring.errors.KeyringError as error:
            raise RuntimeError(f"secret read failed: {service}/{account}") from error
        if encoded is not None and type(encoded) is not str:
            raise RuntimeError(f"invalid stored secret: {service}/{account}")
        return encoded

    @staticmethod
    def _decode(encoded: str, service: str, account: str) -> bytes:
        try:
            if not 1 <= len(encoded) <= MAX_ENCODED_SECRET_CHARS:
                raise ValueError("stored secret encoding is not bounded")
            value = base64.b64decode(encoded, validate=True)
            value = validate_secret_value(value)
            if base64.b64encode(value).decode("ascii") != encoded:
                raise ValueError("stored secret encoding is not canonical")
            return value
        except (binascii.Error, ValueError) as error:
            raise RuntimeError(f"invalid stored secret: {service}/{account}") from error

    def get(self, service: str, account: str) -> bytes:
        service, account = validate_secret_identifier(service, account)
        encoded = self._read_encoded(service, account)
        if encoded is None:
            raise RuntimeError(f"missing secret: {service}/{account}")
        return self._decode(encoded, service, account)

    def set(self, service: str, account: str, value: bytes) -> None:
        service, account = validate_secret_identifier(service, account)
        value = validate_secret_value(value)
        encoded = base64.b64encode(value).decode("ascii")
        try:
            self._backend.set_password(service, account, encoded)
        except keyring.errors.KeyringError as error:
            raise RuntimeError(f"secret write failed: {service}/{account}") from error
        if not hmac.compare_digest(self.get(service, account), value):
            raise RuntimeError(f"secret write verification failed: {service}/{account}")

    def delete(self, service: str, account: str) -> None:
        service, account = validate_secret_identifier(service, account)
        if self._read_encoded(service, account) is None:
            return
        try:
            self._backend.delete_password(service, account)
        except keyring.errors.PasswordDeleteError as error:
            try:
                absent = self._read_encoded(service, account) is None
            except RuntimeError as verification_error:
                raise RuntimeError(
                    f"secret deletion could not be verified: {service}/{account}"
                ) from verification_error
            if absent:
                return
            raise RuntimeError(f"secret deletion failed: {service}/{account}") from error
        except keyring.errors.KeyringError as error:
            raise RuntimeError(f"secret deletion failed: {service}/{account}") from error
        if self._read_encoded(service, account) is not None:
            raise RuntimeError(f"secret deletion verification failed: {service}/{account}")

    def exists(self, service: str, account: str) -> bool:
        service, account = validate_secret_identifier(service, account)
        encoded = self._read_encoded(service, account)
        if encoded is None:
            return False
        self._decode(encoded, service, account)
        return True

    def __repr__(self) -> str:
        return "MacOSKeychainSecretProvider()"
