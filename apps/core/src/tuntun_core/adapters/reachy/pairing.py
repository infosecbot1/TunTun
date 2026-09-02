from __future__ import annotations

import hashlib
import hmac
import re
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final, Literal, Protocol, Self
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from tuntun_contracts.reachy_control import PairingMaterial

Direction = Literal["edge_to_core", "core_to_edge"]
_ED25519_KEY_ID_PATTERN: Final = re.compile(r"^ed25519:[a-z0-9][a-z0-9._-]{0,63}:v[1-9][0-9]{0,8}$")
_PAIRING_ID_PATTERN: Final = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")
_SHA256_HEX: Final = frozenset("0123456789abcdef")


class EndpointBinding(Protocol):
    generation: int
    certificate_generation: int
    server_key_generation: int
    server_public_key_sha256: str
    trust_digest_generation: int
    household_ca_sha256: str
    server_leaf_sha256: str
    server_key_id: str
    client_certificate_sha256: str
    client_tls_key_id: str
    client_tls_key_generation: int
    device_signing_key_id: str
    device_signing_key_generation: int
    device_signing_public_key_sha256: str
    hmac_key_id: str
    hmac_key_generation: int
    hmac_key_sha256: str


class PairingRow(Protocol):
    device_id: UUID
    material: PairingMaterial
    endpoint_generation: int


class PairingRepository(Protocol):
    def require_current(self, device_id: UUID) -> AbstractAsyncContextManager[PairingRow]: ...


class AsyncPairingRepository(Protocol):
    async def require_current(self, device_id: UUID) -> PairingRow: ...

    async def require_current_endpoint(self, endpoint_generation: int) -> EndpointBinding: ...

    async def require_current_core_outbound_tuple(
        self,
        row: PairingRow,
        now: datetime,
    ) -> PairingKeyBinding: ...

    async def require_accepted_rotation_tuple(
        self,
        row: PairingRow,
        signing_key_id: str,
        hmac_key_id: str,
        now: datetime,
        *,
        direction: Direction,
    ) -> PairingKeyBinding: ...


class PairingKeyVault(Protocol):
    async def resolve_private_signing_epoch(
        self,
        device_id: UUID,
        key_id: str,
        now: datetime,
    ) -> PrivateSigningKeyEpoch: ...

    async def resolve_signing_epoch(
        self,
        device_id: UUID,
        key_id: str,
        now: datetime,
    ) -> PublicSigningKeyEpoch: ...

    async def resolve_hmac_epoch(
        self,
        device_id: UUID,
        key_id: str,
        now: datetime,
    ) -> HmacRootEpoch: ...


@dataclass(frozen=True, slots=True)
class PairingKeyBinding:
    direction: Direction
    endpoint_generation: int
    certificate_generation: int
    server_key_id: str
    server_key_generation: int
    server_public_key_sha256: str
    trust_digest_generation: int
    household_ca_sha256: str
    server_leaf_sha256: str
    tls_key_id: str
    tls_key_generation: int
    client_certificate_sha256: str
    signing_key_id: str
    signing_key_generation: int
    signing_public_key_sha256: str
    hmac_key_id: str
    hmac_key_generation: int
    hmac_key_sha256: str
    active_from: datetime
    accept_until: datetime

    @classmethod
    def from_material(
        cls,
        material: PairingMaterial,
        *,
        direction: Direction,
        active_from: datetime,
        accept_until: datetime,
    ) -> Self:
        signing_key_id, signing_generation, signing_digest = _current_signing_tuple(
            material,
            direction,
        )
        return cls(
            direction=direction,
            endpoint_generation=material.endpoint_generation,
            certificate_generation=material.certificate_generation,
            server_key_id=material.server_key_id,
            server_key_generation=material.server_key_generation,
            server_public_key_sha256=material.server_public_key_sha256,
            trust_digest_generation=material.trust_digest_generation,
            household_ca_sha256=material.household_ca_sha256,
            server_leaf_sha256=material.server_leaf_sha256,
            tls_key_id=material.tls_key_id,
            tls_key_generation=material.tls_key_generation,
            client_certificate_sha256=material.client_certificate_sha256,
            signing_key_id=signing_key_id,
            signing_key_generation=signing_generation,
            signing_public_key_sha256=signing_digest,
            hmac_key_id=material.hmac_key_id,
            hmac_key_generation=material.hmac_key_generation,
            hmac_key_sha256=material.hmac_key_sha256,
            active_from=active_from,
            accept_until=accept_until,
        )

    def __post_init__(self) -> None:
        if self.direction not in {"edge_to_core", "core_to_edge"}:
            raise ValueError("pairing direction invalid")
        if not _valid_binding_metadata(self):
            raise ValueError("pairing key metadata invalid")
        active_from = _normalize_utc(
            self.active_from,
            "pairing key epoch bounds must be timezone-aware",
        )
        accept_until = _normalize_utc(
            self.accept_until,
            "pairing key epoch bounds must be timezone-aware",
        )
        if accept_until < active_from:
            raise ValueError("pairing key epoch accept_until before active_from")
        object.__setattr__(self, "active_from", active_from)
        object.__setattr__(self, "accept_until", accept_until)


@dataclass(frozen=True, slots=True)
class PrivateSigningKeyEpoch:
    key_id: str
    generation: int
    sha256: str
    private_key: Ed25519PrivateKey = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not _valid_ed25519_key_id(self.key_id)
            or not _valid_generation(self.generation)
            or not _valid_sha256_hex(self.sha256)
            or not isinstance(self.private_key, Ed25519PrivateKey)
        ):
            raise ValueError("key epoch metadata invalid")


@dataclass(frozen=True, slots=True)
class PublicSigningKeyEpoch:
    key_id: str
    generation: int
    sha256: str
    public_bytes: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not _valid_ed25519_key_id(self.key_id)
            or not _valid_generation(self.generation)
            or not _valid_sha256_hex(self.sha256)
            or type(self.public_bytes) is not bytes
            or len(self.public_bytes) != 32
        ):
            raise ValueError("key epoch metadata invalid")


class _ImmutableRuntimeObject:
    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")


class HmacRootEpoch(_ImmutableRuntimeObject):
    __slots__ = ("_generation", "_key_id", "_sha256", "_value")
    _generation: int
    _key_id: str
    _sha256: str
    _value: bytes

    def __init__(self, *, key_id: str, generation: int, sha256: str, value: bytes) -> None:
        if (
            not _valid_pairing_id(key_id)
            or not _valid_generation(generation)
            or not _valid_sha256_hex(sha256)
            or type(value) is not bytes
            or len(value) != 32
        ):
            raise ValueError("key epoch metadata invalid")
        object.__setattr__(self, "_key_id", key_id)
        object.__setattr__(self, "_generation", generation)
        object.__setattr__(self, "_sha256", sha256)
        object.__setattr__(self, "_value", value)

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def sha256(self) -> str:
        return self._sha256

    @property
    def value(self) -> bytes:
        return self._value

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"key_id={self.key_id!r}, generation={self.generation!r}, sha256={self.sha256!r})"
        )


class ResolvedInboundKeys(_ImmutableRuntimeObject):
    __slots__ = ("_hmac_key_id", "_hmac_root", "_pairing", "_public_key", "_signing_key_id")
    _hmac_key_id: str
    _hmac_root: bytes
    _pairing: PairingMaterial
    _public_key: Ed25519PublicKey
    _signing_key_id: str

    def __init__(
        self,
        *,
        pairing: PairingMaterial,
        public_key: Ed25519PublicKey,
        signing_key_id: str,
        hmac_key_id: str,
        hmac_root: bytes,
    ) -> None:
        object.__setattr__(self, "_pairing", pairing)
        object.__setattr__(self, "_public_key", public_key)
        object.__setattr__(self, "_signing_key_id", signing_key_id)
        object.__setattr__(self, "_hmac_key_id", hmac_key_id)
        object.__setattr__(self, "_hmac_root", hmac_root)

    @property
    def pairing(self) -> PairingMaterial:
        return self._pairing

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._public_key

    @property
    def signing_key_id(self) -> str:
        return self._signing_key_id

    @property
    def hmac_key_id(self) -> str:
        return self._hmac_key_id

    @property
    def hmac_root(self) -> bytes:
        return self._hmac_root

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"pairing={self.pairing!r}, public_key=<Ed25519PublicKey>, "
            f"signing_key_id={self.signing_key_id!r}, hmac_key_id={self.hmac_key_id!r})"
        )


class ResolvedOutboundKeys(_ImmutableRuntimeObject):
    __slots__ = ("_hmac_key_id", "_hmac_root", "_pairing", "_signer", "_signing_key_id")
    _hmac_key_id: str
    _hmac_root: bytes
    _pairing: PairingMaterial
    _signer: Ed25519PrivateKey
    _signing_key_id: str

    def __init__(
        self,
        *,
        pairing: PairingMaterial,
        signer: Ed25519PrivateKey,
        signing_key_id: str,
        hmac_key_id: str,
        hmac_root: bytes,
    ) -> None:
        object.__setattr__(self, "_pairing", pairing)
        object.__setattr__(self, "_signer", signer)
        object.__setattr__(self, "_signing_key_id", signing_key_id)
        object.__setattr__(self, "_hmac_key_id", hmac_key_id)
        object.__setattr__(self, "_hmac_root", hmac_root)

    @property
    def pairing(self) -> PairingMaterial:
        return self._pairing

    @property
    def signer(self) -> Ed25519PrivateKey:
        return self._signer

    @property
    def signing_key_id(self) -> str:
        return self._signing_key_id

    @property
    def hmac_key_id(self) -> str:
        return self._hmac_key_id

    @property
    def hmac_root(self) -> bytes:
        return self._hmac_root

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"pairing={self.pairing!r}, signer=<Ed25519PrivateKey>, "
            f"signing_key_id={self.signing_key_id!r}, hmac_key_id={self.hmac_key_id!r})"
        )


class PairingKeyResolver:
    """Resolve declared frame IDs only through current server-owned pairing repositories."""

    def __init__(
        self,
        pairings: AsyncPairingRepository,
        key_vault: PairingKeyVault,
        clock: object | None = None,
    ) -> None:
        self._pairings = pairings
        self._keys = key_vault
        self._clock = clock

    async def current_outbound(
        self,
        *,
        device_id: UUID,
        tls_peer_sha256: str,
        now: datetime,
    ) -> ResolvedOutboundKeys:
        now = _normalize_utc(now, "timestamp must be timezone-aware")
        row, material = await self._current_material(device_id)
        if not _secure_equal(tls_peer_sha256, material.client_certificate_sha256):
            raise PermissionError("pairing_key_binding")
        binding = await self._current_core_binding(row, now)
        _require_binding_matches_pairing(
            binding,
            material,
            direction="core_to_edge",
            now=now,
            require_current_key_material=True,
        )
        signing = await self._private_signing_epoch(device_id, binding.signing_key_id, now)
        hmac_epoch = await self._hmac_epoch(device_id, binding.hmac_key_id, now)
        signer = _require_private_signing_matches(signing, binding)
        hmac_root = _require_hmac_matches(hmac_epoch, binding)
        return ResolvedOutboundKeys(
            pairing=material,
            signer=signer,
            signing_key_id=binding.signing_key_id,
            hmac_key_id=binding.hmac_key_id,
            hmac_root=hmac_root,
        )

    async def resolve_inbound(
        self,
        *,
        device_id: UUID,
        tls_peer_sha256: str,
        signing_key_id: str,
        hmac_key_id: str,
        now: datetime,
    ) -> ResolvedInboundKeys:
        now = _normalize_utc(now, "timestamp must be timezone-aware")
        row, material = await self._current_material(device_id)
        if not _secure_equal(tls_peer_sha256, material.client_certificate_sha256):
            raise PermissionError("pairing_key_binding")
        binding = await self._accepted_binding(
            row,
            signing_key_id=signing_key_id,
            hmac_key_id=hmac_key_id,
            now=now,
            direction="edge_to_core",
        )
        _require_requested_binding(binding, signing_key_id, hmac_key_id)
        _require_binding_matches_pairing(
            binding,
            material,
            direction="edge_to_core",
            now=now,
            require_current_key_material=False,
        )
        signing = await self._public_signing_epoch(device_id, signing_key_id, now)
        hmac_epoch = await self._hmac_epoch(device_id, hmac_key_id, now)
        public_key = _require_public_signing_matches(signing, binding)
        hmac_root = _require_hmac_matches(hmac_epoch, binding)
        return ResolvedInboundKeys(
            pairing=material,
            public_key=public_key,
            signing_key_id=signing_key_id,
            hmac_key_id=hmac_key_id,
            hmac_root=hmac_root,
        )

    async def _current_material(self, device_id: UUID) -> tuple[PairingRow, PairingMaterial]:
        try:
            row = await self._pairings.require_current(device_id)
        except PermissionError:
            raise
        except (LookupError, OSError) as error:
            raise PermissionError("revoked_or_stale_pairing_key") from error
        material = row.material
        if row.device_id != device_id or row.endpoint_generation != material.endpoint_generation:
            raise PermissionError("pairing_generation_or_digest")
        try:
            endpoint = await self._pairings.require_current_endpoint(row.endpoint_generation)
        except PermissionError:
            raise
        except (LookupError, OSError) as error:
            raise PermissionError("revoked_or_stale_pairing_key") from error
        return row, validate_pairing(material, endpoint)

    async def _current_core_binding(
        self,
        row: PairingRow,
        now: datetime,
    ) -> PairingKeyBinding:
        try:
            return await self._pairings.require_current_core_outbound_tuple(row, now)
        except PermissionError:
            raise
        except (LookupError, OSError) as error:
            raise PermissionError("revoked_or_stale_pairing_key") from error

    async def _accepted_binding(
        self,
        row: PairingRow,
        *,
        signing_key_id: str,
        hmac_key_id: str,
        now: datetime,
        direction: Direction,
    ) -> PairingKeyBinding:
        try:
            return await self._pairings.require_accepted_rotation_tuple(
                row,
                signing_key_id,
                hmac_key_id,
                now,
                direction=direction,
            )
        except PermissionError:
            raise
        except OSError as error:
            raise PermissionError("revoked_or_stale_pairing_key") from error
        except LookupError as error:
            raise PermissionError("pairing_key_binding") from error

    async def _private_signing_epoch(
        self,
        device_id: UUID,
        key_id: str,
        now: datetime,
    ) -> PrivateSigningKeyEpoch:
        try:
            return await self._keys.resolve_private_signing_epoch(device_id, key_id, now)
        except (LookupError, OSError) as error:
            raise PermissionError("pairing_key_digest_mismatch") from error

    async def _public_signing_epoch(
        self,
        device_id: UUID,
        key_id: str,
        now: datetime,
    ) -> PublicSigningKeyEpoch:
        try:
            return await self._keys.resolve_signing_epoch(device_id, key_id, now)
        except (LookupError, OSError) as error:
            raise PermissionError("pairing_key_digest_mismatch") from error

    async def _hmac_epoch(
        self,
        device_id: UUID,
        key_id: str,
        now: datetime,
    ) -> HmacRootEpoch:
        try:
            return await self._keys.resolve_hmac_epoch(device_id, key_id, now)
        except (LookupError, OSError) as error:
            raise PermissionError("pairing_key_digest_mismatch") from error


def validate_pairing(material: PairingMaterial, endpoint: EndpointBinding) -> PairingMaterial:
    expected: tuple[tuple[object, object], ...] = (
        (material.endpoint_generation, endpoint.generation),
        (material.certificate_generation, endpoint.certificate_generation),
        (material.server_key_id, endpoint.server_key_id),
        (material.server_key_generation, endpoint.server_key_generation),
        (material.server_public_key_sha256, endpoint.server_public_key_sha256),
        (material.trust_digest_generation, endpoint.trust_digest_generation),
        (material.household_ca_sha256, endpoint.household_ca_sha256),
        (material.server_leaf_sha256, endpoint.server_leaf_sha256),
        (material.client_certificate_sha256, endpoint.client_certificate_sha256),
        (material.tls_key_id, endpoint.client_tls_key_id),
        (material.tls_key_generation, endpoint.client_tls_key_generation),
        (material.signing_key_id, endpoint.device_signing_key_id),
        (material.signing_key_generation, endpoint.device_signing_key_generation),
        (material.signing_public_key_sha256, endpoint.device_signing_public_key_sha256),
        (material.hmac_key_id, endpoint.hmac_key_id),
        (material.hmac_key_generation, endpoint.hmac_key_generation),
        (material.hmac_key_sha256, endpoint.hmac_key_sha256),
    )
    if any(not _same_pairing_value(left, right) for left, right in expected):
        raise PermissionError("pairing_endpoint_binding")
    return material


def _require_binding_matches_pairing(
    binding: PairingKeyBinding,
    material: PairingMaterial,
    *,
    direction: Direction,
    now: datetime,
    require_current_key_material: bool,
) -> None:
    if binding.direction != direction:
        raise PermissionError("pairing_key_binding")
    normalized_now = _normalize_utc(now, "timestamp must be timezone-aware")
    if not (binding.active_from <= normalized_now <= binding.accept_until):
        raise PermissionError("revoked_or_stale_pairing_key")

    stable_values: tuple[tuple[object, object], ...] = (
        (binding.endpoint_generation, material.endpoint_generation),
        (binding.certificate_generation, material.certificate_generation),
        (binding.server_key_id, material.server_key_id),
        (binding.server_key_generation, material.server_key_generation),
        (binding.server_public_key_sha256, material.server_public_key_sha256),
        (binding.trust_digest_generation, material.trust_digest_generation),
        (binding.household_ca_sha256, material.household_ca_sha256),
        (binding.server_leaf_sha256, material.server_leaf_sha256),
        (binding.client_certificate_sha256, material.client_certificate_sha256),
        (binding.tls_key_id, material.tls_key_id),
        (binding.tls_key_generation, material.tls_key_generation),
    )
    if any(not _same_pairing_value(left, right) for left, right in stable_values):
        raise PermissionError("pairing_generation_or_digest")
    if require_current_key_material:
        signing_key_id, signing_generation, signing_digest = _current_signing_tuple(
            material,
            direction,
        )
        current_values: tuple[tuple[object, object], ...] = (
            (binding.signing_key_id, signing_key_id),
            (binding.signing_key_generation, signing_generation),
            (binding.signing_public_key_sha256, signing_digest),
            (binding.hmac_key_id, material.hmac_key_id),
            (binding.hmac_key_generation, material.hmac_key_generation),
            (binding.hmac_key_sha256, material.hmac_key_sha256),
        )
        if any(not _same_pairing_value(left, right) for left, right in current_values):
            raise PermissionError("pairing_generation_or_digest")


def _require_requested_binding(
    binding: PairingKeyBinding,
    signing_key_id: str,
    hmac_key_id: str,
) -> None:
    if not _secure_equal(binding.signing_key_id, signing_key_id) or not _secure_equal(
        binding.hmac_key_id,
        hmac_key_id,
    ):
        raise PermissionError("pairing_key_binding")


def _require_private_signing_matches(
    epoch: PrivateSigningKeyEpoch,
    binding: PairingKeyBinding,
) -> Ed25519PrivateKey:
    if type(epoch) is not PrivateSigningKeyEpoch:
        raise PermissionError("pairing_key_digest_mismatch")
    key_id = epoch.key_id
    generation = epoch.generation
    sha256 = epoch.sha256
    private_key = epoch.private_key
    if not _epoch_metadata_matches(
        key_id=key_id,
        generation=generation,
        sha256=sha256,
        expected_key_id=binding.signing_key_id,
        expected_generation=binding.signing_key_generation,
        expected_sha256=binding.signing_public_key_sha256,
    ):
        raise PermissionError("pairing_generation_or_digest")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise PermissionError("pairing_key_digest_mismatch")
    try:
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise PermissionError("pairing_key_digest_mismatch") from error
    if not _secure_equal(_sha256(public_bytes), sha256):
        raise PermissionError("pairing_key_digest_mismatch")
    return private_key


def _require_public_signing_matches(
    epoch: PublicSigningKeyEpoch,
    binding: PairingKeyBinding,
) -> Ed25519PublicKey:
    if type(epoch) is not PublicSigningKeyEpoch:
        raise PermissionError("pairing_key_digest_mismatch")
    key_id = epoch.key_id
    generation = epoch.generation
    sha256 = epoch.sha256
    public_bytes = epoch.public_bytes
    if not _epoch_metadata_matches(
        key_id=key_id,
        generation=generation,
        sha256=sha256,
        expected_key_id=binding.signing_key_id,
        expected_generation=binding.signing_key_generation,
        expected_sha256=binding.signing_public_key_sha256,
    ):
        raise PermissionError("pairing_generation_or_digest")
    if type(public_bytes) is not bytes or len(public_bytes) != 32:
        raise PermissionError("pairing_key_digest_mismatch")
    if not _secure_equal(_sha256(public_bytes), sha256):
        raise PermissionError("pairing_key_digest_mismatch")
    try:
        return Ed25519PublicKey.from_public_bytes(public_bytes)
    except ValueError as error:
        raise PermissionError("pairing_key_digest_mismatch") from error


def _require_hmac_matches(epoch: HmacRootEpoch, binding: PairingKeyBinding) -> bytes:
    if type(epoch) is not HmacRootEpoch:
        raise PermissionError("pairing_key_digest_mismatch")
    key_id = epoch.key_id
    generation = epoch.generation
    sha256 = epoch.sha256
    value = epoch.value
    if not _epoch_metadata_matches(
        key_id=key_id,
        generation=generation,
        sha256=sha256,
        expected_key_id=binding.hmac_key_id,
        expected_generation=binding.hmac_key_generation,
        expected_sha256=binding.hmac_key_sha256,
    ):
        raise PermissionError("pairing_generation_or_digest")
    if type(value) is not bytes or len(value) != 32:
        raise PermissionError("pairing_key_digest_mismatch")
    if not _secure_equal(_sha256(value), sha256):
        raise PermissionError("pairing_key_digest_mismatch")
    return value


def _epoch_metadata_matches(
    *,
    key_id: str,
    generation: int,
    sha256: str,
    expected_key_id: str,
    expected_generation: int,
    expected_sha256: str,
) -> bool:
    return (
        _valid_generation(generation)
        and _valid_generation(expected_generation)
        and _secure_equal(key_id, expected_key_id)
        and generation == expected_generation
        and _secure_equal(sha256, expected_sha256)
    )


def _current_signing_tuple(
    material: PairingMaterial,
    direction: Direction,
) -> tuple[str, int, str]:
    if direction == "core_to_edge":
        return (
            material.server_key_id,
            material.server_key_generation,
            material.server_public_key_sha256,
        )
    return (
        material.signing_key_id,
        material.signing_key_generation,
        material.signing_public_key_sha256,
    )


def _same_pairing_value(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if type(left) is str and type(right) is str:
        return hmac.compare_digest(left, right)
    return left == right


def _secure_equal(left: str, right: str) -> bool:
    return type(left) is str and type(right) is str and hmac.compare_digest(left, right)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _valid_binding_metadata(binding: PairingKeyBinding) -> bool:
    return (
        _valid_ed25519_key_id(binding.server_key_id)
        and _valid_ed25519_key_id(binding.signing_key_id)
        and _valid_pairing_id(binding.tls_key_id)
        and _valid_pairing_id(binding.hmac_key_id)
        and all(
            _valid_generation(generation)
            for generation in (
                binding.endpoint_generation,
                binding.certificate_generation,
                binding.server_key_generation,
                binding.trust_digest_generation,
                binding.tls_key_generation,
                binding.signing_key_generation,
                binding.hmac_key_generation,
            )
        )
        and all(
            _valid_sha256_hex(digest)
            for digest in (
                binding.server_public_key_sha256,
                binding.household_ca_sha256,
                binding.server_leaf_sha256,
                binding.client_certificate_sha256,
                binding.signing_public_key_sha256,
                binding.hmac_key_sha256,
            )
        )
    )


def _valid_ed25519_key_id(value: object) -> bool:
    return type(value) is str and _ED25519_KEY_ID_PATTERN.fullmatch(value) is not None


def _valid_pairing_id(value: object) -> bool:
    return type(value) is str and _PAIRING_ID_PATTERN.fullmatch(value) is not None


def _valid_generation(value: object) -> bool:
    return type(value) is int and value >= 1


def _valid_sha256_hex(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in _SHA256_HEX for character in value)
    )


def _normalize_utc(value: datetime, message: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(message)
    return value.astimezone(UTC)


__all__ = (
    "Direction",
    "HmacRootEpoch",
    "PairingKeyBinding",
    "PairingKeyResolver",
    "PrivateSigningKeyEpoch",
    "PublicSigningKeyEpoch",
    "ResolvedInboundKeys",
    "ResolvedOutboundKeys",
    "validate_pairing",
)
