from __future__ import annotations

import hashlib
import hmac
import re
from datetime import UTC, datetime
from typing import Final, Literal, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from tuntun_contracts.events import SignedEventEnvelope
from tuntun_contracts.reachy_control import HmacKeyEpoch, PairingMaterial, RotationKeyring

from .commissioning import (
    CommissioningStateV1,
    OwnerOnlyArtifactStorePort,
    ReachyCoreEndpointV1,
)

Direction = Literal["edge_to_core", "core_to_edge"]
_ED25519_KEY_ID_PATTERN: Final = re.compile(r"^ed25519:[a-z0-9][a-z0-9._-]{0,63}:v[1-9][0-9]{0,8}$")
_PAIRING_ID_PATTERN: Final = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")
_SHA256_HEX: Final = frozenset("0123456789abcdef")


class CommissioningRepository(Protocol):
    def require_current(self) -> CommissioningStateV1: ...

    def require_usable(self, endpoint: ReachyCoreEndpointV1) -> ReachyCoreEndpointV1: ...


class PairingKeyBinding(Protocol):
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


class CoreInboundRuntimeKeys(Protocol):
    binding: PairingKeyBinding
    public_bytes: bytes
    hmac_root: bytes


class EdgePairingKeyRepository(Protocol):
    async def require_current_edge_outbound_tuple(
        self,
        material: PairingMaterial,
        now: datetime,
    ) -> PairingKeyBinding: ...

    async def require_accepted_core_tuple(
        self,
        material: PairingMaterial,
        signing_key_id: str,
        hmac_key_id: str,
        now: datetime,
    ) -> CoreInboundRuntimeKeys: ...


class _ImmutableRuntimeObject:
    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")


class EdgeOutboundKeys(_ImmutableRuntimeObject):
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


class EdgeInboundKeys(_ImmutableRuntimeObject):
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


class EdgePairingKeyResolver:
    """Resolve Reachy frame keys only from current commissioning and key repositories."""

    def __init__(
        self,
        commissioning: CommissioningRepository,
        pairing_keys: EdgePairingKeyRepository,
        artifacts: OwnerOnlyArtifactStorePort,
    ) -> None:
        self._commissioning = commissioning
        self._pairing_keys = pairing_keys
        self._artifacts = artifacts

    async def current_outbound(
        self,
        *,
        tls_peer_sha256: str,
        now: datetime,
    ) -> EdgeOutboundKeys:
        now = _normalize_utc(now, "timestamp must be timezone-aware")
        state, endpoint, material = self._current_material()
        if not _secure_equal(tls_peer_sha256, material.server_leaf_sha256):
            raise PermissionError("pairing_key_binding")
        binding = await self._current_edge_binding(material, now)
        _require_binding_matches_pairing(
            binding,
            material,
            direction="edge_to_core",
            now=now,
            require_current_key_material=True,
        )
        artifact_map = state.artifact_map
        if artifact_map is None:
            raise PermissionError("revoked_or_stale_pairing_key")
        signer = _load_private_signer(
            self._artifacts,
            artifact_map.device_signing_private_key_handle,
        )
        hmac_root = _read_hmac_root(self._artifacts, artifact_map.frame_hmac_root_handle)
        public_bytes = signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if (
            not _secure_equal(_sha256(public_bytes), endpoint.device_signing_public_key_sha256)
            or not _secure_equal(_sha256(public_bytes), binding.signing_public_key_sha256)
            or not _secure_equal(_sha256(hmac_root), endpoint.hmac_key_sha256)
            or not _secure_equal(_sha256(hmac_root), binding.hmac_key_sha256)
        ):
            raise PermissionError("pairing_key_digest_mismatch")
        return EdgeOutboundKeys(
            pairing=material,
            signer=signer,
            signing_key_id=binding.signing_key_id,
            hmac_key_id=binding.hmac_key_id,
            hmac_root=hmac_root,
        )

    async def resolve_frame(
        self,
        frame: SignedEventEnvelope,
        *,
        tls_peer_sha256: str,
        now: datetime,
    ) -> EdgeInboundKeys:
        now = _normalize_utc(now, "timestamp must be timezone-aware")
        _state, _endpoint, material = self._current_material()
        if not _secure_equal(tls_peer_sha256, material.server_leaf_sha256):
            raise PermissionError("pairing_key_binding")
        hmac_key_id = frame.envelope.payload_commitment.key_id
        runtime_keys = await self._accepted_core_keys(
            material,
            signing_key_id=frame.signing_key_id,
            hmac_key_id=hmac_key_id,
            now=now,
        )
        try:
            binding = runtime_keys.binding
        except AttributeError as error:
            raise PermissionError("pairing_key_binding") from error
        _require_binding_matches_pairing(
            binding,
            material,
            direction="core_to_edge",
            now=now,
            require_current_key_material=False,
        )
        _require_requested_binding(binding, frame.signing_key_id, hmac_key_id)
        try:
            public_bytes = runtime_keys.public_bytes
            hmac_root = runtime_keys.hmac_root
        except AttributeError as error:
            raise PermissionError("pairing_key_digest_mismatch") from error
        if type(public_bytes) is not bytes or len(public_bytes) != 32:
            raise PermissionError("pairing_key_digest_mismatch")
        if not _secure_equal(_sha256(public_bytes), binding.signing_public_key_sha256):
            raise PermissionError("pairing_key_digest_mismatch")
        if type(hmac_root) is not bytes or len(hmac_root) != 32:
            raise PermissionError("pairing_key_digest_mismatch")
        if not _secure_equal(_sha256(hmac_root), binding.hmac_key_sha256):
            raise PermissionError("pairing_key_digest_mismatch")
        try:
            public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        except ValueError as error:
            raise PermissionError("pairing_key_digest_mismatch") from error
        return EdgeInboundKeys(
            pairing=material,
            public_key=public_key,
            signing_key_id=frame.signing_key_id,
            hmac_key_id=hmac_key_id,
            hmac_root=hmac_root,
        )

    def _current_material(
        self,
    ) -> tuple[CommissioningStateV1, ReachyCoreEndpointV1, PairingMaterial]:
        try:
            state = self._commissioning.require_current()
        except (LookupError, OSError) as error:
            raise PermissionError("revoked_or_stale_pairing_key") from error
        if state.status != "active" or state.legacy_key_id_format or state.artifact_map is None:
            raise PermissionError("revoked_or_stale_pairing_key")
        try:
            endpoint = self._commissioning.require_usable(state.endpoint)
        except (LookupError, OSError) as error:
            raise PermissionError("revoked_or_stale_pairing_key") from error
        if endpoint != state.endpoint:
            raise PermissionError("revoked_or_stale_pairing_key")
        try:
            material = pairing_material_from_endpoint(endpoint)
        except (AttributeError, TypeError, ValueError) as error:
            raise PermissionError("revoked_or_stale_pairing_key") from error
        return state, endpoint, material

    async def _current_edge_binding(
        self,
        material: PairingMaterial,
        now: datetime,
    ) -> PairingKeyBinding:
        try:
            return await self._pairing_keys.require_current_edge_outbound_tuple(material, now)
        except PermissionError:
            raise
        except (LookupError, OSError) as error:
            raise PermissionError("revoked_or_stale_pairing_key") from error

    async def _accepted_core_keys(
        self,
        material: PairingMaterial,
        *,
        signing_key_id: str,
        hmac_key_id: str,
        now: datetime,
    ) -> CoreInboundRuntimeKeys:
        try:
            return await self._pairing_keys.require_accepted_core_tuple(
                material,
                signing_key_id,
                hmac_key_id,
                now,
            )
        except PermissionError:
            raise
        except OSError as error:
            raise PermissionError("revoked_or_stale_pairing_key") from error
        except LookupError as error:
            raise PermissionError("pairing_key_binding") from error


def pairing_material_from_endpoint(endpoint: ReachyCoreEndpointV1) -> PairingMaterial:
    return PairingMaterial(
        server_key_id=endpoint.server_key_id,
        server_public_key_sha256=endpoint.server_public_key_sha256,
        tls_key_id=endpoint.client_tls_key_id,
        tls_key_generation=endpoint.client_tls_key_generation,
        signing_key_id=endpoint.device_signing_key_id,
        signing_key_generation=endpoint.device_signing_key_generation,
        signing_public_key_sha256=endpoint.device_signing_public_key_sha256,
        hmac_key_id=endpoint.hmac_key_id,
        hmac_key_generation=endpoint.hmac_key_generation,
        hmac_key_sha256=endpoint.hmac_key_sha256,
        endpoint_generation=endpoint.generation,
        certificate_generation=endpoint.certificate_generation,
        server_key_generation=endpoint.server_key_generation,
        trust_digest_generation=endpoint.trust_digest_generation,
        household_ca_sha256=endpoint.household_ca_sha256,
        server_leaf_sha256=endpoint.server_leaf_sha256,
        client_certificate_sha256=endpoint.client_certificate_sha256,
    )


def _load_private_signer(
    artifacts: OwnerOnlyArtifactStorePort,
    handle: str,
) -> Ed25519PrivateKey:
    try:
        private_bytes = artifacts.read(handle)
    except (OSError, ValueError) as error:
        raise PermissionError("pairing_key_digest_mismatch") from error
    if type(private_bytes) is not bytes or len(private_bytes) != 32:
        raise PermissionError("pairing_key_digest_mismatch")
    try:
        return Ed25519PrivateKey.from_private_bytes(private_bytes)
    except ValueError as error:
        raise PermissionError("pairing_key_digest_mismatch") from error


def _read_hmac_root(artifacts: OwnerOnlyArtifactStorePort, handle: str) -> bytes:
    try:
        value = artifacts.read(handle)
    except (OSError, ValueError) as error:
        raise PermissionError("pairing_key_digest_mismatch") from error
    if type(value) is not bytes or len(value) != 32:
        raise PermissionError("pairing_key_digest_mismatch")
    return value


def _require_binding_matches_pairing(
    binding: PairingKeyBinding,
    material: PairingMaterial,
    *,
    direction: Direction,
    now: datetime,
    require_current_key_material: bool,
) -> None:
    try:
        binding_direction = binding.direction
    except AttributeError as error:
        raise PermissionError("pairing_key_binding") from error
    if binding_direction != direction:
        raise PermissionError("pairing_key_binding")
    _require_valid_binding_metadata(binding)
    if direction == "core_to_edge":
        _require_core_signing_tuple_coherent(binding)
    normalized_now = _normalize_utc(now, "timestamp must be timezone-aware")
    try:
        active_from = _normalize_utc(
            binding.active_from,
            "pairing key epoch bounds must be timezone-aware",
        )
        accept_until = _normalize_utc(
            binding.accept_until,
            "pairing key epoch bounds must be timezone-aware",
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise PermissionError("revoked_or_stale_pairing_key") from error
    if accept_until < active_from or not (active_from <= normalized_now <= accept_until):
        raise PermissionError("revoked_or_stale_pairing_key")
    stable_values: tuple[tuple[object, object], ...] = (
        (binding.endpoint_generation, material.endpoint_generation),
        (binding.certificate_generation, material.certificate_generation),
        (binding.server_leaf_sha256, material.server_leaf_sha256),
        (binding.client_certificate_sha256, material.client_certificate_sha256),
        (binding.tls_key_id, material.tls_key_id),
        (binding.tls_key_generation, material.tls_key_generation),
        (binding.trust_digest_generation, material.trust_digest_generation),
        (binding.household_ca_sha256, material.household_ca_sha256),
    )
    if any(not _same_pairing_value(left, right) for left, right in stable_values):
        raise PermissionError("pairing_generation_or_digest")
    if direction == "edge_to_core" or require_current_key_material:
        server_values: tuple[tuple[object, object], ...] = (
            (binding.server_key_id, material.server_key_id),
            (binding.server_key_generation, material.server_key_generation),
            (binding.server_public_key_sha256, material.server_public_key_sha256),
        )
        if any(not _same_pairing_value(left, right) for left, right in server_values):
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


def _require_valid_binding_metadata(binding: PairingKeyBinding) -> None:
    try:
        valid = (
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
    except (AttributeError, TypeError, ValueError) as error:
        raise PermissionError("pairing_generation_or_digest") from error
    if not valid:
        raise PermissionError("pairing_generation_or_digest")


def _require_core_signing_tuple_coherent(binding: PairingKeyBinding) -> None:
    coherent_values: tuple[tuple[object, object], ...] = (
        (binding.server_key_id, binding.signing_key_id),
        (binding.server_key_generation, binding.signing_key_generation),
        (binding.server_public_key_sha256, binding.signing_public_key_sha256),
    )
    if any(not _same_pairing_value(left, right) for left, right in coherent_values):
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
    "EdgeInboundKeys",
    "EdgeOutboundKeys",
    "EdgePairingKeyResolver",
    "HmacKeyEpoch",
    "PairingMaterial",
    "RotationKeyring",
    "pairing_material_from_endpoint",
)
