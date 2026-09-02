from __future__ import annotations

import hashlib
import inspect
from collections.abc import Callable
from dataclasses import asdict, dataclass, is_dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tuntun_contracts.base import Sensitivity, canonical_bytes
from tuntun_contracts.commitments import commit_private
from tuntun_contracts.events import (
    EventEnvelope,
    EventType,
    SignedEventEnvelope,
    StopRequestedPayload,
)
from tuntun_contracts.reachy_control import PairingMaterial, sign_envelope
from tuntun_core.adapters.reachy.pairing import (
    HmacRootEpoch,
    PairingKeyBinding,
    PairingKeyResolver,
    PrivateSigningKeyEpoch,
    PublicSigningKeyEpoch,
    ResolvedOutboundKeys,
    validate_pairing,
)
from tuntun_edge.transport.commissioning import (
    CommissioningStateV1,
    ReachyCommissioningArtifactMapV1,
    ReachyCoreEndpointV1,
)
from tuntun_edge.transport.commissioning_repository import OwnerOnlyArtifactStore
from tuntun_edge.transport.pairing import (
    EdgeOutboundKeys,
    EdgePairingKeyResolver,
    pairing_material_from_endpoint,
)

NOW = datetime(2026, 9, 2, 12, 30, tzinfo=UTC)
HOUSEHOLD_ID = UUID("00000000-0000-0000-0000-000000000901")
DEVICE_ID = UUID("00000000-0000-0000-0000-000000000902")
EVENT_ID = UUID("00000000-0000-0000-0000-000000000903")
CORRELATION_ID = UUID("00000000-0000-0000-0000-000000000904")

Direction = Literal["edge_to_core", "core_to_edge"]


def _sha256(value: bytes | str) -> str:
    raw = value.encode("ascii") if type(value) is str else value
    return hashlib.sha256(raw).hexdigest()


def _private_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _event(
    *,
    root: bytes,
    hmac_key_id: str,
    occurred_at: datetime = NOW,
) -> EventEnvelope:
    payload = StopRequestedPayload(
        kind="safety.stop_requested",
        turn_id=None,
        source="edge_keyword",  # type: ignore[arg-type]
    )
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
            event_type.value,
            canonical_bytes(payload),
        ),
        payload=payload,
    )


def _signed_core_frame(
    key_material: _KeyMaterial, *, occurred_at: datetime = NOW
) -> SignedEventEnvelope:
    material = key_material.material
    return sign_envelope(
        key_material.server_private_key,
        material.server_key_id,
        key_material.hmac_root,
        _event(
            root=key_material.hmac_root,
            hmac_key_id=material.hmac_key_id,
            occurred_at=occurred_at,
        ),
    )


@dataclass(frozen=True, slots=True)
class _KeyMaterial:
    generation: int
    server_private_key: Ed25519PrivateKey
    device_private_key: Ed25519PrivateKey
    hmac_root: bytes
    material: PairingMaterial


def _key_material(generation: int = 1) -> _KeyMaterial:
    server_private_key = Ed25519PrivateKey.generate()
    device_private_key = Ed25519PrivateKey.generate()
    hmac_root = bytes(((generation * 17) + index) % 256 for index in range(32))
    material = PairingMaterial(
        server_key_id=f"ed25519:reachy-server:v{generation}",
        server_public_key_sha256=_sha256(_public_bytes(server_private_key)),
        tls_key_id=f"reachy-client-tls-id-g{generation}",
        tls_key_generation=generation,
        signing_key_id=f"ed25519:reachy-edge:v{generation}",
        signing_key_generation=generation,
        signing_public_key_sha256=_sha256(_public_bytes(device_private_key)),
        hmac_key_id=f"reachy-frame-hmac-id-g{generation}",
        hmac_key_generation=generation,
        hmac_key_sha256=_sha256(hmac_root),
        endpoint_generation=generation,
        certificate_generation=generation,
        server_key_generation=generation,
        trust_digest_generation=generation,
        household_ca_sha256=_sha256(f"household-ca-{generation}"),
        server_leaf_sha256=_sha256(f"server-leaf-{generation}"),
        client_certificate_sha256=_sha256(f"client-certificate-{generation}"),
    )
    return _KeyMaterial(
        generation=generation,
        server_private_key=server_private_key,
        device_private_key=device_private_key,
        hmac_root=hmac_root,
        material=material,
    )


def _endpoint(material: PairingMaterial) -> ReachyCoreEndpointV1:
    generation = material.endpoint_generation
    return ReachyCoreEndpointV1(
        schema_version="tuntun.reachy-core-endpoint.v1",
        commissioning_uuid=f"00000000-0000-4000-8000-{generation:012d}",
        generation=generation,
        certificate_generation=material.certificate_generation,
        server_key_generation=material.server_key_generation,
        trust_digest_generation=material.trust_digest_generation,
        client_tls_key_generation=material.tls_key_generation,
        device_signing_key_generation=material.signing_key_generation,
        hmac_key_generation=material.hmac_key_generation,
        core_ipv4="192.168.50.10",
        core_link_address="02:00:5e:00:53:01",
        port=7443,
        household_ca_sha256=material.household_ca_sha256,
        server_leaf_sha256=material.server_leaf_sha256,
        server_key_id=material.server_key_id,
        server_public_key_sha256=material.server_public_key_sha256,
        server_ip_sans=("192.168.50.10",),
        client_certificate_sha256=material.client_certificate_sha256,
        client_tls_key_id=material.tls_key_id,
        client_tls_public_key_sha256=_sha256(f"client-tls-public-{generation}"),
        device_signing_key_id=material.signing_key_id,
        device_signing_public_key_sha256=material.signing_public_key_sha256,
        hmac_key_id=material.hmac_key_id,
        hmac_key_sha256=material.hmac_key_sha256,
        hmac_agreement_public_key_sha256=_sha256(f"hmac-agreement-{generation}"),
        dhcp_reservation_receipt_sha256=_sha256(f"dhcp-{generation}"),
        boot_identity_sha256=_sha256(f"boot-{generation}"),
        capability_evidence_sha256=_sha256(f"capability-{generation}"),
    )


def _artifact_map(generation: int = 1) -> ReachyCommissioningArtifactMapV1:
    return ReachyCommissioningArtifactMapV1(
        generation=generation,
        client_tls_private_key_handle=f"reachy-client-tls-g{generation}",
        client_certificate_handle=f"reachy-client-cert-g{generation}",
        device_signing_private_key_handle=f"reachy-device-sign-g{generation}",
        frame_hmac_root_handle=f"reachy-frame-hmac-g{generation}",
    )


def _state(
    material: PairingMaterial,
    *,
    status: Literal["active", "revoked"] = "active",
    legacy_key_id_format: bool = False,
) -> CommissioningStateV1:
    endpoint = _endpoint(material)
    revoked_key_ids: tuple[str, ...] = ()
    revoked_certificate_sha256: tuple[str, ...] = ()
    if status == "revoked":
        revoked_key_ids = (
            endpoint.server_key_id,
            endpoint.client_tls_key_id,
            endpoint.device_signing_key_id,
            endpoint.hmac_key_id,
        )
        revoked_certificate_sha256 = (
            endpoint.server_leaf_sha256,
            endpoint.client_certificate_sha256,
        )
    elif material.endpoint_generation > 1:
        prior_generation = material.endpoint_generation - 1
        revoked_key_ids = (
            f"ed25519:previous-server:v{prior_generation}",
            f"previous-client-tls-id-g{prior_generation}",
            f"ed25519:previous-device:v{prior_generation}",
            f"previous-frame-hmac-id-g{prior_generation}",
        )
        revoked_certificate_sha256 = (
            _sha256(f"previous-server-leaf-{prior_generation}"),
            _sha256(f"previous-client-certificate-{prior_generation}"),
        )
    return CommissioningStateV1(
        schema_version="tuntun.reachy-commissioning-state.v1",
        status=status,
        endpoint=endpoint,
        artifact_map=None if legacy_key_id_format else _artifact_map(material.endpoint_generation),
        legacy_key_id_format=legacy_key_id_format,
        revoked_key_ids=revoked_key_ids,
        revoked_certificate_sha256=revoked_certificate_sha256,
    )


def _mutated_value(field: str) -> object:
    if field in {
        "endpoint_generation",
        "certificate_generation",
        "server_key_generation",
        "trust_digest_generation",
        "tls_key_generation",
        "signing_key_generation",
        "hmac_key_generation",
    }:
        return 9
    if field == "server_key_id":
        return "ed25519:reachy-server:v9"
    if field == "signing_key_id":
        return "ed25519:reachy-edge:v9"
    if field == "tls_key_id":
        return "reachy-client-tls-id-g9"
    if field == "hmac_key_id":
        return "reachy-frame-hmac-id-g9"
    return _sha256(f"mutated-{field}")


@pytest.mark.parametrize(
    "field",
    (
        "endpoint_generation",
        "certificate_generation",
        "server_key_id",
        "server_key_generation",
        "server_public_key_sha256",
        "trust_digest_generation",
        "server_leaf_sha256",
        "client_certificate_sha256",
        "tls_key_id",
        "tls_key_generation",
        "signing_key_id",
        "signing_key_generation",
        "signing_public_key_sha256",
        "hmac_key_id",
        "hmac_key_generation",
        "hmac_key_sha256",
        "household_ca_sha256",
    ),
)
def test_pairing_material_is_bound_to_commissioned_endpoint(field: str) -> None:
    key_material = _key_material()
    endpoint = _endpoint(key_material.material)
    forged = replace(key_material.material, **{field: _mutated_value(field)})

    with pytest.raises(PermissionError, match="pairing_endpoint_binding"):
        validate_pairing(forged, endpoint)


class _CoreFrame:
    def __init__(self, *, signing_key_id: str, hmac_key_id: str) -> None:
        self.signing_key_id = signing_key_id
        self.hmac_key_id = hmac_key_id


@dataclass(frozen=True, slots=True)
class _PairingRow:
    device_id: UUID
    material: PairingMaterial
    endpoint_generation: int


class _CorePairingRepository:
    def __init__(
        self,
        key_material: _KeyMaterial,
        *,
        old_edge_binding: PairingKeyBinding | None = None,
    ) -> None:
        self.key_material = key_material
        self.endpoint = _endpoint(key_material.material)
        self.calls: list[str] = []
        self.current_edge_binding = PairingKeyBinding.from_material(
            key_material.material,
            direction="edge_to_core",
            active_from=NOW - timedelta(seconds=5),
            accept_until=NOW + timedelta(seconds=60),
        )
        self.current_core_binding = PairingKeyBinding.from_material(
            key_material.material,
            direction="core_to_edge",
            active_from=NOW - timedelta(seconds=5),
            accept_until=NOW + timedelta(seconds=60),
        )
        self.accepted_bindings: dict[tuple[Direction, str, str], PairingKeyBinding] = {
            (
                "edge_to_core",
                self.current_edge_binding.signing_key_id,
                self.current_edge_binding.hmac_key_id,
            ): self.current_edge_binding,
            (
                "core_to_edge",
                self.current_core_binding.signing_key_id,
                self.current_core_binding.hmac_key_id,
            ): self.current_core_binding,
        }
        if old_edge_binding is not None:
            self.accepted_bindings[
                ("edge_to_core", old_edge_binding.signing_key_id, old_edge_binding.hmac_key_id)
            ] = old_edge_binding

    async def require_current(self, device_id: UUID) -> _PairingRow:
        self.calls.append("require_current")
        if device_id != DEVICE_ID:
            raise PermissionError("revoked_or_stale_pairing_key")
        return _PairingRow(
            device_id=device_id,
            material=self.key_material.material,
            endpoint_generation=self.key_material.material.endpoint_generation,
        )

    async def require_current_endpoint(self, endpoint_generation: int) -> ReachyCoreEndpointV1:
        self.calls.append("require_current_endpoint")
        if endpoint_generation != self.key_material.material.endpoint_generation:
            raise PermissionError("pairing_generation_or_digest")
        return self.endpoint

    async def require_current_core_outbound_tuple(
        self,
        row: _PairingRow,
        now: datetime,
    ) -> PairingKeyBinding:
        self.calls.append("require_current_core_outbound_tuple")
        return self.current_core_binding

    async def require_accepted_rotation_tuple(
        self,
        row: _PairingRow,
        signing_key_id: str,
        hmac_key_id: str,
        now: datetime,
        *,
        direction: Direction,
    ) -> PairingKeyBinding:
        self.calls.append("require_accepted_rotation_tuple")
        try:
            return self.accepted_bindings[(direction, signing_key_id, hmac_key_id)]
        except KeyError as error:
            raise PermissionError("pairing_key_binding") from error


class _KeyVault:
    def __init__(self, key_materials: tuple[_KeyMaterial, ...]) -> None:
        self.private_signing: dict[str, PrivateSigningKeyEpoch] = {}
        self.public_signing: dict[str, PublicSigningKeyEpoch] = {}
        self.hmac_roots: dict[str, HmacRootEpoch] = {}
        self.calls: list[tuple[str, str]] = []
        for key_material in key_materials:
            material = key_material.material
            self.private_signing[material.server_key_id] = PrivateSigningKeyEpoch(
                key_id=material.server_key_id,
                generation=material.server_key_generation,
                sha256=material.server_public_key_sha256,
                private_key=key_material.server_private_key,
            )
            self.public_signing[material.signing_key_id] = PublicSigningKeyEpoch(
                key_id=material.signing_key_id,
                generation=material.signing_key_generation,
                sha256=material.signing_public_key_sha256,
                public_bytes=_public_bytes(key_material.device_private_key),
            )
            self.hmac_roots[material.hmac_key_id] = HmacRootEpoch(
                key_id=material.hmac_key_id,
                generation=material.hmac_key_generation,
                sha256=material.hmac_key_sha256,
                value=key_material.hmac_root,
            )

    async def resolve_private_signing_epoch(
        self,
        device_id: UUID,
        key_id: str,
        now: datetime,
    ) -> PrivateSigningKeyEpoch:
        self.calls.append(("private_signing", key_id))
        return self.private_signing[key_id]

    async def resolve_signing_epoch(
        self,
        device_id: UUID,
        key_id: str,
        now: datetime,
    ) -> PublicSigningKeyEpoch:
        self.calls.append(("public_signing", key_id))
        return self.public_signing[key_id]

    async def resolve_hmac_epoch(
        self,
        device_id: UUID,
        key_id: str,
        now: datetime,
    ) -> HmacRootEpoch:
        self.calls.append(("hmac", key_id))
        return self.hmac_roots[key_id]


class _PrivateSigningKeyEpochSubclass(PrivateSigningKeyEpoch):
    pass


class _PublicSigningKeyEpochSubclass(PublicSigningKeyEpoch):
    pass


class _HmacRootEpochSubclass(HmacRootEpoch):
    pass


class _ForeignPrivateSigningEpoch:
    def __init__(self, key_material: _KeyMaterial) -> None:
        self.key_id = key_material.material.server_key_id
        self.generation = key_material.material.server_key_generation
        self.sha256 = key_material.material.server_public_key_sha256
        self.private_key = key_material.server_private_key


class _ForeignPublicSigningEpoch:
    def __init__(self, key_material: _KeyMaterial) -> None:
        self.key_id = key_material.material.signing_key_id
        self.generation = key_material.material.signing_key_generation
        self.sha256 = key_material.material.signing_public_key_sha256
        self.public_bytes = _public_bytes(key_material.device_private_key)


class _ForeignHmacRootEpoch:
    def __init__(self, key_material: _KeyMaterial) -> None:
        self.key_id = key_material.material.hmac_key_id
        self.generation = key_material.material.hmac_key_generation
        self.sha256 = key_material.material.hmac_key_sha256
        self.value = key_material.hmac_root


class _StatefulPrivateSigningEpoch(_ForeignPrivateSigningEpoch):
    def __init__(self, key_material: _KeyMaterial, reread_key: Ed25519PrivateKey) -> None:
        super().__init__(key_material)
        self._keys = (key_material.server_private_key, reread_key)
        self._reads = 0

    @property
    def private_key(self) -> Ed25519PrivateKey:
        index = min(self._reads, len(self._keys) - 1)
        self._reads += 1
        return self._keys[index]

    @private_key.setter
    def private_key(self, value: Ed25519PrivateKey) -> None:
        self._keys = (value, value)


class _StatefulPublicSigningEpoch(_ForeignPublicSigningEpoch):
    def __init__(self, key_material: _KeyMaterial, reread_key: Ed25519PrivateKey) -> None:
        super().__init__(key_material)
        self._public_values = (
            _public_bytes(key_material.device_private_key),
            _public_bytes(reread_key),
        )
        self._reads = 0

    @property
    def public_bytes(self) -> bytes:
        index = min(self._reads, len(self._public_values) - 1)
        self._reads += 1
        return self._public_values[index]

    @public_bytes.setter
    def public_bytes(self, value: bytes) -> None:
        self._public_values = (value, value)


class _StatefulHmacRootEpoch(_ForeignHmacRootEpoch):
    def __init__(self, key_material: _KeyMaterial, reread_root: bytes) -> None:
        super().__init__(key_material)
        self._values = (key_material.hmac_root, key_material.hmac_root, reread_root)
        self._reads = 0

    @property
    def value(self) -> bytes:
        index = min(self._reads, len(self._values) - 1)
        self._reads += 1
        return self._values[index]

    @value.setter
    def value(self, root: bytes) -> None:
        self._values = (root, root, root)


@dataclass(frozen=True, slots=True)
class _CoreCase:
    current: _KeyMaterial
    repository: _CorePairingRepository
    vault: _KeyVault
    resolver: PairingKeyResolver


def _core_case(
    *,
    current: _KeyMaterial | None = None,
    additional_key_materials: tuple[_KeyMaterial, ...] = (),
    old_edge_binding: PairingKeyBinding | None = None,
) -> _CoreCase:
    current = current or _key_material(1)
    repository = _CorePairingRepository(current, old_edge_binding=old_edge_binding)
    vault = _KeyVault((current, *additional_key_materials))
    resolver = PairingKeyResolver(repository, vault)
    return _CoreCase(current=current, repository=repository, vault=vault, resolver=resolver)


@pytest.mark.asyncio
async def test_core_resolver_rejects_naive_now_before_repository_or_vault_calls() -> None:
    case = _core_case()
    material = case.current.material

    with pytest.raises(ValueError, match="timestamp must be timezone-aware"):
        await case.resolver.resolve_inbound(
            device_id=DEVICE_ID,
            tls_peer_sha256=material.client_certificate_sha256,
            signing_key_id=material.signing_key_id,
            hmac_key_id=material.hmac_key_id,
            now=NOW.replace(tzinfo=None),
        )

    assert case.repository.calls == []
    assert case.vault.calls == []


@pytest.mark.asyncio
async def test_core_resolver_returns_server_resolved_edge_keys_without_caller_bytes() -> None:
    case = _core_case()
    material = case.current.material

    resolved = await case.resolver.resolve_inbound(
        device_id=DEVICE_ID,
        tls_peer_sha256=material.client_certificate_sha256,
        signing_key_id=material.signing_key_id,
        hmac_key_id=material.hmac_key_id,
        now=NOW,
    )

    assert resolved.pairing == material
    assert resolved.signing_key_id == material.signing_key_id
    assert resolved.hmac_key_id == material.hmac_key_id
    assert resolved.hmac_root == case.current.hmac_root
    assert resolved.public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ) == _public_bytes(case.current.device_private_key)


@pytest.mark.asyncio
async def test_core_resolver_rejects_wrong_mtls_peer_without_address_fallback() -> None:
    case = _core_case()
    material = case.current.material

    with pytest.raises(PermissionError, match="pairing_key_binding"):
        await case.resolver.resolve_inbound(
            device_id=DEVICE_ID,
            tls_peer_sha256=_sha256("new-observed-client-certificate"),
            signing_key_id=material.signing_key_id,
            hmac_key_id=material.hmac_key_id,
            now=NOW,
        )

    assert case.vault.calls == []


@pytest.mark.asyncio
async def test_handshake_and_frame_key_tuple_must_match_one_current_pairing_row() -> None:
    old = _key_material(1)
    current = _key_material(2)
    case = _core_case(current=current, additional_key_materials=(old,))

    with pytest.raises(PermissionError, match="pairing_key_binding"):
        await case.resolver.resolve_inbound(
            device_id=DEVICE_ID,
            tls_peer_sha256=current.material.client_certificate_sha256,
            signing_key_id=old.material.signing_key_id,
            hmac_key_id=current.material.hmac_key_id,
            now=NOW,
        )

    assert case.vault.calls == []


@pytest.mark.asyncio
async def test_rotation_overlap_accepts_only_repository_epochs_until_cutoff() -> None:
    old = _key_material(1)
    current = _key_material(2)
    old_binding = replace(
        PairingKeyBinding.from_material(
            current.material,
            direction="edge_to_core",
            active_from=NOW - timedelta(minutes=5),
            accept_until=NOW + timedelta(seconds=30),
        ),
        signing_key_id=old.material.signing_key_id,
        signing_key_generation=old.material.signing_key_generation,
        signing_public_key_sha256=old.material.signing_public_key_sha256,
        hmac_key_id=old.material.hmac_key_id,
        hmac_key_generation=old.material.hmac_key_generation,
        hmac_key_sha256=old.material.hmac_key_sha256,
    )
    case = _core_case(
        current=current,
        additional_key_materials=(old,),
        old_edge_binding=old_binding,
    )

    old_resolved = await case.resolver.resolve_inbound(
        device_id=DEVICE_ID,
        tls_peer_sha256=current.material.client_certificate_sha256,
        signing_key_id=old.material.signing_key_id,
        hmac_key_id=old.material.hmac_key_id,
        now=NOW,
    )
    current_resolved = await case.resolver.resolve_inbound(
        device_id=DEVICE_ID,
        tls_peer_sha256=current.material.client_certificate_sha256,
        signing_key_id=current.material.signing_key_id,
        hmac_key_id=current.material.hmac_key_id,
        now=NOW,
    )

    assert old_resolved.hmac_key_id == old.material.hmac_key_id
    assert current_resolved.hmac_key_id == current.material.hmac_key_id
    with pytest.raises(PermissionError, match="revoked_or_stale_pairing_key"):
        await case.resolver.resolve_inbound(
            device_id=DEVICE_ID,
            tls_peer_sha256=current.material.client_certificate_sha256,
            signing_key_id=old.material.signing_key_id,
            hmac_key_id=old.material.hmac_key_id,
            now=NOW + timedelta(seconds=30, microseconds=1),
        )


@pytest.mark.asyncio
async def test_recommission_rejects_old_tls_signing_and_hmac_tuple() -> None:
    old = _key_material(1)
    current = _key_material(2)
    old_binding = PairingKeyBinding.from_material(
        old.material,
        direction="edge_to_core",
        active_from=NOW - timedelta(minutes=5),
        accept_until=NOW + timedelta(minutes=5),
    )
    case = _core_case(
        current=current,
        additional_key_materials=(old,),
        old_edge_binding=old_binding,
    )

    with pytest.raises(PermissionError, match="pairing_generation_or_digest"):
        await case.resolver.resolve_inbound(
            device_id=DEVICE_ID,
            tls_peer_sha256=current.material.client_certificate_sha256,
            signing_key_id=old.material.signing_key_id,
            hmac_key_id=old.material.hmac_key_id,
            now=NOW,
        )


@pytest.mark.asyncio
async def test_core_current_outbound_binds_server_public_digest_and_hmac_root() -> None:
    case = _core_case()
    material = case.current.material

    resolved = await case.resolver.current_outbound(
        device_id=DEVICE_ID,
        tls_peer_sha256=material.client_certificate_sha256,
        now=NOW,
    )

    assert resolved.signing_key_id == material.server_key_id
    assert resolved.hmac_key_id == material.hmac_key_id
    assert resolved.hmac_root == case.current.hmac_root
    assert (
        resolved.signer.public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        .hex()
        == _public_bytes(case.current.server_private_key).hex()
    )


class _OSErrorKeyVault(_KeyVault):
    async def resolve_hmac_epoch(
        self,
        device_id: UUID,
        key_id: str,
        now: datetime,
    ) -> HmacRootEpoch:
        raise OSError("keychain read failed at /private/tuntun/secret")


@pytest.mark.asyncio
async def test_core_key_vault_oserror_is_normalized_without_path_detail() -> None:
    key_material = _key_material()
    repository = _CorePairingRepository(key_material)
    resolver = PairingKeyResolver(repository, _OSErrorKeyVault((key_material,)))

    with pytest.raises(PermissionError) as error:
        await resolver.resolve_inbound(
            device_id=DEVICE_ID,
            tls_peer_sha256=key_material.material.client_certificate_sha256,
            signing_key_id=key_material.material.signing_key_id,
            hmac_key_id=key_material.material.hmac_key_id,
            now=NOW,
        )

    assert str(error.value) == "pairing_key_digest_mismatch"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("epoch_kind", "epoch_factory"),
    (
        ("private", lambda key_material: _ForeignPrivateSigningEpoch(key_material)),
        (
            "private",
            lambda key_material: _PrivateSigningKeyEpochSubclass(
                key_id=key_material.material.server_key_id,
                generation=key_material.material.server_key_generation,
                sha256=key_material.material.server_public_key_sha256,
                private_key=key_material.server_private_key,
            ),
        ),
        ("public", lambda key_material: _ForeignPublicSigningEpoch(key_material)),
        (
            "public",
            lambda key_material: _PublicSigningKeyEpochSubclass(
                key_id=key_material.material.signing_key_id,
                generation=key_material.material.signing_key_generation,
                sha256=key_material.material.signing_public_key_sha256,
                public_bytes=_public_bytes(key_material.device_private_key),
            ),
        ),
        ("hmac", lambda key_material: _ForeignHmacRootEpoch(key_material)),
        (
            "hmac",
            lambda key_material: _HmacRootEpochSubclass(
                key_id=key_material.material.hmac_key_id,
                generation=key_material.material.hmac_key_generation,
                sha256=key_material.material.hmac_key_sha256,
                value=key_material.hmac_root,
            ),
        ),
    ),
)
async def test_core_resolver_rejects_non_exact_vault_epoch_objects(
    epoch_kind: str,
    epoch_factory: Callable[[_KeyMaterial], object],
) -> None:
    case = _core_case()
    material = case.current.material
    if epoch_kind == "private":
        case.vault.private_signing[material.server_key_id] = epoch_factory(case.current)
        operation = case.resolver.current_outbound(
            device_id=DEVICE_ID,
            tls_peer_sha256=material.client_certificate_sha256,
            now=NOW,
        )
    else:
        if epoch_kind == "public":
            case.vault.public_signing[material.signing_key_id] = epoch_factory(case.current)
        else:
            case.vault.hmac_roots[material.hmac_key_id] = epoch_factory(case.current)
        operation = case.resolver.resolve_inbound(
            device_id=DEVICE_ID,
            tls_peer_sha256=material.client_certificate_sha256,
            signing_key_id=material.signing_key_id,
            hmac_key_id=material.hmac_key_id,
            now=NOW,
        )

    with pytest.raises(PermissionError) as error:
        await operation

    assert str(error.value) == "pairing_key_digest_mismatch"


@pytest.mark.asyncio
async def test_core_current_outbound_rejects_stateful_private_epoch_properties() -> None:
    case = _core_case()
    material = case.current.material
    case.vault.private_signing[material.server_key_id] = _StatefulPrivateSigningEpoch(
        case.current,
        Ed25519PrivateKey.generate(),
    )

    with pytest.raises(PermissionError) as error:
        await case.resolver.current_outbound(
            device_id=DEVICE_ID,
            tls_peer_sha256=material.client_certificate_sha256,
            now=NOW,
        )

    assert str(error.value) == "pairing_key_digest_mismatch"


@pytest.mark.asyncio
async def test_core_resolve_inbound_rejects_stateful_public_epoch_properties() -> None:
    case = _core_case()
    material = case.current.material
    case.vault.public_signing[material.signing_key_id] = _StatefulPublicSigningEpoch(
        case.current,
        Ed25519PrivateKey.generate(),
    )

    with pytest.raises(PermissionError) as error:
        await case.resolver.resolve_inbound(
            device_id=DEVICE_ID,
            tls_peer_sha256=material.client_certificate_sha256,
            signing_key_id=material.signing_key_id,
            hmac_key_id=material.hmac_key_id,
            now=NOW,
        )

    assert str(error.value) == "pairing_key_digest_mismatch"


@pytest.mark.asyncio
async def test_core_resolve_inbound_rejects_stateful_hmac_epoch_properties() -> None:
    case = _core_case()
    material = case.current.material
    case.vault.hmac_roots[material.hmac_key_id] = _StatefulHmacRootEpoch(
        case.current,
        b"\x7f" * 32,
    )

    with pytest.raises(PermissionError) as error:
        await case.resolver.resolve_inbound(
            device_id=DEVICE_ID,
            tls_peer_sha256=material.client_certificate_sha256,
            signing_key_id=material.signing_key_id,
            hmac_key_id=material.hmac_key_id,
            now=NOW,
        )

    assert str(error.value) == "pairing_key_digest_mismatch"


@pytest.mark.asyncio
async def test_core_resolve_inbound_rejects_exact_public_epoch_malformed_bytes_stably() -> None:
    case = _core_case()
    material = case.current.material
    epoch = case.vault.public_signing[material.signing_key_id]
    object.__setattr__(epoch, "public_bytes", "not-bytes")

    with pytest.raises(PermissionError) as error:
        await case.resolver.resolve_inbound(
            device_id=DEVICE_ID,
            tls_peer_sha256=material.client_certificate_sha256,
            signing_key_id=material.signing_key_id,
            hmac_key_id=material.hmac_key_id,
            now=NOW,
        )

    assert str(error.value) == "pairing_key_digest_mismatch"


class _UsableCommissioningRepository:
    def __init__(self, state: CommissioningStateV1) -> None:
        self.state = state
        self.calls: list[str] = []

    def require_current(self) -> CommissioningStateV1:
        self.calls.append("require_current")
        return self.state

    def require_usable(self, endpoint: ReachyCoreEndpointV1) -> ReachyCoreEndpointV1:
        self.calls.append("require_usable")
        if (
            self.state.status != "active"
            or self.state.legacy_key_id_format
            or self.state.artifact_map is None
            or endpoint != self.state.endpoint
        ):
            raise PermissionError("commissioning_material_revoked")
        return endpoint


class _RecordingArtifactStore:
    def __init__(self, backing: OwnerOnlyArtifactStore) -> None:
        self._backing = backing
        self.reads: list[str] = []

    def write(self, identifier: str, value: bytes) -> None:
        self._backing.write(identifier, value)

    def read(self, identifier: str) -> bytes:
        self.reads.append(identifier)
        return self._backing.read(identifier)

    def delete(self, identifier: str) -> None:
        self._backing.delete(identifier)


class _OSErrorArtifactStore:
    def write(self, identifier: str, value: bytes) -> None:
        raise AssertionError("test does not write through failing store")

    def read(self, identifier: str) -> bytes:
        raise OSError("artifact read failed at /private/tuntun/secret")

    def delete(self, identifier: str) -> None:
        raise AssertionError("test does not delete through failing store")


class _FailingCommissioningRepository:
    def __init__(self, error_factory: Callable[[], BaseException]) -> None:
        self._error_factory = error_factory

    def require_current(self) -> CommissioningStateV1:
        raise self._error_factory()

    def require_usable(self, endpoint: ReachyCoreEndpointV1) -> ReachyCoreEndpointV1:
        raise AssertionError("require_usable should not run after failed current lookup")


class _BindingProxy:
    def __init__(
        self,
        binding: PairingKeyBinding,
        **overrides: object,
    ) -> None:
        self._binding = binding
        self._overrides = overrides

    def __getattr__(self, name: str) -> object:
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._binding, name)


@dataclass(frozen=True, slots=True)
class _EdgeRuntimeKeys:
    binding: object
    public_bytes: object
    hmac_root: object


class _MissingRuntimeRoot:
    def __init__(self, binding: object, public_bytes: object) -> None:
        self.binding = binding
        self.public_bytes = public_bytes


class _MalformedCoreBindingObject:
    direction: Direction = "core_to_edge"
    active_from: datetime = NOW - timedelta(seconds=5)
    accept_until: datetime = NOW + timedelta(seconds=60)

    def __init__(self, material: PairingMaterial) -> None:
        self.signing_key_id = material.server_key_id
        self.hmac_key_id = material.hmac_key_id


class _EdgeKeyRepository:
    def __init__(
        self,
        material: PairingMaterial,
        *,
        accepted_core_keys: tuple[object, ...] = (),
    ) -> None:
        self.current_edge_binding = PairingKeyBinding.from_material(
            material,
            direction="edge_to_core",
            active_from=NOW - timedelta(seconds=5),
            accept_until=NOW + timedelta(seconds=60),
        )
        self.accepted_core_keys: dict[tuple[str, str], object] = {}
        for runtime_keys in accepted_core_keys:
            binding = runtime_keys.binding
            self.accepted_core_keys[(binding.signing_key_id, binding.hmac_key_id)] = runtime_keys

    async def require_current_edge_outbound_tuple(
        self,
        material: PairingMaterial,
        now: datetime,
    ) -> PairingKeyBinding:
        return self.current_edge_binding

    async def require_accepted_core_tuple(
        self,
        material: PairingMaterial,
        signing_key_id: str,
        hmac_key_id: str,
        now: datetime,
    ) -> object:
        try:
            return self.accepted_core_keys[(signing_key_id, hmac_key_id)]
        except KeyError as error:
            raise PermissionError("pairing_key_binding") from error


def _edge_runtime_keys(
    key_material: _KeyMaterial,
    binding: object,
    *,
    public_bytes: object | None = None,
    hmac_root: object | None = None,
) -> _EdgeRuntimeKeys:
    return _EdgeRuntimeKeys(
        binding=binding,
        public_bytes=_public_bytes(key_material.server_private_key)
        if public_bytes is None
        else public_bytes,
        hmac_root=key_material.hmac_root if hmac_root is None else hmac_root,
    )


def _edge_core_binding(
    material: PairingMaterial,
    *,
    active_from: datetime = NOW - timedelta(seconds=5),
    accept_until: datetime = NOW + timedelta(seconds=60),
) -> PairingKeyBinding:
    return PairingKeyBinding.from_material(
        material,
        direction="core_to_edge",
        active_from=active_from,
        accept_until=accept_until,
    )


def _edge_case(
    tmp_path: Path,
    *,
    key_material: _KeyMaterial | None = None,
    state_mutator: Callable[[CommissioningStateV1], CommissioningStateV1] | None = None,
) -> tuple[EdgePairingKeyResolver, _RecordingArtifactStore, CommissioningStateV1, _KeyMaterial]:
    key_material = key_material or _key_material()
    state = _state(key_material.material)
    if state_mutator is not None:
        state = state_mutator(state)
    artifact_map = state.artifact_map
    store = _RecordingArtifactStore(OwnerOnlyArtifactStore(tmp_path / "edge-private"))
    if artifact_map is not None:
        store.write(
            artifact_map.device_signing_private_key_handle,
            _private_bytes(key_material.device_private_key),
        )
        store.write(artifact_map.frame_hmac_root_handle, key_material.hmac_root)
    resolver = EdgePairingKeyResolver(
        _UsableCommissioningRepository(state),
        _EdgeKeyRepository(key_material.material),
        store,
    )
    return resolver, store, state, key_material


def _edge_resolve_case(
    tmp_path: Path,
    *,
    key_material: _KeyMaterial | None = None,
    state_mutator: Callable[[CommissioningStateV1], CommissioningStateV1] | None = None,
    accepted_core_keys: tuple[object, ...] = (),
) -> tuple[EdgePairingKeyResolver, _EdgeKeyRepository, CommissioningStateV1, _KeyMaterial]:
    key_material = key_material or _key_material()
    state = _state(key_material.material)
    if state_mutator is not None:
        state = state_mutator(state)
    repository = _EdgeKeyRepository(
        key_material.material,
        accepted_core_keys=accepted_core_keys,
    )
    resolver = EdgePairingKeyResolver(
        _UsableCommissioningRepository(state),
        repository,
        _RecordingArtifactStore(OwnerOnlyArtifactStore(tmp_path / "edge-private")),
    )
    return resolver, repository, state, key_material


@pytest.mark.asyncio
async def test_edge_resolver_rejects_naive_now_before_commissioning_or_artifact_calls(
    tmp_path: Path,
) -> None:
    key_material = _key_material()
    state = _state(key_material.material)
    commissioning = _UsableCommissioningRepository(state)
    store = _RecordingArtifactStore(OwnerOnlyArtifactStore(tmp_path / "edge-private"))
    resolver = EdgePairingKeyResolver(
        commissioning,
        _EdgeKeyRepository(key_material.material),
        store,
    )

    with pytest.raises(ValueError, match="timestamp must be timezone-aware"):
        await resolver.current_outbound(
            tls_peer_sha256=key_material.material.server_leaf_sha256,
            now=NOW.replace(tzinfo=None),
        )

    assert commissioning.calls == []
    assert store.reads == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error_factory",
    (
        lambda: OSError("commissioning read failed at /private/tuntun/state"),
        lambda: LookupError("commissioning state not found at /private/tuntun/state"),
    ),
)
async def test_edge_commissioning_repository_errors_are_normalized_without_path_detail(
    error_factory: Callable[[], BaseException],
) -> None:
    key_material = _key_material()
    resolver = EdgePairingKeyResolver(
        _FailingCommissioningRepository(error_factory),
        _EdgeKeyRepository(key_material.material),
        _OSErrorArtifactStore(),
    )

    with pytest.raises(PermissionError) as error:
        await resolver.current_outbound(
            tls_peer_sha256=key_material.material.server_leaf_sha256,
            now=NOW,
        )

    assert str(error.value) == "revoked_or_stale_pairing_key"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("active_from", NOW.replace(tzinfo=None)),
        ("accept_until", "2026-09-02T12:30:00Z"),
    ),
)
async def test_edge_rejects_malformed_repository_binding_bounds_with_stable_error(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    resolver, _store, _state, key_material = _edge_case(tmp_path)
    repository = resolver._pairing_keys
    assert isinstance(repository, _EdgeKeyRepository)
    repository.current_edge_binding = _BindingProxy(
        repository.current_edge_binding,
        **{field: value},
    )

    with pytest.raises(PermissionError) as error:
        await resolver.current_outbound(
            tls_peer_sha256=key_material.material.server_leaf_sha256,
            now=NOW,
        )

    assert str(error.value) == "revoked_or_stale_pairing_key"


@pytest.mark.asyncio
async def test_edge_resolve_frame_returns_repository_resolved_core_keys(tmp_path: Path) -> None:
    key_material = _key_material()
    binding = _edge_core_binding(key_material.material)
    runtime_keys = _edge_runtime_keys(key_material, binding)
    resolver, _repository, _state, _current = _edge_resolve_case(
        tmp_path,
        key_material=key_material,
        accepted_core_keys=(runtime_keys,),
    )

    resolved = await resolver.resolve_frame(
        _signed_core_frame(key_material),
        tls_peer_sha256=key_material.material.server_leaf_sha256,
        now=NOW,
    )

    assert resolved.signing_key_id == key_material.material.server_key_id
    assert resolved.hmac_key_id == key_material.material.hmac_key_id
    assert resolved.hmac_root == key_material.hmac_root
    assert resolved.public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ) == _public_bytes(key_material.server_private_key)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("signing_key_generation", True),
        ("hmac_key_generation", -1),
        ("signing_key_id", "bad key"),
        ("hmac_key_id", "bad key"),
        ("signing_public_key_sha256", "A" * 64),
        ("hmac_key_sha256", "not-a-sha256"),
    ),
)
async def test_edge_resolve_frame_validates_repository_binding_metadata(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    key_material = _key_material()
    frame = _signed_core_frame(key_material)
    binding = _BindingProxy(_edge_core_binding(key_material.material), **{field: value})
    runtime_keys = _edge_runtime_keys(key_material, binding)
    resolver, repository, _state, _current = _edge_resolve_case(
        tmp_path,
        key_material=key_material,
        accepted_core_keys=(runtime_keys,),
    )
    repository.accepted_core_keys[
        (key_material.material.server_key_id, key_material.material.hmac_key_id)
    ] = runtime_keys

    with pytest.raises(PermissionError) as error:
        await resolver.resolve_frame(
            frame,
            tls_peer_sha256=key_material.material.server_leaf_sha256,
            now=NOW,
        )

    assert str(error.value) == "pairing_generation_or_digest"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("server_key_id", "ed25519:other-server:v9"),
        ("server_key_generation", 9),
        ("server_public_key_sha256", _sha256("other-valid-server-public")),
    ),
)
async def test_edge_resolve_frame_rejects_internally_incoherent_core_signing_binding(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    key_material = _key_material()
    frame = _signed_core_frame(key_material)
    binding = _BindingProxy(_edge_core_binding(key_material.material), **{field: value})
    runtime_keys = _edge_runtime_keys(key_material, binding)
    resolver, repository, _state, _current = _edge_resolve_case(
        tmp_path,
        key_material=key_material,
        accepted_core_keys=(runtime_keys,),
    )
    repository.accepted_core_keys[
        (key_material.material.server_key_id, key_material.material.hmac_key_id)
    ] = runtime_keys

    with pytest.raises(PermissionError) as error:
        await resolver.resolve_frame(
            frame,
            tls_peer_sha256=key_material.material.server_leaf_sha256,
            now=NOW,
        )

    assert str(error.value) == "pairing_generation_or_digest"


@pytest.mark.asyncio
async def test_edge_resolve_frame_rejects_malformed_binding_object_with_stable_error(
    tmp_path: Path,
) -> None:
    key_material = _key_material()
    malformed_binding = _MalformedCoreBindingObject(key_material.material)
    runtime_keys = _edge_runtime_keys(key_material, malformed_binding)
    resolver, _repository, _state, _current = _edge_resolve_case(
        tmp_path,
        key_material=key_material,
        accepted_core_keys=(runtime_keys,),
    )

    with pytest.raises(PermissionError) as error:
        await resolver.resolve_frame(
            _signed_core_frame(key_material),
            tls_peer_sha256=key_material.material.server_leaf_sha256,
            now=NOW,
        )

    assert str(error.value) == "pairing_generation_or_digest"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "public_bytes",
    (
        "not-bytes",
        b"short",
    ),
)
async def test_edge_resolve_frame_type_checks_runtime_public_bytes_before_hashing(
    tmp_path: Path,
    public_bytes: object,
) -> None:
    key_material = _key_material()
    binding = _edge_core_binding(key_material.material)
    runtime_keys = _edge_runtime_keys(key_material, binding, public_bytes=public_bytes)
    resolver, _repository, _state, _current = _edge_resolve_case(
        tmp_path,
        key_material=key_material,
        accepted_core_keys=(runtime_keys,),
    )

    with pytest.raises(PermissionError) as error:
        await resolver.resolve_frame(
            _signed_core_frame(key_material),
            tls_peer_sha256=key_material.material.server_leaf_sha256,
            now=NOW,
        )

    assert str(error.value) == "pairing_key_digest_mismatch"


@pytest.mark.asyncio
async def test_edge_resolve_frame_rejects_malformed_runtime_root_with_stable_error(
    tmp_path: Path,
) -> None:
    key_material = _key_material()
    binding = _edge_core_binding(key_material.material)
    runtime_keys = _MissingRuntimeRoot(binding, _public_bytes(key_material.server_private_key))
    resolver, _repository, _state, _current = _edge_resolve_case(
        tmp_path,
        key_material=key_material,
        accepted_core_keys=(runtime_keys,),
    )

    with pytest.raises(PermissionError) as error:
        await resolver.resolve_frame(
            _signed_core_frame(key_material),
            tls_peer_sha256=key_material.material.server_leaf_sha256,
            now=NOW,
        )

    assert str(error.value) == "pairing_key_digest_mismatch"


@pytest.mark.asyncio
async def test_edge_resolve_frame_normalizes_malformed_commissioning_material(
    tmp_path: Path,
) -> None:
    key_material = _key_material()
    binding = _edge_core_binding(key_material.material)
    runtime_keys = _edge_runtime_keys(key_material, binding)
    resolver, _repository, _state, _current = _edge_resolve_case(
        tmp_path,
        key_material=key_material,
        state_mutator=lambda state: state.model_copy(update={"endpoint": object()}),
        accepted_core_keys=(runtime_keys,),
    )

    with pytest.raises(PermissionError) as error:
        await resolver.resolve_frame(
            _signed_core_frame(key_material),
            tls_peer_sha256=key_material.material.server_leaf_sha256,
            now=NOW,
        )

    assert str(error.value) == "revoked_or_stale_pairing_key"


@pytest.mark.asyncio
async def test_edge_resolve_frame_accepts_old_bounded_core_tuple_until_cutoff(
    tmp_path: Path,
) -> None:
    old = _key_material(1)
    current = _key_material(2)
    current_binding = _edge_core_binding(current.material)
    old_binding = replace(
        _edge_core_binding(
            current.material,
            active_from=NOW - timedelta(minutes=5),
            accept_until=NOW + timedelta(seconds=30),
        ),
        server_key_id=old.material.server_key_id,
        server_key_generation=old.material.server_key_generation,
        server_public_key_sha256=old.material.server_public_key_sha256,
        signing_key_id=old.material.server_key_id,
        signing_key_generation=old.material.server_key_generation,
        signing_public_key_sha256=old.material.server_public_key_sha256,
        hmac_key_id=old.material.hmac_key_id,
        hmac_key_generation=old.material.hmac_key_generation,
        hmac_key_sha256=old.material.hmac_key_sha256,
    )
    resolver, _repository, _state, _current = _edge_resolve_case(
        tmp_path,
        key_material=current,
        accepted_core_keys=(
            _edge_runtime_keys(current, current_binding),
            _edge_runtime_keys(old, old_binding),
        ),
    )

    old_resolved = await resolver.resolve_frame(
        _signed_core_frame(old),
        tls_peer_sha256=current.material.server_leaf_sha256,
        now=NOW,
    )
    current_resolved = await resolver.resolve_frame(
        _signed_core_frame(current),
        tls_peer_sha256=current.material.server_leaf_sha256,
        now=NOW,
    )

    assert old_resolved.signing_key_id == old.material.server_key_id
    assert old_resolved.hmac_key_id == old.material.hmac_key_id
    assert current_resolved.signing_key_id == current.material.server_key_id
    assert current_resolved.hmac_key_id == current.material.hmac_key_id
    with pytest.raises(PermissionError, match="revoked_or_stale_pairing_key"):
        await resolver.resolve_frame(
            _signed_core_frame(old, occurred_at=NOW + timedelta(seconds=30, microseconds=1)),
            tls_peer_sha256=current.material.server_leaf_sha256,
            now=NOW + timedelta(seconds=30, microseconds=1),
        )


@pytest.mark.asyncio
async def test_edge_artifact_lookup_uses_colonless_handles_not_public_ids(tmp_path: Path) -> None:
    resolver, store, state, key_material = _edge_case(tmp_path)
    material = pairing_material_from_endpoint(state.endpoint)

    resolved = await resolver.current_outbound(
        tls_peer_sha256=key_material.material.server_leaf_sha256,
        now=NOW,
    )

    assert material == key_material.material
    assert resolved.signing_key_id == key_material.material.signing_key_id
    assert resolved.hmac_key_id == key_material.material.hmac_key_id
    assert resolved.hmac_root == key_material.hmac_root
    assert ":" in key_material.material.signing_key_id
    assert ":" not in state.artifact_map.device_signing_private_key_handle
    assert store.reads == [
        state.artifact_map.device_signing_private_key_handle,
        state.artifact_map.frame_hmac_root_handle,
    ]
    assert key_material.material.signing_key_id not in store.reads
    assert key_material.material.hmac_key_id not in store.reads


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutate_store",
    (
        "missing_signing",
        "wrong_signing",
        "wrong_hmac",
    ),
)
async def test_edge_rejects_missing_or_wrong_private_material(
    tmp_path: Path,
    mutate_store: str,
) -> None:
    key_material = _key_material()
    state = _state(key_material.material)
    artifact_map = state.artifact_map
    assert artifact_map is not None
    store = _RecordingArtifactStore(OwnerOnlyArtifactStore(tmp_path / "edge-private"))
    if mutate_store == "wrong_signing":
        store.write(
            artifact_map.device_signing_private_key_handle,
            _private_bytes(Ed25519PrivateKey.generate()),
        )
    elif mutate_store != "missing_signing":
        store.write(
            artifact_map.device_signing_private_key_handle,
            _private_bytes(key_material.device_private_key),
        )
    if mutate_store == "wrong_hmac":
        store.write(artifact_map.frame_hmac_root_handle, bytes(reversed(key_material.hmac_root)))
    else:
        store.write(artifact_map.frame_hmac_root_handle, key_material.hmac_root)
    resolver = EdgePairingKeyResolver(
        _UsableCommissioningRepository(state),
        _EdgeKeyRepository(key_material.material),
        store,
    )

    with pytest.raises(PermissionError, match="pairing_key_digest_mismatch"):
        await resolver.current_outbound(
            tls_peer_sha256=key_material.material.server_leaf_sha256,
            now=NOW,
        )


@pytest.mark.asyncio
async def test_edge_artifact_oserror_is_normalized_without_path_detail() -> None:
    key_material = _key_material()
    state = _state(key_material.material)
    resolver = EdgePairingKeyResolver(
        _UsableCommissioningRepository(state),
        _EdgeKeyRepository(key_material.material),
        _OSErrorArtifactStore(),
    )

    with pytest.raises(PermissionError) as error:
        await resolver.current_outbound(
            tls_peer_sha256=key_material.material.server_leaf_sha256,
            now=NOW,
        )

    assert str(error.value) == "pairing_key_digest_mismatch"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state_mutator",
    (
        lambda state: state.model_copy(update={"legacy_key_id_format": True, "artifact_map": None}),
        lambda state: _state(pairing_material_from_endpoint(state.endpoint), status="revoked"),
    ),
)
async def test_edge_rejects_legacy_or_revoked_commissioning_state(
    tmp_path: Path,
    state_mutator: Callable[[CommissioningStateV1], CommissioningStateV1],
) -> None:
    resolver, _store, _state_value, key_material = _edge_case(
        tmp_path,
        state_mutator=state_mutator,
    )

    with pytest.raises(PermissionError, match="revoked_or_stale_pairing_key"):
        await resolver.current_outbound(
            tls_peer_sha256=key_material.material.server_leaf_sha256,
            now=NOW,
        )


def test_core_pairing_adapter_does_not_import_edge_internals() -> None:
    import tuntun_core.adapters.reachy.pairing as core_pairing

    source_path = inspect.getsourcefile(core_pairing)
    assert source_path is not None
    source = Path(source_path).read_text(encoding="utf-8")
    assert "tuntun_edge" not in source


def test_pairing_material_serializes_no_runtime_secret_bytes() -> None:
    key_material = _key_material()

    fields = PairingMaterial.__dataclass_fields__
    assert "hmac_root" not in fields
    assert "private_key" not in fields
    assert all(
        type(getattr(key_material.material, field_name)) is not bytes for field_name in fields
    )


def test_resolved_outbound_key_material_requires_complete_tuple_members() -> None:
    key_material = _key_material()

    with pytest.raises(TypeError):
        ResolvedOutboundKeys(pairing=key_material.material, signer=key_material.server_private_key)
    with pytest.raises(TypeError):
        EdgeOutboundKeys(pairing=key_material.material, signer=key_material.device_private_key)


def test_hmac_root_epoch_does_not_dataclass_serialize_or_mutate_secret_value() -> None:
    key_material = _key_material()
    epoch = HmacRootEpoch(
        key_id=key_material.material.hmac_key_id,
        generation=key_material.material.hmac_key_generation,
        sha256=key_material.material.hmac_key_sha256,
        value=key_material.hmac_root,
    )

    assert epoch.value == key_material.hmac_root
    assert not is_dataclass(epoch)
    with pytest.raises(TypeError):
        asdict(epoch)
    with pytest.raises(TypeError):
        vars(epoch)
    with pytest.raises(AttributeError):
        epoch.value = b"\x00" * 32
    assert key_material.hmac_root.hex() not in repr(epoch)
    assert repr(key_material.hmac_root) not in repr(epoch)


def test_resolved_runtime_keys_do_not_dataclass_serialize_or_mutate_secrets() -> None:
    key_material = _key_material()
    core_resolved = ResolvedOutboundKeys(
        pairing=key_material.material,
        signer=key_material.server_private_key,
        signing_key_id=key_material.material.server_key_id,
        hmac_key_id=key_material.material.hmac_key_id,
        hmac_root=key_material.hmac_root,
    )
    edge_resolved = EdgeOutboundKeys(
        pairing=key_material.material,
        signer=key_material.device_private_key,
        signing_key_id=key_material.material.signing_key_id,
        hmac_key_id=key_material.material.hmac_key_id,
        hmac_root=key_material.hmac_root,
    )

    for resolved in (core_resolved, edge_resolved):
        assert resolved.hmac_root == key_material.hmac_root
        assert not is_dataclass(resolved)
        with pytest.raises(TypeError):
            asdict(resolved)
        with pytest.raises(TypeError):
            vars(resolved)
        with pytest.raises(AttributeError):
            resolved.hmac_root = b"\x00" * 32
        assert key_material.hmac_root.hex() not in repr(resolved)
        assert repr(key_material.hmac_root) not in repr(resolved)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("hmac_key_generation", True),
        ("signing_key_generation", True),
        ("server_public_key_sha256", "A" * 64),
        ("tls_key_id", "bad key"),
        ("signing_key_id", "bad key"),
    ),
)
def test_pairing_key_binding_rejects_malformed_metadata(field: str, value: object) -> None:
    binding = PairingKeyBinding.from_material(
        _key_material().material,
        direction="edge_to_core",
        active_from=NOW - timedelta(seconds=1),
        accept_until=NOW + timedelta(seconds=1),
    )

    with pytest.raises(ValueError, match="pairing key metadata invalid"):
        replace(binding, **{field: value})


def test_pairing_key_binding_rejects_naive_epoch_bounds() -> None:
    material = _key_material().material

    with pytest.raises(ValueError, match="pairing key epoch bounds must be timezone-aware"):
        PairingKeyBinding.from_material(
            material,
            direction="edge_to_core",
            active_from=NOW.replace(tzinfo=None),
            accept_until=NOW + timedelta(seconds=1),
        )


@pytest.mark.parametrize(
    "factory",
    (
        lambda key_material: PrivateSigningKeyEpoch(
            key_id=key_material.material.server_key_id,
            generation=True,
            sha256=key_material.material.server_public_key_sha256,
            private_key=key_material.server_private_key,
        ),
        lambda key_material: PublicSigningKeyEpoch(
            key_id="bad key",
            generation=key_material.material.signing_key_generation,
            sha256=key_material.material.signing_public_key_sha256,
            public_bytes=_public_bytes(key_material.device_private_key),
        ),
        lambda key_material: HmacRootEpoch(
            key_id=key_material.material.hmac_key_id,
            generation=key_material.material.hmac_key_generation,
            sha256="A" * 64,
            value=key_material.hmac_root,
        ),
        lambda key_material: HmacRootEpoch(
            key_id=key_material.material.hmac_key_id,
            generation=key_material.material.hmac_key_generation,
            sha256=key_material.material.hmac_key_sha256,
            value=b"short",
        ),
    ),
)
def test_key_epoch_metadata_rejects_bool_generations_malformed_ids_or_digests(
    factory: Callable[[_KeyMaterial], object],
) -> None:
    with pytest.raises(ValueError, match="key epoch metadata invalid"):
        factory(_key_material())
