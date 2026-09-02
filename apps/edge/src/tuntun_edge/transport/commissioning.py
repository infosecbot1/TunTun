from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Literal, Protocol, Self, TypeVar, cast
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import Field, StringConstraints, field_validator, model_validator
from tuntun_contracts.base import (
    ContractModel,
    ContractParseError,
    canonical_bytes,
    canonical_mapping_bytes,
    parse_contract_json,
    validate_canonical_base64,
)

SHA256_PATTERN = r"^[0-9a-f]{64}$"
ARTIFACT_HANDLE_PATTERN = r"^[A-Za-z0-9_.-]{8,128}$"
ED25519_KEY_ID_PATTERN = r"^ed25519:[a-z0-9][a-z0-9._-]{0,63}:v[1-9][0-9]{0,8}$"
PUBLIC_KEY_ID_PATTERN = (
    r"^(?:[A-Za-z0-9_.-]{8,128}|ed25519:[a-z0-9][a-z0-9._-]{0,63}:v[1-9][0-9]{0,8})$"
)
CANONICAL_UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
FRAME_HMAC_INFO = b"tuntun/reachy/frame-hmac/v1"
SYNTHETIC_ISSUER_STATE_ID = "synthetic-core-issuer-state.v1"
SYNTHETIC_ISSUER_CLEANUP_STATE_ID = "synthetic-core-issuer-cleanup.v1"
MAX_SYNTHETIC_ISSUER_STATE_BYTES = 16_384
MAX_SYNTHETIC_ISSUER_CLEANUP_STATE_BYTES = 16_384
MAX_SYNTHETIC_ISSUER_PENDING_DELETIONS = 64
SYNTHETIC_CORE_PRIVATE_KEY_HANDLE_PATTERN = r"^reachy-server-g[1-9][0-9]{0,8}-[0-9a-f]{16}$"
REACHY_GENERATOR_CLEANUP_STATE_ID = "reachy-generator-cleanup.v1"
MAX_REACHY_GENERATOR_CLEANUP_STATE_BYTES = 16_384
MAX_REACHY_GENERATOR_PENDING_ARTIFACT_DELETIONS = 16
REACHY_GENERATOR_ARTIFACT_HANDLE_PATTERNS = {
    "client_tls_private_key_handle": r"^reachy-client-tls-g{generation}-[0-9a-f]{{16}}$",
    "client_certificate_handle": r"^reachy-client-cert-g{generation}-[0-9a-f]{{16}}$",
    "device_signing_private_key_handle": r"^reachy-device-sign-g{generation}-[0-9a-f]{{16}}$",
    "frame_hmac_root_handle": r"^reachy-frame-hmac-g{generation}-[0-9a-f]{{16}}$",
}

Sha256Hex = Annotated[str, Field(pattern=SHA256_PATTERN)]
ArtifactHandle = Annotated[
    str,
    Field(min_length=8, max_length=128, pattern=ARTIFACT_HANDLE_PATTERN),
]
Ed25519KeyId = Annotated[
    str,
    Field(min_length=12, max_length=83, pattern=ED25519_KEY_ID_PATTERN),
]
PublicKeyId = Annotated[
    str,
    Field(min_length=8, max_length=128, pattern=PUBLIC_KEY_ID_PATTERN),
]
ArtifactSafePublicKeyId = ArtifactHandle
KeyId = ArtifactHandle
MacAddress = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$"),
]
_LocalPhysicalTransitionResultT = TypeVar("_LocalPhysicalTransitionResultT")


class _SyntheticLocalPhysicalEvidence(ContractModel):
    local_tty: bool
    ssh_host_key_verified: bool
    one_time_code_verified: bool
    dhcp_reservations_verified: bool

    def require_valid(self) -> None:
        if not (
            self.local_tty
            and self.ssh_host_key_verified
            and self.one_time_code_verified
            and self.dhcp_reservations_verified
        ):
            raise PermissionError("local_physical_commissioning_required")


class LocalPhysicalProof(ContractModel):
    schema_version: Literal["tuntun.reachy-local-physical-proof.v1"]
    proof_id: Annotated[str, Field(pattern=CANONICAL_UUID_PATTERN)]
    operation: Literal["commission", "recommission", "revoke"]
    request_sha256: Sha256Hex | None
    current_state_sha256: Sha256Hex | None
    current_generation: Annotated[int, Field(ge=1)] | None
    target_generation: Annotated[int, Field(ge=1)]
    verifier_mac_sha256: Sha256Hex

    @model_validator(mode="after")
    def scope_is_closed(self) -> Self:
        if self.operation in {"commission", "recommission"} and self.request_sha256 is None:
            raise ValueError("local physical proof request binding required")
        if self.operation == "commission":
            if self.current_state_sha256 is not None or self.current_generation is not None:
                raise ValueError("initial local physical proof cannot bind current state")
            if self.target_generation != 1:
                raise ValueError("initial local physical proof must target generation 1")
        else:
            if self.current_state_sha256 is None or self.current_generation is None:
                raise ValueError("local physical proof current binding required")
            expected_target = (
                self.current_generation
                if self.operation == "revoke"
                else self.current_generation + 1
            )
            if self.target_generation != expected_target:
                raise ValueError("local physical proof target generation mismatch")
        if self.operation == "revoke" and self.request_sha256 is not None:
            raise ValueError("revoke local physical proof cannot bind a request")
        return self


class LocalPhysicalProofVerifier:
    def __init__(self) -> None:
        self._key = secrets.token_bytes(32)
        self._issued: set[str] = set()
        self._consumed: set[str] = set()

    @classmethod
    def _from_synthetic_issuer(
        cls,
        *,
        key: bytes,
        issued: set[str],
        consumed: set[str],
    ) -> LocalPhysicalProofVerifier:
        if type(key) is not bytes or len(key) != 32:
            raise ValueError("local physical proof verifier key must be 32 bytes")
        instance = cls.__new__(cls)
        instance._key = key
        instance._issued = issued
        instance._consumed = consumed
        return instance

    def consume(
        self,
        proof: LocalPhysicalProof,
        *,
        operation: Literal["commission", "recommission", "revoke"],
        request: ReachyCommissioningRequestV1 | None = None,
        current: CommissioningStateV1 | None = None,
    ) -> None:
        _consume_local_physical_proof(
            key=self._key,
            issued=self._issued,
            consumed=self._consumed,
            proof=proof,
            operation=operation,
            request=request,
            current=current,
        )

    def consume_and_execute(
        self,
        proof: LocalPhysicalProof,
        *,
        operation: Literal["commission", "recommission", "revoke"],
        request: ReachyCommissioningRequestV1 | None = None,
        current: CommissioningStateV1 | None = None,
        transition: Callable[[], _LocalPhysicalTransitionResultT],
    ) -> _LocalPhysicalTransitionResultT:
        self.consume(
            proof=proof,
            operation=operation,
            request=request,
            current=current,
        )
        return transition()


class _SyntheticLocalPhysicalProofIssuer:
    def __init__(self, *, key: bytes | None = None) -> None:
        if key is None:
            key = secrets.token_bytes(32)
        if type(key) is not bytes or len(key) != 32:
            raise ValueError("local physical proof issuer key must be 32 bytes")
        self._key = key
        self._issued: set[str] = set()
        self._consumed: set[str] = set()
        self.consumer = LocalPhysicalProofVerifier._from_synthetic_issuer(
            key=self._key,
            issued=self._issued,
            consumed=self._consumed,
        )

    def issue(
        self,
        evidence: _SyntheticLocalPhysicalEvidence,
        *,
        operation: Literal["commission", "recommission", "revoke"],
        request: ReachyCommissioningRequestV1 | None = None,
        current: CommissioningStateV1 | None = None,
    ) -> LocalPhysicalProof:
        evidence.require_valid()
        proof_id = str(uuid4())
        values = _local_physical_proof_values(
            proof_id=proof_id,
            operation=operation,
            request=request,
            current=current,
        )
        proof = LocalPhysicalProof(
            schema_version="tuntun.reachy-local-physical-proof.v1",
            proof_id=cast(str, values["proof_id"]),
            operation=cast(Literal["commission", "recommission", "revoke"], values["operation"]),
            request_sha256=cast(str | None, values["request_sha256"]),
            current_state_sha256=cast(str | None, values["current_state_sha256"]),
            current_generation=cast(int | None, values["current_generation"]),
            target_generation=cast(int, values["target_generation"]),
            verifier_mac_sha256=_local_physical_proof_mac(self._key, values),
        )
        self._issued.add(proof.proof_id)
        return proof


def _consume_local_physical_proof(
    *,
    key: bytes,
    issued: set[str],
    consumed: set[str],
    proof: LocalPhysicalProof,
    operation: Literal["commission", "recommission", "revoke"],
    request: ReachyCommissioningRequestV1 | None,
    current: CommissioningStateV1 | None,
) -> None:
    if proof.proof_id not in issued:
        raise PermissionError("local_physical_proof_unrecognized")
    if proof.proof_id in consumed:
        raise PermissionError("local_physical_proof_consumed")
    expected_values = _local_physical_proof_values(
        proof_id=proof.proof_id,
        operation=operation,
        request=request,
        current=current,
    )
    if proof.operation != expected_values["operation"]:
        raise PermissionError("local_physical_proof_operation_mismatch")
    if proof.request_sha256 != expected_values["request_sha256"]:
        raise PermissionError("local_physical_proof_request_mismatch")
    if (
        proof.current_state_sha256 != expected_values["current_state_sha256"]
        or proof.current_generation != expected_values["current_generation"]
        or proof.target_generation != expected_values["target_generation"]
    ):
        raise PermissionError("local_physical_proof_current_mismatch")
    if not hmac.compare_digest(
        proof.verifier_mac_sha256,
        _local_physical_proof_mac(key, expected_values),
    ):
        raise PermissionError("local_physical_proof_authentication_failed")
    consumed.add(proof.proof_id)


class ReachyCommissioningRequestV1(ContractModel):
    schema_version: Literal["tuntun.reachy-commissioning-request.v1"]
    commissioning_uuid: Annotated[str, Field(pattern=CANONICAL_UUID_PATTERN)]
    core_ipv4: Annotated[str, Field(min_length=7, max_length=15)]
    core_link_address: MacAddress
    port: Literal[7443]
    boot_identity_sha256: Sha256Hex
    capability_evidence_sha256: Sha256Hex
    dhcp_reservation_receipt_sha256: Sha256Hex

    @field_validator("core_ipv4")
    @classmethod
    def canonical_rfc1918_core_ipv4(cls, value: str) -> str:
        return _canonical_rfc1918_ipv4(value, label="core endpoint")

    @field_validator("core_link_address")
    @classmethod
    def canonical_unicast_link_address(cls, value: str) -> str:
        return _canonical_unicast_mac(value, label="core link address")


class ReachyCoreEndpointV1(ContractModel):
    schema_version: Literal["tuntun.reachy-core-endpoint.v1"]
    commissioning_uuid: Annotated[str, Field(pattern=CANONICAL_UUID_PATTERN)]
    generation: Annotated[int, Field(ge=1)]
    certificate_generation: Annotated[int, Field(ge=1)]
    server_key_generation: Annotated[int, Field(ge=1)]
    trust_digest_generation: Annotated[int, Field(ge=1)]
    client_tls_key_generation: Annotated[int, Field(ge=1)]
    device_signing_key_generation: Annotated[int, Field(ge=1)]
    hmac_key_generation: Annotated[int, Field(ge=1)]
    core_ipv4: Annotated[str, Field(min_length=7, max_length=15)]
    core_link_address: MacAddress
    port: Literal[7443]
    household_ca_sha256: Sha256Hex
    server_leaf_sha256: Sha256Hex
    server_key_id: PublicKeyId
    server_public_key_sha256: Sha256Hex
    server_ip_sans: tuple[str, ...]
    client_certificate_sha256: Sha256Hex
    client_tls_key_id: ArtifactSafePublicKeyId
    client_tls_public_key_sha256: Sha256Hex
    device_signing_key_id: PublicKeyId
    device_signing_public_key_sha256: Sha256Hex
    hmac_key_id: ArtifactSafePublicKeyId
    hmac_key_sha256: Sha256Hex
    hmac_agreement_public_key_sha256: Sha256Hex
    dhcp_reservation_receipt_sha256: Sha256Hex
    boot_identity_sha256: Sha256Hex
    capability_evidence_sha256: Sha256Hex

    @field_validator("core_ipv4")
    @classmethod
    def canonical_rfc1918_core_ipv4(cls, value: str) -> str:
        return _canonical_rfc1918_ipv4(value, label="core endpoint")

    @field_validator("core_link_address")
    @classmethod
    def canonical_unicast_link_address(cls, value: str) -> str:
        return _canonical_unicast_mac(value, label="core link address")

    @field_validator("server_ip_sans")
    @classmethod
    def canonical_numeric_ip_sans(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for address in value:
            _canonical_rfc1918_ipv4(address, label="server certificate SAN")
        return value

    @model_validator(mode="after")
    def exact_endpoint_binding(self) -> Self:
        if self.server_ip_sans != (self.core_ipv4,):
            raise ValueError("server certificate requires sole exact numeric Mac IP SAN")
        generations = {
            self.generation,
            self.certificate_generation,
            self.server_key_generation,
            self.trust_digest_generation,
            self.client_tls_key_generation,
            self.device_signing_key_generation,
            self.hmac_key_generation,
        }
        if len(generations) != 1:
            raise ValueError("commissioning endpoint contains mixed generations")
        if len(set(_endpoint_key_ids(self))) != 4:
            raise ValueError("commissioning endpoint key identifiers must be unique")
        if self.server_leaf_sha256 == self.client_certificate_sha256:
            raise ValueError("commissioning endpoint certificate digests must be distinct")
        return self


class ReachyCommissioningArtifactMapV1(ContractModel):
    schema_version: Literal["tuntun.reachy-commissioning-artifact-map.v1"] = (
        "tuntun.reachy-commissioning-artifact-map.v1"
    )
    generation: Annotated[int, Field(ge=1)]
    client_tls_private_key_handle: ArtifactHandle
    client_certificate_handle: ArtifactHandle
    device_signing_private_key_handle: ArtifactHandle
    frame_hmac_root_handle: ArtifactHandle

    @field_validator(
        "client_tls_private_key_handle",
        "client_certificate_handle",
        "device_signing_private_key_handle",
        "frame_hmac_root_handle",
    )
    @classmethod
    def artifact_handles_are_not_reserved(cls, value: str) -> str:
        if value in {
            SYNTHETIC_ISSUER_STATE_ID,
            SYNTHETIC_ISSUER_CLEANUP_STATE_ID,
            REACHY_GENERATOR_CLEANUP_STATE_ID,
        }:
            raise ValueError("commissioning artifact handle is reserved")
        return value

    @model_validator(mode="after")
    def artifact_handles_are_unique(self) -> Self:
        handles = _artifact_map_handles(self)
        if len(set(handles)) != len(handles):
            raise ValueError("commissioning artifact handles must be unique")
        return self


class ReachyGeneratorArtifactCleanupEntryV1(ContractModel):
    generation: Annotated[int, Field(ge=1)]
    client_tls_private_key_handle: ArtifactHandle
    client_certificate_handle: ArtifactHandle
    device_signing_private_key_handle: ArtifactHandle
    frame_hmac_root_handle: ArtifactHandle

    @field_validator(
        "client_tls_private_key_handle",
        "client_certificate_handle",
        "device_signing_private_key_handle",
        "frame_hmac_root_handle",
    )
    @classmethod
    def cleanup_artifact_handles_are_not_reserved(cls, value: str) -> str:
        if value in {
            SYNTHETIC_ISSUER_STATE_ID,
            SYNTHETIC_ISSUER_CLEANUP_STATE_ID,
            REACHY_GENERATOR_CLEANUP_STATE_ID,
        }:
            raise ValueError("Reachy generator cleanup artifact handle is reserved")
        return value

    @model_validator(mode="after")
    def cleanup_artifact_handles_are_exact_generated_bundle(self) -> Self:
        handles = _reachy_cleanup_entry_handles(self)
        if len(set(handles)) != len(handles):
            raise ValueError("Reachy generator cleanup artifact handles must be unique")
        for field_name, pattern_template in REACHY_GENERATOR_ARTIFACT_HANDLE_PATTERNS.items():
            pattern = pattern_template.format(generation=self.generation)
            if re.fullmatch(pattern, getattr(self, field_name)) is None:
                raise ValueError("Reachy generator cleanup artifact handle invalid")
        return self


class ReachyGeneratorArtifactCleanupJournalV1(ContractModel):
    schema_version: Literal["tuntun.reachy-generator-artifact-cleanup.v1"]
    pending_artifact_deletions: Annotated[
        tuple[ReachyGeneratorArtifactCleanupEntryV1, ...],
        Field(max_length=MAX_REACHY_GENERATOR_PENDING_ARTIFACT_DELETIONS),
    ] = ()

    @field_validator("pending_artifact_deletions")
    @classmethod
    def pending_artifact_deletions_are_unique_and_sorted(
        cls,
        value: tuple[ReachyGeneratorArtifactCleanupEntryV1, ...],
    ) -> tuple[ReachyGeneratorArtifactCleanupEntryV1, ...]:
        keys = tuple(_reachy_cleanup_entry_key(entry) for entry in value)
        if len(set(keys)) != len(keys):
            raise ValueError("Reachy generator cleanup entries must be unique")
        if tuple(sorted(keys)) != keys:
            raise ValueError("Reachy generator cleanup entries must be sorted")
        return value


class CommissioningStateV1(ContractModel):
    schema_version: Literal["tuntun.reachy-commissioning-state.v1"]
    status: Literal["active", "revoked"] = "active"
    endpoint: ReachyCoreEndpointV1
    artifact_map: ReachyCommissioningArtifactMapV1 | None = None
    legacy_key_id_format: bool = False
    revoked_key_ids: Annotated[tuple[PublicKeyId, ...], Field(max_length=4)] = ()
    revoked_certificate_sha256: Annotated[tuple[Sha256Hex, ...], Field(max_length=2)] = ()

    @field_validator("revoked_key_ids")
    @classmethod
    def revoked_key_ids_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("revoked key identifiers must be unique")
        return value

    @field_validator("revoked_certificate_sha256")
    @classmethod
    def revoked_certificates_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("revoked certificate digests must be unique")
        return value

    @model_validator(mode="after")
    def validate_identity_split_and_revocation_inventory(self) -> Self:
        if self.legacy_key_id_format:
            if self.artifact_map is not None:
                raise ValueError("legacy commissioning state must not include artifact_map")
        else:
            if self.artifact_map is None:
                raise ValueError("commissioning artifact_map is required")
            if self.artifact_map.generation != self.endpoint.generation:
                raise ValueError("artifact_map generation must match endpoint generation")
            if not _is_ed25519_key_id(self.endpoint.server_key_id) or not _is_ed25519_key_id(
                self.endpoint.device_signing_key_id
            ):
                raise ValueError(
                    "server_key_id and device_signing_key_id must be public ed25519 ids"
                )
            private_handles = set(_artifact_map_handles(self.artifact_map))
            if private_handles & set(_endpoint_key_ids(self.endpoint)):
                raise ValueError("private artifact handles must be distinct from public key ids")
        if self.status == "active" and self.endpoint.generation == 1:
            if self.revoked_key_ids or self.revoked_certificate_sha256:
                raise ValueError("initial generation cannot revoke material")
            return self
        if self.status == "active":
            if len(self.revoked_key_ids) != 4 or len(self.revoked_certificate_sha256) != 2:
                raise ValueError(
                    "active recommissioning state requires exactly four revoked key "
                    "identifiers and two revoked certificate digests"
                )
            return self
        if self.revoked_key_ids != _endpoint_key_ids(self.endpoint) or (
            self.revoked_certificate_sha256 != _endpoint_certificate_digests(self.endpoint)
        ):
            raise ValueError("revoked state must bind exactly current endpoint material")
        return self


class LegacyReachyCoreEndpointV1(ContractModel):
    schema_version: Literal["tuntun.reachy-core-endpoint.v1"]
    commissioning_uuid: Annotated[str, Field(pattern=CANONICAL_UUID_PATTERN)]
    generation: Annotated[int, Field(ge=1)]
    certificate_generation: Annotated[int, Field(ge=1)]
    server_key_generation: Annotated[int, Field(ge=1)]
    trust_digest_generation: Annotated[int, Field(ge=1)]
    client_tls_key_generation: Annotated[int, Field(ge=1)]
    device_signing_key_generation: Annotated[int, Field(ge=1)]
    hmac_key_generation: Annotated[int, Field(ge=1)]
    core_ipv4: Annotated[str, Field(min_length=7, max_length=15)]
    core_link_address: MacAddress
    port: Literal[7443]
    household_ca_sha256: Sha256Hex
    server_leaf_sha256: Sha256Hex
    server_key_id: ArtifactHandle
    server_public_key_sha256: Sha256Hex
    server_ip_sans: tuple[str, ...]
    client_certificate_sha256: Sha256Hex
    client_tls_key_id: ArtifactHandle
    client_tls_public_key_sha256: Sha256Hex
    device_signing_key_id: ArtifactHandle
    device_signing_public_key_sha256: Sha256Hex
    hmac_key_id: ArtifactHandle
    hmac_key_sha256: Sha256Hex
    hmac_agreement_public_key_sha256: Sha256Hex
    dhcp_reservation_receipt_sha256: Sha256Hex
    boot_identity_sha256: Sha256Hex
    capability_evidence_sha256: Sha256Hex

    @field_validator("core_ipv4")
    @classmethod
    def canonical_rfc1918_core_ipv4(cls, value: str) -> str:
        return _canonical_rfc1918_ipv4(value, label="core endpoint")

    @field_validator("core_link_address")
    @classmethod
    def canonical_unicast_link_address(cls, value: str) -> str:
        return _canonical_unicast_mac(value, label="core link address")

    @field_validator("server_ip_sans")
    @classmethod
    def canonical_numeric_ip_sans(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for address in value:
            _canonical_rfc1918_ipv4(address, label="server certificate SAN")
        return value

    @model_validator(mode="after")
    def exact_endpoint_binding(self) -> Self:
        if self.server_ip_sans != (self.core_ipv4,):
            raise ValueError("server certificate requires sole exact numeric Mac IP SAN")
        generations = {
            self.generation,
            self.certificate_generation,
            self.server_key_generation,
            self.trust_digest_generation,
            self.client_tls_key_generation,
            self.device_signing_key_generation,
            self.hmac_key_generation,
        }
        if len(generations) != 1:
            raise ValueError("commissioning endpoint contains mixed generations")
        if len(set(_legacy_endpoint_key_ids(self))) != 4:
            raise ValueError("commissioning endpoint key identifiers must be unique")
        if self.server_leaf_sha256 == self.client_certificate_sha256:
            raise ValueError("commissioning endpoint certificate digests must be distinct")
        return self


class LegacyCommissioningStateV1(ContractModel):
    schema_version: Literal["tuntun.reachy-commissioning-state.v1"]
    status: Literal["active", "revoked"] = "active"
    endpoint: LegacyReachyCoreEndpointV1
    revoked_key_ids: Annotated[tuple[ArtifactHandle, ...], Field(max_length=4)] = ()
    revoked_certificate_sha256: Annotated[tuple[Sha256Hex, ...], Field(max_length=2)] = ()

    @field_validator("revoked_key_ids")
    @classmethod
    def revoked_key_ids_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("revoked key identifiers must be unique")
        return value

    @field_validator("revoked_certificate_sha256")
    @classmethod
    def revoked_certificates_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("revoked certificate digests must be unique")
        return value

    @model_validator(mode="after")
    def bounded_revocation_inventory(self) -> Self:
        if self.status == "active" and self.endpoint.generation == 1:
            if self.revoked_key_ids or self.revoked_certificate_sha256:
                raise ValueError("initial generation cannot revoke material")
            return self
        if self.status == "active":
            if len(self.revoked_key_ids) != 4 or len(self.revoked_certificate_sha256) != 2:
                raise ValueError(
                    "active recommissioning state requires exactly four revoked key "
                    "identifiers and two revoked certificate digests"
                )
            return self
        if self.revoked_key_ids != _legacy_endpoint_key_ids(self.endpoint) or (
            self.revoked_certificate_sha256 != _legacy_endpoint_certificate_digests(self.endpoint)
        ):
            raise ValueError("revoked state must bind exactly current endpoint material")
        return self


class CommissioningAssuranceV1(ContractModel):
    schema_version: Literal["tuntun.reachy-commissioning-assurance.v1"]
    source: Literal["synthetic", "hardware"]
    generation: Annotated[int, Field(ge=1)]
    endpoint_sha256: Sha256Hex


_ASSURANCE_CAPABILITY_MARKER = object()
_HARDWARE_CEREMONY_MARKER = object()


class _CommissioningAssuranceCapability:
    __slots__ = ("_marker", "_source")

    def __init__(
        self,
        *,
        source: Literal["synthetic", "hardware"],
        marker: object,
    ) -> None:
        if marker is not _ASSURANCE_CAPABILITY_MARKER:
            raise PermissionError("commissioning_assurance_capability_required")
        self._source = source
        self._marker = marker

    @property
    def source(self) -> Literal["synthetic", "hardware"]:
        if self._marker is not _ASSURANCE_CAPABILITY_MARKER:
            raise PermissionError("commissioning_assurance_capability_required")
        return self._source


class _SyntheticCommissioningAssuranceCapability(_CommissioningAssuranceCapability):
    def __init__(self) -> None:
        super().__init__(source="synthetic", marker=_ASSURANCE_CAPABILITY_MARKER)


class _HardwareCommissioningAssuranceCapability(_CommissioningAssuranceCapability):
    def __init__(self) -> None:
        raise TypeError("hardware commissioning assurance requires physical ceremony boundary")

    @classmethod
    def _from_physical_ceremony(
        cls,
        marker: object,
    ) -> _HardwareCommissioningAssuranceCapability:
        if marker is not _HARDWARE_CEREMONY_MARKER:
            raise PermissionError("hardware_commissioning_ceremony_required")
        instance = cls.__new__(cls)
        _CommissioningAssuranceCapability.__init__(
            instance,
            source="hardware",
            marker=_ASSURANCE_CAPABILITY_MARKER,
        )
        return instance


def _commissioning_assurance_kind(
    assurance: object,
) -> Literal["synthetic", "hardware"]:
    if type(assurance) not in {
        _SyntheticCommissioningAssuranceCapability,
        _HardwareCommissioningAssuranceCapability,
    }:
        raise PermissionError("commissioning_assurance_capability_required")
    if not isinstance(assurance, _CommissioningAssuranceCapability):
        raise PermissionError("commissioning_assurance_capability_required")
    return assurance.source


class GeneratedReachyMaterialV1(ContractModel):
    schema_version: Literal["tuntun.reachy-generated-public-material.v1"]
    generation: Annotated[int, Field(ge=1)]
    client_tls_key_id: ArtifactSafePublicKeyId
    client_tls_csr_pem: Annotated[str, Field(min_length=64, max_length=4096)]
    client_tls_public_key_sha256: Sha256Hex
    device_signing_key_id: Ed25519KeyId
    device_signing_public_key_b64: Annotated[str, Field(min_length=44, max_length=44)]
    device_signing_public_key_sha256: Sha256Hex
    hmac_key_id: ArtifactSafePublicKeyId
    hmac_agreement_public_key_b64: Annotated[str, Field(min_length=44, max_length=44)]
    hmac_agreement_public_key_sha256: Sha256Hex
    hmac_key_sha256: Sha256Hex

    @field_validator("device_signing_public_key_b64", "hmac_agreement_public_key_b64")
    @classmethod
    def canonical_public_key_b64(cls, value: str) -> str:
        return validate_canonical_base64(value, expected_bytes=32, label="Reachy public key")

    @field_validator("client_tls_csr_pem")
    @classmethod
    def public_csr_only(cls, value: str) -> str:
        if "PRIVATE" in value.upper() or "SYMMETRIC" in value.upper():
            raise ValueError("Reachy public exchange cannot contain private material")
        if not value.startswith("-----BEGIN CERTIFICATE REQUEST-----\n"):
            raise ValueError("Reachy client TLS CSR must be PEM encoded")
        if not value.endswith("\n-----END CERTIFICATE REQUEST-----\n"):
            raise ValueError("Reachy client TLS CSR must be PEM encoded")
        return value


@dataclass(frozen=True, slots=True)
class GeneratedReachyMaterialBundle:
    public: GeneratedReachyMaterialV1
    artifacts: ReachyCommissioningArtifactMapV1


class PreparedCoreMaterialV1(ContractModel):
    schema_version: Literal["tuntun.core-prepared-commissioning-material.v1"]
    generation: Annotated[int, Field(ge=1)]
    commissioning_uuid: Annotated[str, Field(pattern=CANONICAL_UUID_PATTERN)]
    core_ipv4: Annotated[str, Field(min_length=7, max_length=15)]
    core_link_address: MacAddress
    port: Literal[7443]
    boot_identity_sha256: Sha256Hex
    capability_evidence_sha256: Sha256Hex
    dhcp_reservation_receipt_sha256: Sha256Hex
    household_ca_sha256: Sha256Hex
    certificate_generation: Annotated[int, Field(ge=1)]
    server_key_generation: Annotated[int, Field(ge=1)]
    trust_digest_generation: Annotated[int, Field(ge=1)]
    server_leaf_sha256: Sha256Hex
    server_key_id: Ed25519KeyId
    server_private_key_handle: ArtifactHandle
    server_public_key_sha256: Sha256Hex
    core_hmac_agreement_public_key_b64: Annotated[str, Field(min_length=44, max_length=44)]
    core_hmac_agreement_public_key_sha256: Sha256Hex

    @field_validator("core_ipv4")
    @classmethod
    def canonical_rfc1918_core_ipv4(cls, value: str) -> str:
        return _canonical_rfc1918_ipv4(value, label="core endpoint")

    @field_validator("core_link_address")
    @classmethod
    def canonical_unicast_link_address(cls, value: str) -> str:
        return _canonical_unicast_mac(value, label="core link address")

    @field_validator("core_hmac_agreement_public_key_b64")
    @classmethod
    def canonical_core_public_key_b64(cls, value: str) -> str:
        return validate_canonical_base64(value, expected_bytes=32, label="Core public key")

    @field_validator("server_private_key_handle")
    @classmethod
    def server_private_key_handle_is_not_reserved(cls, value: str) -> str:
        if value in {SYNTHETIC_ISSUER_STATE_ID, SYNTHETIC_ISSUER_CLEANUP_STATE_ID}:
            raise ValueError("synthetic issuer state identifier is reserved")
        return value

    @model_validator(mode="after")
    def generations_match(self) -> Self:
        if {
            self.generation,
            self.certificate_generation,
            self.server_key_generation,
            self.trust_digest_generation,
        } != {self.generation}:
            raise ValueError("core commissioning material contains mixed generations")
        return self


class LegacyPreparedCoreMaterialV1(ContractModel):
    schema_version: Literal["tuntun.core-prepared-commissioning-material.v1"]
    generation: Annotated[int, Field(ge=1)]
    commissioning_uuid: Annotated[str, Field(pattern=CANONICAL_UUID_PATTERN)]
    core_ipv4: Annotated[str, Field(min_length=7, max_length=15)]
    core_link_address: MacAddress
    port: Literal[7443]
    boot_identity_sha256: Sha256Hex
    capability_evidence_sha256: Sha256Hex
    dhcp_reservation_receipt_sha256: Sha256Hex
    household_ca_sha256: Sha256Hex
    certificate_generation: Annotated[int, Field(ge=1)]
    server_key_generation: Annotated[int, Field(ge=1)]
    trust_digest_generation: Annotated[int, Field(ge=1)]
    server_leaf_sha256: Sha256Hex
    server_key_id: ArtifactHandle
    server_public_key_sha256: Sha256Hex
    core_hmac_agreement_public_key_b64: Annotated[str, Field(min_length=44, max_length=44)]
    core_hmac_agreement_public_key_sha256: Sha256Hex

    @field_validator("core_ipv4")
    @classmethod
    def canonical_rfc1918_core_ipv4(cls, value: str) -> str:
        return _canonical_rfc1918_ipv4(value, label="core endpoint")

    @field_validator("core_link_address")
    @classmethod
    def canonical_unicast_link_address(cls, value: str) -> str:
        return _canonical_unicast_mac(value, label="core link address")

    @field_validator("core_hmac_agreement_public_key_b64")
    @classmethod
    def canonical_core_public_key_b64(cls, value: str) -> str:
        return validate_canonical_base64(value, expected_bytes=32, label="Core public key")

    @model_validator(mode="after")
    def generations_match(self) -> Self:
        if {
            self.generation,
            self.certificate_generation,
            self.server_key_generation,
            self.trust_digest_generation,
        } != {self.generation}:
            raise ValueError("core commissioning material contains mixed generations")
        return self


class IssuedClientMaterialV1(ContractModel):
    schema_version: Literal["tuntun.issued-client-commissioning-material.v1"]
    generation: Annotated[int, Field(ge=1)]
    client_certificate_pem: Annotated[str, Field(min_length=64, max_length=4096)]
    client_certificate_sha256: Sha256Hex
    hmac_key_sha256: Sha256Hex

    @field_validator("client_certificate_pem")
    @classmethod
    def public_certificate_only(cls, value: str) -> str:
        if "PRIVATE" in value.upper() or "SYMMETRIC" in value.upper():
            raise ValueError("issued certificate cannot contain private material")
        if not value.startswith("-----BEGIN CERTIFICATE-----\n"):
            raise ValueError("issued client certificate must be PEM encoded")
        if not value.endswith("\n-----END CERTIFICATE-----\n"):
            raise ValueError("issued client certificate must be PEM encoded")
        return value


class SyntheticCoreIssuerLifecycleV1(ContractModel):
    schema_version: Literal["tuntun.synthetic-core-issuer-lifecycle.v1"]
    active_generation: Annotated[int, Field(ge=1)] | None
    staged_generations: tuple[PreparedCoreMaterialV1, ...] = ()
    revoked_generations: tuple[Annotated[int, Field(ge=1)], ...] = ()

    @field_validator("staged_generations")
    @classmethod
    def staged_generations_are_unique(
        cls,
        value: tuple[PreparedCoreMaterialV1, ...],
    ) -> tuple[PreparedCoreMaterialV1, ...]:
        generations = tuple(item.generation for item in value)
        if len(set(generations)) != len(generations):
            raise ValueError("synthetic issuer staged generations must be unique")
        if tuple(sorted(generations)) != generations:
            raise ValueError("synthetic issuer staged generations must be sorted")
        handles = tuple(item.server_private_key_handle for item in value)
        if len(set(handles)) != len(handles):
            raise ValueError("synthetic issuer staged private key handles must be unique")
        return value

    @field_validator("revoked_generations")
    @classmethod
    def revoked_generations_are_unique(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if len(set(value)) != len(value):
            raise ValueError("synthetic issuer revoked generations must be unique")
        if tuple(sorted(value)) != value:
            raise ValueError("synthetic issuer revoked generations must be sorted")
        return value

    @model_validator(mode="after")
    def active_generation_is_staged(self) -> Self:
        staged_generations = {item.generation for item in self.staged_generations}
        revoked_generations = set(self.revoked_generations)
        if self.active_generation is not None and self.active_generation not in staged_generations:
            raise ValueError("synthetic issuer active generation must be staged")
        if staged_generations & revoked_generations:
            raise ValueError("synthetic issuer revoked generations must not be staged")
        if self.active_generation is not None and self.active_generation in revoked_generations:
            raise ValueError("synthetic issuer active generation must not be revoked")
        return self


class SyntheticCoreIssuerCleanupV1(ContractModel):
    schema_version: Literal["tuntun.synthetic-core-issuer-cleanup.v1"]
    pending_private_key_deletions: Annotated[
        tuple[ArtifactHandle, ...],
        Field(max_length=MAX_SYNTHETIC_ISSUER_PENDING_DELETIONS),
    ] = ()

    @field_validator("pending_private_key_deletions")
    @classmethod
    def pending_private_key_deletions_are_unique_and_sorted(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        reserved = {SYNTHETIC_ISSUER_STATE_ID, SYNTHETIC_ISSUER_CLEANUP_STATE_ID}
        if any(handle in reserved for handle in value):
            raise ValueError("synthetic issuer state identifiers are reserved")
        if any(
            re.fullmatch(SYNTHETIC_CORE_PRIVATE_KEY_HANDLE_PATTERN, handle) is None
            for handle in value
        ):
            raise ValueError("synthetic issuer pending private key deletion handle invalid")
        if len(set(value)) != len(value):
            raise ValueError("synthetic issuer pending private key deletions must be unique")
        if tuple(sorted(value)) != value:
            raise ValueError("synthetic issuer pending private key deletions must be sorted")
        return value


class LegacySyntheticCoreIssuerLifecycleV1(ContractModel):
    schema_version: Literal["tuntun.synthetic-core-issuer-lifecycle.v1"]
    active_generation: Annotated[int, Field(ge=1)] | None
    staged_generations: tuple[LegacyPreparedCoreMaterialV1, ...] = ()
    revoked_generations: tuple[Annotated[int, Field(ge=1)], ...] = ()

    @field_validator("staged_generations")
    @classmethod
    def staged_generations_are_unique(
        cls,
        value: tuple[LegacyPreparedCoreMaterialV1, ...],
    ) -> tuple[LegacyPreparedCoreMaterialV1, ...]:
        generations = tuple(item.generation for item in value)
        if len(set(generations)) != len(generations):
            raise ValueError("synthetic issuer staged generations must be unique")
        if tuple(sorted(generations)) != generations:
            raise ValueError("synthetic issuer staged generations must be sorted")
        return value

    @field_validator("revoked_generations")
    @classmethod
    def revoked_generations_are_unique(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if len(set(value)) != len(value):
            raise ValueError("synthetic issuer revoked generations must be unique")
        if tuple(sorted(value)) != value:
            raise ValueError("synthetic issuer revoked generations must be sorted")
        return value

    @model_validator(mode="after")
    def active_generation_is_staged(self) -> Self:
        staged_generations = {item.generation for item in self.staged_generations}
        revoked_generations = set(self.revoked_generations)
        if self.active_generation is not None and self.active_generation not in staged_generations:
            raise ValueError("synthetic issuer active generation must be staged")
        if staged_generations & revoked_generations:
            raise ValueError("synthetic issuer revoked generations must not be staged")
        if self.active_generation is not None and self.active_generation in revoked_generations:
            raise ValueError("synthetic issuer active generation must not be revoked")
        return self


@dataclass(frozen=True, slots=True)
class _LoadedSyntheticCoreIssuerLifecycle:
    active_generation: int | None
    staged_generations: tuple[PreparedCoreMaterialV1, ...]
    legacy_staged_generations: tuple[LegacyPreparedCoreMaterialV1, ...]
    revoked_generations: tuple[int, ...]
    storage_bytes: bytes | None


@dataclass(frozen=True, slots=True)
class _ProposedSyntheticCoreIssuerLifecycle:
    active_generation: int | None
    staged_generations: tuple[PreparedCoreMaterialV1, ...]
    legacy_staged_generations: tuple[LegacyPreparedCoreMaterialV1, ...]
    revoked_generations: tuple[int, ...]
    lifecycle: SyntheticCoreIssuerLifecycleV1


@dataclass(frozen=True, slots=True)
class _PendingSyntheticCoreIssuerLifecycleUpdate:
    proposed: _ProposedSyntheticCoreIssuerLifecycle
    lifecycle_bytes: bytes
    cleanup_private_key_handles: tuple[str, ...]
    not_published_private_key_handles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _PendingReachyPublicationReconciliation:
    generation: int
    state: CommissioningStateV1
    material: GeneratedReachyMaterialBundle | None


class CommissioningRepositoryPort(Protocol):
    def has_current(self) -> bool: ...

    def require_current(self) -> CommissioningStateV1: ...

    def replace_atomic(
        self,
        state: CommissioningStateV1,
        *,
        expected_generation: int | None = None,
        expected_current: CommissioningStateV1 | None = None,
        assurance: object | None = None,
    ) -> None: ...

    def reopen(self) -> CommissioningRepositoryPort: ...


class OwnerOnlyArtifactStorePort(Protocol):
    def write(self, identifier: str, value: bytes) -> None: ...

    def read(self, identifier: str) -> bytes: ...

    def delete(self, identifier: str) -> None: ...


class ReachyPrivateMaterialGeneratorPort(Protocol):
    def generate(
        self,
        *,
        request: ReachyCommissioningRequestV1,
        generation: int,
        core_hmac_agreement_public_key_b64: str,
    ) -> GeneratedReachyMaterialBundle: ...

    def install_client_certificate(
        self,
        *,
        material: GeneratedReachyMaterialBundle,
        certificate_pem: str,
    ) -> None: ...

    def discard(self, material: GeneratedReachyMaterialBundle) -> None: ...

    def reconcile_artifact_cleanup(
        self,
        current_artifact_map: ReachyCommissioningArtifactMapV1 | None,
    ) -> None: ...


class CoreCommissioningIssuerPort(Protocol):
    def begin_generation(
        self,
        *,
        request: ReachyCommissioningRequestV1,
        generation: int,
    ) -> PreparedCoreMaterialV1: ...

    def complete_generation(
        self,
        *,
        prepared: PreparedCoreMaterialV1,
        reachy_material: GeneratedReachyMaterialV1,
    ) -> IssuedClientMaterialV1: ...

    def activate_staged_generation(
        self,
        *,
        generation: int,
        endpoint: ReachyCoreEndpointV1,
    ) -> None: ...

    def abort_staged_generation(self, generation: int) -> None: ...

    def revoke_generation(self, *, endpoint: ReachyCoreEndpointV1) -> None: ...

    def commissioning_assurance(self) -> object | None: ...


class OperatorAcceptancePublisherPort(Protocol):
    def clear_before_recommission(self, state: CommissioningStateV1) -> None: ...

    def clear_before_revoke(self, state: CommissioningStateV1) -> None: ...


class LocalPhysicalProofVerifierPort(Protocol):
    def consume_and_execute(
        self,
        proof: LocalPhysicalProof,
        *,
        operation: Literal["commission", "recommission", "revoke"],
        request: ReachyCommissioningRequestV1 | None = None,
        current: CommissioningStateV1 | None = None,
        transition: Callable[[], _LocalPhysicalTransitionResultT],
    ) -> _LocalPhysicalTransitionResultT: ...


class ReachyCommissioningRequestFactoryPort(Protocol):
    def current_rfc1918_request(self) -> ReachyCommissioningRequestV1: ...


class SyntheticReachyPrivateMaterialGenerator:
    def __init__(
        self,
        *,
        key_store: OwnerOnlyArtifactStorePort,
        certificate_store: OwnerOnlyArtifactStorePort,
    ) -> None:
        self._key_store = key_store
        self._certificate_store = certificate_store
        self._pending_artifact_deletions = self._load_pending_artifact_deletions()
        self.generated_material: list[GeneratedReachyMaterialBundle] = []

    def generate(
        self,
        *,
        request: ReachyCommissioningRequestV1,
        generation: int,
        core_hmac_agreement_public_key_b64: str,
    ) -> GeneratedReachyMaterialBundle:
        if generation < 1:
            raise ValueError("commissioning generation must be positive")
        suffix = secrets.token_hex(8)
        client_tls_key_id = _artifact_handle("reachy-client-tls-id", generation, suffix)
        device_signing_key_id = _public_ed25519_key_id("reachy-device-sign", generation)
        hmac_key_id = _artifact_handle("reachy-frame-hmac-id", generation, suffix)
        artifacts = ReachyCommissioningArtifactMapV1(
            generation=generation,
            client_tls_private_key_handle=_artifact_handle(
                "reachy-client-tls",
                generation,
                suffix,
            ),
            client_certificate_handle=_artifact_handle("reachy-client-cert", generation, suffix),
            device_signing_private_key_handle=_artifact_handle(
                "reachy-device-sign",
                generation,
                suffix,
            ),
            frame_hmac_root_handle=_artifact_handle("reachy-frame-hmac", generation, suffix),
        )
        client_public = _synthetic_public_bytes("client-tls", generation, suffix)
        device_private_key = Ed25519PrivateKey.generate()
        device_private = device_private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        device_public = device_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        hmac_public = _synthetic_public_bytes("hmac-agreement", generation, suffix)
        hmac_root = _derive_synthetic_frame_hmac_root(
            request=request,
            generation=generation,
            core_public_key_b64=core_hmac_agreement_public_key_b64,
            reachy_public_key_b64=_b64(hmac_public),
        )
        csr_pem = _pem(
            "CERTIFICATE REQUEST",
            canonical_mapping_bytes(
                {
                    "generation": generation,
                    "client_tls_public_key_sha256": hashlib.sha256(client_public).hexdigest(),
                    "commissioning_uuid": request.commissioning_uuid,
                }
            ),
        )
        material = GeneratedReachyMaterialV1(
            schema_version="tuntun.reachy-generated-public-material.v1",
            generation=generation,
            client_tls_key_id=client_tls_key_id,
            client_tls_csr_pem=csr_pem,
            client_tls_public_key_sha256=hashlib.sha256(client_public).hexdigest(),
            device_signing_key_id=device_signing_key_id,
            device_signing_public_key_b64=_b64(device_public),
            device_signing_public_key_sha256=hashlib.sha256(device_public).hexdigest(),
            hmac_key_id=hmac_key_id,
            hmac_agreement_public_key_b64=_b64(hmac_public),
            hmac_agreement_public_key_sha256=hashlib.sha256(hmac_public).hexdigest(),
            hmac_key_sha256=hashlib.sha256(hmac_root).hexdigest(),
        )
        bundle = GeneratedReachyMaterialBundle(public=material, artifacts=artifacts)
        cleanup_entry = _reachy_artifact_cleanup_entry_from_map(artifacts)
        try:
            self._queue_artifact_deletions((cleanup_entry,))
            self._key_store.write(
                artifacts.client_tls_private_key_handle,
                _pem("PRIVATE KEY", b"synthetic-client-tls-" + client_public).encode("ascii"),
            )
            self._key_store.write(artifacts.device_signing_private_key_handle, device_private)
            self._key_store.write(artifacts.frame_hmac_root_handle, hmac_root)
        except Exception as error:
            cleanup_error: Exception | None = None
            try:
                self._delete_artifact_deletion_entry(cleanup_entry)
            except Exception as exception:
                cleanup_error = exception
            if cleanup_error is None:
                try:
                    self._unqueue_artifact_deletions((cleanup_entry,))
                except Exception as exception:
                    cleanup_error = exception
            if cleanup_error is not None:
                error.add_note(f"Reachy generated artifact cleanup failed: {cleanup_error}")
            raise
        self.generated_material.append(bundle)
        return bundle

    def install_client_certificate(
        self,
        *,
        material: GeneratedReachyMaterialBundle,
        certificate_pem: str,
    ) -> None:
        if material.public.generation < 1:
            raise ValueError("commissioning generation must be positive")
        self._certificate_store.write(
            material.artifacts.client_certificate_handle,
            certificate_pem.encode("ascii"),
        )

    def discard(self, material: GeneratedReachyMaterialBundle) -> None:
        cleanup_entry = _reachy_artifact_cleanup_entry_from_map(material.artifacts)
        self._delete_artifact_deletion_entry(cleanup_entry)
        self._unqueue_artifact_deletions((cleanup_entry,))

    def reconcile_artifact_cleanup(
        self,
        current_artifact_map: ReachyCommissioningArtifactMapV1 | None,
    ) -> None:
        if not self._pending_artifact_deletions:
            return
        current_key: tuple[str, str, str, str, str] | None = None
        if current_artifact_map is not None:
            current_entry = _reachy_artifact_cleanup_entry_from_map(current_artifact_map)
            current_key = _reachy_cleanup_entry_key(current_entry)
        remaining = dict(self._pending_artifact_deletions)
        for key, entry in sorted(self._pending_artifact_deletions.items()):
            if current_key is not None and key == current_key:
                remaining.pop(key, None)
                continue
            self._delete_artifact_deletion_entry(entry)
            remaining.pop(key, None)
        self._persist_pending_artifact_deletions(remaining)
        self._pending_artifact_deletions = remaining

    def _load_pending_artifact_deletions(
        self,
    ) -> dict[tuple[str, str, str, str, str], ReachyGeneratorArtifactCleanupEntryV1]:
        try:
            raw = self._key_store.read(REACHY_GENERATOR_CLEANUP_STATE_ID)
        except FileNotFoundError:
            return {}
        journal = parse_contract_json(
            ReachyGeneratorArtifactCleanupJournalV1,
            raw,
            max_bytes=MAX_REACHY_GENERATOR_CLEANUP_STATE_BYTES,
            require_canonical=True,
        )
        return {
            _reachy_cleanup_entry_key(entry): entry for entry in journal.pending_artifact_deletions
        }

    def _queue_artifact_deletions(
        self,
        entries: tuple[ReachyGeneratorArtifactCleanupEntryV1, ...],
    ) -> None:
        if not entries:
            return
        updated = dict(self._pending_artifact_deletions)
        for entry in entries:
            updated[_reachy_cleanup_entry_key(entry)] = entry
        self._persist_pending_artifact_deletions(updated)
        self._pending_artifact_deletions = updated

    def _unqueue_artifact_deletions(
        self,
        entries: tuple[ReachyGeneratorArtifactCleanupEntryV1, ...],
    ) -> None:
        if not entries:
            return
        updated = dict(self._pending_artifact_deletions)
        for entry in entries:
            updated.pop(_reachy_cleanup_entry_key(entry), None)
        self._persist_pending_artifact_deletions(updated)
        self._pending_artifact_deletions = updated

    def _persist_pending_artifact_deletions(
        self,
        entries: dict[tuple[str, str, str, str, str], ReachyGeneratorArtifactCleanupEntryV1],
    ) -> None:
        if not entries:
            self._key_store.delete(REACHY_GENERATOR_CLEANUP_STATE_ID)
            return
        journal = ReachyGeneratorArtifactCleanupJournalV1(
            schema_version="tuntun.reachy-generator-artifact-cleanup.v1",
            pending_artifact_deletions=tuple(entry for _key, entry in sorted(entries.items())),
        )
        self._key_store.write(REACHY_GENERATOR_CLEANUP_STATE_ID, canonical_bytes(journal))

    def _delete_artifact_deletion_entry(
        self,
        entry: ReachyGeneratorArtifactCleanupEntryV1,
    ) -> None:
        self._key_store.delete(entry.client_tls_private_key_handle)
        self._key_store.delete(entry.device_signing_private_key_handle)
        self._key_store.delete(entry.frame_hmac_root_handle)
        self._certificate_store.delete(entry.client_certificate_handle)


class SyntheticCoreCommissioningIssuer:
    def __init__(self, *, state_store: OwnerOnlyArtifactStorePort | None = None) -> None:
        self._state_store = state_store
        lifecycle = self._load_lifecycle()
        self.active_generation: int | None = lifecycle.active_generation
        self.staged_generations: dict[int, PreparedCoreMaterialV1] = {
            prepared.generation: prepared for prepared in lifecycle.staged_generations
        }
        self._legacy_staged_generations: dict[int, LegacyPreparedCoreMaterialV1] = {
            prepared.generation: prepared for prepared in lifecycle.legacy_staged_generations
        }
        self.revoked_generations: list[int] = list(lifecycle.revoked_generations)
        self._lifecycle_storage_bytes = lifecycle.storage_bytes
        self._pending_private_key_deletions = self._load_pending_private_key_deletions()
        self._pending_lifecycle_update: _PendingSyntheticCoreIssuerLifecycleUpdate | None = None

    def begin_generation(
        self,
        *,
        request: ReachyCommissioningRequestV1,
        generation: int,
    ) -> PreparedCoreMaterialV1:
        state_store = self._require_state_store()
        self._reconcile_pending_lifecycle_update()
        self._drain_pending_private_key_deletions()
        suffix = secrets.token_hex(8)
        core_public = _synthetic_public_bytes("core-hmac-agreement", generation, suffix)
        server_private_key = Ed25519PrivateKey.generate()
        server_private = server_private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        server_public = server_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        server_private_key_handle = _artifact_handle("reachy-server", generation, suffix)
        prepared = PreparedCoreMaterialV1(
            schema_version="tuntun.core-prepared-commissioning-material.v1",
            generation=generation,
            commissioning_uuid=request.commissioning_uuid,
            core_ipv4=request.core_ipv4,
            core_link_address=request.core_link_address,
            port=request.port,
            boot_identity_sha256=request.boot_identity_sha256,
            capability_evidence_sha256=request.capability_evidence_sha256,
            dhcp_reservation_receipt_sha256=request.dhcp_reservation_receipt_sha256,
            household_ca_sha256=_digest_hex("household-ca", generation, suffix),
            certificate_generation=generation,
            server_key_generation=generation,
            trust_digest_generation=generation,
            server_leaf_sha256=_digest_hex("server-leaf", generation, suffix),
            server_key_id=_public_ed25519_key_id("reachy-server", generation),
            server_private_key_handle=server_private_key_handle,
            server_public_key_sha256=hashlib.sha256(server_public).hexdigest(),
            core_hmac_agreement_public_key_b64=_b64(core_public),
            core_hmac_agreement_public_key_sha256=hashlib.sha256(core_public).hexdigest(),
        )
        self._queue_private_key_deletions((server_private_key_handle,))
        state_store.write(server_private_key_handle, server_private)
        previous_prepared = self.staged_generations.get(generation)
        proposed_staged = dict(self.staged_generations)
        proposed_legacy_staged = dict(self._legacy_staged_generations)
        proposed_staged[generation] = prepared
        proposed_legacy_staged.pop(generation, None)
        proposed = self._propose_lifecycle(
            active_generation=self.active_generation,
            staged_generations=proposed_staged,
            legacy_staged_generations=proposed_legacy_staged,
            revoked_generations=self.revoked_generations,
        )
        cleanup_handles = (
            () if previous_prepared is None else (previous_prepared.server_private_key_handle,)
        )
        self._publish_lifecycle_update(
            proposed,
            cleanup_private_key_handles=cleanup_handles,
            not_published_private_key_handles=(server_private_key_handle,),
        )
        return prepared

    def complete_generation(
        self,
        *,
        prepared: PreparedCoreMaterialV1,
        reachy_material: GeneratedReachyMaterialV1,
    ) -> IssuedClientMaterialV1:
        if type(prepared) is not PreparedCoreMaterialV1:
            raise PermissionError("commissioning_generation_not_staged")
        if prepared.generation != reachy_material.generation:
            raise PermissionError("commissioning_public_material_generation_mismatch")
        if self.staged_generations.get(prepared.generation) != prepared:
            raise PermissionError("commissioning_generation_not_staged")
        request = ReachyCommissioningRequestV1(
            schema_version="tuntun.reachy-commissioning-request.v1",
            commissioning_uuid=prepared.commissioning_uuid,
            core_ipv4=prepared.core_ipv4,
            core_link_address=prepared.core_link_address,
            port=prepared.port,
            boot_identity_sha256=prepared.boot_identity_sha256,
            capability_evidence_sha256=prepared.capability_evidence_sha256,
            dhcp_reservation_receipt_sha256=prepared.dhcp_reservation_receipt_sha256,
        )
        hmac_root = _derive_synthetic_frame_hmac_root(
            request=request,
            generation=prepared.generation,
            core_public_key_b64=prepared.core_hmac_agreement_public_key_b64,
            reachy_public_key_b64=reachy_material.hmac_agreement_public_key_b64,
        )
        hmac_key_sha256 = hashlib.sha256(hmac_root).hexdigest()
        if not hmac.compare_digest(hmac_key_sha256, reachy_material.hmac_key_sha256):
            raise PermissionError("commissioning_hmac_derivation_mismatch")
        certificate_payload = canonical_mapping_bytes(
            {
                "client_tls_public_key_sha256": reachy_material.client_tls_public_key_sha256,
                "generation": reachy_material.generation,
                "issuer_server_key_id": prepared.server_key_id,
            }
        )
        certificate_pem = _pem("CERTIFICATE", certificate_payload)
        return IssuedClientMaterialV1(
            schema_version="tuntun.issued-client-commissioning-material.v1",
            generation=prepared.generation,
            client_certificate_pem=certificate_pem,
            client_certificate_sha256=hashlib.sha256(certificate_payload).hexdigest(),
            hmac_key_sha256=hmac_key_sha256,
        )

    def activate_staged_generation(
        self,
        *,
        generation: int,
        endpoint: ReachyCoreEndpointV1,
    ) -> None:
        if endpoint.generation != generation:
            raise PermissionError("endpoint_generation_mismatch")
        self._reconcile_pending_lifecycle_update()
        self._drain_pending_private_key_deletions()
        prepared = self.staged_generations.get(generation)
        legacy_prepared = self._legacy_staged_generations.get(generation)
        if prepared is not None:
            _require_endpoint_matches_prepared_core_material(prepared, endpoint)
        elif legacy_prepared is not None:
            _require_endpoint_matches_prepared_core_material(legacy_prepared, endpoint)
            raise PermissionError("legacy_staged_activation_recommission_required")
        else:
            raise PermissionError("commissioning_generation_not_staged")
        retired_prepared = {
            staged_generation: staged
            for staged_generation, staged in self.staged_generations.items()
            if staged_generation < generation
        }
        retired_legacy_prepared = {
            staged_generation: staged
            for staged_generation, staged in self._legacy_staged_generations.items()
            if staged_generation < generation
        }
        proposed_staged = dict(self.staged_generations)
        proposed_legacy_staged = dict(self._legacy_staged_generations)
        proposed_revoked_generations = list(self.revoked_generations)
        for staged_generation in retired_prepared:
            proposed_staged.pop(staged_generation, None)
        for staged_generation in retired_legacy_prepared:
            proposed_legacy_staged.pop(staged_generation, None)
        for staged_generation in (*retired_prepared, *retired_legacy_prepared):
            if staged_generation not in proposed_revoked_generations:
                proposed_revoked_generations.append(staged_generation)
        proposed_revoked_generations.sort()
        proposed = self._propose_lifecycle(
            active_generation=generation,
            staged_generations=proposed_staged,
            legacy_staged_generations=proposed_legacy_staged,
            revoked_generations=proposed_revoked_generations,
        )
        self._publish_lifecycle_update(
            proposed,
            cleanup_private_key_handles=tuple(
                retired.server_private_key_handle for retired in retired_prepared.values()
            ),
        )

    def abort_staged_generation(self, generation: int) -> None:
        self._reconcile_pending_lifecycle_update()
        self._drain_pending_private_key_deletions()
        if self.active_generation == generation:
            return
        prepared = self.staged_generations.get(generation)
        legacy_prepared = self._legacy_staged_generations.get(generation)
        if prepared is None and legacy_prepared is None:
            return
        proposed_staged = dict(self.staged_generations)
        proposed_legacy_staged = dict(self._legacy_staged_generations)
        proposed_staged.pop(generation, None)
        proposed_legacy_staged.pop(generation, None)
        proposed = self._propose_lifecycle(
            active_generation=self.active_generation,
            staged_generations=proposed_staged,
            legacy_staged_generations=proposed_legacy_staged,
            revoked_generations=self.revoked_generations,
        )
        cleanup_handles = () if prepared is None else (prepared.server_private_key_handle,)
        self._publish_lifecycle_update(
            proposed,
            cleanup_private_key_handles=cleanup_handles,
        )

    def revoke_generation(self, *, endpoint: ReachyCoreEndpointV1) -> None:
        self._reconcile_pending_lifecycle_update()
        self._drain_pending_private_key_deletions()
        previous_active_generation = self.active_generation
        prepared = self.staged_generations.get(endpoint.generation)
        legacy_prepared = self._legacy_staged_generations.get(endpoint.generation)
        if prepared is not None:
            _require_endpoint_matches_prepared_core_material(prepared, endpoint)
        elif legacy_prepared is not None:
            _require_endpoint_matches_prepared_core_material(legacy_prepared, endpoint)
        else:
            if (
                endpoint.generation in self.revoked_generations
                and self.active_generation != endpoint.generation
            ):
                return
            raise PermissionError("commissioning_generation_not_staged")
        if endpoint.generation not in self.revoked_generations:
            proposed_revoked_generations = [*self.revoked_generations, endpoint.generation]
            proposed_revoked_generations.sort()
        else:
            proposed_revoked_generations = list(self.revoked_generations)
        proposed_active_generation = previous_active_generation
        if proposed_active_generation == endpoint.generation:
            proposed_active_generation = None
        proposed_staged = dict(self.staged_generations)
        proposed_legacy_staged = dict(self._legacy_staged_generations)
        proposed_staged.pop(endpoint.generation, None)
        proposed_legacy_staged.pop(endpoint.generation, None)
        proposed = self._propose_lifecycle(
            active_generation=proposed_active_generation,
            staged_generations=proposed_staged,
            legacy_staged_generations=proposed_legacy_staged,
            revoked_generations=proposed_revoked_generations,
        )
        cleanup_handles = () if prepared is None else (prepared.server_private_key_handle,)
        self._publish_lifecycle_update(
            proposed,
            cleanup_private_key_handles=cleanup_handles,
        )

    def commissioning_assurance(self) -> object:
        return _SyntheticCommissioningAssuranceCapability()

    def _load_lifecycle(self) -> _LoadedSyntheticCoreIssuerLifecycle:
        if self._state_store is None:
            return _LoadedSyntheticCoreIssuerLifecycle(
                active_generation=None,
                staged_generations=(),
                legacy_staged_generations=(),
                revoked_generations=(),
                storage_bytes=None,
            )
        try:
            raw = self._state_store.read(SYNTHETIC_ISSUER_STATE_ID)
        except FileNotFoundError:
            return _LoadedSyntheticCoreIssuerLifecycle(
                active_generation=None,
                staged_generations=(),
                legacy_staged_generations=(),
                revoked_generations=(),
                storage_bytes=None,
            )
        try:
            lifecycle = parse_contract_json(
                SyntheticCoreIssuerLifecycleV1,
                raw,
                max_bytes=MAX_SYNTHETIC_ISSUER_STATE_BYTES,
                require_canonical=True,
            )
        except ContractParseError as current_error:
            try:
                legacy = parse_contract_json(
                    LegacySyntheticCoreIssuerLifecycleV1,
                    raw,
                    max_bytes=MAX_SYNTHETIC_ISSUER_STATE_BYTES,
                    require_canonical=True,
                )
            except ContractParseError:
                raise current_error from None
            return _LoadedSyntheticCoreIssuerLifecycle(
                active_generation=legacy.active_generation,
                staged_generations=(),
                legacy_staged_generations=legacy.staged_generations,
                revoked_generations=legacy.revoked_generations,
                storage_bytes=raw,
            )
        for prepared in lifecycle.staged_generations:
            _require_synthetic_core_server_private_key(self._state_store, prepared)
        return _LoadedSyntheticCoreIssuerLifecycle(
            active_generation=lifecycle.active_generation,
            staged_generations=lifecycle.staged_generations,
            legacy_staged_generations=(),
            revoked_generations=lifecycle.revoked_generations,
            storage_bytes=raw,
        )

    def _load_pending_private_key_deletions(self) -> set[str]:
        if self._state_store is None:
            return set()
        try:
            raw = self._state_store.read(SYNTHETIC_ISSUER_CLEANUP_STATE_ID)
        except FileNotFoundError:
            return set()
        cleanup = parse_contract_json(
            SyntheticCoreIssuerCleanupV1,
            raw,
            max_bytes=MAX_SYNTHETIC_ISSUER_CLEANUP_STATE_BYTES,
            require_canonical=True,
        )
        return set(cleanup.pending_private_key_deletions)

    def _persist_lifecycle(
        self,
        lifecycle: SyntheticCoreIssuerLifecycleV1 | None = None,
    ) -> None:
        if self._state_store is None:
            return
        if lifecycle is None:
            lifecycle = self._current_lifecycle()
        lifecycle_bytes = canonical_bytes(lifecycle)
        self._state_store.write(SYNTHETIC_ISSUER_STATE_ID, lifecycle_bytes)
        self._lifecycle_storage_bytes = lifecycle_bytes

    def _current_lifecycle(self) -> SyntheticCoreIssuerLifecycleV1:
        return self._propose_lifecycle(
            active_generation=self.active_generation,
            staged_generations=self.staged_generations,
            legacy_staged_generations=self._legacy_staged_generations,
            revoked_generations=self.revoked_generations,
        ).lifecycle

    def _propose_lifecycle(
        self,
        *,
        active_generation: int | None,
        staged_generations: dict[int, PreparedCoreMaterialV1],
        legacy_staged_generations: dict[int, LegacyPreparedCoreMaterialV1],
        revoked_generations: list[int] | tuple[int, ...],
    ) -> _ProposedSyntheticCoreIssuerLifecycle:
        if active_generation is None or active_generation in staged_generations:
            lifecycle_active_generation = active_generation
        elif active_generation in legacy_staged_generations:
            lifecycle_active_generation = None
        else:
            raise ValueError("synthetic issuer active generation must be staged")
        staged = tuple(staged_generations[generation] for generation in sorted(staged_generations))
        legacy_staged = tuple(
            legacy_staged_generations[generation]
            for generation in sorted(legacy_staged_generations)
        )
        revoked = tuple(revoked_generations)
        lifecycle = SyntheticCoreIssuerLifecycleV1(
            schema_version="tuntun.synthetic-core-issuer-lifecycle.v1",
            active_generation=lifecycle_active_generation,
            staged_generations=staged,
            revoked_generations=revoked,
        )
        return _ProposedSyntheticCoreIssuerLifecycle(
            active_generation=active_generation,
            staged_generations=staged,
            legacy_staged_generations=legacy_staged,
            revoked_generations=revoked,
            lifecycle=lifecycle,
        )

    def _publish_lifecycle_update(
        self,
        proposed: _ProposedSyntheticCoreIssuerLifecycle,
        *,
        cleanup_private_key_handles: tuple[str, ...] = (),
        not_published_private_key_handles: tuple[str, ...] = (),
    ) -> None:
        lifecycle_bytes = canonical_bytes(proposed.lifecycle)
        queued_private_key_handles = tuple(
            sorted({*cleanup_private_key_handles, *not_published_private_key_handles})
        )
        pending = _PendingSyntheticCoreIssuerLifecycleUpdate(
            proposed=proposed,
            lifecycle_bytes=lifecycle_bytes,
            cleanup_private_key_handles=cleanup_private_key_handles,
            not_published_private_key_handles=not_published_private_key_handles,
        )
        self._pending_lifecycle_update = pending
        try:
            self._queue_private_key_deletions(queued_private_key_handles)
        except Exception:
            self._pending_lifecycle_update = None
            self._delete_private_key_handles(not_published_private_key_handles)
            raise
        try:
            self._persist_lifecycle(proposed.lifecycle)
        except Exception as publish_error:
            status = self._persisted_lifecycle_status(proposed.lifecycle)
            if status == "published":
                self._apply_proposed_lifecycle(proposed, lifecycle_bytes)
                self._pending_lifecycle_update = None
                try:
                    self._drain_pending_private_key_deletions()
                except Exception as cleanup_error:
                    publish_error.add_note(
                        f"synthetic core private key cleanup failed: {cleanup_error}"
                    )
            elif status == "not_published":
                try:
                    self._drain_pending_private_key_deletions()
                except Exception as cleanup_error:
                    publish_error.add_note(
                        f"synthetic core cleanup journal update failed: {cleanup_error}"
                    )
                else:
                    self._pending_lifecycle_update = None
            raise
        self._apply_proposed_lifecycle(proposed, lifecycle_bytes)
        self._pending_lifecycle_update = None
        self._drain_pending_private_key_deletions()

    def _reconcile_pending_lifecycle_update(self) -> None:
        pending = self._pending_lifecycle_update
        if pending is None:
            return
        status = self._persisted_lifecycle_status(pending.proposed.lifecycle)
        if status == "published":
            self._apply_proposed_lifecycle(pending.proposed, pending.lifecycle_bytes)
            self._pending_lifecycle_update = None
            self._drain_pending_private_key_deletions()
            return
        if status == "not_published":
            self._drain_pending_private_key_deletions()
            self._pending_lifecycle_update = None
            return
        raise OSError("synthetic_core_issuer_lifecycle_reconciliation_ambiguous")

    def _apply_proposed_lifecycle(
        self,
        proposed: _ProposedSyntheticCoreIssuerLifecycle,
        storage_bytes: bytes,
    ) -> None:
        self.active_generation = proposed.active_generation
        self.staged_generations = {
            prepared.generation: prepared for prepared in proposed.staged_generations
        }
        self._legacy_staged_generations = {
            prepared.generation: prepared for prepared in proposed.legacy_staged_generations
        }
        self.revoked_generations = list(proposed.revoked_generations)
        self._lifecycle_storage_bytes = storage_bytes

    def _queue_private_key_deletions(self, handles: tuple[str, ...]) -> None:
        if not handles:
            return
        updated = self._pending_private_key_deletions | set(handles)
        self._persist_pending_private_key_deletions(updated)
        self._pending_private_key_deletions = updated

    def _unqueue_private_key_deletions(self, handles: tuple[str, ...]) -> None:
        if not handles:
            return
        updated = self._pending_private_key_deletions - set(handles)
        self._persist_pending_private_key_deletions(updated)
        self._pending_private_key_deletions = updated

    def _persist_pending_private_key_deletions(self, handles: set[str]) -> None:
        if self._state_store is None:
            return
        if not handles:
            self._state_store.delete(SYNTHETIC_ISSUER_CLEANUP_STATE_ID)
            return
        cleanup = SyntheticCoreIssuerCleanupV1(
            schema_version="tuntun.synthetic-core-issuer-cleanup.v1",
            pending_private_key_deletions=tuple(sorted(handles)),
        )
        self._state_store.write(SYNTHETIC_ISSUER_CLEANUP_STATE_ID, canonical_bytes(cleanup))

    def _drain_pending_private_key_deletions(self) -> None:
        if not self._pending_private_key_deletions:
            return
        referenced_handles = {
            prepared.server_private_key_handle for prepared in self.staged_generations.values()
        }
        state_store = self._require_state_store()
        remaining = set(self._pending_private_key_deletions)
        for handle in sorted(self._pending_private_key_deletions):
            if handle in referenced_handles:
                remaining.remove(handle)
                continue
            state_store.delete(handle)
            remaining.remove(handle)
        self._persist_pending_private_key_deletions(remaining)
        self._pending_private_key_deletions = remaining

    def _delete_private_key_handles(self, handles: tuple[str, ...]) -> None:
        if not handles:
            return
        state_store = self._require_state_store()
        for handle in handles:
            state_store.delete(handle)

    def _persisted_lifecycle_status(
        self,
        lifecycle: SyntheticCoreIssuerLifecycleV1,
    ) -> Literal["published", "not_published", "ambiguous"]:
        if self._state_store is None:
            return "not_published"
        expected = canonical_bytes(lifecycle)
        try:
            visible = self._state_store.read(SYNTHETIC_ISSUER_STATE_ID)
        except FileNotFoundError:
            if self._lifecycle_storage_bytes is None:
                return "not_published"
            return "ambiguous"
        except Exception:
            return "ambiguous"
        if hmac.compare_digest(visible, expected):
            return "published"
        if self._lifecycle_storage_bytes is not None and hmac.compare_digest(
            visible,
            self._lifecycle_storage_bytes,
        ):
            return "not_published"
        return "ambiguous"

    def _require_state_store(self) -> OwnerOnlyArtifactStorePort:
        if self._state_store is None:
            raise RuntimeError("synthetic_core_issuer_state_store_required")
        return self._state_store


class ReachyCommissioningService:
    def __init__(
        self,
        *,
        repository: CommissioningRepositoryPort,
        generator: ReachyPrivateMaterialGeneratorPort,
        issuer: CoreCommissioningIssuerPort,
        acceptance_publisher: OperatorAcceptancePublisherPort | None = None,
        request_factory: ReachyCommissioningRequestFactoryPort | None = None,
        local_proof_verifier: LocalPhysicalProofVerifierPort | None = None,
    ) -> None:
        self._repository = repository
        self._generator = generator
        self._issuer = issuer
        self._acceptance_publisher = acceptance_publisher
        self._request_factory = request_factory
        self._local_proof_verifier = local_proof_verifier
        self._pending_publication_reconciliations: dict[
            int,
            _PendingReachyPublicationReconciliation,
        ] = {}

    def resume_current_activation(self) -> CommissioningStateV1:
        self._reconcile_generator_artifact_cleanup()
        self._reconcile_pending_publications()
        state = self._repository.require_current()
        if state.legacy_key_id_format or state.artifact_map is None:
            raise RuntimeError("commissioning_material_legacy_recommission_required")
        if state.status != "active":
            raise PermissionError("commissioning_revoked")
        self._issuer.activate_staged_generation(
            generation=state.endpoint.generation,
            endpoint=state.endpoint,
        )
        return state

    def reopen(self) -> ReachyCommissioningService:
        return type(self)(
            repository=self._repository.reopen(),
            generator=self._generator,
            issuer=self._issuer,
            acceptance_publisher=self._acceptance_publisher,
            request_factory=self._request_factory,
            local_proof_verifier=self._local_proof_verifier,
        )

    def commission_local(
        self,
        proof: LocalPhysicalProof,
        request: ReachyCommissioningRequestV1 | None = None,
    ) -> CommissioningStateV1:
        self._reconcile_generator_artifact_cleanup()
        self._reconcile_pending_publications()
        selected = self._select_request(request)
        generation = 1

        def transition() -> CommissioningStateV1:
            if self._repository.has_current():
                raise PermissionError("already_commissioned_use_recommission")
            prepared: PreparedCoreMaterialV1 | None = None
            material: GeneratedReachyMaterialBundle | None = None
            state: CommissioningStateV1 | None = None
            try:
                prepared = self._issuer.begin_generation(request=selected, generation=generation)
                material = self._generator.generate(
                    request=selected,
                    generation=generation,
                    core_hmac_agreement_public_key_b64=prepared.core_hmac_agreement_public_key_b64,
                )
                issued = self._issuer.complete_generation(
                    prepared=prepared,
                    reachy_material=material.public,
                )
                self._generator.install_client_certificate(
                    material=material,
                    certificate_pem=issued.client_certificate_pem,
                )
                endpoint = _endpoint_from_material(
                    request=selected,
                    prepared=prepared,
                    reachy_material=material.public,
                    issued=issued,
                )
                state = CommissioningStateV1(
                    schema_version="tuntun.reachy-commissioning-state.v1",
                    status="active",
                    endpoint=endpoint,
                    artifact_map=material.artifacts,
                    legacy_key_id_format=False,
                    revoked_key_ids=(),
                    revoked_certificate_sha256=(),
                )
                self._repository.replace_atomic(
                    state,
                    expected_current=None,
                    assurance=self._issuer.commissioning_assurance(),
                )
                self._generator.reconcile_artifact_cleanup(state.artifact_map)
                self._issuer.activate_staged_generation(generation=generation, endpoint=endpoint)
                return state
            except Exception as error:
                self._record_pending_publication_reconciliation(
                    generation=generation,
                    state=state,
                    material=material,
                )
                publication_status = _published_state_status(self._repository, state)
                cleanup_error: Exception | None = None
                if publication_status == "not_published":
                    try:
                        self._cleanup_unpublished_generation(generation, material)
                    except Exception as exception:
                        cleanup_error = exception
                    else:
                        self._clear_pending_publication_reconciliation(generation, state)
                elif publication_status == "published":
                    self._clear_pending_publication_reconciliation(generation, state)
                if cleanup_error is not None:
                    error.add_note(f"unpublished Reachy material cleanup failed: {cleanup_error}")
                raise

        return self._require_local_proof_verifier().consume_and_execute(
            proof,
            operation="commission",
            request=selected,
            current=None,
            transition=transition,
        )

    def recommission_local(
        self,
        proof: LocalPhysicalProof,
        request: ReachyCommissioningRequestV1 | None = None,
    ) -> CommissioningStateV1:
        self._reconcile_generator_artifact_cleanup()
        self._reconcile_pending_publications()
        selected = self._select_request(request)
        current = self._repository.require_current()
        generation = current.endpoint.generation + 1

        def transition() -> CommissioningStateV1:
            self._require_acceptance_publisher().clear_before_recommission(current)
            prepared: PreparedCoreMaterialV1 | None = None
            material: GeneratedReachyMaterialBundle | None = None
            state: CommissioningStateV1 | None = None
            try:
                prepared = self._issuer.begin_generation(request=selected, generation=generation)
                material = self._generator.generate(
                    request=selected,
                    generation=generation,
                    core_hmac_agreement_public_key_b64=prepared.core_hmac_agreement_public_key_b64,
                )
                issued = self._issuer.complete_generation(
                    prepared=prepared,
                    reachy_material=material.public,
                )
                self._generator.install_client_certificate(
                    material=material,
                    certificate_pem=issued.client_certificate_pem,
                )
                endpoint = _endpoint_from_material(
                    request=selected,
                    prepared=prepared,
                    reachy_material=material.public,
                    issued=issued,
                )
                state = CommissioningStateV1(
                    schema_version="tuntun.reachy-commissioning-state.v1",
                    status="active",
                    endpoint=endpoint,
                    artifact_map=material.artifacts,
                    legacy_key_id_format=False,
                    revoked_key_ids=_endpoint_key_ids(current.endpoint),
                    revoked_certificate_sha256=_endpoint_certificate_digests(current.endpoint),
                )
                self._repository.replace_atomic(
                    state,
                    expected_current=current,
                    assurance=self._issuer.commissioning_assurance(),
                )
                self._generator.reconcile_artifact_cleanup(state.artifact_map)
                self._issuer.activate_staged_generation(generation=generation, endpoint=endpoint)
                return state
            except Exception as error:
                self._record_pending_publication_reconciliation(
                    generation=generation,
                    state=state,
                    material=material,
                )
                publication_status = _published_state_status(self._repository, state)
                cleanup_error: Exception | None = None
                if publication_status == "not_published":
                    try:
                        self._cleanup_unpublished_generation(generation, material)
                    except Exception as exception:
                        cleanup_error = exception
                    else:
                        self._clear_pending_publication_reconciliation(generation, state)
                elif publication_status == "published":
                    self._clear_pending_publication_reconciliation(generation, state)
                if cleanup_error is not None:
                    error.add_note(f"unpublished Reachy material cleanup failed: {cleanup_error}")
                raise

        return self._require_local_proof_verifier().consume_and_execute(
            proof,
            operation="recommission",
            request=selected,
            current=current,
            transition=transition,
        )

    def revoke_local(self, proof: LocalPhysicalProof) -> CommissioningStateV1:
        self._reconcile_generator_artifact_cleanup()
        self._reconcile_pending_publications()
        current = self._repository.require_current()

        def transition() -> CommissioningStateV1:
            if current.status != "revoked":
                self._require_acceptance_publisher().clear_before_revoke(current)
            if current.status == "revoked":
                return current
            revoked = CommissioningStateV1(
                schema_version="tuntun.reachy-commissioning-state.v1",
                status="revoked",
                endpoint=current.endpoint,
                artifact_map=current.artifact_map,
                legacy_key_id_format=current.legacy_key_id_format,
                revoked_key_ids=_endpoint_key_ids(current.endpoint),
                revoked_certificate_sha256=_endpoint_certificate_digests(current.endpoint),
            )
            self._repository.replace_atomic(
                revoked,
                expected_current=current,
            )
            try:
                self._issuer.revoke_generation(endpoint=current.endpoint)
            except PermissionError as error:
                if (
                    current.legacy_key_id_format or current.artifact_map is None
                ) and error.args == ("commissioning_generation_not_staged",):
                    return revoked
                raise
            return revoked

        return self._require_local_proof_verifier().consume_and_execute(
            proof,
            operation="revoke",
            current=current,
            transition=transition,
        )

    def _select_request(
        self,
        request: ReachyCommissioningRequestV1 | None,
    ) -> ReachyCommissioningRequestV1:
        if request is not None:
            return request
        if self._request_factory is None:
            raise RuntimeError("commissioning_request_required")
        return self._request_factory.current_rfc1918_request()

    def _require_acceptance_publisher(self) -> OperatorAcceptancePublisherPort:
        if self._acceptance_publisher is None:
            raise RuntimeError("operator_acceptance_publisher_required")
        return self._acceptance_publisher

    def _require_local_proof_verifier(self) -> LocalPhysicalProofVerifierPort:
        if self._local_proof_verifier is None:
            raise RuntimeError("local_physical_proof_verifier_required")
        return self._local_proof_verifier

    def _reconcile_generator_artifact_cleanup(self) -> None:
        try:
            current = self._repository.require_current()
        except FileNotFoundError:
            self._generator.reconcile_artifact_cleanup(None)
            return
        if current.legacy_key_id_format:
            self._generator.reconcile_artifact_cleanup(None)
            return
        self._generator.reconcile_artifact_cleanup(current.artifact_map)

    def _record_pending_publication_reconciliation(
        self,
        *,
        generation: int,
        state: CommissioningStateV1 | None,
        material: GeneratedReachyMaterialBundle | None,
    ) -> None:
        if state is None:
            return
        self._pending_publication_reconciliations[generation] = (
            _PendingReachyPublicationReconciliation(
                generation=generation,
                state=state,
                material=material,
            )
        )

    def _clear_pending_publication_reconciliation(
        self,
        generation: int,
        state: CommissioningStateV1 | None,
    ) -> None:
        if state is None:
            return
        pending = self._pending_publication_reconciliations.get(generation)
        if pending is not None and pending.state == state:
            self._pending_publication_reconciliations.pop(generation, None)

    def _reconcile_pending_publications(self) -> None:
        for generation, pending in tuple(sorted(self._pending_publication_reconciliations.items())):
            publication_status = _published_state_status(self._repository, pending.state)
            if publication_status == "published":
                self._pending_publication_reconciliations.pop(generation, None)
                continue
            if publication_status == "not_published":
                self._cleanup_unpublished_generation(pending.generation, pending.material)
                self._pending_publication_reconciliations.pop(generation, None)
                continue
            raise OSError("commissioning_publication_reconciliation_ambiguous")

    def _cleanup_unpublished_generation(
        self,
        generation: int,
        material: GeneratedReachyMaterialBundle | None,
    ) -> None:
        self._issuer.abort_staged_generation(generation)
        if material is not None:
            self._generator.discard(material)


def _endpoint_from_material(
    *,
    request: ReachyCommissioningRequestV1,
    prepared: PreparedCoreMaterialV1,
    reachy_material: GeneratedReachyMaterialV1,
    issued: IssuedClientMaterialV1,
) -> ReachyCoreEndpointV1:
    generation = prepared.generation
    if reachy_material.generation != generation or issued.generation != generation:
        raise PermissionError("commissioning_material_generation_mismatch")
    if not hmac.compare_digest(issued.hmac_key_sha256, reachy_material.hmac_key_sha256):
        raise PermissionError("commissioning_hmac_derivation_mismatch")
    return ReachyCoreEndpointV1(
        schema_version="tuntun.reachy-core-endpoint.v1",
        commissioning_uuid=request.commissioning_uuid,
        generation=generation,
        certificate_generation=prepared.certificate_generation,
        server_key_generation=prepared.server_key_generation,
        trust_digest_generation=prepared.trust_digest_generation,
        client_tls_key_generation=generation,
        device_signing_key_generation=generation,
        hmac_key_generation=generation,
        core_ipv4=request.core_ipv4,
        core_link_address=request.core_link_address,
        port=request.port,
        household_ca_sha256=prepared.household_ca_sha256,
        server_leaf_sha256=prepared.server_leaf_sha256,
        server_key_id=prepared.server_key_id,
        server_public_key_sha256=prepared.server_public_key_sha256,
        server_ip_sans=(request.core_ipv4,),
        client_certificate_sha256=issued.client_certificate_sha256,
        client_tls_key_id=reachy_material.client_tls_key_id,
        client_tls_public_key_sha256=reachy_material.client_tls_public_key_sha256,
        device_signing_key_id=reachy_material.device_signing_key_id,
        device_signing_public_key_sha256=reachy_material.device_signing_public_key_sha256,
        hmac_key_id=reachy_material.hmac_key_id,
        hmac_key_sha256=reachy_material.hmac_key_sha256,
        hmac_agreement_public_key_sha256=reachy_material.hmac_agreement_public_key_sha256,
        dhcp_reservation_receipt_sha256=request.dhcp_reservation_receipt_sha256,
        boot_identity_sha256=request.boot_identity_sha256,
        capability_evidence_sha256=request.capability_evidence_sha256,
    )


def _published_state_status(
    repository: CommissioningRepositoryPort,
    state: CommissioningStateV1 | None,
) -> Literal["published", "not_published", "ambiguous"]:
    if state is None:
        return "not_published"
    try:
        visible = repository.require_current()
    except FileNotFoundError:
        return "not_published"
    except Exception:
        return "ambiguous"
    return "published" if visible == state else "not_published"


def _local_physical_proof_values(
    *,
    proof_id: str,
    operation: Literal["commission", "recommission", "revoke"],
    request: ReachyCommissioningRequestV1 | None,
    current: CommissioningStateV1 | None,
) -> dict[str, object]:
    if operation == "commission":
        if request is None or current is not None:
            raise ValueError("initial local physical proof scope invalid")
        return {
            "proof_id": proof_id,
            "operation": operation,
            "request_sha256": hashlib.sha256(canonical_bytes(request)).hexdigest(),
            "current_state_sha256": None,
            "current_generation": None,
            "target_generation": 1,
        }
    if current is None:
        raise ValueError("local physical proof current state required")
    current_generation = current.endpoint.generation
    values: dict[str, object] = {
        "proof_id": proof_id,
        "operation": operation,
        "request_sha256": None,
        "current_state_sha256": hashlib.sha256(canonical_bytes(current)).hexdigest(),
        "current_generation": current_generation,
        "target_generation": current_generation,
    }
    if operation == "recommission":
        if request is None:
            raise ValueError("recommission local physical proof request required")
        values["request_sha256"] = hashlib.sha256(canonical_bytes(request)).hexdigest()
        values["target_generation"] = current_generation + 1
    elif operation != "revoke":
        raise ValueError("unsupported local physical proof operation")
    return values


def _local_physical_proof_mac(key: bytes, values: dict[str, object]) -> str:
    return hmac.new(key, canonical_mapping_bytes(values), hashlib.sha256).hexdigest()


def _canonical_rfc1918_ipv4(value: str, *, label: str) -> str:
    if type(value) is not str:
        raise ValueError(f"{label} must be canonical RFC1918 IPv4")
    pieces = value.split(".")
    if len(pieces) != 4:
        raise ValueError(f"{label} must be canonical RFC1918 IPv4")
    octets: list[int] = []
    for piece in pieces:
        if not piece.isdecimal() or (len(piece) > 1 and piece.startswith("0")):
            raise ValueError(f"{label} must be canonical RFC1918 IPv4")
        number = int(piece)
        if number > 255 or str(number) != piece:
            raise ValueError(f"{label} must be canonical RFC1918 IPv4")
        octets.append(number)
    first, second = octets[0], octets[1]
    if first == 10 or (first == 172 and 16 <= second <= 31) or (first == 192 and second == 168):
        return value
    raise ValueError(f"{label} must be canonical RFC1918 IPv4")


def _canonical_unicast_mac(value: str, *, label: str) -> str:
    if type(value) is not str:
        raise ValueError(f"{label} must be a canonical unicast MAC address")
    pieces = value.split(":")
    if len(pieces) != 6:
        raise ValueError(f"{label} must be a canonical unicast MAC address")
    octets = tuple(int(piece, 16) for piece in pieces)
    if all(octet == 0 for octet in octets) or all(octet == 0xFF for octet in octets):
        raise ValueError(f"{label} must be a canonical unicast MAC address")
    if octets[0] & 0x01:
        raise ValueError(f"{label} must be a canonical unicast MAC address")
    return value


def _is_ed25519_key_id(identifier: str) -> bool:
    return type(identifier) is str and re.fullmatch(ED25519_KEY_ID_PATTERN, identifier) is not None


def _public_ed25519_key_id(name: str, generation: int) -> Ed25519KeyId:
    identifier = f"ed25519:{name}:v{generation}"
    if generation < 1 or not _is_ed25519_key_id(identifier):
        raise ValueError("public Ed25519 key identifier invalid")
    return identifier


def _artifact_handle(kind: str, generation: int, suffix: str) -> ArtifactHandle:
    identifier = f"{kind}-g{generation}-{suffix}"
    if (
        generation < 1
        or type(suffix) is not str
        or re.fullmatch(ARTIFACT_HANDLE_PATTERN, identifier) is None
    ):
        raise ValueError("commissioning artifact handle invalid")
    return identifier


def _artifact_map_handles(
    artifact_map: ReachyCommissioningArtifactMapV1,
) -> tuple[str, str, str, str]:
    return (
        artifact_map.client_tls_private_key_handle,
        artifact_map.client_certificate_handle,
        artifact_map.device_signing_private_key_handle,
        artifact_map.frame_hmac_root_handle,
    )


def _reachy_cleanup_entry_handles(
    entry: ReachyGeneratorArtifactCleanupEntryV1,
) -> tuple[str, str, str, str]:
    return (
        entry.client_tls_private_key_handle,
        entry.client_certificate_handle,
        entry.device_signing_private_key_handle,
        entry.frame_hmac_root_handle,
    )


def _reachy_cleanup_entry_key(
    entry: ReachyGeneratorArtifactCleanupEntryV1,
) -> tuple[str, str, str, str, str]:
    return (str(entry.generation), *_reachy_cleanup_entry_handles(entry))


def _reachy_artifact_cleanup_entry_from_map(
    artifact_map: ReachyCommissioningArtifactMapV1,
) -> ReachyGeneratorArtifactCleanupEntryV1:
    return ReachyGeneratorArtifactCleanupEntryV1(
        generation=artifact_map.generation,
        client_tls_private_key_handle=artifact_map.client_tls_private_key_handle,
        client_certificate_handle=artifact_map.client_certificate_handle,
        device_signing_private_key_handle=artifact_map.device_signing_private_key_handle,
        frame_hmac_root_handle=artifact_map.frame_hmac_root_handle,
    )


def _endpoint_key_ids(endpoint: ReachyCoreEndpointV1) -> tuple[str, str, str, str]:
    return (
        endpoint.server_key_id,
        endpoint.client_tls_key_id,
        endpoint.device_signing_key_id,
        endpoint.hmac_key_id,
    )


def _endpoint_certificate_digests(endpoint: ReachyCoreEndpointV1) -> tuple[str, str]:
    return (endpoint.server_leaf_sha256, endpoint.client_certificate_sha256)


def _require_endpoint_matches_prepared_core_material(
    prepared: PreparedCoreMaterialV1 | LegacyPreparedCoreMaterialV1,
    endpoint: ReachyCoreEndpointV1,
) -> None:
    expected_values = {
        "commissioning_uuid": prepared.commissioning_uuid,
        "generation": prepared.generation,
        "certificate_generation": prepared.certificate_generation,
        "server_key_generation": prepared.server_key_generation,
        "trust_digest_generation": prepared.trust_digest_generation,
        "core_ipv4": prepared.core_ipv4,
        "core_link_address": prepared.core_link_address,
        "port": prepared.port,
        "household_ca_sha256": prepared.household_ca_sha256,
        "server_leaf_sha256": prepared.server_leaf_sha256,
        "server_key_id": prepared.server_key_id,
        "server_public_key_sha256": prepared.server_public_key_sha256,
        "dhcp_reservation_receipt_sha256": prepared.dhcp_reservation_receipt_sha256,
        "boot_identity_sha256": prepared.boot_identity_sha256,
        "capability_evidence_sha256": prepared.capability_evidence_sha256,
    }
    for field_name, expected in expected_values.items():
        if getattr(endpoint, field_name) != expected:
            raise PermissionError("commissioning_staged_endpoint_mismatch")


def _require_synthetic_core_server_private_key(
    state_store: OwnerOnlyArtifactStorePort,
    prepared: PreparedCoreMaterialV1,
) -> None:
    try:
        private_bytes = state_store.read(prepared.server_private_key_handle)
    except FileNotFoundError as error:
        raise PermissionError("synthetic_core_server_private_key_missing") from error
    if type(private_bytes) is not bytes or len(private_bytes) != 32:
        raise PermissionError("synthetic_core_server_private_key_invalid")
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    except ValueError as error:
        raise PermissionError("synthetic_core_server_private_key_invalid") from error
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if not hmac.compare_digest(
        hashlib.sha256(public_bytes).hexdigest(),
        prepared.server_public_key_sha256,
    ):
        raise PermissionError("synthetic_core_server_private_key_public_digest_mismatch")


def _legacy_endpoint_key_ids(endpoint: LegacyReachyCoreEndpointV1) -> tuple[str, str, str, str]:
    return (
        endpoint.server_key_id,
        endpoint.client_tls_key_id,
        endpoint.device_signing_key_id,
        endpoint.hmac_key_id,
    )


def _legacy_endpoint_certificate_digests(
    endpoint: LegacyReachyCoreEndpointV1,
) -> tuple[str, str]:
    return (endpoint.server_leaf_sha256, endpoint.client_certificate_sha256)


def _commissioning_state_from_legacy(
    legacy: LegacyCommissioningStateV1,
) -> CommissioningStateV1:
    return CommissioningStateV1(
        schema_version="tuntun.reachy-commissioning-state.v1",
        status=legacy.status,
        endpoint=ReachyCoreEndpointV1.model_validate(legacy.endpoint.model_dump(mode="python")),
        artifact_map=None,
        legacy_key_id_format=True,
        revoked_key_ids=legacy.revoked_key_ids,
        revoked_certificate_sha256=legacy.revoked_certificate_sha256,
    )


def _commissioning_state_storage_sha256(state: CommissioningStateV1) -> str:
    if state.legacy_key_id_format:
        legacy = LegacyCommissioningStateV1(
            schema_version="tuntun.reachy-commissioning-state.v1",
            status=state.status,
            endpoint=LegacyReachyCoreEndpointV1.model_validate(
                state.endpoint.model_dump(mode="python")
            ),
            revoked_key_ids=state.revoked_key_ids,
            revoked_certificate_sha256=state.revoked_certificate_sha256,
        )
        return hashlib.sha256(canonical_bytes(legacy)).hexdigest()
    return hashlib.sha256(canonical_bytes(state)).hexdigest()


def _synthetic_public_bytes(purpose: str, generation: int, suffix: str) -> bytes:
    return hashlib.sha256(f"{purpose}:{generation}:{suffix}".encode("ascii")).digest()


def _derive_synthetic_frame_hmac_root(
    *,
    request: ReachyCommissioningRequestV1,
    generation: int,
    core_public_key_b64: str,
    reachy_public_key_b64: str,
) -> bytes:
    validate_canonical_base64(core_public_key_b64, expected_bytes=32, label="Core public key")
    validate_canonical_base64(reachy_public_key_b64, expected_bytes=32, label="Reachy public key")
    salt = canonical_mapping_bytes(
        {
            "boot_identity_sha256": request.boot_identity_sha256,
            "capability_evidence_sha256": request.capability_evidence_sha256,
            "commissioning_uuid": request.commissioning_uuid,
            "core_ipv4": request.core_ipv4,
            "core_link_address": request.core_link_address,
            "core_public_key_b64": core_public_key_b64,
            "generation": generation,
            "hmac_info_b64": base64.b64encode(FRAME_HMAC_INFO).decode("ascii"),
            "port": request.port,
            "reachy_public_key_b64": reachy_public_key_b64,
        }
    )
    return hmac.new(salt, b"synthetic-reachy-frame-hmac-root", hashlib.sha256).digest()


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _pem(label: str, payload: bytes) -> str:
    encoded = base64.b64encode(payload).decode("ascii")
    return f"-----BEGIN {label}-----\n{encoded}\n-----END {label}-----\n"


def _digest_hex(prefix: str, generation: int, suffix: str) -> str:
    return hashlib.sha256(f"{prefix}:{generation}:{suffix}".encode("ascii")).hexdigest()
