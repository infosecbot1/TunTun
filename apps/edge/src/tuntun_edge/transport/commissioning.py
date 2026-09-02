from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Annotated, Literal, Protocol, Self, cast
from uuid import uuid4

from pydantic import Field, StringConstraints, field_validator, model_validator
from tuntun_contracts.base import (
    ContractModel,
    canonical_bytes,
    canonical_mapping_bytes,
    parse_contract_json,
    validate_canonical_base64,
)

SHA256_PATTERN = r"^[0-9a-f]{64}$"
KEY_ID_PATTERN = r"^[A-Za-z0-9_.-]{8,128}$"
CANONICAL_UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
FRAME_HMAC_INFO = b"tuntun/reachy/frame-hmac/v1"
SYNTHETIC_ISSUER_STATE_ID = "synthetic-core-issuer-state.v1"
MAX_SYNTHETIC_ISSUER_STATE_BYTES = 16_384

Sha256Hex = Annotated[str, Field(pattern=SHA256_PATTERN)]
KeyId = Annotated[str, Field(min_length=8, max_length=128, pattern=KEY_ID_PATTERN)]
MacAddress = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$"),
]


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
    server_key_id: KeyId
    server_public_key_sha256: Sha256Hex
    server_ip_sans: tuple[str, ...]
    client_certificate_sha256: Sha256Hex
    client_tls_key_id: KeyId
    client_tls_public_key_sha256: Sha256Hex
    device_signing_key_id: KeyId
    device_signing_public_key_sha256: Sha256Hex
    hmac_key_id: KeyId
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


class CommissioningStateV1(ContractModel):
    schema_version: Literal["tuntun.reachy-commissioning-state.v1"]
    status: Literal["active", "revoked"] = "active"
    endpoint: ReachyCoreEndpointV1
    revoked_key_ids: Annotated[tuple[KeyId, ...], Field(max_length=4)] = ()
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
        if self.revoked_key_ids != _endpoint_key_ids(self.endpoint) or (
            self.revoked_certificate_sha256 != _endpoint_certificate_digests(self.endpoint)
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
    client_tls_key_id: KeyId
    client_tls_csr_pem: Annotated[str, Field(min_length=64, max_length=4096)]
    client_tls_public_key_sha256: Sha256Hex
    device_signing_key_id: KeyId
    device_signing_public_key_b64: Annotated[str, Field(min_length=44, max_length=44)]
    device_signing_public_key_sha256: Sha256Hex
    hmac_key_id: KeyId
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
    server_key_id: KeyId
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
        return value

    @field_validator("revoked_generations")
    @classmethod
    def revoked_generations_are_unique(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if len(set(value)) != len(value):
            raise ValueError("synthetic issuer revoked generations must be unique")
        if tuple(sorted(value)) != value:
            raise ValueError("synthetic issuer revoked generations must be sorted")
        return value


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
    ) -> GeneratedReachyMaterialV1: ...

    def install_client_certificate(
        self,
        *,
        material: GeneratedReachyMaterialV1,
        certificate_pem: str,
    ) -> None: ...

    def discard(self, material: GeneratedReachyMaterialV1) -> None: ...


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
    def consume(
        self,
        proof: LocalPhysicalProof,
        *,
        operation: Literal["commission", "recommission", "revoke"],
        request: ReachyCommissioningRequestV1 | None = None,
        current: CommissioningStateV1 | None = None,
    ) -> None: ...


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
        self.generated_material: list[GeneratedReachyMaterialV1] = []

    def generate(
        self,
        *,
        request: ReachyCommissioningRequestV1,
        generation: int,
        core_hmac_agreement_public_key_b64: str,
    ) -> GeneratedReachyMaterialV1:
        if generation < 1:
            raise ValueError("commissioning generation must be positive")
        suffix = secrets.token_hex(8)
        client_tls_key_id = f"reachy-client-tls-g{generation}-{suffix}"
        device_signing_key_id = f"reachy-device-sign-g{generation}-{suffix}"
        hmac_key_id = f"reachy-frame-hmac-g{generation}-{suffix}"
        client_public = _synthetic_public_bytes("client-tls", generation, suffix)
        device_public = _synthetic_public_bytes("device-signing", generation, suffix)
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
        written: list[str] = []
        try:
            self._key_store.write(
                client_tls_key_id,
                _pem("PRIVATE KEY", b"synthetic-client-tls-" + client_public).encode("ascii"),
            )
            written.append(client_tls_key_id)
            self._key_store.write(
                device_signing_key_id,
                _pem("PRIVATE KEY", b"synthetic-device-signing-" + device_public).encode("ascii"),
            )
            written.append(device_signing_key_id)
            self._key_store.write(hmac_key_id, hmac_root)
            written.append(hmac_key_id)
        except BaseException:
            for identifier in written:
                self._key_store.delete(identifier)
            raise
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
        self.generated_material.append(material)
        return material

    def install_client_certificate(
        self,
        *,
        material: GeneratedReachyMaterialV1,
        certificate_pem: str,
    ) -> None:
        if material.generation < 1:
            raise ValueError("commissioning generation must be positive")
        self._certificate_store.write(material.client_tls_key_id, certificate_pem.encode("ascii"))

    def discard(self, material: GeneratedReachyMaterialV1) -> None:
        self._key_store.delete(material.client_tls_key_id)
        self._key_store.delete(material.device_signing_key_id)
        self._key_store.delete(material.hmac_key_id)
        self._certificate_store.delete(material.client_tls_key_id)


class SyntheticCoreCommissioningIssuer:
    def __init__(self, *, state_store: OwnerOnlyArtifactStorePort | None = None) -> None:
        self._state_store = state_store
        lifecycle = self._load_lifecycle()
        self.active_generation = lifecycle.active_generation
        self.staged_generations = {
            prepared.generation: prepared for prepared in lifecycle.staged_generations
        }
        self.revoked_generations = list(lifecycle.revoked_generations)

    def begin_generation(
        self,
        *,
        request: ReachyCommissioningRequestV1,
        generation: int,
    ) -> PreparedCoreMaterialV1:
        suffix = secrets.token_hex(8)
        core_public = _synthetic_public_bytes("core-hmac-agreement", generation, suffix)
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
            server_key_id=f"reachy-server-g{generation}-{suffix}",
            server_public_key_sha256=_digest_hex("server-public", generation, suffix),
            core_hmac_agreement_public_key_b64=_b64(core_public),
            core_hmac_agreement_public_key_sha256=hashlib.sha256(core_public).hexdigest(),
        )
        self.staged_generations[generation] = prepared
        self._persist_lifecycle()
        return prepared

    def complete_generation(
        self,
        *,
        prepared: PreparedCoreMaterialV1,
        reachy_material: GeneratedReachyMaterialV1,
    ) -> IssuedClientMaterialV1:
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
        if generation not in self.staged_generations:
            raise PermissionError("commissioning_generation_not_staged")
        self.active_generation = generation
        self._persist_lifecycle()

    def abort_staged_generation(self, generation: int) -> None:
        if self.active_generation != generation:
            self.staged_generations.pop(generation, None)
            self._persist_lifecycle()

    def revoke_generation(self, *, endpoint: ReachyCoreEndpointV1) -> None:
        if endpoint.generation not in self.revoked_generations:
            self.revoked_generations.append(endpoint.generation)
            self.revoked_generations.sort()
        if self.active_generation == endpoint.generation:
            self.active_generation = None
        self._persist_lifecycle()

    def commissioning_assurance(self) -> object:
        return _SyntheticCommissioningAssuranceCapability()

    def _load_lifecycle(self) -> SyntheticCoreIssuerLifecycleV1:
        if self._state_store is None:
            return SyntheticCoreIssuerLifecycleV1(
                schema_version="tuntun.synthetic-core-issuer-lifecycle.v1",
                active_generation=None,
            )
        try:
            raw = self._state_store.read(SYNTHETIC_ISSUER_STATE_ID)
        except FileNotFoundError:
            return SyntheticCoreIssuerLifecycleV1(
                schema_version="tuntun.synthetic-core-issuer-lifecycle.v1",
                active_generation=None,
            )
        return parse_contract_json(
            SyntheticCoreIssuerLifecycleV1,
            raw,
            max_bytes=MAX_SYNTHETIC_ISSUER_STATE_BYTES,
            require_canonical=True,
        )

    def _persist_lifecycle(self) -> None:
        if self._state_store is None:
            return
        lifecycle = SyntheticCoreIssuerLifecycleV1(
            schema_version="tuntun.synthetic-core-issuer-lifecycle.v1",
            active_generation=self.active_generation,
            staged_generations=tuple(
                self.staged_generations[generation]
                for generation in sorted(self.staged_generations)
            ),
            revoked_generations=tuple(self.revoked_generations),
        )
        self._state_store.write(SYNTHETIC_ISSUER_STATE_ID, canonical_bytes(lifecycle))


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

    def resume_current_activation(self) -> CommissioningStateV1:
        state = self._repository.require_current()
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
        selected = self._select_request(request)
        self._require_local_proof_verifier().consume(
            proof,
            operation="commission",
            request=selected,
            current=None,
        )
        if self._repository.has_current():
            raise PermissionError("already_commissioned_use_recommission")
        return self._replace(current=None, request=selected)

    def recommission_local(
        self,
        proof: LocalPhysicalProof,
        request: ReachyCommissioningRequestV1 | None = None,
    ) -> CommissioningStateV1:
        selected = self._select_request(request)
        current = self._repository.require_current()
        self._require_local_proof_verifier().consume(
            proof,
            operation="recommission",
            request=selected,
            current=current,
        )
        self._require_acceptance_publisher().clear_before_recommission(current)
        return self._replace(current=current, request=selected)

    def revoke_local(self, proof: LocalPhysicalProof) -> CommissioningStateV1:
        current = self._repository.require_current()
        self._require_local_proof_verifier().consume(
            proof,
            operation="revoke",
            current=current,
        )
        if current.status == "revoked":
            return current
        self._require_acceptance_publisher().clear_before_revoke(current)
        revoked = CommissioningStateV1(
            schema_version="tuntun.reachy-commissioning-state.v1",
            status="revoked",
            endpoint=current.endpoint,
            revoked_key_ids=_endpoint_key_ids(current.endpoint),
            revoked_certificate_sha256=_endpoint_certificate_digests(current.endpoint),
        )
        self._repository.replace_atomic(
            revoked,
            expected_current=current,
        )
        self._issuer.revoke_generation(endpoint=current.endpoint)
        return revoked

    def _select_request(
        self,
        request: ReachyCommissioningRequestV1 | None,
    ) -> ReachyCommissioningRequestV1:
        if request is not None:
            return request
        if self._request_factory is None:
            raise RuntimeError("commissioning_request_required")
        return self._request_factory.current_rfc1918_request()

    def _replace(
        self,
        *,
        current: CommissioningStateV1 | None,
        request: ReachyCommissioningRequestV1,
    ) -> CommissioningStateV1:
        generation = 1 if current is None else current.endpoint.generation + 1
        prepared: PreparedCoreMaterialV1 | None = None
        material: GeneratedReachyMaterialV1 | None = None
        state: CommissioningStateV1 | None = None
        try:
            prepared = self._issuer.begin_generation(request=request, generation=generation)
            material = self._generator.generate(
                request=request,
                generation=generation,
                core_hmac_agreement_public_key_b64=prepared.core_hmac_agreement_public_key_b64,
            )
            issued = self._issuer.complete_generation(
                prepared=prepared,
                reachy_material=material,
            )
            self._generator.install_client_certificate(
                material=material,
                certificate_pem=issued.client_certificate_pem,
            )
            endpoint = _endpoint_from_material(
                request=request,
                prepared=prepared,
                reachy_material=material,
                issued=issued,
            )
            revoked_key_ids = () if current is None else _endpoint_key_ids(current.endpoint)
            revoked_certificates = (
                () if current is None else _endpoint_certificate_digests(current.endpoint)
            )
            state = CommissioningStateV1(
                schema_version="tuntun.reachy-commissioning-state.v1",
                status="active",
                endpoint=endpoint,
                revoked_key_ids=revoked_key_ids,
                revoked_certificate_sha256=revoked_certificates,
            )
            self._repository.replace_atomic(
                state,
                expected_current=current,
                assurance=self._issuer.commissioning_assurance(),
            )
            self._issuer.activate_staged_generation(generation=generation, endpoint=endpoint)
            return state
        except BaseException:
            publication_status = _published_state_status(self._repository, state)
            if publication_status == "not_published":
                self._issuer.abort_staged_generation(generation)
                if material is not None:
                    self._generator.discard(material)
            raise

    def _require_acceptance_publisher(self) -> OperatorAcceptancePublisherPort:
        if self._acceptance_publisher is None:
            raise RuntimeError("operator_acceptance_publisher_required")
        return self._acceptance_publisher

    def _require_local_proof_verifier(self) -> LocalPhysicalProofVerifierPort:
        if self._local_proof_verifier is None:
            raise RuntimeError("local_physical_proof_verifier_required")
        return self._local_proof_verifier


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
    except BaseException:
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


def _endpoint_key_ids(endpoint: ReachyCoreEndpointV1) -> tuple[str, str, str, str]:
    return (
        endpoint.server_key_id,
        endpoint.client_tls_key_id,
        endpoint.device_signing_key_id,
        endpoint.hmac_key_id,
    )


def _endpoint_certificate_digests(endpoint: ReachyCoreEndpointV1) -> tuple[str, str]:
    return (endpoint.server_leaf_sha256, endpoint.client_certificate_sha256)


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
