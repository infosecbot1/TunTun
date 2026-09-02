from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from tuntun_contracts.base import canonical_bytes

from tuntun_edge.transport.commissioning import (
    CommissioningStateV1,
    ReachyCommissioningService,
    SyntheticCoreCommissioningIssuer,
    SyntheticReachyPrivateMaterialGenerator,
)
from tuntun_edge.transport.commissioning_repository import (
    CommissioningRepository,
    OwnerOnlyArtifactStore,
    ReachyOperatorStateRepository,
)
from tuntun_edge.transport.reachy_local_ceremony import (
    ReachyLocalCeremony,
    ReachyLocalCeremonyInputPaths,
    ReachyLocalProofAuthority,
    load_reachy_local_ceremony,
)


@dataclass(frozen=True, slots=True)
class ReachyCommissioningRoots:
    input_descriptor_path: Path
    pinned_host_key_path: Path
    dhcp_reservations_path: Path
    state_root: Path
    private_material_root: Path
    certificate_root: Path
    issuer_state_root: Path
    operator_state_root: Path

    def input_paths(self) -> ReachyLocalCeremonyInputPaths:
        return ReachyLocalCeremonyInputPaths(
            descriptor_path=self.input_descriptor_path,
            pinned_host_key_path=self.pinned_host_key_path,
            dhcp_reservations_path=self.dhcp_reservations_path,
        )


PRODUCTION_ROOTS = ReachyCommissioningRoots(
    input_descriptor_path=Path("/etc/tuntun/reachy/commissioning.json"),
    pinned_host_key_path=Path("/etc/tuntun/reachy/pinned-host-key.sha256"),
    dhcp_reservations_path=Path("/etc/tuntun/reachy/dhcp-reservations.json"),
    state_root=Path("/var/lib/tuntun/reachy/commissioning"),
    private_material_root=Path("/var/lib/tuntun/reachy/private"),
    certificate_root=Path("/var/lib/tuntun/reachy/certificates"),
    issuer_state_root=Path("/var/lib/tuntun/reachy/issuer-state"),
    operator_state_root=Path("/var/lib/tuntun/reachy/operator-state"),
)


def explicit_test_roots(root: Path) -> ReachyCommissioningRoots:
    base = root / "tuntun-reachy"
    return ReachyCommissioningRoots(
        input_descriptor_path=base / "etc" / "tuntun" / "reachy" / "commissioning.json",
        pinned_host_key_path=base / "etc" / "tuntun" / "reachy" / "pinned-host-key.sha256",
        dhcp_reservations_path=base / "etc" / "tuntun" / "reachy" / "dhcp-reservations.json",
        state_root=base / "var" / "lib" / "tuntun" / "reachy" / "commissioning",
        private_material_root=base / "var" / "lib" / "tuntun" / "reachy" / "private",
        certificate_root=base / "var" / "lib" / "tuntun" / "reachy" / "certificates",
        issuer_state_root=base / "var" / "lib" / "tuntun" / "reachy" / "issuer-state",
        operator_state_root=base / "var" / "lib" / "tuntun" / "reachy" / "operator-state",
    )


class _MissingOperatorProjectionOkPublisher:
    def __init__(self, repository: ReachyOperatorStateRepository) -> None:
        self._repository = repository

    def clear_before_recommission(self, state: CommissioningStateV1) -> None:
        self._clear(state)

    def clear_before_revoke(self, state: CommissioningStateV1) -> None:
        self._clear(state)

    def _clear(self, state: CommissioningStateV1) -> None:
        try:
            self._repository.clear_accepted_capability(
                commissioning_generation=state.endpoint.generation,
                commissioning_state_sha256=hashlib.sha256(canonical_bytes(state)).hexdigest(),
            )
        except FileNotFoundError:
            return


class ReachyCommissioningComposition:
    def __init__(self, *, roots: ReachyCommissioningRoots, expected_input_owner_uid: int) -> None:
        self.roots = roots
        self._expected_input_owner_uid = expected_input_owner_uid
        self._proof_authority = ReachyLocalProofAuthority()
        self.repository = CommissioningRepository(roots.state_root)
        self.key_store = OwnerOnlyArtifactStore(roots.private_material_root)
        self.certificate_store = OwnerOnlyArtifactStore(roots.certificate_root)
        self.issuer_state_store = OwnerOnlyArtifactStore(roots.issuer_state_root)
        self.operator_state_repository = ReachyOperatorStateRepository(roots.operator_state_root)
        self.generator = SyntheticReachyPrivateMaterialGenerator(
            key_store=self.key_store,
            certificate_store=self.certificate_store,
        )
        self.issuer = SyntheticCoreCommissioningIssuer(state_store=self.issuer_state_store)
        self.acceptance_publisher = _MissingOperatorProjectionOkPublisher(
            self.operator_state_repository
        )
        self.ceremony = self._load_ceremony()
        self.service = self._service_for_ceremony(self.ceremony)

    def reopen(self) -> ReachyCommissioningComposition:
        return type(self)(roots=self.roots, expected_input_owner_uid=self._expected_input_owner_uid)

    def resume_current_activation(self) -> CommissioningStateV1:
        return self.service.resume_current_activation()

    def commission(self, one_time_code: str) -> CommissioningStateV1:
        ceremony = self._refresh_ceremony()
        request = ceremony.current_rfc1918_request()
        proof = ceremony.issue_proof(
            operation="commission",
            request=request,
            current=None,
            one_time_code=one_time_code,
        )
        return self.service.commission_local(proof, request)

    def recommission(self, one_time_code: str) -> CommissioningStateV1:
        current = self.repository.require_current()
        ceremony = self._refresh_ceremony()
        request = ceremony.current_rfc1918_request()
        proof = ceremony.issue_proof(
            operation="recommission",
            request=request,
            current=current,
            one_time_code=one_time_code,
        )
        return self.service.recommission_local(proof, request)

    def revoke(self, one_time_code: str) -> CommissioningStateV1:
        current = self.repository.require_current()
        ceremony = self._refresh_ceremony()
        proof = ceremony.issue_proof(
            operation="revoke",
            request=None,
            current=current,
            one_time_code=one_time_code,
        )
        return self.service.revoke_local(proof)

    def _refresh_ceremony(self) -> ReachyLocalCeremony:
        self.ceremony = self._load_ceremony()
        self.service = self._service_for_ceremony(self.ceremony)
        return self.ceremony

    def _load_ceremony(self) -> ReachyLocalCeremony:
        return load_reachy_local_ceremony(
            self.roots.input_paths(),
            expected_owner_uid=self._expected_input_owner_uid,
            proof_authority=self._proof_authority,
        )

    def _service_for_ceremony(self, ceremony: ReachyLocalCeremony) -> ReachyCommissioningService:
        return ReachyCommissioningService(
            repository=self.repository,
            generator=self.generator,
            issuer=self.issuer,
            acceptance_publisher=self.acceptance_publisher,
            request_factory=ceremony,
            local_proof_verifier=ceremony.proof_verifier,
        )


def build_production_commissioning() -> ReachyCommissioningComposition:
    return ReachyCommissioningComposition(roots=PRODUCTION_ROOTS, expected_input_owner_uid=0)


def build_commissioning_for_test_roots(root: Path) -> ReachyCommissioningComposition:
    return ReachyCommissioningComposition(
        roots=explicit_test_roots(root),
        expected_input_owner_uid=os.geteuid(),
    )
