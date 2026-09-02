from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from typing import Protocol
from uuid import UUID

from tuntun_contracts.ports import ConversationWorkflow
from tuntun_core.services.sessions.manager import SessionAdmission


class ReadinessDependency(Protocol):
    def require_ready(self) -> None: ...


class SessionManagerPort(Protocol):
    async def open(self, household_id: UUID, turn_id: UUID) -> SessionAdmission: ...


@dataclass(frozen=True, slots=True)
class SimulatedGuestAppDependencies:
    session_manager: SessionManagerPort
    workflow: ConversationWorkflow
    household_id: UUID
    device_id: UUID
    loopback_host: str
    readiness_dependencies: tuple[ReadinessDependency, ...]

    def __post_init__(self) -> None:
        if type(self.household_id) is not UUID:
            raise TypeError("household_id must be an exact UUID")
        if type(self.device_id) is not UUID:
            raise TypeError("device_id must be an exact UUID")
        if type(self.loopback_host) is not str:
            raise TypeError("loopback_host must be an exact str")
        try:
            address = ip_address(self.loopback_host)
        except ValueError as error:
            raise ValueError("loopback host must be an IP literal") from error
        if not address.is_loopback:
            raise ValueError("loopback host must be loopback")
        if type(self.readiness_dependencies) is not tuple:
            raise TypeError("readiness dependencies must be a tuple")

    def require_ready(self) -> None:
        for dependency in self.readiness_dependencies:
            dependency.require_ready()
