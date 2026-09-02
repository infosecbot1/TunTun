from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from typing import Protocol
from uuid import UUID, uuid4

from tuntun_contracts.ports import ConversationWorkflow
from tuntun_core.services.sessions.manager import SessionAdmission


class ReadinessDependency(Protocol):
    def require_ready(self) -> None: ...


class SessionManagerPort(Protocol):
    async def open(
        self,
        household_id: UUID,
        turn_id: UUID,
        *,
        context_session_id: UUID | None = None,
    ) -> SessionAdmission: ...

    async def end_context_session(self, context_session_id: UUID) -> bool: ...


class SimulatedContextSession:
    def __init__(self, initial_id: UUID | None = None) -> None:
        if initial_id is None:
            initial_id = uuid4()
        if type(initial_id) is not UUID:
            raise TypeError("context_session_id must be an exact UUID")
        self._context_session_id = initial_id

    @property
    def context_session_id(self) -> UUID:
        return self._context_session_id

    def rotate(self) -> UUID:
        ended = self._context_session_id
        self._context_session_id = uuid4()
        return ended


@dataclass(frozen=True, slots=True)
class SimulatedGuestAppDependencies:
    session_manager: SessionManagerPort
    workflow: ConversationWorkflow
    household_id: UUID
    device_id: UUID
    loopback_host: str
    readiness_dependencies: tuple[ReadinessDependency, ...]
    context_session: SimulatedContextSession | None = None

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
        if self.context_session is None:
            object.__setattr__(self, "context_session", SimulatedContextSession())
        elif type(self.context_session) is not SimulatedContextSession:
            raise TypeError("context_session must be an exact SimulatedContextSession")

    @property
    def context_session_id(self) -> UUID:
        if self.context_session is None:
            raise RuntimeError("context_session_unavailable")
        return self.context_session.context_session_id

    def require_ready(self) -> None:
        for dependency in self.readiness_dependencies:
            dependency.require_ready()

    async def end_context_session(self) -> UUID:
        context_session = self.context_session
        if context_session is None:
            raise RuntimeError("context_session_unavailable")
        ended = context_session.context_session_id
        await self.session_manager.end_context_session(ended)
        context_session.rotate()
        return ended
