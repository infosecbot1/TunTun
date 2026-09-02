from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from tuntun_core.workflows.ephemeral_turn_context import EphemeralTurnContext


@dataclass(frozen=True, slots=True)
class TurnRequest:
    turn_id: UUID
    wav_bytes: bytes

    def __post_init__(self) -> None:
        if type(self.turn_id) is not UUID:
            raise TypeError("turn_id must be an exact UUID")
        if type(self.wav_bytes) is not bytes:
            raise TypeError("wav_bytes must be exact bytes")


@dataclass(frozen=True, slots=True)
class TurnOutcome:
    spoken: bool

    def __post_init__(self) -> None:
        if type(self.spoken) is not bool:
            raise TypeError("spoken must be an exact bool")


class WorkflowPorts(Protocol):
    async def start(self, turn_id: UUID) -> None: ...

    async def transcribe(self, wav_bytes: bytes) -> object: ...

    async def guest_identity(self) -> str: ...

    async def generate(self, transcript: object, identity: str) -> str: ...

    async def synthesize(self, answer: str) -> bytes: ...

    async def play(self, turn_id: UUID, pcm: bytes) -> None: ...

    async def finish(self, turn_id: UUID) -> None: ...


def _always_accepts_results(turn_id: UUID) -> bool:
    del turn_id
    return True


class LinearConversationEngine:
    """Private deterministic orchestrator for the simulated Guest slice."""

    def __init__(
        self,
        ports: WorkflowPorts,
        *,
        accepts_results: Callable[[UUID], bool] = _always_accepts_results,
    ) -> None:
        self._ports = ports
        self._accepts_results = accepts_results
        self.ephemeral: EphemeralTurnContext[dict[str, object]] = EphemeralTurnContext()
        self.cleanup_reason_codes: list[str] = []

    async def run(self, turn: TurnRequest) -> TurnOutcome:
        if type(turn) is not TurnRequest:
            raise TypeError("turn must be an exact TurnRequest")
        start_attempted = False
        primary_error: BaseException | None = None
        self.ephemeral.put(turn.turn_id, {"wav": turn.wav_bytes})
        try:
            start_attempted = True
            await self._ports.start(turn.turn_id)
            transcript = await self._ports.transcribe(turn.wav_bytes)
            self.ephemeral.put(turn.turn_id, {"transcript": transcript})
            identity = await self._ports.guest_identity()
            answer = await self._ports.generate(transcript, identity)
            self.ephemeral.put(turn.turn_id, {"answer": answer})
            pcm = await self._ports.synthesize(answer)
            if not self._accepts_results(turn.turn_id):
                return TurnOutcome(spoken=False)
            await self._ports.play(turn.turn_id, pcm)
            return TurnOutcome(spoken=True)
        except BaseException as error:
            primary_error = error
            raise
        finally:
            cleanup_error: BaseException | None = None
            try:
                self.ephemeral.clear(turn.turn_id)
            except BaseException as error:
                cleanup_error = error
            if start_attempted:
                try:
                    await self._ports.finish(turn.turn_id)
                except BaseException as error:
                    if cleanup_error is None:
                        cleanup_error = error
            if cleanup_error is not None:
                self.cleanup_reason_codes.append("turn_cleanup_failed")
                if primary_error is None:
                    raise cleanup_error
