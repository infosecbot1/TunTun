from __future__ import annotations

import asyncio
from typing import Literal, Protocol
from uuid import UUID

from tuntun_contracts.ports import TurnInput, TurnOutput
from tuntun_core.workflows.conversation import TurnOutcome, TurnRequest

_PublicOutcome = Literal["completed", "cancelled", "denied", "failed"]


class _ObservedExternalCancellation(RuntimeError):
    pass


class CompletedTurnAudioPort(Protocol):
    async def consume_once(self, turn: TurnInput) -> bytes: ...


class ConversationEngine(Protocol):
    async def run(self, turn: TurnRequest) -> TurnOutcome: ...


class TurnCoordinatorPort(Protocol):
    def track_task(self, turn_id: UUID, task: asyncio.Task[object]) -> None: ...

    def untrack_task(self, turn_id: UUID, task: asyncio.Task[object]) -> None: ...

    def accepts_results(self, turn_id: UUID) -> bool: ...

    async def finish(self, turn_id: UUID) -> bool: ...

    async def cancel(self, turn_id: UUID, reason: str) -> None: ...


class ContractConversationWorkflow:
    """Adapter preserving the frozen public ConversationWorkflow contract."""

    def __init__(
        self,
        audio: CompletedTurnAudioPort,
        engine: ConversationEngine,
        coordinator: TurnCoordinatorPort,
    ) -> None:
        self._audio = audio
        self._engine = engine
        self._coordinator = coordinator
        self._cleanup_reason_codes: list[str] = []

    async def _complete_cancel_barrier(self, turn_id: UUID, reason: str) -> None:
        barrier = asyncio.create_task(
            self._coordinator.cancel(turn_id, reason),
            name=f"workflow-cancel-barrier:{turn_id}",
        )
        while not barrier.done():
            try:
                await asyncio.shield(barrier)
            except asyncio.CancelledError:
                continue
        barrier.result()

    def _untrack_if_terminal(
        self,
        *,
        tracked: bool,
        turn_id: UUID,
        task: asyncio.Task[object] | None,
    ) -> None:
        if tracked and task is not None and task.done():
            self._coordinator.untrack_task(turn_id, task)

    async def run(self, turn: TurnInput) -> TurnOutput:
        if type(turn) is not TurnInput:
            raise TypeError("turn must be an exact TurnInput")
        task: asyncio.Task[object] | None = None
        tracked = False
        result: _PublicOutcome = "failed"
        cancel_reason: str | None = None

        async def execute() -> TurnOutcome:
            wav_bytes = await self._audio.consume_once(turn)
            if not self._coordinator.accepts_results(turn.turn_id):
                raise _ObservedExternalCancellation
            return await self._engine.run(TurnRequest(turn_id=turn.turn_id, wav_bytes=wav_bytes))

        try:
            task = asyncio.create_task(execute(), name=f"conversation:{turn.turn_id}")
            try:
                self._coordinator.track_task(turn.turn_id, task)
            except RuntimeError:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                result = "cancelled"
                cancel_reason = "workflow_observed_external_cancel"
            else:
                tracked = True
                outcome = await asyncio.shield(task)
                if not self._coordinator.accepts_results(turn.turn_id):
                    result = "cancelled"
                    cancel_reason = "workflow_observed_external_cancel"
                else:
                    result = "completed" if outcome.spoken else "denied"
        except asyncio.CancelledError:
            result = "cancelled"
            cancel_reason = "workflow_cancelled"
        except TimeoutError:
            result = "cancelled"
            cancel_reason = "workflow_timeout"
        except _ObservedExternalCancellation:
            result = "cancelled"
            cancel_reason = "workflow_observed_external_cancel"
        except PermissionError:
            result = "denied"
        except Exception:
            result = "failed"
        finally:
            if cancel_reason is None:
                self._untrack_if_terminal(tracked=tracked, turn_id=turn.turn_id, task=task)
                try:
                    released = await self._coordinator.finish(turn.turn_id)
                except asyncio.CancelledError:
                    result = "cancelled"
                    cancel_reason = "workflow_cancelled_during_finish"
                except BaseException:
                    self._cleanup_reason_codes.append("coordinator_finish_failed")
                    result = "failed"
                else:
                    if not released:
                        result = "cancelled"
                        cancel_reason = "workflow_observed_external_cancel"
            if cancel_reason is not None:
                try:
                    await self._complete_cancel_barrier(turn.turn_id, cancel_reason)
                except BaseException:
                    self._cleanup_reason_codes.append("coordinator_cancel_barrier_failed")
                    result = "failed"
                self._untrack_if_terminal(tracked=tracked, turn_id=turn.turn_id, task=task)
        return TurnOutput(turn_id=turn.turn_id, outcome=result)
