from __future__ import annotations

import asyncio
import inspect
from uuid import UUID, uuid4

import pytest
from tuntun_contracts.ports import TurnInput
from tuntun_core.workflows.contract_workflow import ContractConversationWorkflow
from tuntun_core.workflows.conversation import TurnOutcome


def _turn() -> TurnInput:
    return TurnInput(turn_id=uuid4(), household_id=uuid4(), device_id=uuid4())


class _Audio:
    def __init__(self, result: bytes | BaseException = b"RIFF") -> None:
        self.result = result
        self.calls = 0

    async def consume_once(self, turn: TurnInput) -> bytes:
        del turn
        self.calls += 1
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


class _Engine:
    def __init__(self, result: TurnOutcome | BaseException) -> None:
        self.result = result
        self.calls = 0
        self.seen_wav: bytes | None = None

    async def run(self, turn) -> TurnOutcome:
        self.calls += 1
        self.seen_wav = turn.wav_bytes
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


class _Coordinator:
    def __init__(
        self,
        *,
        finish_result: bool = True,
        finish_error: BaseException | None = None,
    ) -> None:
        self.finish_result = finish_result
        self.finish_error = finish_error
        self.tracked: list[asyncio.Task[object]] = []
        self.untracked: list[asyncio.Task[object]] = []
        self.finish_calls: list[UUID] = []
        self.cancel_calls: list[tuple[UUID, str]] = []
        self.accepting = True

    def track_task(self, turn_id: UUID, task: asyncio.Task[object]) -> None:
        del turn_id
        self.tracked.append(task)

    def untrack_task(self, turn_id: UUID, task: asyncio.Task[object]) -> None:
        del turn_id
        if not task.done():
            raise RuntimeError("cannot untrack live task")
        self.untracked.append(task)

    def accepts_results(self, turn_id: UUID) -> bool:
        del turn_id
        return self.accepting

    async def finish(self, turn_id: UUID) -> bool:
        self.finish_calls.append(turn_id)
        if self.finish_error is not None:
            raise self.finish_error
        return self.finish_result

    async def cancel(self, turn_id: UUID, reason: str) -> None:
        self.cancel_calls.append((turn_id, reason))


def test_public_workflow_surface_remains_run_only() -> None:
    assert inspect.signature(ContractConversationWorkflow.run).parameters.keys() == {
        "self",
        "turn",
    }
    assert not hasattr(ContractConversationWorkflow, "cancel")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("engine_result", "expected"),
    (
        (TurnOutcome(spoken=True), "completed"),
        (TurnOutcome(spoken=False), "denied"),
        (PermissionError("provider_denied"), "denied"),
        (ValueError("malformed_audio"), "failed"),
    ),
)
async def test_non_cancellation_terminals_attempt_finish_once(
    engine_result: TurnOutcome | BaseException,
    expected: str,
) -> None:
    turn = _turn()
    audio = _Audio()
    engine = _Engine(engine_result)
    coordinator = _Coordinator()
    workflow = ContractConversationWorkflow(audio, engine, coordinator)

    output = await workflow.run(turn)

    assert output.outcome == expected
    assert output.turn_id == turn.turn_id
    assert coordinator.finish_calls == [turn.turn_id]
    assert coordinator.cancel_calls == []
    assert coordinator.untracked == coordinator.tracked


@pytest.mark.asyncio
async def test_finished_child_result_is_rejected_when_turn_no_longer_accepts_results() -> None:
    turn = _turn()
    coordinator = _Coordinator(finish_result=False)
    coordinator.accepting = False
    workflow = ContractConversationWorkflow(
        _Audio(),
        _Engine(TurnOutcome(spoken=True)),
        coordinator,
    )

    output = await workflow.run(turn)

    assert output.outcome == "cancelled"
    assert coordinator.finish_calls == []
    assert coordinator.cancel_calls == [(turn.turn_id, "workflow_observed_external_cancel")]


@pytest.mark.asyncio
async def test_finish_false_joins_cancel_barrier_without_accepting_completed_result() -> None:
    turn = _turn()
    coordinator = _Coordinator(finish_result=False)
    workflow = ContractConversationWorkflow(
        _Audio(),
        _Engine(TurnOutcome(spoken=True)),
        coordinator,
    )

    output = await workflow.run(turn)

    assert output.outcome == "cancelled"
    assert coordinator.finish_calls == [turn.turn_id]
    assert coordinator.cancel_calls == [(turn.turn_id, "workflow_observed_external_cancel")]


@pytest.mark.asyncio
async def test_unsettled_finish_failure_does_not_fall_back_to_cancel_or_finish_again() -> None:
    turn = _turn()
    coordinator = _Coordinator(finish_error=RuntimeError("turn_has_unsettled_budget_attempts"))
    workflow = ContractConversationWorkflow(
        _Audio(),
        _Engine(TurnOutcome(spoken=True)),
        coordinator,
    )

    output = await workflow.run(turn)

    assert output.outcome == "failed"
    assert coordinator.finish_calls == [turn.turn_id]
    assert coordinator.cancel_calls == []


@pytest.mark.asyncio
async def test_audio_binding_denial_maps_to_denied_before_engine_entry() -> None:
    turn = _turn()
    audio = _Audio(PermissionError("completed_turn_audio_already_consumed"))
    engine = _Engine(TurnOutcome(spoken=True))
    coordinator = _Coordinator()
    workflow = ContractConversationWorkflow(audio, engine, coordinator)

    output = await workflow.run(turn)

    assert output.outcome == "denied"
    assert engine.calls == 0
    assert coordinator.finish_calls == [turn.turn_id]
