from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from tuntun_contracts.budget import BudgetReconciliationRequest
from tuntun_contracts.ports import TurnInput
from tuntun_contracts.reachy import SafetyReceipt
from tuntun_core.services.sessions.turn_coordinator import TurnCoordinator
from tuntun_core.workflows.contract_workflow import ContractConversationWorkflow
from tuntun_core.workflows.conversation import TurnOutcome
from tuntun_testing.fake_clock import FakeClock


class _Budget:
    def __init__(self) -> None:
        self.reconciliations: list[BudgetReconciliationRequest] = []

    async def reconcile_turn(
        self,
        request: BudgetReconciliationRequest,
    ) -> tuple[()]:
        self.reconciliations.append(request)
        return ()


class _Reachy:
    def __init__(self) -> None:
        self.stop_calls: list[UUID | None] = []

    async def stop_all(self, turn_id: UUID | None) -> SafetyReceipt:
        self.stop_calls.append(turn_id)
        return SafetyReceipt(
            turn_id=turn_id,
            playback_stopped=True,
            motion_stopped=True,
            buffers_cleared=True,
        )


class _Audio:
    async def consume_once(self, turn: TurnInput) -> bytes:
        del turn
        return b"synthetic-wav"


class _Engine:
    def __init__(self, terminal: str) -> None:
        self.terminal = terminal

    async def run(self, turn) -> TurnOutcome:
        del turn
        if self.terminal == "success":
            return TurnOutcome(spoken=True)
        if self.terminal == "denied":
            return TurnOutcome(spoken=False)
        if self.terminal == "permission":
            raise PermissionError("provider_denied")
        if self.terminal == "timeout":
            raise TimeoutError("workflow_timeout")
        if self.terminal == "cancelled":
            raise asyncio.CancelledError
        raise RuntimeError("provider_error")


def _coordinator(reachy: _Reachy) -> TurnCoordinator:
    return TurnCoordinator(
        budget=_Budget(),
        reachy=reachy,
        clock=FakeClock(datetime(2026, 8, 27, tzinfo=UTC)),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("terminal", "expected"),
    (
        ("success", "completed"),
        ("denied", "denied"),
        ("permission", "denied"),
        ("error", "failed"),
    ),
)
async def test_non_cancellation_terminal_path_attempts_coordinator_finish_once(
    terminal: str,
    expected: str,
) -> None:
    reachy = _Reachy()
    coordinator = _coordinator(reachy)
    turn = TurnInput(turn_id=uuid4(), household_id=uuid4(), device_id=uuid4())
    await coordinator.start(turn.turn_id)
    workflow = ContractConversationWorkflow(_Audio(), _Engine(terminal), coordinator)

    output = await workflow.run(turn)

    assert output.outcome == expected
    assert reachy.stop_calls == [turn.turn_id]
    assert coordinator.is_current(turn.turn_id) is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("terminal", "expected_reason"),
    (
        ("cancelled", "workflow_cancelled"),
        ("timeout", "workflow_timeout"),
    ),
)
async def test_cancellation_terminal_path_uses_cancel_barrier_and_never_ordinary_finish(
    terminal: str,
    expected_reason: str,
) -> None:
    budget = _Budget()
    reachy = _Reachy()
    coordinator = TurnCoordinator(
        budget=budget,
        reachy=reachy,
        clock=FakeClock(datetime(2026, 8, 27, tzinfo=UTC)),
    )
    turn = TurnInput(turn_id=uuid4(), household_id=uuid4(), device_id=uuid4())
    await coordinator.start(turn.turn_id)
    workflow = ContractConversationWorkflow(_Audio(), _Engine(terminal), coordinator)

    output = await workflow.run(turn)

    assert output.outcome == "cancelled"
    assert reachy.stop_calls == [turn.turn_id]
    assert coordinator.is_current(turn.turn_id) is False
    assert budget.reconciliations[0].turn_id == turn.turn_id
    assert all(
        proof.evidence_code == f"turn_cancelled:{expected_reason}"
        for proof in budget.reconciliations[0].proofs
    )


@pytest.mark.asyncio
async def test_unsettled_provider_attempt_blocks_finish_and_successor() -> None:
    reachy = _Reachy()
    coordinator = _coordinator(reachy)
    turn = TurnInput(turn_id=uuid4(), household_id=uuid4(), device_id=uuid4())
    reservation_id = uuid4()
    attempt_id = uuid4()
    await coordinator.start(turn.turn_id)
    coordinator.track_reservation(turn.turn_id, reservation_id, attempt_id)
    workflow = ContractConversationWorkflow(_Audio(), _Engine("success"), coordinator)

    output = await workflow.run(turn)

    assert output.outcome == "failed"
    assert coordinator.active_turn_id() == turn.turn_id
    assert coordinator.tracked_attempts(turn.turn_id) == frozenset({(reservation_id, attempt_id)})
    assert reachy.stop_calls == []
    with pytest.raises(RuntimeError, match="household conversation busy"):
        await coordinator.start(uuid4())


@pytest.mark.asyncio
async def test_durable_settlement_completes_pair_then_finish_runs_safety_barrier() -> None:
    reachy = _Reachy()
    coordinator = _coordinator(reachy)
    turn = TurnInput(turn_id=uuid4(), household_id=uuid4(), device_id=uuid4())
    reservation_id = uuid4()
    attempt_id = uuid4()
    await coordinator.start(turn.turn_id)
    coordinator.track_reservation(turn.turn_id, reservation_id, attempt_id)
    coordinator.complete_reservation(turn.turn_id, reservation_id, attempt_id)
    workflow = ContractConversationWorkflow(_Audio(), _Engine("success"), coordinator)

    output = await workflow.run(turn)

    assert output.outcome == "completed"
    assert coordinator.tracked_attempts(turn.turn_id) == frozenset()
    assert reachy.stop_calls == [turn.turn_id]
    assert coordinator.active_turn_id() is None
