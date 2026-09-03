from __future__ import annotations

import ast
import asyncio
import contextlib
import re
import signal
import subprocess
import sys
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import pytest
from tuntun_contracts.base import canonical_bytes, parse_contract_json
from tuntun_contracts.reachy import (
    ReachyCommand,
    ReachyReceipt,
    ReachyState,
    SafetyReceipt,
    StopAllReceiptBundleV1,
)
from tuntun_contracts.reachy_wire import MAX_CONTROL_PAYLOAD_BYTES
from tuntun_core.adapters.reachy.authenticated_control import (  # type: ignore[import-untyped]
    AuthenticatedControlClient,
)
from tuntun_core.adapters.reachy.gateway import ReachyGateway  # type: ignore[import-untyped]

NOW = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)
TURN_ID = UUID("00000000-0000-0000-0000-00000000d001")
ROOT = Path(__file__).resolve().parents[3]
EDGE_PACKAGE_ROOT = ROOT / "apps" / "edge"
PEP701_FSTRING_WITH_COMMENT = 'value = f"""{1 # comment\n}"""\n'
RUFF_PY311_PARSE_COMMAND = (
    sys.executable,
    "-m",
    "ruff",
    "check",
    "--isolated",
    "--target-version",
    "py311",
    "--no-cache",
    "--select",
    "E9",
)
PEP695_DECLARATION = re.compile(
    r"(?m)^\s*(?:(?:async\s+)?def|class)\s+[A-Za-z_][A-Za-z0-9_]*\["
    r"|^\s*type\s+[A-Za-z_][A-Za-z0-9_]*\s*=",
)


class Clock:
    def now(self) -> datetime:
        return NOW


class FakeMediaBuffers:
    def __init__(self, case: ProductionReachyGatewayCase) -> None:
        self.case = case

    async def clear(self) -> None:
        await self.case.operation("clear_buffers")


class FakeReachyDaemon:
    def __init__(self, case: ProductionReachyGatewayCase) -> None:
        self.case = case
        self.state = ReachyState.IDLE
        self.running_calls = 0

    async def running_ids(self) -> tuple[str, ...]:
        self.running_calls += 1
        label = "running_ids_before" if self.running_calls == 1 else "running_ids_after"
        self.case.attempted.append("running_ids")
        self.case.attempted.append(label)
        if self.case.failure == "running_ids_suppresses_cancel" and self.running_calls == 1:
            await self.case.suppress_cancellation(label)
        if self.case.failure == "running_ids_raise" and self.running_calls == 1:
            raise RuntimeError("running ids failed")
        if self.case.failure == "running_ids_raise_then_late_motion" and self.running_calls == 1:
            raise RuntimeError("running ids failed")
        if self.case.failure == "running_ids_hang" and self.running_calls == 1:
            await asyncio.Future()
        if self.case.failure == "running_ids_raise_then_late_motion":
            return ("late-motion-1",)
        if self.running_calls == 1:
            return self.case.movement_inventory_value()
        return ()

    async def stop(self, movement_id: str) -> None:
        self.case.attempted.append("stop_motion")
        self.case.attempted.append(f"stop_motion:{movement_id}")
        self.case.motion_stop_task_count += 1
        if self.case.failure == "one_motion_raise":
            raise RuntimeError("motion failed")
        if self.case.failure == "one_motion_hang":
            await asyncio.Future()
        if self.case.failure == "one_motion_suppresses_cancel":
            await self.case.suppress_cancellation(f"stop_motion:{movement_id}")

    async def stop_playback(self) -> None:
        await self.case.operation("stop_playback")

    async def play_stream(self, stream_id: UUID) -> None:
        self.case.attempted.append(f"play_stream:{stream_id}")
        if self.case.failure == "play_stream_suppresses_cancel":
            await self.case.suppress_cancellation("play_stream")

    async def set_state(self, state: ReachyState) -> None:
        if state is ReachyState.ERROR_SAFE:
            await self.case.operation("enter_error_safe")
        elif state is ReachyState.IDLE:
            await self.case.operation("restore_idle")
        self.state = state

    async def gesture(self, gesture_id: str) -> None:
        self.case.attempted.append(f"gesture:{gesture_id}")
        if self.case.failure == "gesture_suppresses_cancel":
            await self.case.suppress_cancellation("gesture")

    async def connected(self) -> bool:
        self.case.attempted.append("connected")
        if self.case.failure == "connected_suppresses_cancel":
            await self.case.suppress_cancellation("connected")
        return True

    async def queue_depth(self) -> int:
        self.case.attempted.append("queue_depth")
        if self.case.failure == "queue_depth_suppresses_cancel":
            await self.case.suppress_cancellation("queue_depth")
        return 0


class _TaskFactorySaboteur:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, case: ProductionReachyGatewayCase) -> None:
        self._case = case
        self._real_create_task = asyncio.create_task
        self._real_task = asyncio.Task
        self._create_failed = False
        self._task_failed = False
        monkeypatch.setattr(asyncio, "create_task", self._create_task)
        if case.task_factory_unavailable_at is not None:
            monkeypatch.setattr(asyncio, "Task", self._task)

    def _should_fail(self, name: str | None) -> bool:
        if name is None:
            return False
        return name in {
            self._case.task_factory_fail_once_at,
            self._case.task_factory_unavailable_at,
        }

    def _create_task(self, coro: Any, *, name: str | None = None, context: Any = None) -> Any:
        if self._should_fail(name) and not self._create_failed:
            self._create_failed = True
            raise RuntimeError(f"{name}:factory_failed_once")
        if context is None:
            return self._real_create_task(coro, name=name)
        return self._real_create_task(coro, name=name, context=context)

    def _task(
        self,
        coro: Any,
        *,
        loop: asyncio.AbstractEventLoop | None = None,
        name: str | None = None,
        context: Any = None,
    ) -> Any:
        if name == self._case.task_factory_unavailable_at and not self._task_failed:
            self._task_failed = True
            raise RuntimeError(f"{name}:factory_unavailable")
        kwargs: dict[str, Any] = {"loop": loop, "name": name}
        if context is not None:
            kwargs["context"] = context
        return self._real_task(coro, **kwargs)


class FakeSignedSession:
    def __init__(self, case: ProductionReachyGatewayCase) -> None:
        self.case = case

    async def exchange_signed(self, *, purpose: str, payload: bytes) -> bytes:
        self.case.signed_transport_requests += 1
        if purpose == "reachy.stop_all.v1":
            command = parse_contract_json(
                ReachyCommand,
                payload,
                max_bytes=MAX_CONTROL_PAYLOAD_BYTES,
                require_canonical=True,
            )
            if self.case.wrong_turn_once:
                self.case.wrong_turn_once = False
                command_receipt = ReachyReceipt(
                    command_id=command.command_id,
                    accepted=True,
                    reason_code="accepted",
                )
                safety_receipt = SafetyReceipt(
                    turn_id=uuid4(),
                    playback_stopped=True,
                    motion_stopped=True,
                    buffers_cleared=True,
                )
            else:
                command_receipt, maybe_safety_receipt = await self.case.edge_client.execute(command)
                assert type(maybe_safety_receipt) is SafetyReceipt
                safety_receipt = maybe_safety_receipt
            return canonical_bytes(
                StopAllReceiptBundleV1(
                    command_receipt=command_receipt,
                    safety_receipt=safety_receipt,
                )
            )
        if purpose == "reachy.health.v1":
            return canonical_bytes(await self.case.edge_client.health())
        raise AssertionError(purpose)


@dataclass
class ProductionReachyGatewayCase:
    failure: str | None = None
    operation_timeout: float = 0.05
    movement_inventory: str | None = None
    task_factory_fail_once_at: str | None = None
    task_factory_unavailable_at: str | None = None

    def __post_init__(self) -> None:
        from tuntun_edge.reachy.client import ReachyClient

        self.turn_id = TURN_ID
        self.attempted: list[str] = []
        self.motion_stop_task_count = 0
        self.signed_transport_requests = 0
        self.wrong_turn_once = False
        self.edge_private_ack_types: list[str] = []
        self.suppressed_cancel_entered = asyncio.Event()
        self.release_suppressed_cancel = asyncio.Event()
        self.daemon = FakeReachyDaemon(self)
        self.buffers = FakeMediaBuffers(self)
        self.edge_client = ReachyClient(
            self.daemon,
            self.buffers,
            Clock(),
            operation_timeout=self.operation_timeout,
        )
        self.gateway = ReachyGateway(AuthenticatedControlClient(FakeSignedSession(self)), Clock())

    def install_task_factory_sabotage(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _TaskFactorySaboteur(monkeypatch, self)

    @property
    def client_state(self) -> ReachyState:
        return self.edge_client.state

    @property
    def client_task_factory_failure_points(self) -> tuple[str, ...]:
        return self.edge_client.task_factory_failure_points

    @property
    def client_process_restart_required(self) -> bool:
        return self.edge_client.process_restart_required

    @property
    def client_safety_failure_codes(self) -> tuple[str, ...]:
        return self.edge_client.last_safety_failure_codes

    @property
    def gateway_stop_calls(self) -> int:
        return self.signed_transport_requests

    @property
    def no_unobserved_tasks(self) -> bool:
        live = [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and not task.done()
        ]
        return not live

    def movement_inventory_value(self) -> tuple[str, ...]:
        if self.movement_inventory == "non_tuple":
            return ["motion-1"]  # type: ignore[return-value]
        if self.movement_inventory == "duplicate":
            return ("motion-1", "motion-1")
        if self.movement_inventory == "control_character":
            return ("motion\n1",)
        if self.movement_inventory == "too_many":
            return tuple(f"motion-{index}" for index in range(33))
        return ("motion-1",)

    async def operation(self, name: str) -> None:
        self.attempted.append(name)
        if self.failure == f"{_failure_prefix(name)}_raise":
            raise RuntimeError(f"{name} failed")
        if self.failure == f"{_failure_prefix(name)}_hang":
            await asyncio.Future()
        if self.failure == f"{_failure_prefix(name)}_suppresses_cancel":
            await self.suppress_cancellation(name)

    async def suppress_cancellation(self, name: str) -> None:
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            self.attempted.append(f"{name}:suppressed_cancel")
            self.suppressed_cancel_entered.set()
            await self.release_suppressed_cancel.wait()

    def reply_with_wrong_turn_once(self) -> None:
        self.wrong_turn_once = True


@pytest.fixture()
def production_reachy_gateway_case(
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[..., ProductionReachyGatewayCase]:
    def build(**kwargs: Any) -> ProductionReachyGatewayCase:
        case = ProductionReachyGatewayCase(**kwargs)
        case.install_task_factory_sabotage(monkeypatch)
        return case

    return build


@pytest.fixture()
def coordinator_factory() -> Any:
    class Coordinator:
        def __init__(self, reachy: ReachyGateway) -> None:
            self._reachy = reachy
            self._turn_id: UUID | None = None

        async def start(self, turn_id: UUID) -> None:
            self._turn_id = turn_id

        async def cancel(self, turn_id: UUID, reason: str) -> None:
            del reason
            try:
                await self._reachy.stop_all(turn_id)
            except (PermissionError, RuntimeError):
                await self._reachy.stop_all(turn_id)
            self._turn_id = None

        def active_turn_id(self) -> UUID | None:
            return self._turn_id

    return Coordinator


@pytest.mark.asyncio
async def test_production_gateway_returns_exact_frozen_safety_receipt(
    production_reachy_gateway_case: Callable[..., ProductionReachyGatewayCase],
) -> None:
    case = production_reachy_gateway_case()

    assert type(case.gateway) is ReachyGateway
    receipt = await case.gateway.stop_all(case.turn_id)

    assert type(receipt) is SafetyReceipt
    assert receipt == SafetyReceipt(
        turn_id=case.turn_id,
        playback_stopped=True,
        motion_stopped=True,
        buffers_cleared=True,
    )
    assert case.signed_transport_requests == 1
    assert case.edge_private_ack_types == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    (
        "running_ids_raise",
        "running_ids_hang",
        "one_motion_raise",
        "one_motion_hang",
        "playback_raise",
        "playback_hang",
        "buffers_raise",
        "buffers_hang",
        "error_safe_raise",
        "error_safe_hang",
        "idle_restore_raise",
        "idle_restore_hang",
    ),
)
async def test_every_edge_stop_failure_is_independently_attempted_truthful_and_error_safe(
    production_reachy_gateway_case: Callable[..., ProductionReachyGatewayCase],
    failure: str,
) -> None:
    case = production_reachy_gateway_case(failure=failure, operation_timeout=0.01)

    receipt = await asyncio.wait_for(case.gateway.stop_all(case.turn_id), timeout=0.15)

    assert receipt.turn_id == case.turn_id
    assert set(case.attempted) >= {
        "running_ids",
        "stop_playback",
        "clear_buffers",
        "enter_error_safe",
    }
    assert case.client_state is ReachyState.ERROR_SAFE
    assert not all((receipt.playback_stopped, receipt.motion_stopped, receipt.buffers_cleared))
    assert case.no_unobserved_tasks


@pytest.mark.asyncio
@pytest.mark.parametrize("inventory", ("non_tuple", "duplicate", "control_character", "too_many"))
async def test_malformed_or_oversized_motion_inventory_is_bounded_and_degraded(
    production_reachy_gateway_case: Callable[..., ProductionReachyGatewayCase],
    inventory: str,
) -> None:
    case = production_reachy_gateway_case(movement_inventory=inventory)

    receipt = await case.gateway.stop_all(case.turn_id)

    assert case.motion_stop_task_count <= 32
    assert receipt.motion_stopped is False
    assert case.client_state is ReachyState.ERROR_SAFE
    assert "running_ids_before:invalid" in case.client_safety_failure_codes
    assert case.no_unobserved_tasks


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    ("running_ids_suppresses_cancel", "one_motion_suppresses_cancel", "playback_suppresses_cancel"),
)
async def test_stop_all_suppressed_cancellation_is_quarantined_and_degraded(
    production_reachy_gateway_case: Callable[..., ProductionReachyGatewayCase],
    failure: str,
) -> None:
    case = production_reachy_gateway_case(failure=failure, operation_timeout=0.01)
    caller = asyncio.create_task(case.gateway.stop_all(case.turn_id))

    try:
        await asyncio.wait_for(case.suppressed_cancel_entered.wait(), timeout=0.2)
        done, _pending = await asyncio.wait({caller}, timeout=0.25)
        assert caller in done
        receipt = caller.result()
        assert receipt.turn_id == case.turn_id
        assert not all((receipt.playback_stopped, receipt.motion_stopped, receipt.buffers_cleared))
        assert case.client_state is ReachyState.ERROR_SAFE
        assert case.client_process_restart_required is True
    finally:
        case.release_suppressed_cancel.set()
        if not caller.done():
            caller.cancel()
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(caller, timeout=1.0)
        await asyncio.sleep(0)
    assert case.no_unobserved_tasks


@pytest.mark.asyncio
async def test_first_inventory_failure_with_late_motion_remains_truthfully_degraded(
    production_reachy_gateway_case: Callable[..., ProductionReachyGatewayCase],
) -> None:
    case = production_reachy_gateway_case(failure="running_ids_raise_then_late_motion")

    receipt = await case.gateway.stop_all(case.turn_id)

    assert receipt.motion_stopped is False
    assert "running_ids_before:RuntimeError" in case.client_safety_failure_codes
    assert "stop_motion:late-motion-1" not in case.attempted
    assert case.client_state is ReachyState.ERROR_SAFE


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure", ("connected_suppresses_cancel", "queue_depth_suppresses_cancel")
)
async def test_reachy_health_suppressed_cancellation_is_bounded_and_error_safe(
    production_reachy_gateway_case: Callable[..., ProductionReachyGatewayCase],
    failure: str,
) -> None:
    case = production_reachy_gateway_case(failure=failure, operation_timeout=0.01)
    caller = asyncio.create_task(case.edge_client.health())

    try:
        await asyncio.wait_for(case.suppressed_cancel_entered.wait(), timeout=0.2)
        done, _pending = await asyncio.wait({caller}, timeout=0.25)
        assert caller in done
        health = caller.result()
        assert health.state is ReachyState.ERROR_SAFE
        assert health.daemon_connected is False
        assert health.queue_depth == 0
        assert case.client_process_restart_required is True
    finally:
        case.release_suppressed_cancel.set()
        if not caller.done():
            caller.cancel()
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(caller, timeout=1.0)
        await asyncio.sleep(0)
    assert case.no_unobserved_tasks


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "command"),
    (
        (
            "idle_restore_suppresses_cancel",
            lambda: ReachyCommand(
                command_id=uuid4(),
                turn_id=TURN_ID,
                kind="state",
                state=ReachyState.IDLE,
                media_stream_id=None,
                gesture_id=None,
                expires_at=NOW + timedelta(seconds=1),
            ),
        ),
        (
            "play_stream_suppresses_cancel",
            lambda: ReachyCommand(
                command_id=uuid4(),
                turn_id=TURN_ID,
                kind="playback",
                state=None,
                media_stream_id=uuid4(),
                gesture_id=None,
                expires_at=NOW + timedelta(seconds=1),
            ),
        ),
        (
            "gesture_suppresses_cancel",
            lambda: ReachyCommand(
                command_id=uuid4(),
                turn_id=TURN_ID,
                kind="gesture",
                state=None,
                media_stream_id=None,
                gesture_id="acknowledge",
                expires_at=NOW + timedelta(seconds=1),
            ),
        ),
    ),
)
async def test_reachy_execute_public_command_suppressed_cancellation_is_bounded(
    production_reachy_gateway_case: Callable[..., ProductionReachyGatewayCase],
    failure: str,
    command: Callable[[], ReachyCommand],
) -> None:
    case = production_reachy_gateway_case(failure=failure, operation_timeout=0.01)
    caller = asyncio.create_task(case.edge_client.execute(command()))

    try:
        await asyncio.wait_for(case.suppressed_cancel_entered.wait(), timeout=0.2)
        done, _pending = await asyncio.wait({caller}, timeout=0.25)
        assert caller in done
        receipt, safety = caller.result()
        assert receipt.accepted is False
        assert receipt.reason_code == "edge_execution_failed"
        assert safety is None
        assert case.client_state is ReachyState.ERROR_SAFE
        assert case.client_process_restart_required is True
    finally:
        case.release_suppressed_cancel.set()
        if not caller.done():
            caller.cancel()
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(caller, timeout=1.0)
        await asyncio.sleep(0)
    assert case.no_unobserved_tasks


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "factory_point",
    (
        "edge-stop-all",
        "running_ids_before",
        "stop_playback",
        "clear_buffers",
        "enter_error_safe",
        "stop_motion:motion-1",
        "running_ids_after",
        "restore_idle",
    ),
)
async def test_one_edge_task_factory_failure_uses_observed_fallback_without_skipping_safety(
    production_reachy_gateway_case: Callable[..., ProductionReachyGatewayCase],
    factory_point: str,
) -> None:
    case = production_reachy_gateway_case(task_factory_fail_once_at=factory_point)

    receipt = await case.gateway.stop_all(case.turn_id)

    assert all((receipt.playback_stopped, receipt.motion_stopped, receipt.buffers_cleared))
    assert factory_point in case.client_task_factory_failure_points
    assert set(case.attempted) >= {
        "running_ids",
        "stop_playback",
        "clear_buffers",
        "enter_error_safe",
        "stop_motion",
    }
    assert case.no_unobserved_tasks


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "factory_point",
    (
        "running_ids_before",
        "stop_playback",
        "clear_buffers",
        "enter_error_safe",
        "stop_motion:motion-1",
        "running_ids_after",
        "restore_idle",
    ),
)
async def test_unavailable_inner_edge_task_owner_degrades_truthfully_and_latches_restart(
    production_reachy_gateway_case: Callable[..., ProductionReachyGatewayCase],
    factory_point: str,
) -> None:
    case = production_reachy_gateway_case(task_factory_unavailable_at=factory_point)

    receipt = await case.gateway.stop_all(case.turn_id)

    assert case.client_state is ReachyState.ERROR_SAFE
    assert case.client_process_restart_required is True
    assert not all((receipt.playback_stopped, receipt.motion_stopped, receipt.buffers_cleared))
    assert case.no_unobserved_tasks


@pytest.mark.asyncio
async def test_unavailable_outer_edge_safety_owner_returns_only_degraded_proof(
    production_reachy_gateway_case: Callable[..., ProductionReachyGatewayCase],
) -> None:
    case = production_reachy_gateway_case(task_factory_unavailable_at="edge-stop-all")

    receipt = await case.gateway.stop_all(case.turn_id)

    assert case.client_state is ReachyState.ERROR_SAFE
    assert case.client_process_restart_required is True
    assert receipt == SafetyReceipt(
        turn_id=case.turn_id,
        playback_stopped=False,
        motion_stopped=False,
        buffers_cleared=False,
    )
    assert case.no_unobserved_tasks


@pytest.mark.asyncio
async def test_coordinator_consumes_real_gateway_receipt_and_rejects_wrong_turn(
    production_reachy_gateway_case: Callable[..., ProductionReachyGatewayCase],
    coordinator_factory: Any,
) -> None:
    case = production_reachy_gateway_case()
    coordinator = coordinator_factory(case.gateway)

    await coordinator.start(case.turn_id)
    case.reply_with_wrong_turn_once()
    await coordinator.cancel(case.turn_id, "privacy")

    assert case.gateway_stop_calls == 2
    assert coordinator.active_turn_id() is None


@pytest.mark.asyncio
async def test_reachy_client_execute_uses_explicit_validation_for_payloads(
    production_reachy_gateway_case: Callable[..., ProductionReachyGatewayCase],
) -> None:
    case = production_reachy_gateway_case()
    command = ReachyCommand(
        command_id=uuid4(),
        turn_id=case.turn_id,
        kind="gesture",
        state=None,
        media_stream_id=None,
        gesture_id="acknowledge",
        expires_at=NOW + timedelta(seconds=1),
    )
    bad = command.model_copy(update={"gesture_id": object()})

    receipt, safety = await case.edge_client.execute(bad)

    assert receipt.accepted is False
    assert receipt.reason_code == "edge_execution_failed"
    assert safety is None
    assert case.client_state is ReachyState.ERROR_SAFE


def test_validate_gesture_accepts_only_exact_safe_names() -> None:
    from tuntun_edge.reachy.gestures import SAFE_GESTURES, validate_gesture

    assert (
        frozenset(
            {
                "neutral",
                "acknowledge",
                "listen",
                "think",
                "speak",
                "confirm",
                "deny",
                "error",
                "sleep",
            }
        )
        == SAFE_GESTURES
    )
    assert validate_gesture("listen") == "listen"
    with pytest.raises(ValueError, match="gesture_not_allowlisted"):
        validate_gesture("wave")
    with pytest.raises(TypeError, match="gesture_id must be an exact str"):
        validate_gesture(type("Gesture", (str,), {})("listen"))


def _edge_python_sources() -> tuple[Path, ...]:
    return tuple(sorted((EDGE_PACKAGE_ROOT / "src" / "tuntun_edge").rglob("*.py")))


def _run_ruff_py311_parse_check(paths: tuple[Path, ...]) -> subprocess.CompletedProcess[str]:
    assert paths
    return subprocess.run(
        [*RUFF_PY311_PARSE_COMMAND, *(str(path) for path in paths)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def _ruff_result_message(result: subprocess.CompletedProcess[str]) -> str:
    return "\n".join(
        part
        for part in (
            "command: " + " ".join(str(argument) for argument in result.args),
            "stdout:\n" + result.stdout.strip(),
            "stderr:\n" + result.stderr.strip(),
        )
        if part.strip()
    )


def test_edge_task11_sources_parse_on_declared_python_311_floor() -> None:
    edge_metadata = tomllib.loads((EDGE_PACKAGE_ROOT / "pyproject.toml").read_text("utf-8"))
    assert edge_metadata["project"]["requires-python"] == ">=3.11,<3.13"

    edge_sources = _edge_python_sources()
    result = _run_ruff_py311_parse_check(edge_sources)
    assert result.returncode == 0, _ruff_result_message(result)

    parse_failures: list[str] = []
    pep695_declarations: list[str] = []
    for source in edge_sources:
        text = source.read_text("utf-8")
        try:
            ast.parse(text, filename=str(source), feature_version=(3, 11))
        except SyntaxError as error:
            parse_failures.append(
                f"{source.relative_to(ROOT)}:{error.lineno}:{error.offset}: {error.msg}"
            )
        if PEP695_DECLARATION.search(text):
            pep695_declarations.append(str(source.relative_to(ROOT)))

    assert parse_failures == []
    assert pep695_declarations == []


def test_ruff_py311_parser_canary_rejects_pep701_fstring_comments(tmp_path: Path) -> None:
    canary = tmp_path / "pep701_canary.py"
    canary.write_text(PEP701_FSTRING_WITH_COMMENT, "utf-8")

    result = _run_ruff_py311_parse_check((canary,))

    assert result.returncode != 0
    assert "Cannot use comments in f-strings on Python 3.11" in _ruff_result_message(result)


def test_managed_edge_composition_passes_exact_supervisor_and_safety_objects() -> None:
    from tuntun_edge.bootstrap.managed import ManagedEdgeComposition

    captured: list[dict[str, Any]] = []

    def factory(**kwargs: Any) -> RecordingWssClient:
        captured.append(kwargs)
        return RecordingWssClient([])

    composition = ManagedEdgeComposition.build(
        endpoint=object(),
        tls_context=object(),
        pairing_keys=object(),
        duplex_state=object(),
        daemon=StaticDaemon(),
        buffers=StaticBuffers(),
        clock=Clock(),
        reachy_wss_client_factory=factory,
    )

    assert len(captured) == 1
    assert composition.readiness_dependencies == (composition.reachy_transport_supervisor,)
    assert captured[0]["readiness"] is composition.reachy_transport_supervisor
    assert captured[0]["safety"] is composition.disconnect_safety
    assert captured[0]["handler"] is composition.reachy_client


def test_production_managed_edge_builder_is_release_packaging_gated() -> None:
    from tuntun_edge.bootstrap.managed import build_production_managed_edge

    with pytest.raises(RuntimeError, match="release packaging"):
        build_production_managed_edge()


@pytest.mark.asyncio
async def test_disconnect_safety_leaves_local_error_safe_latched_after_successful_cleanup() -> None:
    from tuntun_edge.bootstrap.managed import EdgeDisconnectSafety
    from tuntun_edge.reachy.client import ReachyClient

    client = ReachyClient(StaticDaemon(), StaticBuffers(), Clock())
    safety = EdgeDisconnectSafety(client)

    await safety.close_media_stop_playback_motion_and_forget_turn()

    assert client.state is ReachyState.ERROR_SAFE


@pytest.mark.asyncio
async def test_managed_edge_runtime_gates_before_socket_or_media() -> None:
    from tuntun_edge.runtime import ManagedEdgeRuntime

    events: list[str] = []
    readiness = RecordingReadiness(events)
    safety = RecordingSafety(events)
    stop = asyncio.Event()
    wss_client = RecordingWssClient(events, on_run=stop.set)
    runtime = ManagedEdgeRuntime(
        active_release_gate=RecordingGate(events, "active_release"),
        firewall_baseline=RecordingGate(events, "emergency_firewall"),
        boot_gate=RecordingGate(events, "verified_firewall_receipt"),
        commissioning_gate=RecordingGate(events, "commissioning"),
        secure_time_gate=RecordingGate(events, "secure_time"),
        controller_guard=RecordingControllerGuard(events, ready=True),
        startup_safety=safety,
        reachy_wss_client=wss_client,
        readiness=readiness,
    )

    await runtime.run(stop)

    assert events[:7] == [
        "active_release",
        "emergency_firewall",
        "verified_firewall_receipt",
        "commissioning",
        "secure_time",
        "controller_guard",
        "startup_safety",
    ]
    assert "socket" in events
    assert events.index("startup_safety") < events.index("socket")


@pytest.mark.asyncio
async def test_managed_edge_runtime_degraded_startup_safety_blocks_socket_and_latches_restart() -> (
    None
):
    from tuntun_edge.runtime import ManagedEdgeRuntime

    events: list[str] = []
    readiness = RecordingReadiness(events)
    safety = RecordingSafety(
        events,
        receipts=[
            SafetyReceipt(
                turn_id=None,
                playback_stopped=True,
                motion_stopped=False,
                buffers_cleared=True,
            )
        ],
        process_restart_required=True,
    )
    stop = asyncio.Event()
    wss_client = RecordingWssClient(events, on_run=stop.set)
    runtime = ManagedEdgeRuntime(
        active_release_gate=RecordingGate(events, "active_release"),
        firewall_baseline=RecordingGate(events, "emergency_firewall"),
        boot_gate=RecordingGate(events, "verified_firewall_receipt"),
        commissioning_gate=RecordingGate(events, "commissioning"),
        secure_time_gate=RecordingGate(events, "secure_time"),
        controller_guard=RecordingControllerGuard(events, ready=True),
        startup_safety=safety,
        reachy_wss_client=wss_client,
        readiness=readiness,
    )

    with pytest.raises(PermissionError, match="managed_edge_startup_safety"):
        await runtime.run(stop)

    assert "socket" not in events
    assert "readiness:managed_edge_startup_safety_incomplete" in events
    assert readiness.restart_required is True


@pytest.mark.asyncio
async def test_managed_edge_runtime_controller_restart_required_blocks_socket() -> None:
    from tuntun_edge.runtime import ManagedEdgeRuntime

    events: list[str] = []
    readiness = RecordingReadiness(events)
    stop = asyncio.Event()
    wss_client = RecordingWssClient(events, on_run=stop.set)
    runtime = ManagedEdgeRuntime(
        active_release_gate=RecordingGate(events, "active_release"),
        firewall_baseline=RecordingGate(events, "emergency_firewall"),
        boot_gate=RecordingGate(events, "verified_firewall_receipt"),
        commissioning_gate=RecordingGate(events, "commissioning"),
        secure_time_gate=RecordingGate(events, "secure_time"),
        controller_guard=RecordingControllerGuard(
            events,
            ready=True,
            process_restart_required=True,
        ),
        startup_safety=RecordingSafety(events),
        reachy_wss_client=wss_client,
        readiness=readiness,
    )

    with pytest.raises(PermissionError, match="managed_edge_controller_restart_required"):
        await runtime.run(stop)

    assert "socket" not in events
    assert "readiness:managed_edge_controller_restart_required" in events
    assert events.index("readiness:managed_edge_controller_restart_required") < events.index(
        "startup_safety"
    )
    assert readiness.restart_required is True


@pytest.mark.asyncio
async def test_managed_edge_runtime_controller_error_safe_blocks_socket() -> None:
    from tuntun_edge.runtime import ManagedEdgeRuntime

    events: list[str] = []
    readiness = RecordingReadiness(events)
    stop = asyncio.Event()
    wss_client = RecordingWssClient(events, on_run=stop.set)
    runtime = ManagedEdgeRuntime(
        active_release_gate=RecordingGate(events, "active_release"),
        firewall_baseline=RecordingGate(events, "emergency_firewall"),
        boot_gate=RecordingGate(events, "verified_firewall_receipt"),
        commissioning_gate=RecordingGate(events, "commissioning"),
        secure_time_gate=RecordingGate(events, "secure_time"),
        controller_guard=RecordingControllerGuard(
            events,
            ready=True,
            error_safe_latched=True,
        ),
        startup_safety=RecordingSafety(events),
        reachy_wss_client=wss_client,
        readiness=readiness,
    )

    with pytest.raises(PermissionError, match="managed_edge_controller_error_safe"):
        await runtime.run(stop)

    assert "socket" not in events
    assert "readiness:managed_edge_controller_error_safe" in events
    assert events.index("readiness:managed_edge_controller_error_safe") < events.index(
        "startup_safety"
    )
    assert readiness.restart_required is True


@pytest.mark.asyncio
async def test_managed_edge_runtime_withdraws_readiness_and_cleans_up_on_exit() -> None:
    from tuntun_edge.runtime import ManagedEdgeRuntime

    events: list[str] = []
    readiness = RecordingReadiness(events)
    release = asyncio.Event()
    stop = asyncio.Event()
    wss_client = RecordingWssClient(events, release=release)
    safety = RecordingSafety(events)
    runtime = ManagedEdgeRuntime(
        active_release_gate=RecordingGate(events, "active_release"),
        firewall_baseline=RecordingGate(events, "emergency_firewall"),
        boot_gate=RecordingGate(events, "verified_firewall_receipt"),
        commissioning_gate=RecordingGate(events, "commissioning"),
        secure_time_gate=RecordingGate(events, "secure_time"),
        controller_guard=RecordingControllerGuard(events, ready=True),
        startup_safety=safety,
        reachy_wss_client=wss_client,
        readiness=readiness,
    )
    task = asyncio.create_task(runtime.run(stop))
    await wss_client.entered.wait()

    stop.set()
    release.set()
    await task

    assert readiness.ready is False
    assert readiness.codes == ("managed_edge_runtime_exited",)
    assert events[-2:] == ["startup_safety", "readiness:managed_edge_runtime_exited"]


@pytest.mark.asyncio
async def test_managed_edge_runtime_cleanup_degraded_receipt_is_truthfully_reported() -> None:
    from tuntun_edge.runtime import ManagedEdgeRuntime

    events: list[str] = []
    readiness = RecordingReadiness(events)
    release = asyncio.Event()
    stop = asyncio.Event()
    wss_client = RecordingWssClient(events, release=release)
    safety = RecordingSafety(
        events,
        receipts=[
            _clean_safety_receipt(),
            SafetyReceipt(
                turn_id=None,
                playback_stopped=True,
                motion_stopped=False,
                buffers_cleared=True,
            ),
        ],
    )
    runtime = ManagedEdgeRuntime(
        active_release_gate=RecordingGate(events, "active_release"),
        firewall_baseline=RecordingGate(events, "emergency_firewall"),
        boot_gate=RecordingGate(events, "verified_firewall_receipt"),
        commissioning_gate=RecordingGate(events, "commissioning"),
        secure_time_gate=RecordingGate(events, "secure_time"),
        controller_guard=RecordingControllerGuard(events, ready=True),
        startup_safety=safety,
        reachy_wss_client=wss_client,
        readiness=readiness,
    )
    task = asyncio.create_task(runtime.run(stop))
    await wss_client.entered.wait()

    stop.set()
    release.set()
    with pytest.raises(RuntimeError, match="managed_edge_cleanup_failed"):
        await task

    assert readiness.ready is False
    assert readiness.restart_required is True
    assert "readiness:managed_edge_cleanup_safety_incomplete" in events


@pytest.mark.asyncio
async def test_managed_edge_runtime_cleanup_suppressed_cancellation_is_quarantined() -> None:
    from tuntun_edge.runtime import ManagedEdgeRuntime

    events: list[str] = []
    readiness = RecordingReadiness(events)
    run_release = asyncio.Event()
    cleanup_release = asyncio.Event()
    stop = asyncio.Event()
    wss_client = RecordingWssClient(events, release=run_release)
    safety = RecordingSafety(
        events,
        release=cleanup_release,
        block_after_calls=1,
        suppress_cancel=True,
    )
    runtime = ManagedEdgeRuntime(
        active_release_gate=RecordingGate(events, "active_release"),
        firewall_baseline=RecordingGate(events, "emergency_firewall"),
        boot_gate=RecordingGate(events, "verified_firewall_receipt"),
        commissioning_gate=RecordingGate(events, "commissioning"),
        secure_time_gate=RecordingGate(events, "secure_time"),
        controller_guard=RecordingControllerGuard(events, ready=True),
        startup_safety=safety,
        reachy_wss_client=wss_client,
        readiness=readiness,
        cleanup_timeout=0.01,
    )
    caller = asyncio.create_task(runtime.run(stop))
    await wss_client.entered.wait()
    stop.set()
    run_release.set()

    try:
        done, _pending = await asyncio.wait({caller}, timeout=0.25)
        assert caller in done
        with pytest.raises(RuntimeError, match="managed_edge_cleanup_failed"):
            caller.result()
        assert readiness.ready is False
        assert readiness.restart_required is True
        assert "readiness:managed_edge_cleanup:TimeoutError" in events
    finally:
        cleanup_release.set()
        if not caller.done():
            caller.cancel()
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(caller, timeout=1.0)
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_managed_edge_runtime_repeated_cancellation_preserves_cleanup_barrier() -> None:
    from tuntun_edge.runtime import ManagedEdgeRuntime

    events: list[str] = []
    readiness = RecordingReadiness(events)
    run_release = asyncio.Event()
    cleanup_release = asyncio.Event()
    stop = asyncio.Event()
    wss_client = RecordingWssClient(events, release=run_release)
    safety = RecordingSafety(events, release=cleanup_release, block_after_calls=1)
    runtime = ManagedEdgeRuntime(
        active_release_gate=RecordingGate(events, "active_release"),
        firewall_baseline=RecordingGate(events, "emergency_firewall"),
        boot_gate=RecordingGate(events, "verified_firewall_receipt"),
        commissioning_gate=RecordingGate(events, "commissioning"),
        secure_time_gate=RecordingGate(events, "secure_time"),
        controller_guard=RecordingControllerGuard(events, ready=True),
        startup_safety=safety,
        reachy_wss_client=wss_client,
        readiness=readiness,
    )
    caller = asyncio.create_task(runtime.run(stop))
    await wss_client.entered.wait()
    caller.cancel()
    await safety.cleanup_entered.wait()
    caller.cancel()
    caller.cancel()

    assert caller.done() is False
    cleanup_release.set()
    run_release.set()
    with pytest.raises(asyncio.CancelledError):
        await caller
    assert readiness.ready is False
    assert events[-2:] == ["startup_safety", "readiness:managed_edge_runtime_exited"]


@pytest.mark.asyncio
async def test_production_runner_routes_repeated_signals_through_runtime_cleanup_order() -> None:
    import tuntun_edge.bootstrap.managed as module
    from tuntun_edge.runtime import ManagedEdgeRuntime

    events: list[str] = []
    readiness = RecordingReadiness(events)
    release = asyncio.Event()
    wss_client = RecordingWssClient(events, release=release)
    runtime = ManagedEdgeRuntime(
        active_release_gate=RecordingGate(events, "active_release"),
        firewall_baseline=RecordingGate(events, "emergency_firewall"),
        boot_gate=RecordingGate(events, "verified_firewall_receipt"),
        commissioning_gate=RecordingGate(events, "commissioning"),
        secure_time_gate=RecordingGate(events, "secure_time"),
        controller_guard=RecordingControllerGuard(events, ready=True),
        startup_safety=RecordingSafety(events),
        reachy_wss_client=wss_client,
        readiness=readiness,
    )
    registered: dict[signal.Signals, Callable[[], None]] = {}

    def install_signal_handlers(stop: asyncio.Event) -> Callable[[], None]:
        events.append("signals:installed")

        def trigger(signum: signal.Signals) -> None:
            events.append(f"signal:{signum.name}")
            stop.set()
            release.set()

        registered[signal.SIGTERM] = lambda: trigger(signal.SIGTERM)
        registered[signal.SIGINT] = lambda: trigger(signal.SIGINT)
        return lambda: events.append("signals:removed")

    task = asyncio.create_task(
        module.run_managed_edge(
            SimpleNamespace(runtime=runtime),
            install_signal_handlers=install_signal_handlers,
        )
    )
    await wss_client.entered.wait()

    registered[signal.SIGTERM]()
    registered[signal.SIGINT]()
    await task

    socket_index = events.index("socket")
    cleanup_index = max(index for index, event in enumerate(events) if event == "startup_safety")
    assert socket_index < events.index("signal:SIGTERM") < cleanup_index
    assert events.index("readiness:managed_edge_runtime_exited") < events.index("signals:removed")


@pytest.mark.asyncio
async def test_install_stop_signal_handlers_rolls_back_loop_handler_on_partial_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tuntun_edge.bootstrap.managed as module

    events: list[str] = []
    stop = asyncio.Event()

    class FakeLoop:
        def add_signal_handler(self, signum: signal.Signals, callback: Callable[[], None]) -> None:
            del callback
            events.append(f"loop:add:{signum.name}")
            if signum is signal.SIGTERM:
                raise NotImplementedError

        def remove_signal_handler(self, signum: signal.Signals) -> None:
            events.append(f"loop:remove:{signum.name}")

        def call_soon_threadsafe(self, callback: Callable[[], None]) -> None:
            callback()

    monkeypatch.setattr(asyncio, "get_running_loop", lambda: FakeLoop())
    monkeypatch.setattr(signal, "getsignal", lambda signum: signal.SIG_DFL)

    def fail_fallback_install(signum: signal.Signals, handler: Any) -> Any:
        del signum, handler
        raise ValueError("not main thread")

    monkeypatch.setattr(signal, "signal", fail_fallback_install)

    with pytest.raises(ValueError, match="not main thread"):
        module.install_stop_signal_handlers(stop)

    assert events == ["loop:add:SIGINT", "loop:add:SIGTERM", "loop:remove:SIGINT"]


@pytest.mark.asyncio
async def test_install_stop_signal_handlers_rolls_back_fallback_handler_on_partial_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tuntun_edge.bootstrap.managed as module

    stop = asyncio.Event()
    previous_handlers: dict[signal.Signals, Any] = {
        signal.SIGINT: object(),
        signal.SIGTERM: object(),
    }
    installed: dict[signal.Signals, Any] = {}
    calls: list[tuple[signal.Signals, Any]] = []

    class FakeLoop:
        def add_signal_handler(self, signum: signal.Signals, callback: Callable[[], None]) -> None:
            del signum, callback
            raise NotImplementedError

    def fake_signal(signum: signal.Signals, handler: Any) -> Any:
        calls.append((signum, handler))
        if signum is signal.SIGTERM and handler is not previous_handlers[signal.SIGTERM]:
            raise ValueError("not main thread")
        installed[signum] = handler
        return previous_handlers[signum]

    monkeypatch.setattr(asyncio, "get_running_loop", lambda: FakeLoop())
    monkeypatch.setattr(signal, "getsignal", lambda signum: previous_handlers[signum])
    monkeypatch.setattr(signal, "signal", fake_signal)

    with pytest.raises(ValueError, match="not main thread"):
        module.install_stop_signal_handlers(stop)

    assert calls[-1] == (signal.SIGINT, previous_handlers[signal.SIGINT])
    assert installed[signal.SIGINT] is previous_handlers[signal.SIGINT]


@pytest.mark.asyncio
async def test_stop_signal_handler_cleanup_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tuntun_edge.bootstrap.managed as module

    removed: list[signal.Signals] = []
    stop = asyncio.Event()

    class FakeLoop:
        def add_signal_handler(self, signum: signal.Signals, callback: Callable[[], None]) -> None:
            del signum, callback

        def remove_signal_handler(self, signum: signal.Signals) -> None:
            removed.append(signum)

    monkeypatch.setattr(asyncio, "get_running_loop", lambda: FakeLoop())

    remove = module.install_stop_signal_handlers(stop)
    remove()
    remove()

    assert set(removed) == {signal.SIGINT, signal.SIGTERM}
    assert len(removed) == 2


class StaticDaemon:
    async def running_ids(self) -> tuple[str, ...]:
        return ()

    async def stop(self, movement_id: str) -> None:
        del movement_id

    async def stop_playback(self) -> None:
        return None

    async def play_stream(self, stream_id: UUID) -> None:
        del stream_id

    async def set_state(self, state: ReachyState) -> None:
        del state

    async def gesture(self, gesture_id: str) -> None:
        del gesture_id

    async def connected(self) -> bool:
        return True

    async def queue_depth(self) -> int:
        return 0


class StaticBuffers:
    async def clear(self) -> None:
        return None


class RecordingGate:
    def __init__(self, events: list[str], name: str) -> None:
        self._events = events
        self._name = name

    async def require(self) -> None:
        self._events.append(self._name)


class RecordingControllerGuard:
    def __init__(
        self,
        events: list[str],
        *,
        ready: bool,
        process_restart_required: bool = False,
        error_safe_latched: bool = False,
    ) -> None:
        self._events = events
        self._ready = ready
        self.process_restart_required = process_restart_required
        self.error_safe_latched = error_safe_latched

    async def poll(self) -> bool:
        self._events.append("controller_guard")
        return self._ready


class RecordingSafety:
    def __init__(
        self,
        events: list[str],
        release: asyncio.Event | None = None,
        *,
        block_after_calls: int = 0,
        suppress_cancel: bool = False,
        receipts: list[SafetyReceipt] | None = None,
        process_restart_required: bool = False,
        failure_codes: tuple[str, ...] = (),
    ) -> None:
        self._events = events
        self._release = release
        self._block_after_calls = block_after_calls
        self._suppress_cancel = suppress_cancel
        self._receipts = list(receipts or [])
        self.process_restart_required = process_restart_required
        self.last_failure_codes = failure_codes
        self.calls = 0
        self.cleanup_entered = asyncio.Event()

    def latch_error_safe(self, reason: str) -> None:
        self._events.append(f"latch:{reason}")

    async def close_media_stop_playback_motion_and_forget_turn(self) -> SafetyReceipt:
        self.calls += 1
        if self.calls > self._block_after_calls:
            self.cleanup_entered.set()
        if self._release is not None and self.calls > self._block_after_calls:
            if self._suppress_cancel:
                try:
                    await asyncio.Future()
                except asyncio.CancelledError:
                    await self._release.wait()
            else:
                await self._release.wait()
        self._events.append("startup_safety")
        if self._receipts:
            return self._receipts.pop(0)
        return _clean_safety_receipt()


class RecordingReadiness:
    def __init__(self, events: list[str]) -> None:
        self._events = events
        self.codes: tuple[str, ...] = ()
        self.restart_required = False

    @property
    def ready(self) -> bool:
        return not self.codes and not self.restart_required

    def latch_disconnect_degraded(
        self,
        codes: tuple[str, ...],
        *,
        restart_required: bool = False,
    ) -> None:
        self.restart_required = self.restart_required or restart_required
        self.codes = tuple(dict.fromkeys((*self.codes, *codes)))
        self._events.append(f"readiness:{codes[-1]}")


class RecordingWssClient:
    def __init__(
        self,
        events: list[str],
        *,
        on_run: Callable[[], object] | None = None,
        release: asyncio.Event | None = None,
    ) -> None:
        self._events = events
        self._on_run = on_run
        self._release = release
        self.entered = asyncio.Event()

    async def run(self, stop: asyncio.Event) -> None:
        self._events.append("socket")
        self.entered.set()
        if self._on_run is not None:
            self._on_run()
        if self._release is not None:
            await self._release.wait()
        await stop.wait()


def _failure_prefix(name: str) -> str:
    return {
        "stop_playback": "playback",
        "clear_buffers": "buffers",
        "enter_error_safe": "error_safe",
        "restore_idle": "idle_restore",
    }.get(name, name)


def _clean_safety_receipt() -> SafetyReceipt:
    return SafetyReceipt(
        turn_id=None,
        playback_stopped=True,
        motion_stopped=True,
        buffers_cleared=True,
    )
