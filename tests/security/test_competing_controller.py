from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest
from tuntun_edge.safety.controller_guard import ControllerGuard


class FakeControllerSource:
    def __init__(self, case: CompetingControllerCase) -> None:
        self.case = case

    async def active_controllers(self) -> set[str]:
        self.case.attempted.append("controller_inventory")
        self.case.controller_inventory_entered.set()
        if self.case.block_inventory:
            await asyncio.Future()
        if self.case.failure == "controller_inventory_suppresses_cancel":
            await self.case.suppress_cancellation("controller_inventory")
        if self.case.failure == "controller_inventory_raise":
            raise RuntimeError("controller inventory failed")
        if self.case.failure == "controller_inventory_hang":
            await asyncio.Future()
        return self.case.controller_inventory_value()


class FakeEdgeSafety:
    def __init__(self, case: CompetingControllerCase) -> None:
        self.case = case
        self.calls: list[str] = []

    async def close_media(self) -> None:
        await self.case.safety_operation("close_media")

    async def stop_playback(self) -> None:
        await self.case.safety_operation("stop_playback")

    async def stop_motion(self) -> None:
        await self.case.safety_operation("stop_motion")

    async def enter_error_safe(self, reason: str) -> None:
        assert reason == "competing_controller"
        await self.case.safety_operation("error_safe")


class _TaskFactorySaboteur:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, case: CompetingControllerCase) -> None:
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


@dataclass
class CompetingControllerCase:
    failure: str | None = None
    operation_timeout: float = 0.05
    unmanaged: bool = True
    controller_inventory: str | None = None
    block_at: str | None = None
    block_inventory: bool = False
    task_factory_fail_once_at: str | None = None
    task_factory_unavailable_at: str | None = None

    def __post_init__(self) -> None:
        self.attempted: list[str] = []
        self.blocked_operation_entered = asyncio.Event()
        self.release_blocked_operation = asyncio.Event()
        self.suppressed_cancel_entered = asyncio.Event()
        self.release_suppressed_cancel = asyncio.Event()
        self.controller_inventory_entered = asyncio.Event()
        self.source = FakeControllerSource(self)
        self.safety = FakeEdgeSafety(self)
        self.guard = ControllerGuard(
            source=self.source,
            safety=self.safety,
            expected="tuntun-edge",
            operation_timeout=self.operation_timeout,
        )

    def install_task_factory_sabotage(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _TaskFactorySaboteur(monkeypatch, self)

    def controller_inventory_value(self) -> set[str]:
        if self.controller_inventory == "empty":
            return set()
        if self.controller_inventory == "non_set":
            return ["tuntun-edge"]  # type: ignore[return-value]
        if self.controller_inventory == "too_many":
            return {f"controller-{index}" for index in range(33)}
        if self.controller_inventory == "control_character":
            return {"tuntun-edge", "bad\ncontroller"}
        if self.unmanaged:
            return {"tuntun-edge", "unknown-sdk-client"}
        return {"tuntun-edge"}

    async def safety_operation(self, name: str) -> None:
        self.attempted.append(name)
        self.safety.calls.append(name)
        if self.block_at == name:
            self.blocked_operation_entered.set()
            await self.release_blocked_operation.wait()
            return
        failure_name = _failure_prefix(name)
        if self.failure == f"{failure_name}_raise":
            raise RuntimeError(f"{name} failed")
        if self.failure == f"{failure_name}_hang":
            await asyncio.Future()
        if self.failure == f"{failure_name}_suppresses_cancel":
            await self.suppress_cancellation(name)

    async def suppress_cancellation(self, name: str) -> None:
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            self.attempted.append(f"{name}:suppressed_cancel")
            self.suppressed_cancel_entered.set()
            await self.release_suppressed_cancel.wait()

    @property
    def no_unobserved_tasks(self) -> bool:
        live = [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and not task.done()
        ]
        return not live


@pytest.fixture()
def competing_controller_case(
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[..., CompetingControllerCase]:
    def build(**kwargs: Any) -> CompetingControllerCase:
        case = CompetingControllerCase(**kwargs)
        case.install_task_factory_sabotage(monkeypatch)
        return case

    return build


@pytest.mark.asyncio
async def test_unmanaged_controller_closes_media_and_stops_motion() -> None:
    case = CompetingControllerCase(unmanaged=True)

    assert await case.guard.poll() is False

    assert set(case.safety.calls) == {"close_media", "stop_playback", "stop_motion", "error_safe"}
    assert case.guard.error_safe_latched is True
    assert case.guard.last_receipt.playback_stopped
    assert case.guard.last_receipt.motion_stopped
    assert case.guard.last_receipt.buffers_cleared


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    (
        "close_media_raise",
        "close_media_hang",
        "playback_raise",
        "playback_hang",
        "motion_raise",
        "motion_hang",
        "error_safe_raise",
        "error_safe_hang",
    ),
)
async def test_each_controller_safety_failure_is_bounded_truthful_and_latched(
    competing_controller_case: Callable[..., CompetingControllerCase],
    failure: str,
) -> None:
    case = competing_controller_case(failure=failure, operation_timeout=0.01)

    assert await asyncio.wait_for(case.guard.poll(), timeout=0.1) is False

    assert set(case.attempted) >= {"close_media", "stop_playback", "stop_motion", "error_safe"}
    assert case.guard.error_safe_latched is True
    assert case.guard.last_failure_codes
    assert not all(
        (
            case.guard.last_receipt.playback_stopped,
            case.guard.last_receipt.motion_stopped,
            case.guard.last_receipt.buffers_cleared,
        )
    )
    assert case.no_unobserved_tasks


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ("controller_inventory_raise", "controller_inventory_hang"))
async def test_controller_inventory_failure_is_bounded_and_runs_full_safety(
    competing_controller_case: Callable[..., CompetingControllerCase],
    failure: str,
) -> None:
    case = competing_controller_case(failure=failure, operation_timeout=0.01)

    assert await asyncio.wait_for(case.guard.poll(), timeout=0.1) is False

    assert set(case.attempted) >= {
        "controller_inventory",
        "close_media",
        "stop_playback",
        "stop_motion",
        "error_safe",
    }
    assert case.guard.error_safe_latched is True
    assert case.no_unobserved_tasks


@pytest.mark.asyncio
async def test_controller_inventory_suppressed_cancellation_cannot_block_safety(
    competing_controller_case: Callable[..., CompetingControllerCase],
) -> None:
    case = competing_controller_case(
        failure="controller_inventory_suppresses_cancel",
        operation_timeout=0.01,
    )
    caller = asyncio.create_task(case.guard.poll())

    try:
        await asyncio.wait_for(case.suppressed_cancel_entered.wait(), timeout=0.2)
        done, _pending = await asyncio.wait({caller}, timeout=0.2)
        assert caller in done
        assert caller.result() is False
        assert set(case.attempted) >= {
            "controller_inventory",
            "close_media",
            "stop_playback",
            "stop_motion",
            "error_safe",
        }
        assert case.guard.error_safe_latched is True
        assert case.guard.process_restart_required is True
    finally:
        case.release_suppressed_cancel.set()
        if not caller.done():
            caller.cancel()
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(caller, timeout=1.0)
        await asyncio.sleep(0)
    assert case.no_unobserved_tasks


@pytest.mark.asyncio
async def test_repeated_cancellation_during_suppressed_inventory_still_runs_safety(
    competing_controller_case: Callable[..., CompetingControllerCase],
) -> None:
    case = competing_controller_case(
        failure="controller_inventory_suppresses_cancel",
        operation_timeout=0.05,
    )
    caller = asyncio.create_task(case.guard.poll())
    await case.controller_inventory_entered.wait()

    try:
        caller.cancel()
        await asyncio.wait_for(case.suppressed_cancel_entered.wait(), timeout=0.2)
        caller.cancel()
        caller.cancel()
        await asyncio.sleep(0)

        assert caller.done() is False
        while "error_safe" not in case.attempted:
            await asyncio.sleep(0.01)

        with pytest.raises(asyncio.CancelledError):
            await caller
        assert set(case.attempted) >= {
            "controller_inventory",
            "close_media",
            "stop_playback",
            "stop_motion",
            "error_safe",
        }
        assert case.guard.error_safe_latched is True
        assert case.guard.process_restart_required is True
        assert case.guard.last_caller_cancellations >= 3
    finally:
        case.release_suppressed_cancel.set()
        if not caller.done():
            caller.cancel()
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(caller, timeout=1.0)
        await asyncio.sleep(0)
    assert case.no_unobserved_tasks


@pytest.mark.asyncio
@pytest.mark.parametrize("inventory", ("empty", "non_set", "too_many", "control_character"))
async def test_unverified_controller_inventory_never_bypasses_safety(
    competing_controller_case: Callable[..., CompetingControllerCase],
    inventory: str,
) -> None:
    case = competing_controller_case(controller_inventory=inventory)

    assert await case.guard.poll() is False

    assert set(case.attempted) >= {
        "controller_inventory",
        "close_media",
        "stop_playback",
        "stop_motion",
        "error_safe",
    }
    assert case.guard.error_safe_latched is True
    assert case.guard.last_failure_codes[0] == "controller_inventory:invalid"
    assert case.no_unobserved_tasks


@pytest.mark.asyncio
async def test_controller_safety_suppressed_cancellation_is_quarantined(
    competing_controller_case: Callable[..., CompetingControllerCase],
) -> None:
    case = competing_controller_case(
        failure="playback_suppresses_cancel",
        operation_timeout=0.01,
    )
    caller = asyncio.create_task(case.guard.poll())

    try:
        await asyncio.wait_for(case.suppressed_cancel_entered.wait(), timeout=0.2)
        done, _pending = await asyncio.wait({caller}, timeout=0.2)
        assert caller in done
        assert caller.result() is False
        assert "stop_playback:timeout" in case.guard.last_failure_codes
        assert case.guard.error_safe_latched is True
        assert case.guard.process_restart_required is True
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
    "blocked_phase", ("close_media", "stop_playback", "stop_motion", "error_safe")
)
async def test_repeated_caller_cancellation_waits_for_safety_then_remains_cancelled(
    competing_controller_case: Callable[..., CompetingControllerCase],
    blocked_phase: str,
) -> None:
    case = competing_controller_case(block_at=blocked_phase, operation_timeout=0.05)
    caller = asyncio.create_task(case.guard.poll())
    await case.blocked_operation_entered.wait()

    for _ in range(3):
        caller.cancel()
        await asyncio.sleep(0)

    assert caller.done() is False
    assert set(case.attempted) >= {"close_media", "stop_playback", "stop_motion", "error_safe"}
    case.release_blocked_operation.set()
    with pytest.raises(asyncio.CancelledError):
        await caller
    assert caller.cancelled()
    assert case.guard.last_caller_cancellations == 3
    assert case.guard.error_safe_latched is True
    assert case.no_unobserved_tasks


@pytest.mark.asyncio
async def test_cancellation_during_controller_inventory_is_preserved_after_safety(
    competing_controller_case: Callable[..., CompetingControllerCase],
) -> None:
    case = competing_controller_case(
        block_inventory=True,
        block_at="error_safe",
        operation_timeout=0.05,
    )
    caller = asyncio.create_task(case.guard.poll())
    await case.controller_inventory_entered.wait()
    caller.cancel()
    await case.blocked_operation_entered.wait()
    caller.cancel()
    caller.cancel()

    assert caller.done() is False
    assert set(case.attempted) >= {"close_media", "stop_playback", "stop_motion", "error_safe"}
    case.release_blocked_operation.set()
    with pytest.raises(asyncio.CancelledError):
        await caller
    assert caller.cancelled()
    assert case.guard.last_caller_cancellations == 3
    assert case.guard.error_safe_latched is True
    assert case.no_unobserved_tasks


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "factory_point",
    (
        "controller-inventory",
        "competing-controller-safety",
        "close_media",
        "stop_playback",
        "stop_motion",
        "error_safe",
    ),
)
async def test_one_task_factory_failure_cannot_skip_controller_safety(
    competing_controller_case: Callable[..., CompetingControllerCase],
    factory_point: str,
) -> None:
    case = competing_controller_case(unmanaged=True, task_factory_fail_once_at=factory_point)

    assert await case.guard.poll() is False

    assert set(case.attempted) >= {
        "controller_inventory",
        "close_media",
        "stop_playback",
        "stop_motion",
        "error_safe",
    }
    assert factory_point in case.guard.task_factory_failure_points
    assert case.guard.error_safe_latched is True
    assert case.no_unobserved_tasks


@pytest.mark.asyncio
async def test_unavailable_controller_safety_owner_latches_restart_without_releasing(
    competing_controller_case: Callable[..., CompetingControllerCase],
) -> None:
    case = competing_controller_case(
        unmanaged=True,
        task_factory_unavailable_at="competing-controller-safety",
    )

    assert await case.guard.poll() is False

    assert case.guard.error_safe_latched is True
    assert case.guard.process_restart_required is True
    assert not all(
        (
            case.guard.last_receipt.playback_stopped,
            case.guard.last_receipt.motion_stopped,
            case.guard.last_receipt.buffers_cleared,
        )
    )
    assert case.no_unobserved_tasks


@pytest.mark.asyncio
async def test_expected_controller_inventory_returns_ready_without_safety(
    competing_controller_case: Callable[..., CompetingControllerCase],
) -> None:
    case = competing_controller_case(unmanaged=False)

    assert await case.guard.poll() is True

    assert case.attempted == ["controller_inventory"]
    assert case.guard.error_safe_latched is False


@pytest.mark.asyncio
async def test_process_restart_required_is_monotonic_and_poll_cannot_self_heal(
    competing_controller_case: Callable[..., CompetingControllerCase],
) -> None:
    case = competing_controller_case(
        unmanaged=True,
        task_factory_unavailable_at="competing-controller-safety",
    )
    assert await case.guard.poll() is False
    assert case.guard.process_restart_required is True

    case.unmanaged = False
    case.attempted.clear()

    assert await case.guard.poll() is False
    assert case.guard.error_safe_latched is True
    assert "controller_process_restart_required" in case.guard.last_failure_codes
    assert "controller_inventory" not in case.attempted


def _failure_prefix(name: str) -> str:
    return {
        "stop_playback": "playback",
        "stop_motion": "motion",
    }.get(name, name)
