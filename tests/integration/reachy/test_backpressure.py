from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
import tuntun_core.adapters.reachy.playback as reachy_playback_module
from tuntun_contracts.reachy import ReachyCommand, ReachyReceipt, ReachyState
from tuntun_contracts.reachy_media import (
    MAX_CAMERA_PAYLOAD,
    MAX_HEADER,
    MEDIA_MAGIC,
    MEDIA_TYPE_CAMERA,
    PREFIX,
)
from tuntun_contracts.reachy_wire import MAX_CONTROL_FRAME_JSON_BYTES
from tuntun_core.adapters.reachy.playback import ReachyPlaybackAdapter
from tuntun_core.adapters.reachy.session import PriorityControlQueues

NOW = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)


class Clock:
    def now(self) -> datetime:
        return NOW


@pytest.mark.asyncio
async def test_priority_queues_keep_stop_and_safety_ahead_of_media_pressure() -> None:
    queues = PriorityControlQueues(safety_max=2, control_max=2, media_max=3)

    for index in range(50):
        assert queues.put_media_nowait(f"media-{index}".encode()) is True
    assert queues.depths == {"safety": 0, "control": 0, "media": 3}

    queues.put_control_nowait(b"state-update")
    queues.put_safety_nowait(b"stop")

    assert await queues.get() == ("safety", b"stop")
    assert await queues.get() == ("control", b"state-update")
    assert [await queues.get() for _ in range(3)] == [
        ("media", b"media-47"),
        ("media", b"media-48"),
        ("media", b"media-49"),
    ]
    assert queues.depths == {"safety": 0, "control": 0, "media": 0}


def test_priority_queues_reject_unbounded_or_malformed_frames() -> None:
    queues = PriorityControlQueues(safety_max=1, control_max=1, media_max=1, max_frame_bytes=4)

    for operation in (
        lambda: PriorityControlQueues(safety_max=0, control_max=1, media_max=1),
        lambda: PriorityControlQueues(safety_max=True, control_max=1, media_max=1),
        lambda: queues.put_safety_nowait(b"12345"),
        lambda: queues.put_control_nowait(bytearray(b"x")),
        lambda: queues.put_media_nowait(b"12345"),
    ):
        with pytest.raises((TypeError, ValueError)):
            operation()


@pytest.mark.asyncio
async def test_priority_queues_media_lane_accepts_full_contract_camera_frame() -> None:
    queues = PriorityControlQueues(safety_max=1, control_max=1, media_max=1)
    frame = (
        PREFIX.pack(MEDIA_MAGIC, MEDIA_TYPE_CAMERA, 0, MAX_HEADER, MAX_CAMERA_PAYLOAD)
        + (b"h" * MAX_HEADER)
        + (b"c" * MAX_CAMERA_PAYLOAD)
    )
    assert len(frame) == 1_052_684
    assert len(frame) > MAX_CONTROL_FRAME_JSON_BYTES

    assert queues.put_media_nowait(frame) is True
    assert await queues.get() == ("media", frame)

    with pytest.raises(ValueError, match="queued frame outside byte bound"):
        queues.put_control_nowait(b"x" * (MAX_CONTROL_FRAME_JSON_BYTES + 1))


@dataclass(slots=True)
class RegisteredStream:
    stream_id: UUID
    turn_id: UUID
    audio: AsyncIterator[bytes]
    max_bytes: int


class TrackingAsyncAudio:
    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self._chunks = list(chunks)
        self.reads = 0

    def __aiter__(self) -> TrackingAsyncAudio:
        return self

    async def __anext__(self) -> bytes:
        self.reads += 1
        if not self._chunks:
            raise StopAsyncIteration
        return self._chunks.pop(0)


class Converter:
    def __init__(self) -> None:
        self.converted = TrackingAsyncAudio((b"pcm",))
        self.calls: list[tuple[AsyncIterator[bytes], object, object]] = []

    def convert(
        self,
        audio: AsyncIterator[bytes],
        source: object,
        target: object,
    ) -> AsyncIterator[bytes]:
        self.calls.append((audio, source, target))
        return self.converted


class MediaRegistry:
    def __init__(self) -> None:
        self.registered: list[RegisteredStream] = []
        self.closed: list[UUID] = []

    async def register_bounded_playback(
        self,
        stream_id: UUID,
        turn_id: UUID,
        audio: AsyncIterator[bytes],
        *,
        max_bytes: int,
    ) -> None:
        self.registered.append(
            RegisteredStream(
                stream_id=stream_id,
                turn_id=turn_id,
                audio=audio,
                max_bytes=max_bytes,
            )
        )

    async def close(self, stream_id: UUID) -> None:
        self.closed.append(stream_id)


class Reachy:
    def __init__(self, *, accepted: bool = True, release: asyncio.Event | None = None) -> None:
        self.accepted = accepted
        self.release = release
        self.sent: list[ReachyCommand] = []
        self.send_entered = asyncio.Event()

    async def send(self, command: ReachyCommand) -> ReachyReceipt:
        self.sent.append(command)
        self.send_entered.set()
        if self.release is not None:
            await self.release.wait()
        return ReachyReceipt(
            command_id=command.command_id,
            accepted=self.accepted,
            reason_code="accepted" if self.accepted else "edge_rejected",
        )


async def _audio() -> AsyncIterator[bytes]:
    yield b"source"


@pytest.mark.asyncio
async def test_playback_registers_bounded_stream_without_prefetch_and_closes_on_rejection() -> None:
    media = MediaRegistry()
    converter = Converter()
    reachy = Reachy(accepted=False)
    turn_id = uuid4()
    adapter = ReachyPlaybackAdapter(
        reachy,
        media,
        converter,
        Clock(),
        source_format="source-pcm",
        reachy_format="reachy-pcm",
    )

    with pytest.raises(RuntimeError, match="reachy_playback_rejected"):
        await adapter.play(turn_id, _audio())

    assert len(media.registered) == 1
    registered = media.registered[0]
    assert registered.turn_id == turn_id
    assert registered.audio is converter.converted
    assert registered.max_bytes == 8_388_608
    assert converter.converted.reads == 0
    assert media.closed == [registered.stream_id]
    assert reachy.sent == [
        ReachyCommand(
            command_id=reachy.sent[0].command_id,
            turn_id=turn_id,
            kind="playback",
            state=None,
            media_stream_id=registered.stream_id,
            gesture_id=None,
            expires_at=NOW + timedelta(seconds=2),
        )
    ]


@pytest.mark.asyncio
async def test_playback_closes_registered_stream_on_cancellation_or_fault() -> None:
    release = asyncio.Event()
    media = MediaRegistry()
    converter = Converter()
    reachy = Reachy(release=release)
    adapter = ReachyPlaybackAdapter(
        reachy,
        media,
        converter,
        Clock(),
        source_format=object(),
        reachy_format=object(),
    )
    task = asyncio.create_task(adapter.play(uuid4(), _audio()))
    await reachy.send_entered.wait()

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert media.closed == [media.registered[0].stream_id]

    class FaultyReachy(Reachy):
        async def send(self, command: ReachyCommand) -> ReachyReceipt:
            await super().send(command)
            raise RuntimeError("transport closed")

    media = MediaRegistry()
    adapter = ReachyPlaybackAdapter(
        FaultyReachy(),
        media,
        Converter(),
        Clock(),
        source_format=object(),
        reachy_format=object(),
    )
    with pytest.raises(RuntimeError, match="transport closed"):
        await adapter.play(uuid4(), _audio())
    assert media.closed == [media.registered[0].stream_id]


class ReleasableCloseMedia(MediaRegistry):
    def __init__(self) -> None:
        super().__init__()
        self.close_entered = asyncio.Event()
        self.close_finished = asyncio.Event()
        self.release_close = asyncio.Event()

    async def close(self, stream_id: UUID) -> None:
        self.closed.append(stream_id)
        self.close_entered.set()
        await self.release_close.wait()
        self.close_finished.set()


@pytest.mark.asyncio
async def test_playback_close_is_bounded_and_degraded_when_rejection_close_hangs() -> None:
    media = ReleasableCloseMedia()
    adapter = ReachyPlaybackAdapter(
        Reachy(accepted=False),
        media,
        Converter(),
        Clock(),
        source_format=object(),
        reachy_format=object(),
        close_timeout=0.01,
    )

    with pytest.raises(RuntimeError, match="reachy_playback_rejected"):
        await asyncio.wait_for(adapter.play(uuid4(), _audio()), timeout=0.5)

    assert media.close_entered.is_set()
    assert media.close_finished.is_set() is False
    assert adapter.close_degradation_codes == ("media_close:timeout",)


@pytest.mark.asyncio
async def test_playback_close_defers_repeated_cancellation_until_close_finishes() -> None:
    media = ReleasableCloseMedia()
    reachy = Reachy(release=asyncio.Event())
    adapter = ReachyPlaybackAdapter(
        reachy,
        media,
        Converter(),
        Clock(),
        source_format=object(),
        reachy_format=object(),
        close_timeout=0.5,
    )
    task = asyncio.create_task(adapter.play(uuid4(), _audio()))
    await reachy.send_entered.wait()

    task.cancel()
    await asyncio.wait_for(media.close_entered.wait(), timeout=0.5)
    task.cancel()
    task.cancel()
    media.release_close.set()

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=0.5)
    assert media.close_finished.is_set()
    assert "media_close:cancelled_deferred" in adapter.close_degradation_codes


@pytest.mark.asyncio
async def test_playback_close_uses_fresh_direct_task_when_create_task_factory_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    media = MediaRegistry()
    adapter = ReachyPlaybackAdapter(
        Reachy(accepted=False),
        media,
        Converter(),
        Clock(),
        source_format=object(),
        reachy_format=object(),
    )
    original_create_task = asyncio.create_task
    failed = False

    def fail_once(
        coroutine: Any,
        *,
        name: str | None = None,
        context: object | None = None,
    ) -> asyncio.Task[Any]:
        nonlocal failed
        del context
        if name == "reachy_playback_media_close" and not failed:
            failed = True
            raise RuntimeError("synthetic close task factory failure")
        return original_create_task(cast(Any, coroutine), name=name)

    monkeypatch.setattr(reachy_playback_module.asyncio, "create_task", fail_once)

    with pytest.raises(RuntimeError, match="reachy_playback_rejected"):
        await adapter.play(uuid4(), _audio())

    assert failed is True
    assert media.closed == [media.registered[0].stream_id]
    assert adapter.close_degradation_codes == ("media_close:factory_fallback",)


@pytest.mark.asyncio
async def test_playback_close_preserves_primary_error_when_all_task_factories_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    media = MediaRegistry()
    adapter = ReachyPlaybackAdapter(
        Reachy(accepted=False),
        media,
        Converter(),
        Clock(),
        source_format=object(),
        reachy_format=object(),
    )
    original_direct_task = asyncio.Task

    def create_task_fail(
        coroutine: Any,
        *,
        name: str | None = None,
        context: object | None = None,
    ) -> asyncio.Task[Any]:
        del context
        if name == "reachy_playback_media_close":
            raise RuntimeError("synthetic close task factory failure")
        return original_direct_task(cast(Any, coroutine), name=name)

    def direct_task_fail(
        coroutine: Any,
        *,
        loop: asyncio.AbstractEventLoop | None = None,
        name: str | None = None,
        context: object | None = None,
    ) -> asyncio.Task[Any]:
        del loop, context
        if name == "reachy_playback_media_close":
            raise RuntimeError("synthetic direct close task failure")
        return original_direct_task(cast(Any, coroutine), name=name)

    monkeypatch.setattr(reachy_playback_module.asyncio, "create_task", create_task_fail)
    monkeypatch.setattr(reachy_playback_module.asyncio, "Task", direct_task_fail)

    with pytest.raises(RuntimeError, match="reachy_playback_rejected"):
        await adapter.play(uuid4(), _audio())

    assert media.closed == []
    assert adapter.close_degradation_codes == ("media_close:factory_unavailable",)


@pytest.mark.asyncio
async def test_state_updates_are_bound_and_timeout_limited() -> None:
    class HangingReachy(Reachy):
        async def send(self, command: ReachyCommand) -> ReachyReceipt:
            self.sent.append(command)
            self.send_entered.set()
            await asyncio.sleep(3600)
            raise AssertionError("unreachable")

    reachy = HangingReachy()
    adapter = ReachyPlaybackAdapter(
        reachy,
        MediaRegistry(),
        Converter(),
        Clock(),
        source_format=object(),
        reachy_format=object(),
        command_timeout=0.01,
    )

    with pytest.raises(TimeoutError):
        await adapter.set_state(ReachyState.ERROR_SAFE)
    assert reachy.sent[0].kind == "state"
    assert reachy.sent[0].state == ReachyState.ERROR_SAFE
