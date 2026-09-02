from __future__ import annotations

# The import split below deliberately bootstraps the uninstalled root namespace.
# ruff: noqa: E402
import asyncio
import sys
import traceback as traceback_module
from collections.abc import AsyncIterator
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

# The root project is not an installed package; preserve package-import coverage
# without changing workspace metadata or adding a suite-wide import side effect.
ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest
import tuntun_core.adapters.reachy.completed_audio as completed_audio_module
from tuntun_contracts.ports import TurnInput
from tuntun_core.adapters.reachy.completed_audio import (
    BoundedCompletedTurnAudio,
    CompletedAudioStream,
    PersistentTurnAudioClaims,
)

pytest_plugins = ("tests.fixtures.provider_routes",)


class _CompletedAudioSource:
    def __init__(self, stream: CompletedAudioStream) -> None:
        self.stream = stream
        self.expected_bytes = b"".join(
            chunk for chunk in getattr(stream.chunks, "_chunks", ()) if type(chunk) is bytes
        )
        self.opened: list[TurnInput] = []
        self.closed: list[CompletedAudioStream] = []
        self.open_streams = 0

    async def open_completed(self, turn: TurnInput) -> CompletedAudioStream:
        self.opened.append(turn)
        self.open_streams += 1
        return self.stream

    async def close_completed(self, stream: CompletedAudioStream) -> None:
        self.closed.append(stream)
        self.open_streams -= 1


class _Chunks:
    def __init__(self, chunks: tuple[object, ...]) -> None:
        self._chunks = chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk  # type: ignore[misc]


class _BlockingChunks:
    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.cancelled = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        yield b"unreachable"


class _NoopClaims:
    async def claim_once(self, turn: TurnInput) -> None:
        del turn


class _FailingCloseSource(_CompletedAudioSource):
    async def close_completed(self, stream: CompletedAudioStream) -> None:
        self.closed.append(stream)
        self.open_streams -= 1
        raise RuntimeError("private-close-sentinel")


class _GatedCloseSource(_CompletedAudioSource):
    def __init__(self, stream: CompletedAudioStream) -> None:
        super().__init__(stream)
        self.close_entered = asyncio.Event()
        self.close_release = asyncio.Event()
        self.close_finished = False
        self.close_cancel_count = 0

    async def close_completed(self, stream: CompletedAudioStream) -> None:
        self.closed.append(stream)
        self.open_streams -= 1
        self.close_entered.set()
        while not self.close_release.is_set():
            try:
                await self.close_release.wait()
            except asyncio.CancelledError:
                self.close_cancel_count += 1
        self.close_finished = True


class _FailingGatedCloseSource(_GatedCloseSource):
    async def close_completed(self, stream: CompletedAudioStream) -> None:
        await super().close_completed(stream)
        raise RuntimeError("private-close-sentinel")


def _turn() -> TurnInput:
    return TurnInput(turn_id=uuid4(), household_id=uuid4(), device_id=uuid4())


def _stream(turn: TurnInput, chunks: object, *, duration_ms: int = 40) -> CompletedAudioStream:
    return CompletedAudioStream(
        turn_id=turn.turn_id,
        household_id=turn.household_id,
        device_id=turn.device_id,
        duration_ms=duration_ms,
        chunks=chunks,  # type: ignore[arg-type]
    )


def _claims(route_uow_factory, route_clock) -> PersistentTurnAudioClaims:
    return PersistentTurnAudioClaims(route_uow_factory, route_clock)


def _track_completed_audio_buffers(monkeypatch: pytest.MonkeyPatch) -> list[bytearray]:
    buffers: list[bytearray] = []
    real_bytearray = bytearray

    class TrackingBuffer(bytearray):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, **kwargs)
            buffers.append(self)

    monkeypatch.setattr(completed_audio_module, "bytearray", TrackingBuffer, raising=False)
    assert completed_audio_module.bytearray is TrackingBuffer
    assert real_bytearray is not TrackingBuffer
    return buffers


def _assert_exception_has_no_private_chain(
    error: BaseException,
    *,
    sentinels: tuple[str, ...],
    expected_note_fragments: tuple[str, ...] = (),
) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    assert error.__suppress_context__ is True
    notes = tuple(getattr(error, "__notes__", ()))
    assert all(fragment in " ".join(notes) for fragment in expected_note_fragments)
    formatted = "".join(traceback_module.format_exception(error))
    inspected = (
        str(error),
        repr(error.__cause__),
        repr(error.__context__),
        repr(notes),
        formatted,
    )
    for sentinel in sentinels:
        assert all(sentinel not in candidate for candidate in inspected)


def _assert_completed_audio_frames_do_not_retain(
    error: BaseException,
    *,
    sentinels: tuple[str, ...],
) -> None:
    frames = []
    traceback = error.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        if frame.f_code.co_filename.endswith("completed_audio.py"):
            frames.append(frame)
        traceback = traceback.tb_next

    assert frames
    for frame in frames:
        for name, value in frame.f_locals.items():
            rendered = repr(value)
            assert all(sentinel not in rendered for sentinel in sentinels), name


@pytest.mark.asyncio
async def test_completed_audio_is_exact_bounded_and_consume_once(
    route_uow_factory,
    route_clock,
) -> None:
    turn = _turn()
    source = _CompletedAudioSource(_stream(turn, _Chunks((b"RIFF", b"audio"))))
    adapter = BoundedCompletedTurnAudio(source, _claims(route_uow_factory, route_clock))

    assert await adapter.consume_once(turn) == b"RIFFaudio"
    with pytest.raises(PermissionError, match="completed_turn_audio_already_consumed"):
        await adapter.consume_once(turn)

    assert source.opened == [turn, turn]
    assert source.closed == [source.stream, source.stream]
    assert source.open_streams == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stream_update",
    (
        {"device_id": uuid4()},
        {"duration_ms": 0},
        {"duration_ms": 90_001},
    ),
)
async def test_binding_or_duration_mismatch_denies_and_closes_without_claiming(
    stream_update: dict[str, object],
    route_uow_factory,
    route_clock,
) -> None:
    turn = _turn()
    valid = _stream(turn, _Chunks((b"RIFF",)))
    source = _CompletedAudioSource(replace(valid, **stream_update))
    adapter = BoundedCompletedTurnAudio(source, _claims(route_uow_factory, route_clock))

    with pytest.raises(PermissionError, match="completed_turn_audio_binding_or_duration_invalid"):
        await adapter.consume_once(turn)
    assert source.closed == [source.stream]

    source.stream = valid
    assert await adapter.consume_once(turn) == b"RIFF"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("chunks", "message"),
    (
        ((_Chunks((b"",)), "completed audio chunk outside bound")),
        ((_Chunks(("text",)), "completed audio chunk outside bound")),
        ((_Chunks((b"x" * 65_537,)), "completed audio chunk outside bound")),
        (
            (_Chunks(((b"x" * 65_536,) * 128) + (b"y",))),
            "completed audio turn outside bound",
        ),
    ),
)
async def test_chunk_and_total_bounds_are_checked_before_content_is_returned(
    chunks: object,
    message: str,
    route_uow_factory,
    route_clock,
) -> None:
    turn = _turn()
    source = _CompletedAudioSource(_stream(turn, chunks))
    adapter = BoundedCompletedTurnAudio(source, _claims(route_uow_factory, route_clock))

    with pytest.raises(ValueError, match=message):
        await adapter.consume_once(turn)
    assert source.open_streams == 0
    with pytest.raises(PermissionError, match="completed_turn_audio_already_consumed"):
        await adapter.consume_once(turn)


@pytest.mark.asyncio
async def test_cancellation_during_chunk_read_closes_stream_and_consumes_claim(
    route_uow_factory,
    route_clock,
) -> None:
    turn = _turn()
    chunks = _BlockingChunks()
    source = _CompletedAudioSource(_stream(turn, chunks))
    adapter = BoundedCompletedTurnAudio(source, _claims(route_uow_factory, route_clock))
    task = asyncio.create_task(adapter.consume_once(turn))
    await asyncio.wait_for(chunks.entered.wait(), timeout=15)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert chunks.cancelled is True
    assert source.closed == [source.stream]
    assert source.open_streams == 0
    with pytest.raises(PermissionError, match="completed_turn_audio_already_consumed"):
        await adapter.consume_once(turn)


@pytest.mark.asyncio
async def test_primary_cancellation_message_during_chunk_read_is_sanitized() -> None:
    private_cancel = "private-cancel-sentinel"
    turn = _turn()
    chunks = _BlockingChunks()
    source = _CompletedAudioSource(_stream(turn, chunks))
    adapter = BoundedCompletedTurnAudio(source, _NoopClaims())  # type: ignore[arg-type]
    task = asyncio.create_task(adapter.consume_once(turn))
    await asyncio.wait_for(chunks.entered.wait(), timeout=15)

    task.cancel(private_cancel)
    with pytest.raises(asyncio.CancelledError) as captured:
        await task

    _assert_exception_has_no_private_chain(
        captured.value,
        sentinels=(private_cancel,),
    )
    _assert_completed_audio_frames_do_not_retain(
        captured.value,
        sentinels=(private_cancel,),
    )
    assert chunks.cancelled is True
    assert source.closed == [source.stream]
    assert source.open_streams == 0


@pytest.mark.asyncio
async def test_close_failure_still_wipes_completed_audio_buffer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_audio = "private-audio-sentinel"
    private_close = "private-close-sentinel"
    buffers = _track_completed_audio_buffers(monkeypatch)
    turn = _turn()
    source = _FailingCloseSource(_stream(turn, _Chunks((private_audio.encode("ascii"),))))
    adapter = BoundedCompletedTurnAudio(source, _NoopClaims())  # type: ignore[arg-type]

    with pytest.raises(RuntimeError) as captured:
        await adapter.consume_once(turn)

    assert str(captured.value) == "completed_turn_audio_close_failed"
    _assert_exception_has_no_private_chain(
        captured.value,
        sentinels=(private_audio, private_close),
    )
    _assert_completed_audio_frames_do_not_retain(
        captured.value,
        sentinels=(private_audio, private_close),
    )
    assert source.closed == [source.stream]
    assert source.open_streams == 0
    assert len(buffers) == 1
    assert bytes(buffers[0]) == b""


@pytest.mark.asyncio
async def test_primary_error_precedence_hides_close_failure_details() -> None:
    private_audio = "private-audio-sentinel"
    private_close = "private-close-sentinel"
    turn = _turn()
    source = _FailingCloseSource(
        _stream(turn, _Chunks((private_audio.encode("ascii"), b"")))
    )
    adapter = BoundedCompletedTurnAudio(source, _NoopClaims())  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="completed audio chunk outside bound") as captured:
        await adapter.consume_once(turn)

    assert str(captured.value) == "completed audio chunk outside bound"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert "RuntimeError" in " ".join(getattr(captured.value, "__notes__", ()))
    formatted = "".join(traceback_module.format_exception(captured.value))
    assert private_close not in formatted
    _assert_completed_audio_frames_do_not_retain(
        captured.value,
        sentinels=(private_audio, private_close),
    )


@pytest.mark.asyncio
async def test_close_failure_traceback_does_not_retain_last_immutable_chunk() -> None:
    private_chunk = b"private-immutable-chunk-sentinel"
    turn = _turn()
    source = _FailingCloseSource(_stream(turn, _Chunks((private_chunk,))))
    adapter = BoundedCompletedTurnAudio(source, _NoopClaims())  # type: ignore[arg-type]

    with pytest.raises(RuntimeError) as captured:
        await adapter.consume_once(turn)

    production_frames = []
    traceback = captured.value.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        if frame.f_code.co_filename.endswith("completed_audio.py"):
            production_frames.append(frame)
        traceback = traceback.tb_next

    assert production_frames
    assert all(frame.f_locals.get("chunk") is not private_chunk for frame in production_frames)


@pytest.mark.asyncio
async def test_close_is_shielded_through_repeated_caller_cancellation_and_wipes_buffer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    buffers = _track_completed_audio_buffers(monkeypatch)
    turn = _turn()
    source = _GatedCloseSource(_stream(turn, _Chunks((b"private-audio-sentinel",))))
    adapter = BoundedCompletedTurnAudio(source, _NoopClaims())  # type: ignore[arg-type]
    task = asyncio.create_task(adapter.consume_once(turn))
    await asyncio.wait_for(source.close_entered.wait(), timeout=1)

    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0)
    assert task.done() is False

    source.close_release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=1)

    assert source.closed == [source.stream]
    assert source.close_cancel_count == 0
    assert source.close_finished is True
    assert source.open_streams == 0
    assert len(buffers) == 1
    assert bytes(buffers[0]) == b""


@pytest.mark.asyncio
async def test_cancellation_message_is_sanitized_after_shielded_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_audio = "private-audio-sentinel"
    private_cancel = "private-cancel-sentinel"
    buffers = _track_completed_audio_buffers(monkeypatch)
    turn = _turn()
    source = _GatedCloseSource(_stream(turn, _Chunks((private_audio.encode("ascii"),))))
    adapter = BoundedCompletedTurnAudio(source, _NoopClaims())  # type: ignore[arg-type]
    task = asyncio.create_task(adapter.consume_once(turn))
    await asyncio.wait_for(source.close_entered.wait(), timeout=1)

    task.cancel(private_cancel)
    await asyncio.sleep(0)
    assert task.done() is False

    source.close_release.set()
    with pytest.raises(asyncio.CancelledError) as captured:
        await asyncio.wait_for(task, timeout=1)

    _assert_exception_has_no_private_chain(
        captured.value,
        sentinels=(private_audio, private_cancel),
    )
    _assert_completed_audio_frames_do_not_retain(
        captured.value,
        sentinels=(private_audio, private_cancel),
    )
    assert source.closed == [source.stream]
    assert source.close_finished is True
    assert source.open_streams == 0
    assert len(buffers) == 1
    assert bytes(buffers[0]) == b""


@pytest.mark.asyncio
async def test_cancellation_message_and_close_failure_are_both_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_audio = "private-audio-sentinel"
    private_cancel = "private-cancel-sentinel"
    private_close = "private-close-sentinel"
    buffers = _track_completed_audio_buffers(monkeypatch)
    turn = _turn()
    source = _FailingGatedCloseSource(
        _stream(turn, _Chunks((private_audio.encode("ascii"),)))
    )
    adapter = BoundedCompletedTurnAudio(source, _NoopClaims())  # type: ignore[arg-type]
    task = asyncio.create_task(adapter.consume_once(turn))
    await asyncio.wait_for(source.close_entered.wait(), timeout=1)

    task.cancel(private_cancel)
    await asyncio.sleep(0)
    assert task.done() is False

    source.close_release.set()
    with pytest.raises(asyncio.CancelledError) as captured:
        await asyncio.wait_for(task, timeout=1)

    _assert_exception_has_no_private_chain(
        captured.value,
        sentinels=(private_audio, private_cancel, private_close),
        expected_note_fragments=("RuntimeError",),
    )
    _assert_completed_audio_frames_do_not_retain(
        captured.value,
        sentinels=(private_audio, private_cancel, private_close),
    )
    assert source.closed == [source.stream]
    assert source.close_finished is True
    assert source.open_streams == 0
    assert len(buffers) == 1
    assert bytes(buffers[0]) == b""
