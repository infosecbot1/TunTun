from __future__ import annotations

import inspect
import os
import traceback as traceback_module
from contextlib import suppress
from pathlib import Path

import pytest
import tuntun_core.cli.commands.talk as talk_module
from tuntun_core.cli.commands.talk import read_synthetic_wav, run_synthetic_turn
from tuntun_core.cli.main import app
from typer.testing import CliRunner


def _assert_talk_traceback_does_not_retain(
    error: BaseException,
    *,
    sentinels: tuple[str, ...],
) -> None:
    notes = tuple(getattr(error, "__notes__", ()))
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

    frames = []
    traceback = error.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        if frame.f_code.co_filename.endswith("talk.py"):
            frames.append(frame)
        traceback = traceback.tb_next

    assert frames
    for frame in frames:
        for name, value in frame.f_locals.items():
            rendered = repr(value)
            assert all(sentinel not in rendered for sentinel in sentinels), name


def test_talk_command_is_registered_without_starting_provider_or_server_stack() -> None:
    result = CliRunner().invoke(app, ["talk", "--help"])

    assert result.exit_code == 0
    assert "synthetic WAV" in result.stdout


def test_run_synthetic_turn_requires_explicit_personalized_context_provider() -> None:
    parameter = inspect.signature(run_synthetic_turn).parameters["context_provider"]

    assert parameter.default is inspect.Parameter.empty


def test_read_synthetic_wav_uses_single_link_regular_descriptor(tmp_path: Path) -> None:
    wav = tmp_path / "turn.wav"
    wav.write_bytes(b"RIFFsynthetic")

    assert read_synthetic_wav(wav) == b"RIFFsynthetic"

    symlink = tmp_path / "turn-link.wav"
    symlink.symlink_to(wav)
    with pytest.raises(PermissionError, match="unsafe synthetic WAV"):
        read_synthetic_wav(symlink)

    hardlink = tmp_path / "turn-hardlink.wav"
    os.link(wav, hardlink)
    with pytest.raises(PermissionError, match="unsafe synthetic WAV"):
        read_synthetic_wav(wav)


def test_read_synthetic_wav_enforces_nonempty_turn_cap(tmp_path: Path) -> None:
    empty = tmp_path / "empty.wav"
    empty.write_bytes(b"")
    with pytest.raises(ValueError, match="synthetic WAV outside turn bounds"):
        read_synthetic_wav(empty)

    oversized = tmp_path / "oversized.wav"
    with oversized.open("wb") as handle:
        handle.seek(8_388_608)
        handle.write(b"x")
    with pytest.raises(ValueError, match="synthetic WAV outside turn bounds"):
        read_synthetic_wav(oversized)


@pytest.mark.parametrize(
    "relative",
    (
        Path("missing.wav"),
        Path("missing-parent") / "turn.wav",
    ),
)
def test_read_synthetic_wav_rejects_missing_paths_without_path_content(
    tmp_path: Path,
    relative: Path,
) -> None:
    requested = tmp_path / relative

    with pytest.raises(PermissionError) as captured:
        read_synthetic_wav(requested)

    assert str(captured.value) == "unsafe synthetic WAV"
    assert "missing" not in str(captured.value)
    assert "turn.wav" not in str(captured.value)


def test_read_synthetic_wav_rejects_symlink_parent_without_following(
    tmp_path: Path,
) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    (real_parent / "turn.wav").write_bytes(b"RIFFprivate")
    symlink_parent = tmp_path / "symlink-parent"
    symlink_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(PermissionError) as captured:
        read_synthetic_wav(symlink_parent / "turn.wav")

    assert str(captured.value) == "unsafe synthetic WAV"


def test_read_synthetic_wav_rejects_inaccessible_parent_without_path_content(
    tmp_path: Path,
) -> None:
    inaccessible = tmp_path / "private-parent"
    inaccessible.mkdir()
    (inaccessible / "turn.wav").write_bytes(b"RIFFprivate")
    inaccessible.chmod(0)
    try:
        with pytest.raises(PermissionError) as captured:
            read_synthetic_wav(inaccessible / "turn.wav")
    finally:
        inaccessible.chmod(0o700)

    assert str(captured.value) == "unsafe synthetic WAV"
    assert "private-parent" not in str(captured.value)


def test_read_synthetic_wav_identity_drift_does_not_retain_private_read_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_audio = "private-audio-sentinel"
    private_close = "private-close-sentinel"
    private_bytes = b"RIFF-" + private_audio.encode("ascii")
    replacement = b"RIFF-public-replacement".ljust(len(private_bytes), b"x")
    wav = tmp_path / "turn.wav"
    wav.write_bytes(private_bytes)
    monkeypatch.chdir(tmp_path)

    real_read = talk_module.os.read
    real_close = talk_module.os.close
    drifted = False
    leaked_fds: list[int] = []

    def drift_after_content_read(fd: int, byte_count: int) -> bytes:
        nonlocal drifted
        chunk = real_read(fd, byte_count)
        if chunk and not drifted:
            wav.write_bytes(replacement)
            talk_module.os.utime(
                wav,
                ns=(2_000_000_000_000_000_000, 2_000_000_000_000_000_000),
            )
            drifted = True
        return chunk

    def fail_close(fd: int) -> None:
        leaked_fds.append(fd)
        raise OSError(private_close)

    monkeypatch.setattr(talk_module.os, "read", drift_after_content_read)
    monkeypatch.setattr(talk_module.os, "close", fail_close)
    try:
        with pytest.raises(PermissionError) as captured:
            read_synthetic_wav(Path("turn.wav"))
    finally:
        for fd in leaked_fds:
            with suppress(OSError):
                real_close(fd)

    assert drifted is True
    assert str(captured.value) == "unsafe synthetic WAV"
    assert "OSError" in " ".join(getattr(captured.value, "__notes__", ()))
    _assert_talk_traceback_does_not_retain(
        captured.value,
        sentinels=(private_audio, private_close),
    )


def test_read_synthetic_wav_close_failure_after_read_does_not_retain_private_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_audio = "private-audio-sentinel"
    private_close = "private-close-sentinel"
    wav = tmp_path / "turn.wav"
    wav.write_bytes(b"RIFF-" + private_audio.encode("ascii"))
    monkeypatch.chdir(tmp_path)

    real_close = talk_module.os.close
    leaked_fds: list[int] = []

    def fail_close(fd: int) -> None:
        leaked_fds.append(fd)
        raise OSError(private_close)

    monkeypatch.setattr(talk_module.os, "close", fail_close)
    try:
        with pytest.raises(PermissionError) as captured:
            read_synthetic_wav(Path("turn.wav"))
    finally:
        for fd in leaked_fds:
            with suppress(OSError):
                real_close(fd)

    assert str(captured.value) == "unsafe synthetic WAV"
    _assert_talk_traceback_does_not_retain(
        captured.value,
        sentinels=(private_audio, private_close),
    )
