from __future__ import annotations

import os
from pathlib import Path

import pytest
from tuntun_core.cli.commands.talk import read_synthetic_wav
from tuntun_core.cli.main import app
from typer.testing import CliRunner


def test_talk_command_is_registered_without_starting_provider_or_server_stack() -> None:
    result = CliRunner().invoke(app, ["talk", "--help"])

    assert result.exit_code == 0
    assert "synthetic WAV" in result.stdout


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
