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
