from __future__ import annotations

import ast
from pathlib import Path

import pytest
from tuntun_contracts.poc.framing import PttInputMode
from tuntun_core.cli.commands.talk import (
    TalkModeError,
    exact_mode_matrix,
    validate_talk_mode,
)


def test_task5_mode_matrix_exposes_only_fake_over_simulated() -> None:
    assert exact_mode_matrix() == {
        ("fake", "simulated"): {
            "available": True,
            "input_mode": PttInputMode.CORE_TERMINAL_TOGGLE.value,
            "status": "task5_fake_simulated_only",
        },
        ("fake", "ssh"): {
            "available": False,
            "input_mode": None,
            "status": "reachy_hardware_deferred_to_task7",
        },
        ("live-cloud", "simulated"): {
            "available": False,
            "input_mode": None,
            "status": "cloud_gate_deferred_to_task6",
        },
        ("live-cloud", "ssh"): {
            "available": False,
            "input_mode": None,
            "status": "cloud_and_hardware_deferred",
        },
    }


@pytest.mark.parametrize(
    ("mode", "transport"),
    [("fake", "ssh"), ("live-cloud", "simulated"), ("live-cloud", "ssh")],
)
def test_unsupported_mode_cells_fail_before_any_external_effect(
    mode: str,
    transport: str,
) -> None:
    effects: list[str] = []

    with pytest.raises(TalkModeError, match="^unsupported-talk-mode$"):
        validate_talk_mode(
            mode,
            transport,
            before_keychain=lambda: effects.append("keychain"),
            before_budget=lambda: effects.append("budget"),
            before_audio=lambda: effects.append("audio"),
            before_network=lambda: effects.append("network"),
            before_ssh=lambda: effects.append("ssh"),
        )

    assert effects == []


def test_fake_simulated_defaults_to_core_terminal_toggle() -> None:
    effects: list[str] = []

    selection = validate_talk_mode(
        "fake",
        "simulated",
        before_audio=lambda: effects.append("audio"),
    )

    assert selection.input_mode is PttInputMode.CORE_TERMINAL_TOGGLE
    assert selection.status == "task5_fake_simulated_only"
    assert effects == ["audio"]


def test_task5_core_fake_path_does_not_import_edge_testing_storage_or_hardware_sdks() -> None:
    forbidden_roots = {
        "tuntun_edge",
        "tuntun_testing",
        "socket",
        "websockets",
        "sqlalchemy",
        "sqlcipher3",
        "reachy2_sdk",
    }
    violations: list[str] = []
    checked = (
        Path("apps/core/src/tuntun_core/cli/commands/talk.py"),
        Path("apps/core/src/tuntun_core/adapters/poc/fake_voice.py"),
        Path("apps/core/src/tuntun_core/adapters/poc/terminal_ptt.py"),
        Path("apps/core/src/tuntun_core/services/poc/session_supervisor.py"),
    )
    for path in checked:
        if not path.exists():
            violations.append(f"{path}:missing")
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            imported: list[str] = []
            if isinstance(node, ast.Import):
                imported = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                imported = [node.module or ""]
            for name in imported:
                root = name.split(".", 1)[0]
                if root in forbidden_roots:
                    violations.append(f"{path}:{name}")

    assert violations == []


def test_tuntun_testing_remains_optional_not_core_runtime_dependency() -> None:
    pyproject = Path("apps/core/pyproject.toml").read_text(encoding="utf-8")

    runtime_block = pyproject.split("[project.optional-dependencies]", maxsplit=1)[0]

    assert '"tuntun-testing"' not in runtime_block
    assert 'simulation = ["tuntun-testing"]' in pyproject
