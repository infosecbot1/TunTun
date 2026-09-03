from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import pytest
from tuntun_core.adapters.poc.terminal_ptt import (
    ScriptedTerminalBytes,
    TerminalPttInput,
)
from tuntun_core.services.poc.ports import CorePttEvent


class _TerminalMode:
    def __init__(self) -> None:
        self.events: list[str] = []

    def enter(self) -> object:
        self.events.append("enter")
        return ("prior-mode", len(self.events))

    def restore(self, token: object) -> None:
        self.events.append(f"restore:{token!r}")


def test_space_toggles_start_then_submit_escape_cancels_and_ignores_other_keys() -> None:
    terminal = _TerminalMode()
    raw = ScriptedTerminalBytes([b"x", b" ", b"q", b" ", b"\x1b"])
    ptt = TerminalPttInput(raw.read, terminal_mode=terminal, debounce_seconds=0)

    async def collect() -> tuple[CorePttEvent, CorePttEvent, CorePttEvent]:
        return await ptt.receive(), await ptt.receive(), await ptt.receive()

    assert asyncio.run(collect()) == (
        CorePttEvent.START,
        CorePttEvent.SUBMIT,
        CorePttEvent.CANCEL,
    )
    assert terminal.events == [
        "enter",
        "restore:('prior-mode', 1)",
        "enter",
        "restore:('prior-mode', 3)",
        "enter",
        "restore:('prior-mode', 5)",
    ]


def test_terminal_ptt_debounces_space_without_keyup_or_accessibility_hook() -> None:
    terminal = _TerminalMode()
    current = 10.0

    def now() -> float:
        return current

    raw = ScriptedTerminalBytes([b" "])
    ptt = TerminalPttInput(raw.read, terminal_mode=terminal, monotonic=now, debounce_seconds=0.25)

    async def collect() -> tuple[CorePttEvent, CorePttEvent]:
        nonlocal current
        first = await ptt.receive()
        current += 0.05
        ignored = asyncio.create_task(ptt.receive())
        raw.push(b" ")
        await asyncio.sleep(0)
        assert not ignored.done()
        current += 0.25
        raw.push(b" ")
        second = await ignored
        return first, second

    assert asyncio.run(collect()) == (CorePttEvent.START, CorePttEvent.SUBMIT)


@pytest.mark.parametrize("failure", [TimeoutError, KeyboardInterrupt, RuntimeError])
def test_terminal_mode_restores_after_error_timeout_or_ctrl_c(
    failure: type[BaseException],
) -> None:
    terminal = _TerminalMode()

    async def fail() -> bytes:
        raise failure("injected")

    ptt = TerminalPttInput(fail, terminal_mode=terminal, debounce_seconds=0)

    with pytest.raises(failure):
        asyncio.run(ptt.receive())

    assert terminal.events == ["enter", "restore:('prior-mode', 1)"]


def test_terminal_adapter_has_no_logging_or_platform_key_hook_imports() -> None:
    module_path = Path("apps/core/src/tuntun_core/adapters/poc/terminal_ptt.py")
    tree = ast.parse(module_path.read_text(encoding="utf-8"), filename=str(module_path))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")

    assert not {"logging", "pynput", "Quartz", "AppKit", "keyboard"}.intersection(imported)
