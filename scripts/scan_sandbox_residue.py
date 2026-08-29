from __future__ import annotations

import os
import platform
import stat
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from assurance_common import (
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        finish,
        incomplete,
        lexical_path,
        validate_root,
    )
elif __package__:
    from .assurance_common import (
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        finish,
        incomplete,
        lexical_path,
        validate_root,
    )
else:
    from assurance_common import (
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        finish,
        incomplete,
        lexical_path,
        validate_root,
    )

TOOL = "sandbox-residue"


def _parser() -> ClosedArgumentParser:
    parser = ClosedArgumentParser(prog="scan_sandbox_residue.py")
    parser.add_argument("--root", required=True)
    parser.add_argument("--require-empty", action="store_true")
    return parser


def _entries(root: Path) -> tuple[str, ...]:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(root, flags)
    opened = os.fstat(descriptor)
    try:
        names = []
        with os.scandir(descriptor) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > 1:
                    break
        renamed = os.stat(root, follow_symlinks=False)
        if not stat.S_ISDIR(renamed.st_mode) or (
            opened.st_dev,
            opened.st_ino,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != (renamed.st_dev, renamed.st_ino, renamed.st_mtime_ns, renamed.st_ctime_ns):
            raise AssuranceInputError(root, "input-changed-during-scan")
        return tuple(names)
    except OSError as error:
        raise AssuranceInputError(root, "unreadable-input", error.strerror) from error
    finally:
        os.close(descriptor)


def _process_handles(root: Path) -> tuple[str, ...]:
    system = platform.system()
    if system == "Darwin":
        try:
            result = subprocess.run(
                ("/usr/sbin/lsof", "-Fn", "+D", str(root)),
                shell=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=10,
                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise AssuranceInputError(root, "handle-inventory-unavailable") from error
        if len(result.stdout) > 4 * 1024 * 1024 or len(result.stderr) > 4 * 1024 * 1024:
            raise AssuranceInputError(root, "handle-inventory-truncated")
        if result.returncode not in {0, 1}:
            raise AssuranceInputError(root, "handle-inventory-unavailable")
        return tuple(
            line[1:] for line in result.stdout.decode("utf-8").splitlines() if line.startswith("n")
        )
    if system == "Linux":
        proc = Path("/proc")
        if not proc.is_dir():
            raise AssuranceInputError(root, "handle-inventory-unavailable")
        handles = []
        count = 0
        for process in proc.iterdir():
            if not process.name.isdecimal():
                continue
            descriptors = process / "fd"
            try:
                for descriptor in descriptors.iterdir():
                    count += 1
                    if count > 1_000_000:
                        raise AssuranceInputError(root, "handle-inventory-limit")
                    try:
                        target = Path(os.readlink(descriptor))
                    except (OSError, UnicodeError):
                        continue
                    if target == root or root in target.parents:
                        handles.append(f"{process.name}:{descriptor.name}")
            except PermissionError:
                raise AssuranceInputError(root, "handle-inventory-incomplete") from None
            except FileNotFoundError:
                continue
        return tuple(handles)
    raise AssuranceInputError(root, "handle-inventory-unavailable")


def evaluate(argv: Sequence[str] | None = None) -> AssuranceResult:
    try:
        arguments = _parser().parse_args(argv)
        if not arguments.require_empty:
            raise ValueError("--require-empty is required")
        root = validate_root(lexical_path(arguments.root))
        entries = _entries(root)
        mounted = os.path.ismount(root)
        handles = _process_handles(root)
    except AssuranceInputError as error:
        return incomplete(TOOL, error)
    except (ValueError, TypeError) as error:
        return AssuranceResult(
            TOOL, False, (AssuranceFinding(Path("."), "invalid-arguments", str(error)),)
        )
    findings = [AssuranceFinding(root / name, "sandbox-entry") for name in entries]
    if mounted:
        findings.append(AssuranceFinding(root, "sandbox-mount"))
    findings.extend(AssuranceFinding(root, "sandbox-process-handle", handle) for handle in handles)
    return AssuranceResult(TOOL, True, tuple(findings))


def main(argv: Sequence[str] | None = None) -> int:
    return finish(evaluate(argv))


if __name__ == "__main__":
    raise SystemExit(main())
