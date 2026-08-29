from __future__ import annotations

import os
import platform
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from assurance_common import (
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        BoundDirectory,
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
        BoundDirectory,
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
        BoundDirectory,
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


def _entries(root: Path, descriptor: int) -> tuple[str, ...]:
    try:
        names = []
        with os.scandir(descriptor) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > 1:
                    break
        return tuple(names)
    except OSError as error:
        raise AssuranceInputError(root, "unreadable-input", error.strerror) from error


def _process_handles(root: Path, scanner_handle: tuple[int, int]) -> tuple[str, ...]:
    system = platform.system()
    if system == "Darwin":
        try:
            result = subprocess.run(
                ("/usr/sbin/lsof", "-Fpfn", "+D", str(root)),
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
        try:
            lines = result.stdout.decode("utf-8").splitlines()
        except UnicodeDecodeError as error:
            raise AssuranceInputError(root, "handle-inventory-unavailable") from error
        handles = []
        pid: int | None = None
        handle_fd: int | None = None
        for line in lines:
            if line.startswith("p") and line[1:].isdecimal():
                pid = int(line[1:])
                handle_fd = None
            elif line.startswith("f"):
                handle_fd = int(line[1:]) if line[1:].isdecimal() else None
            elif line.startswith("n") and (pid, handle_fd) != scanner_handle:
                handles.append(f"{pid}:{handle_fd}:{line[1:]}")
        return tuple(handles)
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
                for descriptor_path in descriptors.iterdir():
                    count += 1
                    if count > 1_000_000:
                        raise AssuranceInputError(root, "handle-inventory-limit")
                    try:
                        target = Path(os.readlink(descriptor_path))
                    except (OSError, UnicodeError):
                        continue
                    if (int(process.name), int(descriptor_path.name)) == scanner_handle:
                        continue
                    if target == root or root in target.parents:
                        handles.append(f"{process.name}:{descriptor_path.name}")
            except PermissionError:
                raise AssuranceInputError(root, "handle-inventory-incomplete") from None
            except FileNotFoundError:
                continue
        return tuple(handles)
    raise AssuranceInputError(root, "handle-inventory-unavailable")


def evaluate(argv: Sequence[str] | None = None) -> AssuranceResult:
    binding: BoundDirectory | None = None
    try:
        arguments = _parser().parse_args(argv)
        if not arguments.require_empty:
            raise ValueError("--require-empty is required")
        root = validate_root(lexical_path(arguments.root))
        binding = BoundDirectory.open(root)
        entries = _entries(root, binding.descriptor)
        binding.revalidate()
        mounted = os.path.ismount(root)
        binding.revalidate()
        handles = _process_handles(root, (os.getpid(), binding.descriptor))
        binding.revalidate()
    except AssuranceInputError as error:
        return incomplete(TOOL, error)
    except (ValueError, TypeError) as error:
        return AssuranceResult(
            TOOL, False, (AssuranceFinding(Path("."), "invalid-arguments", str(error)),)
        )
    finally:
        if binding is not None:
            binding.close()
    findings = [AssuranceFinding(root / name, "sandbox-entry") for name in entries]
    if mounted:
        findings.append(AssuranceFinding(root, "sandbox-mount"))
    findings.extend(AssuranceFinding(root, "sandbox-process-handle", handle) for handle in handles)
    return AssuranceResult(TOOL, True, tuple(findings))


def main(argv: Sequence[str] | None = None) -> int:
    return finish(evaluate(argv))


if __name__ == "__main__":
    raise SystemExit(main())
