from __future__ import annotations

import os
import runpy
import stat
import sys
from pathlib import Path


def _site_packages() -> str:
    executable = Path(sys.executable).absolute()
    repository_root = Path(__file__).absolute().parent.parent
    if executable.parent != repository_root / ".venv/bin":
        raise SystemExit(97)
    directory = (
        repository_root
        / ".venv/lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    descriptor = -1
    original_directory = -1
    try:
        original_directory = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
        descriptor = os.open(
            directory,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        value = os.fstat(descriptor)
        if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or value.st_mode & 0o022:
            raise SystemExit(97)
        os.fchdir(descriptor)
        resolved = os.getcwd()
        rebound = os.stat(resolved, follow_symlinks=False)
        if (rebound.st_dev, rebound.st_ino, rebound.st_mode, rebound.st_uid) != (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
        ):
            raise SystemExit(97)
        return resolved
    except OSError as error:
        raise SystemExit(97) from error
    finally:
        if original_directory >= 0:
            os.fchdir(original_directory)
            os.close(original_directory)
        if descriptor >= 0:
            os.close(descriptor)


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] != "mypy":
        return 97
    module = sys.argv.pop(1)
    sys.path.append(_site_packages())
    runpy.run_module(module, run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
