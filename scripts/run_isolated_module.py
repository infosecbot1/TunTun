from __future__ import annotations

import importlib
import os
import stat
import sys
from os import PathLike
from pathlib import Path
from unittest import mock

_RETAINED_SITE_MARKER = "__tuntun_retained_site_packages__"


def _run_from_retained_site(module: str) -> None:
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
    path_index = -1
    real_getcwd = os.getcwd
    real_abspath = os.path.abspath
    try:
        try:
            original_directory = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
            descriptor = os.open(
                directory,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            value = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(value.st_mode)
                or value.st_uid != os.geteuid()
                or value.st_mode & 0o022
            ):
                raise SystemExit(97)
            os.fchdir(descriptor)
            resolved = real_getcwd()
            rebound = os.stat(resolved, follow_symlinks=False)
            if (rebound.st_dev, rebound.st_ino, rebound.st_mode, rebound.st_uid) != (
                value.st_dev,
                value.st_ino,
                value.st_mode,
                value.st_uid,
            ):
                raise SystemExit(97)
        except OSError as error:
            raise SystemExit(97) from error
        path_index = len(sys.path)
        sys.path.append(".")
        entry_module = importlib.import_module(f"{module}.__main__")
        entry_point = getattr(entry_module, "console_entry", None)
        if not callable(entry_point):
            raise SystemExit(97)

        module_finder = importlib.import_module("mypy.modulefinder")
        mypy_main = importlib.import_module("mypy.main")

        def retained_abspath(value: str | PathLike[str]) -> str:
            if value == _RETAINED_SITE_MARKER:
                return "."
            return real_abspath(value)

        def retained_search_dirs(
            _python_executable: str | None,
        ) -> tuple[list[str], list[str]]:
            return ([], [_RETAINED_SITE_MARKER])

        with (
            mock.patch.object(os, "getcwd", return_value=str(repository_root)),
            mock.patch.object(os.path, "abspath", side_effect=retained_abspath),
            mock.patch.object(module_finder, "get_search_dirs", retained_search_dirs),
            mock.patch.object(mypy_main, "get_search_dirs", retained_search_dirs),
        ):
            entry_point()
    finally:
        if path_index >= 0 and path_index < len(sys.path) and sys.path[path_index] == ".":
            del sys.path[path_index]
        if original_directory >= 0:
            os.fchdir(original_directory)
            os.close(original_directory)
        if descriptor >= 0:
            os.close(descriptor)


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] != "mypy":
        return 97
    module = sys.argv.pop(1)
    _run_from_retained_site(module)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
