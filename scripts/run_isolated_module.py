from __future__ import annotations

import importlib
import os
import stat
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from os import PathLike
from pathlib import Path
from unittest import mock

_RETAINED_SITE_MARKER = "__tuntun_retained_site_packages__"
_MAX_MYPY_CONFIG_BYTES = 1_048_576


@contextmanager
def _retained_mypy_config(repository_root: Path, arguments: list[str]) -> Iterator[None]:
    if (
        arguments.count("--config-file") != 1
        or arguments.count("--no-incremental") != 1
        or arguments.count("--cache-dir") != 1
        or arguments.count("--no-fast-exit") != 1
    ):
        raise SystemExit(97)
    config_index = arguments.index("--config-file") + 1
    cache_index = arguments.index("--cache-dir") + 1
    expected = repository_root / "pyproject.toml"
    if (
        config_index >= len(arguments)
        or arguments[config_index] != str(expected)
        or cache_index >= len(arguments)
        or arguments[cache_index] != os.devnull
    ):
        raise SystemExit(97)
    descriptor = -1
    try:
        descriptor = os.open(expected, os.O_RDONLY | os.O_NOFOLLOW)
        initial = os.fstat(descriptor)
        if (
            not stat.S_ISREG(initial.st_mode)
            or initial.st_uid != os.geteuid()
            or initial.st_mode & 0o022
            or not 0 < initial.st_size <= _MAX_MYPY_CONFIG_BYTES
        ):
            raise SystemExit(97)
        remaining = initial.st_size
        content = bytearray()
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise SystemExit(97)
            content.extend(chunk)
            remaining -= len(chunk)
        final = os.fstat(descriptor)
        if os.read(descriptor, 1) or (
            final.st_dev,
            final.st_ino,
            final.st_mode,
            final.st_uid,
            final.st_size,
        ) != (initial.st_dev, initial.st_ino, initial.st_mode, initial.st_uid, initial.st_size):
            raise SystemExit(97)
    except OSError as error:
        raise SystemExit(97) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    original = arguments[config_index]
    with tempfile.TemporaryDirectory(prefix="tuntun-mypy-config.") as temporary:
        retained = Path(temporary) / "pyproject.toml"
        output = -1
        try:
            output = os.open(
                retained,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            view = memoryview(content)
            while view:
                written = os.write(output, view)
                if written <= 0:
                    raise SystemExit(97)
                view = view[written:]
        except OSError as error:
            raise SystemExit(97) from error
        finally:
            if output >= 0:
                os.close(output)
        arguments[config_index] = str(retained)
        try:
            yield
        finally:
            arguments[config_index] = original


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
    repository_root = Path(__file__).absolute().parent.parent
    with _retained_mypy_config(repository_root, sys.argv):
        _run_from_retained_site(module)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
