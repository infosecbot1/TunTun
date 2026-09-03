#!/usr/bin/env python3
"""Print non-content metadata used by the prompt path trust guard."""

from __future__ import annotations

import ctypes
import json
import os
import stat
from pathlib import Path


def _filesystem_magic(library: ctypes.CDLL, descriptor: int) -> str:
    filesystem_words = (ctypes.c_long * 32)()
    inspector = library.fstatfs
    inspector.argtypes = [ctypes.c_int, ctypes.c_void_p]
    inspector.restype = ctypes.c_int
    ctypes.set_errno(0)
    if inspector(descriptor, ctypes.byref(filesystem_words)) != 0:
        error_number = ctypes.get_errno()
        return f"error:{error_number}:{os.strerror(error_number)}"
    word_bits = ctypes.sizeof(ctypes.c_long) * 8
    return hex(int(filesystem_words[0]) & ((1 << word_bits) - 1))


def _extended_attribute_names(library: ctypes.CDLL, descriptor: int) -> list[str] | str:
    lister = library.flistxattr
    lister.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
    lister.restype = ctypes.c_ssize_t
    ctypes.set_errno(0)
    required = lister(descriptor, None, 0)
    if required < 0:
        error_number = ctypes.get_errno()
        return f"error:{error_number}:{os.strerror(error_number)}"
    if required == 0:
        return []
    buffer = ctypes.create_string_buffer(required)
    ctypes.set_errno(0)
    actual = lister(descriptor, buffer, required)
    if actual < 0:
        error_number = ctypes.get_errno()
        return f"error:{error_number}:{os.strerror(error_number)}"
    raw_names = buffer.raw[:actual]
    if not raw_names.endswith(b"\0"):
        return "error:malformed"
    return [name.decode("ascii", "replace") for name in raw_names[:-1].split(b"\0")]


def main() -> None:
    library = ctypes.CDLL(None, use_errno=True)
    target = Path("prompts/conversation/base.md").absolute()
    paths = [Path("/")]
    current = Path("/")
    for component in target.parts[1:]:
        current /= component
        paths.append(current)

    print(
        json.dumps(
            {
                "cwd": os.fspath(Path.cwd()),
                "euid": os.geteuid(),
                "target": os.fspath(target),
            },
            sort_keys=True,
        )
    )
    for path in paths:
        named = path.lstat()
        is_directory = stat.S_ISDIR(named.st_mode)
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        if is_directory:
            flags |= os.O_DIRECTORY
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            print(
                json.dumps(
                    {
                        "open_error": f"{error.errno}:{error.strerror}",
                        "path": os.fspath(path),
                    },
                    sort_keys=True,
                )
            )
            continue
        try:
            opened = os.fstat(descriptor)
            print(
                json.dumps(
                    {
                        "device": opened.st_dev,
                        "filesystem_magic": _filesystem_magic(library, descriptor),
                        "gid": opened.st_gid,
                        "inode": opened.st_ino,
                        "mode": oct(stat.S_IMODE(opened.st_mode)),
                        "nlink": opened.st_nlink,
                        "path": os.fspath(path),
                        "type": "directory" if is_directory else "file",
                        "uid": opened.st_uid,
                        "xattrs": _extended_attribute_names(library, descriptor),
                    },
                    sort_keys=True,
                )
            )
        finally:
            os.close(descriptor)


if __name__ == "__main__":
    main()
