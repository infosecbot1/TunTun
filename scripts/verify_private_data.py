from __future__ import annotations

import hashlib
import io
import os
import re
import selectors
import stat
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, BinaryIO, Literal, Protocol

FORBIDDEN_SUFFIXES = {
    ".db",
    ".sqlite",
    ".sqlite3",
    ".pem",
    ".key",
    ".crt",
    ".wav",
    ".mp3",
    ".mp4",
    ".jpg",
    ".jpeg",
    ".png",
    ".onnx",
    ".safetensors",
}
ALLOWED_DETERMINISTIC_OFFLINE_WAVS: Mapping[PurePosixPath, tuple[int, str]] = MappingProxyType(
    {
        PurePosixPath("assets/offline-prompts/confirm.wav"): (
            12_044,
            "90a1d8db8ce933937181954b71c8d28acff657e60e1ad0e67425211f8f2af822",
        ),
        PurePosixPath("assets/offline-prompts/unavailable.wav"): (
            12_044,
            "768cb24891237a6a70d2dd9c3642998db27bfa6739b7924587b827cc2e57ed35",
        ),
    }
)
PATTERNS = (
    ("credential-pattern", re.compile(rb"(?:sk-proj-|AKIA)[A-Za-z0-9_-]{16,}")),
    ("private-key", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)
GENERATED_ROOT_PARTS = {
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "htmlcov",
    "node_modules",
    "out",
    "var",
}
ARTIFACT_ROOT_PARTS = {"artifact", "artifacts", "candidate", "candidates", "evidence", "release"}
ARCHIVE_ROOT_SUFFIXES = (".zip", ".whl", ".tar", ".tar.gz", ".tgz")
GIT_TIMEOUT_SECONDS = 10.0
GIT_REAP_TIMEOUT_SECONDS = 1.0
GIT_EXECUTABLE = "/usr/bin/git"
GIT_FD_EXEC_HELPER = (
    "import os,sys;"
    "os.fchdir(int(sys.argv[1]));"
    "os.execve(sys.argv[2],tuple(sys.argv[2:]),os.environ)"
)
MAX_GIT_INVENTORY_BYTES = 64 * 1024 * 1024
MAX_GIT_STDERR_BYTES = 1024 * 1024
MAX_HISTORY_COMMITS = 10_000
MAX_HISTORY_INVENTORY_SECONDS = 60.0
MAX_HISTORY_BLOB_PATHS = 128
STREAM_CHUNK_BYTES = 1024 * 1024
MAX_GIT_BATCH_BUFFER_BYTES = 2 * STREAM_CHUNK_BYTES
PATTERN_OVERLAP_BYTES = 256
MAX_RAW_FILE_BYTES = 4 * 1024 * 1024 * 1024
MAX_COMPRESSED_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
MAX_TOTAL_INPUT_BYTES = 16 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
MAX_CUMULATIVE_EXPANDED_BYTES = 12 * 1024 * 1024 * 1024
MAX_FILES = 100_000
MAX_PATH_ENTRIES = 100_000
MAX_ARCHIVE_MEMBERS = 50_000
MAX_ARCHIVE_DEPTH = 3
MAX_ZIP_CENTRAL_DIRECTORY_BYTES = 64 * 1024 * 1024
MAX_TAR_METADATA_BYTES = 64 * 1024
MAX_TAR_TRAILING_PADDING_BYTES = 1024 * 1024
MAX_GZIP_HEADER_BYTES = 64 * 1024
MAX_GZIP_TRAILING_PADDING_BYTES = 1024 * 1024
ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


class BinaryWriter(Protocol):
    def write(self, value: bytes) -> int: ...


@dataclass(frozen=True, slots=True)
class Finding:
    path: Path
    reason: str


@dataclass(slots=True)
class OpenedCandidate:
    path: Path
    metadata: os.stat_result
    fd: int | None
    parent_fd: int | None
    name: str | None


class ScanLimit(RuntimeError):
    def __init__(self, path: Path, reason: str) -> None:
        self.path, self.reason = path, reason


@dataclass(slots=True)
class ScanBudget:
    path_entries: int = 0
    files: int = 0
    archive_members: int = 0
    input_bytes: int = 0
    expanded_bytes: int = 0

    def consume(self, field: str, amount: int, limit: int, path: Path, reason: str) -> None:
        value = getattr(self, field) + amount
        setattr(self, field, value)
        if value > limit:
            raise ScanLimit(path, reason)

    def path_entry(self, path: Path) -> None:
        self.consume("path_entries", 1, MAX_PATH_ENTRIES, path, "path-entry-limit")

    def file(self, path: Path) -> None:
        self.consume("files", 1, MAX_FILES, path, "file-count-limit")

    def input(self, path: Path, size: int) -> None:
        self.consume("input_bytes", size, MAX_TOTAL_INPUT_BYTES, path, "total-input-byte-limit")

    def member(self, path: Path) -> None:
        self.consume("archive_members", 1, MAX_ARCHIVE_MEMBERS, path, "archive-member-limit")

    def expanded(self, path: Path, size: int) -> None:
        self.consume(
            "expanded_bytes",
            size,
            MAX_CUMULATIVE_EXPANDED_BYTES,
            path,
            "cumulative-expanded-byte-limit",
        )


class FrozenFileView:
    def __init__(self, source: Any, size: int) -> None:
        self._source, self._size = source, size

    def tell(self) -> int:
        return int(self._source.tell())

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        remaining = max(0, self._size - self.tell())
        return bytes(
            self._source.read(remaining if size is None or size < 0 else min(size, remaining))
        )

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            target = offset
        elif whence == os.SEEK_CUR:
            target = self.tell() + offset
        elif whence == os.SEEK_END:
            target = self._size + offset
        else:
            raise ValueError("invalid seek mode")
        if not 0 <= target <= self._size:
            raise OSError("scan input changed bounds")
        return int(self._source.seek(target, os.SEEK_SET))


class ArchiveFormatError(RuntimeError):
    pass


def _read_exact(source: Any, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = source.read(remaining)
        if not chunk:
            raise ArchiveFormatError("truncated archive")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class StrictGzipReader:
    """One bounded RFC-1952 member; concatenated members are deliberately blocked."""

    def __init__(self, source: Any, display: Path) -> None:
        self._source = source
        self._display = display
        self._pending = b""
        self._decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
        self._crc = 0
        self._size = 0
        self._finished = False
        self._read_header()

    def _compressed(self, size: int) -> bytes:
        result = self._pending[:size]
        self._pending = self._pending[len(result) :]
        if len(result) < size:
            result += self._source.read(size - len(result))
        return result

    def _header_exact(self, size: int, counter: list[int]) -> bytes:
        counter[0] += size
        if counter[0] > MAX_GZIP_HEADER_BYTES:
            raise ScanLimit(self._display, "gzip-header-limit")
        value = self._compressed(size)
        if len(value) != size:
            raise ArchiveFormatError("truncated gzip header")
        return value

    def _header_c_string(self, counter: list[int]) -> bytes:
        value = bytearray()
        while True:
            byte = self._header_exact(1, counter)
            value.extend(byte)
            if byte == b"\0":
                return bytes(value)

    def _read_header(self) -> None:
        count = [0]
        fixed = self._header_exact(10, count)
        header = bytearray(fixed)
        if fixed[:3] != b"\x1f\x8b\x08" or fixed[3] & 0xE0:
            raise ArchiveFormatError("invalid gzip header")
        flags = fixed[3]
        if flags & 0x04:
            raw_length = self._header_exact(2, count)
            header.extend(raw_length)
            length = struct.unpack("<H", raw_length)[0]
            header.extend(self._header_exact(length, count))
        if flags & 0x08:
            header.extend(self._header_c_string(count))
        if flags & 0x10:
            header.extend(self._header_c_string(count))
        if flags & 0x02:
            expected = struct.unpack("<H", self._header_exact(2, count))[0]
            if expected != (zlib.crc32(header) & 0xFFFF):
                raise ArchiveFormatError("invalid gzip header crc")

    def _finish(self) -> None:
        trailer = self._compressed(8)
        if len(trailer) != 8:
            raise ArchiveFormatError("truncated gzip trailer")
        expected_crc, expected_size = struct.unpack("<II", trailer)
        if expected_crc != self._crc or expected_size != (self._size & 0xFFFFFFFF):
            raise ArchiveFormatError("invalid gzip trailer")
        trailing = 0
        while True:
            chunk = self._compressed(64 * 1024)
            if not chunk:
                break
            trailing += len(chunk)
            if trailing > MAX_GZIP_TRAILING_PADDING_BYTES:
                raise ScanLimit(self._display, "gzip-trailing-padding-limit")
            if any(chunk):
                raise ScanLimit(self._display, "gzip-trailing-data")
        self._finished = True

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            raise ValueError("bounded read size required")
        output = bytearray()
        while len(output) < size and not self._finished:
            if self._decompressor.eof:
                self._finish()
                break
            if not self._pending:
                self._pending = self._source.read(64 * 1024)
                if not self._pending:
                    raise ArchiveFormatError("truncated deflate stream")
            compressed = self._pending
            self._pending = b""
            try:
                decoded = self._decompressor.decompress(compressed, size - len(output))
            except zlib.error as error:
                raise ArchiveFormatError("invalid deflate stream") from error
            if self._decompressor.eof:
                self._pending = self._decompressor.unused_data
            elif self._decompressor.unconsumed_tail:
                self._pending = self._decompressor.unconsumed_tail
            output.extend(decoded)
            self._crc = zlib.crc32(decoded, self._crc)
            self._size += len(decoded)
        return bytes(output)


class ExpandedBudgetReader:
    def __init__(self, source: Any, budget: ScanBudget, display: Path) -> None:
        self._source, self._budget, self._display = source, budget, display

    def read(self, size: int = -1) -> bytes:
        value = bytes(self._source.read(size))
        self._budget.expanded(self._display, len(value))
        return value


class TarMemberReader:
    def __init__(self, source: Any, size: int) -> None:
        self._source, self.remaining = source, size

    def read(self, size: int = -1) -> bytes:
        if self.remaining == 0:
            return b""
        requested = self.remaining if size is None or size < 0 else min(size, self.remaining)
        value = bytes(self._source.read(requested))
        self.remaining -= len(value)
        return value


def _patterns_stream(
    path: Path,
    source: Any,
    *,
    expected_size: int | None,
    byte_limit: int,
    limit_reason: str,
    budget: ScanBudget | None = None,
    expanded: bool = False,
    initial: bytes = b"",
    sink: BinaryIO | None = None,
    repository_relative_path: PurePosixPath | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    suffix = Path(path.name.split("!", 1)[-1]).suffix.lower()
    deferred_wav_check = suffix == ".wav"
    if suffix in FORBIDDEN_SUFFIXES and not deferred_wav_check:
        findings.append(Finding(path, "forbidden-extension"))
    if expected_size is not None and expected_size > byte_limit:
        if deferred_wav_check:
            findings.insert(0, Finding(path, "forbidden-extension"))
        return [*findings, Finding(path, limit_reason)]
    total = 0
    tail = b""
    matched: set[str] = set()
    pending = initial
    wav_digest = hashlib.sha256() if deferred_wav_check else None
    while pending or (pending := source.read(STREAM_CHUNK_BYTES)):
        chunk = pending
        pending = b""
        total += len(chunk)
        if wav_digest is not None:
            wav_digest.update(chunk)
        if total > byte_limit:
            if deferred_wav_check:
                findings.insert(0, Finding(path, "forbidden-extension"))
            return [*findings, Finding(path, limit_reason)]
        if expected_size is not None and total > expected_size:
            if deferred_wav_check:
                findings.insert(0, Finding(path, "forbidden-extension"))
            return [*findings, Finding(path, "archive-read-failed")]
        if budget is not None and expanded:
            budget.expanded(path, len(chunk))
        if sink is not None:
            sink.write(chunk)
        window = tail + chunk
        for reason, pattern in PATTERNS:
            if reason not in matched and pattern.search(window):
                matched.add(reason)
                findings.append(Finding(path, reason))
        tail = window[-PATTERN_OVERLAP_BYTES:]
    if expected_size is not None and total != expected_size:
        findings.append(Finding(path, "archive-read-failed"))
    if deferred_wav_check:
        assert wav_digest is not None
        if not _is_allowed_deterministic_offline_wav(
            path,
            repository_relative_path,
            total,
            wav_digest.hexdigest(),
        ):
            findings.insert(0, Finding(path, "forbidden-extension"))
    return findings


def _is_allowed_deterministic_offline_wav(
    display_path: Path,
    repository_relative_path: PurePosixPath | None,
    size_bytes: int,
    sha256: str,
) -> bool:
    if "!" in display_path.as_posix() or repository_relative_path is None:
        return False
    if (
        repository_relative_path.is_absolute()
        or repository_relative_path.as_posix() != str(repository_relative_path)
        or any(part in {"", ".", ".."} for part in repository_relative_path.parts)
    ):
        return False
    expected = ALLOWED_DETERMINISTIC_OFFLINE_WAVS.get(repository_relative_path)
    return expected == (size_bytes, sha256)


def _repository_relative_path(path: Path) -> PurePosixPath | None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    for parent in absolute.parents:
        try:
            marker = os.stat(parent / ".git", follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError:
            return None
        if stat.S_ISLNK(marker.st_mode) or not (
            stat.S_ISDIR(marker.st_mode) or stat.S_ISREG(marker.st_mode)
        ):
            return None
        try:
            relative = absolute.relative_to(parent)
        except ValueError:
            return None
        return PurePosixPath(relative.as_posix())
    return None


def _archive_intent(name: str, prefix: bytes) -> str | None:
    name = name.lower()
    if name.endswith((".zip", ".whl")) or prefix.startswith(ZIP_MAGIC):
        return "zip"
    if name.endswith((".tar.gz", ".tgz")) or prefix.startswith(b"\x1f\x8b"):
        return "compressed_tar"
    if name.endswith(".tar") or prefix[257:262] == b"ustar":
        return "tar"
    return None


def _is_audio_like_bytes(prefix: bytes) -> bool:
    return len(prefix) >= 12 and prefix[:4] == b"RIFF" and prefix[8:12] == b"WAVE"


def _zip_member_count(source: Any, display: Path, budget: ScanBudget) -> None:
    source.seek(0, os.SEEK_END)
    size = source.tell()
    tail_offset = max(0, size - 65_557)
    source.seek(tail_offset)
    tail = source.read(65_557)
    marker = tail.rfind(b"PK\x05\x06")
    while marker >= 0:
        if len(tail) - marker >= 22:
            comment_size = struct.unpack_from("<H", tail, marker + 20)[0]
            if tail_offset + marker + 22 + comment_size == size:
                break
        marker = tail.rfind(b"PK\x05\x06", 0, marker)
    if marker < 0:
        raise zipfile.BadZipFile("missing EOCD")
    disk, directory_disk, disk_count, count = struct.unpack_from("<HHHH", tail, marker + 4)
    directory_size, directory_offset = struct.unpack_from("<II", tail, marker + 12)
    if (
        any(value == 0xFFFF for value in (disk, directory_disk, disk_count, count))
        or directory_size == 0xFFFFFFFF
        or directory_offset == 0xFFFFFFFF
    ):
        raise ScanLimit(display, "zip64-unsupported")
    if disk != 0 or directory_disk != 0 or disk_count != count:
        raise ScanLimit(display, "zip-central-directory-invalid")
    if directory_size > MAX_ZIP_CENTRAL_DIRECTORY_BYTES:
        raise ScanLimit(display, "zip-central-directory-limit")
    eocd_offset = tail_offset + marker
    if (
        directory_size < count * 46
        or directory_offset > eocd_offset
        or directory_offset + directory_size != eocd_offset
    ):
        raise ScanLimit(display, "zip-central-directory-invalid")
    source.seek(directory_offset)
    remaining = directory_size
    actual_count = 0
    while remaining:
        header = source.read(46)
        if len(header) != 46 or not header.startswith(b"PK\x01\x02"):
            raise ScanLimit(display, "zip-central-directory-invalid")
        name_size, extra_size, comment_size = struct.unpack_from("<HHH", header, 28)
        record_size = 46 + name_size + extra_size + comment_size
        if record_size > remaining:
            raise ScanLimit(display, "zip-central-directory-invalid")
        source.seek(record_size - 46, os.SEEK_CUR)
        remaining -= record_size
        actual_count += 1
        if actual_count > MAX_ARCHIVE_MEMBERS:
            raise ScanLimit(display, "archive-member-limit")
    if actual_count != count:
        raise ScanLimit(display, "zip-central-directory-invalid")
    if budget.archive_members + count > MAX_ARCHIVE_MEMBERS:
        raise ScanLimit(display, "archive-member-limit")
    source.seek(0)


def _canonical_archive_name(raw: str) -> str:
    if not raw or "\\" in raw or any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise ValueError("unsafe archive name")
    trimmed = raw[:-1] if raw.endswith("/") else raw
    path = PurePosixPath(trimmed)
    if (
        not trimmed
        or path.is_absolute()
        or path.as_posix() != trimmed
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("unsafe archive name")
    return path.as_posix()


def _scan_member(
    source: Any,
    name: str,
    display: Path,
    expected_size: int,
    budget: ScanBudget,
    depth: int,
    *,
    charge_expanded: bool = True,
) -> list[Finding]:
    prefix = source.read(min(512, expected_size))
    intent = _archive_intent(name, prefix)
    if intent is None:
        return _patterns_stream(
            display,
            source,
            initial=prefix,
            expected_size=expected_size,
            byte_limit=MAX_ARCHIVE_MEMBER_BYTES,
            limit_reason="archive-member-byte-limit",
            budget=budget,
            expanded=charge_expanded,
        )
    if depth >= MAX_ARCHIVE_DEPTH:
        return [Finding(display, "archive-depth-limit")]
    with tempfile.TemporaryFile() as nested:
        findings = _patterns_stream(
            display,
            source,
            initial=prefix,
            expected_size=expected_size,
            byte_limit=MAX_ARCHIVE_MEMBER_BYTES,
            limit_reason="archive-member-byte-limit",
            budget=budget,
            expanded=charge_expanded,
            sink=nested,
        )
        if any(
            item.reason.endswith("limit") or item.reason == "archive-read-failed"
            for item in findings
        ):
            return findings
        nested.seek(0)
        return [*findings, *_scan_archive(nested, intent, display, budget, depth + 1)]


def _tar_octal(field: bytes) -> int:
    value = field.rstrip(b"\0 ").lstrip(b" ")
    if not value or re.fullmatch(rb"[0-7]+", value) is None:
        raise ArchiveFormatError("invalid tar number")
    return int(value, 8)


def _tar_name(header: bytes) -> str:
    name = header[0:100].split(b"\0", 1)[0]
    prefix = header[345:500].split(b"\0", 1)[0]
    raw = (prefix + b"/" if prefix else b"") + name
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ArchiveFormatError("invalid tar name") from error
    value = value[:-1] if value.endswith("/") else value
    parts = value.split("/")
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ArchiveFormatError("unsafe tar name")
    return value


def _discard_exact(source: Any, size: int) -> None:
    remaining = size
    while remaining:
        chunk = source.read(min(STREAM_CHUNK_BYTES, remaining))
        if not chunk:
            raise ArchiveFormatError("truncated tar member")
        remaining -= len(chunk)


def _scan_ustar(source: Any, display: Path, budget: ScanBudget, depth: int) -> list[Finding]:
    findings: list[Finding] = []
    saw_end = False
    while True:
        header = _read_exact(source, 512)
        if header == b"\0" * 512:
            if _read_exact(source, 512) != b"\0" * 512:
                raise ArchiveFormatError("invalid tar end marker")
            saw_end = True
            break
        if header[257:263] not in {b"ustar\0", b"ustar "}:
            raise ArchiveFormatError("unsupported tar format")
        findings.extend(
            _patterns_stream(
                display,
                io.BytesIO(header),
                expected_size=len(header),
                byte_limit=len(header),
                limit_reason="archive-member-byte-limit",
            )
        )
        stored = _tar_octal(header[148:156])
        checksum = sum(header[:148]) + 8 * ord(" ") + sum(header[156:])
        if stored != checksum:
            raise ArchiveFormatError("invalid tar checksum")
        size = _tar_octal(header[124:136])
        name = _tar_name(header)
        member_display = Path(str(display) + "!" + name)
        budget.member(member_display)
        kind = header[156:157]
        if kind in {b"x", b"g", b"L", b"K"}:
            if size > MAX_TAR_METADATA_BYTES:
                raise ScanLimit(member_display, "tar-metadata-limit")
            _discard_exact(source, size)
            findings.append(Finding(member_display, "unsupported-tar-metadata"))
        elif kind == b"5":
            if size:
                raise ArchiveFormatError("directory has tar payload")
        elif kind in {b"", b"\0", b"0"}:
            if size > MAX_ARCHIVE_MEMBER_BYTES:
                raise ScanLimit(member_display, "archive-member-byte-limit")
            member_source = TarMemberReader(source, size)
            findings.extend(
                _scan_member(
                    member_source,
                    name,
                    member_display,
                    size,
                    budget,
                    depth,
                    charge_expanded=False,
                )
            )
            if member_source.remaining:
                raise ArchiveFormatError("truncated tar member")
        else:
            if size:
                raise ScanLimit(member_display, "unsafe-archive-member")
            findings.append(Finding(member_display, "unsafe-archive-member"))
        padding = (-size) % 512
        if padding and _read_exact(source, padding) != b"\0" * padding:
            raise ArchiveFormatError("invalid tar member padding")
    if not saw_end:
        raise ArchiveFormatError("missing tar end marker")
    trailing = 0
    while chunk := source.read(512):
        trailing += len(chunk)
        if trailing > MAX_TAR_TRAILING_PADDING_BYTES:
            raise ScanLimit(display, "tar-trailing-padding-limit")
        if len(chunk) != 512 or any(chunk):
            raise ScanLimit(display, "tar-trailing-data")
    return findings


def _scan_archive(
    source: Any, intent: str, display: Path, budget: ScanBudget, depth: int
) -> list[Finding]:
    findings: list[Finding] = []
    if intent == "zip":
        _zip_member_count(source, display, budget)
        with zipfile.ZipFile(source) as archive:
            seen: set[str] = set()
            for member in archive.infolist():
                raw_display = Path(str(display) + "!" + member.filename)
                budget.member(raw_display)
                try:
                    canonical = _canonical_archive_name(member.filename)
                except ValueError:
                    findings.append(Finding(raw_display, "unsafe-archive-member"))
                    continue
                member_display = Path(str(display) + "!" + canonical)
                mode = (member.external_attr >> 16) & 0o170000
                if canonical in seen:
                    findings.append(Finding(member_display, "unsafe-archive-member"))
                    continue
                seen.add(canonical)
                if member.is_dir():
                    if mode != stat.S_IFDIR or member.file_size != 0 or member.compress_size != 0:
                        findings.append(Finding(member_display, "unsafe-archive-member"))
                    continue
                if mode == stat.S_IFDIR or (mode and mode != stat.S_IFREG):
                    findings.append(Finding(member_display, "unsafe-archive-member"))
                    continue
                with archive.open(member) as member_source:
                    findings.extend(
                        _scan_member(
                            member_source,
                            member.filename,
                            member_display,
                            member.file_size,
                            budget,
                            depth,
                        )
                    )
        return findings
    tar_source = StrictGzipReader(source, display) if intent == "compressed_tar" else source
    return _scan_ustar(ExpandedBudgetReader(tar_source, budget, display), display, budget, depth)


def _scan_file(
    path: Path,
    display: Path,
    budget: ScanBudget,
    candidate: OpenedCandidate | None = None,
    repository_relative_path: PurePosixPath | None = None,
) -> list[Finding]:
    try:
        metadata = path.lstat() if candidate is None else candidate.metadata
        if stat.S_ISLNK(metadata.st_mode):
            return [Finding(display, "filesystem-symlink")]
        if not stat.S_ISREG(metadata.st_mode):
            return [Finding(display, "filesystem-special")]
        budget.file(display)
        descriptor = (
            os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            if candidate is None
            else candidate.fd
        )
        if descriptor is None:
            return [Finding(display, "unreadable-input")]
        if candidate is not None:
            candidate.fd = None
        with os.fdopen(descriptor, "rb") as source:
            opened = os.fstat(source.fileno())
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                return [Finding(display, "input-changed-during-scan")]
            budget.input(display, opened.st_size)
            frozen = FrozenFileView(source, opened.st_size)
            prefix = frozen.read(512)
            frozen.seek(0)
            intent = _archive_intent(path.name, prefix)
            input_limit = (
                MAX_COMPRESSED_ARCHIVE_BYTES
                if intent in {"zip", "compressed_tar"}
                else MAX_RAW_FILE_BYTES
            )
            if opened.st_size > input_limit:
                reason = (
                    "compressed-byte-limit"
                    if intent in {"zip", "compressed_tar"}
                    else "raw-byte-limit"
                )
                return [Finding(display, reason)]
            if intent is not None:
                # Scan every physical archive byte as well as expanded members;
                # this covers ZIP comments/extras, GZip optional headers, and TAR
                # header/reserved bytes that archive libraries do not yield.
                findings = _patterns_stream(
                    display,
                    frozen,
                    expected_size=opened.st_size,
                    byte_limit=input_limit,
                    limit_reason="compressed-byte-limit",
                    repository_relative_path=repository_relative_path,
                )
                frozen.seek(0)
                findings.extend(_scan_archive(frozen, intent, display, budget, 0))
            else:
                findings = _patterns_stream(
                    display,
                    frozen,
                    expected_size=opened.st_size,
                    byte_limit=MAX_RAW_FILE_BYTES,
                    limit_reason="raw-byte-limit",
                    repository_relative_path=repository_relative_path,
                )
            final = os.fstat(source.fileno())
            opened_identity = (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            )
            final_identity = (
                final.st_dev,
                final.st_ino,
                final.st_size,
                final.st_mtime_ns,
                final.st_ctime_ns,
            )
            try:
                if candidate is None:
                    renamed = path.stat(follow_symlinks=False)
                else:
                    assert candidate.name is not None
                    assert candidate.parent_fd is not None
                    renamed = os.stat(
                        candidate.name,
                        dir_fd=candidate.parent_fd,
                        follow_symlinks=False,
                    )
            except OSError:
                return [*findings, Finding(display, "input-changed-during-scan")]
            if (
                final_identity != opened_identity
                or not stat.S_ISREG(renamed.st_mode)
                or (renamed.st_dev, renamed.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                return [*findings, Finding(display, "input-changed-during-scan")]
            return findings
    except ScanLimit as error:
        return [Finding(error.path, error.reason)]
    except (EOFError, RuntimeError, zipfile.BadZipFile):
        return [Finding(display, "corrupt-archive")]
    except OSError:
        return [Finding(display, "unreadable-input")]
    finally:
        if candidate is not None and candidate.fd is not None:
            os.close(candidate.fd)
            candidate.fd = None


class GitInventoryError(ScanLimit):
    pass


@dataclass(frozen=True, slots=True)
class IndexEntry:
    mode: str
    oid: str
    path: PurePosixPath


@dataclass(frozen=True, slots=True)
class IgnoredEntry:
    path: PurePosixPath
    directory: bool


Identity = tuple[int, int, int, int, int, int]
AnchorIdentity = tuple[int, int, int]


@dataclass(slots=True)
class DirectoryBinding:
    path: Path
    paths: tuple[Path, ...]
    names: tuple[str | None, ...]
    fds: tuple[int, ...]
    identities: tuple[AnchorIdentity, ...]

    @classmethod
    def open(cls, path: Path) -> DirectoryBinding:
        path = Path(os.path.abspath(os.fspath(path)))
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        paths = [Path("/")]
        names: list[str | None] = [None]
        fds = [os.open("/", flags)]
        identities = [_anchor_identity(os.fstat(fds[0]))]
        try:
            current = Path("/")
            for part in path.parts[1:]:
                current = current / part
                metadata = os.stat(part, dir_fd=fds[-1], follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    raise ScanLimit(current, "filesystem-symlink-ancestor")
                if not stat.S_ISDIR(metadata.st_mode):
                    raise ScanLimit(current, "filesystem-special")
                child = os.open(part, flags, dir_fd=fds[-1])
                opened = os.fstat(child)
                if _anchor_identity(opened) != _anchor_identity(metadata):
                    os.close(child)
                    raise ScanLimit(current, "input-changed-during-scan")
                paths.append(current)
                names.append(part)
                fds.append(child)
                identities.append(_anchor_identity(opened))
            return cls(path, tuple(paths), tuple(names), tuple(fds), tuple(identities))
        except BaseException:
            for fd in reversed(fds):
                os.close(fd)
            raise

    @property
    def fd(self) -> int:
        return self.fds[-1]

    def revalidate(self) -> None:
        for index, (fd, expected) in enumerate(zip(self.fds, self.identities, strict=True)):
            if _anchor_identity(os.fstat(fd)) != expected:
                raise ScanLimit(self.paths[index], "input-changed-during-scan")
            if index:
                name = self.names[index]
                assert name is not None
                metadata = os.stat(
                    name,
                    dir_fd=self.fds[index - 1],
                    follow_symlinks=False,
                )
                if _anchor_identity(metadata) != expected:
                    raise ScanLimit(self.paths[index], "input-changed-during-scan")

    def close(self) -> None:
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds = ()


@dataclass(slots=True)
class RootBinding:
    path: Path
    parent: DirectoryBinding
    name: str
    fd: int
    identity: Identity
    directory: bool

    @classmethod
    def open(cls, path: Path) -> RootBinding:
        path = Path(os.path.abspath(os.fspath(path)))
        if path == Path("/"):
            raise ScanLimit(path, "root-scope-unsupported")
        parent = DirectoryBinding.open(path.parent)
        try:
            metadata = os.stat(path.name, dir_fd=parent.fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise ScanLimit(path, "filesystem-symlink")
            directory = stat.S_ISDIR(metadata.st_mode)
            if not directory and not stat.S_ISREG(metadata.st_mode):
                raise ScanLimit(path, "filesystem-special")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            if directory:
                flags |= getattr(os, "O_DIRECTORY", 0)
            fd = os.open(path.name, flags, dir_fd=parent.fd)
            opened = os.fstat(fd)
            if _identity(opened) != _identity(metadata):
                os.close(fd)
                raise ScanLimit(path, "input-changed-during-scan")
            return cls(path, parent, path.name, fd, _identity(opened), directory)
        except BaseException:
            parent.close()
            raise

    def revalidate(self) -> None:
        self.parent.revalidate()
        if _identity(os.fstat(self.fd)) != self.identity:
            raise ScanLimit(self.path, "input-changed-during-scan")
        metadata = os.stat(self.name, dir_fd=self.parent.fd, follow_symlinks=False)
        if _identity(metadata) != self.identity:
            raise ScanLimit(self.path, "input-changed-during-scan")

    def ancestry(self) -> tuple[tuple[Path, int, AnchorIdentity], ...]:
        result = []
        if self.directory:
            result.append((self.path, self.fd, _anchor_identity(os.fstat(self.fd))))
        result.extend(
            reversed(
                tuple(zip(self.parent.paths, self.parent.fds, self.parent.identities, strict=True))
            )
        )
        return tuple(result)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
        self.parent.close()


@dataclass(slots=True)
class RepositoryBinding:
    root: RootBinding
    marker_identity: Identity
    object_format: str | None = None

    @property
    def path(self) -> Path:
        return self.root.path

    @property
    def fd(self) -> int:
        return self.root.fd

    def revalidate(self) -> None:
        self.root.revalidate()
        marker = os.stat(".git", dir_fd=self.fd, follow_symlinks=False)
        if _identity(marker) != self.marker_identity:
            raise GitInventoryError(self.path, "git-state-unprovable")

    def close(self) -> None:
        self.root.close()


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    index_raw: bytes
    untracked_raw: bytes
    ignored_raw: bytes
    ignore_sources_raw: bytes
    index: tuple[IndexEntry, ...]
    untracked: tuple[PurePosixPath, ...]
    ignored: tuple[IgnoredEntry, ...]
    ignored_files: frozenset[PurePosixPath]
    ignored_directories: frozenset[PurePosixPath]
    working: tuple[tuple[str, Identity | None], ...]
    ignore_sources: tuple[tuple[str, Identity], ...]


@dataclass(slots=True)
class RootClassification:
    repository: RepositoryBinding | None
    scope: PurePosixPath | None

    @property
    def source(self) -> bool:
        return self.repository is not None and self.scope is not None


def _identity(metadata: os.stat_result) -> Identity:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _anchor_identity(metadata: os.stat_result) -> AnchorIdentity:
    return metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode)


def _git_environment() -> dict[str, str]:
    return {
        "ALL_PROXY": "",
        "GCM_INTERACTIVE": "never",
        "GIT_ASKPASS": "/bin/false",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "LC_ALL": "C",
        "NO_PROXY": "*",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "SSH_ASKPASS": "/bin/false",
        "TMPDIR": "/tmp",
        "all_proxy": "",
        "http_proxy": "",
        "https_proxy": "",
    }


def _git_command(arguments: Sequence[str]) -> tuple[str, ...]:
    return (
        GIT_EXECUTABLE,
        "-c",
        "core.excludesFile=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "maintenance.auto=false",
        "-c",
        "gc.auto=0",
        "--git-dir=.git",
        "--work-tree=.",
        *arguments,
    )


def _git_argv(repository: RepositoryBinding, arguments: Sequence[str]) -> tuple[str, ...]:
    return (
        sys.executable,
        "-I",
        "-S",
        "-c",
        GIT_FD_EXEC_HELPER,
        str(repository.fd),
        *_git_command(arguments),
    )


def _wait_process(process: subprocess.Popen[bytes], deadline: float, path: Path) -> int:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise GitInventoryError(path, "git-inventory-timeout")
    try:
        return process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as error:
        raise GitInventoryError(path, "git-inventory-timeout") from error


def _bounded_git_deadline(path: Path, deadline: float | None = None) -> float:
    now = time.monotonic()
    effective_deadline = now + GIT_TIMEOUT_SECONDS
    if deadline is not None:
        effective_deadline = min(effective_deadline, deadline)
    if effective_deadline <= now:
        raise GitInventoryError(path, "git-inventory-timeout")
    return effective_deadline


def _ensure_git_deadline(path: Path, deadline: float) -> None:
    if deadline - time.monotonic() <= 0:
        raise GitInventoryError(path, "git-inventory-timeout")


def _kill_and_reap(process: subprocess.Popen[bytes], path: Path) -> None:
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=GIT_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise GitInventoryError(path, "git-process-reap-timeout") from error


def _run_git(
    repository: RepositoryBinding,
    arguments: Sequence[str],
    *,
    max_bytes: int,
    allowed_returncodes: tuple[int, ...] = (0,),
    deadline: float | None = None,
) -> tuple[int, bytes]:
    repository.revalidate()
    effective_deadline = _bounded_git_deadline(repository.path, deadline)
    process = subprocess.Popen(
        _git_argv(repository, arguments),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        env=_git_environment(),
        pass_fds=(repository.fd,),
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    output = bytearray()
    errors = bytearray()
    try:
        while selector.get_map():
            remaining = effective_deadline - time.monotonic()
            if remaining <= 0:
                raise GitInventoryError(repository.path, "git-inventory-timeout")
            ready = selector.select(remaining)
            if not ready:
                raise GitInventoryError(repository.path, "git-inventory-timeout")
            for key, _ in ready:
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = output if key.data == "stdout" else errors
                target.extend(chunk)
                limit = max_bytes if key.data == "stdout" else MAX_GIT_STDERR_BYTES
                if len(target) > limit:
                    raise GitInventoryError(repository.path, "git-inventory-output-limit")
        returncode = _wait_process(process, effective_deadline, repository.path)
        if returncode not in allowed_returncodes or errors:
            raise GitInventoryError(repository.path, "git-inventory-failed")
        repository.revalidate()
        return returncode, bytes(output)
    except subprocess.SubprocessError as error:
        raise GitInventoryError(repository.path, "git-inventory-failed") from error
    finally:
        selector.close()
        _kill_and_reap(process, repository.path)


def _git_output(
    repository: RepositoryBinding,
    arguments: Sequence[str],
    *,
    max_bytes: int,
    deadline: float | None = None,
) -> bytes:
    return _run_git(repository, arguments, max_bytes=max_bytes, deadline=deadline)[1]


def _repository_for(root: RootBinding) -> RepositoryBinding | None:
    for path, directory_fd, expected_identity in root.ancestry():
        try:
            marker = os.stat(".git", dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise GitInventoryError(path, "git-state-unprovable") from error
        if stat.S_ISLNK(marker.st_mode) or not (
            stat.S_ISDIR(marker.st_mode) or stat.S_ISREG(marker.st_mode)
        ):
            raise GitInventoryError(path, "git-state-unprovable")
        candidate = RootBinding.open(path)
        if _anchor_identity(os.fstat(candidate.fd)) != expected_identity:
            candidate.close()
            raise GitInventoryError(path, "git-state-unprovable")
        repository = RepositoryBinding(candidate, _identity(marker))
        break
    else:
        return None
    try:
        state = _git_output(
            repository,
            ("rev-parse", "--is-inside-work-tree", "--is-inside-git-dir"),
            max_bytes=64,
        )
        if state != b"true\nfalse\n":
            raise GitInventoryError(repository.path, "git-state-unprovable")
        object_format = _git_output(
            repository,
            ("rev-parse", "--show-object-format"),
            max_bytes=16,
        )
        if object_format not in {b"sha1\n", b"sha256\n"}:
            raise GitInventoryError(repository.path, "git-object-format-unsupported")
        repository.object_format = object_format[:-1].decode("ascii")
        repository.revalidate()
        return repository
    except BaseException:
        repository.close()
        raise


def _canonical_git_path(
    raw: bytes,
    repository: Path,
    scope: PurePosixPath,
) -> PurePosixPath:
    if not raw or len(raw) > 4096:
        raise GitInventoryError(repository, "git-inventory-malformed")
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GitInventoryError(repository, "git-inventory-malformed") from error
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or "\\" in value
        or any(part in {"", ".", ".."} for part in path.parts)
        or (scope != PurePosixPath(".") and path != scope and scope not in path.parents)
    ):
        raise GitInventoryError(repository, "git-inventory-malformed")
    return path


def _nul_records(raw: bytes, repository: Path) -> tuple[bytes, ...]:
    if not raw:
        return ()
    if not raw.endswith(b"\0"):
        raise GitInventoryError(repository, "git-inventory-malformed")
    records = tuple(raw[:-1].split(b"\0"))
    if len(records) > MAX_PATH_ENTRIES or any(not record for record in records):
        raise GitInventoryError(repository, "path-entry-limit")
    return records


def _parse_index_inventory(
    raw: bytes,
    repository: Path,
    scope: PurePosixPath,
    object_format: str,
) -> tuple[IndexEntry, ...]:
    result = []
    seen = set()
    for record in _nul_records(raw, repository):
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, oid, stage = header.split(b" ")
        except ValueError as error:
            raise GitInventoryError(repository, "git-inventory-malformed") from error
        if stage not in {b"0", b"1", b"2", b"3"}:
            raise GitInventoryError(repository, "git-inventory-malformed")
        path = _canonical_git_path(raw_path, repository, scope)
        if stage != b"0":
            raise GitInventoryError(repository / Path(path.as_posix()), "git-index-conflict")
        if mode not in {b"100644", b"100755"}:
            raise GitInventoryError(repository / Path(path.as_posix()), "git-index-mode-invalid")
        oid_width = 40 if object_format == "sha1" else 64
        if len(oid) != oid_width or re.fullmatch(rb"[0-9a-f]+", oid) is None:
            raise GitInventoryError(repository, "git-inventory-malformed")
        if path in seen:
            raise GitInventoryError(repository, "git-inventory-malformed")
        seen.add(path)
        result.append(IndexEntry(mode.decode("ascii"), oid.decode("ascii"), path))
    return tuple(result)


def _parse_untracked_inventory(
    raw: bytes,
    repository: Path,
    scope: PurePosixPath,
) -> tuple[PurePosixPath, ...]:
    result = []
    seen = set()
    for record in _nul_records(raw, repository):
        path = _canonical_git_path(record, repository, scope)
        if path in seen:
            raise GitInventoryError(repository, "git-inventory-malformed")
        seen.add(path)
        result.append(path)
    return tuple(result)


def _parse_ignored_inventory(
    raw: bytes,
    repository: Path,
    scope: PurePosixPath,
) -> tuple[IgnoredEntry, ...]:
    result = []
    seen = set()
    for record in _nul_records(raw, repository):
        directory = record.endswith(b"/")
        canonical = record[:-1] if directory else record
        path = _canonical_git_path(canonical, repository, scope)
        if path in seen:
            raise GitInventoryError(repository, "git-inventory-malformed")
        seen.add(path)
        result.append(IgnoredEntry(path, directory))
    return tuple(result)


def _captured_identity(
    repository: RepositoryBinding,
    relative: PurePosixPath,
) -> Identity | None:
    try:
        for candidate in _open_relative_candidate(
            repository.fd,
            repository.path,
            Path(relative.as_posix()),
            None,
        ):
            identity = _identity(candidate.metadata)
            if candidate.fd is not None:
                os.close(candidate.fd)
                candidate.fd = None
            return identity
    except FileNotFoundError:
        return None
    raise GitInventoryError(repository.path, "git-inventory-malformed")


def _capture_source_snapshot(
    repository: RepositoryBinding,
    scope: PurePosixPath,
) -> SourceSnapshot:
    pathspec = scope.as_posix()
    index_raw = _git_output(
        repository,
        ("ls-files", "--stage", "-z", "--", pathspec),
        max_bytes=MAX_GIT_INVENTORY_BYTES,
    )
    untracked_raw = _git_output(
        repository,
        (
            "ls-files",
            "--others",
            "--exclude-per-directory=.gitignore",
            "-z",
            "--",
            pathspec,
        ),
        max_bytes=MAX_GIT_INVENTORY_BYTES,
    )
    ignored_raw = _git_output(
        repository,
        (
            "ls-files",
            "--others",
            "--ignored",
            "--directory",
            "--exclude-per-directory=.gitignore",
            "-z",
            "--",
            pathspec,
        ),
        max_bytes=MAX_GIT_INVENTORY_BYTES,
    )
    ignore_sources_raw = _git_output(
        repository,
        (
            "ls-files",
            "--cached",
            "--others",
            "-z",
            "--",
            ".gitignore",
            ":(glob)**/.gitignore",
        ),
        max_bytes=MAX_GIT_INVENTORY_BYTES,
    )
    assert repository.object_format is not None
    index = _parse_index_inventory(
        index_raw,
        repository.path,
        scope,
        repository.object_format,
    )
    untracked = _parse_untracked_inventory(untracked_raw, repository.path, scope)
    ignored = _parse_ignored_inventory(ignored_raw, repository.path, scope)
    ignore_sources = _parse_untracked_inventory(
        ignore_sources_raw,
        repository.path,
        PurePosixPath("."),
    )
    tracked_paths = tuple(entry.path for entry in index)
    if set(tracked_paths) & set(untracked):
        raise GitInventoryError(repository.path, "git-inventory-malformed")
    if (set(tracked_paths) | set(untracked)) & {entry.path for entry in ignored}:
        raise GitInventoryError(repository.path, "git-inventory-malformed")
    working = []
    untracked_set = set(untracked)
    for relative in (*tracked_paths, *untracked):
        try:
            identity = _captured_identity(repository, relative)
        except OSError as error:
            raise GitInventoryError(
                repository.path / Path(relative.as_posix()),
                "unreadable-input",
            ) from error
        if identity is None and relative in untracked_set:
            raise GitInventoryError(
                repository.path / Path(relative.as_posix()),
                "source-inventory-drift",
            )
        working.append((relative.as_posix(), identity))
    captured_ignores = []
    for relative in ignore_sources:
        identity = _captured_identity(repository, relative)
        if identity is None:
            raise GitInventoryError(
                repository.path / Path(relative.as_posix()),
                "source-inventory-drift",
            )
        captured_ignores.append((relative.as_posix(), identity))
    repository.revalidate()
    return SourceSnapshot(
        index_raw=index_raw,
        untracked_raw=untracked_raw,
        ignored_raw=ignored_raw,
        ignore_sources_raw=ignore_sources_raw,
        index=index,
        untracked=untracked,
        ignored=ignored,
        ignored_files=frozenset(entry.path for entry in ignored if not entry.directory),
        ignored_directories=frozenset(entry.path for entry in ignored if entry.directory),
        working=tuple(working),
        ignore_sources=tuple(captured_ignores),
    )


def _is_explicit_artifact(root: Path, repository: Path) -> bool:
    relative = root.relative_to(repository)
    lowered = tuple(part.lower() for part in relative.parts)
    if any(part in GENERATED_ROOT_PARTS | ARTIFACT_ROOT_PARTS for part in lowered):
        return True
    name = root.name.lower()
    if name.endswith(ARCHIVE_ROOT_SUFFIXES):
        return True
    return Path(name).stem in ARTIFACT_ROOT_PARTS


def _classify_root(root: RootBinding) -> RootClassification:
    repository = _repository_for(root)
    if repository is None:
        return RootClassification(None, None)
    try:
        relative = root.path.relative_to(repository.path)
    except ValueError as error:
        repository.close()
        raise GitInventoryError(root.path, "git-state-unprovable") from error
    scope = PurePosixPath(".") if not relative.parts else PurePosixPath(relative.as_posix())
    if scope == PurePosixPath("."):
        return RootClassification(repository, scope)
    if _is_explicit_artifact(root.path, repository.path):
        repository.close()
        return RootClassification(None, None)
    try:
        returncode, output = _run_git(
            repository,
            ("check-ignore", "--no-index", "-q", "--", scope.as_posix()),
            max_bytes=1,
            allowed_returncodes=(0, 1),
        )
    except BaseException:
        repository.close()
        raise
    if output:
        repository.close()
        raise GitInventoryError(root.path, "git-inventory-malformed")
    if returncode == 0:
        repository.close()
        return RootClassification(None, None)
    return RootClassification(repository, scope)


def _opened_candidate(
    parent_fd: int,
    name: str,
    path: Path,
    expected_identity: Identity | None = None,
) -> OpenedCandidate:
    metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if expected_identity is not None and _identity(metadata) != expected_identity:
        raise ScanLimit(path, "input-changed-during-scan")
    if not stat.S_ISREG(metadata.st_mode):
        return OpenedCandidate(path, metadata, None, parent_fd, name)
    fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
    opened = os.fstat(fd)
    if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
        os.close(fd)
        raise ScanLimit(path, "input-changed-during-scan")
    return OpenedCandidate(path, metadata, fd, parent_fd, name)


def _open_relative_candidate(
    root_fd: int,
    root: Path,
    relative: Path,
    expected_identity: Identity | None,
) -> Iterator[OpenedCandidate]:
    current = os.dup(root_fd)
    try:
        for index, part in enumerate(relative.parts):
            path = root.joinpath(*relative.parts[: index + 1])
            if index == len(relative.parts) - 1:
                yield _opened_candidate(current, part, path, expected_identity)
                return
            metadata = os.stat(part, dir_fd=current, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise ScanLimit(path, "filesystem-symlink")
            if not stat.S_ISDIR(metadata.st_mode):
                raise ScanLimit(path, "filesystem-special")
            child = os.open(
                part,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current,
            )
            opened = os.fstat(child)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                os.close(child)
                raise ScanLimit(path, "input-changed-during-scan")
            os.close(current)
            current = child
    finally:
        os.close(current)


def _walk_directory(
    root: Path,
    directory: Path,
    directory_fd: int,
    budget: ScanBudget,
    *,
    depth: int,
) -> Iterator[OpenedCandidate]:
    if depth > 64:
        raise ScanLimit(directory, "directory-depth-limit")
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            path = directory / entry.name
            relative = path.relative_to(root)
            budget.path_entry(relative)
            metadata = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(
                    entry.name,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    os.close(child)
                    raise ScanLimit(path, "input-changed-during-scan")
                try:
                    yield from _walk_directory(root, path, child, budget, depth=depth + 1)
                    renamed = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
                    if _identity(renamed) != _identity(opened):
                        raise ScanLimit(path, "input-changed-during-scan")
                finally:
                    os.close(child)
                continue
            yield _opened_candidate(directory_fd, entry.name, path, _identity(metadata))


def _walk(root: RootBinding, budget: ScanBudget) -> Iterator[OpenedCandidate]:
    root_fd = os.dup(root.fd)
    opened = os.fstat(root_fd)
    try:
        root.revalidate()
        if not stat.S_ISDIR(opened.st_mode) or _identity(opened) != root.identity:
            raise ScanLimit(root.path, "input-changed-during-scan")
        yield from _walk_directory(root.path, root.path, root_fd, budget, depth=0)
        root.revalidate()
    finally:
        os.close(root_fd)


def _joined_git_path(parent: PurePosixPath, name: str) -> PurePosixPath:
    return PurePosixPath(name) if parent == PurePosixPath(".") else parent / name


def _ignored_by_snapshot(path: PurePosixPath, snapshot: SourceSnapshot) -> bool:
    if path in snapshot.ignored_files:
        return True
    return any(parent in snapshot.ignored_directories for parent in (path, *path.parents))


def _physical_source_directory(
    root: RootBinding,
    repository: RepositoryBinding,
    directory_fd: int,
    directory_path: Path,
    relative: PurePosixPath,
    candidates: set[PurePosixPath],
    snapshot: SourceSnapshot,
    budget: ScanBudget,
    depth: int,
) -> None:
    if depth > 64:
        raise ScanLimit(directory_path, "directory-depth-limit")
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            path = directory_path / entry.name
            child_relative = _joined_git_path(relative, entry.name)
            if relative == PurePosixPath(".") and entry.name == ".git":
                marker = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
                if _identity(marker) != repository.marker_identity:
                    raise GitInventoryError(repository.path, "git-state-unprovable")
                continue
            budget.path_entry(Path(child_relative.as_posix()))
            metadata = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
            if _ignored_by_snapshot(child_relative, snapshot):
                continue
            if stat.S_ISLNK(metadata.st_mode):
                raise ScanLimit(path, "filesystem-symlink")
            if stat.S_ISDIR(metadata.st_mode):
                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
                child = os.open(entry.name, flags, dir_fd=directory_fd)
                opened = os.fstat(child)
                if _identity(opened) != _identity(metadata):
                    os.close(child)
                    raise ScanLimit(path, "input-changed-during-scan")
                try:
                    _physical_source_directory(
                        root,
                        repository,
                        child,
                        path,
                        child_relative,
                        candidates,
                        snapshot,
                        budget,
                        depth + 1,
                    )
                    renamed = os.stat(
                        entry.name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    if _identity(renamed) != _identity(opened):
                        raise ScanLimit(path, "input-changed-during-scan")
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ScanLimit(path, "filesystem-special")
            if child_relative not in candidates:
                raise GitInventoryError(path, "source-inventory-incomplete")
    root.revalidate()


def _supplement_source_inventory(
    root: RootBinding,
    classification: RootClassification,
    snapshot: SourceSnapshot,
    budget: ScanBudget,
) -> None:
    repository = classification.repository
    scope = classification.scope
    assert repository is not None and scope is not None
    candidates = {entry.path for entry in snapshot.index} | set(snapshot.untracked)
    if root.directory:
        directory_fd = os.dup(root.fd)
        try:
            _physical_source_directory(
                root,
                repository,
                directory_fd,
                root.path,
                scope,
                candidates,
                snapshot,
                budget,
                0,
            )
        finally:
            os.close(directory_fd)
    elif scope not in candidates:
        raise GitInventoryError(root.path, "source-inventory-incomplete")
    root.revalidate()
    repository.revalidate()


def _terminal_limit(findings: Sequence[Finding]) -> bool:
    return bool(findings) and findings[-1].reason in {
        "path-entry-limit",
        "file-count-limit",
        "total-input-byte-limit",
        "archive-member-limit",
        "cumulative-expanded-byte-limit",
    }


def _source_display(
    root: RootBinding,
    repository: RepositoryBinding,
    relative: PurePosixPath,
    *,
    index: bool,
) -> Path:
    if index:
        return Path("<git-index>") / Path(relative.as_posix())
    if not root.directory:
        return root.path
    scope = root.path.relative_to(repository.path)
    visible = relative if not scope.parts else relative.relative_to(PurePosixPath(scope.as_posix()))
    return Path(visible.as_posix())


def _parse_batch_header(header: bytes, expected_oid: str, display: Path) -> int:
    if header == b"missing\n" or header.endswith(b" missing\n"):
        raise GitInventoryError(display, "git-batch-object-missing")
    if not header.endswith(b"\n") or len(header) > 256:
        raise GitInventoryError(display, "git-batch-framing")
    fields = header[:-1].split(b" ")
    if len(fields) != 3:
        raise GitInventoryError(display, "git-batch-framing")
    raw_oid, object_type, raw_size = fields
    if object_type != b"blob":
        raise GitInventoryError(display, "git-batch-type-invalid")
    if raw_oid != expected_oid.encode("ascii"):
        raise GitInventoryError(display, "git-batch-oid-mismatch")
    if (
        not raw_size
        or re.fullmatch(rb"[0-9]+", raw_size) is None
        or (len(raw_size) > 1 and raw_size.startswith(b"0"))
    ):
        raise GitInventoryError(display, "git-batch-size-invalid")
    return int(raw_size)


def _validate_batch_delimiter(delimiter: bytes, display: Path) -> None:
    if not delimiter:
        raise GitInventoryError(display, "git-batch-short-read")
    if delimiter == b"\n":
        return
    if delimiter.startswith(b"\n"):
        raise GitInventoryError(display, "git-batch-trailing-data")
    raise GitInventoryError(display, "git-batch-framing")


class DigestingWriter:
    def __init__(self, destination: BinaryWriter, digest: Any) -> None:
        self.destination = destination
        self.digest = digest

    def write(self, value: bytes) -> int:
        self.digest.update(value)
        return self.destination.write(value)


class GitBatch:
    def __init__(self, repository: RepositoryBinding, process: subprocess.Popen[bytes]):
        self.repository = repository
        self.process = process
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        self.stdin = process.stdin
        self.stdout = process.stdout
        self.stderr = process.stderr
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.stdout, selectors.EVENT_READ, "stdout")
        self.selector.register(self.stderr, selectors.EVENT_READ, "stderr")
        self.output = bytearray()
        self.errors = bytearray()
        self.deadline = time.monotonic() + GIT_TIMEOUT_SECONDS

    def __enter__(self) -> GitBatch:
        return self

    def _pump(self, display: Path) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise GitInventoryError(display, "git-inventory-timeout")
        ready = self.selector.select(remaining)
        if not ready:
            raise GitInventoryError(display, "git-inventory-timeout")
        for key, _ in ready:
            chunk = os.read(key.fd, 64 * 1024)
            if not chunk:
                self.selector.unregister(key.fileobj)
                continue
            target = self.output if key.data == "stdout" else self.errors
            target.extend(chunk)
            if key.data == "stdout" and len(target) > MAX_GIT_BATCH_BUFFER_BYTES:
                raise GitInventoryError(display, "git-batch-output-limit")
            if key.data == "stderr" and len(target) > MAX_GIT_STDERR_BYTES:
                raise GitInventoryError(display, "git-inventory-output-limit")

    def _read_exact(self, size: int, display: Path) -> bytes:
        while len(self.output) < size:
            if self.stdout not in self.selector.get_map():
                raise GitInventoryError(display, "git-batch-short-read")
            self._pump(display)
        value = bytes(self.output[:size])
        del self.output[:size]
        return value

    def _readline(self, display: Path) -> bytes:
        while b"\n" not in self.output:
            if len(self.output) > 256:
                raise GitInventoryError(display, "git-batch-framing")
            if self.stdout not in self.selector.get_map():
                raise GitInventoryError(display, "git-batch-short-read")
            self._pump(display)
        end = self.output.index(b"\n") + 1
        value = bytes(self.output[:end])
        del self.output[:end]
        return value

    def _copy_body(
        self,
        destination: BinaryWriter,
        declared_size: int,
        display: Path,
        budget: ScanBudget,
    ) -> None:
        remaining = declared_size
        while remaining:
            chunk = self._read_exact(min(STREAM_CHUNK_BYTES, remaining), display)
            destination.write(chunk)
            remaining -= len(chunk)

    @contextmanager
    def blob(
        self, entry: IndexEntry, budget: ScanBudget
    ) -> Iterator[tuple[FrozenFileView, int, Path]]:
        display = Path("<git-index>") / Path(entry.path.as_posix())
        self.deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
        try:
            self.stdin.write(entry.oid.encode("ascii") + b"\n")
            self.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            raise GitInventoryError(display, "git-inventory-failed") from error
        declared_size = _parse_batch_header(self._readline(display), entry.oid, display)
        if declared_size > MAX_RAW_FILE_BYTES:
            raise ScanLimit(display, "raw-byte-limit")
        budget.path_entry(display)
        budget.file(display)
        budget.input(display, declared_size)
        object_format = self.repository.object_format
        if object_format not in {"sha1", "sha256"}:
            raise GitInventoryError(display, "git-object-format-unsupported")
        digest = hashlib.new(object_format)
        digest.update(b"blob " + str(declared_size).encode("ascii") + b"\0")
        with tempfile.TemporaryFile() as source:
            self._copy_body(
                DigestingWriter(source, digest),
                declared_size,
                display,
                budget,
            )
            _validate_batch_delimiter(self._read_exact(1, display), display)
            if digest.hexdigest() != entry.oid:
                raise GitInventoryError(display, "git-batch-content-oid-mismatch")
            source.seek(0)
            yield FrozenFileView(source, declared_size), declared_size, display

    def _finish(self) -> None:
        self.stdin.close()
        self.deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
        while self.selector.get_map():
            self._pump(self.repository.path)
        if self.output:
            raise GitInventoryError(self.repository.path, "git-batch-trailing-data")
        if self.errors:
            raise GitInventoryError(self.repository.path, "git-inventory-failed")
        returncode = _wait_process(
            self.process,
            self.deadline,
            self.repository.path,
        )
        if returncode != 0:
            raise GitInventoryError(self.repository.path, "git-inventory-failed")
        self.repository.revalidate()

    def _terminate(self) -> None:
        _kill_and_reap(self.process, self.repository.path)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: Any,
    ) -> Literal[False]:
        try:
            if exc_type is None:
                self._finish()
            else:
                self._terminate()
        finally:
            self.selector.close()
            if self.process.poll() is None:
                self._terminate()
        return False


def _parse_history_header(
    header: bytes,
    object_format: str | None,
    repository: Path,
) -> tuple[str, bytes, int]:
    if not header.endswith(b"\n") or len(header) > 256:
        raise GitInventoryError(repository, "git-batch-framing")
    fields = header[:-1].split(b" ")
    if len(fields) != 3:
        raise GitInventoryError(repository, "git-batch-framing")
    raw_oid, object_type, raw_size = fields
    if object_format not in {"sha1", "sha256"}:
        raise GitInventoryError(repository, "git-object-format-unsupported")
    oid_width = 40 if object_format == "sha1" else 64
    if len(raw_oid) != oid_width or re.fullmatch(rb"[0-9a-f]+", raw_oid) is None:
        raise GitInventoryError(repository, "git-batch-oid-mismatch")
    if object_type not in {b"blob", b"tree", b"commit", b"tag"}:
        raise GitInventoryError(repository, "git-batch-type-invalid")
    if (
        not raw_size
        or re.fullmatch(rb"[0-9]+", raw_size) is None
        or (len(raw_size) > 1 and raw_size.startswith(b"0"))
    ):
        raise GitInventoryError(repository, "git-batch-size-invalid")
    return raw_oid.decode("ascii"), object_type, int(raw_size)


def _parse_history_commit_inventory(
    raw: bytes,
    repository: Path,
    object_format: str | None,
) -> tuple[str, ...]:
    if object_format not in {"sha1", "sha256"}:
        raise GitInventoryError(repository, "git-object-format-unsupported")
    oid_width = 40 if object_format == "sha1" else 64
    commits = raw.splitlines()
    if any(
        len(commit) != oid_width or re.fullmatch(rb"[0-9a-f]+", commit) is None
        for commit in commits
    ):
        raise GitInventoryError(repository, "git-inventory-malformed")
    return tuple(commit.decode("ascii") for commit in commits)


def _parse_history_tree_inventory(
    raw: bytes,
    repository: Path,
    object_format: str | None,
    budget: ScanBudget,
) -> dict[str, set[PurePosixPath]]:
    if object_format not in {"sha1", "sha256"}:
        raise GitInventoryError(repository, "git-object-format-unsupported")
    oid_width = 40 if object_format == "sha1" else 64
    result: dict[str, set[PurePosixPath]] = {}
    for record in _nul_records(raw, repository):
        try:
            header, raw_path = record.split(b"\t", 1)
            raw_mode, object_type, raw_oid = header.split(b" ")
        except ValueError as error:
            raise GitInventoryError(repository, "git-inventory-malformed") from error
        if (
            raw_mode not in {b"100644", b"100755", b"120000", b"160000"}
            or object_type not in {b"blob", b"commit"}
            or len(raw_oid) != oid_width
            or re.fullmatch(rb"[0-9a-f]+", raw_oid) is None
        ):
            raise GitInventoryError(repository, "git-inventory-malformed")
        relative = _canonical_git_path(raw_path, repository, PurePosixPath("."))
        budget.path_entry(Path("<git-history>") / Path(relative.as_posix()))
        if object_type != b"blob":
            continue
        oid = raw_oid.decode("ascii")
        oid_paths = result.setdefault(oid, set())
        oid_paths.add(relative)
        if len(oid_paths) > MAX_HISTORY_BLOB_PATHS:
            raise GitInventoryError(
                Path("<git-history>") / oid,
                "history-blob-path-fanout-limit",
            )
    return result


def _history_path_inventory(
    repository: RepositoryBinding,
    budget: ScanBudget,
) -> dict[str, frozenset[PurePosixPath]]:
    deadline = time.monotonic() + MAX_HISTORY_INVENTORY_SECONDS
    remaining = MAX_GIT_INVENTORY_BYTES
    commits_raw = _git_output(
        repository,
        ("rev-list", "--all"),
        max_bytes=remaining,
        deadline=deadline,
    )
    remaining -= len(commits_raw)
    commits = _parse_history_commit_inventory(
        commits_raw,
        repository.path,
        repository.object_format,
    )
    if len(commits) > MAX_HISTORY_COMMITS:
        raise GitInventoryError(repository.path, "git-history-commit-limit")
    paths: dict[str, set[PurePosixPath]] = {}
    for commit in commits:
        if remaining <= 0:
            raise GitInventoryError(repository.path, "git-inventory-output-limit")
        _ensure_git_deadline(repository.path, deadline)
        tree_raw = _git_output(
            repository,
            ("ls-tree", "-rz", "-r", "--full-tree", commit),
            max_bytes=remaining,
            deadline=deadline,
        )
        remaining -= len(tree_raw)
        for oid, tree_paths in _parse_history_tree_inventory(
            tree_raw,
            repository.path,
            repository.object_format,
            budget,
        ).items():
            oid_paths = paths.setdefault(oid, set())
            oid_paths.update(tree_paths)
            if len(oid_paths) > MAX_HISTORY_BLOB_PATHS:
                raise GitInventoryError(
                    Path("<git-history>") / oid,
                    "history-blob-path-fanout-limit",
                )
    return {oid: frozenset(tree_paths) for oid, tree_paths in paths.items()}


class GitHistoryStream:
    def __init__(self, repository: RepositoryBinding, process: subprocess.Popen[bytes]) -> None:
        self.repository = repository
        self.process = process
        assert process.stdout is not None
        assert process.stderr is not None
        self.stdout = process.stdout
        self.stderr = process.stderr
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.stdout, selectors.EVENT_READ, "stdout")
        self.selector.register(self.stderr, selectors.EVENT_READ, "stderr")
        self.output = bytearray()
        self.errors = bytearray()
        self.deadline = time.monotonic() + GIT_TIMEOUT_SECONDS

    def __enter__(self) -> GitHistoryStream:
        return self

    def _pump(self, display: Path) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise GitInventoryError(display, "git-inventory-timeout")
        ready = self.selector.select(remaining)
        if not ready:
            raise GitInventoryError(display, "git-inventory-timeout")
        for key, _ in ready:
            chunk = os.read(key.fd, 64 * 1024)
            if not chunk:
                self.selector.unregister(key.fileobj)
                continue
            target = self.output if key.data == "stdout" else self.errors
            target.extend(chunk)
            if key.data == "stdout" and len(target) > MAX_GIT_BATCH_BUFFER_BYTES:
                raise GitInventoryError(display, "git-batch-output-limit")
            if key.data == "stderr" and len(target) > MAX_GIT_STDERR_BYTES:
                raise GitInventoryError(display, "git-inventory-output-limit")

    def _read_exact(self, size: int, display: Path) -> bytes:
        while len(self.output) < size:
            if self.stdout not in self.selector.get_map():
                raise GitInventoryError(display, "git-batch-short-read")
            self._pump(display)
        value = bytes(self.output[:size])
        del self.output[:size]
        return value

    def _readline_or_eof(self) -> bytes | None:
        while b"\n" not in self.output:
            if len(self.output) > 256:
                raise GitInventoryError(self.repository.path, "git-batch-framing")
            if self.stdout not in self.selector.get_map():
                if self.output:
                    raise GitInventoryError(self.repository.path, "git-batch-short-read")
                return None
            self._pump(self.repository.path)
        end = self.output.index(b"\n") + 1
        value = bytes(self.output[:end])
        del self.output[:end]
        return value

    def _copy_body(
        self,
        destination: BinaryWriter,
        declared_size: int,
        display: Path,
    ) -> None:
        remaining = declared_size
        while remaining:
            chunk = self._read_exact(min(STREAM_CHUNK_BYTES, remaining), display)
            destination.write(chunk)
            remaining -= len(chunk)

    def objects(
        self,
        budget: ScanBudget,
    ) -> Iterator[tuple[str, FrozenFileView, int, Path, bytes]]:
        seen: set[str] = set()
        while True:
            self.deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
            header = self._readline_or_eof()
            if header is None:
                return
            oid, object_type, declared_size = _parse_history_header(
                header,
                self.repository.object_format,
                self.repository.path,
            )
            display = Path("<git-history>") / oid
            if oid in seen:
                raise GitInventoryError(display, "git-inventory-malformed")
            seen.add(oid)
            if declared_size > MAX_RAW_FILE_BYTES:
                raise ScanLimit(display, "raw-byte-limit")
            budget.path_entry(display)
            budget.file(display)
            budget.input(display, declared_size)
            object_format = self.repository.object_format
            assert object_format is not None
            digest = hashlib.new(object_format)
            digest.update(object_type + b" " + str(declared_size).encode("ascii") + b"\0")
            with tempfile.TemporaryFile() as source:
                self._copy_body(DigestingWriter(source, digest), declared_size, display)
                _validate_batch_delimiter(self._read_exact(1, display), display)
                if digest.hexdigest() != oid:
                    raise GitInventoryError(display, "git-batch-content-oid-mismatch")
                source.seek(0)
                yield (
                    oid,
                    FrozenFileView(source, declared_size),
                    declared_size,
                    display,
                    object_type,
                )

    def _finish(self) -> None:
        self.deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
        while self.selector.get_map():
            self._pump(self.repository.path)
        if self.output:
            raise GitInventoryError(self.repository.path, "git-batch-trailing-data")
        if self.errors:
            raise GitInventoryError(self.repository.path, "git-inventory-failed")
        returncode = _wait_process(self.process, self.deadline, self.repository.path)
        if returncode != 0:
            raise GitInventoryError(self.repository.path, "git-inventory-failed")
        self.repository.revalidate()

    def _terminate(self) -> None:
        _kill_and_reap(self.process, self.repository.path)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: Any,
    ) -> Literal[False]:
        try:
            if exc_type is None:
                self._finish()
            else:
                self._terminate()
        finally:
            self.selector.close()
            if self.process.poll() is None:
                self._terminate()
        return False


def _start_git_batch(repository: RepositoryBinding) -> GitBatch:
    repository.revalidate()
    process = subprocess.Popen(
        _git_argv(repository, ("cat-file", "--batch")),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        env=_git_environment(),
        pass_fds=(repository.fd,),
    )
    return GitBatch(repository, process)


def _start_git_history(repository: RepositoryBinding) -> GitHistoryStream:
    repository.revalidate()
    process = subprocess.Popen(
        _git_argv(repository, ("cat-file", "--batch-all-objects", "--batch")),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        env=_git_environment(),
        pass_fds=(repository.fd,),
    )
    return GitHistoryStream(repository, process)


def _history_connectivity_finding(repository: RepositoryBinding) -> Finding | None:
    output = _git_output(
        repository,
        ("rev-list", "--objects", "--all", "--missing=print", "--no-object-names"),
        max_bytes=MAX_GIT_INVENTORY_BYTES,
    )
    if repository.object_format not in {"sha1", "sha256"}:
        raise GitInventoryError(repository.path, "git-object-format-unsupported")
    oid_width = 40 if repository.object_format == "sha1" else 64
    for line in output.splitlines():
        missing = line.startswith(b"?")
        raw_oid = line[1:] if missing else line
        if len(raw_oid) != oid_width or re.fullmatch(rb"[0-9a-f]+", raw_oid) is None:
            raise GitInventoryError(repository.path, "git-inventory-malformed")
        if missing:
            oid = raw_oid.decode("ascii")
            return Finding(Path("<git-history>") / oid, "git-history-object-missing")
    return None


def _scan_index_blob(
    batch: GitBatch,
    entry: IndexEntry,
    budget: ScanBudget,
) -> list[Finding]:
    with batch.blob(entry, budget) as (source, declared_size, display):
        prefix = source.read(512)
        source.seek(0)
        intent = _archive_intent(entry.path.name, prefix)
        limit = (
            MAX_COMPRESSED_ARCHIVE_BYTES
            if intent in {"zip", "compressed_tar"}
            else MAX_RAW_FILE_BYTES
        )
        if declared_size > limit:
            reason = (
                "compressed-byte-limit" if intent in {"zip", "compressed_tar"} else "raw-byte-limit"
            )
            return [Finding(display, reason)]
        findings = _patterns_stream(
            display,
            source,
            expected_size=declared_size,
            byte_limit=limit,
            limit_reason=(
                "compressed-byte-limit" if intent in {"zip", "compressed_tar"} else "raw-byte-limit"
            ),
            repository_relative_path=entry.path,
        )
        if intent is not None:
            source.seek(0)
            findings.extend(_scan_archive(source, intent, display, budget, 0))
        return findings


def _scan_git_history(
    repository: RepositoryBinding,
    budget: ScanBudget,
) -> list[Finding]:
    findings: list[Finding] = []
    history_paths: Mapping[str, frozenset[PurePosixPath]]
    history_inventory_finding: Finding | None = None
    try:
        history_paths = _history_path_inventory(repository, budget)
    except GitInventoryError as error:
        history_paths = {}
        history_inventory_finding = Finding(error.path, error.reason)
    with _start_git_history(repository) as stream:
        for oid, source, declared_size, display, object_type in stream.objects(budget):
            prefix = source.read(512)
            source.seek(0)
            paths = history_paths.get(oid, frozenset()) if object_type == b"blob" else frozenset()
            if len(paths) > MAX_HISTORY_BLOB_PATHS:
                raise ScanLimit(display, "history-blob-path-fanout-limit")
            displays: tuple[tuple[Path, PurePosixPath | None], ...] = (
                tuple(
                    (Path("<git-history>") / Path(path.as_posix()), path)
                    for path in sorted(paths, key=lambda item: item.as_posix())
                )
                if paths
                else ((display, None),)
            )
            for history_display, repository_relative_path in displays:
                source.seek(0)
                intent = (
                    _archive_intent(history_display.name, prefix)
                    if object_type == b"blob"
                    else None
                )
                if repository_relative_path is not None:
                    budget.file(history_display)
                    budget.input(history_display, declared_size)
                findings.extend(
                    _patterns_stream(
                        history_display,
                        source,
                        expected_size=declared_size,
                        byte_limit=MAX_RAW_FILE_BYTES,
                        limit_reason="raw-byte-limit",
                        repository_relative_path=repository_relative_path,
                    )
                )
                if intent is not None:
                    source.seek(0)
                    findings.extend(_scan_archive(source, intent, history_display, budget, 0))
            if object_type == b"blob" and not paths and _is_audio_like_bytes(prefix):
                findings.append(Finding(display, "forbidden-audio-bytes"))
    if history_inventory_finding is not None:
        findings.append(history_inventory_finding)
    try:
        connectivity = _history_connectivity_finding(repository)
    except GitInventoryError as error:
        findings.append(Finding(error.path, error.reason))
    else:
        if connectivity is not None:
            findings.append(connectivity)
    return findings


def _scan_source(
    root: RootBinding,
    classification: RootClassification,
    budget: ScanBudget,
) -> list[Finding]:
    repository = classification.repository
    scope = classification.scope
    assert repository is not None and scope is not None
    first = _capture_source_snapshot(repository, scope)
    snapshot = _capture_source_snapshot(repository, scope)
    if first != snapshot:
        return [Finding(root.path, "source-inventory-drift")]
    _supplement_source_inventory(root, classification, snapshot, budget)
    findings = []
    if snapshot.index:
        with _start_git_batch(repository) as batch:
            for entry in snapshot.index:
                findings.extend(_scan_index_blob(batch, entry, budget))
                if _terminal_limit(findings):
                    return findings
    working = dict(snapshot.working)
    for relative in (
        *(entry.path for entry in snapshot.index),
        *snapshot.untracked,
    ):
        expected_identity = working[relative.as_posix()]
        if expected_identity is None:
            continue
        budget.path_entry(Path(relative.as_posix()))
        for candidate in _open_relative_candidate(
            repository.fd,
            repository.path,
            Path(relative.as_posix()),
            expected_identity,
        ):
            display = _source_display(root, repository, relative, index=False)
            findings.extend(
                _scan_file(
                    candidate.path,
                    display,
                    budget,
                    candidate,
                    repository_relative_path=relative,
                )
            )
        if _terminal_limit(findings):
            return findings
    final = _capture_source_snapshot(repository, scope)
    final_classification = _classify_root(root)
    final_repository = final_classification.repository
    try:
        same_classification = (
            final_repository is not None
            and final_classification.scope == scope
            and final_repository.root.identity == repository.root.identity
            and final_repository.marker_identity == repository.marker_identity
        )
    finally:
        if final_repository is not None:
            final_repository.close()
    root.revalidate()
    repository.revalidate()
    if final != snapshot or not same_classification:
        findings.append(Finding(root.path, "source-inventory-drift"))
    return findings


def scan(
    roots: Path | Sequence[Path],
    *,
    include_git_history: bool = False,
) -> tuple[Finding, ...]:
    supplied = (roots,) if isinstance(roots, Path) else tuple(roots)
    if not supplied:
        return (Finding(Path("."), "no-scan-roots"),)
    requested = tuple(Path(os.path.abspath(os.fspath(root))) for root in supplied)
    lexical: set[Path] = set()
    for root in requested:
        if root in lexical:
            return (Finding(root, "duplicate-root"),)
        lexical.add(root)
    bindings: list[RootBinding] = []
    identities: set[tuple[int, int, int]] = set()
    preflight_findings: list[Finding] = []
    for root in requested:
        try:
            binding = RootBinding.open(root)
        except FileNotFoundError:
            preflight_findings.append(Finding(root, "missing-root"))
            continue
        except ScanLimit as error:
            preflight_findings.append(Finding(error.path, error.reason))
            continue
        except OSError:
            preflight_findings.append(Finding(root, "unreadable-input"))
            continue
        alias = (binding.identity[0], binding.identity[1], stat.S_IFMT(binding.identity[2]))
        if alias in identities:
            binding.close()
            for opened in bindings:
                opened.close()
            return (Finding(root, "duplicate-root"),)
        identities.add(alias)
        bindings.append(binding)
    findings: list[Finding] = preflight_findings
    budget = ScanBudget()
    try:
        for bound_root in bindings:
            try:
                classification = _classify_root(bound_root)
                try:
                    if classification.source:
                        findings.extend(_scan_source(bound_root, classification, budget))
                        if _terminal_limit(findings):
                            return tuple(findings)
                        if include_git_history and bound_root.path == requested[0]:
                            repository = classification.repository
                            assert repository is not None
                            findings.extend(_scan_git_history(repository, budget))
                        continue
                    if include_git_history and bound_root.path == requested[0]:
                        findings.append(Finding(bound_root.path, "git-state-unprovable"))
                        return tuple(findings)
                    if bound_root.directory:
                        candidates: Iterator[OpenedCandidate] | tuple[OpenedCandidate, ...]
                        candidates = _walk(bound_root, budget)
                    else:
                        candidates = (
                            _opened_candidate(
                                bound_root.parent.fd,
                                bound_root.name,
                                bound_root.path,
                                bound_root.identity,
                            ),
                        )
                    try:
                        for candidate in candidates:
                            path = candidate.path
                            display = (
                                path.relative_to(bound_root.path) if bound_root.directory else path
                            )
                            findings.extend(
                                _scan_file(
                                    path,
                                    display,
                                    budget,
                                    candidate,
                                    repository_relative_path=_repository_relative_path(path),
                                )
                            )
                            if _terminal_limit(findings):
                                return tuple(findings)
                    finally:
                        close = getattr(candidates, "close", None)
                        if close is not None:
                            close()
                finally:
                    if classification.repository is not None:
                        classification.repository.close()
            except (GitInventoryError, ScanLimit) as error:
                findings.append(Finding(error.path, error.reason))
                return tuple(findings)
            except OSError:
                findings.append(Finding(bound_root.path, "unreadable-input"))
                return tuple(findings)
        return tuple(findings)
    finally:
        for bound_root in bindings:
            bound_root.close()


def main() -> int:
    # abspath is lexical: unlike resolve(), it does not erase an explicit
    # symlink before scan() performs lstat/O_NOFOLLOW validation.
    roots = tuple(Path(os.path.abspath(item)) for item in (sys.argv[1:] or ["."]))
    findings = scan(roots)
    for finding in findings:
        print(f"{finding.path}: {finding.reason}")
    if findings:
        return 1
    print("private-data scan: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
