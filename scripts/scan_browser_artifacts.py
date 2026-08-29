from __future__ import annotations

import io
import re
import stat
import struct
import tarfile
import zipfile
import zlib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Protocol, cast

if TYPE_CHECKING:
    from assurance_common import (
        MAX_JSON_CONTAINERS,
        MAX_JSON_DEPTH,
        MAX_JSON_TOKENS,
        MAX_REGULAR_FILE_BYTES,
        MAX_WALK_FILES,
        MAX_WALK_TOTAL_BYTES,
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        CsvSet,
        finish,
        incomplete,
        lexical_path,
        parse_json_object,
        read_regular_file,
        validate_root,
        walk_regular_files,
    )
elif __package__:
    from .assurance_common import (
        MAX_JSON_CONTAINERS,
        MAX_JSON_DEPTH,
        MAX_JSON_TOKENS,
        MAX_REGULAR_FILE_BYTES,
        MAX_WALK_FILES,
        MAX_WALK_TOTAL_BYTES,
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        CsvSet,
        finish,
        incomplete,
        lexical_path,
        parse_json_object,
        read_regular_file,
        validate_root,
        walk_regular_files,
    )
else:
    from assurance_common import (
        MAX_JSON_CONTAINERS,
        MAX_JSON_DEPTH,
        MAX_JSON_TOKENS,
        MAX_REGULAR_FILE_BYTES,
        MAX_WALK_FILES,
        MAX_WALK_TOTAL_BYTES,
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        CsvSet,
        finish,
        incomplete,
        lexical_path,
        parse_json_object,
        read_regular_file,
        validate_root,
        walk_regular_files,
    )

TOOL = "browser-artifacts"
NORMALIZED_TOKEN = re.compile(rb"[A-Za-z][A-Za-z0-9_-]{1,127}")
ALIASES = {
    "credential": (b"credential", b"authorization", b"password"),
    "reusable_token": (b"reusabletoken", b"accesstoken", b"refreshtoken"),
    "reusable_urls": (b"https://", b"http://", b"ws://", b"wss://"),
    "service_workers": (b"serviceworker", b"navigator.serviceworker"),
    "persistent_storage": (b"localstorage", b"sessionstorage", b"indexeddb"),
    "storage_path": (b"storagepath", b"filepath", b"filesystempath"),
}


ARCHIVE_CHUNK_BYTES = 64 * 1024
MAX_BROWSER_ARCHIVE_DEPTH = 3


@dataclass
class ArchiveBudget:
    members: int = 0
    expanded_bytes: int = 0

    def member(self, path: Path) -> None:
        self.members += 1
        if self.members > MAX_WALK_FILES:
            raise AssuranceInputError(path, "browser-archive-member-limit")

    def expanded(self, path: Path, amount: int) -> None:
        self.expanded_bytes += amount
        if self.expanded_bytes > MAX_WALK_TOTAL_BYTES:
            raise AssuranceInputError(path, "browser-archive-expanded-byte-limit")


def _parser() -> ClosedArgumentParser:
    parser = ClosedArgumentParser(prog="scan_browser_artifacts.py")
    parser.add_argument("--root", default=".")
    parser.add_argument("--playwright-output")
    parser.add_argument("--forbid", required=True, type=CsvSet.parse)
    return parser


def _normalized(value: bytes) -> bytes:
    return re.sub(rb"[^a-z0-9]", b"", value.lower())


def _bounded_gzip(path: Path, raw: bytes) -> bytes:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    output = bytearray()
    pending = raw
    try:
        while pending and not decoder.eof:
            chunk, pending = pending[:ARCHIVE_CHUNK_BYTES], pending[ARCHIVE_CHUNK_BYTES:]
            while chunk and not decoder.eof:
                remaining = MAX_REGULAR_FILE_BYTES + 1 - len(output)
                decoded = decoder.decompress(chunk, remaining)
                output.extend(decoded)
                if len(output) > MAX_REGULAR_FILE_BYTES:
                    raise AssuranceInputError(path, "expanded-byte-limit")
                chunk = decoder.unconsumed_tail
        if not decoder.eof:
            raise AssuranceInputError(path, "corrupt-browser-compression")
        if decoder.unused_data or pending:
            raise AssuranceInputError(path, "corrupt-browser-compression")
    except zlib.error as error:
        raise AssuranceInputError(path, "corrupt-browser-compression") from error
    return bytes(output)


def _bounded_brotli(path: Path, _raw: bytes) -> bytes:
    raise AssuranceInputError(
        path, "browser-decoder-unavailable", "bounded-isolated-worker-unavailable"
    )


def _decoded(path: Path, raw: bytes) -> bytes:
    lowered = path.name.lower()
    if lowered.endswith((".gz", ".tgz")):
        return _bounded_gzip(path, raw)
    if lowered.endswith(".br"):
        return _bounded_brotli(path, raw)
    return raw


def _decoded_name(path: Path) -> Path:
    lowered = path.name.lower()
    if lowered.endswith(".tgz"):
        return path.with_name(f"{path.name[:-4]}.tar")
    if lowered.endswith(".gz"):
        return path.with_name(path.name[:-3])
    if lowered.endswith(".br"):
        return path.with_name(path.name[:-3])
    return path


def _validate_structured(path: Path, raw: bytes) -> None:
    name = path.name.lower()
    if name.endswith((".json", ".map")):
        try:
            parse_json_object(
                raw,
                max_depth=MAX_JSON_DEPTH,
                max_containers=MAX_JSON_CONTAINERS,
                max_tokens=MAX_JSON_TOKENS,
            )
        except ValueError as error:
            raise AssuranceInputError(path, str(error)) from error


def _archive_kind(path: Path, raw: bytes) -> str | None:
    lowered = path.name.lower()
    if lowered.endswith((".zip", ".whl")) or raw.startswith(
        (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
    ):
        return "zip"
    if lowered.endswith(".tar") or raw[257:263] in {b"ustar\0", b"ustar "}:
        return "tar"
    return None


def _canonical_member(raw: str, path: Path) -> str:
    if not raw or "\\" in raw or any(ord(character) < 32 for character in raw):
        raise AssuranceInputError(path, "unsafe-browser-archive-member")
    trimmed = raw[:-1] if raw.endswith("/") else raw
    candidate = PurePosixPath(trimmed)
    if (
        not trimmed
        or candidate.is_absolute()
        or candidate.as_posix() != trimmed
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise AssuranceInputError(path, "unsafe-browser-archive-member")
    return candidate.as_posix()


def _zip_preflight(path: Path, raw: bytes) -> None:
    minimum_eocd = 22
    search_start = max(0, len(raw) - (65_535 + minimum_eocd))
    cursor = len(raw)
    eocd = -1
    while cursor > search_start:
        candidate = raw.rfind(b"PK\x05\x06", search_start, cursor)
        if candidate < 0:
            break
        if candidate + minimum_eocd <= len(raw):
            comment_size = struct.unpack_from("<H", raw, candidate + 20)[0]
            if candidate + minimum_eocd + comment_size == len(raw):
                eocd = candidate
                break
        cursor = candidate
    if eocd < 0:
        raise AssuranceInputError(path, "corrupt-browser-archive")
    disk, directory_disk, disk_count, count = struct.unpack_from("<HHHH", raw, eocd + 4)
    directory_size, directory_offset = struct.unpack_from("<II", raw, eocd + 12)
    if (
        any(value == 0xFFFF for value in (disk, directory_disk, disk_count, count))
        or directory_size == 0xFFFFFFFF
        or directory_offset == 0xFFFFFFFF
    ):
        raise AssuranceInputError(path, "browser-archive-unsupported")
    if disk != 0 or directory_disk != 0 or disk_count != count:
        raise AssuranceInputError(path, "browser-archive-unsupported")
    if count > MAX_WALK_FILES:
        raise AssuranceInputError(path, "browser-archive-member-limit")
    if directory_size > MAX_REGULAR_FILE_BYTES:
        raise AssuranceInputError(path, "browser-archive-central-directory-limit")
    directory_end = directory_offset + directory_size
    if directory_offset > eocd or directory_end != eocd:
        raise AssuranceInputError(path, "corrupt-browser-archive")
    position = directory_offset
    actual_count = 0
    while position < directory_end:
        if position + 46 > directory_end or raw[position : position + 4] != b"PK\x01\x02":
            raise AssuranceInputError(path, "corrupt-browser-archive")
        name_size, extra_size, comment_size = struct.unpack_from("<HHH", raw, position + 28)
        record_size = 46 + name_size + extra_size + comment_size
        if position + record_size > directory_end:
            raise AssuranceInputError(path, "corrupt-browser-archive")
        actual_count += 1
        if actual_count > MAX_WALK_FILES:
            raise AssuranceInputError(path, "browser-archive-member-limit")
        position += record_size
    if actual_count != count:
        raise AssuranceInputError(path, "corrupt-browser-archive")


def _read_member(
    source: object,
    *,
    expected_size: int,
    path: Path,
    budget: ArchiveBudget,
) -> bytes:
    if expected_size > MAX_REGULAR_FILE_BYTES:
        raise AssuranceInputError(path, "expanded-byte-limit")
    reader = cast(ProtocolReader, source)
    output = bytearray()
    while len(output) <= expected_size:
        chunk = reader.read(min(ARCHIVE_CHUNK_BYTES, expected_size + 1 - len(output)))
        if not chunk:
            break
        output.extend(chunk)
        if len(output) > expected_size or len(output) > MAX_REGULAR_FILE_BYTES:
            raise AssuranceInputError(path, "corrupt-browser-archive")
    if len(output) != expected_size:
        raise AssuranceInputError(path, "corrupt-browser-archive")
    budget.expanded(path, len(output))
    return bytes(output)


class ProtocolReader(Protocol):
    def read(self, size: int = -1) -> bytes: ...


def _archive_payloads(
    path: Path,
    raw: bytes,
    *,
    budget: ArchiveBudget,
    depth: int,
) -> tuple[tuple[Path, bytes], ...]:
    kind = _archive_kind(path, raw)
    if kind is None:
        decoded_path = _decoded_name(path)
        decoded = _decoded(path, raw)
        if decoded_path != path:
            budget.expanded(decoded_path, len(decoded))
            if _archive_kind(decoded_path, decoded) is not None:
                return _archive_payloads(
                    decoded_path,
                    decoded,
                    budget=budget,
                    depth=depth + 1,
                )
        return ((decoded_path, decoded),)
    if depth >= MAX_BROWSER_ARCHIVE_DEPTH:
        raise AssuranceInputError(path, "browser-archive-depth-limit")
    payloads: list[tuple[Path, bytes]] = [(path, raw)]
    try:
        if kind == "zip":
            _zip_preflight(path, raw)
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                seen: set[str] = set()
                for zip_member in archive.infolist():
                    member_path = Path(f"{path}!{zip_member.filename}")
                    budget.member(member_path)
                    canonical = _canonical_member(zip_member.filename, member_path)
                    canonical_path = Path(f"{path}!{canonical}")
                    if canonical in seen or zip_member.flag_bits & 1:
                        raise AssuranceInputError(canonical_path, "unsafe-browser-archive-member")
                    seen.add(canonical)
                    mode = (zip_member.external_attr >> 16) & 0o170000
                    if zip_member.is_dir():
                        if zip_member.file_size or zip_member.compress_size:
                            raise AssuranceInputError(
                                canonical_path, "unsafe-browser-archive-member"
                            )
                        continue
                    if mode == stat.S_IFDIR or (mode and mode != stat.S_IFREG):
                        raise AssuranceInputError(canonical_path, "unsafe-browser-archive-member")
                    with archive.open(zip_member) as member_source:
                        member_raw = _read_member(
                            member_source,
                            expected_size=zip_member.file_size,
                            path=canonical_path,
                            budget=budget,
                        )
                    payloads.extend(
                        _archive_payloads(
                            canonical_path,
                            member_raw,
                            budget=budget,
                            depth=depth + 1,
                        )
                    )
        else:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
                seen = set()
                for tar_member in archive:
                    member_path = Path(f"{path}!{tar_member.name}")
                    budget.member(member_path)
                    canonical = _canonical_member(tar_member.name, member_path)
                    canonical_path = Path(f"{path}!{canonical}")
                    if canonical in seen:
                        raise AssuranceInputError(canonical_path, "unsafe-browser-archive-member")
                    seen.add(canonical)
                    if tar_member.isdir():
                        if tar_member.size:
                            raise AssuranceInputError(
                                canonical_path, "unsafe-browser-archive-member"
                            )
                        continue
                    if not tar_member.isfile():
                        raise AssuranceInputError(canonical_path, "unsafe-browser-archive-member")
                    tar_source = archive.extractfile(tar_member)
                    if tar_source is None:
                        raise AssuranceInputError(canonical_path, "corrupt-browser-archive")
                    with tar_source:
                        member_raw = _read_member(
                            tar_source,
                            expected_size=tar_member.size,
                            path=canonical_path,
                            budget=budget,
                        )
                    payloads.extend(
                        _archive_payloads(
                            canonical_path,
                            member_raw,
                            budget=budget,
                            depth=depth + 1,
                        )
                    )
    except AssuranceInputError:
        raise
    except (zipfile.LargeZipFile, NotImplementedError, tarfile.CompressionError) as error:
        raise AssuranceInputError(path, "browser-archive-unsupported") from error
    except (EOFError, OSError, RuntimeError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise AssuranceInputError(path, "corrupt-browser-archive") from error
    return tuple(payloads)


def evaluate(argv: Sequence[str] | None = None) -> AssuranceResult:
    try:
        arguments = _parser().parse_args(argv)
        if any(re.fullmatch(r"[a-z][a-z0-9_]{0,63}", item) is None for item in arguments.forbid):
            raise ValueError("forbidden classes must be canonical")
        root = validate_root(lexical_path(arguments.root))
        requested_roots: list[Path] = []
        apps = root / "apps"
        try:
            application_entries = tuple(apps.iterdir())
        except FileNotFoundError:
            application_entries = ()
        except OSError as error:
            raise AssuranceInputError(apps, "unreadable-input", str(error)) from error
        for application in application_entries:
            build = application / "dist"
            try:
                build.lstat()
            except FileNotFoundError:
                continue
            except OSError as error:
                raise AssuranceInputError(build, "unreadable-input", str(error)) from error
            requested_roots.append(build)
        playwright: Path | None = None
        if arguments.playwright_output is not None:
            candidate = Path(arguments.playwright_output)
            playwright = lexical_path(candidate if candidate.is_absolute() else root / candidate)
            requested_roots.append(playwright)
        if not requested_roots:
            raise AssuranceInputError(root, "browser-inventory-missing")
        frozen = tuple(
            walk_regular_files(
                tuple(requested_roots),
                max_files=MAX_WALK_FILES,
                max_total_bytes=MAX_WALK_TOTAL_BYTES,
            )
        )
        if playwright is not None:
            read_regular_file(
                next(
                    (
                        item.path
                        for item in frozen
                        if item.path == playwright or playwright in item.path.parents
                    ),
                    playwright,
                ),
                max_bytes=MAX_REGULAR_FILE_BYTES,
            ) if playwright.is_file() else None
    except AssuranceInputError as error:
        return incomplete(TOOL, error)
    except (ValueError, TypeError) as error:
        return AssuranceResult(
            TOOL, False, (AssuranceFinding(Path("."), "invalid-arguments", str(error)),)
        )

    candidates = []
    for item in frozen:
        try:
            relative = item.path.relative_to(root)
        except ValueError:
            relative = None
        in_dist = (
            relative is not None
            and len(relative.parts) >= 4
            and relative.parts[0] == "apps"
            and relative.parts[2] == "dist"
        )
        in_playwright = playwright is not None and (
            item.path == playwright or playwright in item.path.parents
        )
        if in_dist or in_playwright:
            candidates.append(item)
    if not candidates:
        return AssuranceResult(TOOL, False, (AssuranceFinding(root, "browser-inventory-missing"),))
    if not any(item.path.name == "manifest.json" for item in candidates):
        return AssuranceResult(TOOL, False, (AssuranceFinding(root, "browser-manifest-missing"),))

    findings: list[AssuranceFinding] = []
    archive_budget = ArchiveBudget()
    for item in candidates:
        try:
            payloads = _archive_payloads(
                item.path,
                item.raw,
                budget=archive_budget,
                depth=0,
            )
        except AssuranceInputError as error:
            return incomplete(TOOL, error)
        for payload_path, raw in payloads:
            try:
                _validate_structured(payload_path, raw)
            except AssuranceInputError as error:
                return incomplete(TOOL, error)
            lowered = raw.lower()
            normalized = _normalized(raw)
            normalized_tokens = {_normalized(token) for token in NORMALIZED_TOKEN.findall(raw)}
            for forbidden in arguments.forbid:
                key = forbidden.encode("ascii")
                aliases = ALIASES.get(forbidden, (key,))
                if any(
                    alias in lowered
                    or _normalized(alias) in normalized_tokens
                    or _normalized(alias) in normalized
                    for alias in aliases
                ):
                    findings.append(
                        AssuranceFinding(payload_path, "forbidden-browser-artifact", forbidden)
                    )
    return AssuranceResult(TOOL, True, tuple(findings))


def main(argv: Sequence[str] | None = None) -> int:
    return finish(evaluate(argv))


if __name__ == "__main__":
    raise SystemExit(main())
