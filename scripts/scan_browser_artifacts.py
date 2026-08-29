from __future__ import annotations

import gzip
import importlib
import re
from collections.abc import Sequence
from pathlib import Path
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


class BrotliDecoder(Protocol):
    def decompress(self, data: bytes) -> bytes: ...


def _parser() -> ClosedArgumentParser:
    parser = ClosedArgumentParser(prog="scan_browser_artifacts.py")
    parser.add_argument("--root", default=".")
    parser.add_argument("--playwright-output")
    parser.add_argument("--forbid", required=True, type=CsvSet.parse)
    return parser


def _normalized(value: bytes) -> bytes:
    return re.sub(rb"[^a-z0-9]", b"", value.lower())


def _decoded(path: Path, raw: bytes) -> bytes:
    lowered = path.name.lower()
    if lowered.endswith(".gz"):
        try:
            value = gzip.decompress(raw)
        except (OSError, EOFError) as error:
            raise AssuranceInputError(path, "corrupt-browser-compression") from error
        if len(value) > MAX_REGULAR_FILE_BYTES:
            raise AssuranceInputError(path, "expanded-byte-limit")
        return value
    if lowered.endswith(".br"):
        try:
            brotli = cast(BrotliDecoder, importlib.import_module("brotli"))
        except ImportError as error:
            raise AssuranceInputError(path, "browser-decoder-unavailable") from error
        try:
            value = brotli.decompress(raw)
        except Exception as error:
            raise AssuranceInputError(path, "corrupt-browser-compression") from error
        if len(value) > MAX_REGULAR_FILE_BYTES:
            raise AssuranceInputError(path, "expanded-byte-limit")
        return value
    return raw


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
    for item in candidates:
        try:
            raw = _decoded(item.path, item.raw)
            _validate_structured(item.path, raw)
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
                    AssuranceFinding(item.path, "forbidden-browser-artifact", forbidden)
                )
    return AssuranceResult(TOOL, True, tuple(findings))


def main(argv: Sequence[str] | None = None) -> int:
    return finish(evaluate(argv))


if __name__ == "__main__":
    raise SystemExit(main())
