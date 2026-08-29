from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from assurance_common import (
        MAX_JSON_CONTAINERS,
        MAX_JSON_DEPTH,
        MAX_JSON_TOKENS,
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
        revalidate_frozen_inventory,
        walk_regular_files,
    )
    from verify_private_data import scan as scan_private_data
elif __package__:
    from .assurance_common import (
        MAX_JSON_CONTAINERS,
        MAX_JSON_DEPTH,
        MAX_JSON_TOKENS,
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
        revalidate_frozen_inventory,
        walk_regular_files,
    )
    from .verify_private_data import scan as scan_private_data
else:
    from assurance_common import (
        MAX_JSON_CONTAINERS,
        MAX_JSON_DEPTH,
        MAX_JSON_TOKENS,
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
        revalidate_frozen_inventory,
        walk_regular_files,
    )
    from verify_private_data import scan as scan_private_data

TOOL = "backup-artifacts"
PORTABLE_SECRET_SUFFIXES = {".key", ".pem", ".p12", ".pfx", ".token", ".secret"}
VIDEO_SUFFIXES = {".mp4", ".mov", ".mkv", ".webm", ".avi"}
AUTHENTICATED_CIPHERS = {"xchacha20-poly1305": (b"TUNTUN-AEAD\0\x01\x01", 24, 16)}


def _parser() -> ClosedArgumentParser:
    parser = ClosedArgumentParser(prog="scan_backup_artifacts.py")
    parser.add_argument("--root", required=True)
    parser.add_argument("--require-encrypted", action="store_true")
    parser.add_argument("--forbid", required=True, type=CsvSet.parse)
    return parser


def _authenticated_envelope(raw: bytes, cipher: str) -> bool:
    header, nonce_bytes, tag_bytes = AUTHENTICATED_CIPHERS[cipher]
    minimum_size = len(header) + nonce_bytes + 1 + tag_bytes
    return len(raw) >= minimum_size and raw.startswith(header)


def evaluate(argv: Sequence[str] | None = None) -> AssuranceResult:
    try:
        arguments = _parser().parse_args(argv)
        if not arguments.require_encrypted:
            raise ValueError("--require-encrypted is required")
        if any(re.fullmatch(r"[a-z][a-z0-9_]{0,63}", item) is None for item in arguments.forbid):
            raise ValueError("forbidden classes must be canonical")
        root = lexical_path(arguments.root)
        frozen = tuple(
            walk_regular_files(
                (root,), max_files=MAX_WALK_FILES, max_total_bytes=MAX_WALK_TOTAL_BYTES
            )
        )
        by_relative = {str(item.path.relative_to(root)): item for item in frozen}
        manifest_path = root / "manifest.json"
        manifest_item = by_relative.get("manifest.json")
        if manifest_item is None:
            raise AssuranceInputError(manifest_path, "missing-input")
        try:
            manifest = parse_json_object(
                manifest_item.raw,
                max_depth=MAX_JSON_DEPTH,
                max_containers=MAX_JSON_CONTAINERS,
                max_tokens=MAX_JSON_TOKENS,
            )
        except ValueError as error:
            raise AssuranceInputError(manifest_path, str(error)) from error
        cipher = manifest.get("cipher")
        if (
            manifest.get("format") != "tuntun-authenticated-backup-v1"
            or manifest.get("authenticated") is not True
            or not isinstance(cipher, str)
            or cipher not in AUTHENTICATED_CIPHERS
        ):
            raise AssuranceInputError(manifest_path, "encryption-proof-invalid")
        declared = manifest.get("files")
        if not isinstance(declared, list) or not all(isinstance(item, str) for item in declared):
            raise AssuranceInputError(manifest_path, "backup-file-inventory-invalid")
        if len(set(declared)) != len(declared):
            raise AssuranceInputError(manifest_path, "backup-file-inventory-duplicate")
    except AssuranceInputError as error:
        return incomplete(TOOL, error)
    except (ValueError, TypeError) as error:
        return AssuranceResult(
            TOOL, False, (AssuranceFinding(Path("."), "invalid-arguments", str(error)),)
        )

    findings: list[AssuranceFinding] = []
    for relative in declared:
        assert isinstance(relative, str)
        path = Path(relative)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            return AssuranceResult(
                TOOL, False, (AssuranceFinding(manifest_path, "backup-path-invalid", relative),)
            )
        item = by_relative.get(relative)
        if item is None:
            return AssuranceResult(
                TOOL, False, (AssuranceFinding(root / path, "backup-payload-missing"),)
            )
        if path.suffix != ".enc" or not _authenticated_envelope(item.raw, cipher):
            findings.append(AssuranceFinding(item.path, "encryption-proof-missing"))
    expected = {"manifest.json", *declared}
    for relative, item in by_relative.items():
        if relative in expected:
            continue
        suffix = item.path.suffix.lower()
        matched = False
        if "portable_secret" in arguments.forbid and suffix in PORTABLE_SECRET_SUFFIXES:
            findings.append(
                AssuranceFinding(item.path, "forbidden-backup-class", "portable_secret")
            )
            matched = True
        if "video" in arguments.forbid and suffix in VIDEO_SUFFIXES:
            findings.append(AssuranceFinding(item.path, "forbidden-backup-class", "video"))
            matched = True
        if "plaintext" in arguments.forbid and suffix != ".enc":
            findings.append(AssuranceFinding(item.path, "forbidden-backup-class", "plaintext"))
            matched = True
        if not matched:
            findings.append(AssuranceFinding(item.path, "unknown-backup-class"))
        if item.path.name.lower().endswith((".zip", ".tar", ".tar.gz", ".tgz")):
            archive_findings = scan_private_data(item.path)
            if any(value.reason == "corrupt-archive" for value in archive_findings):
                return AssuranceResult(
                    TOOL, False, (AssuranceFinding(item.path, "corrupt-archive"),)
                )
    try:
        revalidate_frozen_inventory(
            (root,),
            frozen,
            max_files=MAX_WALK_FILES,
            max_total_bytes=MAX_WALK_TOTAL_BYTES,
        )
    except AssuranceInputError as error:
        return incomplete(TOOL, error)
    return AssuranceResult(TOOL, True, tuple(findings))


def main(argv: Sequence[str] | None = None) -> int:
    return finish(evaluate(argv))


if __name__ == "__main__":
    raise SystemExit(main())
