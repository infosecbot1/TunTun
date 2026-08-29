from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from assurance_common import (
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
        read_json_object,
        walk_regular_files,
    )
    from verify_private_data import scan as scan_private_data
elif __package__:
    from .assurance_common import (
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
        read_json_object,
        walk_regular_files,
    )
    from .verify_private_data import scan as scan_private_data
else:
    from assurance_common import (
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
        read_json_object,
        walk_regular_files,
    )
    from verify_private_data import scan as scan_private_data

TOOL = "backup-artifacts"
PORTABLE_SECRET_SUFFIXES = {".key", ".pem", ".p12", ".pfx", ".token", ".secret"}
VIDEO_SUFFIXES = {".mp4", ".mov", ".mkv", ".webm", ".avi"}


def _parser() -> ClosedArgumentParser:
    parser = ClosedArgumentParser(prog="scan_backup_artifacts.py")
    parser.add_argument("--root", required=True)
    parser.add_argument("--require-encrypted", action="store_true")
    parser.add_argument("--forbid", required=True, type=CsvSet.parse)
    return parser


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
        manifest_path = root / "manifest.json"
        manifest = read_json_object(manifest_path, max_bytes=MAX_REGULAR_FILE_BYTES)
        if (
            manifest.get("format") != "tuntun-authenticated-backup-v1"
            or manifest.get("authenticated") is not True
            or not isinstance(manifest.get("cipher"), str)
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

    by_relative = {str(item.path.relative_to(root)): item for item in frozen}
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
        if path.suffix != ".enc" or not item.raw.startswith(b"TUNTUN-AEAD\0"):
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
    return AssuranceResult(TOOL, True, tuple(findings))


def main(argv: Sequence[str] | None = None) -> int:
    return finish(evaluate(argv))


if __name__ == "__main__":
    raise SystemExit(main())
