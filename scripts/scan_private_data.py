from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts.assurance_common import (
        AssuranceFinding,
        AssuranceResult,
        ClosedArgumentParser,
        finish,
        lexical_path,
    )
    from scripts.verify_private_data import Finding, scan
elif __package__:
    from .assurance_common import (
        AssuranceFinding,
        AssuranceResult,
        ClosedArgumentParser,
        finish,
        lexical_path,
    )
    from .verify_private_data import Finding, scan
else:
    from assurance_common import (
        AssuranceFinding,
        AssuranceResult,
        ClosedArgumentParser,
        finish,
        lexical_path,
    )
    from verify_private_data import Finding, scan

TOOL = "private-data"
INCOMPLETE_REASONS = {
    "no-scan-roots",
    "root-scope-unsupported",
    "missing-root",
    "filesystem-symlink",
    "filesystem-symlink-ancestor",
    "filesystem-special",
    "unreadable-input",
    "input-changed-during-scan",
    "corrupt-archive",
    "raw-byte-limit",
    "compressed-byte-limit",
    "archive-member-byte-limit",
    "cumulative-expanded-byte-limit",
    "total-input-byte-limit",
    "file-count-limit",
    "path-entry-limit",
    "archive-member-limit",
    "archive-depth-limit",
    "directory-depth-limit",
    "zip-central-directory-limit",
    "zip-central-directory-invalid",
    "zip64-unsupported",
    "gzip-header-limit",
    "gzip-trailing-padding-limit",
    "gzip-trailing-data",
    "tar-metadata-limit",
    "tar-trailing-padding-limit",
    "tar-trailing-data",
    "tracked-path-length-limit",
    "tracked-inventory-invalid",
    "tracked-inventory-failed",
    "unsafe-archive-member",
    "unsupported-tar-metadata",
    "archive-read-failed",
    "git-state-unprovable",
    "git-inventory-failed",
    "git-inventory-timeout",
    "git-inventory-output-limit",
    "git-inventory-malformed",
    "git-history-object-missing",
    "git-object-format-unsupported",
    "git-process-reap-timeout",
    "git-index-conflict",
    "git-index-mode-invalid",
    "source-inventory-drift",
    "source-inventory-incomplete",
    "git-batch-object-missing",
    "git-batch-framing",
    "git-batch-type-invalid",
    "git-batch-oid-mismatch",
    "git-batch-size-invalid",
    "git-batch-short-read",
    "git-batch-trailing-data",
    "git-batch-output-limit",
    "git-batch-content-oid-mismatch",
    "duplicate-root",
}


def _parser() -> ClosedArgumentParser:
    parser = ClosedArgumentParser(prog="scan_private_data.py")
    parser.add_argument("--paths", nargs="+", required=True)
    parser.add_argument("--include-git-history", action="store_true")
    parser.add_argument("--allow-safe-ids", action="store_true")
    return parser


def _result(findings: tuple[Finding, ...]) -> AssuranceResult:
    converted = []
    complete = True
    for finding in findings:
        converted.append(AssuranceFinding(finding.path, finding.reason))
        if finding.reason in INCOMPLETE_REASONS:
            complete = False
    return AssuranceResult(TOOL, complete, tuple(converted))


def evaluate(argv: Sequence[str] | None = None) -> AssuranceResult:
    try:
        arguments = _parser().parse_args(argv)
        paths = tuple(lexical_path(item) for item in arguments.paths)
        if len(set(paths)) != len(paths):
            raise ValueError("paths must be unique")
    except (ValueError, TypeError) as error:
        return AssuranceResult(
            TOOL, False, (AssuranceFinding(Path("."), "invalid-arguments", str(error)),)
        )
    return _result(scan(paths, include_git_history=arguments.include_git_history))


def main(argv: Sequence[str] | None = None) -> int:
    return finish(evaluate(argv))


if __name__ == "__main__":
    raise SystemExit(main())
