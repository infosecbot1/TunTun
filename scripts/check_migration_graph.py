from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from assurance_common import (
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        finish,
        incomplete,
        lexical_path,
    )
    from check_migration_ownership import (
        REVISION_NAME,
        graph_findings,
        parse_migration_inventory,
    )
elif __package__:
    from .assurance_common import (
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        finish,
        incomplete,
        lexical_path,
    )
    from .check_migration_ownership import (
        REVISION_NAME,
        graph_findings,
        parse_migration_inventory,
    )
else:
    from assurance_common import (
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        finish,
        incomplete,
        lexical_path,
    )
    from check_migration_ownership import (
        REVISION_NAME,
        graph_findings,
        parse_migration_inventory,
    )

TOOL = "migration-graph"
VERSION_TABLE = re.compile(r"[a-z][a-z0-9_]{0,62}")


def _parser() -> ClosedArgumentParser:
    parser = ClosedArgumentParser(prog="check_migration_graph.py")
    parser.add_argument("--root", default=".")
    parser.add_argument("--core-version-table", required=True)
    parser.add_argument("--exact-head", required=True)
    parser.add_argument("--exact-edge", action="append", default=[])
    parser.add_argument("--forbid-forks", action="store_true")
    parser.add_argument("--forbid-merges", action="store_true")
    parser.add_argument("--forbid-orphans", action="store_true")
    return parser


def _edge(value: str) -> tuple[str, str]:
    if value.count(":") != 1:
        raise ValueError("exact edge must be CHILD:PARENT")
    child, parent = value.split(":")
    if REVISION_NAME.fullmatch(child) is None or REVISION_NAME.fullmatch(parent) is None:
        raise ValueError("exact edge revisions must be canonical")
    return child, parent


def evaluate(argv: Sequence[str] | None = None) -> AssuranceResult:
    try:
        arguments = _parser().parse_args(argv)
        if VERSION_TABLE.fullmatch(arguments.core_version_table) is None:
            raise ValueError("core version table must be canonical")
        if REVISION_NAME.fullmatch(arguments.exact_head) is None:
            raise ValueError("exact head must be a canonical revision name")
        edges = tuple(_edge(value) for value in arguments.exact_edge)
        if len(set(edges)) != len(edges):
            raise ValueError("exact edges must be unique")
        inventory = parse_migration_inventory(lexical_path(arguments.root))
    except AssuranceInputError as error:
        return incomplete(TOOL, error)
    except (ValueError, TypeError) as error:
        return AssuranceResult(
            TOOL, False, (AssuranceFinding(Path("."), "invalid-arguments", str(error)),)
        )

    findings = list(
        graph_findings(
            inventory,
            forbid_forks=arguments.forbid_forks,
            forbid_merges=arguments.forbid_merges,
            forbid_orphans=arguments.forbid_orphans,
        )
    )
    if arguments.core_version_table != "alembic_version":
        findings.append(
            AssuranceFinding(
                inventory.root,
                "core-version-table-mismatch",
                arguments.core_version_table,
            )
        )
    grouped = inventory.by_revision()
    children = Counter(parent for node in inventory.nodes for parent in node.down_revisions)
    heads = sorted(revision for revision in grouped if children[revision] == 0)
    if heads != [arguments.exact_head]:
        findings.append(
            AssuranceFinding(inventory.root, "exact-head-mismatch", arguments.exact_head)
        )
    actual_edges = {
        (node.revision, parent) for node in inventory.nodes for parent in node.down_revisions
    }
    for child, parent in edges:
        if (child, parent) not in actual_edges:
            findings.append(
                AssuranceFinding(inventory.root, "exact-edge-missing", f"{child}:{parent}")
            )
    return AssuranceResult(TOOL, True, tuple(findings))


def main(argv: Sequence[str] | None = None) -> int:
    return finish(evaluate(argv))


if __name__ == "__main__":
    raise SystemExit(main())
