from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts.assurance_common import (
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        CsvSet,
        finish,
        incomplete,
        lexical_path,
    )
    from scripts.check_migration_ownership import parse_migration_inventory
elif __package__:
    from .assurance_common import (
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        CsvSet,
        finish,
        incomplete,
        lexical_path,
    )
    from .check_migration_ownership import parse_migration_inventory
else:
    from assurance_common import (
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        CsvSet,
        finish,
        incomplete,
        lexical_path,
    )
    from check_migration_ownership import parse_migration_inventory

TOOL = "sql-schema"
SQL_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _parser() -> ClosedArgumentParser:
    parser = ClosedArgumentParser(prog="scan_sql_schema.py")
    parser.add_argument("--root", default=".")
    parser.add_argument("--db-kind", required=True, choices=("vision", "canonical"))
    parser.add_argument("--forbid", required=True, type=CsvSet.parse)
    return parser


def evaluate(argv: Sequence[str] | None = None) -> AssuranceResult:
    try:
        arguments = _parser().parse_args(argv)
        if any(re.fullmatch(r"[a-z][a-z0-9_]{0,63}", item) is None for item in arguments.forbid):
            raise ValueError("forbidden SQL tokens must be canonical")
        inventory = parse_migration_inventory(lexical_path(arguments.root))
    except AssuranceInputError as error:
        return incomplete(TOOL, error)
    except (ValueError, TypeError) as error:
        return AssuranceResult(
            TOOL, False, (AssuranceFinding(Path("."), "invalid-arguments", str(error)),)
        )
    registered_owners = {"vision", "core"}
    nodes_with_owners = []
    for node in inventory.nodes:
        path_owner = node.path.relative_to(inventory.root).parts[1]
        if path_owner not in registered_owners:
            return AssuranceResult(
                TOOL,
                False,
                (AssuranceFinding(node.path, "schema-owner-unknown", path_owner),),
            )
        if node.schema_owner is None or not node.ddl:
            return AssuranceResult(
                TOOL, False, (AssuranceFinding(node.path, "unowned-or-unknown-ddl"),)
            )
        if node.schema_owner != path_owner:
            return AssuranceResult(
                TOOL,
                False,
                (
                    AssuranceFinding(
                        node.path,
                        "schema-owner-mismatch",
                        f"{node.schema_owner}!={path_owner}",
                    ),
                ),
            )
        nodes_with_owners.append((node, path_owner))
    selected_owner = "vision" if arguments.db_kind == "vision" else "core"
    selected = [node for node, path_owner in nodes_with_owners if path_owner == selected_owner]
    if not selected:
        return AssuranceResult(
            TOOL,
            False,
            (AssuranceFinding(inventory.root, "schema-inventory-missing", arguments.db_kind),),
        )
    findings: list[AssuranceFinding] = []
    for node in selected:
        assert node.ddl is not None
        tokens = {token.lower() for token in SQL_TOKEN.findall(node.ddl)}
        for forbidden in arguments.forbid:
            if forbidden in tokens:
                findings.append(AssuranceFinding(node.path, "forbidden-schema-token", forbidden))
    return AssuranceResult(TOOL, True, tuple(findings))


def main(argv: Sequence[str] | None = None) -> int:
    return finish(evaluate(argv))


if __name__ == "__main__":
    raise SystemExit(main())
