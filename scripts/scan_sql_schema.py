from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
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
    selected = [
        node
        for node in inventory.nodes
        if (arguments.db_kind == "vision" and node.schema_owner == "vision")
        or (arguments.db_kind == "canonical" and node.schema_owner == "core")
    ]
    if not selected:
        return AssuranceResult(
            TOOL,
            False,
            (AssuranceFinding(inventory.root, "schema-inventory-missing", arguments.db_kind),),
        )
    findings: list[AssuranceFinding] = []
    for node in selected:
        if node.ddl is None or node.schema_owner is None:
            return AssuranceResult(
                TOOL, False, (AssuranceFinding(node.path, "unowned-or-unknown-ddl"),)
            )
        tokens = {token.lower() for token in SQL_TOKEN.findall(node.ddl)}
        for forbidden in arguments.forbid:
            if forbidden in tokens:
                findings.append(AssuranceFinding(node.path, "forbidden-schema-token", forbidden))
    return AssuranceResult(TOOL, True, tuple(findings))


def main(argv: Sequence[str] | None = None) -> int:
    return finish(evaluate(argv))


if __name__ == "__main__":
    raise SystemExit(main())
