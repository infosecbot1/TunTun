from __future__ import annotations

import ast
import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from assurance_common import (
        MAX_WALK_FILES,
        MAX_WALK_TOTAL_BYTES,
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        finish,
        incomplete,
        lexical_path,
        walk_regular_files,
    )
elif __package__:
    from .assurance_common import (
        MAX_WALK_FILES,
        MAX_WALK_TOTAL_BYTES,
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        finish,
        incomplete,
        lexical_path,
        walk_regular_files,
    )
else:
    from assurance_common import (
        MAX_WALK_FILES,
        MAX_WALK_TOTAL_BYTES,
        AssuranceFinding,
        AssuranceInputError,
        AssuranceResult,
        ClosedArgumentParser,
        finish,
        incomplete,
        lexical_path,
        walk_regular_files,
    )

TOOL = "migration-ownership"
MAX_AST_NODES = 200_000
NUMERIC_REVISION = re.compile(r"[0-9]{4}")
REVISION_NAME = re.compile(r"[0-9]{4}_[a-z0-9_]+")


@dataclass(frozen=True)
class MigrationNode:
    path: Path
    revision: str
    down_revisions: tuple[str, ...]
    schema_owner: str | None
    ddl: str | None


@dataclass(frozen=True)
class MigrationInventory:
    root: Path
    nodes: tuple[MigrationNode, ...]

    def by_revision(self) -> Mapping[str, tuple[MigrationNode, ...]]:
        grouped: dict[str, list[MigrationNode]] = defaultdict(list)
        for node in self.nodes:
            grouped[node.revision].append(node)
        return {revision: tuple(values) for revision, values in grouped.items()}


def _literal_assignment(module: ast.Module, name: str, path: Path) -> object:
    values: list[object] = []
    for statement in module.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        if not any(isinstance(target, ast.Name) and target.id == name for target in targets):
            continue
        if statement.value is None:
            raise AssuranceInputError(path, "migration-structure-invalid", name)
        try:
            values.append(ast.literal_eval(statement.value))
        except (ValueError, TypeError) as error:
            raise AssuranceInputError(path, "migration-literal-required", name) from error
    if len(values) != 1:
        raise AssuranceInputError(path, "migration-assignment-count", name)
    return values[0]


def _optional_literal(module: ast.Module, name: str, path: Path) -> object | None:
    assignments = []
    for statement in module.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            if statement.value is None:
                raise AssuranceInputError(path, "migration-structure-invalid", name)
            try:
                assignments.append(ast.literal_eval(statement.value))
            except (ValueError, TypeError) as error:
                raise AssuranceInputError(path, "migration-literal-required", name) from error
    if len(assignments) > 1:
        raise AssuranceInputError(path, "migration-assignment-count", name)
    return assignments[0] if assignments else None


def _parents(value: object, path: Path) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str) and REVISION_NAME.fullmatch(value):
        return (value,)
    if isinstance(value, (tuple, list)):
        if not value or not all(
            isinstance(item, str) and REVISION_NAME.fullmatch(item) for item in value
        ):
            raise AssuranceInputError(path, "down-revision-invalid")
        if len(set(value)) != len(value):
            raise AssuranceInputError(path, "down-revision-duplicate")
        return tuple(value)
    raise AssuranceInputError(path, "down-revision-invalid")


def _parse_node(path: Path, raw: bytes) -> MigrationNode:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AssuranceInputError(path, "invalid-utf8") from error
    try:
        module = ast.parse(text, filename=str(path))
    except (SyntaxError, RecursionError) as error:
        raise AssuranceInputError(path, "migration-parse-failed") from error
    if sum(1 for _ in ast.walk(module)) > MAX_AST_NODES:
        raise AssuranceInputError(path, "ast-node-limit")
    revision = _literal_assignment(module, "revision", path)
    if not isinstance(revision, str) or REVISION_NAME.fullmatch(revision) is None:
        raise AssuranceInputError(path, "revision-invalid")
    down_revision = _literal_assignment(module, "down_revision", path)
    owner = _optional_literal(module, "schema_owner", path)
    ddl = _optional_literal(module, "ddl", path)
    if owner is not None and not isinstance(owner, str):
        raise AssuranceInputError(path, "schema-owner-invalid")
    if ddl is not None and not isinstance(ddl, str):
        raise AssuranceInputError(path, "ddl-invalid")
    return MigrationNode(path, revision, _parents(down_revision, path), owner, ddl)


def parse_migration_inventory(root: Path) -> MigrationInventory:
    lexical = lexical_path(root)
    nodes: list[MigrationNode] = []
    for frozen in walk_regular_files(
        (lexical,), max_files=MAX_WALK_FILES, max_total_bytes=MAX_WALK_TOTAL_BYTES
    ):
        relative = frozen.path.relative_to(lexical)
        parts = relative.parts
        if (
            len(parts) == 5
            and parts[0] == "apps"
            and parts[2] == "migrations"
            and parts[3] == "versions"
            and frozen.path.suffix == ".py"
        ):
            nodes.append(_parse_node(frozen.path, frozen.raw))
    if not nodes:
        raise AssuranceInputError(lexical, "migration-inventory-missing")
    return MigrationInventory(lexical, tuple(nodes))


def graph_findings(
    inventory: MigrationInventory,
    *,
    forbid_forks: bool,
    forbid_merges: bool,
    forbid_orphans: bool,
) -> tuple[AssuranceFinding, ...]:
    grouped = inventory.by_revision()
    findings: list[AssuranceFinding] = []
    for revision, nodes in grouped.items():
        if len(nodes) > 1:
            findings.append(AssuranceFinding(nodes[0].path, "duplicate-revision", revision))
    unique = {revision: nodes[0] for revision, nodes in grouped.items() if len(nodes) == 1}
    child_counts: Counter[str] = Counter()
    for node in unique.values():
        if forbid_merges and len(node.down_revisions) > 1:
            findings.append(AssuranceFinding(node.path, "migration-merge", node.revision))
        for parent in node.down_revisions:
            child_counts[parent] += 1
            if parent not in unique and forbid_orphans:
                findings.append(AssuranceFinding(node.path, "migration-orphan", parent))
    if forbid_forks:
        for parent, count in child_counts.items():
            if count > 1:
                findings.append(AssuranceFinding(unique[parent].path, "migration-fork", parent))
    return tuple(findings)


def _parser() -> ClosedArgumentParser:
    parser = ClosedArgumentParser(prog="check_migration_ownership.py")
    parser.add_argument("--root", default=".")
    parser.add_argument("--revisions", nargs="+", required=True)
    parser.add_argument("--exact-head")
    parser.add_argument("--forbid-branch-merge-orphan", action="store_true")
    return parser


def evaluate(argv: Sequence[str] | None = None) -> AssuranceResult:
    try:
        arguments = _parser().parse_args(argv)
        revisions = tuple(arguments.revisions)
        if any(NUMERIC_REVISION.fullmatch(item) is None for item in revisions):
            raise ValueError("revisions must be canonical four-digit values")
        if len(set(revisions)) != len(revisions):
            raise ValueError("revisions must be unique")
        if (
            arguments.exact_head is not None
            and REVISION_NAME.fullmatch(arguments.exact_head) is None
        ):
            raise ValueError("exact head must be a canonical revision name")
        inventory = parse_migration_inventory(lexical_path(arguments.root))
    except AssuranceInputError as error:
        return incomplete(TOOL, error)
    except (ValueError, TypeError) as error:
        return AssuranceResult(
            TOOL,
            False,
            (AssuranceFinding(Path("."), "invalid-arguments", str(error)),),
        )

    findings = list(
        graph_findings(
            inventory,
            forbid_forks=arguments.forbid_branch_merge_orphan,
            forbid_merges=arguments.forbid_branch_merge_orphan,
            forbid_orphans=True,
        )
    )
    grouped_numeric: dict[str, list[MigrationNode]] = defaultdict(list)
    for node in inventory.nodes:
        grouped_numeric[node.revision[:4]].append(node)
        if node.path.stem != node.revision:
            findings.append(AssuranceFinding(node.path, "edited-revision", node.revision))
    requested_nodes: list[MigrationNode] = []
    for requested in revisions:
        matches = grouped_numeric.get(requested, [])
        if not matches:
            return AssuranceResult(
                TOOL,
                False,
                (AssuranceFinding(inventory.root, "missing-revision", requested),),
            )
        if len(matches) != 1:
            findings.append(
                AssuranceFinding(inventory.root, "duplicate-revision-number", requested)
            )
        else:
            requested_nodes.append(matches[0])
    if arguments.exact_head is not None:
        children = Counter(parent for node in inventory.nodes for parent in node.down_revisions)
        heads = [node.revision for node in inventory.nodes if children[node.revision] == 0]
        if heads != [arguments.exact_head]:
            findings.append(
                AssuranceFinding(inventory.root, "exact-head-mismatch", arguments.exact_head)
            )
    if arguments.forbid_branch_merge_orphan and requested_nodes:
        requested_names = {node.revision for node in requested_nodes}
        for node in requested_nodes:
            if any(parent not in requested_names for parent in node.down_revisions):
                findings.append(
                    AssuranceFinding(node.path, "requested-ancestry-not-closed", node.revision)
                )
    return AssuranceResult(TOOL, True, tuple(findings))


def main(argv: Sequence[str] | None = None) -> int:
    return finish(evaluate(argv))


if __name__ == "__main__":
    raise SystemExit(main())
