import gzip
import importlib
import io
import json
import os
import stat
import struct
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest
from assurance_cases import MigrationWorkspace

from scripts import (
    assurance_common,
    check_feature_absence,
    check_import_boundaries,
    check_migration_graph,
    check_migration_ownership,
    scan_backup_artifacts,
    scan_browser_artifacts,
    scan_network_surface,
    scan_private_data,
    scan_sandbox_residue,
    scan_sql_schema,
)


@pytest.mark.parametrize(
    ("tool", "argv"),
    [
        (check_feature_absence, ["--feature", "selected_frame_perception", "--phase", "3"]),
        (check_import_boundaries, ["--domain", "vision"]),
        (check_migration_ownership, ["--revisions", "0013", "0014", "0015"]),
        (scan_browser_artifacts, ["--forbid", "credential,reusable_token"]),
        (scan_network_surface, ["--forbid-wildcard", "--forbid-core-tcp"]),
    ],
)
def test_shared_assurance_cli_is_owned_and_callable(
    tool: object, argv: list[str], shared_assurance_harness
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(tool)
    assert tool.main(["--root", str(workspace), *argv]) == 0


@pytest.mark.parametrize(
    ("tool", "argv"),
    [
        (check_feature_absence, ["--feature", "selected_frame_perception", "--phase", "3"]),
        (check_import_boundaries, ["--domain", "vision"]),
        (check_migration_ownership, ["--revisions", "0013", "0014", "0015"]),
        (scan_browser_artifacts, ["--forbid", "credential,reusable_token"]),
    ],
)
def test_file_backed_shared_tools_ignore_only_git_proven_generated_outputs(
    tool: object,
    argv: list[str],
    shared_assurance_harness,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(tool)
    (workspace / ".gitignore").write_text(
        "node_modules/\napps/*/dist/\n",
        encoding="utf-8",
    )
    subprocess.run(
        ("git", "-C", str(workspace), "init", "-q"),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ("git", "-C", str(workspace), "add", "-A"),
        check=True,
        capture_output=True,
    )
    ignored = workspace / "node_modules"
    ignored.mkdir()
    (ignored / "synthetic-package").symlink_to(workspace, target_is_directory=True)

    assert tool.main(["--root", str(workspace), *argv]) == 0


@pytest.mark.parametrize(
    "fault",
    [
        "missing_input",
        "symlink_input",
        "special_input",
        "input_replaced",
        "duplicate_json_key",
        "invalid_utf8",
        "oversize",
        "overdepth",
        "too_many_files",
        "ambiguous_process_owner",
        "truncated_socket_inventory",
    ],
)
def test_shared_assurance_tools_never_convert_incomplete_scan_to_pass(
    shared_assurance_harness, fault: str
) -> None:
    result = shared_assurance_harness.run_every_tool_with(fault)
    assert result.exit_codes
    assert all(code == 2 for code in result.exit_codes)
    assert all(receipt.complete is False for receipt in result.receipts)


@pytest.mark.parametrize(
    ("tool", "argv"),
    (
        (
            check_feature_absence,
            ["--feature", "selected_frame_perception", "--phase", "not-an-integer"],
        ),
        (
            scan_backup_artifacts,
            ["--require-encrypted", "--forbid", "plaintext,plaintext"],
        ),
        (
            scan_sql_schema,
            ["--db-kind", "unknown", "--forbid", "credential"],
        ),
    ),
)
def test_shared_argument_conversion_failures_return_incomplete_exit_two(
    tmp_path: Path,
    tool,
    argv: list[str],
) -> None:
    receipt = tool.evaluate(["--root", str(tmp_path), *argv])

    assert receipt.complete is False
    assert receipt.findings[0].code == "invalid-arguments"
    assert tool.main(["--root", str(tmp_path), *argv]) == 2


def test_feature_absence_checks_direct_replay_and_every_registration_surface(
    shared_assurance_harness,
) -> None:
    for surface in (
        "source",
        "config",
        "api",
        "openapi",
        "package",
        "browser_chunk",
        "ipc",
        "launchd",
        "direct_request",
        "replay",
    ):
        result = shared_assurance_harness.feature_present_only_on(surface)
        assert check_feature_absence.main(result.argv) == 1


@pytest.mark.parametrize(
    "surfaces",
    (
        [],
        [
            "src/feature_registry.py",
            "config/features.json",
            "api/routes.json",
            "openapi/openapi.json",
            "package.json",
            "apps/admin/dist/assets/app.js",
            "ipc/services.json",
            "ipc/services.json",
        ],
        [
            "src/feature_registry.py",
            "config/features.json",
            "api/routes.json",
            "openapi/openapi.json",
            "package.json",
            "apps/admin/dist/assets/app.js",
            "ipc/services.json",
            "synthetic/unknown-surface.json",
        ],
    ),
)
def test_feature_absence_requires_each_canonical_surface_exactly_once(
    shared_assurance_harness,
    surfaces: list[str],
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(check_feature_absence)
    manifest = workspace / ".assurance" / "features.json"
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["surfaces"] = surfaces
    manifest.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    for relative in surfaces:
        surface = workspace / relative
        if surface.exists():
            continue
        surface.parent.mkdir(parents=True, exist_ok=True)
        surface.write_text("{}" if surface.suffix == ".json" else "synthetic\n", encoding="utf-8")
    argv = [
        "--root",
        str(workspace),
        "--feature",
        "selected_frame_perception",
        "--phase",
        "3",
    ]

    receipt = check_feature_absence.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code == "surface-inventory-invalid"
    assert check_feature_absence.main(argv) == 2


def test_feature_absence_always_attests_direct_and_replay_reachability(
    shared_assurance_harness,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(check_feature_absence)
    probes = workspace / ".assurance" / "direct_replay.json"
    payload = json.loads(probes.read_text(encoding="utf-8"))
    payload["replay"] = {"result": "reachable", "side_effects": False}
    probes.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    assert (
        check_feature_absence.main(
            [
                "--root",
                str(workspace),
                "--feature",
                "selected_frame_perception",
                "--phase",
                "3",
            ]
        )
        == 1
    )


@pytest.mark.parametrize(
    "selector",
    (
        ("--feature", "selected_frame_perception", "--phase", "3"),
        (
            "--manifest",
            ".assurance/features.json",
            "--feature",
            "selected_frame_perception",
        ),
    ),
    ids=("phase", "manifest"),
)
def test_feature_absence_rejects_direct_replay_flag_in_feature_selector_modes(
    shared_assurance_harness,
    selector: tuple[str, ...],
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(check_feature_absence)
    argv = ["--root", str(workspace), *selector, "--direct-and-replay"]

    receipt = check_feature_absence.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code == "invalid-arguments"
    assert check_feature_absence.main(argv) == 2


def test_feature_absence_parses_manifest_from_frozen_inventory_bytes(
    shared_assurance_harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(check_feature_absence)

    def forbidden_pathname_read(*args, **kwargs):
        raise AssertionError("feature manifest was reread by pathname")

    monkeypatch.setattr(
        check_feature_absence,
        "read_json_object",
        forbidden_pathname_read,
        raising=False,
    )
    argv = [
        "--root",
        str(workspace),
        "--feature",
        "selected_frame_perception",
        "--phase",
        "3",
    ]

    assert check_feature_absence.main(argv) == 0


def test_feature_absence_revalidates_manifest_after_analysis(
    shared_assurance_harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(check_feature_absence)
    manifest = workspace / ".assurance" / "features.json"
    original_json = check_feature_absence._json
    replacements = 0

    def replace_manifest(path: Path, raw: bytes):
        nonlocal replacements
        replacements += 1
        content = manifest.read_bytes()
        manifest.rename(
            workspace.parent / f"{workspace.name}-features-previous-{replacements}.json"
        )
        manifest.write_bytes(content)
        return original_json(path, raw)

    monkeypatch.setattr(check_feature_absence, "_json", replace_manifest)
    argv = [
        "--root",
        str(workspace),
        "--feature",
        "selected_frame_perception",
        "--phase",
        "3",
    ]

    receipt = check_feature_absence.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code in {
        "input-changed-during-scan",
        "source-inventory-drift",
    }
    assert check_feature_absence.main(argv) == 2


def test_feature_absence_revalidates_ignored_required_evidence(
    shared_assurance_harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(check_feature_absence)
    (workspace / ".gitignore").write_text(
        "apps/admin/dist/\n.assurance/direct_replay*\n",
        encoding="utf-8",
    )
    subprocess.run(
        ("git", "-C", str(workspace), "init", "-q"),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ("git", "-C", str(workspace), "add", "-A"),
        check=True,
        capture_output=True,
    )
    ignored = (
        workspace / "apps" / "admin" / "dist" / "assets" / "app.js",
        workspace / ".assurance" / "direct_replay.json",
    )
    original_json = check_feature_absence._json
    replacements = 0

    def replace_ignored_evidence(path: Path, raw: bytes):
        nonlocal replacements
        replacements += 1
        for target in ignored:
            content = target.read_bytes()
            target.rename(target.with_name(f"{target.name}.previous-{replacements}"))
            target.write_bytes(content)
        return original_json(path, raw)

    monkeypatch.setattr(check_feature_absence, "_json", replace_ignored_evidence)
    argv = [
        "--root",
        str(workspace),
        "--feature",
        "selected_frame_perception",
        "--phase",
        "3",
    ]

    receipt = check_feature_absence.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code in {
        "input-changed-during-scan",
        "source-inventory-drift",
    }
    assert check_feature_absence.main(argv) == 2


def test_import_boundaries_reconstructs_from_imported_private_targets(
    shared_assurance_harness,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(check_import_boundaries)
    source = workspace / "src"
    (source / "vision" / "services").mkdir()
    (source / "vision" / "services" / "consumer.py").write_text(
        "from vision import adapters\nfrom identity import _private\n",
        encoding="utf-8",
    )
    (source / "vision" / "adapters.py").write_text("synthetic = True\n", encoding="utf-8")
    (source / "identity").mkdir()
    (source / "identity" / "__init__.py").write_text("", encoding="utf-8")
    (source / "identity" / "_private.py").write_text("synthetic = True\n", encoding="utf-8")

    receipt = check_import_boundaries.evaluate(["--root", str(workspace), "--domain", "vision"])

    assert receipt.complete is True
    assert {finding.code for finding in receipt.findings} == {
        "adapter-import-boundary",
        "cross-domain-private-import",
    }
    assert check_import_boundaries.main(["--root", str(workspace), "--domain", "vision"]) == 1


def test_import_boundaries_parses_pyproject_from_frozen_inventory_bytes(
    shared_assurance_harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(check_import_boundaries)

    def forbidden_pathname_read(*args, **kwargs):
        raise AssertionError("pyproject was reread by pathname")

    monkeypatch.setattr(
        check_import_boundaries,
        "read_regular_file",
        forbidden_pathname_read,
        raising=False,
    )
    argv = ["--root", str(workspace), "--domain", "vision"]

    assert check_import_boundaries.main(argv) == 0


def test_import_boundaries_revalidates_pyproject_after_analysis(
    shared_assurance_harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(check_import_boundaries)
    pyproject = workspace / "pyproject.toml"
    original_dependencies = check_import_boundaries._declared_dependencies
    replacements = 0

    def replace_pyproject(document):
        nonlocal replacements
        replacements += 1
        content = pyproject.read_bytes()
        pyproject.rename(
            workspace.parent / f"{workspace.name}-pyproject-previous-{replacements}.toml"
        )
        pyproject.write_bytes(content)
        return original_dependencies(document)

    monkeypatch.setattr(check_import_boundaries, "_declared_dependencies", replace_pyproject)
    argv = ["--root", str(workspace), "--domain", "vision"]

    receipt = check_import_boundaries.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code in {
        "input-changed-during-scan",
        "source-inventory-drift",
    }
    assert check_import_boundaries.main(argv) == 2


def test_import_boundaries_resolves_aliased_dynamic_import_functions(
    shared_assurance_harness,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(check_import_boundaries)
    source = workspace / "src"
    (source / "vision" / "services").mkdir()
    (source / "vision" / "services" / "consumer.py").write_text(
        "import importlib as loader\n"
        "from importlib import import_module as load_module\n"
        'loader.import_module("vision.adapters")\n'
        'load_module("identity._private")\n',
        encoding="utf-8",
    )
    (source / "vision" / "adapters.py").write_text("synthetic = True\n", encoding="utf-8")
    (source / "identity").mkdir()
    (source / "identity" / "__init__.py").write_text("", encoding="utf-8")
    (source / "identity" / "_private.py").write_text("synthetic = True\n", encoding="utf-8")

    receipt = check_import_boundaries.evaluate(["--root", str(workspace), "--domain", "vision"])

    assert receipt.complete is True
    assert {finding.code for finding in receipt.findings} == {
        "adapter-import-boundary",
        "cross-domain-private-import",
    }
    assert check_import_boundaries.main(["--root", str(workspace), "--domain", "vision"]) == 1


def test_import_boundaries_resolves_imported_and_qualified_builtins_aliases(
    shared_assurance_harness,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(check_import_boundaries)
    source = workspace / "src"
    (source / "vision" / "services").mkdir()
    (source / "vision" / "services" / "consumer.py").write_text(
        "import builtins as runtime\n"
        "from builtins import __import__ as load\n"
        'runtime.__import__("vision.adapters")\n'
        'load("identity._private")\n',
        encoding="utf-8",
    )
    (source / "vision" / "adapters.py").write_text("synthetic = True\n", encoding="utf-8")
    (source / "identity").mkdir()
    (source / "identity" / "__init__.py").write_text("", encoding="utf-8")
    (source / "identity" / "_private.py").write_text("synthetic = True\n", encoding="utf-8")

    receipt = check_import_boundaries.evaluate(["--root", str(workspace), "--domain", "vision"])

    assert receipt.complete is True
    assert {finding.code for finding in receipt.findings} == {
        "adapter-import-boundary",
        "cross-domain-private-import",
    }
    assert check_import_boundaries.main(["--root", str(workspace), "--domain", "vision"]) == 1


@pytest.mark.parametrize(
    ("hostile_source", "expected_code"),
    (
        (b"synthetic_value = 0\n" * 60_000, "ast-token-limit"),
        (
            b"synthetic_value = " + b"(" * 129 + b"0" + b")" * 129 + b"\n",
            "ast-depth-limit",
        ),
    ),
    ids=("token-limit", "depth-limit"),
)
def test_import_parser_preflights_source_before_ast_allocation(
    shared_assurance_harness,
    monkeypatch: pytest.MonkeyPatch,
    hostile_source: bytes,
    expected_code: str,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(check_import_boundaries)
    candidate = workspace / "src" / "vision" / "service.py"
    candidate.write_bytes(hostile_source)

    real_ast = check_import_boundaries.ast

    class GuardedAst:
        def __getattr__(self, name: str):
            return getattr(real_ast, name)

        def parse(self, source: str, *args, **kwargs):
            if "synthetic_value" in source:
                raise AssertionError("ast.parse reached before bounded source preflight")
            return real_ast.parse(source, *args, **kwargs)

    monkeypatch.setattr(check_import_boundaries, "ast", GuardedAst())
    argv = ["--root", str(workspace), "--domain", "vision"]

    receipt = check_import_boundaries.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code == expected_code
    assert check_import_boundaries.main(argv) == 2


def test_migration_checker_rejects_duplicate_revision_and_hidden_fork(migration_workspace) -> None:
    migration_workspace.add_duplicate_revision("0015")
    assert (
        check_migration_ownership.main(
            [
                "--root",
                str(migration_workspace.root),
                "--revisions",
                "0013",
                "0014",
                "0015",
                "--exact-head",
                "0015_presence_checkpoint",
                "--forbid-branch-merge-orphan",
            ]
        )
        == 1
    )


@pytest.mark.parametrize(
    ("hostile_suffix", "expected_code"),
    (
        (b"synthetic_value = 0\n" * 60_000, "ast-token-limit"),
        (
            b"synthetic_value = " + b"(" * 129 + b"0" + b")" * 129 + b"\n",
            "ast-depth-limit",
        ),
    ),
    ids=("token-limit", "depth-limit"),
)
def test_migration_parser_preflights_source_before_ast_allocation(
    migration_workspace,
    monkeypatch: pytest.MonkeyPatch,
    hostile_suffix: bytes,
    expected_code: str,
) -> None:
    candidate = (
        migration_workspace.root
        / "apps"
        / "core"
        / "migrations"
        / "versions"
        / "0013_presence_checkpoint.py"
    )
    candidate.write_bytes(candidate.read_bytes() + hostile_suffix)

    real_ast = check_migration_ownership.ast

    class GuardedAst:
        def __getattr__(self, name: str):
            return getattr(real_ast, name)

        def parse(self, source: str, *args, **kwargs):
            if "synthetic_value" in source:
                raise AssertionError("ast.parse reached before bounded source preflight")
            return real_ast.parse(source, *args, **kwargs)

    monkeypatch.setattr(check_migration_ownership, "ast", GuardedAst())
    argv = [
        "--root",
        str(migration_workspace.root),
        "--revisions",
        "0013",
        "0014",
        "0015",
    ]

    receipt = check_migration_ownership.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code == expected_code
    assert check_migration_ownership.main(argv) == 2


def test_migration_ownership_rejects_reordered_requested_chain(migration_workspace) -> None:
    argv = [
        "--root",
        str(migration_workspace.root),
        "--revisions",
        "0013",
        "0015",
        "0014",
        "--forbid-branch-merge-orphan",
    ]

    receipt = check_migration_ownership.evaluate(argv)

    assert receipt.complete is True
    assert {finding.code for finding in receipt.findings} == {"requested-revision-order-mismatch"}
    assert check_migration_ownership.main(argv) == 1


def test_migration_graph_reports_fork_with_multiple_children_of_missing_parent(
    migration_workspace,
) -> None:
    versions = migration_workspace.root / "apps" / "core" / "migrations" / "versions"
    for revision in ("0016_synthetic_left", "0017_synthetic_right"):
        (versions / f"{revision}.py").write_text(
            f'revision = "{revision}"\n'
            'down_revision = "0099_missing_parent"\n'
            'schema_owner = "core"\n'
            'ddl = "CREATE TABLE synthetic_checkpoint (id TEXT PRIMARY KEY)"\n',
            encoding="utf-8",
        )
    argv = [
        "--root",
        str(migration_workspace.root),
        "--core-version-table",
        "alembic_version",
        "--exact-head",
        "0015_presence_checkpoint",
        "--forbid-forks",
        "--forbid-orphans",
    ]

    receipt = check_migration_graph.evaluate(argv)

    assert receipt.complete is True
    codes = [finding.code for finding in receipt.findings]
    assert codes.count("migration-orphan") == 2
    assert codes.count("migration-fork") == 1
    assert check_migration_graph.main(argv) == 1


def test_strict_migration_graph_rejects_disconnected_cycle(migration_workspace) -> None:
    versions = migration_workspace.root / "apps" / "core" / "migrations" / "versions"
    cycle = (
        ("0020_synthetic_cycle_left", "0021_synthetic_cycle_right"),
        ("0021_synthetic_cycle_right", "0020_synthetic_cycle_left"),
    )
    for revision, parent in cycle:
        (versions / f"{revision}.py").write_text(
            f'revision = "{revision}"\n'
            f'down_revision = "{parent}"\n'
            'schema_owner = "core"\n'
            'ddl = "CREATE TABLE synthetic_cycle (id TEXT PRIMARY KEY)"\n',
            encoding="utf-8",
        )
    argv = [
        "--root",
        str(migration_workspace.root),
        "--revisions",
        "0013",
        "0014",
        "0015",
        "--forbid-branch-merge-orphan",
    ]

    receipt = check_migration_ownership.evaluate(argv)

    assert receipt.complete is True
    assert {finding.code for finding in receipt.findings} >= {
        "migration-cycle",
        "migration-disconnected",
    }
    assert check_migration_ownership.main(argv) == 1


def test_strict_migration_graph_requires_exactly_one_root_and_head(
    migration_workspace,
) -> None:
    versions = migration_workspace.root / "apps" / "core" / "migrations" / "versions"
    (versions / "0020_synthetic_second_root.py").write_text(
        'revision = "0020_synthetic_second_root"\n'
        "down_revision = None\n"
        'schema_owner = "core"\n'
        'ddl = "CREATE TABLE synthetic_root (id TEXT PRIMARY KEY)"\n',
        encoding="utf-8",
    )
    argv = [
        "--root",
        str(migration_workspace.root),
        "--revisions",
        "0013",
        "0014",
        "0015",
        "--forbid-branch-merge-orphan",
    ]

    receipt = check_migration_ownership.evaluate(argv)

    assert receipt.complete is True
    assert {finding.code for finding in receipt.findings} >= {
        "migration-root-count",
        "migration-head-count",
        "migration-disconnected",
    }
    assert check_migration_ownership.main(argv) == 1


def test_strict_migration_request_rejects_parent_before_requested_ancestry(tmp_path: Path) -> None:
    workspace = MigrationWorkspace.create_linear(
        tmp_path / "migrations",
        ("0012", "0013", "0014", "0015"),
    )
    argv = [
        "--root",
        str(workspace.root),
        "--revisions",
        "0013",
        "0014",
        "0015",
        "--forbid-branch-merge-orphan",
    ]

    receipt = check_migration_ownership.evaluate(argv)

    assert receipt.complete is True
    assert "requested-ancestry-not-closed" in {finding.code for finding in receipt.findings}
    assert check_migration_ownership.main(argv) == 1


def test_network_checker_requires_complete_pid_owner_snapshot(
    network_inventory, monkeypatch: pytest.MonkeyPatch
) -> None:
    network_inventory.truncate_between_socket_and_process_tables()
    network_inventory.install_as_probe(monkeypatch)
    assert (
        scan_network_surface.main(
            [
                "--root",
                str(network_inventory.root),
                "--require-listener",
                "127.0.0.1:8787=owner_ingress",
                "--forbid-wildcard",
            ]
        )
        == 2
    )


@pytest.mark.parametrize(
    ("capture", "socket_rows"),
    (
        (
            scan_network_surface._capture_linux,
            b'tcp LISTEN 0 128 127.0.0.1:8787 0.0.0.0:* users:(("python",pid=4101,fd=7))\n',
        ),
        (
            scan_network_surface._capture_darwin,
            b"p4101\ncpython\nPTCP\nTST=LISTEN\nn127.0.0.1:8787\n",
        ),
    ),
)
def test_network_capture_binds_listener_to_stable_canonical_service_owner(
    monkeypatch: pytest.MonkeyPatch,
    capture,
    socket_rows: bytes,
) -> None:
    process_rows = (
        b"4101 Sat Aug 29 16:00:00 2026 python -m tuntun_owner_ingress.entrypoint start\n"
    )

    def probe(argv: tuple[str, ...]) -> bytes:
        return process_rows if Path(argv[0]).name == "ps" else socket_rows

    monkeypatch.setattr(scan_network_surface, "_bounded_command", probe)

    snapshot = capture(7001)

    assert snapshot.complete is True
    assert scan_network_surface._listeners(snapshot) == (
        scan_network_surface.ListenerRecord(
            "tcp", "127.0.0.1", 8787, 4101, "python", "owner_ingress"
        ),
    )


@pytest.mark.parametrize(
    ("capture", "socket_rows"),
    (
        (
            scan_network_surface._capture_linux,
            b'tcp LISTEN 0 128 127.0.0.1:8787 0.0.0.0:* users:(("python",pid=4101,fd=7))\n',
        ),
        (
            scan_network_surface._capture_darwin,
            b"p4101\ncpython\nPTCP\nTST=LISTEN\nn127.0.0.1:8787\n",
        ),
    ),
)
def test_network_capture_rejects_pid_identity_change_across_socket_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    capture,
    socket_rows: bytes,
) -> None:
    process_samples = iter(
        (
            b"4101 Sat Aug 29 16:00:00 2026 python -m tuntun_owner_ingress.entrypoint start\n",
            b"4101 Sat Aug 29 16:00:01 2026 python -m tuntun_core.cli.main start\n",
        )
    )

    def probe(argv: tuple[str, ...]) -> bytes:
        return next(process_samples) if Path(argv[0]).name == "ps" else socket_rows

    monkeypatch.setattr(scan_network_surface, "_bounded_command", probe)

    snapshot = capture(7001)

    assert snapshot.complete is False
    assert snapshot.errors == ("process-inventory-drift",)


@pytest.mark.parametrize(
    ("capture", "socket_rows"),
    (
        (
            scan_network_surface._capture_linux,
            b'tcp LISTEN 0 128 127.0.0.1:8787 0.0.0.0:* users:(("python",pid=4101,fd=7))\n',
        ),
        (
            scan_network_surface._capture_darwin,
            b"p4101\ncpython\nPTCP\nTST=LISTEN\nn127.0.0.1:8787\n",
        ),
    ),
)
def test_network_capture_rejects_unresolved_generic_process_owner(
    monkeypatch: pytest.MonkeyPatch,
    capture,
    socket_rows: bytes,
) -> None:
    process_rows = b"4101 Sat Aug 29 16:00:00 2026 python synthetic_worker.py\n"

    def probe(argv: tuple[str, ...]) -> bytes:
        return process_rows if Path(argv[0]).name == "ps" else socket_rows

    monkeypatch.setattr(scan_network_surface, "_bounded_command", probe)

    snapshot = capture(7001)

    assert snapshot.complete is False
    assert snapshot.errors == ("service-owner-unresolved",)


@pytest.mark.parametrize(
    ("capture", "socket_rows"),
    (
        (
            scan_network_surface._capture_linux,
            b'tcp LISTEN 0 128 0.0.0.0:9797 0.0.0.0:* users:(("syntheticd",pid=4102,fd=7))\n',
        ),
        (
            scan_network_surface._capture_darwin,
            b"p4102\ncsyntheticd\nPTCP\nTST=LISTEN\nn0.0.0.0:9797\n",
        ),
    ),
)
def test_network_capture_assigns_stable_native_owner_and_applies_wildcard_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capture,
    socket_rows: bytes,
) -> None:
    process_rows = b"4102 Sat Aug 29 16:05:00 2026 /usr/sbin/syntheticd --serve\n"

    def probe(argv: tuple[str, ...]) -> bytes:
        return process_rows if Path(argv[0]).name == "ps" else socket_rows

    monkeypatch.setattr(scan_network_surface, "_bounded_command", probe)
    snapshot = capture(7001)

    assert snapshot.complete is True
    assert scan_network_surface._listeners(snapshot) == (
        scan_network_surface.ListenerRecord(
            "tcp", "0.0.0.0", 9797, 4102, "syntheticd", "external_syntheticd"
        ),
    )
    monkeypatch.setattr(scan_network_surface, "capture_inventory", lambda: snapshot)
    assert scan_network_surface.main(["--root", str(tmp_path), "--forbid-wildcard"]) == 1


def test_network_capture_normalizes_spawn_failure_to_incomplete_exit_two(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(*args, **kwargs):
        raise PermissionError("synthetic process enumeration denial")

    monkeypatch.setattr(scan_network_surface.platform, "system", lambda: "Linux")
    monkeypatch.setattr(scan_network_surface.subprocess, "Popen", unavailable)
    argv = ["--root", str(tmp_path), "--forbid-wildcard"]

    receipt = scan_network_surface.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code == "inventory-incomplete"
    assert scan_network_surface.main(argv) == 2


def test_network_process_capture_uses_unambiguous_pid_start_and_args_shape() -> None:
    rows = (
        b"4100 Sat Aug 29 15:59:59 2026 "
        b"/Applications/Synthetic Helper.app/Contents/MacOS/Helper --idle\n"
        b"4101 Sat Aug 29 16:00:00 2026 python -m tuntun_owner_ingress.entrypoint start\n"
    )

    processes = scan_network_surface._process_records(rows, 7001)

    assert processes[1] == scan_network_surface.ProcessRecord(
        4101,
        "python",
        "owner_ingress",
        7001,
        "Sat Aug 29 16:00:00 2026",
        "python -m tuntun_owner_ingress.entrypoint start",
    )


def test_darwin_socket_parser_buffers_real_file_records_and_ignores_unbound_udp() -> None:
    rows = (
        b"p4101\nf21u\nPTCP\nn127.0.0.1:8787\nTST=LISTEN\n"
        b"p4102\nf22u\nPUDP\nn*:*\n"
        b"p4103\nf23u\nPUDP\nn127.0.0.1:5353\n"
    )

    sockets = scan_network_surface._darwin_socket_records(rows, 7001)

    assert sockets == (
        scan_network_surface.SocketRecord("tcp", "127.0.0.1", 8787, 4101, 7001),
        scan_network_surface.SocketRecord("udp", "127.0.0.1", 5353, 4103, 7001),
    )


def test_linux_shared_listener_with_one_canonical_owner_is_normalized_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_rows = (
        b"4101 Sat Aug 29 16:00:00 2026 python -m tuntun_owner_ingress.worker_a start\n"
        b"4102 Sat Aug 29 16:00:00 2026 python -m tuntun_owner_ingress.worker_b start\n"
    )
    socket_rows = (
        b"tcp LISTEN 0 128 127.0.0.1:8787 0.0.0.0:* users:"
        b'(("python",pid=4101,fd=7),("python",pid=4102,fd=8))\n'
    )

    def probe(argv: tuple[str, ...]) -> bytes:
        return process_rows if Path(argv[0]).name == "ps" else socket_rows

    monkeypatch.setattr(scan_network_surface, "_bounded_command", probe)

    snapshot = scan_network_surface._capture_linux(7001)

    assert snapshot.complete is True
    assert tuple(process.pid for process in snapshot.processes) == (4101, 4102)
    assert scan_network_surface._listeners(snapshot) == (
        scan_network_surface.ListenerRecord(
            "tcp", "127.0.0.1", 8787, 4101, "python", "owner_ingress"
        ),
    )


@pytest.mark.parametrize(
    ("second_process", "expected_code"),
    (
        (
            b"4102 Sat Aug 29 16:00:00 2026 python -m tuntun_core.worker start\n",
            "socket-owner-ambiguous",
        ),
        (b"", "inventory-incomplete"),
    ),
    ids=("mixed-owner", "missing-process-row"),
)
def test_linux_shared_listener_with_ambiguous_process_inventory_exits_two(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    second_process: bytes,
    expected_code: str,
) -> None:
    process_rows = (
        b"4101 Sat Aug 29 16:00:00 2026 python -m tuntun_owner_ingress.worker start\n"
        + second_process
    )
    socket_rows = (
        b"tcp LISTEN 0 128 127.0.0.1:8787 0.0.0.0:* users:"
        b'(("python",pid=4101,fd=7),("python",pid=4102,fd=8))\n'
    )

    def probe(argv: tuple[str, ...]) -> bytes:
        return process_rows if Path(argv[0]).name == "ps" else socket_rows

    monkeypatch.setattr(scan_network_surface, "_bounded_command", probe)
    snapshot = scan_network_surface._capture_linux(7001)
    monkeypatch.setattr(scan_network_surface, "capture_inventory", lambda: snapshot)
    argv = ["--root", str(tmp_path), "--forbid-wildcard"]

    receipt = scan_network_surface.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code == expected_code
    assert scan_network_surface.main(argv) == 2


@pytest.mark.parametrize("suffix", (".json.gz", ".map.gz"))
def test_browser_artifacts_structurally_validate_compressed_json(
    shared_assurance_harness,
    suffix: str,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(scan_browser_artifacts)
    candidate = workspace / "apps" / "admin" / "dist" / "assets" / f"invalid{suffix}"
    candidate.write_bytes(gzip.compress(b'{"synthetic":'))
    argv = ["--root", str(workspace), "--forbid", "credential,reusable_token"]

    receipt = scan_browser_artifacts.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code == "invalid-json"
    assert scan_browser_artifacts.main(argv) == 2


def test_browser_artifacts_parse_archive_members_for_forbidden_content(
    shared_assurance_harness,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(scan_browser_artifacts)
    candidate = workspace / "apps" / "admin" / "dist" / "assets" / "browser.zip"
    with zipfile.ZipFile(candidate, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("chunks/app.js", "window.localStorage.setItem('role', 'synthetic');")
    argv = ["--root", str(workspace), "--forbid", "persistent_storage"]

    receipt = scan_browser_artifacts.evaluate(argv)

    assert receipt.complete is True
    assert [(finding.code, finding.detail) for finding in receipt.findings] == [
        ("forbidden-browser-artifact", "persistent_storage")
    ]
    assert scan_browser_artifacts.main(argv) == 1


def test_browser_artifacts_reject_corrupt_archive_as_incomplete(
    shared_assurance_harness,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(scan_browser_artifacts)
    candidate = workspace / "apps" / "admin" / "dist" / "assets" / "truncated.zip"
    candidate.write_bytes(b"PK\x03\x04synthetic-truncated")
    argv = ["--root", str(workspace), "--forbid", "credential"]

    receipt = scan_browser_artifacts.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code == "corrupt-browser-archive"
    assert scan_browser_artifacts.main(argv) == 2


def test_browser_zip_preflight_rejects_over_limit_count_before_zipfile_allocation(
    shared_assurance_harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(scan_browser_artifacts)
    candidate = workspace / "apps" / "admin" / "dist" / "assets" / "over-count.zip"
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("chunks/app.js", "const syntheticRole = 'operator';")
    raw = bytearray(archive_bytes.getvalue())
    eocd = raw.rfind(b"PK\x05\x06")
    assert eocd >= 0
    struct.pack_into("<HH", raw, eocd + 8, 4097, 4097)
    candidate.write_bytes(raw)

    def forbidden_zipfile(*args, **kwargs):
        raise AssertionError("ZipFile allocated before bounded central-directory preflight")

    monkeypatch.setattr(scan_browser_artifacts.zipfile, "ZipFile", forbidden_zipfile)
    argv = ["--root", str(workspace), "--forbid", "credential"]

    receipt = scan_browser_artifacts.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code == "browser-archive-member-limit"
    assert scan_browser_artifacts.main(argv) == 2


def test_browser_unsupported_archive_codec_normalizes_to_incomplete_exit_two(
    shared_assurance_harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(scan_browser_artifacts)
    candidate = workspace / "apps" / "admin" / "dist" / "assets" / "unsupported.zip"
    with zipfile.ZipFile(candidate, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("chunks/app.js", "const syntheticRole = 'operator';")

    def unsupported_archive(*args, **kwargs):
        raise zipfile.LargeZipFile("synthetic unsupported archive codec")

    monkeypatch.setattr(scan_browser_artifacts.zipfile, "ZipFile", unsupported_archive)
    argv = ["--root", str(workspace), "--forbid", "credential"]

    receipt = scan_browser_artifacts.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code == "browser-archive-unsupported"
    assert scan_browser_artifacts.main(argv) == 2


def test_browser_artifacts_structurally_validate_json_inside_archive(
    shared_assurance_harness,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(scan_browser_artifacts)
    candidate = workspace / "apps" / "admin" / "dist" / "assets" / "maps.zip"
    with zipfile.ZipFile(candidate, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("chunks/app.js.map", '{"version":')
    argv = ["--root", str(workspace), "--forbid", "credential"]

    receipt = scan_browser_artifacts.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code == "invalid-json"
    assert scan_browser_artifacts.main(argv) == 2


def test_browser_artifacts_scan_physical_archive_metadata(
    shared_assurance_harness,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(scan_browser_artifacts)
    candidate = workspace / "apps" / "admin" / "dist" / "assets" / "metadata.zip"
    with zipfile.ZipFile(candidate, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("chunks/app.js", "const syntheticRole = 'operator';")
        archive.comment = b"localStorage"
    argv = ["--root", str(workspace), "--forbid", "persistent_storage"]

    receipt = scan_browser_artifacts.evaluate(argv)

    assert receipt.complete is True
    assert any(
        finding.path == candidate
        and finding.code == "forbidden-browser-artifact"
        and finding.detail == "persistent_storage"
        for finding in receipt.findings
    )
    assert scan_browser_artifacts.main(argv) == 1


def test_browser_artifacts_recurse_into_gzip_wrapped_archive(
    shared_assurance_harness,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(scan_browser_artifacts)
    nested = io.BytesIO()
    with zipfile.ZipFile(nested, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("chunks/app.js", "window.localStorage.setItem('role', 'synthetic');")
    candidate = workspace / "apps" / "admin" / "dist" / "assets" / "nested.zip.gz"
    candidate.write_bytes(gzip.compress(nested.getvalue()))
    argv = ["--root", str(workspace), "--forbid", "persistent_storage"]

    receipt = scan_browser_artifacts.evaluate(argv)

    assert receipt.complete is True
    assert any(
        finding.path == Path(f"{candidate.with_suffix('')}!chunks/app.js")
        and finding.code == "forbidden-browser-artifact"
        and finding.detail == "persistent_storage"
        for finding in receipt.findings
    )
    assert scan_browser_artifacts.main(argv) == 1


def test_browser_compressed_members_charge_shared_cumulative_expansion(
    shared_assurance_harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(scan_browser_artifacts)
    payload = b'{"synthetic":"' + b"x" * 4096 + b'"}'
    compressed = gzip.compress(payload)
    candidate = workspace / "apps" / "admin" / "dist" / "assets" / "compressed.zip"
    with zipfile.ZipFile(candidate, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("chunks/one.json.gz", compressed)
        archive.writestr("chunks/two.json.gz", compressed)
    physical_total = sum(
        path.stat().st_size
        for path in (workspace / "apps" / "admin" / "dist").rglob("*")
        if path.is_file()
    )
    current_archive_charge = 2 * len(compressed)
    limit = max(physical_total, current_archive_charge) + 1
    assert limit < current_archive_charge + 2 * len(payload)
    monkeypatch.setattr(scan_browser_artifacts, "MAX_WALK_TOTAL_BYTES", limit)
    argv = ["--root", str(workspace), "--forbid", "credential"]

    receipt = scan_browser_artifacts.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code == "browser-archive-expanded-byte-limit"
    assert scan_browser_artifacts.main(argv) == 2


def test_browser_tar_gzip_charges_decoded_headers_and_padding(
    shared_assurance_harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(scan_browser_artifacts)
    payload = b"const syntheticRole = 'operator';"
    compressed = io.BytesIO()
    with tarfile.open(fileobj=compressed, mode="w:gz") as archive:
        member = tarfile.TarInfo("chunks/app.js")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    candidate = workspace / "apps" / "admin" / "dist" / "assets" / "bundle.tar.gz"
    candidate.write_bytes(compressed.getvalue())
    physical_total = sum(
        path.stat().st_size
        for path in (workspace / "apps" / "admin" / "dist").rglob("*")
        if path.is_file()
    )
    decoded_size = len(gzip.decompress(compressed.getvalue()))
    limit = max(physical_total, len(payload)) + 1
    assert limit < decoded_size
    monkeypatch.setattr(scan_browser_artifacts, "MAX_WALK_TOTAL_BYTES", limit)
    argv = ["--root", str(workspace), "--forbid", "credential"]

    receipt = scan_browser_artifacts.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code == "browser-archive-expanded-byte-limit"
    assert scan_browser_artifacts.main(argv) == 2


def test_browser_gzip_expansion_avoids_full_payload_materializer(
    shared_assurance_harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(scan_browser_artifacts)
    candidate = workspace / "apps" / "admin" / "dist" / "assets" / "clean.json.gz"
    candidate.write_bytes(gzip.compress(b'{"synthetic":"role"}'))

    def forbidden_full_materialization(raw: bytes) -> bytes:
        raise AssertionError("full gzip payload materialization is forbidden")

    monkeypatch.setattr(gzip, "decompress", forbidden_full_materialization)
    argv = ["--root", str(workspace), "--forbid", "credential"]

    assert scan_browser_artifacts.main(argv) == 0


def test_browser_brotli_expansion_avoids_full_payload_materializer(
    shared_assurance_harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(scan_browser_artifacts)
    candidate = workspace / "apps" / "admin" / "dist" / "assets" / "clean.json.br"
    candidate.write_bytes(b'{"synthetic":"role"}')

    def forbidden_discovery(name: str):
        if name == "brotli":
            raise AssertionError("Brotli discovery is forbidden without a bounded worker")
        return None

    monkeypatch.setattr(importlib.util, "find_spec", forbidden_discovery)
    argv = ["--root", str(workspace), "--forbid", "credential"]

    receipt = scan_browser_artifacts.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code == "browser-decoder-unavailable"
    assert scan_browser_artifacts.main(argv) == 2


def test_browser_brotli_high_ratio_single_call_fails_closed_without_isolated_decoder(
    shared_assurance_harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_calls = 0

    class SyntheticHighRatioBrotli:
        class Decompressor:
            def process(self, raw: bytes) -> bytes:
                nonlocal process_calls
                process_calls += 1
                return b"x" * (scan_browser_artifacts.MAX_REGULAR_FILE_BYTES + 1)

            def is_finished(self) -> bool:
                return True

    workspace = shared_assurance_harness.complete_positive_workspace_for(scan_browser_artifacts)
    candidate = workspace / "apps" / "admin" / "dist" / "assets" / "ratio.js.br"
    candidate.write_bytes(b"synthetic compressed bytes")
    real_import = importlib.import_module

    def forbidden_import(name: str, *args, **kwargs):
        if name == "brotli":
            return SyntheticHighRatioBrotli
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", forbidden_import)
    argv = ["--root", str(workspace), "--forbid", "credential"]

    receipt = scan_browser_artifacts.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code == "browser-decoder-unavailable"
    assert process_calls == 0
    assert scan_browser_artifacts.main(argv) == 2
    assert process_calls == 0


def test_thin_private_data_cli_exercises_pass_finding_and_incomplete_exit_classes(
    tmp_path: Path,
) -> None:
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "fixture.txt").write_text("synthetic-role", encoding="utf-8")
    assert scan_private_data.main(["--paths", str(clean)]) == 0

    finding = tmp_path / "finding"
    finding.mkdir()
    (finding / "state.sqlite3").write_bytes(b"SQLite format 3\x00")
    assert scan_private_data.main(["--paths", str(finding)]) == 1

    missing = tmp_path / "missing"
    receipt = scan_private_data.evaluate(["--paths", str(missing)])
    assert receipt.complete is False
    assert scan_private_data.main(["--paths", str(missing)]) == 2


def _synthetic_authenticated_backup_payload() -> bytes:
    return b"TUNTUN-AEAD\x00" + b"\x01\x01" + b"N" * 24 + b"synthetic-ciphertext" + b"T" * 16


def _synthetic_backup_fixture(root: Path) -> list[str]:
    root.mkdir()
    (root / "manifest.json").write_text(
        '{"format":"tuntun-authenticated-backup-v1",'
        '"cipher":"xchacha20-poly1305","authenticated":true,'
        '"files":["payload.enc"]}',
        encoding="utf-8",
    )
    (root / "payload.enc").write_bytes(_synthetic_authenticated_backup_payload())
    return [
        "--root",
        str(root),
        "--require-encrypted",
        "--forbid",
        "portable_secret,video,plaintext",
    ]


def test_backup_parses_manifest_from_frozen_inventory_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    argv = _synthetic_backup_fixture(tmp_path / "backup")

    def forbidden_pathname_read(*args, **kwargs):
        raise AssertionError("backup manifest was reread by pathname")

    monkeypatch.setattr(
        scan_backup_artifacts,
        "read_json_object",
        forbidden_pathname_read,
        raising=False,
    )

    assert scan_backup_artifacts.main(argv) == 0


def test_backup_revalidates_manifest_after_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backup = tmp_path / "backup"
    argv = _synthetic_backup_fixture(backup)
    manifest = backup / "manifest.json"
    original_envelope = scan_backup_artifacts._authenticated_envelope
    replacements = 0

    def replace_manifest(raw: bytes, cipher: str) -> bool:
        nonlocal replacements
        replacements += 1
        content = manifest.read_bytes()
        manifest.rename(backup.parent / f"{backup.name}-manifest-previous-{replacements}.json")
        manifest.write_bytes(content)
        return original_envelope(raw, cipher)

    monkeypatch.setattr(scan_backup_artifacts, "_authenticated_envelope", replace_manifest)

    receipt = scan_backup_artifacts.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code in {
        "input-changed-during-scan",
        "source-inventory-drift",
    }
    assert scan_backup_artifacts.main(argv) == 2


def test_backup_rejects_unknown_manifest_cipher_as_incomplete(tmp_path: Path) -> None:
    backup = tmp_path / "backup"
    backup.mkdir()
    (backup / "manifest.json").write_text(
        '{"format":"tuntun-authenticated-backup-v1","cipher":"synthetic-arbitrary",'
        '"authenticated":true,"files":["payload.enc"]}',
        encoding="utf-8",
    )
    (backup / "payload.enc").write_bytes(_synthetic_authenticated_backup_payload())
    argv = ["--root", str(backup), "--require-encrypted", "--forbid", "plaintext"]

    receipt = scan_backup_artifacts.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code == "encryption-proof-invalid"
    assert scan_backup_artifacts.main(argv) == 2


def test_backup_rejects_header_only_payload_as_missing_encryption_proof(
    tmp_path: Path,
) -> None:
    backup = tmp_path / "backup"
    backup.mkdir()
    (backup / "manifest.json").write_text(
        '{"format":"tuntun-authenticated-backup-v1",'
        '"cipher":"xchacha20-poly1305","authenticated":true,'
        '"files":["payload.enc"]}',
        encoding="utf-8",
    )
    (backup / "payload.enc").write_bytes(b"TUNTUN-AEAD\x00")
    argv = ["--root", str(backup), "--require-encrypted", "--forbid", "plaintext"]

    receipt = scan_backup_artifacts.evaluate(argv)

    assert receipt.complete is True
    assert [finding.code for finding in receipt.findings] == ["encryption-proof-missing"]
    assert scan_backup_artifacts.main(argv) == 1


@pytest.mark.parametrize(
    ("declaration", "expected_code"),
    (
        ('schema_owner = "core"\n', "schema-owner-mismatch"),
        ("", "unowned-or-unknown-ddl"),
    ),
)
def test_sql_schema_rejects_omitted_or_false_self_declared_ownership(
    tmp_path: Path,
    declaration: str,
    expected_code: str,
) -> None:
    versions = tmp_path / "apps" / "vision" / "migrations" / "versions"
    versions.mkdir(parents=True)
    (versions / "0001_vision_schema.py").write_text(
        'revision = "0001_vision_schema"\n'
        "down_revision = None\n"
        'schema_owner = "vision"\n'
        'ddl = "CREATE TABLE observation (id TEXT PRIMARY KEY)"\n',
        encoding="utf-8",
    )
    (versions / "0002_hidden_schema.py").write_text(
        'revision = "0002_hidden_schema"\n'
        'down_revision = "0001_vision_schema"\n'
        f"{declaration}"
        'ddl = "CREATE TABLE credential (id TEXT PRIMARY KEY)"\n',
        encoding="utf-8",
    )
    argv = ["--root", str(tmp_path), "--db-kind", "vision", "--forbid", "credential"]

    receipt = scan_sql_schema.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code == expected_code
    assert scan_sql_schema.main(argv) == 2


def test_sandbox_scan_retains_and_revalidates_root_descriptor_through_handle_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    replacement_count = 0

    def replace_during_handle_check(
        root: Path,
        scanner_handle: tuple[int, int] | None = None,
    ) -> tuple[str, ...]:
        nonlocal replacement_count
        assert scanner_handle is not None
        scanner_pid, descriptor = scanner_handle
        assert scanner_pid == os.getpid()
        assert stat.S_ISDIR(os.fstat(descriptor).st_mode)
        replacement_count += 1
        root.rename(root.with_name(f"sandbox-original-{replacement_count}"))
        root.mkdir()
        return ()

    monkeypatch.setattr(
        scan_sandbox_residue,
        "_process_handles",
        replace_during_handle_check,
    )
    argv = ["--root", str(sandbox), "--require-empty"]

    receipt = scan_sandbox_residue.evaluate(argv)

    assert receipt.complete is False
    assert receipt.findings[0].code == "input-changed-during-scan"
    assert scan_sandbox_residue.main(argv) == 2


@pytest.mark.parametrize(
    ("failure_stage", "error_type", "expected_exit"),
    (
        ("readlink", FileNotFoundError, 0),
        ("readlink", PermissionError, 2),
        ("readlink", OSError, 2),
        ("enumeration", FileNotFoundError, 0),
        ("enumeration", PermissionError, 2),
        ("enumeration", OSError, 2),
    ),
)
def test_linux_sandbox_handle_scan_only_tolerates_process_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
    error_type: type[OSError],
    expected_exit: int,
) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    proc = Path("/proc")
    process = proc / "4101"
    descriptors = process / "fd"
    descriptor = descriptors / "7"

    def synthetic_iterdir(path: Path):
        if path == proc:
            return iter((process,))
        if path == descriptors:
            if failure_stage == "enumeration":
                raise error_type("synthetic descriptor inventory failure")
            return iter((descriptor,))
        raise AssertionError(f"unexpected directory enumeration: {path}")

    def synthetic_readlink(path: Path) -> str:
        assert path == descriptor
        if failure_stage == "readlink":
            raise error_type("synthetic descriptor read failure")
        return str(sandbox / "synthetic-handle")

    monkeypatch.setattr(scan_sandbox_residue.platform, "system", lambda: "Linux")
    monkeypatch.setattr(Path, "is_dir", lambda path: path == proc)
    monkeypatch.setattr(Path, "iterdir", synthetic_iterdir)
    monkeypatch.setattr(scan_sandbox_residue.os, "readlink", synthetic_readlink)
    argv = ["--root", str(sandbox), "--require-empty"]

    receipt = scan_sandbox_residue.evaluate(argv)

    assert receipt.exit_code() == expected_exit
    if expected_exit == 2:
        assert receipt.complete is False
        assert receipt.findings[0].code == "handle-inventory-incomplete"
    else:
        assert receipt.complete is True
    assert scan_sandbox_residue.main(argv) == expected_exit


@pytest.mark.parametrize(
    ("raw", "limits", "expected"),
    (
        (
            b'{"synthetic":[[[]]]}',
            {"max_depth": 3, "max_containers": 20, "max_tokens": 20},
            "json-depth-limit",
        ),
        (
            b'{"synthetic":[[[]]]}',
            {"max_depth": 20, "max_containers": 3, "max_tokens": 20},
            "json-container-limit",
        ),
        (
            b'{"synthetic":[0,1]}',
            {"max_depth": 20, "max_containers": 20, "max_tokens": 4},
            "json-token-limit",
        ),
    ),
)
def test_json_limits_are_enforced_before_object_graph_materialization(
    monkeypatch: pytest.MonkeyPatch,
    raw: bytes,
    limits: dict[str, int],
    expected: str,
) -> None:
    def forbidden_materialization(*args, **kwargs):
        raise AssertionError("JSON object graph was materialized before preflight")

    monkeypatch.setattr(assurance_common.json, "loads", forbidden_materialization)

    with pytest.raises(ValueError, match=f"^{expected}$"):
        assurance_common.parse_json_object(raw, **limits)


def test_backup_sandbox_and_sql_clis_exercise_all_exit_classes(tmp_path: Path) -> None:
    backup = tmp_path / "backup"
    backup.mkdir()
    (backup / "manifest.json").write_text(
        '{"format":"tuntun-authenticated-backup-v1",'
        '"cipher":"xchacha20-poly1305",'
        '"authenticated":true,"files":["payload.enc"]}',
        encoding="utf-8",
    )
    (backup / "payload.enc").write_bytes(_synthetic_authenticated_backup_payload())
    backup_args = [
        "--root",
        str(backup),
        "--require-encrypted",
        "--forbid",
        "portable_secret,video,plaintext",
    ]
    assert scan_backup_artifacts.main(backup_args) == 0
    (backup / "notes.txt").write_text("synthetic", encoding="utf-8")
    assert scan_backup_artifacts.main(backup_args) == 1
    assert (
        scan_backup_artifacts.main(
            ["--root", str(tmp_path / "missing"), "--require-encrypted", "--forbid", "plaintext"]
        )
        == 2
    )

    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    assert scan_sandbox_residue.main(["--root", str(sandbox), "--require-empty"]) == 0
    (sandbox / "residue.txt").write_text("synthetic", encoding="utf-8")
    assert scan_sandbox_residue.main(["--root", str(sandbox), "--require-empty"]) == 1
    assert scan_sandbox_residue.main(["--root", str(tmp_path / "absent"), "--require-empty"]) == 2

    schema = tmp_path / "schema"
    versions = schema / "apps" / "vision" / "migrations" / "versions"
    versions.mkdir(parents=True)
    (versions / "0001_schema.py").write_text(
        'revision = "0001_vision_schema"\n'
        "down_revision = None\n"
        'schema_owner = "vision"\n'
        'ddl = "CREATE TABLE observation (id TEXT PRIMARY KEY)"\n',
        encoding="utf-8",
    )
    schema_args = ["--root", str(schema), "--db-kind", "vision", "--forbid", "biometric,credential"]
    assert scan_sql_schema.main(schema_args) == 0
    (versions / "0001_schema.py").write_text(
        'revision = "0001_vision_schema"\n'
        "down_revision = None\n"
        'schema_owner = "vision"\n'
        'ddl = "CREATE TABLE credential (id TEXT PRIMARY KEY)"\n',
        encoding="utf-8",
    )
    assert scan_sql_schema.main(schema_args) == 1
    assert (
        scan_sql_schema.main(
            [
                "--root",
                str(tmp_path / "missing-schema"),
                "--db-kind",
                "vision",
                "--forbid",
                "credential",
            ]
        )
        == 2
    )


def test_migration_graph_exercises_pass_finding_and_incomplete_exit_classes(
    migration_workspace,
) -> None:
    args = [
        "--root",
        str(migration_workspace.root),
        "--core-version-table",
        "alembic_version",
        "--exact-head",
        "0015_presence_checkpoint",
        "--exact-edge",
        "0015_presence_checkpoint:0014_presence_checkpoint",
        "--forbid-forks",
        "--forbid-merges",
        "--forbid-orphans",
    ]
    assert check_migration_graph.main(args) == 0
    migration_workspace.add_duplicate_revision("0015")
    assert check_migration_graph.main(args) == 1
    missing_args = [*args]
    missing_args[1] = str(Path(migration_workspace.root) / "missing")
    receipt = check_migration_graph.evaluate(missing_args)
    assert receipt.complete is False
    assert check_migration_graph.main(missing_args) == 2
