import subprocess
from pathlib import Path

import pytest

from scripts import (
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
    assert all(code in {1, 2} for code in result.exit_codes)
    assert all(receipt.complete is False for receipt in result.receipts)


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


def test_backup_sandbox_and_sql_clis_exercise_all_exit_classes(tmp_path: Path) -> None:
    backup = tmp_path / "backup"
    backup.mkdir()
    (backup / "manifest.json").write_text(
        '{"format":"tuntun-authenticated-backup-v1","cipher":"synthetic-aead",'
        '"authenticated":true,"files":["payload.enc"]}',
        encoding="utf-8",
    )
    (backup / "payload.enc").write_bytes(b"TUNTUN-AEAD\x00synthetic-ciphertext")
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
