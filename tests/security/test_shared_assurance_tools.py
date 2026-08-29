import gzip
import importlib
import io
import json
import os
import stat
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

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
    class SyntheticBrotli:
        class Decompressor:
            def process(self, raw: bytes) -> bytes:
                return raw

            def is_finished(self) -> bool:
                return True

        @staticmethod
        def decompress(raw: bytes) -> bytes:
            raise AssertionError("full brotli payload materialization is forbidden")

    workspace = shared_assurance_harness.complete_positive_workspace_for(scan_browser_artifacts)
    candidate = workspace / "apps" / "admin" / "dist" / "assets" / "clean.json.br"
    candidate.write_bytes(b'{"synthetic":"role"}')
    real_import = importlib.import_module
    monkeypatch.setattr(
        scan_browser_artifacts.importlib,
        "import_module",
        lambda name: SyntheticBrotli if name == "brotli" else real_import(name),
    )
    argv = ["--root", str(workspace), "--forbid", "credential"]

    assert scan_browser_artifacts.main(argv) == 0


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
