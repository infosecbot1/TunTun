from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from scripts.assurance_common import AssuranceResult


@dataclass(frozen=True)
class HarnessRun:
    exit_codes: tuple[int, ...]
    receipts: tuple[AssuranceResult, ...]


@dataclass(frozen=True)
class FeatureCase:
    argv: tuple[str, ...]


@dataclass
class MigrationWorkspace:
    root: Path
    revisions: tuple[str, ...]

    @classmethod
    def create_linear(cls, root: Path, revisions: tuple[str, ...]) -> MigrationWorkspace:
        versions = root / "apps" / "core" / "migrations" / "versions"
        versions.mkdir(parents=True)
        previous: str | None = None
        for revision in revisions:
            declared = f"{revision}_presence_checkpoint"
            down_revision = "None" if previous is None else repr(previous)
            (versions / f"{declared}.py").write_text(
                f'revision = "{declared}"\n'
                f"down_revision = {down_revision}\n"
                'schema_owner = "core"\n'
                'ddl = "CREATE TABLE checkpoint (id TEXT PRIMARY KEY)"\n',
                encoding="utf-8",
            )
            previous = declared
        return cls(root=root, revisions=revisions)

    def add_duplicate_revision(self, revision: str) -> None:
        if revision not in self.revisions:
            raise ValueError(f"unknown revision: {revision}")
        versions = self.root / "apps" / "core" / "migrations" / "versions"
        declared = f"{revision}_presence_checkpoint"
        hidden_parent = f"{self.revisions[0]}_presence_checkpoint"
        (versions / f"{declared}_duplicate.py").write_text(
            f'revision = "{declared}"\n'
            f'down_revision = "{hidden_parent}"\n'
            'schema_owner = "core"\n'
            'ddl = "CREATE TABLE duplicate_checkpoint (id TEXT PRIMARY KEY)"\n',
            encoding="utf-8",
        )


@dataclass
class NetworkInventory:
    root: Path
    generation: int
    socket_rows: list[tuple[str, str, int, int]]
    process_rows: list[tuple[int, str, str]]
    complete_join: bool = True
    errors: tuple[str, ...] = ()

    @classmethod
    def complete(
        cls,
        root: Path,
        *,
        listeners: tuple[tuple[str, str, int, int, str, str], ...],
    ) -> NetworkInventory:
        root.mkdir(parents=True)
        sockets = [
            (protocol, address, port, pid) for protocol, address, port, pid, _, _ in listeners
        ]
        processes = [(pid, executable, owner) for _, _, _, pid, executable, owner in listeners]
        return cls(root=root, generation=7001, socket_rows=sockets, process_rows=processes)

    def truncate_between_socket_and_process_tables(self) -> None:
        if self.process_rows:
            self.process_rows.pop()
        self.complete_join = False
        self.errors = ("truncated-process-table",)

    def make_owner_ambiguous(self) -> None:
        if not self.process_rows:
            raise ValueError("an owner row is required")
        pid, executable, owner = self.process_rows[0]
        self.process_rows.append((pid, executable + "-other", owner + "_other"))
        self.complete_join = False
        self.errors = ("ambiguous-process-owner",)

    def install_as_probe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from scripts import scan_network_surface

        def probe() -> scan_network_surface.InventorySnapshot:
            return scan_network_surface.InventorySnapshot(
                sockets=tuple(
                    scan_network_surface.SocketRecord(
                        protocol=protocol,
                        address=address,
                        port=port,
                        pid=pid,
                        generation=self.generation,
                    )
                    for protocol, address, port, pid in self.socket_rows
                ),
                processes=tuple(
                    scan_network_surface.ProcessRecord(
                        pid=pid,
                        executable=executable,
                        service_owner=owner,
                        generation=self.generation,
                    )
                    for pid, executable, owner in self.process_rows
                ),
                generation=self.generation,
                complete=self.complete_join,
                errors=self.errors,
            )

        monkeypatch.setattr(scan_network_surface, "capture_inventory", probe)


class SharedAssuranceHarness:
    _FAULTS = {
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
    }
    _SURFACES = {
        "source": "src/feature_registry.py",
        "config": "config/features.json",
        "api": "api/routes.json",
        "openapi": "openapi/openapi.json",
        "package": "package.json",
        "browser_chunk": "apps/admin/dist/assets/app.js",
        "ipc": "ipc/services.json",
        "launchd": "launchd/services.json",
    }

    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.root = root
        self._monkeypatch = monkeypatch
        self._serial = 0
        self._network_by_root: dict[Path, NetworkInventory] = {}

    def _fresh_root(self, tool_name: str) -> Path:
        self._serial += 1
        return self.root / f"{self._serial:04d}-{tool_name}"

    def complete_positive_workspace_for(self, tool: object) -> Path:
        tool_name = getattr(tool, "__name__", "").rsplit(".", 1)[-1]
        workspace = self._fresh_root(tool_name)
        if tool_name == "check_feature_absence":
            self._create_feature_workspace(workspace)
        elif tool_name == "check_import_boundaries":
            self._create_import_workspace(workspace)
        elif tool_name == "check_migration_ownership":
            MigrationWorkspace.create_linear(workspace, ("0013", "0014", "0015"))
        elif tool_name == "scan_browser_artifacts":
            self._create_browser_workspace(workspace)
        elif tool_name == "scan_network_surface":
            inventory = NetworkInventory.complete(
                workspace,
                listeners=(("tcp", "127.0.0.1", 8787, 4101, "python", "owner_ingress"),),
            )
            inventory.install_as_probe(self._monkeypatch)
            self._network_by_root[workspace] = inventory
        else:
            raise ValueError(f"unsupported assurance tool: {tool_name}")
        return workspace

    def run_every_tool_with(self, fault: str) -> HarnessRun:
        if fault not in self._FAULTS:
            raise ValueError(f"unknown fault: {fault}")
        from scripts import (
            check_feature_absence,
            check_import_boundaries,
            check_migration_ownership,
            scan_browser_artifacts,
            scan_network_surface,
        )

        cases: tuple[tuple[ModuleType, tuple[str, ...]], ...] = (
            (
                check_feature_absence,
                ("--feature", "selected_frame_perception", "--phase", "3"),
            ),
            (check_import_boundaries, ("--domain", "vision")),
            (check_migration_ownership, ("--revisions", "0013", "0014", "0015")),
            (scan_browser_artifacts, ("--forbid", "credential,reusable_token")),
            (scan_network_surface, ("--forbid-wildcard", "--forbid-core-tcp")),
        )
        exits: list[int] = []
        receipts: list[AssuranceResult] = []
        for tool, arguments in cases:
            with self._monkeypatch.context() as scoped:
                scoped_harness = SharedAssuranceHarness(self.root, scoped)
                workspace = scoped_harness.complete_positive_workspace_for(tool)
                scoped_harness._apply_fault(tool, workspace, fault, scoped)
                argv = ["--root", str(workspace), *arguments]
                receipts.append(tool.evaluate(argv))
                exits.append(tool.main(argv))
        return HarnessRun(tuple(exits), tuple(receipts))

    def feature_present_only_on(self, surface: str) -> FeatureCase:
        if surface not in {*self._SURFACES, "direct_request", "replay"}:
            raise ValueError(f"unknown surface: {surface}")
        from scripts import check_feature_absence

        workspace = self.complete_positive_workspace_for(check_feature_absence)
        if surface in self._SURFACES:
            path = workspace / self._SURFACES[surface]
            if path.suffix == ".json":
                path.write_text('{"registered":["selected_frame_perception"]}', encoding="utf-8")
            else:
                path.write_text("selected_frame_perception = True\n", encoding="utf-8")
        else:
            direct_replay = workspace / ".assurance" / "direct_replay.json"
            payload = json.loads(direct_replay.read_text(encoding="utf-8"))
            payload[surface] = {"result": "reachable", "side_effects": False}
            direct_replay.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        argv = [
            "--root",
            str(workspace),
            "--feature",
            "selected_frame_perception",
            "--phase",
            "3",
        ]
        return FeatureCase(tuple(argv))

    def _create_feature_workspace(self, root: Path) -> None:
        surface_paths = tuple(self._SURFACES.values())
        manifest = root / ".assurance" / "features.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "features": {"selected_frame_perception": {"phase": 3, "state": "absent"}},
                    "surfaces": list(surface_paths),
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        for relative in surface_paths:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.suffix == ".json":
                path.write_text('{"registered":[]}', encoding="utf-8")
            else:
                path.write_text("SYNTHETIC_REGISTRY = ()\n", encoding="utf-8")
        (root / ".assurance" / "direct_replay.json").write_text(
            json.dumps(
                {
                    "direct_request": {"result": "schema-unsupported", "side_effects": False},
                    "replay": {"result": "no-route", "side_effects": False},
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    @staticmethod
    def _create_import_workspace(root: Path) -> None:
        source = root / "src" / "vision"
        source.mkdir(parents=True)
        (root / "pyproject.toml").write_text(
            '[project]\nname = "synthetic-workspace"\nversion = "0.0.0"\n'
            '[tool.tuntun-assurance]\nsrc-roots = ["src"]\n',
            encoding="utf-8",
        )
        (source / "__init__.py").write_text("", encoding="utf-8")
        (source / "service.py").write_text(
            "from __future__ import annotations\nimport pathlib\n", encoding="utf-8"
        )

    @staticmethod
    def _create_browser_workspace(root: Path) -> None:
        build = root / "apps" / "admin" / "dist"
        assets = build / "assets"
        assets.mkdir(parents=True)
        (build / "manifest.json").write_text(
            '{"schema_version":1,"assets":["assets/app.js","assets/app.js.map"]}',
            encoding="utf-8",
        )
        (assets / "app.js").write_text("const syntheticRole = 'operator';\n", encoding="utf-8")
        (assets / "app.js.map").write_text(
            '{"version":3,"sources":["app.ts"],"names":[],"mappings":""}',
            encoding="utf-8",
        )

    def _required_input(self, tool: ModuleType, workspace: Path) -> Path:
        name = tool.__name__.rsplit(".", 1)[-1]
        if name == "check_feature_absence":
            return workspace / ".assurance" / "features.json"
        if name == "check_import_boundaries":
            return workspace / "pyproject.toml"
        if name == "check_migration_ownership":
            return (
                workspace
                / "apps"
                / "core"
                / "migrations"
                / "versions"
                / "0013_presence_checkpoint.py"
            )
        if name == "scan_browser_artifacts":
            return workspace / "apps" / "admin" / "dist" / "manifest.json"
        raise ValueError(f"tool has probe inventory instead of file input: {name}")

    def _apply_fault(
        self,
        tool: ModuleType,
        workspace: Path,
        fault: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from scripts import assurance_common, scan_network_surface

        if tool is scan_network_surface:
            inventory = self._network_by_root[workspace]
            if fault == "missing_input":
                workspace.rmdir()
                return
            if fault == "symlink_input":
                target = workspace.with_name(workspace.name + "-target")
                workspace.rename(target)
                workspace.symlink_to(target, target_is_directory=True)
                return
            if fault == "special_input":
                workspace.rmdir()
                os.mkfifo(workspace)
                return
            if fault == "input_replaced":
                inventory.complete_join = False
                inventory.errors = ("input-changed-during-scan",)
            elif fault == "ambiguous_process_owner":
                inventory.make_owner_ambiguous()
            else:
                inventory.truncate_between_socket_and_process_tables()
            inventory.install_as_probe(monkeypatch)
            return

        target = self._required_input(tool, workspace)
        if fault == "missing_input":
            target.unlink()
        elif fault == "symlink_input":
            saved = target.with_name(target.name + ".target")
            target.rename(saved)
            target.symlink_to(saved.name)
        elif fault == "special_input":
            target.unlink()
            os.mkfifo(target)
        elif fault == "input_replaced":
            sibling = target.with_name(target.name + ".alternate")
            sibling.write_bytes(target.read_bytes())
            original_open = assurance_common.os.open

            def replacing_open(path: object, *args: object, **kwargs: object) -> int:
                if Path(path) == target or str(path) == target.name:
                    temporary = target.with_name(target.name + ".swap")
                    target.rename(temporary)
                    sibling.rename(target)
                    temporary.rename(sibling)
                return original_open(path, *args, **kwargs)

            monkeypatch.setattr(assurance_common.os, "open", replacing_open)
        elif fault == "invalid_utf8":
            target.write_bytes(b"\xff\xfe")
        elif fault == "oversize":
            target.write_bytes(b"x" * (assurance_common.MAX_REGULAR_FILE_BYTES + 1))
        elif fault == "overdepth":
            if target.suffix == ".json":
                target.write_text("[" * 65 + "0" + "]" * 65, encoding="utf-8")
            else:
                target.write_text("value = " + "(" * 300 + "0" + ")" * 300, encoding="utf-8")
        elif fault == "too_many_files":
            directory = target.parent / "inventory-overflow"
            directory.mkdir()
            for index in range(assurance_common.MAX_WALK_FILES + 1):
                (directory / f"{index:04d}.txt").write_text("synthetic", encoding="utf-8")
        elif fault in {"duplicate_json_key", "ambiguous_process_owner"}:
            if target.suffix == ".json":
                target.write_bytes(b'{"schema_version":1,"schema_version":1}')
            else:
                target.write_text(
                    'revision = "duplicate"\nrevision = "duplicate"\n', encoding="utf-8"
                )
        elif fault == "truncated_socket_inventory":
            target.write_bytes(target.read_bytes()[:3])
        else:
            raise ValueError(f"unknown fault: {fault}")
