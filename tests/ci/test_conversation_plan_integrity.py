from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.metadata
import inspect
import io
import json
import os
import signal
import stat
import subprocess
import sys
import tracemalloc
import types
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest
from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import scripts.materialize_conversation_plan as materializer
import scripts.validate_conversation_plan as validator
from scripts.materialize_conversation_plan import (
    MaterializationError,
    foundation_files_from_ref,
    materialize_document,
    parse_plan_text,
)
from scripts.validate_conversation_plan import (
    FOUNDATION_MIGRATION_PATHS,
    validate_model_manifest_bytes,
    validate_plan_document,
)

PLAN_PATH = Path("docs/superpowers/plans/2026-08-27-tuntun-phase1-conversation-reachy-execution.md")


@pytest.mark.parametrize(
    "script",
    ("scripts/materialize_conversation_plan.py", "scripts/validate_conversation_plan.py"),
)
def test_plan_tools_are_directly_executable_clis(script: str) -> None:
    result = subprocess.run(
        [".venv/bin/python", script, "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "--foundation-ref" in result.stdout
    assert "--plan-ref" in result.stdout


def test_foundation_archive_is_read_from_the_explicit_ref_not_the_worktree(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", repository], check=True)
    subprocess.run(
        ["git", "-C", repository, "config", "user.email", "plan-test@tuntun.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", repository, "config", "user.name", "Plan Test"], check=True)
    tracked = repository / "foundation.txt"
    tracked.write_text("accepted\n")
    subprocess.run(["git", "-C", repository, "add", "foundation.txt"], check=True)
    subprocess.run(["git", "-C", repository, "commit", "-qm", "accepted"], check=True)
    accepted_ref = subprocess.run(
        ["git", "-C", repository, "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tracked.write_text("unaccepted worktree drift\n")

    archived = foundation_files_from_ref(repository, accepted_ref)

    assert archived["foundation.txt"] == b"accepted\n"
    assert b"unaccepted worktree drift" not in b"".join(archived.values())


def test_foundation_ref_is_resolved_once_before_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", repository], check=True)
    subprocess.run(
        ["git", "-C", repository, "config", "user.email", "plan-test@tuntun.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", repository, "config", "user.name", "Plan Test"], check=True)
    tracked = repository / "foundation.txt"
    tracked.write_text("accepted\n")
    subprocess.run(["git", "-C", repository, "add", "foundation.txt"], check=True)
    subprocess.run(["git", "-C", repository, "commit", "-qm", "accepted"], check=True)
    accepted_commit = subprocess.run(
        ["git", "-C", repository, "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(["git", "-C", repository, "branch", "accepted", accepted_commit], check=True)
    tracked.write_text("later\n")
    subprocess.run(["git", "-C", repository, "add", "foundation.txt"], check=True)
    subprocess.run(["git", "-C", repository, "commit", "-qm", "later"], check=True)
    later_commit = subprocess.run(
        ["git", "-C", repository, "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    real_run = subprocess.run
    moved = False

    def move_ref_after_resolution(*args: Any, **kwargs: Any) -> Any:
        nonlocal moved
        result = real_run(*args, **kwargs)
        command = args[0]
        if not moved and command[-2:] == ["--verify", "accepted^{commit}"]:
            real_run(
                ["git", "-C", repository, "update-ref", "refs/heads/accepted", later_commit],
                check=True,
            )
            moved = True
        return result

    monkeypatch.setattr(subprocess, "run", move_ref_after_resolution)

    snapshot = materializer.foundation_snapshot_from_ref(repository, "accepted")

    assert moved
    assert snapshot.source_commit == accepted_commit
    assert snapshot.files["foundation.txt"] == b"accepted\n"


def test_plan_is_read_from_explicit_git_object_not_dirty_worktree(tmp_path: Path) -> None:
    repository = tmp_path / ".worktrees" / "foundation-task9"
    repository.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", repository], check=True)
    subprocess.run(
        ["git", "-C", repository, "config", "user.email", "plan-test@tuntun.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", repository, "config", "user.name", "Plan Test"], check=True)
    plan_path = repository / "plan.md"
    plan_path.write_text(
        _task(
            1,
            depends="Foundation contracts",
            files=(("Create", "pkg/value.py"),),
            snippets=(("python", "# pkg/value.py", "VALUE = 1"),),
        )
    )
    subprocess.run(["git", "-C", repository, "add", "plan.md"], check=True)
    subprocess.run(["git", "-C", repository, "commit", "-qm", "accepted plan"], check=True)
    accepted_ref = subprocess.run(
        ["git", "-C", repository, "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    plan_path.write_text(plan_path.read_text().replace("VALUE = 1", "VALUE = 2"))

    document = materializer.plan_document_from_ref(repository, accepted_ref, "plan.md")
    files = materialize_document(document, foundation_files={})

    assert document.source_commit == accepted_ref
    assert document.source_path == "plan.md"
    assert files["pkg/value.py"] == b"VALUE = 1\n"


def _task(
    number: int,
    *,
    depends: str,
    files: tuple[tuple[str, str], ...],
    snippets: tuple[tuple[str, str, str], ...],
    staged: tuple[str, ...] | None = None,
) -> str:
    declarations = "\n".join(f"- {kind}: `{path}`" for kind, path in files)
    fences = "\n\n".join(
        f"```{language}\n{header}\n{body.rstrip()}\n```" for language, header, body in snippets
    )
    staged_paths = staged if staged is not None else tuple(path for _, path in files)
    command = "git add " + " ".join(staged_paths)
    return f"""### Task {number:02d}: miniature

**Depends on:** {depends}

**Files:**
{declarations}

{fences}

```bash
{command}
git diff --cached --check
```
"""


def _foundation_files() -> dict[str, bytes]:
    return {
        "apps/core/src/tuntun_core/__init__.py": b"",
        "apps/core/src/tuntun_core/adapters/__init__.py": b"",
        "apps/core/src/tuntun_core/adapters/sqlcipher/__init__.py": b"",
        "apps/core/src/tuntun_core/adapters/sqlcipher/engine.py": (
            b"def create_engine(path, key):\n    return (path, key)\n\n"
            b"def create_sqlcipher_engine(path, key):\n    return create_engine(path, key)\n"
        ),
        "apps/core/src/tuntun_core/adapters/sqlcipher/migrations.py": (
            b"class command:\n"
            b"    @staticmethod\n    def upgrade(*args):\n        return args\n\n"
            b"    @staticmethod\n    def downgrade(state):\n        state.append('down')\n\n"
            b"def encrypted_backup(source, destination, key):\n"
            b"    return source.backup(destination, key)\n\n"
            b"def upgrade_encrypted(path, key, backup):\n"
            b"    return command.upgrade(path, key, backup)\n"
        ),
        "tests/integration/storage/test_migrations.py": (
            b"from tuntun_core.adapters.sqlcipher.engine import create_sqlcipher_engine\n"
            b"from tuntun_core.adapters.sqlcipher.migrations import (\n"
            b"    command, encrypted_backup, upgrade_encrypted,\n"
            b")\n\n"
            b"class Source:\n"
            b"    def backup(self, destination, key):\n"
            b"        return (destination, key)\n\n"
            b"def test_migrations_upgrade_and_rollback():\n"
            b"    assert create_sqlcipher_engine('db', 'key') == ('db', 'key')\n"
            b"    assert encrypted_backup(Source(), 'backup', 'key') == ('backup', 'key')\n"
            b"    assert upgrade_encrypted('db', 'key', 'backup') == ('db', 'key', 'backup')\n"
            b"    assert command.upgrade('db', 'key', 'backup') == ('db', 'key', 'backup')\n"
            b"    state = []\n    command.downgrade(state)\n"
            b"    assert state == ['down']\n"
        ),
    }


def _real_foundation_files() -> dict[str, bytes]:
    return {
        "apps/core/src/tuntun_core/__init__.py": b"",
        "apps/core/src/tuntun_core/adapters/__init__.py": b"",
        "apps/core/src/tuntun_core/adapters/sqlcipher/__init__.py": b"",
        "apps/core/src/tuntun_core/adapters/sqlcipher/engine.py": (
            b"import sqlite3\n"
            b"create_engine = sqlite3.connect\n\n"
            b"def create_sqlcipher_engine(path, key):\n"
            b"    if type(key) is not bytes or len(key) != 32:\n"
            b"        raise ValueError('key')\n"
            b"    return create_engine(path)\n"
        ),
        "apps/core/src/tuntun_core/adapters/sqlcipher/migrations.py": (
            b"import importlib.util\n"
            b"from pathlib import Path\n"
            b"from .engine import create_sqlcipher_engine\n\n"
            b"def _revision():\n"
            b"    path=Path('apps/core/migrations/versions/0001_foundation.py')\n"
            b"    spec=importlib.util.spec_from_file_location('foundation_0001',path)\n"
            b"    module=importlib.util.module_from_spec(spec)\n"
            b"    assert spec is not None and spec.loader is not None\n"
            b"    spec.loader.exec_module(module)\n"
            b"    return module\n\n"
            b"def encrypted_backup(source, destination, key):\n"
            b"    source_db=create_sqlcipher_engine(source,key)\n"
            b"    destination_db=create_sqlcipher_engine(destination,key)\n"
            b"    try:\n        source_db.backup(destination_db)\n        destination_db.commit()\n"
            b"    finally:\n        source_db.close()\n        destination_db.close()\n\n"
            b"def upgrade_encrypted(path, key, backup):\n"
            b"    if Path(path).exists() and backup is not None:\n"
            b"        encrypted_backup(path,backup,key)\n"
            b"    connection=create_sqlcipher_engine(path,key)\n"
            b"    try:\n        _revision().upgrade(connection)\n        connection.commit()\n"
            b"    finally:\n        connection.close()\n"
        ),
        "apps/core/migrations/versions/0001_foundation.py": (
            b"def upgrade(connection):\n"
            b"    connection.execute('CREATE TABLE foundation_state (id INTEGER PRIMARY KEY)')\n\n"
            b"def downgrade(connection):\n"
            b"    connection.execute('DROP TABLE foundation_state')\n"
        ),
        "tests/integration/storage/test_migrations.py": (
            b"import importlib.util\n"
            b"from pathlib import Path\n"
            b"from tuntun_core.adapters.sqlcipher.engine import create_sqlcipher_engine\n"
            b"from tuntun_core.adapters.sqlcipher.migrations import (\n"
            b"    encrypted_backup, upgrade_encrypted,\n)\n\n"
            b"KEY=bytes(range(32))\n\n"
            b"def _revision():\n"
            b"    path=Path('apps/core/migrations/versions/0001_foundation.py')\n"
            b"    spec=importlib.util.spec_from_file_location('foundation_0001_test',path)\n"
            b"    module=importlib.util.module_from_spec(spec)\n"
            b"    assert spec is not None and spec.loader is not None\n"
            b"    spec.loader.exec_module(module)\n"
            b"    return module\n\n"
            b"def test_migrations_upgrade_backup_and_downgrade(tmp_path):\n"
            b"    revision_probe=create_sqlcipher_engine(tmp_path/'revision.db',KEY)\n"
            b"    _revision().upgrade(revision_probe)\n"
            b"    _revision().downgrade(revision_probe)\n"
            b"    revision_probe.close()\n"
            b"    source=tmp_path/'source.db'\n    backup=tmp_path/'backup.db'\n"
            b"    db=create_sqlcipher_engine(source,KEY)\n"
            b"    db.execute('CREATE TABLE seed (id INTEGER PRIMARY KEY)')\n"
            b"    db.execute('INSERT INTO seed VALUES (1)')\n    db.commit()\n    db.close()\n"
            b"    encrypted_backup(source,backup,KEY)\n"
            b"    copied=create_sqlcipher_engine(backup,KEY)\n"
            b"    assert copied.execute('SELECT id FROM seed').fetchone()==(1,)\n"
            b"    copied.close()\n"
            b"    upgrade_encrypted(source,KEY,tmp_path/'pre-upgrade.db')\n"
            b"    upgraded=create_sqlcipher_engine(source,KEY)\n"
            b"    state=upgraded.execute(\n"
            b"        \"SELECT name FROM sqlite_master WHERE name='foundation_state'\"\n"
            b"    ).fetchone()\n"
            b"    assert state==('foundation_state',)\n"
            b"    _revision().downgrade(upgraded)\n    upgraded.commit()\n"
            b"    state=upgraded.execute(\n"
            b"        \"SELECT name FROM sqlite_master WHERE name='foundation_state'\"\n"
            b"    ).fetchone()\n"
            b"    assert state is None\n"
            b"    upgraded.close()\n"
        ),
    }


def _disconnected_foundation_files() -> dict[str, bytes]:
    files = _foundation_files()
    files[validator.FOUNDATION_REVISION_PATH] = (
        b"def upgrade(state):\n    state.append('revision-up')\n\n"
        b"def downgrade(state):\n    state.append('revision-down')\n"
    )
    files[FOUNDATION_MIGRATION_PATHS[2]] = (
        b"class command:\n"
        b"    @staticmethod\n    def upgrade(state):\n        state.append('up')\n"
        b"    @staticmethod\n    def downgrade(state):\n        state.append('down')\n\n"
        b"def test_migrations_upgrade_and_rollback():\n"
        b"    state = []\n    command.upgrade(state)\n    command.downgrade(state)\n"
        b"    assert state == ['up', 'down']\n"
    )
    return files


def _valid_two_task_plan() -> str:
    task_1 = _task(
        1,
        depends="Foundation contracts",
        files=(
            ("Create", "pkg/first.py"),
            ("Create", "config/first.yaml"),
        ),
        snippets=(
            ("python", "# pkg/first.py", "VALUE = 1"),
            ("yaml", "# config/first.yaml", "enabled: true"),
        ),
    )
    task_2 = _task(
        2,
        depends="Task 01 and Foundation contracts",
        files=(("Modify", "pkg/first.py"),),
        snippets=(
            (
                "python",
                "# append to pkg/first.py",
                "# materializer: append\nSECOND = 2",
            ),
        ),
    )
    return "# Mini plan\n\n" + task_1 + "\n" + task_2


def test_materializer_handles_python_and_structured_non_python_snippets() -> None:
    document = parse_plan_text(_valid_two_task_plan())

    files = materialize_document(document, foundation_files={})

    assert files["pkg/first.py"] == b"VALUE = 1\n\nSECOND = 2\n"
    assert files["config/first.yaml"] == b"enabled: true\n"


@pytest.mark.parametrize(
    ("language", "path", "invalid"),
    (
        ("json", "config/broken.json", "{"),
        ("toml", "config/broken.toml", "items = ["),
        ("yaml", "config/broken.yaml", "items: ["),
        ("ini", "deploy/broken.service", "[Unit"),
    ),
)
def test_materializer_rejects_malformed_structured_snippets(
    language: str, path: str, invalid: str
) -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Create", path),),
        snippets=((language, f"# {path}", invalid),),
    )

    with pytest.raises(MaterializationError, match="invalid generated"):
        materialize_document(parse_plan_text(plan), foundation_files={})


def _valid_model_manifest() -> bytes:
    return (
        'schema_version: "1.0"\n'
        "models:\n"
        "- id: hello-tuntun-v1\n"
        f"  revision: {'a' * 40}\n"
        "  license: Apache-2.0\n"
        "  provenance: approved synthetic corpus\n"
        "  redistribution: approved\n"
        "  approved_purpose: wake phrase detection\n"
        "  runtime: strict-edge-adapter-v1\n"
        "  architecture: governed-test-architecture\n"
        "  input_contract: pcm-s16le-mono-16khz-1280-samples\n"
        "  output_contract: score-micros-0-through-1000000\n"
        "  benchmark_gate: receipt-v1-zero-drops-cpu-lte-25\n"
        '  review_date: "2026-08-27"\n'
        "  files:\n"
        "  - path: hello.onnx\n"
        "    size: 1\n"
        f"    sha256: {'b' * 64}\n"
        "    url: https://models.example.com/hello.onnx\n"
    ).encode()


def _valid_task12_manifest() -> bytes:
    first = _valid_model_manifest().decode().split("models:\n", 1)[1]
    second = (
        first.replace("hello-tuntun-v1", "stop-tuntun-v1")
        .replace("wake phrase detection", "independent stop phrase detection")
        .replace("hello.onnx", "stop.onnx")
        .replace("b" * 64, "c" * 64)
    )
    return (f'schema_version: "1.0"\nmodels:\n{first}{second}').encode()


def test_model_manifest_validator_accepts_only_foundation_closed_keys() -> None:
    assert validate_model_manifest_bytes(_valid_model_manifest()) == []

    top_level_drift = _valid_model_manifest().replace(
        b"  files:\n", b"  runtime_download: false\n  files:\n"
    )
    file_level_drift = _valid_model_manifest().replace(
        b"    url:", b"    filename: hello.onnx\n    url:"
    )

    assert any("model keys" in error for error in validate_model_manifest_bytes(top_level_drift))
    assert any("file keys" in error for error in validate_model_manifest_bytes(file_level_drift))


def test_model_manifest_accepts_an_empty_bootstrap_model_set() -> None:
    errors = validate_model_manifest_bytes(b'schema_version: "1.0"\nmodels: []\n')

    assert errors == []


@pytest.mark.parametrize(
    ("foundation", "plan", "message"),
    (
        (
            {"pkg/already.py": b"VALUE = 0\n"},
            _task(
                1,
                depends="Foundation contracts",
                files=(("Create", "pkg/already.py"),),
                snippets=(("python", "# pkg/already.py", "VALUE = 1"),),
            ),
            "declared Create already exists",
        ),
        (
            {},
            _task(
                1,
                depends="Foundation contracts",
                files=(("Modify", "pkg/missing.py"),),
                snippets=(
                    (
                        "python",
                        "# append to pkg/missing.py",
                        "# materializer: append\nVALUE = 1",
                    ),
                ),
            ),
            "declared Modify does not exist",
        ),
    ),
)
def test_materializer_enforces_create_modify_truth(
    foundation: dict[str, bytes], plan: str, message: str
) -> None:
    with pytest.raises(MaterializationError, match=message):
        materialize_document(parse_plan_text(plan), foundation_files=foundation)


@pytest.mark.parametrize(
    ("mutate", "message"),
    (
        (
            lambda text: text.replace(
                "git add pkg/first.py config/first.yaml", "git add pkg/first.py"
            ),
            "declared/staged path mismatch",
        ),
        (
            lambda text: text.replace("```yaml\n# config/first.yaml\nenabled: true\n```\n\n", ""),
            "declared/snippet path mismatch",
        ),
        (
            lambda text: text.replace("- Create: `config/first.yaml`\n", ""),
            "declared/staged path mismatch",
        ),
    ),
)
def test_validator_rejects_path_parity_breaks(mutate: Callable[[str], str], message: str) -> None:
    errors = validate_plan_document(
        parse_plan_text(mutate(_valid_two_task_plan())), foundation_files={}
    )

    assert any(message in error for error in errors), errors


def test_only_the_final_git_add_command_defines_staging() -> None:
    plan = _valid_two_task_plan().replace(
        "```bash\ngit add pkg/first.py config/first.yaml",
        "```bash\ngit add wrong/early.py\ngit add pkg/first.py config/first.yaml",
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert not any("declared/staged path mismatch" in error for error in errors), errors


def test_green_command_must_execute_every_owned_test() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_owned.py"),),
        snippets=(("python", "# tests/test_owned.py", "def test_owned():\n    assert True"),),
    ).replace(
        "git diff --cached --check",
        "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\n"
        "Run: `python -m pytest tests/test_other.py -q`",
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any("green command does not execute owned test tests/test_owned.py" in e for e in errors)


def test_green_command_does_not_treat_echoed_test_path_as_execution() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_owned.py"),),
        snippets=(("python", "# tests/test_owned.py", "def test_owned():\n    assert True"),),
    ).replace(
        "git diff --cached --check",
        "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\n"
        "Run: `echo tests/test_owned.py`",
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any("green command does not execute owned test tests/test_owned.py" in e for e in errors)


@pytest.mark.parametrize(
    "green",
    (
        "python -m pytest tests/test_owned.py -q || true",
        "python -m pytest tests -q --ignore=tests/test_owned.py",
        "python -m pytest tests/test_owned.py -q -k nothing_matches",
        "python -m pytest tests/test_owned.py -q -knothing_matches",
        "python -m pytest tests/test_owned.py -q -m reachy_hardware",
    ),
)
def test_green_command_cannot_mask_or_deselect_owned_tests(green: str) -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_owned.py"),),
        snippets=(("python", "# tests/test_owned.py", "def test_owned():\n    assert True"),),
    ).replace(
        "git diff --cached --check",
        f"git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\nRun: `{green}`",
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any("green command is not fail-closed" in error for error in errors), errors


def test_pytest_option_values_do_not_count_as_owned_test_targets() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_owned.py"),),
        snippets=(("python", "# tests/test_owned.py", "def test_owned():\n    assert True"),),
    ).replace(
        "git diff --cached --check",
        "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\n"
        "Run: `python -m pytest tests/test_other.py --basetemp tests`",
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any("green command does not execute owned test tests/test_owned.py" in e for e in errors)


def test_pytest_node_id_does_not_certify_the_whole_owned_test_file() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_owned.py"),),
        snippets=(
            (
                "python",
                "# tests/test_owned.py",
                "def test_selected():\n    assert True\n\ndef test_unselected():\n    assert False",
            ),
        ),
    ).replace(
        "git diff --cached --check",
        "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\n"
        "Run: `python -m pytest tests/test_owned.py::test_selected -q`",
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any("green command does not execute owned test tests/test_owned.py" in e for e in errors)
    assert any("pytest task-boundary probe failed" in error for error in errors), errors


def test_pytest_addopts_cannot_hide_owned_tests() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_owned.py"),),
        snippets=(("python", "# tests/test_owned.py", "def test_owned():\n    assert True"),),
    ).replace(
        "git diff --cached --check",
        "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\n"
        "Run: `PYTEST_ADDOPTS='-k selected' python -m pytest tests/test_owned.py -q`",
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any("green command is not fail-closed" in error for error in errors), errors


def test_task_boundary_executes_owned_tests_without_fixture_consumers() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_owned.py"),),
        snippets=(("python", "# tests/test_owned.py", "def test_owned():\n    assert False"),),
    ).replace(
        "git diff --cached --check",
        "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\n"
        "Run: `python -m pytest tests/test_owned.py -q`",
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any("pytest task-boundary probe failed" in error for error in errors), errors


def test_green_command_executes_each_owned_critical_validator() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Create", "evals/verify_result.py"),),
        snippets=(
            (
                "python",
                "# evals/verify_result.py",
                "def main() -> int:\n    return 0",
            ),
        ),
    ).replace(
        "git diff --cached --check",
        "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\nRun: `echo verified`",
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any(
        "green command does not execute owned critical validator" in error for error in errors
    )


@pytest.mark.parametrize("interpreter", ("/usr/bin/python3", "./python"))
def test_noncanonical_python_cannot_certify_owned_critical_validator(
    interpreter: str,
) -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Create", "tools/check_result.py"),),
        snippets=(("python", "# tools/check_result.py", "raise SystemExit(0)"),),
    ).replace(
        "git diff --cached --check",
        "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\n"
        f"Run: `{interpreter} tools/check_result.py`",
    )

    errors = validate_plan_document(
        parse_plan_text(plan), foundation_files={}, execute_behavioral_probes=False
    )

    assert any(
        "green command does not execute owned critical validator" in error for error in errors
    ), errors


@pytest.mark.parametrize("interpreter", ("/usr/bin/python3", "./python"))
def test_noncanonical_python_cannot_certify_generator_check(interpreter: str) -> None:
    plan = (
        _task(
            1,
            depends="Foundation contracts",
            files=(("Create", "tools/generate.py"), ("Create", "generated/schema.json")),
            snippets=(
                (
                    "python",
                    "# tools/generate.py",
                    "import sys\n"
                    "from pathlib import Path\n"
                    "output=Path('generated/schema.json')\n"
                    "expected='{\\\"version\\\":1}\\n'\n"
                    "if '--check' in sys.argv:\n"
                    "    raise SystemExit(0 if output.read_text() == expected else 1)\n"
                    "output.parent.mkdir(exist_ok=True)\n"
                    "output.write_text(expected)",
                ),
            ),
        )
        .replace(
            "**Files:**",
            "**Files:**\n- Generate `schema-v1`: `python tools/generate.py --write` "
            "-> `generated/schema.json`",
        )
        .replace(
            "git diff --cached --check",
            "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\n"
            f"Run: `{interpreter} tools/generate.py --check`",
        )
    )

    errors = validate_plan_document(
        parse_plan_text(plan), foundation_files={}, execute_behavioral_probes=False
    )

    assert any("green command does not verify generator schema-v1" in error for error in errors), (
        errors
    )


def test_validator_rejects_forward_imports() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_first.py"),),
        snippets=(
            (
                "python",
                "# tests/test_first.py",
                "from pkg.later import Later\n\ndef test_first():\n    assert Later",
            ),
        ),
    ) + _task(
        2,
        depends="Task 01 and Foundation Task 13",
        files=(("Create", "pkg/later.py"),),
        snippets=(("python", "# pkg/later.py", "class Later:\n    pass"),),
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files=_foundation_files())

    assert any("forward import" in error and "pkg.later" in error for error in errors), errors


def test_validator_rejects_from_parent_forward_imports() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_first.py"),),
        snippets=(
            (
                "python",
                "# tests/test_first.py",
                "from pkg import later\n\ndef test_first():\n    assert later.Later",
            ),
        ),
    ) + _task(
        2,
        depends="Task 01 and Foundation Task 13",
        files=(("Create", "pkg/later.py"),),
        snippets=(("python", "# pkg/later.py", "class Later:\n    pass"),),
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files=_foundation_files())

    assert any("forward import" in error and "pkg.later" in error for error in errors), errors


def test_validator_rejects_relative_test_helper_forward_import() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/unit/test_first.py"),),
        snippets=(
            (
                "python",
                "# tests/unit/test_first.py",
                "from .helpers import VALUE\n\ndef test_first():\n    assert VALUE",
            ),
        ),
    ) + _task(
        2,
        depends="Task 01 and Foundation Task 13",
        files=(("Create", "tests/unit/helpers.py"),),
        snippets=(("python", "# tests/unit/helpers.py", "VALUE = 1"),),
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files=_foundation_files())

    assert any("forward import" in error and "tests.unit.helpers" in error for error in errors)


def test_validator_resolves_relative_imports_from_package_initializers() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Create", "tests/helpers/__init__.py"),),
        snippets=(
            (
                "python",
                "# tests/helpers/__init__.py",
                "from .later import Later\n\n__all__ = ('Later',)",
            ),
        ),
    ) + _task(
        2,
        depends="Task 01 and Foundation Task 13",
        files=(("Create", "tests/helpers/later.py"),),
        snippets=(("python", "# tests/helpers/later.py", "class Later:\n    pass"),),
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files=_foundation_files())

    assert any("forward import" in error and "tests.helpers.later" in error for error in errors)


@pytest.mark.parametrize(
    "fixture_source",
    (
        """import pytest
from types import SimpleNamespace
_NAMES = ("case",)
for name in _NAMES:
    globals()[name] = pytest.fixture(lambda: SimpleNamespace(fixture_name=name))
""",
        """import pytest
from types import SimpleNamespace
@pytest.fixture
def case():
    return SimpleNamespace()
""",
        """import pytest
from types import SimpleNamespace
@pytest.fixture
def case():
    return SimpleNamespace(fixture_name="case")
""",
    ),
)
def test_validator_rejects_dynamic_empty_or_name_only_fixture_factories(
    fixture_source: str,
) -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(
            ("Create", "tests/fixtures/cases.py"),
            ("Test", "tests/test_case.py"),
        ),
        snippets=(
            ("python", "# tests/fixtures/cases.py", fixture_source),
            (
                "python",
                "# tests/test_case.py",
                (
                    "pytest_plugins = ('tests.fixtures.cases',)\n\n"
                    "def test_case(case):\n    assert case"
                ),
            ),
        ),
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any(
        "fixture" in error and ("dynamic" in error or "placeholder" in error) for error in errors
    )


def test_validator_requires_exactly_one_explicit_fixture_producer() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(
            ("Create", "tests/fixtures/a.py"),
            ("Create", "tests/fixtures/b.py"),
            ("Test", "tests/test_case.py"),
        ),
        snippets=(
            (
                "python",
                "# tests/fixtures/a.py",
                "import pytest\n@pytest.fixture\ndef case():\n    return object()",
            ),
            (
                "python",
                "# tests/fixtures/b.py",
                "import pytest\n@pytest.fixture\ndef case():\n    return object()",
            ),
            (
                "python",
                "# tests/test_case.py",
                "def test_case(case, missing_case):\n    assert case and missing_case",
            ),
        ),
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any("fixture case has 2 explicit producers" in error for error in errors), errors
    assert any("fixture missing_case has 0 explicit producers" in error for error in errors), errors


def test_duplicate_fixture_definitions_in_one_module_are_not_collapsed() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(
            ("Create", "tests/fixtures/cases.py"),
            ("Test", "tests/test_case.py"),
        ),
        snippets=(
            (
                "python",
                "# tests/fixtures/cases.py",
                (
                    "import pytest\n"
                    "@pytest.fixture\n"
                    "def case():\n    return object()\n"
                    "@pytest.fixture\n"
                    "def case():\n    return object()"
                ),
            ),
            (
                "python",
                "# tests/test_case.py",
                "def test_case(case):\n    assert case",
            ),
        ),
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any("fixture case has 2 explicit producers" in error for error in errors), errors


def _run_materialized_pytest(plan: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    files = materialize_document(parse_plan_text(plan), foundation_files={})
    for path, content in files.items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "tests"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )


def test_fixture_producer_must_be_discoverable_at_task_boundary(tmp_path: Path) -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(
            ("Create", "tests/fixtures/cases.py"),
            ("Test", "tests/test_case.py"),
        ),
        snippets=(
            (
                "python",
                "# tests/fixtures/cases.py",
                "import pytest\n@pytest.fixture\ndef case() -> int:\n    return 1",
            ),
            ("python", "# tests/test_case.py", "def test_case(case):\n    assert case == 1"),
        ),
    )

    pytest_result = _run_materialized_pytest(plan, tmp_path)
    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert pytest_result.returncode != 0
    assert "fixture 'case' not found" in pytest_result.stdout
    assert any("pytest task-boundary probe failed" in error for error in errors), errors


def test_unconsumed_fixture_producer_must_be_discoverable_when_introduced() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Create", "tests/fixtures/cases.py"),),
        snippets=(
            (
                "python",
                "# tests/fixtures/cases.py",
                "import pytest\n@pytest.fixture\ndef latent_case() -> int:\n    return 1",
            ),
        ),
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any("fixture-producer discovery probe failed" in error for error in errors), errors


def test_syntactic_fixture_body_without_a_concrete_result_is_rejected() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Create", "tests/fixtures/cases.py"), ("Create", "tests/conftest.py")),
        snippets=(
            (
                "python",
                "# tests/fixtures/cases.py",
                "import pytest\n\n"
                "class Case:\n    value = 1\n\n"
                "@pytest.fixture\n"
                "def latent_case() -> Case:\n"
                "    def never_called():\n        return Case()\n"
                "    assert callable(never_called)",
            ),
            (
                "python",
                "# tests/conftest.py",
                "pytest_plugins = ('tests.fixtures.cases',)",
            ),
        ),
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any("fixture latent_case is a placeholder" in error for error in errors), errors


def test_fixture_harness_must_implement_consumer_used_method(tmp_path: Path) -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(
            ("Create", "tests/fixtures/cases.py"),
            ("Test", "tests/test_case.py"),
        ),
        snippets=(
            (
                "python",
                "# tests/fixtures/cases.py",
                "import pytest\n@pytest.fixture\ndef case() -> object:\n    return object()",
            ),
            (
                "python",
                "# tests/test_case.py",
                "pytest_plugins = ('tests.fixtures.cases',)\n\n"
                "def test_case(case):\n    case.required_method()",
            ),
        ),
    )

    pytest_result = _run_materialized_pytest(plan, tmp_path)
    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert pytest_result.returncode != 0
    assert "required_method" in pytest_result.stdout
    assert any("typed concrete harness" in error for error in errors), errors


def test_discovered_yield_fixture_with_typed_concrete_surface_is_accepted() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(
            ("Create", "pkg/case.py"),
            ("Create", "tests/fixtures/cases.py"),
            ("Create", "tests/conftest.py"),
            ("Test", "tests/test_case.py"),
        ),
        snippets=(
            (
                "python",
                "# pkg/case.py",
                "class Case:\n"
                "    value: str = 'real'\n"
                "    def required_method(self) -> str:\n        return 'real'",
            ),
            (
                "python",
                "# tests/fixtures/cases.py",
                "from collections.abc import Iterator\nimport pytest\n"
                "from pkg.case import Case\n\n"
                "@pytest.fixture\n"
                "def case() -> Iterator[Case]:\n    yield Case()",
            ),
            (
                "python",
                "# tests/conftest.py",
                "pytest_plugins = ('tests.fixtures.cases',)",
            ),
            (
                "python",
                "# tests/test_case.py",
                "def test_case(case):\n    assert case.required_method() == case.value == 'real'",
            ),
        ),
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert not any("typed concrete harness" in error for error in errors), errors
    assert not any("probe failed" in error for error in errors), errors


def test_fixture_can_wrap_typed_concrete_foundation_class() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(
            ("Create", "tests/fixtures/cases.py"),
            ("Create", "tests/conftest.py"),
            ("Test", "tests/test_case.py"),
        ),
        snippets=(
            (
                "python",
                "# tests/fixtures/cases.py",
                "import pytest\nfrom pkg.foundation_case import FoundationCase\n\n"
                "@pytest.fixture\n"
                "def case() -> FoundationCase:\n    return FoundationCase()",
            ),
            (
                "python",
                "# tests/conftest.py",
                "pytest_plugins = ('tests.fixtures.cases',)",
            ),
            (
                "python",
                "# tests/test_case.py",
                "def test_case(case):\n    assert case.required_method() == 'real'",
            ),
        ),
    )
    foundation = {
        "pkg/__init__.py": b"",
        "pkg/foundation_case.py": (
            b"class FoundationCase:\n    def required_method(self) -> str:\n        return 'real'\n"
        ),
    }

    errors = validate_plan_document(parse_plan_text(plan), foundation_files=foundation)

    assert not any("typed concrete harness" in error for error in errors), errors
    assert not any("probe failed" in error for error in errors), errors


def test_fixture_diagnostics_preserve_occurrences_and_distinct_missing_names() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_cases.py"),),
        snippets=(
            (
                "python",
                "# tests/test_cases.py",
                "def test_a(missing):\n    assert missing\n\n"
                "def test_b(missing, other_missing):\n    assert missing and other_missing",
            ),
        ),
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert sum("fixture consumer missing" in error for error in errors) == 2
    assert any("3 consumer occurrences" in error for error in errors)
    assert any("2 distinct missing producers" in error for error in errors)


def test_fixture_dependencies_are_counted_as_consumer_occurrences() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(
            ("Create", "tests/fixtures/cases.py"),
            ("Test", "tests/test_case.py"),
        ),
        snippets=(
            (
                "python",
                "# tests/fixtures/cases.py",
                "import pytest\n\n"
                "@pytest.fixture\n"
                "def case(missing_dependency) -> int:\n    return missing_dependency",
            ),
            (
                "python",
                "# tests/test_case.py",
                "pytest_plugins = ('tests.fixtures.cases',)\n\n"
                "def test_case(case):\n    assert case",
            ),
        ),
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any(
        "fixture missing_dependency has 0 explicit producers" in error for error in errors
    ), errors
    assert any("2 consumer occurrences" in error for error in errors), errors


def test_usefixtures_consumer_requires_discoverable_producer() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_case.py"),),
        snippets=(
            (
                "python",
                "# tests/test_case.py",
                "import pytest\n\n"
                "@pytest.mark.usefixtures('missing_case')\n"
                "def test_case():\n    assert True",
            ),
        ),
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any("fixture missing_case has 0 explicit producers" in error for error in errors)


def test_tasks_03_through_16_require_foundation_task_13() -> None:
    errors = validate_plan_document(parse_plan_text(PLAN_PATH.read_text()), foundation_files={})

    missing = [error for error in errors if "must depend on accepted Foundation Task 13" in error]
    assert missing == [], missing


def test_authoritative_plan_now_owns_offline_wake_model_gate() -> None:
    errors = validate_plan_document(parse_plan_text(PLAN_PATH.read_text()), foundation_files={})

    assert not any(
        "green command does not execute owned test "
        "tests/unit/edge/test_wake_model_offline.py" in error
        for error in errors
    ), errors
    assert not any(
        "green command does not execute owned test tests/hardware/bench_wakeword.py" in error
        for error in errors
    ), errors


def test_authoritative_plan_green_gate_verifies_generated_schema() -> None:
    document = parse_plan_text(PLAN_PATH.read_text())
    errors = validate_plan_document(document, foundation_files={})

    assert not any(
        "green command does not verify generator bilingual-report-schema-v1" in error
        for error in errors
    ), errors
    task_15 = next(task for task in document.tasks if task.number == 15)
    assert task_15.generators[0].argv[:6] == (
        "uv",
        "run",
        "--project",
        "evals",
        "--locked",
        "python",
    )


def test_authoritative_schema_generator_declares_the_validated_dialect() -> None:
    task_15 = next(
        task for task in parse_plan_text(PLAN_PATH.read_text()).tasks if task.number == 15
    )
    generator = next(
        snippet
        for snippet in task_15.snippets
        if snippet.path == "evals/generate_bilingual_report_schema.py"
    )

    assert b'schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"' in generator.body


def test_task12_green_gate_must_execute_strict_manifest_loader_for_both_copies() -> None:
    source = PLAN_PATH.read_text().replace(
        " && uv run python scripts/check_model_manifest.py models/manifest.yaml"
        " && uv run python scripts/check_model_manifest.py "
        "apps/core/src/tuntun_core/resources/model-manifest.yaml",
        "",
        1,
    )

    errors = validate_plan_document(parse_plan_text(source), foundation_files={})

    assert any("green command does not validate both model manifests" in error for error in errors)


def test_authoritative_plan_has_removed_the_forbidden_manifest_key() -> None:
    errors = validate_plan_document(parse_plan_text(PLAN_PATH.read_text()), foundation_files={})

    assert not any("forbidden key runtime_download" in error for error in errors), errors


def test_foundation_ref_must_materialize_migration_engine_and_integration_test() -> None:
    plan = parse_plan_text(_valid_two_task_plan())
    incomplete = _foundation_files()
    incomplete.pop(FOUNDATION_MIGRATION_PATHS[-1])

    errors = validate_plan_document(
        plan, foundation_files=incomplete, require_foundation_task_13=True
    )

    assert any(FOUNDATION_MIGRATION_PATHS[-1] in error for error in errors), errors


def test_foundation_pass_classes_and_comment_tokens_do_not_satisfy_capabilities() -> None:
    fake = {
        FOUNDATION_MIGRATION_PATHS[0]: b"# create_sqlcipher_engine\nclass Engine: pass\n",
        FOUNDATION_MIGRATION_PATHS[1]: (
            b"# encrypted_backup upgrade_encrypted\nclass Migration: pass\n"
        ),
        FOUNDATION_MIGRATION_PATHS[2]: b"# upgrade downgrade\ndef test_migrations():\n    pass\n",
    }

    errors = validate_plan_document(
        parse_plan_text(_valid_two_task_plan()),
        foundation_files=fake,
        require_foundation_task_13=True,
    )

    assert any("behavioral interface" in error for error in errors), errors


def test_foundation_migration_integration_test_must_execute_successfully() -> None:
    broken = _foundation_files() | {
        validator.FOUNDATION_REVISION_PATH: (
            b"def upgrade(state):\n    state.append('revision-up')\n\n"
            b"def downgrade(state):\n    state.append('revision-down')\n"
        ),
        FOUNDATION_MIGRATION_PATHS[2]: (
            b"class command:\n"
            b"    @staticmethod\n    def upgrade(state):\n        state.append('up')\n"
            b"    @staticmethod\n    def downgrade(state):\n        state.append('down')\n\n"
            b"def test_migrations_upgrade_and_rollback():\n"
            b"    state = []\n    command.upgrade(state)\n    command.downgrade(state)\n"
            b"    assert state == ['never', 'passes']\n"
        ),
    }

    errors = validate_plan_document(
        parse_plan_text(_valid_two_task_plan()),
        foundation_files=broken,
        require_foundation_task_13=True,
    )

    assert any("Foundation Task 13 behavioral probe failed" in error for error in errors)


def test_foundation_migration_integration_test_cannot_skip() -> None:
    skipped = _foundation_files() | {
        validator.FOUNDATION_REVISION_PATH: (
            b"def upgrade(state):\n    state.append('revision-up')\n\n"
            b"def downgrade(state):\n    state.append('revision-down')\n"
        ),
        FOUNDATION_MIGRATION_PATHS[2]: (
            b"import pytest\n\n"
            b"class command:\n"
            b"    @staticmethod\n    def upgrade(state):\n        state.append('up')\n"
            b"    @staticmethod\n    def downgrade(state):\n        state.append('down')\n\n"
            b"def test_migrations_upgrade_and_rollback():\n"
            b"    command.upgrade([])\n    command.downgrade([])\n"
            b"    assert True\n    pytest.skip('not evidence')\n"
        ),
    }

    errors = validate_plan_document(
        parse_plan_text(_valid_two_task_plan()),
        foundation_files=skipped,
        require_foundation_task_13=True,
    )

    assert any("Foundation Task 13" in error and "skip/xfail" in error for error in errors), errors


def test_foundation_behavioral_probe_rejects_runtime_aliased_skip() -> None:
    skipped = _foundation_files() | {
        validator.FOUNDATION_REVISION_PATH: (
            b"def upgrade(state):\n    state.append('revision-up')\n\n"
            b"def downgrade(state):\n    state.append('revision-down')\n"
        ),
        FOUNDATION_MIGRATION_PATHS[2]: (
            b"import pytest\n_skip = pytest.skip\n\n"
            b"class command:\n"
            b"    @staticmethod\n    def upgrade(state):\n        state.append('up')\n"
            b"    @staticmethod\n    def downgrade(state):\n        state.append('down')\n\n"
            b"def test_migrations_upgrade_and_rollback():\n"
            b"    state = []\n    command.upgrade(state)\n    command.downgrade(state)\n"
            b"    assert state == ['up', 'down']\n    _skip('not evidence')\n"
        ),
    }

    errors = validate_plan_document(
        parse_plan_text(_valid_two_task_plan()),
        foundation_files=skipped,
        require_foundation_task_13=True,
    )

    assert any("Foundation Task 13 behavioral probe failed" in error for error in errors)


def test_foundation_integration_test_must_exercise_supplied_production_modules() -> None:
    errors = validate_plan_document(
        parse_plan_text(_valid_two_task_plan()),
        foundation_files=_disconnected_foundation_files(),
        require_foundation_task_13=True,
    )

    assert any(
        "not behaviorally coupled" in error and FOUNDATION_MIGRATION_PATHS[0] in error
        for error in errors
    ), errors
    assert any(
        "not behaviorally coupled" in error and FOUNDATION_MIGRATION_PATHS[1] in error
        for error in errors
    ), errors


def test_synthetic_accepted_foundation_capabilities_pass_the_boundary_gate() -> None:
    errors = validate_plan_document(
        parse_plan_text(_valid_two_task_plan()),
        foundation_files=_real_foundation_files(),
        require_foundation_task_13=True,
    )

    assert [error for error in errors if "Foundation Task 13" in error] == []


def test_foundation_conftest_fixture_is_in_static_and_runtime_closure() -> None:
    foundation = _foundation_files() | {
        "pkg/foundation_case.py": (
            b"class FoundationCase:\n    def required_method(self):\n        return 'ready'\n"
        ),
        "tests/conftest.py": (
            b"import pytest\n"
            b"from pkg.foundation_case import FoundationCase\n\n"
            b"@pytest.fixture\n"
            b"def foundation_case() -> FoundationCase:\n"
            b"    return FoundationCase()\n"
        ),
    }
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_foundation_case.py"),),
        snippets=(
            (
                "python",
                "# tests/test_foundation_case.py",
                "def test_foundation_case(foundation_case):\n"
                "    assert foundation_case.required_method() == 'ready'",
            ),
        ),
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files=foundation)

    assert not any("fixture foundation_case" in error for error in errors), errors
    assert not any("pytest task-boundary probe failed" in error for error in errors), errors


def test_foundation_typed_factory_fixture_uses_runtime_discovery_evidence() -> None:
    foundation = _foundation_files() | {
        "pkg/foundation_case.py": (
            b"class FoundationCase:\n"
            b"    @classmethod\n"
            b"    def build(cls):\n        return cls()\n"
            b"    def required_method(self):\n        return 'ready'\n"
        ),
        "tests/conftest.py": (
            b"import pytest\n"
            b"from pkg.foundation_case import FoundationCase\n\n"
            b"@pytest.fixture\n"
            b"def foundation_case() -> FoundationCase:\n"
            b"    return FoundationCase.build()\n"
        ),
    }
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_foundation_case.py"),),
        snippets=(
            (
                "python",
                "# tests/test_foundation_case.py",
                "def test_foundation_case(foundation_case):\n"
                "    assert foundation_case.required_method() == 'ready'",
            ),
        ),
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files=foundation)

    assert not any(
        "fixture foundation_case does not return a typed concrete harness" in error
        for error in errors
    ), errors
    assert not any("pytest task-boundary probe failed" in error for error in errors), errors


def test_foundation_callable_fixture_annotation_is_concrete() -> None:
    foundation = _foundation_files() | {
        "tests/conftest.py": (
            b"from collections.abc import Callable\nimport pytest\n\n"
            b"@pytest.fixture\n"
            b"def text_builder() -> Callable[[str], str]:\n"
            b"    def build(value: str) -> str:\n        return value.upper()\n"
            b"    return build\n"
        )
    }
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_builder.py"),),
        snippets=(
            (
                "python",
                "# tests/test_builder.py",
                "def test_builder(text_builder):\n    assert text_builder('ready') == 'READY'",
            ),
        ),
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files=foundation)

    assert not any(
        "fixture text_builder does not return a typed concrete harness" in error for error in errors
    ), errors
    assert not any("pytest task-boundary probe failed" in error for error in errors), errors


def test_unregistered_foundation_fixture_module_does_not_close_consumer() -> None:
    foundation = _foundation_files() | {
        "tests/fixtures/cases.py": (
            b"import pytest\n\n"
            b"class FoundationCase:\n"
            b"    def required_method(self):\n        return 'ready'\n\n"
            b"@pytest.fixture\n"
            b"def foundation_case() -> FoundationCase:\n"
            b"    return FoundationCase()\n"
        )
    }
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_foundation_case.py"),),
        snippets=(
            (
                "python",
                "# tests/test_foundation_case.py",
                "def test_foundation_case(foundation_case):\n"
                "    assert foundation_case.required_method() == 'ready'",
            ),
        ),
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files=foundation)

    assert any("fixture foundation_case has 0 explicit producers" in error for error in errors)
    assert any("pytest task-boundary probe failed" in error for error in errors)


def test_authoritative_plan_and_current_foundation_are_truthfully_blocked() -> None:
    foundation_ref = subprocess.run(
        ["git", "rev-parse", "feat/foundation-task9"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    foundation_files = {
        path: subprocess.run(
            ["git", "show", f"{foundation_ref}:{path}"],
            check=True,
            capture_output=True,
        ).stdout
        for path in subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", foundation_ref],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
    }

    errors = validate_plan_document(
        parse_plan_text(PLAN_PATH.read_text()),
        foundation_files=foundation_files,
        require_foundation_task_13=True,
    )

    for capability in FOUNDATION_MIGRATION_PATHS:
        assert any(capability in error for error in errors), (capability, errors)
    assert any("declared/snippet path mismatch" in error for error in errors), errors
    assert any("dynamic fixture name table is forbidden" in error for error in errors), errors
    assert any("wake benchmark behavioral probe" in error for error in errors), errors
    assert not any("must generate the bilingual report schema" in error for error in errors), errors
    assert any(error.startswith("Task 15: declared/snippet path mismatch") for error in errors), (
        errors
    )


@pytest.mark.parametrize(
    "mutation",
    (
        lambda data: data.replace(b"models:\n", b"models:\n- id: duplicate\n  id: hidden\n", 1),
        lambda data: data.replace(b"id: hello-tuntun-v1", b"id: true"),
        lambda data: data.replace(b"id: hello-tuntun-v1", b"id: ../wake"),
        lambda data: data.replace(b"a" * 40, b"main"),
        lambda data: data.replace(b"size: 1", b"size: true"),
        lambda data: data.replace(b"b" * 64, b"B" * 64),
        lambda data: data.replace(b"hello.onnx", b"../hello.onnx"),
        lambda data: data.replace(
            b"https://models.example.com/hello.onnx", b"http://models.example.com/hello.onnx"
        ),
        lambda data: data.replace(
            b"https://models.example.com/hello.onnx", b"https://127.0.0.1/hello.onnx"
        ),
        lambda data: data.replace(b"models:\n", b"models: &models\n", 1) + b"shadow: *models\n",
        lambda data: data.replace(
            b"https://models.example.com/hello.onnx",
            b"https://bad host/hello.onnx",
        ),
        lambda data: data.replace(
            b"https://models.example.com/hello.onnx",
            b"https://models.example.com/../hello.onnx",
        ),
    ),
)
def test_model_manifest_semantics_reject_hostile_values(
    mutation: Callable[[bytes], bytes],
) -> None:
    assert validate_model_manifest_bytes(mutation(_valid_model_manifest()))


def test_model_manifest_parser_rejects_oversized_or_deep_documents() -> None:
    assert validate_model_manifest_bytes(_valid_model_manifest() + b"#" * 1_048_576)
    nested_alias_free = b"schema_version: '1.0'\nmodels: " + b"[" * 40 + b"]" * 40
    assert validate_model_manifest_bytes(nested_alias_free)


@pytest.mark.parametrize(
    "content",
    (
        _valid_model_manifest().replace(
            b"  license: Apache-2.0\n  provenance: approved synthetic corpus",
            b"  license: &approved Apache-2.0\n  provenance: *approved",
        ),
        _valid_model_manifest().replace(b"  license: Apache-2.0", b"  license: !!str Apache-2.0"),
    ),
)
def test_model_manifest_parser_rejects_aliases_and_explicit_tags(content: bytes) -> None:
    assert validate_model_manifest_bytes(content)


def test_materialized_manifests_not_snippet_text_are_compared() -> None:
    plan = _task(
        12,
        depends="Foundation Task 13",
        files=(
            ("Modify", "models/manifest.yaml"),
            ("Modify", "apps/core/src/tuntun_core/resources/model-manifest.yaml"),
        ),
        snippets=(
            (
                "yaml",
                "# replace models/manifest.yaml",
                "# materializer: replace-file\n" + _valid_model_manifest().decode(),
            ),
            (
                "yaml",
                "# append to apps/core/src/tuntun_core/resources/model-manifest.yaml",
                "# materializer: append\n# snippet differs but final bytes cannot",
            ),
        ),
    )
    foundation = _foundation_files() | {
        "models/manifest.yaml": _valid_model_manifest(),
        "apps/core/src/tuntun_core/resources/model-manifest.yaml": _valid_model_manifest(),
    }

    errors = validate_plan_document(parse_plan_text(plan), foundation_files=foundation)

    assert any("materialized repository and packaged manifests" in error for error in errors)


def test_task12_manifest_requires_exactly_both_wake_model_ids() -> None:
    manifest = _valid_model_manifest()
    plan = _task(
        12,
        depends="Foundation Task 13",
        files=(
            ("Modify", "models/manifest.yaml"),
            ("Modify", "apps/core/src/tuntun_core/resources/model-manifest.yaml"),
        ),
        snippets=(
            (
                "yaml",
                "# replace models/manifest.yaml",
                "# materializer: replace-file\n" + manifest.decode(),
            ),
            (
                "yaml",
                "# replace apps/core/src/tuntun_core/resources/model-manifest.yaml",
                "# materializer: replace-file\n" + manifest.decode(),
            ),
        ),
    )
    foundation = _foundation_files() | {
        "models/manifest.yaml": _valid_task12_manifest(),
        "apps/core/src/tuntun_core/resources/model-manifest.yaml": _valid_task12_manifest(),
    }

    errors = validate_plan_document(parse_plan_text(plan), foundation_files=foundation)

    assert any("exact model IDs hello-tuntun-v1 and stop-tuntun-v1" in error for error in errors), (
        errors
    )


def _controlled_bilingual_schema() -> bytes:
    fields = (
        "schema_version",
        "candidate_commit",
        "model_id",
        "prompt_bundle_sha256",
        "policy_sha256",
        "corpus_sha256",
        "scorer_sha256",
        "evaluator_model_lock_sha256",
        "calibration_corpus_sha256",
        "child_safety_corpus_sha256",
        "evaluator_license",
        "evaluator_artifacts_sha256",
        "verification_key_sha256",
        "calibration_evidence_sha256",
        "result_manifest_paths",
        "result_manifest_sha256",
        "ordered_case_ids_sha256",
        "aggregates",
        "signer_key_id",
        "signature_domain",
        "signature_purpose",
        "issued_at",
        "expires_at",
        "signature_b64",
    )
    aggregate_fields = (
        "bilingual_total",
        "bilingual_language_ok",
        "child_adversarial_total",
        "child_adversarial_safe",
        "child_benign_total",
        "child_benign_appropriate",
        "role_mismatches",
        "relevance_failures",
        "word_cap_failures",
        "boundary_failures",
        "leaked_claims",
        "child_search_action_memory_attempts",
    )

    def titled(name: str, **values: object) -> dict[str, object]:
        return {**values, "title": name.replace("_", " ").title()}

    properties = {name: titled(name, type="string") for name in fields}
    properties["schema_version"] = {
        "const": "tuntun.bilingual-persona-score.v1",
        "title": "Schema Version",
        "type": "string",
    }
    properties["candidate_commit"] = titled(
        "candidate_commit", pattern="^[0-9a-f]{40}$", type="string"
    )
    properties["model_id"] = titled("model_id", minLength=1, maxLength=128, type="string")
    for name in (
        "prompt_bundle_sha256",
        "policy_sha256",
        "corpus_sha256",
        "scorer_sha256",
        "evaluator_model_lock_sha256",
        "calibration_corpus_sha256",
        "child_safety_corpus_sha256",
        "verification_key_sha256",
        "calibration_evidence_sha256",
        "ordered_case_ids_sha256",
    ):
        properties[name] = titled(name, pattern="^[0-9a-f]{64}$", type="string")
    properties["evaluator_license"] = titled(
        "evaluator_license",
        enum=["MIT", "Apache-2.0", "CC-BY-4.0"],
        type="string",
    )
    properties["evaluator_artifacts_sha256"] = titled(
        "evaluator_artifacts_sha256",
        items={"type": "string"},
        minItems=2,
        maxItems=8,
        type="array",
    )
    properties["result_manifest_paths"] = titled(
        "result_manifest_paths",
        items={"format": "path", "type": "string"},
        minItems=2,
        maxItems=8,
        type="array",
    )
    properties["result_manifest_sha256"] = titled(
        "result_manifest_sha256",
        items={"type": "string"},
        minItems=2,
        maxItems=8,
        type="array",
    )
    properties["aggregates"] = {"$ref": "#/$defs/RecomputedAggregates"}
    properties["signer_key_id"] = titled("signer_key_id", minLength=1, maxLength=128, type="string")
    properties["signature_domain"] = {
        "const": "tuntun.bilingual-persona-score.v1",
        "title": "Signature Domain",
        "type": "string",
    }
    properties["signature_purpose"] = {
        "const": "phase1_release_acceptance",
        "title": "Signature Purpose",
        "type": "string",
    }
    properties["issued_at"] = titled("issued_at", format="date-time", type="string")
    properties["expires_at"] = titled("expires_at", format="date-time", type="string")
    properties["signature_b64"] = titled("signature_b64", minLength=88, maxLength=88, type="string")
    schema = {
        "$defs": {
            "RecomputedAggregates": {
                "additionalProperties": False,
                "properties": {name: titled(name, type="integer") for name in aggregate_fields},
                "required": list(aggregate_fields),
                "title": "RecomputedAggregates",
                "type": "object",
            }
        },
        "$id": "https://tuntun.local/schemas/bilingual-persona-score-v1.schema.json",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": properties,
        "required": list(fields),
        "title": "BilingualScoreReportV1",
        "type": "object",
    }
    return (json.dumps(schema, sort_keys=True, separators=(",", ":")) + "\n").encode()


def test_bilingual_schema_validator_executes_controlled_good_and_bad_artifacts() -> None:
    good = _controlled_bilingual_schema()
    assert validator.validate_bilingual_schema_bytes(good) == []

    mutations: tuple[Callable[[dict[str, Any]], dict[str, Any]], ...] = (
        lambda value: value | {"additionalProperties": True},
        lambda value: value | {"required": value["required"][:-1]},
        lambda value: (
            value | {"properties": value["properties"] | {"schema_version": {"type": "string"}}}
        ),
        lambda value: (
            value | {"properties": value["properties"] | {"candidate_commit": {"type": "string"}}}
        ),
    )
    for mutate in mutations:
        hostile = mutate(json.loads(good))
        errors = validator.validate_bilingual_schema_bytes(json.dumps(hostile).encode())
        assert errors, hostile


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value["$defs"]["RecomputedAggregates"].update(additionalProperties=True),
        lambda value: value["$defs"]["RecomputedAggregates"]["properties"][
            "bilingual_total"
        ].update(type="number"),
        lambda value: value["properties"]["aggregates"].update({"$ref": "#/$defs/Other"}),
        lambda value: value["properties"]["evaluator_artifacts_sha256"].update(maxItems=9),
        lambda value: value["properties"]["result_manifest_paths"]["items"].update(type="integer"),
        lambda value: value["properties"]["evaluator_license"].update(enum=["MIT"]),
        lambda value: value["properties"]["issued_at"].update(format="date"),
        lambda value: value["properties"]["signature_b64"].update(minLength=1),
        lambda value: value["properties"]["signer_key_id"].update(maxLength=129),
    ),
)
def test_bilingual_schema_rejects_nested_contract_drift(
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    hostile = json.loads(_controlled_bilingual_schema())
    mutation(hostile)
    content = (json.dumps(hostile, sort_keys=True, separators=(",", ":")) + "\n").encode()

    assert validator.validate_bilingual_schema_bytes(content), hostile


def _bilingual_report_model_source() -> bytes:
    return b"""from datetime import datetime
from pathlib import Path
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

HEX64 = r"^[0-9a-f]{64}$"

class RecomputedAggregates(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    bilingual_total: int
    bilingual_language_ok: int
    child_adversarial_total: int
    child_adversarial_safe: int
    child_benign_total: int
    child_benign_appropriate: int
    role_mismatches: int
    relevance_failures: int
    word_cap_failures: int
    boundary_failures: int
    leaked_claims: int
    child_search_action_memory_attempts: int

class BilingualScoreReportV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    schema_version: Literal["tuntun.bilingual-persona-score.v1"]
    candidate_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    model_id: str = Field(min_length=1, max_length=128)
    prompt_bundle_sha256: str = Field(pattern=HEX64)
    policy_sha256: str = Field(pattern=HEX64)
    corpus_sha256: str = Field(pattern=HEX64)
    scorer_sha256: str = Field(pattern=HEX64)
    evaluator_model_lock_sha256: str = Field(pattern=HEX64)
    calibration_corpus_sha256: str = Field(pattern=HEX64)
    child_safety_corpus_sha256: str = Field(pattern=HEX64)
    evaluator_license: Literal["MIT", "Apache-2.0", "CC-BY-4.0"]
    evaluator_artifacts_sha256: tuple[str, ...] = Field(min_length=2, max_length=8)
    verification_key_sha256: str = Field(pattern=HEX64)
    calibration_evidence_sha256: str = Field(pattern=HEX64)
    result_manifest_paths: tuple[Path, ...] = Field(min_length=2, max_length=8)
    result_manifest_sha256: tuple[str, ...] = Field(min_length=2, max_length=8)
    ordered_case_ids_sha256: str = Field(pattern=HEX64)
    aggregates: RecomputedAggregates
    signer_key_id: str = Field(min_length=1, max_length=128)
    signature_domain: Literal["tuntun.bilingual-persona-score.v1"]
    signature_purpose: Literal["phase1_release_acceptance"]
    issued_at: datetime
    expires_at: datetime
    signature_b64: str = Field(min_length=88, max_length=88)

    @model_validator(mode="after")
    def lifecycle(self):
        if (
            self.issued_at.tzinfo is None
            or self.expires_at.tzinfo is None
            or not self.issued_at < self.expires_at
            or (self.expires_at - self.issued_at).total_seconds() > 86400
            or len(self.result_manifest_paths) != len(self.result_manifest_sha256)
            or len(set(self.result_manifest_paths)) != len(self.result_manifest_paths)
        ):
            raise ValueError("report lifecycle invalid")
        return self
"""


def _distribution_wheel(distribution_name: str) -> tuple[str, bytes, str, str]:
    distribution = importlib.metadata.distribution(distribution_name)
    canonical = distribution.metadata["Name"].replace("-", "_")
    version = distribution.version
    filename = f"{canonical}-{version}-py3-none-any.whl"
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for relative in distribution.files or ():
            path = Path(str(relative))
            if path.is_absolute() or ".." in path.parts:
                continue
            source = Path(str(distribution.locate_file(relative)))
            if source.is_file():
                archive.writestr(path.as_posix(), source.read_bytes())
    wheel = stream.getvalue()
    return filename, wheel, hashlib.sha256(wheel).hexdigest(), version


def _bilingual_runtime_files(source: bytes) -> dict[str, bytes]:
    distributions = (
        "annotated-types",
        "pydantic",
        "pydantic-core",
        "typing-extensions",
        "typing-inspection",
    )
    wheels = {name: _distribution_wheel(name) for name in distributions}
    dependency_literals = ", ".join(f"'{name}=={wheel[3]}'" for name, wheel in wheels.items())
    project_dependencies = ", ".join(f'{{ name = "{name}" }}' for name in wheels)
    project_metadata = ", ".join(
        f'{{ name = "{name}", specifier = "=={wheel[3]}" }}' for name, wheel in wheels.items()
    )
    locked_names = {str(canonicalize_name(name)) for name in wheels}
    marker_environment = {key: str(value) for key, value in default_environment().items()}
    marker_environment["extra"] = ""
    locked_packages = []
    for name, (filename, wheel, digest, version) in wheels.items():
        distribution = importlib.metadata.distribution(name)
        active_dependencies = []
        for value in distribution.requires or ():
            requirement = Requirement(value)
            if requirement.marker is not None and not requirement.marker.evaluate(
                environment=marker_environment,
                context="metadata",
            ):
                continue
            dependency_name = str(canonicalize_name(requirement.name))
            assert not requirement.extras and requirement.url is None
            assert dependency_name in locked_names
            active_dependencies.append(f'{{ name = "{dependency_name}" }}')
        dependency_record = (
            f"dependencies = [{', '.join(sorted(active_dependencies))}]\n"
            if active_dependencies
            else ""
        )
        locked_packages.append(
            f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
            f"{dependency_record}"
            "[[package.wheels]]\n"
            f'url = "https://files.pythonhosted.org/packages/tuntun/{filename}"\n'
            f'hash = "sha256:{digest}"\nsize = {len(wheel)}\n'
        )
    lock = (
        'version = 1\nrevision = 3\nrequires-python = "==3.12.*"\n\n'
        '[[package]]\nname = "bilingual-runtime-fixture"\nversion = "0.0.0"\n'
        'source = { virtual = "." }\n'
        f"dependencies = [{project_dependencies}]\n\n"
        "[package.metadata]\n"
        f"requires-dist = [{project_metadata}]\n\n" + "\n".join(locked_packages)
    )
    files = {
        "evals/verify_bilingual_report.py": source,
        "evals/pyproject.toml": (
            "[project]\nname = 'bilingual-runtime-fixture'\nversion = '0.0.0'\n"
            "requires-python = '==3.12.*'\n"
            f"dependencies = [{dependency_literals}]\n"
        ).encode(),
        "evals/uv.lock": lock.encode(),
    }
    files.update(
        {f".tuntun/locked-wheels/{filename}": wheel for filename, wheel, _, _ in wheels.values()}
    )
    return files


def test_bilingual_report_runtime_enforces_lifecycle_and_signature_contract() -> None:
    files = _bilingual_runtime_files(_bilingual_report_model_source())

    assert validator.validate_bilingual_report_model_files(files) == []

    disconnected = _bilingual_runtime_files(
        _bilingual_report_model_source().replace(b"        if (\n", b"        if False and (\n", 1)
    )
    assert validator.validate_bilingual_report_model_files(disconnected)


def _disconnected_wake_benchmark() -> bytes:
    return b"""def run_benchmark(*, frames, converter, adapter, detector, process_time,
                  boot_uuid, operator_generation, model_sha256, runtime_sha256,
                  max_one_core_percent):
    started = process_time()
    input_count = inference_count = output_count = drop_count = 0
    for frame in frames:
        input_count += 1
        converted = converter.convert(frame)
        if converted is None:
            drop_count += 1
            continue
        before = adapter.inference_count
        detector.process(converted)
        inference_count += adapter.inference_count - before
        output_count += 1
    duration_seconds = input_count * 1280 / 16000
    one_core_percent = (process_time() - started) / duration_seconds * 100
    if adapter.model_sha256 != model_sha256 or adapter.runtime_sha256 != runtime_sha256:
        raise RuntimeError("artifact/runtime mismatch")
    if drop_count or inference_count != input_count or output_count != input_count:
        raise RuntimeError("pipeline count mismatch")
    if one_core_percent > max_one_core_percent:
        raise RuntimeError("CPU threshold exceeded")
    return {
        "boot_uuid": boot_uuid,
        "operator_generation": operator_generation,
        "model_sha256": model_sha256,
        "runtime_sha256": runtime_sha256,
        "input_count": input_count,
        "inference_count": inference_count,
        "output_count": output_count,
        "drop_count": drop_count,
        "duration_seconds": duration_seconds,
        "one_core_percent": one_core_percent,
        "threshold_percent": max_one_core_percent,
    }
"""


def test_wake_benchmark_behavioral_probe_executes_good_and_fault_artifacts() -> None:
    fake_receipt = b"""def run_benchmark(**kwargs):
    return {
        "boot_uuid": kwargs["boot_uuid"], "operator_generation": kwargs["operator_generation"],
        "model_sha256": kwargs["model_sha256"], "runtime_sha256": kwargs["runtime_sha256"],
        "input_count": 4, "inference_count": 4, "output_count": 4, "drop_count": 0,
        "duration_seconds": 0.32, "one_core_percent": 1.0,
        "threshold_percent": kwargs["max_one_core_percent"],
    }
"""

    errors = validator.validate_wake_benchmark_bytes(fake_receipt)

    assert any("behavioral probe" in error for error in errors), errors


def _production_wake_files() -> dict[str, bytes]:
    benchmark = b"""import argparse
import asyncio
import time

from tuntun_core.services.models.registry import ModelRegistry
from tuntun_edge.audio.converter import StreamingAudioConverter
from tuntun_edge.audio.wakeword import WakeDetector
from tuntun_contracts.speech import AudioFormat

MODEL_SHA = "a" * 64
RUNTIME_SHA = "b" * 64

async def run_benchmark(*, frames, converter, adapter, detector, process_time,
                        max_one_core_percent):
    started = process_time()
    input_count = inference_count = output_count = drop_count = 0
    async def source_frames():
        for frame in frames:
            yield frame
    source = AudioFormat(16000, 1, "s16le", True, "mono")
    target = AudioFormat(16000, 1, "s16le", True, "mono")
    async for converted in converter.convert(source_frames(), source, target):
        input_count += 1
        before = adapter.inference_count
        detected = detector.process(converted)
        inference_count += adapter.inference_count - before
        output_count += int(detected)
    duration_seconds = input_count * 1280 / 16000
    one_core_percent = (process_time() - started) / duration_seconds * 100
    if adapter.model_sha256 != MODEL_SHA or adapter.runtime_sha256 != RUNTIME_SHA:
        raise RuntimeError("artifact/runtime mismatch")
    if drop_count or inference_count != input_count or output_count != input_count:
        raise RuntimeError("pipeline count mismatch")
    if one_core_percent > max_one_core_percent:
        raise RuntimeError("CPU threshold exceeded")
    return {
        "input_count": input_count,
        "inference_count": inference_count,
        "output_count": output_count,
        "drop_count": drop_count,
        "model_sha256": adapter.model_sha256,
        "runtime_sha256": adapter.runtime_sha256,
    }

def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--frames", type=int, required=True)
    parser.add_argument("--max-one-core-percent", type=float, required=True)
    args = parser.parse_args(argv)
    if not 1 <= args.frames <= 64:
        raise ValueError("frame_count_invalid")
    registry = ModelRegistry.from_document({
        "schema_version": "1.0",
        "models": [{"id": "hello-tuntun-v1", "model_sha256": MODEL_SHA,
                    "runtime_sha256": RUNTIME_SHA}],
    })
    activated = registry.activate("hello-tuntun-v1")
    adapter = activated.load_with()
    converter = StreamingAudioConverter()
    detector = WakeDetector(adapter.infer, 750000)
    receipt = asyncio.run(
        run_benchmark(
            frames=[b"\\x00" * 2560 for _ in range(args.frames)],
            converter=converter,
            adapter=adapter,
            detector=detector,
            process_time=time.process_time,
            max_one_core_percent=args.max_one_core_percent,
        )
    )
    if set(receipt) != {
        "input_count", "inference_count", "output_count", "drop_count",
        "model_sha256", "runtime_sha256",
    } or receipt["input_count"] != args.frames:
        raise RuntimeError("receipt mismatch")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
"""
    return {
        "packages/contracts/src/tuntun_contracts/__init__.py": b"",
        "packages/contracts/src/tuntun_contracts/speech.py": (
            b"from dataclasses import dataclass\n\n"
            b"@dataclass(frozen=True)\n"
            b"class AudioFormat:\n"
            b"    sample_rate_hz: int\n    channels: int\n    sample_format: str\n"
            b"    interleaved: bool\n    channel_layout: str\n"
        ),
        "apps/edge/src/tuntun_edge/__init__.py": b"",
        "apps/edge/src/tuntun_edge/audio/__init__.py": b"",
        "apps/edge/src/tuntun_edge/audio/converter.py": (
            b"class StreamingAudioConverter:\n"
            b"    def convert(self, audio, source, target):\n"
            b"        if source != target:\n            raise ValueError('format')\n"
            b"        async def converted():\n"
            b"            async for frame in audio:\n"
            b"                if len(frame) != 2560:\n"
            b"                    raise ValueError('frame')\n"
            b"                yield frame\n"
            b"        return converted()\n"
        ),
        "apps/edge/src/tuntun_edge/audio/wakeword.py": (
            b"class WakeDetector:\n"
            b"    def __init__(self, infer, threshold_micros):\n"
            b"        self._infer = infer\n        self._threshold = threshold_micros\n"
            b"    def process(self, frame):\n"
            b"        if len(frame) != 2560:\n            raise ValueError('frame')\n"
            b"        return self._infer(frame) >= self._threshold\n"
        ),
        "apps/core/src/tuntun_core/__init__.py": b"",
        "apps/core/src/tuntun_core/services/__init__.py": b"",
        "apps/core/src/tuntun_core/services/models/__init__.py": b"",
        "apps/core/src/tuntun_core/services/models/registry.py": (
            b"class Adapter:\n"
            b"    model_sha256 = 'a' * 64\n    runtime_sha256 = 'b' * 64\n"
            b"    def __init__(self):\n        self.inference_count = 0\n"
            b"    def infer(self, frame):\n"
            b"        self.inference_count += 1\n        return 900000\n\n"
            b"class ActivatedModel:\n"
            b"    def load_with(self):\n        return Adapter()\n\n"
            b"class ModelRegistry:\n"
            b"    @classmethod\n"
            b"    def from_document(cls, raw):\n"
            b"        if raw.get('schema_version') != '1.0':\n"
            b"            raise ValueError('manifest')\n"
            b"        return cls()\n"
            b"    def activate(self, model_id):\n"
            b"        if model_id != 'hello-tuntun-v1':\n            raise ValueError('model')\n"
            b"        return ActivatedModel()\n"
        ),
        "tests/hardware/bench_wakeword.py": benchmark,
    }


def test_wake_benchmark_uses_delivered_production_pipeline_and_main() -> None:
    files = _production_wake_files()

    assert (
        validator.validate_wake_benchmark_bytes(
            files["tests/hardware/bench_wakeword.py"], materialized_files=files
        )
        == []
    )

    disconnected = _disconnected_wake_benchmark()
    errors = validator.validate_wake_benchmark_bytes(
        disconnected,
        materialized_files=files | {"tests/hardware/bench_wakeword.py": disconnected},
    )
    assert any("production pipeline" in error or "main" in error for error in errors), errors


def test_wake_probe_rejects_sync_converter_and_zero_arg_registry_fake() -> None:
    files = _production_wake_files()
    files["apps/edge/src/tuntun_edge/audio/converter.py"] = (
        b"class StreamingAudioConverter:\n    def convert(self, frame):\n        return frame\n"
    )

    errors = validator.validate_wake_benchmark_bytes(
        files["tests/hardware/bench_wakeword.py"], materialized_files=files
    )

    assert any("production-faithful async" in error for error in errors), errors


def test_wake_benchmark_noop_main_cannot_certify_physical_command() -> None:
    files = _production_wake_files()
    benchmark = files["tests/hardware/bench_wakeword.py"].replace(
        b"def main(argv=None):\n", b"def real_main(argv=None):\n", 1
    )
    benchmark += b"\ndef main(argv=None):\n    return 0\n"
    files["tests/hardware/bench_wakeword.py"] = benchmark

    errors = validator.validate_wake_benchmark_bytes(benchmark, materialized_files=files)

    assert any("main" in error or "controlled mutation" in error for error in errors), errors


def test_named_generator_is_deterministic_and_owns_exact_output() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(
            ("Create", "tools/generate.py"),
            ("Create", "generated/schema.json"),
        ),
        snippets=(
            (
                "python",
                "# tools/generate.py",
                "from pathlib import Path\n"
                "Path('generated').mkdir(exist_ok=True)\n"
                "Path('generated/schema.json').write_text('{\\\"version\\\":1}\\n')",
            ),
        ),
    ).replace(
        "**Files:**",
        "**Files:**\n- Generate `schema-v1`: `python tools/generate.py` -> `generated/schema.json`",
    )

    files = materialize_document(parse_plan_text(plan), foundation_files={})

    assert files["generated/schema.json"] == b'{"version":1}\n'


def test_named_generator_supports_exact_atomic_output_staging() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Create", "tools/generate.py"), ("Create", "generated/schema.json")),
        snippets=(
            (
                "python",
                "# tools/generate.py",
                "import os\n"
                "from pathlib import Path\n"
                "output=Path('generated/schema.json')\n"
                "output.parent.mkdir(exist_ok=True)\n"
                "temporary=output.with_name(f'.{output.name}.{os.getpid()}.tmp')\n"
                "temporary.write_text('{\\\"version\\\":1}\\n')\n"
                "os.replace(temporary,output)",
            ),
        ),
    ).replace(
        "**Files:**",
        "**Files:**\n- Generate `schema-v1`: `python tools/generate.py` -> `generated/schema.json`",
    )

    files = materialize_document(parse_plan_text(plan), foundation_files={})

    assert files["generated/schema.json"] == b'{"version":1}\n'
    assert not any(path.endswith(".tmp") for path in files)


@pytest.mark.parametrize(
    "mutation",
    (
        "Path('generated/.schema.json.attacker.tmp').write_text('hostile')",
        "Path('tools/generate.py').write_text('hostile')",
    ),
)
def test_named_generator_atomic_staging_keeps_siblings_and_sources_read_only(
    mutation: str,
) -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Create", "tools/generate.py"), ("Create", "generated/schema.json")),
        snippets=(
            (
                "python",
                "# tools/generate.py",
                "from pathlib import Path\n"
                "Path('generated').mkdir(exist_ok=True)\n"
                f"{mutation}\n"
                "Path('generated/schema.json').write_text('{}')",
            ),
        ),
    ).replace(
        "**Files:**",
        "**Files:**\n- Generate `schema-v1`: `python tools/generate.py` -> `generated/schema.json`",
    )

    with pytest.raises(MaterializationError, match="writable|undeclared"):
        materialize_document(parse_plan_text(plan), foundation_files={})


def test_named_generator_rejects_undeclared_side_effect(tmp_path: Path) -> None:
    del tmp_path
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Create", "tools/generate.py"), ("Create", "generated/schema.json")),
        snippets=(
            (
                "python",
                "# tools/generate.py",
                "from pathlib import Path\n"
                "Path('generated').mkdir(exist_ok=True)\n"
                "Path('generated/schema.json').write_text('{}')\n"
                "Path('unexpected.txt').write_text('side effect')",
            ),
        ),
    ).replace(
        "**Files:**",
        "**Files:**\n- Generate `schema-v1`: `python tools/generate.py` -> `generated/schema.json`",
    )

    with pytest.raises(MaterializationError, match="undeclared outputs"):
        materialize_document(parse_plan_text(plan), foundation_files={})


def test_named_generator_diagnostic_output_is_bounded() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Create", "tools/generate.py"), ("Create", "generated/schema.json")),
        snippets=(
            (
                "python",
                "# tools/generate.py",
                "from pathlib import Path\n"
                "Path('generated').mkdir(exist_ok=True)\n"
                "Path('generated/schema.json').write_text('{}')\n"
                "print('x' * 1_100_000)",
            ),
        ),
    ).replace(
        "**Files:**",
        "**Files:**\n- Generate `schema-v1`: `python tools/generate.py` -> `generated/schema.json`",
    )

    with pytest.raises(MaterializationError, match="diagnostic output exceeded"):
        materialize_document(parse_plan_text(plan), foundation_files={})


def test_named_generator_cannot_observe_ambient_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TUNTUN_GENERATOR_HOST_INPUT", "host-secret")
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Create", "tools/generate.py"), ("Create", "generated/schema.json")),
        snippets=(
            (
                "python",
                "# tools/generate.py",
                "import json\nimport os\nfrom pathlib import Path\n"
                "Path('generated').mkdir(exist_ok=True)\n"
                "value = os.getenv('TUNTUN_GENERATOR_HOST_INPUT', 'absent')\n"
                "Path('generated/schema.json').write_text(json.dumps({'value': value}))",
            ),
        ),
    ).replace(
        "**Files:**",
        "**Files:**\n- Generate `schema-v1`: `python tools/generate.py` -> `generated/schema.json`",
    )

    files = materialize_document(parse_plan_text(plan), foundation_files={})

    assert json.loads(files["generated/schema.json"])["value"] == "absent"


def test_named_generator_output_limit_interrupts_before_process_exit() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Create", "tools/generate.py"), ("Create", "generated/schema.json")),
        snippets=(
            (
                "python",
                "# tools/generate.py",
                "import sys\nimport time\nfrom pathlib import Path\n"
                "Path('generated').mkdir(exist_ok=True)\n"
                "Path('generated/schema.json').write_text('{}')\n"
                "sys.stdout.write('x' * 1_100_000)\n"
                "sys.stdout.flush()\n"
                "time.sleep(30)",
            ),
        ),
    ).replace(
        "**Files:**",
        "**Files:**\n- Generate `schema-v1`: `python tools/generate.py` -> `generated/schema.json`",
    )

    with pytest.raises(MaterializationError, match="diagnostic output exceeded"):
        materialize_document(parse_plan_text(plan), foundation_files={})


def test_generator_check_must_reject_controlled_output_drift() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Create", "tools/generate.py"), ("Create", "generated/schema.json")),
        snippets=(
            (
                "python",
                "# tools/generate.py",
                "import argparse\nfrom pathlib import Path\n"
                "parser = argparse.ArgumentParser()\n"
                "parser.add_argument('--write', action='store_true')\n"
                "parser.add_argument('--check', action='store_true')\n"
                "args = parser.parse_args()\n"
                "if args.write:\n"
                "    Path('generated').mkdir(exist_ok=True)\n"
                "    Path('generated/schema.json').write_text('{}')\n"
                "# malicious --check always succeeds",
            ),
        ),
    ).replace(
        "**Files:**",
        "**Files:**\n- Generate `schema-v1`: `python tools/generate.py --write` "
        "-> `generated/schema.json`",
    )

    with pytest.raises(MaterializationError, match="check accepted controlled output drift"):
        materialize_document(parse_plan_text(plan), foundation_files={})


def test_offline_wake_test_executes_against_good_and_networking_artifacts() -> None:
    def plan_for(activation: str) -> str:
        return _task(
            1,
            depends="Foundation contracts",
            files=(
                ("Create", "tests/fixtures/wake.py"),
                ("Create", "tests/conftest.py"),
                ("Test", "tests/test_wake_offline.py"),
            ),
            snippets=(
                (
                    "python",
                    "# tests/fixtures/wake.py",
                    "import socket\nimport pytest\n\n"
                    "class OfflineCase:\n"
                    f"    def activate(self):\n        {activation}\n\n"
                    "@pytest.fixture\n"
                    "def offline_case() -> OfflineCase:\n    return OfflineCase()",
                ),
                (
                    "python",
                    "# tests/conftest.py",
                    "pytest_plugins = ('tests.fixtures.wake',)",
                ),
                (
                    "python",
                    "# tests/test_wake_offline.py",
                    "import socket\n"
                    "\n"
                    "def test_offline(monkeypatch, offline_case):\n"
                    "    def deny(*args, **kwargs):\n"
                    "        raise AssertionError('network attempted')\n"
                    "    monkeypatch.setattr(socket, 'socket', deny)\n"
                    "    monkeypatch.setattr(socket, 'getaddrinfo', deny)\n"
                    "    assert offline_case.activate() == 'ready'",
                ),
            ),
        )

    good = validate_plan_document(parse_plan_text(plan_for("return 'ready'")), foundation_files={})
    bad = validate_plan_document(
        parse_plan_text(plan_for("socket.getaddrinfo('models.example.com', 443); return 'ready'")),
        foundation_files={},
    )

    assert not any("probe failed" in error for error in good), good
    assert any("pytest task-boundary probe failed" in error for error in bad), bad


def test_green_command_must_execute_owned_python_gate() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Create", "tools/probe_gate.py"),),
        snippets=(
            (
                "python",
                "# tools/probe_gate.py",
                "raise SystemExit('owned gate really executed')",
            ),
        ),
    ).replace(
        "git diff --cached --check",
        "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\n"
        "Run: `python tools/probe_gate.py`",
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any("owned green command failed" in error for error in errors), errors


@pytest.mark.parametrize("help_option", ("--help", "-h"))
def test_green_command_help_mode_never_counts_as_execution(help_option: str) -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Create", "tools/probe_gate.py"),),
        snippets=(
            (
                "python",
                "# tools/probe_gate.py",
                "import argparse\nargparse.ArgumentParser().parse_args()",
            ),
        ),
    ).replace(
        "git diff --cached --check",
        "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\n"
        f"Run: `python tools/probe_gate.py {help_option}`",
    )

    errors = validate_plan_document(
        parse_plan_text(plan), foundation_files={}, execute_behavioral_probes=False
    )

    assert any("green command is not fail-closed" in error for error in errors), errors


def test_final_materialized_tree_reruns_prior_task_tests() -> None:
    task_1 = _task(
        1,
        depends="Foundation contracts",
        files=(
            ("Create", "pkg/service.py"),
            ("Test", "tests/test_service.py"),
        ),
        snippets=(
            ("python", "# pkg/service.py", "def value():\n    return 'ready'"),
            (
                "python",
                "# tests/test_service.py",
                "from pkg.service import value\n\ndef test_value():\n    assert value() == 'ready'",
            ),
        ),
    ).replace(
        "git diff --cached --check",
        "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\n"
        "Run: `python -m pytest tests/test_service.py -q`",
    )
    task_2 = _task(
        2,
        depends="Task 01 and Foundation contracts",
        files=(("Modify", "pkg/service.py"),),
        snippets=(
            (
                "python",
                "# replace pkg/service.py",
                "# materializer: replace-file\ndef value():\n    return 'regressed'",
            ),
        ),
    )

    errors = validate_plan_document(parse_plan_text(task_1 + "\n" + task_2), foundation_files={})

    assert any("final cumulative pytest probe failed" in error for error in errors), errors


def test_external_only_status_is_computed_for_each_collected_class_method() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_mixed.py"),),
        snippets=(
            (
                "python",
                "# tests/test_mixed.py",
                "import pytest\n\n"
                "@pytest.mark.reachy_hardware\n"
                "def test_physical():\n    assert True\n\n"
                "class TestHiddenSoftwareRegression:\n"
                "    def test_ordinary(self):\n        assert False",
            ),
        ),
    ).replace(
        "git diff --cached --check",
        "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\n"
        "Run: `python -m pytest tests/test_mixed.py -q`",
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any("pytest task-boundary probe failed" in error for error in errors), errors


def test_external_marker_selection_cannot_hide_ordinary_node_in_mixed_file() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_mixed.py"),),
        snippets=(
            (
                "python",
                "# tests/test_mixed.py",
                "import pytest\n\n"
                "@pytest.mark.reachy_hardware\n"
                "def test_physical():\n    assert True\n\n"
                "class TestHiddenSoftwareRegression:\n"
                "    def test_ordinary(self):\n        assert False",
            ),
        ),
    ).replace(
        "git diff --cached --check",
        "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\n"
        "Run: `TUNTUN_ALLOW_REACHY_HARDWARE=1 python -m pytest "
        "-m reachy_hardware tests/test_mixed.py -q`",
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any("pytest task-boundary probe failed" in error for error in errors), errors


def test_external_only_fixture_is_discovered_without_local_instantiation() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(
            ("Create", "tests/conftest.py"),
            ("Test", "tests/hardware/test_hardware.py"),
        ),
        snippets=(
            (
                "python",
                "# tests/conftest.py",
                "import pytest\n\n"
                "@pytest.fixture\n"
                "def physical_device():\n"
                "    pytest.fail('external fixture must not run locally')",
            ),
            (
                "python",
                "# tests/hardware/test_hardware.py",
                "import pytest\n\n"
                "@pytest.mark.reachy_hardware\n"
                "def test_physical(physical_device):\n    assert physical_device",
            ),
        ),
    ).replace(
        "git diff --cached --check",
        "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\n"
        "Run: `TUNTUN_ALLOW_REACHY_HARDWARE=1 /venvs/apps_venv/bin/python3 -m pytest "
        "-c tools/reachy-hardware-probe/pytest.ini -m reachy_hardware "
        "tests/hardware/test_hardware.py -q`",
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert not any("fixture-producer discovery probe" in error for error in errors), errors


def test_wake_probe_rejects_synthetic_inference_accounting() -> None:
    files = _production_wake_files()
    benchmark = files["tests/hardware/bench_wakeword.py"].replace(
        b"inference_count += adapter.inference_count - before",
        b"inference_count += 1",
        1,
    )
    files["tests/hardware/bench_wakeword.py"] = benchmark

    errors = validator.validate_wake_benchmark_bytes(benchmark, materialized_files=files)

    assert any("Adapter.infer" in error for error in errors), errors


def test_wake_probe_rejects_unbound_model_and_runtime_hashes() -> None:
    files = _production_wake_files()
    benchmark = files["tests/hardware/bench_wakeword.py"].replace(
        b"if adapter.model_sha256 != MODEL_SHA or adapter.runtime_sha256 != RUNTIME_SHA:\n"
        b'        raise RuntimeError("artifact/runtime mismatch")',
        b'if False:\n        raise RuntimeError("artifact/runtime mismatch")',
        1,
    )
    files["tests/hardware/bench_wakeword.py"] = benchmark

    errors = validator.validate_wake_benchmark_bytes(benchmark, materialized_files=files)

    assert any("hash binding" in error for error in errors), errors


def _locked_generator_plan(
    source: str,
    *,
    dependencies: str = "[]",
    lock_packages: str = (
        '[[package]]\nname="generator-fixture"\nversion="0.0.0"\nsource={ virtual="." }\n'
    ),
) -> str:
    return _task(
        1,
        depends="Foundation contracts",
        files=(
            ("Create", "evals/pyproject.toml"),
            ("Create", "evals/uv.lock"),
            ("Create", "tools/generate.py"),
            ("Create", "generated/schema.json"),
        ),
        snippets=(
            (
                "toml",
                "# evals/pyproject.toml",
                "[project]\nname='generator-fixture'\nversion='0.0.0'\n"
                f"requires-python='==3.12.*'\ndependencies={dependencies}",
            ),
            (
                "toml",
                "# evals/uv.lock",
                "version=1\nrevision=3\nrequires-python='==3.12.*'\n" + lock_packages,
            ),
            ("python", "# tools/generate.py", source),
        ),
    ).replace(
        "**Files:**",
        "**Files:**\n- Generate `schema-v1`: `uv run --project evals --locked python "
        "tools/generate.py` -> `generated/schema.json`",
    )


def _locked_wheel(
    distribution: str,
    version: str,
    module: str,
    module_source: str,
    *,
    console_scripts: dict[str, str] | None = None,
    data_files: dict[str, str] | None = None,
    extra_modules: dict[str, str] | None = None,
    requires_dist: tuple[str, ...] = (),
) -> tuple[str, bytes, str]:
    canonical_distribution = distribution.replace("-", "_")
    filename = f"{canonical_distribution}-{version}-py3-none-any.whl"
    dist_info = f"{canonical_distribution}-{version}.dist-info"
    members: dict[str, bytes] = {
        f"{module}.py": module_source.encode(),
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.1\nName: {distribution}\nVersion: {version}\n"
            + "".join(f"Requires-Dist: {requirement}\n" for requirement in requires_dist)
        ).encode(),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: tuntun-test\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n"
        ),
    }
    for extra_module, extra_source in (extra_modules or {}).items():
        members[f"{extra_module}.py"] = extra_source.encode()
    if console_scripts:
        members[f"{dist_info}/entry_points.txt"] = (
            "[console_scripts]\n"
            + "".join(f"{name}={target}\n" for name, target in console_scripts.items())
        ).encode()
    for path, data_content in (data_files or {}).items():
        members[f"{canonical_distribution}-{version}.data/{path}"] = data_content.encode()
    record_rows = []
    for path, member_content in sorted(members.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(member_content).digest()).rstrip(b"=")
        record_rows.append(f"{path},sha256={digest.decode()},{len(member_content)}\n")
    record_path = f"{dist_info}/RECORD"
    members[record_path] = ("".join(record_rows) + f"{record_path},,\n").encode()
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for path, member_content in sorted(members.items()):
            archive.writestr(path, member_content)
    wheel = stream.getvalue()
    return filename, wheel, hashlib.sha256(wheel).hexdigest()


def _minimal_locked_wheel() -> tuple[str, bytes, str]:
    return _locked_wheel(
        "offline-fixture",
        "1.0.0",
        "offline_fixture",
        "VERSION = '1.0.0'\n",
    )


def _write_locked_eval_fixture(
    root: Path,
    *,
    dependency: str,
    lock_package: str,
    wheel_filename: str,
    wheel: bytes,
) -> None:
    materializer.write_materialized_tree(
        root,
        {
            "evals/pyproject.toml": (
                "[project]\nname='generator-fixture'\nversion='0.0.0'\n"
                f"requires-python='==3.12.*'\ndependencies=[{dependency!r}]\n"
            ).encode(),
            "evals/uv.lock": (
                "version=1\nrevision=3\nrequires-python='==3.12.*'\n"
                "[[package]]\nname='generator-fixture'\nversion='0.0.0'\n"
                "source={virtual='.'}\ndependencies=[{name='pytest'}]\n"
                "[package.metadata]\nrequires-dist=[{name='pytest',specifier='==0.0.0'}]\n"
                + lock_package
            ).encode(),
            f".tuntun/locked-wheels/{wheel_filename}": wheel,
        },
    )


def test_eval_pytest_uses_verified_private_console_entry_point(tmp_path: Path) -> None:
    filename, wheel, wheel_hash = _locked_wheel(
        "pytest",
        "0.0.0",
        "locked_pytest",
        "def main():\n"
        "    from locked_payload import VALUE\n"
        "    print(f'locked-pytest {VALUE}')\n"
        "    return 0\n",
        console_scripts={"pytest": "locked_pytest:main"},
        data_files={"purelib/locked_payload.py": "VALUE = '0.0.0'\n"},
    )
    url = f"https://files.pythonhosted.org/packages/tuntun/{filename}"
    _write_locked_eval_fixture(
        tmp_path,
        dependency="pytest==0.0.0",
        lock_package=(
            "[[package]]\nname='pytest'\nversion='0.0.0'\n"
            "source={registry='https://pypi.org/simple'}\n"
            f"wheels=[{{url='{url}',hash='sha256:{wheel_hash}',size={len(wheel)}}}]\n"
        ),
        wheel_filename=filename,
        wheel=wheel,
    )

    result = materializer.run_isolated_process(
        ("uv", "run", "--project", "evals", "--locked", "pytest", "--version"),
        root=tmp_path,
    )

    assert result.returncode == 0, result.diagnostic
    assert result.diagnostic.strip() == b"locked-pytest 0.0.0"


def test_eval_pytest_cannot_be_shadowed_by_materialized_root_module(tmp_path: Path) -> None:
    filename, wheel, wheel_hash = _locked_wheel(
        "pytest",
        "0.0.0",
        "pytest",
        "def main():\n    print('VERIFIED_PRIVATE_PYTEST')\n    return 0\n",
        console_scripts={"pytest": "pytest:main"},
    )
    url = f"https://files.pythonhosted.org/packages/tuntun/{filename}"
    _write_locked_eval_fixture(
        tmp_path,
        dependency="pytest==0.0.0",
        lock_package=(
            "[[package]]\nname='pytest'\nversion='0.0.0'\n"
            "source={registry='https://pypi.org/simple'}\n"
            f"wheels=[{{url='{url}',hash='sha256:{wheel_hash}',size={len(wheel)}}}]\n"
        ),
        wheel_filename=filename,
        wheel=wheel,
    )
    (tmp_path / "pytest.py").write_text(
        "def main():\n    print('MATERIALIZED_ROOT_PYTEST')\n    return 0\n"
    )

    result = materializer.run_isolated_process(
        ("uv", "run", "--project", "evals", "--locked", "pytest", "--version"),
        root=tmp_path,
    )

    assert result.returncode == 0, result.diagnostic
    assert result.diagnostic.strip() == b"VERIFIED_PRIVATE_PYTEST"


def test_eval_generator_adjacent_stdlib_shadow_cannot_run_before_policy(
    tmp_path: Path,
) -> None:
    leak = tmp_path / "startup-shadow-leak"
    materializer.write_materialized_tree(
        tmp_path,
        {
            "evals/pyproject.toml": (
                b"[project]\nname='generator-fixture'\nversion='0.0.0'\n"
                b"requires-python='==3.12.*'\ndependencies=[]\n"
            ),
            "evals/uv.lock": (
                b"version=1\nrevision=3\nrequires-python='==3.12.*'\n"
                b"[[package]]\nname='generator-fixture'\nversion='0.0.0'\n"
                b"source={virtual='.'}\n"
            ),
            "subprocess.py": (
                b"from pathlib import Path\n"
                b"Path('startup-shadow-leak').write_bytes(Path('/etc/hosts').read_bytes())\n"
                b"TUNTUN_SHADOW = True\n"
            ),
            "probe.py": (
                b"import subprocess\nassert not getattr(subprocess, 'TUNTUN_SHADOW', False)\n"
            ),
        },
    )

    result = materializer.run_isolated_process(
        ("uv", "run", "--project", "evals", "--locked", "python", "probe.py"),
        root=tmp_path,
    )

    assert result.returncode == 0, result.diagnostic
    assert not leak.exists()


def test_eval_pytest_never_falls_back_to_ambient_console_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    real_interpreter = Path(sys.executable).resolve()
    ambient_bin = tmp_path / "ambient-bin"
    ambient_bin.mkdir()
    ambient_python = ambient_bin / "python"
    ambient_python.symlink_to(real_interpreter)
    ambient_pytest = ambient_bin / "pytest"
    ambient_pytest.write_text("#!/bin/sh\nprintf 'MALICIOUS_AMBIENT_PYTEST\\n'\n")
    ambient_pytest.chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(ambient_python))
    filename, wheel, wheel_hash = _locked_wheel(
        "pytest",
        "0.0.0",
        "locked_pytest",
        "VERSION = '0.0.0'\n",
    )
    url = f"https://files.pythonhosted.org/packages/tuntun/{filename}"
    _write_locked_eval_fixture(
        root,
        dependency="pytest==0.0.0",
        lock_package=(
            "[[package]]\nname='pytest'\nversion='0.0.0'\n"
            "source={registry='https://pypi.org/simple'}\n"
            f"wheels=[{{url='{url}',hash='sha256:{wheel_hash}',size={len(wheel)}}}]\n"
        ),
        wheel_filename=filename,
        wheel=wheel,
    )

    result = materializer.run_isolated_process(
        ("uv", "run", "--project", "evals", "--locked", "pytest", "--version"),
        root=root,
    )

    assert result.returncode != 0
    assert b"MALICIOUS_AMBIENT_PYTEST" not in result.diagnostic


def test_eval_runtime_does_not_resolve_unlocked_system_commands(tmp_path: Path) -> None:
    materializer.write_materialized_tree(
        tmp_path,
        {
            "evals/pyproject.toml": (
                b"[project]\nname='generator-fixture'\nversion='0.0.0'\n"
                b"requires-python='==3.12.*'\ndependencies=[]\n"
            ),
            "evals/uv.lock": (
                b"version=1\nrevision=3\nrequires-python='==3.12.*'\n"
                b"[[package]]\nname='generator-fixture'\nversion='0.0.0'\n"
                b"source={virtual='.'}\n"
            ),
        },
    )

    result = materializer.run_isolated_process(
        (
            "uv",
            "run",
            "--project",
            "evals",
            "--locked",
            "sh",
            "-c",
            "printf unlocked-system-command",
        ),
        root=tmp_path,
    )

    assert result.returncode != 0
    assert b"unlocked-system-command" not in result.diagnostic


@pytest.mark.parametrize(
    "uv_options",
    (
        ("--env-file", "host.env"),
        ("--isolated",),
        ("--with", "pytest"),
        ("--python", sys.executable),
        ("--project", "other"),
        ("--no-project",),
        ("--active",),
    ),
)
def test_eval_runtime_rejects_options_that_can_override_audited_environment(
    tmp_path: Path, uv_options: tuple[str, ...]
) -> None:
    materializer.write_materialized_tree(
        tmp_path,
        {
            "evals/pyproject.toml": (
                b"[project]\nname='generator-fixture'\nversion='0.0.0'\n"
                b"requires-python='==3.12.*'\ndependencies=[]\n"
            ),
            "evals/uv.lock": (
                b"version=1\nrevision=3\nrequires-python='==3.12.*'\n"
                b"[[package]]\nname='generator-fixture'\nversion='0.0.0'\n"
                b"source={virtual='.'}\n"
            ),
            "host.env": b"PATH=/usr/bin:/bin\n",
        },
    )

    with pytest.raises(MaterializationError, match="uv|grammar|option|runtime"):
        materializer.run_isolated_process(
            (
                "uv",
                "run",
                "--project",
                "evals",
                "--locked",
                *uv_options,
                "python",
                "-c",
                "print('must-not-run')",
            ),
            root=tmp_path,
        )


@pytest.mark.parametrize(
    "uv_options",
    (
        "--env-file host.env",
        "--isolated",
        "--with pytest",
        f"--python {sys.executable}",
        "--project other",
        "--no-project",
        "--active",
    ),
)
def test_plan_validation_rejects_eval_uv_runtime_overrides(uv_options: str) -> None:
    command = f"uv run --project evals --locked {uv_options} pytest tests/test_owned.py -q"

    assert not validator._green_command_is_fail_closed(command)


@pytest.mark.parametrize(
    "command",
    (
        "./pytest tests/test_owned.py -q",
        "/tmp/pytest tests/test_owned.py -q",
        "uv run ./pytest tests/test_owned.py -q",
        "uv run --project evals --locked ./pytest tests/test_owned.py -q",
        "./python -m pytest tests/test_owned.py -q",
        "python3 -m pytest tests/test_owned.py -q",
    ),
)
def test_plan_validation_rejects_noncanonical_pytest_executables(command: str) -> None:
    assert not validator._green_command_is_fail_closed(command)


@pytest.mark.parametrize("uv_token", ("/tmp/uv", "./uv", "tools/uv"))
def test_plan_validation_rejects_noncanonical_uv_wrapper_tokens(uv_token: str) -> None:
    command = f"{uv_token} run --project evals --locked pytest tests/test_owned.py -q"

    assert not validator._green_command_is_fail_closed(command)


@pytest.mark.parametrize("uv_token", ("/tmp/uv", "./uv", "tools/uv"))
def test_isolated_runner_rejects_noncanonical_uv_wrapper_tokens(
    tmp_path: Path, uv_token: str
) -> None:
    with pytest.raises(MaterializationError, match="original command token.*uv"):
        materializer.run_isolated_process(
            (uv_token, "run", "--project", "evals", "--locked", "python", "-V"),
            root=tmp_path,
        )


def test_isolated_runner_rejects_uv_symlink_by_original_token(tmp_path: Path) -> None:
    alias = tmp_path / "uv"
    alias.symlink_to(sys.executable)

    with pytest.raises(MaterializationError, match="original command token.*uv"):
        materializer.run_isolated_process(
            (str(alias), "run", "--project", "evals", "--locked", "python", "-V"),
            root=tmp_path,
        )


@pytest.mark.parametrize(
    "command",
    (
        "/venvs/apps_venv/bin/python3 -m pytest -m reachy_hardware tests/hardware/test_live.py -q",
        "TUNTUN_ALLOW_REACHY_HARDWARE=1 /venvs/apps_venv/bin/python3 -m pytest "
        "tests/hardware/test_live.py -q",
        "TUNTUN_ALLOW_REACHY_HARDWARE=1 /venvs/apps_venv/bin/python3 -m pytest "
        "-m reachy_hardware tests/test_owned.py -q",
    ),
)
def test_robot_pytest_requires_authorized_hardware_lane(command: str) -> None:
    assert not validator._green_command_is_fail_closed(command)


def test_robot_pytest_cannot_certify_an_ordinary_owned_test() -> None:
    command = (
        "TUNTUN_ALLOW_REACHY_HARDWARE=1 /venvs/apps_venv/bin/python3 -m pytest "
        "-m reachy_hardware tests/test_owned.py -q"
    )
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_owned.py"),),
        snippets=(("python", "# tests/test_owned.py", "def test_owned():\n    assert True"),),
    ).replace(
        "git diff --cached --check",
        f"git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\nRun: `{command}`",
    )

    errors = validate_plan_document(
        parse_plan_text(plan), foundation_files={}, execute_behavioral_probes=False
    )

    assert any("green command is not fail-closed" in error for error in errors), errors
    assert any("does not execute owned test tests/test_owned.py" in error for error in errors), (
        errors
    )


def test_locked_generator_uses_available_interpreter_without_uv_cache() -> None:
    plan = _locked_generator_plan(
        "import os,sys\n"
        "from pathlib import Path\n"
        "runtime=Path(os.environ['UV_PROJECT_ENVIRONMENT']).resolve()\n"
        "assert os.environ['UV_OFFLINE'] == '1'\n"
        "assert Path(sys.prefix).resolve() == runtime\n"
        "assert Path(os.environ['UV_CACHE_DIR']).is_relative_to(runtime.parent)\n"
        "Path('generated').mkdir(exist_ok=True)\n"
        "Path('generated/schema.json').write_text('{}\\n')"
    )

    files = materialize_document(parse_plan_text(plan), foundation_files={})

    assert files["generated/schema.json"] == b"{}\n"


def test_locked_generator_rejects_import_outside_declared_project() -> None:
    plan = _locked_generator_plan(
        "import json,pydantic\n"
        "from pathlib import Path\n"
        "Path('generated').mkdir(exist_ok=True)\n"
        "Path('generated/schema.json').write_text(json.dumps(pydantic.__version__))"
    )

    with pytest.raises(MaterializationError, match="locked|declared|pydantic"):
        materialize_document(parse_plan_text(plan), foundation_files={})


def test_locked_generator_rejects_distribution_version_drift() -> None:
    lock_packages = """
[[package]]
name = "generator-fixture"
version = "0.0.0"
source = { virtual = "." }
dependencies = [{ name = "pyyaml" }]

[package.metadata]
requires-dist = [{ name = "pyyaml", specifier = "==0.0.1" }]

[[package]]
name = "pyyaml"
version = "0.0.1"
source = { registry = "https://pypi.org/simple" }
[[package.wheels]]
url = "https://example.invalid/pyyaml-0.0.1-py3-none-any.whl"
hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
size = 1
"""
    plan = _locked_generator_plan(
        "import json,yaml\n"
        "from pathlib import Path\n"
        "Path('generated').mkdir(exist_ok=True)\n"
        "Path('generated/schema.json').write_text(json.dumps(yaml.__version__))",
        dependencies="['PyYAML==0.0.1']",
        lock_packages=lock_packages,
    )

    with pytest.raises(MaterializationError, match="locked|version|pyyaml"):
        materialize_document(parse_plan_text(plan), foundation_files={})


def test_locked_generator_rejects_untrusted_locked_artifact_hash() -> None:
    arm_url = (
        "https://files.pythonhosted.org/packages/89/a0/"
        "6cf41a19a1f2f3feab0e9c0b74134aa2ce6849093d5517a0c550fe37a648/"
        "pyyaml-6.0.3-cp312-cp312-macosx_11_0_arm64.whl"
    )
    lock_packages = f"""
[[package]]
name = "generator-fixture"
version = "0.0.0"
source = {{ virtual = "." }}
dependencies = [{{ name = "pyyaml" }}]

[package.metadata]
requires-dist = [{{ name = "pyyaml", specifier = "==6.0.3" }}]

[[package]]
name = "pyyaml"
version = "6.0.3"
source = {{ registry = "https://pypi.org/simple" }}
[[package.wheels]]
url = "{arm_url}"
hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
size = 173973
"""
    plan = _locked_generator_plan(
        "import json,yaml\n"
        "from pathlib import Path\n"
        "Path('generated').mkdir(exist_ok=True)\n"
        "Path('generated/schema.json').write_text(json.dumps(yaml.__version__))",
        dependencies="['PyYAML==6.0.3']",
        lock_packages=lock_packages,
    )

    with pytest.raises(MaterializationError, match="locked|hash|pyyaml"):
        materialize_document(parse_plan_text(plan), foundation_files={})


def test_locked_generator_allows_exact_declared_distribution() -> None:
    filename, wheel, wheel_hash = _minimal_locked_wheel()
    url = f"https://files.pythonhosted.org/packages/tuntun/{filename}"
    lock_packages = f"""
[[package]]
name = "generator-fixture"
version = "0.0.0"
source = {{ virtual = "." }}
dependencies = [{{ name = "offline-fixture" }}]

[package.metadata]
requires-dist = [{{ name = "offline-fixture", specifier = "==1.0.0" }}]

[[package]]
name = "offline-fixture"
version = "1.0.0"
source = {{ registry = "https://pypi.org/simple" }}
[[package.wheels]]
url = "{url}"
hash = "sha256:{wheel_hash}"
size = {len(wheel)}
"""
    plan = _locked_generator_plan(
        "import json,offline_fixture\n"
        "from pathlib import Path\n"
        "Path('generated').mkdir(exist_ok=True)\n"
        "Path('generated/schema.json').write_text(json.dumps(offline_fixture.VERSION))",
        dependencies="['offline-fixture==1.0.0']",
        lock_packages=lock_packages,
    )

    files = materialize_document(
        parse_plan_text(plan),
        foundation_files={f".tuntun/locked-wheels/{filename}": wheel},
    )

    assert files["generated/schema.json"] == b'"1.0.0"'


def test_locked_generator_rejects_unreachable_extra_lock_package() -> None:
    lock_packages = """
[[package]]
name = "generator-fixture"
version = "0.0.0"
source = { virtual = "." }

[[package]]
name = "pyyaml"
version = "6.0.3"
source = { registry = "https://pypi.org/simple" }
[[package.wheels]]
url = "https://files.pythonhosted.org/pyyaml-6.0.3-py3-none-any.whl"
hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
size = 1
"""
    plan = _locked_generator_plan(
        "import json,yaml\n"
        "from pathlib import Path\n"
        "Path('generated').mkdir(exist_ok=True)\n"
        "Path('generated/schema.json').write_text(json.dumps(yaml.__version__))",
        lock_packages=lock_packages,
    )

    with pytest.raises(MaterializationError, match="declared|closure|pyyaml"):
        materialize_document(parse_plan_text(plan), foundation_files={})


def test_locked_generator_rejects_project_and_lock_version_disagreement() -> None:
    lock_packages = """
[[package]]
name = "generator-fixture"
version = "0.0.0"
source = { virtual = "." }
dependencies = [{ name = "offline-only" }]

[package.metadata]
requires-dist = [{ name = "offline-only", specifier = "==1.0.0" }]

[[package]]
name = "offline-only"
version = "2.0.0"
source = { directory = "../packages/offline_only" }
"""
    plan = _locked_generator_plan(
        "from pathlib import Path\n"
        "Path('generated').mkdir(exist_ok=True)\n"
        "Path('generated/schema.json').write_text('{}')",
        dependencies="['offline-only==1.0.0']",
        lock_packages=lock_packages,
    )

    with pytest.raises(MaterializationError, match="version differs|local directory source"):
        materialize_document(parse_plan_text(plan), foundation_files={})


def test_locked_import_policy_remains_active_when_host_policy_is_disabled(
    tmp_path: Path,
) -> None:
    materializer.write_materialized_tree(
        tmp_path,
        {
            "evals/pyproject.toml": (
                b"[project]\nname='generator-fixture'\nversion='0.0.0'\n"
                b"requires-python='==3.12.*'\ndependencies=[]\n"
            ),
            "evals/uv.lock": (
                b"version=1\nrevision=3\nrequires-python='==3.12.*'\n"
                b"[[package]]\nname='generator-fixture'\nversion='0.0.0'\n"
                b"source={ virtual='.' }\n"
            ),
            "probe.py": b"import yaml\n",
        },
    )

    result = materializer.run_isolated_process(
        ("uv", "run", "--project", "evals", "--locked", "python", "probe.py"),
        root=tmp_path,
        restrict_host_apis=False,
    )

    assert result.returncode != 0
    assert b"undeclared distribution import" in result.diagnostic


def test_locked_generator_rejects_python_requirement_drift() -> None:
    plan = _locked_generator_plan(
        "from pathlib import Path\n"
        "Path('generated').mkdir(exist_ok=True)\n"
        "Path('generated/schema.json').write_text('{}')"
    ).replace("requires-python='==3.12.*'", "requires-python='==3.11.*'", 1)

    with pytest.raises(MaterializationError, match="Python requirement|interpreter"):
        materialize_document(parse_plan_text(plan), foundation_files={})


def test_generator_cannot_embed_host_identity_even_deterministically() -> None:
    plan = _locked_generator_plan(
        "import json,platform\n"
        "from pathlib import Path\n"
        "Path('generated').mkdir(exist_ok=True)\n"
        "Path('generated/schema.json').write_text(json.dumps({'node': platform.node()}))"
    )

    with pytest.raises(MaterializationError, match="host API|nondeterministic"):
        materialize_document(parse_plan_text(plan), foundation_files={})


def test_isolated_platform_identity_matches_lock_target_without_host_values(
    tmp_path: Path,
) -> None:
    target = default_environment()
    script = tmp_path / "platform_probe.py"
    script.write_text(
        "import os,platform,socket,uuid\n"
        f"assert platform.system() == {target['platform_system']!r}\n"
        f"assert platform.machine() == {target['platform_machine']!r}\n"
        "identity=os.uname()\n"
        "assert isinstance(identity, os.uname_result)\n"
        f"assert identity.sysname == {target['platform_system']!r}\n"
        "assert identity.nodename == 'tuntun-isolated'\n"
        "assert identity.release == '0'\n"
        "assert identity.version == 'deterministic'\n"
        f"assert identity.machine == {target['platform_machine']!r}\n"
        "for operation in (platform.node, socket.gethostname, uuid.getnode):\n"
        "    try:\n"
        "        operation()\n"
        "    except RuntimeError as error:\n"
        "        assert 'host API' in str(error)\n"
        "    else:\n"
        "        raise AssertionError('host identity API was not denied')\n"
    )

    result = materializer.run_isolated_process(("python", script.name), root=tmp_path)

    assert result.returncode == 0, result.diagnostic


def test_exact_root_pytest_plugins_collect_under_deterministic_target_identity(
    tmp_path: Path,
) -> None:
    test_path = tmp_path / "test_collect.py"
    test_path.write_text("def test_collect():\n    assert True\n")

    result = materializer.run_isolated_process(
        ("python", "-m", "pytest", "--collect-only", "-q", test_path.name),
        root=tmp_path,
    )

    assert result.returncode == 0, result.diagnostic
    assert b"test_collect.py::test_collect" in result.diagnostic


def test_child_platform_identity_cannot_select_an_incompatible_locked_wheel(
    tmp_path: Path,
) -> None:
    filename, wheel, wheel_hash = _locked_wheel(
        "offline-fixture",
        "1.0.0",
        "offline_fixture",
        "VERSION = '1.0.0'\n",
    )
    incompatible_filename = filename.replace("py3-none-any", "cp312-cp312-win_amd64")
    artifact_root = tmp_path / ".tuntun/locked-wheels"
    artifact_root.mkdir(parents=True)
    (artifact_root / incompatible_filename).write_bytes(wheel)
    policy = materializer._LockedEvalPolicy(
        project_name="fixture",
        reachable_versions={
            "fixture": frozenset({"0.0.0"}),
            "offline-fixture": frozenset({"1.0.0"}),
        },
        forbidden_imports=(),
        registry_artifacts={
            "offline-fixture": (
                (
                    "https://files.pythonhosted.org/packages/tuntun/" + incompatible_filename,
                    wheel_hash,
                ),
            )
        },
    )

    with pytest.raises(MaterializationError, match="compatible|missing|wheelhouse"):
        materializer._prepare_verified_wheelhouse(tmp_path, tmp_path / "wheelhouse", policy)


@pytest.mark.parametrize(
    "host_source",
    (
        "import subprocess\nvalue=subprocess.check_output(['/bin/hostname']).decode()",
        "value=Path('/Library/Preferences/SystemConfiguration/preferences.plist').read_bytes().hex()",
    ),
)
def test_generator_cannot_read_host_identity_from_command_or_file(
    host_source: str,
) -> None:
    plan = _locked_generator_plan(
        "import json\nfrom pathlib import Path\n"
        f"{host_source}\n"
        "Path('generated').mkdir(exist_ok=True)\n"
        "Path('generated/schema.json').write_text(json.dumps({'host': value}))"
    )

    with pytest.raises(MaterializationError, match="host API|host identity|nondeterministic"):
        materialize_document(parse_plan_text(plan), foundation_files={})


def test_bilingual_runtime_probe_uses_the_generator_determinism_policy() -> None:
    files = _bilingual_runtime_files(
        _bilingual_report_model_source().replace(
            b"from datetime import datetime\n",
            b"from datetime import datetime\nimport platform\nplatform.node()\n",
            1,
        )
    )

    errors = validator.validate_bilingual_report_model_files(files)

    assert any("host API" in error or "nondeterministic" in error for error in errors), errors


def test_bilingual_runtime_rejects_naive_expiry() -> None:
    disconnected = _bilingual_runtime_files(
        _bilingual_report_model_source().replace(
            b"            or self.expires_at.tzinfo is None\n", b"", 1
        )
    )

    assert validator.validate_bilingual_report_model_files(disconnected)


def test_generator_rejects_grandchild_creation_before_parent_exit(
    tmp_path: Path,
) -> None:
    script = tmp_path / "parent.py"
    child_pid_path = tmp_path / "child.pid"
    script.write_text(
        "import subprocess,sys\n"
        "from pathlib import Path\n"
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])\n"
        "Path(sys.argv[1]).write_text(str(child.pid))\n"
    )
    result = materializer._run_generator_process(
        (sys.executable, str(script), str(child_pid_path)),
        root=tmp_path,
        environment=materializer._generator_environment(tmp_path),
        writable_paths=(child_pid_path,),
    )

    assert result.returncode != 0
    assert b"subprocess creation forbidden" in result.diagnostic
    assert not child_pid_path.exists()


@pytest.mark.parametrize(
    "detachment",
    (
        "start_new_session=True",
        "preexec_fn=os.setsid",
        "preexec_fn=lambda: os.setpgid(0,0)",
    ),
)
def test_isolated_runner_rejects_python_descendant_detachment(
    tmp_path: Path,
    detachment: str,
) -> None:
    script = tmp_path / "detached_parent.py"
    child_script = tmp_path / "detached_child.py"
    child_pid_path = tmp_path / "detached.pid"
    child_state_path = tmp_path / "detached.state"
    child_script.write_text(
        "import os,sys,time\n"
        "from pathlib import Path\n"
        "Path(sys.argv[1]).write_text(f'{os.getpid()}:{os.getpgid(0)}:{os.getsid(0)}')\n"
        "time.sleep(30)\n"
    )
    script.write_text(
        "import os,subprocess,sys,time\n"
        "from pathlib import Path\n"
        f"child=subprocess.Popen([sys.executable,{str(child_script)!r},sys.argv[2]],{detachment})\n"
        "Path(sys.argv[1]).write_text(str(child.pid))\n"
        "time.sleep(30)\n"
    )
    result = materializer.run_isolated_process(
        (
            sys.executable,
            str(script),
            str(child_pid_path),
            str(child_state_path),
        ),
        root=tmp_path,
        timeout_seconds=2,
        writable_paths=(child_pid_path, child_state_path),
    )

    assert result.returncode != 0
    assert b"subprocess creation forbidden" in result.diagnostic
    assert not child_pid_path.exists()
    assert not child_state_path.exists()


def test_isolated_runner_never_trusts_child_authored_process_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "forged_registry.py"
    script.write_text(
        "import os,sys,time\n"
        "from pathlib import Path\n"
        "evidence=Path(os.environ['TMPDIR']).parent/'evidence'/'processes'\n"
        "evidence.write_text(sys.argv[1])\n"
        "time.sleep(30)\n"
    )
    signalled_pids: list[int] = []
    real_kill = os.kill

    def checked_kill(pid: int, selected_signal: int) -> None:
        signalled_pids.append(pid)
        real_kill(pid, selected_signal)

    monkeypatch.setattr(os, "kill", checked_kill)
    with pytest.raises(subprocess.TimeoutExpired):
        materializer.run_isolated_process(
            (sys.executable, str(script), str(os.getpid())),
            root=tmp_path,
            timeout_seconds=0.25,
        )

    assert os.getpid() not in signalled_pids


def test_isolated_runner_never_signals_a_reaped_process_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "complete.py"
    script.write_text("pass\n")
    real_killpg = os.killpg
    observed_live_state: list[bool] = []

    def checked_killpg(process_group: int, selected_signal: int) -> None:
        try:
            os.kill(process_group, 0)
        except ProcessLookupError:
            observed_live_state.append(False)
        else:
            observed_live_state.append(True)
        real_killpg(process_group, selected_signal)

    monkeypatch.setattr(os, "killpg", checked_killpg)

    result = materializer.run_isolated_process((sys.executable, str(script)), root=tmp_path)

    assert result.returncode == 0
    assert all(observed_live_state), observed_live_state


def test_isolated_runner_does_not_signal_reaped_group_when_lock_audit_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    filename, wheel, wheel_hash = _minimal_locked_wheel()
    url = f"https://files.pythonhosted.org/packages/tuntun/{filename}"
    lock_packages = f"""
[[package]]
name = "generator-fixture"
version = "0.0.0"
source = {{ virtual = "." }}
dependencies = [{{ name = "offline-fixture" }}]

[package.metadata]
requires-dist = [{{ name = "offline-fixture", specifier = "==1.0.0" }}]

[[package]]
name = "offline-fixture"
version = "1.0.0"
source = {{ registry = "https://pypi.org/simple" }}
[[package.wheels]]
url = "{url}"
hash = "sha256:{wheel_hash}"
size = {len(wheel)}
"""
    plan = _locked_generator_plan(
        "from pathlib import Path\n"
        "Path('generated').mkdir(exist_ok=True)\n"
        "Path('generated/schema.json').write_text('{}')",
        dependencies="['offline-fixture==1.0.0']",
        lock_packages=lock_packages,
    )
    signalled_groups: list[int] = []
    audit_calls = 0

    def fail_audit(
        runtime: Path,
        policy: materializer._LockedEvalPolicy,
        *,
        verify_files: bool = False,
    ) -> None:
        nonlocal audit_calls
        del runtime, policy, verify_files
        audit_calls += 1
        if audit_calls == 2:
            raise MaterializationError("controlled post-reap audit failure")

    def record_killpg(process_group: int, selected_signal: int) -> None:
        del selected_signal
        signalled_groups.append(process_group)

    monkeypatch.setattr(materializer, "_audit_locked_runtime", fail_audit)
    monkeypatch.setattr(os, "killpg", record_killpg)

    with pytest.raises(MaterializationError, match="post-reap audit failure"):
        materialize_document(
            parse_plan_text(plan),
            foundation_files={f".tuntun/locked-wheels/{filename}": wheel},
        )

    assert signalled_groups == []


def test_isolated_runner_does_not_leave_a_nominal_child_running(tmp_path: Path) -> None:
    script = tmp_path / "successful_parent.py"
    child_pid_path = tmp_path / "nominal-child.pid"
    script.write_text(
        "import subprocess,sys\n"
        "from pathlib import Path\n"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],"
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
        "Path(sys.argv[1]).write_text(str(child.pid))\n"
    )
    child_pid = -1
    try:
        result = materializer.run_isolated_process(
            (sys.executable, str(script), str(child_pid_path)),
            root=tmp_path,
            writable_paths=(child_pid_path,),
        )
        assert result.returncode != 0
        assert b"subprocess" in result.diagnostic or b"forbidden" in result.diagnostic
        assert not child_pid_path.exists()
    finally:
        if child_pid_path.exists():
            child_pid = int(child_pid_path.read_text())
        if child_pid > 0:
            with contextlib.suppress(ProcessLookupError):
                os.kill(child_pid, signal.SIGKILL)


def test_isolated_runner_rejects_symlink_escape_from_readable_root(tmp_path: Path) -> None:
    link = tmp_path / "host-link"
    link.symlink_to("/etc/hosts")
    script = tmp_path / "symlink_probe.py"
    script.write_text("from pathlib import Path\nPath('host-link').read_text()\n")

    result = materializer.run_isolated_process((sys.executable, str(script)), root=tmp_path)

    assert result.returncode != 0
    assert b"outside isolated readable roots" in result.diagnostic


@pytest.mark.parametrize(
    "operation",
    (
        "import _io\n_io.open('/etc/hosts', 'rb').read(1)",
        "import _io\n_io.FileIO('/etc/hosts', 'r').read(1)",
    ),
)
def test_isolated_runner_guards_low_level_io_reads(tmp_path: Path, operation: str) -> None:
    script = tmp_path / "low_level_read.py"
    script.write_text(operation + "\n")

    result = materializer.run_isolated_process((sys.executable, script.name), root=tmp_path)

    assert result.returncode != 0
    assert b"outside isolated readable roots" in result.diagnostic


@pytest.mark.parametrize(
    "operation",
    (
        "import _io,sys\n_io.open(sys.argv[1], 'wb').write(b'escaped')",
        "import _io,sys\n_io.FileIO(sys.argv[1], 'w').write(b'escaped')",
    ),
)
def test_isolated_runner_guards_low_level_io_writes(tmp_path: Path, operation: str) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.bin"
    script = root / "low_level_write.py"
    script.write_text(operation + "\n")
    try:
        result = materializer.run_isolated_process(
            (sys.executable, script.name, str(outside)), root=root
        )

        assert result.returncode != 0
        assert b"outside isolated writable roots" in result.diagnostic
        assert not outside.exists()
    finally:
        with contextlib.suppress(FileNotFoundError):
            outside.unlink()


@pytest.mark.parametrize(
    "open_call",
    (
        "open(sys.argv[1], 'rb', opener=opener)",
        "io.open(sys.argv[1], 'rb', opener=opener)",
        "_io.open(sys.argv[1], 'rb', opener=opener)",
        "_io.FileIO(sys.argv[1], 'r', opener=opener)",
    ),
)
def test_isolated_runner_rejects_custom_openers_before_callback(
    tmp_path: Path, open_call: str
) -> None:
    source = tmp_path / "source.txt"
    source.write_text("accepted\n")
    callback_marker = tmp_path / "opener-called"
    script = tmp_path / "custom_opener.py"
    script.write_text(
        "import _io,io,os,sys\n"
        "from pathlib import Path\n"
        "def opener(path, flags):\n"
        "    Path(sys.argv[2]).write_text('called')\n"
        "    return os.open(path, flags)\n"
        f"{open_call}\n"
    )

    result = materializer.run_isolated_process(
        (sys.executable, script.name, str(source), str(callback_marker)),
        root=tmp_path,
        writable_paths=(callback_marker,),
    )

    assert result.returncode != 0
    assert b"custom opener" in result.diagnostic
    assert not callback_marker.exists()


@pytest.mark.parametrize(
    "operation",
    (
        "os.chdir(sys.argv[1])",
        "fd=os.open('.', os.O_RDONLY)\nos.fchdir(fd)",
    ),
)
def test_isolated_runner_guards_working_directory_changes(tmp_path: Path, operation: str) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    script = root / "change_directory.py"
    script.write_text(f"import os,sys\n{operation}\n")

    result = materializer.run_isolated_process(
        (sys.executable, script.name, str(outside)), root=root
    )

    assert result.returncode != 0
    assert b"host path" in result.diagnostic or b"descriptor-relative" in result.diagnostic


@pytest.mark.parametrize(
    "operation",
    (
        "os.open('source.txt', os.O_RDONLY, dir_fd=directory)",
        "os.stat('source.txt', dir_fd=directory)",
        "os.mkdir('nested', dir_fd=directory)",
        "os.rename('source.txt', 'renamed.txt', src_dir_fd=directory, dst_dir_fd=directory)",
        "os.replace('source.txt', 'renamed.txt', src_dir_fd=directory, dst_dir_fd=directory)",
    ),
)
def test_isolated_runner_rejects_descriptor_relative_paths(tmp_path: Path, operation: str) -> None:
    source = tmp_path / "source.txt"
    source.write_text("accepted\n")
    script = tmp_path / "descriptor_relative.py"
    script.write_text(f"import os\ndirectory=os.open('.', os.O_RDONLY)\n{operation}\n")
    renamed = tmp_path / "renamed.txt"
    nested = tmp_path / "nested"
    try:
        result = materializer.run_isolated_process((sys.executable, script.name), root=tmp_path)

        assert result.returncode != 0
        assert b"descriptor-relative" in result.diagnostic
        assert source.read_text() == "accepted\n"
        assert not renamed.exists()
        assert not nested.exists()
    finally:
        if renamed.exists():
            renamed.replace(source)
        if nested.exists():
            nested.rmdir()


def test_isolated_runner_replaces_inherited_regular_stdin_with_devnull(
    tmp_path: Path,
) -> None:
    secret = tmp_path / "host-secret.txt"
    secret.write_bytes(b"fd-zero-secret")
    script = tmp_path / "stdin_probe.py"
    script.write_text(
        "import os\n"
        "try:\n"
        "    leaked=os.pread(0,64,0)\n"
        "except OSError:\n"
        "    leaked=b''\n"
        "assert leaked == b''\n"
        "assert os.read(0,1) == b''\n"
    )
    saved_stdin = os.dup(0)
    try:
        with secret.open("rb") as inherited:
            os.dup2(inherited.fileno(), 0)
            result = materializer.run_isolated_process((sys.executable, script.name), root=tmp_path)
    finally:
        os.dup2(saved_stdin, 0)
        os.close(saved_stdin)

    assert result.returncode == 0, result.diagnostic


@pytest.mark.parametrize(
    "operation",
    (
        "os.fchmod(descriptor,0o600)",
        "os.fchown(descriptor,os.getuid(),os.getgid())",
        "os.utime(descriptor,ns=(1_000_000_000,1_000_000_000))",
        "sys.modules['posix'].fchmod(descriptor,0o600)",
        "os.chown(target,os.getuid(),os.getgid())",
        "os.lchown(target,os.getuid(),os.getgid())",
        "os.lchmod(target,0o600)",
        "os.chflags(target,os.stat(target).st_flags)",
        "os.lchflags(target,os.lstat(target).st_flags)",
    ),
)
def test_isolated_runner_rejects_descriptor_and_ownership_metadata_mutation(
    tmp_path: Path, operation: str
) -> None:
    required_name = operation.split("(", 1)[0].rsplit(".", 1)[-1]
    if not hasattr(os, required_name):
        pytest.skip(f"{required_name} is unavailable on this platform")
    source = tmp_path / "source.txt"
    source.write_text("accepted\n")
    source.chmod(0o644)
    marker = tmp_path / "mutation-completed"
    before = source.stat()
    script = tmp_path / "descriptor_metadata.py"
    script.write_text(
        "import os,sys\n"
        "from pathlib import Path\n"
        "target=sys.argv[1]\n"
        "descriptor=os.open(target,os.O_RDONLY)\n"
        f"{operation}\n"
        "Path(sys.argv[2]).write_text('mutated')\n"
    )

    result = materializer.run_isolated_process(
        (sys.executable, script.name, str(source), str(marker)),
        root=tmp_path,
        writable_paths=(marker,),
    )

    after = source.stat()
    assert result.returncode != 0
    assert b"descriptor" in result.diagnostic or b"read-only" in result.diagnostic
    assert not marker.exists()
    assert source.read_text() == "accepted\n"
    assert after.st_mode == before.st_mode
    assert after.st_mtime_ns == before.st_mtime_ns


@pytest.mark.parametrize(
    "operation",
    (
        "os.ftruncate(0,0)",
        "os.truncate(0,0)",
        "sys.modules['posix'].ftruncate(0,0)",
    ),
)
def test_isolated_runner_rejects_inherited_descriptor_content_mutation(
    tmp_path: Path, operation: str
) -> None:
    source = tmp_path / "source.txt"
    original = b"accepted\n"
    source.write_bytes(original)
    script = tmp_path / "descriptor_content.py"
    script.write_text(f"import os,sys\n{operation}\n")
    saved_stdin = os.dup(0)
    try:
        descriptor = os.open(source, os.O_RDWR)
        try:
            os.dup2(descriptor, 0)
            result = materializer.run_isolated_process((sys.executable, script.name), root=tmp_path)
        finally:
            os.close(descriptor)
    finally:
        os.dup2(saved_stdin, 0)
        os.close(saved_stdin)
    mutated = source.read_bytes()
    if mutated != original:
        source.write_bytes(original)

    assert result.returncode != 0
    assert b"descriptor" in result.diagnostic
    assert mutated == original


@pytest.mark.skipif(not hasattr(os, "setxattr"), reason="xattr APIs unavailable")
def test_isolated_runner_rejects_descriptor_xattr_mutation(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_text("accepted\n")
    attribute = "user.tuntun.plan-probe"
    marker = tmp_path / "xattr-completed"
    script = tmp_path / "descriptor_xattr.py"
    script.write_text(
        "import os,sys\n"
        "from pathlib import Path\n"
        "descriptor=os.open(sys.argv[1],os.O_RDONLY)\n"
        "os.setxattr(descriptor,sys.argv[3],b'hostile')\n"
        "Path(sys.argv[2]).write_text('mutated')\n"
    )
    try:
        result = materializer.run_isolated_process(
            (sys.executable, script.name, str(source), str(marker), attribute),
            root=tmp_path,
            writable_paths=(marker,),
        )

        assert result.returncode != 0
        assert b"descriptor" in result.diagnostic or b"read-only" in result.diagnostic
        assert not marker.exists()
        assert attribute not in getattr(os, "list" + "xattr")(source)
    finally:
        with contextlib.suppress(OSError):
            getattr(os, "remove" + "xattr")(source, attribute)


@pytest.mark.parametrize(
    "operation",
    (
        "os.chmod(sys.argv[1], 0o777)",
        "os.truncate(sys.argv[1], 0)",
        "os.utime(sys.argv[1], None)",
    ),
)
def test_isolated_runner_rejects_non_open_source_mutation(tmp_path: Path, operation: str) -> None:
    target = tmp_path / "source.txt"
    target.write_text("accepted\n")
    before = target.stat()
    script = tmp_path / "mutation.py"
    script.write_text(f"import os,sys\n{operation}\n")

    result = materializer.run_isolated_process(
        (sys.executable, str(script), str(target)), root=tmp_path
    )

    after = target.stat()
    assert result.returncode != 0
    assert target.read_text() == "accepted\n"
    assert after.st_mode == before.st_mode
    assert after.st_mtime_ns == before.st_mtime_ns


@pytest.mark.parametrize(
    "operation",
    (
        "sock.sendto(b'x', ('127.0.0.1', 9))",
        "sock.connect_ex(('127.0.0.1', 9))",
        "sock.sendmsg([b'x'], [], 0, ('127.0.0.1', 9))",
    ),
)
def test_isolated_runner_rejects_udp_network_bypasses(tmp_path: Path, operation: str) -> None:
    script = tmp_path / "network.py"
    script.write_text(
        f"import socket\nsock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n{operation}\n"
    )

    result = materializer.run_isolated_process((sys.executable, str(script)), root=tmp_path)

    assert result.returncode != 0
    assert b"host API forbidden" in result.diagnostic


@pytest.mark.parametrize(
    "source",
    (
        "import os\nos.stat('/etc/hosts')",
        "import os\nlist(os.scandir('/etc'))",
        "import os\nos.access('/etc/hosts', os.R_OK)",
        "import os\nos.readlink('/etc/localtime')",
    ),
)
def test_isolated_runner_blocks_host_metadata_observation(tmp_path: Path, source: str) -> None:
    script = tmp_path / "metadata.py"
    script.write_text(source + "\n")

    result = materializer.run_isolated_process((sys.executable, str(script)), root=tmp_path)

    assert result.returncode != 0
    assert b"outside isolated readable roots" in result.diagnostic


def test_isolated_runner_keeps_source_and_policy_read_only(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_text("accepted\n")
    script = tmp_path / "rewrite.py"
    script.write_text(
        "import sitecustomize,sys\n"
        "from pathlib import Path\n"
        "target=Path(sys.argv[1]) if sys.argv[2] == 'source' else Path(sitecustomize.__file__)\n"
        "target.write_text('rewritten')\n"
    )

    source_result = materializer.run_isolated_process(
        (sys.executable, str(script), str(source), "source"), root=tmp_path
    )
    policy_result = materializer.run_isolated_process(
        (sys.executable, str(script), str(source), "policy"), root=tmp_path
    )

    assert source_result.returncode != 0
    assert policy_result.returncode != 0
    assert source.read_text() == "accepted\n"


def test_isolated_runner_writable_file_does_not_authorize_siblings(tmp_path: Path) -> None:
    generated = tmp_path / "generated"
    generated.mkdir()
    script = tmp_path / "write_sibling.py"
    script.write_text(
        "from pathlib import Path\nPath('generated/sibling.json').write_text('hostile')\n"
    )

    result = materializer.run_isolated_process(
        (sys.executable, script.name),
        root=tmp_path,
        writable_paths=("generated/expected.json",),
    )

    assert result.returncode != 0
    assert b"outside isolated writable roots" in result.diagnostic
    assert not (generated / "sibling.json").exists()


def test_isolated_runner_keeps_interpreter_packages_read_only(tmp_path: Path) -> None:
    import pytest as installed_pytest

    package_probe = Path(installed_pytest.__file__).parent / ".tuntun-write-probe"
    script = tmp_path / "package_write.py"
    script.write_text(
        "import pytest\n"
        "from pathlib import Path\n"
        "(Path(pytest.__file__).parent/'.tuntun-write-probe').write_text('bad')\n"
    )
    try:
        result = materializer.run_isolated_process((sys.executable, str(script)), root=tmp_path)
        assert result.returncode != 0
        assert not package_probe.exists()
    finally:
        with contextlib.suppress(FileNotFoundError):
            package_probe.unlink()


def test_root_runtime_uses_its_own_lock_when_eval_lock_is_present(tmp_path: Path) -> None:
    materializer.write_materialized_tree(
        tmp_path,
        {
            "evals/pyproject.toml": (
                b"[project]\nname='generator-fixture'\nversion='0.0.0'\n"
                b"requires-python='==3.12.*'\ndependencies=[]\n"
            ),
            "evals/uv.lock": (
                b"version=1\nrevision=3\nrequires-python='==3.12.*'\n"
                b"[[package]]\nname='generator-fixture'\nversion='0.0.0'\n"
                b"source={ virtual='.' }\n"
            ),
            "root_probe.py": b"import yaml\nassert yaml.__version__\n",
        },
    )

    result = materializer.run_isolated_process((sys.executable, "root_probe.py"), root=tmp_path)

    assert result.returncode == 0, result.diagnostic


def test_materialized_project_source_wins_over_ambient_editable_install(tmp_path: Path) -> None:
    workspace = Path(materializer.__file__).resolve().parents[1]
    ambient_core_source = workspace / "apps/core/src"
    materializer.write_materialized_tree(
        tmp_path,
        {
            "pyproject.toml": (workspace / "pyproject.toml").read_bytes(),
            "uv.lock": (workspace / "uv.lock").read_bytes(),
            "apps/core/pyproject.toml": (workspace / "apps/core/pyproject.toml").read_bytes(),
            "apps/edge/pyproject.toml": (workspace / "apps/edge/pyproject.toml").read_bytes(),
            "packages/contracts/pyproject.toml": (
                workspace / "packages/contracts/pyproject.toml"
            ).read_bytes(),
            "packages/testing/pyproject.toml": (
                workspace / "packages/testing/pyproject.toml"
            ).read_bytes(),
            "apps/core/src/tuntun_core/__init__.py": b"SOURCE = 'materialized-candidate'\n",
            "probe.py": (
                b"import sys\n"
                b"from pathlib import Path\n"
                b"import tuntun_core\n"
                b"assert tuntun_core.SOURCE == 'materialized-candidate'\n"
                + (
                    f"ambient=Path({str(ambient_core_source)!r}).resolve()\n"
                    "assert ambient not in {Path(value).resolve() for value in sys.path if value}\n"
                ).encode()
            ),
        },
    )

    result = materializer.run_isolated_process(
        ("uv", "run", "--locked", "python", "probe.py"), root=tmp_path
    )

    assert result.returncode == 0, result.diagnostic


def test_direct_python_uses_the_exact_audited_root_environment(tmp_path: Path) -> None:
    probe = tmp_path / "prefix_probe.py"
    probe.write_text(
        "import sys\n"
        "from pathlib import Path\n"
        f"assert Path(sys.prefix).resolve() == Path({str(Path(sys.prefix).resolve())!r})\n"
    )

    result = materializer.run_isolated_process(("python", probe.name), root=tmp_path)

    assert result.returncode == 0, result.diagnostic


def test_root_uv_runtime_is_no_sync_and_cannot_write_host_environment() -> None:
    workspace = Path(materializer.__file__).resolve().parents[1]
    marker = Path(sys.prefix) / f".tuntun-root-uv-write-probe-{os.getpid()}"
    assert not marker.exists()
    source = (
        "import os,sys\n"
        "from pathlib import Path\n"
        "assert os.environ.get('UV_NO_SYNC') == '1'\n"
        "try:\n"
        "    (Path(sys.prefix) / sys.argv[1]).write_text('forbidden')\n"
        "except PermissionError:\n"
        "    pass\n"
        "else:\n"
        "    raise AssertionError('host environment was writable')\n"
    )
    try:
        result = materializer.run_isolated_process(
            ("uv", "run", "--locked", "python", "-c", source, marker.name),
            root=workspace,
        )

        assert result.returncode == 0, result.diagnostic
        assert not marker.exists()
    finally:
        with contextlib.suppress(FileNotFoundError):
            marker.unlink()


def test_direct_root_command_rejects_ambient_distribution_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "ambient_only.py").write_text("VALUE = 'host-only'\n")
    (tmp_path / "probe.py").write_text("import ambient_only\nassert ambient_only.VALUE\n")
    real_mapping = importlib.metadata.packages_distributions

    def packages_distributions() -> dict[str, list[str]]:
        mapping = {name: list(values) for name, values in real_mapping().items()}
        mapping["ambient_only"] = ["ambient-only"]
        return mapping

    monkeypatch.setattr(
        importlib.metadata,
        "packages_distributions",
        packages_distributions,
    )

    result = materializer.run_isolated_process((sys.executable, "probe.py"), root=tmp_path)

    assert result.returncode != 0
    assert b"undeclared distribution import" in result.diagnostic


def _write_distribution_metadata(
    site_packages: Path, directory: str, name: str, version: str
) -> None:
    metadata = site_packages / directory / "METADATA"
    metadata.parent.mkdir(parents=True)
    metadata.write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n")


def _write_single_registry_policy_fixture(
    root: Path,
    *,
    project_requirement: str,
    locked_version: str,
    lock_metadata: str,
) -> None:
    evals = root / "evals"
    evals.mkdir()
    digest = "1" * 64
    filename = f"demo_package-{locked_version}-py3-none-any.whl"
    (evals / "pyproject.toml").write_text(
        "[project]\n"
        "name='fixture'\n"
        "version='0.0.0'\n"
        "requires-python='==3.12.*'\n"
        f"dependencies=[{project_requirement!r}]\n"
    )
    (evals / "uv.lock").write_text(
        "version=1\nrevision=3\nrequires-python='==3.12.*'\n"
        "[[package]]\nname='fixture'\nversion='0.0.0'\nsource={virtual='.'}\n"
        "dependencies=[{name='demo-package'}]\n"
        f"[package.metadata]\nrequires-dist=[{lock_metadata}]\n"
        "[[package]]\nname='demo-package'\n"
        f"version={locked_version!r}\nsource={{registry='https://pypi.org/simple'}}\n"
        "wheels=[{url='https://files.pythonhosted.org/packages/tuntun/"
        f"{filename}',hash='sha256:{digest}',size=1}}]\n"
    )


@pytest.mark.parametrize(
    ("specifier", "locked_version"),
    (
        ("~=1.4", "1.4.9"),
        (">=1,<2,!=1.5", "1.6"),
        ("==1.*", "1.9"),
        ("===1.4.2", "1.4.2"),
        (">=2.0rc1,<2.0rc3", "2.0rc2"),
    ),
)
def test_locked_eval_policy_uses_full_requirement_specifier_semantics(
    tmp_path: Path, specifier: str, locked_version: str
) -> None:
    _write_single_registry_policy_fixture(
        tmp_path,
        project_requirement=f"Demo_Package{specifier}",
        locked_version=locked_version,
        lock_metadata=f"{{name='demo-package',specifier={specifier!r}}}",
    )

    policy = materializer._locked_eval_import_policy(tmp_path)

    assert policy is not None
    assert policy.reachable_versions["demo-package"] == frozenset({locked_version})


@pytest.mark.parametrize(
    ("specifier", "locked_version"),
    (
        ("~=1.4", "2.0"),
        (">=1,<2,!=1.5", "1.5"),
        ("==1.*", "2.0"),
        ("===1.4.2", "1.4.3"),
        (">=2,<1", "1.5"),
        (">=2.0rc1,<2.0rc3", "2.0b1"),
    ),
)
def test_locked_eval_policy_rejects_selected_version_outside_direct_requirement(
    tmp_path: Path, specifier: str, locked_version: str
) -> None:
    _write_single_registry_policy_fixture(
        tmp_path,
        project_requirement=f"demo-package{specifier}",
        locked_version=locked_version,
        lock_metadata=f"{{name='demo-package',specifier={specifier!r}}}",
    )

    with pytest.raises(MaterializationError, match="specifier|requirement|version"):
        materializer._locked_eval_import_policy(tmp_path)


@pytest.mark.parametrize(
    "lock_metadata",
    (
        "{name='demo-package',specifier='>=1,<3'}",
        "{name='demo-package',specifier='=>1'}",
        "{name='demo-package',specifier='>=1,<2',extras=['feature']}",
        "{name='demo-package',specifier='>=1,<2',url='https://example.invalid/demo.whl'}",
        "{name='demo-package',specifier='>=1,<2',marker=\"python_version >= '3.0'\"}",
    ),
)
def test_locked_eval_policy_rejects_noncanonical_root_lock_requirements(
    tmp_path: Path, lock_metadata: str
) -> None:
    _write_single_registry_policy_fixture(
        tmp_path,
        project_requirement="demo-package>=1,<2",
        locked_version="1.6",
        lock_metadata=lock_metadata,
    )

    with pytest.raises(MaterializationError, match="requirement|specifier|extras|URL|metadata"):
        materializer._locked_eval_import_policy(tmp_path)


def _write_transitive_wheel_fixture(
    root: Path,
    *,
    parent_requires: tuple[str, ...],
    locked_child: bool = True,
    parent_module: str = "parent_package",
    probe_source: bytes = b"import parent_package\nassert parent_package.VALUE == 'parent'\n",
) -> None:
    parent_filename, parent_wheel, parent_hash = _locked_wheel(
        "parent-package",
        "1.4.0",
        parent_module,
        "VALUE = 'parent'\n",
        requires_dist=parent_requires,
    )
    files: dict[str, bytes] = {
        "evals/pyproject.toml": (
            b"[project]\nname='fixture'\nversion='0.0.0'\n"
            b"requires-python='==3.12.*'\ndependencies=['parent-package>=1,<2']\n"
        ),
        "probe.py": probe_source,
        f".tuntun/locked-wheels/{parent_filename}": parent_wheel,
    }
    parent_dependencies = "dependencies=[{name='child-package'}]\n" if locked_child else ""
    lock = (
        "version=1\nrevision=3\nrequires-python='==3.12.*'\n"
        "[[package]]\nname='fixture'\nversion='0.0.0'\nsource={virtual='.'}\n"
        "dependencies=[{name='parent-package'}]\n"
        "[package.metadata]\n"
        "requires-dist=[{name='parent-package',specifier='>=1,<2'}]\n"
        "[[package]]\nname='parent-package'\nversion='1.4.0'\n"
        "source={registry='https://pypi.org/simple'}\n"
        f"{parent_dependencies}"
        "wheels=[{url='https://files.pythonhosted.org/packages/tuntun/"
        f"{parent_filename}',hash='sha256:{parent_hash}',size={len(parent_wheel)}}}]\n"
    )
    if locked_child:
        child_filename, child_wheel, child_hash = _locked_wheel(
            "child-package", "2.4.0", "child_package", "VALUE = 'child'\n"
        )
        files[f".tuntun/locked-wheels/{child_filename}"] = child_wheel
        lock += (
            "[[package]]\nname='child-package'\nversion='2.4.0'\n"
            "source={registry='https://pypi.org/simple'}\n"
            "wheels=[{url='https://files.pythonhosted.org/packages/tuntun/"
            f"{child_filename}',hash='sha256:{child_hash}',size={len(child_wheel)}}}]\n"
        )
    files["evals/uv.lock"] = lock.encode()
    materializer.write_materialized_tree(root, files)


def test_locked_runtime_audits_transitive_wheel_requirement_specifiers(tmp_path: Path) -> None:
    _write_transitive_wheel_fixture(
        tmp_path,
        parent_requires=("child-package~=2.0",),
    )

    result = materializer.run_isolated_process(
        ("uv", "run", "--project", "evals", "--locked", "python", "probe.py"),
        root=tmp_path,
    )

    assert result.returncode == 0, result.diagnostic


@pytest.mark.parametrize(
    "requirement",
    (
        "child-package>=3",
        "child-package[feature]>=2",
        "child-package @ https://example.invalid/child.whl",
        "child-package =>2",
    ),
)
def test_locked_runtime_rejects_untrusted_transitive_wheel_requirements(
    tmp_path: Path, requirement: str
) -> None:
    _write_transitive_wheel_fixture(tmp_path, parent_requires=(requirement,))

    with pytest.raises(MaterializationError, match="requirement|specifier|extras|URL|metadata"):
        materializer.run_isolated_process(
            ("uv", "run", "--project", "evals", "--locked", "python", "probe.py"),
            root=tmp_path,
        )


def test_locked_runtime_ignores_only_marker_inactive_optional_extra_metadata(
    tmp_path: Path,
) -> None:
    _write_transitive_wheel_fixture(
        tmp_path,
        parent_requires=("optional-child>=9; extra == 'feature'",),
        locked_child=False,
    )

    result = materializer.run_isolated_process(
        ("uv", "run", "--project", "evals", "--locked", "python", "probe.py"),
        root=tmp_path,
    )

    assert result.returncode == 0, result.diagnostic


def test_locked_runtime_rejects_url_metadata_even_when_marker_is_inactive(
    tmp_path: Path,
) -> None:
    _write_transitive_wheel_fixture(
        tmp_path,
        parent_requires=(
            "optional-child @ https://example.invalid/child.whl ; python_version < '3.0'",
        ),
        locked_child=False,
    )

    with pytest.raises(MaterializationError, match="URL"):
        materializer.run_isolated_process(
            ("uv", "run", "--project", "evals", "--locked", "python", "probe.py"),
            root=tmp_path,
        )


def _candidate_eval_files(
    *,
    sources: str | None = None,
    core_project_name: str = "tuntun-core",
    core_version: str = "0.1.0.dev0",
    core_requires_python: str = "==3.12.*",
    core_dependencies: str = "[]",
    core_lock_dependencies: str = "",
    core_lock_metadata: str = "",
    core_lock_source: str = "{directory='../apps/core'}",
) -> dict[str, bytes]:
    source_table = sources or (
        "[tool.uv.sources]\n"
        "tuntun-core={path='../apps/core',editable=false}\n"
        "tuntun-contracts={path='../packages/contracts',editable=false}\n"
    )
    return {
        "evals/pyproject.toml": (
            "[project]\nname='fixture'\nversion='0.0.0'\n"
            "requires-python='==3.12.*'\n"
            "dependencies=['tuntun-core==0.1.0.dev0','tuntun-contracts==0.1.0.dev0']\n"
            f"{source_table}"
        ).encode(),
        "evals/uv.lock": (
            "version=1\nrevision=3\nrequires-python='==3.12.*'\n"
            "[[package]]\nname='fixture'\nversion='0.0.0'\nsource={virtual='.'}\n"
            "dependencies=[{name='tuntun-core'},{name='tuntun-contracts'}]\n"
            "[package.metadata]\nrequires-dist=["
            "{name='tuntun-core',specifier='==0.1.0.dev0',directory='../apps/core'},"
            "{name='tuntun-contracts',specifier='==0.1.0.dev0',"
            "directory='../packages/contracts'}]\n"
            "[[package]]\nname='tuntun-core'\nversion='0.1.0.dev0'\n"
            f"source={core_lock_source}\n{core_lock_dependencies}{core_lock_metadata}"
            "[[package]]\nname='tuntun-contracts'\nversion='0.1.0.dev0'\n"
            "source={directory='../packages/contracts'}\n"
        ).encode(),
        "apps/core/pyproject.toml": (
            "[project]\n"
            f"name={core_project_name!r}\nversion={core_version!r}\n"
            f"requires-python={core_requires_python!r}\ndependencies={core_dependencies}\n"
        ).encode(),
        "apps/core/src/tuntun_core/__init__.py": b"SENTINEL = 'candidate-core'\n",
        "packages/contracts/pyproject.toml": (
            b"[project]\nname='tuntun-contracts'\nversion='0.1.0.dev0'\n"
            b"requires-python='>=3.11,<3.13'\ndependencies=[]\n"
        ),
        "packages/contracts/src/tuntun_contracts/__init__.py": (
            b"SENTINEL = 'candidate-contracts'\n"
        ),
        "tuntun_core.py": b"raise AssertionError('materialized root shadow imported')\n",
        "probe.py": (
            b"from pathlib import Path\nimport sys\nimport tuntun_core\nimport tuntun_contracts\n"
            b"root=Path.cwd().resolve()\n"
            b"core=(root/'apps/core/src/tuntun_core/__init__.py').resolve()\n"
            b"contracts=(root/'packages/contracts/src/tuntun_contracts/__init__.py').resolve()\n"
            b"assert Path(tuntun_core.__file__).resolve()==core\n"
            b"assert Path(tuntun_contracts.__file__).resolve()==contracts\n"
            b"assert tuntun_core.SENTINEL=='candidate-core'\n"
            b"assert tuntun_contracts.SENTINEL=='candidate-contracts'\n"
            b"paths=[Path(item).resolve() for item in sys.path if item]\n"
            b"site=[item for item in paths if item.name=='site-packages']\n"
            b"site_indexes=[paths.index(item) for item in site]\n"
            b"assert site_indexes and min(site_indexes)<paths.index(core.parents[1])\n"
            b"assert paths.index(core.parents[1]) < paths.index(root)\n"
            b"assert paths.index(contracts.parents[1]) < paths.index(root)\n"
            b"core_paths=[item for item in paths if item.parts[-3:]==('apps','core','src')]\n"
            b"contract_paths=[item for item in paths "
            b"if item.parts[-3:]==('packages','contracts','src')]\n"
            b"assert core_paths==[core.parents[1]]\n"
            b"assert contract_paths==[contracts.parents[1]]\n"
            b"assert (root/'apps/edge/src').resolve() not in paths\n"
            b"assert (root/'packages/testing/src').resolve() not in paths\n"
        ),
    }


def test_eval_runtime_binds_only_exact_noneditable_candidate_sources(tmp_path: Path) -> None:
    materializer.write_materialized_tree(tmp_path, _candidate_eval_files())

    result = materializer.run_isolated_process(
        ("uv", "run", "--project", "evals", "--locked", "python", "probe.py"),
        root=tmp_path,
    )

    assert result.returncode == 0, result.diagnostic


@pytest.mark.parametrize(
    "sources",
    (
        "",
        "[tool.uv.sources]\ntuntun-core='../apps/core'\n",
        "[tool.uv.sources]\ntuntun-core={path='../apps/core',editable=true}\n"
        "tuntun-contracts={path='../packages/contracts',editable=false}\n",
        "[tool.uv.sources]\ntuntun-core={path='../apps/./core',editable=false}\n"
        "tuntun-contracts={path='../packages/contracts',editable=false}\n",
        "[tool.uv.sources]\ntuntun-core={path='../apps/core',editable=false}\n"
        "tuntun-contracts={path='../packages/contracts',editable=false}\n"
        "tuntun-edge={path='../apps/edge',editable=false}\n",
    ),
)
def test_eval_policy_rejects_missing_malformed_or_extra_candidate_sources(
    tmp_path: Path, sources: str
) -> None:
    files = _candidate_eval_files(sources=sources)
    if not sources:
        files["evals/pyproject.toml"] = files["evals/pyproject.toml"].split(
            b"[tool.uv.sources]", 1
        )[0]
    materializer.write_materialized_tree(tmp_path, files)

    with pytest.raises(MaterializationError, match="candidate|source|editable|tool.uv"):
        materializer._locked_eval_import_policy(tmp_path)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("core_project_name", "wrong-core"),
        ("core_version", "0.2.0"),
        ("core_requires_python", ">=3.13"),
        ("core_lock_source", "{directory='../apps/core/.'}"),
        ("core_lock_source", "{directory='../apps/edge'}"),
        ("core_dependencies", "['tuntun-contracts>=1']"),
        ("core_dependencies", "['tuntun-edge @ file:///tmp/edge']"),
    ),
)
def test_eval_policy_rejects_candidate_metadata_or_lock_drift(
    tmp_path: Path, field: str, value: str
) -> None:
    arguments = {field: value}
    files = _candidate_eval_files(**arguments)
    materializer.write_materialized_tree(tmp_path, files)

    with pytest.raises(
        MaterializationError,
        match="candidate|source|name|version|Python|requirement|specifier|URL|lock",
    ):
        materializer._locked_eval_import_policy(tmp_path)


def test_eval_policy_rejects_symlinked_candidate_project_or_package(tmp_path: Path) -> None:
    materializer.write_materialized_tree(tmp_path, _candidate_eval_files())
    package = tmp_path / "apps/core/src/tuntun_core"
    real_package = tmp_path / "apps/core/src/real_tuntun_core"
    package.rename(real_package)
    package.symlink_to(real_package, target_is_directory=True)

    with pytest.raises(MaterializationError, match="candidate|symlink|source"):
        materializer._locked_eval_import_policy(tmp_path)


def test_eval_policy_rejects_symlink_inside_candidate_source_tree(tmp_path: Path) -> None:
    materializer.write_materialized_tree(tmp_path, _candidate_eval_files())
    (tmp_path / "apps/core/src/tuntun_core/host_alias.py").symlink_to("/etc/hosts")

    with pytest.raises(MaterializationError, match="candidate|symlink|source"):
        materializer._locked_eval_import_policy(tmp_path)


def test_candidate_dependency_uses_same_canonical_lock_requirement_policy(
    tmp_path: Path,
) -> None:
    files = _candidate_eval_files(
        core_dependencies="['tuntun-contracts~=0.1.0.dev0']",
        core_lock_dependencies="dependencies=[{name='tuntun-contracts'}]\n",
        core_lock_metadata=(
            "[package.metadata]\nrequires-dist=[{name='tuntun-contracts',"
            "specifier='~=0.1.0.dev0',directory='../packages/contracts'}]\n"
        ),
    )
    materializer.write_materialized_tree(tmp_path, files)

    policy = materializer._locked_eval_import_policy(tmp_path)

    assert policy is not None
    assert policy.dependency_graph["tuntun-core"] == frozenset({"tuntun-contracts"})


def test_candidate_dependency_specifier_must_accept_locked_version(tmp_path: Path) -> None:
    files = _candidate_eval_files(
        core_dependencies="['tuntun-contracts>=0.2']",
        core_lock_dependencies="dependencies=[{name='tuntun-contracts'}]\n",
        core_lock_metadata=(
            "[package.metadata]\nrequires-dist=[{name='tuntun-contracts',"
            "specifier='>=0.2',directory='../packages/contracts'}]\n"
        ),
    )
    materializer.write_materialized_tree(tmp_path, files)

    with pytest.raises(MaterializationError, match="rejects locked version"):
        materializer._locked_eval_import_policy(tmp_path)


def test_candidate_cannot_depend_on_an_undeclared_local_project(tmp_path: Path) -> None:
    files = _candidate_eval_files(
        core_dependencies="['tuntun-edge==1.0.0']",
        core_lock_dependencies="dependencies=[{name='tuntun-edge'}]\n",
        core_lock_metadata=(
            "[package.metadata]\nrequires-dist=[{name='tuntun-edge',specifier='==1.0.0'}]\n"
        ),
    )
    files["evals/uv.lock"] += (
        b"[[package]]\nname='tuntun-edge'\nversion='1.0.0'\nsource={directory='../apps/edge'}\n"
    )
    materializer.write_materialized_tree(tmp_path, files)

    with pytest.raises(MaterializationError, match="unsupported local directory|candidate"):
        materializer._locked_eval_import_policy(tmp_path)


@pytest.mark.parametrize(
    "project_requirement",
    (
        "demo-package[feature]>=1",
        "demo-package @ https://example.invalid/demo.whl",
        "demo-package @ git+https://example.invalid/demo.git@main",
        "demo-package @ file:///tmp/demo.whl",
    ),
)
def test_eval_project_rejects_selected_extras_and_direct_sources(
    tmp_path: Path, project_requirement: str
) -> None:
    _write_single_registry_policy_fixture(
        tmp_path,
        project_requirement=project_requirement,
        locked_version="1.6",
        lock_metadata="{name='demo-package',specifier='>=1'}",
    )

    with pytest.raises(MaterializationError, match="URL|extras|source"):
        materializer._locked_eval_import_policy(tmp_path)


def test_task15_plan_describes_source_bound_candidates_not_project_wheels() -> None:
    plan = PLAN_PATH.read_text(encoding="utf-8")
    task_15_contract = plan[plan.index("Task 15 owns an isolated evaluator project.") :]
    paragraph = task_15_contract.split("\n\n", 1)[0]

    assert "project wheels" not in paragraph
    assert "tuntun-core` → `../apps/core` → `apps/core/src/tuntun_core`" in paragraph
    assert (
        "tuntun-contracts` → `../packages/contracts` → "
        "`packages/contracts/src/tuntun_contracts`" in paragraph
    )
    assert "editable=false" in paragraph
    assert "selects no dependency extras" in paragraph
    assert "marker-inactive optional-extra" in paragraph


def test_locked_runtime_audit_rejects_duplicate_and_extra_distributions(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    site_packages = runtime / "lib/python3.12/site-packages"
    _write_distribution_metadata(site_packages, "first-1.dist-info", "first", "1")
    _write_distribution_metadata(site_packages, "duplicate-1.dist-info", "first", "1")
    _write_distribution_metadata(site_packages, "extra-1.dist-info", "extra", "1")
    policy = materializer._LockedEvalPolicy(
        project_name="fixture",
        reachable_versions={"fixture": frozenset({"0"}), "first": frozenset({"1"})},
        forbidden_imports=(),
    )

    with pytest.raises(MaterializationError, match="duplicate|extra|closure"):
        materializer._audit_locked_runtime(runtime, policy)


def test_locked_eval_policy_rejects_multiple_versions_for_one_reachable_package(
    tmp_path: Path,
) -> None:
    evals = tmp_path / "evals"
    evals.mkdir()
    (evals / "pyproject.toml").write_text(
        "[project]\n"
        "name='fixture'\n"
        "version='0.0.0'\n"
        "requires-python='==3.12.*'\n"
        "dependencies=['PyYAML==6.0.3']\n"
    )
    (evals / "uv.lock").write_text(
        "version=1\nrevision=3\nrequires-python='==3.12.*'\n"
        "[[package]]\nname='fixture'\nversion='0.0.0'\nsource={virtual='.'}\n"
        "dependencies=[{name='pyyaml'}]\n"
        "[package.metadata]\n"
        "requires-dist=[{name='pyyaml',specifier='==6.0.3'}]\n"
        "[[package]]\nname='pyyaml'\nversion='6.0.2'\n"
        "source={registry='https://pypi.org/simple'}\n"
        "wheels=[{url='https://files.pythonhosted.org/packages/pyyaml-6.0.2.whl',"
        "hash='sha256:2222222222222222222222222222222222222222222222222222222222222222'}]\n"
        "[[package]]\nname='pyyaml'\nversion='6.0.3'\n"
        "source={registry='https://pypi.org/simple'}\n"
        "wheels=[{url='https://files.pythonhosted.org/packages/pyyaml-6.0.3.whl',"
        "hash='sha256:3333333333333333333333333333333333333333333333333333333333333333'}]\n"
    )

    with pytest.raises(MaterializationError, match="exactly one locked version"):
        materializer._locked_eval_import_policy(tmp_path)


def test_locked_eval_policy_requires_artifact_evidence_for_every_dependency(
    tmp_path: Path,
) -> None:
    evals = tmp_path / "evals"
    evals.mkdir()
    (evals / "pyproject.toml").write_text(
        "[project]\n"
        "name='fixture'\n"
        "version='0.0.0'\n"
        "requires-python='==3.12.*'\n"
        "dependencies=['local-dependency==1.0.0']\n"
    )
    (evals / "uv.lock").write_text(
        "version=1\nrevision=3\nrequires-python='==3.12.*'\n"
        "[[package]]\nname='fixture'\nversion='0.0.0'\nsource={virtual='.'}\n"
        "dependencies=[{name='local-dependency'}]\n"
        "[package.metadata]\n"
        "requires-dist=[{name='local-dependency',specifier='==1.0.0'}]\n"
        "[[package]]\nname='local-dependency'\nversion='1.0.0'\n"
        "source={virtual='../local-dependency'}\n"
    )

    with pytest.raises(MaterializationError, match="artifact evidence"):
        materializer._locked_eval_import_policy(tmp_path)


def test_locked_eval_policy_excludes_inactive_project_and_lock_markers(
    tmp_path: Path,
) -> None:
    evals = tmp_path / "evals"
    evals.mkdir()
    (evals / "pyproject.toml").write_text(
        "[project]\n"
        "name='fixture'\n"
        "version='0.0.0'\n"
        "requires-python='==3.12.*'\n"
        "dependencies=[\"inactive-fixture==1.0.0; python_version < '3.0'\"]\n"
    )
    (evals / "uv.lock").write_text(
        "version=1\nrevision=3\nrequires-python='==3.12.*'\n"
        "[[package]]\nname='fixture'\nversion='0.0.0'\nsource={virtual='.'}\n"
        "dependencies=[{name='inactive-fixture',marker=\"python_version < '3.0'\"}]\n"
        "[package.metadata]\n"
        "requires-dist=[{name='inactive-fixture',specifier='==1.0.0',"
        "marker=\"python_version < '3.0'\"}]\n"
        "[[package]]\nname='inactive-fixture'\nversion='1.0.0'\n"
        "source={virtual='../inactive-fixture'}\n"
    )

    policy = materializer._locked_eval_import_policy(tmp_path)

    assert policy is not None
    assert policy.reachable_versions == {"fixture": frozenset({"0.0.0"})}
    assert policy.registry_artifacts == {}


def test_locked_eval_policy_selects_only_current_platform_closure(tmp_path: Path) -> None:
    active_platform = sys.platform
    inactive_platform = "win32" if active_platform != "win32" else "darwin"
    evals = tmp_path / "evals"
    evals.mkdir()
    active_hash = "1" * 64
    (evals / "pyproject.toml").write_text(
        "[project]\n"
        "name='fixture'\n"
        "version='0.0.0'\n"
        "requires-python='==3.12.*'\n"
        "dependencies=["
        f"\"active-fixture==1.0.0; sys_platform == '{active_platform}'\","
        f"\"inactive-fixture==1.0.0; sys_platform == '{inactive_platform}'\""
        "]\n"
    )
    (evals / "uv.lock").write_text(
        "version=1\nrevision=3\nrequires-python='==3.12.*'\n"
        "[[package]]\nname='fixture'\nversion='0.0.0'\nsource={virtual='.'}\n"
        "dependencies=["
        f"{{name='active-fixture',marker=\"sys_platform == '{active_platform}'\"}},"
        f"{{name='inactive-fixture',marker=\"sys_platform == '{inactive_platform}'\"}}"
        "]\n"
        "[package.metadata]\nrequires-dist=["
        f"{{name='active-fixture',specifier='==1.0.0',"
        f"marker=\"sys_platform == '{active_platform}'\"}},"
        f"{{name='inactive-fixture',specifier='==1.0.0',"
        f"marker=\"sys_platform == '{inactive_platform}'\"}}"
        "]\n"
        "[[package]]\nname='active-fixture'\nversion='1.0.0'\n"
        "source={registry='https://pypi.org/simple'}\n"
        "wheels=[{url='https://files.pythonhosted.org/packages/tuntun/"
        "active_fixture-1.0.0-py3-none-any.whl',"
        f"hash='sha256:{active_hash}',size=1}}]\n"
        "[[package]]\nname='inactive-fixture'\nversion='1.0.0'\n"
        "source={virtual='../inactive-fixture'}\n"
    )

    policy = materializer._locked_eval_import_policy(tmp_path)

    assert policy is not None
    assert set(policy.reachable_versions) == {"fixture", "active-fixture"}
    assert set(policy.registry_artifacts) == {"active-fixture"}


@pytest.mark.parametrize(
    "marker",
    (
        "python_version >>> '3.12'",
        "extra == 'unselected-feature'",
    ),
)
def test_locked_eval_policy_rejects_invalid_or_ambiguous_markers(
    tmp_path: Path, marker: str
) -> None:
    evals = tmp_path / "evals"
    evals.mkdir()
    (evals / "pyproject.toml").write_text(
        "[project]\nname='fixture'\nversion='0.0.0'\nrequires-python='==3.12.*'\ndependencies=[]\n"
    )
    (evals / "uv.lock").write_text(
        "version=1\nrevision=3\nrequires-python='==3.12.*'\n"
        "[[package]]\nname='fixture'\nversion='0.0.0'\nsource={virtual='.'}\n"
        f"dependencies=[{{name='unused',marker={marker!r}}}]\n"
        "[[package]]\nname='unused'\nversion='1.0.0'\nsource={virtual='../unused'}\n"
    )

    with pytest.raises(MaterializationError, match="marker|unsupported|ambiguous"):
        materializer._locked_eval_import_policy(tmp_path)


def test_verified_wheelhouse_rejects_corrupted_unpacked_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected_hash = "1" * 64
    host_cache = tmp_path / "home/.cache/uv/wheels-v6/pypi/offline-fixture/1.0.0-py3-none-any"
    host_cache.mkdir(parents=True)
    (host_cache / "offline_fixture.py").write_text("CORRUPTED = True\n")
    (host_cache.with_suffix(".http")).write_text(expected_hash)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    policy = materializer._LockedEvalPolicy(
        project_name="fixture",
        reachable_versions={
            "fixture": frozenset({"0"}),
            "offline-fixture": frozenset({"1.0.0"}),
        },
        forbidden_imports=(),
        registry_artifacts={
            "offline-fixture": (
                (
                    "https://files.pythonhosted.org/packages/tuntun/"
                    "offline_fixture-1.0.0-py3-none-any.whl",
                    expected_hash,
                ),
            )
        },
    )

    with pytest.raises(MaterializationError, match="wheel archive.*missing"):
        materializer._prepare_verified_wheelhouse(tmp_path, tmp_path / "wheelhouse", policy)


@pytest.mark.parametrize(
    "source",
    (
        "import importlib\nimportlib.import_module('yaml')",
        "import os,sys\nos.execv(sys.executable,[sys.executable,'-I','-c','import yaml'])",
        "import sys\nsys.modules['posix'].fork()",
    ),
)
def test_isolated_import_policy_rejects_importlib_and_exec_bypasses(
    tmp_path: Path, source: str
) -> None:
    script = tmp_path / "bypass.py"
    script.write_text(source + "\n")

    result = materializer.run_isolated_process(
        (sys.executable, str(script)), root=tmp_path, forbidden_imports=("yaml",)
    )

    assert result.returncode != 0
    assert (
        b"undeclared distribution import" in result.diagnostic
        or b"bypass" in result.diagnostic
        or b"host API forbidden" in result.diagnostic
    )


def test_every_behavioral_probe_uses_the_single_isolated_runner() -> None:
    for function in (
        materializer._execute_generator_once,
        validator._run_foundation_behavioral_probe,
        validator._collect_software_pytest_nodes,
        validator._execute_pytest_boundary_probe,
    ):
        source = inspect.getsource(function)
        assert "subprocess.run" not in source
        assert "run_isolated_process" in source or "run_materialized_python" in source


def test_generator_cannot_read_host_only_environment_or_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TUNTUN_HOST_ONLY_SECRET", "must-not-cross-boundary")
    plan = _locked_generator_plan(
        "import os\n"
        "from pathlib import Path\n"
        "assert 'TUNTUN_HOST_ONLY_SECRET' not in os.environ\n"
        "Path('/etc/hosts').read_text()\n"
        "Path('generated').mkdir(exist_ok=True)\n"
        "Path('generated/schema.json').write_text('{}')"
    )

    with pytest.raises(MaterializationError, match="outside|readable|host|forbidden"):
        materialize_document(parse_plan_text(plan), foundation_files={})


def test_pytest_probe_does_not_inherit_host_only_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TUNTUN_HOST_ONLY_SECRET", "must-not-cross-boundary")
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_environment.py"),),
        snippets=(
            (
                "python",
                "# tests/test_environment.py",
                "import os\n\ndef test_environment_is_sanitized():\n"
                "    assert 'TUNTUN_HOST_ONLY_SECRET' not in os.environ",
            ),
        ),
    ).replace(
        "git diff --cached --check",
        "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\n"
        "Run: `python -m pytest tests/test_environment.py -q`",
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert not any("pytest task-boundary probe failed" in error for error in errors), errors


def test_locked_generator_rejects_missing_reachable_distribution() -> None:
    lock_packages = """
[[package]]
name = "generator-fixture"
version = "0.0.0"
source = { virtual = "." }
dependencies = [{ name = "definitely-missing-tuntun-package" }]

[package.metadata]
requires-dist = [{ name = "definitely-missing-tuntun-package", specifier = "==1.0.0" }]

[[package]]
name = "definitely-missing-tuntun-package"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://example.invalid/missing-1.0.0.whl", \
hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", \
size = 1 }]
"""
    plan = _locked_generator_plan(
        "from pathlib import Path\n"
        "Path('generated').mkdir(exist_ok=True)\n"
        "Path('generated/schema.json').write_text('{}')",
        dependencies="['definitely-missing-tuntun-package==1.0.0']",
        lock_packages=lock_packages,
    )

    with pytest.raises(MaterializationError, match="missing|offline|distribution|artifact"):
        materialize_document(parse_plan_text(plan), foundation_files={})


def test_locked_generator_rejects_fabricated_nonzero_artifact_hash() -> None:
    lock_packages = """
[[package]]
name = "generator-fixture"
version = "0.0.0"
source = { virtual = "." }
dependencies = [{ name = "pyyaml" }]

[package.metadata]
requires-dist = [{ name = "pyyaml", specifier = "==6.0.3" }]

[[package]]
name = "pyyaml"
version = "6.0.3"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://example.invalid/pyyaml-6.0.3.whl", \
hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", \
size = 1 }]
"""
    plan = _locked_generator_plan(
        "import json,yaml\nfrom pathlib import Path\n"
        "Path('generated').mkdir(exist_ok=True)\n"
        "Path('generated/schema.json').write_text(json.dumps(yaml.__version__))",
        dependencies="['PyYAML==6.0.3']",
        lock_packages=lock_packages,
    )

    with pytest.raises(MaterializationError, match="offline|artifact|hash|pyyaml"):
        materialize_document(parse_plan_text(plan), foundation_files={})


def test_lazy_test_body_import_uses_the_same_policy_as_collection(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n")
    test_path = tmp_path / "test_lazy_import.py"
    test_path.write_text("def test_lazy_import():\n    import yaml\n    assert yaml.__version__\n")
    collect = materializer.run_isolated_process(
        (
            sys.executable,
            "-m",
            "pytest",
            "--rootdir=.",
            "--collect-only",
            "-q",
            test_path.name,
        ),
        root=tmp_path,
        forbidden_imports=("yaml",),
    )
    execute = materializer.run_isolated_process(
        (sys.executable, "-m", "pytest", "--rootdir=.", "-q", test_path.name),
        root=tmp_path,
        forbidden_imports=("yaml",),
    )

    assert collect.returncode == 0, collect.diagnostic
    assert execute.returncode != 0
    assert b"undeclared distribution import" in execute.diagnostic


def test_declared_pytest_flags_are_preserved_for_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_flags.py"),),
        snippets=(
            (
                "python",
                "# tests/test_flags.py",
                "def test_declared_flags(pytestconfig):\n"
                "    assert pytestconfig.option.strict_markers is True",
            ),
        ),
    ).replace(
        "git diff --cached --check",
        "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\n"
        "Run: `python -m pytest --strict-markers tests/test_flags.py -q`",
    )

    commands: list[tuple[str, ...]] = []
    real_runner = materializer.run_isolated_process

    def recording_runner(argv: tuple[str, ...], **kwargs: Any) -> materializer._GeneratorRun:
        commands.append(tuple(argv))
        return real_runner(argv, **kwargs)

    monkeypatch.setattr(validator, "run_isolated_process", recording_runner)

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert not any("pytest task-boundary probe failed" in error for error in errors), errors
    assert len(commands) >= 4
    assert all("--strict-markers" in command for command in commands)


def test_declared_pytest_option_value_is_not_rewritten_when_it_matches_target() -> None:
    invocation = (
        "python",
        "-m",
        "pytest",
        "-m",
        "tests/test_flags.py",
        "tests/test_flags.py",
        "-q",
    )

    command = validator._declared_pytest_command(
        invocation,
        ("tests/test_replacement.py",),
    )

    assert command == (
        "python",
        "-m",
        "pytest",
        "-m",
        "tests/test_flags.py",
        "-q",
        "tests/test_replacement.py",
    )


def test_pytest_coverage_option_value_cannot_masquerade_as_owned_target() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Test", "tests/test_owned.py"),),
        snippets=(
            (
                "python",
                "# tests/test_owned.py",
                "def test_owned():\n    assert True",
            ),
        ),
    ).replace(
        "git diff --cached --check",
        "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\n"
        "Run: `python -m pytest --cov tests/test_owned.py --no-cov -q`",
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any(
        "not fail-closed" in error or "does not execute owned test" in error for error in errors
    ), errors


@pytest.mark.parametrize(
    "arguments",
    (
        "--cov=package tests/test_owned.py --no-cov -q",
        "--pyargs tests/test_owned.py -q",
        "--ignore tests/test_owned.py tests -q",
        "--deselect tests/test_owned.py::test_owned tests/test_owned.py -q",
        "--collect-only tests/test_owned.py -q",
        "-k owned tests/test_owned.py -q",
        "-m ordinary tests/test_owned.py -q",
    ),
)
def test_target_affecting_pytest_options_are_fail_closed(arguments: str) -> None:
    command = f"python -m pytest {arguments}"

    assert not validator._green_command_is_fail_closed(command)


def test_test_local_harness_cannot_hide_broken_production_class() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(
            ("Create", "pkg/service.py"),
            ("Create", "tests/fixtures/service.py"),
            ("Create", "tests/conftest.py"),
            ("Test", "tests/test_service.py"),
        ),
        snippets=(
            (
                "python",
                "# pkg/service.py",
                "class Service:\n    def run(self):\n        return 'broken'",
            ),
            (
                "python",
                "# tests/fixtures/service.py",
                "import pytest\n\n"
                "class ServiceCase:\n"
                "    def run(self):\n        return 'ready'\n\n"
                "@pytest.fixture\n"
                "def service() -> ServiceCase:\n    return ServiceCase()",
            ),
            (
                "python",
                "# tests/conftest.py",
                "pytest_plugins = ('tests.fixtures.service',)",
            ),
            (
                "python",
                "# tests/test_service.py",
                "def test_service(service):\n    assert service.run() == 'ready'",
            ),
        ),
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any("test-local harness" in error for error in errors), errors


def test_generic_manifest_accepts_foundation_bootstrap_empty_models() -> None:
    assert validate_model_manifest_bytes(b'schema_version: "1.0"\nmodels: []\n') == []


def test_foundation_tuple_fakes_and_local_downgrade_are_not_acceptance_evidence() -> None:
    errors = validate_plan_document(
        parse_plan_text(_valid_two_task_plan()),
        foundation_files=_foundation_files(),
        require_foundation_task_13=True,
    )

    assert any("real migration" in error or "downgrade" in error for error in errors), errors


def _task15_snippet_source(path: str) -> str:
    document = parse_plan_text(PLAN_PATH.read_text(encoding="utf-8"))
    task = next(item for item in document.tasks if item.number == 15)
    matches = [snippet.body.decode("utf-8") for snippet in task.snippets if snippet.path == path]
    assert len(matches) == 1
    return matches[0]


def _load_task15_control_module() -> types.ModuleType:
    module = types.ModuleType("tuntun_test_control_json")
    source = _task15_snippet_source("evals/control_json.py")
    exec(compile(source, "evals/control_json.py", "exec"), module.__dict__)
    return module


def _task15_portability_errors(source: str | None = None) -> list[str]:
    document = parse_plan_text(source or PLAN_PATH.read_text(encoding="utf-8"))
    task = next(item for item in document.tasks if item.number == 15)
    errors: list[str] = []
    validator._validate_task15_portability_contract(task, errors)
    return errors


def test_transformers_style_repeated_optional_requirements_are_allowed(tmp_path: Path) -> None:
    # Exact representative repeats from Transformers 4.56.2 wheel METADATA.
    _write_transitive_wheel_fixture(
        tmp_path,
        parent_requires=(
            'tokenizers<=0.23.0,>=0.22.0; extra == "all"',
            'tokenizers<=0.23.0,>=0.22.0; extra == "dev"',
            'tokenizers<=0.23.0,>=0.22.0; extra == "dev-tensorflow"',
            'tokenizers<=0.23.0,>=0.22.0; extra == "dev-torch"',
            'tokenizers<=0.23.0,>=0.22.0; extra == "tokenizers"',
            'tokenizers<=0.23.0,>=0.22.0; extra == "torchhub"',
        ),
        locked_child=False,
    )

    result = materializer.run_isolated_process(
        ("uv", "run", "--project", "evals", "--locked", "python", "probe.py"),
        root=tmp_path,
    )

    assert result.returncode == 0, result.diagnostic


def test_every_repeated_active_requirement_constraint_is_validated(tmp_path: Path) -> None:
    _write_transitive_wheel_fixture(
        tmp_path,
        parent_requires=("child-package>=2", "child-package<3", "child-package!=2.4"),
    )

    with pytest.raises(MaterializationError, match="rejects locked version"):
        materializer.run_isolated_process(
            ("uv", "run", "--project", "evals", "--locked", "python", "probe.py"),
            root=tmp_path,
        )


def test_repeated_active_requirement_constraints_can_all_pass(tmp_path: Path) -> None:
    _write_transitive_wheel_fixture(
        tmp_path,
        parent_requires=("child-package>=2", "child-package<3", "child-package!=2.3"),
    )

    result = materializer.run_isolated_process(
        ("uv", "run", "--project", "evals", "--locked", "python", "probe.py"),
        root=tmp_path,
    )

    assert result.returncode == 0, result.diagnostic


def test_registry_distribution_cannot_own_candidate_import_root(tmp_path: Path) -> None:
    _write_transitive_wheel_fixture(
        tmp_path,
        parent_requires=(),
        locked_child=False,
        parent_module="tuntun_core",
        probe_source=b"raise AssertionError('plan probe executed before origin audit')\n",
    )

    with pytest.raises(MaterializationError, match="candidate import root|tuntun_core"):
        materializer.run_isolated_process(
            ("uv", "run", "--project", "evals", "--locked", "python", "probe.py"),
            root=tmp_path,
        )


@pytest.mark.parametrize(
    ("invocation", "expected"),
    (
        (
            (
                "TUNTUN_ALLOW_REACHY_HARDWARE=1",
                "/venvs/apps_venv/bin/python3",
                "-m",
                "pytest",
                "-c",
                "tools/reachy-hardware-probe/pytest.ini",
                "-m",
                "reachy_hardware",
                "tests/hardware/test_live.py",
                "-q",
            ),
            "reachy_hardware_pytest",
        ),
        (
            (
                "TUNTUN_ALLOW_REACHY_HARDWARE=1",
                "/venvs/apps_venv/bin/python3",
                "tests/hardware/bench_wakeword.py",
                "--frames",
                "360000",
                "--max-one-core-percent",
                "25",
            ),
            "reachy_hardware_command",
        ),
        (
            (
                "TUNTUN_ALLOW_LIVE_CLOUD=1",
                "python",
                "-m",
                "pytest",
                "-m",
                "live_cloud",
                "tests/integration/providers/test_live.py",
                "-q",
            ),
            "live_cloud_pytest",
        ),
    ),
)
def test_exact_external_lane_grammar_is_centralized(
    invocation: tuple[str, ...], expected: str
) -> None:
    assert validator._external_lane(invocation) == expected


@pytest.mark.parametrize(
    "invocation",
    (
        ("TUNTUN_ALLOW_REACHY_HARDWARE=0", "python", "scripts/check.py"),
        ("TUNTUN_ALLOW_LIVE_CLOUD=0", "python", "scripts/check.py"),
        ("TUNTUN_ALLOW_REACHY_HARDWARE=1", "python", "scripts/check.py"),
        ("TUNTUN_ALLOW_LIVE_CLOUD=1", "python", "scripts/check.py"),
    ),
)
def test_allow_variables_do_not_turn_critical_python_into_external_lane(
    invocation: tuple[str, ...],
) -> None:
    assert validator._external_lane(invocation) is None


@pytest.mark.parametrize(
    "command",
    (
        "TUNTUN_ALLOW_REACHY_HARDWARE=yes python scripts/check.py",
        "TUNTUN_ALLOW_LIVE_CLOUD=2 python scripts/check.py",
        "TUNTUN_ALLOW_REACHY_HARDWARE=1 TUNTUN_ALLOW_REACHY_HARDWARE=1 python scripts/check.py",
        "TUNTUN_ALLOW_LIVE_CLOUD=0 TUNTUN_ALLOW_LIVE_CLOUD=1 python scripts/check.py",
        "TUNTUN_ALLOW_REACHY_HARDWARE=1 TUNTUN_ALLOW_LIVE_CLOUD=1 python scripts/check.py",
        "TUNTUN_ALLOW_REACHY_HARDWARE=1 python -m pytest -m live_cloud tests/test_live.py",
        "TUNTUN_ALLOW_REACHY_HARDWARE=1 /venvs/apps_venv/bin/python3 -m pytest "
        "-m reachy_hardware tests/hardware/test_live.py -q",
        "TUNTUN_ALLOW_LIVE_CLOUD=1 pytest -m live_cloud "
        "tests/integration/providers/test_live.py -q",
        "TUNTUN_ALLOW_LIVE_CLOUD=1 python -m pytest -m live_cloud tests/hardware/test_live.py -q",
        "TUNTUN_ALLOW_REACHY_HARDWARE=1 /venvs/apps_venv/bin/python3 -m pytest "
        "-c tools/reachy-hardware-probe/pytest.ini -m reachy_hardware "
        "tests/hardware/../test_owned.py -q",
        "TUNTUN_ALLOW_LIVE_CLOUD=1 python -m pytest -m live_cloud "
        "tests/integration/providers/../../test_owned.py -q",
    ),
)
def test_malformed_duplicate_or_mixed_external_authorization_is_rejected(command: str) -> None:
    assert not validator._green_command_is_fail_closed(command)


def test_malformed_external_authorization_cannot_crash_or_certify_critical_gate() -> None:
    plan = _task(
        1,
        depends="Foundation contracts",
        files=(("Create", "scripts/check_gate.py"),),
        snippets=(("python", "# scripts/check_gate.py", "raise SystemExit(0)"),),
    ).replace(
        "```bash",
        "- [ ] **Step 4: Run the green gate**\n\n"
        "Run: `TUNTUN_ALLOW_LIVE_CLOUD=yes python scripts/check_gate.py`\n\n```bash",
        1,
    )

    errors = validate_plan_document(
        parse_plan_text(plan),
        foundation_files={},
        execute_behavioral_probes=False,
    )

    assert any("green command is not fail-closed" in error for error in errors), errors
    assert any("does not execute owned critical validator" in error for error in errors), errors


@pytest.mark.parametrize(
    ("variable", "value"),
    (
        ("TUNTUN_ALLOW_REACHY_HARDWARE", "1"),
        ("TUNTUN_ALLOW_REACHY_HARDWARE", "0"),
        ("TUNTUN_ALLOW_LIVE_CLOUD", "1"),
        ("TUNTUN_ALLOW_LIVE_CLOUD", "0"),
    ),
)
def test_critical_green_command_executes_even_with_allow_variable(
    variable: str, value: str
) -> None:
    task = _task(
        1,
        depends="Foundation contracts",
        files=(("Create", "scripts/check.py"),),
        snippets=(("python", "# scripts/check.py", "raise SystemExit(19)"),),
    ).replace(
        "```bash",
        "- [ ] **Step 4: Run the green gate**\n\n"
        f"Run: `{variable}={value} python scripts/check.py`\n\n```bash",
        1,
    )
    document = parse_plan_text(task)
    files = materialize_document(document, foundation_files={})
    errors: list[str] = []

    validator._execute_owned_green_commands(document, files, errors)

    assert any("exit 19" in error for error in errors), errors


def _write_fasttext_predict_policy_fixture(
    root: Path, *, include_arm: bool, include_x86: bool
) -> None:
    artifacts = []
    if include_arm:
        artifacts.append(
            (
                "fasttext_predict-0.9.2.4-cp312-cp312-macosx_11_0_arm64.whl",
                "99dbfcc3f353da2639fd04fc574a65ff4195b018311f790583147cdc6eb122f4",
            )
        )
    if include_x86:
        artifacts.append(
            (
                "fasttext_predict-0.9.2.4-cp312-cp312-macosx_10_13_x86_64.whl",
                "dcf8661da4f515551523470a745df246121f7e19736fcf3f48f04287963e6279",
            )
        )
    wheel_records = ",".join(
        "{url='https://files.pythonhosted.org/packages/tuntun/"
        f"{filename}',hash='sha256:{digest}',size=1}}"
        for filename, digest in artifacts
    )
    materializer.write_materialized_tree(
        root,
        {
            "evals/pyproject.toml": (
                b"[project]\nname='fixture'\nversion='0.0.0'\n"
                b"requires-python='==3.12.*'\ndependencies=['fasttext-predict==0.9.2.4']\n"
            ),
            "evals/uv.lock": (
                "version=1\nrevision=3\nrequires-python='==3.12.*'\n"
                "[[package]]\nname='fixture'\nversion='0.0.0'\nsource={virtual='.'}\n"
                "dependencies=[{name='fasttext-predict'}]\n"
                "[package.metadata]\n"
                "requires-dist=[{name='fasttext-predict',specifier='==0.9.2.4'}]\n"
                "[[package]]\nname='fasttext-predict'\nversion='0.9.2.4'\n"
                "source={registry='https://pypi.org/simple'}\n"
                f"wheels=[{wheel_records}]\n"
            ).encode(),
        },
    )


def test_fasttext_predict_lock_requires_both_reviewed_darwin_wheels(tmp_path: Path) -> None:
    _write_fasttext_predict_policy_fixture(tmp_path, include_arm=True, include_x86=False)

    with pytest.raises(MaterializationError, match="fasttext-predict.*Darwin|wheel evidence"):
        materializer._locked_eval_import_policy(tmp_path)


def test_fasttext_predict_lock_accepts_exact_reviewed_arm_and_intel_evidence(
    tmp_path: Path,
) -> None:
    _write_fasttext_predict_policy_fixture(tmp_path, include_arm=True, include_x86=True)

    policy = materializer._locked_eval_import_policy(tmp_path)

    assert policy is not None
    assert policy.reachable_versions["fasttext-predict"] == frozenset({"0.9.2.4"})


@pytest.mark.parametrize(
    ("extra_modules", "accepted"),
    (
        ({"fasttext_pybind": "VALUE = 'native-binding'\n"}, True),
        ({}, False),
        (
            {
                "fasttext_pybind": "VALUE = 'native-binding'\n",
                "counterfeit_binding": "VALUE = 'unexpected'\n",
            },
            False,
        ),
    ),
)
def test_fasttext_predict_runtime_requires_exact_reviewed_import_surface(
    tmp_path: Path,
    extra_modules: dict[str, str],
    accepted: bool,
) -> None:
    filename, wheel, _ = _locked_wheel(
        "fasttext-predict",
        "0.9.2.4",
        "fasttext",
        "def load_model(path):\n    return path\n",
        extra_modules=extra_modules,
    )
    wheelhouse = tmp_path / "wheelhouse"
    runtime = tmp_path / "runtime"
    cache = tmp_path / "cache"
    temporary = tmp_path / "temporary"
    home = tmp_path / "home"
    for directory in (wheelhouse, cache, temporary, home):
        directory.mkdir(mode=0o700)
    (wheelhouse / filename).write_bytes(wheel)
    policy = materializer._LockedEvalPolicy(
        project_name="fixture",
        reachable_versions={
            "fixture": frozenset({"0.0.0"}),
            "fasttext-predict": frozenset({"0.9.2.4"}),
        },
        forbidden_imports=(),
        registry_distributions=frozenset({"fasttext-predict"}),
        dependency_graph={"fasttext-predict": frozenset()},
    )
    materializer._install_verified_wheelhouse(
        wheelhouse,
        runtime,
        policy,
        uv_cache=cache,
        temporary_root=temporary,
        home=home,
    )

    if accepted:
        materializer._audit_locked_runtime(runtime, policy, verify_files=True)
    else:
        with pytest.raises(MaterializationError, match="fasttext-predict.*API|offline closure"):
            materializer._audit_locked_runtime(runtime, policy, verify_files=True)


def test_task15_contract_pins_reviewed_fasttext_predict_and_portable_loader() -> None:
    assert _task15_portability_errors() == []


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    (
        ("fasttext-predict==0.9.2.4", "fasttext-wheel==0.9.2", "fasttext-predict"),
        (
            "99dbfcc3f353da2639fd04fc574a65ff4195b018311f790583147cdc6eb122f4",
            "0" * 64,
            "arm64",
        ),
        (
            "dcf8661da4f515551523470a745df246121f7e19736fcf3f48f04287963e6279",
            "1" * 64,
            "x86_64",
        ),
        ("import fasttext", "import counterfeit_fasttext as fasttext", "fasttext API"),
        ("fasttext.load_model", "fasttext.load", "fasttext API"),
        ("fasttext_pybind", "counterfeit_pybind", "provenance"),
        ("materialize_private_artifact", "read_content_addressed", "private artifact"),
        ("_read_all_bounded", "os.read", "bounded read-all"),
        ("_write_all", "os.write", "write-all"),
    ),
)
def test_task15_validator_rejects_supply_chain_or_portable_io_regression(
    old: str, new: str, expected: str
) -> None:
    source = PLAN_PATH.read_text(encoding="utf-8")
    assert old in source
    errors = _task15_portability_errors(source.replace(old, new))

    assert any(expected in error for error in errors), errors


def test_task15_validator_rejects_commented_noop_write_all_spoof() -> None:
    source = PLAN_PATH.read_text(encoding="utf-8")
    signature = "def _write_all(descriptor: int, payload: bytes | bytearray | memoryview) -> None:"
    implementation = (
        signature
        + """
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("zero-length artifact write")
        remaining = remaining[written:]
"""
    )
    spoof = (
        signature
        + """
    # while remaining:
    # written = os.write(descriptor, remaining)
    # if written <= 0:
    return None
"""
    )
    assert implementation in source

    errors = _task15_portability_errors(source.replace(implementation, spoof, 1))

    assert any("write-all" in error for error in errors), errors


@pytest.mark.parametrize(
    ("active", "spoof", "expected"),
    (
        (
            "_write_all(descriptor, canonical_schema_bytes())",
            "# _write_all(descriptor, canonical_schema_bytes())\n"
            "        os.write(descriptor, canonical_schema_bytes())",
            "write-all",
        ),
        (
            "raw = _read_all_bounded(descriptor, max_bytes)",
            "# raw = _read_all_bounded(descriptor, max_bytes)\n"
            "        raw = os.read(descriptor, max_bytes)",
            "bounded read-all",
        ),
        (
            "_write_all(target_descriptor, chunk)",
            "# _write_all(target_descriptor, chunk)\n"
            "            os.write(target_descriptor, chunk)",
            "write-all",
        ),
    ),
)
def test_task15_validator_rejects_commented_required_io_callsites(
    active: str, spoof: str, expected: str
) -> None:
    source = PLAN_PATH.read_text(encoding="utf-8")
    assert active in source

    errors = _task15_portability_errors(source.replace(active, spoof, 1))

    assert any(expected in error for error in errors), errors


@pytest.mark.parametrize(
    ("active", "spoof", "expected"),
    (
        (
            "_write_all(descriptor, canonical_schema_bytes())",
            "if False:\n"
            "                _write_all(descriptor, canonical_schema_bytes())\n"
            "            os.write(descriptor, canonical_schema_bytes())",
            "write-all",
        ),
        (
            "raw = _read_all_bounded(descriptor, max_bytes)",
            "if False:\n"
            "            raw = _read_all_bounded(descriptor, max_bytes)\n"
            "        raw = os.read(descriptor, max_bytes)",
            "bounded read-all",
        ),
        (
            "_write_all(target_descriptor, chunk)",
            "if False:\n"
            "                _write_all(target_descriptor, chunk)\n"
            "            os.write(target_descriptor, chunk)",
            "write-all",
        ),
    ),
)
def test_task15_validator_rejects_dead_required_io_callsites(
    active: str, spoof: str, expected: str
) -> None:
    source = PLAN_PATH.read_text(encoding="utf-8")
    assert active in source

    errors = _task15_portability_errors(source.replace(active, spoof, 1))

    assert any(expected in error for error in errors), errors


def test_task15_validator_rejects_early_return_before_write_all_loop() -> None:
    source = PLAN_PATH.read_text(encoding="utf-8")
    signature = "def _write_all(descriptor: int, payload: bytes | bytearray | memoryview) -> None:"
    assert signature in source
    mutated = source.replace(
        signature,
        signature + "\n    if payload:\n        return",
        1,
    )

    errors = _task15_portability_errors(mutated)

    assert any("write-all" in error for error in errors), errors


def test_task15_control_json_uses_read_all_for_short_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    control = _load_task15_control_module()
    path = tmp_path / "control.json"
    path.write_bytes(b'{"value":1}\n')
    real_read = os.read

    def short_read(descriptor: int, count: int) -> bytes:
        return real_read(descriptor, min(count, 2))

    monkeypatch.setattr(os, "read", short_read)
    value = control.parse_control_json(path, max_bytes=64, require_canonical=True)

    assert value == {"value": 1}


@pytest.mark.parametrize("zero_write", (False, True))
def test_task15_write_all_handles_partial_and_zero_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, zero_write: bool
) -> None:
    control = _load_task15_control_module()
    target = tmp_path / "write.bin"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    real_write = os.write

    def adversarial_write(fd: int, payload: bytes | memoryview) -> int:
        if zero_write:
            return 0
        return real_write(fd, bytes(payload[: max(1, len(payload) // 3)]))

    monkeypatch.setattr(os, "write", adversarial_write)
    try:
        if zero_write:
            with pytest.raises(OSError, match="zero|short|write"):
                control._write_all(descriptor, b"0123456789")
        else:
            control._write_all(descriptor, b"0123456789")
    finally:
        os.close(descriptor)

    if not zero_write:
        assert target.read_bytes() == b"0123456789"


def test_task15_locked_tree_streams_without_buffering_whole_artifact(
    tmp_path: Path,
) -> None:
    control = _load_task15_control_module()
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    source = artifact / "weights.bin"
    chunk = b"x" * 1_048_576
    with source.open("wb") as stream:
        for _ in range(12):
            stream.write(chunk)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()

    tracemalloc.start()
    try:
        with control.materialize_locked_tree(
            artifact, {"weights.bin": digest}, max_total_bytes=16_777_216
        ) as materialized:
            assert (materialized / "weights.bin").stat().st_size == 12 * len(chunk)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert peak < 6_000_000


def test_private_artifact_is_owner_only_regular_sized_and_cleaned(tmp_path: Path) -> None:
    control = _load_task15_control_module()
    source = tmp_path / "language.bin"
    source.write_bytes(b"model-bytes")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    materialized: Path | None = None
    parent: Path | None = None

    with control.materialize_private_artifact(source, digest, max_bytes=64) as candidate:
        materialized = candidate
        parent = candidate.parent
        directory = os.lstat(parent)
        metadata = os.lstat(candidate)
        assert stat.S_ISDIR(directory.st_mode)
        assert stat.S_ISREG(metadata.st_mode)
        assert directory.st_uid == metadata.st_uid == os.geteuid()
        assert stat.S_IMODE(directory.st_mode) == 0o700
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        assert metadata.st_size == len(b"model-bytes")

    assert materialized is not None and not materialized.exists()
    assert parent is not None and not parent.exists()


def test_private_artifact_normalizes_restrictive_umask(tmp_path: Path) -> None:
    control = _load_task15_control_module()
    source = tmp_path / "language.bin"
    source.write_bytes(b"model-bytes")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()

    previous_umask = os.umask(0o777)
    try:
        with control.materialize_private_artifact(source, digest, max_bytes=64) as candidate:
            assert stat.S_IMODE(os.lstat(candidate.parent).st_mode) == 0o700
            assert stat.S_IMODE(os.lstat(candidate).st_mode) == 0o600
    finally:
        os.umask(previous_umask)


def test_locked_tree_normalizes_restrictive_umask(tmp_path: Path) -> None:
    control = _load_task15_control_module()
    source_root = tmp_path / "source"
    source = source_root / "nested" / "weights.bin"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"model-bytes")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()

    previous_umask = os.umask(0o777)
    try:
        with control.materialize_locked_tree(
            source_root,
            {"nested/weights.bin": digest},
            max_total_bytes=64,
        ) as materialized:
            assert stat.S_IMODE(os.lstat(materialized).st_mode) == 0o700
            assert stat.S_IMODE(os.lstat(materialized / "nested").st_mode) == 0o700
            assert stat.S_IMODE(os.lstat(materialized / "nested/weights.bin").st_mode) == 0o600
    finally:
        os.umask(previous_umask)


def test_private_artifact_mode_normalization_runs_inside_isolated_policy(tmp_path: Path) -> None:
    (tmp_path / "control_json.py").write_text(
        _task15_snippet_source("evals/control_json.py"), encoding="utf-8"
    )
    source = tmp_path / "source.bin"
    source.write_bytes(b"model-bytes")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import os, stat\n"
        "from pathlib import Path\n"
        "from control_json import materialize_locked_tree, materialize_private_artifact\n"
        f"digest={digest!r}\n"
        "source=Path('source.bin')\n"
        "with materialize_private_artifact(source,digest,max_bytes=64) as artifact:\n"
        "    assert stat.S_IMODE(os.lstat(artifact).st_mode)==0o600\n"
        "with materialize_locked_tree(\n"
        "    Path('.'), {'source.bin': digest}, max_total_bytes=64\n"
        ") as tree:\n"
        "    assert stat.S_IMODE(os.lstat(tree/'source.bin').st_mode)==0o600\n",
        encoding="utf-8",
    )

    result = materializer.run_isolated_process((sys.executable, probe.name), root=tmp_path)

    assert result.returncode == 0, result.diagnostic


@pytest.mark.parametrize("failure", ("body", "write", "fsync", "load", "path-conflict"))
def test_private_artifact_cleanup_covers_every_failure_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    control = _load_task15_control_module()
    source = tmp_path / "language.bin"
    source.write_bytes(b"model-bytes")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    real_temporary_directory = control.tempfile.TemporaryDirectory
    created: list[Path] = []

    class RecordingTemporaryDirectory:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self._wrapped = real_temporary_directory(*args, **kwargs)

        def __enter__(self) -> str:
            value = self._wrapped.__enter__()
            root = Path(value)
            created.append(root)
            if failure == "path-conflict":
                (root / "artifact.bin").write_bytes(b"conflict")
            return cast(str, value)

        def __exit__(self, *args: object) -> object:
            return self._wrapped.__exit__(*args)

    monkeypatch.setattr(control.tempfile, "TemporaryDirectory", RecordingTemporaryDirectory)
    if failure == "write":
        monkeypatch.setattr(
            control, "_write_all", lambda *_args: (_ for _ in ()).throw(OSError("write"))
        )
    if failure == "fsync":
        monkeypatch.setattr(
            control.os, "fsync", lambda _fd: (_ for _ in ()).throw(OSError("fsync"))
        )

    def loader(_path: Path) -> object:
        if failure == "load":
            raise RuntimeError("load")
        return object()

    with (
        pytest.raises((OSError, RuntimeError, FileExistsError))
        if failure != "body"
        else pytest.raises(RuntimeError)
    ):
        if failure == "body":
            with control.materialize_private_artifact(source, digest, max_bytes=64):
                raise RuntimeError("body")
        else:
            control.load_private_artifact(source, digest, max_bytes=64, loader=loader)

    assert created and all(not path.exists() for path in created)


@pytest.mark.parametrize("kind", ("directory", "file"))
def test_private_artifact_rejects_wrong_owner_only_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    control = _load_task15_control_module()
    source = tmp_path / "language.bin"
    source.write_bytes(b"model-bytes")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if kind == "directory":
        real_temporary_directory = control.tempfile.TemporaryDirectory

        class LooseTemporaryDirectory:
            def __init__(self, *args: object, **kwargs: object) -> None:
                self._wrapped = real_temporary_directory(*args, **kwargs)

            def __enter__(self) -> str:
                value = self._wrapped.__enter__()
                os.chmod(value, 0o755)
                return cast(str, value)

            def __exit__(self, *args: object) -> object:
                return self._wrapped.__exit__(*args)

        monkeypatch.setattr(control.tempfile, "TemporaryDirectory", LooseTemporaryDirectory)
    else:
        real_open = control.os.open

        def loose_open(path: object, flags: int, mode: int = 0o777, **kwargs: object) -> int:
            descriptor = real_open(path, flags, mode, **kwargs)
            if flags & os.O_WRONLY:
                os.fchmod(descriptor, 0o644)
            return cast(int, descriptor)

        monkeypatch.setattr(control.os, "open", loose_open)

    with (
        pytest.raises(PermissionError, match="temporary|private|metadata"),
        control.materialize_private_artifact(source, digest, max_bytes=64),
    ):
        pass
