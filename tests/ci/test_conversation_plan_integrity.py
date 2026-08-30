from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

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


def test_bilingual_report_runtime_enforces_lifecycle_and_signature_contract() -> None:
    files = {"evals/verify_bilingual_report.py": _bilingual_report_model_source()}

    assert validator.validate_bilingual_report_model_files(files) == []

    disconnected = {
        "evals/verify_bilingual_report.py": _bilingual_report_model_source().replace(
            b"        if (\n", b"        if False and (\n", 1
        )
    }
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


def test_locked_generator_uses_available_interpreter_without_uv_cache() -> None:
    plan = _locked_generator_plan(
        "from pathlib import Path\n"
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
    intel_url = (
        "https://files.pythonhosted.org/packages/d1/33/"
        "422b98d2195232ca1826284a76852ad5a86fe23e31b009c9886b2d0fb8b2/"
        "pyyaml-6.0.3-cp312-cp312-macosx_10_13_x86_64.whl"
    )
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
url = "{intel_url}"
hash = "sha256:7f047e29dcae44602496db43be01ad42fc6f1cc0d8cd6c83d342306c32270196"
size = 182063
[[package.wheels]]
url = "{arm_url}"
hash = "sha256:fc09d0aa354569bc501d4e787133afc08552722d3ab34836a80547331bb5d4a0"
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

    files = materialize_document(parse_plan_text(plan), foundation_files={})

    assert files["generated/schema.json"] == b'"6.0.3"'


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

    with pytest.raises(MaterializationError, match="version differs"):
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

    result = materializer.run_materialized_python(
        ("probe.py",), root=tmp_path, restrict_host_apis=False
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


def test_bilingual_runtime_probe_uses_the_generator_sandbox_policy() -> None:
    files = {
        "evals/verify_bilingual_report.py": _bilingual_report_model_source().replace(
            b"from datetime import datetime\n",
            b"from datetime import datetime\nimport platform\nplatform.node()\n",
            1,
        )
    }

    errors = validator.validate_bilingual_report_model_files(files)

    assert any("host API" in error or "nondeterministic" in error for error in errors), errors


def test_bilingual_runtime_rejects_naive_expiry() -> None:
    disconnected = {
        "evals/verify_bilingual_report.py": _bilingual_report_model_source().replace(
            b"            or self.expires_at.tzinfo is None\n", b"", 1
        )
    }

    assert validator.validate_bilingual_report_model_files(disconnected)


def test_generator_timeout_kills_grandchild_after_parent_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "parent.py"
    child_pid_path = tmp_path / "child.pid"
    script.write_text(
        "import subprocess,sys\n"
        "from pathlib import Path\n"
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])\n"
        "Path(sys.argv[1]).write_text(str(child.pid))\n"
    )
    monkeypatch.setattr(materializer, "GENERATOR_TIMEOUT_SECONDS", 0.25)
    child_pid = -1
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            materializer._run_generator_process(
                (sys.executable, str(script), str(child_pid_path)),
                root=tmp_path,
                environment=materializer._generator_environment(tmp_path),
            )
        child_pid = int(child_pid_path.read_text())
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        else:
            pytest.fail(f"grandchild {child_pid} survived generator timeout")
    finally:
        if child_pid > 0:
            with contextlib.suppress(ProcessLookupError):
                os.kill(child_pid, signal.SIGKILL)


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
