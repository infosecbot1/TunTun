from __future__ import annotations

import json
import subprocess
import sys
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

PLAN_PATH = Path(
    "docs/superpowers/plans/2026-08-27-tuntun-phase1-conversation-reachy-execution.md"
)


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
    subprocess.run(
        ["git", "-C", repository, "config", "user.name", "Plan Test"], check=True
    )
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
    subprocess.run(
        ["git", "-C", repository, "config", "user.name", "Plan Test"], check=True
    )
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
    subprocess.run(
        ["git", "-C", repository, "config", "user.name", "Plan Test"], check=True
    )
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
        f"```{language}\n{header}\n{body.rstrip()}\n```"
        for language, header, body in snippets
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


def _disconnected_foundation_files() -> dict[str, bytes]:
    files = _foundation_files()
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


def test_model_manifest_rejects_an_empty_model_set() -> None:
    errors = validate_model_manifest_bytes(b'schema_version: "1.0"\nmodels: []\n')

    assert any("models shape" in error for error in errors), errors


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
            lambda text: text.replace(
                "```yaml\n# config/first.yaml\nenabled: true\n```\n\n", ""
            ),
            "declared/snippet path mismatch",
        ),
        (
            lambda text: text.replace("- Create: `config/first.yaml`\n", ""),
            "declared/staged path mismatch",
        ),
    ),
)
def test_validator_rejects_path_parity_breaks(
    mutate: Callable[[str], str], message: str
) -> None:
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
        "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\n"
        f"Run: `{green}`",
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
                "def test_selected():\n    assert True\n\n"
                "def test_unselected():\n    assert False",
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
        "git diff --cached --check\n\n- [ ] **Step 4: Run the green gate**\n\n"
        "Run: `echo verified`",
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any(
        "green command does not execute owned critical validator" in error
        for error in errors
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
        "fixture" in error and ("dynamic" in error or "placeholder" in error)
        for error in errors
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
            ("Create", "tests/fixtures/cases.py"),
            ("Create", "tests/conftest.py"),
            ("Test", "tests/test_case.py"),
        ),
        snippets=(
            (
                "python",
                "# tests/fixtures/cases.py",
                "from collections.abc import Iterator\nimport pytest\n\n"
                "class Case:\n"
                "    value: str = 'real'\n"
                "    def required_method(self) -> str:\n        return 'real'\n\n"
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
                "def test_case(case):\n"
                "    assert case.required_method() == case.value == 'real'",
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
            b"class FoundationCase:\n"
            b"    def required_method(self) -> str:\n        return 'real'\n"
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
        "green command does not execute owned test tests/hardware/bench_wakeword.py"
        in error
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
        FOUNDATION_MIGRATION_PATHS[2]: (
            b"class command:\n"
            b"    @staticmethod\n    def upgrade(state):\n        state.append('up')\n"
            b"    @staticmethod\n    def downgrade(state):\n        state.append('down')\n\n"
            b"def test_migrations_upgrade_and_rollback():\n"
            b"    state = []\n    command.upgrade(state)\n    command.downgrade(state)\n"
            b"    assert state == ['never', 'passes']\n"
        )
    }

    errors = validate_plan_document(
        parse_plan_text(_valid_two_task_plan()),
        foundation_files=broken,
        require_foundation_task_13=True,
    )

    assert any("Foundation Task 13 behavioral probe failed" in error for error in errors)


def test_foundation_migration_integration_test_cannot_skip() -> None:
    skipped = _foundation_files() | {
        FOUNDATION_MIGRATION_PATHS[2]: (
            b"import pytest\n\n"
            b"class command:\n"
            b"    @staticmethod\n    def upgrade(state):\n        state.append('up')\n"
            b"    @staticmethod\n    def downgrade(state):\n        state.append('down')\n\n"
            b"def test_migrations_upgrade_and_rollback():\n"
            b"    command.upgrade([])\n    command.downgrade([])\n"
            b"    assert True\n    pytest.skip('not evidence')\n"
        )
    }

    errors = validate_plan_document(
        parse_plan_text(_valid_two_task_plan()),
        foundation_files=skipped,
        require_foundation_task_13=True,
    )

    assert any(
        "Foundation Task 13" in error and "skip/xfail" in error for error in errors
    ), errors


def test_foundation_behavioral_probe_rejects_runtime_aliased_skip() -> None:
    skipped = _foundation_files() | {
        FOUNDATION_MIGRATION_PATHS[2]: (
            b"import pytest\n_skip = pytest.skip\n\n"
            b"class command:\n"
            b"    @staticmethod\n    def upgrade(state):\n        state.append('up')\n"
            b"    @staticmethod\n    def downgrade(state):\n        state.append('down')\n\n"
            b"def test_migrations_upgrade_and_rollback():\n"
            b"    state = []\n    command.upgrade(state)\n    command.downgrade(state)\n"
            b"    assert state == ['up', 'down']\n    _skip('not evidence')\n"
        )
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
        foundation_files=_foundation_files(),
        require_foundation_task_13=True,
    )

    assert [error for error in errors if "Foundation Task 13" in error] == []


def test_foundation_conftest_fixture_is_in_static_and_runtime_closure() -> None:
    foundation = _foundation_files() | {
        "tests/conftest.py": (
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

    assert not any("fixture foundation_case" in error for error in errors), errors
    assert not any("pytest task-boundary probe failed" in error for error in errors), errors


def test_foundation_typed_factory_fixture_uses_runtime_discovery_evidence() -> None:
    foundation = _foundation_files() | {
        "tests/conftest.py": (
            b"import pytest\n\n"
            b"class FoundationCase:\n"
            b"    @classmethod\n"
            b"    def build(cls):\n        return cls()\n"
            b"    def required_method(self):\n        return 'ready'\n\n"
            b"@pytest.fixture\n"
            b"def foundation_case() -> FoundationCase:\n"
            b"    return FoundationCase.build()\n"
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
                "def test_builder(text_builder):\n"
                "    assert text_builder('ready') == 'READY'",
            ),
        ),
    )

    errors = validate_plan_document(parse_plan_text(plan), foundation_files=foundation)

    assert not any(
        "fixture text_builder does not return a typed concrete harness" in error
        for error in errors
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
    assert any(
        error.startswith("Task 15: declared/snippet path mismatch") for error in errors
    ), errors


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
        lambda data: data.replace(b"https://models.example.com/hello.onnx", b"http://models.example.com/hello.onnx"),
        lambda data: data.replace(b"https://models.example.com/hello.onnx", b"https://127.0.0.1/hello.onnx"),
        lambda data: data.replace(b"models:\n", b"models: &models\n", 1)
        + b"shadow: *models\n",
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
        _valid_model_manifest().replace(
            b"  license: Apache-2.0", b"  license: !!str Apache-2.0"
        ),
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

    assert any(
        "exact model IDs hello-tuntun-v1 and stop-tuntun-v1" in error
        for error in errors
    ), errors


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
    properties["model_id"] = titled(
        "model_id", minLength=1, maxLength=128, type="string"
    )
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
    properties["signer_key_id"] = titled(
        "signer_key_id", minLength=1, maxLength=128, type="string"
    )
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
    properties["signature_b64"] = titled(
        "signature_b64", minLength=88, maxLength=88, type="string"
    )
    schema = {
        "$defs": {
            "RecomputedAggregates": {
                "additionalProperties": False,
                "properties": {
                    name: titled(name, type="integer") for name in aggregate_fields
                },
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
        lambda value: value
        | {
            "properties": value["properties"]
            | {"schema_version": {"type": "string"}}
        },
        lambda value: value
        | {
            "properties": value["properties"]
            | {"candidate_commit": {"type": "string"}}
        },
    )
    for mutate in mutations:
        hostile = mutate(json.loads(good))
        errors = validator.validate_bilingual_schema_bytes(json.dumps(hostile).encode())
        assert errors, hostile


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value["$defs"]["RecomputedAggregates"].update(
            additionalProperties=True
        ),
        lambda value: value["$defs"]["RecomputedAggregates"]["properties"][
            "bilingual_total"
        ].update(type="number"),
        lambda value: value["properties"]["aggregates"].update(
            {"$ref": "#/$defs/Other"}
        ),
        lambda value: value["properties"]["evaluator_artifacts_sha256"].update(
            maxItems=9
        ),
        lambda value: value["properties"]["result_manifest_paths"]["items"].update(
            type="integer"
        ),
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
    content = (
        json.dumps(hostile, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()

    assert validator.validate_bilingual_schema_bytes(content), hostile


def _bilingual_report_model_source() -> bytes:
    return b'''from datetime import datetime
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
'''


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
    benchmark = b'''import argparse
import time

from tuntun_core.services.models.registry import ModelRegistry
from tuntun_edge.audio.converter import StreamingAudioConverter
from tuntun_edge.audio.wakeword import WakeDetector

MODEL_SHA = "a" * 64
RUNTIME_SHA = "b" * 64

def run_benchmark(*, frames, converter, adapter, detector, process_time,
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
    activated = ModelRegistry().activate("hello-tuntun-v1")
    adapter = activated.load_with()
    converter = StreamingAudioConverter()
    detector = WakeDetector(adapter.infer, 750000)
    receipt = run_benchmark(
        frames=[b"\\x00" * 2560 for _ in range(args.frames)],
        converter=converter,
        adapter=adapter,
        detector=detector,
        process_time=time.process_time,
        max_one_core_percent=args.max_one_core_percent,
    )
    if set(receipt) != {
        "input_count", "inference_count", "output_count", "drop_count",
        "model_sha256", "runtime_sha256",
    } or receipt["input_count"] != args.frames:
        raise RuntimeError("receipt mismatch")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
'''
    return {
        "apps/edge/src/tuntun_edge/__init__.py": b"",
        "apps/edge/src/tuntun_edge/audio/__init__.py": b"",
        "apps/edge/src/tuntun_edge/audio/converter.py": (
            b"class StreamingAudioConverter:\n"
            b"    def convert(self, frame):\n"
            b"        if len(frame) != 2560:\n            raise ValueError('frame')\n"
            b"        return frame\n"
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
            b"    def activate(self, model_id):\n"
            b"        if model_id != 'hello-tuntun-v1':\n            raise ValueError('model')\n"
            b"        return ActivatedModel()\n"
        ),
        "tests/hardware/bench_wakeword.py": benchmark,
    }


def test_wake_benchmark_uses_delivered_production_pipeline_and_main() -> None:
    files = _production_wake_files()

    assert validator.validate_wake_benchmark_bytes(
        files["tests/hardware/bench_wakeword.py"], materialized_files=files
    ) == []

    disconnected = _disconnected_wake_benchmark()
    errors = validator.validate_wake_benchmark_bytes(
        disconnected,
        materialized_files=files | {"tests/hardware/bench_wakeword.py": disconnected},
    )
    assert any("production pipeline" in error or "main" in error for error in errors), errors


def test_wake_benchmark_noop_main_cannot_certify_physical_command() -> None:
    files = _production_wake_files()
    benchmark = files["tests/hardware/bench_wakeword.py"].replace(
        b"def main(argv=None):\n", b"def real_main(argv=None):\n", 1
    )
    benchmark += b"\ndef main(argv=None):\n    return 0\n"
    files["tests/hardware/bench_wakeword.py"] = benchmark

    errors = validator.validate_wake_benchmark_bytes(
        benchmark, materialized_files=files
    )

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
        "**Files:**\n- Generate `schema-v1`: `python tools/generate.py` "
        "-> `generated/schema.json`",
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
        "**Files:**\n- Generate `schema-v1`: `python tools/generate.py` "
        "-> `generated/schema.json`",
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
        "**Files:**\n- Generate `schema-v1`: `python tools/generate.py` "
        "-> `generated/schema.json`",
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

    good = validate_plan_document(
        parse_plan_text(plan_for("return 'ready'")), foundation_files={}
    )
    bad = validate_plan_document(
        parse_plan_text(
            plan_for("socket.getaddrinfo('models.example.com', 443); return 'ready'")
        ),
        foundation_files={},
    )

    assert not any("probe failed" in error for error in good), good
    assert any("pytest task-boundary probe failed" in error for error in bad), bad
