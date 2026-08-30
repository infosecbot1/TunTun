from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

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
        "apps/core/src/tuntun_core/adapters/sqlcipher/engine.py": (
            b"def create_engine(path, key):\n    return (path, key)\n\n"
            b"def create_sqlcipher_engine(path, key):\n    return create_engine(path, key)\n"
        ),
        "apps/core/src/tuntun_core/adapters/sqlcipher/migrations.py": (
            b"class command:\n"
            b"    @staticmethod\n    def upgrade(*args):\n        return args\n\n"
            b"def encrypted_backup(source, destination, key):\n"
            b"    return source.backup(destination, key)\n\n"
            b"def upgrade_encrypted(path, key, backup):\n"
            b"    return command.upgrade(path, key, backup)\n"
        ),
        "tests/integration/storage/test_migrations.py": (
            b"class command:\n"
            b"    @staticmethod\n    def upgrade(state):\n        state.append('up')\n"
            b"    @staticmethod\n    def downgrade(state):\n        state.append('down')\n\n"
            b"def test_migrations_upgrade_and_rollback():\n"
            b"    state = []\n    command.upgrade(state)\n    command.downgrade(state)\n"
            b"    assert state == ['up', 'down']\n"
        ),
    }


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
def test_validator_rejects_path_parity_breaks(mutate, message: str) -> None:
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


def test_synthetic_accepted_foundation_capabilities_pass_the_boundary_gate() -> None:
    errors = validate_plan_document(
        parse_plan_text(_valid_two_task_plan()),
        foundation_files=_foundation_files(),
        require_foundation_task_13=True,
    )

    assert [error for error in errors if "Foundation Task 13" in error] == []


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
def test_model_manifest_semantics_reject_hostile_values(mutation) -> None:
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


def _controlled_bilingual_schema() -> bytes:
    fields = {
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
    }
    properties = {name: {"type": "string", "minLength": 1} for name in fields}
    properties["schema_version"] = {
        "const": "tuntun.bilingual-persona-score.v1",
        "type": "string",
    }
    properties["candidate_commit"] = {"pattern": "^[0-9a-f]{40}$", "type": "string"}
    for name in fields:
        if name.endswith("sha256"):
            properties[name] = {"pattern": "^[0-9a-f]{64}$", "type": "string"}
    properties["signature_domain"] = {
        "const": "tuntun.bilingual-persona-score.v1",
        "type": "string",
    }
    properties["signature_purpose"] = {
        "const": "phase1_release_acceptance",
        "type": "string",
    }
    schema = {
        "$id": "https://tuntun.local/schemas/bilingual-persona-score-v1.schema.json",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": properties,
        "required": sorted(fields),
        "type": "object",
    }
    return (json.dumps(schema, sort_keys=True, separators=(",", ":")) + "\n").encode()


def test_bilingual_schema_validator_executes_controlled_good_and_bad_artifacts() -> None:
    good = _controlled_bilingual_schema()
    assert validator.validate_bilingual_schema_bytes(good) == []

    for mutate in (
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
    ):
        hostile = mutate(json.loads(good))
        errors = validator.validate_bilingual_schema_bytes(json.dumps(hostile).encode())
        assert errors, hostile


def _behavioral_wake_benchmark() -> bytes:
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
    assert validator.validate_wake_benchmark_bytes(_behavioral_wake_benchmark()) == []

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
