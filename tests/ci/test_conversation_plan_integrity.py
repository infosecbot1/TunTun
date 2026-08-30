from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

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


def test_materializer_source_contains_no_developer_worktree_or_branch_binding() -> None:
    source = Path("scripts/materialize_conversation_plan.py").read_text()

    assert ".worktrees" not in source
    assert "foundation-task9" not in source


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
        "apps/core/src/tuntun_core/adapters/sqlcipher/connection.py": (
            b"class SqlCipherEngine:\n    pass\n"
        ),
        "apps/core/src/tuntun_core/adapters/sqlcipher/migrations.py": (
            b"class MigrationRunner:\n    pass\n"
        ),
        "tests/integration/storage/test_migrations.py": (
            b"def test_migrations_upgrade_and_rollback():\n    pass\n"
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
        "  review_date: 2026-08-27\n"
        "  files:\n"
        "  - path: hello.onnx\n"
        "    size: 1\n"
        f"    sha256: {'b' * 64}\n"
        "    url: https://models.example.invalid/hello.onnx\n"
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


def test_tasks_03_through_16_require_foundation_task_13() -> None:
    errors = validate_plan_document(parse_plan_text(PLAN_PATH.read_text()), foundation_files={})

    missing = [error for error in errors if "must depend on accepted Foundation Task 13" in error]
    assert missing == [], missing


def test_authoritative_plan_now_owns_offline_wake_model_gate() -> None:
    errors = validate_plan_document(parse_plan_text(PLAN_PATH.read_text()), foundation_files={})

    assert not any("offline wake-model test" in error for error in errors), errors


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

    assert any(FOUNDATION_MIGRATION_PATHS[1] in error for error in errors), errors
    assert any(FOUNDATION_MIGRATION_PATHS[2] in error for error in errors), errors
    assert any("declared/snippet path mismatch" in error for error in errors), errors
    assert any("dynamic fixture name table is forbidden" in error for error in errors), errors
    assert any("wake benchmark missing required binding" in error for error in errors), errors
    assert not any(
        "schema generator missing canonical binding" in error for error in errors
    ), errors
    assert any(
        error.startswith("Task 15: declared/snippet path mismatch") for error in errors
    ), errors
