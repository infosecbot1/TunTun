import re
import tomllib
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from yaml.nodes import MappingNode, ScalarNode

FULL_SHA = re.compile(r"^[^@]+@[0-9a-f]{40}$")
FIXED_RUNNERS = {"ubuntu-24.04", "macos-26", "macos-15-intel"}
MATRIX_RUNNER = "${{ matrix.os }}"
APPROVED_MATRIX = {"os": ["ubuntu-24.04", "macos-26", "macos-15-intel"]}
EXPECTED_ARCHITECTURES = {
    "ubuntu-24.04": "x86_64",
    "macos-26": "arm64",
    "macos-15-intel": "x86_64",
}
ARCHITECTURE_CHECK_STEP_NAME = "Assert runner architecture"
ARCHITECTURE_CHECK_SHELL = "/bin/bash --noprofile --norc -p -euo pipefail {0}"
MAKE_CHECK_COMMAND = (
    "PYTEST_ADDOPTS=--basetemp=/tmp/t7-${{ github.run_id }}-${{ github.run_attempt }} "
    "/usr/bin/make check"
)
MANAGED_SYNC_COMMAND = "uv sync --all-packages --locked --managed-python"
ARCHITECTURE_CHECK_SCRIPT = """case "${{ matrix.os }}" in
  ubuntu-24.04)
    expected="x86_64"
    ;;
  macos-26)
    expected="arm64"
    ;;
  macos-15-intel)
    expected="x86_64"
    ;;
  *)
    echo "unsupported runner label: ${{ matrix.os }}" >&2
    exit 1
    ;;
esac
actual="$(/usr/bin/uname -m)"
if [ "$actual" != "$expected" ]; then
  echo "runner architecture mismatch: expected $expected, got $actual" >&2
  exit 1
fi
"""
CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_UV_ACTION = "astral-sh/setup-uv@20cfd1bf945f4377ade1205e4dbc17946fc9a30d"
SETUP_PNPM_ACTION = "pnpm/action-setup@0977fd99725f1db4007ccb2928dbb4e90d06cc86"
SETUP_NODE_ACTION = "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020"
CONTRACT_STEPS = [
    {"uses": CHECKOUT_ACTION},
    {"uses": SETUP_UV_ACTION, "with": {"version": "0.8.13", "enable-cache": True}},
    {"shell": ARCHITECTURE_CHECK_SHELL, "run": "uv python install 3.11"},
    {
        "shell": ARCHITECTURE_CHECK_SHELL,
        "run": "uv build --package tuntun-contracts --wheel --out-dir dist-py311",
    },
    {
        "shell": ARCHITECTURE_CHECK_SHELL,
        "run": "uv build --package tuntun-edge --wheel --out-dir dist-py311",
    },
    {
        "shell": ARCHITECTURE_CHECK_SHELL,
        "run": "uv venv --python 3.11 .venv-contracts-edge-py311",
    },
    {
        "shell": ARCHITECTURE_CHECK_SHELL,
        "run": (
            "/usr/bin/env -u PYTHONPATH uv pip install "
            "--python .venv-contracts-edge-py311/bin/python "
            'dist-py311/*.whl "pytest>=8.4,<9" "pytest-asyncio>=1.1,<2" '
            '"hypothesis>=6.138,<7"'
        ),
    },
    {
        "shell": ARCHITECTURE_CHECK_SHELL,
        "run": (
            "/usr/bin/env -u PYTHONPATH .venv-contracts-edge-py311/bin/python -m pytest "
            "tests/contract/test_v1_types_and_ports.py tests/unit/poc/test_framing.py "
            "tests/unit/edge/test_reachy_ptt.py -q"
        ),
    },
    {
        "shell": ARCHITECTURE_CHECK_SHELL,
        "run": (
            "/usr/bin/env -u PYTHONPATH .venv-contracts-edge-py311/bin/python -c "
            '"import importlib.util, tuntun_contracts, tuntun_edge; '
            "forbidden=('tuntun_core','tuntun_testing',"
            "'reachy_mini'); found=[name for name in forbidden if "
            'importlib.util.find_spec(name) is not None]; assert not found, found"'
        ),
    },
]
CHECK_STEPS = [
    {
        "name": ARCHITECTURE_CHECK_STEP_NAME,
        "shell": ARCHITECTURE_CHECK_SHELL,
        "run": ARCHITECTURE_CHECK_SCRIPT,
    },
    {"uses": CHECKOUT_ACTION},
    {"uses": SETUP_UV_ACTION, "with": {"version": "0.8.13", "enable-cache": True}},
    {
        "uses": SETUP_PNPM_ACTION,
        "with": {"version": "10.15.0", "run_install": False},
    },
    {
        "uses": SETUP_NODE_ACTION,
        "with": {"node-version": "22", "cache": "pnpm"},
    },
    {
        "shell": ARCHITECTURE_CHECK_SHELL,
        "run": MANAGED_SYNC_COMMAND,
    },
    {
        "shell": ARCHITECTURE_CHECK_SHELL,
        "run": "pnpm install --frozen-lockfile",
    },
    {"shell": ARCHITECTURE_CHECK_SHELL, "run": MAKE_CHECK_COMMAND},
]


def test_edge_package_exposes_only_frozen_runtime_dependencies_and_script() -> None:
    edge_project = tomllib.loads(Path("apps/edge/pyproject.toml").read_text(encoding="utf-8"))

    assert edge_project["project"]["dependencies"] == [
        "tuntun-contracts==0.1.0.dev0",
        "typer>=0.16,<1",
    ]
    assert edge_project["project"]["scripts"] == {"tuntun-edge": "tuntun_edge.cli.main:app"}
    assert edge_project["tool"]["uv"]["sources"] == {"tuntun-contracts": {"workspace": True}}


WORKFLOW_ROOT = Path(".github/workflows")
FOUNDATION_PLAN = Path("docs/superpowers/plans/2026-08-27-tuntun-phase1-foundation-execution.md")
FOUNDATION_ACCEPTANCE_ROWS = (
    "Ubuntu x86_64 (`check (ubuntu-24.04)`)",
    "Darwin arm64 (`check (macos-26)`)",
    "Darwin Intel x86_64 (`check (macos-15-intel)`)",
)
FOUNDATION_ACTIVE_HOST_RULING = (
    "Darwin Intel x86_64 remains mandatory distribution CI only; the active "
    "household/development target remains the verified Darwin arm64 host."
)


def workflow_paths(root: Path = WORKFLOW_ROOT) -> tuple[Path, ...]:
    paths = tuple(sorted((*root.glob("*.yml"), *root.glob("*.yaml"))))
    assert paths, "at least one workflow is required"
    return paths


def _assert_uses_is_immutable(value: str) -> None:
    if value.startswith("./"):
        return
    assert FULL_SHA.fullmatch(value), value


SECRET_EXPRESSION = re.compile(r"\bsecrets\s*(?:\.|\[)", re.IGNORECASE)


def _assert_no_secret_channel(value: object) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            assert str(key).casefold() != "secrets"
            _assert_no_secret_channel(item)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for item in value:
            _assert_no_secret_channel(item)
    elif isinstance(value, str):
        assert value.casefold() != "inherit"
        assert SECRET_EXPRESSION.search(value) is None


def _assert_permissions(owner: Mapping[str, object], *, required: bool) -> None:
    if "permissions" not in owner:
        assert not required
        return
    assert owner["permissions"] == {"contents": "read"}


def _assert_strategy_matches_runner(job: Mapping[str, object]) -> None:
    runner = job.get("runs-on")
    strategy = job.get("strategy")
    if runner != MATRIX_RUNNER:
        assert strategy is None
        return
    assert isinstance(strategy, Mapping)
    assert set(strategy) == {"fail-fast", "matrix"}
    assert strategy["fail-fast"] is False
    assert strategy["matrix"] == APPROVED_MATRIX


def _assert_matrix_job_checks_expected_architecture(job: Mapping[str, object]) -> None:
    if job.get("runs-on") != MATRIX_RUNNER:
        return
    steps = job.get("steps")
    assert isinstance(steps, Sequence)
    architecture_steps = [
        index
        for index, step in enumerate(steps)
        if isinstance(step, Mapping) and step.get("name") == ARCHITECTURE_CHECK_STEP_NAME
    ]
    assert architecture_steps == [0]
    architecture_step = steps[architecture_steps[0]]
    assert isinstance(architecture_step, Mapping)
    assert set(architecture_step) == {"name", "shell", "run"}
    assert architecture_step.get("shell") == ARCHITECTURE_CHECK_SHELL
    run = architecture_step.get("run")
    assert run == ARCHITECTURE_CHECK_SCRIPT
    for command in (
        MANAGED_SYNC_COMMAND,
        "pnpm install --frozen-lockfile",
        MAKE_CHECK_COMMAND,
    ):
        command_index = next(
            index
            for index, step in enumerate(steps)
            if isinstance(step, Mapping) and step.get("run") == command
        )
        assert command_index > architecture_steps[0]


def _literal_workflow_root_keys(raw: str) -> list[str]:
    root = yaml.compose(raw, Loader=yaml.SafeLoader)
    assert isinstance(root, MappingNode)
    keys: list[str] = []
    for key, _value in root.value:
        assert isinstance(key, ScalarNode)
        assert key.style is None
        assert raw[key.start_mark.index : key.end_mark.index] == key.value
        keys.append(key.value)
    return keys


def _assert_literal_workflow_on_spelling(raw: str) -> None:
    assert "on" in _literal_workflow_root_keys(raw)


def _assert_literal_workflow_root(raw: str) -> None:
    keys = _literal_workflow_root_keys(raw)
    assert keys == ["name", "on", "permissions", "jobs"]


def _dump_workflow_mutation(workflow: object) -> str:
    assert isinstance(workflow, dict)
    rendered = yaml.safe_dump(workflow, sort_keys=False)
    lines = rendered.splitlines(keepends=True)
    normalized = [index for index, line in enumerate(lines) if line == "true:\n"]
    assert len(normalized) == 1
    lines[normalized[0]] = "on:\n"
    canonical = "".join(lines)
    _assert_literal_workflow_on_spelling(canonical)
    assert yaml.safe_load(canonical) == workflow
    return canonical


def _write_workflow_mutation(path: Path, workflow: object) -> None:
    path.write_text(_dump_workflow_mutation(workflow), encoding="utf-8")


def _assert_mutation_reaches_policy(
    path: Path,
    *,
    root_shape_is_target: bool = False,
) -> None:
    raw = path.read_text(encoding="utf-8")
    _assert_literal_workflow_on_spelling(raw)
    if not root_shape_is_target:
        _assert_literal_workflow_root(raw)


def test_workflow_mutation_roundtrip_preserves_literal_on_key() -> None:
    workflow = yaml.safe_load((WORKFLOW_ROOT / "ci.yml").read_text(encoding="utf-8"))

    rendered = _dump_workflow_mutation(workflow)

    _assert_literal_workflow_root(rendered)
    assert yaml.safe_load(rendered) == workflow


def test_foundation_plan_workflow_snippets_use_fixed_portability_contract() -> None:
    text = FOUNDATION_PLAN.read_text(encoding="utf-8")

    assert re.search(r"(?<![\w/])uname -m", text) is None
    assert re.search(r"(?m)^\s*shell:\s*bash\s*$", text) is None
    assert 'get("shell") == "bash"' not in text
    assert text.count('actual="$(/usr/bin/uname -m)"') == 4
    assert text.count(ARCHITECTURE_CHECK_SHELL) >= 3


def test_foundation_plan_acceptance_requires_every_mandatory_ci_row() -> None:
    text = FOUNDATION_PLAN.read_text(encoding="utf-8")
    task_7_acceptance = text.split(
        "- [ ] **Step 8: Require the committed three-row acceptance matrix**", 1
    )[1].split("### Task 8:", 1)[0]
    task_9_acceptance = text.split("- [ ] **Step 8: Require same-SHA three-row acceptance**", 1)[
        1
    ].split("### Task 10:", 1)[0]
    for section in (task_7_acceptance, task_9_acceptance):
        section = " ".join(section.split())
        assert (
            re.search(
                r"\bboth(?:\s+hosted)?\s+(?:jobs|checks)\b|\brequire both\b",
                section,
                re.IGNORECASE,
            )
            is None
        )
        for row in FOUNDATION_ACCEPTANCE_ROWS:
            assert row in section
        assert FOUNDATION_ACTIVE_HOST_RULING in section


def _assert_workflow_policy(path: Path) -> None:
    assert path.is_file() and not path.is_symlink()
    raw = path.read_text(encoding="utf-8")
    _assert_literal_workflow_root(raw)
    lowered = raw.lower()
    for forbidden in (
        "contents: write",
        "pages: write",
        "gh release create",
        "git tag ",
        "npm publish",
        "pnpm publish",
        "twine upload",
        "reachy_hardware",
        "live_cloud",
    ):
        assert forbidden not in lowered, (path, forbidden)
    workflow = yaml.safe_load(raw)
    assert isinstance(workflow, dict) and isinstance(workflow.get("jobs"), dict)
    assert set(workflow) == {"name", True, "permissions", "jobs"}
    assert workflow["name"] == "ci"
    assert workflow[True] == ["push", "pull_request"]
    _assert_permissions(workflow, required=True)
    _assert_no_secret_channel(workflow)
    jobs = workflow["jobs"]
    assert set(jobs) == {"contracts-edge-python311", "check"}
    contract_job = jobs["contracts-edge-python311"]
    check_job = jobs["check"]
    assert contract_job == {
        "runs-on": "ubuntu-24.04",
        "steps": CONTRACT_STEPS,
    }
    assert set(check_job) == {"strategy", "runs-on", "steps"}
    assert check_job["runs-on"] == MATRIX_RUNNER
    assert check_job["steps"] == CHECK_STEPS
    _assert_strategy_matches_runner(check_job)
    _assert_matrix_job_checks_expected_architecture(check_job)
    for job in jobs.values():
        assert isinstance(job, dict)
        for step in job["steps"]:
            if "uses" in step:
                _assert_uses_is_immutable(step["uses"])
            else:
                assert step["shell"] == ARCHITECTURE_CHECK_SHELL
                run = step["run"]
                assert "GITHUB_PATH" not in run
                assert "GITHUB_ENV" not in run


def test_every_yml_and_yaml_workflow_has_only_fixed_runners_and_full_sha_actions() -> None:
    for path in workflow_paths():
        _assert_workflow_policy(path)


def test_ci_matrix_remains_exact() -> None:
    workflow = yaml.safe_load((WORKFLOW_ROOT / "ci.yml").read_text())
    assert workflow["jobs"]["check"]["strategy"]["matrix"] == {
        "os": ["ubuntu-24.04", "macos-26", "macos-15-intel"],
    }


def test_ci_check_asserts_expected_architectures_before_dependency_installation() -> None:
    workflow = yaml.safe_load((WORKFLOW_ROOT / "ci.yml").read_text())
    _assert_matrix_job_checks_expected_architecture(workflow["jobs"]["check"])


def test_ci_check_requires_an_owner_controlled_managed_python_runtime() -> None:
    workflow = yaml.safe_load((WORKFLOW_ROOT / "ci.yml").read_text())
    steps = workflow["jobs"]["check"]["steps"]

    sync_steps = [step for step in steps if str(step.get("run", "")).startswith("uv sync")]
    assert sync_steps == [
        {
            "shell": ARCHITECTURE_CHECK_SHELL,
            "run": MANAGED_SYNC_COMMAND,
        }
    ]
    task_9_acceptance = (
        FOUNDATION_PLAN.read_text(encoding="utf-8")
        .split("- [ ] **Step 8: Require same-SHA three-row acceptance**", 1)[1]
        .split("### Task 10:", 1)[0]
    )
    assert MANAGED_SYNC_COMMAND in task_9_acceptance


@pytest.mark.parametrize("yaml_11_alias", ("yes", "true"))
def test_workflow_trigger_key_must_be_spelled_literal_on(
    yaml_11_alias: str,
    tmp_path: Path,
) -> None:
    raw = (WORKFLOW_ROOT / "ci.yml").read_text(encoding="utf-8")
    mutated = raw.replace("\non:", f"\n{yaml_11_alias}:", 1)
    assert mutated != raw
    assert yaml.safe_load(mutated) == yaml.safe_load(raw)
    path = tmp_path / "ci.yml"
    path.write_text(mutated, encoding="utf-8")

    with pytest.raises(AssertionError):
        _assert_workflow_policy(path)


@pytest.mark.parametrize("nonliteral_spelling", ('"on"', "'on'", "!!bool on"))
def test_workflow_root_keys_reject_quoted_or_tagged_spellings(
    nonliteral_spelling: str,
    tmp_path: Path,
) -> None:
    raw = (WORKFLOW_ROOT / "ci.yml").read_text(encoding="utf-8")
    mutated = raw.replace("\non:", f"\n{nonliteral_spelling}:", 1)
    assert mutated != raw
    path = tmp_path / "ci.yml"
    path.write_text(mutated, encoding="utf-8")

    with pytest.raises(AssertionError):
        _assert_workflow_policy(path)


@pytest.mark.parametrize(
    "mutation",
    (
        "comment_only",
        "reordered",
        "changed_command",
        "relative_uname",
        "extra_step_key",
        "step_if",
        "step_continue",
        "step_env_path",
        "job_if",
        "job_continue",
        "job_env_bash_env",
        "workflow_env_path",
        "matrix_exclude",
        "matrix_fail_fast",
        "matrix_remove_runner",
    ),
)
def test_architecture_assertion_mutations_fail_full_workflow_policy(
    mutation: str,
    tmp_path: Path,
) -> None:
    workflow = yaml.safe_load((WORKFLOW_ROOT / "ci.yml").read_text())
    workflow = deepcopy(workflow)
    job = workflow["jobs"]["check"]
    steps = job["steps"]
    architecture_step = next(
        step for step in steps if step.get("name") == ARCHITECTURE_CHECK_STEP_NAME
    )
    if mutation == "comment_only":
        architecture_step["run"] = (
            "# uname -m ubuntu-24.04 x86_64 macos-26 arm64 macos-15-intel\ntrue\n"
        )
    elif mutation == "reordered":
        steps.remove(architecture_step)
        steps.insert(1, architecture_step)
    elif mutation == "changed_command":
        architecture_step["run"] = ARCHITECTURE_CHECK_SCRIPT.replace(
            'actual="$(/usr/bin/uname -m)"', 'actual="arm64"'
        )
    elif mutation == "relative_uname":
        architecture_step["run"] = ARCHITECTURE_CHECK_SCRIPT.replace("/usr/bin/uname", "uname")
    elif mutation == "extra_step_key":
        architecture_step["timeout-minutes"] = 1
    elif mutation == "step_if":
        architecture_step["if"] = "${{ false }}"
    elif mutation == "step_continue":
        architecture_step["continue-on-error"] = True
    elif mutation == "step_env_path":
        architecture_step["env"] = {"PATH": "/tmp/private-shim"}
    elif mutation == "job_if":
        job["if"] = "${{ false }}"
    elif mutation == "job_continue":
        job["continue-on-error"] = True
    elif mutation == "job_env_bash_env":
        job["env"] = {"BASH_ENV": "/tmp/private-bootstrap"}
    elif mutation == "workflow_env_path":
        workflow["env"] = {"PATH": "/tmp/private-shim"}
    elif mutation == "matrix_exclude":
        job["strategy"]["matrix"]["exclude"] = [{"os": "macos-15-intel"}]
    elif mutation == "matrix_fail_fast":
        job["strategy"]["fail-fast"] = True
    else:
        job["strategy"]["matrix"]["os"].remove("macos-15-intel")

    path = tmp_path / "ci.yml"
    _write_workflow_mutation(path, workflow)
    _assert_mutation_reaches_policy(
        path,
        root_shape_is_target=mutation == "workflow_env_path",
    )
    with pytest.raises(AssertionError):
        _assert_workflow_policy(path)


def test_ci_is_unprivileged_and_has_no_hardware_or_provider_secrets() -> None:
    text = (WORKFLOW_ROOT / "ci.yml").read_text()
    workflow = yaml.safe_load(text)
    assert workflow["permissions"] == {"contents": "read"}
    assert "secrets." not in text
    assert "reachy_hardware" not in text and "live_cloud" not in text


def test_discovery_includes_later_yml_and_yaml_and_mutations_fail(tmp_path: Path) -> None:
    root = tmp_path / ".github" / "workflows"
    root.mkdir(parents=True)
    valid = yaml.safe_load((WORKFLOW_ROOT / "ci.yml").read_text())
    _write_workflow_mutation(root / "security.yml", valid)
    _write_workflow_mutation(root / "release.yaml", valid)
    assert {path.name for path in workflow_paths(root)} == {"security.yml", "release.yaml"}
    for name, mutation in (
        ("security.yml", {"runs-on": "ubuntu-latest"}),
        ("release.yaml", {"steps": [{"uses": "actions/checkout@v4"}]}),
        ("security.yml", {"steps": [{"run": "gh release create v1"}]}),
        ("release.yaml", {"steps": [{"run": "echo ${{ secrets.TOKEN }}"}]}),
        ("security.yml", {"steps": [{"run": "echo ${{ secrets['TOKEN'] }}"}]}),
        ("release.yaml", {"permissions": {"contents": "write"}}),
        ("security.yml", {"permissions": {"issues": "write"}}),
        ("release.yaml", {"permissions": None}),
        (
            "security.yml",
            {
                "runs-on": "${{ matrix.os }}",
                "strategy": {
                    "matrix": {
                        "os": ["ubuntu-24.04", "macos-15-intel"],
                        "include": [{"os": "self-hosted"}],
                    }
                },
            },
        ),
        (
            "release.yaml",
            {
                "runs-on": "${{ matrix.os }}",
                "strategy": {
                    "matrix": {
                        "os": ["ubuntu-24.04", "macos-15-intel"],
                        "exclude": [{"os": "ubuntu-24.04"}],
                    }
                },
            },
        ),
        ("security.yml", {"strategy": {"matrix": {"python": ["3.12"]}}}),
        (
            "release.yaml",
            {
                "strategy": {
                    "matrix": {
                        "os": ["ubuntu-24.04", "macos-15-intel"],
                        "include": [{"os": "ubuntu-24.04"}],
                    }
                }
            },
        ),
        (
            "security.yml",
            {
                "strategy": {
                    "matrix": {
                        "os": ["ubuntu-24.04", "macos-15-intel"],
                        "exclude": [{"os": "macos-15-intel"}],
                    }
                }
            },
        ),
        (
            "release.yaml",
            {
                "runs-on": "${{ matrix.os }}",
                "strategy": {
                    "matrix": {
                        "os": ["ubuntu-24.04", "macos-15-intel"],
                        "python": ["3.12"],
                    }
                },
            },
        ),
    ):
        changed = {
            **valid,
            "jobs": {
                **valid["jobs"],
                "check": {**valid["jobs"]["check"], **mutation},
            },
        }
        path = root / name
        _write_workflow_mutation(path, changed)
        _assert_mutation_reaches_policy(path)
        with pytest.raises(AssertionError):
            _assert_workflow_policy(path)
        _write_workflow_mutation(path, valid)
    privileged = {**valid, "permissions": {"contents": "write"}}
    path = root / "release.yaml"
    _write_workflow_mutation(path, privileged)
    _assert_mutation_reaches_policy(path)
    with pytest.raises(AssertionError):
        _assert_workflow_policy(path)

    for reusable in (
        {"uses": "owner/repository/.github/workflows/reuse.yml@" + "b" * 40, "secrets": "inherit"},
        {
            "uses": "owner/repository/.github/workflows/reuse.yml@" + "b" * 40,
            "secrets": {"token": "${{ secrets['TOKEN'] }}"},
        },
        {
            "uses": "owner/repository/.github/workflows/reuse.yml@" + "b" * 40,
            "permissions": {"actions": "write"},
        },
        {
            "uses": "owner/repository/.github/workflows/reuse.yml@" + "b" * 40,
            "strategy": {"matrix": {"python": ["3.12"]}},
        },
    ):
        workflow_with_reusable_job = {**valid, "jobs": {"reuse": reusable}}
        _write_workflow_mutation(path, workflow_with_reusable_job)
        _assert_mutation_reaches_policy(path)
        with pytest.raises(AssertionError):
            _assert_workflow_policy(path)


def test_ci_check_uses_short_per_run_pytest_basetemp() -> None:
    workflow = yaml.safe_load((WORKFLOW_ROOT / "ci.yml").read_text())

    assert workflow["jobs"]["check"]["steps"][-1] == {
        "run": (
            "PYTEST_ADDOPTS=--basetemp=/tmp/t7-${{ github.run_id }}-"
            "${{ github.run_attempt }} /usr/bin/make check"
        ),
        "shell": ARCHITECTURE_CHECK_SHELL,
    }


def test_every_run_step_uses_the_fixed_hardened_shell() -> None:
    workflow = yaml.safe_load((WORKFLOW_ROOT / "ci.yml").read_text())

    for job in workflow["jobs"].values():
        for step in job["steps"]:
            if "run" in step:
                assert step["shell"] == ARCHITECTURE_CHECK_SHELL


@pytest.mark.parametrize(
    "mutation",
    (
        "workflow_defaults",
        "workflow_extra_key",
        "extra_job",
        "job_defaults",
        "job_extra_key",
        "run_shell_true",
        "run_extra_key",
        "action_extra_key",
        "github_path_make_shim",
        "github_env_bash_env",
        "extra_action",
        "reordered_steps",
        "removed_step",
        "duplicate_step",
    ),
)
def test_ci_rejects_unreviewed_structure_and_environment_file_mutations(
    mutation: str,
    tmp_path: Path,
) -> None:
    workflow = deepcopy(yaml.safe_load((WORKFLOW_ROOT / "ci.yml").read_text()))
    check_job = workflow["jobs"]["check"]
    steps = check_job["steps"]
    if mutation == "workflow_defaults":
        workflow["defaults"] = {"run": {"shell": "/bin/true"}}
    elif mutation == "workflow_extra_key":
        workflow["concurrency"] = {"cancel-in-progress": True}
    elif mutation == "extra_job":
        workflow["jobs"]["neutralize"] = {
            "runs-on": "ubuntu-24.04",
            "steps": [{"run": "/bin/true"}],
        }
    elif mutation == "job_defaults":
        check_job["defaults"] = {"run": {"shell": "/bin/true"}}
    elif mutation == "job_extra_key":
        check_job["timeout-minutes"] = 1
    elif mutation == "run_shell_true":
        steps[-1]["shell"] = "/bin/true"
    elif mutation == "run_extra_key":
        steps[-1]["timeout-minutes"] = 1
    elif mutation == "action_extra_key":
        steps[1]["shell"] = "/bin/true"
    elif mutation == "github_path_make_shim":
        steps.insert(
            -1,
            {
                "shell": ARCHITECTURE_CHECK_SHELL,
                "run": 'echo "/tmp/make-shim" >> "$GITHUB_PATH"',
            },
        )
    elif mutation == "github_env_bash_env":
        steps.insert(
            -1,
            {
                "shell": ARCHITECTURE_CHECK_SHELL,
                "run": 'echo "BASH_ENV=/tmp/bootstrap" >> "$GITHUB_ENV"',
            },
        )
    elif mutation == "extra_action":
        steps.insert(1, {"uses": "actions/checkout@" + "a" * 40})
    elif mutation == "reordered_steps":
        steps[1], steps[2] = steps[2], steps[1]
    elif mutation == "removed_step":
        steps.pop(1)
    else:
        steps.insert(2, deepcopy(steps[1]))

    path = tmp_path / "ci.yml"
    _write_workflow_mutation(path, workflow)
    _assert_mutation_reaches_policy(
        path,
        root_shape_is_target=mutation in {"workflow_defaults", "workflow_extra_key"},
    )
    with pytest.raises(AssertionError):
        _assert_workflow_policy(path)
