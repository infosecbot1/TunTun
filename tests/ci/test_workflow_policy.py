import re
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
import yaml

FULL_SHA = re.compile(r"^[^@]+@[0-9a-f]{40}$")
FIXED_RUNNERS = {"ubuntu-24.04", "macos-15-intel"}
MATRIX_RUNNER = "${{ matrix.os }}"
APPROVED_MATRIX = {"os": ["ubuntu-24.04", "macos-15-intel"]}
WORKFLOW_ROOT = Path(".github/workflows")


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
    assert set(strategy) <= {"fail-fast", "matrix"}
    assert strategy["matrix"] == APPROVED_MATRIX


def _assert_workflow_policy(path: Path) -> None:
    assert path.is_file() and not path.is_symlink()
    raw = path.read_text()
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
    _assert_permissions(workflow, required=True)
    _assert_no_secret_channel(workflow)
    for job in workflow["jobs"].values():
        assert isinstance(job, dict)
        _assert_permissions(job, required=False)
        _assert_strategy_matches_runner(job)
        if "uses" in job:
            assert set(job) <= {
                "name",
                "needs",
                "if",
                "uses",
                "with",
                "permissions",
            }
            _assert_uses_is_immutable(job["uses"])
            continue
        runner = job["runs-on"]
        if isinstance(runner, str) and runner.startswith("${{"):
            assert runner == MATRIX_RUNNER
        else:
            assert runner in FIXED_RUNNERS
        for step in job.get("steps", []):
            if "uses" in step:
                _assert_uses_is_immutable(step["uses"])


def test_every_yml_and_yaml_workflow_has_only_fixed_runners_and_full_sha_actions() -> None:
    for path in workflow_paths():
        _assert_workflow_policy(path)


def test_ci_matrix_remains_exact() -> None:
    workflow = yaml.safe_load((WORKFLOW_ROOT / "ci.yml").read_text())
    assert workflow["jobs"]["check"]["strategy"]["matrix"] == {
        "os": ["ubuntu-24.04", "macos-15-intel"],
    }


def test_ci_is_unprivileged_and_has_no_hardware_or_provider_secrets() -> None:
    text = (WORKFLOW_ROOT / "ci.yml").read_text()
    workflow = yaml.safe_load(text)
    assert workflow["permissions"] == {"contents": "read"}
    assert "secrets." not in text
    assert "reachy_hardware" not in text and "live_cloud" not in text


def test_discovery_includes_later_yml_and_yaml_and_mutations_fail(tmp_path: Path) -> None:
    root = tmp_path / ".github" / "workflows"
    root.mkdir(parents=True)
    valid = {
        "permissions": {"contents": "read"},
        "jobs": {
            "check": {
                "runs-on": "ubuntu-24.04",
                "steps": [{"uses": "actions/checkout@" + "a" * 40}],
            }
        },
    }
    (root / "security.yml").write_text(yaml.safe_dump(valid))
    (root / "release.yaml").write_text(yaml.safe_dump(valid))
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
        changed = {**valid, "jobs": {"check": {**valid["jobs"]["check"], **mutation}}}
        path = root / name
        path.write_text(yaml.safe_dump(changed))
        with pytest.raises(AssertionError):
            _assert_workflow_policy(path)
        path.write_text(yaml.safe_dump(valid))
    privileged = {**valid, "permissions": {"contents": "write"}}
    path = root / "release.yaml"
    path.write_text(yaml.safe_dump(privileged))
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
        workflow_with_reusable_job = {
            "permissions": {"contents": "read"},
            "jobs": {"reuse": reusable},
        }
        path.write_text(yaml.safe_dump(workflow_with_reusable_job))
        with pytest.raises(AssertionError):
            _assert_workflow_policy(path)


def test_ci_check_uses_short_per_run_pytest_basetemp() -> None:
    workflow = yaml.safe_load((WORKFLOW_ROOT / "ci.yml").read_text())

    assert workflow["jobs"]["check"]["steps"][-1] == {
        "run": "make check",
        "env": {
            "PYTEST_ADDOPTS": ("--basetemp=/tmp/t7-${{ github.run_id }}-${{ github.run_attempt }}"),
        },
    }
