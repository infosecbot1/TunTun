import importlib.util
import io
import json
import re
import subprocess
import sys
import tarfile
import tomllib
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from types import ModuleType

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
            "tests/unit/edge/test_reachy_ptt.py --confcutdir=tests/contract -q"
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
OPENSSH_LOCK_PATH = Path(".github/ci/openssh-ubuntu-24.04.lock")
OPENSSH_DOWNLOAD_ROOT = "/tmp/t4-openssh-${{ github.run_id }}-${{ github.run_attempt }}"
OPENSSH_VERIFY_DOWNLOAD_COMMAND = (
    "python .github/ci/verify_openssh_ubuntu_lock.py verify-download "
    "--lock-path .github/ci/openssh-ubuntu-24.04.lock "
    f"--download-root {OPENSSH_DOWNLOAD_ROOT}"
)
OPENSSH_INSTALL_COMMAND = (
    "sudo /usr/bin/python3 .github/ci/verify_openssh_ubuntu_lock.py install "
    "--lock-path .github/ci/openssh-ubuntu-24.04.lock "
    f"--download-root {OPENSSH_DOWNLOAD_ROOT}"
)
OPENSSH_VERIFY_INSTALLED_COMMAND = (
    "python .github/ci/verify_openssh_ubuntu_lock.py verify-installed "
    "--lock-path .github/ci/openssh-ubuntu-24.04.lock"
)
OPENSSH_CONTRACT_COMMAND = (
    "PYTEST_ADDOPTS=--basetemp=/tmp/t4-openssh-test-${{ github.run_id }}-"
    "${{ github.run_attempt }} .venv/bin/pytest "
    "tests/integration/test_ssh_forced_command_local.py -q"
)
BOOTSTRAP_KEYRING_TAR_PATH = "usr/share/keyrings/ubuntu-archive-keyring.gpg"


def _load_openssh_verifier() -> ModuleType:
    module_name = f"_tuntun_openssh_verifier_under_test_{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(
        module_name,
        Path(".github/ci/verify_openssh_ubuntu_lock.py"),
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _ar_member(name: str, body: bytes) -> bytes:
    header = (f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{0o100644:<8}{len(body):<10}`\n").encode("ascii")
    return header + body + (b"\n" if len(body) % 2 else b"")


def _bootstrap_keyring_deb_stub() -> bytes:
    return (
        b"!<arch>\n"
        + _ar_member("debian-binary", b"2.0\n")
        + _ar_member(
            "data.tar.zst",
            b"synthetic-compressed-tar",
        )
    )


def _tar_file(
    name: str,
    body: bytes = b"keyring",
    *,
    mode: int = 0o644,
    uid: int = 0,
    gid: int = 0,
) -> tuple[tarfile.TarInfo, bytes | None]:
    member = tarfile.TarInfo(name)
    member.type = tarfile.REGTYPE
    member.mode = mode
    member.uid = uid
    member.gid = gid
    member.size = len(body)
    return member, body


def _tar_special(
    name: str,
    member_type: bytes,
    *,
    linkname: str = "",
) -> tuple[tarfile.TarInfo, bytes | None]:
    member = tarfile.TarInfo(name)
    member.type = member_type
    member.mode = 0o644
    member.uid = 0
    member.gid = 0
    member.linkname = linkname
    member.size = 0
    return member, None


def _tar_raw(*members: tuple[tarfile.TarInfo, bytes | None]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for member, body in members:
            archive.addfile(member, None if body is None else io.BytesIO(body))
    return output.getvalue()


def _install_bootstrap_keyring_fakes(
    module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tar_raw: bytes,
) -> None:
    monkeypatch.setattr(module, "fetch_url", lambda _url: _bootstrap_keyring_deb_stub())

    def fake_run(
        argv: Sequence[str],
        *,
        check: bool,
        capture_output: bool,
    ) -> subprocess.CompletedProcess[bytes]:
        assert argv[:2] == ["zstd", "-dc"]
        assert check is True
        assert capture_output is True
        return subprocess.CompletedProcess(argv, 0, stdout=tar_raw)

    monkeypatch.setattr(module.subprocess, "run", fake_run)


OPENSSH_STEPS = [
    {"uses": CHECKOUT_ACTION},
    {"uses": SETUP_UV_ACTION, "with": {"version": "0.8.13", "enable-cache": True}},
    {"shell": ARCHITECTURE_CHECK_SHELL, "run": "uv sync --all-packages --locked --managed-python"},
    {"shell": ARCHITECTURE_CHECK_SHELL, "run": OPENSSH_VERIFY_DOWNLOAD_COMMAND},
    {"shell": ARCHITECTURE_CHECK_SHELL, "run": OPENSSH_INSTALL_COMMAND},
    {"shell": ARCHITECTURE_CHECK_SHELL, "run": OPENSSH_VERIFY_INSTALLED_COMMAND},
    {"shell": ARCHITECTURE_CHECK_SHELL, "run": OPENSSH_CONTRACT_COMMAND},
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
        "cryptography>=45,<46",
        "packaging>=26,<27",
        "tuntun-contracts==0.1.0.dev0",
        "typer>=0.16,<1",
        "websockets==15.0.1",
    ]
    assert edge_project["project"]["scripts"] == {"tuntun-edge": "tuntun_edge.cli.main:main"}
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
    assert set(jobs) == {"contracts-edge-python311", "openssh-forced-command-local", "check"}
    contract_job = jobs["contracts-edge-python311"]
    openssh_job = jobs["openssh-forced-command-local"]
    check_job = jobs["check"]
    assert contract_job == {
        "runs-on": "ubuntu-24.04",
        "steps": CONTRACT_STEPS,
    }
    assert openssh_job == {
        "runs-on": "ubuntu-24.04",
        "steps": OPENSSH_STEPS,
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


def test_openssh_lock_freezes_signed_ubuntu_origin_and_openssh_package_set() -> None:
    lock = json.loads(OPENSSH_LOCK_PATH.read_text(encoding="utf-8"))

    assert lock["schema_version"] == "tuntun.openssh-ubuntu-24.04.lock.v1"
    assert lock["runner"] == "ubuntu-24.04"
    closure_scope = lock["closure_scope"]
    assert closure_scope == {
        "locked_package_set": (
            "Complete transitive Depends/Pre-Depends closure for openssh-client, "
            "openssh-server, and openssh-sftp-server on Ubuntu 24.04 amd64 from signed "
            "main archive pockets."
        ),
        "closure_status": "complete_signed_packages_closure",
        "root_packages": ["openssh-client", "openssh-server", "openssh-sftp-server"],
        "dependency_fields": ["Pre-Depends", "Depends"],
        "components": ["main"],
        "architectures": ["amd64", "all"],
        "suites": ["noble", "noble-updates", "noble-security"],
    }
    assert "base_dependency_policy" not in closure_scope
    assert "blocker" not in closure_scope

    signed_origins = lock["signed_origins"]
    assert isinstance(signed_origins, list)
    assert {origin["suite"] for origin in signed_origins} == {
        "noble",
        "noble-updates",
        "noble-security",
    }
    for origin in signed_origins:
        assert set(origin) == {
            "id",
            "origin",
            "suite",
            "component",
            "architecture",
            "base_url",
            "inrelease_url",
            "inrelease_size_bytes",
            "inrelease_sha256",
        }
        assert origin["origin"] == "Ubuntu"
        assert origin["component"] == "main"
        assert origin["architecture"] == "amd64"
        assert origin["base_url"] in {
            "https://archive.ubuntu.com/ubuntu/",
            "https://security.ubuntu.com/ubuntu/",
        }
        assert origin["inrelease_url"] == (f"{origin['base_url']}dists/{origin['suite']}/InRelease")
        assert isinstance(origin["inrelease_size_bytes"], int)
        assert origin["inrelease_size_bytes"] > 0
        assert re.fullmatch(r"[0-9a-f]{64}", origin["inrelease_sha256"])

    package_indexes = lock["package_indexes"]
    assert isinstance(package_indexes, list)
    assert {index["suite"] for index in package_indexes} == {
        "noble",
        "noble-updates",
        "noble-security",
    }
    origin_ids = {origin["id"] for origin in signed_origins}
    for index in package_indexes:
        assert set(index) == {
            "id",
            "origin_id",
            "suite",
            "component",
            "architecture",
            "relative_path",
            "url",
            "size_bytes",
            "sha256",
            "compression",
        }
        assert index["origin_id"] in origin_ids
        assert index["component"] == "main"
        assert index["architecture"] == "amd64"
        assert index["relative_path"] == "main/binary-amd64/Packages.xz"
        assert index["url"].endswith(f"dists/{index['suite']}/main/binary-amd64/Packages.xz")
        assert isinstance(index["size_bytes"], int)
        assert index["size_bytes"] > 0
        assert re.fullmatch(r"[0-9a-f]{64}", index["sha256"])
        assert index["compression"] == "xz"

    packages = lock["packages"]
    assert isinstance(packages, list)
    assert len(packages) > 3
    names = [package["name"] for package in packages]
    assert names == sorted(names)
    assert {"openssh-client", "openssh-server", "openssh-sftp-server"}.issubset(names)
    index_ids = {index["id"] for index in package_indexes}
    for package in packages:
        assert set(package) == {
            "name",
            "version",
            "architecture",
            "source_index_id",
            "filename",
            "url",
            "size_bytes",
            "sha256",
            "record_sha256",
            "pre_depends",
            "depends",
            "provides",
        }
        assert package["architecture"] in {"amd64", "all"}
        assert package["source_index_id"] in index_ids
        assert package["filename"].startswith("pool/main/")
        assert package["url"].startswith(
            (
                "https://archive.ubuntu.com/ubuntu/pool/main/",
                "https://security.ubuntu.com/ubuntu/pool/main/",
            )
        )
        assert package["url"].endswith(package["filename"])
        assert package["filename"].endswith(".deb")
        assert isinstance(package["size_bytes"], int) and package["size_bytes"] > 0
        assert re.fullmatch(r"[0-9a-f]{64}", package["sha256"])
        assert re.fullmatch(r"[0-9a-f]{64}", package["record_sha256"])
        assert isinstance(package["pre_depends"], list)
        assert isinstance(package["depends"], list)
        assert isinstance(package["provides"], list)


def test_openssh_lock_has_no_unresolved_dependency_names() -> None:
    lock = json.loads(OPENSSH_LOCK_PATH.read_text(encoding="utf-8"))
    package_names = {package["name"] for package in lock["packages"]}
    provided_names = {
        provided.split(" ", 1)[0]
        for package in lock["packages"]
        for provided in package["provides"]
    }
    satisfied_names = package_names | provided_names
    unresolved: set[str] = set()
    relation_pattern = re.compile(r"^\s*([A-Za-z0-9.+-]+)")
    for package in lock["packages"]:
        for field in ("pre_depends", "depends"):
            for relation_group in package[field]:
                alternatives = relation_group.split("|")
                if not any(
                    (match := relation_pattern.match(alternative))
                    and match.group(1) in satisfied_names
                    for alternative in alternatives
                ):
                    unresolved.add(f"{package['name']}: {relation_group}")
    assert unresolved == set()


def test_openssh_verifier_script_is_present_for_signed_metadata_and_closure_checks() -> None:
    script = Path(".github/ci/verify_openssh_ubuntu_lock.py")
    text = script.read_text(encoding="utf-8")

    for required in (
        "gpgv",
        "InRelease",
        "Packages.xz",
        "verify_complete_dependency_closure",
        "verify_package_records",
        "download_packages",
        "verify_installed_packages",
    ):
        assert required in text


def test_locked_package_install_replays_only_the_verified_closure_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = _load_openssh_verifier()
    packages = (
        {"filename": "pool/main/libpam-modules-bin.deb"},
        {"filename": "pool/main/libpam-modules.deb"},
    )
    calls: list[tuple[list[str], bool]] = []

    monkeypatch.setattr(
        verifier,
        "verify_downloaded_packages",
        lambda _lock, *, download_root: None,
    )
    monkeypatch.setattr(verifier, "package_install_order", lambda _lock: packages)

    def fake_run(argv: list[str], *, check: bool) -> subprocess.CompletedProcess[bytes]:
        calls.append((argv, check))
        return subprocess.CompletedProcess(argv, 1 if len(calls) == 1 else 0)

    monkeypatch.setattr(verifier.subprocess, "run", fake_run)

    verifier.install_packages({"packages": []}, download_root=tmp_path)

    expected_argv = [
        "dpkg",
        "-i",
        str(tmp_path / "libpam-modules-bin.deb"),
        str(tmp_path / "libpam-modules.deb"),
    ]
    assert calls == [(expected_argv, False), (expected_argv, True)]


def test_locked_package_install_does_not_replay_a_successful_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = _load_openssh_verifier()
    packages = ({"filename": "pool/main/libpam-modules-bin.deb"},)
    calls: list[tuple[list[str], bool]] = []

    monkeypatch.setattr(
        verifier,
        "verify_downloaded_packages",
        lambda _lock, *, download_root: None,
    )
    monkeypatch.setattr(verifier, "package_install_order", lambda _lock: packages)

    def fake_run(argv: list[str], *, check: bool) -> subprocess.CompletedProcess[bytes]:
        calls.append((argv, check))
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(verifier.subprocess, "run", fake_run)

    verifier.install_packages({"packages": []}, download_root=tmp_path)

    assert calls == [(["dpkg", "-i", str(tmp_path / "libpam-modules-bin.deb")], False)]


def test_identity_fixture_plugin_is_registered_only_at_test_root() -> None:
    root_conftest = Path("tests/conftest.py").read_text(encoding="utf-8")
    assert 'pytest_plugins = ("tests.identity_support",)' in root_conftest
    assert not Path("tests/unit/identity/conftest.py").exists()
    assert not Path("tests/integration/identity/conftest.py").exists()


def test_bootstrap_keyring_tar_extraction_extracts_only_required_keyring(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = _load_openssh_verifier()
    tar_raw = _tar_raw(
        _tar_file(BOOTSTRAP_KEYRING_TAR_PATH, b"synthetic-keyring"),
        _tar_file("usr/share/doc/ubuntu-keyring/changelog", b"doc"),
    )
    _install_bootstrap_keyring_fakes(verifier, monkeypatch, tar_raw)
    work_root = tmp_path / "work"
    work_root.mkdir()

    keyring = verifier.extract_bootstrap_keyring(work_root=work_root)

    assert keyring == work_root / BOOTSTRAP_KEYRING_TAR_PATH
    assert keyring.read_bytes() == b"synthetic-keyring"
    assert not (work_root / "usr/share/doc/ubuntu-keyring/changelog").exists()


@pytest.mark.parametrize(
    "hostile_member",
    (
        _tar_file("../escape", b"x"),
        _tar_special("usr/share/doc/link", tarfile.SYMTYPE, linkname="../escape"),
        _tar_special(
            "usr/share/doc/hardlink",
            tarfile.LNKTYPE,
            linkname=BOOTSTRAP_KEYRING_TAR_PATH,
        ),
        _tar_special("usr/share/doc/fifo", tarfile.FIFOTYPE),
        _tar_special("usr/share/doc/device", tarfile.CHRTYPE),
        _tar_file(BOOTSTRAP_KEYRING_TAR_PATH, b"synthetic-keyring", mode=0o666),
        _tar_file(BOOTSTRAP_KEYRING_TAR_PATH, b"synthetic-keyring", uid=501),
    ),
)
def test_bootstrap_keyring_tar_extraction_rejects_unsafe_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    hostile_member: tuple[tarfile.TarInfo, bytes | None],
) -> None:
    verifier = _load_openssh_verifier()
    members = [hostile_member]
    if hostile_member[0].name != BOOTSTRAP_KEYRING_TAR_PATH:
        members.insert(0, _tar_file(BOOTSTRAP_KEYRING_TAR_PATH, b"synthetic-keyring"))
    tar_raw = _tar_raw(*members)
    _install_bootstrap_keyring_fakes(verifier, monkeypatch, tar_raw)
    work_root = tmp_path / "work"
    work_root.mkdir()

    with pytest.raises(SystemExit, match="unsafe bootstrap keyring tar member"):
        verifier.extract_bootstrap_keyring(work_root=work_root)

    assert not (tmp_path / "escape").exists()


def test_bootstrap_keyring_tar_extraction_rejects_absolute_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = _load_openssh_verifier()
    absolute_escape = tmp_path / "absolute-escape"
    tar_raw = _tar_raw(
        _tar_file(BOOTSTRAP_KEYRING_TAR_PATH, b"synthetic-keyring"),
        _tar_file(str(absolute_escape), b"x"),
    )
    _install_bootstrap_keyring_fakes(verifier, monkeypatch, tar_raw)
    work_root = tmp_path / "work"
    work_root.mkdir()

    with pytest.raises(SystemExit, match="unsafe bootstrap keyring tar member"):
        verifier.extract_bootstrap_keyring(work_root=work_root)

    assert not absolute_escape.exists()


def test_bootstrap_keyring_tar_extraction_rejects_duplicate_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = _load_openssh_verifier()
    tar_raw = _tar_raw(
        _tar_file(BOOTSTRAP_KEYRING_TAR_PATH, b"one"),
        _tar_file(BOOTSTRAP_KEYRING_TAR_PATH, b"two"),
    )
    _install_bootstrap_keyring_fakes(verifier, monkeypatch, tar_raw)
    work_root = tmp_path / "work"
    work_root.mkdir()

    with pytest.raises(SystemExit, match="duplicate bootstrap keyring tar member"):
        verifier.extract_bootstrap_keyring(work_root=work_root)


def test_bootstrap_keyring_tar_extraction_rejects_member_count_and_byte_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = _load_openssh_verifier()
    monkeypatch.setattr(verifier, "BOOTSTRAP_KEYRING_MAX_TAR_MEMBERS", 1, raising=False)
    tar_raw = _tar_raw(
        _tar_file(BOOTSTRAP_KEYRING_TAR_PATH, b"synthetic-keyring"),
        _tar_file("usr/share/doc/ubuntu-keyring/changelog", b"doc"),
    )
    _install_bootstrap_keyring_fakes(verifier, monkeypatch, tar_raw)
    work_root = tmp_path / "work"
    work_root.mkdir()

    with pytest.raises(SystemExit, match="bootstrap keyring tar member count exceeded"):
        verifier.extract_bootstrap_keyring(work_root=work_root)

    verifier = _load_openssh_verifier()
    monkeypatch.setattr(verifier, "BOOTSTRAP_KEYRING_MAX_FILE_BYTES", 8, raising=False)
    tar_raw = _tar_raw(_tar_file(BOOTSTRAP_KEYRING_TAR_PATH, b"123456789"))
    _install_bootstrap_keyring_fakes(verifier, monkeypatch, tar_raw)
    with pytest.raises(SystemExit, match="bootstrap keyring tar member size exceeded"):
        verifier.extract_bootstrap_keyring(work_root=work_root)

    verifier = _load_openssh_verifier()
    monkeypatch.setattr(verifier, "BOOTSTRAP_KEYRING_MAX_TOTAL_BYTES", 8, raising=False)
    tar_raw = _tar_raw(
        _tar_file(BOOTSTRAP_KEYRING_TAR_PATH, b"1234567"),
        _tar_file("usr/share/doc/ubuntu-keyring/changelog", b"89"),
    )
    _install_bootstrap_keyring_fakes(verifier, monkeypatch, tar_raw)
    with pytest.raises(SystemExit, match="bootstrap keyring tar total size exceeded"):
        verifier.extract_bootstrap_keyring(work_root=work_root)


def test_openssh_contract_job_uses_only_the_locked_closure() -> None:
    workflow = yaml.safe_load((WORKFLOW_ROOT / "ci.yml").read_text())
    job = workflow["jobs"]["openssh-forced-command-local"]

    assert job == {
        "runs-on": "ubuntu-24.04",
        "steps": OPENSSH_STEPS,
    }
    rendered_commands = "\n".join(
        step.get("run", "") for step in job["steps"] if isinstance(step, Mapping)
    ).casefold()
    assert "apt install" not in rendered_commands
    assert "apt-get install" not in rendered_commands
    assert "ubuntu-latest" not in rendered_commands
    assert "openssh-server" not in rendered_commands.replace(
        "openssh-ubuntu-24.04.lock",
        "",
    )


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
