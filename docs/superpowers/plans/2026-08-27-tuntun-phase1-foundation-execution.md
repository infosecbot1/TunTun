# Tuntun Phase 1 Foundation Execution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build master work packages 01–06 from an otherwise empty repository, ending with strict version-1 contracts, fail-closed configuration and secrets, deterministic fakes/model governance, verified SQLCipher/record encryption, the exact `0001_foundation` schema, and a tamper-evident audit ledger.

**Architecture:** Establish four Python workspace packages and one minimal React application, then freeze project-owned contracts before adding adapters. Configuration, Keychain, model installation, SQLCipher, record encryption, migrations, transactions, and audit are separate ports/adapters with fail-closed boundaries; the only durable database produced by this plan is encrypted and contains exactly the tables owned by `0001_foundation.py`.

**Tech Stack:** Python 3.12 for the Mac core and repository tooling; Python 3.11/3.12-compatible edge/shared-contract source selected later by the delivered-Reachy gate; `uv`, Pydantic v2, Pydantic Settings, Typer, RFC 8785/JCS, SQLAlchemy 2, Alembic, `sqlcipher3==0.6.2`, `cryptography`, keyring/macOS Keychain, structlog, JSON Schema, pytest, pytest-asyncio, Hypothesis, Ruff, strict mypy; React 19, TypeScript, Vite, Vitest, Testing Library, pnpm, Playwright, and GitHub Actions.

## Global Constraints

1. The normative specification is `docs/superpowers/specs/2026-08-27-tuntun-phase1-anchor-design.md`; changing a locked decision requires a specification update and ADR before implementation.
2. The repository runner and Mac core are exactly Python 3.12. The pure-Python `tuntun-edge` and `tuntun-contracts` distributions declare `>=3.11,<3.13`, avoid 3.12-only syntax, and are installed only for the exact delivered Reachy interpreter/version/ABI/platform combination accepted by the later hardware gate; every other combination blocks packaging. `sqlcipher3==0.6.2` is the Mac-core storage compatibility candidate: its path/WAL behavior, metadata-only multi-connection guard, and subprocess lock regression must pass the exact Ubuntu and hosted Intel-macOS CI jobs, and it is accepted only after the real target Intel Mac encrypted probe passes.
3. No real family name, audio, transcript, image, embedding, credential, memory, provider response, database, backup, key, certificate, local username, hostname, IP, MAC address, or serial number may enter source control, test reports, CI artifacts, or public issues.
4. All Pydantic trust-boundary models are frozen, reject unknown fields, use aware UTC timestamps, bounded text/bytes, random UUIDs, integer confidence/money, and explicit schema version `1.0`.
5. RFC 8785/JCS canonical bytes normalize Unicode to NFC and serialize UTC timestamps with exactly six fractional digits. Private or low-entropy values use purpose-separated HMAC-SHA-256 commitments, never bare hashes.
6. Domain, service, and workflow modules never import `tuntun_core.adapters`. Concrete database, key-store, model, clock, provider, network, speech, identity, and robot implementations remain behind project-owned protocols.
7. Reachy stores no cloud credential, Mac database key, canonical memory, or durable biometric template. The Mac is the canonical-state owner.
8. Unknown configuration, wildcard/public production binds, absent production keys, wrong database keys, missing cipher support, invalid manifests, unsafe model serialization, and schema/audit failures fail closed. There is no plaintext database fallback.
9. The owner API defaults to `127.0.0.1:8787`; the edge gateway defaults to port `7443`; household timezone is exactly `Asia/Singapore`; active conversation limit is exactly one.
10. Cloud-budget defaults are S$100 soft (`100_000_000` micro-SGD) and S$150 hard (`150_000_000` micro-SGD). Qwen is disabled by default. This foundation plan performs no paid or hardware call.
11. Ordinary tests never access hardware, macOS Keychain, or paid APIs. Keychain and clock tests use in-memory fakes; target-Mac probes are explicit and separately recorded.
12. Project-wide branch coverage is at least 85%; audit-integrity code is at least 95%. Every task follows red → green → refactor → affected suite → static checks → documentation → exact-path commit.
13. Before every commit, `git status --short` must contain only paths listed by that task. Stage only the explicit pathspecs, inspect `git diff --cached --name-only` and `git diff --cached`, and abort if any unrelated path appears.

---

## Locked File and Interface Map

| Area | Files | Responsibility |
|---|---|---|
| Workspace | `.python-version`, root/package `pyproject.toml`, `uv.lock`, `Makefile`, pnpm files | Reproducible Python/web workspaces and commands |
| Assurance | `scripts/verify_private_data.py`, `scripts/assurance_common.py`, `scripts/check_feature_absence.py`, `scripts/check_import_boundaries.py`, `scripts/check_migration_ownership.py`, `scripts/scan_browser_artifacts.py`, `scripts/scan_network_surface.py` | First owner of fail-closed cross-phase scanners required by Phases 3–6 |
| Contracts | `packages/contracts/src/tuntun_contracts/*.py`, `fixtures/v1/*.json`, `scripts/generate_{schemas,openapi}.py`, `packages/contracts/{schema/v1/contracts.schema.json,openapi/admin-v1.yaml}` | Frozen DTOs, canonical bytes, async ports, and their sole complete generated schema/OpenAPI artifacts; no adapters |
| Configuration | `apps/core/src/tuntun_core/config/*.py`, `config/tuntun.example.yaml` | Strict defaults, YAML/env precedence, owner-only paths |
| Secrets/logging | `apps/core/src/tuntun_core/adapters/keychain/*.py` | `SecretProvider`, macOS backend, typed redaction |
| Deterministic tools | `packages/testing/src/tuntun_testing/*.py`, `apps/core/src/tuntun_core/services/models/*.py` | Fake clock/providers/Reachy, scenario runner, governed model registry |
| Storage | `apps/core/src/tuntun_core/adapters/sqlcipher/*.py` | Key-first SQLCipher connection, record AEAD, engine, unit of work, schema metadata |
| Migration | `apps/core/migrations/env.py`, `versions/0001_foundation.py`, `apps/core/src/tuntun_core/adapters/sqlcipher/foundation_0001.py` | Immutable revision-0001 table snapshot, exactly the foundation-owned tables, and DB triggers |
| Audit | `apps/core/src/tuntun_core/services/audit/*.py` | Ordered public SHA-256 chain plus versioned HMAC commitments and verification |

Exact cross-task interfaces are fixed here and repeated in the owning task:

```python
class ClockPort(Protocol):
    def now(self) -> AwareDatetime: raise NotImplementedError
    def monotonic(self) -> float: raise NotImplementedError

class SecretProvider(Protocol):
    def get(self, service: str, account: str) -> bytes: raise NotImplementedError
    def set(self, service: str, account: str, value: bytes) -> None: raise NotImplementedError
    def delete(self, service: str, account: str) -> None: raise NotImplementedError
    def exists(self, service: str, account: str) -> bool: raise NotImplementedError

def open_sqlcipher(path: Path, key: bytes) -> sqlcipher3.Connection: raise NotImplementedError
def create_sqlcipher_engine(path: Path, key: bytes) -> sqlalchemy.Engine: raise NotImplementedError

@runtime_checkable
class UnitOfWorkProtocol(Protocol):
    def execute(self, statement: Executable, parameters: Mapping[str, object] | None = None) -> CursorResult[Any]: raise NotImplementedError
    def exec_driver_sql(self, statement: str, parameters: tuple[object, ...] | Mapping[str, object] = ()) -> CursorResult[Any]: raise NotImplementedError
    def commit(self) -> None: raise NotImplementedError
    def rollback(self) -> None: raise NotImplementedError

@runtime_checkable
class AsyncUnitOfWorkProtocol(Protocol):
    async def run_sync(self, operation: Callable[[UnitOfWorkProtocol], T]) -> T: raise NotImplementedError
    def signal_after_commit(self, name: str) -> None: raise NotImplementedError
    async def commit(self) -> None: raise NotImplementedError
    async def rollback(self) -> None: raise NotImplementedError

class RecordCipher:
    def encrypt(self, plaintext: bytes, context: RecordContext) -> EncryptedRecord: raise NotImplementedError
    def decrypt(self, record: EncryptedRecord, context: RecordContext) -> bytes: raise NotImplementedError

class UnitOfWork:
    def __enter__(self) -> UnitOfWork: raise NotImplementedError
    def execute(self, statement: Executable, parameters: Mapping[str, object] | None = None) -> CursorResult[Any]: raise NotImplementedError
    def exec_driver_sql(self, statement: str, parameters: tuple[object, ...] | Mapping[str, object] = ()) -> CursorResult[Any]: raise NotImplementedError
    def commit(self) -> None: raise NotImplementedError
    def rollback(self) -> None: raise NotImplementedError
    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> bool: raise NotImplementedError

class AsyncUnitOfWork:
    async def __aenter__(self) -> AsyncUnitOfWork: raise NotImplementedError
    async def run_sync(self, operation: Callable[[UnitOfWork], T]) -> T: raise NotImplementedError
    def signal_after_commit(self, name: str) -> None: raise NotImplementedError
    async def commit(self) -> None: raise NotImplementedError
    async def rollback(self) -> None: raise NotImplementedError
    async def __aexit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> bool: raise NotImplementedError

class AtomicMutationScope:
    def open(self) -> AsyncContextManager[AsyncUnitOfWorkProtocol]: raise NotImplementedError
    def require_active_uow(self) -> AsyncUnitOfWorkProtocol: raise NotImplementedError

class AuditLedger:
    def __init__(self, key_id: str, key: bytes, clock: ClockPort) -> None: raise NotImplementedError
    def append(self, uow: UnitOfWorkProtocol, draft: AuditDraft) -> AuditReceipt: raise NotImplementedError
    def seal(self, uow: UnitOfWorkProtocol, first_ordinal: int, last_ordinal: int) -> AuditSegment: raise NotImplementedError

class AsyncAuditLedger:
    async def append(self, uow: AsyncUnitOfWorkProtocol, draft: AuditDraft) -> AuditReceipt: raise NotImplementedError
    async def seal(self, uow: AsyncUnitOfWorkProtocol, first_ordinal: int, last_ordinal: int) -> AuditSegment: raise NotImplementedError

class AuditVerifier:
    def verify(self, connection: Connection) -> AuditVerification: raise NotImplementedError
```

### Task 1: Bootstrap the Python workspace and package smoke gate

**Master package:** 01
**Depends on:** None; first task in an empty repository.
**Estimated effort:** 0.5 person-day.

**Files:**
- Create: `.python-version`
- Create: `pyproject.toml`
- Create: `apps/core/pyproject.toml`
- Create: `apps/edge/pyproject.toml`
- Create: `packages/contracts/pyproject.toml`
- Create: `packages/testing/pyproject.toml`
- Create: `apps/core/src/tuntun_core/__init__.py`
- Create: `apps/core/src/tuntun_core/cli/main.py`
- Create: `apps/edge/src/tuntun_edge/__init__.py`
- Create: `packages/contracts/src/tuntun_contracts/__init__.py`
- Create: `packages/testing/src/tuntun_testing/__init__.py`
- Test: `tests/unit/test_package_smoke.py`

**Interfaces:**
- Consumes: an empty repository containing only documentation and the existing root `README.md`.
- Produces: importable `tuntun_core`, `tuntun_edge`, `tuntun_contracts`, and `tuntun_testing`, each exposing `__version__: str = "0.1.0.dev0"`; console script `tuntunctl = tuntun_core.cli.main:app`.

- [ ] **Step 1: Create the test runner configuration and failing smoke test**

```toml
# pyproject.toml
[project]
name = "tuntun-workspace"
version = "0.1.0.dev0"
requires-python = "==3.12.*"

[dependency-groups]
dev = [
  "coverage[toml]>=7.10,<8",
  "hypothesis>=6.138,<7",
  "mypy>=1.17,<2",
  "pytest>=8.4,<9",
  "pytest-asyncio>=1.1,<2",
  "respx>=0.22,<1",
  "ruff>=0.12,<1",
]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "--strict-markers --strict-config"
markers = [
  "live_cloud: explicit paid-provider tests",
  "reachy_hardware: explicit physical Reachy tests",
]

[tool.ruff]
target-version = "py312"
line-length = 100

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM"]

[tool.mypy]
python_version = "3.12"
strict = true
warn_unused_configs = true
```

```python
# tests/unit/test_package_smoke.py
import importlib

import pytest


@pytest.mark.parametrize(
    "package_name",
    ["tuntun_core", "tuntun_edge", "tuntun_contracts", "tuntun_testing"],
)
def test_workspace_package_exposes_version(package_name: str) -> None:
    package = importlib.import_module(package_name)
    assert package.__version__ == "0.1.0.dev0"
```

- [ ] **Step 2: Run the red test**

Run: `uv sync && uv run pytest tests/unit/test_package_smoke.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core'`.

- [ ] **Step 3: Add the workspace packages and minimal CLI**

```toml
# append to pyproject.toml
[tool.uv.workspace]
members = ["apps/core", "apps/edge", "packages/contracts", "packages/testing"]

[tool.coverage.run]
branch = true
source = ["tuntun_core", "tuntun_edge", "tuntun_contracts", "tuntun_testing"]

[tool.coverage.report]
fail_under = 85
show_missing = true
```

```toml
# apps/core/pyproject.toml
[project]
name = "tuntun-core"
version = "0.1.0.dev0"
requires-python = "==3.12.*"
dependencies = ["typer>=0.16,<1"]

[project.scripts]
tuntunctl = "tuntun_core.cli.main:app"

[build-system]
requires = ["hatchling>=1.27,<2"]
build-backend = "hatchling.build"
```

```toml
# apps/edge/pyproject.toml
[project]
name = "tuntun-edge"
version = "0.1.0.dev0"
requires-python = ">=3.11,<3.13"

[build-system]
requires = ["hatchling>=1.27,<2"]
build-backend = "hatchling.build"
```

```toml
# packages/contracts/pyproject.toml
[project]
name = "tuntun-contracts"
version = "0.1.0.dev0"
requires-python = ">=3.11,<3.13"
dependencies = ["pydantic>=2.11,<3", "rfc8785>=0.1.4,<0.2"]

[build-system]
requires = ["hatchling>=1.27,<2"]
build-backend = "hatchling.build"
```

```toml
# packages/testing/pyproject.toml
[project]
name = "tuntun-testing"
version = "0.1.0.dev0"
requires-python = "==3.12.*"
dependencies = ["tuntun-contracts"]

[tool.uv.sources]
tuntun-contracts = { workspace = true }

[build-system]
requires = ["hatchling>=1.27,<2"]
build-backend = "hatchling.build"
```

```python
# each package __init__.py
__version__: str = "0.1.0.dev0"
```

```python
# apps/core/src/tuntun_core/cli/main.py
import typer

app = typer.Typer(no_args_is_help=True)


@app.command()
def version() -> None:
    """Print the application version without reading configuration or secrets."""
    typer.echo("0.1.0.dev0")
```

Set `.python-version` to the single line `3.12`.

- [ ] **Step 4: Lock and run the green package gate**

Run: `uv lock && uv sync --all-packages && uv run pytest tests/unit/test_package_smoke.py -q && uv run ruff check tests/unit/test_package_smoke.py apps/core/src apps/edge/src packages/contracts/src packages/testing/src && uv run mypy apps/core/src apps/edge/src packages/contracts/src packages/testing/src`

Expected: PASS with `4 passed`; Ruff and mypy exit 0.

- [ ] **Step 5: Commit exact Task 1 paths**

```bash
git status --short
git add .python-version pyproject.toml uv.lock apps/core/pyproject.toml apps/edge/pyproject.toml packages/contracts/pyproject.toml packages/testing/pyproject.toml apps/core/src/tuntun_core/__init__.py apps/core/src/tuntun_core/cli/main.py apps/edge/src/tuntun_edge/__init__.py packages/contracts/src/tuntun_contracts/__init__.py packages/testing/src/tuntun_testing/__init__.py tests/unit/test_package_smoke.py
git diff --cached --name-only
git diff --cached
git commit -m "build: bootstrap Tuntun Python workspace"
```

### Task 2: Bootstrap the admin app, standard commands, and baseline CI

**Master package:** 01
**Depends on:** Task 1.
**Estimated effort:** 0.5 person-day.

**Files:**
- Modify: `pyproject.toml`
- Modify: `uv.lock`
- Modify: `apps/core/src/tuntun_core/cli/main.py`
- Create: `package.json`
- Create: `pnpm-workspace.yaml`
- Create: `pnpm-lock.yaml`
- Create: `apps/admin/package.json`
- Create: `apps/admin/index.html`
- Create: `apps/admin/vite.config.ts`
- Create: `apps/admin/tsconfig.json`
- Create: `apps/admin/eslint.config.js`
- Create: `apps/admin/playwright.config.ts`
- Create: `apps/admin/src/main.tsx`
- Create: `apps/admin/src/app.tsx`
- Create: `apps/admin/src/test-setup.ts`
- Test: `apps/admin/src/app.test.tsx`
- Test: `tests/unit/test_cli.py`
- Test: `tests/unit/admin/root-discovery.test.ts`
- Test: `tests/e2e/admin-smoke.spec.ts`
- Test: `tests/ui/admin-accessibility.spec.ts`
- Create: `Makefile`
- Modify: `.gitignore`
- Create: `.pre-commit-config.yaml`
- Create: `.github/workflows/ci.yml`
- Test: `tests/ci/test_workflow_policy.py`
- Test: `tests/ci/test_web_command_contract.py`

**Interfaces:**
- Consumes: Task 1 workspace commands.
- Produces: root development dependencies `PyYAML>=6.0,<7` and `pytest-cov>=6.2,<7` locked in `uv.lock` before any Task 2 Python or coverage gate; a group-preserving, no-I/O Typer callback so `tuntunctl version` remains an explicit subcommand; working `make bootstrap|format|lint|typecheck|test|test-security|test-contract|web-test|web-build|web-e2e`; explicit fail-closed `make verify-private-data` and therefore fail-closed `make check` until Task 3 installs the required scanner; a non-networked admin page rendering `Tuntun setup in progress`; CI with exact root read-only contents permission, absent-or-exact-read-only job permissions, no secret forwarding/expression, and no hardware/provider jobs.

- [ ] **Step 1: Write the failing admin smoke test**

```tsx
// apps/admin/src/app.test.tsx
import {render, screen} from "@testing-library/react";
import {describe, expect, it} from "vitest";
import {App} from "./app";

describe("App", () => {
  it("renders the offline setup shell", () => {
    render(<App />);
    expect(screen.getByRole("heading", {name: "Tuntun setup in progress"})).toBeVisible();
  });
});
```

Also write the workflow-policy test before adding CI. It treats workflow syntax as a release contract rather than trusting a visual review:

```python
# tests/ci/test_workflow_policy.py
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
        "contents: write", "pages: write", "gh release create", "git tag ",
        "npm publish", "pnpm publish", "twine upload",
        "reachy_hardware", "live_cloud",
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
                "name", "needs", "if", "uses", "with", "permissions",
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
        }
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
        ("security.yml", {
            "runs-on": "${{ matrix.os }}",
            "strategy": {"matrix": {
                "os": ["ubuntu-24.04", "macos-15-intel"],
                "include": [{"os": "self-hosted"}],
            }},
        }),
        ("release.yaml", {
            "runs-on": "${{ matrix.os }}",
            "strategy": {"matrix": {
                "os": ["ubuntu-24.04", "macos-15-intel"],
                "exclude": [{"os": "ubuntu-24.04"}],
            }},
        }),
        ("security.yml", {"strategy": {"matrix": {"python": ["3.12"]}}}),
        ("release.yaml", {"strategy": {"matrix": {
            "os": ["ubuntu-24.04", "macos-15-intel"],
            "include": [{"os": "ubuntu-24.04"}],
        }}}),
        ("security.yml", {"strategy": {"matrix": {
            "os": ["ubuntu-24.04", "macos-15-intel"],
            "exclude": [{"os": "macos-15-intel"}],
        }}}),
        ("release.yaml", {
            "runs-on": "${{ matrix.os }}",
            "strategy": {"matrix": {
                "os": ["ubuntu-24.04", "macos-15-intel"],
                "python": ["3.12"],
            }},
        }),
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
        {"uses": "owner/repository/.github/workflows/reuse.yml@" + "b" * 40,
         "secrets": "inherit"},
        {"uses": "owner/repository/.github/workflows/reuse.yml@" + "b" * 40,
         "secrets": {"token": "${{ secrets['TOKEN'] }}"}},
        {"uses": "owner/repository/.github/workflows/reuse.yml@" + "b" * 40,
         "permissions": {"actions": "write"}},
        {"uses": "owner/repository/.github/workflows/reuse.yml@" + "b" * 40,
         "strategy": {"matrix": {"python": ["3.12"]}}},
    ):
        workflow_with_reusable_job = {
            "permissions": {"contents": "read"},
            "jobs": {"reuse": reusable},
        }
        path.write_text(yaml.safe_dump(workflow_with_reusable_job))
        with pytest.raises(AssertionError):
            _assert_workflow_policy(path)
```

Add the Python CLI coverage sentinel before any coverage-bearing `make test` gate:

```python
# tests/unit/test_cli.py
from typer.testing import CliRunner

from tuntun_core.cli.main import app


def test_version_command_exercises_the_bootstrap_cli() -> None:
    result = CliRunner().invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout == "0.1.0.dev0\n"
```

The explicit `version` subcommand needs a Typer group even though its callback
does no work. Add the smallest no-I/O callback before this coverage gate:

```python
# apps/core/src/tuntun_core/cli/main.py
import typer

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main() -> None:
    """Manage local Tuntun development commands."""


@app.command()
def version() -> None:
    """Print the application version without reading configuration or secrets."""
    typer.echo("0.1.0.dev0")
```

- [ ] **Step 2: Run the red web test**

The original absent-workspace observation printed a missing-project diagnostic
but exited zero, so it is not a valid RED. Preserve that chronology honestly:
reconstruct the immutable pre-Task-2 base only to prove the replacement
sentinel, rather than relabeling the old diagnostic. In a disposable worktree
at `aa24b9c033732a30e521a472d3ce11f7be5ac7fc`, run:

Run: `pnpm --filter @tuntun/admin --fail-if-no-match test`

Expected: exit `1` with `No projects found in "/private/tmp/tuntun-task2-red-base"`
because the admin workspace is absent. This is the maintained executable
missing-workspace contract; the same command exits zero after the workspace is
created.

- [ ] **Step 3: Add the minimal web application and command surface**

Before running any Task 2 Python policy test or any `make test` coverage command, add these two entries to the existing root `[dependency-groups].dev` array in `pyproject.toml`, run `uv lock`, and retain the resulting `uv.lock` change in this task:

```toml
  "PyYAML>=6.0,<7",
  "pytest-cov>=6.2,<7",
```

`PyYAML` is the direct owner of the `yaml` import used by both Task 2 CI-policy tests. `pytest-cov` is the direct owner of the `--cov`, `--cov-branch`, and later `--cov-fail-under` pytest options; `coverage[toml]` alone does not provide those pytest options. Do not defer either dependency to Task 7 or Task 15.

`package.json`

```json
{"name":"tuntun-workspace","private":true,"packageManager":"pnpm@10.15.0","devDependencies":{"@axe-core/playwright":"4.10.2","@playwright/test":"1.55.0","@testing-library/jest-dom":"6.8.0","@testing-library/react":"16.3.0","@types/react":"19.1.10","@types/react-dom":"19.1.7","jsdom":"26.1.0","react":"19.1.1","react-dom":"19.1.1","typescript":"5.9.2","vite":"7.1.3","vitest":"3.2.4"}}
```

```yaml
# pnpm-workspace.yaml
packages:
  - apps/*
  - packages/*
```

`apps/admin/package.json`

```json
{
  "name": "@tuntun/admin",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite --host 127.0.0.1 --port 4173",
    "lint": "cd ../.. && ./apps/admin/node_modules/.bin/eslint --config apps/admin/eslint.config.js apps/admin/src apps/admin/vite.config.ts tests/unit/admin tests/e2e tests/ui --max-warnings 0",
    "typecheck": "tsc --noEmit",
    "test": "vitest run",
    "build": "pnpm run typecheck && vite build",
    "e2e": "playwright test",
    "generate:openapi": "openapi-typescript ../../packages/contracts/openapi/admin-v1.yaml -o src/api/generated/admin-v1.ts"
  },
  "dependencies": {"@tanstack/react-query":"5.85.5","react":"19.1.1","react-dom":"19.1.1","react-intl":"7.1.11","react-router-dom":"7.8.2"},
  "devDependencies": {"@axe-core/playwright":"4.10.2","@eslint/js":"9.34.0","@playwright/test":"1.55.0","@testing-library/jest-dom":"6.8.0","@testing-library/react":"16.3.0","@types/react":"19.1.10","@types/react-dom":"19.1.7","@vitejs/plugin-react":"5.0.2","eslint":"9.34.0","eslint-plugin-react-hooks":"5.2.0","eslint-plugin-react-refresh":"0.4.20","globals":"16.3.0","jsdom":"26.1.0","openapi-typescript":"7.9.1","typescript":"5.9.2","typescript-eslint":"8.41.0","vite":"7.1.3","vitest":"3.2.4"}
}
```

```tsx
// apps/admin/src/app.tsx
export function App() {
  return <main><h1>Tuntun setup in progress</h1></main>;
}
```

```tsx
// apps/admin/src/main.tsx
import React from "react";
import ReactDOM from "react-dom/client";
import {App} from "./app";
ReactDOM.createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
```

```ts
// apps/admin/vite.config.ts
import react from "@vitejs/plugin-react";
import {defineConfig} from "vitest/config";
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
    include: [
      "src/**/*.{test,spec}.{ts,tsx}",
      "../../tests/unit/admin/**/*.{test,spec}.{ts,tsx}",
      "../../tests/ui/**/*.spec.tsx",
    ],
    exclude: ["../../tests/e2e/**", "../../tests/ui/e2e/**"],
  },
});
```

```js
// apps/admin/eslint.config.js
import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {basePath: "../..", ignores: ["apps/admin/dist", "apps/admin/playwright-report", "apps/admin/test-results"]},
  {...js.configs.recommended, basePath: "../.."},
  ...tseslint.configs.recommended.map((config) => ({...config, basePath: "../.."})),
  {
    basePath: "../..",
    files: [
      "apps/admin/**/*.{ts,tsx}",
      "tests/unit/admin/**/*.{ts,tsx}",
      "tests/e2e/**/*.{ts,tsx}",
      "tests/ui/**/*.{ts,tsx}",
    ],
    languageOptions: {ecmaVersion: 2022, globals: {...globals.browser, ...globals.node}},
    plugins: {"react-hooks": reactHooks, "react-refresh": reactRefresh},
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": ["error", {allowConstantExport: true}],
    },
  },
);
```

```ts
// apps/admin/playwright.config.ts
import {defineConfig, devices} from "@playwright/test";

export default defineConfig({
  testDir: "../../tests",
  testMatch: ["**/e2e/**/*.spec.ts", "**/ui/**/*.spec.ts", "**/performance/ui/**/*.spec.ts"],
  testIgnore: [
    "**/e2e/ui/subject-*.spec.ts",
    "**/ui/subject-*.spec.ts",
    "**/ui/display-*.spec.ts",
    "**/ui/e2e/display-agent-*.spec.ts",
  ],
  fullyParallel: false,
  workers: 1,
  retries: 0,
  use: {
    baseURL: "http://127.0.0.1:4173",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
  },
  webServer: {
    command: "pnpm run dev",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: false,
    timeout: 120_000,
  },
  projects: [{name: "chromium", use: {...devices["Desktop Chrome"]}}],
});
```

```ts
// apps/admin/src/test-setup.ts
import "@testing-library/jest-dom/vitest";
```

`apps/admin/tsconfig.json`

```json
{"compilerOptions":{"target":"ES2022","module":"ESNext","moduleResolution":"Bundler","jsx":"react-jsx","strict":true,"noEmit":true,"skipLibCheck":true,"types":["vite/client","vitest/globals"]},"include":["src","vite.config.ts","../../tests/unit/admin/**/*.ts","../../tests/unit/admin/**/*.tsx","../../tests/e2e/**/*.ts","../../tests/e2e/**/*.tsx","../../tests/ui/**/*.ts","../../tests/ui/**/*.tsx"]}
```

```html
<!-- apps/admin/index.html -->
<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Tuntun</title></head><body><div id="root"></div><script type="module" src="/src/main.tsx"></script></body></html>
```

```ts
// tests/unit/admin/root-discovery.test.ts
import {describe, expect, it} from "vitest";
import {App} from "../../../apps/admin/src/app";

describe("root unit-test discovery", () => {
  it("loads an admin module from the root test tree", () => {
    expect(typeof App).toBe("function");
  });
});
```

```ts
// tests/e2e/admin-smoke.spec.ts
import {expect, test} from "@playwright/test";

test("serves the offline setup shell", async ({page}) => {
  await page.goto("/");
  await expect(page.getByRole("heading", {name: "Tuntun setup in progress"})).toBeVisible();
});
```

```ts
// tests/ui/admin-accessibility.spec.ts
import AxeBuilder from "@axe-core/playwright";
import {expect, test} from "@playwright/test";

test("has no serious or critical baseline accessibility violations", async ({page}) => {
  await page.goto("/");
  const result = await new AxeBuilder({page}).analyze();
  expect(result.violations.filter(({impact}) => impact === "serious" || impact === "critical")).toHaveLength(0);
});
```

```python
# tests/ci/test_web_command_contract.py
import json
import re
import subprocess
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def test_admin_owns_every_public_web_command() -> None:
    package = json.loads((ROOT / "apps/admin/package.json").read_text())
    expected_scripts = {
        "dev",
        "lint",
        "typecheck",
        "test",
        "build",
        "e2e",
        "generate:openapi",
    }
    expected_tools = {
        "@axe-core/playwright",
        "@playwright/test",
        "eslint",
        "typescript",
        "vitest",
    }
    assert expected_scripts <= set(package["scripts"])
    assert expected_tools <= set(package["devDependencies"])


def test_workspace_admits_all_later_apps_and_typescript_packages() -> None:
    workspace = yaml.safe_load((ROOT / "pnpm-workspace.yaml").read_text())
    assert workspace == {"packages": ["apps/*", "packages/*"]}


def test_web_test_fails_closed_without_an_admin_workspace(tmp_path: Path) -> None:
    completed = subprocess.run(
        ["make", "-f", str(ROOT / "Makefile"), "web-test"],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode != 0, completed.stdout + completed.stderr
    assert "No projects found" in completed.stdout + completed.stderr


def test_playwright_config_owns_root_discovery_server_and_project() -> None:
    config = (ROOT / "apps/admin/playwright.config.ts").read_text()
    required_fragments = (
        'testDir: "../../tests"',
        '"**/e2e/**/*.spec.ts"',
        '"**/ui/**/*.spec.ts"',
        "testIgnore:",
        "webServer:",
        "projects:",
        "127.0.0.1:4173",
    )
    for required in required_fragments:
        assert required in config


def test_playwright_discovers_root_e2e_and_ui_suites() -> None:
    completed = subprocess.run(
        ["pnpm", "--filter", "@tuntun/admin", "e2e", "--list"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "e2e/admin-smoke.spec.ts" in output
    assert "ui/admin-accessibility.spec.ts" in output
    discovered = re.search(r"Total:\s+(\d+)\s+tests?", output)
    assert discovered and int(discovered.group(1)) >= 2, output


def test_typecheck_and_lint_scope_every_root_e2e_and_ui_typescript_file() -> None:
    tsconfig = json.loads((ROOT / "apps/admin/tsconfig.json").read_text())
    assert {
        "../../tests/e2e/**/*.ts", "../../tests/e2e/**/*.tsx",
        "../../tests/ui/**/*.ts", "../../tests/ui/**/*.tsx",
    } <= set(tsconfig["include"])
    eslint = (ROOT / "apps/admin/eslint.config.js").read_text()
    for required in (
        'basePath: "../.."',
        '"apps/admin/**/*.{ts,tsx}"',
        '"tests/unit/admin/**/*.{ts,tsx}"',
        '"tests/e2e/**/*.{ts,tsx}"',
        '"tests/ui/**/*.{ts,tsx}"',
    ):
        assert required in eslint

    for path in (
        "apps/admin/src/app.tsx",
        "tests/unit/admin/root-discovery.test.ts",
        "tests/e2e/admin-smoke.spec.ts",
        "tests/ui/admin-accessibility.spec.ts",
    ):
        completed = subprocess.run(
            [
                str(ROOT / "apps/admin/node_modules/.bin/eslint"),
                "--config",
                "apps/admin/eslint.config.js",
                "--print-config",
                path,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr
        assert completed.stdout.lstrip().startswith("{"), completed.stdout

    lint = subprocess.run(
        ["pnpm", "--filter", "@tuntun/admin", "lint"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert lint.returncode == 0, lint.stdout + lint.stderr
```

```make
# Makefile
.PHONY: bootstrap format lint typecheck test test-security test-contract web-test web-build web-e2e check verify-private-data
bootstrap:
	uv sync --all-packages
	pnpm install --frozen-lockfile
format:
	uv run ruff format .
lint:
	uv run ruff check .
	pnpm --filter @tuntun/admin lint
typecheck:
	uv run mypy apps/core/src apps/edge/src packages/contracts/src packages/testing/src
	pnpm --filter @tuntun/admin typecheck
test:
	uv run pytest -m "not live_cloud and not reachy_hardware" --cov --cov-branch
test-security:
	@files="$$(find tests/security -type f -name 'test_*.py' -print 2>/dev/null | sort)"; count="$$(printf '%s\n' "$$files" | sed '/^$$/d' | wc -l | tr -d ' ')"; echo "test-security: $$count discovered files"; if [ "$$count" -gt 0 ]; then uv run pytest $$files -m "not live_cloud and not reachy_hardware"; fi
test-contract:
	@files="$$(find tests/contract -type f -name 'test_*.py' -print 2>/dev/null | sort)"; count="$$(printf '%s\n' "$$files" | sed '/^$$/d' | wc -l | tr -d ' ')"; echo "test-contract: $$count discovered files"; if [ "$$count" -gt 0 ]; then uv run pytest $$files; fi
web-test:
	pnpm --filter @tuntun/admin --fail-if-no-match test
web-build:
	pnpm --filter @tuntun/admin build
web-e2e:
	pnpm --filter @tuntun/admin e2e
verify-private-data:
	@echo "verify-private-data: UNAVAILABLE until Task 3 installs the required fail-closed scanner" >&2
	@exit 2
check: lint typecheck test test-security test-contract web-test web-build verify-private-data
```

```gitignore
# .gitignore
.worktrees/
.superpowers/sdd/
.env
.venv/
__pycache__/
*.py[cod]
.pytest_cache/
.ruff_cache/
.mypy_cache/
node_modules/
dist/
var/
.coverage
coverage.xml
htmlcov/
playwright-report/
test-results/
*.db
*.sqlite*
*.pem
*.key
*.crt
*.wav
*.mp3
*.mp4
*.png
*.jpg
*.onnx
*.safetensors
*.bin
```

The file already contains `.worktrees/` and `.superpowers/sdd/` from reviewed-document/worktree setup. Modify it in place and preserve those two lines exactly while adding the remaining ignores above; losing either line makes the isolated worktree or durable SDD ledger trackable and fails Task 2.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.12.11
    hooks:
      - id: ruff-check
        args: [--fix]
      - id: ruff-format
```

```yaml
# .github/workflows/ci.yml
name: ci
on: [push, pull_request]
permissions:
  contents: read
jobs:
  check:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-24.04, macos-15-intel]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: astral-sh/setup-uv@20cfd1bf945f4377ade1205e4dbc17946fc9a30d # v10.0.1
        with: {version: "0.8.13", enable-cache: true}
      - uses: pnpm/action-setup@0977fd99725f1db4007ccb2928dbb4e90d06cc86 # v6.0.10
        with: {version: "10.15.0", run_install: false}
      - uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0
        with: {node-version: "22", cache: pnpm}
      - run: uv sync --all-packages --locked
      - run: pnpm install --frozen-lockfile
      - run: make lint typecheck test test-security test-contract web-test web-build
```

The four action revisions are full reviewed commit SHAs and the comments are informational only. The policy test enumerates the union of `.github/workflows/*.yml` and `.github/workflows/*.yaml` on every run, so later security/release workflows cannot escape review by using the other suffix. It checks strategy before any job-kind branch: fixed-runner and reusable jobs carry no strategy; only `${{ matrix.os }}` may carry strategy, whose keys are limited to `fail-fast` and `matrix`, and whose literal matrix is exactly the ordered `os` pair shown above. Therefore `include`, `exclude`, another axis, or another runner label is rejected everywhere. It checks job-level reusable workflows and every step-level third-party `uses`, while allowing only repository-local `./` actions, and validates every literal runner against the fixed set. Dependabot may propose an update, but CI rejects a tag, branch, abbreviated SHA, `*-latest` runner, unreviewed runner label, secret reference, or hardware/provider job. Linux remains the portable gate; `macos-15-intel` proves hosted Intel compatibility only. It is not evidence for the household Mac, Reachy, network, reboot, thermal, firewall, or lifecycle qualification gates.

- [ ] **Step 4: Run the green web/build gate**

Run: `uv lock && uv sync --all-packages --locked && pnpm install && pnpm --filter @tuntun/admin --fail-if-no-match test && pnpm --filter @tuntun/admin lint && pnpm --filter @tuntun/admin typecheck && pnpm --filter @tuntun/admin build && pnpm --filter @tuntun/admin e2e --list && uv run python -c "import coverage, pytest_cov, yaml" && uv run pytest tests/unit/test_package_smoke.py tests/unit/test_cli.py tests/ci/test_workflow_policy.py tests/ci/test_web_command_contract.py -q && make test && make test-security test-contract && make lint && make typecheck && sh -c 'make verify-private-data; code=$?; test "$code" -eq 2' && sh -c 'make check; code=$?; test "$code" -eq 2'`

Expected: PASS on Linux and Intel macOS; `uv.lock` contains resolved `PyYAML` and `pytest-cov`, `uv sync --locked` accepts it as current, the direct import probe exits 0, the CLI test prints exactly `0.1.0.dev0` and `make test` meets the 85% branch-coverage gate, and both Python policy modules reject root/job write permissions, reusable-job secret forwarding, dot/index secret expressions, fixed/reusable strategy bypasses, and matrix `include`/`exclude` or extra-axis runner expansion. `test-security` and `test-contract` print an explicit zero-file count now and automatically execute every matching future file once its owning directory exists. `verify-private-data` and `check` exit exactly 2 until Task 3 installs the scanner, so Task 2 CI runs only the complete current gates. The app-local/root-unit Vitest sentinels pass, Playwright's `--list` output contains the `testDir`-relative paths `e2e/admin-smoke.spec.ts` and `ui/admin-accessibility.spec.ts` with a nonzero discovery total, the executable empty-workspace contract proves `web-test` fails nonzero with `No projects found`, all `.ts`/`.tsx` app, root-unit, e2e, and UI trees are in ESLint and TypeScript scopes with repository-root `basePath: "../.."`, the Vite build succeeds, and static checks report zero errors. `git diff -- .gitignore` retains `.worktrees/` and `.superpowers/sdd/` and adds every listed runtime/build/Python-cache ignore.

- [ ] **Step 5: Commit exact Task 2 paths**

```bash
git status --short
git add pyproject.toml uv.lock package.json pnpm-workspace.yaml pnpm-lock.yaml apps/core/src/tuntun_core/cli/main.py apps/admin/package.json apps/admin/index.html apps/admin/vite.config.ts apps/admin/tsconfig.json apps/admin/eslint.config.js apps/admin/playwright.config.ts apps/admin/src/main.tsx apps/admin/src/app.tsx apps/admin/src/app.test.tsx apps/admin/src/test-setup.ts tests/unit/test_cli.py tests/unit/admin/root-discovery.test.ts tests/e2e/admin-smoke.spec.ts tests/ui/admin-accessibility.spec.ts Makefile .gitignore .pre-commit-config.yaml .github/workflows/ci.yml tests/ci/test_workflow_policy.py tests/ci/test_web_command_contract.py
git diff --cached --name-only
git diff --cached
git commit -m "build: add web workspace and baseline CI"
```

### Task 3: Add fail-closed private-data and shared structural-assurance scanners

**Master package:** 01
**Depends on:** Tasks 1–2.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `scripts/verify_private_data.py`
- Create: `scripts/assurance_common.py`
- Create: `scripts/check_feature_absence.py`
- Create: `scripts/check_import_boundaries.py`
- Create: `scripts/check_migration_ownership.py`
- Create: `scripts/scan_browser_artifacts.py`
- Create: `scripts/scan_network_surface.py`
- Create: `scripts/scan_private_data.py`
- Create: `scripts/scan_backup_artifacts.py`
- Create: `scripts/scan_sandbox_residue.py`
- Create: `scripts/scan_sql_schema.py`
- Create: `scripts/check_migration_graph.py`
- Test: `tests/security/test_private_data_scanner.py`
- Test: `tests/security/test_shared_assurance_tools.py`
- Create: `tests/security/conftest.py`
- Create: `tests/security/assurance_cases.py`
- Create: `tests/fixtures/synthetic/README.md`
- Modify: `Makefile`
- Modify: `.github/workflows/ci.yml`
- Modify: `tests/ci/test_web_command_contract.py`

**Interfaces:**
- Consumes: one or more explicit repository, evidence, candidate, or artifact roots.
- Produces: `scan(roots: Path | Sequence[Path]) -> tuple[Finding, ...]`; the positional `verify_private_data.py [ROOT ...]` form and every existing `scan_private_data.py --paths ROOT...` form remain supported. The positional CLI exits 1 and prints root-qualified paths/reason codes for either a forbidden finding or an incomplete scan, otherwise prints `private-data scan: PASS` and exits 0.
- Produces the first and only owners of the shared commands already consumed by later phase plans: `check_feature_absence.py`, `check_import_boundaries.py`, `check_migration_ownership.py`, `scan_browser_artifacts.py`, and `scan_network_surface.py`. Each exposes `main(argv: Sequence[str] | None = None) -> int`, accepts an optional lexical `--root PATH` that defaults to the current repository, returns `0` only for a complete passing scan, returns `1` for a policy finding, and returns `2` for invalid arguments, a missing/unreadable/changing input, parser/structure exhaustion, or an unavailable required inventory. They perform no network access and no repository/runtime mutation.
- `scripts/assurance_common.py` produces descriptor-bound `read_regular_file(path: Path, *, max_bytes: int) -> bytes`, duplicate-safe `parse_json_object(raw: bytes, *, max_depth: int, max_containers: int, max_tokens: int) -> Mapping[str, object]`, bounded `walk_regular_files(roots: Sequence[Path], *, max_files: int, max_total_bytes: int) -> Iterator[FrozenRegularFile]`, `CsvSet.parse(value: str) -> tuple[str, ...]`, and `AssuranceFinding(path: Path, code: str, detail: str | None)`. Every tool uses these primitives; symlinks, special files, duplicate JSON keys, non-UTF-8, input replacement, duplicate CSV values, excess depth/count/bytes, and partial subprocess output block rather than pass.
- Every shared assurance module exposes `evaluate(argv: Sequence[str] | None = None) -> AssuranceResult`; `main()` is exactly `finish(evaluate(argv))`. Tests use `evaluate` to inspect completeness receipts and `main` to assert the public exit code, so no fixture infers completeness from an exit code.
- `check_feature_absence.py` supports exactly one selector mode: `--manifest PATH --feature ID`, `--manifest PATH --features CSV`, `--feature ID --phase N`, `--features CSV --phase N`, or `--all-canonically-absent --direct-and-replay`. `--direct-and-replay` is valid only in that final all-absent selector; every selector nevertheless attests the complete source/route/config/OpenAPI/package/chunk/IPC/launchd inventory and the mandatory direct-request and replay probes. An unknown feature, missing required surface/probe inventory, or cross-mode flag combination is a blocking incomplete scan.
- `check_import_boundaries.py` supports exactly one of `--domain NAME` or `--all`, builds a bounded Python AST import graph from workspace `src` roots, resolves absolute and relative imports, and rejects domain/service/workflow imports of adapter implementations, cross-domain private modules, dynamic imports with non-literal targets, and modules that cannot be parsed.
- `check_migration_ownership.py` accepts `--revisions REV [REV ...]`, optional `--exact-head REVISION_NAME`, and optional `--forbid-branch-merge-orphan`. It parses Alembic modules without importing them, requires each requested numeric revision to have exactly one file/`revision` value, validates `down_revision`, rejects duplicate/edited/unknown ancestry and, under the strict flag, requires one linear reachable head with no branch, merge, or orphan.
- `scan_browser_artifacts.py` accepts optional `--playwright-output PATH` and required `--forbid CSV`; it scans every existing production browser bundle/source map/manifest plus the explicit Playwright tree when named, including compressed/textual assets, and matches normalized JSON/property names and literal browser persistence/URL/path patterns. A missing explicit output, corrupt map/archive, unreadable bundle, or build tree changing during the scan blocks.
- `scan_network_surface.py` accepts the closed Phase 3/6 flag vocabulary `--require-listener ADDRESS:PORT=OWNER`, `--forbid-lan-port PORT`, `--optional-exact-commissioned-private-lan-port PORT=OWNER`, `--forbid-wildcard`, `--forbid-ipv6`, `--forbid-core-tcp`, `--forbid-media-proxy-tcp`, `--forbid-camera-ports`, and `--forbid-camera-public`. It obtains one bounded point-in-time process/socket snapshot, joins socket owner PID to executable/service identity, rejects ambiguous/truncated inventory, and never treats an unavailable platform probe as an empty passing surface.
- `scan_private_data.py` is a thin CLI over the same `verify_private_data.scan` engine, not a second matcher. It preserves the later closed `--paths PATH...`, `--include-git-history`, and `--allow-safe-ids` grammar; history mode uses one bounded fixed-argv Git object stream and applies the same byte/archive budgets. Its incomplete-reason set includes `git-state-unprovable`, `git-inventory-failed`, `git-inventory-timeout`, `git-inventory-output-limit`, `git-inventory-malformed`, `git-object-format-unsupported`, `git-process-reap-timeout`, `git-index-conflict`, `git-index-mode-invalid`, `source-inventory-drift`, `source-inventory-incomplete`, every `git-batch-*` framing/object failure, `filesystem-symlink-ancestor`, and `duplicate-root`, so every such result exits `2` rather than being mislabeled as a complete policy finding. The pre-existing `--allow-safe-ids` mode remains limited to its documented synthetic/public identifier grammar and cannot suppress a credential/private-key match, forbidden suffix, household/device/subject/network value, or arbitrary caller-supplied pattern/path. Task 3 adds no scanner allowlist or repository-path exemption.
- `scan_backup_artifacts.py --root PATH --require-encrypted --forbid CSV` verifies a bounded nofollow backup tree contains only declared manifests and structurally valid, versioned, allowlisted AEAD envelopes with the canonical algorithm identifier, nonce length, nonempty ciphertext, and tag-length framing, and none of the named portable-secret/video/plaintext classes. This no-key artifact scanner does not claim to authenticate an AEAD tag; keyed backup verification/restore is the sole cryptographic authenticity authority. Unknown classes/ciphers/versions, malformed or truncated envelopes, corrupt archives, or incomplete inventory block. `scan_sandbox_residue.py --root PATH --require-empty` proves the descriptor-walked root has no remaining entry/mount/process handle and fails on an absent, changing, symlinked, unreadable, or nonempty root. `scan_sql_schema.py --db-kind vision|canonical --forbid CSV` uses the migration/schema parser without importing migrations, requires the selected registered schema inventory to be complete, and rejects forbidden normalized table/column/index/trigger/view tokens or unowned/unknown DDL.
- `check_migration_graph.py` is the richer graph-view CLI over `check_migration_ownership.py`'s same parser. It accepts exact core version table/head plus repeated `--exact-edge CHILD:PARENT` and `--forbid-forks|--forbid-merges|--forbid-orphans`; it proves the complete unique closed ancestry without importing migration code. The two CLIs share implementation and fixtures, so no second migration truth exists.

- [ ] **Step 1: Write the scanner’s red tests**

```python
# tests/security/test_private_data_scanner.py
import dataclasses
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest
import scripts.verify_private_data as private_data_scanner
from scripts import scan_private_data as private_data_cli
from scripts.verify_private_data import scan


def _credential(fill: bytes = b"A") -> bytes:
    return b"".join((b"sk-", b"proj-", fill * 24))


def _private_key_marker() -> bytes:
    return b"".join((b"-----BEGIN ", b"PRIVATE ", b"KEY-----"))


def _git(root: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    return subprocess.run(
        ("git", "-C", str(root), *arguments),
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout


def _source_repository(root: Path) -> Path:
    _git(root, "init", "-q")
    return root


def test_scanner_rejects_secret_and_database(tmp_path: Path) -> None:
    credential = _credential().decode("ascii")
    (tmp_path / "leak.txt").write_text(credential, encoding="utf-8")
    (tmp_path / "family.sqlite3").write_bytes(b"SQLite format 3\x00")
    assert {(finding.path.name, finding.reason) for finding in scan(tmp_path)} == {
        ("family.sqlite3", "forbidden-extension"),
        ("leak.txt", "credential-pattern"),
    }


def test_scanner_allows_declared_synthetic_text(tmp_path: Path) -> None:
    fixture = tmp_path / "tests" / "fixtures" / "synthetic"
    fixture.mkdir(parents=True)
    (fixture / "case.json").write_text('{"speaker":"synthetic-guest"}', encoding="utf-8")
    assert scan(tmp_path) == ()


def test_source_root_omits_git_ignored_tool_cache_and_pnpm_outputs(
    tmp_path: Path,
) -> None:
    root = _source_repository(tmp_path)
    (root / ".gitignore").write_text(
        "__pycache__/\n.mypy_cache/\nnode_modules/\ndist/\nvar/\n",
        encoding="utf-8",
    )
    _git(root, "add", ".gitignore")
    (root / ".mypy_cache").mkdir()
    (root / ".mypy_cache" / "cache.db").write_bytes(b"SQLite format 3\x00")
    (root / "pkg" / "__pycache__").mkdir(parents=True)
    (root / "pkg" / "__pycache__" / "compiled.pyc").write_bytes(_credential())
    pnpm = root / "apps" / "admin" / "node_modules"
    (pnpm / ".pnpm" / "synthetic").mkdir(parents=True)
    (pnpm / "synthetic").symlink_to(".pnpm/synthetic", target_is_directory=True)
    assert scan(root) == ()


def test_nonignored_source_subtree_uses_git_inventory(tmp_path: Path) -> None:
    root = _source_repository(tmp_path)
    (root / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
    source = root / "src"
    source.mkdir()
    (source / "tracked.py").write_text("VALUE = 'synthetic'\n", encoding="utf-8")
    _git(root, "add", ".gitignore", "src/tracked.py")
    ignored = source / "__pycache__" / "tracked.pyc"
    ignored.parent.mkdir()
    ignored.write_bytes(_credential())
    assert scan(source) == ()


def test_visible_untracked_source_file_is_scanned(tmp_path: Path) -> None:
    root = _source_repository(tmp_path)
    leak = root / "visible-untracked.txt"
    leak.write_bytes(_credential())
    assert any(
        finding.path == Path("visible-untracked.txt")
        and finding.reason == "credential-pattern"
        for finding in scan(root)
    )


def test_staged_index_blob_is_scanned_even_when_worktree_copy_is_clean(
    tmp_path: Path,
) -> None:
    root = _source_repository(tmp_path)
    staged = root / "staged-only.txt"
    staged.write_bytes(_credential())
    _git(root, "add", "staged-only.txt")
    staged.write_text("synthetic working tree\n", encoding="utf-8")
    assert any(
        finding.path == Path("<git-index>/staged-only.txt")
        and finding.reason == "credential-pattern"
        for finding in scan(root)
    )


def test_force_tracked_file_beneath_ignored_directory_is_scanned(
    tmp_path: Path,
) -> None:
    root = _source_repository(tmp_path)
    (root / ".gitignore").write_text("dist/\n", encoding="utf-8")
    leak = root / "dist" / "tracked.txt"
    leak.parent.mkdir()
    leak.write_bytes(_credential())
    _git(root, "add", ".gitignore")
    _git(root, "add", "-f", "dist/tracked.txt")
    assert any(item.reason == "credential-pattern" for item in scan(root))


def test_explicit_ignored_artifact_root_receives_complete_physical_scan(
    tmp_path: Path,
) -> None:
    root = _source_repository(tmp_path)
    (root / ".gitignore").write_text("dist/\n", encoding="utf-8")
    _git(root, "add", ".gitignore")
    artifact = root / "dist"
    artifact.mkdir()
    (artifact / "candidate.txt").write_bytes(_credential())
    assert scan(root) == ()
    assert any(item.reason == "credential-pattern" for item in scan(artifact))


def test_conflicted_git_index_blocks_source_attestation(tmp_path: Path) -> None:
    root = _source_repository(tmp_path)
    ours = _git(root, "hash-object", "-w", "--stdin", input_bytes=b"ours\n").strip()
    theirs = _git(root, "hash-object", "-w", "--stdin", input_bytes=b"theirs\n").strip()
    _git(
        root,
        "update-index",
        "--index-info",
        input_bytes=b"".join(
            (
                b"100644 ", ours, b" 2\tconflict.txt\n",
                b"100644 ", theirs, b" 3\tconflict.txt\n",
            )
        ),
    )
    assert scan(root)[0].reason == "git-index-conflict"
    receipt = private_data_cli.evaluate(["--paths", str(root)])
    assert receipt.complete is False
    assert private_data_cli.main(["--paths", str(root)]) == 2


@pytest.mark.parametrize(
    "reason",
    ("git-inventory-failed", "git-inventory-timeout"),
)
def test_failed_or_timed_out_git_inventory_blocks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason: str,
) -> None:
    root = _source_repository(tmp_path)

    def fail(*_args, **_kwargs):
        raise private_data_scanner.GitInventoryError(root, reason)

    monkeypatch.setattr(private_data_scanner, "_git_output", fail)
    assert scan(root)[0].reason == reason


def test_malformed_git_inventory_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _source_repository(tmp_path)
    original = private_data_scanner._git_output

    def malformed(repository, arguments, *, max_bytes):
        if tuple(arguments[:2]) == ("ls-files", "--stage"):
            return b"not-an-index-record\0"
        return original(repository, arguments, max_bytes=max_bytes)

    monkeypatch.setattr(private_data_scanner, "_git_output", malformed)
    assert scan(root)[0].reason == "git-inventory-malformed"


def test_git_inventory_drift_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _source_repository(tmp_path)
    tracked = root / "tracked.txt"
    tracked.write_text("synthetic\n", encoding="utf-8")
    _git(root, "add", "tracked.txt")
    original = private_data_scanner._capture_source_snapshot
    calls = 0

    def drift(repository, scope):
        nonlocal calls
        calls += 1
        snapshot = original(repository, scope)
        if calls == 2:
            return dataclasses.replace(snapshot, index_raw=snapshot.index_raw + b"\0")
        return snapshot

    monkeypatch.setattr(private_data_scanner, "_capture_source_snapshot", drift)
    assert any(item.reason == "source-inventory-drift" for item in scan(root))


def test_symlink_ancestor_cannot_swap_the_classified_repository(tmp_path: Path) -> None:
    dirty = tmp_path / "dirty"
    clean = tmp_path / "clean"
    dirty.mkdir(); clean.mkdir()
    _source_repository(dirty); _source_repository(clean)
    (dirty / "secret.txt").write_bytes(_credential())
    (clean / "secret.txt").write_text("synthetic\n", encoding="utf-8")
    _git(dirty, "add", "secret.txt"); _git(clean, "add", "secret.txt")
    entry = tmp_path / "selected"
    entry.symlink_to(dirty, target_is_directory=True)
    findings = scan(entry / "secret.txt")
    assert findings == (
        private_data_scanner.Finding(entry, "filesystem-symlink-ancestor"),
    )


def test_opened_working_candidate_must_match_snapshot_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _source_repository(tmp_path)
    candidate = root / "visible.txt"
    replacement = root / "replacement.txt"
    candidate.write_bytes(_credential())
    replacement.write_text("synthetic\n", encoding="utf-8")
    original = private_data_scanner._open_relative_candidate
    swapped = False

    def replace_before_open(root_fd, repository, relative, expected_identity):
        nonlocal swapped
        if not swapped and relative == Path("visible.txt"):
            swapped = True
            candidate.replace(root / "old-visible.txt")
            replacement.replace(candidate)
        yield from original(root_fd, repository, relative, expected_identity)

    monkeypatch.setattr(
        private_data_scanner, "_open_relative_candidate", replace_before_open,
    )
    assert any(item.reason == "input-changed-during-scan" for item in scan(root))


@pytest.mark.parametrize("kind", ("fifo", "socket"))
def test_unignored_special_entry_missing_from_git_inventory_blocks(
    tmp_path: Path, kind: str,
) -> None:
    root = _source_repository(tmp_path)
    special = root / f"visible-{kind}"
    listener = None
    if kind == "fifo":
        os.mkfifo(special)
    else:
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(special))
    try:
        assert any(
            item.path == special and item.reason == "filesystem-special"
            for item in scan(root)
        )
    finally:
        if listener is not None:
            listener.close()


def test_explicit_out_root_with_ignored_child_is_artifact_scanned(tmp_path: Path) -> None:
    root = _source_repository(tmp_path)
    (root / ".gitignore").write_text("out/*\n", encoding="utf-8")
    _git(root, "add", ".gitignore")
    output = root / "out"
    output.mkdir()
    (output / "hidden.txt").write_bytes(_credential())
    assert any(item.reason == "credential-pattern" for item in scan(output))


@pytest.mark.parametrize("exclude_source", ("info", "local", "global", "system"))
def test_ambient_git_excludes_cannot_hide_source_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exclude_source: str,
) -> None:
    root = _source_repository(tmp_path)
    hidden = root / "hidden.txt"
    hidden.write_bytes(_credential())
    if exclude_source == "info":
        (root / ".git" / "info" / "exclude").write_text("hidden.txt\n", encoding="utf-8")
    elif exclude_source == "local":
        exclude = tmp_path / "local-excludes"
        exclude.write_text("hidden.txt\n", encoding="utf-8")
        _git(root, "config", "core.excludesFile", str(exclude))
    else:
        config = tmp_path / f"{exclude_source}.gitconfig"
        exclude = tmp_path / f"{exclude_source}-excludes"
        exclude.write_text("hidden.txt\n", encoding="utf-8")
        config.write_text(
            f"[core]\n\texcludesFile = {exclude}\n", encoding="utf-8",
        )
        monkeypatch.setenv(f"GIT_CONFIG_{exclude_source.upper()}", str(config))
    assert any(item.reason == "credential-pattern" for item in scan(root))


def test_git_processes_disable_lazy_fetch_prompts_configs_and_proxies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _source_repository(tmp_path)
    tracked = root / "tracked.txt"
    tracked.write_text("synthetic\n", encoding="utf-8")
    _git(root, "add", "tracked.txt")
    observed = []
    original = private_data_scanner.subprocess.Popen

    def recording_popen(*args, **kwargs):
        observed.append((args[0], dict(kwargs["env"]), kwargs.get("pass_fds", ())))
        return original(*args, **kwargs)

    monkeypatch.setattr(private_data_scanner.subprocess, "Popen", recording_popen)
    assert scan(root) == ()
    assert observed
    for argv, environment, pass_fds in observed:
        assert argv[:5] == (
            sys.executable, "-I", "-S", "-c",
            private_data_scanner.GIT_FD_EXEC_HELPER,
        )
        assert argv[5].isascii() and argv[5].isdigit()
        assert argv[6] == private_data_scanner.GIT_EXECUTABLE
        git_arguments = argv[6:]
        assert "-C" not in git_arguments
        assert "--git-dir=.git" in git_arguments
        assert "--work-tree=." in git_arguments
        for override in (
            "core.excludesFile=/dev/null", "core.fsmonitor=false",
            "core.hooksPath=/dev/null", "core.untrackedCache=false",
            "maintenance.auto=false", "gc.auto=0",
        ):
            assert override in git_arguments
        assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
        assert environment["GIT_CONFIG_GLOBAL"] == "/dev/null"
        assert environment["GIT_CONFIG_SYSTEM"] == "/dev/null"
        assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
        assert environment["GIT_NO_LAZY_FETCH"] == "1"
        assert environment["GIT_OPTIONAL_LOCKS"] == "0"
        assert environment["GIT_ATTR_NOSYSTEM"] == "1"
        assert environment["GIT_TERMINAL_PROMPT"] == "0"
        assert environment["GCM_INTERACTIVE"] == "never"
        assert environment["http_proxy"] == environment["https_proxy"] == ""
        assert pass_fds == (int(argv[5]),)


def test_missing_promised_blob_blocks_without_lazy_fetch(tmp_path: Path) -> None:
    root = _source_repository(tmp_path)
    missing_oid = "f" * 40
    _git(root, "config", "extensions.partialClone", "origin")
    _git(root, "config", "remote.origin.promisor", "true")
    _git(root, "config", "remote.origin.url", "https://127.0.0.1:9/unreachable")
    _git(
        root, "update-index", "--add", "--info-only", "--cacheinfo",
        f"100644,{missing_oid},promised.txt",
    )
    assert scan(root) == (
        private_data_scanner.Finding(
            Path("<git-index>/promised.txt"), "git-batch-object-missing",
        ),
    )
    assert private_data_cli.evaluate(["--paths", str(root)]).complete is False
    assert private_data_cli.main(["--paths", str(root)]) == 2


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin descriptor launch contract")
def test_darwin_git_startup_never_uses_swappable_lexical_worktree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected_slot = tmp_path / "selected"
    clean_slot = tmp_path / "clean"
    dirty = selected_slot / "repo"
    clean = clean_slot / "repo"
    dirty.mkdir(parents=True); clean.mkdir(parents=True)
    _source_repository(dirty); _source_repository(clean)
    (dirty / ".gitignore").write_text("ordinary-cache/*\n", encoding="utf-8")
    (dirty / "private.txt").write_bytes(_credential(b"D"))
    (clean / ".gitignore").write_text("private.txt\n", encoding="utf-8")
    (clean / "private.txt").write_text("synthetic\n", encoding="utf-8")

    original_popen = private_data_scanner.subprocess.Popen
    parked_dirty = tmp_path / "parked-dirty"
    swaps = 0

    class RestoringProcess:
        def __init__(self, process):
            self.process = process
            self.restored = False

        def restore(self) -> None:
            if self.restored:
                return
            selected_slot.rename(clean_slot)
            parked_dirty.rename(selected_slot)
            self.restored = True

        def wait(self, *args, **kwargs):
            try:
                return self.process.wait(*args, **kwargs)
            finally:
                self.restore()

        def poll(self):
            return self.process.poll()

        def kill(self):
            return self.process.kill()

        def __getattr__(self, name):
            return getattr(self.process, name)

    def swap_for_lexical_git(arguments, *args, **kwargs):
        nonlocal swaps
        vector = tuple(os.fspath(item) for item in arguments)
        lexical_git = (
            len(vector) >= 5
            and vector[0] == "git"
            and "-C" in vector
            and vector[vector.index("-C") + 1] == str(dirty)
        )
        descriptor_helper = (
            len(vector) >= 8
            and vector[:4] == (sys.executable, "-I", "-S", "-c")
            and vector[4] == getattr(
                private_data_scanner, "GIT_FD_EXEC_HELPER", "not-present",
            )
            and "--git-dir=.git" in vector
        )
        if not (lexical_git or descriptor_helper):
            return original_popen(arguments, *args, **kwargs)
        swaps += 1
        selected_slot.rename(parked_dirty)
        clean_slot.rename(selected_slot)
        try:
            return RestoringProcess(original_popen(arguments, *args, **kwargs))
        except BaseException:
            selected_slot.rename(clean_slot)
            parked_dirty.rename(selected_slot)
            raise

    monkeypatch.setattr(private_data_scanner.subprocess, "Popen", swap_for_lexical_git)
    findings = scan(dirty)
    assert swaps > 0
    assert any(item.reason == "credential-pattern" for item in findings)


def test_replacement_ref_cannot_replace_index_blob_bytes(tmp_path: Path) -> None:
    root = _source_repository(tmp_path)
    payload = root / "payload.txt"
    payload.write_bytes(_credential(b"R"))
    _git(root, "add", "payload.txt")
    indexed_oid = _git(root, "rev-parse", ":payload.txt").strip().decode("ascii")
    clean_oid = _git(
        root, "hash-object", "-w", "--stdin", input_bytes=b"ordinary\n",
    ).strip().decode("ascii")
    _git(root, "replace", indexed_oid, clean_oid)
    payload.write_text("ordinary\n", encoding="utf-8")
    assert any(item.reason == "credential-pattern" for item in scan(root))


def test_alternate_object_body_must_match_index_oid(tmp_path: Path) -> None:
    import zlib

    root = _source_repository(tmp_path)
    payload = root / "payload.txt"
    payload.write_bytes(_credential(b"A"))
    _git(root, "add", "payload.txt")
    indexed_oid = _git(root, "rev-parse", ":payload.txt").strip().decode("ascii")
    original = root / ".git" / "objects" / indexed_oid[:2] / indexed_oid[2:]
    alternate = tmp_path / "alternate-objects"
    forged = alternate / indexed_oid[:2] / indexed_oid[2:]
    forged.parent.mkdir(parents=True)
    clean = b"ordinary\n"
    forged.write_bytes(zlib.compress(b"blob 9\0" + clean))
    (root / ".git" / "objects" / "info" / "alternates").write_text(
        str(alternate) + "\n", encoding="utf-8",
    )
    original.unlink()
    payload.write_bytes(clean)
    assert scan(root) == (
        private_data_scanner.Finding(
            Path("<git-index>/payload.txt"), "git-batch-content-oid-mismatch",
        ),
    )


def test_repository_fsmonitor_helper_is_never_invoked(tmp_path: Path) -> None:
    root = _source_repository(tmp_path)
    (root / "ordinary.txt").write_text("ordinary\n", encoding="utf-8")
    _git(root, "add", "ordinary.txt")
    marker = tmp_path / "fsmonitor-was-run"
    hook = tmp_path / "fsmonitor-hook.sh"
    hook.write_text(
        "#!/bin/sh\n"
        f"/usr/bin/touch {marker}\n"
        "printf 'token\\n'\n",
        encoding="utf-8",
    )
    hook.chmod(0o700)
    _git(root, "config", "core.fsmonitor", str(hook))
    assert scan(root) == ()
    assert not marker.exists()


def test_git_batch_trailing_stdout_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _source_repository(tmp_path)
    (root / "ordinary.txt").write_bytes(b"ordinary\n")
    _git(root, "add", "ordinary.txt")
    original_popen = private_data_scanner.subprocess.Popen
    script = (
        "import sys\n"
        "oid=sys.stdin.buffer.readline().strip()\n"
        "body=b'ordinary\\n'\n"
        "sys.stdout.buffer.write(oid+b' blob 9\\n'+body+b'\\n'+b'x'*1024)\n"
        "sys.stdout.buffer.flush()\n"
    )

    def inject_trailing_output(arguments, *args, **kwargs):
        vector = tuple(os.fspath(item) for item in arguments)
        if "cat-file" in vector and "--batch" in vector:
            return original_popen(
                (sys.executable, "-I", "-S", "-c", script), *args, **kwargs,
            )
        return original_popen(arguments, *args, **kwargs)

    monkeypatch.setattr(private_data_scanner, "MAX_GIT_BATCH_BUFFER_BYTES", 128, raising=False)
    monkeypatch.setattr(
        private_data_scanner.subprocess, "Popen", inject_trailing_output,
    )
    assert scan(root)[-1].reason == "git-batch-output-limit"


def test_every_git_process_wait_is_deadline_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _source_repository(tmp_path)
    (root / "ordinary.txt").write_text("ordinary\n", encoding="utf-8")
    _git(root, "add", "ordinary.txt")
    original_popen = private_data_scanner.subprocess.Popen
    waits = []

    class RecordingProcess:
        def __init__(self, process):
            self.process = process

        def wait(self, *args, **kwargs):
            waits.append(kwargs.get("timeout"))
            return self.process.wait(*args, **kwargs)

        def __getattr__(self, name):
            return getattr(self.process, name)

    def record_waits(*args, **kwargs):
        return RecordingProcess(original_popen(*args, **kwargs))

    monkeypatch.setattr(private_data_scanner.subprocess, "Popen", record_waits)
    assert scan(root) == ()
    assert waits
    assert all(timeout is not None for timeout in waits)


def test_index_blobs_use_one_batch_and_charge_before_body_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _source_repository(tmp_path)
    for name in ("one.txt", "two.txt"):
        (root / name).write_bytes(b"x" * 256)
    _git(root, "add", "one.txt", "two.txt")
    starts = 0
    original_start = private_data_scanner._start_git_batch
    original_copy = private_data_scanner.GitBatch._copy_body

    def counted_start(*args, **kwargs):
        nonlocal starts
        starts += 1
        return original_start(*args, **kwargs)

    def charged_copy(self, destination, declared_size, display, budget):
        assert budget.input_bytes >= declared_size
        return original_copy(self, destination, declared_size, display, budget)

    monkeypatch.setattr(private_data_scanner, "_start_git_batch", counted_start)
    monkeypatch.setattr(private_data_scanner.GitBatch, "_copy_body", charged_copy)
    assert scan(root) == ()
    assert starts == 1


def test_shared_budget_blocks_index_blob_before_body_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _source_repository(tmp_path)
    (root / "large.txt").write_bytes(b"x" * 1024)
    _git(root, "add", "large.txt")
    monkeypatch.setattr(private_data_scanner, "MAX_TOTAL_INPUT_BYTES", 100)
    monkeypatch.setattr(
        private_data_scanner.GitBatch,
        "_copy_body",
        lambda *_args, **_kwargs: pytest.fail("blob body read before budget rejection"),
    )
    assert scan(root)[-1].reason == "total-input-byte-limit"


@pytest.mark.parametrize(
    ("header", "reason"),
    (
        (b"missing\n", "git-batch-object-missing"),
        (b"0" * 40 + b" tree 1\n", "git-batch-type-invalid"),
        (b"1" * 40 + b" blob 1\n", "git-batch-oid-mismatch"),
        (b"0" * 40 + b" blob -1\n", "git-batch-size-invalid"),
        (b"0" * 40 + b" blob 01\n", "git-batch-size-invalid"),
    ),
)
def test_git_batch_header_is_exact(header: bytes, reason: str) -> None:
    with pytest.raises(private_data_scanner.GitInventoryError) as captured:
        private_data_scanner._parse_batch_header(header, "0" * 40, Path("index.txt"))
    assert captured.value.reason == reason


@pytest.mark.parametrize(
    ("delimiter", "reason"),
    ((b"", "git-batch-short-read"), (b"x", "git-batch-framing"), (b"\nextra", "git-batch-trailing-data")),
)
def test_git_batch_delimiter_is_exact(delimiter: bytes, reason: str) -> None:
    with pytest.raises(private_data_scanner.GitInventoryError) as captured:
        private_data_scanner._validate_batch_delimiter(delimiter, Path("index.txt"))
    assert captured.value.reason == reason


@pytest.mark.parametrize("alias_kind", ("same", "lexical", "hardlink"))
def test_duplicate_or_alias_roots_block_before_scanning(
    tmp_path: Path, alias_kind: str,
) -> None:
    first = tmp_path / "first.txt"
    first.write_text("synthetic\n", encoding="utf-8")
    if alias_kind == "same":
        second = first
    elif alias_kind == "lexical":
        second = tmp_path / "." / "first.txt"
    else:
        second = tmp_path / "second.txt"
        os.link(first, second)
    assert scan((first, second)) == (
        private_data_scanner.Finding(second.absolute(), "duplicate-root"),
    )


def test_one_budget_spans_mixed_source_and_artifact_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _source_repository(source)
    (source / "visible.txt").write_bytes(b"s" * 600)
    artifact = tmp_path / "candidate.bin"
    artifact.write_bytes(b"a" * 600)
    monkeypatch.setattr(private_data_scanner, "MAX_TOTAL_INPUT_BYTES", 1000)
    assert scan((source, artifact))[-1].reason == "total-input-byte-limit"


def test_explicit_generated_artifacts_and_bytes_after_two_megabytes_are_scanned(tmp_path: Path) -> None:
    artifact = tmp_path / "dist" / "candidate.bin"
    artifact.parent.mkdir()
    artifact.write_bytes(b"x" * 2_100_000 + _credential())
    findings = scan((tmp_path / "tests", artifact))
    assert (artifact, "credential-pattern") in {
        (finding.path, finding.reason) for finding in findings
    }


def test_every_bounded_archive_member_is_scanned(tmp_path: Path) -> None:
    import io
    import tarfile

    archive = tmp_path / "dist" / "candidate.tar.gz"
    archive.parent.mkdir()
    payload = b"x" * 2_100_000 + _private_key_marker()
    with tarfile.open(archive, "w:gz") as output:
        member = tarfile.TarInfo("nested/config.txt")
        member.size = len(payload)
        output.addfile(member, io.BytesIO(payload))
    findings = scan(archive)
    assert any(
        finding.path == Path(str(archive) + "!nested/config.txt")
        and finding.reason == "private-key"
        for finding in findings
    )


def test_realistic_reachy_wheelhouse_archive_is_streamed_past_old_16mib_limit(
    tmp_path: Path,
) -> None:
    import io
    import tarfile
    import zipfile

    archive = tmp_path / "tuntun-edge-realistic.tar.gz"
    wheel=io.BytesIO()
    with zipfile.ZipFile(wheel,"w",compression=zipfile.ZIP_STORED) as output:
        output.writestr("synthetic_runtime/payload.bin",b"synthetic-wheel-bytes\n"*1_100_000)
    payload=wheel.getvalue()
    with tarfile.open(archive, "w:gz") as output:
        member = tarfile.TarInfo("wheelhouse/synthetic_runtime-1.0-cp312-manylinux_aarch64.whl")
        member.size = len(payload)
        output.addfile(member, io.BytesIO(payload))
    assert len(payload) > 16 * 1024 * 1024
    assert scan(archive) == ()


def test_separate_raw_compressed_member_and_cumulative_limits_fail_closed(
    tmp_path: Path, monkeypatch,
) -> None:
    import io
    import tarfile

    large = tmp_path / "large.txt"
    large.write_bytes(b"x" * 1025)
    monkeypatch.setattr(private_data_scanner, "MAX_RAW_FILE_BYTES", 1024)
    assert scan(large)[0].reason == "raw-byte-limit"

    archive = tmp_path / "bomb.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        for name in ("one.bin", "two.bin"):
            member = tarfile.TarInfo(name)
            member.size = 800
            output.addfile(member, io.BytesIO(b"z" * member.size))
    monkeypatch.setattr(private_data_scanner, "MAX_COMPRESSED_ARCHIVE_BYTES", 1)
    assert scan(archive)[0].reason == "compressed-byte-limit"
    monkeypatch.setattr(private_data_scanner, "MAX_COMPRESSED_ARCHIVE_BYTES", 1024 * 1024)
    monkeypatch.setattr(private_data_scanner, "MAX_ARCHIVE_MEMBER_BYTES", 700)
    assert any(item.reason == "archive-member-byte-limit" for item in scan(archive))
    monkeypatch.setattr(private_data_scanner, "MAX_ARCHIVE_MEMBER_BYTES", 1024)
    monkeypatch.setattr(private_data_scanner, "MAX_CUMULATIVE_EXPANDED_BYTES", 1500)
    assert any(item.reason == "cumulative-expanded-byte-limit" for item in scan(archive))


def test_missing_explicit_release_root_fails_closed(tmp_path: Path) -> None:
    missing = tmp_path / "dist"
    assert [(item.path, item.reason) for item in scan(missing)] == [
        (missing, "missing-root")
    ]


def test_explicit_corrupt_archive_suffix_never_passes_as_an_ordinary_file(tmp_path: Path) -> None:
    for name in ("candidate.zip", "candidate.tar", "candidate.tar.gz", "candidate.tgz"):
        path=tmp_path/name; path.write_bytes(b"not a parseable archive")
        assert [(item.path,item.reason) for item in scan(path)]==[(path,"corrupt-archive")]


def test_corrupt_archive_magic_without_suffix_fails_closed(tmp_path: Path) -> None:
    for name,prefix in (("zipish.bin",b"PK\x03\x04broken"),("gzipish.bin",b"\x1f\x8bbroken")):
        path=tmp_path/name; path.write_bytes(prefix)
        assert [(item.path,item.reason) for item in scan(path)]==[(path,"corrupt-archive")]


@pytest.mark.parametrize(("mutation","reason"),(
    ("oversized_directory","zip-central-directory-limit"),
    ("inconsistent_offset","zip-central-directory-invalid"),
    ("dishonest_entry_count","zip-central-directory-invalid"),
))
def test_zip_eocd_preflight_bounds_directory_before_zipfile_allocation(
    tmp_path: Path,mutation:str,reason:str,
) -> None:
    import struct
    import zipfile

    archive=tmp_path/"malformed.zip"
    with zipfile.ZipFile(archive,"w") as output:
        output.writestr("safe.txt",b"safe"); output.writestr("also-safe.txt",b"safe")
    data=bytearray(archive.read_bytes()); marker=data.rfind(b"PK\x05\x06")
    assert marker>=0
    if mutation=="oversized_directory":
        struct.pack_into("<I",data,marker+12,private_data_scanner.MAX_ZIP_CENTRAL_DIRECTORY_BYTES+1)
    else:
        if mutation=="inconsistent_offset":
            offset=struct.unpack_from("<I",data,marker+16)[0]
            struct.pack_into("<I",data,marker+16,offset+1)
        else:
            struct.pack_into("<H",data,marker+8,1)
            struct.pack_into("<H",data,marker+10,1)
    archive.write_bytes(data)
    assert scan(archive)[0].reason==reason


def test_nested_archive_member_is_recursively_scanned_under_the_same_budget(tmp_path: Path) -> None:
    import io
    import tarfile
    import zipfile

    nested=io.BytesIO()
    with zipfile.ZipFile(nested,"w",compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr("nested/config.txt", _credential())
    outer=tmp_path/"candidate.tar.gz"
    with tarfile.open(outer,"w:gz") as output:
        member=tarfile.TarInfo("wheelhouse/example.whl")
        member.size=len(nested.getvalue())
        output.addfile(member,io.BytesIO(nested.getvalue()))
    assert any(item.reason=="credential-pattern" for item in scan(outer))


def test_filesystem_and_archive_symlink_or_special_entries_fail_closed(tmp_path: Path) -> None:
    import os
    import tarfile

    target=tmp_path/"target.txt"; target.write_text("synthetic")
    (tmp_path/"alias.txt").symlink_to(target)
    os.mkfifo(tmp_path/"named-pipe")
    archive=tmp_path/"links.tar"
    with tarfile.open(archive,"w") as output:
        symlink=tarfile.TarInfo("alias"); symlink.type=tarfile.SYMTYPE; symlink.linkname="target"
        output.addfile(symlink)
        device=tarfile.TarInfo("device"); device.type=tarfile.CHRTYPE
        output.addfile(device)
    reasons={item.reason for item in scan(tmp_path)}
    assert {"filesystem-symlink","filesystem-special","unsafe-archive-member"}<=reasons


def test_cumulative_actual_expansion_is_shared_across_archives(
    tmp_path: Path,monkeypatch,
) -> None:
    import gzip
    import io
    import tarfile

    archives=[]
    for index in range(2):
        archive=tmp_path/f"part-{index}.tar.gz"
        with tarfile.open(archive,"w:gz") as output:
            member=tarfile.TarInfo("payload.bin"); member.size=800
            output.addfile(member,io.BytesIO(b"x"*member.size))
        archives.append(archive)
    one_archive_expansion=len(gzip.decompress(archives[0].read_bytes()))
    monkeypatch.setattr(
        private_data_scanner,"MAX_CUMULATIVE_EXPANDED_BYTES",one_archive_expansion+512,
    )
    assert scan(archives[0])==()
    assert any(item.reason=="cumulative-expanded-byte-limit" for item in scan(tuple(archives)))


def test_files_input_bytes_and_archive_members_share_one_budget_across_roots(
    tmp_path: Path,monkeypatch,
) -> None:
    import io
    import tarfile

    raw=[]
    for index in range(2):
        path=tmp_path/f"raw-{index}.txt"; path.write_bytes(b"x"*800); raw.append(path)
    monkeypatch.setattr(private_data_scanner,"MAX_TOTAL_INPUT_BYTES",1500)
    assert scan(tuple(raw))[-1].reason=="total-input-byte-limit"
    monkeypatch.setattr(private_data_scanner,"MAX_TOTAL_INPUT_BYTES",4096)
    monkeypatch.setattr(private_data_scanner,"MAX_FILES",1)
    assert scan(tuple(raw))[-1].reason=="file-count-limit"

    monkeypatch.setattr(private_data_scanner,"MAX_FILES",10)
    archives=[]
    for index in range(2):
        archive=tmp_path/f"members-{index}.tar"
        with tarfile.open(archive,"w") as output:
            member=tarfile.TarInfo("payload.bin"); member.size=1
            output.addfile(member,io.BytesIO(b"x"))
        archives.append(archive)
    monkeypatch.setattr(private_data_scanner,"MAX_TOTAL_INPUT_BYTES",100_000)
    monkeypatch.setattr(private_data_scanner,"MAX_ARCHIVE_MEMBERS",1)
    assert scan(tuple(archives))[-1].reason=="archive-member-limit"


def test_streaming_walk_stops_before_materializing_a_million_entries(
    tmp_path: Path,monkeypatch,
) -> None:
    class Entry:
        def __init__(self,index): self.name=f"missing-{index}"
    class LazyMillion:
        emitted=0
        def __enter__(self): return self
        def __exit__(self,*_args): return False
        def __iter__(self): return self
        def __next__(self):
            if self.emitted==1_000_000: raise StopIteration
            item=Entry(self.emitted); self.emitted+=1; return item
    lazy=LazyMillion()
    original_stat=private_data_scanner.os.stat
    def bounded_stat(path,*args,dir_fd=None,**kwargs):
        if dir_fd is not None and str(path).startswith("missing-"):
            return type("Metadata",(),{
                "st_mode":private_data_scanner.stat.S_IFLNK,
                "st_dev":1,"st_ino":1,"st_size":0,"st_mtime_ns":0,"st_ctime_ns":0,
            })()
        return original_stat(path,*args,dir_fd=dir_fd,**kwargs)
    monkeypatch.setattr(private_data_scanner,"MAX_PATH_ENTRIES",3)
    monkeypatch.setattr(private_data_scanner.os,"scandir",lambda _path:lazy)
    monkeypatch.setattr(private_data_scanner.os,"stat",bounded_stat)
    assert any(item.reason=="path-entry-limit" for item in scan(tmp_path))
    assert lazy.emitted==4


def _ustar_header(name: bytes, size: int, kind: bytes = b"0") -> bytes:
    header=bytearray(512); header[0:len(name)]=name
    for offset,width,value in ((100,8,0o644),(108,8,0),(116,8,0),(124,12,size),(136,12,0)):
        encoded=(f"{value:0{width-1}o}\0").encode("ascii")
        header[offset:offset+width]=encoded
    header[148:156]=b"        "; header[156:157]=kind
    header[257:265]=b"ustar\x0000"
    checksum=sum(header); header[148:156]=f"{checksum:06o}\0 ".encode("ascii")
    return bytes(header)


@pytest.mark.parametrize("kind",(b"x",b"g",b"L",b"K"))
def test_tar_extended_metadata_is_blocked_before_declared_payload_allocation(
    tmp_path: Path,kind:bytes,
) -> None:
    archive=tmp_path/"hostile.tar"
    archive.write_bytes(_ustar_header(b"metadata",private_data_scanner.MAX_TAR_METADATA_BYTES+1,kind))
    assert scan(archive)[0].reason=="tar-metadata-limit"


def test_tar_and_gzip_trailing_bytes_are_bounded_and_must_be_zero(
    tmp_path: Path,monkeypatch,
) -> None:
    import gzip

    monkeypatch.setattr(private_data_scanner,"MAX_TAR_TRAILING_PADDING_BYTES",1024)
    monkeypatch.setattr(private_data_scanner,"MAX_GZIP_TRAILING_PADDING_BYTES",1024)
    end=b"\0"*1024
    excessive_tar=tmp_path/"tar-padding.tar.gz"
    excessive_tar.write_bytes(gzip.compress(end+b"\0"*1536,mtime=0))
    assert scan(excessive_tar)[0].reason=="tar-trailing-padding-limit"

    valid=tmp_path/"gzip-padding.tar.gz"
    compressed=gzip.compress(end,mtime=0)
    valid.write_bytes(compressed+b"\0"*1025)
    assert scan(valid)[0].reason=="gzip-trailing-padding-limit"
    valid.write_bytes(compressed+b"\0"*32+b"x")
    assert scan(valid)[0].reason=="gzip-trailing-data"


def test_gzip_header_crc_is_validated(tmp_path: Path) -> None:
    import gzip
    import struct
    import zlib

    compressed=gzip.compress(b"\0"*1024,mtime=0)
    header=bytearray(compressed[:10]); header[3]|=0x02
    crc=zlib.crc32(header)&0xffff
    valid=tmp_path/"valid-fhcrc.tar.gz"
    valid.write_bytes(bytes(header)+struct.pack("<H",crc)+compressed[10:])
    assert scan(valid)==()
    invalid=tmp_path/"invalid-fhcrc.tar.gz"
    invalid.write_bytes(bytes(header)+struct.pack("<H",crc^1)+compressed[10:])
    assert scan(invalid)[0].reason=="corrupt-archive"


@pytest.mark.parametrize("container",("zip_comment","zip_extra","tar_header","gzip_comment"))
def test_archive_metadata_bytes_are_pattern_scanned(tmp_path: Path,container:str) -> None:
    import gzip
    import struct
    import zipfile

    secret = _credential(b"M")
    path=tmp_path/(container+(".zip" if container.startswith("zip") else ".tar.gz"))
    if container.startswith("zip"):
        with zipfile.ZipFile(path,"w") as archive:
            item=zipfile.ZipInfo("safe.txt")
            if container=="zip_extra": item.extra=struct.pack("<HH",0xCAFE,len(secret))+secret
            archive.writestr(item,b"synthetic")
            if container=="zip_comment": archive.comment=secret
    elif container=="tar_header":
        header=bytearray(_ustar_header(b"safe.txt",0)); header[265:265+len(secret)]=secret
        header[148:156]=b"        "; header[148:156]=f"{sum(header):06o}\0 ".encode()
        path.write_bytes(gzip.compress(bytes(header)+b"\0"*1024,mtime=0))
    else:
        payload=gzip.compress(b"\0"*1024,mtime=0); fixed=bytearray(payload[:10]); fixed[3]|=0x10
        path.write_bytes(bytes(fixed)+secret+b"\0"+payload[10:])
    assert any(item.reason=="credential-pattern" for item in scan(path))


def test_cli_preserves_explicit_symlink_for_nofollow_rejection(
    tmp_path: Path,monkeypatch,capsys,
) -> None:
    target=tmp_path/"target.txt"; target.write_text("synthetic")
    alias=tmp_path/"explicit.txt"; alias.symlink_to(target)
    monkeypatch.setattr(private_data_scanner.sys,"argv",["verify_private_data.py",str(alias)])
    assert private_data_scanner.main()==1
    assert "filesystem-symlink" in capsys.readouterr().out


@pytest.mark.parametrize("generated_name",("dist","var","node_modules"))
def test_nested_generated_name_is_not_a_skip_boundary(
    tmp_path: Path,generated_name:str,
) -> None:
    nested=tmp_path/"src"/generated_name/"tracked-secret.txt"
    nested.parent.mkdir(parents=True); nested.write_bytes(_credential())
    assert any(item.reason=="credential-pattern" for item in scan(tmp_path))


def test_tracked_file_inside_exact_generated_root_is_scanned(tmp_path: Path) -> None:
    import subprocess

    subprocess.run(("git","init","-q",str(tmp_path)),check=True)
    secret=tmp_path/"dist"/"tracked-secret.txt"
    secret.parent.mkdir(); secret.write_bytes(_credential())
    subprocess.run(("git","-C",str(tmp_path),"add","dist/tracked-secret.txt"),check=True)
    assert any(item.reason=="credential-pattern" for item in scan(tmp_path))


def test_explicit_generated_root_does_not_skip_its_nested_generated_name(tmp_path: Path) -> None:
    root = _source_repository(tmp_path)
    (root / ".gitignore").write_text("var/\n", encoding="utf-8")
    _git(root, "add", ".gitignore")
    explicit=root/"var"; secret=explicit/"node_modules"/"secret.txt"
    secret.parent.mkdir(parents=True); secret.write_bytes(_credential())
    assert scan(root) == ()
    assert any(item.reason=="credential-pattern" for item in scan(explicit))


def test_zip_directory_payload_duplicate_and_unsafe_virtual_names_block(tmp_path: Path) -> None:
    import stat
    import zipfile

    for name,write in (
        ("payload.zip",lambda value: value.writestr("secret.txt/", _credential())),
        ("duplicate.zip",lambda value: (value.writestr("same.txt",b"one"),value.writestr("same.txt",b"two"))),
        ("escape.zip",lambda value: value.writestr("../escape.txt",b"synthetic")),
    ):
        archive=tmp_path/name
        with zipfile.ZipFile(archive,"w") as output: write(output)
        assert any(item.reason=="unsafe-archive-member" for item in scan(archive))
    valid=tmp_path/"directory.zip"
    with zipfile.ZipFile(valid,"w") as output:
        item=zipfile.ZipInfo("empty/"); item.external_attr=(stat.S_IFDIR|0o755)<<16
        output.writestr(item,b"")
    assert scan(valid)==()


def test_special_tar_member_with_nonzero_body_is_rejected_before_body_read(
    tmp_path: Path,
) -> None:
    archive=tmp_path/"special.tar"
    archive.write_bytes(_ustar_header(b"device",2*1024*1024*1024,b"3"))
    assert scan(archive)[0].reason=="unsafe-archive-member"


def test_named_file_and_queued_directory_replacement_cannot_attest_substitute(
    tmp_path: Path,monkeypatch,
) -> None:
    clean=tmp_path/"clean.txt"; clean.write_text("synthetic")
    substitute=tmp_path/"substitute.txt"; substitute.write_bytes(_credential())
    original_read=private_data_scanner.FrozenFileView.read; replaced=False
    def replacing_read(self,size=-1):
        nonlocal replaced
        if not replaced:
            replaced=True; clean.replace(tmp_path/"old.txt"); substitute.replace(clean)
        return original_read(self,size)
    monkeypatch.setattr(private_data_scanner.FrozenFileView,"read",replacing_read)
    assert any(item.reason=="input-changed-during-scan" for item in scan(clean))

    directory=tmp_path/"tree"; directory.mkdir(); (directory/"safe.txt").write_text("synthetic")
    replacement=tmp_path/"replacement"; replacement.mkdir()
    (replacement/"secret.txt").write_bytes(_credential(b"B"))
    original_scandir=private_data_scanner.os.scandir; swapped=False
    def replacing_scandir(path):
        nonlocal swapped
        if isinstance(path,int) and not swapped:
            swapped=True; directory.replace(tmp_path/"old-tree"); replacement.replace(directory)
        return original_scandir(path)
    monkeypatch.setattr(private_data_scanner.os,"scandir",replacing_scandir)
    findings=scan(directory)
    assert any(item.reason in {"input-changed-during-scan","credential-pattern"} for item in findings)


@pytest.mark.parametrize("replacement_kind",("regular","symlink","fifo"))
def test_walk_entry_replacement_between_first_stat_and_open_is_blocked(
    tmp_path:Path,monkeypatch,replacement_kind:str,
) -> None:
    tree=tmp_path/"walk-race"; tree.mkdir(); candidate=tree/"race.txt"
    candidate.write_text("synthetic"); substitute=tree/"substitute"
    substitute.write_bytes(_credential(b"R")); target=tree/"target"; target.write_text("synthetic")
    original_stat=private_data_scanner.os.stat; calls=0
    def replacing_stat(path,*args,dir_fd=None,**kwargs):
        nonlocal calls
        if dir_fd is not None and str(path)=="race.txt":
            calls+=1
            if calls==2:
                candidate.unlink()
                if replacement_kind=="regular": substitute.replace(candidate)
                elif replacement_kind=="symlink": candidate.symlink_to(target.name)
                else: private_data_scanner.os.mkfifo(candidate)
        return original_stat(path,*args,dir_fd=dir_fd,**kwargs)
    monkeypatch.setattr(private_data_scanner.os,"stat",replacing_stat)
    findings=scan(tree)
    assert calls>=2
    assert any(item.reason=="input-changed-during-scan" for item in findings)
```

Append a behavior-oriented Make contract test. It executes `web-build` with fake tools, proves the
scanner sees an already-created build tree, and proves a failed build prevents the scan:

```python
# tests/ci/test_web_command_contract.py (append)
def test_web_build_scans_dist_only_after_a_successful_build(tmp_path: Path) -> None:
    commands = tmp_path / "bin"
    commands.mkdir()
    log = tmp_path / "commands.log"
    pnpm = commands / "pnpm"
    pnpm.write_text(
        "#!/bin/sh\n"
        "printf 'build\\n' >> \"$COMMAND_LOG\"\n"
        "if test \"${FAIL_BUILD:-0}\" = 1; then exit 7; fi\n"
        "mkdir -p apps/admin/dist\n",
        encoding="utf-8",
    )
    scanner = commands / "uv"
    scanner.write_text(
        "#!/bin/sh\n"
        "test -d apps/admin/dist || exit 9\n"
        "test \"$*\" = "
        "'run python scripts/verify_private_data.py apps/admin/dist' || exit 10\n"
        "printf 'scan\\n' >> \"$COMMAND_LOG\"\n",
        encoding="utf-8",
    )
    pnpm.chmod(0o755)
    scanner.chmod(0o755)
    environment = {
        **os.environ,
        "COMMAND_LOG": str(log),
        "PATH": f"{commands}:{os.environ['PATH']}",
    }

    passed = subprocess.run(
        ["make", "-f", str(ROOT / "Makefile"), "web-build"],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert passed.returncode == 0, passed.stdout + passed.stderr
    assert log.read_text(encoding="utf-8").splitlines() == ["build", "scan"]

    log.unlink()
    failed = subprocess.run(
        ["make", "-f", str(ROOT / "Makefile"), "web-build"],
        cwd=tmp_path,
        env={**environment, "FAIL_BUILD": "1"},
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert failed.returncode == 2
    assert log.read_text(encoding="utf-8").splitlines() == ["build"]
```

Add `import os` to this test module's imports. This test owns execution order and exact scanner
arguments without parsing Makefile prose.

```python
# tests/security/test_shared_assurance_tools.py
import pytest

from scripts import (
    check_feature_absence,
    check_import_boundaries,
    check_migration_ownership,
    scan_browser_artifacts,
    scan_network_surface,
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
    tool, argv, shared_assurance_harness,
) -> None:
    workspace = shared_assurance_harness.complete_positive_workspace_for(tool)
    assert tool.main(["--root", str(workspace), *argv]) == 0


@pytest.mark.parametrize("fault", [
    "missing_input", "symlink_input", "special_input", "input_replaced",
    "duplicate_json_key", "invalid_utf8", "oversize", "overdepth", "too_many_files",
    "ambiguous_process_owner", "truncated_socket_inventory",
])
def test_shared_assurance_tools_never_convert_incomplete_scan_to_pass(
    shared_assurance_harness, fault,
) -> None:
    result = shared_assurance_harness.run_every_tool_with(fault)
    assert result.exit_codes
    assert all(code in {1, 2} for code in result.exit_codes)
    assert all(receipt.complete is False for receipt in result.receipts)


def test_feature_absence_checks_direct_replay_and_every_registration_surface(
    shared_assurance_harness,
) -> None:
    for surface in (
        "source", "config", "api", "openapi", "package", "browser_chunk",
        "ipc", "launchd", "direct_request", "replay",
    ):
        result = shared_assurance_harness.feature_present_only_on(surface)
        assert check_feature_absence.main(result.argv) == 1


def test_migration_checker_rejects_duplicate_revision_and_hidden_fork(
    migration_workspace,
) -> None:
    migration_workspace.add_duplicate_revision("0015")
    assert check_migration_ownership.main([
        "--root", str(migration_workspace.root), "--revisions", "0013", "0014", "0015",
        "--exact-head", "0015_presence_checkpoint", "--forbid-branch-merge-orphan",
    ]) == 1


def test_network_checker_requires_complete_pid_owner_snapshot(
    network_inventory, monkeypatch,
) -> None:
    network_inventory.truncate_between_socket_and_process_tables()
    network_inventory.install_as_probe(monkeypatch)
    assert scan_network_surface.main([
        "--require-listener", "127.0.0.1:8787=owner_ingress",
        "--forbid-wildcard",
    ]) == 2
```

Own the three named fixtures at the `tests/security` pytest scope. `tests/security/conftest.py` is executable fixture registration, not a declaration-only placeholder:

```python
# tests/security/conftest.py
from pathlib import Path

import pytest

from tests.security.assurance_cases import (
    MigrationWorkspace,
    NetworkInventory,
    SharedAssuranceHarness,
)


@pytest.fixture
def shared_assurance_harness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> SharedAssuranceHarness:
    return SharedAssuranceHarness(tmp_path / "shared", monkeypatch)


@pytest.fixture
def migration_workspace(tmp_path: Path) -> MigrationWorkspace:
    return MigrationWorkspace.create_linear(
        tmp_path / "migrations", ("0013", "0014", "0015")
    )


@pytest.fixture
def network_inventory(tmp_path: Path) -> NetworkInventory:
    return NetworkInventory.complete(
        tmp_path / "network",
        listeners=(("tcp", "127.0.0.1", 8787, 4101, "python", "owner_ingress"),),
    )
```

`tests/security/assurance_cases.py` implements these exact mutation interfaces:

- `SharedAssuranceHarness.complete_positive_workspace_for(tool) -> Path` creates a fresh descriptor-safe repository containing every inventory that the selected tool requires. It uses only regular UTF-8/duplicate-free files and, for network checks, installs a complete `capture_inventory() -> InventorySnapshot` probe through the captured `MonkeyPatch` before returning.
- `SharedAssuranceHarness.run_every_tool_with(fault) -> HarnessRun` creates a separate positive workspace per tool, applies exactly the named fault to that tool's required input/probe, calls both `tool.evaluate(argv)` and `tool.main(argv)`, and returns `HarnessRun(exit_codes: tuple[int, ...], receipts: tuple[AssuranceResult, ...])`. `exit_codes` contains the actual `main` result; `receipts` contains the actual `evaluate` result. The fault vocabulary is the eleven strings parameterized in the test; filesystem faults use lexical nofollow paths, parser faults mutate raw bytes, size/depth/count faults cross the production constant by exactly one, and process/socket faults alter the injected snapshot.
- `SharedAssuranceHarness.feature_present_only_on(surface) -> FeatureCase` begins from the complete feature-absence workspace, introduces `selected_frame_perception` on exactly one of the ten named registration/reachability surfaces, and returns `FeatureCase(argv: tuple[str, ...])` containing `--root`, `--feature selected_frame_perception`, `--phase 3`, and `--direct-and-replay` when the selected surface is direct/replay.
- `MigrationWorkspace.create_linear(root, revisions)` writes one import-free Alembic module per revision with a single linear `down_revision` and exposes `root: Path`. `add_duplicate_revision(revision)` writes a second module with the same `revision` value and a distinct filename while preserving the hidden fork, so the production AST inventory—not fixture metadata—causes exit 1.
- `NetworkInventory.complete(...)` stores normalized socket and process rows separately. `truncate_between_socket_and_process_tables()` removes the process row after the socket snapshot generation is fixed and marks the join incomplete. `install_as_probe(monkeypatch)` replaces only `scan_network_surface.capture_inventory` with a zero-argument callable returning that immutable snapshot; it does not replace the checker or its decision logic.

Implement the helper with concrete dataclasses (`HarnessRun`, `FeatureCase`, `MigrationWorkspace`, `NetworkInventory`) and literal file/probe mutations matching the contracts above. Its constructors reject an unknown fault/surface and never catch a tool assertion or synthesize a receipt. This makes all three fixtures available to `tests/security/test_shared_assurance_tools.py` without global fixture leakage.

- [ ] **Step 2: Run the red scanner tests**

Run: `uv run pytest tests/security/test_private_data_scanner.py tests/security/test_shared_assurance_tools.py tests/ci/test_web_command_contract.py -q`

Expected: RED. The security tests fail during collection because the private-data and shared
assurance modules do not exist; once their import owners are present, the new Make contract still
fails because `web-build` does not yet invoke the artifact scan.

- [ ] **Step 3: Implement bounded private-data and structural-assurance scanning**

```python
# scripts/verify_private_data.py
from __future__ import annotations

import hashlib
import io
import os
import re
import selectors
import stat
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path,PurePosixPath
from collections.abc import Sequence

FORBIDDEN_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".pem", ".key", ".crt", ".wav", ".mp3", ".mp4", ".jpg", ".jpeg", ".png", ".onnx", ".safetensors"}
PATTERNS = (("credential-pattern", re.compile(rb"(?:sk-proj-|AKIA)[A-Za-z0-9_-]{16,}")), ("private-key", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")))
GENERATED_ROOT_PARTS = {
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".venv", "__pycache__",
    "build", "coverage", "dist", "htmlcov", "node_modules", "out", "var",
}
ARTIFACT_ROOT_PARTS = {"artifact", "artifacts", "candidate", "candidates", "evidence", "release"}
ARCHIVE_ROOT_SUFFIXES = (".zip", ".whl", ".tar", ".tar.gz", ".tgz")
GIT_TIMEOUT_SECONDS = 10.0
GIT_REAP_TIMEOUT_SECONDS = 1.0
GIT_EXECUTABLE = "/usr/bin/git"
GIT_FD_EXEC_HELPER = (
    "import os,sys;"
    "os.fchdir(int(sys.argv[1]));"
    "os.execve(sys.argv[2],tuple(sys.argv[2:]),os.environ)"
)
MAX_GIT_INVENTORY_BYTES = 64 * 1024 * 1024
MAX_GIT_STDERR_BYTES = 1024 * 1024
STREAM_CHUNK_BYTES = 1024 * 1024
MAX_GIT_BATCH_BUFFER_BYTES = 2 * STREAM_CHUNK_BYTES
PATTERN_OVERLAP_BYTES = 256
MAX_RAW_FILE_BYTES = 4 * 1024 * 1024 * 1024
MAX_COMPRESSED_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
MAX_TOTAL_INPUT_BYTES = 16 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
MAX_CUMULATIVE_EXPANDED_BYTES = 12 * 1024 * 1024 * 1024
MAX_FILES = 100_000
MAX_PATH_ENTRIES = 100_000
MAX_ARCHIVE_MEMBERS = 50_000
MAX_ARCHIVE_DEPTH = 3
MAX_ZIP_CENTRAL_DIRECTORY_BYTES = 64 * 1024 * 1024
MAX_TAR_METADATA_BYTES = 64 * 1024
MAX_TAR_TRAILING_PADDING_BYTES = 1024 * 1024
MAX_GZIP_HEADER_BYTES = 64 * 1024
MAX_GZIP_TRAILING_PADDING_BYTES = 1024 * 1024
ZIP_MAGIC=(b"PK\x03\x04",b"PK\x05\x06",b"PK\x07\x08")


@dataclass(frozen=True, slots=True)
class Finding:
    path: Path
    reason: str


@dataclass(slots=True)
class OpenedCandidate:
    path:Path
    metadata:os.stat_result
    fd:int|None
    parent_fd:int|None
    name:str|None


class ScanLimit(RuntimeError):
    def __init__(self,path:Path,reason:str): self.path,self.reason=path,reason


@dataclass(slots=True)
class ScanBudget:
    path_entries:int=0; files:int=0; archive_members:int=0
    input_bytes:int=0; expanded_bytes:int=0
    def consume(self,field:str,amount:int,limit:int,path:Path,reason:str) -> None:
        value=getattr(self,field)+amount; setattr(self,field,value)
        if value>limit: raise ScanLimit(path,reason)
    def path_entry(self,path): self.consume("path_entries",1,MAX_PATH_ENTRIES,path,"path-entry-limit")
    def file(self,path): self.consume("files",1,MAX_FILES,path,"file-count-limit")
    def input(self,path,size): self.consume("input_bytes",size,MAX_TOTAL_INPUT_BYTES,path,"total-input-byte-limit")
    def member(self,path): self.consume("archive_members",1,MAX_ARCHIVE_MEMBERS,path,"archive-member-limit")
    def expanded(self,path,size): self.consume("expanded_bytes",size,MAX_CUMULATIVE_EXPANDED_BYTES,path,"cumulative-expanded-byte-limit")


class FrozenFileView:
    def __init__(self,source,size:int): self._source,self._size=source,size
    def tell(self): return self._source.tell()
    def readable(self): return True
    def seekable(self): return True
    def read(self,size=-1):
        remaining=max(0,self._size-self.tell())
        return self._source.read(remaining if size is None or size<0 else min(size,remaining))
    def seek(self,offset,whence=os.SEEK_SET):
        if whence==os.SEEK_SET: target=offset
        elif whence==os.SEEK_CUR: target=self.tell()+offset
        elif whence==os.SEEK_END: target=self._size+offset
        else: raise ValueError("invalid seek mode")
        if not 0<=target<=self._size: raise OSError("scan input changed bounds")
        return self._source.seek(target,os.SEEK_SET)


class ArchiveFormatError(RuntimeError):
    pass


def _read_exact(source,size:int) -> bytes:
    chunks=[]; remaining=size
    while remaining:
        chunk=source.read(remaining)
        if not chunk: raise ArchiveFormatError("truncated archive")
        chunks.append(chunk); remaining-=len(chunk)
    return b"".join(chunks)


class StrictGzipReader:
    """One bounded RFC-1952 member; concatenated members are deliberately blocked."""
    def __init__(self,source,display:Path):
        self._source=source; self._display=display; self._pending=b""
        self._decompressor=zlib.decompressobj(-zlib.MAX_WBITS)
        self._crc=0; self._size=0; self._finished=False
        self._read_header()
    def _compressed(self,size:int) -> bytes:
        result=self._pending[:size]; self._pending=self._pending[len(result):]
        if len(result)<size: result+=self._source.read(size-len(result))
        return result
    def _header_exact(self,size:int,counter:list[int]) -> bytes:
        counter[0]+=size
        if counter[0]>MAX_GZIP_HEADER_BYTES:
            raise ScanLimit(self._display,"gzip-header-limit")
        value=self._compressed(size)
        if len(value)!=size: raise ArchiveFormatError("truncated gzip header")
        return value
    def _header_c_string(self,counter:list[int]) -> bytes:
        value=bytearray()
        while True:
            byte=self._header_exact(1,counter); value.extend(byte)
            if byte==b"\0": return bytes(value)
    def _read_header(self) -> None:
        count=[0]; fixed=self._header_exact(10,count); header=bytearray(fixed)
        if fixed[:3]!=b"\x1f\x8b\x08" or fixed[3]&0xE0:
            raise ArchiveFormatError("invalid gzip header")
        flags=fixed[3]
        if flags&0x04:
            raw_length=self._header_exact(2,count); header.extend(raw_length)
            length=struct.unpack("<H",raw_length)[0]
            header.extend(self._header_exact(length,count))
        if flags&0x08: header.extend(self._header_c_string(count))
        if flags&0x10: header.extend(self._header_c_string(count))
        if flags&0x02:
            expected=struct.unpack("<H",self._header_exact(2,count))[0]
            if expected!=(zlib.crc32(header)&0xffff):
                raise ArchiveFormatError("invalid gzip header crc")
    def _finish(self) -> None:
        trailer=self._compressed(8)
        if len(trailer)!=8: raise ArchiveFormatError("truncated gzip trailer")
        expected_crc,expected_size=struct.unpack("<II",trailer)
        if expected_crc!=self._crc or expected_size!=(self._size&0xFFFFFFFF):
            raise ArchiveFormatError("invalid gzip trailer")
        trailing=0
        while True:
            chunk=self._compressed(64*1024)
            if not chunk: break
            trailing+=len(chunk)
            if trailing>MAX_GZIP_TRAILING_PADDING_BYTES:
                raise ScanLimit(self._display,"gzip-trailing-padding-limit")
            if any(chunk): raise ScanLimit(self._display,"gzip-trailing-data")
        self._finished=True
    def read(self,size=-1):
        if size is None or size<0: raise ValueError("bounded read size required")
        output=bytearray()
        while len(output)<size and not self._finished:
            if self._decompressor.eof:
                self._finish(); break
            if not self._pending:
                self._pending=self._source.read(64*1024)
                if not self._pending: raise ArchiveFormatError("truncated deflate stream")
            compressed=self._pending; self._pending=b""
            try:
                decoded=self._decompressor.decompress(compressed,size-len(output))
            except zlib.error as error:
                raise ArchiveFormatError("invalid deflate stream") from error
            if self._decompressor.eof:
                self._pending=self._decompressor.unused_data
            elif self._decompressor.unconsumed_tail:
                self._pending=self._decompressor.unconsumed_tail
            output.extend(decoded); self._crc=zlib.crc32(decoded,self._crc)
            self._size+=len(decoded)
        return bytes(output)


class ExpandedBudgetReader:
    def __init__(self,source,budget:ScanBudget,display:Path):
        self._source,self._budget,self._display=source,budget,display
    def read(self,size=-1):
        value=self._source.read(size)
        self._budget.expanded(self._display,len(value))
        return value


class TarMemberReader:
    def __init__(self,source,size:int): self._source,self.remaining=source,size
    def read(self,size=-1):
        if self.remaining==0: return b""
        requested=self.remaining if size is None or size<0 else min(size,self.remaining)
        value=self._source.read(requested); self.remaining-=len(value)
        return value


def _patterns_stream(
    path: Path, source, *, expected_size: int | None, byte_limit: int,
    limit_reason: str, budget:ScanBudget|None=None, expanded:bool=False,
    initial:bytes=b"", sink=None,
) -> list[Finding]:
    findings = []
    if Path(path.name.split("!", 1)[-1]).suffix.lower() in FORBIDDEN_SUFFIXES:
        findings.append(Finding(path, "forbidden-extension"))
    if expected_size is not None and expected_size > byte_limit:
        return [*findings, Finding(path, limit_reason)]
    total = 0
    tail = b""
    matched = set()
    pending=initial
    while pending or (pending:=source.read(STREAM_CHUNK_BYTES)):
        chunk=pending; pending=b""
        total += len(chunk)
        if total > byte_limit:
            return [*findings, Finding(path, limit_reason)]
        if expected_size is not None and total > expected_size:
            return [*findings, Finding(path, "archive-read-failed")]
        if budget is not None and expanded:
            budget.expanded(path,len(chunk))
        if sink is not None: sink.write(chunk)
        window = tail + chunk
        for reason, pattern in PATTERNS:
            if reason not in matched and pattern.search(window):
                matched.add(reason)
                findings.append(Finding(path, reason))
        tail = window[-PATTERN_OVERLAP_BYTES:]
    if expected_size is not None and total != expected_size:
        findings.append(Finding(path, "archive-read-failed"))
    return findings


def _archive_intent(name:str,prefix:bytes) -> str | None:
    name=name.lower()
    if name.endswith((".zip",".whl")) or prefix.startswith(ZIP_MAGIC): return "zip"
    if name.endswith((".tar.gz",".tgz")) or prefix.startswith(b"\x1f\x8b"):
        return "compressed_tar"
    if name.endswith(".tar") or prefix[257:262]==b"ustar": return "tar"
    return None


def _zip_member_count(source,display:Path,budget:ScanBudget) -> None:
    source.seek(0,os.SEEK_END); size=source.tell(); tail_offset=max(0,size-65_557)
    source.seek(tail_offset); tail=source.read(65_557); marker=tail.rfind(b"PK\x05\x06")
    while marker>=0:
        if len(tail)-marker>=22:
            comment_size=struct.unpack_from("<H",tail,marker+20)[0]
            if tail_offset+marker+22+comment_size==size: break
        marker=tail.rfind(b"PK\x05\x06",0,marker)
    if marker<0: raise zipfile.BadZipFile("missing EOCD")
    disk,directory_disk,disk_count,count=struct.unpack_from("<HHHH",tail,marker+4)
    directory_size,directory_offset=struct.unpack_from("<II",tail,marker+12)
    if (any(value==0xFFFF for value in (disk,directory_disk,disk_count,count))
        or directory_size==0xFFFFFFFF or directory_offset==0xFFFFFFFF):
        raise ScanLimit(display,"zip64-unsupported")
    if disk!=0 or directory_disk!=0 or disk_count!=count:
        raise ScanLimit(display,"zip-central-directory-invalid")
    if directory_size>MAX_ZIP_CENTRAL_DIRECTORY_BYTES:
        raise ScanLimit(display,"zip-central-directory-limit")
    eocd_offset=tail_offset+marker
    if (directory_size<count*46 or directory_offset>eocd_offset
        or directory_offset+directory_size!=eocd_offset):
        raise ScanLimit(display,"zip-central-directory-invalid")
    source.seek(directory_offset); remaining=directory_size; actual_count=0
    while remaining:
        header=source.read(46)
        if len(header)!=46 or not header.startswith(b"PK\x01\x02"):
            raise ScanLimit(display,"zip-central-directory-invalid")
        name_size,extra_size,comment_size=struct.unpack_from("<HHH",header,28)
        record_size=46+name_size+extra_size+comment_size
        if record_size>remaining:
            raise ScanLimit(display,"zip-central-directory-invalid")
        source.seek(record_size-46,os.SEEK_CUR); remaining-=record_size
        actual_count+=1
        if actual_count>MAX_ARCHIVE_MEMBERS:
            raise ScanLimit(display,"archive-member-limit")
    if actual_count!=count:
        raise ScanLimit(display,"zip-central-directory-invalid")
    if budget.archive_members+count>MAX_ARCHIVE_MEMBERS:
        raise ScanLimit(display,"archive-member-limit")
    source.seek(0)


def _canonical_archive_name(raw:str) -> str:
    if (not raw or "\\" in raw
        or any(ord(char)<32 or ord(char)==127 for char in raw)):
        raise ValueError("unsafe archive name")
    trimmed=raw[:-1] if raw.endswith("/") else raw
    path=PurePosixPath(trimmed)
    if (not trimmed or path.is_absolute() or path.as_posix()!=trimmed
        or any(part in {"",".",".."} for part in path.parts)):
        raise ValueError("unsafe archive name")
    return path.as_posix()


def _scan_member(
    source,name:str,display:Path,expected_size:int,budget:ScanBudget,depth:int,
    *,charge_expanded:bool=True,
):
    prefix=source.read(min(512,expected_size)); intent=_archive_intent(name,prefix)
    if intent is None:
        return _patterns_stream(
            display,source,initial=prefix,expected_size=expected_size,
            byte_limit=MAX_ARCHIVE_MEMBER_BYTES,limit_reason="archive-member-byte-limit",
            budget=budget,expanded=charge_expanded,
        )
    if depth>=MAX_ARCHIVE_DEPTH: return [Finding(display,"archive-depth-limit")]
    with tempfile.TemporaryFile() as nested:
        findings=_patterns_stream(
            display,source,initial=prefix,expected_size=expected_size,
            byte_limit=MAX_ARCHIVE_MEMBER_BYTES,limit_reason="archive-member-byte-limit",
            budget=budget,expanded=charge_expanded,sink=nested,
        )
        if any(item.reason.endswith("limit") or item.reason=="archive-read-failed" for item in findings):
            return findings
        nested.seek(0)
        return [*findings,*_scan_archive(nested,intent,display,budget,depth+1)]


def _tar_octal(field:bytes) -> int:
    value=field.rstrip(b"\0 ").lstrip(b" ")
    if not value or re.fullmatch(rb"[0-7]+",value) is None:
        raise ArchiveFormatError("invalid tar number")
    return int(value,8)


def _tar_name(header:bytes) -> str:
    name=header[0:100].split(b"\0",1)[0]
    prefix=header[345:500].split(b"\0",1)[0]
    raw=(prefix+b"/" if prefix else b"")+name
    try: value=raw.decode("utf-8")
    except UnicodeDecodeError as error: raise ArchiveFormatError("invalid tar name") from error
    value=value[:-1] if value.endswith("/") else value
    parts=value.split("/")
    if (not value or value.startswith("/") or "\\" in value
        or any(part in {"",".",".."} for part in parts)):
        raise ArchiveFormatError("unsafe tar name")
    return value


def _discard_exact(source,size:int) -> None:
    remaining=size
    while remaining:
        chunk=source.read(min(STREAM_CHUNK_BYTES,remaining))
        if not chunk: raise ArchiveFormatError("truncated tar member")
        remaining-=len(chunk)


def _scan_ustar(source,display:Path,budget:ScanBudget,depth:int):
    findings=[]; saw_end=False
    while True:
        header=_read_exact(source,512)
        if header==b"\0"*512:
            if _read_exact(source,512)!=b"\0"*512:
                raise ArchiveFormatError("invalid tar end marker")
            saw_end=True; break
        if header[257:263] not in {b"ustar\0",b"ustar "}:
            raise ArchiveFormatError("unsupported tar format")
        findings.extend(_patterns_stream(
            display,io.BytesIO(header),expected_size=len(header),byte_limit=len(header),
            limit_reason="archive-member-byte-limit",
        ))
        stored=_tar_octal(header[148:156])
        checksum=sum(header[:148])+8*ord(" ")+sum(header[156:])
        if stored!=checksum: raise ArchiveFormatError("invalid tar checksum")
        size=_tar_octal(header[124:136]); name=_tar_name(header)
        member_display=Path(str(display)+"!"+name); budget.member(member_display)
        kind=header[156:157]
        if kind in {b"x",b"g",b"L",b"K"}:
            if size>MAX_TAR_METADATA_BYTES:
                raise ScanLimit(member_display,"tar-metadata-limit")
            _discard_exact(source,size)
            findings.append(Finding(member_display,"unsupported-tar-metadata"))
        elif kind==b"5":
            if size: raise ArchiveFormatError("directory has tar payload")
        elif kind in {b"",b"\0",b"0"}:
            if size>MAX_ARCHIVE_MEMBER_BYTES:
                raise ScanLimit(member_display,"archive-member-byte-limit")
            member_source=TarMemberReader(source,size)
            findings.extend(_scan_member(
                member_source,name,member_display,size,budget,depth,
                charge_expanded=False,
            ))
            if member_source.remaining: raise ArchiveFormatError("truncated tar member")
        else:
            if size:
                raise ScanLimit(member_display,"unsafe-archive-member")
            findings.append(Finding(member_display,"unsafe-archive-member"))
        padding=(-size)%512
        if padding and _read_exact(source,padding)!=b"\0"*padding:
            raise ArchiveFormatError("invalid tar member padding")
    if not saw_end: raise ArchiveFormatError("missing tar end marker")
    trailing=0
    while chunk:=source.read(512):
        trailing+=len(chunk)
        if trailing>MAX_TAR_TRAILING_PADDING_BYTES:
            raise ScanLimit(display,"tar-trailing-padding-limit")
        if len(chunk)!=512 or any(chunk):
            raise ScanLimit(display,"tar-trailing-data")
    return findings


def _scan_archive(source,intent:str,display:Path,budget:ScanBudget,depth:int):
    findings=[]
    if intent=="zip":
        _zip_member_count(source,display,budget)
        with zipfile.ZipFile(source) as archive:
            seen=set()
            for member in archive.infolist():
                raw_display=Path(str(display)+"!"+member.filename); budget.member(raw_display)
                try: canonical=_canonical_archive_name(member.filename)
                except ValueError:
                    findings.append(Finding(raw_display,"unsafe-archive-member")); continue
                member_display=Path(str(display)+"!"+canonical)
                mode=(member.external_attr>>16)&0o170000
                if canonical in seen:
                    findings.append(Finding(member_display,"unsafe-archive-member")); continue
                seen.add(canonical)
                if member.is_dir():
                    if (mode!=stat.S_IFDIR or member.file_size!=0
                        or member.compress_size!=0):
                        findings.append(Finding(member_display,"unsafe-archive-member"))
                    continue
                if mode==stat.S_IFDIR or (mode and mode!=stat.S_IFREG):
                    findings.append(Finding(member_display,"unsafe-archive-member")); continue
                with archive.open(member) as member_source:
                    findings.extend(_scan_member(
                        member_source,member.filename,member_display,
                        member.file_size,budget,depth,
                    ))
        return findings
    tar_source=(StrictGzipReader(source,display) if intent=="compressed_tar" else source)
    return _scan_ustar(ExpandedBudgetReader(tar_source,budget,display),display,budget,depth)


def _scan_file(
    path:Path,display:Path,budget:ScanBudget,candidate:OpenedCandidate|None=None,
) -> list[Finding]:
    try:
        metadata=path.lstat() if candidate is None else candidate.metadata
        if stat.S_ISLNK(metadata.st_mode): return [Finding(display,"filesystem-symlink")]
        if not stat.S_ISREG(metadata.st_mode): return [Finding(display,"filesystem-special")]
        budget.file(display)
        descriptor=(
            os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
            if candidate is None else candidate.fd
        )
        if descriptor is None: return [Finding(display,"unreadable-input")]
        if candidate is not None: candidate.fd=None
        with os.fdopen(descriptor,"rb") as source:
            opened=os.fstat(source.fileno())
            if (opened.st_dev,opened.st_ino)!=(metadata.st_dev,metadata.st_ino):
                return [Finding(display,"input-changed-during-scan")]
            budget.input(display,opened.st_size)
            frozen=FrozenFileView(source,opened.st_size)
            prefix=frozen.read(512); frozen.seek(0)
            intent=_archive_intent(path.name,prefix)
            input_limit = (
                MAX_COMPRESSED_ARCHIVE_BYTES
                if intent in {"zip", "compressed_tar"}
                else MAX_RAW_FILE_BYTES
            )
            if opened.st_size > input_limit:
                reason = (
                    "compressed-byte-limit"
                    if intent in {"zip", "compressed_tar"}
                    else "raw-byte-limit"
                )
                return [Finding(display, reason)]
            if intent is not None:
                # Scan every physical archive byte as well as expanded members;
                # this covers ZIP comments/extras, GZip optional headers, and TAR
                # header/reserved bytes that archive libraries do not yield.
                findings=_patterns_stream(
                    display,frozen,expected_size=opened.st_size,
                    byte_limit=input_limit,limit_reason="compressed-byte-limit",
                )
                frozen.seek(0)
                findings.extend(_scan_archive(frozen,intent,display,budget,0))
            else:
                findings=_patterns_stream(
                    display,frozen,expected_size=opened.st_size,
                    byte_limit=MAX_RAW_FILE_BYTES,limit_reason="raw-byte-limit",
                )
            final=os.fstat(source.fileno())
            opened_identity=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
            final_identity=(final.st_dev,final.st_ino,final.st_size,final.st_mtime_ns,final.st_ctime_ns)
            try:
                renamed=(
                    path.stat(follow_symlinks=False)
                    if candidate is None
                    else os.stat(
                        candidate.name,dir_fd=candidate.parent_fd,follow_symlinks=False,
                    )
                )
            except OSError:
                return [*findings,Finding(display,"input-changed-during-scan")]
            if (final_identity!=opened_identity or not stat.S_ISREG(renamed.st_mode)
                or (renamed.st_dev,renamed.st_ino)!=(opened.st_dev,opened.st_ino)):
                return [*findings,Finding(display,"input-changed-during-scan")]
            return findings
    except ScanLimit as error:
        return [Finding(error.path,error.reason)]
    except (EOFError,RuntimeError,zipfile.BadZipFile):
        return [Finding(display,"corrupt-archive")]
    except OSError:
        return [Finding(display, "unreadable-input")]
    finally:
        if candidate is not None and candidate.fd is not None:
            os.close(candidate.fd); candidate.fd=None


class GitInventoryError(ScanLimit):
    pass


@dataclass(frozen=True, slots=True)
class IndexEntry:
    mode: str
    oid: str
    path: PurePosixPath


@dataclass(frozen=True, slots=True)
class IgnoredEntry:
    path: PurePosixPath
    directory: bool


Identity = tuple[int, int, int, int, int, int]
AnchorIdentity = tuple[int, int, int]


@dataclass(slots=True)
class DirectoryBinding:
    path: Path
    paths: tuple[Path, ...]
    names: tuple[str | None, ...]
    fds: tuple[int, ...]
    identities: tuple[AnchorIdentity, ...]

    @classmethod
    def open(cls, path: Path) -> DirectoryBinding:
        path = Path(os.path.abspath(os.fspath(path)))
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        paths = [Path("/")]
        names: list[str | None] = [None]
        fds = [os.open("/", flags)]
        identities = [_anchor_identity(os.fstat(fds[0]))]
        try:
            current = Path("/")
            for part in path.parts[1:]:
                current = current / part
                metadata = os.stat(part, dir_fd=fds[-1], follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    raise ScanLimit(current, "filesystem-symlink-ancestor")
                if not stat.S_ISDIR(metadata.st_mode):
                    raise ScanLimit(current, "filesystem-special")
                child = os.open(part, flags, dir_fd=fds[-1])
                opened = os.fstat(child)
                if _anchor_identity(opened) != _anchor_identity(metadata):
                    os.close(child)
                    raise ScanLimit(current, "input-changed-during-scan")
                paths.append(current)
                names.append(part)
                fds.append(child)
                identities.append(_anchor_identity(opened))
            return cls(path, tuple(paths), tuple(names), tuple(fds), tuple(identities))
        except BaseException:
            for fd in reversed(fds):
                os.close(fd)
            raise

    @property
    def fd(self) -> int:
        return self.fds[-1]

    def revalidate(self) -> None:
        for index, (fd, expected) in enumerate(zip(self.fds, self.identities, strict=True)):
            if _anchor_identity(os.fstat(fd)) != expected:
                raise ScanLimit(self.paths[index], "input-changed-during-scan")
            if index:
                metadata = os.stat(
                    self.names[index], dir_fd=self.fds[index - 1], follow_symlinks=False,
                )
                if _anchor_identity(metadata) != expected:
                    raise ScanLimit(self.paths[index], "input-changed-during-scan")

    def close(self) -> None:
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds = ()


@dataclass(slots=True)
class RootBinding:
    path: Path
    parent: DirectoryBinding
    name: str
    fd: int
    identity: Identity
    directory: bool

    @classmethod
    def open(cls, path: Path) -> RootBinding:
        path = Path(os.path.abspath(os.fspath(path)))
        if path == Path("/"):
            raise ScanLimit(path, "root-scope-unsupported")
        parent = DirectoryBinding.open(path.parent)
        try:
            metadata = os.stat(path.name, dir_fd=parent.fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise ScanLimit(path, "filesystem-symlink")
            directory = stat.S_ISDIR(metadata.st_mode)
            if not directory and not stat.S_ISREG(metadata.st_mode):
                raise ScanLimit(path, "filesystem-special")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            if directory:
                flags |= getattr(os, "O_DIRECTORY", 0)
            fd = os.open(path.name, flags, dir_fd=parent.fd)
            opened = os.fstat(fd)
            if _identity(opened) != _identity(metadata):
                os.close(fd)
                raise ScanLimit(path, "input-changed-during-scan")
            return cls(path, parent, path.name, fd, _identity(opened), directory)
        except BaseException:
            parent.close()
            raise

    def revalidate(self) -> None:
        self.parent.revalidate()
        if _identity(os.fstat(self.fd)) != self.identity:
            raise ScanLimit(self.path, "input-changed-during-scan")
        metadata = os.stat(self.name, dir_fd=self.parent.fd, follow_symlinks=False)
        if _identity(metadata) != self.identity:
            raise ScanLimit(self.path, "input-changed-during-scan")

    def ancestry(self) -> tuple[tuple[Path, int, AnchorIdentity], ...]:
        result = []
        if self.directory:
            result.append((self.path, self.fd, _anchor_identity(os.fstat(self.fd))))
        result.extend(
            reversed(tuple(zip(self.parent.paths, self.parent.fds, self.parent.identities, strict=True)))
        )
        return tuple(result)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
        self.parent.close()


@dataclass(slots=True)
class RepositoryBinding:
    root: RootBinding
    marker_identity: Identity
    object_format: str | None = None

    @property
    def path(self) -> Path:
        return self.root.path

    @property
    def fd(self) -> int:
        return self.root.fd

    def revalidate(self) -> None:
        self.root.revalidate()
        marker = os.stat(".git", dir_fd=self.fd, follow_symlinks=False)
        if _identity(marker) != self.marker_identity:
            raise GitInventoryError(self.path, "git-state-unprovable")

    def close(self) -> None:
        self.root.close()


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    index_raw: bytes
    untracked_raw: bytes
    ignored_raw: bytes
    ignore_sources_raw: bytes
    index: tuple[IndexEntry, ...]
    untracked: tuple[PurePosixPath, ...]
    ignored: tuple[IgnoredEntry, ...]
    working: tuple[tuple[str, Identity | None], ...]
    ignore_sources: tuple[tuple[str, Identity], ...]


@dataclass(slots=True)
class RootClassification:
    repository: RepositoryBinding | None
    scope: PurePosixPath | None

    @property
    def source(self) -> bool:
        return self.repository is not None and self.scope is not None


def _identity(metadata: os.stat_result) -> Identity:
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def _anchor_identity(metadata: os.stat_result) -> AnchorIdentity:
    return metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode)


def _git_environment() -> dict[str, str]:
    return {
        "ALL_PROXY": "",
        "GCM_INTERACTIVE": "never",
        "GIT_ASKPASS": "/bin/false",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "LC_ALL": "C",
        "NO_PROXY": "*",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "SSH_ASKPASS": "/bin/false",
        "TMPDIR": "/tmp",
        "all_proxy": "",
        "http_proxy": "",
        "https_proxy": "",
    }


def _git_command(arguments: Sequence[str]) -> tuple[str, ...]:
    return (
        GIT_EXECUTABLE,
        "-c", "core.excludesFile=/dev/null",
        "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.untrackedCache=false",
        "-c", "maintenance.auto=false",
        "-c", "gc.auto=0",
        "--git-dir=.git", "--work-tree=.",
        *arguments,
    )


def _git_argv(repository: RepositoryBinding, arguments: Sequence[str]) -> tuple[str, ...]:
    return (
        sys.executable, "-I", "-S", "-c", GIT_FD_EXEC_HELPER,
        str(repository.fd), *_git_command(arguments),
    )


def _wait_process(process, deadline: float, path: Path) -> int:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise GitInventoryError(path, "git-inventory-timeout")
    try:
        return process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as error:
        raise GitInventoryError(path, "git-inventory-timeout") from error


def _kill_and_reap(process, path: Path) -> None:
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=GIT_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise GitInventoryError(path, "git-process-reap-timeout") from error


def _run_git(
    repository: RepositoryBinding,
    arguments: Sequence[str],
    *,
    max_bytes: int,
    allowed_returncodes: tuple[int, ...] = (0,),
) -> tuple[int, bytes]:
    repository.revalidate()
    process = subprocess.Popen(
        _git_argv(repository, arguments),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        env=_git_environment(),
        pass_fds=(repository.fd,),
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    output = bytearray()
    errors = bytearray()
    deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GitInventoryError(repository.path, "git-inventory-timeout")
            ready = selector.select(remaining)
            if not ready:
                raise GitInventoryError(repository.path, "git-inventory-timeout")
            for key, _ in ready:
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = output if key.data == "stdout" else errors
                target.extend(chunk)
                limit = max_bytes if key.data == "stdout" else MAX_GIT_STDERR_BYTES
                if len(target) > limit:
                    raise GitInventoryError(repository.path, "git-inventory-output-limit")
        returncode = _wait_process(process, deadline, repository.path)
        if returncode not in allowed_returncodes or errors:
            raise GitInventoryError(repository.path, "git-inventory-failed")
        repository.revalidate()
        return returncode, bytes(output)
    except subprocess.SubprocessError as error:
        raise GitInventoryError(repository.path, "git-inventory-failed") from error
    finally:
        selector.close()
        _kill_and_reap(process, repository.path)


def _git_output(
    repository: RepositoryBinding, arguments: Sequence[str], *, max_bytes: int,
) -> bytes:
    return _run_git(repository, arguments, max_bytes=max_bytes)[1]


def _repository_for(root: RootBinding) -> RepositoryBinding | None:
    for path, directory_fd, expected_identity in root.ancestry():
        try:
            marker = os.stat(".git", dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise GitInventoryError(path, "git-state-unprovable") from error
        if stat.S_ISLNK(marker.st_mode) or not (
            stat.S_ISDIR(marker.st_mode) or stat.S_ISREG(marker.st_mode)
        ):
            raise GitInventoryError(path, "git-state-unprovable")
        candidate = RootBinding.open(path)
        if _anchor_identity(os.fstat(candidate.fd)) != expected_identity:
            candidate.close()
            raise GitInventoryError(path, "git-state-unprovable")
        repository = RepositoryBinding(candidate, _identity(marker))
        break
    else:
        return None
    try:
        state = _git_output(
            repository,
            ("rev-parse", "--is-inside-work-tree", "--is-inside-git-dir"),
            max_bytes=64,
        )
        if state != b"true\nfalse\n":
            raise GitInventoryError(repository.path, "git-state-unprovable")
        object_format = _git_output(
            repository, ("rev-parse", "--show-object-format"), max_bytes=16,
        )
        if object_format not in {b"sha1\n", b"sha256\n"}:
            raise GitInventoryError(repository.path, "git-object-format-unsupported")
        repository.object_format = object_format[:-1].decode("ascii")
        repository.revalidate()
        return repository
    except BaseException:
        repository.close()
        raise


def _canonical_git_path(
    raw: bytes, repository: Path, scope: PurePosixPath,
) -> PurePosixPath:
    if not raw or len(raw) > 4096:
        raise GitInventoryError(repository, "git-inventory-malformed")
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GitInventoryError(repository, "git-inventory-malformed") from error
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or "\\" in value
        or any(part in {"", ".", ".."} for part in path.parts)
        or (scope != PurePosixPath(".") and path != scope and scope not in path.parents)
    ):
        raise GitInventoryError(repository, "git-inventory-malformed")
    return path


def _nul_records(raw: bytes, repository: Path) -> tuple[bytes, ...]:
    if not raw:
        return ()
    if not raw.endswith(b"\0"):
        raise GitInventoryError(repository, "git-inventory-malformed")
    records = tuple(raw[:-1].split(b"\0"))
    if len(records) > MAX_PATH_ENTRIES or any(not record for record in records):
        raise GitInventoryError(repository, "path-entry-limit")
    return records


def _parse_index_inventory(
    raw: bytes, repository: Path, scope: PurePosixPath, object_format: str,
) -> tuple[IndexEntry, ...]:
    result = []
    seen = set()
    for record in _nul_records(raw, repository):
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, oid, stage = header.split(b" ")
        except ValueError as error:
            raise GitInventoryError(repository, "git-inventory-malformed") from error
        if stage not in {b"0", b"1", b"2", b"3"}:
            raise GitInventoryError(repository, "git-inventory-malformed")
        path = _canonical_git_path(raw_path, repository, scope)
        if stage != b"0":
            raise GitInventoryError(repository / Path(path.as_posix()), "git-index-conflict")
        if mode not in {b"100644", b"100755"}:
            raise GitInventoryError(repository / Path(path.as_posix()), "git-index-mode-invalid")
        oid_width = 40 if object_format == "sha1" else 64
        if len(oid) != oid_width or re.fullmatch(rb"[0-9a-f]+", oid) is None:
            raise GitInventoryError(repository, "git-inventory-malformed")
        if path in seen:
            raise GitInventoryError(repository, "git-inventory-malformed")
        seen.add(path)
        result.append(IndexEntry(mode.decode("ascii"), oid.decode("ascii"), path))
    return tuple(result)


def _parse_untracked_inventory(
    raw: bytes, repository: Path, scope: PurePosixPath,
) -> tuple[PurePosixPath, ...]:
    result = []
    seen = set()
    for record in _nul_records(raw, repository):
        path = _canonical_git_path(record, repository, scope)
        if path in seen:
            raise GitInventoryError(repository, "git-inventory-malformed")
        seen.add(path)
        result.append(path)
    return tuple(result)


def _parse_ignored_inventory(
    raw: bytes, repository: Path, scope: PurePosixPath,
) -> tuple[IgnoredEntry, ...]:
    result = []
    seen = set()
    for record in _nul_records(raw, repository):
        directory = record.endswith(b"/")
        canonical = record[:-1] if directory else record
        path = _canonical_git_path(canonical, repository, scope)
        if path in seen:
            raise GitInventoryError(repository, "git-inventory-malformed")
        seen.add(path)
        result.append(IgnoredEntry(path, directory))
    return tuple(result)


def _captured_identity(
    repository: RepositoryBinding, relative: PurePosixPath,
) -> Identity | None:
    try:
        for candidate in _open_relative_candidate(
            repository.fd, repository.path, Path(relative.as_posix()), None,
        ):
            identity = _identity(candidate.metadata)
            if candidate.fd is not None:
                os.close(candidate.fd)
                candidate.fd = None
            return identity
    except FileNotFoundError:
        return None
    raise GitInventoryError(repository.path, "git-inventory-malformed")


def _capture_source_snapshot(
    repository: RepositoryBinding, scope: PurePosixPath,
) -> SourceSnapshot:
    pathspec = scope.as_posix()
    index_raw = _git_output(
        repository,
        ("ls-files", "--stage", "-z", "--", pathspec),
        max_bytes=MAX_GIT_INVENTORY_BYTES,
    )
    untracked_raw = _git_output(
        repository,
        (
            "ls-files", "--others", "--exclude-per-directory=.gitignore",
            "-z", "--", pathspec,
        ),
        max_bytes=MAX_GIT_INVENTORY_BYTES,
    )
    ignored_raw = _git_output(
        repository,
        (
            "ls-files", "--others", "--ignored", "--directory",
            "--exclude-per-directory=.gitignore", "-z", "--", pathspec,
        ),
        max_bytes=MAX_GIT_INVENTORY_BYTES,
    )
    ignore_sources_raw = _git_output(
        repository,
        (
            "ls-files", "--cached", "--others", "-z", "--",
            ".gitignore", ":(glob)**/.gitignore",
        ),
        max_bytes=MAX_GIT_INVENTORY_BYTES,
    )
    assert repository.object_format is not None
    index = _parse_index_inventory(
        index_raw, repository.path, scope, repository.object_format,
    )
    untracked = _parse_untracked_inventory(untracked_raw, repository.path, scope)
    ignored = _parse_ignored_inventory(ignored_raw, repository.path, scope)
    ignore_sources = _parse_untracked_inventory(
        ignore_sources_raw, repository.path, PurePosixPath("."),
    )
    tracked_paths = tuple(entry.path for entry in index)
    if set(tracked_paths) & set(untracked):
        raise GitInventoryError(repository.path, "git-inventory-malformed")
    if (set(tracked_paths) | set(untracked)) & {entry.path for entry in ignored}:
        raise GitInventoryError(repository.path, "git-inventory-malformed")
    working = []
    untracked_set = set(untracked)
    for relative in (*tracked_paths, *untracked):
        try:
            identity = _captured_identity(repository, relative)
        except OSError as error:
            raise GitInventoryError(
                repository.path / Path(relative.as_posix()), "unreadable-input",
            ) from error
        if identity is None and relative in untracked_set:
            raise GitInventoryError(
                repository.path / Path(relative.as_posix()), "source-inventory-drift",
            )
        working.append((relative.as_posix(), identity))
    captured_ignores = []
    for relative in ignore_sources:
        identity = _captured_identity(repository, relative)
        if identity is None:
            raise GitInventoryError(
                repository.path / Path(relative.as_posix()), "source-inventory-drift",
            )
        captured_ignores.append((relative.as_posix(), identity))
    repository.revalidate()
    return SourceSnapshot(
        index_raw, untracked_raw, ignored_raw, ignore_sources_raw, index, untracked,
        ignored, tuple(working), tuple(captured_ignores),
    )


def _is_explicit_artifact(root: Path, repository: Path) -> bool:
    relative = root.relative_to(repository)
    lowered = tuple(part.lower() for part in relative.parts)
    if any(part in GENERATED_ROOT_PARTS | ARTIFACT_ROOT_PARTS for part in lowered):
        return True
    name = root.name.lower()
    if name.endswith(ARCHIVE_ROOT_SUFFIXES):
        return True
    return Path(name).stem in ARTIFACT_ROOT_PARTS


def _classify_root(root: RootBinding) -> RootClassification:
    repository = _repository_for(root)
    if repository is None:
        return RootClassification(None, None)
    try:
        relative = root.path.relative_to(repository.path)
    except ValueError as error:
        repository.close()
        raise GitInventoryError(root.path, "git-state-unprovable") from error
    scope = PurePosixPath(".") if not relative.parts else PurePosixPath(relative.as_posix())
    if scope == PurePosixPath("."):
        return RootClassification(repository, scope)
    if _is_explicit_artifact(root.path, repository.path):
        repository.close()
        return RootClassification(None, None)
    try:
        returncode, output = _run_git(
            repository,
            ("check-ignore", "--no-index", "-q", "--", scope.as_posix()),
            max_bytes=1,
            allowed_returncodes=(0, 1),
        )
    except BaseException:
        repository.close()
        raise
    if output:
        repository.close()
        raise GitInventoryError(root.path, "git-inventory-malformed")
    if returncode == 0:
        repository.close()
        return RootClassification(None, None)
    return RootClassification(repository, scope)


def _opened_candidate(
    parent_fd:int,name:str,path:Path,expected_identity:Identity|None=None,
) -> OpenedCandidate:
    metadata=os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
    if expected_identity is not None and _identity(metadata)!=expected_identity:
        raise ScanLimit(path,"input-changed-during-scan")
    if not stat.S_ISREG(metadata.st_mode):
        return OpenedCandidate(path,metadata,None,parent_fd,name)
    fd=os.open(name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=parent_fd)
    opened=os.fstat(fd)
    if (opened.st_dev,opened.st_ino)!=(metadata.st_dev,metadata.st_ino):
        os.close(fd); raise ScanLimit(path,"input-changed-during-scan")
    return OpenedCandidate(path,metadata,fd,parent_fd,name)


def _open_relative_candidate(
    root_fd:int,root:Path,relative:Path,expected_identity:Identity|None,
):
    current=os.dup(root_fd)
    try:
        for index,part in enumerate(relative.parts):
            path=root.joinpath(*relative.parts[:index+1])
            if index==len(relative.parts)-1:
                yield _opened_candidate(current,part,path,expected_identity); return
            metadata=os.stat(part,dir_fd=current,follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode): raise ScanLimit(path,"filesystem-symlink")
            if not stat.S_ISDIR(metadata.st_mode): raise ScanLimit(path,"filesystem-special")
            child=os.open(
                part,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0),
                dir_fd=current,
            )
            opened=os.fstat(child)
            if (opened.st_dev,opened.st_ino)!=(metadata.st_dev,metadata.st_ino):
                os.close(child); raise ScanLimit(path,"input-changed-during-scan")
            os.close(current); current=child
    finally: os.close(current)


def _walk_directory(
    root:Path,directory:Path,directory_fd:int,budget:ScanBudget,*,depth:int,
):
    if depth>64: raise ScanLimit(directory,"directory-depth-limit")
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            path=directory/entry.name; relative=path.relative_to(root); budget.path_entry(relative)
            metadata=os.stat(entry.name,dir_fd=directory_fd,follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                child=os.open(
                    entry.name,
                    os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0),
                    dir_fd=directory_fd,
                )
                opened=os.fstat(child)
                if (opened.st_dev,opened.st_ino)!=(metadata.st_dev,metadata.st_ino):
                    os.close(child); raise ScanLimit(path,"input-changed-during-scan")
                try:
                    yield from _walk_directory(root,path,child,budget,depth=depth+1)
                    renamed=os.stat(entry.name,dir_fd=directory_fd,follow_symlinks=False)
                    if _identity(renamed)!=_identity(opened):
                        raise ScanLimit(path,"input-changed-during-scan")
                finally: os.close(child)
                continue
            yield _opened_candidate(directory_fd,entry.name,path,_identity(metadata))


def _walk(root:RootBinding,budget:ScanBudget):
    root_fd=os.dup(root.fd); opened=os.fstat(root_fd)
    try:
        root.revalidate()
        if not stat.S_ISDIR(opened.st_mode) or _identity(opened)!=root.identity:
            raise ScanLimit(root.path,"input-changed-during-scan")
        yield from _walk_directory(root.path,root.path,root_fd,budget,depth=0)
        root.revalidate()
    finally: os.close(root_fd)


def _joined_git_path(parent: PurePosixPath, name: str) -> PurePosixPath:
    return PurePosixPath(name) if parent == PurePosixPath(".") else parent / name


def _ignored_by_snapshot(path: PurePosixPath, snapshot: SourceSnapshot) -> bool:
    for entry in snapshot.ignored:
        if path == entry.path or (entry.directory and entry.path in path.parents):
            return True
    return False


def _physical_source_directory(
    root: RootBinding,
    repository: RepositoryBinding,
    directory_fd: int,
    directory_path: Path,
    relative: PurePosixPath,
    candidates: set[PurePosixPath],
    snapshot: SourceSnapshot,
    budget: ScanBudget,
    depth: int,
) -> None:
    if depth > 64:
        raise ScanLimit(directory_path, "directory-depth-limit")
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            path = directory_path / entry.name
            child_relative = _joined_git_path(relative, entry.name)
            if relative == PurePosixPath(".") and entry.name == ".git":
                marker = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
                if _identity(marker) != repository.marker_identity:
                    raise GitInventoryError(repository.path, "git-state-unprovable")
                continue
            budget.path_entry(Path(child_relative.as_posix()))
            metadata = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
            if _ignored_by_snapshot(child_relative, snapshot):
                continue
            if stat.S_ISLNK(metadata.st_mode):
                raise ScanLimit(path, "filesystem-symlink")
            if stat.S_ISDIR(metadata.st_mode):
                flags = (
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                child = os.open(entry.name, flags, dir_fd=directory_fd)
                opened = os.fstat(child)
                if _identity(opened) != _identity(metadata):
                    os.close(child)
                    raise ScanLimit(path, "input-changed-during-scan")
                try:
                    _physical_source_directory(
                        root, repository, child, path, child_relative, candidates,
                        snapshot, budget, depth + 1,
                    )
                    renamed = os.stat(
                        entry.name, dir_fd=directory_fd, follow_symlinks=False,
                    )
                    if _identity(renamed) != _identity(opened):
                        raise ScanLimit(path, "input-changed-during-scan")
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ScanLimit(path, "filesystem-special")
            if child_relative not in candidates:
                raise GitInventoryError(path, "source-inventory-incomplete")
    root.revalidate()


def _supplement_source_inventory(
    root: RootBinding,
    classification: RootClassification,
    snapshot: SourceSnapshot,
    budget: ScanBudget,
) -> None:
    repository = classification.repository
    scope = classification.scope
    assert repository is not None and scope is not None
    candidates = {entry.path for entry in snapshot.index} | set(snapshot.untracked)
    if root.directory:
        directory_fd = os.dup(root.fd)
        try:
            _physical_source_directory(
                root, repository, directory_fd, root.path, scope, candidates,
                snapshot, budget, 0,
            )
        finally:
            os.close(directory_fd)
    elif scope not in candidates:
        raise GitInventoryError(root.path, "source-inventory-incomplete")
    root.revalidate()
    repository.revalidate()


def _terminal_limit(findings: Sequence[Finding]) -> bool:
    return bool(findings) and findings[-1].reason in {
        "path-entry-limit", "file-count-limit", "total-input-byte-limit",
        "archive-member-limit", "cumulative-expanded-byte-limit",
    }


def _source_display(
    root: RootBinding, repository: RepositoryBinding, relative: PurePosixPath, *, index: bool,
) -> Path:
    if index:
        return Path("<git-index>") / Path(relative.as_posix())
    if not root.directory:
        return root.path
    scope = root.path.relative_to(repository.path)
    visible = relative if not scope.parts else relative.relative_to(PurePosixPath(scope.as_posix()))
    return Path(visible.as_posix())


def _parse_batch_header(header: bytes, expected_oid: str, display: Path) -> int:
    if header == b"missing\n" or header.endswith(b" missing\n"):
        raise GitInventoryError(display, "git-batch-object-missing")
    if not header.endswith(b"\n") or len(header) > 256:
        raise GitInventoryError(display, "git-batch-framing")
    fields = header[:-1].split(b" ")
    if len(fields) != 3:
        raise GitInventoryError(display, "git-batch-framing")
    raw_oid, object_type, raw_size = fields
    if object_type != b"blob":
        raise GitInventoryError(display, "git-batch-type-invalid")
    if raw_oid != expected_oid.encode("ascii"):
        raise GitInventoryError(display, "git-batch-oid-mismatch")
    if (
        not raw_size or re.fullmatch(rb"[0-9]+", raw_size) is None
        or (len(raw_size) > 1 and raw_size.startswith(b"0"))
    ):
        raise GitInventoryError(display, "git-batch-size-invalid")
    return int(raw_size)


def _validate_batch_delimiter(delimiter: bytes, display: Path) -> None:
    if not delimiter:
        raise GitInventoryError(display, "git-batch-short-read")
    if delimiter == b"\n":
        return
    if delimiter.startswith(b"\n"):
        raise GitInventoryError(display, "git-batch-trailing-data")
    raise GitInventoryError(display, "git-batch-framing")


class DigestingWriter:
    def __init__(self, destination, digest):
        self.destination = destination
        self.digest = digest

    def write(self, value: bytes) -> int:
        self.digest.update(value)
        return self.destination.write(value)


class GitBatch:
    def __init__(self, repository: RepositoryBinding, process: subprocess.Popen[bytes]):
        self.repository = repository
        self.process = process
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        self.stdin = process.stdin
        self.stdout = process.stdout
        self.stderr = process.stderr
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.stdout, selectors.EVENT_READ, "stdout")
        self.selector.register(self.stderr, selectors.EVENT_READ, "stderr")
        self.output = bytearray()
        self.errors = bytearray()
        self.deadline = time.monotonic() + GIT_TIMEOUT_SECONDS

    def __enter__(self) -> GitBatch:
        return self

    def _pump(self, display: Path) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise GitInventoryError(display, "git-inventory-timeout")
        ready = self.selector.select(remaining)
        if not ready:
            raise GitInventoryError(display, "git-inventory-timeout")
        for key, _ in ready:
            chunk = os.read(key.fd, 64 * 1024)
            if not chunk:
                self.selector.unregister(key.fileobj)
                continue
            target = self.output if key.data == "stdout" else self.errors
            target.extend(chunk)
            if key.data == "stdout" and len(target) > MAX_GIT_BATCH_BUFFER_BYTES:
                raise GitInventoryError(display, "git-batch-output-limit")
            if key.data == "stderr" and len(target) > MAX_GIT_STDERR_BYTES:
                raise GitInventoryError(display, "git-inventory-output-limit")

    def _read_exact(self, size: int, display: Path) -> bytes:
        while len(self.output) < size:
            if self.stdout not in self.selector.get_map():
                raise GitInventoryError(display, "git-batch-short-read")
            self._pump(display)
        value = bytes(self.output[:size])
        del self.output[:size]
        return value

    def _readline(self, display: Path) -> bytes:
        while b"\n" not in self.output:
            if len(self.output) > 256:
                raise GitInventoryError(display, "git-batch-framing")
            if self.stdout not in self.selector.get_map():
                raise GitInventoryError(display, "git-batch-short-read")
            self._pump(display)
        end = self.output.index(b"\n") + 1
        value = bytes(self.output[:end])
        del self.output[:end]
        return value

    def _copy_body(
        self, destination, declared_size: int, display: Path, budget: ScanBudget,
    ) -> None:
        remaining = declared_size
        while remaining:
            chunk = self._read_exact(min(STREAM_CHUNK_BYTES, remaining), display)
            destination.write(chunk)
            remaining -= len(chunk)

    @contextmanager
    def blob(self, entry: IndexEntry, budget: ScanBudget):
        display = Path("<git-index>") / Path(entry.path.as_posix())
        self.deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
        try:
            self.stdin.write(entry.oid.encode("ascii") + b"\n")
            self.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            raise GitInventoryError(display, "git-inventory-failed") from error
        declared_size = _parse_batch_header(self._readline(display), entry.oid, display)
        if declared_size > MAX_RAW_FILE_BYTES:
            raise ScanLimit(display, "raw-byte-limit")
        budget.path_entry(display)
        budget.file(display)
        budget.input(display, declared_size)
        object_format = self.repository.object_format
        if object_format not in {"sha1", "sha256"}:
            raise GitInventoryError(display, "git-object-format-unsupported")
        digest = hashlib.new(object_format)
        digest.update(b"blob " + str(declared_size).encode("ascii") + b"\0")
        with tempfile.TemporaryFile() as source:
            self._copy_body(
                DigestingWriter(source, digest), declared_size, display, budget,
            )
            _validate_batch_delimiter(self._read_exact(1, display), display)
            if digest.hexdigest() != entry.oid:
                raise GitInventoryError(display, "git-batch-content-oid-mismatch")
            source.seek(0)
            yield FrozenFileView(source, declared_size), declared_size, display

    def _finish(self) -> None:
        self.stdin.close()
        self.deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
        while self.selector.get_map():
            self._pump(self.repository.path)
        if self.output:
            raise GitInventoryError(self.repository.path, "git-batch-trailing-data")
        if self.errors:
            raise GitInventoryError(self.repository.path, "git-inventory-failed")
        returncode = _wait_process(
            self.process, self.deadline, self.repository.path,
        )
        if returncode != 0:
            raise GitInventoryError(self.repository.path, "git-inventory-failed")
        self.repository.revalidate()

    def _terminate(self) -> None:
        _kill_and_reap(self.process, self.repository.path)

    def __exit__(self, exc_type, _exc, _traceback) -> bool:
        try:
            if exc_type is None:
                self._finish()
            else:
                self._terminate()
        finally:
            self.selector.close()
            if self.process.poll() is None:
                self._terminate()
        return False


def _start_git_batch(repository: RepositoryBinding) -> GitBatch:
    repository.revalidate()
    process = subprocess.Popen(
        _git_argv(repository, ("cat-file", "--batch")),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        env=_git_environment(),
        pass_fds=(repository.fd,),
    )
    return GitBatch(repository, process)


def _scan_index_blob(
    batch: GitBatch, entry: IndexEntry, budget: ScanBudget,
) -> list[Finding]:
    with batch.blob(entry, budget) as (source, declared_size, display):
        prefix = source.read(512)
        source.seek(0)
        intent = _archive_intent(entry.path.name, prefix)
        limit = (
            MAX_COMPRESSED_ARCHIVE_BYTES
            if intent in {"zip", "compressed_tar"}
            else MAX_RAW_FILE_BYTES
        )
        if declared_size > limit:
            reason = (
                "compressed-byte-limit"
                if intent in {"zip", "compressed_tar"}
                else "raw-byte-limit"
            )
            return [Finding(display, reason)]
        findings = _patterns_stream(
            display, source, expected_size=declared_size, byte_limit=limit,
            limit_reason=(
                "compressed-byte-limit"
                if intent in {"zip", "compressed_tar"}
                else "raw-byte-limit"
            ),
        )
        if intent is not None:
            source.seek(0)
            findings.extend(_scan_archive(source, intent, display, budget, 0))
        return findings


def _scan_source(
    root: RootBinding, classification: RootClassification, budget: ScanBudget,
) -> list[Finding]:
    repository = classification.repository
    scope = classification.scope
    assert repository is not None and scope is not None
    first = _capture_source_snapshot(repository, scope)
    snapshot = _capture_source_snapshot(repository, scope)
    if first != snapshot:
        return [Finding(root.path, "source-inventory-drift")]
    _supplement_source_inventory(root, classification, snapshot, budget)
    findings = []
    if snapshot.index:
        with _start_git_batch(repository) as batch:
            for entry in snapshot.index:
                findings.extend(_scan_index_blob(batch, entry, budget))
                if _terminal_limit(findings):
                    return findings
    working = dict(snapshot.working)
    for relative in (
        *(entry.path for entry in snapshot.index),
        *snapshot.untracked,
    ):
        expected_identity = working[relative.as_posix()]
        if expected_identity is None:
            continue
        budget.path_entry(Path(relative.as_posix()))
        for candidate in _open_relative_candidate(
            repository.fd, repository.path, Path(relative.as_posix()), expected_identity,
        ):
            display = _source_display(root, repository, relative, index=False)
            findings.extend(_scan_file(candidate.path, display, budget, candidate))
        if _terminal_limit(findings):
            return findings
    final = _capture_source_snapshot(repository, scope)
    final_classification = _classify_root(root)
    final_repository = final_classification.repository
    try:
        same_classification = (
            final_repository is not None
            and final_classification.scope == scope
            and final_repository.root.identity == repository.root.identity
            and final_repository.marker_identity == repository.marker_identity
        )
    finally:
        if final_repository is not None:
            final_repository.close()
    root.revalidate()
    repository.revalidate()
    if final != snapshot or not same_classification:
        findings.append(Finding(root.path, "source-inventory-drift"))
    return findings


def scan(roots: Path | Sequence[Path]) -> tuple[Finding, ...]:
    supplied = (roots,) if isinstance(roots, Path) else tuple(roots)
    if not supplied:
        return (Finding(Path("."), "no-scan-roots"),)
    requested = tuple(Path(os.path.abspath(os.fspath(root))) for root in supplied)
    lexical = set()
    for root in requested:
        if root in lexical:
            return (Finding(root, "duplicate-root"),)
        lexical.add(root)
    bindings = []
    identities = set()
    preflight_findings = []
    for root in requested:
        try:
            binding = RootBinding.open(root)
        except FileNotFoundError:
            preflight_findings.append(Finding(root, "missing-root"))
            continue
        except ScanLimit as error:
            preflight_findings.append(Finding(error.path, error.reason))
            continue
        except OSError:
            preflight_findings.append(Finding(root, "unreadable-input"))
            continue
        alias = (binding.identity[0], binding.identity[1], stat.S_IFMT(binding.identity[2]))
        if alias in identities:
            binding.close()
            for opened in bindings:
                opened.close()
            return (Finding(root, "duplicate-root"),)
        identities.add(alias)
        bindings.append(binding)
    findings: list[Finding] = preflight_findings
    budget=ScanBudget()
    try:
        for root in bindings:
            try:
                classification = _classify_root(root)
                try:
                    if classification.source:
                        findings.extend(_scan_source(root, classification, budget))
                        if _terminal_limit(findings):
                            return tuple(findings)
                        continue
                    if root.directory:
                        candidates = _walk(root, budget)
                    else:
                        candidates = (
                            _opened_candidate(
                                root.parent.fd, root.name, root.path, root.identity,
                            ),
                        )
                    try:
                        for candidate in candidates:
                            path = candidate.path
                            display = path.relative_to(root.path) if root.directory else path
                            findings.extend(_scan_file(path, display, budget, candidate))
                            if _terminal_limit(findings): return tuple(findings)
                    finally:
                        close=getattr(candidates,"close",None)
                        if close is not None: close()
                finally:
                    if classification.repository is not None:
                        classification.repository.close()
            except (GitInventoryError,ScanLimit) as error:
                findings.append(Finding(error.path,error.reason)); return tuple(findings)
            except OSError:
                findings.append(Finding(root.path,"unreadable-input")); return tuple(findings)
        return tuple(findings)
    finally:
        for root in bindings:
            root.close()


def main() -> int:
    # abspath is lexical: unlike resolve(), it does not erase an explicit
    # symlink before scan() performs lstat/O_NOFOLLOW validation.
    roots = tuple(Path(os.path.abspath(item)) for item in (sys.argv[1:] or ["."]))
    findings = scan(roots)
    for finding in findings:
        print(f"{finding.path}: {finding.reason}")
    if findings:
        return 1
    print("private-data scan: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Create the shared structural scanners on the same nofollow/bounded-input foundation. Their command grammar and pass conditions are closed here so later plans may extend recognized domains/features but may not invent a second implementation:

```python
# scripts/assurance_common.py
@dataclass(frozen=True, order=True)
class AssuranceFinding:
    path: Path
    code: str
    detail: str | None = None


@dataclass(frozen=True)
class AssuranceResult:
    tool: str
    complete: bool
    findings: tuple[AssuranceFinding, ...]

    def exit_code(self) -> int:
        if not self.complete:
            return 2
        return 1 if self.findings else 0


def finish(result: AssuranceResult) -> int:
    for finding in sorted(result.findings):
        suffix = "" if finding.detail is None else f": {finding.detail}"
        print(f"{finding.path}: {finding.code}{suffix}")
    if result.complete and not result.findings:
        print(f"{result.tool}: PASS")
    elif not result.complete:
        print(f"{result.tool}: INCOMPLETE")
    return result.exit_code()
```

| Tool | Bounded inventory | Exact zero-exit condition |
|---|---|---|
| `check_feature_absence.py` | Canonical feature manifests plus tracked Python/TypeScript/config/OpenAPI/package/launchd/IPC artifacts; direct/replay probes use only the synthetic local harness | Every requested ID is declared absent and absent from every requested surface; direct and replay both return schema-unsupported/no-route without side effects |
| `check_import_boundaries.py` | All tracked `.py` files under workspace `src` roots, parsed with an AST-node cap; module roots come from workspace `pyproject.toml` files | Every import resolves or is an approved stdlib/third-party import, no forbidden layer/cross-domain edge exists, and every literal `importlib` target obeys the same graph |
| `check_migration_ownership.py` | All regular `apps/*/migrations/versions/*.py` files, AST-parsed without execution | Requested revisions are unique and present; declared names/parents form the requested reachable graph and satisfy optional exact-head/linear-history constraints |
| `scan_browser_artifacts.py` | Every regular asset/source map/manifest below existing `apps/*/dist` roots and the explicit Playwright output; gzip/brotli/source-map JSON is bounded before decode | All required build roots were inventoried completely and no normalized forbidden key/literal/persistence pattern occurs |
| `scan_network_surface.py` | One process table and TCP/UDP socket table captured under one monotonic generation with bounded command time/output and PID/executable/service join | Every required listener has one exact owner, every optional commissioned listener is either absent or exact, every forbidden bind/port/process class is absent, and the inventory has no unresolved/truncated row |

Use `argparse` sub-free parsers with `allow_abbrev=False`; reject mutually combined selector modes, empty/duplicate CSV entries, non-canonical ports/addresses/revisions/domains, unknown flags, and any repository root that is not a nofollow directory. AST parsing never imports scanned application or migration modules. Browser decoding never executes JavaScript. The network scanner invokes fixed absolute/basename command argument vectors with `shell=False`, a ten-second timeout, a 4 MiB stdout/stderr cap per probe, `LC_ALL=C`, and no inherited secret-bearing environment; Darwin and Linux parsers must agree on one normalized `ListenerRecord(protocol, address, port, pid, executable, service_owner)` shape. If a platform cannot produce every required field, the result is incomplete rather than empty.

Create `tests/fixtures/synthetic/README.md` stating that fixtures use generated UUIDs and roles only, never recorded media, real names, credentials, addresses, host identifiers, or provider bodies.

Classify every lexical root independently before reading content. Open every absolute ancestor descriptor-relative from `/` with `O_DIRECTORY|O_NOFOLLOW`, retain that descriptor/identity chain through the scan, and reject a symlink or special ancestor. Reject duplicate lexical roots and device/inode aliases before scanning any root. A verified Git worktree root, or a non-ignored descendant that is not itself a generated/evidence/candidate/archive root, is a **source root**. A retained repository descriptor and `.git` identity bind classification, inventory, and candidate opens. Every Git process on Darwin and Linux starts through the fixed current Python interpreter in `-I -S` mode; the isolated helper inherits only that repository descriptor, calls `os.fchdir(fd)`, and immediately `os.execve`s fixed `/usr/bin/git` with `--git-dir=.git --work-tree=.` and the closed environment. It uses no lexical repository path, shell, site import, or `preexec_fn`, so holding a substitute at the lexical name for the complete child lifetime cannot redirect Git. Every opened working candidate must equal the identity captured for that exact Git-relative path.

Source mode captures the same bounded inventory twice before scanning and once after scanning: complete stage-0 `git ls-files --stage -z` records, visible untracked records using only repository `.gitignore` files, repository-`.gitignore` ignored records used as physical-prune boundaries, identities for every applicable `.gitignore`, and nofollow working-tree identities for every inventoried path within the requested pathspec. A descriptor-relative physical supplement walks the requested source subtree to prove that every unignored regular/symlink entry belongs to the Git inventory and to block unignored FIFOs, devices, sockets, or other omitted special entries; it skips only the bound worktree's `.git` marker and ignored entries proven by the captured repository `.gitignore` inventory. It is a completeness proof, not an artifact content scan. Ordinary ignored pytest/Ruff/mypy caches, build outputs, and pnpm links are therefore omitted only through source classification and the captured ignore inventory; an explicit ignored/generated/evidence/candidate/archive root always takes artifact mode, and ambiguity takes artifact mode or blocks.

Source content scanning first binds exactly one supported repository object format (`sha1` or `sha256`) and its canonical OID width, then uses one bounded `git cat-file --batch` process for all stage-0 objects. For each response it validates the requested OID echo, `blob` type, canonical declared size, header/body delimiter, short read, missing object, and trailing output; charges the per-file and shared input budgets before reading the body; and streams exactly the declared bytes into bounded anonymous temporary storage before matching/archive parsing. During that same stream it independently computes the canonical Git blob digest over `b"blob " + ascii_size + b"\0" + body` and compares it to the stage-0 OID before the bytes can attest. Replacement refs are disabled, and an alternate object stored under a mismatched OID therefore blocks even if `cat-file` echoes the requested name. It then scans the nofollow bytes of every present tracked working-tree file and every visible untracked/non-ignored file. Thus a staged-only leak is visible and a tracked file below an ignored directory remains visible through the index.

A nonzero stage, wrong-width OID, unsupported object format, duplicate/malformed/non-UTF-8/non-canonical/out-of-scope path, invalid mode, failed/truncated/oversized/timed-out Git command or batch response, local blob-digest mismatch, unreadable/changing input, physical/Git disagreement, or any before/after inventory or identity drift blocks and terminates the batch process. Git commands use fixed argument vectors, `shell=False`, retained descriptors, stdout/stderr caps, a two-MiB batch-stdout buffer cap, a ten-second operation deadline, and a one-second bounded kill/reap deadline. They set `GIT_NO_REPLACE_OBJECTS=1`, `GIT_OPTIONAL_LOCKS=0`, and `GIT_ATTR_NOSYSTEM=1`; disable system/global config, `core.excludesFile`, lazy fetching, credential prompts, and proxies; and override local `core.fsmonitor`, `core.hooksPath`, `core.untrackedCache`, `core.worktree`, automatic maintenance, and GC behavior through command-line settings plus the descriptor-relative worktree pair. `.git/info/exclude` and ambient exclude/config sources cannot hide source candidates, and repository config cannot execute an fsmonitor helper or redirect the worktree. Inability to prove a discovered worktree's state is never reclassified as an artifact pass.

An ignored root, a root whose relative path contains a generated/evidence/candidate component, an explicitly named archive, or any root outside Git is an **artifact root** and receives the existing complete physical nofollow walk. Explicit `dist`, `var`, nested generated names, evidence/candidate trees, and archives never inherit source exclusions, even when they are below a worktree or force-tracked. Missing, symlink, FIFO, device, socket, unreadable, or changing explicit roots block. CLI normalization remains lexical so an explicitly supplied symlink reaches the nofollow check. No matcher, suffix, credential/private-key rule, archive parser, race check, limit, or special-file rejection is weakened, and Task 3 adds no repository path allowlist.

One mutable `ScanBudget` spans streamed index blobs, tracked and untracked working-tree bytes, the source completeness walk, physical artifact walks, every explicit root, and every archive nesting level. It caps path entries, regular files, physical input bytes, archive members, and actual decompressed bytes rather than trusting declared member sizes. Raw ordinary files remain capped at 4 GiB, compressed ZIP/GZip inputs at 4 GiB, one expanded member at 2 GiB, total physical input at 16 GiB, and total actual expansion at 12 GiB across 50,000 members. Artifact-directory traversal uses the retained lexical-root chain and opens every child through descriptor-relative `O_DIRECTORY|O_NOFOLLOW`, scans depth-first with at most 64 directory descriptors, opens each file relative to its still-open parent, and rechecks the first directory-entry metadata, opened descriptor, and final file/directory name against the same device/inode/type/size/change timestamps before attesting. New, removed, renamed, symlink-swapped, special-file-swapped, or changed queued paths therefore block instead of redirecting the walk. Each file's opened size is charged to the shared input budget, and all parsers receive a frozen view that cannot seek or read beyond that size. The descriptor-relative `os.scandir` walk charges an entry before yielding it and never materializes or sorts the complete tree.

Before `ZipFile` may allocate its member list, the EOCD is found by its exact comment boundary, multi-disk/ZIP64 sentinels are blocked, and the central-directory size is capped at 64 MiB and required to end exactly at the EOCD. A bounded streaming header walk then proves every complete central record and requires its actual count to equal the capped EOCD count, so a forged small count cannot make `ZipFile` allocate an oversized list. ZIP virtual names must be unique, canonical, relative, and safe; a directory requires directory mode plus zero compressed/uncompressed size, while a directory-mode non-directory or payload-bearing trailing-slash entry blocks. TAR/GZip uses a bounded single-member deflate reader and a conservative streaming USTAR parser instead of `tarfile`: GZip optional headers, compressed padding, every decompressed TAR header/body/padding byte, member metadata, and trailing TAR padding are capped and charged before further parsing, and FHCRC is verified when present. Concatenated GZip, PAX/GNU long-name/extended metadata, sparse entries, links, devices, and every non-USTAR/special member are blocked before any declared special-member body is read; release archives are already required to be deterministic USTAR. Every bounded physical archive byte is pattern-scanned before parsing, in addition to each expanded regular member, so ZIP comments/extras, GZip names/comments/extra fields, TAR names/owner/reserved header bytes, and parser-ignored metadata cannot carry an unreported literal credential. Pattern matching retains a 256-byte overlap so a credential split across chunks is still found. A bounded file or member is read completely; exceeding any per-object or scan-wide bound is a blocking finding and stops traversal. Filesystem symlinks, FIFOs, devices, sockets, and archive symlink/hardlink/device/special members are blocking inputs. ZIP, wheel, TAR, GZip, and magic-identified regular members recurse through bounded anonymous temporary storage under the same depth/member/byte budget, so a secret inside the Reachy wheelhouse cannot hide in an archive-inside-archive. Archive paths remain virtual and nothing is extracted into the candidate or repository tree. An intended archive that cannot be parsed returns blocking `corrupt-archive`, never an ordinary passing file. Corrupt, changing, or unreadable explicit inputs also block.

Replace Task 2's fail-closed `verify-private-data` recipe in `Makefile` with `uv run python scripts/verify_private_data.py .`; retain `verify-private-data` as a prerequisite of `check`. Extend `web-build` so its first recipe line remains `pnpm --filter @tuntun/admin build` and its immediately following line is `uv run python scripts/verify_private_data.py apps/admin/dist`. Make stops after a failed build, while a successful build therefore receives an explicit artifact-root physical scan before `web-build` passes. Maintain that behavior through `tests/ci/test_web_command_contract.py`. Then change the final CI command in `.github/workflows/ci.yml` from `make lint typecheck test test-security test-contract web-test web-build` to `make check`. Task 3 now owns the scanner that activates the full repository gate; before this exact change Task 2 intentionally keeps `check` unavailable.

- [ ] **Step 4: Run the green scanner and shared assurance gate**

Run: `uv run pytest tests/security/test_private_data_scanner.py tests/security/test_shared_assurance_tools.py tests/ci/test_web_command_contract.py -q && mkdir -p dist var && uv run python scripts/verify_private_data.py . && uv run python scripts/verify_private_data.py dist var && uv run python scripts/verify_private_data.py . dist var && uv run python scripts/scan_private_data.py --paths . dist var && uv run ruff check scripts/verify_private_data.py scripts/assurance_common.py scripts/check_feature_absence.py scripts/check_import_boundaries.py scripts/check_migration_ownership.py scripts/check_migration_graph.py scripts/scan_browser_artifacts.py scripts/scan_network_surface.py scripts/scan_private_data.py scripts/scan_backup_artifacts.py scripts/scan_sandbox_residue.py scripts/scan_sql_schema.py tests/security/test_private_data_scanner.py tests/security/test_shared_assurance_tools.py tests/ci/test_web_command_contract.py && uv run mypy scripts && make check`

Expected: PASS after the test gate creates the two bounded empty artifact/evidence roots. Positional, mixed `. dist var`, and `--paths` forms all use the same shared-budget engine. The repository and non-ignored subtree cases use only stable Git source inventories; normal ignored tool/cache/pnpm output is absent indirectly, while visible untracked, stage-only, and force-tracked-below-ignored leaks are found. Conflicted, malformed, failed, timed-out, or drifting Git inventories block. Every Git process starts from the inherited repository descriptor through the isolated helper even while the lexical worktree name is replaced for the child's complete lifetime; local fsmonitor is disabled, replacement refs cannot substitute index bytes, a mismatched alternate-store body fails the locally computed canonical blob digest, batch stdout remains bounded through shutdown, and every child wait/reap has a deadline. Explicit ignored/generated/evidence/candidate/archive roots use the complete physical walk, and the mixed source/artifact case proves that their budgets do not reset. The scanner also fails closed for a missing/unreadable/changing or rename-substituted root/file/directory, a regular/symlink/special replacement between entry stat and open, explicit symlink, filesystem/archive special entry, unsafe/duplicate/payload-directory ZIP entry, nested-archive leak, malformed or oversized ZIP central directory, invalid GZip FHCRC, hostile PAX/GNU metadata, nonzero special-member body, nonzero or excessive TAR/GZip padding, or any per-object/scan-wide path, file, physical-input, member, metadata, header, directory-depth, archive-depth, or actual-expansion limit. Literal credential patterns in ZIP comments/extras, GZip optional headers, and TAR header fields are reported. The lazy million-entry fixture stops after the first over-limit entry; explicit/nested generated roots do not skip content; and two individually small archives share one cumulative expansion budget. Complete streaming includes every bounded nested wheel member and a realistic Reachy wheelhouse beyond the old 16 MiB ceiling without extracting into a public tree. The Make contract proves build-before-scan and no scan after a failed build. All five structural tools pass their synthetic positive cases, reject every injected finding, and return `2` for incomplete/raced/unparseable inventories.

- [ ] **Step 5: Commit exact Task 3 paths**

```bash
git status --short
git add scripts/verify_private_data.py scripts/assurance_common.py scripts/check_feature_absence.py scripts/check_import_boundaries.py scripts/check_migration_ownership.py scripts/check_migration_graph.py scripts/scan_browser_artifacts.py scripts/scan_network_surface.py scripts/scan_private_data.py scripts/scan_backup_artifacts.py scripts/scan_sandbox_residue.py scripts/scan_sql_schema.py tests/security/test_private_data_scanner.py tests/security/test_shared_assurance_tools.py tests/security/conftest.py tests/security/assurance_cases.py tests/fixtures/synthetic/README.md tests/ci/test_web_command_contract.py Makefile .github/workflows/ci.yml
git diff --cached --name-only
git diff --cached
git commit -m "security: add fail-closed assurance scanners"
```

### Task 4: Freeze canonical contract primitives and signed event envelopes

**Master package:** 02
**Depends on:** Tasks 1 and 3.
**Estimated effort:** 1 person-day.

**Files:**
- Create: `packages/contracts/src/tuntun_contracts/base.py`
- Create: `packages/contracts/src/tuntun_contracts/events.py`
- Create: `scripts/contract_generator_common.py`
- Create: `scripts/generate_schemas.py`
- Create: `scripts/generate_openapi.py`
- Create: `scripts/__init__.py`
- Create: `packages/contracts/src/tuntun_contracts/py.typed`
- Create: `packages/contracts/schema/v1/contracts.schema.json`
- Create: `packages/contracts/openapi/admin-v1.yaml`
- Modify: `packages/contracts/src/tuntun_contracts/__init__.py`
- Modify: `scripts/check_feature_absence.py`
- Modify: `scripts/check_import_boundaries.py`
- Modify: `scripts/check_migration_graph.py`
- Modify: `scripts/check_migration_ownership.py`
- Modify: `scripts/scan_backup_artifacts.py`
- Modify: `scripts/scan_browser_artifacts.py`
- Modify: `scripts/scan_network_surface.py`
- Modify: `scripts/scan_private_data.py`
- Modify: `scripts/scan_sandbox_residue.py`
- Modify: `scripts/scan_sql_schema.py`
- Test: `tests/contract/test_strict_models.py`
- Test: `tests/contract/test_event_canonicalization.py`
- Test: `tests/contract/test_contract_generators.py`

**Interfaces:**
- Consumes: Task 1's existing `tuntun_contracts.__version__: str = "0.1.0.dev0"`; Task 3's root `PyYAML>=6.0,<7` development dependency and `scripts.assurance_common.AssuranceInputError`, `FrozenRegularFile`, `lexical_path`, `read_regular_file`, `validate_root`, and `walk_regular_files`; Pydantic v2; and `rfc8785.dumps(value) -> bytes` plus `rfc8785.CanonicalizationError`.
- Produces: Python 3.11-compatible recursive `JSONValue`; `JCS_MIN_SAFE_INTEGER == -(2**53 - 1)` and `JCS_MAX_SAFE_INTEGER == 2**53 - 1`; `ContractParseError`; bounded duplicate-safe `parse_bounded_json_value(raw, *, max_bytes, max_depth=32, max_containers=4096, max_structure_tokens=16384)`; `ContractModel`; closed package-owned `registered_contract_models()`; `Sensitivity`; `Commitment`; `canonical_bytes(model: ContractModel) -> bytes`; `canonical_mapping_bytes(value: Mapping[str, Any]) -> bytes`; `parse_contract_json(model_type, raw: bytes, *, max_bytes, require_canonical=False)`; `EventType`; `WakeDetectedPayload`; `StopRequestedPayload`; `EventEnvelope`; and `SignedEventEnvelope` exactly as shown below.
- The Task 4 registry is the immutable, explicitly named tuple in `tuntun_contracts/__init__.py`; at the end of Task 4 it contains exactly these five fully qualified names in sorted order: `tuntun_contracts.base.Commitment`, `tuntun_contracts.events.EventEnvelope`, `tuntun_contracts.events.SignedEventEnvelope`, `tuntun_contracts.events.StopRequestedPayload`, and `tuntun_contracts.events.WakeDetectedPayload`. There is no subclass hook, mutable set/list, import-time callback, or reflective subclass walk. Task 5 already owns `tuntun_contracts/__init__.py`; when it adds public DTOs, it must replace this tuple with the new explicit complete sorted tuple. The Task 4 test oracle independently derives the exhaustive expected tuple from public `ContractModel` class exports named by `tuntun_contracts.__all__`, excludes only `ContractModel` itself, and separately requires the five Task 4 names, package ownership, sorted uniqueness, tuple identity, and equality to the package-owned tuple. It never derives its expected set from `registered_contract_models()`, so omitting a later public model fails while a correctly exported and explicitly registered Task 5 model passes without editing the Task 4 test. `registered_contract_models()` remains importable from `tuntun_contracts.base` for the already-frozen Task 5 consumer.
- Task 1 remains the owner of the package version. Task 4 must preserve `__version__: str = "0.1.0.dev0"`, test it, and explicitly import and re-export every Task 4 event type from the package root. Task 4 owns `scripts/contract_generator_common.py` as the single shared schema/OpenAPI generation helper; Task 5 and later contract tasks consume it and may not fork its registry, reference rewriting, checking, or publication logic.
- Hostile bytes (size, UTF-8, syntax, duplicate, shape, unsafe integer, non-finite/range, schema, or canonicality faults) normalize to `ContractParseError`. `model_type` is validated before any hostile byte is decoded. Caller/programmer errors such as an invalid parser configuration, a non-`bytes` raw value, a non-contract model type, or a non-string canonical mapping key remain ordinary `TypeError`/`ValueError`. RFC 8785 canonicalizer domain failures, including nested unsafe integers, non-finite floats, and invalid Unicode code points, normalize to `ContractParseError`. Recursive NFC normalization, post-normalization mapping/set collision detection, and safe-integer checks run before every Pydantic field/model constraint, so normalization cannot expand or contract a value around a length bound. Strict JSON ingress first preserves Pydantic's supported JSON forms for UUID, datetime, tuple, nested-model, and discriminated-union fields through per-field `TypeAdapter.validate_json`, then applies the same pre-constraint normalization; Python-origin strictness remains unchanged.
- A `SignedEventEnvelope` signs exactly `canonical_bytes(signed.envelope)`; neither `signing_key_id` nor `signature_b64` is part of the signing input. Its key ID grammar is exactly `ed25519:<label>:v<positive-version>`, where `<label>` matches `[a-z0-9][a-z0-9._-]{0,63}` and the version matches `[1-9][0-9]{0,8}`. Its signature is standard canonical base64 of exactly 64 bytes: exactly 88 ASCII characters matching `[A-Za-z0-9+/]{86}==`, strict-decoding to 64 bytes, and byte-for-byte equal to its own re-encoding.
- This task owns the sole deterministic `generate_schemas.py` and `generate_openapi.py` and their complete generated outputs. Each exposes exactly `OUTPUT_PATH`, `render() -> bytes`, and `main(argv: Sequence[str] | None = None) -> int`; each supports exactly one of `--check` or explicit maintainer-only `--write`, with success `0` and every usage, drift, unsafe-input, render, race, or publication failure `1`. Check mode performs two renders in a private temporary tree, opens only an already-existing output parent without creating missing path components, retains that nofollow descriptor across two exact inventories plus the byte comparison, checks the terminal pathname identity, and never mutates either the repository or a missing path. Write mode rejects symlink/special/changing outputs and siblings; `_ensure_output_parent()` returns one retained nofollow descriptor plus its captured device/inode identity, `_capture_output_baseline()` retains the exact prior bytes and mode, and publication never reopens the parent by path. The helper revalidates the retained identity after baseline capture, immediately after descriptor-relative atomic replacement, during final artifact verification, and at one terminal postcondition after the parent fsync. Any parent substitution observed before that terminal point triggers descriptor-relative rollback: an existing output is restored atomically with its exact bytes and mode, or a newly published output is unlinked; rollback-owned temporary entries are cleaned and the retained parent descriptor is fsynced. Successful rollback therefore leaves both the lexical replacement tree and renamed old tree equal to their full pre-run snapshots. A rollback-operation failure follows the distinct `publication failed and rollback failed` path, still returns `1`, cleans any rollback temporary entry and fsyncs when those cleanup operations remain available, but may leave the renamed old tree requiring operator handling; no non-mutation claim applies to a failed rollback. The terminal identity check is the end of the bounded publication operation, and this contract makes no impossible claim about an unobservable directory substitution after that final postcondition point. Missing/stale/nondeterministic outputs, either tested parent-swap seam, and any extra regular/symlink/special entry below the owned output parent fail closed.
- The JSON Schema artifact has exactly top-level `$schema`, `schema_version`, and `models`; `$schema` is `https://json-schema.org/draft/2020-12/schema` and `schema_version` is `1.0`. The OpenAPI artifact has exactly top-level `openapi`, `info`, `paths`, and `components`; `openapi` is `3.1.0`; `info` is exactly `{title: "Tuntun Admin API", version: "1.0.0", description: "Foundation contract components; no HTTP paths are owned yet."}`; and `paths` is empty. Both model maps use exact sorted FQNs. For each independently generated Pydantic model schema, the shared helper recursively rewrites only literal `$ref` values and mapping targets inside structurally recognized discriminator objects from `#/$defs/...` to that model's escaped JSON Pointer location under `#/models/<FQN>/$defs/...` or `#/components/schemas/<FQN>/$defs/...`; any unsupported local target fails generation, while unrelated strings/mappings remain untouched. Tests exhaustively walk both `$ref` values and discriminator mappings and prove that every local JSON Pointer resolves.
- `PyYAML` remains the Task 3-pinned runtime dependency. Because PyYAML 6 does not publish a `py.typed` marker, only its two import sites carry the fully scoped `# type: ignore[import-untyped]` annotation; Task 4 does not add `types-PyYAML`, edit dependency metadata, or churn `uv.lock`.
- `scripts/__init__.py` establishes one static `scripts.*` namespace. In the ten listed legacy dual-mode scripts, only imports under `TYPE_CHECKING` become package-qualified (`scripts.assurance_common`, plus `scripts.check_migration_ownership` or `scripts.verify_private_data` where consumed); the package-relative `elif __package__` and direct-execution `else` runtime branches remain behaviorally unchanged. `packages/contracts/src/tuntun_contracts/py.typed` marks the contracts wheel as typed, and the built wheel plus its `RECORD` must contain that marker. No mypy flag, project configuration, or ignore is weakened.
- Neither generator imports app bootstrap, reads household state/credentials, opens listeners, performs network access, or reads private-data matcher fixtures.

- [ ] **Step 1: Write strictness, signing, registry, generator, and non-mutation tests**

```python
# tests/contract/test_strict_models.py
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from enum import StrEnum
from typing import cast
from uuid import UUID

import pytest
import tuntun_contracts
from pydantic import AwareDatetime, Field, ValidationError
from tuntun_contracts.base import (
    JCS_MAX_SAFE_INTEGER,
    JCS_MIN_SAFE_INTEGER,
    Commitment,
    ContractModel,
    ContractParseError,
    Sensitivity,
    canonical_bytes,
    canonical_mapping_bytes,
    parse_bounded_json_value,
    parse_contract_json,
)
from tuntun_contracts.events import EventEnvelope, EventType, WakeDetectedPayload


def valid_python_event() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "event_id": UUID(int=1),
        "event_type": EventType.WAKE_DETECTED,
        "household_id": UUID(int=2),
        "device_id": UUID(int=3),
        "session_id": None,
        "correlation_id": UUID(int=4),
        "causation_id": None,
        "device_sequence": 1,
        "occurred_at": datetime(2026, 8, 27, 1, 2, 3, tzinfo=UTC),
        "sensitivity": Sensitivity.HOUSEHOLD,
        "payload_commitment": Commitment(
            algorithm="HMAC-SHA-256",
            key_id="audit-v1",
            value_b64="A" * 43 + "=",
        ),
        "payload": WakeDetectedPayload(
            kind="speech.wake_detected",
            turn_id=UUID(int=5),
            score_micros=900_000,
        ),
    }


def test_task1_version_and_task4_event_exports_are_preserved() -> None:
    assert tuntun_contracts.__version__ == "0.1.0.dev0"
    assert tuntun_contracts.EventEnvelope is EventEnvelope
    assert tuntun_contracts.WakeDetectedPayload is WakeDetectedPayload


def test_contracts_reject_extra_fields_and_naive_time() -> None:
    with pytest.raises(ValidationError):
        Commitment.model_validate(
            {
                "algorithm": "HMAC-SHA-256",
                "key_id": "audit-v1",
                "value_b64": "A" * 43 + "=",
                "extra": True,
            }
        )
    with pytest.raises(ValidationError, match="timezone"):
        EventEnvelope.model_validate(
            {
                **valid_python_event(),
                "occurred_at": datetime(2026, 8, 27, 1, 2, 3),
            }
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("device_sequence", "1"),
        ("device_sequence", True),
        ("schema_version", 1),
        ("event_id", str(UUID(int=1))),
        ("occurred_at", "2026-08-27T01:02:03Z"),
        ("event_type", "speech.wake_detected"),
    ),
)
def test_python_contract_path_rejects_all_coercion(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        EventEnvelope.model_validate({**valid_python_event(), field: value})


class _StringProbe(ContractModel):
    value: str


@pytest.mark.parametrize("value", (1, True, b"text", ["text"]))
def test_string_fields_never_coerce_non_strings(value: object) -> None:
    with pytest.raises(ValidationError):
        _StringProbe(value=value)  # type: ignore[arg-type]


def test_strict_json_path_accepts_only_json_native_uuid_and_time_strings() -> None:
    valid_wake_json = json.loads(
        canonical_bytes(EventEnvelope.model_validate(valid_python_event()))
    )
    parsed = EventEnvelope.model_validate_json(json.dumps(valid_wake_json), strict=True)
    assert parsed.event_id == UUID(valid_wake_json["event_id"])
    for field, value in (
        ("device_sequence", "1"),
        ("device_sequence", True),
        ("schema_version", 1),
    ):
        with pytest.raises(ValidationError):
            EventEnvelope.model_validate_json(
                json.dumps({**valid_wake_json, field: value}),
                strict=True,
            )


@pytest.mark.parametrize(
    "value",
    (
        "A" * 44,
        "A" * 42 + "==",
        "A" * 43,
        "A" * 43 + "==",
        "_" * 43 + "=",
        "A" * 42 + "B=",
    ),
)
def test_commitment_requires_canonical_base64_of_exactly_32_bytes(value: str) -> None:
    with pytest.raises(ValidationError):
        Commitment(
            algorithm="HMAC-SHA-256",
            key_id="audit-v1",
            value_b64=value,
        )


def test_contract_json_ingress_rejects_duplicates_nonfinite_size_and_noncanonical() -> None:
    commitment = Commitment(
        algorithm="HMAC-SHA-256",
        key_id="audit-v1",
        value_b64="A" * 43 + "=",
    )
    canonical = canonical_bytes(commitment)
    assert (
        parse_contract_json(
            Commitment,
            canonical,
            max_bytes=1_024,
            require_canonical=True,
        )
        == commitment
    )
    duplicate = (
        b'{"algorithm":"HMAC-SHA-256","algorithm":"HMAC-SHA-256",'
        b'"key_id":"audit-v1","value_b64":"' + b"A" * 43 + b'="}'
    )
    giant_decimal = b'{"x":0.' + b"1" * 65 + b"}"
    too_deep = b"[" * 33 + b"0" + b"]" * 33
    too_many = b"[" + b",".join((b"[]",) * 4_097) + b"]"
    too_flat = b"[" + b",".join((b"0",) * 16_385) + b"]"
    for raw in (
        duplicate,
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":-Infinity}',
        giant_decimal,
        b'{"x":1e999999}',
        b'{"x":1e-999999}',
        too_deep,
        too_many,
        too_flat,
    ):
        with pytest.raises(ContractParseError):
            parse_contract_json(
                Commitment,
                raw,
                max_bytes=32_000,
                require_canonical=False,
            )
    with pytest.raises(ContractParseError):
        parse_contract_json(
            Commitment,
            canonical,
            max_bytes=len(canonical) - 1,
            require_canonical=False,
        )
    noncanonical = json.dumps(
        commitment.model_dump(mode="json"),
        sort_keys=False,
    ).encode("utf-8")
    with pytest.raises(ContractParseError, match="not canonical"):
        parse_contract_json(
            Commitment,
            noncanonical,
            max_bytes=1_024,
            require_canonical=True,
        )
    assert (
        parse_contract_json(
            Commitment,
            noncanonical,
            max_bytes=1_024,
            require_canonical=False,
        )
        == commitment
    )


def test_bounded_json_value_is_reusable_without_a_contract_model() -> None:
    assert parse_bounded_json_value(
        b'{"vendor":true,"ports":[443,8443]}',
        max_bytes=64,
    ) == {"vendor": True, "ports": [443, 8443]}
    at_limit = b"[" + b",".join((b"0",) * 16_384) + b"]"
    parsed_at_limit = parse_bounded_json_value(at_limit, max_bytes=65_536)
    assert isinstance(parsed_at_limit, list)
    assert len(parsed_at_limit) == 16_384
    flat = b"[" + b",".join((b"0",) * 16_385) + b"]"
    with pytest.raises(ContractParseError, match="ingress rejected"):
        parse_bounded_json_value(flat, max_bytes=65_536)
    for raw in (b'{"x":1e999999}', b'{"x":1e-999999}'):
        with pytest.raises(ContractParseError, match="ingress rejected"):
            parse_bounded_json_value(raw, max_bytes=64)


@pytest.mark.parametrize("value", (JCS_MIN_SAFE_INTEGER, JCS_MAX_SAFE_INTEGER))
def test_jcs_safe_integer_boundaries_are_recursive_and_inclusive(value: int) -> None:
    raw = f'{{"nested":[{{"value":{value}}}]}}'.encode()
    assert parse_bounded_json_value(raw, max_bytes=128) == {"nested": [{"value": value}]}
    assert canonical_mapping_bytes({"nested": [{"value": value}]}) == raw


@pytest.mark.parametrize(
    "value",
    (JCS_MIN_SAFE_INTEGER - 1, JCS_MAX_SAFE_INTEGER + 1),
)
def test_jcs_unsafe_integers_fail_at_parse_model_and_canonical_boundaries(value: int) -> None:
    raw = f'{{"nested":[{{"value":{value}}}]}}'.encode()
    with pytest.raises(ContractParseError, match="ingress rejected"):
        parse_bounded_json_value(raw, max_bytes=128)
    with pytest.raises(ValidationError, match="safe integer"):
        _IntegerProbe(value={"nested": [value]})
    with pytest.raises(ContractParseError, match="canonicalization rejected"):
        canonical_mapping_bytes({"nested": [{"value": value}]})


class _CanonicalKind(StrEnum):
    SAMPLE = "sample"


class _NFCProbe(ContractModel):
    text: str
    nested: dict[str, tuple[str, ...]]


class _IntegerProbe(ContractModel):
    value: dict[str, list[int]]


class _NFCMaxLengthProbe(ContractModel):
    value: str = Field(max_length=1)


class _NFCMinLengthProbe(ContractModel):
    value: str = Field(min_length=2)


class _StrictJSONModeProbe(ContractModel):
    identifier: UUID
    occurred_at: AwareDatetime
    labels: tuple[str, ...]


def test_before_normalization_preserves_strict_json_native_conversions() -> None:
    parsed = _StrictJSONModeProbe.model_validate_json(
        b'{"identifier":"00000000-0000-0000-0000-000000000001",'
        b'"occurred_at":"2026-08-27T01:02:03Z","labels":["e\\u0301"]}',
        strict=True,
    )
    assert parsed.identifier == UUID(int=1)
    assert parsed.occurred_at == datetime(2026, 8, 27, 1, 2, 3, tzinfo=UTC)
    assert parsed.labels == ("\u00e9",)


def test_nfc_expansion_is_validated_before_max_length_in_python_and_json_modes() -> None:
    assert len("\u0344") == 1
    assert len("\u0308\u0301") == 2
    with pytest.raises(ValidationError):
        _NFCMaxLengthProbe(value="\u0344")
    with pytest.raises(ValidationError):
        _NFCMaxLengthProbe.model_validate_json(
            b'{"value":"\\u0344"}',
            strict=True,
        )


def test_nfc_contraction_is_validated_before_min_length_in_python_and_json_modes() -> None:
    assert len("e\u0301") == 2
    assert len("\u00e9") == 1
    with pytest.raises(ValidationError):
        _NFCMinLengthProbe(value="e\u0301")
    with pytest.raises(ValidationError):
        _NFCMinLengthProbe.model_validate_json(
            b'{"value":"e\\u0301"}',
            strict=True,
        )


def test_contract_ingress_normalizes_nfc_recursively_in_python_and_json_modes() -> None:
    python_value = _NFCProbe(text="e\u0301", nested={"a\u030a": ("n\u0303",)})
    json_value = _NFCProbe.model_validate_json(
        b'{"text":"e\\u0301","nested":{"a\\u030a":["n\\u0303"]}}',
        strict=True,
    )
    expected = _NFCProbe(text="\u00e9", nested={"\u00e5": ("\u00f1",)})
    assert python_value == json_value == expected
    with pytest.raises(ValidationError, match="collide after NFC"):
        _NFCProbe(
            text="ok",
            nested={"e\u0301": ("one",), "\u00e9": ("two",)},
        )


def test_shared_canonical_mapping_has_one_cross_phase_golden_encoding() -> None:
    value = {
        "text": "e\u0301",
        "time": datetime(
            2026,
            8,
            27,
            9,
            2,
            3,
            4,
            tzinfo=timezone(timedelta(hours=8)),
        ),
        "id": UUID(int=1),
        "kind": _CanonicalKind.SAMPLE,
        "blob": b"\x00\xff",
    }
    assert canonical_mapping_bytes(value) == (
        b'{"blob":"AP8=","id":"00000000-0000-0000-0000-000000000001",'
        b'"kind":"sample","text":"\xc3\xa9","time":"2026-08-27T01:02:03.000004Z"}'
    )


@pytest.mark.parametrize(
    "value",
    (
        {1: "non-string-key"},
        {"e\u0301": 1, "\u00e9": 2},
    ),
)
def test_shared_canonical_mapping_rejects_key_coercion_or_nfc_collision(
    value: object,
) -> None:
    mapping = cast(dict[str, object], value)
    with pytest.raises((TypeError, ValueError)):
        canonical_mapping_bytes(mapping)


def test_rfc8785_canonicalizer_faults_normalize_to_contract_parse_error() -> None:
    with pytest.raises(ContractParseError, match="canonicalization rejected"):
        canonical_mapping_bytes({"nested": [float("inf")]})
    with pytest.raises(ContractParseError, match="canonicalization rejected"):
        canonical_mapping_bytes({"nested": [chr(0xD800)]})


def test_model_type_is_validated_before_hostile_bytes() -> None:
    non_contract_type = cast(type[ContractModel], dict)
    with pytest.raises(TypeError, match="ContractModel"):
        parse_contract_json(non_contract_type, b"\xff", max_bytes=1)


def test_hostile_parse_faults_normalize_but_programmer_faults_propagate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ContractParseError):
        parse_bounded_json_value(b"\xff", max_bytes=64)
    with pytest.raises(ContractParseError):
        parse_contract_json(Commitment, b"{}", max_bytes=64)
    with pytest.raises(TypeError):
        parse_bounded_json_value("{}", max_bytes=64)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="configuration"):
        parse_bounded_json_value(b"{}", max_bytes=0)

    def unexpected_programmer_failure(*args: object, **kwargs: object) -> object:
        raise ValueError("injected programmer failure")

    monkeypatch.setattr(
        "tuntun_contracts.base.json.loads",
        unexpected_programmer_failure,
    )
    with pytest.raises(ValueError, match="injected programmer failure") as raised:
        parse_bounded_json_value(b"{}", max_bytes=64)
    assert type(raised.value) is ValueError
```

```python
# tests/contract/test_event_canonicalization.py
from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError
from tuntun_contracts.base import (
    Commitment,
    Sensitivity,
    canonical_bytes,
    parse_contract_json,
)
from tuntun_contracts.events import (
    EventEnvelope,
    EventType,
    SignedEventEnvelope,
    WakeDetectedPayload,
)

VALID_SIGNATURE = base64.b64encode(bytes(range(64))).decode("ascii")
VALID_WAKE: dict[str, object] = {
    "schema_version": "1.0",
    "event_id": str(UUID(int=1)),
    "event_type": "speech.wake_detected",
    "household_id": str(UUID(int=2)),
    "device_id": str(UUID(int=3)),
    "session_id": None,
    "correlation_id": str(UUID(int=4)),
    "causation_id": None,
    "device_sequence": 1,
    "occurred_at": "2026-08-27T01:02:03.000004Z",
    "sensitivity": "household",
    "payload_commitment": {
        "algorithm": "HMAC-SHA-256",
        "key_id": "audit-v1",
        "value_b64": "A" * 43 + "=",
    },
    "payload": {
        "kind": "speech.wake_detected",
        "turn_id": str(UUID(int=5)),
        "score_micros": 900_000,
    },
}


def make_envelope() -> EventEnvelope:
    return EventEnvelope(
        schema_version="1.0",
        event_id=UUID(int=1),
        event_type=EventType.WAKE_DETECTED,
        household_id=UUID(int=2),
        device_id=UUID(int=3),
        session_id=None,
        correlation_id=UUID(int=4),
        causation_id=None,
        device_sequence=7,
        occurred_at=datetime(2026, 8, 27, 1, 2, 3, 4, UTC),
        sensitivity=Sensitivity.HOUSEHOLD,
        payload_commitment=Commitment(
            algorithm="HMAC-SHA-256",
            key_id="audit-v1",
            value_b64="A" * 43 + "=",
        ),
        payload=WakeDetectedPayload(
            kind="speech.wake_detected",
            turn_id=UUID(int=5),
            score_micros=900_000,
        ),
    )


def test_event_canonical_bytes_use_nfc_and_six_utc_digits() -> None:
    envelope = make_envelope()
    encoded = canonical_bytes(envelope)
    assert b'"occurred_at":"2026-08-27T01:02:03.000004Z"' in encoded
    assert encoded == canonical_bytes(envelope)


def test_event_type_must_equal_payload_kind() -> None:
    data = EventEnvelope.model_json_schema()
    assert data["title"] == "EventEnvelope"
    with pytest.raises(ValidationError, match="event_type must equal payload.kind"):
        EventEnvelope.model_validate_json(
            json.dumps({**VALID_WAKE, "event_type": "safety.stop_requested"}),
            strict=True,
        )


def test_signed_event_signing_input_is_exactly_the_canonical_envelope() -> None:
    envelope = make_envelope()
    first = SignedEventEnvelope(
        envelope=envelope,
        signing_key_id="ed25519:reachy-edge-01:v1",
        signature_b64=VALID_SIGNATURE,
    )
    second = SignedEventEnvelope(
        envelope=envelope,
        signing_key_id="ed25519:reachy-edge-02:v2",
        signature_b64=base64.b64encode(bytes(reversed(range(64)))).decode("ascii"),
    )
    expected = canonical_bytes(envelope)
    assert first.signing_bytes() == second.signing_bytes() == expected
    assert b"signing_key_id" not in expected
    assert b"signature_b64" not in expected


def test_signed_event_accepts_one_canonical_64_byte_ed25519_signature() -> None:
    signed = SignedEventEnvelope(
        envelope=make_envelope(),
        signing_key_id="ed25519:reachy-edge-01:v1",
        signature_b64=VALID_SIGNATURE,
    )
    assert len(signed.signature_b64) == 88
    assert len(base64.b64decode(signed.signature_b64, validate=True)) == 64
    encoded = canonical_bytes(signed)
    assert (
        parse_contract_json(
            SignedEventEnvelope,
            encoded,
            max_bytes=8_192,
            require_canonical=True,
        )
        == signed
    )


@pytest.mark.parametrize(
    "signature",
    (
        base64.b64encode(bytes(63)).decode("ascii"),
        base64.b64encode(bytes(65)).decode("ascii"),
        VALID_SIGNATURE.rstrip("="),
        base64.urlsafe_b64encode(bytes([255]) * 64).decode("ascii"),
        "A" * 86 + "=A",
        "!" + VALID_SIGNATURE[1:],
    ),
)
def test_signed_event_rejects_wrong_length_alphabet_padding_or_noncanonical_base64(
    signature: str,
) -> None:
    with pytest.raises(ValidationError, match="signature"):
        SignedEventEnvelope(
            envelope=make_envelope(),
            signing_key_id="ed25519:reachy-edge-01:v1",
            signature_b64=signature,
        )


@pytest.mark.parametrize(
    "key_id",
    (
        "ED25519:reachy-edge-01:v1",
        "ed25519:-reachy:v1",
        "ed25519:reachy edge:v1",
        "ed25519:reachy:v0",
        "ed25519:reachy:v01",
        "ed25519:reachy:extra:v1",
        "ed25519:" + "a" * 65 + ":v1",
    ),
)
def test_signed_event_rejects_every_key_id_outside_the_closed_grammar(
    key_id: str,
) -> None:
    with pytest.raises(ValidationError, match="signing_key_id"):
        SignedEventEnvelope(
            envelope=make_envelope(),
            signing_key_id=key_id,
            signature_b64=VALID_SIGNATURE,
        )
```

```python
# tests/contract/test_contract_generators.py
from __future__ import annotations

# The import split below deliberately bootstraps the uninstalled root namespace.
# ruff: noqa: E402
import hashlib
import json
import os
import stat
import subprocess
import sys
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Protocol, cast

# The root project is not an installed package; preserve package-import coverage
# without changing workspace metadata or adding a suite-wide import side effect.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest
import tuntun_contracts
import yaml  # type: ignore[import-untyped]  # PyYAML 6 has no py.typed marker.
from tuntun_contracts.base import ContractModel, registered_contract_models

from scripts import contract_generator_common, generate_openapi, generate_schemas
from scripts.assurance_common import (
    AssuranceInputError,
    FrozenRegularFile,
    lexical_path,
    read_regular_file,
)
from scripts.contract_generator_common import GeneratorError

SCHEMA_OUTPUT = Path("packages/contracts/schema/v1/contracts.schema.json")
OPENAPI_OUTPUT = Path("packages/contracts/openapi/admin-v1.yaml")
REQUIRED_TASK4_MODELS = frozenset(
    {
        "tuntun_contracts.base.Commitment",
        "tuntun_contracts.events.EventEnvelope",
        "tuntun_contracts.events.SignedEventEnvelope",
        "tuntun_contracts.events.StopRequestedPayload",
        "tuntun_contracts.events.WakeDetectedPayload",
    }
)


class _GeneratorModule(Protocol):
    __name__: str
    OUTPUT_PATH: Path

    def render(self) -> bytes: ...

    def main(self, argv: Sequence[str] | None = None) -> int: ...


def _mapping(value: object) -> Mapping[str, object]:
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return cast(dict[str, object], value)


def _model_name(model: type[ContractModel]) -> str:
    return f"{model.__module__}.{model.__qualname__}"


def _public_contract_models() -> tuple[type[ContractModel], ...]:
    models: list[type[ContractModel]] = []
    for export_name in tuntun_contracts.__all__:
        exported = getattr(tuntun_contracts, export_name)
        if (
            isinstance(exported, type)
            and issubclass(exported, ContractModel)
            and exported is not ContractModel
        ):
            models.append(exported)
    return tuple(sorted(models, key=_model_name))


def _public_model_names() -> tuple[str, ...]:
    return tuple(_model_name(model) for model in _public_contract_models())


def _assert_registry_matches_public_exports(
    models: tuple[type[ContractModel], ...],
) -> None:
    names = tuple(_model_name(model) for model in models)
    assert names == tuple(sorted(names))
    assert len(set(names)) == len(names)
    assert frozenset(names) >= REQUIRED_TASK4_MODELS
    assert all(name.startswith("tuntun_contracts.") for name in names)
    assert models == _public_contract_models()


def _subprocess_render(module_name: str, *, hash_seed: str) -> bytes:
    source = (
        "import sys\n"
        f"from scripts import {module_name} as generator\n"
        "sys.stdout.buffer.write(generator.render())\n"
    )
    environment = {**os.environ, "PYTHONHASHSEED": hash_seed}
    completed = subprocess.run(
        [sys.executable, "-c", source],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
    )
    assert completed.stderr == b""
    return completed.stdout


def _subprocess_cli(
    script: str,
    arguments: Sequence[str],
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, script, *arguments],
        cwd=ROOT,
        env={**os.environ, "PYTHONHASHSEED": "1"},
        check=False,
        capture_output=True,
    )


def _walk_refs(value: object) -> Iterator[str]:
    if isinstance(value, dict):
        if "propertyName" in value and "mapping" in value:
            assert isinstance(value["propertyName"], str)
            mapping = value["mapping"]
            assert isinstance(mapping, dict)
            for target in mapping.values():
                assert isinstance(target, str)
                yield target
        for key, child in value.items():
            if key == "$ref":
                assert isinstance(child, str)
                yield child
            else:
                yield from _walk_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_refs(child)


def _resolve_local_ref(document: object, reference: str) -> object:
    assert reference.startswith("#/")
    current = document
    for encoded in reference[2:].split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = current[token]
        elif isinstance(current, list):
            current = current[int(token)]
        else:
            raise AssertionError(f"reference traversed a scalar: {reference}")
    return current


def _tree_snapshot(root: Path) -> tuple[tuple[str, int, int, bytes], ...]:
    if not root.exists() and not root.is_symlink():
        return ()
    snapshot: list[tuple[str, int, int, bytes]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        metadata = path.lstat()
        payload = b""
        if stat.S_ISREG(metadata.st_mode):
            payload = read_regular_file(path, max_bytes=4 * 1024 * 1024)
        elif stat.S_ISLNK(metadata.st_mode):
            payload = os.readlink(path).encode("utf-8")
        snapshot.append(
            (
                path.relative_to(root).as_posix(),
                metadata.st_mode,
                metadata.st_size,
                hashlib.sha256(payload).digest(),
            )
        )
    return tuple(snapshot)


def test_registry_is_closed_exhaustive_immutable_and_package_owned() -> None:
    registered = registered_contract_models()
    assert type(registered) is tuple
    _assert_registry_matches_public_exports(registered)
    assert registered is registered_contract_models()
    assert registered is tuntun_contracts._REGISTERED_CONTRACT_MODELS


def test_registry_oracle_adapts_and_rejects_every_public_model_omission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_models = _public_contract_models()
    for omitted in public_models:
        with pytest.raises(AssertionError):
            _assert_registry_matches_public_exports(
                tuple(model for model in public_models if model is not omitted)
            )

    class FuturePublicModel(ContractModel):
        marker: str

    FuturePublicModel.__module__ = "tuntun_contracts.future"
    monkeypatch.setattr(
        tuntun_contracts,
        "FuturePublicModel",
        FuturePublicModel,
        raising=False,
    )
    monkeypatch.setattr(
        tuntun_contracts,
        "__all__",
        (*tuntun_contracts.__all__, "FuturePublicModel"),
    )
    expanded_models: tuple[type[ContractModel], ...] = (
        *registered_contract_models(),
        FuturePublicModel,
    )
    expanded = tuple(sorted(expanded_models, key=_model_name))
    _assert_registry_matches_public_exports(expanded)


def test_generators_freeze_metadata_exact_models_and_independent_process_determinism() -> None:
    assert generate_schemas.OUTPUT_PATH == SCHEMA_OUTPUT
    assert generate_openapi.OUTPUT_PATH == OPENAPI_OUTPUT

    schema_first = _subprocess_render("generate_schemas", hash_seed="1")
    schema_second = _subprocess_render("generate_schemas", hash_seed="987654")
    openapi_first = _subprocess_render("generate_openapi", hash_seed="1")
    openapi_second = _subprocess_render("generate_openapi", hash_seed="987654")
    assert schema_first == schema_second == generate_schemas.render()
    assert openapi_first == openapi_second == generate_openapi.render()

    expected_models = _public_model_names()
    schema = _mapping(json.loads(schema_first))
    assert set(schema) == {"$schema", "schema_version", "models"}
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["schema_version"] == "1.0"
    assert tuple(_mapping(schema["models"])) == expected_models

    openapi = _mapping(yaml.safe_load(openapi_first))
    assert set(openapi) == {"openapi", "info", "paths", "components"}
    assert openapi["openapi"] == "3.1.0"
    assert openapi["info"] == {
        "title": "Tuntun Admin API",
        "version": "1.0.0",
        "description": "Foundation contract components; no HTTP paths are owned yet.",
    }
    assert openapi["paths"] == {}
    components = _mapping(openapi["components"])
    assert set(components) == {"schemas"}
    assert tuple(_mapping(components["schemas"])) == expected_models


@pytest.mark.parametrize(
    ("script", "output"),
    (
        ("scripts/generate_schemas.py", SCHEMA_OUTPUT),
        ("scripts/generate_openapi.py", OPENAPI_OUTPUT),
    ),
)
def test_generator_process_cli_has_closed_error_codes_and_nonmutating_check(
    script: str,
    output: Path,
) -> None:
    before = _tree_snapshot(ROOT / output.parent)
    for arguments in (
        (),
        ("--check", "--write"),
        ("--check", "--check"),
        ("--chec",),
        ("--unknown",),
    ):
        completed = _subprocess_cli(script, arguments)
        assert completed.returncode == 1
        assert completed.stdout == completed.stderr == b""
        assert _tree_snapshot(ROOT / output.parent) == before
    completed = _subprocess_cli(script, ("--check",))
    assert completed.returncode == 0
    assert completed.stdout == completed.stderr == b""
    assert _tree_snapshot(ROOT / output.parent) == before


def test_every_generated_local_reference_resolves() -> None:
    documents = (
        json.loads(generate_schemas.render()),
        yaml.safe_load(generate_openapi.render()),
        json.loads(read_regular_file(ROOT / SCHEMA_OUTPUT, max_bytes=4 * 1024 * 1024)),
        yaml.safe_load(read_regular_file(ROOT / OPENAPI_OUTPUT, max_bytes=4 * 1024 * 1024)),
    )
    for document in documents:
        references = tuple(_walk_refs(document))
        assert references
        for reference in references:
            assert reference.startswith("#/")
            assert _resolve_local_ref(document, reference) is not None


def test_schema_reference_rewrite_is_limited_to_supported_reference_positions() -> None:
    source: dict[str, object] = {
        "$ref": "#/$defs/Root",
        "discriminator": {
            "propertyName": "kind",
            "mapping": {
                "one": "#/$defs/One",
                "two": "#/$defs/Two",
            },
        },
        "default": "#/$defs/MustRemainLiteral",
        "metadata": {"mapping": {"literal": "#/$defs/AlsoLiteral"}},
    }
    assert contract_generator_common._rewrite_local_refs(
        source,
        model_pointer="#/models/example.Model",
    ) == {
        "$ref": "#/models/example.Model/$defs/Root",
        "discriminator": {
            "propertyName": "kind",
            "mapping": {
                "one": "#/models/example.Model/$defs/One",
                "two": "#/models/example.Model/$defs/Two",
            },
        },
        "default": "#/$defs/MustRemainLiteral",
        "metadata": {"mapping": {"literal": "#/$defs/AlsoLiteral"}},
    }


@pytest.mark.parametrize("target", (None, 1, "#/unsupported/Target"))
def test_schema_reference_rewrite_rejects_invalid_discriminator_mapping_targets(
    target: object,
) -> None:
    with pytest.raises(GeneratorError, match="schema reference"):
        contract_generator_common._rewrite_local_refs(
            {
                "propertyName": "kind",
                "mapping": {"sample": target},
            },
            model_pointer="#/models/example.Model",
        )


def test_duplicate_fully_qualified_model_names_fail_before_schema_render(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def make_collision() -> type[ContractModel]:
        class Collision(ContractModel):
            value: str

        return Collision

    duplicate_models = (make_collision(), make_collision())

    def duplicate_registry() -> tuple[type[ContractModel], ...]:
        return duplicate_models

    for generator in (generate_schemas, generate_openapi):
        monkeypatch.setattr(generator, "registered_contract_models", duplicate_registry)
        with pytest.raises(GeneratorError, match="duplicate fully qualified"):
            generator.render()


@pytest.mark.parametrize("generator", (generate_schemas, generate_openapi))
def test_nondeterministic_render_fails_without_output_mutation(
    generator: _GeneratorModule,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / generator.__name__
    parent.mkdir()
    output = parent / generator.OUTPUT_PATH.name
    monkeypatch.setattr(generator, "OUTPUT_PATH", output)
    output.write_bytes(b"first render\n")
    output.chmod(0o600)
    renders = iter((b"first render\n", b"second render\n"))
    render_count = 0

    def nondeterministic_render() -> bytes:
        nonlocal render_count
        render_count += 1
        return next(renders)

    monkeypatch.setattr(generator, "render", nondeterministic_render)
    before = _tree_snapshot(parent)
    assert generator.main(["--check"]) == 1
    assert render_count == 2
    assert _tree_snapshot(parent) == before


@pytest.mark.parametrize("generator", (generate_schemas, generate_openapi))
def test_generator_cli_is_closed_and_check_mode_never_mutates(
    generator: _GeneratorModule,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / generator.__name__
    parent.mkdir()
    owned = parent / generator.OUTPUT_PATH.name
    monkeypatch.setattr(generator, "OUTPUT_PATH", owned)
    main = generator.main
    render = generator.render

    for argv in ([], ["--check", "--write"], ["--check", "--check"], ["--chec"], ["--unknown"]):
        assert main(argv) == 1

    before_missing = _tree_snapshot(parent)
    assert main(["--check"]) == 1
    assert _tree_snapshot(parent) == before_missing

    owned.write_bytes(b"stale\n")
    before_stale = _tree_snapshot(parent)
    assert main(["--check"]) == 1
    assert _tree_snapshot(parent) == before_stale

    assert main(["--write"]) == 0
    assert stat.S_IMODE(owned.stat().st_mode) == 0o600
    assert owned.read_bytes() == render()
    before_current = _tree_snapshot(parent)
    assert main(["--check"]) == 0
    assert _tree_snapshot(parent) == before_current

    extra = parent / "extra.generated"
    extra.write_text("unexpected\n", encoding="utf-8")
    before_extra = _tree_snapshot(parent)
    assert main(["--check"]) == 1
    assert _tree_snapshot(parent) == before_extra
    extra.unlink()

    target = tmp_path / f"{generator.__name__}-outside"
    target.write_bytes(b"outside\n")
    extra.symlink_to(target)
    before_extra_symlink = _tree_snapshot(parent)
    assert main(["--check"]) == 1
    assert _tree_snapshot(parent) == before_extra_symlink
    assert target.read_bytes() == b"outside\n"
    extra.unlink()

    os.mkfifo(extra, mode=0o600)
    before_special = _tree_snapshot(parent)
    assert main(["--check"]) == 1
    assert _tree_snapshot(parent) == before_special
    extra.unlink()

    owned.unlink()
    owned.symlink_to(target)
    before_output_symlink = _tree_snapshot(parent)
    assert main(["--check"]) == 1
    assert _tree_snapshot(parent) == before_output_symlink
    assert target.read_bytes() == b"outside\n"
    owned.unlink()

    os.mkfifo(owned, mode=0o600)
    before_output_special = _tree_snapshot(parent)
    assert main(["--check"]) == 1
    assert _tree_snapshot(parent) == before_output_special


@pytest.mark.parametrize("generator", (generate_schemas, generate_openapi))
def test_generator_rejects_symlinked_output_parent_without_mutation(
    generator: _GeneratorModule,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real_parent, target_is_directory=True)
    output = alias / "must-not-be-created" / generator.OUTPUT_PATH.name
    monkeypatch.setattr(generator, "OUTPUT_PATH", output)
    before = _tree_snapshot(real_parent)
    assert generator.main(["--check"]) == 1
    assert generator.main(["--write"]) == 1
    assert _tree_snapshot(real_parent) == before


@pytest.mark.parametrize("generator", (generate_schemas, generate_openapi))
def test_write_failure_preserves_prior_output_and_removes_private_temp(
    generator: _GeneratorModule,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / generator.__name__
    parent.mkdir()
    output = parent / generator.OUTPUT_PATH.name
    output.write_bytes(b"prior bytes\n")
    output.chmod(0o600)
    monkeypatch.setattr(generator, "OUTPUT_PATH", output)

    def fail_replace(source_name: str, destination_name: str, parent_fd: int) -> None:
        raise OSError("injected replace failure")

    monkeypatch.setattr(contract_generator_common, "_atomic_replace", fail_replace)
    before = _tree_snapshot(parent)
    assert generator.main(["--write"]) == 1
    assert _tree_snapshot(parent) == before
    assert output.read_bytes() == b"prior bytes\n"


@pytest.mark.parametrize("generator", (generate_schemas, generate_openapi))
def test_write_rejects_parent_swap_between_baseline_and_publication(
    generator: _GeneratorModule,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / generator.__name__
    parent.mkdir()
    replacement = tmp_path / f"{generator.__name__}-replacement"
    replacement.mkdir()
    old_tree = tmp_path / f"{generator.__name__}-old"
    output = parent / generator.OUTPUT_PATH.name
    monkeypatch.setattr(generator, "OUTPUT_PATH", output)
    original_snapshot = contract_generator_common._owned_snapshot
    swapped = False

    def swap_after_baseline(
        output_path: Path,
        *,
        allow_missing: bool,
        output_parent: contract_generator_common.OutputParent | None = None,
    ) -> tuple[FrozenRegularFile, ...]:
        nonlocal swapped
        result = original_snapshot(
            output_path,
            allow_missing=allow_missing,
            output_parent=output_parent,
        )
        if allow_missing and not swapped:
            parent.rename(old_tree)
            replacement.rename(parent)
            swapped = True
        return result

    monkeypatch.setattr(contract_generator_common, "_owned_snapshot", swap_after_baseline)
    assert generator.main(["--write"]) == 1
    assert swapped
    assert _tree_snapshot(parent) == ()
    assert _tree_snapshot(old_tree) == ()


@pytest.mark.parametrize("generator", (generate_schemas, generate_openapi))
def test_check_rejects_parent_swap_after_clean_inventory_without_mutation(
    generator: _GeneratorModule,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / generator.__name__
    parent.mkdir()
    replacement = tmp_path / f"{generator.__name__}-replacement"
    replacement.mkdir()
    old_tree = tmp_path / f"{generator.__name__}-old"
    output = parent / generator.OUTPUT_PATH.name
    replacement_output = replacement / generator.OUTPUT_PATH.name
    rendered = generator.render()
    output.write_bytes(rendered)
    output.chmod(0o600)
    replacement_output.write_bytes(rendered)
    replacement_output.chmod(0o600)
    (replacement / "extra.generated").write_bytes(b"unexpected\n")
    monkeypatch.setattr(generator, "OUTPUT_PATH", output)
    old_before = _tree_snapshot(parent)
    replacement_before = _tree_snapshot(replacement)
    original_snapshot = contract_generator_common._owned_snapshot
    swapped = False

    def swap_after_inventory(
        output_path: Path,
        *,
        allow_missing: bool,
        output_parent: contract_generator_common.OutputParent | None = None,
    ) -> tuple[FrozenRegularFile, ...]:
        nonlocal swapped
        result = original_snapshot(
            output_path,
            allow_missing=allow_missing,
            output_parent=output_parent,
        )
        if not allow_missing and not swapped:
            parent.rename(old_tree)
            replacement.rename(parent)
            swapped = True
        return result

    monkeypatch.setattr(contract_generator_common, "_owned_snapshot", swap_after_inventory)
    assert generator.main(["--check"]) == 1
    assert swapped
    assert _tree_snapshot(parent) == replacement_before
    assert _tree_snapshot(old_tree) == old_before


@pytest.mark.parametrize("generator", (generate_schemas, generate_openapi))
@pytest.mark.parametrize("baseline", (None, b"prior bytes\n"))
def test_write_rolls_back_parent_swap_inside_atomic_replace(
    generator: _GeneratorModule,
    baseline: bytes | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / generator.__name__
    parent.mkdir()
    replacement = tmp_path / f"{generator.__name__}-replacement"
    replacement.mkdir()
    replacement_sentinel = replacement / "replacement.sentinel"
    replacement_sentinel.write_bytes(b"replacement tree\n")
    old_tree = tmp_path / f"{generator.__name__}-old"
    output = parent / generator.OUTPUT_PATH.name
    if baseline is not None:
        output.write_bytes(baseline)
        output.chmod(0o640)
    monkeypatch.setattr(generator, "OUTPUT_PATH", output)
    old_before = _tree_snapshot(parent)
    replacement_before = _tree_snapshot(replacement)
    real_replace = contract_generator_common._atomic_replace
    swapped = False

    def swap_inside_replace(source_name: str, destination_name: str, parent_fd: int) -> None:
        nonlocal swapped
        if not swapped:
            parent.rename(old_tree)
            replacement.rename(parent)
            swapped = True
        real_replace(source_name, destination_name, parent_fd)

    monkeypatch.setattr(contract_generator_common, "_atomic_replace", swap_inside_replace)
    assert generator.main(["--write"]) == 1
    assert swapped
    assert _tree_snapshot(parent) == replacement_before
    assert _tree_snapshot(old_tree) == old_before


@pytest.mark.parametrize("generator", (generate_schemas, generate_openapi))
@pytest.mark.parametrize("baseline", (None, b"prior bytes\n"))
def test_parent_swap_rollback_failure_returns_one_and_cleans_temps(
    generator: _GeneratorModule,
    baseline: bytes | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / generator.__name__
    parent.mkdir()
    replacement = tmp_path / f"{generator.__name__}-replacement"
    replacement.mkdir()
    replacement_sentinel = replacement / "replacement.sentinel"
    replacement_sentinel.write_bytes(b"replacement tree\n")
    old_tree = tmp_path / f"{generator.__name__}-old"
    output = parent / generator.OUTPUT_PATH.name
    if baseline is not None:
        output.write_bytes(baseline)
        output.chmod(0o640)
    monkeypatch.setattr(generator, "OUTPUT_PATH", output)
    old_before = _tree_snapshot(parent)
    replacement_before = _tree_snapshot(replacement)
    real_replace = contract_generator_common._atomic_replace
    real_write = contract_generator_common._write_atomically
    swapped = False

    def swap_inside_replace(source_name: str, destination_name: str, parent_fd: int) -> None:
        nonlocal swapped
        if not swapped:
            parent.rename(old_tree)
            replacement.rename(parent)
            swapped = True
        real_replace(source_name, destination_name, parent_fd)

    rollback_failures = 0

    def fail_rollback(source_or_destination: str, *arguments: object) -> None:
        nonlocal rollback_failures
        rollback_failures += 1
        raise OSError(f"injected rollback failure: {source_or_destination}")

    observed_errors: list[str] = []

    def capture_rollback_error(output_path: Path, rendered: bytes) -> None:
        try:
            real_write(output_path, rendered)
        except GeneratorError as error:
            observed_errors.append(str(error))
            raise

    monkeypatch.setattr(contract_generator_common, "_atomic_replace", swap_inside_replace)
    rollback_operation = "_rollback_unlink" if baseline is None else "_rollback_replace"
    monkeypatch.setattr(contract_generator_common, rollback_operation, fail_rollback)
    monkeypatch.setattr(contract_generator_common, "_write_atomically", capture_rollback_error)
    assert generator.main(["--write"]) == 1
    assert swapped
    assert rollback_failures == 1
    assert observed_errors == ["publication failed and rollback failed"]
    assert _tree_snapshot(parent) == replacement_before
    assert _tree_snapshot(old_tree) != old_before
    assert all(not entry[0].startswith(".") for entry in _tree_snapshot(old_tree))


@pytest.mark.parametrize("generator", (generate_schemas, generate_openapi))
def test_task3_race_signal_fails_check_closed_without_generator_mutation(
    generator: _GeneratorModule,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / generator.__name__
    parent.mkdir()
    output = parent / generator.OUTPUT_PATH.name
    monkeypatch.setattr(generator, "OUTPUT_PATH", output)
    assert generator.main(["--write"]) == 0
    before = _tree_snapshot(parent)
    original_read = read_regular_file

    def race_read(path: Path, *, max_bytes: int) -> bytes:
        if lexical_path(path) == lexical_path(output):
            raise AssuranceInputError(path, "input-changed-during-scan")
        return original_read(path, max_bytes=max_bytes)

    monkeypatch.setattr(contract_generator_common, "read_regular_file", race_read)
    assert generator.main(["--check"]) == 1
    assert _tree_snapshot(parent) == before
```

- [ ] **Step 2: Run the focused red contract test**

Run: `uv run pytest tests/contract/test_strict_models.py -q`

Expected: collection ERROR with `ModuleNotFoundError: No module named 'tuntun_contracts.base'`. Task 1 already supplies and installs `tuntun_contracts`; the missing Task 4 submodule—not the package itself—is the exact red condition.

- [ ] **Step 3: Implement strict base/event types, the closed registry, and both generators**

```python
# packages/contracts/src/tuntun_contracts/base.py
from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum, StrEnum
from typing import Any, Literal, NoReturn, TypeAlias, TypeVar, cast
from unicodedata import normalize
from uuid import UUID

import rfc8785
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

JCS_MAX_SAFE_INTEGER = 2**53 - 1
JCS_MIN_SAFE_INTEGER = -JCS_MAX_SAFE_INTEGER

JSONValue: TypeAlias = (  # noqa: UP040 -- contracts remain Python 3.11 compatible.
    str | int | Decimal | bool | None | list["JSONValue"] | dict[str, "JSONValue"]
)
ContractT = TypeVar("ContractT", bound="ContractModel")


class ContractParseError(ValueError):
    """Untrusted contract input or canonicalization failed closed."""


class _HostileJSONError(Exception):
    pass


def _is_jcs_safe_integer(value: int) -> bool:
    return JCS_MIN_SAFE_INTEGER <= value <= JCS_MAX_SAFE_INTEGER


def _normalize_contract_input(value: Any) -> Any:
    if isinstance(value, Enum):
        return value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("datetime must be timezone-aware")
        return value
    if type(value) is int and not _is_jcs_safe_integer(value):
        raise ValueError("integer must be in the RFC 8785 safe integer domain")
    if isinstance(value, str):
        return normalize("NFC", value)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("contract mapping keys must be strings")
            normalized_key = normalize("NFC", key)
            if normalized_key in result:
                raise ValueError("contract mapping keys collide after NFC")
            result[normalized_key] = _normalize_contract_input(item)
        return result
    if isinstance(value, tuple):
        return tuple(_normalize_contract_input(item) for item in value)
    if isinstance(value, list):
        return [_normalize_contract_input(item) for item in value]
    if isinstance(value, frozenset):
        frozen_normalized = frozenset(_normalize_contract_input(item) for item in value)
        if len(frozen_normalized) != len(value):
            raise ValueError("contract set values collide after NFC")
        return frozen_normalized
    if isinstance(value, set):
        mutable_normalized = {_normalize_contract_input(item) for item in value}
        if len(mutable_normalized) != len(value):
            raise ValueError("contract set values collide after NFC")
        return mutable_normalized
    return value


class ContractModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        allow_inf_nan=False,
        validate_assignment=True,
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_and_validate_contract_value(
        cls,
        value: Any,
        info: ValidationInfo,
    ) -> Any:
        normalized = _normalize_contract_input(value)
        if info.mode != "json" or not isinstance(normalized, Mapping):
            return normalized
        result = dict(normalized)
        for field_name, field in cls.model_fields.items():
            input_name = field.alias or field_name
            if input_name not in result:
                continue
            field_json = json.dumps(
                result[input_name],
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
            )
            result[input_name] = TypeAdapter(field.rebuild_annotation()).validate_json(
                field_json,
                strict=True,
                context=info.context,
            )
        return result


def registered_contract_models() -> tuple[type[ContractModel], ...]:
    # Import after package initialization so Task 5 can replace the one closed,
    # package-owned tuple while preserving this already-frozen import path.
    from . import _REGISTERED_CONTRACT_MODELS

    return _REGISTERED_CONTRACT_MODELS


def _unique_json_object(
    pairs: list[tuple[str, JSONValue]],
) -> dict[str, JSONValue]:
    result: dict[str, JSONValue] = {}
    for key, value in pairs:
        if key in result:
            raise _HostileJSONError("duplicate JSON key")
        result[key] = value
    return result


def _bounded_json_int(value: str) -> int:
    if len(value.removeprefix("-")) > 16:
        raise _HostileJSONError("JSON integer outside JCS safe domain")
    parsed = int(value)
    if not _is_jcs_safe_integer(parsed):
        raise _HostileJSONError("JSON integer outside JCS safe domain")
    return parsed


def _bounded_json_decimal(value: str) -> Decimal:
    if len(value) > 64:
        raise _HostileJSONError("JSON decimal too large")
    result = Decimal(value)
    if not result.is_finite():
        raise _HostileJSONError("non-finite JSON number")
    if len(result.as_tuple().digits) > 64 or not -308 <= result.adjusted() <= 308:
        raise _HostileJSONError("JSON decimal range exceeded")
    return result


def _reject_json_constant(value: str) -> NoReturn:
    raise _HostileJSONError(f"non-finite JSON number: {value}")


def _require_bounded_json_shape(
    text: str,
    *,
    max_depth: int,
    max_containers: int,
    max_structure_tokens: int,
) -> None:
    depth = 0
    containers = 0
    structure_tokens = 1
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            containers += 1
            if depth > max_depth or containers > max_containers:
                raise _HostileJSONError("contract JSON shape limit exceeded")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise _HostileJSONError("contract JSON shape invalid")
        elif character in ",:":
            structure_tokens += 1
            if structure_tokens > max_structure_tokens:
                raise _HostileJSONError("contract JSON shape limit exceeded")
    if in_string or depth != 0:
        raise _HostileJSONError("contract JSON shape invalid")


def parse_bounded_json_value(
    raw: bytes,
    *,
    max_bytes: int,
    max_depth: int = 32,
    max_containers: int = 4_096,
    max_structure_tokens: int = 16_384,
) -> JSONValue:
    limits = (max_bytes, max_depth, max_containers, max_structure_tokens)
    ceilings = (8_388_608, 32, 4_096, 16_384)
    if type(raw) is not bytes:
        raise TypeError("contract JSON raw input must be bytes")
    if any(type(value) is not int for value in limits) or any(
        not 1 <= value <= ceiling for value, ceiling in zip(limits, ceilings, strict=True)
    ):
        raise ValueError("invalid contract JSON parser configuration")
    if not 1 <= len(raw) <= max_bytes:
        raise ContractParseError("contract JSON size invalid")
    try:
        text = raw.decode("utf-8", errors="strict")
        _require_bounded_json_shape(
            text,
            max_depth=max_depth,
            max_containers=max_containers,
            max_structure_tokens=max_structure_tokens,
        )
        return cast(
            JSONValue,
            json.loads(
                text,
                object_pairs_hook=_unique_json_object,
                parse_int=_bounded_json_int,
                parse_float=_bounded_json_decimal,
                parse_constant=_reject_json_constant,
            ),
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, _HostileJSONError) as error:
        raise ContractParseError("contract JSON ingress rejected") from error


def parse_contract_json(  # noqa: UP047 -- contracts remain Python 3.11 compatible.
    model_type: type[ContractT],
    raw: bytes,
    *,
    max_bytes: int,
    require_canonical: bool = False,
) -> ContractT:
    if not isinstance(model_type, type) or not issubclass(model_type, ContractModel):
        raise TypeError("model_type must be a ContractModel subclass")
    parse_bounded_json_value(raw, max_bytes=max_bytes)
    try:
        model = model_type.model_validate_json(raw, strict=True)
    except (ValidationError, RecursionError) as error:
        raise ContractParseError("contract JSON schema rejected") from error
    if require_canonical and canonical_bytes(model) != raw:
        raise ContractParseError("contract JSON is not canonical JCS")
    return model


class Sensitivity(StrEnum):
    PUBLIC = "public"
    HOUSEHOLD = "household"
    PERSONAL = "personal"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"


def validate_canonical_base64(
    value: str,
    *,
    expected_bytes: int,
    label: str,
) -> str:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError(f"{label} must be canonical base64") from error
    if len(decoded) != expected_bytes or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{label} must encode exactly {expected_bytes} bytes canonically")
    return value


class Commitment(ContractModel):
    algorithm: Literal["HMAC-SHA-256"]
    key_id: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9_.:-]+$",
    )
    value_b64: str = Field(
        min_length=44,
        max_length=44,
        pattern=r"^[A-Za-z0-9+/]{43}=$",
    )

    @field_validator("value_b64")
    @classmethod
    def canonical_hmac_sha256(cls, value: str) -> str:
        return validate_canonical_base64(
            value,
            expected_bytes=32,
            label="commitment",
        )


def _canonical_value(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("datetime must be timezone-aware")
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(value, str):
        return normalize("NFC", value)
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Enum):
        return _canonical_value(value.value)
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if type(value) is int:
        if not _is_jcs_safe_integer(value):
            raise rfc8785.IntegerDomainError(value)
        return value
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("canonical JSON mapping keys must be strings")
            normalized_key = normalize("NFC", key)
            if normalized_key in result:
                raise ValueError("canonical JSON mapping keys collide after NFC")
            result[normalized_key] = _canonical_value(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    return value


def canonical_mapping_bytes(value: Mapping[str, Any]) -> bytes:
    if not isinstance(value, Mapping):
        raise TypeError("canonical JSON root must be a mapping")
    try:
        return rfc8785.dumps(_canonical_value(value))
    except rfc8785.CanonicalizationError as error:
        raise ContractParseError("contract canonicalization rejected") from error


def canonical_bytes(model: ContractModel) -> bytes:
    if not isinstance(model, ContractModel):
        raise TypeError("canonical_bytes requires a ContractModel")
    return canonical_mapping_bytes(model.model_dump(mode="python"))
```

```python
# packages/contracts/src/tuntun_contracts/events.py
from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self, TypeAlias
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from .base import (
    JCS_MAX_SAFE_INTEGER,
    Commitment,
    ContractModel,
    Sensitivity,
    canonical_bytes,
    validate_canonical_base64,
)


class EventType(StrEnum):
    WAKE_DETECTED = "speech.wake_detected"
    STOP_REQUESTED = "safety.stop_requested"


class WakeDetectedPayload(ContractModel):
    kind: Literal["speech.wake_detected"]
    turn_id: UUID
    score_micros: Annotated[int, Field(ge=0, le=1_000_000)]


class StopRequestedPayload(ContractModel):
    kind: Literal["safety.stop_requested"]
    turn_id: UUID | None
    source: Literal[
        "edge_keyword",
        "physical_input",
        "owner_console",
        "watchdog",
    ]


EventPayload: TypeAlias = Annotated[  # noqa: UP040 -- Python 3.11 compatibility.
    WakeDetectedPayload | StopRequestedPayload,
    Field(discriminator="kind"),
]


class EventEnvelope(ContractModel):
    schema_version: Literal["1.0"]
    event_id: UUID
    event_type: EventType
    household_id: UUID
    device_id: UUID
    session_id: UUID | None
    correlation_id: UUID
    causation_id: UUID | None
    device_sequence: Annotated[int, Field(ge=0, le=JCS_MAX_SAFE_INTEGER)]
    occurred_at: AwareDatetime
    sensitivity: Sensitivity
    payload_commitment: Commitment
    payload: EventPayload

    @model_validator(mode="after")
    def matching_type(self) -> Self:
        if self.event_type.value != self.payload.kind:
            raise ValueError("event_type must equal payload.kind")
        return self


class SignedEventEnvelope(ContractModel):
    envelope: EventEnvelope
    signing_key_id: Annotated[
        str,
        Field(
            min_length=12,
            max_length=83,
            pattern=r"^ed25519:[a-z0-9][a-z0-9._-]{0,63}:v[1-9][0-9]{0,8}$",
        ),
    ]
    signature_b64: Annotated[
        str,
        Field(
            min_length=88,
            max_length=88,
            pattern=r"^[A-Za-z0-9+/]{86}==$",
        ),
    ]

    @field_validator("signature_b64")
    @classmethod
    def canonical_ed25519_signature(cls, value: str) -> str:
        return validate_canonical_base64(
            value,
            expected_bytes=64,
            label="signature",
        )

    def signing_bytes(self) -> bytes:
        """Return the sole Ed25519 signing input; wrapper fields are excluded."""
        return canonical_bytes(self.envelope)
```

```python
# packages/contracts/src/tuntun_contracts/__init__.py
from typing import Final

from .base import (
    JCS_MAX_SAFE_INTEGER,
    JCS_MIN_SAFE_INTEGER,
    Commitment,
    ContractModel,
    ContractParseError,
    JSONValue,
    Sensitivity,
    canonical_bytes,
    canonical_mapping_bytes,
    parse_bounded_json_value,
    parse_contract_json,
    registered_contract_models,
)
from .events import (
    EventEnvelope,
    EventPayload,
    EventType,
    SignedEventEnvelope,
    StopRequestedPayload,
    WakeDetectedPayload,
)

__version__: str = "0.1.0.dev0"

_REGISTERED_CONTRACT_MODELS: Final[tuple[type[ContractModel], ...]] = (
    Commitment,
    EventEnvelope,
    SignedEventEnvelope,
    StopRequestedPayload,
    WakeDetectedPayload,
)

__all__ = (
    "JCS_MAX_SAFE_INTEGER",
    "JCS_MIN_SAFE_INTEGER",
    "JSONValue",
    "Commitment",
    "ContractModel",
    "ContractParseError",
    "EventEnvelope",
    "EventPayload",
    "EventType",
    "Sensitivity",
    "SignedEventEnvelope",
    "StopRequestedPayload",
    "WakeDetectedPayload",
    "__version__",
    "canonical_bytes",
    "canonical_mapping_bytes",
    "parse_bounded_json_value",
    "parse_contract_json",
    "registered_contract_models",
)
```

```python
# scripts/contract_generator_common.py
from __future__ import annotations

import json
import os
import secrets
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory, gettempdir
from typing import TYPE_CHECKING, Literal, TypeAlias

from tuntun_contracts.base import ContractModel

if TYPE_CHECKING:
    from scripts.assurance_common import (
        AssuranceInputError,
        FrozenRegularFile,
        lexical_path,
        read_regular_file,
        validate_root,
        walk_regular_files,
    )
elif __package__:
    from .assurance_common import (
        AssuranceInputError,
        FrozenRegularFile,
        lexical_path,
        read_regular_file,
        validate_root,
        walk_regular_files,
    )
else:
    from assurance_common import (
        AssuranceInputError,
        FrozenRegularFile,
        lexical_path,
        read_regular_file,
        validate_root,
        walk_regular_files,
    )

MAX_GENERATED_BYTES = 4 * 1024 * 1024
MAX_PARENT_FILES = 3
GeneratorMode: TypeAlias = Literal["check", "write"]  # noqa: UP040
Renderer: TypeAlias = Callable[[], bytes]  # noqa: UP040


@dataclass(frozen=True)
class OutputParent:
    """Open output-parent descriptor and the directory identity it captured."""

    path: Path
    descriptor: int
    device: int
    inode: int


@dataclass(frozen=True)
class OutputBaseline:
    """Exact sole-output snapshot retained for descriptor-relative rollback."""

    snapshot: tuple[FrozenRegularFile, ...]
    mode: int | None


class GeneratorError(RuntimeError):
    """Generation, inventory, determinism, or publication failed closed."""


def _json_pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _rewrite_local_ref(value: object, *, model_pointer: str) -> str:
    if not isinstance(value, str):
        raise GeneratorError("generated schema reference is not a string")
    if not value.startswith("#/$defs/"):
        raise GeneratorError(f"unsupported generated schema reference: {value}")
    return f"{model_pointer}/$defs/{value.removeprefix('#/$defs/')}"


def _registered_model_map(
    models: Sequence[type[ContractModel]],
) -> dict[str, type[ContractModel]]:
    result: dict[str, type[ContractModel]] = {}
    for model in models:
        name = f"{model.__module__}.{model.__qualname__}"
        if name in result:
            raise GeneratorError(f"duplicate fully qualified contract model: {name}")
        result[name] = model
    if not result:
        raise GeneratorError("contract registry must not be empty")
    return dict(sorted(result.items()))


def _rewrite_local_refs(value: object, *, model_pointer: str) -> object:
    if isinstance(value, dict):
        is_discriminator = "propertyName" in value and "mapping" in value
        if is_discriminator:
            if not isinstance(value["propertyName"], str):
                raise GeneratorError("generated discriminator propertyName is not a string")
            if not isinstance(value["mapping"], dict):
                raise GeneratorError("generated discriminator mapping is not an object")
        result: dict[str, object] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise GeneratorError("generated schema key is not a string")
            if key == "$ref":
                result[key] = _rewrite_local_ref(child, model_pointer=model_pointer)
            elif is_discriminator and key == "mapping":
                mapping: dict[str, object] = {}
                for discriminator_value, reference in child.items():
                    if not isinstance(discriminator_value, str):
                        raise GeneratorError("generated discriminator value is not a string")
                    mapping[discriminator_value] = _rewrite_local_ref(
                        reference,
                        model_pointer=model_pointer,
                    )
                result[key] = mapping
            else:
                result[key] = _rewrite_local_refs(child, model_pointer=model_pointer)
        return result
    if isinstance(value, list):
        return [_rewrite_local_refs(child, model_pointer=model_pointer) for child in value]
    return value


def build_model_schemas(
    models: Sequence[type[ContractModel]],
    *,
    container_pointer: str,
) -> dict[str, object]:
    if not container_pointer.startswith("/") or container_pointer.endswith("/"):
        raise ValueError("container_pointer must be one nonempty absolute JSON Pointer")
    result: dict[str, object] = {}
    for name, model in _registered_model_map(models).items():
        model_pointer = f"#{container_pointer}/{_json_pointer_escape(name)}"
        raw_schema = model.model_json_schema(
            mode="validation",
            ref_template="#/$defs/{model}",
        )
        result[name] = _rewrite_local_refs(raw_schema, model_pointer=model_pointer)
    return result


def render_json_document(document: Mapping[str, object]) -> bytes:
    return (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
        + "\n"
    ).encode("utf-8")


def _require_rendered_bytes(value: object) -> bytes:
    if type(value) is not bytes:
        raise GeneratorError("renderer must return bytes")
    rendered = value
    if not 1 <= len(rendered) <= MAX_GENERATED_BYTES:
        raise GeneratorError("rendered artifact byte limit exceeded")
    return rendered


def _write_all(descriptor: int, value: bytes) -> None:
    view = memoryview(value)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise OSError("short generated-artifact write")
        offset += written


def _render_twice_in_private_tree(renderer: Renderer, filename: str) -> bytes:
    first = _require_rendered_bytes(renderer())
    second = _require_rendered_bytes(renderer())
    if first != second:
        raise GeneratorError("nondeterministic generator render")
    system_temporary_root = validate_root(Path(os.path.realpath(gettempdir())))
    with TemporaryDirectory(
        prefix="tuntun-contract-generator-",
        dir=system_temporary_root,
    ) as temporary:
        candidate = Path(temporary) / filename
        descriptor = os.open(
            candidate,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            _write_all(descriptor, first)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if read_regular_file(candidate, max_bytes=MAX_GENERATED_BYTES) != first:
            raise GeneratorError("private render verification failed")
    return first


def _scan_parent(parent: Path) -> tuple[FrozenRegularFile, ...]:
    return tuple(
        sorted(
            walk_regular_files(
                (parent,),
                max_files=MAX_PARENT_FILES,
                max_total_bytes=MAX_GENERATED_BYTES * MAX_PARENT_FILES,
            ),
            key=lambda item: item.path.as_posix(),
        )
    )


def _output_parent_is_current(output_parent: OutputParent) -> bool:
    try:
        named = os.stat(output_parent.path, follow_symlinks=False)
        opened = os.fstat(output_parent.descriptor)
    except OSError:
        return False
    return (
        stat.S_ISDIR(named.st_mode)
        and stat.S_ISDIR(opened.st_mode)
        and named.st_dev == output_parent.device == opened.st_dev
        and named.st_ino == output_parent.inode == opened.st_ino
    )


def _owned_snapshot(
    output_path: Path,
    *,
    allow_missing: bool,
    output_parent: OutputParent | None = None,
) -> tuple[FrozenRegularFile, ...]:
    expected = lexical_path(output_path)
    if output_parent is not None and (
        expected.parent != output_parent.path or not _output_parent_is_current(output_parent)
    ):
        raise GeneratorError("output parent changed during generation")
    files = _scan_parent(expected.parent)
    if output_parent is not None and not _output_parent_is_current(output_parent):
        raise GeneratorError("output parent changed during generation")
    if not files and allow_missing:
        return ()
    if len(files) != 1 or files[0].path != expected:
        raise GeneratorError("owned output inventory is not exact")
    if read_regular_file(expected, max_bytes=MAX_GENERATED_BYTES) != files[0].raw:
        raise AssuranceInputError(expected, "input-changed-during-scan")
    if output_parent is not None and not _output_parent_is_current(output_parent):
        raise GeneratorError("output parent changed during generation")
    return files


def _capture_output_baseline(output: Path, output_parent: OutputParent) -> OutputBaseline:
    snapshot = _owned_snapshot(
        output,
        allow_missing=True,
        output_parent=output_parent,
    )
    if not snapshot:
        return OutputBaseline(snapshot=(), mode=None)
    metadata = os.stat(
        output.name,
        dir_fd=output_parent.descriptor,
        follow_symlinks=False,
    )
    frozen = snapshot[0]
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_dev != frozen.device
        or metadata.st_ino != frozen.inode
        or metadata.st_size != frozen.size
        or metadata.st_mtime_ns != frozen.modified_ns
        or metadata.st_ctime_ns != frozen.changed_ns
    ):
        raise AssuranceInputError(output, "input-changed-during-scan")
    return OutputBaseline(snapshot=snapshot, mode=stat.S_IMODE(metadata.st_mode))


def _bind_output_parent(
    output_path: Path,
    *,
    create_missing: bool,
) -> OutputParent:
    parent = lexical_path(output_path).parent
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    current_fd = os.open(os.path.sep, flags)
    keep_descriptor = False
    try:
        for index, part in enumerate(parent.parts[1:]):
            display = Path(os.path.sep).joinpath(*parent.parts[1 : index + 2])
            try:
                before = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
            except FileNotFoundError:
                if not create_missing:
                    raise AssuranceInputError(display, "missing-input") from None
                os.mkdir(part, mode=0o700, dir_fd=current_fd)
                before = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                raise AssuranceInputError(display, "symlink-input")
            if not stat.S_ISDIR(before.st_mode):
                raise AssuranceInputError(display, "not-directory")
            child_fd = os.open(part, flags, dir_fd=current_fd)
            opened = os.fstat(child_fd)
            if before.st_dev != opened.st_dev or before.st_ino != opened.st_ino:
                os.close(child_fd)
                raise AssuranceInputError(display, "input-changed-during-scan")
            os.close(current_fd)
            current_fd = child_fd
        validated = validate_root(parent)
        opened = os.fstat(current_fd)
        output_parent = OutputParent(
            path=validated,
            descriptor=current_fd,
            device=opened.st_dev,
            inode=opened.st_ino,
        )
        if not _output_parent_is_current(output_parent):
            raise GeneratorError("output parent changed during generation")
        keep_descriptor = True
        return output_parent
    finally:
        if not keep_descriptor:
            os.close(current_fd)


def _ensure_output_parent(output_path: Path) -> OutputParent:
    return _bind_output_parent(output_path, create_missing=True)


def _open_existing_output_parent(output_path: Path) -> OutputParent:
    return _bind_output_parent(output_path, create_missing=False)


def _atomic_replace(source_name: str, destination_name: str, parent_fd: int) -> None:
    os.replace(
        source_name,
        destination_name,
        src_dir_fd=parent_fd,
        dst_dir_fd=parent_fd,
    )


def _rollback_replace(source_name: str, destination_name: str, parent_fd: int) -> None:
    os.replace(
        source_name,
        destination_name,
        src_dir_fd=parent_fd,
        dst_dir_fd=parent_fd,
    )


def _rollback_unlink(destination_name: str, parent_fd: int) -> None:
    os.unlink(destination_name, dir_fd=parent_fd)


def _rollback_publication(
    output_name: str,
    baseline: OutputBaseline,
    parent_fd: int,
) -> None:
    rollback_name: str | None = None
    rollback_fd: int | None = None
    try:
        if baseline.snapshot:
            if baseline.mode is None:
                raise GeneratorError("existing baseline is missing its mode")
            rollback_name = f".{output_name}.{secrets.token_hex(16)}.rollback"
            rollback_fd = os.open(
                rollback_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_fd,
            )
            _write_all(rollback_fd, baseline.snapshot[0].raw)
            os.fchmod(rollback_fd, baseline.mode)
            os.fsync(rollback_fd)
            os.close(rollback_fd)
            rollback_fd = None
            _rollback_replace(rollback_name, output_name, parent_fd)
            rollback_name = None
        else:
            if baseline.mode is not None:
                raise GeneratorError("missing baseline unexpectedly has a mode")
            with suppress(FileNotFoundError):
                _rollback_unlink(output_name, parent_fd)
        os.fsync(parent_fd)
    finally:
        if rollback_fd is not None:
            os.close(rollback_fd)
        try:
            if rollback_name is not None:
                with suppress(FileNotFoundError):
                    os.unlink(rollback_name, dir_fd=parent_fd)
        finally:
            os.fsync(parent_fd)


def _write_atomically(output_path: Path, rendered: bytes) -> None:
    output = lexical_path(output_path)
    output_parent = _ensure_output_parent(output)
    temporary_name = f".{output.name}.{secrets.token_hex(16)}.tmp"
    temporary_path = output_parent.path / temporary_name
    temporary_fd: int | None = None
    published = False
    try:
        baseline = _capture_output_baseline(output, output_parent)
        if not _output_parent_is_current(output_parent):
            raise GeneratorError("output parent changed during generation")
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=output_parent.descriptor,
        )
        os.fchmod(temporary_fd, 0o600)
        _write_all(temporary_fd, rendered)
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None

        current = _scan_parent(output_parent.path)
        temporary_entries = tuple(
            item for item in current if item.path == lexical_path(temporary_path)
        )
        remaining = tuple(item for item in current if item.path != lexical_path(temporary_path))
        if (
            len(temporary_entries) != 1
            or temporary_entries[0].raw != rendered
            or stat.S_IMODE(os.stat(temporary_path, follow_symlinks=False).st_mode) != 0o600
        ):
            raise GeneratorError("private publication file verification failed")
        if remaining != baseline.snapshot or not _output_parent_is_current(output_parent):
            raise GeneratorError("output changed during generation")

        _atomic_replace(temporary_name, output.name, output_parent.descriptor)
        published = True
        try:
            if not _output_parent_is_current(output_parent):
                raise GeneratorError("output parent changed during publication")
            os.fsync(output_parent.descriptor)
            final = _owned_snapshot(
                output,
                allow_missing=False,
                output_parent=output_parent,
            )
            if final[0].raw != rendered:
                raise GeneratorError("published generated artifact verification failed")
            if not _output_parent_is_current(output_parent):
                raise GeneratorError("output parent changed at final postcondition")
        except Exception as publication_error:
            try:
                _rollback_publication(
                    output.name,
                    baseline,
                    output_parent.descriptor,
                )
            except Exception as rollback_error:
                raise GeneratorError("publication failed and rollback failed") from rollback_error
            raise GeneratorError(
                "publication failed and baseline was restored"
            ) from publication_error
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        if not published:
            try:
                os.unlink(temporary_name, dir_fd=output_parent.descriptor)
                os.fsync(output_parent.descriptor)
            except FileNotFoundError:
                pass
        os.close(output_parent.descriptor)


def _check_current_output(output_path: Path, rendered: bytes) -> bool:
    output = lexical_path(output_path)
    output_parent = _open_existing_output_parent(output)
    try:
        initial = _owned_snapshot(
            output,
            allow_missing=False,
            output_parent=output_parent,
        )
        final = _owned_snapshot(
            output,
            allow_missing=False,
            output_parent=output_parent,
        )
        matches = initial == final and final[0].raw == rendered
        if not _output_parent_is_current(output_parent):
            raise GeneratorError("output parent changed at check postcondition")
        return matches
    finally:
        os.close(output_parent.descriptor)


def _parse_mode(argv: Sequence[str] | None) -> GeneratorMode:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if arguments == ("--check",):
        return "check"
    if arguments == ("--write",):
        return "write"
    raise ValueError("exactly one of --check or --write is required")


def run_generator(
    *,
    output_path: Path,
    renderer: Renderer,
    argv: Sequence[str] | None,
) -> int:
    try:
        mode = _parse_mode(argv)
        rendered = _render_twice_in_private_tree(renderer, output_path.name)
        if mode == "check":
            return 0 if _check_current_output(output_path, rendered) else 1
        _write_atomically(output_path, rendered)
        return 0
    except Exception:
        return 1
```

```python
# scripts/generate_schemas.py
from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Final

from tuntun_contracts.base import registered_contract_models

if TYPE_CHECKING:
    from scripts.contract_generator_common import (
        build_model_schemas,
        render_json_document,
        run_generator,
    )
elif __package__:
    from .contract_generator_common import (
        build_model_schemas,
        render_json_document,
        run_generator,
    )
else:
    from contract_generator_common import (
        build_model_schemas,
        render_json_document,
        run_generator,
    )

OUTPUT_PATH: Final = Path("packages/contracts/schema/v1/contracts.schema.json")


def render() -> bytes:
    document: dict[str, object] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "schema_version": "1.0",
        "models": build_model_schemas(
            registered_contract_models(),
            container_pointer="/models",
        ),
    }
    return render_json_document(document)


def main(argv: Sequence[str] | None = None) -> int:
    return run_generator(
        output_path=OUTPUT_PATH,
        renderer=render,
        argv=argv,
    )


if __name__ == "__main__":
    raise SystemExit(main())
```

```python
# scripts/generate_openapi.py
from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import yaml  # type: ignore[import-untyped]  # PyYAML 6 has no py.typed marker.
from tuntun_contracts.base import registered_contract_models

if TYPE_CHECKING:
    from scripts.contract_generator_common import build_model_schemas, run_generator
elif __package__:
    from .contract_generator_common import build_model_schemas, run_generator
else:
    from contract_generator_common import build_model_schemas, run_generator

OUTPUT_PATH: Final = Path("packages/contracts/openapi/admin-v1.yaml")


def render() -> bytes:
    document: dict[str, object] = {
        "openapi": "3.1.0",
        "info": {
            "title": "Tuntun Admin API",
            "version": "1.0.0",
            "description": "Foundation contract components; no HTTP paths are owned yet.",
        },
        "paths": {},
        "components": {
            "schemas": build_model_schemas(
                registered_contract_models(),
                container_pointer="/components/schemas",
            )
        },
    }
    rendered = cast(
        str,
        yaml.safe_dump(
            document,
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
            width=100,
        ),
    )
    return rendered.encode("utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    return run_generator(
        output_path=OUTPUT_PATH,
        renderer=render,
        argv=argv,
    )


if __name__ == "__main__":
    raise SystemExit(main())
```

Create empty `scripts/__init__.py` and `packages/contracts/src/tuntun_contracts/py.typed` marker files. Apply only the package-qualified `TYPE_CHECKING` imports described above to the ten listed legacy scripts; do not change their package-relative or direct-execution branches.

Generate `packages/contracts/schema/v1/contracts.schema.json` only with `uv run python scripts/generate_schemas.py --write`, and generate `packages/contracts/openapi/admin-v1.yaml` only with `uv run python scripts/generate_openapi.py --write`. Do not hand-edit either artifact.

- [ ] **Step 4: Run the green canonical-contract gate, prove check-mode non-mutation, and run the repository gate**

Run:

```bash
uv run python scripts/generate_schemas.py --write
uv run python scripts/generate_openapi.py --write
uv run pytest tests/contract/test_strict_models.py tests/contract/test_event_canonicalization.py tests/contract/test_contract_generators.py -q
uv run ruff format --check packages/contracts/src/tuntun_contracts/base.py packages/contracts/src/tuntun_contracts/events.py packages/contracts/src/tuntun_contracts/__init__.py scripts/__init__.py scripts/contract_generator_common.py scripts/generate_schemas.py scripts/generate_openapi.py scripts/check_feature_absence.py scripts/check_import_boundaries.py scripts/check_migration_graph.py scripts/check_migration_ownership.py scripts/scan_backup_artifacts.py scripts/scan_browser_artifacts.py scripts/scan_network_surface.py scripts/scan_private_data.py scripts/scan_sandbox_residue.py scripts/scan_sql_schema.py tests/contract/test_strict_models.py tests/contract/test_event_canonicalization.py tests/contract/test_contract_generators.py
uv run ruff check packages/contracts/src/tuntun_contracts/base.py packages/contracts/src/tuntun_contracts/events.py packages/contracts/src/tuntun_contracts/__init__.py scripts/__init__.py scripts/contract_generator_common.py scripts/generate_schemas.py scripts/generate_openapi.py scripts/check_feature_absence.py scripts/check_import_boundaries.py scripts/check_migration_graph.py scripts/check_migration_ownership.py scripts/scan_backup_artifacts.py scripts/scan_browser_artifacts.py scripts/scan_network_surface.py scripts/scan_private_data.py scripts/scan_sandbox_residue.py scripts/scan_sql_schema.py tests/contract/test_strict_models.py tests/contract/test_event_canonicalization.py tests/contract/test_contract_generators.py
MYPYPATH=packages/contracts/src:. uv run mypy --explicit-package-bases --python-version 3.11 packages/contracts/src scripts/contract_generator_common.py scripts/generate_schemas.py scripts/generate_openapi.py tests/contract/test_strict_models.py tests/contract/test_event_canonicalization.py tests/contract/test_contract_generators.py
uv run mypy scripts

uv run python - <<'PY'
from pathlib import Path
from subprocess import run
from tempfile import TemporaryDirectory
from zipfile import ZipFile

with TemporaryDirectory(prefix="tuntun-contract-wheel-") as temporary:
    output = Path(temporary)
    run(
        [
            "uv",
            "build",
            "--offline",
            "--wheel",
            "packages/contracts",
            "--out-dir",
            str(output),
        ],
        check=True,
    )
    wheels = tuple(output.glob("*.whl"))
    assert len(wheels) == 1
    with ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
        assert "tuntun_contracts/py.typed" in names
        record_name = next(name for name in names if name.endswith(".dist-info/RECORD"))
        record = archive.read(record_name).decode("utf-8")
        assert "tuntun_contracts/py.typed," in record
PY

before_diff="$(git diff --binary HEAD -- . | shasum -a 256)"
before_status="$(git status --porcelain=v1 --untracked-files=all | shasum -a 256)"
before_outputs="$(shasum -a 256 packages/contracts/schema/v1/contracts.schema.json packages/contracts/openapi/admin-v1.yaml)"
uv run python scripts/generate_schemas.py --check
uv run python scripts/generate_openapi.py --check
test "$before_diff" = "$(git diff --binary HEAD -- . | shasum -a 256)"
test "$before_status" = "$(git status --porcelain=v1 --untracked-files=all | shasum -a 256)"
test "$before_outputs" = "$(shasum -a 256 packages/contracts/schema/v1/contracts.schema.json packages/contracts/openapi/admin-v1.yaml)"

make check
git diff --check
```

Expected: PASS with `85 passed` from the focused pytest command. The package smoke assertion still reports `tuntun_contracts.__version__ == "0.1.0.dev0"`; both independent generator processes report the exact exhaustive public model registry (the five required Task 4 FQNs now, with correctly exported and explicitly registered later models admitted automatically); the deliberate omission oracle fails for every public model; and all literal `$ref` plus structurally recognized discriminator-mapping targets resolve. Unsafe-integer/signature/key-ID/coercion/duplicate-FQN/CLI/symlink/special/race/mutation/error-code cases fail exactly as asserted. NFC expansion/contraction cannot bypass Python or strict-JSON field constraints, while strict JSON UUID/datetime/tuple/nested/discriminated-union forms remain supported. The seeded nondeterminism regression observes exactly two renderer calls, and replacing the second call with a reuse of the first render makes that test fail. Replacing the output parent immediately after baseline capture returns `1` without mutation. Replacing it after either clean check-mode snapshot or inside `_atomic_replace`, immediately before the real descriptor-relative `os.replace`, returns `1`; normal rollback leaves both the lexical replacement and renamed old tree equal to their full pre-run snapshots for both missing and existing baselines, restoring the latter's exact bytes and `0640` mode. Check mode never creates a missing parent. Injected rollback-unlink and rollback-replace failures each return `1`, expose the distinct `publication failed and rollback failed` evidence, leave the lexical replacement unchanged, and leave no rollback temporary entry; the test explicitly records that the renamed old tree differs and therefore requires operator handling rather than claiming non-mutation. Both generators return `0` only for current/write success and `1` for every asserted failure. The three before/after values are identical, proving check mode changed neither tracked diffs, worktree inventory, nor either owned artifact. The contracts wheel contains `tuntun_contracts/py.typed` and lists it in `RECORD`; both the Task 4 strict Python 3.11 mypy gate and the exact predecessor `uv run mypy scripts` gate pass under one static script namespace. Ruff, `make check`, and `git diff --check` exit 0.

- [ ] **Step 5: Commit exact Task 4 paths**

```bash
git status --short
git add packages/contracts/src/tuntun_contracts/base.py packages/contracts/src/tuntun_contracts/events.py packages/contracts/src/tuntun_contracts/__init__.py packages/contracts/src/tuntun_contracts/py.typed scripts/__init__.py scripts/contract_generator_common.py scripts/generate_schemas.py scripts/generate_openapi.py scripts/check_feature_absence.py scripts/check_import_boundaries.py scripts/check_migration_graph.py scripts/check_migration_ownership.py scripts/scan_backup_artifacts.py scripts/scan_browser_artifacts.py scripts/scan_network_surface.py scripts/scan_private_data.py scripts/scan_sandbox_residue.py scripts/scan_sql_schema.py packages/contracts/schema/v1/contracts.schema.json packages/contracts/openapi/admin-v1.yaml tests/contract/test_strict_models.py tests/contract/test_event_canonicalization.py tests/contract/test_contract_generators.py
git diff --cached --name-only
git diff --cached
git diff --cached --check
git commit -m "feat(contracts): freeze canonical event primitives"
```

### Task 5: Define the remaining version-1 DTOs and async ports

**Master package:** 02
**Depends on:** Task 4.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `packages/contracts/src/tuntun_contracts/audit.py`
- Create: `packages/contracts/src/tuntun_contracts/actions.py`
- Create: `packages/contracts/src/tuntun_contracts/budget.py`
- Create: `packages/contracts/src/tuntun_contracts/identity.py`
- Create: `packages/contracts/src/tuntun_contracts/memory.py`
- Create: `packages/contracts/src/tuntun_contracts/policy.py`
- Create: `packages/contracts/src/tuntun_contracts/provider.py`
- Create: `packages/contracts/src/tuntun_contracts/reachy.py`
- Create: `packages/contracts/src/tuntun_contracts/speech.py`
- Create: `packages/contracts/src/tuntun_contracts/ports.py`
- Modify: `packages/contracts/src/tuntun_contracts/__init__.py`
- Modify: `packages/contracts/schema/v1/contracts.schema.json`
- Modify: `packages/contracts/openapi/admin-v1.yaml`
- Test: `tests/contract/test_v1_types_and_ports.py`
- Test: `tests/contract/test_dependency_direction.py`

**Interfaces:**
- Consumes: `ContractModel`, `Commitment`, `Sensitivity`, event DTOs, and the sole schema/OpenAPI generators and owned artifact paths from Task 4.
- Produces the following exact public types and methods; later plans must import these names rather than redefining them:

```python
class ClockPort(Protocol):
    def now(self) -> AwareDatetime: raise NotImplementedError
    def monotonic(self) -> float: raise NotImplementedError

class ReachyPort(Protocol):
    async def send(self, command: ReachyCommand) -> ReachyReceipt: raise NotImplementedError
    async def health(self) -> ReachyHealth: raise NotImplementedError
    async def stop_all(self, turn_id: UUID | None) -> SafetyReceipt: raise NotImplementedError

class StopInputPort(Protocol):
    async def receive(self) -> StopSignal: raise NotImplementedError

class AudioConverterPort(Protocol):
    def convert(self, audio: AsyncIterator[bytes], source: AudioFormat, target: AudioFormat) -> AsyncIterator[bytes]: raise NotImplementedError

class SpeechToTextPort(Protocol):
    async def transcribe(self, request: AuthorizedTranscriptionRequest, audio: AsyncIterator[bytes]) -> TranscriptResult: raise NotImplementedError

class TextToSpeechPort(Protocol):
    def synthesize(self, request: AuthorizedSynthesisRequest) -> AsyncIterator[SpeechChunk]: raise NotImplementedError

class LanguageModelPort(Protocol):
    async def complete(self, request: SanitizedProviderRequest) -> ProviderResponse: raise NotImplementedError

class IdentityFusionPort(Protocol):
    async def resolve(self, request: IdentityRequest) -> IdentityDecision: raise NotImplementedError

class MemoryRepositoryPort(Protocol):
    async def create(self, memory: ApprovedMemory, expected_absent: bool = True) -> MemoryRecord: raise NotImplementedError
    async def replace(self, memory_id: UUID, expected_version: int, memory: ApprovedMemory) -> MemoryRecord: raise NotImplementedError
    async def delete(self, memory_id: UUID, expected_version: int, auth: AuthContext, approved_proposal_id: UUID) -> None: raise NotImplementedError
    async def query(self, query: MemoryQuery) -> tuple[MemoryRecord, ...]: raise NotImplementedError

class MemoryProposalServicePort(Protocol):
    async def stage(self, draft: MemoryProposalDraft, context: ProposalContext) -> MemoryProposal: raise NotImplementedError
    async def decide(self, command: DecideMemoryProposal, auth: AuthContext) -> MemoryProposal: raise NotImplementedError

class PolicyEnginePort(Protocol):
    async def decide(self, request: PolicyRequest) -> PolicyDecision: raise NotImplementedError

class AuthenticationPort(Protocol):
    async def start(self, request: AuthenticationRequest) -> AuthenticationChallenge: raise NotImplementedError
    async def verify(self, response: AuthenticationResponse) -> AuthGrant: raise NotImplementedError
    async def consume(self, grant_id: UUID, binding: ActionBinding) -> AuthContext: raise NotImplementedError

class ActionProviderPort(Protocol):
    async def execute(self, proposal: ValidatedActionProposal, auth: AuthContext) -> ActionReceipt: raise NotImplementedError

class AuditPort(Protocol):
    async def append(self, uow: AsyncUnitOfWork, draft: AuditDraft) -> AuditReceipt: raise NotImplementedError

class BudgetPort(Protocol):
    async def reserve(self, request: BudgetReservationRequest) -> BudgetReservation: raise NotImplementedError
    async def mark_sent(self, reservation_id: UUID, attempt_id: UUID) -> None: raise NotImplementedError
    async def settle(self, request: BudgetSettlementRequest) -> BudgetSettlement: raise NotImplementedError
    async def release_unsent(self, reservation_id: UUID, attempt_id: UUID, proof: TransportProof) -> None: raise NotImplementedError
    async def reconcile_turn(self, request: BudgetReconciliationRequest) -> tuple[BudgetSettlement, ...]: raise NotImplementedError

class RouteAuthorizerPort(Protocol):
    async def authorize(self, request: RouteAuthorizationRequest) -> RouteAuthorization: raise NotImplementedError
    async def consume(self, authorization_id: UUID, consumption: RouteConsumption) -> None: raise NotImplementedError

class ConversationWorkflow(Protocol):
    async def run(self, turn: TurnInput) -> TurnOutput: raise NotImplementedError
```

- [ ] **Step 1: Write the red DTO and protocol test**

```python
# tests/contract/test_v1_types_and_ports.py
import inspect
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import TypeAdapter, ValidationError

from tuntun_contracts.actions import ActionBinding, ActionProposalDraft, ActionReceipt, ConsentActionDraft, IdentityActionDraft, ProfileActionDraft, TimerCreateActionDraft, TimerTargetActionDraft
from tuntun_contracts import actions, audit, budget, events, identity, memory, policy, ports, provider, reachy, speech
from tuntun_contracts.base import Commitment, canonical_bytes, registered_contract_models
from tuntun_contracts.budget import BudgetReconciliationRequest, BudgetReservation, BudgetReservationRequest, BudgetSettlement, BudgetSettlementRequest, LlmUsageUnits, ProviderUsageReceiptV1, SttUsageUnits, TransportProof, TtsUsageUnits, WebSearchUsageUnits
from tuntun_contracts.events import StopRequestedPayload
from tuntun_contracts.identity import IdentityEvidence, IdentityRequest, PersonaProjection, PersonaTraits
from tuntun_contracts.memory import ApprovedMemory, EpisodicContent, MemoryAudience, MemoryKind, MemoryQuery, PreferenceContent, ProceduralContent, WorkingContent
from tuntun_contracts.policy import AdminSessionPrincipal, AssuranceLevel, AuthGrant, CurrentOwnerAuthority
from tuntun_contracts.ports import ActionProviderPort, AuthenticationPort, BudgetPort, LanguageModelPort, MemoryRepositoryPort, RouteAuthorizerPort, ReachyPort
from tuntun_contracts.provider import ProviderName, ProviderResponse, RedactionReceipt, RouteAuthorization, SanitizedProviderMessage, SanitizedProviderRequest, SanitizedToolReference
from tuntun_contracts.reachy import StopSignal
from tuntun_contracts.speech import AudioFormat, AuthorizedSynthesisRequest, AuthorizedTranscriptionRequest


def test_every_registered_contract_model_is_strict_closed_and_frozen() -> None:
    # Importing every owning module above completes the registry before this
    # reflection gate; fixture discovery is not the authority for this test.
    registered=registered_contract_models()
    assert registered
    violations={
        f"{model.__module__}.{model.__qualname__}":dict(model.model_config)
        for model in registered
        if model.model_config.get("strict") is not True
        or model.model_config.get("extra") != "forbid"
        or model.model_config.get("frozen") is not True
    }
    assert violations=={}


def test_public_contract_collection_schemas_are_never_variadic() -> None:
    expected={
        (SanitizedProviderRequest,"messages"):(1,32),(SanitizedProviderRequest,"allowed_tools"):(0,8),
        (AuthorizedTranscriptionRequest,"language_hints"):(1,2),
        (IdentityRequest,"evidence"):(0,2),(BudgetReconciliationRequest,"proofs"):(0,8),
        (RedactionReceipt,"removed_categories"):(0,16),
        (WorkingContent,"unresolved_intents"):(0,8),(EpisodicContent,"participant_ids"):(0,16),
        (ProceduralContent,"steps"):(1,32),(MemoryQuery,"kinds"):(1,7),
        (ApprovedMemory,"source_receipt_ids"):(1,8),
    }
    for (model,field),(minimum,maximum) in expected.items():
        schema=model.model_json_schema()["properties"][field]
        assert schema.get("minItems",0)==minimum
        assert schema["maxItems"]==maximum


def test_required_memory_kinds_are_exact() -> None:
    assert {kind.value for kind in MemoryKind} == {
        "working", "episodic", "semantic", "preference", "procedural", "relational", "policy"
    }
    with pytest.raises(ValidationError):
        PreferenceContent(category="food", key="spice", value="high", strength_micros=1.5)

def test_memory_audiences_are_closed() -> None:
    assert {audience.value for audience in MemoryAudience} == {
        "subject_private", "guardian_child", "household_adults", "household_all"
    }


def test_budget_request_carries_closed_usage_not_a_caller_cost() -> None:
    common = {
        "household_id": UUID(int=61), "turn_id": UUID(int=62), "request_id": UUID(int=63),
        "attempt_id": UUID(int=64), "provider": "openai", "model": "gpt-5.6-sol",
        "category": "llm", "month_key": "2026-08",
        "usage_ceiling": LlmUsageUnits(category="llm", input_tokens=8_000, output_tokens=2_000),
    }
    request = BudgetReservationRequest.model_validate(common)
    assert tuple(BudgetReservationRequest.model_fields) == (
        "household_id", "turn_id", "request_id", "attempt_id", "provider", "model",
        "category", "usage_ceiling", "month_key",
    )
    assert request.usage_ceiling.category == "llm"
    for caller_amount in (-1, 0, 1, 1_000_000_000_001):
        with pytest.raises(ValidationError):
            BudgetReservationRequest.model_validate(common | {"worst_case_micros_sgd": caller_amount})
    with pytest.raises(ValidationError):
        BudgetReservationRequest.model_validate(common | {
            "category": "stt",
        })
    with pytest.raises(ValidationError):
        BudgetReservationRequest.model_validate(common | {
            "usage_ceiling": LlmUsageUnits(category="llm", input_tokens=0, output_tokens=0),
        })
    with pytest.raises(ValidationError):
        LlmUsageUnits(category="llm", input_tokens=10_000_001, output_tokens=0)
    with pytest.raises(ValidationError):
        SttUsageUnits(category="stt", audio_millis=3_600_001)
    with pytest.raises(ValidationError):
        TtsUsageUnits(category="tts", characters=4_097)
    assert WebSearchUsageUnits(
        category="web_search",input_tokens=1,output_tokens=1,web_search_calls=1,
    ).web_search_calls==1
    for calls in (0,2,-1,17):
        with pytest.raises(ValidationError):
            BudgetReservationRequest.model_validate(common | {
                "category":"web_search",
                "usage_ceiling":{
                    "category":"web_search","input_tokens":1,"output_tokens":1,
                    "web_search_calls":calls,
                },
            })


def test_budget_settlement_has_no_caller_actual_and_reports_overrun_freeze_truth() -> None:
    request = BudgetSettlementRequest(reservation_id=UUID(int=65), attempt_id=UUID(int=66))
    assert tuple(BudgetSettlementRequest.model_fields) == ("reservation_id", "attempt_id")
    for injected in ({"actual_micros_sgd": 1}, {"provider_usage_present": True}):
        with pytest.raises(ValidationError):
            BudgetSettlementRequest.model_validate(request.model_dump() | injected)
    settlement = BudgetSettlement(
        reservation_id=request.reservation_id, charged_micros_sgd=501,
        conservative_estimate_used=False, estimate_overrun=True, cloud_egress_frozen=True,
    )
    assert settlement.estimate_overrun and settlement.cloud_egress_frozen
    with pytest.raises(ValidationError):
        BudgetSettlement.model_validate(settlement.model_dump() | {"charged_micros_sgd": 1_000_000_000_001})


def test_provider_usage_receipt_is_closed_and_bound_to_the_exact_call() -> None:
    commitment = Commitment(algorithm="HMAC-SHA-256", key_id="provider-usage-v1", value_b64="A" * 43 + "=")
    receipt = ProviderUsageReceiptV1(
        schema_version="tuntun.provider-usage-receipt.v1",
        receipt_id=UUID(int=67), provider_call_id=UUID(int=68), reservation_id=UUID(int=69),
        request_id=UUID(int=70), attempt_id=UUID(int=71), authorization_id=UUID(int=72),
        provider="openai", model="gpt-5.6-sol", category="llm",
        accounting_basis="provider_reported_exact",
        billable_usage=LlmUsageUnits(category="llm", input_tokens=100, output_tokens=25),
        provider_response_commitment=commitment, observed_at=datetime(2026, 8, 27, tzinfo=UTC),
        receipt_commitment=commitment,
    )
    assert tuple(ProviderUsageReceiptV1.model_fields) == (
        "schema_version", "receipt_id", "provider_call_id", "reservation_id", "request_id", "attempt_id",
        "authorization_id", "provider", "model", "category", "accounting_basis",
        "billable_usage",
        "provider_response_commitment", "observed_at", "receipt_commitment",
    )
    with pytest.raises(ValidationError):
        ProviderUsageReceiptV1.model_validate(receipt.model_dump() | {
            "category": "stt", "billable_usage": {"category": "llm", "input_tokens": 100, "output_tokens": 25},
        })
    with pytest.raises(ValidationError,match="web_search_receipt_requires_exactly_one_call"):
        ProviderUsageReceiptV1.model_validate(receipt.model_dump() | {
            "category":"web_search",
            "billable_usage":{
                "category":"web_search","input_tokens":100,"output_tokens":25,
                "web_search_calls":2,
            },
        })


def test_provider_response_exposes_only_the_persisted_usage_receipt_identity() -> None:
    response = ProviderResponse(
        request_id=UUID(int=76), text="synthetic", language="en",
        provider_usage_receipt_id=UUID(int=77),
    )
    assert tuple(ProviderResponse.model_fields) == (
        "request_id", "text", "language", "provider_usage_receipt_id",
    )
    assert ProviderResponse(
        request_id=UUID(int=78), text="synthetic-without-usage", language="en",
        provider_usage_receipt_id=None,
    ).provider_usage_receipt_id is None
    with pytest.raises(ValidationError):
        ProviderResponse.model_validate(response.model_dump() | {
            "usage": {"input_units": 1, "output_units": 1, "audio_millis": 0,
                      "provider_usage_present": True},
        })


@pytest.mark.parametrize(("outcome", "amount", "commitment_present"), [
    ("allow", 1, True), ("allow_soft_warning", 1_000_000_000_000, True),
    ("deny_hard_limit", 0, True), ("deny_unknown_price", 0, False),
    ("deny_cloud_egress_frozen", 0, False),
])
def test_budget_reservation_outcome_amount_and_quote_commitment_are_exact(outcome, amount, commitment_present) -> None:
    commitment = Commitment(algorithm="HMAC-SHA-256", key_id="pricing-v1", value_b64="A" * 43 + "=")
    reservation = BudgetReservation(
        reservation_id=UUID(int=73), request_id=UUID(int=74), attempt_id=UUID(int=75),
        outcome=outcome, amount_micros_sgd=amount,
        pricing_commitment=commitment if commitment_present else None,
        expires_at=datetime(2026, 8, 27, tzinfo=UTC),
    )
    assert reservation.amount_micros_sgd == amount
    with pytest.raises(ValidationError):
        BudgetReservation.model_validate(reservation.model_dump() | {
            "pricing_commitment": None if commitment_present else commitment,
        })


def test_assurance_values_are_exact_and_auth_grants_have_no_biometric_source() -> None:
    assert {value.value for value in AssuranceLevel} == {"guest","identified","confirmed","pin_verified","passkey_verified","recovery_verified"}
    assert "biometric" not in str(AuthGrant.model_json_schema()).lower()


def test_stop_event_and_stop_signal_share_the_exact_closed_sources() -> None:
    expected = {"edge_keyword", "physical_input", "owner_console", "watchdog"}
    assert set(StopRequestedPayload.model_json_schema()["properties"]["source"]["enum"]) == expected
    assert set(StopSignal.model_json_schema()["properties"]["source"]["enum"]) == expected


def test_route_authorization_is_attempt_and_purpose_specific() -> None:
    route = RouteAuthorization(
        authorization_id=UUID(int=1), request_id=UUID(int=9), attempt_id=UUID(int=2), purpose="cloud_reasoning",
        household_id=UUID(int=3), subject_id=None, session_id=UUID(int=4), turn_id=UUID(int=5),
        provider="openai", model="gpt-5.6-sol",
        request_commitment=Commitment(algorithm="HMAC-SHA-256", key_id="route-v1", value_b64="A" * 43 + "="),
        max_input_bytes=8_388_608, max_input_units=8_000,
        privacy_receipt_id=UUID(int=6), consent_receipt_ids=(UUID(int=7),),
        budget_reservation_id=UUID(int=8), maximum_sensitivity="household",
        expires_at=datetime(2026, 8, 27, tzinfo=UTC),
    )
    assert route.purpose == "cloud_reasoning" and route.subject_id is None
    assert tuple(RouteAuthorization.model_fields) == (
        "authorization_id", "request_id", "attempt_id", "purpose", "household_id", "subject_id", "session_id", "turn_id",
        "provider", "model", "request_commitment", "max_input_bytes", "max_input_units", "privacy_receipt_id",
        "consent_receipt_ids", "budget_reservation_id", "maximum_sensitivity", "expires_at",
    )
    with pytest.raises(ValidationError):
        RouteAuthorization.model_validate(route.model_dump() | {"consent_receipt_ids": []})
    assert {"audio_commitment","audio_bytes","duration_ms"} <= set(AuthorizedTranscriptionRequest.model_fields)
    assert {"text_commitment","segment_index","segment_count"} <= set(AuthorizedSynthesisRequest.model_fields)


def test_public_request_collections_have_exact_caps_and_uniqueness() -> None:
    commitment=Commitment(
        algorithm="HMAC-SHA-256",key_id="bounds-v1",value_b64="A"*43+"=",
    )
    route=RouteAuthorization(
        authorization_id=UUID(int=801),request_id=UUID(int=802),attempt_id=UUID(int=803),
        purpose="cloud_reasoning",household_id=UUID(int=804),subject_id=None,
        session_id=UUID(int=805),turn_id=UUID(int=806),provider="openai",model="gpt-5.6-sol",
        request_commitment=commitment,max_input_bytes=1024,max_input_units=1024,
        privacy_receipt_id=UUID(int=807),consent_receipt_ids=(UUID(int=808),),
        budget_reservation_id=UUID(int=809),maximum_sensitivity="household",
        expires_at=datetime(2026,8,27,tzinfo=UTC),
    )
    message=SanitizedProviderMessage(role="user",content="synthetic")
    tool=SanitizedToolReference(
        registered_name="safe.tool",schema_version="1.0",schema_commitment=commitment,
    )
    request=dict(
        request_id=route.request_id,provider=ProviderName.OPENAI,model=route.model,
        messages=(message,),allowed_tools=(),max_output_tokens=10,store=False,
        redaction_receipt_id=UUID(int=810),route=route,timeout_ms=1_000,
    )
    SanitizedProviderRequest(**request)
    for mutation in ({"messages":()},{"messages":(message,)*33},{"allowed_tools":(tool,)*9}):
        with pytest.raises(ValidationError): SanitizedProviderRequest(**(request|mutation))

    audio=dict(
        request_id=UUID(int=811),turn_id=route.turn_id,
        audio_format=AudioFormat(sample_format="s16le",sample_rate_hz=16_000,channels=1,interleaved=True,channel_layout="mono"),
        audio_commitment=commitment,audio_bytes=2,duration_ms=1,language_hints=("en",),route=route,
    )
    AuthorizedTranscriptionRequest(**audio)
    for hints in ((),("en","en"),("en","hi","en")):
        with pytest.raises(ValidationError): AuthorizedTranscriptionRequest(**(audio|{"language_hints":hints}))

    observed=datetime(2026,8,27,tzinfo=UTC)
    evidence=IdentityEvidence(
        modality="face",subject_id=None,confidence_micros=1,quality_micros=1,
        liveness_accepted=False,model_version="synthetic",observed_at=observed,expires_at=observed,
    )
    with pytest.raises(ValidationError):
        IdentityRequest(household_id=route.household_id,session_id=route.session_id,evidence=(evidence,evidence))
    with pytest.raises(ValidationError):
        IdentityRequest(household_id=route.household_id,session_id=route.session_id,evidence=(evidence,)*3)

    proof=TransportProof(
        reservation_id=route.budget_reservation_id,attempt_id=route.attempt_id,
        disposition="never_sent",evidence_code="synthetic",observed_at=observed,
    )
    with pytest.raises(ValidationError): BudgetReconciliationRequest(turn_id=route.turn_id,proofs=(proof,proof))
    with pytest.raises(ValidationError): BudgetReconciliationRequest(turn_id=route.turn_id,proofs=(proof,)*9)

    provider_schema=SanitizedProviderRequest.model_json_schema()["properties"]
    speech_schema=AuthorizedTranscriptionRequest.model_json_schema()["properties"]
    assert (provider_schema["messages"]["minItems"],provider_schema["messages"]["maxItems"])==(1,32)
    assert provider_schema["allowed_tools"]["maxItems"]==8
    assert (speech_schema["language_hints"]["minItems"],speech_schema["language_hints"]["maxItems"])==(1,2)


def test_action_receipt_is_frozen_for_downstream_consumers() -> None:
    fields = ActionReceipt.model_fields
    assert tuple(fields) == (
        "receipt_id", "proposal_id", "household_id", "action_name", "resource_scope",
        "resource_id", "idempotency_key", "outcome", "reason_code", "occurred_at",
    )


def test_owner_authority_and_admin_session_bind_all_current_epochs() -> None:
    assert tuple(CurrentOwnerAuthority.model_fields) == (
        "household_id", "subject_id", "owner_generation", "profile_version", "observed_at",
    )
    assert tuple(AdminSessionPrincipal.model_fields) == (
        "admin_session_id", "household_id", "subject_id", "owner_generation", "profile_version",
        "session_version", "access_mode", "authenticated_at", "idle_expires_at", "absolute_expires_at",
    )


def test_action_drafts_are_a_closed_discriminated_union() -> None:
    schema = TypeAdapter(ActionProposalDraft).json_schema()
    assert schema["discriminator"]["propertyName"] == "action_name"
    encoded = str(schema)
    assert all(name in encoded for name in (
        "timer.create", "backup.restore", "backup.recovery_key.create", "profile.delete",
        "identity.enroll", "identity.enrollment.cancel", "security.finding.suppress",
        "search.profile_mode.change", "search.experimental.activate",
        "release.latency.accept", "release.family_stage.review", "release.p1r0",
    ))
    assert "identity.discovery" not in encoded
    assert "identity.candidate" not in encoded
    assert "additionalProperties': True" not in encoded
    with pytest.raises(ValidationError):
        TypeAdapter(ActionProposalDraft).validate_python({"action_name": "smart_home.unlock", "parameters": {}})


def test_timer_drafts_bind_the_exact_server_resource(valid_action_fields) -> None:
    with pytest.raises(ValidationError):
        TimerCreateActionDraft.model_validate(valid_action_fields("timer.create") | {
            "resource_type": "timer", "resource_id": None, "duration_seconds": 30, "label": "tea",
        })
    timer_id = UUID(int=81)
    with pytest.raises(ValidationError):
        TimerTargetActionDraft.model_validate(valid_action_fields("timer.cancel") | {
            "resource_type": "timer", "resource_id": UUID(int=82), "timer_id": timer_id,
        })


def test_ordinary_profile_create_cannot_create_an_owner(valid_action_fields) -> None:
    subject_id = UUID(int=83)
    with pytest.raises(ValidationError):
        ProfileActionDraft.model_validate(valid_action_fields("profile.create") | {
            "resource_type": "profile", "resource_id": subject_id, "subject_id": subject_id,
            "profile_class": "owner", "display_label": "second owner",
        })


def test_enrollment_cancel_requires_exact_non_null_enrollment_resource(valid_action_fields) -> None:
    subject_id, enrollment_id = UUID(int=84), UUID(int=85)
    common = valid_action_fields("identity.enrollment.cancel") | {
        "resource_type": "identity", "subject_id": subject_id, "enrollment_id": enrollment_id,
    }
    for resource_id in (None, UUID(int=86)):
        with pytest.raises(ValidationError):
            IdentityActionDraft.model_validate(common | {"resource_id": resource_id})


def test_prepared_consent_action_schema_has_exact_durable_purposes() -> None:
    purpose_schema = ConsentActionDraft.model_json_schema()["properties"]["purpose"]
    assert set(purpose_schema["enum"]) == {
        "face", "voice", "personalization", "cloud_stt", "cloud_reasoning", "cloud_tts",
        "web_search", "child_durable_memory_v1",
    }


def test_persona_contract_is_minimized_typed_and_identifier_free() -> None:
    assert tuple(PersonaProjection.model_fields) == ("role", "context", "tone", "depth", "learning_level")
    assert set(PersonaTraits.model_json_schema()["properties"]["context"]["enum"]) == {
        "general", "technical_security", "household_practical", "early_learning"
    }
    encoded = str(PersonaProjection.model_json_schema()).lower()
    assert all(forbidden not in encoded for forbidden in ("subject_id", "name", "birth", "school", "secret", "free_form"))
    with pytest.raises(ValidationError):
        PersonaTraits(context="my private biography", tone="warm", depth="standard", learning_level="none")
    assert {"persona_traits", "clear_persona_traits", "target_profile_class", "expected_version", "guardian_generation"} <= set(ProfileActionDraft.model_fields)
    assert "profile_persona" in str(ActionProposalDraft.model_json_schema())


@pytest.mark.parametrize("change", [
    {},
    {"persona_traits": PersonaTraits(context="general", tone="neutral", depth="standard", learning_level="none")},
    {"profile_class": "adult", "persona_traits": PersonaTraits(context="general", tone="neutral", depth="standard", learning_level="none"), "expected_version": 1},
    {"persona_traits": PersonaTraits(context="general", tone="neutral", depth="standard", learning_level="none"), "expected_version": 1, "guardian_generation": 2},
    {"persona_traits": PersonaTraits(context="general", tone="neutral", depth="standard", learning_level="none"), "clear_persona_traits": True, "expected_version": 1},
])
def test_profile_edit_is_exactly_versioned_replace_or_clear_without_role_change(change) -> None:
    common = {
        "proposal_id": UUID(int=21), "schema_version": "1.0", "action_name": "profile.edit",
        "resource_type": "profile", "resource_id": UUID(int=22), "subject_id": UUID(int=22),
        "target_profile_class": "adult",
        "parameters_commitment": Commitment(algorithm="HMAC-SHA-256", key_id="action-hmac-v1", value_b64="A" * 43 + "="),
        "uncertainty_micros": 0, "expires_at": datetime(2026, 8, 27, tzinfo=UTC), "idempotency_key": UUID(int=23),
    }
    with pytest.raises(ValidationError):
        ProfileActionDraft.model_validate(common | change)


@pytest.mark.parametrize(("target_profile_class", "guardian_generation", "operation"), [
    ("owner", None, "replace"), ("adult", None, "clear"),
    ("k2", 3, "replace"), ("n1", 4, "clear"),
])
def test_profile_edit_allows_exact_server_derived_self_or_guardian_shape(target_profile_class, guardian_generation, operation) -> None:
    traits = PersonaTraits(context="early_learning" if target_profile_class in {"k2", "n1"} else "general", tone="warm", depth="brief", learning_level=target_profile_class if target_profile_class in {"k2", "n1"} else "none")
    draft = ProfileActionDraft(
        proposal_id=UUID(int=24), schema_version="1.0", action_name="profile.edit",
        resource_type="profile", resource_id=UUID(int=25), subject_id=UUID(int=25),
        target_profile_class=target_profile_class,
        persona_traits=traits if operation == "replace" else None,
        clear_persona_traits=operation == "clear", expected_version=2,
        guardian_generation=guardian_generation,
        parameters_commitment=Commitment(algorithm="HMAC-SHA-256", key_id="action-hmac-v1", value_b64="A" * 43 + "="),
        uncertainty_micros=0, expires_at=datetime(2026, 8, 27, tzinfo=UTC), idempotency_key=UUID(int=26),
    )
    assert draft.target_profile_class == target_profile_class
    if guardian_generation is not None:
        assert canonical_bytes(draft) != canonical_bytes(draft.model_copy(update={"guardian_generation": guardian_generation + 1}))


@pytest.mark.parametrize(("target_profile_class", "guardian_generation"), [
    ("owner", 1), ("adult", 1), ("k2", None), ("n1", None),
])
def test_profile_edit_rejects_cross_role_or_null_guardian_generation(target_profile_class, guardian_generation) -> None:
    with pytest.raises(ValidationError):
        ProfileActionDraft(
            proposal_id=UUID(int=27), schema_version="1.0", action_name="profile.edit",
            resource_type="profile", resource_id=UUID(int=28), subject_id=UUID(int=28),
            target_profile_class=target_profile_class,
            persona_traits=PersonaTraits(context="general", tone="neutral", depth="brief", learning_level="none"),
            expected_version=1, guardian_generation=guardian_generation,
            parameters_commitment=Commitment(algorithm="HMAC-SHA-256", key_id="action-hmac-v1", value_b64="A" * 43 + "="),
            uncertainty_micros=0, expires_at=datetime(2026, 8, 27, tzinfo=UTC), idempotency_key=UUID(int=29),
        )


@pytest.fixture
def valid_action_payloads() -> dict[str, dict[str, object]]:
    def base(action_name: str, resource_id: int) -> dict[str, object]:
        return {
            "proposal_id": UUID(int=100 + resource_id), "schema_version": "1.0", "action_name": action_name,
            "resource_type": action_name.split(".", 1)[0], "resource_id": UUID(int=resource_id),
            "parameters_commitment": Commitment(algorithm="HMAC-SHA-256", key_id="action-hmac-v1", value_b64="A" * 43 + "="),
            "uncertainty_micros": 0, "expires_at": datetime(2026, 8, 27, tzinfo=UTC),
            "idempotency_key": UUID(int=200 + resource_id),
        }
    edited = PreferenceContent(category="food", key="spice", value="medium", strength_micros=500_000)
    return {
        "privacy.off": base("privacy.off", 41) | {"typed_confirmation": "TURN OFF PRIVACY"},
        "provider.configure": base("provider.configure", 42) | {"provider": "openai", "enabled": True, "review_record_id": UUID(int=242), "expected_provider_version": 1},
        "credential.passkey.revoke": base("credential.passkey.revoke", 43) | {"credential_id": UUID(int=243), "expected_version": 1},
        "backup.restore": base("backup.restore", 44) | {"backup_id": UUID(int=244), "manifest_sha256": "a" * 64},
        "memory.edit_approve": base("memory.edit_approve", 45) | {"subject_id": UUID(int=245), "proposal_id_ref": UUID(int=246), "expected_version": 1, "decision": "approve", "edited_content": edited},
        "memory.export": base("memory.export", 49) | {"resource_id": UUID(int=253), "subject_id": UUID(int=254), "memory_id": UUID(int=253), "expected_version": 3, "export_format": "json"},
        "identity.enroll": base("identity.enroll", 46) | {"subject_id": UUID(int=247), "modality": "face", "expected_profile_version": 1, "expected_consent_receipt_id": UUID(int=248), "reenrollment_days": 180},
        "search.profile_mode.change": base("search.profile_mode.change", 47) | {"subject_id": UUID(int=249), "expected_profile_version": 1, "mode": "controlled", "expected_web_consent_receipt_id": UUID(int=250)},
        "search.experimental.activate": base("search.experimental.activate", 48) | {"subject_id": UUID(int=251), "expected_profile_version": 1, "expected_web_consent_receipt_id": UUID(int=252), "provider_review_version": 1, "pricing_version": 1, "privacy_generation": 1, "feature_generation": 1, "activation_issued_at": datetime(2026, 8, 27, 0, 0, tzinfo=UTC), "activation_expires_at": datetime(2026, 8, 27, 0, 30, tzinfo=UTC), "max_passes": 4, "max_sources": 20, "max_duration_seconds": 1800, "no_memory": True, "no_authenticated_sites": True, "no_files": True, "no_tools": True},
    }


@pytest.mark.parametrize("action_name,invalid", [
    ("privacy.off", {"typed_confirmation": "UNMUTE"}),
    ("provider.configure", {"provider": "openai", "enabled": True, "expected_provider_version": 1, "hard_limit_micros_sgd": 1}),
    ("credential.passkey.revoke", {"credential_id": UUID(int=31), "expected_version": None}),
    ("backup.restore", {"backup_id": None, "manifest_sha256": None}),
    ("memory.edit_approve", {"proposal_id_ref": UUID(int=32), "expected_version": 1, "decision": "approve", "edited_content": None}),
    ("memory.export", {"memory_id": None}),
    ("memory.export", {"expected_version": None}),
    ("memory.export", {"resource_id": UUID(int=35)}),
    ("memory.export", {"profile_id": UUID(int=36)}),
    ("identity.enroll", {"subject_id": UUID(int=33), "modality": "face", "expected_profile_version": None}),
    ("search.profile_mode.change", {"subject_id": UUID(int=34), "mode": None, "expected_profile_version": 1}),
    ("search.profile_mode.change", {"expected_web_consent_receipt_id": None}),
    ("search.profile_mode.change", {"mode": "no_web", "expected_web_consent_receipt_id": UUID(int=35)}),
    ("search.experimental.activate", {"subject_id": UUID(int=34), "mode": "controlled", "expected_profile_version": 1}),
])
def test_grouped_action_variants_reject_null_or_cross_operation_substitution(action_name, invalid, valid_action_payloads) -> None:
    payload = valid_action_payloads[action_name] | invalid
    with pytest.raises(ValidationError):
        TypeAdapter(ActionProposalDraft).validate_python(payload)


def test_action_binding_is_household_proposal_turn_and_idempotency_bound() -> None:
    assert tuple(ActionBinding.model_fields) == (
        "household_id", "proposal_id", "turn_id", "idempotency_key", "action_name",
        "resource_type", "resource_id", "parameter_commitment", "policy_version",
        "session_id", "subject_id",
    )


def test_external_ports_are_async() -> None:
    assert inspect.iscoroutinefunction(LanguageModelPort.complete)
    assert inspect.iscoroutinefunction(BudgetPort.reserve)
    assert inspect.iscoroutinefunction(BudgetPort.mark_sent)
    assert inspect.iscoroutinefunction(BudgetPort.release_unsent)
    assert inspect.iscoroutinefunction(BudgetPort.reconcile_turn)
    assert inspect.iscoroutinefunction(ReachyPort.stop_all)
    assert inspect.iscoroutinefunction(ActionProviderPort.execute)
    assert inspect.iscoroutinefunction(AuthenticationPort.consume)
    assert inspect.iscoroutinefunction(MemoryRepositoryPort.create)
    assert inspect.iscoroutinefunction(RouteAuthorizerPort.consume)
```

```python
# tests/contract/test_dependency_direction.py
from pathlib import Path


def test_domain_services_and_workflows_do_not_import_adapters() -> None:
    root = Path("apps/core/src/tuntun_core")
    violations = []
    for area in ("domain", "services", "workflows"):
        for path in (root / area).rglob("*.py") if (root / area).exists() else ():
            if "tuntun_core.adapters" in path.read_text(encoding="utf-8"):
                violations.append(str(path))
    assert violations == []
```

- [ ] **Step 2: Run the red DTO/port tests**

Run: `uv run pytest tests/contract/test_v1_types_and_ports.py tests/contract/test_dependency_direction.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_contracts.memory'`.

- [ ] **Step 3: Implement the exact DTO catalog**

```python
# packages/contracts/src/tuntun_contracts/speech.py
from typing import Annotated, AsyncIterator, Literal
from uuid import UUID
from pydantic import Field, field_validator
from .base import Commitment, ContractModel
from .provider import RouteAuthorization

class AudioFormat(ContractModel):
    sample_format: Literal["float32_le", "s16le"]
    sample_rate_hz: Annotated[int, Field(ge=8_000, le=96_000)]
    channels: Annotated[int, Field(ge=1, le=4)]
    interleaved: bool
    channel_layout: Literal["mono", "stereo", "reachy_native"]

class AuthorizedTranscriptionRequest(ContractModel):
    request_id: UUID; turn_id: UUID; audio_format: AudioFormat
    audio_commitment: Commitment
    audio_bytes: Annotated[int, Field(ge=1, le=8_388_608)]
    duration_ms: Annotated[int, Field(ge=1, le=90_000)]
    language_hints: Annotated[tuple[Literal["en", "hi"], ...], Field(min_length=1, max_length=2)]
    route: RouteAuthorization

    @field_validator("language_hints")
    @classmethod
    def unique_language_hints(cls, value):
        if len(set(value)) != len(value): raise ValueError("duplicate language hint")
        return value

class TranscriptResult(ContractModel):
    request_id: UUID; text: Annotated[str, Field(min_length=1, max_length=32_000)]
    language: Literal["en", "hi", "hinglish", "unknown"]; duration_ms: Annotated[int, Field(ge=0, le=90_000)]

class AuthorizedSynthesisRequest(ContractModel):
    request_id: UUID; turn_id: UUID; text: Annotated[str, Field(min_length=1, max_length=4_096)]
    text_commitment: Commitment
    segment_index: Annotated[int, Field(ge=0, le=255)]
    segment_count: Annotated[int, Field(ge=1, le=256)]
    language: Literal["en", "hi", "hinglish"]; dlp_receipt_id: UUID; route: RouteAuthorization

class SpeechChunk(ContractModel):
    request_id: UUID; sequence: Annotated[int, Field(ge=0)]; pcm: bytes = Field(max_length=65_536)
    final: bool
```

```python
# packages/contracts/src/tuntun_contracts/provider.py
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID
from pydantic import AwareDatetime, Field, field_validator
from .base import Commitment, ContractModel, Sensitivity

class ProviderName(StrEnum):
    OPENAI = "openai"
    QWEN = "qwen"

class RouteAuthorization(ContractModel):
    authorization_id: UUID; request_id: UUID; attempt_id: UUID
    purpose: Literal["cloud_stt", "cloud_reasoning", "cloud_tts"]
    household_id: UUID; subject_id: UUID | None; session_id: UUID; turn_id: UUID
    provider: Literal["openai", "qwen"]
    model: Annotated[str, Field(min_length=1, max_length=128)]
    request_commitment: Commitment
    max_input_bytes: Annotated[int, Field(ge=1, le=8_388_608)]
    max_input_units: Annotated[int, Field(ge=1)]
    privacy_receipt_id: UUID; consent_receipt_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=8)]
    budget_reservation_id: UUID; maximum_sensitivity: Sensitivity; expires_at: AwareDatetime

class RouteAuthorizationRequest(ContractModel):
    request_id: UUID; attempt_id: UUID; purpose: Literal["cloud_stt", "cloud_reasoning", "cloud_tts"]
    household_id: UUID; subject_id: UUID | None; session_id: UUID; turn_id: UUID
    provider: Literal["openai", "qwen"]; model: Annotated[str, Field(min_length=1, max_length=128)]
    request_commitment: Commitment; max_input_bytes: Annotated[int, Field(ge=1, le=8_388_608)]; max_input_units: Annotated[int, Field(ge=1)]
    privacy_receipt_id: UUID; consent_receipt_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=8)]; budget_reservation_id: UUID; maximum_sensitivity: Sensitivity

class RouteConsumption(ContractModel):
    request_id: UUID; attempt_id: UUID; purpose: Literal["cloud_stt", "cloud_reasoning", "cloud_tts"]
    household_id: UUID; subject_id: UUID | None; session_id: UUID; turn_id: UUID
    provider: Literal["openai", "qwen"]; model: Annotated[str, Field(min_length=1, max_length=128)]
    request_commitment: Commitment; input_bytes: Annotated[int, Field(ge=0, le=8_388_608)]; input_units: Annotated[int, Field(ge=0)]
    consumed_at: AwareDatetime

class ProviderResponseReceipt(ContractModel):
    receipt_id: UUID; request_id: UUID; attempt_id: UUID; authorization_id: UUID
    household_id: UUID; subject_id: UUID | None; session_id: UUID; turn_id: UUID
    provider: Literal["openai","qwen"]; model: Annotated[str, Field(min_length=1, max_length=128)]
    output_schema_version: Literal["assistant-turn-v1"]; response_commitment: Commitment
    receipt_hmac_key_id: str; receipt_hmac_b64: str; produced_at: AwareDatetime

class SanitizedProviderMessage(ContractModel):
    role: Literal["system", "user", "assistant", "memory_data"]
    content: Annotated[str, Field(min_length=1, max_length=32_000)]

class SanitizedToolReference(ContractModel):
    registered_name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{1,127}$")]
    schema_version: Literal["1.0"]; schema_commitment: Commitment

class SanitizedProviderRequest(ContractModel):
    request_id: UUID; provider: ProviderName
    model: Annotated[str, Field(min_length=1, max_length=128)]
    messages: Annotated[tuple[SanitizedProviderMessage, ...], Field(min_length=1, max_length=32)]
    allowed_tools: Annotated[tuple[SanitizedToolReference, ...], Field(min_length=0, max_length=8)]
    max_output_tokens: Annotated[int, Field(ge=1, le=16_384)]; store: Literal[False] = False
    redaction_receipt_id: UUID; route: RouteAuthorization
    timeout_ms: Annotated[int, Field(ge=1_000, le=120_000)]

class ProviderResponse(ContractModel):
    request_id: UUID; text: Annotated[str, Field(min_length=1, max_length=8_000)]
    language: Literal["en", "hi", "hinglish"]; provider_usage_receipt_id: UUID | None
class RedactionReceipt(ContractModel):
    receipt_id: UUID; purpose: Literal["cloud_reasoning","cloud_tts"]
    input_commitment: Commitment; output_commitment: Commitment
    removed_categories: Annotated[tuple[Annotated[str,Field(min_length=1,max_length=64)],...],Field(min_length=0,max_length=16)]
    removed_count: Annotated[int, Field(ge=0)]
    policy_version: str; maximum_sensitivity: Sensitivity
    @field_validator("removed_categories")
    @classmethod
    def unique_removed_categories(cls,value):
        if len(set(value))!=len(value): raise ValueError("duplicate redaction category")
        return value
```

```python
# packages/contracts/src/tuntun_contracts/memory.py
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID
from pydantic import AwareDatetime, Field, field_validator, model_validator
from .base import Commitment, ContractModel, Sensitivity

class MemoryKind(StrEnum):
    WORKING="working"; EPISODIC="episodic"; SEMANTIC="semantic"; PREFERENCE="preference"
    PROCEDURAL="procedural"; RELATIONAL="relational"; POLICY="policy"

class MemoryAudience(StrEnum):
    SUBJECT_PRIVATE="subject_private"; GUARDIAN_CHILD="guardian_child"
    HOUSEHOLD_ADULTS="household_adults"; HOUSEHOLD_ALL="household_all"

class WorkingContent(ContractModel):
    kind: Literal["working"]; state_summary: str = Field(max_length=2_000)
    unresolved_intents: Annotated[tuple[Annotated[str,Field(min_length=1,max_length=256)],...],Field(min_length=0,max_length=8)]
class EpisodicContent(ContractModel):
    kind: Literal["episodic"]; event_summary: str = Field(max_length=2_000); occurred_at: AwareDatetime
    participant_ids: Annotated[tuple[UUID,...],Field(min_length=0,max_length=16)]
    @field_validator("participant_ids")
    @classmethod
    def unique_participants(cls,value):
        if len(set(value))!=len(value): raise ValueError("duplicate participant")
        return value
class SemanticContent(ContractModel):
    kind: Literal["semantic"]; subject: str = Field(max_length=256); predicate: str = Field(max_length=128); object: str = Field(max_length=2_000)
class PreferenceContent(ContractModel):
    kind: Literal["preference"] = "preference"; category: str = Field(max_length=128); key: str = Field(max_length=128); value: str = Field(max_length=2_000); strength_micros: Annotated[int, Field(ge=0, le=1_000_000)]
class ProceduralContent(ContractModel):
    kind: Literal["procedural"]; name: str = Field(max_length=256)
    steps: Annotated[tuple[Annotated[str,Field(min_length=1,max_length=512)],...],Field(min_length=1,max_length=32)]
    tool_label: str | None = Field(default=None, max_length=128)
class RelationalContent(ContractModel):
    kind: Literal["relational"]; subject_id: UUID; relation: str = Field(max_length=128); object_subject_id: UUID; note: str | None = Field(default=None, max_length=1_000)
class PolicyContent(ContractModel):
    kind: Literal["policy"]; key: str = Field(max_length=128); value: str | int | bool

MemoryContent = Annotated[
    WorkingContent | EpisodicContent | SemanticContent | PreferenceContent | ProceduralContent | RelationalContent | PolicyContent,
    Field(discriminator="kind"),
]

class MemoryProposalDraft(ContractModel):
    proposal_id: UUID; schema_version: Literal["1.0"]; operation: Literal["create", "replace", "delete"]
    household_id: UUID; subject_id: UUID; session_id: UUID; turn_id: UUID; idempotency_key: UUID
    content: MemoryContent | None; audience: MemoryAudience | None
    target_memory_id: UUID | None; expected_version: int | None
    sensitivity: Sensitivity
    confidence_micros: Annotated[int, Field(ge=0, le=1_000_000)]
    reason: Annotated[str, Field(min_length=1, max_length=256)]
    claim_commitment: Commitment
    source_receipt_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=8)]
    expires_at: AwareDatetime
    @model_validator(mode="after")
    def operation_shape(self) -> "MemoryProposalDraft":
        has_target=self.target_memory_id is not None and self.expected_version is not None
        if self.operation=="create" and (self.content is None or self.audience is None or has_target): raise ValueError("create memory proposal shape")
        if self.operation=="replace" and (self.content is None or self.audience is None or not has_target): raise ValueError("replace memory proposal shape")
        if self.operation=="delete" and (self.content is not None or self.audience is not None or not has_target): raise ValueError("delete memory proposal shape")
        return self

class MemoryProposal(ContractModel):
    draft: MemoryProposalDraft; status: Literal["pending", "approved", "rejected", "expired"]
class MemoryRecord(ContractModel):
    memory_id: UUID; household_id: UUID; subject_id: UUID; version: Annotated[int, Field(ge=1)]
    content: MemoryContent; audience: MemoryAudience; sensitivity: Sensitivity; valid_until: AwareDatetime | None
class MemoryQuery(ContractModel):
    household_id: UUID; subject_id: UUID
    kinds: Annotated[tuple[MemoryKind,...],Field(min_length=1,max_length=7)]
    maximum_sensitivity: Sensitivity; limit: Annotated[int, Field(ge=1, le=6)] = 6
    @field_validator("kinds")
    @classmethod
    def unique_kinds(cls,value):
        if len(set(value))!=len(value): raise ValueError("duplicate memory kind")
        return value
class ApprovedMemory(ContractModel):
    memory_id: UUID; household_id: UUID; subject_id: UUID; content: MemoryContent; audience: MemoryAudience; sensitivity: Sensitivity
    approved_proposal_id: UUID
    source_receipt_ids: Annotated[tuple[UUID,...],Field(min_length=1,max_length=8)]
    valid_until: AwareDatetime | None
    @field_validator("source_receipt_ids")
    @classmethod
    def unique_source_receipts(cls,value):
        if len(set(value))!=len(value): raise ValueError("duplicate source receipt")
        return value
class ProposalContext(ContractModel):
    household_id: UUID; subject_id: UUID | None; session_id: UUID; turn_id: UUID; actor_subject_id: UUID | None
class DecideMemoryProposal(ContractModel):
    proposal_id: UUID; decision: Literal["approve","reject"]; edited_content: MemoryContent | None; expected_version: Annotated[int, Field(ge=1)]
```

Create the remaining modules with these exact declarations:

```python
# identity.py
from pydantic import field_validator

class IdentityStatus(StrEnum): VERIFIED="verified"; AMBIGUOUS="ambiguous"; UNKNOWN="unknown"; CONFLICT="conflict"
class IdentityEvidence(ContractModel):
    modality: Literal["face","voice"]; subject_id: UUID | None
    confidence_micros: Annotated[int, Field(ge=0, le=1_000_000)]
    quality_micros: Annotated[int, Field(ge=0, le=1_000_000)]
    liveness_accepted: bool; model_version: str; observed_at: AwareDatetime; expires_at: AwareDatetime
class IdentityRequest(ContractModel):
    household_id: UUID; session_id: UUID
    evidence: Annotated[tuple[IdentityEvidence, ...], Field(min_length=0, max_length=2)]
    @field_validator("evidence")
    @classmethod
    def unique_modalities(cls,value):
        if len({item.modality for item in value}) != len(value): raise ValueError("duplicate identity modality")
        return value
class IdentityDecision(ContractModel): status: IdentityStatus; subject_id: UUID | None; reason_code: str; expires_at: AwareDatetime
class PersonaTraits(ContractModel):
    context: Literal["general","technical_security","household_practical","early_learning"]
    tone: Literal["neutral","precise","practical","warm"]
    depth: Literal["brief","standard","detailed"]
    learning_level: Literal["none","n1","k2"]
class PersonaProjection(ContractModel):
    role: Literal["owner","adult","k2","n1","guest"]
    context: Literal["general","technical_security","household_practical","early_learning"]
    tone: Literal["neutral","precise","practical","warm"]
    depth: Literal["brief","standard","detailed"]
    learning_level: Literal["none","n1","k2"]

# packages/contracts/src/tuntun_contracts/actions.py
from typing import Annotated, Literal
from uuid import UUID
from pydantic import AwareDatetime, Field, model_validator
from .base import Commitment, ContractModel
from .identity import PersonaTraits
from .memory import MemoryContent, MemoryProposalDraft

class ActionDraftBase(ContractModel):
    proposal_id: UUID; schema_version: Literal["1.0"]
    resource_type: str; resource_id: UUID | None; parameters_commitment: Commitment
    uncertainty_micros: Annotated[int, Field(ge=0, le=1_000_000)]
    expires_at: AwareDatetime; idempotency_key: UUID

class TimerCreateActionDraft(ActionDraftBase):
    action_name: Literal["timer.create"]; duration_seconds: Annotated[int, Field(ge=1, le=86_400)]
    label: Annotated[str, Field(min_length=1, max_length=64)]
    @model_validator(mode="after")
    def exact_timer_create_shape(self) -> "TimerCreateActionDraft":
        if self.resource_type != "timer" or self.resource_id is None:
            raise ValueError("timer.create requires a server-generated exact timer resource")
        return self
class TimerTargetActionDraft(ActionDraftBase):
    action_name: Literal["timer.cancel","timer.status"]; timer_id: UUID
    @model_validator(mode="after")
    def exact_timer_target_shape(self) -> "TimerTargetActionDraft":
        if self.resource_type != "timer" or self.resource_id != self.timer_id:
            raise ValueError("timer target must equal the exact resource")
        return self
class SafetyActionDraft(ActionDraftBase):
    action_name: Literal["privacy.on","mute","stop"]; reason_code: Annotated[str, Field(min_length=1, max_length=64)]
class PrivacyReductionActionDraft(ActionDraftBase):
    action_name: Literal["privacy.off","mute.off"]; typed_confirmation: Literal["TURN OFF PRIVACY","UNMUTE"]
    @model_validator(mode="after")
    def exact_confirmation(self) -> "PrivacyReductionActionDraft":
        expected = {"privacy.off": "TURN OFF PRIVACY", "mute.off": "UNMUTE"}[self.action_name]
        if self.typed_confirmation != expected: raise ValueError("privacy reduction confirmation mismatch")
        return self
class ComponentStatusActionDraft(ActionDraftBase):
    action_name: Literal["system.status","reachy.status"]; component: Literal["system","reachy"]
    @model_validator(mode="after")
    def exact_component(self) -> "ComponentStatusActionDraft":
        if self.component != self.action_name.removesuffix(".status"): raise ValueError("status component mismatch")
        return self
class DiagnosticActionDraft(ActionDraftBase):
    action_name: Literal["reachy.gesture_test","offline.prompt_test"]; registered_asset_id: Annotated[str, Field(min_length=1, max_length=128)]
class MemoryActionDraft(ActionDraftBase):
    action_name: Literal["memory.propose","memory.approve","memory.edit_approve","memory.reject","memory.expire","memory.delete","memory.export"]
    subject_id: UUID; proposal_id_ref: UUID | None = None; memory_id: UUID | None = None
    expected_version: Annotated[int, Field(ge=1)] | None = None
    decision: Literal["approve","reject"] | None = None
    edited_content: MemoryContent | None = None
    memory_proposal: MemoryProposalDraft | None = None
    export_format: Literal["json"] | None = None
    @model_validator(mode="after")
    def exact_memory_operation_shape(self) -> "MemoryActionDraft":
        if self.action_name == "memory.propose":
            if self.memory_proposal is None or self.memory_proposal.subject_id != self.subject_id:
                raise ValueError("memory.propose requires the exact server-mapped proposal")
            if any((self.proposal_id_ref, self.memory_id, self.expected_version, self.decision, self.edited_content, self.export_format)):
                raise ValueError("memory.propose contains decision fields")
        elif self.action_name in {"memory.approve","memory.edit_approve","memory.reject"}:
            expected_decision = "reject" if self.action_name == "memory.reject" else "approve"
            if self.proposal_id_ref is None or self.expected_version is None or self.decision != expected_decision:
                raise ValueError("memory decision draft is incomplete")
            if (self.action_name == "memory.edit_approve") != (self.edited_content is not None):
                raise ValueError("edited content is exclusive to memory.edit_approve")
            if any((self.memory_id, self.memory_proposal, self.export_format)):
                raise ValueError("memory decision draft contains another operation's fields")
        elif self.action_name == "memory.expire":
            if self.proposal_id_ref is None or self.expected_version is None or any((self.memory_id, self.decision, self.edited_content, self.memory_proposal, self.export_format)):
                raise ValueError("memory.expire draft is incomplete")
        elif self.action_name == "memory.delete":
            if self.memory_id is None or self.expected_version is None or any((self.proposal_id_ref, self.decision, self.edited_content, self.memory_proposal, self.export_format)):
                raise ValueError("memory.delete requires only target and version")
        elif self.memory_id is None or self.expected_version is None or self.export_format != "json" or self.resource_id != self.memory_id or any((self.proposal_id_ref, self.decision, self.edited_content, self.memory_proposal)):
            raise ValueError("memory.export requires one exact resource, version, and closed export format")
        return self
class ProfileActionDraft(ActionDraftBase):
    action_name: Literal["profile.create","profile.edit","profile.revoke","profile.delete","profile.export"]
    subject_id: UUID; profile_class: Literal["owner","adult","k2","n1"] | None = None
    target_profile_class: Literal["owner","adult","k2","n1"] | None = None
    display_label: Annotated[str | None, Field(default=None, min_length=1, max_length=128)]
    guardian_id: UUID | None = None
    persona_traits: PersonaTraits | None = None; clear_persona_traits: bool = False
    expected_version: Annotated[int, Field(ge=1)] | None = None
    guardian_generation: Annotated[int, Field(ge=1)] | None = None
    @model_validator(mode="after")
    def exact_operation_shape(self) -> "ProfileActionDraft":
        changes_persona = self.persona_traits is not None or self.clear_persona_traits
        if self.action_name == "profile.create":
            if self.profile_class is None or self.target_profile_class is not None or self.display_label is None or changes_persona or self.expected_version is not None or self.guardian_generation is not None:
                raise ValueError("profile.create requires class and display label only")
            if self.profile_class not in {"adult", "k2", "n1"}:
                raise ValueError("ordinary profile.create cannot create or replace the owner")
            if (self.profile_class in {"k2","n1"}) != (self.guardian_id is not None):
                raise ValueError("profile.create guardian shape mismatch")
        elif self.action_name == "profile.edit":
            if not changes_persona: raise ValueError("profile.edit requires replace or clear")
            if self.persona_traits is not None and self.clear_persona_traits: raise ValueError("replace and clear are exclusive")
            if self.expected_version is None or self.target_profile_class is None or self.profile_class is not None or self.display_label is not None or self.guardian_id is not None:
                raise ValueError("persona edit requires version and cannot change role")
            child_target = self.target_profile_class in {"k2", "n1"}
            if child_target != (self.guardian_generation is not None):
                raise ValueError("guardian generation is required exactly for child persona edits")
        elif self.action_name == "profile.revoke":
            if self.expected_version is None or any((self.profile_class, self.target_profile_class, self.display_label, self.guardian_id, self.persona_traits, self.guardian_generation)) or self.clear_persona_traits:
                raise ValueError("profile.revoke requires only expected version")
        elif self.action_name in {"profile.delete","profile.export"}:
            if self.expected_version is None or any((self.profile_class, self.target_profile_class, self.display_label, self.guardian_id, self.persona_traits, self.guardian_generation)) or self.clear_persona_traits:
                raise ValueError("profile lifecycle draft requires only expected version")
        return self
class ConsentActionDraft(ActionDraftBase):
    action_name: Literal["consent.grant","consent.revoke"]; subject_id: UUID
    purpose: Literal["face","voice","personalization","cloud_stt","cloud_reasoning","cloud_tts","web_search","child_durable_memory_v1"]
    expected_latest_receipt_id: UUID | None
    guardian_generation: Annotated[int, Field(ge=1)] | None = None
    policy_version: Annotated[str, Field(min_length=1, max_length=128)]
    disclosure_version: Annotated[str, Field(min_length=1, max_length=128)]
    @model_validator(mode="after")
    def expected_state_shape(self) -> "ConsentActionDraft":
        if self.action_name == "consent.revoke" and self.expected_latest_receipt_id is None:
            raise ValueError("consent.revoke requires expected latest receipt")
        return self
class IdentityActionDraft(ActionDraftBase):
    action_name: Literal["identity.enroll","identity.enrollment.cancel"]
    subject_id: UUID | None; modality: Literal["face","voice"] | None
    enrollment_id: UUID | None = None
    expected_profile_version: Annotated[int, Field(ge=1)] | None = None
    expected_consent_receipt_id: UUID | None = None
    reenrollment_days: Annotated[int, Field(ge=30, le=365)] | None = None
    @model_validator(mode="after")
    def exact_enrollment_shape(self) -> "IdentityActionDraft":
        if self.action_name == "identity.enroll":
            if None in (self.subject_id, self.modality, self.expected_profile_version, self.expected_consent_receipt_id, self.reenrollment_days) or self.enrollment_id is not None:
                raise ValueError("identity.enroll draft is incomplete")
            if self.resource_type != "identity" or self.resource_id != self.subject_id:
                raise ValueError("identity.enroll resource must equal subject")
        elif self.subject_id is None or self.enrollment_id is None or any((self.modality, self.expected_profile_version, self.expected_consent_receipt_id, self.reenrollment_days)):
            raise ValueError("identity.enrollment.cancel requires only enrollment and derived subject")
        elif self.resource_type != "identity" or self.resource_id != self.enrollment_id:
            raise ValueError("identity.enrollment.cancel resource must equal enrollment")
        return self
class ProviderActionDraft(ActionDraftBase):
    action_name: Literal["provider.review","provider.configure","budget.change","access.change"]
    provider: Literal["openai","qwen"] | None = None; enabled: bool | None = None
    review_record_id: UUID | None = None; hard_limit_micros_sgd: Annotated[int, Field(ge=1)] | None = None
    access_mode: Literal["loopback","lan_https"] | None = None
    expected_provider_version: Annotated[int, Field(ge=1)] | None = None
    expected_budget_version: Annotated[int, Field(ge=1)] | None = None
    expected_access_version: Annotated[int, Field(ge=1)] | None = None
    @model_validator(mode="after")
    def exact_provider_operation_shape(self) -> "ProviderActionDraft":
        present = {
            "provider": self.provider is not None, "enabled": self.enabled is not None,
            "review": self.review_record_id is not None, "limit": self.hard_limit_micros_sgd is not None,
            "access": self.access_mode is not None, "provider_version": self.expected_provider_version is not None,
            "budget_version": self.expected_budget_version is not None, "access_version": self.expected_access_version is not None,
        }
        expected = {
            "provider.review": {"provider", "provider_version"},
            "provider.configure": {"provider", "enabled", "review", "provider_version"},
            "budget.change": {"limit", "budget_version"},
            "access.change": {"access", "access_version"},
        }[self.action_name]
        if {name for name, value in present.items() if value} != expected:
            raise ValueError("provider/admin operation shape mismatch")
        return self
class CredentialActionDraft(ActionDraftBase):
    action_name: Literal["credential.passkey.add","credential.passkey.revoke","credential.pin.change","credential.recovery.rotate"]
    credential_id: UUID | None = None; capability: Literal["owner_admin","adult_self_consent","profile_persona"] | None = None
    ceremony_id: UUID | None = None; expected_version: Annotated[int, Field(ge=1)] | None = None
    @model_validator(mode="after")
    def exact_credential_operation_shape(self) -> "CredentialActionDraft":
        present = {"credential": self.credential_id is not None, "capability": self.capability is not None, "ceremony": self.ceremony_id is not None, "version": self.expected_version is not None}
        expected = {
            "credential.passkey.add": {"credential", "capability", "ceremony"},
            "credential.passkey.revoke": {"credential", "version"},
            "credential.pin.change": {"ceremony", "version"},
            "credential.recovery.rotate": {"version"},
        }[self.action_name]
        if {name for name, value in present.items() if value} != expected:
            raise ValueError("credential operation shape mismatch")
        return self
class AuditActionDraft(ActionDraftBase):
    action_name: Literal["audit.export","audit.verify"]; from_ordinal: Annotated[int, Field(ge=1)] | None
    @model_validator(mode="after")
    def exact_audit_operation_shape(self) -> "AuditActionDraft":
        if self.from_ordinal is None: raise ValueError("audit operation requires starting ordinal")
        return self
class BackupActionDraft(ActionDraftBase):
    action_name: Literal["backup.recovery_key.create","backup.create","backup.verify","backup.restore"]
    backup_id: UUID | None = None; recipient_key_id: Annotated[str | None, Field(default=None, min_length=1, max_length=128)]
    manifest_sha256: Annotated[str | None, Field(default=None, pattern=r"^[0-9a-f]{64}$")]
    @model_validator(mode="after")
    def exact_backup_operation_shape(self) -> "BackupActionDraft":
        present = {"backup": self.backup_id is not None, "recipient": self.recipient_key_id is not None, "manifest": self.manifest_sha256 is not None}
        expected = {
            "backup.recovery_key.create": {"recipient"},
            "backup.create": {"backup", "recipient"},
            "backup.verify": {"backup", "manifest"},
            "backup.restore": {"backup", "manifest"},
        }[self.action_name]
        if {name for name, value in present.items() if value} != expected:
            raise ValueError("backup operation shape mismatch")
        return self
class SearchActionDraft(ActionDraftBase):
    action_name: Literal["search.profile_mode.change","search.experimental.activate"]
    subject_id: UUID; expected_profile_version: Annotated[int, Field(ge=1)]
    mode: Literal["controlled","no_web"] | None = None
    expected_web_consent_receipt_id: UUID | None = None
    provider_review_version: Annotated[int, Field(ge=1)] | None = None
    pricing_version: Annotated[int, Field(ge=1)] | None = None
    privacy_generation: Annotated[int, Field(ge=1)] | None = None
    feature_generation: Annotated[int, Field(ge=1)] | None = None
    activation_issued_at: AwareDatetime | None = None; activation_expires_at: AwareDatetime | None = None
    max_passes: Literal[4] | None = None; max_sources: Literal[20] | None = None
    max_duration_seconds: Literal[1800] | None = None
    no_memory: Literal[True] | None = None; no_authenticated_sites: Literal[True] | None = None
    no_files: Literal[True] | None = None; no_tools: Literal[True] | None = None
    @model_validator(mode="after")
    def exact_search_operation_shape(self) -> "SearchActionDraft":
        experimental = (
            self.provider_review_version, self.pricing_version, self.privacy_generation, self.feature_generation,
            self.activation_issued_at, self.activation_expires_at,
            self.max_passes, self.max_sources, self.max_duration_seconds,
            self.no_memory, self.no_authenticated_sites, self.no_files, self.no_tools,
        )
        if self.action_name == "search.profile_mode.change":
            expected_consent = self.expected_web_consent_receipt_id is not None
            if self.mode is None or expected_consent != (self.mode == "controlled") or any(value is not None for value in experimental):
                raise ValueError("search profile-mode draft shape mismatch")
        elif self.mode is not None or self.expected_web_consent_receipt_id is None or any(value is None for value in experimental):
            raise ValueError("experimental search draft is incomplete")
        elif self.activation_expires_at <= self.activation_issued_at or (self.activation_expires_at-self.activation_issued_at).total_seconds() > 1800:
            raise ValueError("experimental search activation must be positive and at most 30 minutes")
        return self
class SecurityFindingActionDraft(ActionDraftBase):
    action_name: Literal["security.finding.suppress"]
    finding_id: Annotated[str, Field(min_length=1, max_length=128)]
    finding_fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    finding_code: Annotated[str, Field(min_length=1, max_length=128)]
    finding_severity: Literal["critical","high"]
    candidate_version: Annotated[str, Field(min_length=1, max_length=128)]
    candidate_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40,64}$")]
    suppression_expires_at: AwareDatetime
class ReleaseP1R0ActionDraft(ActionDraftBase):
    action_name: Literal["release.p1r0"]
    candidate_version: Annotated[str, Field(min_length=1, max_length=128)]
    candidate_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40,64}$")]
    evidence_commitment: Commitment
class LatencyDeviationActionDraft(ActionDraftBase):
    action_name: Literal["release.latency.accept"]
    candidate_version: Annotated[str, Field(min_length=1, max_length=128)]
    candidate_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40,64}$")]
    run_id: UUID
    metric: Literal["first_audio_p95_ms"]
    observed_ms: Annotated[int, Field(ge=0, le=120_000)]
    limit_ms: Annotated[int, Field(ge=1, le=120_000)]
    release_notes_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
class FamilyStageReviewActionDraft(ActionDraftBase):
    action_name: Literal["release.family_stage.review"]
    candidate_version: Annotated[str, Field(min_length=1, max_length=128)]
    candidate_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40,64}$")]
    reviewed_stage_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    decision: Literal["proceed","stop"]

ActionProposalDraft = Annotated[
    TimerCreateActionDraft | TimerTargetActionDraft | SafetyActionDraft | PrivacyReductionActionDraft |
    ComponentStatusActionDraft | DiagnosticActionDraft |
    MemoryActionDraft | ProfileActionDraft | ConsentActionDraft | IdentityActionDraft |
    ProviderActionDraft | CredentialActionDraft | AuditActionDraft | BackupActionDraft | SearchActionDraft |
    SecurityFindingActionDraft | LatencyDeviationActionDraft | FamilyStageReviewActionDraft | ReleaseP1R0ActionDraft,
    Field(discriminator="action_name"),
]
class ActionBinding(ContractModel):
    household_id: UUID; proposal_id: UUID; turn_id: UUID; idempotency_key: UUID
    action_name: str; resource_type: str; resource_id: UUID | None
    parameter_commitment: Commitment; policy_version: str; session_id: UUID; subject_id: UUID | None
class ValidatedActionProposal(ContractModel):
    draft: ActionProposalDraft; binding: ActionBinding
    resource_scope: Annotated[str, Field(min_length=1, max_length=256)]
    required_assurance: Literal["guest","identified","confirmed","pin_verified","passkey_verified","recovery_verified"]
class ActionReceipt(ContractModel):
    receipt_id: UUID; proposal_id: UUID; household_id: UUID; action_name: str
    resource_scope: Annotated[str, Field(min_length=1, max_length=256)]
    resource_id: UUID | None; idempotency_key: UUID
    outcome: Literal["executed","denied","duplicate","failed"]; reason_code: str; occurred_at: AwareDatetime

# packages/contracts/src/tuntun_contracts/policy.py
from .actions import ActionBinding, ActionProposalDraft

class RiskTier(StrEnum): PERSONALIZATION="personalization"; LOW="low"; MEDIUM="medium"; HIGH="high"
class AssuranceLevel(StrEnum): GUEST="guest"; IDENTIFIED="identified"; CONFIRMED="confirmed"; PIN_VERIFIED="pin_verified"; PASSKEY_VERIFIED="passkey_verified"; RECOVERY_VERIFIED="recovery_verified"
class PolicyEffect(StrEnum): ALLOW="allow"; DENY="deny"; STEP_UP="step_up"
class PolicyRequest(ContractModel): household_id: UUID; subject_id: UUID | None; action: ActionProposalDraft; requested_risk: RiskTier; assurance: AssuranceLevel
class PolicyDecision(ContractModel): effect: PolicyEffect; reason_code: str; policy_version: str; required_assurance: AssuranceLevel | None; expires_at: AwareDatetime
class AuthenticationRequest(ContractModel): subject_id: UUID; binding: ActionBinding; requested_assurance: AssuranceLevel
class AuthenticationChallenge(ContractModel): challenge_id: UUID; subject_id: UUID; binding: ActionBinding; factor: Literal["confirmation","pin","passkey"]; expires_at: AwareDatetime
class AuthenticationResponse(ContractModel): challenge_id: UUID; response: Annotated[str, Field(min_length=1, max_length=16_384)]; occurred_at: AwareDatetime
class AuthGrant(ContractModel):
    grant_id: UUID; subject_id: UUID; binding: ActionBinding; assurance: AssuranceLevel
    assurance_source: Literal["explicit_confirmation","pin","passkey","recovery"]; issued_at: AwareDatetime; expires_at: AwareDatetime
    @model_validator(mode="after")
    def source_matches_assurance(self) -> "AuthGrant":
        expected={"explicit_confirmation":AssuranceLevel.CONFIRMED,"pin":AssuranceLevel.PIN_VERIFIED,"passkey":AssuranceLevel.PASSKEY_VERIFIED,"recovery":AssuranceLevel.RECOVERY_VERIFIED}
        if self.assurance is not expected[self.assurance_source]: raise ValueError("assurance source mismatch")
        return self
class AuthContext(ContractModel):
    grant_id: UUID | None; subject_id: UUID | None; binding: ActionBinding; assurance: AssuranceLevel
    assurance_source: Literal["guest","identity","explicit_confirmation","pin","passkey","recovery"]; consumed_at: AwareDatetime
    @model_validator(mode="after")
    def source_matches_assurance(self) -> "AuthContext":
        expected={"guest":AssuranceLevel.GUEST,"identity":AssuranceLevel.IDENTIFIED,"explicit_confirmation":AssuranceLevel.CONFIRMED,"pin":AssuranceLevel.PIN_VERIFIED,"passkey":AssuranceLevel.PASSKEY_VERIFIED,"recovery":AssuranceLevel.RECOVERY_VERIFIED}
        if self.assurance is not expected[self.assurance_source]: raise ValueError("assurance source mismatch")
        if (self.assurance_source in {"guest","identity"}) != (self.grant_id is None): raise ValueError("grant presence mismatch")
        return self
class CurrentOwnerAuthority(ContractModel):
    household_id: UUID; subject_id: UUID
    owner_generation: Annotated[int, Field(ge=1)]; profile_version: Annotated[int, Field(ge=1)]
    observed_at: AwareDatetime
class AdminSessionPrincipal(ContractModel):
    admin_session_id: UUID; household_id: UUID; subject_id: UUID
    owner_generation: Annotated[int, Field(ge=1)]; profile_version: Annotated[int, Field(ge=1)]
    session_version: Annotated[int, Field(ge=1)]; access_mode: Literal["loopback","lan_https"]
    authenticated_at: AwareDatetime; idle_expires_at: AwareDatetime; absolute_expires_at: AwareDatetime
class TimerIntent(ContractModel): timer_id: UUID; operation: Literal["create","cancel","status"]; duration_seconds: Annotated[int, Field(ge=1, le=86_400)] | None; label_commitment: Commitment | None; idempotency_key: UUID

# budget.py
from pydantic import field_validator

MAX_USAGE_UNITS=10_000_000
MAX_AUDIO_MILLIS=3_600_000
MAX_WEB_SEARCH_CALLS=16
MAX_CHARGE_MICROS_SGD=1_000_000_000_000
class LlmUsageUnits(ContractModel): category: Literal["llm"]; input_tokens: Annotated[int, Field(ge=0,le=MAX_USAGE_UNITS)]; output_tokens: Annotated[int, Field(ge=0,le=MAX_USAGE_UNITS)]
class SttUsageUnits(ContractModel): category: Literal["stt"]; audio_millis: Annotated[int, Field(ge=0,le=MAX_AUDIO_MILLIS)]
class TtsUsageUnits(ContractModel): category: Literal["tts"]; characters: Annotated[int, Field(ge=0,le=4_096)]
class WebSearchUsageUnits(ContractModel): category: Literal["web_search"]; input_tokens: Annotated[int,Field(ge=0,le=MAX_USAGE_UNITS)]; output_tokens: Annotated[int,Field(ge=0,le=MAX_USAGE_UNITS)]; web_search_calls: Annotated[int,Field(ge=0,le=MAX_WEB_SEARCH_CALLS)]
UsageUnits=Annotated[LlmUsageUnits|SttUsageUnits|TtsUsageUnits|WebSearchUsageUnits,Field(discriminator="category")]
def usage_total(value: UsageUnits) -> int:
    if isinstance(value,LlmUsageUnits): return value.input_tokens+value.output_tokens
    if isinstance(value,SttUsageUnits): return value.audio_millis
    if isinstance(value,TtsUsageUnits): return value.characters
    return value.input_tokens+value.output_tokens+value.web_search_calls
class BudgetReservationRequest(ContractModel):
    household_id: UUID; turn_id: UUID; request_id: UUID; attempt_id: UUID
    provider: Literal["openai","qwen"]; model: Annotated[str,Field(min_length=1,max_length=128)]
    category: Literal["stt","llm","tts","web_search"]; usage_ceiling: UsageUnits
    month_key: Annotated[str,Field(pattern=r"^[0-9]{4}-(?:0[1-9]|1[0-2])$")]
    @model_validator(mode="after")
    def exact_pricing_purpose(self) -> "BudgetReservationRequest":
        if self.usage_ceiling.category!=self.category or usage_total(self.usage_ceiling)<=0:
            raise ValueError("budget_usage_ceiling_invalid")
        if isinstance(self.usage_ceiling,WebSearchUsageUnits) and self.usage_ceiling.web_search_calls!=1:
            raise ValueError("web_search_reservation_must_price_exactly_one_call")
        return self
class BudgetReservation(ContractModel):
    reservation_id: UUID; request_id: UUID; attempt_id: UUID
    outcome: Literal["allow","allow_soft_warning","deny_hard_limit","deny_unknown_price","deny_cloud_egress_frozen"]
    amount_micros_sgd: Annotated[int,Field(ge=0,le=MAX_CHARGE_MICROS_SGD)]
    pricing_commitment: Commitment|None; expires_at: AwareDatetime
    @model_validator(mode="after")
    def exact_quote_shape(self) -> "BudgetReservation":
        quote_absent=self.outcome in {"deny_unknown_price","deny_cloud_egress_frozen"}
        if quote_absent!=(self.pricing_commitment is None): raise ValueError("budget_reservation_quote_shape_invalid")
        allowed=self.outcome in {"allow","allow_soft_warning"}
        if allowed!=(self.amount_micros_sgd>0): raise ValueError("budget_reservation_amount_shape_invalid")
        return self
class BudgetSettlementRequest(ContractModel): reservation_id: UUID; attempt_id: UUID
class BudgetSettlement(ContractModel):
    reservation_id: UUID; charged_micros_sgd: Annotated[int,Field(ge=0,le=MAX_CHARGE_MICROS_SGD)]
    conservative_estimate_used: bool; estimate_overrun: bool; cloud_egress_frozen: bool
class ProviderUsageReceiptV1(ContractModel):
    schema_version: Literal["tuntun.provider-usage-receipt.v1"]
    receipt_id: UUID; provider_call_id: UUID; reservation_id: UUID; request_id: UUID; attempt_id: UUID; authorization_id: UUID
    provider: Literal["openai","qwen"]; model: Annotated[str,Field(min_length=1,max_length=128)]
    category: Literal["stt","llm","tts","web_search"]
    accounting_basis: Literal["provider_reported_exact","request_bound_exact","conservative_full_reservation"]
    billable_usage: UsageUnits
    provider_response_commitment: Commitment; observed_at: AwareDatetime; receipt_commitment: Commitment
    @model_validator(mode="after")
    def exact_usage_category(self) -> "ProviderUsageReceiptV1":
        if self.category!=self.billable_usage.category: raise ValueError("provider_usage_category_mismatch")
        if isinstance(self.billable_usage,WebSearchUsageUnits) and self.billable_usage.web_search_calls!=1:
            raise ValueError("web_search_receipt_requires_exactly_one_call")
        return self
class TransportProof(ContractModel): reservation_id: UUID; attempt_id: UUID; disposition: Literal["never_sent","sent","unknown"]; evidence_code: str; observed_at: AwareDatetime
class BudgetReconciliationRequest(ContractModel):
    turn_id: UUID
    proofs: Annotated[tuple[TransportProof, ...], Field(min_length=0, max_length=8)]
    @field_validator("proofs")
    @classmethod
    def unique_attempt_proofs(cls,value):
        keys={(item.reservation_id,item.attempt_id) for item in value}
        if len(keys) != len(value): raise ValueError("duplicate transport proof")
        return value

# audit.py
class AuditDraft(ContractModel): event_id: UUID; occurred_at: AwareDatetime; actor_pseudonym: str; action_code: str; outcome: str; reason_code: str; correlation_id: UUID; payload_commitment: Commitment
class AuditReceipt(ContractModel): receipt_id: UUID; ordinal: Annotated[int, Field(ge=1)]; public_hash_hex: str = Field(pattern=r"^[0-9a-f]{64}$"); hmac_key_id: str; hmac_b64: str; occurred_at: AwareDatetime

# reachy.py
class ReachyState(StrEnum): BOOTING="booting"; CONNECTING="connecting"; IDLE="idle"; WAKE_LISTENING="wake_listening"; THINKING="thinking"; SPEAKING="speaking"; MUTED="muted"; PRIVACY="privacy"; OFFLINE_ESSENTIAL="offline_essential"; ERROR_SAFE="error_safe"; SHUTTING_DOWN="shutting_down"
class ReachyCommand(ContractModel):
    command_id: UUID; turn_id: UUID | None; kind: Literal["state","playback","gesture","stop_all"]
    state: ReachyState | None = None; media_stream_id: UUID | None = None
    gesture_id: Annotated[str | None, Field(default=None, pattern=r"^[a-z][a-z0-9_-]{0,63}$")]
    expires_at: AwareDatetime
    @model_validator(mode="after")
    def exact_payload(self) -> "ReachyCommand":
        present = (self.state is not None, self.media_stream_id is not None, self.gesture_id is not None)
        expected = {"state": (True,False,False), "playback": (False,True,False), "gesture": (False,False,True), "stop_all": (False,False,False)}[self.kind]
        if present != expected: raise ValueError("reachy command payload mismatch")
        if self.kind in {"playback","gesture"} and self.turn_id is None: raise ValueError("turn-scoped Reachy command required")
        return self
class ReachyReceipt(ContractModel): command_id: UUID; accepted: bool; reason_code: str
class ReachyHealth(ContractModel): state: ReachyState; daemon_connected: bool; queue_depth: Annotated[int, Field(ge=0)]
class SafetyReceipt(ContractModel): turn_id: UUID | None; playback_stopped: bool; motion_stopped: bool; buffers_cleared: bool
class StopAllReceiptBundleV1(ContractModel):
    schema_version: Literal["tuntun.reachy-stop-all-receipts.v1"]="tuntun.reachy-stop-all-receipts.v1"
    command_receipt: ReachyReceipt
    safety_receipt: SafetyReceipt
class StopSignal(ContractModel): signal_id: UUID; source: Literal["edge_keyword","physical_input","owner_console","watchdog"]; occurred_at: AwareDatetime
class CameraWindowGrant(ContractModel):
    grant_id: UUID; household_id: UUID; device_id: UUID; session_id: UUID; turn_id: UUID
    subject_id: UUID | None; action_name: Literal["identity.enroll","identity.observe"]
    purpose: Literal["explicit_enrollment","active_conversation_identity"]
    max_frames: Annotated[int, Field(ge=1, le=20)]; max_frame_bytes: Annotated[int, Field(ge=1, le=1_048_576)]
    max_total_bytes: Annotated[int, Field(ge=1, le=10_485_760)]; max_frames_per_second: Annotated[int, Field(ge=1, le=2)]
    issued_at: AwareDatetime; expires_at: AwareDatetime; grant_commitment: Commitment
    @model_validator(mode="after")
    def bounded_window(self) -> "CameraWindowGrant":
        if self.expires_at <= self.issued_at or (self.expires_at - self.issued_at).total_seconds() > 10:
            raise ValueError("camera window must be positive and at most 10 seconds")
        if self.max_frames * self.max_frame_bytes < self.max_total_bytes:
            raise ValueError("camera aggregate bound exceeds frame bounds")
        if self.purpose == "explicit_enrollment" and self.subject_id is None:
            raise ValueError("enrollment camera window requires subject")
        return self

# ports.py turn DTOs
class TurnInput(ContractModel): turn_id: UUID; household_id: UUID; device_id: UUID
class TurnOutput(ContractModel): turn_id: UUID; outcome: Literal["completed","cancelled","denied","failed"]
```

Use `StrEnum`, `Literal`, `Annotated`, `Field`, `AwareDatetime`, `model_validator`, and UUID imports exactly as required by those declarations. In `ports.py`, declare every protocol from the Interfaces block with `@runtime_checkable`; import `AsyncIterator`, `Protocol`, and the DTOs from their owning modules. Export all public names from `tuntun_contracts/__init__.py` without importing any application package.

The contract semantics are also frozen: `IdentityFusionPort` returns identity only and cannot mint assurance. `AuthGrant`/`AuthContext.assurance_source` deliberately has no biometric value, so face/voice evidence cannot create `confirmed` or a stronger assurance. `CurrentOwnerAuthority` is the current database observation of one exact household owner subject, owner generation, and active profile version. `AdminSessionPrincipal` additionally binds that authority snapshot to one exact admin-session version plus idle/absolute expiries; request and mutation boundaries must re-open the session row, reject `revoked_at`, compare every principal field, and revalidate the current owner snapshot before use. It proves only a current owner console session and can never substitute for an action-bound `AuthGrant`/`AuthContext`; every mutation reconstructs its exact binding on the server and consumes a fresh matching grant when the registry requires one. The same admin principal grants no implicit memory-body visibility: every memory create/replace persists one closed `MemoryAudience`, and later read projections use subject, current guardian, and audience policy before decryption. An `ActionBinding` includes household, proposal, turn, idempotency, action, resource, parameter commitment, policy, conversation session, and subject, so a proof cannot be transplanted across any of those boundaries. `ActionReceipt` additionally persists `household_id` and the server-derived `resource_scope`; its idempotency boundary is exactly `(household_id, action_name, resource_scope, idempotency_key)`, matching `action_proposals`, and a global unique idempotency key is forbidden. Frozen DTOs remain fields-only: callers use explicit binding comparators, policy-request factories, and audit-draft mappers rather than calling undeclared methods on them. `RouteAuthorizerPort.consume` is single-use and must compare every `RouteConsumption` binding field to the stored authorization in constant time for commitments before any adapter I/O. `BudgetReservationRequest` carries only a closed, positive, bounded usage ceiling; extra caller monetary estimates are forbidden. Reservation pricing is recomputed locally from the exact provider/model/category and one current price/FX record, and the returned `pricing_commitment` is null exactly for unknown-price or already-frozen denials. `BudgetSettlementRequest` carries no caller cost or usage-presence claim: settlement loads and purpose-verifies the full `ProviderUsageReceiptV1` persisted by the gateway against the exact call/reservation/request/attempt/authorization/provider/model/category and the provider-response commitment, then recomputes the charge from the immutable reservation price snapshot. `ProviderResponse` exposes only the nullable ID of that already-persisted receipt, never raw usage or an authority boolean; a non-null ID is gateway-bound to the exact call/route, while missing or malformed usage never means zero and a succeeded call without one valid persisted receipt freezes/alerts and fails settlement as an unknown possible overage. `BudgetPort.release_unsent` accepts only a matching `TransportProof(disposition="never_sent")`; `sent` and `unknown` reconcile conservatively through settlement, while every retry retains `request_id` and receives a fresh `attempt_id`. A verified actual above the reservation is never clipped; `estimate_overrun` and `cloud_egress_frozen` expose the durable overrun/freeze truth. `CameraWindowGrant` is the only contract that permits camera frames; it is action/subject/session/turn/purpose-bound, single-use, at most 10 seconds/20 frames/10 MiB, and its byte/frame/rate/expiry bounds may only be narrowed downstream.

`web_search` and `child_durable_memory_v1` are Phase 1 contract amendments consumed by the controlled-web and identity/memory supplements. `web_search` is durable owner/adult self-consent; `child_durable_memory_v1` is durable K2/N1 consent granted or revoked only by that child's current primary guardian with the exact guardian generation. Neither widens the baseline `RouteAuthorization` speech/reasoning/TTS purpose union. Every consent draft carries the expected latest receipt ID, guardian generation when applicable, and policy/disclosure versions; revoke requires a non-null expected receipt. Its purpose-separated parameter commitment covers exactly subject, purpose, expected receipt state, guardian generation, and both versions, while the `ActionBinding` separately fixes household, authenticated actor, action, resource, session, and turn. The mutation service reconstructs that payload and compares its HMAC before any receipt access. Guest disclosure/session-consent contracts remain exactly `cloud_stt|cloud_reasoning|cloud_tts`; K2/N1 search and owner/adult child-memory consent are policy-denied even if a caller forges a prepared consent action. This amendment changes no task number or effort estimate.

`PersonaTraits` is the only prepared profile-personalization payload. Its four closed fields contain no arbitrary text, exact child identifier, profession/name string, secret, contact, or household fact. `PersonaProjection` adds only the canonical role and is the complete value allowed into persona/context construction. `profile.edit` must be exactly one of replace or clear, must carry an expected profile version, and cannot carry a role change. Its server mapper loads and freezes `target_profile_class`; owner/adult self-edits require a null `guardian_generation`, while K2/N1 edits require the exact current guardian generation. The parameter commitment binds subject, actor via `ActionBinding`, operation, version, target class, guardian generation, and the full typed payload. The mutation service reconstructs and verifies that commitment before its first profile read, then rechecks the loaded immutable class and current guardian relation/generation in the mutation UoW; stale or substituted generations fail closed. Credential capability `profile_persona` is distinct from `adult_self_consent`: it can authorize only that exact bound `profile.edit` replace/clear path, never consent or administration. This contract work is folded into the existing contract task and changes no task or effort total.

`memory.export` is the one-record export action: `memory_id`, the server-loaded `expected_version`, `resource_id=memory_id`, subject, and `export_format="json"` are all mandatory and commitment-bound. It cannot represent a profile-wide export, omit the version, or carry another memory operation's fields; whole-profile export remains the distinct `profile.export` action. Exact record/version/subject substitution fails before memory projection or decryption.

- [ ] **Step 4: Run the green DTO/port gate**

Run: `uv run python scripts/generate_schemas.py --write && uv run python scripts/generate_openapi.py --write && uv run pytest tests/contract/test_v1_types_and_ports.py tests/contract/test_dependency_direction.py tests/contract/test_contract_generators.py -q && uv run python scripts/generate_schemas.py --check && uv run python scripts/generate_openapi.py --check && uv run ruff check packages/contracts/src tests/contract && uv run mypy packages/contracts/src`

Expected: PASS; required enum values match exactly, every asserted port operation is async, both generated artifacts contain exactly the complete post-DTO public registry, and immediate check-mode rerenders are byte-identical with no missing, stale, or extra output.

- [ ] **Step 5: Commit exact Task 5 paths**

```bash
git status --short
git add packages/contracts/src/tuntun_contracts/actions.py packages/contracts/src/tuntun_contracts/audit.py packages/contracts/src/tuntun_contracts/budget.py packages/contracts/src/tuntun_contracts/identity.py packages/contracts/src/tuntun_contracts/memory.py packages/contracts/src/tuntun_contracts/policy.py packages/contracts/src/tuntun_contracts/provider.py packages/contracts/src/tuntun_contracts/reachy.py packages/contracts/src/tuntun_contracts/speech.py packages/contracts/src/tuntun_contracts/ports.py packages/contracts/src/tuntun_contracts/__init__.py packages/contracts/schema/v1/contracts.schema.json packages/contracts/openapi/admin-v1.yaml tests/contract/test_v1_types_and_ports.py tests/contract/test_dependency_direction.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(contracts): define versioned DTOs and ports"
```

### Task 6: Freeze canonical fixtures and the initial privacy inventory

**Master package:** 02
**Depends on:** Task 5.
**Estimated effort:** 0.5 person-day.

**Files:**
- Create: `packages/contracts/fixtures/v1/actions.json`
- Create: `packages/contracts/fixtures/v1/events.json`
- Create: `packages/contracts/fixtures/v1/speech.json`
- Create: `packages/contracts/fixtures/v1/identity.json`
- Create: `packages/contracts/fixtures/v1/memory.json`
- Create: `packages/contracts/fixtures/v1/policy.json`
- Create: `packages/contracts/fixtures/v1/provider.json`
- Create: `packages/contracts/fixtures/v1/budget.json`
- Create: `packages/contracts/fixtures/v1/audit.json`
- Create: `packages/contracts/fixtures/v1/reachy.json`
- Create: `scripts/contract_fixture_builders.py`
- Create: `scripts/generate_contract_fixtures.py`
- Test: `tests/contract/test_v1_fixtures.py`
- Create: `docs/privacy/threat-model.md`
- Create: `docs/privacy/data-flow-inventory.md`

**Interfaces:**
- Consumes: every public Task 4–5 DTO and `canonical_bytes`.
- Produces: one canonical valid object per public model under a top-level `schema_version: "1.0"`; byte-stable fixture round trips; initial Reachy/LAN/Mac/browser/provider/supply-chain trust-boundary inventory. Every memory create/replace, record, and approved-memory fixture carries one valid closed audience; delete proposals carry explicit `audience: null`; missing/unknown audiences fail validation.

- [ ] **Step 1: Write the failing fixture round-trip test**

```python
# tests/contract/test_v1_fixtures.py
import json
from pathlib import Path

import pytest

from scripts.contract_fixture_builders import BUILDERS, FixtureFactory, semantic_specs
from tuntun_contracts import (
    actions, audit, budget, events, identity, memory, policy, ports, provider, reachy, speech,
)
from tuntun_contracts.base import (
    Commitment, ContractModel, canonical_bytes, parse_contract_json,
    registered_contract_models,
)
from tuntun_contracts.events import EventEnvelope

FIXTURE_ROOT = Path("packages/contracts/fixtures/v1")
MODULES = {
    "actions": (actions,), "events": (events, ports), "speech": (speech,),
    "identity": (identity,), "memory": (memory,), "policy": (policy,),
    "provider": (provider,), "budget": (budget,), "audit": (audit,),
    "reachy": (reachy,),
}


def fixture_registry() -> dict[str, dict[str, type[ContractModel]]]:
    result: dict[str, dict[str, type[ContractModel]]] = {}
    for group, owning_modules in MODULES.items():
        result[group] = {
            name: value
            for module in owning_modules
            for name, value in vars(module).items()
            if isinstance(value, type)
            and issubclass(value, ContractModel)
            and value is not ContractModel
            and value.__module__ == module.__name__
        }
    result["events"]["Commitment"] = Commitment
    return result


MODEL_REGISTRY = fixture_registry()


def test_fixture_registry_is_the_complete_public_contract_registry() -> None:
    fixture_models = {
        model for models in MODEL_REGISTRY.values() for model in models.values()
    }
    assert fixture_models == set(registered_contract_models()) | {Commitment}
    assert set(BUILDERS) == fixture_models
    assert set(semantic_specs(FixtureFactory.preview())) <= fixture_models


@pytest.mark.parametrize("name", ["actions","events","speech","identity","memory","policy","provider","budget","audit","reachy"])
def test_fixture_file_exists_and_is_version_one(name: str) -> None:
    payload = json.loads((FIXTURE_ROOT / f"{name}.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0"
    assert set(payload["examples"]) == set(MODEL_REGISTRY[name])
    for model_name, model_type in MODEL_REGISTRY[name].items():
        model = parse_contract_json(
            model_type,json.dumps(payload["examples"][model_name],separators=(",",":")).encode("utf-8"),
            max_bytes=1_048_576,require_canonical=False,
        )
        assert canonical_bytes(model).decode("utf-8") == payload["canonical_examples"][model_name]


def test_event_fixture_round_trips_to_identical_canonical_bytes() -> None:
    payload = json.loads((FIXTURE_ROOT / "events.json").read_text(encoding="utf-8"))
    model = parse_contract_json(
        EventEnvelope,json.dumps(payload["examples"]["EventEnvelope"],separators=(",",":")).encode("utf-8"),
        max_bytes=1_048_576,require_canonical=False,
    )
    assert canonical_bytes(model).decode("utf-8") == payload["canonical_examples"]["EventEnvelope"]
```

- [ ] **Step 2: Run the red fixture tests**

Run: `uv run pytest tests/contract/test_v1_fixtures.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'scripts.contract_fixture_builders'`; after that builder registry exists but before fixture generation, the failure advances to `FileNotFoundError: packages/contracts/fixtures/v1/events.json`.

- [ ] **Step 3: Add deterministic fixtures and privacy documents**

`scripts/contract_fixture_builders.py` owns one exhaustive builder registry. Schema-derived fields may use a deterministic schema builder, but every field participating in a field/model validator, discriminator correlation, or nested semantically constrained union is supplied by an explicit `SemanticSpec`; those fields are never guessed from JSON Schema.

```python
# core of scripts/contract_fixture_builders.py
@dataclass(frozen=True)
class SemanticSpec:
    fields: frozenset[str]
    values: Callable[["FixtureFactory"], dict[str, object]]


def action_base(factory, action_name, resource_type, resource_id=None):
    return {
        "action_name": action_name,
        "resource_type": resource_type,
        "resource_id": resource_id if resource_id is not None else factory.uuid(),
    }


def semantic_specs(factory: "FixtureFactory") -> dict[type[ContractModel], SemanticSpec]:
    timer_id=factory.uuid(); subject_id=factory.uuid()
    return {
        Commitment: SemanticSpec(frozenset({"algorithm","key_id","value_b64"}),lambda f:{"algorithm":"HMAC-SHA-256","key_id":"fixture-v1","value_b64":"A"*43+"="}),
        events.EventEnvelope: SemanticSpec(frozenset({"event_type","payload"}),lambda f:{"event_type":"speech.wake_detected","payload":f.build(events.WakeDetectedPayload)}),
        speech.AuthorizedTranscriptionRequest: SemanticSpec(frozenset({"language_hints"}),lambda f:{"language_hints":("en","hi")}),
        identity.IdentityRequest: SemanticSpec(frozenset({"evidence"}),lambda f:{"evidence":()}),
        memory.EpisodicContent: SemanticSpec(frozenset({"participant_ids"}),lambda f:{"participant_ids":()}),
        memory.MemoryProposalDraft: SemanticSpec(frozenset({"operation","content","audience","target_memory_id","expected_version"}),lambda f:{"operation":"delete","content":None,"audience":None,"target_memory_id":f.uuid(),"expected_version":1}),
        memory.MemoryProposal: SemanticSpec(frozenset({"draft"}),lambda f:{"draft":f.build(memory.MemoryProposalDraft)}),
        memory.MemoryQuery: SemanticSpec(frozenset({"kinds"}),lambda f:{"kinds":("working",)}),
        memory.ApprovedMemory: SemanticSpec(frozenset({"source_receipt_ids"}),lambda f:{"source_receipt_ids":(f.uuid(),)}),
        actions.TimerCreateActionDraft: SemanticSpec(frozenset({"action_name","resource_type","resource_id"}),lambda f:action_base(f,"timer.create","timer")),
        actions.TimerTargetActionDraft: SemanticSpec(frozenset({"action_name","resource_type","resource_id","timer_id"}),lambda f:{**action_base(f,"timer.cancel","timer",timer_id),"timer_id":timer_id}),
        actions.SafetyActionDraft: SemanticSpec(frozenset({"action_name","resource_type"}),lambda f:{**action_base(f,"privacy.on","privacy"),"reason_code":"fixture"}),
        actions.PrivacyReductionActionDraft: SemanticSpec(frozenset({"action_name","resource_type","typed_confirmation"}),lambda f:{**action_base(f,"privacy.off","privacy"),"typed_confirmation":"TURN OFF PRIVACY"}),
        actions.ComponentStatusActionDraft: SemanticSpec(frozenset({"action_name","resource_type","component"}),lambda f:{**action_base(f,"system.status","system"),"component":"system"}),
        actions.DiagnosticActionDraft: SemanticSpec(frozenset({"action_name","resource_type"}),lambda f:{**action_base(f,"reachy.gesture_test","reachy"),"registered_asset_id":"fixture.asset"}),
        actions.MemoryActionDraft: SemanticSpec(frozenset({"action_name","resource_type","resource_id","subject_id","proposal_id_ref","memory_id","expected_version","decision","edited_content","memory_proposal","export_format"}),lambda f:{**action_base(f,"memory.delete","memory"),"subject_id":f.uuid(),"proposal_id_ref":None,"memory_id":f.uuid(),"expected_version":1,"decision":None,"edited_content":None,"memory_proposal":None,"export_format":None}),
        actions.ProfileActionDraft: SemanticSpec(frozenset({"action_name","resource_type","subject_id","profile_class","target_profile_class","display_label","guardian_id","persona_traits","clear_persona_traits","expected_version","guardian_generation"}),lambda f:{**action_base(f,"profile.revoke","profile",subject_id),"subject_id":subject_id,"profile_class":None,"target_profile_class":None,"display_label":None,"guardian_id":None,"persona_traits":None,"clear_persona_traits":False,"expected_version":1,"guardian_generation":None}),
        actions.ConsentActionDraft: SemanticSpec(frozenset({"action_name","resource_type","subject_id","expected_latest_receipt_id","guardian_generation"}),lambda f:{**action_base(f,"consent.grant","consent",subject_id),"subject_id":subject_id,"purpose":"personalization","expected_latest_receipt_id":None,"guardian_generation":None}),
        actions.IdentityActionDraft: SemanticSpec(frozenset({"action_name","resource_type","resource_id","subject_id","modality","enrollment_id","expected_profile_version","expected_consent_receipt_id","reenrollment_days"}),lambda f:{**action_base(f,"identity.enroll","identity",subject_id),"subject_id":subject_id,"modality":"face","enrollment_id":None,"expected_profile_version":1,"expected_consent_receipt_id":f.uuid(),"reenrollment_days":180}),
        actions.ProviderActionDraft: SemanticSpec(frozenset({"action_name","resource_type","provider","enabled","review_record_id","hard_limit_micros_sgd","access_mode","expected_provider_version","expected_budget_version","expected_access_version"}),lambda f:{**action_base(f,"provider.review","provider"),"provider":"openai","enabled":None,"review_record_id":None,"hard_limit_micros_sgd":None,"access_mode":None,"expected_provider_version":1,"expected_budget_version":None,"expected_access_version":None}),
        actions.CredentialActionDraft: SemanticSpec(frozenset({"action_name","resource_type","credential_id","capability","ceremony_id","expected_version"}),lambda f:{**action_base(f,"credential.recovery.rotate","credential"),"credential_id":None,"capability":None,"ceremony_id":None,"expected_version":1}),
        actions.AuditActionDraft: SemanticSpec(frozenset({"action_name","resource_type","from_ordinal"}),lambda f:{**action_base(f,"audit.verify","audit"),"from_ordinal":1}),
        actions.BackupActionDraft: SemanticSpec(frozenset({"action_name","resource_type","backup_id","recipient_key_id","manifest_sha256"}),lambda f:{**action_base(f,"backup.recovery_key.create","backup"),"backup_id":None,"recipient_key_id":"fixture-key","manifest_sha256":None}),
        actions.SearchActionDraft: SemanticSpec(frozenset({"action_name","resource_type","subject_id","mode","expected_web_consent_receipt_id","provider_review_version","pricing_version","privacy_generation","feature_generation","activation_issued_at","activation_expires_at","max_passes","max_sources","max_duration_seconds","no_memory","no_authenticated_sites","no_files","no_tools"}),lambda f:{**action_base(f,"search.profile_mode.change","search",subject_id),"subject_id":subject_id,"expected_profile_version":1,"mode":"no_web","expected_web_consent_receipt_id":None,"provider_review_version":None,"pricing_version":None,"privacy_generation":None,"feature_generation":None,"activation_issued_at":None,"activation_expires_at":None,"max_passes":None,"max_sources":None,"max_duration_seconds":None,"no_memory":None,"no_authenticated_sites":None,"no_files":None,"no_tools":None}),
        actions.SecurityFindingActionDraft: SemanticSpec(frozenset({"action_name","resource_type"}),lambda f:action_base(f,"security.finding.suppress","security")),
        actions.ReleaseP1R0ActionDraft: SemanticSpec(frozenset({"action_name","resource_type"}),lambda f:action_base(f,"release.p1r0","release")),
        actions.LatencyDeviationActionDraft: SemanticSpec(frozenset({"action_name","resource_type"}),lambda f:action_base(f,"release.latency.accept","release")),
        actions.FamilyStageReviewActionDraft: SemanticSpec(frozenset({"action_name","resource_type"}),lambda f:action_base(f,"release.family_stage.review","release")),
        actions.ValidatedActionProposal: SemanticSpec(frozenset({"draft"}),lambda f:{"draft":f.build(actions.TimerCreateActionDraft)}),
        policy.PolicyRequest: SemanticSpec(frozenset({"action"}),lambda f:{"action":f.build(actions.TimerCreateActionDraft)}),
        policy.AuthGrant: SemanticSpec(frozenset({"assurance","assurance_source"}),lambda f:{"assurance":"confirmed","assurance_source":"explicit_confirmation"}),
        policy.AuthContext: SemanticSpec(frozenset({"grant_id","assurance","assurance_source"}),lambda f:{"grant_id":None,"assurance":"guest","assurance_source":"guest"}),
        provider.RedactionReceipt: SemanticSpec(frozenset({"removed_categories"}),lambda f:{"removed_categories":()}),
        budget.BudgetReservationRequest: SemanticSpec(frozenset({"category","usage_ceiling","month_key"}),lambda f:{"category":"llm","usage_ceiling":{"category":"llm","input_tokens":1,"output_tokens":0},"month_key":"2026-08"}),
        budget.BudgetReservation: SemanticSpec(frozenset({"outcome","amount_micros_sgd","pricing_commitment"}),lambda f:{"outcome":"allow","amount_micros_sgd":1,"pricing_commitment":f.build(Commitment)}),
        budget.ProviderUsageReceiptV1: SemanticSpec(frozenset({"category","billable_usage"}),lambda f:{"category":"llm","billable_usage":{"category":"llm","input_tokens":1,"output_tokens":0}}),
        budget.BudgetReconciliationRequest: SemanticSpec(frozenset({"proofs"}),lambda f:{"proofs":()}),
        reachy.ReachyCommand: SemanticSpec(frozenset({"kind","state","media_stream_id","gesture_id"}),lambda f:{"kind":"state","state":"idle","media_stream_id":None,"gesture_id":None}),
        reachy.CameraWindowGrant: SemanticSpec(frozenset({"subject_id","action_name","purpose","max_frames","max_frame_bytes","max_total_bytes","max_frames_per_second","issued_at","expires_at"}),lambda f:{"subject_id":f.uuid(),"action_name":"identity.enroll","purpose":"explicit_enrollment","max_frames":2,"max_frame_bytes":1024,"max_total_bytes":2048,"max_frames_per_second":1,"issued_at":f.time(),"expires_at":f.time(offset_microseconds=5_000_000)}),
    }
```

`FixtureFactory` owns a deterministic UUID counter and `time(*, offset_microseconds: int = 0)`, which returns the fixed UTC fixture epoch plus the requested `timedelta`; it never reads the clock, random source, environment, or model schema. The schema-only classification is equally explicit, so a newly registered model cannot silently fall into generic generation:

```python
SCHEMA_ONLY_MODELS=frozenset({
    events.WakeDetectedPayload,events.StopRequestedPayload,events.SignedEventEnvelope,
    ports.TurnInput,ports.TurnOutput,
    speech.AudioFormat,speech.TranscriptResult,speech.AuthorizedSynthesisRequest,
    speech.SpeechChunk,
    identity.IdentityEvidence,identity.IdentityDecision,identity.PersonaTraits,
    identity.PersonaProjection,
    memory.WorkingContent,memory.SemanticContent,memory.PreferenceContent,
    memory.ProceduralContent,memory.RelationalContent,memory.PolicyContent,
    memory.MemoryRecord,memory.ProposalContext,memory.DecideMemoryProposal,
    actions.ActionDraftBase,actions.ActionBinding,actions.ActionReceipt,
    policy.PolicyDecision,policy.AuthenticationRequest,policy.AuthenticationChallenge,
    policy.AuthenticationResponse,policy.CurrentOwnerAuthority,
    policy.AdminSessionPrincipal,policy.TimerIntent,
    provider.RouteAuthorization,provider.RouteAuthorizationRequest,
    provider.RouteConsumption,provider.ProviderResponseReceipt,
    provider.SanitizedProviderMessage,provider.SanitizedToolReference,
    provider.SanitizedProviderRequest,provider.ProviderResponse,
    budget.LlmUsageUnits,budget.SttUsageUnits,budget.TtsUsageUnits,
    budget.WebSearchUsageUnits,budget.BudgetSettlementRequest,
    budget.BudgetSettlement,budget.TransportProof,
    audit.AuditDraft,audit.AuditReceipt,
    reachy.ReachyReceipt,reachy.ReachyHealth,reachy.SafetyReceipt,
    reachy.StopAllReceiptBundleV1,reachy.StopSignal,
})
```

`FixtureFactory.schema_payload(model_type)` is limited to those models. It follows `const`, `enum`, required fields, non-null union branches, `minItems`, numeric minima, UUID/date-time formats, and the closed regex cases used by these contracts. When `$ref` or a union branch names another registered `ContractModel`, it calls `self.build(referenced_model)` and embeds that normally validated result instead of recursively guessing the nested semantic model. It increments UUIDs for every item so schema-level uniqueness is deterministic. `FixtureFactory.build` is exactly:

```python
def build(self, model_type: type[ContractModel]) -> ContractModel:
    builder = BUILDERS[model_type]
    model = builder(self)
    if type(model) is not model_type:
        raise TypeError(f"fixture builder returned wrong type for {model_type.__name__}")
    # Exercise the ordinary hostile-ingress validation path again; no
    # model_construct, model_copy(update=...), or skipped validation is allowed.
    return parse_contract_json(
        model_type, canonical_bytes(model), max_bytes=1_048_576,
        require_canonical=True,
    )


SEMANTIC_BUILDERS = {
    model: (lambda current: lambda factory: factory.validated_semantic(current))(model)
    for model in semantic_specs(FixtureFactory.preview()).keys()
}
SCHEMA_ONLY_BUILDERS = {
    model: (lambda current: lambda factory: factory.validated_schema_only(current))(model)
    for model in SCHEMA_ONLY_MODELS
}
BUILDERS = SEMANTIC_BUILDERS | SCHEMA_ONLY_BUILDERS
PUBLIC_MODELS = {
    model for models in fixture_registry().values() for model in models.values()
}
assert not (set(SEMANTIC_BUILDERS) & set(SCHEMA_ONLY_BUILDERS))
assert set(BUILDERS) == PUBLIC_MODELS
```

`validated_semantic` renders the schema-derived independent fields, requires `spec.fields <= set(spec.values(self))`, rejects every supplied key that is not a real model field, replaces the supplied explicit values, and calls `model_type.model_validate(payload)`. Extra supplied real fields are allowed only to make a complete explicit variant easier to review; an omitted correlated field is not. Thus a new public model, an unclassified model, a semantic model accidentally placed in the schema-only set, an omitted correlated field, or an unknown override fails before any fixture file is written. `tests/contract/test_v1_fixtures.py` imports `BUILDERS` and adds `assert set(BUILDERS) == fixture_models`; it also asserts `set(semantic_specs(FixtureFactory.preview())) == set(SEMANTIC_BUILDERS)`.

```python
# scripts/generate_contract_fixtures.py
import json
from pathlib import Path

from scripts.contract_fixture_builders import BUILDERS, FixtureFactory, fixture_registry
from tuntun_contracts.base import canonical_bytes


def main() -> None:
    root=Path("packages/contracts/fixtures/v1")
    root.mkdir(parents=True,exist_ok=True)
    factory=FixtureFactory(first_uuid=101)
    registry=fixture_registry()
    assert set(BUILDERS)=={
        model for models in registry.values() for model in models.values()
    }
    for group,models in registry.items():
        examples={}; canonical={}
        for name,model_type in sorted(models.items()):
            model=factory.build(model_type)
            examples[name]=model.model_dump(mode="json")
            canonical[name]=canonical_bytes(model).decode("utf-8")
        output={"schema_version":"1.0","examples":examples,"canonical_examples":canonical}
        (root/f"{group}.json").write_text(
            json.dumps(output,indent=2,sort_keys=True,ensure_ascii=False)+"\n",
            encoding="utf-8",
        )


if __name__=="__main__": main()
```

The generator assigns fixed UUIDs beginning at `00000000-0000-0000-0000-000000000101`, uses only synthetic closed strings and the fixed timestamp, normally validates every object before serialization, and writes canonical oracles. Review the generated diff once, then retain the builder registry, generator, and fixtures; CI reruns the generator and fails if `git diff --exit-code packages/contracts/fixtures/v1` is non-empty. No fixture contains audio, a conversation transcript, names, addresses, credentials, or provider prose.

Write `docs/privacy/threat-model.md` with assets (database/key roots, audit authenticity, contracts/model manifest, availability), actors (owner, family subject, Guest, LAN attacker, malicious model output, compromised dependency), trust boundaries (Reachy↔LAN↔Mac, browser↔API, Mac↔provider, build↔dependency/model sources), and foundation mitigations mapped to Task 3 scanning, strict contracts, Keychain, SQLCipher, AEAD, manifest hashes, and audit triggers. Write `docs/privacy/data-flow-inventory.md` as a table with columns `Data class | Source | Purpose | Processor | Durable location | Egress | Retention/deletion | Key`; include configuration, secrets, event receipts, audit receipts, provider-price/budget metadata, model metadata, and synthetic fixtures. Mark raw audio/transcripts/frames as “not processed by foundation; durable location none.”

- [ ] **Step 4: Run the green fixture/privacy gate**

Run: `uv run python scripts/generate_contract_fixtures.py && uv run pytest tests/contract/test_v1_fixtures.py -q && uv run python scripts/generate_contract_fixtures.py && git diff --exit-code packages/contracts/fixtures/v1 && uv run ruff check scripts/contract_fixture_builders.py scripts/generate_contract_fixtures.py tests/contract/test_v1_fixtures.py && uv run mypy scripts/contract_fixture_builders.py scripts/generate_contract_fixtures.py && uv run python scripts/verify_private_data.py packages/contracts/fixtures/v1 docs/privacy`

Expected: PASS with 12 fixture/registry tests, `set(BUILDERS)` exactly equal to the complete public registry, every semantic class owned by an explicit `SemanticSpec`, two byte-identical generations, zero Ruff/mypy errors, and `private-data scan: PASS`.

- [ ] **Step 5: Commit exact Task 6 paths**

```bash
git status --short
git add packages/contracts/fixtures/v1/actions.json packages/contracts/fixtures/v1/events.json packages/contracts/fixtures/v1/speech.json packages/contracts/fixtures/v1/identity.json packages/contracts/fixtures/v1/memory.json packages/contracts/fixtures/v1/policy.json packages/contracts/fixtures/v1/provider.json packages/contracts/fixtures/v1/budget.json packages/contracts/fixtures/v1/audit.json packages/contracts/fixtures/v1/reachy.json scripts/contract_fixture_builders.py scripts/generate_contract_fixtures.py tests/contract/test_v1_fixtures.py docs/privacy/threat-model.md docs/privacy/data-flow-inventory.md
git diff --cached --name-only
git diff --cached
git commit -m "test(contracts): freeze version-one fixtures and privacy inventory"
```

### Task 7: Implement strict settings and owner-only filesystem paths

**Master package:** 03
**Depends on:** Tasks 1 and 3.
**Estimated effort:** 1 person-day.

**Files:**
- Modify: `apps/core/pyproject.toml`
- Modify: `uv.lock`
- Create: `apps/core/src/tuntun_core/config/settings.py`
- Create: `apps/core/src/tuntun_core/config/loader.py`
- Create: `apps/core/src/tuntun_core/config/secure_paths.py`
- Create: `apps/core/src/tuntun_core/config/paths.py`
- Create: `config/tuntun.example.yaml`
- Create: `.env.example`
- Test: `tests/unit/config/test_settings.py`
- Test: `tests/unit/config/test_paths.py`
- Create: `tests/unit/config/conftest.py`

**Interfaces:**
- Consumes: YAML file and explicit `TUNTUN_` environment overrides.
- Produces: `Settings` and `load_settings(yaml_path: Path | None, environ: Mapping[str, str]) -> Settings`; descriptor-walked `OwnedPath(path, device, inode).revalidate()`; `open_owned_directory(path: Path) -> OwnedDirectory`, whose context-managed live directory FD remains open until `close()`/context exit; `ensure_private_directory(path: Path) -> OwnedPath`; and `ApplicationPaths.create(base: Path | None = None) -> ApplicationPaths` with `root`, `data`, `logs`, `models`, and `backups` directories at exact mode `0700`. Every initial and revalidation walk opens every lexical path component no-follow relative to its already verified parent; root-owned ancestors must not be group/world writable, user-owned ancestors must be private, and every returned leaf is a user-owned directory whose device/inode/type/mode match its named entry and retained FD. No untrusted application path is accepted by calling `resolve()`/`realpath()` through a symlink. On macOS, tests canonicalize pytest's trusted temporary root once from `/var/...` to `/private/var/...`; production path logic does not canonicalize an untrusted alias.

- [ ] **Step 1: Write red settings/path tests**

```python
# tests/unit/config/test_settings.py
from pathlib import Path
import pytest
from pydantic import ValidationError
from tuntun_core.config.loader import load_settings

def test_defaults_are_locked() -> None:
    settings = load_settings(None, {})
    assert settings.household.timezone == "Asia/Singapore"
    assert settings.conversation.active_limit == 1
    assert settings.network.admin_host == "127.0.0.1"
    assert settings.network.admin_port == 8787
    assert settings.network.admin_lan_port == 8443
    assert settings.network.edge_gateway_port == 7443
    assert settings.providers.primary_model == "gpt-5.6-sol"
    assert settings.providers.qwen_enabled is False
    assert (settings.providers.connect_timeout_ms, settings.providers.write_timeout_ms, settings.providers.read_timeout_ms, settings.providers.pool_timeout_ms, settings.providers.max_attempts) == (5_000,30_000,120_000,5_000,2)
    assert (settings.identity.child_reenrollment_reminder_days, settings.identity.child_biometric_hard_expiry_days) == (180,365)
    assert (settings.admin.session_idle_seconds, settings.admin.session_absolute_seconds, settings.admin.json_body_max_bytes) == (900,28_800,1_048_576)
    assert (settings.admin.read_requests_per_minute, settings.admin.mutation_requests_per_minute, settings.admin.auth_requests_per_minute, settings.admin.trust_proxy_headers) == (120,30,10,False)
    assert (settings.observability.telemetry_enabled, settings.observability.cloud_tracing_enabled, settings.observability.provider_body_logging) == (False,False,False)
    assert settings.budget.soft_limit_micros_sgd == 100_000_000
    assert settings.budget.hard_limit_micros_sgd == 150_000_000

def test_public_bind_and_unknown_yaml_fail(tmp_path: Path) -> None:
    config = tmp_path / "bad.yaml"
    config.write_text("network:\n  admin_host: 0.0.0.0\nunknown: true\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_settings(config, {})

def test_environment_overrides_yaml_but_unspecified_yaml_survives(tmp_path: Path) -> None:
    config=tmp_path/"config.yaml"; config.write_text("providers:\n  primary_model: configured-model\nmemory:\n  max_items_per_turn: 5\n",encoding="utf-8")
    settings=load_settings(config,{"TUNTUN_PROVIDERS__PRIMARY_MODEL":"environment-model"})
    assert settings.providers.primary_model == "environment-model"
    assert settings.memory.max_items_per_turn == 5


@pytest.mark.parametrize("mutation",(
    "duplicate_key","yaml_alias","explicit_tag","overdeep","too_many_events",
    "oversized_file","symlink","fifo","group_writable","changed_during_read",
))
def test_settings_file_is_bounded_duplicate_free_nofollow_and_stable(
    strict_settings_case,mutation,
) -> None:
    strict_settings_case.mutate(mutation)
    with pytest.raises((PermissionError,ValueError)):
        load_settings(strict_settings_case.path,{})


@pytest.mark.parametrize("raw",(
    "[1,2]","{x: 1}","&x value","!custom value","x"*1_025,
))
def test_environment_override_is_one_bounded_plain_scalar(raw) -> None:
    with pytest.raises(ValueError):
        load_settings(None,{"TUNTUN_MEMORY__MAX_ITEMS_PER_TURN":raw})
```

```python
# tests/unit/config/test_paths.py
import os
import stat
from pathlib import Path
import pytest
from tuntun_core.config import secure_paths
from tuntun_core.config.paths import ApplicationPaths
from tuntun_core.config.secure_paths import ensure_private_directory,open_owned_directory

def _fixture_root(tmp_path:Path) -> Path:
    # pytest owns this root. Darwin may report it through the trusted /var alias;
    # production code must never use realpath to bless an untrusted symlink.
    return Path(os.path.realpath(tmp_path))

def test_paths_are_created_owner_only(tmp_path: Path) -> None:
    paths = ApplicationPaths.create(_fixture_root(tmp_path) / "Tuntun")
    for path in (paths.root, paths.data, paths.logs, paths.models, paths.backups):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700


@pytest.mark.parametrize("mutation",(
    "ancestor_symlink","root_symlink","data_symlink","data_fifo",
    "wrong_mode","wrong_owner",
))
def test_application_paths_reject_unsafe_existing_components(
    tmp_path:Path,monkeypatch:pytest.MonkeyPatch,mutation:str,
) -> None:
    root=_fixture_root(tmp_path); base=root/"Tuntun"; target=root/"target"
    target.mkdir(mode=0o700)
    if mutation=="ancestor_symlink":
        real=root/"real-parent"; real.mkdir(mode=0o700)
        alias=root/"alias-parent"; alias.symlink_to(real,directory=True)
        base=alias/"Tuntun"
    elif mutation=="root_symlink": base.symlink_to(target,directory=True)
    else:
        base.mkdir(mode=0o700)
        if mutation=="data_symlink": (base/"data").symlink_to(target,directory=True)
        elif mutation=="data_fifo": os.mkfifo(base/"data",0o600)
        elif mutation=="wrong_mode": base.chmod(0o750)
        elif mutation=="wrong_owner":
            actual_euid=os.geteuid()
            monkeypatch.setattr(secure_paths.os,"geteuid",lambda:actual_euid+1)
    with pytest.raises(PermissionError,match="unsafe application path"):
        ApplicationPaths.create(base)


def test_live_directory_guard_rejects_parent_replacement_and_closes_fd(
    tmp_path:Path,
) -> None:
    root=_fixture_root(tmp_path); base=root/"Tuntun"; base.mkdir(mode=0o700)
    directory=open_owned_directory(base); held_fd=directory.fd
    base.rename(root/"opened-original"); base.mkdir(mode=0o700)
    with pytest.raises(PermissionError,match="unsafe application path"):
        directory.revalidate()
    directory.close()
    with pytest.raises(OSError): os.fstat(held_fd)


def test_owned_path_fresh_walk_rejects_one_way_ancestor_replacement(
    tmp_path:Path,
) -> None:
    root=_fixture_root(tmp_path); parent=root/"parent"; leaf=parent/"leaf"
    parent.mkdir(mode=0o700); identity=ensure_private_directory(leaf)
    parent.rename(root/"old-parent")
    parent.mkdir(mode=0o700); (parent/"leaf").mkdir(mode=0o700)
    with pytest.raises(PermissionError,match="unsafe application path"):
        identity.revalidate()
```

Define `strict_settings_case` in the config subtree where it is consumed. It begins as an owner-only regular valid settings file; every mutation changes exactly one loader invariant:

```python
# tests/unit/config/conftest.py
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import pytest


@dataclass
class StrictSettingsCase:
    path: Path
    monkeypatch: pytest.MonkeyPatch

    def mutate(self, mutation: str) -> None:
        if mutation == "duplicate_key":
            self.path.write_text("memory:\n  max_items_per_turn: 5\nmemory: {}\n")
        elif mutation == "yaml_alias":
            self.path.write_text("memory: &m {max_items_per_turn: 5}\ncopy: *m\n")
        elif mutation == "explicit_tag":
            self.path.write_text("memory: !custom {max_items_per_turn: 5}\n")
        elif mutation == "overdeep":
            self.path.write_text("unknown: " + "[" * 33 + "0" + "]" * 33 + "\n")
        elif mutation == "too_many_events":
            self.path.write_text("unknown: [" + ",".join("0" for _ in range(16_385)) + "]\n")
        elif mutation == "oversized_file":
            self.path.write_bytes(b"#" * 262_145)
        elif mutation == "symlink":
            target = self.path.with_name("target.yaml")
            target.write_text("{}\n"); self.path.unlink(); self.path.symlink_to(target.name)
        elif mutation == "fifo":
            self.path.unlink(); os.mkfifo(self.path, 0o600)
        elif mutation == "group_writable":
            self.path.chmod(0o620)
        elif mutation == "changed_during_read":
            from tuntun_core.config import loader
            replacement = self.path.with_name("replacement.yaml")
            replacement.write_text("memory:\n  max_items_per_turn: 4\n")
            replacement.chmod(0o600)
            original_read = loader.os.read
            swapped = False
            def replacing_read(fd: int, size: int) -> bytes:
                nonlocal swapped
                chunk = original_read(fd, size)
                if chunk and not swapped:
                    swapped = True
                    self.path.replace(self.path.with_name("original.yaml"))
                    replacement.replace(self.path)
                return chunk
            self.monkeypatch.setattr(loader.os, "read", replacing_read)
        else:
            raise AssertionError(f"unknown strict-settings mutation: {mutation}")


@pytest.fixture
def strict_settings_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> StrictSettingsCase:
    path = tmp_path / "settings.yaml"
    path.write_text("memory:\n  max_items_per_turn: 5\n", encoding="utf-8")
    path.chmod(0o600)
    return StrictSettingsCase(path, monkeypatch)
```

- [ ] **Step 2: Run the red settings tests**

Run: `uv run pytest tests/unit/config/test_settings.py tests/unit/config/test_paths.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.config'`.

- [ ] **Step 3: Implement immutable nested settings and explicit precedence**

```python
# apps/core/src/tuntun_core/config/settings.py
from ipaddress import ip_address
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

class FrozenSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
class HouseholdSettings(FrozenSettings): timezone: str = "Asia/Singapore"
class ConversationSettings(FrozenSettings):
    active_limit: int = Field(default=1, ge=1, le=1); follow_up_window_seconds: int = 30
    idle_close_seconds: int = 60; absolute_session_limit_minutes: int = 30
class PrivacySettings(FrozenSettings): audit_default_view_days: int = 180
class NetworkSettings(FrozenSettings):
    admin_host: str = "127.0.0.1"; admin_port: int = 8787; admin_lan_port: int = Field(default=8443, ge=8443, le=8443); edge_gateway_port: int = 7443
    @model_validator(mode="after")
    def private_bind(self) -> "NetworkSettings":
        address = ip_address(self.admin_host)
        if not address.is_loopback:
            raise ValueError("default admin bind must be loopback")
        return self
class ProviderSettings(FrozenSettings):
    primary_model: str = "gpt-5.6-sol"; qwen_enabled: bool = False; context_max_tokens: int = 8_000
    connect_timeout_ms: int = Field(default=5_000, ge=1_000, le=120_000); write_timeout_ms: int = Field(default=30_000, ge=1_000, le=120_000)
    read_timeout_ms: int = Field(default=120_000, ge=1_000, le=120_000); pool_timeout_ms: int = Field(default=5_000, ge=1_000, le=120_000)
    max_attempts: int = Field(default=2, ge=1, le=2)
class MemorySettings(FrozenSettings): max_items_per_turn: int = Field(default=6, ge=1, le=6)
class IdentitySettings(FrozenSettings):
    child_reenrollment_reminder_days: int = Field(default=180, ge=30, le=365); child_biometric_hard_expiry_days: int = Field(default=365, ge=30, le=365)
class AdminSettings(FrozenSettings):
    session_idle_seconds: int = 900; session_absolute_seconds: int = 28_800; json_body_max_bytes: int = 1_048_576
    read_requests_per_minute: int = 120; mutation_requests_per_minute: int = 30; auth_requests_per_minute: int = 10
    trust_proxy_headers: Literal[False] = False
class ObservabilitySettings(FrozenSettings):
    telemetry_enabled: Literal[False] = False; cloud_tracing_enabled: Literal[False] = False; provider_body_logging: Literal[False] = False
class BudgetSettings(FrozenSettings):
    soft_limit_micros_sgd: int = 100_000_000; hard_limit_micros_sgd: int = 150_000_000
    @model_validator(mode="after")
    def ordered_limits(self) -> "BudgetSettings":
        if self.hard_limit_micros_sgd < self.soft_limit_micros_sgd:
            raise ValueError("hard limit must be at least soft limit")
        return self
class Settings(FrozenSettings):
    household: HouseholdSettings = HouseholdSettings(); conversation: ConversationSettings = ConversationSettings()
    privacy: PrivacySettings = PrivacySettings(); network: NetworkSettings = NetworkSettings()
    providers: ProviderSettings = ProviderSettings(); memory: MemorySettings = MemorySettings(); identity: IdentitySettings = IdentitySettings()
    admin: AdminSettings = AdminSettings(); observability: ObservabilitySettings = ObservabilitySettings(); budget: BudgetSettings = BudgetSettings()
```

```python
# apps/core/src/tuntun_core/config/loader.py
import os
from pathlib import Path
import stat
from typing import Mapping
import yaml
from yaml.events import AliasEvent,CollectionEndEvent,CollectionStartEvent
from yaml.nodes import MappingNode
from .settings import Settings

MAX_SETTINGS_BYTES=262_144

class StrictSettingsLoader(yaml.SafeLoader):
    def construct_mapping(self,node,deep=False):
        if not isinstance(node,MappingNode): raise ValueError("invalid configuration")
        result={}
        for key_node,value_node in node.value:
            key=self.construct_object(key_node,deep=deep)
            if type(key) is not str or key in result:
                raise ValueError("invalid configuration")
            result[key]=self.construct_object(value_node,deep=deep)
        return result

def parse_bounded_strict_yaml(
    raw:bytes,*,max_bytes:int,max_events:int=16_384,max_depth:int=32,
):
    if (
        type(raw) is not bytes or type(max_bytes) is not int
        or not 0<=len(raw)<=max_bytes<=1_048_576
    ): raise ValueError("invalid configuration")
    text=raw.decode("utf-8",errors="strict"); depth=count=0
    try:
        for event in yaml.parse(text):
            count+=1
            if (
                count>max_events or isinstance(event,AliasEvent)
                or getattr(event,"anchor",None) is not None
            ):
                raise ValueError("invalid configuration")
            if getattr(event,"tag",None) is not None:
                raise ValueError("invalid configuration")
            if isinstance(event,CollectionStartEvent):
                depth+=1
                if depth>max_depth: raise ValueError("invalid configuration")
            elif isinstance(event,CollectionEndEvent): depth-=1
        if depth!=0: raise ValueError("invalid configuration")
        return yaml.load(text,Loader=StrictSettingsLoader)
    except (UnicodeError,yaml.YAMLError) as error:
        raise ValueError("invalid configuration") from error

def read_bounded_strict_yaml(path:Path,*,max_bytes:int=MAX_SETTINGS_BYTES):
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0))
    except OSError as error:
        raise PermissionError("unsafe configuration file") from error
    try:
        before=os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0,os.geteuid()} or before.st_mode&0o022
            or before.st_size>max_bytes
        ): raise PermissionError("unsafe configuration file")
        chunks=[]; total=0
        while True:
            chunk=os.read(fd,min(65_536,max_bytes+1-total))
            if not chunk: break
            total+=len(chunk)
            if total>max_bytes: raise ValueError("invalid configuration")
            chunks.append(chunk)
        after=os.fstat(fd); named=os.lstat(path)
        if (
            total!=before.st_size
            or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
            !=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
            or (after.st_dev,after.st_ino)!=(named.st_dev,named.st_ino)
        ): raise PermissionError("configuration changed during read")
        return parse_bounded_strict_yaml(b"".join(chunks),max_bytes=max_bytes)
    finally: os.close(fd)

def load_settings(yaml_path: Path | None, environ: Mapping[str, str]) -> Settings:
    data: dict[str, object] = {}
    if yaml_path is not None:
        loaded = read_bounded_strict_yaml(yaml_path) or {}
        if not isinstance(loaded, dict): raise ValueError("configuration root must be a mapping")
        data = loaded
    for name, raw_value in environ.items():
        if not name.startswith("TUNTUN_"): continue
        path=name.removeprefix("TUNTUN_").lower().split("__")
        if len(path) != 2: raise ValueError(f"invalid TUNTUN override: {name}")
        encoded=raw_value.encode("utf-8",errors="strict")
        value=parse_bounded_strict_yaml(
            encoded,max_bytes=1_024,max_events=8,max_depth=1,
        )
        if isinstance(value,(dict,list,tuple,set)) or value is None:
            raise ValueError(f"invalid TUNTUN override: {name}")
        section, key=path; nested=dict(data.get(section, {})); nested[key]=value; data[section]=nested
    return Settings.model_validate(data)
```

```python
# apps/core/src/tuntun_core/config/secure_paths.py
from dataclasses import dataclass
import os,stat
from pathlib import Path
from types import TracebackType

OPEN_FLAGS=os.O_RDONLY|os.O_CLOEXEC|os.O_DIRECTORY|os.O_NOFOLLOW

def _absolute_lexical(path:Path) -> Path:
    raw=os.fspath(path)
    if (
        type(raw) is not str or not raw or "\x00" in raw
        or any(component in {".",".."} for component in raw.split(os.sep))
    ): raise PermissionError("unsafe application path")
    absolute=Path(os.path.abspath(raw))
    if absolute==Path("/") or absolute.name in {".",".."}:
        raise PermissionError("unsafe application path")
    return absolute

def _require_directory(
    opened:os.stat_result,named:os.stat_result,*,leaf:bool,
) -> None:
    owner=os.geteuid()
    if (
        not stat.S_ISDIR(opened.st_mode) or not stat.S_ISDIR(named.st_mode)
        or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino)
        or opened.st_uid not in {0,owner}
        or (opened.st_uid==0 and opened.st_mode&0o022)
        or (opened.st_uid==owner and opened.st_mode&0o077)
        or (leaf and (opened.st_uid!=owner or stat.S_IMODE(opened.st_mode)!=0o700))
    ): raise PermissionError("unsafe application path")

@dataclass(slots=True)
class OwnedDirectory:
    path:Path; fd:int; device:int; inode:int; _closed:bool=False
    def revalidate(self) -> None:
        if self._closed: raise PermissionError("unsafe application path")
        held=os.fstat(self.fd)
        with _walk_owned_directory(self.path,create=False) as fresh:
            if (
                (held.st_dev,held.st_ino)!=(self.device,self.inode)
                or (fresh.device,fresh.inode)!=(self.device,self.inode)
            ): raise PermissionError("unsafe application path")
    def close(self) -> None:
        if not self._closed:
            os.close(self.fd); self._closed=True
    def __enter__(self) -> "OwnedDirectory": return self
    def __exit__(
        self,exc_type:type[BaseException]|None,exc:BaseException|None,
        traceback:TracebackType|None,
    ) -> None: self.close()

@dataclass(frozen=True,slots=True)
class OwnedPath:
    path:Path; device:int; inode:int
    def revalidate(self) -> None:
        with open_owned_directory(self.path) as fresh:
            if (fresh.device,fresh.inode)!=(self.device,self.inode):
                raise PermissionError("unsafe application path")

def _walk_owned_directory(path:Path,*,create:bool) -> OwnedDirectory:
    absolute=_absolute_lexical(path); parts=absolute.parts[1:]
    parent_fd=os.open("/",OPEN_FLAGS)
    try:
        root=os.fstat(parent_fd); _require_directory(root,os.lstat("/"),leaf=False)
        for index,part in enumerate(parts):
            leaf=index==len(parts)-1
            try:
                child_fd=os.open(part,OPEN_FLAGS,dir_fd=parent_fd)
            except FileNotFoundError:
                if not create: raise
                os.mkdir(part,0o700,dir_fd=parent_fd)
                child_fd=os.open(part,OPEN_FLAGS,dir_fd=parent_fd)
            try:
                opened=os.fstat(child_fd)
                named=os.stat(part,dir_fd=parent_fd,follow_symlinks=False)
                _require_directory(opened,named,leaf=leaf)
            except BaseException: os.close(child_fd); raise
            os.close(parent_fd); parent_fd=child_fd
        leaf_value=os.fstat(parent_fd)
        result=OwnedDirectory(absolute,parent_fd,leaf_value.st_dev,leaf_value.st_ino)
        parent_fd=-1
        return result
    except OSError as error:
        if isinstance(error,PermissionError): raise
        raise PermissionError("unsafe application path") from error
    finally:
        if parent_fd>=0: os.close(parent_fd)

def open_owned_directory(path:Path) -> OwnedDirectory:
    return _walk_owned_directory(path,create=False)

def ensure_private_directory(path:Path) -> OwnedPath:
    with _walk_owned_directory(path,create=True) as opened:
        result=OwnedPath(opened.path,opened.device,opened.inode)
    result.revalidate()
    return result
```

```python
# apps/core/src/tuntun_core/config/paths.py
from dataclasses import dataclass
from pathlib import Path
from platformdirs import user_data_path
from .secure_paths import OwnedPath,ensure_private_directory

@dataclass(frozen=True, slots=True)
class ApplicationPaths:
    root: Path; data: Path; logs: Path; models: Path; backups: Path
    _identities: tuple[OwnedPath,...]
    @classmethod
    def create(cls, base: Path | None = None) -> "ApplicationPaths":
        root = Path(base or user_data_path("Tuntun", appauthor=False))
        values=(root,root/"data",root/"logs",root/"models",root/"backups")
        identities=tuple(ensure_private_directory(path) for path in values)
        for identity in identities: identity.revalidate()
        return cls(*values,identities)
```

Add `pydantic-settings>=2.10,<3`, `PyYAML>=6.0,<7`, and `platformdirs>=4.4,<5` to core dependencies. Write `config/tuntun.example.yaml` with exactly the locked defaults asserted above, including all three disabled observability switches, and `.env.example` containing only commented variable names, never credential-shaped values.

- [ ] **Step 4: Lock and run the green settings gate**

Run: `uv lock && uv run pytest tests/unit/config/test_settings.py tests/unit/config/test_paths.py -q && uv run ruff check apps/core/src/tuntun_core/config tests/unit/config && uv run mypy apps/core/src/tuntun_core/config`

Expected: PASS with all settings/path tests passing, including ancestor/leaf symlink, special-file, wrong-owner, wrong-mode, parent-replacement, and device/inode replacement failures. The one trusted Darwin pytest-root alias is canonicalized by the fixture only. Every creation/revalidation uses a fresh full no-follow component walk; each live `OwnedDirectory` retains its exact descriptor-qualified `0700` inode until explicit close/context exit, and all FDs close on success and failure. Ruff/mypy exit 0.

- [ ] **Step 5: Commit exact Task 7 paths**

```bash
git status --short
git add apps/core/pyproject.toml uv.lock apps/core/src/tuntun_core/config/settings.py apps/core/src/tuntun_core/config/loader.py apps/core/src/tuntun_core/config/secure_paths.py apps/core/src/tuntun_core/config/paths.py config/tuntun.example.yaml .env.example tests/unit/config/test_settings.py tests/unit/config/test_paths.py tests/unit/config/conftest.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(core): add fail-closed settings and paths"
```

### Task 8: Implement secret providers and recursive log redaction

**Master package:** 03
**Depends on:** Task 7.
**Estimated effort:** 1 person-day.

**Files:**
- Modify: `apps/core/pyproject.toml`
- Modify: `uv.lock`
- Create: `apps/core/src/tuntun_core/adapters/keychain/provider.py`
- Create: `apps/core/src/tuntun_core/adapters/keychain/macos.py`
- Create: `apps/core/src/tuntun_core/config/logging.py`
- Test: `tests/security/test_key_handling.py`
- Test: `tests/security/test_log_redaction.py`

**Interfaces:**
- Consumes: service/account identifiers and byte-valued secrets.
- Produces: `SecretProvider` signature from the locked map; `InMemorySecretProvider`; `MacOSKeychainSecretProvider`; `validate_production_secrets(provider: SecretProvider) -> None`; immutable closed `PRIVATE_KEY_REGISTRY`; `normalize_private_key(key: str) -> str`; and `redact_private_fields(logger: object, method: str, event: MutableMapping[str, object]) -> MutableMapping[str, object]`. The registry covers authorization headers, cookies, API keys/credentials, PINs, recovery codes, audio, transcripts, search queries/results, prompt/messages, memory content, biometric vectors, embeddings, frames/crops, and provider request/response bodies, including the exact singular/plural/structured aliases tested below.

- [ ] **Step 1: Write red secret and logging tests**

```python
# tests/security/test_key_handling.py
import pytest
from tuntun_core.adapters.keychain.provider import InMemorySecretProvider, validate_production_secrets

def test_secret_provider_never_exposes_values_in_repr() -> None:
    provider = InMemorySecretProvider()
    provider.set("tuntun.database", "root-v1", b"db-secret-sentinel")
    assert provider.get("tuntun.database", "root-v1") == b"db-secret-sentinel"
    assert "db-secret-sentinel" not in repr(provider)

def test_missing_production_roots_fail_closed() -> None:
    with pytest.raises(RuntimeError, match="missing required secret"):
        validate_production_secrets(InMemorySecretProvider())
```

```python
# tests/security/test_log_redaction.py
import json
import pytest
from tuntun_core.config.logging import PRIVATE_KEY_REGISTRY, redact_private_fields

EXPECTED_PRIVATE_KEYS={
    "authorization":frozenset({"authorization","authorization_header","authorization_headers"}),
    "cookie":frozenset({"cookie","cookies","set_cookie"}),
    "api_key":frozenset({"api_key","api_keys","provider_api_key","credential","credentials"}),
    "pin":frozenset({"pin","pins","security_pin"}),
    "recovery_code":frozenset({"recovery_code","recovery_codes"}),
    "audio":frozenset({"audio","audio_bytes","audio_chunk","audio_chunks"}),
    "transcript":frozenset({"transcript","transcripts","transcript_text"}),
    "search_query":frozenset({"search_query","search_queries","search_query_body"}),
    "search_result":frozenset({"search_result","search_results","search_result_body","search_excerpts","page_content"}),
    "prompt_message":frozenset({"prompt","prompts","system_prompt","user_prompt","message","messages","provider_messages"}),
    "memory_content":frozenset({"memory","memories","memory_content","memory_body"}),
    "biometric_vector":frozenset({"biometric_vector","biometric_vectors","face_vector","voice_vector"}),
    "embedding":frozenset({"embedding","embeddings","face_embedding","voice_embedding"}),
    "frame":frozenset({"frame","frames","face_frame","face_frames","face_crop","camera_frame"}),
    "provider_body":frozenset({"provider_body","provider_request_body","provider_response_body","request_body","response_body"}),
}


def test_private_key_registry_is_closed_complete_and_aliases_are_unique() -> None:
    assert PRIVATE_KEY_REGISTRY == EXPECTED_PRIVATE_KEYS
    aliases=[alias for values in PRIVATE_KEY_REGISTRY.values() for alias in values]
    assert len(aliases)==len(set(aliases))


@pytest.mark.parametrize(
    "category,key",
    [(category,key) for category,keys in EXPECTED_PRIVATE_KEYS.items() for key in keys],
)
def test_every_private_category_and_structured_alias_removes_literal_and_encoded_sentinel(
    category: str,key: str,
) -> None:
    sentinel=f"private-{category}-sentinel"
    event={"event":"probe","mapping":{"list":[{"tuple":({key:sentinel},)}]},"ok":7}
    redacted=redact_private_fields(None,"error",event)
    encoded=json.dumps(redacted,sort_keys=True)
    assert sentinel not in encoded
    assert json.dumps(sentinel)[1:-1] not in encoded
    assert redacted["mapping"]["list"][0]["tuple"][0][key] == {"redacted":category}
    assert redacted["ok"]==7


@pytest.mark.parametrize("key,category",(
    ("Authorization Header","authorization"),
    ("SEARCH-RESULTS","search_result"),
    ("provider.response.body","provider_body"),
    ("Biometric Vectors","biometric_vector"),
))
def test_key_normalization_cannot_bypass_a_private_category(key: str,category: str) -> None:
    redacted=redact_private_fields(None,"info",{key:"normalized-sentinel"})
    assert redacted[key]=={"redacted":category}
```

- [ ] **Step 2: Run the red secret/log tests**

Run: `uv run pytest tests/security/test_key_handling.py tests/security/test_log_redaction.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.adapters.keychain'`.

- [ ] **Step 3: Implement fail-closed secrets and typed redaction**

```python
# apps/core/src/tuntun_core/adapters/keychain/provider.py
from typing import Protocol

SECRET_IDS = {
    "database":("tuntun.database","root-v1"), "audit":("tuntun.audit","hmac-v1"),
    "backup":("tuntun.backup","slot-v1"), "records":("tuntun.records","root-v1"),
    "openai":("tuntun.provider.openai","api-v1"), "qwen":("tuntun.provider.qwen","api-v1"),
    "edge_ca":("tuntun.edge.ca","signing-v1"), "device_signing":("tuntun.edge.device","signing-v1"),
}
REQUIRED_SECRETS = tuple(SECRET_IDS[name] for name in ("database","audit","backup","records"))

class SecretProvider(Protocol):
    def get(self, service: str, account: str) -> bytes: raise NotImplementedError
    def set(self, service: str, account: str, value: bytes) -> None: raise NotImplementedError
    def delete(self, service: str, account: str) -> None: raise NotImplementedError
    def exists(self, service: str, account: str) -> bool: raise NotImplementedError

class InMemorySecretProvider:
    def __init__(self) -> None: self._values: dict[tuple[str,str], bytes] = {}
    def get(self, service: str, account: str) -> bytes:
        try: return self._values[(service, account)]
        except KeyError as error: raise RuntimeError(f"missing secret: {service}/{account}") from error
    def set(self, service: str, account: str, value: bytes) -> None:
        if not value: raise ValueError("secret value must not be empty")
        self._values[(service, account)] = bytes(value)
    def delete(self, service: str, account: str) -> None: self._values.pop((service, account), None)
    def exists(self, service: str, account: str) -> bool: return (service, account) in self._values
    def __repr__(self) -> str: return f"InMemorySecretProvider(entries={len(self._values)})"

def validate_production_secrets(provider: SecretProvider) -> None:
    for service, account in REQUIRED_SECRETS:
        if not provider.exists(service, account): raise RuntimeError(f"missing required secret: {service}/{account}")
```

```python
# apps/core/src/tuntun_core/adapters/keychain/macos.py
import base64, platform
import keyring
from .provider import SecretProvider

class MacOSKeychainSecretProvider(SecretProvider):
    def __init__(self) -> None:
        backend = keyring.get_keyring()
        if platform.system() != "Darwin" or backend.__class__.__module__ != "keyring.backends.macOS":
            raise RuntimeError("production secret backend must be macOS Keychain")
    def get(self, service: str, account: str) -> bytes:
        encoded = keyring.get_password(service, account)
        if encoded is None: raise RuntimeError(f"missing secret: {service}/{account}")
        return base64.b64decode(encoded, validate=True)
    def set(self, service: str, account: str, value: bytes) -> None: keyring.set_password(service, account, base64.b64encode(value).decode("ascii"))
    def delete(self, service: str, account: str) -> None:
        try: keyring.delete_password(service, account)
        except keyring.errors.PasswordDeleteError: pass
    def exists(self, service: str, account: str) -> bool: return keyring.get_password(service, account) is not None
```

```python
# apps/core/src/tuntun_core/config/logging.py
import re
from collections.abc import Mapping,MutableMapping
from types import MappingProxyType
from typing import Any
from unicodedata import normalize

PRIVATE_KEY_REGISTRY=MappingProxyType({
    "authorization":frozenset({"authorization","authorization_header","authorization_headers"}),
    "cookie":frozenset({"cookie","cookies","set_cookie"}),
    "api_key":frozenset({"api_key","api_keys","provider_api_key","credential","credentials"}),
    "pin":frozenset({"pin","pins","security_pin"}),
    "recovery_code":frozenset({"recovery_code","recovery_codes"}),
    "audio":frozenset({"audio","audio_bytes","audio_chunk","audio_chunks"}),
    "transcript":frozenset({"transcript","transcripts","transcript_text"}),
    "search_query":frozenset({"search_query","search_queries","search_query_body"}),
    "search_result":frozenset({"search_result","search_results","search_result_body","search_excerpts","page_content"}),
    "prompt_message":frozenset({"prompt","prompts","system_prompt","user_prompt","message","messages","provider_messages"}),
    "memory_content":frozenset({"memory","memories","memory_content","memory_body"}),
    "biometric_vector":frozenset({"biometric_vector","biometric_vectors","face_vector","voice_vector"}),
    "embedding":frozenset({"embedding","embeddings","face_embedding","voice_embedding"}),
    "frame":frozenset({"frame","frames","face_frame","face_frames","face_crop","camera_frame"}),
    "provider_body":frozenset({"provider_body","provider_request_body","provider_response_body","request_body","response_body"}),
})
PRIVATE_KEY_TO_CATEGORY=MappingProxyType({
    alias:category for category,aliases in PRIVATE_KEY_REGISTRY.items() for alias in aliases
})
assert len(PRIVATE_KEY_TO_CATEGORY)==sum(map(len,PRIVATE_KEY_REGISTRY.values()))

def normalize_private_key(key:str) -> str:
    if type(key) is not str: raise TypeError("structured log key must be a string")
    return re.sub(r"[^a-z0-9]+","_",normalize("NFKC",key).casefold()).strip("_")

def _redact(value: Any) -> Any:
    if isinstance(value,Mapping):
        result={}
        for key,item in value.items():
            normalized=normalize_private_key(key)
            category=PRIVATE_KEY_TO_CATEGORY.get(normalized)
            result[key]={"redacted":category} if category is not None else _redact(item)
        return result
    if isinstance(value, list): return [_redact(item) for item in value]
    if isinstance(value, tuple): return tuple(_redact(item) for item in value)
    return value
def redact_private_fields(logger: object, method: str, event: MutableMapping[str, object]) -> MutableMapping[str, object]:
    redacted=_redact(event)
    if not isinstance(redacted,MutableMapping): raise TypeError("structured log root invalid")
    return redacted
```

Add `keyring>=25.6,<26` and `structlog>=25.4,<26` to core dependencies.

- [ ] **Step 4: Lock and run the green secret/log gate**

Run: `uv lock && uv run pytest tests/security/test_key_handling.py tests/security/test_log_redaction.py -q && uv run python scripts/verify_private_data.py tests/security && uv run ruff check apps/core/src/tuntun_core/adapters/keychain apps/core/src/tuntun_core/config/logging.py tests/security/test_key_handling.py tests/security/test_log_redaction.py && uv run mypy apps/core/src/tuntun_core/adapters/keychain apps/core/src/tuntun_core/config/logging.py`

Expected: PASS for both key-provider cases, the exact registry closure, every normative category/alias sentinel, all normalized-key bypass cases, and nested mapping/list/tuple recursion; `private-data scan: PASS`; Ruff/mypy exit 0.

- [ ] **Step 5: Commit exact Task 8 paths**

```bash
git status --short
git add apps/core/pyproject.toml uv.lock apps/core/src/tuntun_core/adapters/keychain/provider.py apps/core/src/tuntun_core/adapters/keychain/macos.py apps/core/src/tuntun_core/config/logging.py tests/security/test_key_handling.py tests/security/test_log_redaction.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(core): add Keychain boundary and log redaction"
```

### Task 9: Build deterministic fakes and a network-free scenario runner

**Master package:** 04
**Depends on:** Tasks 6 and 8.
**Estimated effort:** 2 person-days.

**Files:**
- Modify: `packages/testing/pyproject.toml`
- Modify: `uv.lock`
- Create: `packages/testing/src/tuntun_testing/fake_clock.py`
- Create: `packages/testing/src/tuntun_testing/fake_providers.py`
- Create: `packages/testing/src/tuntun_testing/fake_reachy.py`
- Create: `packages/testing/src/tuntun_testing/scenario.py`
- Modify: `packages/testing/src/tuntun_testing/__init__.py`
- Create: `scripts/run_scenarios.py`
- Create: `apps/core/src/tuntun_core/cli/commands/simulate.py`
- Modify: `apps/core/src/tuntun_core/cli/main.py`
- Create: `tests/fixtures/scenarios/guest-hinglish.yaml`
- Test: `tests/unit/testing/test_scenario.py`
- Test: `tests/unit/testing/test_scenario_cli.py`
- Test: `tests/integration/test_deterministic_turn.py`

**Interfaces:**
- Consumes: Task 5 DTOs and ports; synthetic audio tokens are UUIDs, never media.
- Produces: `FakeClock(start: datetime)`, read-only-observation counter `calls: int`, and `advance(delta: timedelta) -> None`; `FakeSpeechToText`, `FakeTextToSpeech`, `FakeLanguageModel`, `FakeIdentity`, `FakeMemory`, `FakePolicy`, `FakeAuthentication`, `FakeAudit`, `FakeBudget`, and `FakeReachy`, each rejecting unexpected calls; `ScenarioRunner.run(path: Path) -> ScenarioResult`; `ScenarioResult.canonical_json() -> bytes`; CLI `tuntunctl simulate --scenario PATH --json`; and the repository gate `scripts/run_scenarios.py [--scenario PATH ...] --turns N [--assert-resource-bounds] [--json]`.
- `run_scenarios.py` accepts `1 <= N <= 10_000`, rejects duplicate/non-regular/symlink scenario paths and over-limit YAML before parsing, sorts either the explicit paths or the default `tests/fixtures/scenarios/*.yaml` set by normalized repository-relative name, installs the test-suite socket/DNS deny guard before loading application code, uses only synthetic fakes, and exits 2 for invalid input or 1 for a failed assertion. Its versioned `scenario_gate.v1` JSON is emitted only to stdout; diagnostics go to stderr. Task C23 extends this same owned executable with the complete fault/privacy/resource measurements used by B2.

- [ ] **Step 1: Write red deterministic tests**

```python
# tests/unit/testing/test_scenario.py
from datetime import UTC, datetime, timedelta
from tuntun_testing.fake_clock import FakeClock
from tuntun_testing.fake_providers import FakeActionProvider, FakeAuthentication, FakeBudget, FakeMemory, FakeMemoryProposalService, FakeRouteAuthorizer

def test_fake_clock_advances_without_sleep() -> None:
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    before = clock.monotonic()
    clock.advance(timedelta(seconds=5))
    assert clock.now() == datetime(2026, 8, 27, 0, 0, 5, tzinfo=UTC)
    assert clock.monotonic() == before + 5

def test_fakes_expose_the_frozen_v1_port_operations() -> None:
    assert all(hasattr(FakeAuthentication([]), name) for name in ("start","verify","consume"))
    assert all(hasattr(FakeMemory([]), name) for name in ("create","replace","delete","query"))
    assert all(hasattr(FakeMemoryProposalService([]), name) for name in ("stage","decide"))
    assert hasattr(FakeActionProvider([]), "execute")
    assert all(hasattr(FakeBudget([]), name) for name in ("reserve","mark_sent","settle","release_unsent","reconcile_turn"))
    assert all(hasattr(FakeRouteAuthorizer([]), name) for name in ("authorize","consume"))
```

```python
# tests/integration/test_deterministic_turn.py
from pathlib import Path
from tuntun_testing.scenario import ScenarioRunner

def test_scenario_is_byte_deterministic() -> None:
    path = Path("tests/fixtures/scenarios/guest-hinglish.yaml")
    first = ScenarioRunner().run(path).canonical_json()
    second = ScenarioRunner().run(path).canonical_json()
    assert first == second
    assert b'"identity":"guest"' in first
    assert b'"transcript":"synthetic-transcript-hi-en"' in first
```

`tests/unit/testing/test_scenario_cli.py` must run the script in a subprocess and prove identical canonical JSON for repeated runs, exact exit codes for zero/10,001 turns, a symlink, duplicate normalized paths, malformed/oversized YAML, and any attempted socket or DNS use. It also proves that `--assert-resource-bounds` is accepted in the foundation synthetic runner without weakening the later B2 thresholds.

- [ ] **Step 2: Run the red fake/scenario tests**

Run: `uv run pytest tests/unit/testing/test_scenario.py tests/unit/testing/test_scenario_cli.py tests/integration/test_deterministic_turn.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_testing.fake_clock'`.

- [ ] **Step 3: Implement deterministic time, fakes, and scenario serialization**

```python
# packages/testing/src/tuntun_testing/fake_clock.py
from datetime import UTC, datetime, timedelta

class FakeClock:
    def __init__(self, start: datetime) -> None:
        if start.tzinfo is None: raise ValueError("start must be timezone-aware")
        self._now = start.astimezone(UTC); self._monotonic = 0.0; self._calls = 0
    @property
    def calls(self) -> int: return self._calls
    def now(self) -> datetime:
        self._calls += 1
        return self._now
    def monotonic(self) -> float: return self._monotonic
    def advance(self, delta: timedelta) -> None:
        seconds = delta.total_seconds()
        if seconds < 0: raise ValueError("fake clock cannot move backwards")
        self._now += delta; self._monotonic += seconds
```

```python
# packages/testing/src/tuntun_testing/fake_providers.py
from collections import deque
from tuntun_contracts.provider import ProviderResponse, SanitizedProviderRequest

class FakeLanguageModel:
    def __init__(self, script: deque[ProviderResponse]) -> None: self.script = script; self.calls: list[SanitizedProviderRequest] = []
    async def complete(self, request: SanitizedProviderRequest) -> ProviderResponse:
        self.calls.append(request)
        if not self.script: raise AssertionError("unexpected language-model call")
        return self.script.popleft()

class FakeSpeechToText:
    def __init__(self, script) -> None: self.script=deque(script); self.calls=[]
    async def transcribe(self, request, audio):
        self.calls.append(request); chunks=[chunk async for chunk in audio]
        if not chunks: raise AssertionError("synthetic audio iterator was empty")
        if not self.script: raise AssertionError("unexpected STT call")
        result=self.script.popleft()
        if isinstance(result, BaseException): raise result
        return result

class FakeTextToSpeech:
    def __init__(self, script) -> None: self.script=deque(script); self.calls=[]
    async def _stream(self, request):
        self.calls.append(request)
        if not self.script: raise AssertionError("unexpected TTS call")
        for item in self.script.popleft():
            if isinstance(item, BaseException): raise item
            yield item
    def synthesize(self, request): return self._stream(request)

class ScriptedAsyncFake:
    def __init__(self, script) -> None: self.script=deque(script); self.calls=[]
    async def call(self, request):
        self.calls.append(request)
        if not self.script: raise AssertionError("unexpected fake call")
        result=self.script.popleft()
        if isinstance(result, BaseException): raise result
        return result

class FakeIdentity(ScriptedAsyncFake):
    async def resolve(self, request): return await self.call(request)
class FakeMemory(ScriptedAsyncFake):
    async def create(self, memory, expected_absent=True): return await self.call(("create",memory,expected_absent))
    async def replace(self, memory_id, expected_version, memory): return await self.call(("replace",memory_id,expected_version,memory))
    async def delete(self, memory_id, expected_version, auth, approved_proposal_id): return await self.call(("delete",memory_id,expected_version,auth,approved_proposal_id))
    async def query(self, request): return await self.call(("query",request))
class FakeMemoryProposalService(ScriptedAsyncFake):
    async def stage(self, draft, context): return await self.call(("stage",draft,context))
    async def decide(self, command, auth): return await self.call(("decide",command,auth))
class FakePolicy(ScriptedAsyncFake):
    async def decide(self, request): return await self.call(request)
class FakeAuthentication(ScriptedAsyncFake):
    async def start(self, request): return await self.call(("start",request))
    async def verify(self, response): return await self.call(("verify",response))
    async def consume(self, grant_id, binding): return await self.call(("consume",grant_id,binding))
class FakeActionProvider(ScriptedAsyncFake):
    async def execute(self, proposal, auth): return await self.call(("execute",proposal,auth))
class FakeAudit(ScriptedAsyncFake):
    async def append(self, uow, draft): return await self.call((uow,draft))
class FakeBudget(ScriptedAsyncFake):
    async def reserve(self, request): return await self.call(("reserve",request))
    async def mark_sent(self, reservation_id, attempt_id): return await self.call(("mark_sent",reservation_id,attempt_id))
    async def settle(self, request): return await self.call(("settle",request))
    async def release_unsent(self, reservation_id, attempt_id, proof): return await self.call(("release_unsent",reservation_id,attempt_id,proof))
    async def reconcile_turn(self, request): return await self.call(("reconcile_turn",request))
class FakeRouteAuthorizer(ScriptedAsyncFake):
    async def authorize(self, request): return await self.call(("authorize",request))
    async def consume(self, authorization_id, consumption): return await self.call(("consume",authorization_id,consumption))
```

```python
# packages/testing/src/tuntun_testing/fake_reachy.py
from tuntun_contracts.reachy import ReachyCommand, ReachyHealth, ReachyReceipt, ReachyState, SafetyReceipt

class FakeReachy:
    def __init__(self) -> None: self.commands: list[ReachyCommand] = []
    async def send(self, command: ReachyCommand) -> ReachyReceipt:
        self.commands.append(command); return ReachyReceipt(command_id=command.command_id, accepted=True, reason_code="fake.accepted")
    async def health(self) -> ReachyHealth: return ReachyHealth(state=ReachyState.IDLE, daemon_connected=True, queue_depth=0)
    async def stop_all(self, turn_id): return SafetyReceipt(turn_id=turn_id, playback_stopped=True, motion_stopped=True, buffers_cleared=True)
```

```python
# packages/testing/src/tuntun_testing/scenario.py
import json
from dataclasses import dataclass
from pathlib import Path
import yaml

@dataclass(frozen=True, slots=True)
class ScenarioResult:
    events: tuple[str, ...]; identity: str; transcript: str; response: str; audit_outcome: str
    def canonical_json(self) -> bytes:
        return json.dumps({"audit_outcome":self.audit_outcome,"events":self.events,"identity":self.identity,"response":self.response,"transcript":self.transcript}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

class ScenarioRunner:
    def run(self, path: Path) -> ScenarioResult:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        expected = {"schema_version","audio_token","transcript","identity","response","audit_outcome"}
        if set(raw) != expected: raise ValueError("scenario keys do not match version 1")
        return ScenarioResult(("wake","audio","transcript","identity","model","playback","audit"), raw["identity"], raw["transcript"], raw["response"], raw["audit_outcome"])
```

```python
# apps/core/src/tuntun_core/cli/commands/simulate.py
import json
from pathlib import Path
from typing import Annotated
import typer
from tuntun_testing.scenario import ScenarioRunner

def simulate(scenario: Annotated[Path, typer.Option(exists=True, dir_okay=False)], json_output: bool = typer.Option(False, "--json")) -> None:
    result=ScenarioRunner().run(scenario)
    if json_output: typer.echo(result.canonical_json().decode("utf-8"))
    else: typer.echo(f"scenario: {result.audit_outcome}")
```

Import `simulate` in `cli/main.py` and register it with `app.command("simulate")(simulate)`.

```yaml
# tests/fixtures/scenarios/guest-hinglish.yaml
schema_version: "1.0"
audio_token: "00000000-0000-0000-0000-000000000401"
transcript: synthetic-transcript-hi-en
identity: guest
response: synthetic-response-hi-en
audit_outcome: completed
```

Add `PyYAML>=6.0,<7` to `packages/testing/pyproject.toml` and export every public fake/scenario class shown above from `tuntun_testing/__init__.py`.

Implement `scripts/run_scenarios.py` as a thin, import-safe dispatcher over `ScenarioRunner`: bounded reads occur before YAML parsing, the network-deny guard is active before scenario/application imports, every requested turn receives a fresh scripted-fake container, and the process fails closed if a fake has an unconsumed expectation or an unexpected call. The foundation resource assertion is limited to universally available invariants (zero leaked asyncio tasks and zero leaked file descriptors after a warm-up plus collection); C23 owns the production B2 RSS, privacy-latency, sentinel, and duplicate-effect assertions.

- [ ] **Step 4: Run the green deterministic gate**

Run: `uv lock && uv run pytest tests/unit/testing/test_scenario.py tests/unit/testing/test_scenario_cli.py tests/integration/test_deterministic_turn.py -q && uv run tuntunctl simulate --scenario tests/fixtures/scenarios/guest-hinglish.yaml --json > /tmp/tuntun-scenario-a.json && uv run tuntunctl simulate --scenario tests/fixtures/scenarios/guest-hinglish.yaml --json > /tmp/tuntun-scenario-b.json && cmp /tmp/tuntun-scenario-a.json /tmp/tuntun-scenario-b.json && uv run python scripts/run_scenarios.py --scenario tests/fixtures/scenarios/guest-hinglish.yaml --turns 2 --assert-resource-bounds --json && uv run python scripts/verify_private_data.py tests/fixtures/scenarios`

Expected: PASS with all deterministic/CLI tests, a `scenario_gate.v1` success document, and `private-data scan: PASS`.

- [ ] **Step 5: Commit exact Task 9 paths**

```bash
git status --short
git add packages/testing/pyproject.toml packages/testing/src/tuntun_testing/fake_clock.py packages/testing/src/tuntun_testing/fake_providers.py packages/testing/src/tuntun_testing/fake_reachy.py packages/testing/src/tuntun_testing/scenario.py packages/testing/src/tuntun_testing/__init__.py scripts/run_scenarios.py apps/core/src/tuntun_core/cli/commands/simulate.py apps/core/src/tuntun_core/cli/main.py tests/fixtures/scenarios/guest-hinglish.yaml tests/unit/testing/test_scenario.py tests/unit/testing/test_scenario_cli.py tests/integration/test_deterministic_turn.py uv.lock
git diff --cached --name-only
git diff --cached
git commit -m "test: add deterministic foundation scenario"
```

### Task 10: Implement the governed model registry and CLI

**Master package:** 04
**Depends on:** Tasks 7 and 9.
**Estimated effort:** 2 person-days.

**Files:**
- Modify: `apps/core/pyproject.toml`
- Modify: `uv.lock`
- Create: `apps/core/src/tuntun_core/services/models/fs.py`
- Create: `apps/core/src/tuntun_core/services/models/network.py`
- Create: `apps/core/src/tuntun_core/services/models/registry.py`
- Create: `apps/core/src/tuntun_core/services/models/installer.py`
- Create: `apps/core/src/tuntun_core/cli/commands/models.py`
- Modify: `apps/core/src/tuntun_core/cli/main.py`
- Create: `models/manifest.schema.json`
- Create: `models/manifest.yaml`
- Create: `scripts/check_model_manifest.py`
- Test: `tests/security/test_model_governance.py`
- Modify: `tests/security/conftest.py`
- Create: `tests/security/model_governance_cases.py`

**Interfaces:**
- Consumes: owner-invoked immutable HTTPS URL on an exact host allowlist, declared bounded byte size/SHA-256, a bounded duplicate-free manifest, and owner-only no-follow model directory descriptors.
- Produces: `ModelRegistry.load(manifest: Path) -> ModelRegistry`; `activate(model_id: str) -> ActivatedModel` containing only a verified exact nonempty tuple of stable read-only file descriptors; immutable private `_ManifestBoundFile(path, size, sha256, device, inode)` expectations; frozen `VerifiedModelFile`/`ActivatedModel`; derived read-only property `ActivatedModel.all_files_verified: bool`; `ActivatedModel.load_with(adapter, receipt_verifier) -> RuntimeModelReceipt`; and `ModelInstaller.install(model_id: str) -> ActivatedModel`. Public `fd`, `size`, `sha256`, and `files` are getter-only views. `all_files_verified` and runtime receipt comparison use the sealed private manifest tuple and recheck descriptor access/type/mode/device/inode/size/hash; they never derive trust from a caller-replaceable public field. No download occurs in a constructor, registry load, activation, verification, list, or service startup. Runtime adapters consume only a bounded `PreadOnlyModelReader` over a duplicate of each verified `O_RDONLY` descriptor, never receive write/path authority, and never reopen registry paths or depend on a shared descriptor offset.

- [ ] **Step 1: Write red model-governance tests**

```python
# tests/security/test_model_governance.py
import fcntl
import inspect
import os
import stat
from dataclasses import FrozenInstanceError
from pathlib import Path
import pytest
from tuntun_core.services.models.installer import ModelInstaller
from tuntun_core.services.models.fs import hash_exact_fd
from tuntun_core.services.models.registry import ModelRegistry, ModelVerificationError

def test_floating_revision_and_pickle_are_rejected(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text('schema_version: "1.0"\nmodels:\n- id: bad\n  revision: main\n  files:\n  - path: model.pkl\n    size: 1\n    sha256: "' + "0" * 64 + '"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="invalid model manifest"):
        ModelRegistry.load(manifest)

def test_empty_registry_never_downloads(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.yaml"; manifest.write_text('schema_version: "1.0"\nmodels: []\n', encoding="utf-8")
    registry = ModelRegistry.load(manifest)
    with pytest.raises(LookupError, match="model is not registered"): registry.activate("missing")


@pytest.mark.parametrize("mutation",(
    "duplicate_yaml_key","yaml_alias","manifest_too_large","duplicate_model_id",
    "duplicate_file_name","unknown_top_level","unknown_model_field",
    "unknown_file_field","bad_model_id","floating_revision","uppercase_hash",
    "zero_size","file_too_large","total_too_large","nested_path","dot_path",
    "pickle_suffix","http_url","url_credentials","url_port","url_query",
    "too_many_models","too_many_files","bool_size","string_size",
    "list_model_id","mapping_revision","null_url",
))
def test_manifest_runtime_checks_reject_even_without_json_schema(
    governed_model_case,mutation,
) -> None:
    governed_model_case.mutate_manifest(mutation)
    with pytest.raises(ValueError,match="invalid model manifest"):
        ModelRegistry.load(governed_model_case.manifest)


@pytest.mark.parametrize("mutation",(
    "manifest_symlink","model_root_symlink","model_id_symlink",
    "revision_symlink","artifact_symlink","artifact_fifo","artifact_device",
    "wrong_owner","group_writable_root","world_writable_revision",
))
def test_every_named_filesystem_object_is_nofollow_regular_owner_only(
    governed_model_case,mutation,
) -> None:
    governed_model_case.apply_filesystem_mutation(mutation)
    with pytest.raises((PermissionError,RuntimeError),match="unsafe model filesystem"):
        governed_model_case.registry_or_activate()


def test_activation_and_runtime_use_the_same_descriptor_not_a_reopened_path(
    installed_model,runtime_adapter,runtime_receipt_verifier,
) -> None:
    activated=installed_model.registry.activate(installed_model.model_id)
    installed_model.replace_every_named_path_with_attacker_bytes()
    receipt=activated.load_with(runtime_adapter,runtime_receipt_verifier)
    assert receipt.loaded_sha256==installed_model.expected_sha256
    assert runtime_adapter.path_opens==[]


@pytest.mark.parametrize("mutation",(
    "wrong_model","wrong_revision","missing_file","extra_file","reordered_file",
    "wrong_size","wrong_hash","wrong_signature_domain","wrong_key_generation",
    "bad_signature","expired_receipt",
))
def test_runtime_loader_receipt_is_authenticated_and_exact_bound(
    installed_model,runtime_adapter,runtime_receipt_verifier,mutation,
) -> None:
    runtime_adapter.mutate_receipt(mutation)
    activated=installed_model.registry.activate(installed_model.model_id)
    with pytest.raises(ModelVerificationError,match="runtime model receipt mismatch"):
        activated.load_with(runtime_adapter,runtime_receipt_verifier)
    assert runtime_adapter.open_duplicate_fd_count==0
    assert runtime_adapter.abort_calls==1


def test_zero_write_fails_without_publishing(governed_model_case) -> None:
    governed_model_case.inject_os_write_result(0)
    with pytest.raises(OSError): governed_model_case.install()
    assert governed_model_case.open_descriptor_count==0
    assert not governed_model_case.final_revision_exists()


def test_repeated_one_byte_short_writes_eventually_publish_exact_bytes(
    governed_model_case,
) -> None:
    governed_model_case.inject_repeated_os_write_result(1)
    result=governed_model_case.install()
    assert result.all_files_verified
    assert governed_model_case.final_revision_is_complete_and_verified()


def test_installer_retains_only_same_inode_read_only_verified_descriptor(
    governed_model_case,runtime_adapter,runtime_receipt_verifier,
) -> None:
    activated=governed_model_case.install()
    handle=activated.files[0]
    assert governed_model_case.reader_open_expected_modes==[0o600]
    assert fcntl.fcntl(handle.fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY
    assert stat.S_IMODE(os.fstat(handle.fd).st_mode)==0o400
    assert governed_model_case.returned_descriptor_identity(handle.fd)==governed_model_case.written_inode_identity
    governed_model_case.rehash_exact_descriptor(handle.fd)
    with pytest.raises(OSError): os.write(handle.fd,b"mutation")
    receipt=activated.load_with(runtime_adapter,runtime_receipt_verifier)
    assert receipt.loaded_sha256==governed_model_case.expected_sha256
    source=inspect.getsource(ModelInstaller._download)
    assert "return read_fd" in source
    assert "return write_fd" not in source and "return fd" not in source
    assert runtime_adapter.path_opens==[]


def test_activated_manifest_expectations_and_file_tuple_cannot_be_rebased(
    installed_model,tmp_path:Path,
) -> None:
    activated=installed_model.registry.activate(installed_model.model_id)
    handle=activated.files[0]
    attacker=tmp_path/"attacker.onnx"; attacker.write_bytes(b"attacker-bytes"); attacker.chmod(0o400)
    attacker_fd=os.open(attacker,os.O_RDONLY)
    try:
        for attribute,value in (
            ("fd",attacker_fd),("size",os.fstat(attacker_fd).st_size),("sha256","0"*64),
        ):
            with pytest.raises((FrozenInstanceError,AttributeError)):
                setattr(handle,attribute,value)
        with pytest.raises((FrozenInstanceError,AttributeError)):
            activated.files=(handle,)
        assert activated.all_files_verified is True
    finally: os.close(attacker_fd)


@pytest.mark.parametrize("prior_offset",(0,1,"eof"))
def test_rehash_and_repeated_runtime_reads_ignore_shared_descriptor_offset(
    installed_model,runtime_adapter,prior_offset,
) -> None:
    handle=installed_model.registry.activate(installed_model.model_id).files[0]
    offset=handle.size if prior_offset=="eof" else prior_offset
    os.lseek(handle.fd,offset,os.SEEK_SET)
    for _ in range(2):
        hash_exact_fd(handle.fd,handle.size,handle.sha256)
        assert os.lseek(handle.fd,0,os.SEEK_CUR)==offset
        handle.load_with(runtime_adapter)
        assert runtime_adapter.last_loaded_bytes==installed_model.expected_bytes
        assert os.lseek(handle.fd,0,os.SEEK_CUR)==offset


def test_adapter_failure_closes_every_duplicated_runtime_handle(
    installed_model,failing_runtime_adapter,runtime_receipt_verifier,
) -> None:
    activated=installed_model.registry.activate(installed_model.model_id)
    with pytest.raises(RuntimeError):
        activated.load_with(failing_runtime_adapter,runtime_receipt_verifier)
    assert failing_runtime_adapter.open_duplicate_fd_count==0
    assert failing_runtime_adapter.abort_calls==1


@pytest.mark.parametrize("failure",("finish_model","receipt_verifier"))
def test_unverified_runtime_is_aborted_and_never_published(
    installed_model,runtime_adapter,runtime_receipt_verifier,failure,
) -> None:
    runtime_adapter.fail_at(failure,runtime_receipt_verifier)
    activated=installed_model.registry.activate(installed_model.model_id)
    with pytest.raises((RuntimeError,ModelVerificationError)):
        activated.load_with(runtime_adapter,runtime_receipt_verifier)
    assert runtime_adapter.abort_calls==1
    assert runtime_adapter.published_runtime_count==0
    assert runtime_adapter.open_duplicate_fd_count==0


@pytest.mark.parametrize("race",(
    "swap_root_before_open","swap_revision_during_open","swap_file_during_open",
    "grow_file_during_hash","truncate_file_during_hash","overwrite_same_size_during_load",
))
def test_activation_races_fail_or_load_only_bytes_matching_manifest(
    governed_model_case,runtime_adapter,race,
) -> None:
    result=governed_model_case.race_activation(race,runtime_adapter)
    assert result.failed_closed or result.loaded_sha256==governed_model_case.expected_sha256


@pytest.mark.parametrize("network_fault",(
    "redirect_to_127_0_0_1","redirect_to_rfc1918","redirect_to_other_https_host",
    "allowlisted_dns_private_answer","content_length_too_large","stream_plus_one_byte",
    "stream_truncated","timeout_after_first_file","hash_mismatch",
    "slow_drip_past_total_deadline","resolver_hang_past_total_deadline",
))
def test_install_rejects_redirect_lan_oversize_and_partial_downloads(
    governed_model_case,network_fault,
) -> None:
    governed_model_case.network.inject(network_fault)
    with pytest.raises((PermissionError,ValueError,TimeoutError)):
        governed_model_case.install()
    assert not governed_model_case.final_revision_exists()
    assert governed_model_case.previous_revision_unchanged()
    assert governed_model_case.network.followed_redirects==[]


def test_two_installers_publish_one_complete_immutable_revision(concurrent_model_case) -> None:
    results=concurrent_model_case.run_two_installers()
    assert concurrent_model_case.maximum_simultaneous_lock_holders==1
    assert concurrent_model_case.published_revision_count==1
    assert all(result.all_files_verified for result in results)
    assert concurrent_model_case.no_stage_directory_remains()


@pytest.mark.parametrize("fault",(
    "after_each_file","before_stage_fsync","after_stage_fsync",
    "before_publish","after_publish_before_parent_fsync",
))
def test_crash_or_error_never_exposes_a_mixed_revision(governed_model_case,fault) -> None:
    governed_model_case.crash_install_at(fault)
    governed_model_case.restart_and_reconcile()
    assert governed_model_case.final_revision_is_absent_or_complete_and_verified()
    assert governed_model_case.previous_revision_unchanged()
```

Register every named model/runtime fixture in the existing security-scope conftest. The fixture functions are exact and executable:

```python
# append to tests/security/conftest.py
from tests.security.model_governance_cases import (
    GovernedModelCase,
    ScriptedReceiptVerifier,
    ScriptedRuntimeAdapter,
)


@pytest.fixture
def governed_model_case(tmp_path, monkeypatch):
    return GovernedModelCase.create(tmp_path / "governed-model", monkeypatch)


@pytest.fixture
def installed_model(governed_model_case):
    governed_model_case.install()
    return governed_model_case.as_installed_model()


@pytest.fixture
def runtime_adapter():
    return ScriptedRuntimeAdapter()


@pytest.fixture
def failing_runtime_adapter():
    adapter = ScriptedRuntimeAdapter()
    adapter.fail_at("load_verified_reader", None)
    return adapter


@pytest.fixture
def runtime_receipt_verifier():
    return ScriptedReceiptVerifier.current(
        domain="tuntun.runtime-model-loader-receipt.v1",
        key_generation=1,
    )


@pytest.fixture
def concurrent_model_case(governed_model_case):
    return governed_model_case.concurrent_view()
```

`tests/security/model_governance_cases.py` owns the concrete local-only factory used above. `GovernedModelCase.create` writes one valid single-file manifest and a prior immutable revision, binds a scripted byte transport/DNS resolver to the production seams, and records descriptor identities/counts without opening a network socket. Its public surface is exactly the attributes/methods referenced by `test_model_governance.py`: `manifest`, `model_id`, `expected_bytes`, `expected_sha256`, `network.inject()/followed_redirects`, `mutate_manifest`, `apply_filesystem_mutation`, `registry_or_activate`, `inject_os_write_result`, `inject_repeated_os_write_result`, `install`, `as_installed_model`, `concurrent_view`, `race_activation`, `crash_install_at`, `restart_and_reconcile`, `rehash_exact_descriptor`, and every asserted state/identity/count query. Each mutation/race/fault string in the test has one explicit dispatch-table entry; unknown names raise `AssertionError`. Filesystem mutations use real symlinks/FIFOs/modes/inode replacements, write faults monkeypatch only `os.write`, and network faults drive the injected transport/child-resolver seam. State queries inspect the real staged/final filesystem and live descriptors rather than booleans set by the case.

`InstalledModel` exposes only `registry`, `model_id`, `expected_bytes`, `expected_sha256`, and `replace_every_named_path_with_attacker_bytes()`. `ScriptedRuntimeAdapter.load_verified_reader` consumes the bounded reader to EOF, records bytes and open duplicate count, returns an exact per-file receipt, and never accepts a path; `finish_model` returns an unpublished signed candidate; the verifier publishes only after checking the exact domain/generation/expiry/model/revision/ordered file tuple. `mutate_receipt`, `fail_at`, and `abort_model` are closed dispatch methods for the test strings and maintain the asserted `path_opens`, `open_duplicate_fd_count`, `abort_calls`, `published_runtime_count`, and `last_loaded_bytes`. The concurrent view uses two real `ModelInstaller` instances plus a barrier only before lock acquisition, measures lock ownership around the production lock, and derives publication/stage results from disk. This helper contains no pass-through fake of `ModelRegistry`, `ModelInstaller`, descriptor hashing, publication, or receipt comparison.

- [ ] **Step 2: Run the red model tests**

Run: `uv run pytest tests/security/test_model_governance.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.services.models'`.

- [ ] **Step 3: Implement schema validation, activation, and explicit installation**

```python
# apps/core/src/tuntun_core/services/models/fs.py
import ctypes,fcntl,hashlib,os,stat,sys,time
from pathlib import Path
import yaml
from yaml.events import AliasEvent,CollectionEndEvent,CollectionStartEvent
from yaml.nodes import MappingNode

MAX_MANIFEST_BYTES=1_048_576
MAX_MANIFEST_EVENTS=16_384
MAX_MANIFEST_DEPTH=32

def _regular_owner(st,*,mode_mask=0o022):
    return stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and not st.st_mode&mode_mask

class StrictSafeLoader(yaml.SafeLoader):
    def construct_mapping(self,node,deep=False):
        if not isinstance(node,MappingNode):
            raise ValueError("invalid model manifest")
        result={}
        for key_node,value_node in node.value:
            key=self.construct_object(key_node,deep=deep)
            if not isinstance(key,str) or key in result:
                raise ValueError("invalid model manifest")
            result[key]=self.construct_object(value_node,deep=deep)
        return result

def parse_yaml_no_duplicates_aliases_tags(data,*,max_events,max_depth):
    depth=count=0
    for event in yaml.parse(data):
        count+=1
        if count>max_events or isinstance(event,AliasEvent):
            raise ValueError("invalid model manifest")
        if getattr(event,"tag",None) is not None:
            raise ValueError("invalid model manifest")
        if isinstance(event,CollectionStartEvent):
            depth+=1
            if depth>max_depth: raise ValueError("invalid model manifest")
        elif isinstance(event,CollectionEndEvent): depth-=1
    if depth!=0: raise ValueError("invalid model manifest")
    return yaml.load(data,Loader=StrictSafeLoader)

def read_bounded_strict_yaml(path:Path):
    """One no-follow descriptor, no aliases/tags, duplicate keys, or path swap."""
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        if not _regular_owner(before) or before.st_size>MAX_MANIFEST_BYTES:
            raise ValueError("invalid model manifest")
        chunks=[]; total=0
        while True:
            chunk=os.read(fd,min(65_536,MAX_MANIFEST_BYTES+1-total))
            if not chunk: break
            chunks.append(chunk); total+=len(chunk)
            if total>MAX_MANIFEST_BYTES: raise ValueError("invalid model manifest")
        after=os.fstat(fd); named=os.lstat(path)
        if (before.st_dev,before.st_ino,before.st_size)!=(after.st_dev,after.st_ino,after.st_size) or (after.st_dev,after.st_ino)!=(named.st_dev,named.st_ino):
            raise ValueError("invalid model manifest")
        return parse_yaml_no_duplicates_aliases_tags(
            b"".join(chunks),max_events=MAX_MANIFEST_EVENTS,
            max_depth=MAX_MANIFEST_DEPTH,
        )
    except (OSError,UnicodeError) as error:
        raise ValueError("invalid model manifest") from error
    finally: os.close(fd)

class OwnedDirectory:
    """Stable O_DIRECTORY|O_NOFOLLOW dirfd with exact final owner/mode."""
    def __init__(self,fd,mode):
        self.fd=fd; st=os.fstat(fd); self.identity=(st.st_dev,st.st_ino)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=mode:
            os.close(fd); raise PermissionError("unsafe model filesystem")
    @staticmethod
    def _parent(path):
        absolute=path.absolute(); parts=absolute.parts
        fd=os.open(parts[0],os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        for part in parts[1:-1]:
            next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=fd)
            st=os.fstat(next_fd)
            if not stat.S_ISDIR(st.st_mode) or st.st_mode&0o022 or st.st_uid not in {0,os.geteuid()}:
                os.close(next_fd); os.close(fd); raise PermissionError("unsafe model filesystem")
            os.close(fd); fd=next_fd
        return fd,parts[-1]
    @classmethod
    def open(cls,path:Path,mode=0o700):
        parent,name=cls._parent(path)
        try: fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=parent)
        finally: os.close(parent)
        return cls(fd,mode)
    @classmethod
    def open_or_create(cls,path:Path,mode=0o700):
        parent,name=cls._parent(path)
        try:
            try: os.mkdir(name,mode,dir_fd=parent)
            except FileExistsError: pass
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=parent)
        finally: os.close(parent)
        return cls(fd,mode)
    def child(self,name,*,create=False,exist_ok=False,mode=0o700):
        if not name or name in {".",".."} or "/" in name or "\x00" in name:
            raise PermissionError("unsafe model filesystem")
        if create:
            try: os.mkdir(name,mode,dir_fd=self.fd)
            except FileExistsError:
                if not exist_ok: raise PermissionError("unsafe model filesystem")
        fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=self.fd)
        return OwnedDirectory(fd,mode)
    def has_child(self,name):
        try: st=os.stat(name,dir_fd=self.fd,follow_symlinks=False)
        except FileNotFoundError: return False
        if not stat.S_ISDIR(st.st_mode): raise PermissionError("unsafe model filesystem")
        return True
    def fsync(self): os.fsync(self.fd)
    def chmod(self,mode): os.fchmod(self.fd,mode)
    def close(self): os.close(self.fd)
    def remove_private_stage(self,name,identity):
        remove_exact_private_tree_at(self.fd,name,identity)
    def remove_private_stages(self,prefix):
        for name in os.listdir(self.fd):
            if not name.startswith(prefix): continue
            st=os.stat(name,dir_fd=self.fd,follow_symlinks=False)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid():
                raise PermissionError("unsafe model filesystem")
            remove_exact_private_tree_at(
                self.fd,name,(st.st_dev,st.st_ino),
            )
    def lock(self,name,timeout_seconds):
        return nofollow_flock(self.fd,name,timeout_seconds,mode=0o600)

class _HeldLock:
    def __init__(self,fd): self.fd=fd
    def __enter__(self): return self
    def __exit__(self,*_):
        fcntl.flock(self.fd,fcntl.LOCK_UN); os.close(self.fd)

def nofollow_flock(directory_fd,name,timeout_seconds,mode):
    fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_CLOEXEC|os.O_NOFOLLOW,mode,dir_fd=directory_fd)
    try:
        st=os.fstat(fd)
        if not _regular_owner(st,mode_mask=0o077) or stat.S_IMODE(st.st_mode)!=mode or st.st_nlink!=1:
            raise PermissionError("unsafe model filesystem")
        deadline=time.monotonic()+timeout_seconds
        while True:
            try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB); break
            except BlockingIOError:
                if time.monotonic()>=deadline: raise TimeoutError("model install lock timeout")
                time.sleep(0.05)
        owner=f"pid={os.getpid()} start={time.monotonic_ns()}\n".encode()
        os.ftruncate(fd,0); os.write(fd,owner); os.fsync(fd)
        return _HeldLock(fd)
    except Exception: os.close(fd); raise

def remove_exact_private_tree_at(parent_fd,name,identity):
    fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=parent_fd)
    try:
        st=os.fstat(fd)
        if (st.st_dev,st.st_ino)!=identity or st.st_uid!=os.geteuid():
            raise PermissionError("unsafe model filesystem")
        os.fchmod(fd,0o700)
        for child in os.listdir(fd):
            child_st=os.stat(child,dir_fd=fd,follow_symlinks=False)
            if stat.S_ISDIR(child_st.st_mode):
                remove_exact_private_tree_at(fd,child,(child_st.st_dev,child_st.st_ino))
            elif stat.S_ISREG(child_st.st_mode) and child_st.st_uid==os.geteuid() and child_st.st_nlink==1:
                os.unlink(child,dir_fd=fd)
            else: raise PermissionError("unsafe model filesystem")
    finally: os.close(fd)
    os.rmdir(name,dir_fd=parent_fd)

def open_regular_at(directory:OwnedDirectory,name:str,flags:int,mode:int=0o400):
    fd=os.open(name,flags|os.O_CLOEXEC|os.O_NOFOLLOW,mode,dir_fd=directory.fd)
    st=os.fstat(fd)
    if not _regular_owner(st,mode_mask=0o077) or stat.S_IMODE(st.st_mode)!=mode or st.st_nlink!=1:
        os.close(fd); raise PermissionError("unsafe model filesystem")
    return fd

def atomic_publish_dir_noreplace(parent:OwnedDirectory,source:str,destination:str):
    # Platform adapter uses renameat2(RENAME_NOREPLACE) on Linux or
    # renameatx_np(RENAME_EXCL) on macOS. ENOTSUP is fail-closed; there is no
    # existence-check + rename fallback.
    libc=ctypes.CDLL(None,use_errno=True)
    if sys.platform=="darwin":
        result=libc.renameatx_np(parent.fd,source.encode(),parent.fd,destination.encode(),0x00000004)
    elif sys.platform.startswith("linux") and hasattr(libc,"renameat2"):
        result=libc.renameat2(parent.fd,source.encode(),parent.fd,destination.encode(),0x1)
    else: raise OSError("exclusive directory publication unsupported")
    if result!=0:
        error=ctypes.get_errno(); raise OSError(error,os.strerror(error))

def hash_exact_fd(fd:int,expected_size:int,expected_sha256:str):
    digest=hashlib.sha256(); total=0
    while chunk:=os.pread(
        fd,min(1_048_576,expected_size+1-total),total,
    ):
        total+=len(chunk)
        if total>expected_size: raise RuntimeError("model size mismatch")
        digest.update(chunk)
    if total!=expected_size or digest.hexdigest()!=expected_sha256:
        raise RuntimeError("model hash mismatch")
    return total,digest.hexdigest()
```

`parse_yaml_no_duplicates_aliases_tags` first walks the bounded PyYAML event iterator, rejecting every alias, explicit/non-core tag, depth above 32, or event 16,385 before construction; its mapping constructor rejects a repeated scalar key before assignment. `open_componentwise_owned_dir`, `mkdir_and_open_componentwise`, and `open_owned_child_dir` use only no-follow descriptor-relative operations, compare pre/open identities, require the effective owner and exact leaf mode, and reject symlinks, non-directories, hard-linked artifact files, or replaced components. `nofollow_flock` creates/opens the lock with `O_NOFOLLOW|O_CREAT`, validates its descriptor before `flock`, records PID/start identity, uses a bounded timeout, and fails closed. Cleanup recursively enumerates only the exact private stage descriptor and verifies its recorded `(dev,ino)` before unlinking. Every helper has direct race/fault tests; no helper resolves or later reopens a security-qualified pathname.

```python
# apps/core/src/tuntun_core/services/models/registry.py
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
import fcntl,os,re,stat
from .fs import OwnedDirectory,hash_exact_fd,open_regular_at,read_bounded_strict_yaml

SAFE_SUFFIXES={".onnx",".json",".txt",".tflite",".safetensors"}
MODEL_ID=re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
REVISION=re.compile(r"^[0-9a-f]{40,64}$")
DIGEST=re.compile(r"^[0-9a-f]{64}$")
MAX_MODEL_FILE_BYTES=4_000_000_000
MAX_MODEL_REVISION_BYTES=8_000_000_000
MAX_MODEL_FILES=64

class ModelVerificationError(PermissionError): pass

@dataclass(frozen=True,slots=True)
class ModelFile:
    path:str; size:int; sha256:str; url:str
    def __post_init__(self):
        if not isinstance(self.path,str) or type(self.size) is not int or not isinstance(self.sha256,str) or not isinstance(self.url,str):
            raise ValueError("invalid model manifest")
        parsed=urlsplit(self.url)
        if (
            Path(self.path).name!=self.path or self.path in {".",".."}
            or Path(self.path).suffix not in SAFE_SUFFIXES
            or not 1<=self.size<=MAX_MODEL_FILE_BYTES
            or DIGEST.fullmatch(self.sha256) is None
            or parsed.scheme!="https" or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.port not in {None,443} or parsed.query or parsed.fragment
            or not parsed.path.startswith("/")
        ): raise ValueError("invalid model manifest")

@dataclass(frozen=True,slots=True)
class ModelEntry:
    model_id:str; revision:str; license:str; provenance:str; redistribution:str
    approved_purpose:str; runtime:str; architecture:str; input_contract:str
    output_contract:str; benchmark_gate:str; review_date:str
    files:tuple[ModelFile,...]
    def __post_init__(self):
        scalar_values=(
            self.model_id,self.revision,self.license,self.provenance,
            self.redistribution,self.approved_purpose,self.runtime,
            self.architecture,self.input_contract,self.output_contract,
            self.benchmark_gate,self.review_date,
        )
        if any(not isinstance(value,str) for value in scalar_values):
            raise ValueError("invalid model manifest")
        names=tuple(file.path for file in self.files)
        if (
            MODEL_ID.fullmatch(self.model_id) is None
            or REVISION.fullmatch(self.revision) is None
            or not 1<=len(self.files)<=MAX_MODEL_FILES
            or len(set(names))!=len(names)
            or sum(file.size for file in self.files)>MAX_MODEL_REVISION_BYTES
            or any(not value for value in scalar_values[2:])
        ): raise ValueError("invalid model manifest")

@dataclass(frozen=True,slots=True)
class PreadOnlyModelReader:
    __fd:int
    size:int
    def read_at(self,offset:int,length:int) -> bytes:
        if (
            type(offset) is not int or type(length) is not int
            or not 0<=offset<=self.size or not 1<=length<=1_048_576
        ): raise ValueError("invalid model reader range")
        return os.pread(self.__fd,min(length,self.size-offset),offset)
    def chunks(self,chunk_size:int=1_048_576):
        offset=0
        while offset<self.size:
            chunk=self.read_at(offset,chunk_size)
            if not chunk: raise RuntimeError("model descriptor truncated")
            offset+=len(chunk); yield chunk
    def close(self): os.close(self.__fd)

@dataclass(frozen=True,slots=True)
class _ManifestBoundFile:
    path:str; size:int; sha256:str; device:int; inode:int

@dataclass(frozen=True,slots=True)
class VerifiedModelFile:
    __fd:int; __expected:_ManifestBoundFile
    @classmethod
    def from_manifest(cls,item:ModelFile,fd:int) -> "VerifiedModelFile":
        metadata=os.fstat(fd)
        return cls(fd,_ManifestBoundFile(
            item.path,item.size,item.sha256,metadata.st_dev,metadata.st_ino,
        ))
    @property
    def path(self) -> str: return self.__expected.path
    @property
    def size(self) -> int: return self.__expected.size
    @property
    def sha256(self) -> str: return self.__expected.sha256
    @property
    def fd(self) -> int: return self.__fd
    def verified(self) -> bool:
        try:
            metadata=os.fstat(self.__fd)
            if (
                fcntl.fcntl(self.__fd,fcntl.F_GETFL)&os.O_ACCMODE!=os.O_RDONLY
                or not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode)!=0o400
                or (metadata.st_dev,metadata.st_ino)!=(self.__expected.device,self.__expected.inode)
                or metadata.st_size!=self.__expected.size
            ): return False
            hash_exact_fd(self.__fd,self.__expected.size,self.__expected.sha256)
        except (OSError,RuntimeError): return False
        return True
    def load_with(self,adapter):
        # Adapter receives a bounded reader over this dup; the reader hashes the
        # exact bytes it supplies, requires EOF/size/digest, and returns a signed
        # per-file loader receipt. It has no pathname API.
        duplicate=os.dup(self.__fd); reader=None
        try:
            duplicate_metadata=os.fstat(duplicate)
            if (
                (duplicate_metadata.st_dev,duplicate_metadata.st_ino)!=
                (self.__expected.device,self.__expected.inode)
            ): raise ModelVerificationError("runtime model descriptor mismatch")
            hash_exact_fd(duplicate,self.__expected.size,self.__expected.sha256)
            reader=PreadOnlyModelReader(duplicate,self.__expected.size); duplicate=-1
            return adapter.load_verified_reader(
                reader,self.__expected.path,self.__expected.size,self.__expected.sha256,
            )
        finally:
            if duplicate>=0: os.close(duplicate)
            elif reader is not None: reader.close()

@dataclass(frozen=True,slots=True)
class ActivatedModel:
    model_id:str; revision:str
    __files:tuple[VerifiedModelFile,...]
    __manifest_files:tuple[tuple[str,int,str],...]
    @classmethod
    def from_manifest(
        cls,entry:ModelEntry,files:tuple[VerifiedModelFile,...],
    ) -> "ActivatedModel":
        expected=tuple((item.path,item.size,item.sha256) for item in entry.files)
        observed=tuple((item.path,item.size,item.sha256) for item in files)
        if not files or observed!=expected:
            raise ModelVerificationError("activated model is not manifest-bound")
        return cls(entry.model_id,entry.revision,files,expected)
    @property
    def files(self) -> tuple[VerifiedModelFile,...]: return self.__files
    @property
    def all_files_verified(self) -> bool:
        return bool(self.__files) and all(file.verified() for file in self.__files)
    def load_with(self,adapter,receipt_verifier):
        receipts=[]
        try:
            if not self.all_files_verified:
                raise ModelVerificationError("activated model descriptor mismatch")
            for file in self.__files: receipts.append(file.load_with(adapter))
            try: observed=tuple((r.path,r.size,r.sha256) for r in receipts)
            except (AttributeError,TypeError,ValueError) as error:
                raise ModelVerificationError("runtime model receipt mismatch") from error
            if observed!=self.__manifest_files:
                raise ModelVerificationError("runtime model receipt mismatch")
            candidate=adapter.finish_model(self.model_id,self.revision,tuple(receipts))
            try:
                return receipt_verifier.require_exact_signed_current(
                    candidate,signature_domain="tuntun.runtime-model-loader-receipt.v1",
                    model_id=self.model_id,revision=self.revision,files=self.__manifest_files,
                )
            except Exception as error:
                raise ModelVerificationError("runtime model receipt mismatch") from error
        except Exception as error:
            try: adapter.abort_model(self.model_id,self.revision,tuple(receipts))
            except Exception as abort_error:
                raise RuntimeError("runtime model abort failed; disable capability") from abort_error
            raise
    def close(self):
        for file in self.__files: os.close(file.fd)

class ModelRegistry:
    def __init__(self,entries,model_root): self._entries,self._root=entries,model_root
    @classmethod
    def load(cls,manifest:Path,model_root:Path=Path("var/models")):
        raw=read_bounded_strict_yaml(manifest)
        if not isinstance(raw,dict) or set(raw)!={"schema_version","models"} or raw["schema_version"]!="1.0" or not isinstance(raw["models"],list) or len(raw["models"])>256:
            raise ValueError("invalid model manifest")
        entries={}
        entry_keys={"id","revision","license","provenance","redistribution","approved_purpose","runtime","architecture","input_contract","output_contract","benchmark_gate","review_date","files"}
        file_keys={"path","size","sha256","url"}
        for item in raw["models"]:
            if not isinstance(item,dict) or set(item)!=entry_keys or not isinstance(item["files"],list) or not 1<=len(item["files"])<=MAX_MODEL_FILES or any(not isinstance(file,dict) or set(file)!=file_keys for file in item["files"]):
                raise ValueError("invalid model manifest")
            try:
                files=tuple(ModelFile(**file) for file in item["files"])
                entry=ModelEntry(model_id=item["id"],files=files,**{key:item[key] for key in entry_keys-{"id","files"}})
            except (TypeError,ValueError,OverflowError) as error:
                raise ValueError("invalid model manifest") from error
            if entry.model_id in entries: raise ValueError("invalid model manifest")
            entries[entry.model_id]=entry
        return cls(entries,model_root)
    def entry(self,model_id):
        try: return self._entries[model_id]
        except KeyError as error: raise LookupError("model is not registered") from error
    def activate(self,model_id):
        entry=self.entry(model_id); handles=[]
        try:
            root=OwnedDirectory.open(self._root)
            model=root.child(entry.model_id); revision=model.child(entry.revision,mode=0o500)
            for item in entry.files:
                fd=open_regular_at(revision,item.path,os.O_RDONLY)
                hash_exact_fd(fd,item.size,item.sha256)
                handles.append(VerifiedModelFile.from_manifest(item,fd))
            return ActivatedModel.from_manifest(entry,tuple(handles))
        except Exception:
            for handle in handles: os.close(handle.fd)
            raise RuntimeError("model is not installed and verified")
        finally:
            for directory in (locals().get("revision"),locals().get("model"),locals().get("root")):
                if directory is not None: directory.close()
```

```python
# apps/core/src/tuntun_core/services/models/network.py
from contextlib import contextmanager
import http.client,ipaddress,multiprocessing,socket,ssl,threading,time
from urllib.parse import urlsplit

class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self,hostname,pinned_ip,timeout):
        super().__init__(hostname,443,timeout=timeout,context=ssl.create_default_context())
        self._pinned_ip=pinned_ip
    def connect(self):
        raw=socket.create_connection((self._pinned_ip,443),self.timeout)
        self.sock=self._context.wrap_socket(raw,server_hostname=self.host)

def _resolver_child(send,hostname):
    try:
        values=sorted({
            answer[4][0] for answer in socket.getaddrinfo(
                hostname,443,type=socket.SOCK_STREAM,proto=socket.IPPROTO_TCP,
            )
        })
        send.send(("ok",values))
    except BaseException as error:
        send.send(("error",type(error).__name__))
    finally: send.close()

def resolve_public_addresses_bounded(hostname,deadline):
    remaining=deadline-time.monotonic()
    if remaining<=0: raise TimeoutError("model download total deadline")
    context=multiprocessing.get_context("spawn")
    receive,send=context.Pipe(duplex=False)
    process=context.Process(target=_resolver_child,args=(send,hostname),daemon=True)
    process.start(); send.close()
    try:
        if not receive.poll(remaining):
            process.terminate(); process.join(1)
            if process.is_alive(): process.kill(); process.join()
            raise TimeoutError("model DNS deadline")
        status,payload=receive.recv(); process.join(1)
        if process.is_alive(): process.kill(); process.join(); raise RuntimeError("model resolver did not exit")
        if status!="ok" or not isinstance(payload,list) or any(not isinstance(value,str) for value in payload):
            raise OSError("model DNS resolution failed")
        return payload
    finally:
        receive.close()
        if process.is_alive(): process.kill(); process.join()

class _DeadlineBoundResponse:
    def __init__(self,response,sock,deadline,per_read_timeout):
        self._response,self._socket,self._deadline=response,sock,deadline
        self._per_read_timeout=per_read_timeout
        self.status,self.headers=response.status,response.headers
    def read(self,size):
        remaining=self._deadline-time.monotonic()
        if remaining<=0: raise TimeoutError("model download total deadline")
        self._socket.settimeout(min(self._per_read_timeout,remaining))
        try: chunk=self._response.read1(size)
        except socket.timeout as error:
            raise TimeoutError("model download deadline") from error
        if time.monotonic()>self._deadline:
            raise TimeoutError("model download total deadline")
        return chunk

class PinnedHttpsTransport:
    @contextmanager
    def stream_exact(self,url,allowed_hosts,deadline,per_read_timeout=30.0):
        parsed=urlsplit(url); hostname=parsed.hostname
        remaining=deadline-time.monotonic()
        if remaining<=0: raise TimeoutError("model download total deadline")
        if (
            parsed.scheme!="https" or hostname not in allowed_hosts
            or parsed.username is not None or parsed.password is not None
            or parsed.port not in {None,443} or parsed.query or parsed.fragment
        ): raise PermissionError("model URL is not allowlisted HTTPS")
        addresses=resolve_public_addresses_bounded(hostname,deadline)
        if not addresses or any(not ipaddress.ip_address(value).is_global for value in addresses):
            raise PermissionError("model host did not resolve only to public addresses")
        # Connect to one already-validated IP, while TLS SNI/certificate and Host
        # remain the exact allowlisted DNS name. There is no resolver TOCTOU.
        remaining=deadline-time.monotonic()
        if remaining<=0: raise TimeoutError("model download total deadline")
        connection=_PinnedHTTPSConnection(hostname,addresses[0],min(per_read_timeout,remaining))
        deadline_timer=threading.Timer(remaining,connection.close)
        deadline_timer.daemon=True; deadline_timer.start()
        try:
            target=parsed.path or "/"
            connection.request(
                "GET",target,
                headers={"Host":hostname,"Accept-Encoding":"identity","Connection":"close"},
            )
            yield _DeadlineBoundResponse(
                connection.getresponse(),connection.sock,deadline,per_read_timeout,
            )
        except OSError as error:
            if time.monotonic()>=deadline:
                raise TimeoutError("model download total deadline") from error
            raise
        finally:
            deadline_timer.cancel(); connection.close()
```

```python
# apps/core/src/tuntun_core/services/models/installer.py
import fcntl,hashlib,os,secrets,stat,time
from urllib.parse import urlsplit
from .fs import (
    OwnedDirectory,atomic_publish_dir_noreplace,hash_exact_fd,open_regular_at,
)
from .network import PinnedHttpsTransport
from .registry import ActivatedModel,VerifiedModelFile

class ModelInstaller:
    def __init__(self,registry,allowed_hosts,transport=None):
        self.registry=registry; self.allowed_hosts=frozenset(allowed_hosts)
        self.transport=transport or PinnedHttpsTransport()
    MAX_TOTAL_DOWNLOAD_SECONDS=900.0
    def _download(self,stage,item,deadline):
        parsed=urlsplit(item.url)
        if parsed.hostname not in self.allowed_hosts:
            raise PermissionError("model URL is not allowlisted HTTPS")
        write_fd=open_regular_at(
            stage,item.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode=0o600,
        )
        read_fd=None
        try:
            # Open the only retained descriptor before qualification, while the
            # private owner-only stage and exclusive writer still name the new
            # inode. The runtime never receives write authority.
            read_fd=open_regular_at(stage,item.path,os.O_RDONLY,mode=0o600)
            written_identity=os.fstat(write_fd); read_identity=os.fstat(read_fd)
            if (
                not stat.S_ISREG(written_identity.st_mode)
                or written_identity.st_uid!=os.geteuid()
                or written_identity.st_nlink!=1
                or (written_identity.st_dev,written_identity.st_ino)!=
                   (read_identity.st_dev,read_identity.st_ino)
                or fcntl.fcntl(read_fd,fcntl.F_GETFL)&os.O_ACCMODE!=os.O_RDONLY
            ):
                raise PermissionError("model staged descriptor identity invalid")
            digest=hashlib.sha256(); total=0
            with self.transport.stream_exact(item.url,self.allowed_hosts,deadline) as response:
                # No redirect is followed. Any 3xx, changed URL, non-200, or
                # declared oversized length is rejected before response bytes.
                if response.status!=200:
                    raise PermissionError("model redirect or response rejected")
                length=response.headers.get("content-length")
                encoding=response.headers.get("content-encoding")
                if encoding not in {None,"identity"}:
                    raise ValueError("model response encoding rejected")
                if length is not None and (not length.isascii() or not length.isdecimal() or int(length)!=item.size):
                    raise ValueError("model size/hash mismatch")
                while chunk:=response.read(65_536):
                    total+=len(chunk)
                    if total>item.size: raise ValueError("model size/hash mismatch")
                    view=memoryview(chunk)
                    while view:
                        written=os.write(write_fd,view)
                        if written<=0: raise OSError("model artifact write made no progress")
                        view=view[written:]
                    digest.update(chunk)
            if total!=item.size or digest.hexdigest()!=item.sha256:
                raise ValueError("model size/hash mismatch")
            os.fchmod(write_fd,0o400); os.fsync(write_fd)
            final_write=os.fstat(write_fd); final_read=os.fstat(read_fd)
            if (
                not stat.S_ISREG(final_write.st_mode)
                or not stat.S_ISREG(final_read.st_mode)
                or final_write.st_uid!=os.geteuid()
                or final_read.st_uid!=os.geteuid()
                or stat.S_IMODE(final_read.st_mode)!=0o400
                or final_write.st_size!=item.size or final_read.st_size!=item.size
                or final_write.st_nlink!=1 or final_read.st_nlink!=1
                or (final_write.st_dev,final_write.st_ino)!=
                   (written_identity.st_dev,written_identity.st_ino)
                or (final_read.st_dev,final_read.st_ino)!=
                   (written_identity.st_dev,written_identity.st_ino)
            ):
                raise ValueError("model size/hash mismatch")
            hash_exact_fd(read_fd,item.size,item.sha256)
            os.close(write_fd); write_fd=None
            return read_fd
        except Exception:
            if read_fd is not None: os.close(read_fd)
            if write_fd is not None: os.close(write_fd)
            raise

    def install(self,model_id):
        entry=self.registry.entry(model_id)
        root=OwnedDirectory.open_or_create(self.registry._root)
        try:
            with root.lock(".model-install.lock",timeout_seconds=30):
                model=root.child(entry.model_id,create=True,exist_ok=True)
                try:
                    model.remove_private_stages(f".stage-{entry.revision}-")
                    model.fsync()
                    if model.has_child(entry.revision):
                        # Existing revisions are immutable: validate and reuse an
                        # exact complete revision, or fail for owner repair.
                        return self.registry.activate(model_id)
                    stage_name=f".stage-{entry.revision}-{secrets.token_hex(8)}"
                    stage=model.child(stage_name,create=True)
                    stage_identity=stage.identity
                    published=False
                    handles=[]
                    try:
                        download_deadline=time.monotonic()+self.MAX_TOTAL_DOWNLOAD_SECONDS
                        for item in entry.files:
                            fd=self._download(stage,item,download_deadline)
                            handles.append(VerifiedModelFile.from_manifest(item,fd))
                        # Rehash the retained same-inode O_RDONLY descriptions
                        # that are handed to the runtime; publication never
                        # qualifies one pathname and later reopens it.
                        for item,handle in zip(entry.files,handles,strict=True):
                            hash_exact_fd(handle.fd,item.size,item.sha256)
                        stage.chmod(0o500)
                        stage.fsync()
                        atomic_publish_dir_noreplace(model,stage_name,entry.revision)
                        published=True
                        model.fsync()
                        return ActivatedModel.from_manifest(entry,tuple(handles))
                    except Exception:
                        for handle in handles: os.close(handle.fd)
                        if not published:
                            model.remove_private_stage(stage_name,stage_identity)
                            model.fsync()
                        # After an exclusive rename, the final name contains a
                        # complete read-only revision. A parent-fsync failure is
                        # reconciled on restart; it is never deleted or replaced.
                        raise
                    finally: stage.close()
                finally: model.close()
        finally: root.close()
        raise RuntimeError("model install did not publish")
```

`models/manifest.schema.json` is JSON Schema draft 2020-12 with `additionalProperties:false` at every object, exact required `ModelEntry`/file fields, the same closed ID/revision/file/hash/size/URL bounds, and an array-size cap of 256 models and 64 files. Schema validation is defense in depth: `ModelRegistry.load` independently enforces every invariant, rejects booleans and every other wrong scalar type as `ValueError`, caps models before iteration and files before construction, detects duplicate IDs/files, checks total revision bytes, and uses strict YAML parsing. Only the checked-in bootstrap manifest may have `models: []`; release candidates with enabled local-model capabilities must contain their exact governed entries. `scripts/check_model_manifest.py` uses the same bounded strict read, then the schema and runtime loader; it never performs a second pathname read. Add a Typer `models` sub-app with `list`, `verify`, and explicit owner-presence `install MODEL_ID` commands; registering it must not instantiate the installer/client or perform network I/O. Startup accepts only an `ActivatedModel` whose retained handles are `O_RDONLY`; hashing and adapter reads use explicit-offset `pread`, so prior or concurrent descriptor offsets cannot truncate or redirect a load. The adapter receives only the bounded pread reader, and the runtime’s exact signed loader receipt is authoritative. `receipt_verifier` verifies the canonical signature, non-overlapping domain, exact current key generation, expiry, model/revision, and ordered `(path,size,sha256)` inventory; per-file receipts repeat that exact tuple. The adapter keeps any partly loaded runtime private until verification returns; every load, finish, or verification exception invokes mandatory `abort_model`, and abort failure disables/restarts the model capability rather than exposing the candidate. The installer has one 900-second monotonic deadline shared across bounded DNS resolution, connect, headers, and every artifact body; a deadline timer closes a slow-drip socket. Missing/rejected/unverified models produce a disabled capability.

- [ ] **Step 4: Lock and run the green model gate**

Run: `uv lock && uv run pytest tests/security/test_model_governance.py -q && uv run python scripts/check_model_manifest.py models/manifest.yaml && uv run tuntunctl models list`

Expected: PASS with the full manifest/filesystem/network/race/fault matrix, `model manifest: PASS`, and an empty JSON list from the CLI. Redirects, private-address resolution, resolver hangs, overrun/truncation, path/symlink/type swaps, invalid ownership/mode, partial download, and conflicting publication never expose a revision or runtime bytes; two installers serialize and converge on one complete immutable revision; runtime loads repeatedly see the full exact bytes hashed through stable read-only descriptors regardless of prior offsets; list/verify/startup make zero network requests.

- [ ] **Step 5: Commit exact Task 10 paths**

```bash
git status --short
git add apps/core/pyproject.toml uv.lock apps/core/src/tuntun_core/services/models/fs.py apps/core/src/tuntun_core/services/models/network.py apps/core/src/tuntun_core/services/models/registry.py apps/core/src/tuntun_core/services/models/installer.py apps/core/src/tuntun_core/cli/commands/models.py apps/core/src/tuntun_core/cli/main.py models/manifest.schema.json models/manifest.yaml scripts/check_model_manifest.py tests/security/test_model_governance.py tests/security/conftest.py tests/security/model_governance_cases.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(models): add governed registry and explicit installer"
```

### Task 11: Prove key-first SQLCipher compatibility and add the storage probe

**Master package:** 05
**Depends on:** Task 10.
**Estimated effort:** 0.5 person-day.

**Files:**
- Modify: `apps/core/pyproject.toml`
- Modify: `uv.lock`
- Create: `apps/core/src/tuntun_core/adapters/sqlcipher/connection.py`
- Create: `apps/core/src/tuntun_core/adapters/sqlcipher/probe.py`
- Create: `apps/core/src/tuntun_core/cli/commands/storage_probe.py`
- Modify: `apps/core/src/tuntun_core/cli/main.py`
- Test: `tests/security/test_sqlcipher.py`
- Create: `docs/operations/sqlcipher-compatibility.md`

**Interfaces:**
- Consumes: a 32-byte database key and Task 7 `ensure_private_directory`, `open_owned_directory`, and their fresh no-follow component walk. Task 11's `_OPEN_LOCK` serializes qualification/connect windows inside this process only; it is not represented as cross-process protection.
- Produces: immutable `FileIdentity(device, inode, owner, mode, links)` values; `qualified_database_identity(path: Path) -> tuple[int, int]`; `open_sqlcipher(path: Path, key: bytes) -> sqlcipher3.Connection`; concrete subclass `QualifiedSQLCipherConnection.revalidate_storage_path()`, `.guarded_parent_descriptor()`, and `.storage_identities()`; metadata-only process registry `_ACTIVE_DATABASES` keyed by the one canonical symlink-free absolute database path; `probe_storage(path: Path, key: bytes) -> StorageProbe`; CLI `tuntunctl storage probe --path PATH --json`. The adapter retains only the freshly no-follow-walked parent-directory FD. It uses descriptor-relative no-follow `stat` metadata for an existing main file and pre-existing/materialized WAL/SHM, and SQLCipher alone owns every lock-bearing main/WAL/SHM descriptor while any connection may be active or initializing. An absent main may be descriptor-relative `O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`-created only while the canonical path has zero active and zero initializing reservations; that transient FD is validated, `fchmod(0600)`-normalized, and closed before `sqlcipher3.connect`. The normal pathname reopen retains exact `READWRITE|FULLMUTEX|PRIVATECACHE|SQLITE_OPEN_NOFOLLOW` flags with no `CREATE`, URI, or custom VFS.
- `_OPEN_LOCK` covers metadata qualification, reservation, connect, initialization, publish, and failure rollback. The registry value records the immutable main device/inode and active/initializing counts plus a failed-close count; it never owns a main or sidecar FD. A second connection compares the registered main identity and performs no adapter main/WAL/SHM open or close. Successful explicit close is ordered exactly as SQLCipher/base close, registry release, then parent-directory close. If SQLCipher close raises, the lease and parent remain attached for explicit retry/process abort, the registry blocks a new return, and cleanup is not reported as successful. Every failure after connect closes SQLCipher first, then rolls back the initializing reservation, then closes the parent; a close failure preserves all three. If `sqlcipher3.connect` itself raises, constructor/deallocator completion precedes reservation rollback and parent close.
- This is deliberately not an exact descriptor handoff: `sqlcipher3==0.6.2` exposes neither a main-file FD nor Python VFS registration. A hostile same-EUID/root process can perform an ABA swap that restores the checked names between bracket checks, and a process able to read this process's memory can obtain the key. The contract is strong against other users, symlinks, stale/unsafe entries, and one-way/non-ABA replacement; exact binding against a malicious same-EUID process requires a funded native VFS or different driver and blocks this adapter rather than permitting a stronger claim.

- [ ] **Step 1: Pin dependencies and write the red encryption tests**

Add `sqlcipher3==0.6.2` and `cryptography>=45,<46` to core dependencies and run `uv lock` before the red test so a missing system-compatible wheel/build fails at the intended stop/go gate.

```python
# tests/security/test_sqlcipher.py
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import os
import socket
import sqlite3
import stat
import subprocess
import sys
from threading import Event,Thread
import pytest
from sqlcipher3 import dbapi2 as sqlcipher3
from tuntun_core.adapters.sqlcipher import connection as connection_module
from tuntun_core.adapters.sqlcipher.connection import (
    SQLCIPHER_OPEN_FLAGS,SQLITE_OPEN_NOFOLLOW,QualifiedSQLCipherConnection,
    open_sqlcipher,
)
from tuntun_core.adapters.sqlcipher.probe import probe_storage

KEY = bytes(range(32)); WRONG = bytes(reversed(range(32)))

def _database_path(tmp_path:Path,name:str="foundation.db") -> Path:
    # pytest owns this root; canonicalize only its trusted Darwin /var alias.
    root=Path(os.path.realpath(tmp_path)); private=root/"private"
    private.mkdir(mode=0o700,exist_ok=True)
    return private/name

def _regular(path:Path,data:bytes=b"") -> None:
    path.write_bytes(data); path.chmod(0o600)

def _exclusive_empty_main(path:Path) -> None:
    flags=os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW
    fd=os.open(path,flags,0o600)
    try:
        os.fchmod(fd,0o600); opened=os.fstat(fd)
        assert stat.S_ISREG(opened.st_mode) and stat.S_IMODE(opened.st_mode)==0o600
    finally: os.close(fd)
    assert os.stat(path,follow_symlinks=False).st_size==0
    for suffix in ("-wal","-shm"):
        with pytest.raises(FileNotFoundError):
            os.stat(os.fspath(path)+suffix,follow_symlinks=False)

def _identity(path:Path) -> tuple[int,int]:
    value=os.stat(path,follow_symlinks=False)
    return value.st_dev,value.st_ino

LOCK_CONTENDER=r'''\
import os,sys
from sqlcipher3 import dbapi2 as sqlcipher3
SQLITE_OPEN_NOFOLLOW=0x01000000
flags=(sqlcipher3.SQLITE_OPEN_READWRITE|sqlcipher3.SQLITE_OPEN_FULLMUTEX|
       sqlcipher3.SQLITE_OPEN_PRIVATECACHE|SQLITE_OPEN_NOFOLLOW)
db=sqlcipher3.connect(sys.argv[1],isolation_level=None,flags=flags)
db.execute(f"PRAGMA key = \"x'{sys.argv[2]}'\"")
db.execute("PRAGMA busy_timeout=250")
try:
    db.execute("BEGIN IMMEDIATE")
    db.execute("INSERT INTO lock_probe VALUES (2)")
    db.execute("COMMIT")
except sqlcipher3.OperationalError:
    db.close(); raise SystemExit(75)
db.close()
'''

OPEN_LIFECYCLE_PROBE=r'''\
import sys
from pathlib import Path
from tuntun_core.adapters.sqlcipher import connection as module
path=Path(sys.argv[1]); key=bytes.fromhex(sys.argv[2]); checkpoint=sys.argv[3]
if checkpoint!="success":
    def injected(name):
        if name==checkpoint: raise RuntimeError(f"injected {name}")
    module._initialization_checkpoint=injected
try:
    db=module.open_sqlcipher(path,key)
except RuntimeError as error:
    if checkpoint=="success": raise
    if str(error)!=f"injected {checkpoint}": raise
    if module._registry_snapshot(path) is not None: raise SystemExit(21)
else:
    if checkpoint!="success": raise SystemExit(22)
    db.close()
    if module._registry_snapshot(path) is not None: raise SystemExit(23)
'''

def _contend(path:Path,expected_returncode:int) -> None:
    result=subprocess.run(
        [sys.executable,"-c",LOCK_CONTENDER,os.fspath(path),KEY.hex()],
        check=False,capture_output=True,text=True,timeout=10,
    )
    assert result.returncode==expected_returncode,(result.stdout,result.stderr)

@pytest.mark.parametrize("checkpoint",(
    "success","key_validation","keyed_read","wal_activation",
    "sidecar_metadata","integrity",
))
def test_open_and_cleanup_lock_ownership_never_deadlocks(
    tmp_path:Path,checkpoint:str,
) -> None:
    path=_database_path(tmp_path,f"lifecycle-{checkpoint}.db")
    result=subprocess.run(
        [sys.executable,"-c",OPEN_LIFECYCLE_PROBE,os.fspath(path),KEY.hex(),checkpoint],
        check=False,capture_output=True,text=True,timeout=15,
    )
    assert result.returncode==0,(result.stdout,result.stderr)

@pytest.mark.parametrize("path",(Path("."),Path("private")/".."/"database.db",Path("bad\x00name.db")))
def test_database_path_rejects_dot_dotdot_and_nul(path:Path) -> None:
    with pytest.raises(PermissionError,match="unsafe database path"):
        open_sqlcipher(path,KEY)

def test_key_first_database_is_encrypted_and_wrong_key_fails(tmp_path: Path) -> None:
    path=_database_path(tmp_path); sentinel=b"foundation-private-sentinel"
    db=open_sqlcipher(path, KEY); db.execute("CREATE TABLE marker(value BLOB NOT NULL)"); db.execute("INSERT INTO marker VALUES (?)", (sentinel,)); db.commit(); db.close()
    assert sentinel not in path.read_bytes(); assert not path.read_bytes().startswith(b"SQLite format 3\x00")
    with pytest.raises(sqlcipher3.DatabaseError): open_sqlcipher(path, WRONG)
    with pytest.raises(sqlite3.DatabaseError): sqlite3.connect(path).execute("SELECT name FROM sqlite_master").fetchall()

def test_connection_enables_integrity_foreign_keys_and_secure_delete(tmp_path: Path) -> None:
    db=open_sqlcipher(_database_path(tmp_path,"settings.db"), KEY)
    assert db.execute("PRAGMA cipher_version").fetchone()[0]
    assert db.execute("PRAGMA cipher_integrity_check").fetchone()[0] == "ok"
    assert db.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert db.execute("PRAGMA secure_delete").fetchone()[0] == 1
    db.close()

def test_connect_uses_normal_path_exact_flags_and_key_is_first_sql(
    tmp_path:Path,monkeypatch:pytest.MonkeyPatch,
) -> None:
    path=_database_path(tmp_path); calls=[]; statements=[]
    original_connect=connection_module.sqlcipher3.connect
    original_execute=QualifiedSQLCipherConnection.execute
    def recording_connect(database,*args,**kwargs):
        calls.append((database,dict(kwargs)))
        return original_connect(database,*args,**kwargs)
    def recording_execute(self,statement,*args,**kwargs):
        statements.append(str(statement)); return original_execute(self,statement,*args,**kwargs)
    monkeypatch.setattr(connection_module.sqlcipher3,"connect",recording_connect)
    monkeypatch.setattr(QualifiedSQLCipherConnection,"execute",recording_execute)
    db=open_sqlcipher(path,KEY); db.close()
    database,kwargs=calls[0]
    assert database==os.fspath(path) and not database.startswith("/dev/fd/")
    assert kwargs["flags"]==SQLCIPHER_OPEN_FLAGS
    assert kwargs["factory"] is QualifiedSQLCipherConnection
    assert "uri" not in kwargs and "vfs" not in kwargs
    assert SQLCIPHER_OPEN_FLAGS&sqlcipher3.SQLITE_OPEN_CREATE==0
    assert SQLCIPHER_OPEN_FLAGS&SQLITE_OPEN_NOFOLLOW
    assert statements[0]==f'PRAGMA key = "x\'{KEY.hex()}\'"'

@pytest.mark.parametrize("component",("ancestor","leaf"))
def test_pinned_driver_enforces_nofollow_on_each_target_platform(
    tmp_path:Path,component:str,
) -> None:
    real=_database_path(tmp_path,"real.db"); db=open_sqlcipher(real,KEY); db.close()
    if component=="leaf":
        candidate=real.with_name("alias.db"); candidate.symlink_to(real)
    else:
        alias=real.parent.with_name("alias-parent"); alias.symlink_to(real.parent,directory=True)
        candidate=alias/real.name
    with pytest.raises(sqlcipher3.OperationalError):
        sqlcipher3.connect(os.fspath(candidate),flags=SQLCIPHER_OPEN_FLAGS)

@pytest.mark.parametrize("mutation",(
    "symlink","fifo","socket","directory","mode_0640","mode_0400","wrong_owner",
    "hard_link","device_mismatch",
))
def test_database_entry_is_regular_owned_private_single_link_and_same_device(
    tmp_path:Path,monkeypatch:pytest.MonkeyPatch,mutation:str,
) -> None:
    path=_database_path(tmp_path); cleanup=None
    if mutation=="symlink":
        target=path.with_name("target.db"); _regular(target); path.symlink_to(target)
    elif mutation=="fifo": os.mkfifo(path,0o600)
    elif mutation=="socket":
        cleanup=socket.socket(socket.AF_UNIX); cleanup.bind(os.fspath(path))
    elif mutation=="directory": path.mkdir(mode=0o700)
    else:
        _regular(path)
        if mutation.startswith("mode_"): path.chmod(int(mutation.removeprefix("mode_"),8))
        elif mutation=="hard_link": os.link(path,path.with_name("second-link.db"))
        elif mutation=="wrong_owner":
            original=connection_module._reported_owner
            monkeypatch.setattr(connection_module,"_reported_owner",lambda name,value: value.st_uid+1 if name==path.name else original(name,value))
        elif mutation=="device_mismatch":
            original=connection_module._reported_device
            monkeypatch.setattr(connection_module,"_reported_device",lambda name,value: value.st_dev+1 if name==path.name else original(name,value))
    try:
        with pytest.raises(PermissionError,match="unsafe database path"):
            open_sqlcipher(path,KEY)
    finally:
        if cleanup is not None: cleanup.close()

def test_every_ancestor_and_final_symlink_is_rejected(tmp_path:Path) -> None:
    root=Path(os.path.realpath(tmp_path)); target=root/"target"; target.mkdir(mode=0o700)
    alias=root/"alias"; alias.symlink_to(target,directory=True)
    with pytest.raises(PermissionError,match="unsafe database path"):
        open_sqlcipher(alias/"database.db",KEY)
    private=root/"private"; private.mkdir(mode=0o700)
    real=private/"real.db"; _regular(real); (private/"database.db").symlink_to(real)
    with pytest.raises(PermissionError,match="unsafe database path"):
        open_sqlcipher(private/"database.db",KEY)

@pytest.mark.parametrize("replacement",("database","parent"))
def test_one_way_replacement_during_connect_fails_and_closes(
    tmp_path:Path,monkeypatch:pytest.MonkeyPatch,replacement:str,
) -> None:
    path=_database_path(tmp_path); parent=path.parent; captured=[]
    original_connect=connection_module.sqlcipher3.connect
    original_open=connection_module._open_qualified_database
    def recording_open(value):
        guard=original_open(value); captured.append(guard.parent.fd); return guard
    def replacing_connect(*args,**kwargs):
        if replacement=="database":
            path.rename(parent/"qualified-original.db"); _regular(path)
        else:
            parent.rename(parent.with_name("qualified-original-parent"))
            parent.mkdir(mode=0o700); _regular(path)
        return original_connect(*args,**kwargs)
    monkeypatch.setattr(connection_module,"_open_qualified_database",recording_open)
    monkeypatch.setattr(connection_module.sqlcipher3,"connect",replacing_connect)
    with pytest.raises(PermissionError,match="unsafe database path"):
        open_sqlcipher(path,KEY)
    assert captured
    for fd in captured:
        with pytest.raises(OSError): os.fstat(fd)
    assert connection_module._registry_snapshot(path) is None

@pytest.mark.parametrize("suffix",("-wal","-shm"))
@pytest.mark.parametrize("mutation",(
    "symlink","fifo","socket","directory","mode_0640","mode_0400","wrong_owner",
    "hard_link","device_mismatch",
))
def test_preexisting_sidecars_are_qualified_before_sqlite_touches_them(
    tmp_path:Path,monkeypatch:pytest.MonkeyPatch,suffix:str,mutation:str,
) -> None:
    path=_database_path(tmp_path); _exclusive_empty_main(path)
    sidecar=Path(os.fspath(path)+suffix); cleanup=None
    if mutation=="symlink":
        target=sidecar.with_name(sidecar.name+"-target"); _regular(target); sidecar.symlink_to(target)
    elif mutation=="fifo": os.mkfifo(sidecar,0o600)
    elif mutation=="socket":
        cleanup=socket.socket(socket.AF_UNIX); cleanup.bind(os.fspath(sidecar))
    elif mutation=="directory": sidecar.mkdir(mode=0o700)
    else:
        _regular(sidecar)
        if mutation.startswith("mode_"): sidecar.chmod(int(mutation.removeprefix("mode_"),8))
        elif mutation=="hard_link": os.link(sidecar,sidecar.with_name(sidecar.name+"-link"))
        elif mutation=="wrong_owner":
            original=connection_module._reported_owner
            monkeypatch.setattr(connection_module,"_reported_owner",lambda name,value: value.st_uid+1 if name==sidecar.name else original(name,value))
        elif mutation=="device_mismatch":
            original=connection_module._reported_device
            monkeypatch.setattr(connection_module,"_reported_device",lambda name,value: value.st_dev+1 if name==sidecar.name else original(name,value))
    try:
        created=os.stat(sidecar,follow_symlinks=False)
        assert {
            "symlink":stat.S_ISLNK,"fifo":stat.S_ISFIFO,"socket":stat.S_ISSOCK,
            "directory":stat.S_ISDIR,
        }.get(mutation,stat.S_ISREG)(created.st_mode)
        if mutation.startswith("mode_"):
            assert stat.S_IMODE(created.st_mode)==int(mutation.removeprefix("mode_"),8)
        if mutation=="hard_link": assert created.st_nlink==2
        with pytest.raises(PermissionError,match="unsafe database path"):
            open_sqlcipher(path,KEY)
        assert connection_module._registry_snapshot(path) is None
    finally:
        if cleanup is not None: cleanup.close()

def test_creation_only_fd_closes_before_reservation_and_sqlcipher_connect(
    tmp_path:Path,monkeypatch:pytest.MonkeyPatch,
) -> None:
    path=_database_path(tmp_path); events=[]
    original_close=connection_module.os.close
    original_connect=connection_module.sqlcipher3.connect
    def recording_close(fd):
        opened=os.fstat(fd)
        try: named=os.stat(path,follow_symlinks=False)
        except FileNotFoundError: named=None
        if named is not None and (opened.st_dev,opened.st_ino)==(named.st_dev,named.st_ino):
            state=connection_module._ACTIVE_DATABASES.get(path)
            events.append(("creation-close",None if state is None else (state.active,state.initializing)))
        return original_close(fd)
    def recording_connect(*args,**kwargs):
        state=connection_module._ACTIVE_DATABASES[path]
        events.append(("connect",(state.active,state.initializing)))
        return original_connect(*args,**kwargs)
    monkeypatch.setattr(connection_module.os,"close",recording_close)
    monkeypatch.setattr(connection_module.sqlcipher3,"connect",recording_connect)
    db=open_sqlcipher(path,KEY); db.close()
    assert [name for name,_ in events[:2]]==["creation-close","connect"]
    assert events[0][1] is None
    assert events[1][1]==(0,1)

def test_materialized_sidecars_are_metadata_identities_and_only_parent_fd_is_retained(
    tmp_path:Path,
) -> None:
    path=_database_path(tmp_path); db=open_sqlcipher(path,KEY)
    parent_fd=db.guarded_parent_descriptor(); opened_parent=os.fstat(parent_fd)
    assert stat.S_ISDIR(opened_parent.st_mode)
    main_identity,sidecar_identities=db.storage_identities()
    assert (main_identity.device,main_identity.inode)==_identity(path)
    assert {suffix for suffix,_ in sidecar_identities}=={"-wal","-shm"}
    for suffix in ("-wal","-shm"):
        value=os.stat(os.fspath(path)+suffix,follow_symlinks=False)
        assert stat.S_ISREG(value.st_mode) and stat.S_IMODE(value.st_mode)==0o600
        assert value.st_uid==os.geteuid() and value.st_nlink==1
        assert value.st_dev==os.lstat(path.parent).st_dev
    db.close()
    with pytest.raises(OSError): os.fstat(parent_fd)
    assert connection_module._registry_snapshot(path) is None

def test_second_connection_never_adapter_opens_or_closes_main_or_sidecars(
    tmp_path:Path,monkeypatch:pytest.MonkeyPatch,
) -> None:
    path=_database_path(tmp_path); first=open_sqlcipher(path,KEY)
    protected={_identity(path),*(_identity(Path(os.fspath(path)+suffix)) for suffix in ("-wal","-shm"))}
    events=[]; original_open=connection_module.os.open; original_close=connection_module.os.close
    def recording_open(*args,**kwargs):
        fd=original_open(*args,**kwargs); events.append(("open",_identity_from_fd(fd))); return fd
    def recording_close(fd):
        events.append(("close",_identity_from_fd(fd))); return original_close(fd)
    def _identity_from_fd(fd):
        value=os.fstat(fd); return value.st_dev,value.st_ino
    monkeypatch.setattr(connection_module.os,"open",recording_open)
    monkeypatch.setattr(connection_module.os,"close",recording_close)
    second=open_sqlcipher(path,KEY)
    assert second.storage_identities()==first.storage_identities()
    second.close()
    assert not [event for event in events if event[1] in protected]
    assert connection_module._registry_snapshot(path).active==1
    assert first.execute("SELECT 1").fetchone()==(1,)
    first.close()

def test_successful_close_orders_sqlcipher_then_registry_then_parent(
    tmp_path:Path,monkeypatch:pytest.MonkeyPatch,
) -> None:
    path=_database_path(tmp_path); db=open_sqlcipher(path,KEY); events=[]
    original_base=QualifiedSQLCipherConnection._close_sqlcipher_base
    original_release=connection_module._release_reservation_after_close
    original_parent=connection_module.DatabasePathGuard._close_parent_after_release
    def base(connection): events.append("sqlcipher"); return original_base(connection)
    def release(reservation): events.append("registry"); return original_release(reservation)
    def parent(guard): events.append("parent"); return original_parent(guard)
    monkeypatch.setattr(QualifiedSQLCipherConnection,"_close_sqlcipher_base",base)
    monkeypatch.setattr(connection_module,"_release_reservation_after_close",release)
    monkeypatch.setattr(connection_module.DatabasePathGuard,"_close_parent_after_release",parent)
    db.close()
    assert events==["sqlcipher","registry","parent"]

@pytest.mark.parametrize("checkpoint",(
    "key_validation","keyed_read","wal_activation","sidecar_metadata","integrity",
))
def test_initialization_failure_closes_before_rollback_and_preserves_healthy_peer(
    tmp_path:Path,monkeypatch:pytest.MonkeyPatch,checkpoint:str,
) -> None:
    path=_database_path(tmp_path); healthy=open_sqlcipher(path,KEY); before=connection_module._registry_snapshot(path)
    events=[]; original_base=QualifiedSQLCipherConnection._close_sqlcipher_base
    original_rollback=connection_module._rollback_reservation_after_close
    original_parent=connection_module.DatabasePathGuard._close_parent_after_release
    def fail_at(name):
        if name==checkpoint: raise RuntimeError(f"injected {checkpoint}")
    def base(connection): events.append("sqlcipher"); return original_base(connection)
    def rollback(reservation): events.append("registry"); return original_rollback(reservation)
    def parent(guard): events.append("parent"); return original_parent(guard)
    monkeypatch.setattr(connection_module,"_initialization_checkpoint",fail_at)
    monkeypatch.setattr(QualifiedSQLCipherConnection,"_close_sqlcipher_base",base)
    monkeypatch.setattr(connection_module,"_rollback_reservation_after_close",rollback)
    monkeypatch.setattr(connection_module.DatabasePathGuard,"_close_parent_after_release",parent)
    with pytest.raises(RuntimeError,match=f"injected {checkpoint}"):
        open_sqlcipher(path,KEY)
    assert events==["sqlcipher","registry","parent"]
    after=connection_module._registry_snapshot(path)
    assert (after.active,after.initializing)==(before.active,before.initializing)==(1,0)
    assert healthy.execute("SELECT 1").fetchone()==(1,)
    healthy.close()

def test_initialization_close_failure_retains_initializing_lease_until_retry(
    tmp_path:Path,monkeypatch:pytest.MonkeyPatch,
) -> None:
    path=_database_path(tmp_path); healthy=open_sqlcipher(path,KEY)
    original=QualifiedSQLCipherConnection._close_sqlcipher_base; failed=False
    def fail_checkpoint(name):
        if name=="key_validation": raise RuntimeError("injected initialization failure")
    def fail_first_cleanup(connection):
        nonlocal failed
        if not failed:
            failed=True; raise RuntimeError("injected initialization close failure")
        return original(connection)
    monkeypatch.setattr(connection_module,"_initialization_checkpoint",fail_checkpoint)
    monkeypatch.setattr(QualifiedSQLCipherConnection,"_close_sqlcipher_base",fail_first_cleanup)
    with pytest.raises(connection_module.SQLCipherCleanupError) as captured:
        open_sqlcipher(path,KEY)
    failed_connection=captured.value.connection
    parent_fd=failed_connection.guarded_parent_descriptor()
    state=connection_module._registry_snapshot(path)
    assert (state.active,state.initializing,state.failed_closes)==(1,1,1)
    assert os.fstat(parent_fd)
    with pytest.raises(RuntimeError,match="prior SQLCipher close failed"):
        open_sqlcipher(path,KEY)
    failed_connection.close()
    with pytest.raises(OSError): os.fstat(parent_fd)
    state=connection_module._registry_snapshot(path)
    assert (state.active,state.initializing,state.failed_closes)==(1,0,0)
    assert healthy.execute("SELECT 1").fetchone()==(1,)
    healthy.close()

def test_sqlcipher_close_failure_retains_lease_parent_and_blocks_new_return(
    tmp_path:Path,monkeypatch:pytest.MonkeyPatch,
) -> None:
    path=_database_path(tmp_path); db=open_sqlcipher(path,KEY)
    parent_fd=db.guarded_parent_descriptor(); original=QualifiedSQLCipherConnection._close_sqlcipher_base
    failed=False
    def fail_once(connection):
        nonlocal failed
        if connection is db and not failed:
            failed=True; raise RuntimeError("injected SQLCipher close failure")
        return original(connection)
    monkeypatch.setattr(QualifiedSQLCipherConnection,"_close_sqlcipher_base",fail_once)
    with pytest.raises(RuntimeError,match="injected SQLCipher close failure"): db.close()
    state=connection_module._registry_snapshot(path)
    assert (state.active,state.initializing,state.failed_closes)==(1,0,1)
    assert os.fstat(parent_fd) and db.guarded_parent_descriptor()==parent_fd
    with pytest.raises(RuntimeError,match="prior SQLCipher close failed"):
        open_sqlcipher(path,KEY)
    db.close()
    with pytest.raises(OSError): os.fstat(parent_fd)
    reopened=open_sqlcipher(path,KEY); reopened.close()

def test_close_failure_mark_is_atomic_with_respect_to_new_open(
    tmp_path:Path,monkeypatch:pytest.MonkeyPatch,
) -> None:
    path=_database_path(tmp_path); db=open_sqlcipher(path,KEY)
    entered=Event(); allow_failure=Event(); open_done=Event()
    close_errors=[]; open_errors=[]; returned=[]; original=QualifiedSQLCipherConnection._close_sqlcipher_base
    failed_once=False
    def paused_failure(connection):
        nonlocal failed_once
        if connection is db and not failed_once:
            failed_once=True; entered.set()
            assert allow_failure.wait(5); raise RuntimeError("injected paused close failure")
        return original(connection)
    def close_worker():
        try: db.close()
        except BaseException as error: close_errors.append(error)
    def open_worker():
        try: returned.append(open_sqlcipher(path,KEY))
        except BaseException as error: open_errors.append(error)
        finally: open_done.set()
    monkeypatch.setattr(QualifiedSQLCipherConnection,"_close_sqlcipher_base",paused_failure)
    closer=Thread(target=close_worker); closer.start(); assert entered.wait(5)
    opener=Thread(target=open_worker); opener.start()
    assert not open_done.wait(0.2)
    allow_failure.set(); closer.join(5); opener.join(5)
    assert not closer.is_alive() and not opener.is_alive()
    assert len(close_errors)==1 and "paused close failure" in str(close_errors[0])
    assert not returned and len(open_errors)==1
    assert "prior SQLCipher close failed" in str(open_errors[0])
    db.close()

@pytest.mark.parametrize("replacement",("database","parent"))
def test_live_connection_revalidation_rejects_named_entry_drift(
    tmp_path:Path,replacement:str,
) -> None:
    path=_database_path(tmp_path); db=open_sqlcipher(path,KEY); parent=path.parent
    if replacement=="database":
        original=parent/"open-original.db"; path.rename(original)
        _regular(path,original.read_bytes())
    else:
        original_parent=parent.with_name("open-original-parent"); parent.rename(original_parent)
        parent.mkdir(mode=0o700); _regular(path,(original_parent/path.name).read_bytes())
    with pytest.raises(PermissionError,match="unsafe database path"):
        db.revalidate_storage_path()
    db.close()

def test_two_connections_share_canonical_wal_and_complete_concurrent_writes(tmp_path:Path) -> None:
    path=_database_path(tmp_path); first=open_sqlcipher(path,KEY); second=open_sqlcipher(path,KEY)
    first.execute("CREATE TABLE concurrent_writes(value INTEGER NOT NULL)")
    def write(connection,value):
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("INSERT INTO concurrent_writes VALUES (?)",(value,))
        connection.execute("COMMIT")
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda item:write(*item),((first,1),(second,2))))
    expected=os.fspath(path)
    assert first.execute("PRAGMA database_list").fetchone()[2]==expected
    assert second.execute("PRAGMA database_list").fetchone()[2]==expected
    assert Path(expected+"-wal").is_file() and Path(expected+"-shm").is_file()
    assert first.execute("SELECT count(*) FROM concurrent_writes").fetchone()[0]==2
    first.close(); second.close()

def test_closing_peer_does_not_cancel_holder_lock_for_subprocess(tmp_path:Path) -> None:
    path=_database_path(tmp_path); holder=open_sqlcipher(path,KEY); peer=open_sqlcipher(path,KEY)
    holder.execute("CREATE TABLE lock_probe(value INTEGER NOT NULL)")
    holder.execute("BEGIN IMMEDIATE"); holder.execute("INSERT INTO lock_probe VALUES (1)")
    peer.close()
    _contend(path,75)
    holder.execute("COMMIT")
    _contend(path,0)
    assert holder.execute("SELECT count(*) FROM lock_probe").fetchone()[0]==2
    holder.close()

def test_legitimate_close_and_reopen_never_assumes_sidecar_deletion(tmp_path:Path) -> None:
    path=_database_path(tmp_path); db=open_sqlcipher(path,KEY)
    db.execute("CREATE TABLE reopen_probe(value INTEGER NOT NULL)")
    db.execute("INSERT INTO reopen_probe VALUES (1)"); db.close()
    for suffix in ("-wal","-shm"):
        try: surviving=os.stat(os.fspath(path)+suffix,follow_symlinks=False)
        except FileNotFoundError: continue
        assert stat.S_ISREG(surviving.st_mode) and stat.S_IMODE(surviving.st_mode)==0o600
    reopened=open_sqlcipher(path,KEY)
    assert reopened.execute("SELECT value FROM reopen_probe").fetchone()==(1,)
    for suffix in ("-wal","-shm"):
        current=os.stat(os.fspath(path)+suffix,follow_symlinks=False)
        assert stat.S_ISREG(current.st_mode) and stat.S_IMODE(current.st_mode)==0o600
    reopened.close()

def test_probe_is_sanitized_and_records_driver_runtime(tmp_path:Path) -> None:
    value=probe_storage(_database_path(tmp_path),KEY).as_dict(); encoded=json.dumps(value)
    assert set(value)=={
        "operating_system","architecture","python","driver","sqlite","cipher",
        "open_flags","integrity_ok","mode",
    }
    assert value["driver"]=="sqlcipher3==0.6.2"
    assert value["sqlite"]==sqlcipher3.sqlite_version and value["cipher"]
    assert value["open_flags"]==SQLCIPHER_OPEN_FLAGS and value["integrity_ok"] is True
    assert value["mode"]=="0o600"
    assert "path" not in value and "key" not in value
    assert os.fspath(tmp_path) not in encoded and KEY.hex() not in encoded
```

- [ ] **Step 2: Run the red SQLCipher test**

Run: `uv run pytest tests/security/test_sqlcipher.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.adapters.sqlcipher.connection'`. If dependency installation itself fails on the target Intel Mac, stop and record the build error; do not implement a SQLite fallback.

- [ ] **Step 3: Implement the key-first connection and sanitized probe**

```python
# apps/core/src/tuntun_core/adapters/sqlcipher/connection.py
from dataclasses import dataclass
import os,stat
from pathlib import Path
from threading import Lock
from typing import Literal
from sqlcipher3 import dbapi2 as sqlcipher3
from tuntun_core.config.secure_paths import (
    OwnedDirectory,ensure_private_directory,open_owned_directory,
)

NOFOLLOW=os.O_NOFOLLOW
CREATE_FLAGS=os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NONBLOCK|NOFOLLOW
# Official SQLite value; sqlcipher3 0.6.2 does not export it.
# https://sqlite.org/c3ref/c_open_autoproxy.html
SQLITE_OPEN_NOFOLLOW=0x01000000
SQLCIPHER_OPEN_FLAGS=(
    sqlcipher3.SQLITE_OPEN_READWRITE
    |sqlcipher3.SQLITE_OPEN_FULLMUTEX
    |sqlcipher3.SQLITE_OPEN_PRIVATECACHE
    |SQLITE_OPEN_NOFOLLOW
)
_OPEN_LOCK=Lock()

def _reported_owner(name:str,value:os.stat_result) -> int: return value.st_uid
def _reported_device(name:str,value:os.stat_result) -> int: return value.st_dev

def _absolute_database_path(path:Path) -> Path:
    raw=os.fspath(path)
    if type(raw) is not str or "\x00" in raw or any(
        component in {".",".."} for component in raw.split(os.sep)
    ):
        raise PermissionError("unsafe database path")
    absolute=Path(os.path.abspath(raw))
    if absolute==Path("/") or absolute.name in {"",".",".."}:
        raise PermissionError("unsafe database path")
    return absolute

@dataclass(frozen=True,slots=True)
class FileIdentity:
    device:int; inode:int; owner:int; mode:int; links:int

    @classmethod
    def from_stat(cls,value:os.stat_result) -> "FileIdentity":
        return cls(
            value.st_dev,value.st_ino,value.st_uid,
            value.st_mode,value.st_nlink,
        )

def _require_file(parent:OwnedDirectory,name:str) -> FileIdentity:
    named=os.stat(name,dir_fd=parent.fd,follow_symlinks=False)
    if (
        not stat.S_ISREG(named.st_mode)
        or _reported_owner(name,named)!=os.geteuid() or named.st_nlink!=1
        or stat.S_IMODE(named.st_mode)!=0o600
        or _reported_device(name,named)!=parent.device
    ): raise PermissionError("unsafe database path")
    return FileIdentity.from_stat(named)

def _optional_file(parent:OwnedDirectory,name:str) -> FileIdentity|None:
    try: return _require_file(parent,name)
    except FileNotFoundError: return None

def _create_exclusive_main(parent:OwnedDirectory,name:str) -> FileIdentity:
    fd=os.open(name,CREATE_FLAGS,0o600,dir_fd=parent.fd)
    try:
        os.fchmod(fd,0o600); opened=os.fstat(fd); named=_require_file(parent,name)
        if (
            not stat.S_ISREG(opened.st_mode)
            or FileIdentity.from_stat(opened)!=named
        ): raise PermissionError("unsafe database path")
    finally:
        # Creation is allowed only before any reservation, and this close must
        # complete before sqlcipher3.connect can own a lock-bearing descriptor.
        os.close(fd)
    if _require_file(parent,name)!=named:
        raise PermissionError("unsafe database path")
    return named

@dataclass(slots=True)
class _RegistryState:
    main_identity:FileIdentity
    active:int=0
    initializing:int=0
    failed_closes:int=0

@dataclass(frozen=True,slots=True)
class RegistrySnapshot:
    main_identity:FileIdentity
    active:int
    initializing:int
    failed_closes:int

@dataclass(slots=True)
class _Reservation:
    path:Path
    main_identity:FileIdentity
    phase:Literal["initializing","active"]="initializing"
    failed_close:bool=False
    released:bool=False

_ACTIVE_DATABASES:dict[Path,_RegistryState]={}

def _registry_snapshot(path:Path) -> RegistrySnapshot|None:
    absolute=_absolute_database_path(path)
    with _OPEN_LOCK:
        state=_ACTIVE_DATABASES.get(absolute)
        if state is None: return None
        return RegistrySnapshot(
            state.main_identity,state.active,state.initializing,state.failed_closes,
        )

def _reserve_initializing(path:Path,identity:FileIdentity) -> _Reservation:
    state=_ACTIVE_DATABASES.get(path)
    if state is None:
        state=_RegistryState(identity); _ACTIVE_DATABASES[path]=state
    elif state.main_identity!=identity:
        raise PermissionError("unsafe database path")
    if state.failed_closes:
        raise RuntimeError("prior SQLCipher close failed; retry close or abort process")
    state.initializing+=1
    return _Reservation(path,identity)

def _publish_reservation(reservation:_Reservation) -> None:
    state=_ACTIVE_DATABASES[reservation.path]
    if reservation.phase!="initializing" or reservation.released:
        raise RuntimeError("invalid database reservation")
    state.initializing-=1; state.active+=1; reservation.phase="active"

def _mark_reservation_close_failed(reservation:_Reservation) -> None:
    if reservation.released or reservation.failed_close: return
    _ACTIVE_DATABASES[reservation.path].failed_closes+=1
    reservation.failed_close=True

def _remove_empty_registry(path:Path,state:_RegistryState) -> None:
    if state.active==state.initializing==state.failed_closes==0:
        del _ACTIVE_DATABASES[path]

def _rollback_reservation_after_close(reservation:_Reservation) -> None:
    state=_ACTIVE_DATABASES[reservation.path]
    if reservation.phase!="initializing" or reservation.released:
        raise RuntimeError("invalid database reservation")
    state.initializing-=1
    if reservation.failed_close: state.failed_closes-=1
    reservation.released=True; _remove_empty_registry(reservation.path,state)

def _release_reservation_after_close(reservation:_Reservation) -> None:
    state=_ACTIVE_DATABASES[reservation.path]
    if reservation.phase!="active" or reservation.released:
        raise RuntimeError("invalid database reservation")
    state.active-=1
    if reservation.failed_close: state.failed_closes-=1
    reservation.released=True; _remove_empty_registry(reservation.path,state)

@dataclass(slots=True)
class DatabasePathGuard:
    path:Path
    parent:OwnedDirectory
    main_identity:FileIdentity
    reservation:_Reservation
    sidecar_identities:tuple[tuple[str,FileIdentity],...]=()
    _registry_released:bool=False
    _closed:bool=False

    def qualify_materialized_sidecars(self) -> None:
        previous=dict(self.sidecar_identities); current=[]
        for suffix in ("-wal","-shm"):
            identity=_require_file(self.parent,self.path.name+suffix)
            if suffix in previous and previous[suffix]!=identity:
                raise PermissionError("unsafe database path")
            current.append((suffix,identity))
        self.sidecar_identities=tuple(current)

    def revalidate(self) -> None:
        if self._closed: raise PermissionError("unsafe database path")
        try:
            self.parent.revalidate()
            if _require_file(self.parent,self.path.name)!=self.main_identity:
                raise PermissionError("unsafe database path")
            for suffix,identity in self.sidecar_identities:
                if _require_file(self.parent,self.path.name+suffix)!=identity:
                    raise PermissionError("unsafe database path")
        except OSError as error:
            if isinstance(error,PermissionError): raise
            raise PermissionError("unsafe database path") from error

    def publish_locked(self) -> None:
        _publish_reservation(self.reservation)

    def mark_sqlcipher_close_failed_locked(self) -> None:
        _mark_reservation_close_failed(self.reservation)

    def _release_registry_after_sqlcipher_close_locked(self) -> None:
        if self._registry_released: return
        if self.reservation.phase=="initializing":
            _rollback_reservation_after_close(self.reservation)
        else:
            _release_reservation_after_close(self.reservation)
        self._registry_released=True

    def _close_parent_after_release(self) -> None:
        if not self._closed:
            self.parent.close(); self._closed=True

    def rollback_connect_failure_locked(self) -> None:
        # No returned SQLCipher handle exists: connect either was not called or
        # its failing constructor/deallocator completed before control returned.
        self._release_registry_after_sqlcipher_close_locked()
        self._close_parent_after_release()

def _open_qualified_database(path:Path) -> DatabasePathGuard:
    absolute=_absolute_database_path(path)
    registered=_ACTIVE_DATABASES.get(absolute)
    if registered is not None and registered.failed_closes:
        raise RuntimeError("prior SQLCipher close failed; retry close or abort process")
    identity=ensure_private_directory(absolute.parent)
    parent:OwnedDirectory|None=open_owned_directory(identity.path)
    try:
        assert parent is not None
        parent.revalidate()
        main=_optional_file(parent,absolute.name)
        if main is None:
            if registered is not None:
                raise PermissionError("unsafe database path")
            main=_create_exclusive_main(parent,absolute.name)
        elif registered is not None and registered.main_identity!=main:
            raise PermissionError("unsafe database path")
        sidecars=tuple(
            (suffix,value)
            for suffix in ("-wal","-shm")
            if (value:=_optional_file(parent,absolute.name+suffix)) is not None
        )
        reservation=_reserve_initializing(absolute,main)
        guard=DatabasePathGuard(absolute,parent,main,reservation,sidecars)
        parent=None
        return guard
    except OSError as error:
        if isinstance(error,PermissionError): raise
        raise PermissionError("unsafe database path") from error
    finally:
        if parent is not None: parent.close()

def qualified_database_identity(path:Path) -> tuple[int,int]:
    with _OPEN_LOCK:
        absolute=_absolute_database_path(path)
        identity=ensure_private_directory(absolute.parent)
        with open_owned_directory(identity.path) as parent:
            parent.revalidate(); main=_require_file(parent,absolute.name)
            registered=_ACTIVE_DATABASES.get(absolute)
            if registered is not None and registered.main_identity!=main:
                raise PermissionError("unsafe database path")
            return main.device,main.inode

class SQLCipherCleanupError(RuntimeError):
    def __init__(
        self,connection:sqlcipher3.Connection,
        initialization_error:BaseException,close_error:BaseException,
        guard:DatabasePathGuard|None,
    ) -> None:
        super().__init__("SQLCipher initialization failed and close failed; retry close or abort process")
        self.connection=connection
        self.guard=guard
        self.initialization_error=initialization_error
        self.close_error=close_error

class QualifiedSQLCipherConnection(sqlcipher3.Connection):
    _path_guard:DatabasePathGuard|None=None
    def _bind_path_guard(self,guard:DatabasePathGuard) -> None:
        if self._path_guard is not None: raise RuntimeError("path guard already bound")
        self._path_guard=guard
    def revalidate_storage_path(self) -> None:
        if self._path_guard is None: raise PermissionError("unsafe database path")
        self._path_guard.revalidate()
    def guarded_parent_descriptor(self) -> int:
        if self._path_guard is None: raise PermissionError("unsafe database path")
        return self._path_guard.parent.fd
    def storage_identities(
        self,
    ) -> tuple[FileIdentity,tuple[tuple[str,FileIdentity],...]]:
        if self._path_guard is None: raise PermissionError("unsafe database path")
        return self._path_guard.main_identity,self._path_guard.sidecar_identities
    def _close_sqlcipher_base(self) -> None: super().close()
    def _close_after_initialization_failure_locked(self) -> None:
        guard=self._path_guard
        if guard is None:
            self._close_sqlcipher_base(); return
        try: self._close_sqlcipher_base()
        except BaseException:
            guard.mark_sqlcipher_close_failed_locked()
            raise
        guard._release_registry_after_sqlcipher_close_locked()
        guard._close_parent_after_release()
        self._path_guard=None
    def close(self) -> None:
        guard=self._path_guard
        if guard is None:
            self._close_sqlcipher_base(); return
        with _OPEN_LOCK:
            try: self._close_sqlcipher_base()
            except BaseException:
                guard.mark_sqlcipher_close_failed_locked()
                raise
            guard._release_registry_after_sqlcipher_close_locked()
        guard._close_parent_after_release()
        self._path_guard=None
    def __del__(self) -> None:
        # Leak protection only. A failure becomes Python's unraisable cleanup
        # report; it never releases the reservation or parent out of order.
        if self._path_guard is not None: self.close()

_CHECKPOINTS=frozenset({
    "key_validation","keyed_read","wal_activation","sidecar_metadata","integrity",
})
def _initialization_checkpoint(name:str) -> None:
    if name not in _CHECKPOINTS: raise AssertionError("unknown initialization checkpoint")

def open_sqlcipher(path: Path, key: bytes) -> sqlcipher3.Connection:
    if len(key) != 32: raise ValueError("SQLCipher key must be exactly 32 bytes")
    if sqlcipher3.sqlite_version_info<(3,31,0):
        raise RuntimeError("bundled SQLite lacks SQLITE_OPEN_NOFOLLOW")
    with _OPEN_LOCK:
        guard=_open_qualified_database(path); connection=None
        try:
            guard.revalidate()  # immediately before the pathname reopen
            connection=sqlcipher3.connect(
                os.fspath(guard.path),
                isolation_level=None,
                check_same_thread=False,
                flags=SQLCIPHER_OPEN_FLAGS,
                factory=QualifiedSQLCipherConnection,
            )
            if not isinstance(connection,QualifiedSQLCipherConnection):
                raise RuntimeError("SQLCipher connection guard unavailable")
            connection._bind_path_guard(guard); guard=None
            connection.revalidate_storage_path()  # after connect, before key
            # This must remain the first SQL statement issued on the connection.
            connection.execute(f'PRAGMA key = "x\'{key.hex()}\'"')
            _initialization_checkpoint("key_validation")
            connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
            _initialization_checkpoint("keyed_read")
            version=connection.execute("PRAGMA cipher_version").fetchone()
            if version is None or not version[0]:
                raise RuntimeError("SQLCipher support is unavailable")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA secure_delete=ON")
            connection.execute("PRAGMA busy_timeout=5000")
            if connection.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower()!="wal":
                raise RuntimeError("SQLCipher WAL mode is unavailable")
            connection.execute("BEGIN IMMEDIATE"); connection.execute("ROLLBACK")
            _initialization_checkpoint("wal_activation")
            assert connection._path_guard is not None
            connection._path_guard.qualify_materialized_sidecars()
            _initialization_checkpoint("sidecar_metadata")
            connection.revalidate_storage_path()  # after keyed read/WAL setup
            listed=connection.execute("PRAGMA database_list").fetchall()
            assert connection._path_guard is not None
            expected=os.fspath(connection._path_guard.path)
            if [row[2] for row in listed if row[1]=="main"]!=[expected]:
                raise PermissionError("unsafe database path")
            integrity=connection.execute("PRAGMA cipher_integrity_check").fetchone()
            if integrity is None or integrity[0]!="ok":
                raise RuntimeError("SQLCipher integrity check failed")
            _initialization_checkpoint("integrity")
            connection._path_guard.publish_locked()
            return connection
        except BaseException as initialization_error:
            if connection is not None:
                try:
                    if isinstance(connection,QualifiedSQLCipherConnection):
                        connection._close_after_initialization_failure_locked()
                    else:
                        connection.close()
                except BaseException as close_error:
                    raise SQLCipherCleanupError(
                        connection,initialization_error,close_error,guard,
                    ) from close_error
            if guard is not None:
                guard.rollback_connect_failure_locked()
            raise
```

```python
# apps/core/src/tuntun_core/adapters/sqlcipher/probe.py
from dataclasses import asdict, dataclass
from pathlib import Path
import platform
from typing import cast
from sqlcipher3 import dbapi2 as sqlcipher3
from .connection import (
    SQLCIPHER_OPEN_FLAGS,QualifiedSQLCipherConnection,open_sqlcipher,
    qualified_database_identity,
)

@dataclass(frozen=True, slots=True)
class StorageProbe:
    operating_system:str; architecture:str; python:str; driver:str; sqlite:str
    cipher:str; open_flags:int; integrity_ok:bool; mode:str
    def as_dict(self) -> dict[str, object]: return asdict(self)
def probe_storage(path: Path, key: bytes) -> StorageProbe:
    db=cast(QualifiedSQLCipherConnection,open_sqlcipher(path,key))
    try:
        db.revalidate_storage_path(); qualified_database_identity(path)
        cipher=str(db.execute("PRAGMA cipher_version").fetchone()[0]); integrity=db.execute("PRAGMA cipher_integrity_check").fetchone()[0] == "ok"
        return StorageProbe(
            platform.platform(),platform.machine(),platform.python_version(),
            "sqlcipher3==0.6.2",sqlcipher3.sqlite_version,cipher,
            SQLCIPHER_OPEN_FLAGS,integrity,"0o600",
        )
    finally: db.close()
```

Implement the Typer command so `--json` prints `json.dumps(probe.as_dict(), sort_keys=True)` and never prints the path or key. It obtains the key from `MacOSKeychainSecretProvider.get("tuntun.database", "root-v1")`; tests call `probe_storage` directly with a synthetic key.

- [ ] **Step 4: Run the green SQLCipher gate and target-Mac probe**

Run: `uv run pytest tests/security/test_sqlcipher.py -q && uv run tuntunctl storage probe --path var/probe/foundation.db --json`

Expected: PASS in both exact Task 2 CI jobs, `ubuntu-24.04` and `macos-15-intel`, against the pinned wheel and its bundled SQLite, with no platform skip. The behavior gate proves the ordinary absolute database name and exact `READWRITE|FULLMUTEX|PRIVATECACHE|NOFOLLOW` flags, omission of `CREATE`/URI/custom VFS, and key as the first SQL statement; a direct pinned-driver test also proves those flags reject both ancestor and final symlinks on each runner. Every ancestor/final symlink; main or pre-existing WAL/SHM special file, wrong owner/mode, hard link, or device mismatch; and one-way database/parent replacement fails closed. Unsafe sidecar cases begin with a fresh, never-opened exclusive empty main and assert absent sidecars plus the intended malicious entry before calling the adapter. Newly materialized WAL/SHM are exact metadata-qualified siblings; only the parent-directory FD survives initialization; immutable main/sidecar identities back revalidation; and opening/closing a second connection performs no adapter open/close of the main/WAL/SHM inodes. Tests prove the creation FD closes before reservation/connect; base-close → registry release/rollback → parent-close ordering; an initialization-cleanup close failure retains its initializing reservation/parent until retry while preserving the healthy peer; an explicit active close failure likewise retains its lease and blocks new return; a barrier-paused failing close cannot race a newly returned connection before the failed state is published; healthy-peer usability after each injected initialization failure; successful open and all five cleanup checkpoints finish inside a subprocess deadline without recursive-lock deadlock; positive close/reopen without deleting or assuming deletion of legitimate sidecars; two-connection WAL concurrency; and the subprocess lock regression while one connection holds `BEGIN IMMEDIATE`. The same lock regression and all other tests run on both hosted platforms. The minimum bundled-SQLite check is necessary but does not replace these behavior tests. Probe JSON has `"driver":"sqlcipher3==0.6.2"`, the exact bundled `sqlite`, non-empty `cipher`, exact numeric `open_flags`, `"integrity_ok":true`, and `"mode":"0o600"`; it contains no username, absolute path, or key material.

Run the shown encrypted CLI probe again on the actual household Intel Mac before accepting the stop/go checkpoint. Record its exact sanitized JSON, macOS/Intel architecture, Python, `sqlcipher3==0.6.2`, bundled SQLite and cipher versions, numeric flags, `uv.lock` SHA-256, date, and PASS decision in `docs/operations/sqlcipher-compatibility.md`; record the Ubuntu CI result beside it. Also document that WAL/SHM are SQLCipher-managed same-directory sidecars, maintenance checkpoints WAL before backup, startup refuses missing/wrong keys or failed cipher integrity, and the local open lock prevents only cooperative races inside one process. Production startup must acquire the application's later lifecycle-owned singleton-instance lock before storage open, but that later lock is not invented or claimed by this Foundation task.

The compatibility document must state the residual exactly: the DB-API receives a pathname, not a qualified main-file FD. The retained parent-directory FD, immutable no-follow metadata identities, registry, and bracket checks detect stale entries and one-way/non-ABA substitutions, while SQLite `NOFOLLOW` rejects symlink components. They do not defeat a hostile same-EUID/root process that can perform an undetectable swap-and-restore between checks or access process memory/key material. The document must also state that SQLCipher alone owns lock-bearing main/WAL/SHM descriptors and that adapter close ordering prevents external descriptor closes from canceling a healthy peer's POSIX locks. Do not claim descriptor-relative SQLite open or perfect inode binding. If protection from that attacker becomes mandatory, stop and require a native registered VFS/driver with an actual file-handle API.

- [ ] **Step 5: Commit exact Task 11 paths after the target-Mac gate passes**

```bash
git status --short
git add apps/core/pyproject.toml uv.lock apps/core/src/tuntun_core/adapters/sqlcipher/connection.py apps/core/src/tuntun_core/adapters/sqlcipher/probe.py apps/core/src/tuntun_core/cli/commands/storage_probe.py apps/core/src/tuntun_core/cli/main.py tests/security/test_sqlcipher.py docs/operations/sqlcipher-compatibility.md
git diff --cached --name-only
git diff --cached
git commit -m "feat(storage): verify SQLCipher compatibility"
```

### Task 12: Implement purpose-bound record encryption and nonce-reuse defense

**Master package:** 05
**Depends on:** Tasks 4 and 11.
**Estimated effort:** 0.5 person-day.

**Files:**
- Create: `apps/core/src/tuntun_core/adapters/sqlcipher/crypto.py`
- Test: `tests/security/test_record_crypto.py`

**Interfaces:**
- Consumes: 32-byte purpose-specific root key; Task 4 `canonical_mapping_bytes`; and frozen `RecordContext(household_id, table, row_id, purpose, schema_version)` whose `table` is exactly `biometric_templates|memory_embeddings|recovery_sensitive_values`, whose `purpose` is exactly `face-template|voice-template|memory-embedding|recovery-sensitive`, whose table/purpose pair is valid, and whose schema version is exactly `1.0`.
- Produces: `RecordCipher.encrypt(plaintext: bytes, context: RecordContext) -> EncryptedRecord`, `RecordCipher.decrypt(record: EncryptedRecord, context: RecordContext) -> bytes`; random 32-byte DEK, distinct random 96-bit data/wrap nonces, AES-256-GCM, and Task 4 canonical NFC associated data with closed domain `record-data|dek-wrap`. One reuse set spans both AES-GCM key domains, so a repeated nonce is rejected before either encryption call that would consume it.

- [ ] **Step 1: Write red round-trip, binding, and duplicate-nonce tests**

```python
# tests/security/test_record_crypto.py
from uuid import UUID
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import ValidationError
from tuntun_core.adapters.sqlcipher.crypto import RecordCipher, RecordContext

CTX=RecordContext(
    household_id=UUID(int=1),table="biometric_templates",row_id=UUID(int=2),
    purpose="voice-template",schema_version="1.0",
)
def test_record_round_trip_and_context_binding() -> None:
    cipher=RecordCipher(bytes(range(32)))
    encrypted=cipher.encrypt(b"private-template-sentinel", CTX)
    assert b"private-template-sentinel" not in encrypted.ciphertext
    assert cipher.decrypt(encrypted, CTX) == b"private-template-sentinel"
    other_contexts=(
        RecordContext.model_validate(CTX.model_dump() | {"household_id":UUID(int=9)}),
        RecordContext.model_validate(CTX.model_dump() | {"row_id":UUID(int=3)}),
        RecordContext.model_validate(CTX.model_dump() | {"purpose":"face-template"}),
        RecordContext(household_id=UUID(int=1),table="memory_embeddings",row_id=UUID(int=2),purpose="memory-embedding",schema_version="1.0"),
    )
    for other in other_contexts:
        with pytest.raises(InvalidTag): cipher.decrypt(encrypted, other)

def test_record_context_is_closed_nfc_normalized_and_canonical() -> None:
    assert CTX.associated_data("record-data") == (
        b'{"domain":"record-data","household_id":"00000000-0000-0000-0000-000000000001",'
        b'"purpose":"voice-template","row_id":"00000000-0000-0000-0000-000000000002",'
        b'"schema_version":"1.0","table":"biometric_templates"}'
    )
    with pytest.raises(ValueError, match="associated-data domain"):
        CTX.associated_data("caller-authored")
    for hostile in (
        {"purpose":"voice-te\u0301mplate"},
        {"purpose":"status"},
        {"table":"biometric_templates-extra"},
        {"schema_version":"1.1"},
        {"extra":"caller-authored-aad"},
        {"table":"memory_embeddings","purpose":"voice-template"},
    ):
        with pytest.raises(ValidationError):
            RecordContext.model_validate(CTX.model_dump() | hostile)

def test_nonce_reuse_is_rejected_before_second_encryption(monkeypatch) -> None:
    scripted=iter((b"D"*12,b"W"*12,b"D"*12,b"X"*12))
    encrypt_calls=[]; original=AESGCM.encrypt
    def tracking_encrypt(self,nonce,data,aad):
        encrypt_calls.append(nonce); return original(self,nonce,data,aad)
    monkeypatch.setattr(AESGCM,"encrypt",tracking_encrypt)
    cipher=RecordCipher(bytes(range(32)), nonce_source=lambda: next(scripted))
    cipher.encrypt(b"first", CTX)
    with pytest.raises(RuntimeError, match="nonce reuse detected"): cipher.encrypt(b"second", CTX)
    assert encrypt_calls == [b"D"*12,b"W"*12]
```

- [ ] **Step 2: Run the red record-crypto test**

Run: `uv run pytest tests/security/test_record_crypto.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.adapters.sqlcipher.crypto'`.

- [ ] **Step 3: Implement envelope encryption with exact associated data**

```python
# apps/core/src/tuntun_core/adapters/sqlcipher/crypto.py
import os
from dataclasses import dataclass
from typing import Callable, Literal
from uuid import UUID
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import model_validator
from tuntun_contracts.base import ContractModel, canonical_mapping_bytes

class RecordContext(ContractModel):
    household_id: UUID
    table: Literal["biometric_templates","memory_embeddings","recovery_sensitive_values"]
    row_id: UUID
    purpose: Literal["face-template","voice-template","memory-embedding","recovery-sensitive"]
    schema_version: Literal["1.0"]
    @model_validator(mode="after")
    def exact_table_purpose(self) -> "RecordContext":
        allowed={
            "biometric_templates":{"face-template","voice-template"},
            "memory_embeddings":{"memory-embedding"},
            "recovery_sensitive_values":{"recovery-sensitive"},
        }
        if self.purpose not in allowed[self.table]:
            raise ValueError("record table/purpose mismatch")
        return self
    def associated_data(self,domain:Literal["record-data","dek-wrap"]) -> bytes:
        if domain not in {"record-data","dek-wrap"}:
            raise ValueError("unknown associated-data domain")
        return canonical_mapping_bytes({"domain":domain,**self.model_dump(mode="python")})
@dataclass(frozen=True, slots=True)
class EncryptedRecord:
    ciphertext: bytes; nonce: bytes; wrapped_dek: bytes; wrap_nonce: bytes; root_key_id: str

class RecordCipher:
    def __init__(self, root_key: bytes, root_key_id: str="records-v1", nonce_source: Callable[[], bytes] | None=None) -> None:
        if len(root_key) != 32: raise ValueError("record root key must be 32 bytes")
        self._root=AESGCM(root_key); self._root_key_id=root_key_id; self._nonce_source=nonce_source or (lambda: os.urandom(12)); self._used: set[bytes]=set()
    def _nonce(self) -> bytes:
        nonce=self._nonce_source()
        if len(nonce) != 12: raise ValueError("AES-GCM nonce must be 12 bytes")
        if nonce in self._used: raise RuntimeError("nonce reuse detected")
        self._used.add(nonce); return nonce
    def encrypt(self, plaintext: bytes, context: RecordContext) -> EncryptedRecord:
        dek=os.urandom(32)
        nonce=self._nonce(); wrap_nonce=self._nonce()
        data_aad=context.associated_data("record-data")
        wrap_aad=context.associated_data("dek-wrap")
        return EncryptedRecord(AESGCM(dek).encrypt(nonce,plaintext,data_aad),nonce,self._root.encrypt(wrap_nonce,dek,wrap_aad),wrap_nonce,self._root_key_id)
    def decrypt(self, record: EncryptedRecord, context: RecordContext) -> bytes:
        if record.root_key_id != self._root_key_id: raise ValueError("record root key id mismatch")
        dek=self._root.decrypt(record.wrap_nonce,record.wrapped_dek,context.associated_data("dek-wrap"))
        return AESGCM(dek).decrypt(record.nonce,record.ciphertext,context.associated_data("record-data"))
```

- [ ] **Step 4: Run the green record-crypto gate**

Run: `uv run pytest tests/security/test_record_crypto.py -q && uv run ruff check apps/core/src/tuntun_core/adapters/sqlcipher/crypto.py tests/security/test_record_crypto.py && uv run mypy apps/core/src/tuntun_core/adapters/sqlcipher/crypto.py`

Expected: PASS with three tests and zero Ruff/mypy errors. The first encryption consumes distinct data/wrap nonces; the repeated data nonce on the second call is rejected before `AESGCM.encrypt`. Hostile extra/unknown/non-NFC context values fail validation, the golden AAD is Task 4 canonical NFC bytes, and changing any valid context identity fails authentication.

- [ ] **Step 5: Commit exact Task 12 paths**

```bash
git status --short
git add apps/core/src/tuntun_core/adapters/sqlcipher/crypto.py tests/security/test_record_crypto.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(storage): add purpose-bound record encryption"
```

### Task 13: Create the exact foundation metadata and reversible `0001` migration

**Master package:** 06
**Depends on:** Tasks 11 and 12.
**Estimated effort:** 1.5 person-days.

**Files:**
- Modify: `apps/core/pyproject.toml`
- Modify: `uv.lock`
- Create: `apps/core/src/tuntun_core/adapters/sqlcipher/foundation_0001.py`
- Create: `apps/core/src/tuntun_core/adapters/sqlcipher/models.py`
- Create: `apps/core/src/tuntun_core/adapters/sqlcipher/engine.py`
- Create: `apps/core/src/tuntun_core/adapters/sqlcipher/migrations.py`
- Create: `apps/core/migrations/env.py`
- Create: `apps/core/migrations/script.py.mako`
- Create: `apps/core/migrations/versions/0001_foundation.py`
- Create: `apps/core/alembic.ini`
- Create: `tests/integration/storage/conftest.py`
- Test: `tests/integration/storage/test_migrations.py`

**Interfaces:**
- Consumes: `open_sqlcipher(path, key)` from Task 11.
- Produces: immutable revision-scoped `FOUNDATION_0001_METADATA` and `FOUNDATION_TABLE_NAMES: frozenset[str]` in `foundation_0001.py`; extensible application `models.metadata` created by copying only that frozen collection before future tables are declared; `create_sqlcipher_engine(path: Path, key: bytes) -> Engine`; `encrypted_backup(source: Path, destination: Path, key: bytes) -> None`; `upgrade_encrypted(path: Path, key: bytes, backup: Path | None) -> None`; Alembic revision `0001_foundation`, down revision `None`. Revision 0001 imports only `FOUNDATION_0001_METADATA`, never live application metadata; upgrade/drop therefore remain the exact frozen 16-table snapshot after later metadata grows.
- Migration owns exactly 16 application tables: `households`, `devices`, `sessions`, `event_receipts`, `idempotency_receipts`, `audit_receipts`, `audit_segments`, `redaction_receipts`, `provider_calls`, `provider_response_receipts`, `provider_prices`, `budget_reservations`, `cost_ledger`, `runtime_settings`, and the reserved content-free `reachy_core_tx_sequences|reachy_duplex_correlations` tables required by the later duplex repository task without a future-migration dependency. The complete post-upgrade table inventory is those 16 plus Alembic's `alembic_version`, for exactly 17 non-`sqlite_` tables.
- `request_id` groups all attempts for one logical STT/reasoning/TTS/web-search request. `attempt_id` is the unique idempotency boundary for both `budget_reservations` and `provider_calls`; every retry receives a new attempt, authorization, and reservation while retaining its logical request ID. The `(month_key, state, reserved_micros_sgd, charged_micros_sgd)` index supports the `BEGIN IMMEDIATE` atomic monthly sum: use immutable reserved cost for `reserved|sent`, authoritative charged cost for `settled`, and exclude `released|denied`.
- Budget pricing persistence is authoritative and bounded. `provider_prices` keys one exact provider/model/category/pricing-version/FX-version/tier-basis/tier-range record and stores input/output per-million, audio per-minute, and web-search per-call micro-USD rates; the closed primary accounting basis and missing-evidence policy; FX; both immutable version strings; the exact bounded HTTPS price-source URL; and both lowercase SHA-256 source digests. `tier_basis='flat'` requires the canonical `0,0` range; `tier_basis='llm_input_tokens'` is allowed only for LLM input-token ranges bounded by `0..10_000_000`. The catalog must reject overlapping, gapped, mixed-version, mixed-source-URL/digest, mixed-validity, or incomplete tier schedules before any row becomes current. Every signed reservation snapshot carries the complete schedule: reservation chooses the highest applicable rate for its signed input-token ceiling, while exact settlement reselects the tier from the verified provider input-token receipt and never applies a cheaper ceiling tier after a boundary crossing. TTS is `request_bound_exact` with no fabricated response usage. Web search is `provider_reported_exact`, reserves exactly one fixed tool call plus token ceilings, and alone permits `conservative_full_reservation` when missing evidence remains provably within that one-call ceiling. One allowed quote is in `1..1_000_000_000_000` micro-SGD; every denied row stores zero. Checked aggregate arithmetic is limited to `0..9_000_000_000_000_000`; overflow or an out-of-range result fails closed, freezes cloud egress, and requires owner repair.
- Every reservation stores the closed usage ceiling plus an immutable price snapshot, accounting basis, missing-evidence policy, and purpose-specific HMAC. That complete quote/policy group is all-null only for `deny_unknown_price|deny_cloud_egress_frozen`; it is all-non-null for `allow|allow_soft_warning|deny_hard_limit`. `deny_hard_limit` retains the complete projected quote but reserves zero. `charged_micros_sgd` is null unless state is `settled`, `estimate_overrun` is exact truth for `charged > reserved`, and the reservation amount is never overwritten during settlement.
- Budget proof persistence is exact: both reservation and provider-call rows store `gateway_ordering_version` plus the closed `transport_phase`; reservations also store `reconciled_at`, and `cost_ledger.month_key` copies the immutable Singapore month from the reservation. A provider call's nullable usage triple is all-or-none and contains the one authoritative full canonical `ProviderUsageReceiptV1` sealed union (`stt|llm|tts|web_search`) plus its locally verified receipt key/HMAC. The ledger repeats the immutable quote versions/digests and reserved/charged amounts, persists `accounting_basis` and the verified billable-unit/receipt evidence when present, and carries exact conservative-estimate, overrun, and hard-cap-exceeded booleans. The conversation budget task owns the only repository transitions over these foundation columns and the durable monthly cloud-egress freeze/owner-alert record.

- [ ] **Step 1: Write the red upgrade/downgrade ownership test**

```python
# tests/integration/storage/test_migrations.py
import json
from pathlib import Path
import sqlite3
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Column,Engine,Integer,Table
from tuntun_core.adapters.sqlcipher.models import metadata
from tuntun_core.adapters.sqlcipher.connection import open_sqlcipher

EXPECTED={"alembic_version","households","devices","sessions","event_receipts","idempotency_receipts","audit_receipts","audit_segments","redaction_receipts","provider_calls","provider_response_receipts","provider_prices","budget_reservations","cost_ledger","runtime_settings","reachy_core_tx_sequences","reachy_duplex_correlations"}
assert len(EXPECTED)==17

def _config(path: Path, key: bytes) -> Config:
    config=Config("apps/core/alembic.ini"); config.set_main_option("sqlalchemy.url", f"sqlite:///{path}")
    config.attributes["sqlcipher_path"]=path; config.attributes["sqlcipher_key"]=key
    return config

def test_foundation_upgrade_downgrade_upgrade(tmp_path: Path) -> None:
    path=tmp_path/"foundation.db"; key=bytes(range(32)); config=_config(path,key)
    command.upgrade(config,"0001_foundation")
    db=open_sqlcipher(path,key); names={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'") if not row[0].startswith("sqlite_")}
    assert names == EXPECTED
    triggers={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    assert triggers == {"audit_receipts_no_update","audit_receipts_no_delete"}; db.close()
    command.downgrade(config,"base")
    db=open_sqlcipher(path,key); assert {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'") if not row[0].startswith("sqlite_")} == {"alembic_version"}; db.close()
    command.upgrade(config,"head")

def test_revision_0001_ignores_tables_added_to_future_application_metadata(
    tmp_path:Path,
) -> None:
    future=Table("future_phase_table",metadata,Column("id",Integer,primary_key=True))
    try:
        path=tmp_path/"frozen-0001.db"; key=bytes(range(32))
        command.upgrade(_config(path,key),"0001_foundation")
        db=open_sqlcipher(path,key)
        names={row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ) if not row[0].startswith("sqlite_")}
        db.close(); assert names==EXPECTED
    finally: metadata.remove(future)

def test_revision_source_uses_only_its_frozen_table_collection() -> None:
    from tuntun_core.adapters.sqlcipher.foundation_0001 import (
        FOUNDATION_0001_METADATA,FOUNDATION_TABLE_NAMES,
    )
    source=Path("apps/core/migrations/versions/0001_foundation.py").read_text()
    assert "adapters.sqlcipher.models" not in source
    assert "adapters.sqlcipher.foundation_0001" in source
    assert set(FOUNDATION_0001_METADATA.tables)==FOUNDATION_TABLE_NAMES

def test_existing_database_is_backed_up_encrypted_before_upgrade(tmp_path: Path) -> None:
    source=tmp_path/"source.db"; backup=tmp_path/"backup.db"; key=bytes(range(32)); config=_config(source,key)
    command.upgrade(config,"head")
    from tuntun_core.adapters.sqlcipher.migrations import upgrade_encrypted
    upgrade_encrypted(source,key,backup)
    assert backup.is_file() and not backup.read_bytes().startswith(b"SQLite format 3\x00")
    with pytest.raises(sqlite3.DatabaseError): sqlite3.connect(backup).execute("SELECT name FROM sqlite_master").fetchall()

def test_budget_and_provider_attempt_ids_are_the_idempotency_boundary(tmp_path: Path) -> None:
    path=tmp_path/"attempts.db"; key=bytes(range(32)); command.upgrade(_config(path,key),"head")
    db=open_sqlcipher(path,key); request_id="00000000-0000-0000-0000-000000000010"
    budget_sql="INSERT INTO budget_reservations (id,request_id,attempt_id,month_key,category,provider,model,outcome,reserved_micros_sgd,charged_micros_sgd,usage_ceiling_json,price_snapshot_json,primary_accounting_basis,missing_evidence_policy,pricing_version,price_source_sha256,fx_version,fx_source_sha256,pricing_commitment_key_id,pricing_commitment_hmac_b64,estimate_overrun,state,gateway_ordering_version,transport_phase,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    base=("2026-08","llm","openai","gpt-5.6-sol","allow",100,None,json.dumps({"category":"llm","input_tokens":10,"output_tokens":10}),json.dumps({"provider":"openai","model":"gpt-5.6-sol"}),"provider_reported_exact","freeze_unknown_overage","openai-2026-08-27","a"*64,"bootstrap-safety-factor-2026-08-27","b"*64,"pricing-v1","A"*43+"=",0,"reserved",1,"not_claimed","2026-08-27T01:02:03.000004Z","2026-08-27T01:03:03.000004Z")
    db.execute(budget_sql,("00000000-0000-0000-0000-000000000001",request_id,"00000000-0000-0000-0000-000000000101",*base))
    db.execute(budget_sql,("00000000-0000-0000-0000-000000000002",request_id,"00000000-0000-0000-0000-000000000102",*base))
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(budget_sql,("00000000-0000-0000-0000-000000000003",request_id,"00000000-0000-0000-0000-000000000102",*base))
    call_sql="INSERT INTO provider_calls (id,request_id,attempt_id,authorization_id,budget_reservation_id,purpose,provider,model,request_hmac_key_id,request_hmac_b64,category,outcome,gateway_ordering_version,transport_phase,started_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    call_base=(request_id,"cloud_reasoning","openai","gpt-5.6-sol","provider-request-v1","A"*43+"=","llm","started",1,"claim_begun","2026-08-27T01:02:03.000004Z")
    db.execute(call_sql,("00000000-0000-0000-0000-000000000201",request_id,"00000000-0000-0000-0000-000000000101","00000000-0000-0000-0000-000000000301","00000000-0000-0000-0000-000000000001",*call_base[1:]))
    db.execute(call_sql,("00000000-0000-0000-0000-000000000202",request_id,"00000000-0000-0000-0000-000000000102","00000000-0000-0000-0000-000000000302","00000000-0000-0000-0000-000000000002",*call_base[1:]))
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(call_sql,("00000000-0000-0000-0000-000000000203",request_id,"00000000-0000-0000-0000-000000000102","00000000-0000-0000-0000-000000000303","00000000-0000-0000-0000-000000000002",*call_base[1:]))
    indexes={row[1] for row in db.execute("PRAGMA index_list('budget_reservations')")}
    assert "ix_budget_month_state_cost" in indexes
    assert "ix_provider_calls_request" in {row[1] for row in db.execute("PRAGMA index_list('provider_calls')")}
    db.close()


def test_authoritative_budget_quote_usage_and_overrun_columns_are_migrated(tmp_path: Path) -> None:
    path=tmp_path/"proof.db"; key=bytes(range(32)); command.upgrade(_config(path,key),"head")
    db=open_sqlcipher(path,key)
    columns=lambda table: {row[1]: row for row in db.execute(f"PRAGMA table_info('{table}')")}
    prices=columns("provider_prices"); reservations=columns("budget_reservations")
    calls=columns("provider_calls"); ledger=columns("cost_ledger")
    assert {"provider","tier_basis","tier_min_input_tokens","tier_max_input_tokens","input_micro_usd_per_million","output_micro_usd_per_million","audio_micro_usd_per_minute","web_search_micro_usd_per_call","primary_accounting_basis","missing_evidence_policy","pricing_version","price_source_url","price_source_sha256","fx_version","fx_source_sha256"} <= set(prices)
    assert {"reserved_micros_sgd","charged_micros_sgd","usage_ceiling_json","price_snapshot_json","primary_accounting_basis","missing_evidence_policy","pricing_version","price_source_sha256","fx_version","fx_source_sha256","pricing_commitment_key_id","pricing_commitment_hmac_b64","estimate_overrun","gateway_ordering_version","transport_phase","reconciled_at"} <= set(reservations)
    assert {"provider_usage_json","provider_usage_receipt_key_id","provider_usage_receipt_hmac_b64","gateway_ordering_version","transport_phase"} <= set(calls)
    assert {"month_key","reserved_micros_sgd","charged_micros_sgd","provider_usage_receipt_json","provider_usage_receipt_key_id","provider_usage_receipt_hmac_b64","accounting_basis","conservative_estimate_used","estimate_overrun","hard_cap_exceeded","pricing_version","price_source_sha256","fx_version","fx_source_sha256"} <= set(ledger)
    assert all(reservations[name][3] == 1 for name in ("reserved_micros_sgd","usage_ceiling_json","estimate_overrun","gateway_ordering_version","transport_phase"))
    assert all(calls[name][3] == 0 for name in ("provider_usage_json","provider_usage_receipt_key_id","provider_usage_receipt_hmac_b64"))
    assert all(ledger[name][3] == 1 for name in ("month_key","reserved_micros_sgd","charged_micros_sgd","conservative_estimate_used","estimate_overrun","hard_cap_exceeded"))
    db.close()


def test_budget_schema_rejects_unbounded_prices_partial_proofs_and_false_overrun(tmp_path: Path) -> None:
    path=tmp_path/"budget-constraints.db"; key=bytes(range(32)); command.upgrade(_config(path,key),"head")
    db=open_sqlcipher(path,key)
    price_sql="""INSERT INTO provider_prices
        (id,provider,model,category,native_currency,tier_basis,
         tier_min_input_tokens,tier_max_input_tokens,input_micro_usd_per_million,
         output_micro_usd_per_million,audio_micro_usd_per_minute,
         web_search_micro_usd_per_call,primary_accounting_basis,
         missing_evidence_policy,fx_micros_sgd,pricing_version,price_source_url,
         price_source_sha256,fx_version,fx_source_sha256,effective_at,expires_at)
        VALUES (:id,:provider,:model,:category,:currency,:tier_basis,:tier_min,:tier_max,:input_rate,:output_rate,
         :audio_rate,:search_rate,:basis,:missing_policy,:fx_rate,:pricing_version,:source_url,
         :price_sha,:fx_version,:fx_sha,:effective_at,:expires_at)"""
    valid_price={
        "id":"00000000-0000-0000-0000-000000000401","provider":"openai",
        "model":"gpt-5.6-sol","category":"llm","currency":"USD",
        "tier_basis":"flat","tier_min":0,"tier_max":0,
        "input_rate":4_000_000,"output_rate":20_000_000,"audio_rate":0,
        "search_rate":0,"basis":"provider_reported_exact",
        "missing_policy":"freeze_unknown_overage","fx_rate":1_500_000,
        "pricing_version":"openai-2026-08-27",
        "source_url":"https://developers.openai.com/api/docs/pricing",
        "price_sha":"a"*64,
        "fx_version":"bootstrap-safety-factor-2026-08-27","fx_sha":"b"*64,
        "effective_at":"2026-08-27T00:00:00.000000Z",
        "expires_at":"2026-09-27T00:00:00.000000Z",
    }
    db.execute(price_sql,valid_price)
    invalid_prices=(
        valid_price|{"id":"00000000-0000-0000-0000-000000000402","price_sha":"A"*64},
        valid_price|{"id":"00000000-0000-0000-0000-000000000403","input_rate":1_000_000_001},
        valid_price|{"id":"00000000-0000-0000-0000-000000000404","effective_at":valid_price["expires_at"],"expires_at":valid_price["effective_at"]},
        valid_price|{"id":"00000000-0000-0000-0000-000000000405","basis":"request_bound_exact"},
        valid_price|{"id":"00000000-0000-0000-0000-000000000406","missing_policy":"conservative_full_reservation"},
        valid_price|{"id":"00000000-0000-0000-0000-000000000409","audio_rate":1},
        valid_price|{"id":"00000000-0000-0000-0000-000000000413","tier_basis":"flat","tier_max":1},
        valid_price|{"id":"00000000-0000-0000-0000-000000000414","tier_basis":"llm_input_tokens","tier_min":256_001,"tier_max":256_000},
        valid_price|{"id":"00000000-0000-0000-0000-000000000418","source_url":"http://127.0.0.1/price"},
    )
    for invalid in invalid_prices:
        with pytest.raises(sqlite3.IntegrityError): db.execute(price_sql,invalid)
    tts_price=valid_price|{
        "id":"00000000-0000-0000-0000-000000000407","model":"tts-1",
        "category":"tts","input_rate":15_000_000,"output_rate":0,
        "basis":"request_bound_exact",
    }
    db.execute(price_sql,tts_price)
    search_price=valid_price|{
        "id":"00000000-0000-0000-0000-000000000408",
        "category":"web_search","search_rate":10_000,
        "missing_policy":"conservative_full_reservation",
        "pricing_version":"openai-web-search-2026-08-27",
    }
    db.execute(price_sql,search_price)
    for suffix,field in (("410","input_rate"),("411","output_rate"),("412","search_rate")):
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(price_sql,search_price|{
                "id":f"00000000-0000-0000-0000-000000000{suffix}",field:0,
            })
    qwen_low=valid_price|{
        "id":"00000000-0000-0000-0000-000000000415","provider":"qwen",
        "model":"qwen3.7-plus","pricing_version":"qwen3.7-plus-sg-2026-08-28",
        "source_url":"https://www.alibabacloud.com/help/en/model-studio/model-pricing",
        "tier_basis":"llm_input_tokens","tier_min":0,"tier_max":256_000,
        "input_rate":400_000,"output_rate":1_600_000,
    }
    qwen_high=qwen_low|{
        "id":"00000000-0000-0000-0000-000000000416",
        "tier_min":256_001,"tier_max":1_000_000,
        "input_rate":1_200_000,"output_rate":4_800_000,
    }
    db.execute(price_sql,qwen_low); db.execute(price_sql,qwen_high)
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(price_sql,qwen_low|{"id":"00000000-0000-0000-0000-000000000417"})

    reservation_sql="""INSERT INTO budget_reservations
        (id,request_id,attempt_id,month_key,category,provider,model,outcome,reserved_micros_sgd,
         charged_micros_sgd,usage_ceiling_json,price_snapshot_json,pricing_version,price_source_sha256,
         primary_accounting_basis,missing_evidence_policy,fx_version,fx_source_sha256,
         pricing_commitment_key_id,pricing_commitment_hmac_b64,
         estimate_overrun,state,gateway_ordering_version,transport_phase,created_at,expires_at)
        VALUES (:id,:request_id,:attempt_id,:month_key,:category,:provider,:model,:outcome,:reserved,
         :charged,:usage,:snapshot,:pricing_version,:price_sha,:basis,:missing_policy,
         :fx_version,:fx_sha,:commitment_key,
         :commitment_hmac,:overrun,:state,1,:phase,:created_at,:expires_at)"""
    quoted={
        "id":"00000000-0000-0000-0000-000000000501","request_id":"00000000-0000-0000-0000-000000000502",
        "attempt_id":"00000000-0000-0000-0000-000000000503","month_key":"2026-08","category":"llm",
        "provider":"openai","model":"gpt-5.6-sol","outcome":"allow","reserved":100,"charged":None,
        "usage":json.dumps({"category":"llm","input_tokens":10,"output_tokens":5}),
        "snapshot":json.dumps({"provider":"openai","pricing_version":"openai-2026-08-27"}),
        "pricing_version":"openai-2026-08-27","price_sha":"a"*64,
        "basis":"provider_reported_exact","missing_policy":"freeze_unknown_overage",
        "fx_version":"bootstrap-safety-factor-2026-08-27","fx_sha":"b"*64,
        "commitment_key":"pricing-v1","commitment_hmac":"A"*43+"=","overrun":0,"state":"reserved",
        "phase":"not_claimed","created_at":"2026-08-27T01:02:03.000004Z","expires_at":"2026-08-27T01:17:03.000004Z",
    }
    with pytest.raises(sqlite3.IntegrityError): db.execute(reservation_sql,quoted|{"snapshot":None})
    with pytest.raises(sqlite3.IntegrityError): db.execute(reservation_sql,quoted|{"basis":None})
    with pytest.raises(sqlite3.IntegrityError): db.execute(reservation_sql,quoted|{"reserved":1_000_000_000_001})
    with pytest.raises(sqlite3.IntegrityError): db.execute(reservation_sql,quoted|{"state":"settled","charged":None})
    db.execute(reservation_sql,quoted)
    denied=quoted|{
        "id":"00000000-0000-0000-0000-000000000504","attempt_id":"00000000-0000-0000-0000-000000000505",
        "outcome":"deny_unknown_price","reserved":0,"snapshot":None,"pricing_version":None,"price_sha":None,
        "basis":None,"missing_policy":None,"fx_version":None,"fx_sha":None,
        "commitment_key":None,"commitment_hmac":None,"state":"denied",
    }
    db.execute(reservation_sql,denied)
    search_reservation=quoted|{
        "id":"00000000-0000-0000-0000-000000000506",
        "attempt_id":"00000000-0000-0000-0000-000000000507",
        "category":"web_search",
        "usage":json.dumps({"category":"web_search","input_tokens":10,"output_tokens":5,"web_search_calls":1}),
        "missing_policy":"conservative_full_reservation",
    }
    db.execute(reservation_sql,search_reservation)

    call_sql="INSERT INTO provider_calls (id,request_id,attempt_id,authorization_id,budget_reservation_id,purpose,provider,model,request_hmac_key_id,request_hmac_b64,category,outcome,gateway_ordering_version,transport_phase,provider_usage_json,provider_usage_receipt_key_id,provider_usage_receipt_hmac_b64,started_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(call_sql,("00000000-0000-0000-0000-000000000601",quoted["request_id"],quoted["attempt_id"],"00000000-0000-0000-0000-000000000602",quoted["id"],"cloud_reasoning","openai","gpt-5.6-sol","provider-request-v1","A"*43+"=","llm","succeeded",1,"finished","{}",None,None,"2026-08-27T01:02:03.000004Z"))
    db.execute(call_sql,("00000000-0000-0000-0000-000000000603",search_reservation["request_id"],search_reservation["attempt_id"],"00000000-0000-0000-0000-000000000604",search_reservation["id"],"web_search","openai","gpt-5.6-sol","provider-request-v1","A"*43+"=","web_search","started",1,"claim_begun",None,None,None,"2026-08-27T01:02:03.000004Z"))

    ledger_sql="INSERT INTO cost_ledger (id,reservation_id,month_key,reserved_micros_sgd,charged_micros_sgd,usage_json,provider_usage_receipt_json,provider_usage_receipt_key_id,provider_usage_receipt_hmac_b64,accounting_basis,conservative_estimate_used,estimate_overrun,hard_cap_exceeded,pricing_version,price_source_sha256,fx_version,fx_source_sha256,settled_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(ledger_sql,("00000000-0000-0000-0000-000000000701",quoted["id"],"2026-08",100,101,"{}","{}",None,None,"provider_reported_exact",0,1,1,"openai-2026-08-27","a"*64,"bootstrap-safety-factor-2026-08-27","b"*64,"2026-08-27T01:03:03.000004Z"))
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(ledger_sql,("00000000-0000-0000-0000-000000000702",quoted["id"],"2026-08",100,101,"{}",None,None,None,None,0,0,1,"openai-2026-08-27","a"*64,"bootstrap-safety-factor-2026-08-27","b"*64,"2026-08-27T01:03:03.000004Z"))
    db.execute(ledger_sql,("00000000-0000-0000-0000-000000000703",quoted["id"],"2026-08",100,100,"null",None,None,None,None,1,0,0,"openai-2026-08-27","a"*64,"bootstrap-safety-factor-2026-08-27","b"*64,"2026-08-27T01:03:03.000004Z"))
    db.close()


def test_foundation_reserves_content_free_reachy_duplex_state(tmp_path:Path) -> None:
    path=tmp_path/"duplex.db"; key=bytes(range(32))
    command.upgrade(_config(path,key),"0001_foundation")
    db=open_sqlcipher(path,key)
    assert {row[1] for row in db.execute("PRAGMA table_info('reachy_core_tx_sequences')")}=={
        "device_id","last_sequence",
    }
    assert {row[1] for row in db.execute("PRAGMA table_info('reachy_duplex_correlations')")}=={
        "device_id","correlation_id","purpose","request_direction","state",
        "first_sequence","last_sequence","created_at","updated_at",
    }
    sql=" ".join(row[0] for row in db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name LIKE 'reachy_%'"
    ))
    assert "payload" not in sql and "transcript" not in sql and "content" not in sql
    db.close()
```

- [ ] **Step 2: Run the red migration test**

Run: `uv run pytest tests/integration/storage/test_migrations.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.adapters.sqlcipher.models'` or Alembic configuration missing.

- [ ] **Step 3: Implement metadata, SQLCipher engine, and migration**

```python
# apps/core/src/tuntun_core/adapters/sqlcipher/engine.py
from pathlib import Path
from sqlalchemy import Engine, create_engine
from sqlalchemy.pool import NullPool
from .connection import open_sqlcipher

def create_sqlcipher_engine(path: Path, key: bytes) -> Engine:
    return create_engine("sqlite://", creator=lambda: open_sqlcipher(path,key), poolclass=NullPool, future=True)
```

```python
# apps/core/src/tuntun_core/adapters/sqlcipher/migrations.py
from pathlib import Path
from alembic import command
from alembic.config import Config
from .connection import open_sqlcipher

def encrypted_backup(source: Path, destination: Path, key: bytes) -> None:
    if destination.exists(): raise FileExistsError(destination)
    source_db=open_sqlcipher(source,key); destination_db=open_sqlcipher(destination,key)
    try:
        source_db.execute("PRAGMA wal_checkpoint(TRUNCATE)"); source_db.backup(destination_db)
        if destination_db.execute("PRAGMA cipher_integrity_check").fetchone()[0] != "ok": raise RuntimeError("encrypted backup integrity failed")
        # Task 11 already descriptor-created and verified exact 0600; never chmod
        # a caller pathname after the guarded open.
        destination_db.commit()
    except BaseException:
        destination_db.close(); destination.unlink(missing_ok=True); raise
    finally:
        source_db.close(); destination_db.close()

def upgrade_encrypted(path: Path, key: bytes, backup: Path | None) -> None:
    if path.exists() and path.stat().st_size > 0:
        if backup is None: raise RuntimeError("existing database requires encrypted pre-migration backup")
        encrypted_backup(path,backup,key)
    config=Config("apps/core/alembic.ini"); config.attributes["sqlcipher_path"]=path; config.attributes["sqlcipher_key"]=key
    command.upgrade(config,"head")
```

```python
# beginning of immutable apps/core/src/tuntun_core/adapters/sqlcipher/foundation_0001.py
from sqlalchemy import CheckConstraint, Column, ForeignKey, Index, Integer, LargeBinary, MetaData, String, Table, Text, UniqueConstraint

FOUNDATION_0001_METADATA=MetaData()
metadata=FOUNDATION_0001_METADATA
FOUNDATION_TABLE_NAMES=frozenset({"households","devices","sessions","event_receipts","idempotency_receipts","audit_receipts","audit_segments","redaction_receipts","provider_calls","provider_response_receipts","provider_prices","budget_reservations","cost_ledger","runtime_settings","reachy_core_tx_sequences","reachy_duplex_correlations"})
assert len(FOUNDATION_TABLE_NAMES)==16
def uuid_pk(name: str="id") -> Column[str]: return Column(name,String(36),primary_key=True)
def utc_text(name: str, nullable: bool=False) -> Column[str]: return Column(name,String(27),nullable=nullable)

households=Table("households",metadata,uuid_pk(),Column("display_label_ciphertext",LargeBinary,nullable=False),Column("timezone",String(32),nullable=False,server_default="Asia/Singapore"),utc_text("created_at"),CheckConstraint("timezone = 'Asia/Singapore'"))
devices=Table("devices",metadata,uuid_pk(),Column("household_id",String(36),ForeignKey("households.id",ondelete="CASCADE"),nullable=False),Column("kind",String(32),nullable=False),Column("certificate_fingerprint",String(128),nullable=False,unique=True),Column("signing_public_key",LargeBinary,nullable=False),Column("signing_key_id",String(128),nullable=False),Column("last_sequence",Integer,nullable=False,server_default="0"),utc_text("paired_at"),utc_text("revoked_at",True),CheckConstraint("last_sequence >= 0"))
sessions=Table("sessions",metadata,uuid_pk(),Column("household_id",String(36),ForeignKey("households.id",ondelete="CASCADE"),nullable=False),Column("device_id",String(36),ForeignKey("devices.id"),nullable=False),Column("state",String(32),nullable=False),Column("speaker_subject_id",String(36),nullable=True),utc_text("opened_at"),utc_text("last_activity_at"),utc_text("closed_at",True))
Index("uq_sessions_one_active_household",sessions.c.household_id,unique=True,sqlite_where=sessions.c.closed_at.is_(None))
```

Add the following exact table declarations to `foundation_0001.py` after the three declarations shown above. This module is the immutable revision 0001 snapshot; later tasks must never add a table or alter a column here:

```python
event_receipts=Table("event_receipts",metadata,uuid_pk(),Column("household_id",String(36),ForeignKey("households.id",ondelete="CASCADE"),nullable=False),Column("device_id",String(36),ForeignKey("devices.id"),nullable=False),Column("event_type",String(128),nullable=False),Column("correlation_id",String(36),nullable=False),Column("device_sequence",Integer,nullable=False),Column("payload_hmac_key_id",String(128),nullable=False),Column("payload_hmac_b64",String(128),nullable=False),Column("decision",String(64),nullable=False),utc_text("occurred_at"),CheckConstraint("device_sequence >= 0"),UniqueConstraint("device_id","device_sequence",name="uq_event_device_sequence"))
idempotency_receipts=Table("idempotency_receipts",metadata,uuid_pk(),Column("operation",String(128),nullable=False),Column("scope",String(128),nullable=False),Column("idempotency_key",String(36),nullable=False),Column("state",String(32),nullable=False),Column("result_hmac_key_id",String(128),nullable=True),Column("result_hmac_b64",String(128),nullable=True),utc_text("first_seen_at"),utc_text("last_seen_at"),utc_text("expires_at"),UniqueConstraint("operation","scope","idempotency_key",name="uq_idempotency_scope_key"))
audit_receipts=Table("audit_receipts",metadata,uuid_pk(),Column("ordinal",Integer,nullable=False,unique=True),Column("previous_public_hash_hex",String(64),nullable=True),Column("public_hash_hex",String(64),nullable=False),Column("hmac_key_id",String(128),nullable=False),Column("hmac_b64",String(128),nullable=False),Column("canonical_body_json",Text,nullable=False),utc_text("occurred_at"),CheckConstraint("ordinal >= 1"),CheckConstraint("length(public_hash_hex) = 64"),CheckConstraint("previous_public_hash_hex IS NULL OR length(previous_public_hash_hex) = 64"),CheckConstraint("json_valid(canonical_body_json)"))
audit_segments=Table("audit_segments",metadata,uuid_pk(),Column("first_ordinal",Integer,nullable=False),Column("last_ordinal",Integer,nullable=False),Column("receipt_count",Integer,nullable=False),Column("terminal_public_hash_hex",String(64),nullable=False),Column("terminal_hmac_b64",String(128),nullable=False),Column("hmac_key_id",String(128),nullable=False),utc_text("sealed_at"),utc_text("exported_at",True),CheckConstraint("first_ordinal >= 1"),CheckConstraint("last_ordinal >= first_ordinal"),CheckConstraint("receipt_count >= 1"))
redaction_receipts=Table("redaction_receipts",metadata,uuid_pk(),Column("purpose",String(64),nullable=False),Column("input_hmac_key_id",String(128),nullable=False),Column("input_hmac_b64",String(128),nullable=False),Column("output_hmac_key_id",String(128),nullable=False),Column("output_hmac_b64",String(128),nullable=False),Column("removed_categories_json",Text,nullable=False),Column("removed_count",Integer,nullable=False),Column("policy_version",String(128),nullable=False),Column("maximum_sensitivity",String(32),nullable=False),utc_text("occurred_at"),CheckConstraint("removed_count >= 0"),CheckConstraint("json_valid(removed_categories_json)"))
provider_calls=Table("provider_calls",metadata,uuid_pk(),Column("request_id",String(36),nullable=False),Column("attempt_id",String(36),nullable=False,unique=True),Column("authorization_id",String(36),nullable=False,unique=True),Column("budget_reservation_id",String(36),ForeignKey("budget_reservations.id"),nullable=False,unique=True),Column("purpose",String(64),nullable=False),Column("provider",String(32),nullable=False),Column("model",String(128),nullable=False),Column("redaction_receipt_id",String(36),ForeignKey("redaction_receipts.id"),nullable=True),Column("request_hmac_key_id",String(128),nullable=False),Column("request_hmac_b64",String(128),nullable=False),Column("response_hmac_key_id",String(128),nullable=True),Column("response_hmac_b64",String(128),nullable=True),Column("category",String(32),nullable=False),Column("outcome",String(64),nullable=False),Column("gateway_ordering_version",Integer,nullable=False),Column("transport_phase",String(32),nullable=False),Column("provider_usage_json",Text,nullable=True),Column("provider_usage_receipt_key_id",String(128),nullable=True),Column("provider_usage_receipt_hmac_b64",String(128),nullable=True),utc_text("started_at"),utc_text("finished_at",True),CheckConstraint("purpose IN ('cloud_stt','cloud_reasoning','cloud_tts','web_search','experimental_web_search')"),CheckConstraint("provider IN ('openai','qwen')"),CheckConstraint("category IN ('stt','llm','tts','web_search')"),CheckConstraint("outcome IN ('started','succeeded','failed','cancelled','ambiguous')"),CheckConstraint("gateway_ordering_version = 1"),CheckConstraint("transport_phase IN ('claim_begun','marked_sent','network_invocation_starting','finished')"),CheckConstraint("(response_hmac_key_id IS NULL) = (response_hmac_b64 IS NULL)"),CheckConstraint("(provider_usage_json IS NULL AND provider_usage_receipt_key_id IS NULL AND provider_usage_receipt_hmac_b64 IS NULL) OR (provider_usage_json IS NOT NULL AND provider_usage_receipt_key_id IS NOT NULL AND provider_usage_receipt_hmac_b64 IS NOT NULL AND json_valid(provider_usage_json))"))
Index("ix_provider_calls_request",provider_calls.c.request_id)
provider_response_receipts=Table("provider_response_receipts",metadata,uuid_pk(),Column("request_id",String(36),nullable=False),Column("attempt_id",String(36),ForeignKey("provider_calls.attempt_id"),nullable=False,unique=True),Column("authorization_id",String(36),nullable=False,unique=True),Column("household_id",String(36),ForeignKey("households.id"),nullable=False),Column("subject_id",String(36),nullable=True),Column("session_id",String(36),ForeignKey("sessions.id"),nullable=False),Column("turn_id",String(36),nullable=False),Column("provider",String(32),nullable=False),Column("model",String(128),nullable=False),Column("output_schema_version",String(64),nullable=False),Column("response_hmac_key_id",String(128),nullable=False),Column("response_hmac_b64",String(128),nullable=False),Column("receipt_hmac_key_id",String(128),nullable=False),Column("receipt_hmac_b64",String(128),nullable=False),utc_text("produced_at"),CheckConstraint("output_schema_version = 'assistant-turn-v1'"))
provider_prices=Table("provider_prices",metadata,uuid_pk(),Column("provider",String(32),nullable=False),Column("model",String(128),nullable=False),Column("category",String(32),nullable=False),Column("native_currency",String(3),nullable=False),Column("tier_basis",String(32),nullable=False),Column("tier_min_input_tokens",Integer,nullable=False),Column("tier_max_input_tokens",Integer,nullable=False),Column("input_micro_usd_per_million",Integer,nullable=False),Column("output_micro_usd_per_million",Integer,nullable=False),Column("audio_micro_usd_per_minute",Integer,nullable=False),Column("web_search_micro_usd_per_call",Integer,nullable=False),Column("primary_accounting_basis",String(48),nullable=False),Column("missing_evidence_policy",String(48),nullable=False),Column("fx_micros_sgd",Integer,nullable=False),Column("pricing_version",String(128),nullable=False),Column("price_source_url",String(512),nullable=False),Column("price_source_sha256",String(64),nullable=False),Column("fx_version",String(128),nullable=False),Column("fx_source_sha256",String(64),nullable=False),utc_text("effective_at"),utc_text("expires_at"),CheckConstraint("provider IN ('openai','qwen')"),CheckConstraint("category IN ('stt','llm','tts','web_search')"),CheckConstraint("native_currency GLOB '[A-Z][A-Z][A-Z]'"),CheckConstraint("(tier_basis='flat' AND tier_min_input_tokens=0 AND tier_max_input_tokens=0) OR (tier_basis='llm_input_tokens' AND category='llm' AND tier_min_input_tokens BETWEEN 0 AND 10000000 AND tier_max_input_tokens BETWEEN tier_min_input_tokens AND 10000000)"),CheckConstraint("input_micro_usd_per_million BETWEEN 0 AND 1000000000"),CheckConstraint("output_micro_usd_per_million BETWEEN 0 AND 1000000000"),CheckConstraint("audio_micro_usd_per_minute BETWEEN 0 AND 1000000000"),CheckConstraint("web_search_micro_usd_per_call BETWEEN 0 AND 1000000000"),CheckConstraint("primary_accounting_basis IN ('provider_reported_exact','request_bound_exact')"),CheckConstraint("missing_evidence_policy IN ('freeze_unknown_overage','conservative_full_reservation')"),CheckConstraint("(category='tts' AND primary_accounting_basis='request_bound_exact' AND missing_evidence_policy='freeze_unknown_overage' AND input_micro_usd_per_million>0 AND output_micro_usd_per_million=0 AND audio_micro_usd_per_minute=0 AND web_search_micro_usd_per_call=0) OR (category='web_search' AND primary_accounting_basis='provider_reported_exact' AND missing_evidence_policy='conservative_full_reservation' AND input_micro_usd_per_million>0 AND output_micro_usd_per_million>0 AND audio_micro_usd_per_minute=0 AND web_search_micro_usd_per_call>0) OR (category='stt' AND primary_accounting_basis='provider_reported_exact' AND missing_evidence_policy='freeze_unknown_overage' AND input_micro_usd_per_million=0 AND output_micro_usd_per_million=0 AND audio_micro_usd_per_minute>0 AND web_search_micro_usd_per_call=0) OR (category='llm' AND primary_accounting_basis='provider_reported_exact' AND missing_evidence_policy='freeze_unknown_overage' AND input_micro_usd_per_million>0 AND output_micro_usd_per_million>0 AND audio_micro_usd_per_minute=0 AND web_search_micro_usd_per_call=0)"),CheckConstraint("fx_micros_sgd BETWEEN 1 AND 10000000"),CheckConstraint("length(price_source_url) BETWEEN 9 AND 512 AND price_source_url GLOB 'https://*'"),CheckConstraint("length(price_source_sha256)=64 AND price_source_sha256 NOT GLOB '*[^0-9a-f]*'"),CheckConstraint("length(fx_source_sha256)=64 AND fx_source_sha256 NOT GLOB '*[^0-9a-f]*'"),CheckConstraint("effective_at < expires_at"),UniqueConstraint("provider","model","category","pricing_version","fx_version","tier_basis","tier_min_input_tokens","tier_max_input_tokens",name="uq_provider_price_version_tier"))
budget_reservations=Table("budget_reservations",metadata,uuid_pk(),Column("request_id",String(36),nullable=False),Column("attempt_id",String(36),nullable=False,unique=True),Column("month_key",String(7),nullable=False),Column("category",String(32),nullable=False),Column("provider",String(32),nullable=False),Column("model",String(128),nullable=False),Column("outcome",String(32),nullable=False),Column("reserved_micros_sgd",Integer,nullable=False),Column("charged_micros_sgd",Integer,nullable=True),Column("usage_ceiling_json",Text,nullable=False),Column("price_snapshot_json",Text,nullable=True),Column("primary_accounting_basis",String(48),nullable=True),Column("missing_evidence_policy",String(48),nullable=True),Column("pricing_version",String(128),nullable=True),Column("price_source_sha256",String(64),nullable=True),Column("fx_version",String(128),nullable=True),Column("fx_source_sha256",String(64),nullable=True),Column("pricing_commitment_key_id",String(128),nullable=True),Column("pricing_commitment_hmac_b64",String(128),nullable=True),Column("estimate_overrun",Integer,nullable=False,server_default="0"),Column("state",String(32),nullable=False),Column("gateway_ordering_version",Integer,nullable=False),Column("transport_phase",String(32),nullable=False),utc_text("created_at"),utc_text("expires_at"),utc_text("settled_at",True),utc_text("reconciled_at",True),CheckConstraint("reserved_micros_sgd BETWEEN 0 AND 1000000000000"),CheckConstraint("charged_micros_sgd IS NULL OR charged_micros_sgd BETWEEN 0 AND 1000000000000"),CheckConstraint("json_valid(usage_ceiling_json)"),CheckConstraint("price_snapshot_json IS NULL OR json_valid(price_snapshot_json)"),CheckConstraint("primary_accounting_basis IS NULL OR primary_accounting_basis IN ('provider_reported_exact','request_bound_exact')"),CheckConstraint("missing_evidence_policy IS NULL OR missing_evidence_policy IN ('freeze_unknown_overage','conservative_full_reservation')"),CheckConstraint("price_source_sha256 IS NULL OR (length(price_source_sha256)=64 AND price_source_sha256 NOT GLOB '*[^0-9a-f]*')"),CheckConstraint("fx_source_sha256 IS NULL OR (length(fx_source_sha256)=64 AND fx_source_sha256 NOT GLOB '*[^0-9a-f]*')"),CheckConstraint("(price_snapshot_json IS NULL AND primary_accounting_basis IS NULL AND missing_evidence_policy IS NULL AND pricing_version IS NULL AND price_source_sha256 IS NULL AND fx_version IS NULL AND fx_source_sha256 IS NULL AND pricing_commitment_key_id IS NULL AND pricing_commitment_hmac_b64 IS NULL) OR (price_snapshot_json IS NOT NULL AND primary_accounting_basis IS NOT NULL AND missing_evidence_policy IS NOT NULL AND pricing_version IS NOT NULL AND price_source_sha256 IS NOT NULL AND fx_version IS NOT NULL AND fx_source_sha256 IS NOT NULL AND pricing_commitment_key_id IS NOT NULL AND pricing_commitment_hmac_b64 IS NOT NULL)"),CheckConstraint("month_key GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]'"),CheckConstraint("provider IN ('openai','qwen')"),CheckConstraint("category IN ('stt','llm','tts','web_search')"),CheckConstraint("gateway_ordering_version = 1"),CheckConstraint("transport_phase IN ('not_claimed','claim_begun','marked_sent','network_invocation_starting','finished')"),CheckConstraint("outcome IN ('allow','allow_soft_warning','deny_hard_limit','deny_unknown_price','deny_cloud_egress_frozen')"),CheckConstraint("state IN ('reserved','sent','settled','released','denied')"),CheckConstraint("(outcome IN ('allow','allow_soft_warning') AND reserved_micros_sgd BETWEEN 1 AND 1000000000000 AND price_snapshot_json IS NOT NULL AND state IN ('reserved','sent','settled','released')) OR (outcome='deny_hard_limit' AND reserved_micros_sgd=0 AND price_snapshot_json IS NOT NULL AND state='denied') OR (outcome IN ('deny_unknown_price','deny_cloud_egress_frozen') AND reserved_micros_sgd=0 AND price_snapshot_json IS NULL AND state='denied')"),CheckConstraint("(state='settled' AND charged_micros_sgd IS NOT NULL AND settled_at IS NOT NULL) OR (state<>'settled' AND charged_micros_sgd IS NULL AND settled_at IS NULL)"),CheckConstraint("estimate_overrun IN (0,1) AND estimate_overrun = CASE WHEN charged_micros_sgd IS NOT NULL AND charged_micros_sgd > reserved_micros_sgd THEN 1 ELSE 0 END"))
Index("ix_budget_request",budget_reservations.c.request_id)
Index("ix_budget_month_state_cost",budget_reservations.c.month_key,budget_reservations.c.state,budget_reservations.c.reserved_micros_sgd,budget_reservations.c.charged_micros_sgd)
cost_ledger=Table("cost_ledger",metadata,uuid_pk(),Column("reservation_id",String(36),ForeignKey("budget_reservations.id"),nullable=False,unique=True),Column("month_key",String(7),nullable=False),Column("reserved_micros_sgd",Integer,nullable=False),Column("charged_micros_sgd",Integer,nullable=False),Column("usage_json",Text,nullable=False),Column("provider_usage_receipt_json",Text,nullable=True),Column("provider_usage_receipt_key_id",String(128),nullable=True),Column("provider_usage_receipt_hmac_b64",String(128),nullable=True),Column("accounting_basis",String(48),nullable=True),Column("conservative_estimate_used",Integer,nullable=False),Column("estimate_overrun",Integer,nullable=False),Column("hard_cap_exceeded",Integer,nullable=False),Column("pricing_version",String(128),nullable=False),Column("price_source_sha256",String(64),nullable=False),Column("fx_version",String(128),nullable=False),Column("fx_source_sha256",String(64),nullable=False),utc_text("settled_at"),CheckConstraint("month_key GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]'"),CheckConstraint("reserved_micros_sgd BETWEEN 1 AND 1000000000000"),CheckConstraint("charged_micros_sgd BETWEEN 0 AND 1000000000000"),CheckConstraint("json_valid(usage_json)"),CheckConstraint("accounting_basis IS NULL OR accounting_basis IN ('provider_reported_exact','request_bound_exact','conservative_full_reservation')"),CheckConstraint("(provider_usage_receipt_json IS NULL AND provider_usage_receipt_key_id IS NULL AND provider_usage_receipt_hmac_b64 IS NULL AND accounting_basis IS NULL AND conservative_estimate_used=1) OR (provider_usage_receipt_json IS NOT NULL AND provider_usage_receipt_key_id IS NOT NULL AND provider_usage_receipt_hmac_b64 IS NOT NULL AND accounting_basis IS NOT NULL AND json_valid(provider_usage_receipt_json))"),CheckConstraint("conservative_estimate_used IN (0,1)"),CheckConstraint("estimate_overrun IN (0,1) AND estimate_overrun = CASE WHEN charged_micros_sgd > reserved_micros_sgd THEN 1 ELSE 0 END"),CheckConstraint("hard_cap_exceeded IN (0,1)"),CheckConstraint("length(price_source_sha256)=64 AND price_source_sha256 NOT GLOB '*[^0-9a-f]*'"),CheckConstraint("length(fx_source_sha256)=64 AND fx_source_sha256 NOT GLOB '*[^0-9a-f]*'"))
runtime_settings=Table("runtime_settings",metadata,Column("key",String(128),primary_key=True),Column("value_json",Text,nullable=False),Column("version",Integer,nullable=False),utc_text("updated_at"),CheckConstraint("version >= 1"),CheckConstraint("json_valid(value_json)"))
reachy_core_tx_sequences=Table("reachy_core_tx_sequences",metadata,Column("device_id",String(36),ForeignKey("devices.id"),primary_key=True),Column("last_sequence",Integer,nullable=False),CheckConstraint("last_sequence >= 0"))
reachy_duplex_correlations=Table("reachy_duplex_correlations",metadata,Column("device_id",String(36),ForeignKey("devices.id"),primary_key=True),Column("correlation_id",String(36),primary_key=True),Column("purpose",String(64),nullable=False),Column("request_direction",String(16),nullable=False),Column("state",String(16),nullable=False),Column("first_sequence",Integer,nullable=False),Column("last_sequence",Integer,nullable=False),utc_text("created_at"),utc_text("updated_at"),CheckConstraint("request_direction IN ('edge_to_core','core_to_edge')"),CheckConstraint("state IN ('pending','completed','abandoned')"),CheckConstraint("first_sequence >= 1 AND last_sequence >= 1"))
```

```python
# apps/core/src/tuntun_core/adapters/sqlcipher/models.py
from sqlalchemy import MetaData
from .foundation_0001 import FOUNDATION_0001_METADATA,FOUNDATION_TABLE_NAMES

metadata=MetaData()
for frozen_table in FOUNDATION_0001_METADATA.sorted_tables:
    frozen_table.to_metadata(metadata)
globals().update({name:metadata.tables[name] for name in FOUNDATION_TABLE_NAMES})

# Future revisions declare their new tables only against this application
# metadata. They never edit FOUNDATION_0001_METADATA.
```

Every UUID is `String(36)`, every timestamp is `String(27)`, money/counts are bounded `Integer` values, booleans have `CHECK (value IN (0,1))` using the real column name, JSON columns have `CHECK json_valid(column_name)` using the real column name, and no table contains raw audio, transcript, frame, prompt, memory body, credential, or secret. Budget rates, usage units, one-attempt charge, and aggregate arithmetic additionally use the exact frozen maxima above; application code performs checked multiply/add/ceil operations before SQLite and treats any overflow or out-of-range aggregate as `budget_arithmetic_out_of_bounds`. The two Reachy duplex tables are deliberately content-free foundation reservations: later transport work implements repositories against them and must not add another migration.

```python
# apps/core/migrations/versions/0001_foundation.py
from alembic import op
from tuntun_core.adapters.sqlcipher.foundation_0001 import FOUNDATION_0001_METADATA
revision="0001_foundation"; down_revision=None; branch_labels=None; depends_on=None
def upgrade() -> None:
    bind=op.get_bind(); FOUNDATION_0001_METADATA.create_all(bind=bind)
    op.execute("CREATE TRIGGER audit_receipts_no_update BEFORE UPDATE ON audit_receipts BEGIN SELECT RAISE(ABORT, 'audit receipts are append-only'); END")
    op.execute("CREATE TRIGGER audit_receipts_no_delete BEFORE DELETE ON audit_receipts BEGIN SELECT RAISE(ABORT, 'audit receipts are append-only'); END")
def downgrade() -> None:
    bind=op.get_bind(); FOUNDATION_0001_METADATA.drop_all(bind=bind)
```

The source-direction test above and the future-table injection jointly prevent an implementation from silently returning to live `models.metadata.create_all()`.

```python
# apps/core/migrations/env.py core online path
from alembic import context
from tuntun_core.adapters.sqlcipher.engine import create_sqlcipher_engine
from tuntun_core.adapters.sqlcipher.models import metadata
config=context.config
def run_migrations_online() -> None:
    path=config.attributes["sqlcipher_path"]; key=config.attributes["sqlcipher_key"]
    with create_sqlcipher_engine(path,key).connect() as connection:
        context.configure(connection=connection,target_metadata=metadata,transaction_per_migration=True,render_as_batch=True)
        with context.begin_transaction(): context.run_migrations()
if context.is_offline_mode(): raise RuntimeError("offline/plaintext migration mode is forbidden")
run_migrations_online()
```

Configure `apps/core/alembic.ini` with `script_location = %(here)s/migrations`; use Alembic’s standard `script.py.mako`. Add `SQLAlchemy>=2.0.43,<3` and `alembic>=1.16,<2` to core dependencies.

```python
# tests/integration/storage/conftest.py
from dataclasses import dataclass
from pathlib import Path
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine
from tuntun_core.adapters.sqlcipher.engine import create_sqlcipher_engine

@dataclass(frozen=True, slots=True)
class MigratedDatabase:
    engine: Engine; path: Path; key: bytes

@pytest.fixture
def migrated_database(tmp_path: Path):
    path=tmp_path/"foundation.db"; key=bytes(range(32)); config=Config("apps/core/alembic.ini")
    config.attributes["sqlcipher_path"]=path; config.attributes["sqlcipher_key"]=key
    command.upgrade(config,"head"); fixture=MigratedDatabase(create_sqlcipher_engine(path,key),path,key)
    try: yield fixture
    finally:
        fixture.engine.dispose()
        for candidate in (path,Path(f"{path}-wal"),Path(f"{path}-shm")):
            candidate.unlink(missing_ok=True)
```

- [ ] **Step 4: Lock and run the green migration gate**

Run: `uv lock && uv run pytest tests/integration/storage/test_migrations.py -q && uv run mypy apps/core/src/tuntun_core/adapters/sqlcipher apps/core/migrations`

Expected: PASS with upgrade → downgrade → upgrade completing against SQLCipher and exact table/trigger ownership asserted; injecting `future_phase_table` into live application metadata does not change revision 0001's exact set; source assertions prove the revision imports only its frozen snapshot.

- [ ] **Step 5: Commit exact Task 13 paths**

```bash
git status --short
git add apps/core/pyproject.toml uv.lock apps/core/src/tuntun_core/adapters/sqlcipher/foundation_0001.py apps/core/src/tuntun_core/adapters/sqlcipher/models.py apps/core/src/tuntun_core/adapters/sqlcipher/engine.py apps/core/src/tuntun_core/adapters/sqlcipher/migrations.py apps/core/migrations/env.py apps/core/migrations/script.py.mako apps/core/migrations/versions/0001_foundation.py apps/core/alembic.ini tests/integration/storage/conftest.py tests/integration/storage/test_migrations.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(storage): add reversible encrypted foundation schema"
```

### Task 14: Add explicit unit-of-work transaction semantics

**Master package:** 06
**Depends on:** Task 13.
**Estimated effort:** 1 person-day.

**Files:**
- Create: `apps/core/src/tuntun_core/adapters/sqlcipher/unit_of_work.py`
- Create: `apps/core/src/tuntun_core/adapters/sqlcipher/async_unit_of_work.py`
- Create: `apps/core/src/tuntun_core/adapters/sqlcipher/repository_facade.py`
- Create: `apps/core/src/tuntun_core/services/transactions/protocols.py`
- Create: `apps/core/src/tuntun_core/services/transactions/mutation_scope.py`
- Modify: `tests/integration/storage/conftest.py`
- Test: `tests/integration/storage/test_transactions.py`
- Test: `tests/integration/storage/test_async_transactions.py`
- Create: `tests/unit/transactions/conftest.py`
- Test: `tests/unit/transactions/test_mutation_scope.py`

**Interfaces:**
- Consumes: SQLAlchemy `Engine`; SQLite busy errors; one application-owned serialized database worker.
- Produces: project-owned runtime-checkable structural `UnitOfWorkProtocol` and `AsyncUnitOfWorkProtocol` in `tuntun_core.services.transactions.protocols`; exact low-level adapter `UnitOfWork` signature from the locked map conforming structurally without services importing adapters; `AsyncUnitOfWorkFactory(repository_facades) -> AsyncUnitOfWork`; startup-only fixed `register_commit_signal(name, target.offer_nowait)` plus transaction-local `signal_after_commit(name)`; `AsyncRepositoryFacade`; and `AtomicMutationScope.open()/require_active_uow()`. Both unit-of-work layers use `BEGIN IMMEDIATE`, explicit commit/rollback, no implicit commit on context exit, and bounded busy retry of 3 attempts at 25/50/100 ms. The async facade runs enter, every repository operation, audit append, commit/rollback, and close on the same single worker/connection; it never moves a live transaction between threads. Entry is cancellation-terminal: cancellation before lock acquisition creates nothing; cancellation while or immediately after the worker executes `BEGIN IMMEDIATE` waits for that exact worker call, then rolls back/closes on the same worker before releasing the application lock and propagating cancellation. Each bounded context declares a typed structural protocol such as `IdentityUnitOfWork(AsyncUnitOfWorkProtocol)` listing its async repository properties (`profiles`, `consent_receipts`, and so on); the factory installs matching `AsyncRepositoryFacade` instances, so the plan's `await uow.profiles.insert(...)` notation is typed and every call internally delegates through that exact unit's `run_sync`.

- [ ] **Step 1: Write red rollback and explicit-commit tests**

```python
# tests/integration/storage/test_transactions.py
from sqlalchemy import text
from tuntun_core.adapters.sqlcipher.engine import create_sqlcipher_engine
from tuntun_core.adapters.sqlcipher.unit_of_work import UnitOfWork

def test_context_rolls_back_without_explicit_commit(migrated_database) -> None:
    engine=migrated_database.engine
    try:
        with UnitOfWork(engine) as uow:
            uow.execute(text("INSERT INTO households(id,display_label_ciphertext,timezone,created_at) VALUES(:id,:label,'Asia/Singapore',:now)"), {"id":"00000000-0000-0000-0000-000000000601","label":b"ciphertext","now":"2026-08-27T01:02:03.000004Z"})
            raise RuntimeError("kill-point")
    except RuntimeError: pass
    with engine.connect() as connection: assert connection.execute(text("SELECT count(*) FROM households")).scalar_one() == 0

def test_explicit_commit_persists(migrated_database) -> None:
    with UnitOfWork(migrated_database.engine) as uow:
        uow.execute(text("INSERT INTO households(id,display_label_ciphertext,timezone,created_at) VALUES(:id,:label,'Asia/Singapore',:now)"), {"id":"00000000-0000-0000-0000-000000000602","label":b"ciphertext","now":"2026-08-27T01:02:03.000004Z"}); uow.commit()
    with migrated_database.engine.connect() as connection: assert connection.execute(text("SELECT count(*) FROM households")).scalar_one() == 1
```

```python
# tests/integration/storage/test_async_transactions.py
import asyncio
from threading import Event,get_ident
import pytest
from sqlalchemy import text
from tuntun_core.adapters.sqlcipher.async_unit_of_work import AsyncUnitOfWorkFactory
from tuntun_core.adapters.sqlcipher.unit_of_work import UnitOfWork

@pytest.mark.asyncio
async def test_async_facade_keeps_one_worker_and_commits(migrated_database) -> None:
    factory=AsyncUnitOfWorkFactory(migrated_database.engine)
    async with factory() as uow:
        worker=await uow.run_sync(lambda tx: (get_ident(), id(tx.connection)))
        await uow.run_sync(lambda tx: tx.execute(text("INSERT INTO households(id,display_label_ciphertext,timezone,created_at) VALUES(:id,:label,'Asia/Singapore',:now)"),{"id":"00000000-0000-0000-0000-000000000603","label":b"ciphertext","now":"2026-08-27T01:02:03.000004Z"}))
        assert await uow.run_sync(lambda tx: (get_ident(),id(tx.connection)))==worker
        await uow.commit()

@pytest.mark.asyncio
async def test_cancelled_context_rolls_back_and_never_leaves_writer_lock(migrated_database) -> None:
    factory=AsyncUnitOfWorkFactory(migrated_database.engine)
    with pytest.raises(asyncio.CancelledError):
        async with factory() as uow:
            await uow.run_sync(lambda tx: tx.execute(text("INSERT INTO households(id,display_label_ciphertext,timezone,created_at) VALUES(:id,:label,'Asia/Singapore',:now)"),{"id":"00000000-0000-0000-0000-000000000604","label":b"ciphertext","now":"2026-08-27T01:02:03.000004Z"}))
            raise asyncio.CancelledError
    async with factory() as next_uow:
        assert await next_uow.run_sync(lambda tx: tx.execute(text("SELECT count(*) FROM households")).scalar_one())==0
        await next_uow.rollback()


@pytest.mark.asyncio
@pytest.mark.parametrize("point",("before_lock","during_begin","after_begin"))
async def test_cancelled_entry_is_terminal_before_application_lock_release(
    migrated_database,monkeypatch:pytest.MonkeyPatch,point:str,
) -> None:
    factory=AsyncUnitOfWorkFactory(migrated_database.engine); created=[]
    original_enter=UnitOfWork.__enter__; begin_started=Event(); release_begin=Event()
    def controlled_enter(unit):
        created.append(unit)
        if point=="during_begin":
            begin_started.set(); release_begin.wait(timeout=5)
        result=original_enter(unit)
        if point=="after_begin":
            begin_started.set(); release_begin.wait(timeout=5)
        return result
    monkeypatch.setattr(UnitOfWork,"__enter__",controlled_enter)
    if point=="before_lock": await factory._transaction_lock.acquire()
    pending=factory(); task=asyncio.create_task(pending.__aenter__())
    if point=="before_lock":
        await asyncio.sleep(0); task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
        factory._transaction_lock.release()
    else:
        assert await asyncio.to_thread(begin_started.wait,5)
        task.cancel(); release_begin.set()
        with pytest.raises(asyncio.CancelledError): await task
    assert pending._sync is None and not factory._transaction_lock.locked()
    assert all(unit.connection is None or unit.connection.closed for unit in created)
    async with factory() as next_uow:
        assert await next_uow.run_sync(
            lambda tx:tx.execute(text("SELECT count(*) FROM households")).scalar_one()
        )==0
        await next_uow.rollback()

@pytest.mark.asyncio
async def test_typed_repository_facade_stays_on_transaction_worker(migrated_database,household_repository_facade) -> None:
    factory=AsyncUnitOfWorkFactory(migrated_database.engine,{"households":household_repository_facade})
    async with factory() as uow:
        worker=await uow.run_sync(lambda tx:get_ident())
        created=await uow.households.insert_synthetic("00000000-0000-0000-0000-000000000605")
        assert created.worker_ident==worker
        await uow.rollback()

@pytest.mark.asyncio
async def test_concurrent_units_serialize_whole_transaction_lifetimes(migrated_database) -> None:
    factory=AsyncUnitOfWorkFactory(migrated_database.engine)
    first=("1","probe","a","1","done","2026-08-27T00:00:00Z","2026-08-27T00:00:00Z","2026-08-28T00:00:00Z")
    second=("2","probe","b","2","done","2026-08-27T00:00:00Z","2026-08-27T00:00:00Z","2026-08-28T00:00:00Z")
    entered=[]
    async def writer(marker):
        async with factory() as uow:
            entered.append(marker)
            await asyncio.sleep(0)
            await uow.run_sync(lambda tx: tx.exec_driver_sql("INSERT INTO idempotency_receipts(id,operation,scope,idempotency_key,state,first_seen_at,last_seen_at,expires_at) VALUES(?,?,?,?,?,?,?,?)",marker))
            await uow.commit()
    await asyncio.gather(writer(first),writer(second))
    assert entered==[first,second]


@pytest.mark.asyncio
async def test_fixed_post_commit_signal_fires_only_after_successful_commit(
    migrated_database,nonblocking_commit_signal,
) -> None:
    factory=AsyncUnitOfWorkFactory(migrated_database.engine)
    factory.register_commit_signal("subject_revocation",nonblocking_commit_signal)
    async with factory() as committed:
        committed.signal_after_commit("subject_revocation")
        await committed.commit()
    assert nonblocking_commit_signal.offer_count==1
    async with factory() as rolled_back:
        rolled_back.signal_after_commit("subject_revocation")
        await rolled_back.rollback()
    assert nonblocking_commit_signal.offer_count==1


@pytest.mark.asyncio
async def test_post_commit_signal_failure_never_changes_committed_result(
    migrated_database,failing_nonblocking_commit_signal,
) -> None:
    factory=AsyncUnitOfWorkFactory(migrated_database.engine)
    factory.register_commit_signal(
        "subject_revocation",failing_nonblocking_commit_signal,
    )
    async with factory() as uow:
        uow.signal_after_commit("subject_revocation")
        await uow.commit()
    assert failing_nonblocking_commit_signal.offer_count==1
    assert factory.failed_commit_signal_count("subject_revocation")==1
```

```python
# tests/unit/transactions/test_mutation_scope.py
import asyncio
import pytest
from tuntun_core.services.transactions.mutation_scope import AtomicMutationScope

@pytest.mark.asyncio
async def test_scope_is_task_local_rejects_nesting_and_rolls_back_on_failure(async_uow_factory):
    scope=AtomicMutationScope(async_uow_factory)
    with pytest.raises(RuntimeError,match="no active atomic mutation scope"):
        scope.require_active_uow()
    with pytest.raises(RuntimeError,match="nested atomic mutation scope"):
        async with scope.open():
            assert scope.require_active_uow() is not None
            async with scope.open(): pass
    assert await async_uow_factory.persisted_probe_count()==0
    assert await asyncio.create_task(async_uow_factory.probe_scope_is_absent(scope)) is True
```

Use the exact `migrated_database` fixture created by Task 13. Extend that same storage conftest with the integration-only facade and commit-signal fixtures:

```python
# append to tests/integration/storage/conftest.py
from dataclasses import dataclass
from threading import get_ident

from sqlalchemy import text


@dataclass(frozen=True,slots=True)
class CreatedHousehold:
    household_id:str; worker_ident:int


class BoundHouseholdFacade:
    def __init__(self,uow): self._uow=uow
    async def insert_synthetic(self,household_id:str) -> CreatedHousehold:
        def insert(transaction):
            transaction.execute(text("INSERT INTO households(id,display_label_ciphertext,timezone,created_at) VALUES(:id,:label,'Asia/Singapore',:now)"),{"id":household_id,"label":b"ciphertext","now":"2026-08-27T01:02:03.000004Z"})
            return CreatedHousehold(household_id,get_ident())
        return await self._uow.run_sync(insert)


class HouseholdFacadeFactory:
    def bind(self,uow) -> BoundHouseholdFacade:
        return BoundHouseholdFacade(uow)


class CommitSignalProbe:
    def __init__(self,fail:bool=False): self.offer_count=0; self._fail=fail
    def offer_nowait(self) -> None:
        self.offer_count+=1
        if self._fail: raise RuntimeError("synthetic post-commit signal failure")


@pytest.fixture
def household_repository_facade() -> HouseholdFacadeFactory:
    return HouseholdFacadeFactory()


@pytest.fixture
def nonblocking_commit_signal() -> CommitSignalProbe:
    return CommitSignalProbe()


@pytest.fixture
def failing_nonblocking_commit_signal() -> CommitSignalProbe:
    return CommitSignalProbe(fail=True)
```

Own the unit-only `async_uow_factory` at the subtree where `test_mutation_scope.py` consumes it. This fake tests task-local scope behavior only and does not impersonate SQLAlchemy storage:

```python
# tests/unit/transactions/conftest.py
import pytest


class ScopeProbeUnit:
    def __init__(self,factory): self.factory=factory; self.finished=False
    async def __aenter__(self): self.factory.active+=1; return self
    async def commit(self): self.factory.persisted+=1; self.finished=True
    async def rollback(self): self.finished=True
    async def __aexit__(self,exc_type,exc,tb):
        if not self.finished: await self.rollback()
        self.factory.active-=1
        return False


class ScopeProbeFactory:
    def __init__(self): self.active=0; self.persisted=0
    def __call__(self): return ScopeProbeUnit(self)
    async def persisted_probe_count(self) -> int: return self.persisted
    async def probe_scope_is_absent(self,scope) -> bool:
        try: scope.require_active_uow()
        except RuntimeError as error:
            return "no active atomic mutation scope" in str(error)
        return False


@pytest.fixture
def async_uow_factory() -> ScopeProbeFactory:
    return ScopeProbeFactory()
```

- [ ] **Step 2: Run the red transaction tests**

Run: `uv run pytest tests/integration/storage/test_transactions.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.adapters.sqlcipher.unit_of_work'`.

- [ ] **Step 3: Implement explicit transactions and bounded retry**

```python
# apps/core/src/tuntun_core/services/transactions/protocols.py
from collections.abc import Callable,Mapping
from typing import Any,Protocol,TypeVar,runtime_checkable
from sqlalchemy.engine import CursorResult
from sqlalchemy.sql import Executable

T=TypeVar("T")

@runtime_checkable
class UnitOfWorkProtocol(Protocol):
    def execute(self,statement:Executable,parameters:Mapping[str,object]|None=None) -> CursorResult[Any]: raise NotImplementedError
    def exec_driver_sql(self,statement:str,parameters:tuple[object,...]|Mapping[str,object]=()) -> CursorResult[Any]: raise NotImplementedError
    def commit(self) -> None: raise NotImplementedError
    def rollback(self) -> None: raise NotImplementedError

@runtime_checkable
class AsyncUnitOfWorkProtocol(Protocol):
    async def run_sync(self,operation:Callable[[UnitOfWorkProtocol],T]) -> T: raise NotImplementedError
    def signal_after_commit(self,name:str) -> None: raise NotImplementedError
    async def commit(self) -> None: raise NotImplementedError
    async def rollback(self) -> None: raise NotImplementedError
```

The SQLCipher adapter does not inherit from or import this services module; its already exact public methods satisfy the protocol structurally. Add `assert isinstance(UnitOfWork(migrated_database.engine),UnitOfWorkProtocol)` to `test_transactions.py`, and add a source-direction assertion that `tuntun_core.services.transactions.protocols` contains no `tuntun_core.adapters` import.

```python
# apps/core/src/tuntun_core/adapters/sqlcipher/unit_of_work.py
from types import TracebackType
from collections.abc import Mapping
from time import sleep
from typing import Any, Callable
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, CursorResult
from sqlalchemy.exc import OperationalError
from sqlalchemy.sql import Executable

class UnitOfWork:
    def __init__(self, engine: Engine, sleeper: Callable[[float],None]=sleep) -> None: self.engine=engine; self.sleeper=sleeper; self.connection: Connection | None=None; self._finished=False
    def __enter__(self) -> "UnitOfWork":
        self.connection=self.engine.connect()
        for attempt,delay in enumerate((0.025,0.050,0.100),start=1):
            try: self.connection.exec_driver_sql("BEGIN IMMEDIATE"); return self
            except OperationalError as error:
                if "locked" not in str(error).lower() or attempt == 3: self.connection.close(); raise
                self.sleeper(delay)
        raise AssertionError("unreachable")
    def execute(self, statement: Executable, parameters: Mapping[str,object] | None=None) -> CursorResult[Any]:
        if self.connection is None or self._finished: raise RuntimeError("unit of work is not active")
        return self.connection.execute(statement, parameters or {})
    def exec_driver_sql(self, statement: str, parameters: tuple[object,...] | Mapping[str,object]=()) -> CursorResult[Any]:
        if self.connection is None or self._finished: raise RuntimeError("unit of work is not active")
        return self.connection.exec_driver_sql(statement, parameters)
    def commit(self) -> None:
        if self.connection is None or self._finished: raise RuntimeError("unit of work is not active")
        self.connection.commit(); self._finished=True
    def rollback(self) -> None:
        if self.connection is not None and not self._finished: self.connection.rollback(); self._finished=True
    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> bool:
        try:
            if not self._finished: self.rollback()
        finally:
            if self.connection is not None: self.connection.close()
        return False
```

```python
# apps/core/src/tuntun_core/adapters/sqlcipher/async_unit_of_work.py
import asyncio
from concurrent.futures import ThreadPoolExecutor
from tuntun_core.adapters.sqlcipher.unit_of_work import UnitOfWork

class AsyncUnitOfWork:
    def __init__(self, engine, executor, transaction_lock, repository_facades, commit_signals, signal_failures):
        self._engine,self._executor,self._transaction_lock,self._repository_facades=engine,executor,transaction_lock,repository_facades
        self._commit_signals,self._signal_failures=commit_signals,signal_failures
        self._signals_after_commit=set()
        self._sync=None
    async def _call(self,operation):
        loop=asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor,operation)
    async def _terminal_call(self,operation):
        task=asyncio.create_task(self._call(operation))
        cancellation=None
        while not task.done():
            try: await asyncio.shield(task)
            except asyncio.CancelledError as error: cancellation=error
        try: result=task.result()
        except BaseException:
            if cancellation is not None: raise cancellation
            raise
        if cancellation is not None: raise cancellation
        return result
    async def __aenter__(self):
        await self._transaction_lock.acquire()
        try:
            self._sync=UnitOfWork(self._engine)
            await self._terminal_call(self._sync.__enter__)
            for name,facade_factory in self._repository_facades.items():
                setattr(self,name,facade_factory.bind(self))
            return self
        except BaseException as error:
            try:
                if self._sync is not None and self._sync.connection is not None:
                    await self._terminal_call(
                        lambda:self._sync.__exit__(type(error),error,error.__traceback__)
                    )
            finally:
                self._sync=None
                self._transaction_lock.release()
            raise
    async def run_sync(self,operation):
        if self._sync is None: raise RuntimeError("async unit of work is not active")
        return await self._call(lambda: operation(self._sync))
    def signal_after_commit(self,name):
        if self._sync is None or name not in self._commit_signals:
            raise RuntimeError("unregistered post-commit signal")
        self._signals_after_commit.add(name)
    async def commit(self):
        if self._sync is None: raise RuntimeError("async unit of work is not active")
        await self._terminal_call(self._sync.commit)
        signals=tuple(sorted(self._signals_after_commit)); self._signals_after_commit.clear()
        for name in signals:
            try: self._commit_signals[name].offer_nowait()
            except BaseException: self._signal_failures[name]=self._signal_failures.get(name,0)+1
    async def rollback(self):
        self._signals_after_commit.clear()
        if self._sync is not None: await self._terminal_call(self._sync.rollback)
    async def __aexit__(self,exc_type,exc,tb):
        try:
            if self._sync is not None:
                await self._terminal_call(lambda: self._sync.__exit__(exc_type,exc,tb))
        finally:
            self._transaction_lock.release()
        return False

class AsyncUnitOfWorkFactory:
    def __init__(self,engine,repository_facades=None):
        self._engine,self._repository_facades=engine,repository_facades or {}
        self._commit_signals={}; self._signal_failures={}; self._opened=False
        self._executor=ThreadPoolExecutor(max_workers=1,thread_name_prefix="tuntun-sqlcipher")
        self._transaction_lock=asyncio.Lock()
    def register_commit_signal(self,name,target):
        if self._opened or name in self._commit_signals or not hasattr(target,"offer_nowait"):
            raise RuntimeError("post-commit signal registration closed")
        self._commit_signals[name]=target
    def failed_commit_signal_count(self,name): return self._signal_failures.get(name,0)
    def __call__(self):
        self._opened=True
        return AsyncUnitOfWork(
            self._engine,self._executor,self._transaction_lock,
            self._repository_facades,self._commit_signals,self._signal_failures,
        )
```

`AsyncUnitOfWork.__aenter__` binds each registered facade to itself and exposes it under its typed repository property. `AsyncRepositoryFacade` contains no connection of its own: every method executes a synchronous repository operation as `await bound_uow.run_sync(lambda tx: sync_repository(tx).method(...))`. It rejects use before enter or after finish. Bounded-context protocols name every repository method and return type, and strict mypy verifies services against those protocols; there is no dynamic `Any`/string dispatch in application code.

`AtomicMutationScope` is an async context manager backed by a task-local `ContextVar[AsyncUnitOfWorkProtocol | None]`. `open()` rejects nesting, enters exactly one factory unit, installs it only for the current task, commits only when the coordinator explicitly calls `uow.commit()`, and always clears the context after cancellation, rollback, or close. `require_active_uow()` returns `AsyncUnitOfWorkProtocol` and fails closed outside the scope. Child tasks receive no usable mutation authority: the stored scope token also binds the creating `asyncio.current_task()`, and a different task is rejected even if context variables were copied.

The factory is a single application-lifecycle object and closes its worker only during orderly shutdown after all units of work finish. Before the first unit opens, composition may register a closed set of fixed internal post-commit signals whose targets expose only constant-time `offer_nowait()`. A transaction can mark a registered signal by name; rollback/context failure clears it, while successful terminal commit invokes it only after the database commit is terminal. Signal failure is counted and swallowed so it cannot rewrite a committed mutation; the durable outbox plus periodic/startup drain remains authoritative. Arbitrary callbacks and late registration are forbidden. The fair application-level async transaction lock is acquired before `BEGIN IMMEDIATE` and held through close, so operations from two live units can never interleave and a second writer waits instead of exhausting SQLite busy retries behind the first. Lock acquisition is cancellable; once acquired, `_terminal_call` absorbs any number of cancellation deliveries until the single-worker operation finishes, preserves the first cancellation, and entry failure/cancellation executes `UnitOfWork.__exit__` on that worker before clearing `_sync` and releasing the lock. A transaction may await those local serialized repository/audit operations only; it must never await provider, robot, browser, timer, filesystem, or other unbounded I/O while holding `BEGIN IMMEDIATE`. Enter, commit, rollback, and close are terminal before cancellation propagates.

- [ ] **Step 4: Run the green transaction gate**

Run: `uv run pytest tests/integration/storage/test_transactions.py tests/integration/storage/test_async_transactions.py tests/unit/transactions/test_mutation_scope.py -q && uv run ruff check apps/core/src/tuntun_core/adapters/sqlcipher/unit_of_work.py apps/core/src/tuntun_core/adapters/sqlcipher/async_unit_of_work.py apps/core/src/tuntun_core/adapters/sqlcipher/repository_facade.py apps/core/src/tuntun_core/services/transactions/mutation_scope.py tests/integration/storage/test_transactions.py tests/integration/storage/test_async_transactions.py tests/unit/transactions/test_mutation_scope.py && uv run mypy apps/core/src/tuntun_core/adapters/sqlcipher apps/core/src/tuntun_core/services/transactions`

Expected: PASS for all transaction and mutation-scope tests, including cancellation before lock acquisition, while the worker is entering, and immediately after `BEGIN IMMEDIATE`; every case observes `_sync is None`, a released application lock, closed worker connections, zero persisted rows, and a succeeding next writer; Ruff/mypy report zero errors.

- [ ] **Step 5: Commit exact Task 14 paths**

```bash
git status --short
git add apps/core/src/tuntun_core/adapters/sqlcipher/unit_of_work.py apps/core/src/tuntun_core/adapters/sqlcipher/async_unit_of_work.py apps/core/src/tuntun_core/adapters/sqlcipher/repository_facade.py apps/core/src/tuntun_core/services/transactions/protocols.py apps/core/src/tuntun_core/services/transactions/mutation_scope.py tests/integration/storage/conftest.py tests/integration/storage/test_transactions.py tests/integration/storage/test_async_transactions.py tests/unit/transactions/conftest.py tests/unit/transactions/test_mutation_scope.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(storage): add explicit encrypted unit of work"
```

### Task 15: Implement and verify the tamper-evident audit chain

**Master package:** 06
**Depends on:** Tasks 13 and 14.
**Estimated effort:** 1.5 person-days.

**Files:**
- Create: `apps/core/src/tuntun_core/services/audit/ledger.py`
- Create: `apps/core/src/tuntun_core/services/audit/verifier.py`
- Create: `tests/conftest.py`
- Test: `tests/unit/audit/test_chain.py`
- Test: `tests/security/test_audit_tamper.py`
- Test: `tests/integration/audit/test_concurrency.py`
- Create: `docs/operations/foundation-storage.md`

**Interfaces:**
- Consumes: `AuditDraft`, `AuditReceipt`, `canonical_bytes`, HMAC key ID/key, the Task 5 project-owned `ClockPort`, the Task 9 `FakeClock`, and the Task 14 project-owned `UnitOfWorkProtocol` or `AsyncUnitOfWorkProtocol`. Audit service modules never import `tuntun_core.adapters`; composition supplies the structurally conforming SQLCipher adapters and an application-owned clock.
- Produces: `AuditLedger(key_id: str, key: bytes, clock: ClockPort)`; `AuditLedger.append(uow, draft) -> AuditReceipt`; `AsyncAuditLedger.append(uow, draft) -> Awaitable[AuditReceipt]`; `AuditLedger.seal(uow, first_ordinal: int, last_ordinal: int) -> AuditSegment`; `AuditVerifier.verify(connection) -> AuditVerification(valid: bool, count: int, terminal_public_hash_hex: str | None, reason: str)`. `seal` calls the injected clock exactly once, rejects a naive result, normalizes an aware result to UTC, persists the exact six-fractional-digit `YYYY-MM-DDTHH:MM:SS.ffffffZ` value, and returns the same instant as `AuditSegment.sealed_at`; it never reads ambient wall-clock time. `AsyncAuditLedger` delegates through `uow.run_sync` and never opens or commits a transaction. A rotated ledger may append with a new `hmac_key_id`; verification requires every key ID still referenced by a retained receipt/segment.
- Chain formula: `public_hash = SHA256(previous_public_hash_bytes || canonical_body_bytes)`; `hmac = HMAC-SHA-256(key, b"tuntun:audit:v1\x00" || public_hash_bytes || canonical_body_bytes)`.

- [ ] **Step 1: Write red chain, tamper, rollback, and concurrency tests**

```python
# tests/unit/audit/test_chain.py
from datetime import UTC, datetime
from uuid import UUID
from tuntun_contracts.audit import AuditDraft
from tuntun_contracts.base import Commitment
from tuntun_core.services.audit.ledger import compute_chain_values

def test_chain_formula_is_deterministic_and_purpose_separated() -> None:
    draft=AuditDraft(event_id=UUID(int=1),occurred_at=datetime(2026,8,27,tzinfo=UTC),actor_pseudonym="synthetic-guest",action_code="foundation.init",outcome="allow",reason_code="initialized",correlation_id=UUID(int=2),payload_commitment=Commitment(algorithm="HMAC-SHA-256",key_id="audit-v1",value_b64="A"*43+"="))
    first=compute_chain_values(None,draft,"audit-v1",b"K"*32)
    second=compute_chain_values(None,draft,"audit-v1",b"K"*32)
    assert first == second; assert len(first.public_hash_hex) == 64; assert first.hmac_b64 != first.public_hash_hex

def test_rotation_and_segment_sealing_require_all_retained_keys(audit_fixture) -> None:
    audit_fixture.append_with_key("audit-v1", b"K"*32, 1)
    audit_fixture.append_with_key("audit-v2", b"R"*32, 2)
    segment=audit_fixture.seal(1,2)
    assert (segment.first_ordinal,segment.last_ordinal,segment.receipt_count) == (1,2,2)
    assert audit_fixture.verify({"audit-v1":b"K"*32,"audit-v2":b"R"*32}).valid is True
    assert audit_fixture.verify({"audit-v2":b"R"*32}).reason == "missing-hmac-key"

def test_segment_seal_uses_the_injected_clock_exactly(audit_fixture) -> None:
    audit_fixture.append_index(1)
    audit_fixture.append_index(2)
    segment=audit_fixture.seal(1,2)
    expected=datetime(2026,8,27,12,34,56,789123,tzinfo=UTC)
    assert segment.sealed_at == expected
    assert audit_fixture.segment_sealed_at(segment.segment_id) == "2026-08-27T12:34:56.789123Z"
    assert audit_fixture.clock.calls == 1

def test_audit_service_depends_only_on_project_owned_transaction_protocol() -> None:
    import inspect
    import tuntun_core.services.audit.ledger as ledger_module
    source=inspect.getsource(ledger_module)
    assert "tuntun_core.adapters" not in source
    assert "tuntun_core.services.transactions.protocols" in source
```

```python
# tests/security/test_audit_tamper.py
import pytest
from sqlalchemy import text
from tuntun_core.services.audit.verifier import AuditVerifier

def test_database_triggers_reject_audit_update_and_delete(audited_database) -> None:
    connection=audited_database.engine.raw_connection()
    with pytest.raises(Exception, match="append-only"): connection.execute("UPDATE audit_receipts SET canonical_body_json='{}'")
    with pytest.raises(Exception, match="append-only"): connection.execute("DELETE FROM audit_receipts")
    connection.close()

def test_verifier_detects_offline_ciphertext_tamper(audited_database) -> None:
    with audited_database.engine.connect() as connection:
        result=AuditVerifier({"audit-v1":b"K"*32}).verify(connection)
    assert result.valid is True and result.count == 2

@pytest.mark.parametrize("mutation",(
    "duplicate_key","noncanonical_whitespace","overdeep_json",
    "flat_json_overflow","body_over_64k",
))
def test_verifier_fails_closed_on_malformed_persisted_canonical_body(
    audit_fixture,mutation,
) -> None:
    audit_fixture.replace_canonical_body_offline(mutation)
    result=audit_fixture.verify({"audit-v1":b"K"*32})
    assert result.valid is False and result.reason=="invalid-canonical-body"
```

```python
# tests/integration/audit/test_concurrency.py
from concurrent.futures import ThreadPoolExecutor
def test_parallel_append_assigns_unique_contiguous_ordinals(audit_fixture) -> None:
    with ThreadPoolExecutor(max_workers=8) as pool: receipts=list(pool.map(audit_fixture.append_index, range(32)))
    assert sorted(receipt.ordinal for receipt in receipts) == list(range(1,33))
    assert audit_fixture.verify().valid is True
```

Own both cross-tree fixtures in root `tests/conftest.py`, the only pytest scope visible to unit, security, and integration audit tests. `audited_database` creates one migrated encrypted database and appends exactly two synthetic receipts in separate committed adapter units. `audit_fixture` creates a separate empty migrated encrypted database so its first append is ordinal 1; it is not layered on `audited_database`.

```python
# tests/conftest.py
from dataclasses import dataclass
from datetime import UTC,datetime,timedelta
from pathlib import Path
from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine

from tuntun_contracts.audit import AuditDraft
from tuntun_contracts.base import Commitment
from tuntun_core.adapters.sqlcipher.engine import create_sqlcipher_engine
from tuntun_core.adapters.sqlcipher.unit_of_work import UnitOfWork
from tuntun_core.services.audit.ledger import AuditLedger
from tuntun_core.services.audit.verifier import AuditVerifier
from tuntun_testing.fake_clock import FakeClock


@dataclass(frozen=True,slots=True)
class AuditedDatabase:
    engine:Engine; path:Path; key:bytes


def _create_database(path:Path) -> AuditedDatabase:
    key=bytes(range(32)); config=Config("apps/core/alembic.ini")
    config.attributes["sqlcipher_path"]=path
    config.attributes["sqlcipher_key"]=key
    command.upgrade(config,"head")
    return AuditedDatabase(create_sqlcipher_engine(path,key),path,key)


def _draft(index:int) -> AuditDraft:
    return AuditDraft(
        event_id=UUID(int=700+index),
        occurred_at=datetime(2026,8,27,tzinfo=UTC)+timedelta(microseconds=index),
        actor_pseudonym="synthetic-guest",action_code="foundation.fixture",
        outcome="allow",reason_code=f"fixture-{index}",
        correlation_id=UUID(int=800+index),
        payload_commitment=Commitment(
            algorithm="HMAC-SHA-256",key_id="audit-v1",value_b64="A"*43+"=",
        ),
    )


def _audit_clock() -> FakeClock:
    return FakeClock(datetime(2026,8,27,12,34,56,789123,tzinfo=UTC))


def _append(database:AuditedDatabase,key_id:str,key:bytes,index:int,clock:FakeClock):
    with UnitOfWork(database.engine) as uow:
        receipt=AuditLedger(key_id,key,clock).append(uow,_draft(index)); uow.commit()
    return receipt


def _dispose(database:AuditedDatabase) -> None:
    database.engine.dispose()
    for candidate in (database.path,Path(f"{database.path}-wal"),Path(f"{database.path}-shm")):
        candidate.unlink(missing_ok=True)


class AuditFixture:
    def __init__(self,database:AuditedDatabase,clock:FakeClock):
        self.database=database; self.clock=clock; self.keys={"audit-v1":b"K"*32}
    def append_with_key(self,key_id: str,key:bytes,index:int):
        self.keys[key_id]=key; return _append(self.database,key_id,key,index,self.clock)
    def append_index(self,index:int):
        return self.append_with_key("audit-v1",b"K"*32,index)
    def seal(self,first_ordinal:int,last_ordinal:int):
        with UnitOfWork(self.database.engine) as uow:
            segment=AuditLedger("audit-v1",b"K"*32,self.clock).seal(uow,first_ordinal,last_ordinal)
            uow.commit(); return segment
    def segment_sealed_at(self,segment_id:str) -> str:
        with self.database.engine.connect() as connection:
            value=connection.exec_driver_sql(
                "SELECT sealed_at FROM audit_segments WHERE id=?",(segment_id,),
            ).scalar_one()
        return str(value)
    def verify(self,keys=None):
        with self.database.engine.connect() as connection:
            return AuditVerifier(self.keys if keys is None else keys).verify(connection)
    def replace_canonical_body_offline(self,mutation:str) -> None:
        bodies={
            "duplicate_key":'{"event_id":"x","event_id":"y"}',
            "noncanonical_whitespace":'{ "event_id" : "x" }',
            "overdeep_json":"["*33+"0"+"]"*33,
            "flat_json_overflow":"["+",".join("0" for _ in range(16_385))+"]",
            "body_over_64k":'"'+"x"*65_537+'"',
        }
        try: body=bodies[mutation]
        except KeyError as error: raise AssertionError(f"unknown audit mutation: {mutation}") from error
        if self.verify().count==0:
            self.append_index(1)
        with self.database.engine.begin() as connection:
            connection.exec_driver_sql("DROP TRIGGER audit_receipts_no_update")
            connection.exec_driver_sql(
                "UPDATE audit_receipts SET canonical_body_json=? WHERE ordinal=1",(body,),
            )


@pytest.fixture
def audited_database(tmp_path:Path):
    database=_create_database(tmp_path/"audited.db")
    clock=_audit_clock()
    _append(database,"audit-v1",b"K"*32,1,clock); _append(database,"audit-v1",b"K"*32,2,clock)
    try: yield database
    finally: _dispose(database)


@pytest.fixture
def audit_fixture(tmp_path:Path):
    database=_create_database(tmp_path/"audit-fixture.db")
    fixture=AuditFixture(database,_audit_clock())
    try: yield fixture
    finally: _dispose(database)
```

The helper methods above are the full fixture interface consumed by the shown tests. `audit_fixture.clock` is a Task 9 `FakeClock` fixed at `2026-08-27T12:34:56.789123Z`, counts `now()` calls, and `segment_sealed_at(segment_id)` returns the exact persisted text. Mutation bodies are injected only after migration by dropping the update trigger inside that fixture database, modeling an offline attacker; production ledger/verifier code is never monkeypatched. `append_index(index)` uses `UUID(int=700+index)`, correlation `UUID(int=800+index)`, and the fixed aware time plus `index` microseconds. Every teardown disposes the engine and removes DB/WAL/SHM.

- [ ] **Step 2: Run the red audit tests**

Run: `uv run pytest tests/unit/audit/test_chain.py tests/security/test_audit_tamper.py tests/integration/audit/test_concurrency.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.services.audit.ledger'`.

- [ ] **Step 3: Implement append and full-chain verification**

```python
# apps/core/src/tuntun_core/services/audit/ledger.py
import base64, hashlib, hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4
from sqlalchemy import text
from tuntun_contracts.audit import AuditDraft, AuditReceipt
from tuntun_contracts.base import canonical_bytes
from tuntun_contracts.ports import ClockPort
from tuntun_core.services.transactions.protocols import (
    AsyncUnitOfWorkProtocol,UnitOfWorkProtocol,
)

PURPOSE=b"tuntun:audit:v1\x00"
@dataclass(frozen=True, slots=True)
class ChainValues: public_hash_hex: str; hmac_b64: str; canonical_body_json: str
@dataclass(frozen=True, slots=True)
class AuditSegment:
    segment_id: str; first_ordinal: int; last_ordinal: int; receipt_count: int
    terminal_public_hash_hex: str; terminal_hmac_b64: str; hmac_key_id: str
    sealed_at: datetime
def compute_chain_values(previous_public_hash_hex: str | None, draft: AuditDraft, key_id: str, key: bytes) -> ChainValues:
    body=canonical_bytes(draft); previous=bytes.fromhex(previous_public_hash_hex) if previous_public_hash_hex else b""
    public=hashlib.sha256(previous+body).digest(); mac=hmac.new(key,PURPOSE+public+body,hashlib.sha256).digest()
    return ChainValues(public.hex(),base64.b64encode(mac).decode("ascii"),body.decode("utf-8"))
class AuditLedger:
    def __init__(self, key_id: str, key: bytes, clock: ClockPort) -> None:
        if len(key)<32: raise ValueError("audit HMAC key must be at least 32 bytes")
        self.key_id=key_id; self.key=key; self.clock=clock
    def append(self, uow: UnitOfWorkProtocol, draft: AuditDraft) -> AuditReceipt:
        row=uow.execute(text("SELECT ordinal,public_hash_hex FROM audit_receipts ORDER BY ordinal DESC LIMIT 1")).mappings().first()
        ordinal=1 if row is None else int(row["ordinal"])+1; previous=None if row is None else str(row["public_hash_hex"])
        values=compute_chain_values(previous,draft,self.key_id,self.key); receipt_id=uuid4()
        uow.execute(text("INSERT INTO audit_receipts(id,ordinal,previous_public_hash_hex,public_hash_hex,hmac_key_id,hmac_b64,canonical_body_json,occurred_at) VALUES(:id,:ordinal,:previous,:public,:key_id,:mac,:body,:occurred)"), {"id":str(receipt_id),"ordinal":ordinal,"previous":previous,"public":values.public_hash_hex,"key_id":self.key_id,"mac":values.hmac_b64,"body":values.canonical_body_json,"occurred":draft.occurred_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ")})
        return AuditReceipt(receipt_id=receipt_id,ordinal=ordinal,public_hash_hex=values.public_hash_hex,hmac_key_id=self.key_id,hmac_b64=values.hmac_b64,occurred_at=draft.occurred_at)
    def seal(self, uow: UnitOfWorkProtocol, first_ordinal: int, last_ordinal: int) -> AuditSegment:
        rows=uow.execute(text("SELECT ordinal,public_hash_hex,hmac_b64,hmac_key_id FROM audit_receipts WHERE ordinal BETWEEN :first AND :last ORDER BY ordinal"),{"first":first_ordinal,"last":last_ordinal}).mappings().all()
        if not rows or rows[0]["ordinal"] != first_ordinal or rows[-1]["ordinal"] != last_ordinal or len(rows) != last_ordinal-first_ordinal+1: raise ValueError("segment range is not contiguous")
        terminal=rows[-1]; segment_id=str(uuid4()); sealed_at=self.clock.now()
        if sealed_at.tzinfo is None: raise ValueError("audit seal clock must be timezone-aware")
        sealed_at=sealed_at.astimezone(UTC)
        sealed_text=sealed_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        uow.execute(text("INSERT INTO audit_segments(id,first_ordinal,last_ordinal,receipt_count,terminal_public_hash_hex,terminal_hmac_b64,hmac_key_id,sealed_at,exported_at) VALUES(:id,:first,:last,:count,:public,:mac,:key_id,:sealed,NULL)"),{"id":segment_id,"first":first_ordinal,"last":last_ordinal,"count":len(rows),"public":terminal["public_hash_hex"],"mac":terminal["hmac_b64"],"key_id":terminal["hmac_key_id"],"sealed":sealed_text})
        return AuditSegment(segment_id,first_ordinal,last_ordinal,len(rows),str(terminal["public_hash_hex"]),str(terminal["hmac_b64"]),str(terminal["hmac_key_id"]),sealed_at)

class AsyncAuditLedger:
    def __init__(self, ledger: AuditLedger) -> None: self._ledger=ledger
    async def append(self, uow:AsyncUnitOfWorkProtocol, draft: AuditDraft) -> AuditReceipt:
        return await uow.run_sync(lambda transaction: self._ledger.append(transaction,draft))
    async def seal(self, uow:AsyncUnitOfWorkProtocol, first_ordinal: int, last_ordinal: int) -> AuditSegment:
        return await uow.run_sync(lambda transaction: self._ledger.seal(transaction,first_ordinal,last_ordinal))
```

```python
# apps/core/src/tuntun_core/services/audit/verifier.py
from dataclasses import dataclass
from sqlalchemy import Connection, text
from tuntun_contracts.audit import AuditDraft
from tuntun_contracts.base import parse_contract_json
from .ledger import compute_chain_values

@dataclass(frozen=True, slots=True)
class AuditVerification:
    valid: bool; count: int; terminal_public_hash_hex: str | None; reason: str
class AuditVerifier:
    def __init__(self, keys: dict[str,bytes]) -> None: self.keys=keys
    def verify(self, connection: Connection) -> AuditVerification:
        previous=None; count=0
        for row in connection.execute(text("SELECT ordinal,previous_public_hash_hex,public_hash_hex,hmac_key_id,hmac_b64,canonical_body_json FROM audit_receipts ORDER BY ordinal")).mappings():
            count += 1
            if row["ordinal"] != count or row["previous_public_hash_hex"] != previous: return AuditVerification(False,count-1,previous,"ordinal-or-link-mismatch")
            key=self.keys.get(str(row["hmac_key_id"]))
            if key is None: return AuditVerification(False,count-1,previous,"missing-hmac-key")
            try:
                draft=parse_contract_json(
                    AuditDraft,str(row["canonical_body_json"]).encode("utf-8"),
                    max_bytes=65_536,require_canonical=True,
                )
            except (TypeError,UnicodeError,ValueError):
                return AuditVerification(
                    False,count-1,previous,"invalid-canonical-body",
                )
            values=compute_chain_values(previous,draft,str(row["hmac_key_id"]),key)
            if values.public_hash_hex != row["public_hash_hex"] or values.hmac_b64 != row["hmac_b64"]: return AuditVerification(False,count-1,previous,"hash-or-hmac-mismatch")
            previous=values.public_hash_hex
        for segment in connection.execute(text("SELECT first_ordinal,last_ordinal,receipt_count,terminal_public_hash_hex,terminal_hmac_b64,hmac_key_id FROM audit_segments ORDER BY first_ordinal")).mappings():
            terminal=connection.execute(text("SELECT public_hash_hex,hmac_b64,hmac_key_id FROM audit_receipts WHERE ordinal=:ordinal"),{"ordinal":segment["last_ordinal"]}).mappings().first()
            if terminal is None or segment["receipt_count"] != segment["last_ordinal"]-segment["first_ordinal"]+1: return AuditVerification(False,count,previous,"invalid-segment-range")
            if terminal["public_hash_hex"] != segment["terminal_public_hash_hex"] or terminal["hmac_b64"] != segment["terminal_hmac_b64"] or terminal["hmac_key_id"] != segment["hmac_key_id"]: return AuditVerification(False,count,previous,"segment-terminal-mismatch")
        return AuditVerification(True,count,previous,"ok")
```

Add an initialization service test in `test_chain.py` that appends `foundation.init` with application version `0.1.0.dev0` and schema `0001_foundation` encoded only in `action_code`/`reason_code` categories; assert canonical JSON contains neither the current username nor `Path.cwd()`. Add a kill-point test that inserts a household plus audit receipt in one `UnitOfWork`, raises before commit, and observes neither row afterward. Add a raw-byte scan asserting none of the synthetic audit draft values nor `SQLite format 3` appears in DB/WAL/SHM.

Write `docs/operations/foundation-storage.md` with startup order: resolve Keychain roots → open SQLCipher key first → verify cipher/integrity/permissions → encrypted backup before migrations → run Alembic on already-keyed connection → verify schema marker → verify complete audit chain → start services. Document fail-closed outcomes, WAL checkpoint rule, key-version retention, migration downgrade/restore command, and the exact `0001_foundation` table list.

- [ ] **Step 4: Run the green audit/foundation gate**

Run: `uv run pytest tests/integration/storage tests/unit/audit tests/security/test_audit_tamper.py tests/integration/audit -q && uv run pytest tests/unit/audit tests/security/test_audit_tamper.py tests/integration/audit --cov=tuntun_core.services.audit --cov-branch --cov-fail-under=95 && make lint && make typecheck && make verify-private-data`

Expected: PASS for migration, rollback, chain, trigger, concurrency, initialization, and raw-byte tests; audit branch coverage is at least 95%; all static/private-data gates exit 0.

- [ ] **Step 5: Commit exact Task 15 paths**

```bash
git status --short
git add apps/core/src/tuntun_core/services/audit/ledger.py apps/core/src/tuntun_core/services/audit/verifier.py tests/conftest.py tests/unit/audit/test_chain.py tests/security/test_audit_tamper.py tests/integration/audit/test_concurrency.py docs/operations/foundation-storage.md
git diff --cached --name-only
git diff --cached
git commit -m "feat(storage): add tamper-evident foundation audit"
```

## Foundation Completion Checkpoint

Run from a clean checkout on the target Intel Mac:

```bash
make bootstrap
make check
uv run pytest tests/contract tests/unit/config tests/unit/testing tests/security/test_shared_assurance_tools.py tests/security/test_sqlcipher.py tests/security/test_record_crypto.py tests/integration/storage tests/unit/audit tests/security/test_audit_tamper.py tests/integration/audit -q
uv run tuntunctl storage probe --path var/probe/foundation.db --json
uv run python scripts/check_model_manifest.py models/manifest.yaml
uv run python scripts/verify_private_data.py .
git status --short
```

Expected: every test and static gate passes; the five shared assurance commands pass complete synthetic inventories and fail closed for incomplete ones; storage probe reports `sqlcipher3==0.6.2`, a non-empty cipher version, `integrity_ok: true`, mode `0o600`, and no path/key material; model/private-data scans print PASS; `git status --short` is empty. The encrypted DB contains exactly the 16 application tables enumerated by Task 13 plus `alembic_version` (17 non-`sqlite_` tables total), rejects audit update/delete, reveals neither the SQLite header nor any sentinel, and downgrades to only `alembic_version` before upgrading again. The exact-set assertion in `test_foundation_upgrade_downgrade_upgrade` is authoritative; no count-only gate may replace it.

## Execution Handoff

Plan complete at master work package 06. Continue only after the target-Mac SQLCipher checkpoint and the encrypted schema/audit verification are accepted. The next master task is Task 07; no conversation, provider, Reachy transport, profile, biometric, auth, memory, API, or UI feature beyond the bootstrap shell belongs in this subplan.
