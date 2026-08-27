# Tuntun Phase 1 Foundation Execution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build master work packages 01–06 from an otherwise empty repository, ending with strict version-1 contracts, fail-closed configuration and secrets, deterministic fakes/model governance, verified SQLCipher/record encryption, the exact `0001_foundation` schema, and a tamper-evident audit ledger.

**Architecture:** Establish four Python workspace packages and one minimal React application, then freeze project-owned contracts before adding adapters. Configuration, Keychain, model installation, SQLCipher, record encryption, migrations, transactions, and audit are separate ports/adapters with fail-closed boundaries; the only durable database produced by this plan is encrypted and contains exactly the tables owned by `0001_foundation.py`.

**Tech Stack:** Python 3.12, `uv`, Pydantic v2, Pydantic Settings, Typer, RFC 8785/JCS, SQLAlchemy 2, Alembic, `sqlcipher3==0.6.2`, `cryptography`, keyring/macOS Keychain, structlog, JSON Schema, pytest, pytest-asyncio, Hypothesis, Ruff, strict mypy; React 19, TypeScript, Vite, Vitest, Testing Library, pnpm, Playwright, and GitHub Actions.

## Global Constraints

1. The normative specification is `docs/superpowers/specs/2026-08-27-tuntun-phase1-anchor-design.md`; changing a locked decision requires a specification update and ADR before implementation.
2. Python is exactly 3.12 at the repository boundary. `sqlcipher3==0.6.2` is a compatibility candidate and is accepted only after the target Intel Mac probe passes.
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
| Contracts | `packages/contracts/src/tuntun_contracts/*.py`, `fixtures/v1/*.json` | Frozen DTOs, canonical bytes, and async ports; no adapters |
| Configuration | `apps/core/src/tuntun_core/config/*.py`, `config/tuntun.example.yaml` | Strict defaults, YAML/env precedence, owner-only paths |
| Secrets/logging | `apps/core/src/tuntun_core/adapters/keychain/*.py` | `SecretProvider`, macOS backend, typed redaction |
| Deterministic tools | `packages/testing/src/tuntun_testing/*.py`, `apps/core/src/tuntun_core/services/models/*.py` | Fake clock/providers/Reachy, scenario runner, governed model registry |
| Storage | `apps/core/src/tuntun_core/adapters/sqlcipher/*.py` | Key-first SQLCipher connection, record AEAD, engine, unit of work, schema metadata |
| Migration | `apps/core/migrations/env.py`, `versions/0001_foundation.py` | Exactly the foundation-owned tables and DB triggers |
| Audit | `apps/core/src/tuntun_core/services/audit/*.py` | Ordered public SHA-256 chain plus versioned HMAC commitments and verification |

Exact cross-task interfaces are fixed here and repeated in the owning task:

```python
class SecretProvider(Protocol):
    def get(self, service: str, account: str) -> bytes: raise NotImplementedError
    def set(self, service: str, account: str, value: bytes) -> None: raise NotImplementedError
    def delete(self, service: str, account: str) -> None: raise NotImplementedError
    def exists(self, service: str, account: str) -> bool: raise NotImplementedError

def open_sqlcipher(path: Path, key: bytes) -> sqlcipher3.Connection: raise NotImplementedError
def create_sqlcipher_engine(path: Path, key: bytes) -> sqlalchemy.Engine: raise NotImplementedError

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
    async def commit(self) -> None: raise NotImplementedError
    async def rollback(self) -> None: raise NotImplementedError
    async def __aexit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> bool: raise NotImplementedError

class AtomicMutationScope:
    def open(self) -> AsyncContextManager[AsyncUnitOfWork]: raise NotImplementedError
    def require_active_uow(self) -> AsyncUnitOfWork: raise NotImplementedError

class AuditLedger:
    def append(self, uow: UnitOfWork, draft: AuditDraft) -> AuditReceipt: raise NotImplementedError

class AsyncAuditLedger:
    async def append(self, uow: AsyncUnitOfWork, draft: AuditDraft) -> AuditReceipt: raise NotImplementedError

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
requires-python = "==3.12.*"

[build-system]
requires = ["hatchling>=1.27,<2"]
build-backend = "hatchling.build"
```

```toml
# packages/contracts/pyproject.toml
[project]
name = "tuntun-contracts"
version = "0.1.0.dev0"
requires-python = "==3.12.*"
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
- Create: `package.json`
- Create: `pnpm-workspace.yaml`
- Create: `pnpm-lock.yaml`
- Create: `apps/admin/package.json`
- Create: `apps/admin/index.html`
- Create: `apps/admin/vite.config.ts`
- Create: `apps/admin/tsconfig.json`
- Create: `apps/admin/src/main.tsx`
- Create: `apps/admin/src/app.tsx`
- Create: `apps/admin/src/test-setup.ts`
- Test: `apps/admin/src/app.test.tsx`
- Create: `Makefile`
- Create: `.gitignore`
- Create: `.pre-commit-config.yaml`
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: Task 1 workspace commands.
- Produces: `make bootstrap|format|lint|typecheck|test|test-security|test-contract|web-test|web-build|web-e2e|check|verify-private-data`; a non-networked admin page rendering `Tuntun setup in progress`; CI with read-only contents permission and no secrets/hardware/provider jobs.

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

- [ ] **Step 2: Run the red web test**

Run: `corepack enable && pnpm --filter @tuntun/admin test`

Expected: FAIL with `No projects matched the filters` because the pnpm workspace is absent.

- [ ] **Step 3: Add the minimal web application and command surface**

```json
// package.json
{"name":"tuntun-workspace","private":true,"packageManager":"pnpm@10.15.0"}
```

```yaml
# pnpm-workspace.yaml
packages:
  - apps/admin
```

```json
// apps/admin/package.json
{
  "name": "@tuntun/admin",
  "private": true,
  "type": "module",
  "scripts": {
    "build": "tsc --noEmit && vite build",
    "test": "vitest run",
    "e2e": "playwright test"
  },
  "dependencies": {"react":"19.1.1","react-dom":"19.1.1"},
  "devDependencies": {"@playwright/test":"1.55.0","@testing-library/jest-dom":"6.8.0","@testing-library/react":"16.3.0","@types/react":"19.1.10","@types/react-dom":"19.1.7","@vitejs/plugin-react":"5.0.2","jsdom":"26.1.0","typescript":"5.9.2","vite":"7.1.3","vitest":"3.2.4"}
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
import {defineConfig} from "vite";
export default defineConfig({plugins: [react()], test: {environment: "jsdom", setupFiles: ["./src/test-setup.ts"]}});
```

```ts
// apps/admin/src/test-setup.ts
import "@testing-library/jest-dom/vitest";
```

```json
// apps/admin/tsconfig.json
{"compilerOptions":{"target":"ES2022","module":"ESNext","moduleResolution":"Bundler","jsx":"react-jsx","strict":true,"noEmit":true},"include":["src","vite.config.ts"]}
```

```html
<!-- apps/admin/index.html -->
<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Tuntun</title></head><body><div id="root"></div><script type="module" src="/src/main.tsx"></script></body></html>
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
typecheck:
	uv run mypy apps/core/src apps/edge/src packages/contracts/src packages/testing/src
test:
	uv run pytest -m "not live_cloud and not reachy_hardware" --cov --cov-branch
test-security:
	uv run pytest tests/security -m "not live_cloud and not reachy_hardware"
test-contract:
	uv run pytest tests/contract
web-test:
	pnpm --filter @tuntun/admin test
web-build:
	pnpm --filter @tuntun/admin build
web-e2e:
	pnpm --filter @tuntun/admin e2e
verify-private-data:
	uv run python scripts/verify_private_data.py .
check: lint typecheck test web-test web-build verify-private-data
```

```gitignore
# .gitignore
.env
.venv/
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
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v6
        with: {version: "0.8.13", enable-cache: true}
      - uses: pnpm/action-setup@v4
        with: {version: "10.15.0", run_install: false}
      - uses: actions/setup-node@v4
        with: {node-version: "22", cache: pnpm}
      - run: uv sync --all-packages --frozen
      - run: pnpm install --frozen-lockfile
      - run: make lint typecheck test web-test web-build
```

- [ ] **Step 4: Run the green web/build gate**

Run: `pnpm install && pnpm --filter @tuntun/admin test && pnpm --filter @tuntun/admin build && make lint && make typecheck`

Expected: PASS with one Vitest test, a successful Vite production build, and zero Ruff/mypy errors.

- [ ] **Step 5: Commit exact Task 2 paths**

```bash
git status --short
git add package.json pnpm-workspace.yaml pnpm-lock.yaml apps/admin/package.json apps/admin/index.html apps/admin/vite.config.ts apps/admin/tsconfig.json apps/admin/src/main.tsx apps/admin/src/app.tsx apps/admin/src/app.test.tsx apps/admin/src/test-setup.ts Makefile .gitignore .pre-commit-config.yaml .github/workflows/ci.yml
git diff --cached --name-only
git diff --cached
git commit -m "build: add web workspace and baseline CI"
```

### Task 3: Add the fail-closed private-data scanner

**Master package:** 01
**Depends on:** Task 1.
**Estimated effort:** 0.5 person-day.

**Files:**
- Create: `scripts/verify_private_data.py`
- Test: `tests/security/test_private_data_scanner.py`
- Create: `tests/fixtures/synthetic/README.md`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: repository root path.
- Produces: `scan(root: Path) -> tuple[Finding, ...]`; CLI exits 1 and prints relative paths/reason codes for forbidden content, otherwise prints `private-data scan: PASS` and exits 0.

- [ ] **Step 1: Write the scanner’s red tests**

```python
# tests/security/test_private_data_scanner.py
from pathlib import Path

from scripts.verify_private_data import scan


def test_scanner_rejects_secret_and_database(tmp_path: Path) -> None:
    credential = "sk-" + "proj-" + "A" * 24
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
```

- [ ] **Step 2: Run the red scanner tests**

Run: `uv run pytest tests/security/test_private_data_scanner.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'scripts.verify_private_data'`.

- [ ] **Step 3: Implement bounded path/content scanning**

```python
# scripts/verify_private_data.py
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

FORBIDDEN_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".pem", ".key", ".crt", ".wav", ".mp3", ".mp4", ".jpg", ".jpeg", ".png", ".onnx", ".safetensors"}
PATTERNS = (("credential-pattern", re.compile(rb"(?:sk-proj-|AKIA)[A-Za-z0-9_-]{16,}")), ("private-key", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")))
SKIP_PARTS = {".git", ".venv", "node_modules", "dist", "var"}


@dataclass(frozen=True, slots=True)
class Finding:
    path: Path
    reason: str


def scan(root: Path) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        relative = path.relative_to(root)
        if any(part in SKIP_PARTS for part in relative.parts):
            continue
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            findings.append(Finding(relative, "forbidden-extension"))
            continue
        data = path.read_bytes()[:2_000_000]
        for reason, pattern in PATTERNS:
            if pattern.search(data):
                findings.append(Finding(relative, reason))
    return tuple(findings)


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    findings = scan(root)
    for finding in findings:
        print(f"{finding.path}: {finding.reason}")
    if findings:
        return 1
    print("private-data scan: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Create `tests/fixtures/synthetic/README.md` stating that fixtures use generated UUIDs and roles only, never recorded media, real names, credentials, addresses, host identifiers, or provider bodies.

Change the final CI command in `.github/workflows/ci.yml` from `make lint typecheck test web-test web-build` to `make check`; Task 3 now owns the scanner that makes the full command available.

- [ ] **Step 4: Run the green scanner gate**

Run: `uv run pytest tests/security/test_private_data_scanner.py -q && uv run python scripts/verify_private_data.py .`

Expected: PASS with `2 passed` and `private-data scan: PASS`.

- [ ] **Step 5: Commit exact Task 3 paths**

```bash
git status --short
git add scripts/verify_private_data.py tests/security/test_private_data_scanner.py tests/fixtures/synthetic/README.md .github/workflows/ci.yml
git diff --cached --name-only
git diff --cached
git commit -m "security: add fail-closed private-data scanner"
```

### Task 4: Freeze canonical contract primitives and signed event envelopes

**Master package:** 02
**Depends on:** Tasks 1 and 3.
**Estimated effort:** 1 person-day.

**Files:**
- Create: `packages/contracts/src/tuntun_contracts/base.py`
- Create: `packages/contracts/src/tuntun_contracts/events.py`
- Modify: `packages/contracts/src/tuntun_contracts/__init__.py`
- Test: `tests/contract/test_strict_models.py`
- Test: `tests/contract/test_event_canonicalization.py`

**Interfaces:**
- Consumes: Pydantic v2 and `rfc8785.dumps(value) -> bytes`.
- Produces: `ContractModel`, `Sensitivity`, `Commitment`, `canonical_bytes(model: ContractModel) -> bytes`, `EventType`, `WakeDetectedPayload`, `StopRequestedPayload`, `EventEnvelope`, and `SignedEventEnvelope` exactly as shown below.

- [ ] **Step 1: Write strictness and canonical-byte tests**

```python
# tests/contract/test_strict_models.py
from datetime import datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from tuntun_contracts.base import Commitment, canonical_bytes
from tuntun_contracts.events import StopRequestedPayload
from tuntun_contracts.events import EventEnvelope


def test_contracts_reject_extra_fields_and_naive_time() -> None:
    with pytest.raises(ValidationError):
        Commitment(algorithm="HMAC-SHA-256", key_id="audit-v1", value_b64="A" * 44, extra=True)
    with pytest.raises(ValidationError, match="timezone-aware"):
        EventEnvelope.model_validate({
            "schema_version":"1.0","event_id":str(UUID(int=1)),"event_type":"speech.wake_detected",
            "household_id":str(UUID(int=2)),"device_id":str(UUID(int=3)),"session_id":None,
            "correlation_id":str(UUID(int=4)),"causation_id":None,"device_sequence":1,
            "occurred_at":datetime(2026, 8, 27, 1, 2, 3),"sensitivity":"household",
            "payload_commitment":{"algorithm":"HMAC-SHA-256","key_id":"audit-v1","value_b64":"A" * 44},
            "payload":{"kind":"speech.wake_detected","turn_id":str(UUID(int=5)),"score_micros":900000},
        })
```

```python
# tests/contract/test_event_canonicalization.py
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from tuntun_contracts.base import Commitment, Sensitivity, canonical_bytes
from tuntun_contracts.events import EventEnvelope, EventType, WakeDetectedPayload

VALID_WAKE = {
    "schema_version":"1.0","event_id":str(UUID(int=1)),"event_type":"speech.wake_detected",
    "household_id":str(UUID(int=2)),"device_id":str(UUID(int=3)),"session_id":None,
    "correlation_id":str(UUID(int=4)),"causation_id":None,"device_sequence":1,
    "occurred_at":"2026-08-27T01:02:03.000004Z","sensitivity":"household",
    "payload_commitment":{"algorithm":"HMAC-SHA-256","key_id":"audit-v1","value_b64":"A" * 44},
    "payload":{"kind":"speech.wake_detected","turn_id":str(UUID(int=5)),"score_micros":900000},
}


def test_event_canonical_bytes_use_nfc_and_six_utc_digits() -> None:
    envelope = EventEnvelope(
        schema_version="1.0", event_id=UUID(int=1), event_type=EventType.WAKE_DETECTED,
        household_id=UUID(int=2), device_id=UUID(int=3), session_id=None,
        correlation_id=UUID(int=4), causation_id=None, device_sequence=7,
        occurred_at=datetime(2026, 8, 27, 1, 2, 3, 4, UTC), sensitivity=Sensitivity.HOUSEHOLD,
        payload_commitment=Commitment(algorithm="HMAC-SHA-256", key_id="audit-v1", value_b64="A" * 44),
        payload=WakeDetectedPayload(kind="speech.wake_detected", turn_id=UUID(int=5), score_micros=900000),
    )
    encoded = canonical_bytes(envelope)
    assert b'"occurred_at":"2026-08-27T01:02:03.000004Z"' in encoded
    assert encoded == canonical_bytes(envelope)


def test_event_type_must_equal_payload_kind() -> None:
    data = EventEnvelope.model_json_schema()
    assert data["title"] == "EventEnvelope"
    with pytest.raises(ValidationError, match="event_type must equal payload.kind"):
        EventEnvelope.model_validate({**VALID_WAKE, "event_type":"safety.stop_requested"})
```

- [ ] **Step 2: Run the red contract tests**

Run: `uv run pytest tests/contract/test_strict_models.py tests/contract/test_event_canonicalization.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_contracts.base'`.

- [ ] **Step 3: Implement strict base types and event validation**

```python
# packages/contracts/src/tuntun_contracts/base.py
from __future__ import annotations

import base64
from datetime import UTC, datetime
from enum import Enum, StrEnum
from typing import Any, Literal
from unicodedata import normalize
from uuid import UUID

import rfc8785
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, validate_assignment=True, str_strip_whitespace=True)

    @field_validator("*", mode="before")
    @classmethod
    def require_aware_datetimes(cls, value: Any) -> Any:
        if isinstance(value, datetime) and value.tzinfo is None:
            raise ValueError("datetime must be timezone-aware")
        return value


class Sensitivity(StrEnum):
    PUBLIC = "public"; HOUSEHOLD = "household"; PERSONAL = "personal"
    SENSITIVE = "sensitive"; RESTRICTED = "restricted"


class Commitment(ContractModel):
    algorithm: Literal["HMAC-SHA-256"]
    key_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    value_b64: str = Field(min_length=40, max_length=128, pattern=r"^[A-Za-z0-9+/]+={0,2}$")


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
    if isinstance(value, dict):
        return {normalize("NFC", str(key)): _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    return value


def canonical_bytes(model: ContractModel) -> bytes:
    return rfc8785.dumps(_canonical_value(model.model_dump(mode="python")))
```

```python
# packages/contracts/src/tuntun_contracts/events.py
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from .base import Commitment, ContractModel, Sensitivity


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
    source: Literal["edge_keyword", "physical_input", "owner_console", "watchdog"]


EventPayload = Annotated[WakeDetectedPayload | StopRequestedPayload, Field(discriminator="kind")]


class EventEnvelope(ContractModel):
    schema_version: Literal["1.0"]
    event_id: UUID; event_type: EventType; household_id: UUID; device_id: UUID
    session_id: UUID | None; correlation_id: UUID; causation_id: UUID | None
    device_sequence: Annotated[int, Field(ge=0)]
    occurred_at: AwareDatetime; sensitivity: Sensitivity
    payload_commitment: Commitment; payload: EventPayload

    @model_validator(mode="after")
    def matching_type(self) -> "EventEnvelope":
        if self.event_type.value != self.payload.kind:
            raise ValueError("event_type must equal payload.kind")
        return self


class SignedEventEnvelope(ContractModel):
    envelope: EventEnvelope
    signing_key_id: Annotated[str, Field(min_length=8, max_length=128)]
    signature_b64: Annotated[str, Field(min_length=80, max_length=128)]
```

- [ ] **Step 4: Run the green canonical-contract gate**

Run: `uv run pytest tests/contract/test_strict_models.py tests/contract/test_event_canonicalization.py -q && uv run ruff check packages/contracts/src tests/contract && uv run mypy packages/contracts/src`

Expected: PASS with all contract tests passing and Ruff/mypy exiting 0.

- [ ] **Step 5: Commit exact Task 4 paths**

```bash
git status --short
git add packages/contracts/src/tuntun_contracts/base.py packages/contracts/src/tuntun_contracts/events.py packages/contracts/src/tuntun_contracts/__init__.py tests/contract/test_strict_models.py tests/contract/test_event_canonicalization.py
git diff --cached --name-only
git diff --cached
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
- Test: `tests/contract/test_v1_types_and_ports.py`
- Test: `tests/contract/test_dependency_direction.py`

**Interfaces:**
- Consumes: `ContractModel`, `Commitment`, `Sensitivity`, and event DTOs from Task 4.
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
    async def delete(self, memory_id: UUID, expected_version: int, auth: AuthContext) -> None: raise NotImplementedError
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
from tuntun_contracts.base import Commitment, canonical_bytes
from tuntun_contracts.events import StopRequestedPayload
from tuntun_contracts.identity import PersonaProjection, PersonaTraits
from tuntun_contracts.memory import MemoryAudience, MemoryKind, PreferenceContent
from tuntun_contracts.policy import AdminSessionPrincipal, AssuranceLevel, AuthGrant, CurrentOwnerAuthority
from tuntun_contracts.ports import ActionProviderPort, AuthenticationPort, BudgetPort, LanguageModelPort, MemoryRepositoryPort, RouteAuthorizerPort, ReachyPort
from tuntun_contracts.provider import RouteAuthorization
from tuntun_contracts.reachy import StopSignal
from tuntun_contracts.speech import AuthorizedSynthesisRequest, AuthorizedTranscriptionRequest


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
        request_commitment=Commitment(algorithm="HMAC-SHA-256", key_id="route-v1", value_b64="A" * 44),
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
        "parameters_commitment": Commitment(algorithm="HMAC-SHA-256", key_id="action-hmac-v1", value_b64="A" * 44),
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
        parameters_commitment=Commitment(algorithm="HMAC-SHA-256", key_id="action-hmac-v1", value_b64="A" * 44),
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
            parameters_commitment=Commitment(algorithm="HMAC-SHA-256", key_id="action-hmac-v1", value_b64="A" * 44),
            uncertainty_micros=0, expires_at=datetime(2026, 8, 27, tzinfo=UTC), idempotency_key=UUID(int=29),
        )


@pytest.fixture
def valid_action_payloads() -> dict[str, dict[str, object]]:
    def base(action_name: str, resource_id: int) -> dict[str, object]:
        return {
            "proposal_id": UUID(int=100 + resource_id), "schema_version": "1.0", "action_name": action_name,
            "resource_type": action_name.split(".", 1)[0], "resource_id": UUID(int=resource_id),
            "parameters_commitment": Commitment(algorithm="HMAC-SHA-256", key_id="action-hmac-v1", value_b64="A" * 44),
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
from pydantic import Field
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
    language_hints: tuple[Literal["en", "hi"], ...]
    route: RouteAuthorization

class TranscriptResult(ContractModel):
    request_id: UUID; text: Annotated[str, Field(min_length=1, max_length=32_000)]
    language: Literal["en", "hi", "hinglish", "unknown"]; duration_ms: Annotated[int, Field(ge=0, le=90_000)]

class AuthorizedSynthesisRequest(ContractModel):
    request_id: UUID; turn_id: UUID; text: Annotated[str, Field(min_length=1, max_length=8_000)]
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
from pydantic import AwareDatetime, Field
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
    messages: tuple[SanitizedProviderMessage, ...]; allowed_tools: tuple[SanitizedToolReference, ...]
    max_output_tokens: Annotated[int, Field(ge=1, le=16_384)]; store: Literal[False] = False
    redaction_receipt_id: UUID; route: RouteAuthorization
    timeout_ms: Annotated[int, Field(ge=1_000, le=120_000)]

class Usage(ContractModel):
    input_units: Annotated[int, Field(ge=0)]; output_units: Annotated[int, Field(ge=0)]
    audio_millis: Annotated[int, Field(ge=0)]; provider_usage_present: bool

class ProviderResponse(ContractModel):
    request_id: UUID; text: Annotated[str, Field(min_length=1, max_length=8_000)]
    language: Literal["en", "hi", "hinglish"]; usage: Usage
class RedactionReceipt(ContractModel):
    receipt_id: UUID; purpose: Literal["cloud_reasoning","cloud_tts"]
    input_commitment: Commitment; output_commitment: Commitment
    removed_categories: tuple[str, ...]; removed_count: Annotated[int, Field(ge=0)]
    policy_version: str; maximum_sensitivity: Sensitivity
```

```python
# packages/contracts/src/tuntun_contracts/memory.py
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID
from pydantic import AwareDatetime, Field, model_validator
from .base import Commitment, ContractModel, Sensitivity

class MemoryKind(StrEnum):
    WORKING="working"; EPISODIC="episodic"; SEMANTIC="semantic"; PREFERENCE="preference"
    PROCEDURAL="procedural"; RELATIONAL="relational"; POLICY="policy"

class MemoryAudience(StrEnum):
    SUBJECT_PRIVATE="subject_private"; GUARDIAN_CHILD="guardian_child"
    HOUSEHOLD_ADULTS="household_adults"; HOUSEHOLD_ALL="household_all"

class WorkingContent(ContractModel):
    kind: Literal["working"]; state_summary: str = Field(max_length=2_000); unresolved_intents: tuple[str, ...]
class EpisodicContent(ContractModel):
    kind: Literal["episodic"]; event_summary: str = Field(max_length=2_000); occurred_at: AwareDatetime; participant_ids: tuple[UUID, ...]
class SemanticContent(ContractModel):
    kind: Literal["semantic"]; subject: str = Field(max_length=256); predicate: str = Field(max_length=128); object: str = Field(max_length=2_000)
class PreferenceContent(ContractModel):
    kind: Literal["preference"] = "preference"; category: str = Field(max_length=128); key: str = Field(max_length=128); value: str = Field(max_length=2_000); strength_micros: Annotated[int, Field(ge=0, le=1_000_000)]
class ProceduralContent(ContractModel):
    kind: Literal["procedural"]; name: str = Field(max_length=256); steps: tuple[str, ...]; tool_label: str | None = Field(default=None, max_length=128)
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
    household_id: UUID; subject_id: UUID; kinds: tuple[MemoryKind, ...]
    maximum_sensitivity: Sensitivity; limit: Annotated[int, Field(ge=1, le=6)] = 6
class ApprovedMemory(ContractModel):
    memory_id: UUID; household_id: UUID; subject_id: UUID; content: MemoryContent; audience: MemoryAudience; sensitivity: Sensitivity
    source_receipt_ids: tuple[UUID, ...]; valid_until: AwareDatetime | None
class ProposalContext(ContractModel):
    household_id: UUID; subject_id: UUID | None; session_id: UUID; turn_id: UUID; actor_subject_id: UUID | None
class DecideMemoryProposal(ContractModel):
    proposal_id: UUID; decision: Literal["approve","reject"]; edited_content: MemoryContent | None; expected_version: Annotated[int, Field(ge=1)]
```

Create the remaining modules with these exact declarations:

```python
# identity.py
class IdentityStatus(StrEnum): VERIFIED="verified"; AMBIGUOUS="ambiguous"; UNKNOWN="unknown"; CONFLICT="conflict"
class IdentityEvidence(ContractModel):
    modality: Literal["face","voice"]; subject_id: UUID | None
    confidence_micros: Annotated[int, Field(ge=0, le=1_000_000)]
    quality_micros: Annotated[int, Field(ge=0, le=1_000_000)]
    liveness_accepted: bool; model_version: str; observed_at: AwareDatetime; expires_at: AwareDatetime
class IdentityRequest(ContractModel): household_id: UUID; session_id: UUID; evidence: tuple[IdentityEvidence, ...]
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
class BudgetReservationRequest(ContractModel): household_id: UUID; turn_id: UUID; request_id: UUID; attempt_id: UUID; provider: Literal["openai","qwen"]; model: str; category: Literal["stt","llm","tts"]; worst_case_micros_sgd: Annotated[int, Field(ge=0)]; month_key: str
class BudgetReservation(ContractModel): reservation_id: UUID; request_id: UUID; attempt_id: UUID; outcome: Literal["allow","allow_soft_warning","deny_hard_limit","deny_unknown_price"]; amount_micros_sgd: Annotated[int, Field(ge=0)]; expires_at: AwareDatetime
class BudgetSettlementRequest(ContractModel): reservation_id: UUID; attempt_id: UUID; actual_micros_sgd: Annotated[int, Field(ge=0)] | None; provider_usage_present: bool
class BudgetSettlement(ContractModel): reservation_id: UUID; charged_micros_sgd: Annotated[int, Field(ge=0)]; conservative_estimate_used: bool
class TransportProof(ContractModel): reservation_id: UUID; attempt_id: UUID; disposition: Literal["never_sent","sent","unknown"]; evidence_code: str; observed_at: AwareDatetime
class BudgetReconciliationRequest(ContractModel): turn_id: UUID; proofs: tuple[TransportProof, ...]

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

The contract semantics are also frozen: `IdentityFusionPort` returns identity only and cannot mint assurance. `AuthGrant`/`AuthContext.assurance_source` deliberately has no biometric value, so face/voice evidence cannot create `confirmed` or a stronger assurance. `CurrentOwnerAuthority` is the current database observation of one exact household owner subject, owner generation, and active profile version. `AdminSessionPrincipal` additionally binds that authority snapshot to one exact admin-session version plus idle/absolute expiries; request and mutation boundaries must re-open the session row, reject `revoked_at`, compare every principal field, and revalidate the current owner snapshot before use. It proves only a current owner console session and can never substitute for an action-bound `AuthGrant`/`AuthContext`; every mutation reconstructs its exact binding on the server and consumes a fresh matching grant when the registry requires one. The same admin principal grants no implicit memory-body visibility: every memory create/replace persists one closed `MemoryAudience`, and later read projections use subject, current guardian, and audience policy before decryption. An `ActionBinding` includes household, proposal, turn, idempotency, action, resource, parameter commitment, policy, conversation session, and subject, so a proof cannot be transplanted across any of those boundaries. `ActionReceipt` additionally persists `household_id` and the server-derived `resource_scope`; its idempotency boundary is exactly `(household_id, action_name, resource_scope, idempotency_key)`, matching `action_proposals`, and a global unique idempotency key is forbidden. Frozen DTOs remain fields-only: callers use explicit binding comparators, policy-request factories, and audit-draft mappers rather than calling undeclared methods on them. `RouteAuthorizerPort.consume` is single-use and must compare every `RouteConsumption` binding field to the stored authorization in constant time for commitments before any adapter I/O. `BudgetPort.release_unsent` accepts only a matching `TransportProof(disposition="never_sent")`; `sent` and `unknown` reconcile conservatively through settlement, while every retry retains `request_id` and receives a fresh `attempt_id`. `CameraWindowGrant` is the only contract that permits camera frames; it is action/subject/session/turn/purpose-bound, single-use, at most 10 seconds/20 frames/10 MiB, and its byte/frame/rate/expiry bounds may only be narrowed downstream.

`web_search` and `child_durable_memory_v1` are Phase 1 contract amendments consumed by the controlled-web and identity/memory supplements. `web_search` is durable owner/adult self-consent; `child_durable_memory_v1` is durable K2/N1 consent granted or revoked only by that child's current primary guardian with the exact guardian generation. Neither widens the baseline `RouteAuthorization` speech/reasoning/TTS purpose union. Every consent draft carries the expected latest receipt ID, guardian generation when applicable, and policy/disclosure versions; revoke requires a non-null expected receipt. Its purpose-separated parameter commitment covers exactly subject, purpose, expected receipt state, guardian generation, and both versions, while the `ActionBinding` separately fixes household, authenticated actor, action, resource, session, and turn. The mutation service reconstructs that payload and compares its HMAC before any receipt access. Guest disclosure/session-consent contracts remain exactly `cloud_stt|cloud_reasoning|cloud_tts`; K2/N1 search and owner/adult child-memory consent are policy-denied even if a caller forges a prepared consent action. This amendment changes no task number or effort estimate.

`PersonaTraits` is the only prepared profile-personalization payload. Its four closed fields contain no arbitrary text, exact child identifier, profession/name string, secret, contact, or household fact. `PersonaProjection` adds only the canonical role and is the complete value allowed into persona/context construction. `profile.edit` must be exactly one of replace or clear, must carry an expected profile version, and cannot carry a role change. Its server mapper loads and freezes `target_profile_class`; owner/adult self-edits require a null `guardian_generation`, while K2/N1 edits require the exact current guardian generation. The parameter commitment binds subject, actor via `ActionBinding`, operation, version, target class, guardian generation, and the full typed payload. The mutation service reconstructs and verifies that commitment before its first profile read, then rechecks the loaded immutable class and current guardian relation/generation in the mutation UoW; stale or substituted generations fail closed. Credential capability `profile_persona` is distinct from `adult_self_consent`: it can authorize only that exact bound `profile.edit` replace/clear path, never consent or administration. This contract work is folded into the existing contract task and changes no task or effort total.

`memory.export` is the one-record export action: `memory_id`, the server-loaded `expected_version`, `resource_id=memory_id`, subject, and `export_format="json"` are all mandatory and commitment-bound. It cannot represent a profile-wide export, omit the version, or carry another memory operation's fields; whole-profile export remains the distinct `profile.export` action. Exact record/version/subject substitution fails before memory projection or decryption.

- [ ] **Step 4: Run the green DTO/port gate**

Run: `uv run pytest tests/contract/test_v1_types_and_ports.py tests/contract/test_dependency_direction.py -q && uv run ruff check packages/contracts/src tests/contract && uv run mypy packages/contracts/src`

Expected: PASS; required enum values match exactly and every asserted port operation is async.

- [ ] **Step 5: Commit exact Task 5 paths**

```bash
git status --short
git add packages/contracts/src/tuntun_contracts/actions.py packages/contracts/src/tuntun_contracts/audit.py packages/contracts/src/tuntun_contracts/budget.py packages/contracts/src/tuntun_contracts/identity.py packages/contracts/src/tuntun_contracts/memory.py packages/contracts/src/tuntun_contracts/policy.py packages/contracts/src/tuntun_contracts/provider.py packages/contracts/src/tuntun_contracts/reachy.py packages/contracts/src/tuntun_contracts/speech.py packages/contracts/src/tuntun_contracts/ports.py packages/contracts/src/tuntun_contracts/__init__.py tests/contract/test_v1_types_and_ports.py tests/contract/test_dependency_direction.py
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

from tuntun_contracts.base import Commitment, canonical_bytes
from tuntun_contracts.events import EventEnvelope, SignedEventEnvelope, StopRequestedPayload, WakeDetectedPayload
from tuntun_contracts.speech import AudioFormat, AuthorizedTranscriptionRequest, TranscriptResult, AuthorizedSynthesisRequest, SpeechChunk
from tuntun_contracts.identity import IdentityEvidence, IdentityRequest, IdentityDecision
from tuntun_contracts.actions import ActionBinding, ActionProposalDraft, ActionReceipt, ValidatedActionProposal
from tuntun_contracts.memory import WorkingContent, EpisodicContent, SemanticContent, PreferenceContent, ProceduralContent, RelationalContent, PolicyContent, MemoryProposalDraft, MemoryProposal, MemoryRecord, MemoryQuery, ApprovedMemory, ProposalContext, DecideMemoryProposal
from tuntun_contracts.policy import PolicyRequest, PolicyDecision, AuthenticationRequest, AuthenticationChallenge, AuthenticationResponse, AuthGrant, AuthContext, CurrentOwnerAuthority, AdminSessionPrincipal, TimerIntent
from tuntun_contracts.provider import RouteAuthorization, RouteAuthorizationRequest, RouteConsumption, ProviderResponseReceipt, SanitizedProviderMessage, SanitizedToolReference, SanitizedProviderRequest, Usage, ProviderResponse, RedactionReceipt
from tuntun_contracts.budget import BudgetReservationRequest, BudgetReservation, BudgetSettlementRequest, BudgetSettlement, TransportProof, BudgetReconciliationRequest
from tuntun_contracts.audit import AuditDraft, AuditReceipt
from tuntun_contracts.reachy import ReachyCommand, ReachyReceipt, ReachyHealth, SafetyReceipt, StopSignal, CameraWindowGrant
from tuntun_contracts.ports import TurnInput, TurnOutput

FIXTURE_ROOT = Path("packages/contracts/fixtures/v1")
MODEL_REGISTRY = {
    "actions":{"ActionProposalDraft":ActionProposalDraft,"ActionBinding":ActionBinding,"ValidatedActionProposal":ValidatedActionProposal,"ActionReceipt":ActionReceipt},
    "events":{"Commitment":Commitment,"WakeDetectedPayload":WakeDetectedPayload,"StopRequestedPayload":StopRequestedPayload,"EventEnvelope":EventEnvelope,"SignedEventEnvelope":SignedEventEnvelope,"TurnInput":TurnInput,"TurnOutput":TurnOutput},
    "speech":{"AudioFormat":AudioFormat,"AuthorizedTranscriptionRequest":AuthorizedTranscriptionRequest,"TranscriptResult":TranscriptResult,"AuthorizedSynthesisRequest":AuthorizedSynthesisRequest,"SpeechChunk":SpeechChunk},
    "identity":{"IdentityEvidence":IdentityEvidence,"IdentityRequest":IdentityRequest,"IdentityDecision":IdentityDecision},
    "memory":{"WorkingContent":WorkingContent,"EpisodicContent":EpisodicContent,"SemanticContent":SemanticContent,"PreferenceContent":PreferenceContent,"ProceduralContent":ProceduralContent,"RelationalContent":RelationalContent,"PolicyContent":PolicyContent,"MemoryProposalDraft":MemoryProposalDraft,"MemoryProposal":MemoryProposal,"MemoryRecord":MemoryRecord,"MemoryQuery":MemoryQuery,"ApprovedMemory":ApprovedMemory,"ProposalContext":ProposalContext,"DecideMemoryProposal":DecideMemoryProposal},
    "policy":{"PolicyRequest":PolicyRequest,"PolicyDecision":PolicyDecision,"AuthenticationRequest":AuthenticationRequest,"AuthenticationChallenge":AuthenticationChallenge,"AuthenticationResponse":AuthenticationResponse,"AuthGrant":AuthGrant,"AuthContext":AuthContext,"CurrentOwnerAuthority":CurrentOwnerAuthority,"AdminSessionPrincipal":AdminSessionPrincipal,"TimerIntent":TimerIntent},
    "provider":{"RouteAuthorization":RouteAuthorization,"RouteAuthorizationRequest":RouteAuthorizationRequest,"RouteConsumption":RouteConsumption,"ProviderResponseReceipt":ProviderResponseReceipt,"SanitizedProviderMessage":SanitizedProviderMessage,"SanitizedToolReference":SanitizedToolReference,"SanitizedProviderRequest":SanitizedProviderRequest,"Usage":Usage,"ProviderResponse":ProviderResponse,"RedactionReceipt":RedactionReceipt},
    "budget":{"BudgetReservationRequest":BudgetReservationRequest,"BudgetReservation":BudgetReservation,"BudgetSettlementRequest":BudgetSettlementRequest,"BudgetSettlement":BudgetSettlement,"TransportProof":TransportProof,"BudgetReconciliationRequest":BudgetReconciliationRequest},
    "audit":{"AuditDraft":AuditDraft,"AuditReceipt":AuditReceipt},
    "reachy":{"ReachyCommand":ReachyCommand,"ReachyReceipt":ReachyReceipt,"ReachyHealth":ReachyHealth,"SafetyReceipt":SafetyReceipt,"StopSignal":StopSignal,"CameraWindowGrant":CameraWindowGrant},
}


@pytest.mark.parametrize("name", ["actions","events","speech","identity","memory","policy","provider","budget","audit","reachy"])
def test_fixture_file_exists_and_is_version_one(name: str) -> None:
    payload = json.loads((FIXTURE_ROOT / f"{name}.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0"
    assert set(payload["examples"]) == set(MODEL_REGISTRY[name])
    for model_name, model_type in MODEL_REGISTRY[name].items():
        model = model_type.model_validate(payload["examples"][model_name])
        assert canonical_bytes(model).decode("utf-8") == payload["canonical_examples"][model_name]


def test_event_fixture_round_trips_to_identical_canonical_bytes() -> None:
    payload = json.loads((FIXTURE_ROOT / "events.json").read_text(encoding="utf-8"))
    model = EventEnvelope.model_validate(payload["examples"]["EventEnvelope"])
    assert canonical_bytes(model).decode("utf-8") == payload["canonical_examples"]["EventEnvelope"]
```

- [ ] **Step 2: Run the red fixture tests**

Run: `uv run pytest tests/contract/test_v1_fixtures.py -q`

Expected: FAIL with `FileNotFoundError: packages/contracts/fixtures/v1/events.json`.

- [ ] **Step 3: Add deterministic fixtures and privacy documents**

```python
# scripts/generate_contract_fixtures.py
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from tuntun_contracts import actions, audit, budget, events, identity, memory, policy, ports, provider, reachy, speech
from tuntun_contracts.base import Commitment, ContractModel, canonical_bytes

MODULES = {
    "actions": (actions,),
    "events": (events, ports), "speech": (speech,), "identity": (identity,), "memory": (memory,),
    "policy": (policy,), "provider": (provider,), "budget": (budget,), "audit": (audit,), "reachy": (reachy,),
}

def registry() -> dict[str, dict[str, type[ContractModel]]]:
    result: dict[str, dict[str, type[ContractModel]]] = {}
    for group, modules in MODULES.items():
        models: dict[str, type[ContractModel]] = {}
        for module in modules:
            for name, value in vars(module).items():
                if isinstance(value, type) and issubclass(value, ContractModel) and value is not ContractModel and value.__module__ == module.__name__:
                    models[name] = value
        result[group] = models
    result["events"]["Commitment"] = Commitment
    return result

def sample(schema: dict[str, Any], definitions: dict[str, Any], field_name: str, counter: list[int]) -> Any:
    if "$ref" in schema: return sample(definitions[schema["$ref"].split("/")[-1]], definitions, field_name, counter)
    if "const" in schema: return schema["const"]
    if "enum" in schema: return schema["enum"][0]
    if field_name == "subject_id" and any(choice.get("type") == "null" for choice in schema.get("anyOf", [])): return None
    for union_key in ("oneOf", "anyOf"):
        if union_key in schema:
            choices=[choice for choice in schema[union_key] if choice.get("type") != "null"]
            return sample(choices[0], definitions, field_name, counter)
    kind=schema.get("type")
    if kind == "object" or "properties" in schema:
        return {name: sample(child, definitions, name, counter) for name, child in schema.get("properties", {}).items() if name in schema.get("required", [])}
    if kind == "array": return []
    if kind == "integer": return int(schema.get("minimum", 0))
    if kind == "number": return int(schema.get("minimum", 0))
    if kind == "boolean": return False
    if kind == "string":
        if schema.get("format") == "uuid": counter[0]+=1; return f"00000000-0000-0000-0000-{counter[0]:012d}"
        if schema.get("format") == "date-time": return "2026-08-27T01:02:03.000004Z"
        pattern=str(schema.get("pattern", ""))
        if "0-9a-f" in pattern: return "0" * 64
        if "A-Za-z0-9+/" in pattern: return "A" * 44
        length=max(int(schema.get("minLength", 1)), len("status")); return ("status" + "x" * length)[:length]
    if kind == "null": return None
    raise ValueError(f"unsupported fixture schema for {field_name}: {schema}")

def main() -> None:
    root=Path("packages/contracts/fixtures/v1"); root.mkdir(parents=True,exist_ok=True)
    counter=[100]
    for group, models in registry().items():
        examples: dict[str, object]={}; canonical: dict[str, str]={}
        for name, model_type in sorted(models.items()):
            schema=model_type.model_json_schema(); value=sample(schema, schema.get("$defs",{}), name, counter)
            if name == "AuthGrant": value.update({"assurance":"confirmed","assurance_source":"explicit_confirmation"})
            if name == "AuthContext": value.update({"grant_id":None,"assurance":"guest","assurance_source":"guest"})
            model=model_type.model_validate(value); examples[name]=model.model_dump(mode="json"); canonical[name]=canonical_bytes(model).decode("utf-8")
        (root/f"{group}.json").write_text(json.dumps({"schema_version":"1.0","examples":examples,"canonical_examples":canonical},indent=2,sort_keys=True)+"\n",encoding="utf-8")

if __name__ == "__main__": main()
```

This generator discovers every public `ContractModel` declared in the owning modules, assigns fixed UUIDs beginning at `00000000-0000-0000-0000-000000000101`, uses only `status`-derived synthetic strings and the fixed timestamp, validates every generated object, and writes canonical oracles. Review the generated diff once, then retain both the generator and fixtures; CI reruns the generator and fails if `git diff --exit-code packages/contracts/fixtures/v1` is non-empty. No fixture contains audio, a conversation transcript, names, addresses, credentials, or provider prose.

Write `docs/privacy/threat-model.md` with assets (database/key roots, audit authenticity, contracts/model manifest, availability), actors (owner, family subject, Guest, LAN attacker, malicious model output, compromised dependency), trust boundaries (Reachy↔LAN↔Mac, browser↔API, Mac↔provider, build↔dependency/model sources), and foundation mitigations mapped to Task 3 scanning, strict contracts, Keychain, SQLCipher, AEAD, manifest hashes, and audit triggers. Write `docs/privacy/data-flow-inventory.md` as a table with columns `Data class | Source | Purpose | Processor | Durable location | Egress | Retention/deletion | Key`; include configuration, secrets, event receipts, audit receipts, provider-price/budget metadata, model metadata, and synthetic fixtures. Mark raw audio/transcripts/frames as “not processed by foundation; durable location none.”

- [ ] **Step 4: Run the green fixture/privacy gate**

Run: `uv run python scripts/generate_contract_fixtures.py && uv run pytest tests/contract/test_v1_fixtures.py -q && uv run python scripts/generate_contract_fixtures.py && git diff --exit-code packages/contracts/fixtures/v1 && uv run python scripts/verify_private_data.py packages/contracts/fixtures/v1 docs/privacy`

Expected: PASS with 11 fixture tests and `private-data scan: PASS`.

- [ ] **Step 5: Commit exact Task 6 paths**

```bash
git status --short
git add packages/contracts/fixtures/v1/actions.json packages/contracts/fixtures/v1/events.json packages/contracts/fixtures/v1/speech.json packages/contracts/fixtures/v1/identity.json packages/contracts/fixtures/v1/memory.json packages/contracts/fixtures/v1/policy.json packages/contracts/fixtures/v1/provider.json packages/contracts/fixtures/v1/budget.json packages/contracts/fixtures/v1/audit.json packages/contracts/fixtures/v1/reachy.json scripts/generate_contract_fixtures.py tests/contract/test_v1_fixtures.py docs/privacy/threat-model.md docs/privacy/data-flow-inventory.md
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
- Create: `apps/core/src/tuntun_core/config/paths.py`
- Create: `config/tuntun.example.yaml`
- Create: `.env.example`
- Test: `tests/unit/config/test_settings.py`
- Test: `tests/unit/config/test_paths.py`

**Interfaces:**
- Consumes: YAML file and explicit `TUNTUN_` environment overrides.
- Produces: `Settings` and `load_settings(yaml_path: Path | None, environ: Mapping[str, str]) -> Settings`; `ApplicationPaths.create(base: Path | None = None) -> ApplicationPaths` with `root`, `data`, `logs`, `models`, and `backups` directories at mode `0700`.

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
```

```python
# tests/unit/config/test_paths.py
import stat
from pathlib import Path
from tuntun_core.config.paths import ApplicationPaths

def test_paths_are_created_owner_only(tmp_path: Path) -> None:
    paths = ApplicationPaths.create(tmp_path / "Tuntun")
    for path in (paths.root, paths.data, paths.logs, paths.models, paths.backups):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
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
    model_config = ConfigDict(extra="forbid", frozen=True)
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
from pathlib import Path
from typing import Mapping
import yaml
from .settings import Settings

def load_settings(yaml_path: Path | None, environ: Mapping[str, str]) -> Settings:
    data: dict[str, object] = {}
    if yaml_path is not None:
        loaded = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict): raise ValueError("configuration root must be a mapping")
        data = loaded
    for name, raw_value in environ.items():
        if not name.startswith("TUNTUN_"): continue
        path=name.removeprefix("TUNTUN_").lower().split("__")
        if len(path) != 2: raise ValueError(f"invalid TUNTUN override: {name}")
        section, key=path; nested=dict(data.get(section, {})); nested[key]=yaml.safe_load(raw_value); data[section]=nested
    return Settings.model_validate(data)
```

```python
# apps/core/src/tuntun_core/config/paths.py
from dataclasses import dataclass
from pathlib import Path
from platformdirs import user_data_path

@dataclass(frozen=True, slots=True)
class ApplicationPaths:
    root: Path; data: Path; logs: Path; models: Path; backups: Path
    @classmethod
    def create(cls, base: Path | None = None) -> "ApplicationPaths":
        root = base or user_data_path("Tuntun", appauthor=False)
        paths = cls(root, root / "data", root / "logs", root / "models", root / "backups")
        for path in (paths.root, paths.data, paths.logs, paths.models, paths.backups):
            path.mkdir(parents=True, exist_ok=True, mode=0o700); path.chmod(0o700)
        return paths
```

Add `pydantic-settings>=2.10,<3`, `PyYAML>=6.0,<7`, and `platformdirs>=4.4,<5` to core dependencies. Write `config/tuntun.example.yaml` with exactly the locked defaults asserted above, including all three disabled observability switches, and `.env.example` containing only commented variable names, never credential-shaped values.

- [ ] **Step 4: Lock and run the green settings gate**

Run: `uv lock && uv run pytest tests/unit/config/test_settings.py tests/unit/config/test_paths.py -q && uv run ruff check apps/core/src/tuntun_core/config tests/unit/config && uv run mypy apps/core/src/tuntun_core/config`

Expected: PASS with all settings/path tests passing and Ruff/mypy exiting 0.

- [ ] **Step 5: Commit exact Task 7 paths**

```bash
git status --short
git add apps/core/pyproject.toml uv.lock apps/core/src/tuntun_core/config/settings.py apps/core/src/tuntun_core/config/loader.py apps/core/src/tuntun_core/config/paths.py config/tuntun.example.yaml .env.example tests/unit/config/test_settings.py tests/unit/config/test_paths.py
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
- Produces: `SecretProvider` signature from the locked map; `InMemorySecretProvider`; `MacOSKeychainSecretProvider`; `validate_production_secrets(provider: SecretProvider) -> None`; `redact_private_fields(logger: object, method: str, event: MutableMapping[str, object]) -> MutableMapping[str, object]`.

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
from tuntun_core.config.logging import redact_private_fields

def test_redactor_removes_nested_private_values() -> None:
    event = {"event":"provider_failed","authorization":"Bearer secret-sentinel","nested":{"transcript":"private words","ok":7},"audio_bytes":b"secret-audio"}
    redacted = redact_private_fields(None, "error", event)
    encoded = json.dumps(redacted, sort_keys=True)
    assert "secret-sentinel" not in encoded
    assert "private words" not in encoded
    assert "secret-audio" not in encoded
    assert redacted["nested"]["ok"] == 7
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
from collections.abc import MutableMapping
from typing import Any

PRIVATE_KEYS = {"authorization","cookie","api_key","pin","recovery_code","audio","audio_bytes","transcript","prompt","messages","memory","embedding","frame","provider_body"}
def _redact(value: Any) -> Any:
    if isinstance(value, MutableMapping): return {key: ({"redacted": key} if key.lower() in PRIVATE_KEYS else _redact(item)) for key, item in value.items()}
    if isinstance(value, list): return [_redact(item) for item in value]
    if isinstance(value, tuple): return tuple(_redact(item) for item in value)
    return value
def redact_private_fields(logger: object, method: str, event: MutableMapping[str, object]) -> MutableMapping[str, object]:
    return _redact(event)
```

Add `keyring>=25.6,<26` and `structlog>=25.4,<26` to core dependencies.

- [ ] **Step 4: Lock and run the green secret/log gate**

Run: `uv lock && uv run pytest tests/security/test_key_handling.py tests/security/test_log_redaction.py -q && uv run python scripts/verify_private_data.py tests/security && uv run mypy apps/core/src/tuntun_core/adapters/keychain apps/core/src/tuntun_core/config/logging.py`

Expected: PASS with four tests, `private-data scan: PASS`, and mypy exit 0.

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
- Create: `packages/testing/src/tuntun_testing/fake_clock.py`
- Create: `packages/testing/src/tuntun_testing/fake_providers.py`
- Create: `packages/testing/src/tuntun_testing/fake_reachy.py`
- Create: `packages/testing/src/tuntun_testing/scenario.py`
- Modify: `packages/testing/src/tuntun_testing/__init__.py`
- Create: `apps/core/src/tuntun_core/cli/commands/simulate.py`
- Modify: `apps/core/src/tuntun_core/cli/main.py`
- Create: `tests/fixtures/scenarios/guest-hinglish.yaml`
- Test: `tests/unit/testing/test_scenario.py`
- Test: `tests/integration/test_deterministic_turn.py`

**Interfaces:**
- Consumes: Task 5 DTOs and ports; synthetic audio tokens are UUIDs, never media.
- Produces: `FakeClock(start: datetime)`, `advance(delta: timedelta) -> None`; `FakeSpeechToText`, `FakeTextToSpeech`, `FakeLanguageModel`, `FakeIdentity`, `FakeMemory`, `FakePolicy`, `FakeAuthentication`, `FakeAudit`, `FakeBudget`, and `FakeReachy`, each rejecting unexpected calls; `ScenarioRunner.run(path: Path) -> ScenarioResult`; `ScenarioResult.canonical_json() -> bytes`; CLI `tuntunctl simulate --scenario PATH --json`.

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

- [ ] **Step 2: Run the red fake/scenario tests**

Run: `uv run pytest tests/unit/testing/test_scenario.py tests/integration/test_deterministic_turn.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_testing.fake_clock'`.

- [ ] **Step 3: Implement deterministic time, fakes, and scenario serialization**

```python
# packages/testing/src/tuntun_testing/fake_clock.py
from datetime import UTC, datetime, timedelta

class FakeClock:
    def __init__(self, start: datetime) -> None:
        if start.tzinfo is None: raise ValueError("start must be timezone-aware")
        self._now = start.astimezone(UTC); self._monotonic = 0.0
    def now(self) -> datetime: return self._now
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
    async def delete(self, memory_id, expected_version, auth): return await self.call(("delete",memory_id,expected_version,auth))
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

- [ ] **Step 4: Run the green deterministic gate**

Run: `uv lock && uv run pytest tests/unit/testing/test_scenario.py tests/integration/test_deterministic_turn.py -q && uv run tuntunctl simulate --scenario tests/fixtures/scenarios/guest-hinglish.yaml --json > /tmp/tuntun-scenario-a.json && uv run tuntunctl simulate --scenario tests/fixtures/scenarios/guest-hinglish.yaml --json > /tmp/tuntun-scenario-b.json && cmp /tmp/tuntun-scenario-a.json /tmp/tuntun-scenario-b.json && uv run python scripts/verify_private_data.py tests/fixtures/scenarios`

Expected: PASS with three tests and `private-data scan: PASS`.

- [ ] **Step 5: Commit exact Task 9 paths**

```bash
git status --short
git add packages/testing/pyproject.toml packages/testing/src/tuntun_testing/fake_clock.py packages/testing/src/tuntun_testing/fake_providers.py packages/testing/src/tuntun_testing/fake_reachy.py packages/testing/src/tuntun_testing/scenario.py packages/testing/src/tuntun_testing/__init__.py apps/core/src/tuntun_core/cli/commands/simulate.py apps/core/src/tuntun_core/cli/main.py tests/fixtures/scenarios/guest-hinglish.yaml tests/unit/testing/test_scenario.py tests/integration/test_deterministic_turn.py uv.lock
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
- Create: `apps/core/src/tuntun_core/services/models/registry.py`
- Create: `apps/core/src/tuntun_core/services/models/installer.py`
- Create: `apps/core/src/tuntun_core/cli/commands/models.py`
- Modify: `apps/core/src/tuntun_core/cli/main.py`
- Create: `models/manifest.schema.json`
- Create: `models/manifest.yaml`
- Create: `scripts/check_model_manifest.py`
- Test: `tests/security/test_model_governance.py`

**Interfaces:**
- Consumes: owner-invoked immutable HTTPS URL, declared byte size/SHA-256, owner-only model directory.
- Produces: `ModelRegistry.load(manifest: Path) -> ModelRegistry`; `activate(model_id: str) -> ActivatedModel`; `ModelInstaller.install(model_id: str) -> ActivatedModel`; no download occurs in either constructor or `activate`.

- [ ] **Step 1: Write red model-governance tests**

```python
# tests/security/test_model_governance.py
from pathlib import Path
import pytest
from tuntun_core.services.models.registry import ModelRegistry

def test_floating_revision_and_pickle_are_rejected(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text('schema_version: "1.0"\nmodels:\n- id: bad\n  revision: main\n  files:\n  - path: model.pkl\n    size: 1\n    sha256: "' + "0" * 64 + '"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="immutable revision"):
        ModelRegistry.load(manifest)

def test_empty_registry_never_downloads(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.yaml"; manifest.write_text('schema_version: "1.0"\nmodels: []\n', encoding="utf-8")
    registry = ModelRegistry.load(manifest)
    with pytest.raises(LookupError, match="model is not registered"): registry.activate("missing")
```

- [ ] **Step 2: Run the red model tests**

Run: `uv run pytest tests/security/test_model_governance.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.services.models'`.

- [ ] **Step 3: Implement schema validation, activation, and explicit installation**

```python
# apps/core/src/tuntun_core/services/models/registry.py
from dataclasses import dataclass
from pathlib import Path
import re, yaml

SAFE_SUFFIXES = {".onnx", ".json", ".txt", ".tflite", ".safetensors"}
@dataclass(frozen=True, slots=True)
class ModelFile: path: str; size: int; sha256: str; url: str
@dataclass(frozen=True, slots=True)
class ActivatedModel: model_id: str; revision: str; root: Path
@dataclass(frozen=True, slots=True)
class ModelEntry:
    model_id: str; revision: str; license: str; provenance: str; redistribution: str
    approved_purpose: str; runtime: str; architecture: str; input_contract: str; output_contract: str
    benchmark_gate: str; review_date: str; files: tuple[ModelFile, ...]

class ModelRegistry:
    def __init__(self, entries: dict[str, ModelEntry], model_root: Path) -> None: self._entries=entries; self._root=model_root
    @classmethod
    def load(cls, manifest: Path, model_root: Path = Path("var/models")) -> "ModelRegistry":
        raw = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        entries: dict[str, ModelEntry] = {}
        for item in raw.get("models", []):
            revision = str(item.get("revision", ""))
            if not re.fullmatch(r"[0-9a-f]{40,64}", revision): raise ValueError("immutable revision required")
            files = tuple(ModelFile(**file) for file in item["files"])
            if any(Path(file.path).name != file.path or Path(file.path).suffix not in SAFE_SUFFIXES for file in files): raise ValueError("unsafe model serialization or path")
            entry = ModelEntry(model_id=item["id"], revision=revision, license=item["license"], provenance=item["provenance"], redistribution=item["redistribution"], approved_purpose=item["approved_purpose"], runtime=item["runtime"], architecture=item["architecture"], input_contract=item["input_contract"], output_contract=item["output_contract"], benchmark_gate=item["benchmark_gate"], review_date=item["review_date"], files=files)
            entries[entry.model_id] = entry
        return cls(entries, model_root)
    def activate(self, model_id: str) -> ActivatedModel:
        if model_id not in self._entries: raise LookupError("model is not registered")
        entry=self._entries[model_id]; root=self._root/model_id/entry.revision
        for file in entry.files:
            path=root/file.path
            if not path.is_file() or path.stat().st_size != file.size: raise RuntimeError("model is not installed and verified")
            import hashlib
            if hashlib.sha256(path.read_bytes()).hexdigest() != file.sha256: raise RuntimeError("model hash mismatch")
        return ActivatedModel(model_id, entry.revision, root)
```

```python
# apps/core/src/tuntun_core/services/models/installer.py
import hashlib, os, tempfile
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen
from .registry import ActivatedModel, ModelRegistry

class ModelInstaller:
    def __init__(self, registry: ModelRegistry, allowed_hosts: frozenset[str]) -> None: self.registry=registry; self.allowed_hosts=allowed_hosts
    def install(self, model_id: str) -> ActivatedModel:
        entry=self.registry._entries.get(model_id)
        if entry is None: raise LookupError("model is not registered")
        root=self.registry._root/model_id/entry.revision; root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for item in entry.files:
            parsed=urlparse(item.url)
            if parsed.scheme != "https" or parsed.hostname not in self.allowed_hosts: raise ValueError("model URL is not allowlisted HTTPS")
            with urlopen(item.url, timeout=30) as response, tempfile.NamedTemporaryFile(dir=root, delete=False) as target:
                final=urlparse(response.geturl())
                if final.scheme != "https" or final.hostname != parsed.hostname: raise ValueError("model redirect changed origin")
                digest=hashlib.sha256(); size=0
                while chunk := response.read(65536): target.write(chunk); digest.update(chunk); size += len(chunk)
                temporary=Path(target.name)
            if size != item.size or digest.hexdigest() != item.sha256: temporary.unlink(); raise ValueError("model size/hash mismatch")
            os.replace(temporary, root/item.path)
        return self.registry.activate(model_id)
```

Create `models/manifest.schema.json` as JSON Schema draft 2020-12 with `additionalProperties:false` at every object, exact required `ModelEntry` fields from the interface, revision pattern `^[0-9a-f]{40,64}$`, HTTPS URLs, positive file sizes, SHA-256 pattern, and a non-empty models array allowed to be empty only for the initial checked-in `models/manifest.yaml`. Set the initial manifest to `schema_version: "1.0"` and `models: []`. `scripts/check_model_manifest.py` loads YAML, validates it with `jsonschema.Draft202012Validator`, then calls `ModelRegistry.load`; exit 0 with `model manifest: PASS`. Add a Typer `models` sub-app with `list`, `verify`, and explicit `install MODEL_ID` commands; registering the sub-app in `cli/main.py` must not instantiate `ModelInstaller` or perform network I/O at import/startup.

- [ ] **Step 4: Lock and run the green model gate**

Run: `uv lock && uv run pytest tests/security/test_model_governance.py -q && uv run python scripts/check_model_manifest.py models/manifest.yaml && uv run tuntunctl models list`

Expected: PASS with two tests, `model manifest: PASS`, and an empty JSON list from the CLI; no network request occurs.

- [ ] **Step 5: Commit exact Task 10 paths**

```bash
git status --short
git add apps/core/pyproject.toml uv.lock apps/core/src/tuntun_core/services/models/registry.py apps/core/src/tuntun_core/services/models/installer.py apps/core/src/tuntun_core/cli/commands/models.py apps/core/src/tuntun_core/cli/main.py models/manifest.schema.json models/manifest.yaml scripts/check_model_manifest.py tests/security/test_model_governance.py
git diff --cached --name-only
git diff --cached
git commit -m "feat(models): add governed registry and explicit installer"
```

### Task 11: Prove key-first SQLCipher compatibility and add the storage probe

**Master package:** 05
**Depends on:** Task 8.
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
- Consumes: a 32-byte database key and owner-only database path.
- Produces: `open_sqlcipher(path: Path, key: bytes) -> sqlcipher3.Connection`; `probe_storage(path: Path, key: bytes) -> StorageProbe`; CLI `tuntunctl storage probe --path PATH --json`.

- [ ] **Step 1: Pin dependencies and write the red encryption tests**

Add `sqlcipher3==0.6.2` and `cryptography>=45,<46` to core dependencies and run `uv lock` before the red test so a missing system-compatible wheel/build fails at the intended stop/go gate.

```python
# tests/security/test_sqlcipher.py
from pathlib import Path
import sqlite3
import pytest
from sqlcipher3 import dbapi2 as sqlcipher3
from tuntun_core.adapters.sqlcipher.connection import open_sqlcipher

KEY = bytes(range(32)); WRONG = bytes(reversed(range(32)))
def test_key_first_database_is_encrypted_and_wrong_key_fails(tmp_path: Path) -> None:
    path=tmp_path/"foundation.db"; sentinel=b"foundation-private-sentinel"
    db=open_sqlcipher(path, KEY); db.execute("CREATE TABLE marker(value BLOB NOT NULL)"); db.execute("INSERT INTO marker VALUES (?)", (sentinel,)); db.commit(); db.close()
    assert sentinel not in path.read_bytes(); assert not path.read_bytes().startswith(b"SQLite format 3\x00")
    with pytest.raises(sqlcipher3.DatabaseError): open_sqlcipher(path, WRONG)
    with pytest.raises(sqlite3.DatabaseError): sqlite3.connect(path).execute("SELECT name FROM sqlite_master").fetchall()

def test_connection_enables_integrity_foreign_keys_and_secure_delete(tmp_path: Path) -> None:
    db=open_sqlcipher(tmp_path/"settings.db", KEY)
    assert db.execute("PRAGMA cipher_version").fetchone()[0]
    assert db.execute("PRAGMA cipher_integrity_check").fetchone()[0] == "ok"
    assert db.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert db.execute("PRAGMA secure_delete").fetchone()[0] == 1
```

- [ ] **Step 2: Run the red SQLCipher test**

Run: `uv run pytest tests/security/test_sqlcipher.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.adapters.sqlcipher.connection'`. If dependency installation itself fails on the target Intel Mac, stop and record the build error; do not implement a SQLite fallback.

- [ ] **Step 3: Implement the key-first connection and sanitized probe**

```python
# apps/core/src/tuntun_core/adapters/sqlcipher/connection.py
from pathlib import Path
from sqlcipher3 import dbapi2 as sqlcipher3

def open_sqlcipher(path: Path, key: bytes) -> sqlcipher3.Connection:
    if len(key) != 32: raise ValueError("SQLCipher key must be exactly 32 bytes")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700); path.parent.chmod(0o700)
    connection=sqlcipher3.connect(str(path), isolation_level=None, check_same_thread=False)
    try:
        connection.execute(f'PRAGMA key = "x\'{key.hex()}\'"')
        version=connection.execute("PRAGMA cipher_version").fetchone()
        if version is None or not version[0]: raise RuntimeError("SQLCipher support is unavailable")
        connection.execute("PRAGMA foreign_keys=ON"); connection.execute("PRAGMA secure_delete=ON")
        connection.execute("PRAGMA journal_mode=WAL"); connection.execute("PRAGMA busy_timeout=5000")
        integrity=connection.execute("PRAGMA cipher_integrity_check").fetchone()
        if integrity is not None and integrity[0] != "ok": raise RuntimeError("SQLCipher integrity check failed")
        path.touch(mode=0o600, exist_ok=True); path.chmod(0o600)
        return connection
    except BaseException:
        connection.close(); raise
```

```python
# apps/core/src/tuntun_core/adapters/sqlcipher/probe.py
from dataclasses import asdict, dataclass
from pathlib import Path
import platform, stat, sys
from .connection import open_sqlcipher

@dataclass(frozen=True, slots=True)
class StorageProbe:
    architecture: str; python: str; driver: str; cipher: str; integrity_ok: bool; mode: str
    def as_dict(self) -> dict[str, object]: return asdict(self)
def probe_storage(path: Path, key: bytes) -> StorageProbe:
    db=open_sqlcipher(path, key)
    try:
        cipher=str(db.execute("PRAGMA cipher_version").fetchone()[0]); integrity=db.execute("PRAGMA cipher_integrity_check").fetchone()[0] == "ok"
        return StorageProbe(platform.machine(), platform.python_version(), "sqlcipher3==0.6.2", cipher, integrity, oct(stat.S_IMODE(path.stat().st_mode)))
    finally: db.close()
```

Implement the Typer command so `--json` prints `json.dumps(probe.as_dict(), sort_keys=True)` and never prints the path or key. It obtains the key from `MacOSKeychainSecretProvider.get("tuntun.database", "root-v1")`; tests call `probe_storage` directly with a synthetic key.

- [ ] **Step 4: Run the green SQLCipher gate and target-Mac probe**

Run: `uv run pytest tests/security/test_sqlcipher.py -q && uv run tuntunctl storage probe --path var/probe/foundation.db --json`

Expected: PASS with two tests. Probe JSON has `"driver":"sqlcipher3==0.6.2"`, non-empty `cipher`, `"integrity_ok":true`, and `"mode":"0o600"`; it contains no username, absolute path, or key material.

Record the exact probe JSON, macOS version, Intel architecture, `uv.lock` hash, date, and PASS decision in `docs/operations/sqlcipher-compatibility.md`. Also document that WAL/SHM remain SQLCipher-managed sidecars, maintenance checkpoints WAL before backup, and startup refuses missing/wrong keys or failed cipher integrity.

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
**Depends on:** Task 8.
**Estimated effort:** 0.5 person-day.

**Files:**
- Create: `apps/core/src/tuntun_core/adapters/sqlcipher/crypto.py`
- Test: `tests/security/test_record_crypto.py`

**Interfaces:**
- Consumes: 32-byte purpose-specific root key and `RecordContext(household_id, table, row_id, purpose, schema_version)`.
- Produces: `RecordCipher.encrypt(plaintext: bytes, context: RecordContext) -> EncryptedRecord`, `RecordCipher.decrypt(record: EncryptedRecord, context: RecordContext) -> bytes`; random 32-byte DEK, random 96-bit data nonce, random 96-bit wrap nonce, AES-256-GCM, exact canonical associated data.

- [ ] **Step 1: Write red round-trip, binding, and duplicate-nonce tests**

```python
# tests/security/test_record_crypto.py
from collections import deque
from uuid import UUID
import pytest
from cryptography.exceptions import InvalidTag
from tuntun_core.adapters.sqlcipher.crypto import RecordCipher, RecordContext

CTX=RecordContext(UUID(int=1), "biometric_templates", UUID(int=2), "voice-template", "1.0")
def test_record_round_trip_and_context_binding() -> None:
    cipher=RecordCipher(bytes(range(32)))
    encrypted=cipher.encrypt(b"private-template-sentinel", CTX)
    assert b"private-template-sentinel" not in encrypted.ciphertext
    assert cipher.decrypt(encrypted, CTX) == b"private-template-sentinel"
    with pytest.raises(InvalidTag): cipher.decrypt(encrypted, RecordContext(UUID(int=1), "biometric_templates", UUID(int=3), "voice-template", "1.0"))

def test_nonce_reuse_is_rejected() -> None:
    repeated=b"N"*12; cipher=RecordCipher(bytes(range(32)), nonce_source=lambda: repeated)
    cipher.encrypt(b"first", CTX)
    with pytest.raises(RuntimeError, match="nonce reuse detected"): cipher.encrypt(b"second", CTX)
```

- [ ] **Step 2: Run the red record-crypto test**

Run: `uv run pytest tests/security/test_record_crypto.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.adapters.sqlcipher.crypto'`.

- [ ] **Step 3: Implement envelope encryption with exact associated data**

```python
# apps/core/src/tuntun_core/adapters/sqlcipher/crypto.py
import json, os
from dataclasses import dataclass
from typing import Callable
from uuid import UUID
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

@dataclass(frozen=True, slots=True)
class RecordContext:
    household_id: UUID; table: str; row_id: UUID; purpose: str; schema_version: str
    def associated_data(self) -> bytes:
        return json.dumps({"household_id":str(self.household_id),"purpose":self.purpose,"row_id":str(self.row_id),"schema_version":self.schema_version,"table":self.table}, sort_keys=True, separators=(",", ":")).encode()
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
        dek=os.urandom(32); nonce=self._nonce(); wrap_nonce=self._nonce(); aad=context.associated_data()
        return EncryptedRecord(AESGCM(dek).encrypt(nonce, plaintext, aad), nonce, self._root.encrypt(wrap_nonce, dek, aad+b"|dek"), wrap_nonce, self._root_key_id)
    def decrypt(self, record: EncryptedRecord, context: RecordContext) -> bytes:
        if record.root_key_id != self._root_key_id: raise ValueError("record root key id mismatch")
        aad=context.associated_data(); dek=self._root.decrypt(record.wrap_nonce, record.wrapped_dek, aad+b"|dek")
        return AESGCM(dek).decrypt(record.nonce, record.ciphertext, aad)
```

- [ ] **Step 4: Run the green record-crypto gate**

Run: `uv run pytest tests/security/test_record_crypto.py -q && uv run ruff check apps/core/src/tuntun_core/adapters/sqlcipher/crypto.py tests/security/test_record_crypto.py && uv run mypy apps/core/src/tuntun_core/adapters/sqlcipher/crypto.py`

Expected: PASS with two tests and zero Ruff/mypy errors.

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
- Produces: `FOUNDATION_TABLE_NAMES: frozenset[str]`; SQLAlchemy `metadata`; `create_sqlcipher_engine(path: Path, key: bytes) -> Engine`; `encrypted_backup(source: Path, destination: Path, key: bytes) -> None`; `upgrade_encrypted(path: Path, key: bytes, backup: Path | None) -> None`; Alembic revision `0001_foundation`, down revision `None`.
- Migration owns exactly: `households`, `devices`, `sessions`, `event_receipts`, `idempotency_receipts`, `audit_receipts`, `audit_segments`, `redaction_receipts`, `provider_calls`, `provider_response_receipts`, `provider_prices`, `budget_reservations`, `cost_ledger`, `runtime_settings`.
- `request_id` groups all attempts for one logical STT/reasoning/TTS request. `attempt_id` is the unique idempotency boundary for both `budget_reservations` and `provider_calls`; every retry receives a new attempt, authorization, and reservation while retaining its logical request ID. The `(month_key, state, amount_micros_sgd)` index supports the `BEGIN IMMEDIATE` atomic monthly sum over `reserved`, `sent`, and `settled` rows.

- [ ] **Step 1: Write the red upgrade/downgrade ownership test**

```python
# tests/integration/storage/test_migrations.py
from pathlib import Path
import sqlite3
import pytest
from alembic import command
from alembic.config import Config
from tuntun_core.adapters.sqlcipher.connection import open_sqlcipher

EXPECTED={"alembic_version","households","devices","sessions","event_receipts","idempotency_receipts","audit_receipts","audit_segments","redaction_receipts","provider_calls","provider_response_receipts","provider_prices","budget_reservations","cost_ledger","runtime_settings"}

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
    budget_sql="INSERT INTO budget_reservations (id,request_id,attempt_id,month_key,category,provider,model,outcome,amount_micros_sgd,state,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
    base=(request_id,"2026-08","llm","openai","gpt-5.6-sol","allow",100,"reserved","2026-08-27T01:02:03.000004Z","2026-08-27T01:03:03.000004Z")
    db.execute(budget_sql,("00000000-0000-0000-0000-000000000001",request_id,"00000000-0000-0000-0000-000000000101",*base[1:]))
    db.execute(budget_sql,("00000000-0000-0000-0000-000000000002",request_id,"00000000-0000-0000-0000-000000000102",*base[1:]))
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(budget_sql,("00000000-0000-0000-0000-000000000003",request_id,"00000000-0000-0000-0000-000000000102",*base[1:]))
    call_sql="INSERT INTO provider_calls (id,request_id,attempt_id,authorization_id,budget_reservation_id,purpose,provider,model,request_hmac_key_id,request_hmac_b64,category,outcome,started_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
    call_base=(request_id,"cloud_reasoning","openai","gpt-5.6-sol","provider-request-v1","A"*44,"llm","started","2026-08-27T01:02:03.000004Z")
    db.execute(call_sql,("00000000-0000-0000-0000-000000000201",request_id,"00000000-0000-0000-0000-000000000101","00000000-0000-0000-0000-000000000301","00000000-0000-0000-0000-000000000001",*call_base[1:]))
    db.execute(call_sql,("00000000-0000-0000-0000-000000000202",request_id,"00000000-0000-0000-0000-000000000102","00000000-0000-0000-0000-000000000302","00000000-0000-0000-0000-000000000002",*call_base[1:]))
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(call_sql,("00000000-0000-0000-0000-000000000203",request_id,"00000000-0000-0000-0000-000000000102","00000000-0000-0000-0000-000000000303","00000000-0000-0000-0000-000000000002",*call_base[1:]))
    indexes={row[1] for row in db.execute("PRAGMA index_list('budget_reservations')")}
    assert "ix_budget_month_state_amount" in indexes
    assert "ix_provider_calls_request" in {row[1] for row in db.execute("PRAGMA index_list('provider_calls')")}
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
        destination_db.commit(); destination.chmod(0o600)
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
# beginning of apps/core/src/tuntun_core/adapters/sqlcipher/models.py
from sqlalchemy import CheckConstraint, Column, ForeignKey, Index, Integer, LargeBinary, MetaData, String, Table, Text, UniqueConstraint

metadata=MetaData()
FOUNDATION_TABLE_NAMES=frozenset({"households","devices","sessions","event_receipts","idempotency_receipts","audit_receipts","audit_segments","redaction_receipts","provider_calls","provider_response_receipts","provider_prices","budget_reservations","cost_ledger","runtime_settings"})
def uuid_pk(name: str="id") -> Column[str]: return Column(name,String(36),primary_key=True)
def utc_text(name: str, nullable: bool=False) -> Column[str]: return Column(name,String(27),nullable=nullable)

households=Table("households",metadata,uuid_pk(),Column("display_label_ciphertext",LargeBinary,nullable=False),Column("timezone",String(32),nullable=False,server_default="Asia/Singapore"),utc_text("created_at"),CheckConstraint("timezone = 'Asia/Singapore'"))
devices=Table("devices",metadata,uuid_pk(),Column("household_id",String(36),ForeignKey("households.id",ondelete="CASCADE"),nullable=False),Column("kind",String(32),nullable=False),Column("certificate_fingerprint",String(128),nullable=False,unique=True),Column("signing_public_key",LargeBinary,nullable=False),Column("signing_key_id",String(128),nullable=False),Column("last_sequence",Integer,nullable=False,server_default="0"),utc_text("paired_at"),utc_text("revoked_at",True),CheckConstraint("last_sequence >= 0"))
sessions=Table("sessions",metadata,uuid_pk(),Column("household_id",String(36),ForeignKey("households.id",ondelete="CASCADE"),nullable=False),Column("device_id",String(36),ForeignKey("devices.id"),nullable=False),Column("state",String(32),nullable=False),Column("speaker_subject_id",String(36),nullable=True),utc_text("opened_at"),utc_text("last_activity_at"),utc_text("closed_at",True))
Index("uq_sessions_one_active_household",sessions.c.household_id,unique=True,sqlite_where=sessions.c.closed_at.is_(None))
```

Add the following exact table declarations to `models.py` after the three declarations shown above:

```python
event_receipts=Table("event_receipts",metadata,uuid_pk(),Column("household_id",String(36),ForeignKey("households.id",ondelete="CASCADE"),nullable=False),Column("device_id",String(36),ForeignKey("devices.id"),nullable=False),Column("event_type",String(128),nullable=False),Column("correlation_id",String(36),nullable=False),Column("device_sequence",Integer,nullable=False),Column("payload_hmac_key_id",String(128),nullable=False),Column("payload_hmac_b64",String(128),nullable=False),Column("decision",String(64),nullable=False),utc_text("occurred_at"),CheckConstraint("device_sequence >= 0"),UniqueConstraint("device_id","device_sequence",name="uq_event_device_sequence"))
idempotency_receipts=Table("idempotency_receipts",metadata,uuid_pk(),Column("operation",String(128),nullable=False),Column("scope",String(128),nullable=False),Column("idempotency_key",String(36),nullable=False),Column("state",String(32),nullable=False),Column("result_hmac_key_id",String(128),nullable=True),Column("result_hmac_b64",String(128),nullable=True),utc_text("first_seen_at"),utc_text("last_seen_at"),utc_text("expires_at"),UniqueConstraint("operation","scope","idempotency_key",name="uq_idempotency_scope_key"))
audit_receipts=Table("audit_receipts",metadata,uuid_pk(),Column("ordinal",Integer,nullable=False,unique=True),Column("previous_public_hash_hex",String(64),nullable=True),Column("public_hash_hex",String(64),nullable=False),Column("hmac_key_id",String(128),nullable=False),Column("hmac_b64",String(128),nullable=False),Column("canonical_body_json",Text,nullable=False),utc_text("occurred_at"),CheckConstraint("ordinal >= 1"),CheckConstraint("length(public_hash_hex) = 64"),CheckConstraint("previous_public_hash_hex IS NULL OR length(previous_public_hash_hex) = 64"),CheckConstraint("json_valid(canonical_body_json)"))
audit_segments=Table("audit_segments",metadata,uuid_pk(),Column("first_ordinal",Integer,nullable=False),Column("last_ordinal",Integer,nullable=False),Column("receipt_count",Integer,nullable=False),Column("terminal_public_hash_hex",String(64),nullable=False),Column("terminal_hmac_b64",String(128),nullable=False),Column("hmac_key_id",String(128),nullable=False),utc_text("sealed_at"),utc_text("exported_at",True),CheckConstraint("first_ordinal >= 1"),CheckConstraint("last_ordinal >= first_ordinal"),CheckConstraint("receipt_count >= 1"))
redaction_receipts=Table("redaction_receipts",metadata,uuid_pk(),Column("purpose",String(64),nullable=False),Column("input_hmac_key_id",String(128),nullable=False),Column("input_hmac_b64",String(128),nullable=False),Column("output_hmac_key_id",String(128),nullable=False),Column("output_hmac_b64",String(128),nullable=False),Column("removed_categories_json",Text,nullable=False),Column("removed_count",Integer,nullable=False),Column("policy_version",String(128),nullable=False),Column("maximum_sensitivity",String(32),nullable=False),utc_text("occurred_at"),CheckConstraint("removed_count >= 0"),CheckConstraint("json_valid(removed_categories_json)"))
provider_calls=Table("provider_calls",metadata,uuid_pk(),Column("request_id",String(36),nullable=False),Column("attempt_id",String(36),nullable=False,unique=True),Column("authorization_id",String(36),nullable=False,unique=True),Column("budget_reservation_id",String(36),ForeignKey("budget_reservations.id"),nullable=False,unique=True),Column("purpose",String(64),nullable=False),Column("provider",String(32),nullable=False),Column("model",String(128),nullable=False),Column("redaction_receipt_id",String(36),ForeignKey("redaction_receipts.id"),nullable=True),Column("request_hmac_key_id",String(128),nullable=False),Column("request_hmac_b64",String(128),nullable=False),Column("response_hmac_key_id",String(128),nullable=True),Column("response_hmac_b64",String(128),nullable=True),Column("category",String(32),nullable=False),Column("outcome",String(64),nullable=False),utc_text("started_at"),utc_text("finished_at",True),CheckConstraint("purpose IN ('cloud_stt','cloud_reasoning','cloud_tts')"),CheckConstraint("category IN ('stt','llm','tts')"),CheckConstraint("outcome IN ('started','succeeded','failed','cancelled','ambiguous')"),CheckConstraint("(response_hmac_key_id IS NULL) = (response_hmac_b64 IS NULL)"))
Index("ix_provider_calls_request",provider_calls.c.request_id)
provider_response_receipts=Table("provider_response_receipts",metadata,uuid_pk(),Column("request_id",String(36),nullable=False),Column("attempt_id",String(36),ForeignKey("provider_calls.attempt_id"),nullable=False,unique=True),Column("authorization_id",String(36),nullable=False,unique=True),Column("household_id",String(36),ForeignKey("households.id"),nullable=False),Column("subject_id",String(36),nullable=True),Column("session_id",String(36),ForeignKey("sessions.id"),nullable=False),Column("turn_id",String(36),nullable=False),Column("provider",String(32),nullable=False),Column("model",String(128),nullable=False),Column("output_schema_version",String(64),nullable=False),Column("response_hmac_key_id",String(128),nullable=False),Column("response_hmac_b64",String(128),nullable=False),Column("receipt_hmac_key_id",String(128),nullable=False),Column("receipt_hmac_b64",String(128),nullable=False),utc_text("produced_at"),CheckConstraint("output_schema_version = 'assistant-turn-v1'"))
provider_prices=Table("provider_prices",metadata,uuid_pk(),Column("provider",String(32),nullable=False),Column("model",String(128),nullable=False),Column("category",String(32),nullable=False),Column("native_currency",String(3),nullable=False),Column("input_unit_micros",Integer,nullable=False),Column("output_unit_micros",Integer,nullable=False),Column("fx_micros_sgd",Integer,nullable=False),Column("pricing_version",String(128),nullable=False),utc_text("effective_at"),utc_text("expires_at"),CheckConstraint("input_unit_micros >= 0"),CheckConstraint("output_unit_micros >= 0"),CheckConstraint("fx_micros_sgd >= 0"),UniqueConstraint("provider","model","category","pricing_version",name="uq_provider_price_version"))
budget_reservations=Table("budget_reservations",metadata,uuid_pk(),Column("request_id",String(36),nullable=False),Column("attempt_id",String(36),nullable=False,unique=True),Column("month_key",String(7),nullable=False),Column("category",String(32),nullable=False),Column("provider",String(32),nullable=False),Column("model",String(128),nullable=False),Column("outcome",String(32),nullable=False),Column("amount_micros_sgd",Integer,nullable=False),Column("state",String(32),nullable=False),utc_text("created_at"),utc_text("expires_at"),utc_text("settled_at",True),CheckConstraint("amount_micros_sgd >= 0"),CheckConstraint("outcome IN ('allow','allow_soft_warning','deny_hard_limit','deny_unknown_price')"),CheckConstraint("state IN ('reserved','sent','settled','released','denied')"),CheckConstraint("(outcome IN ('allow','allow_soft_warning') AND state IN ('reserved','sent','settled','released')) OR (outcome IN ('deny_hard_limit','deny_unknown_price') AND state = 'denied')"))
Index("ix_budget_request",budget_reservations.c.request_id)
Index("ix_budget_month_state_amount",budget_reservations.c.month_key,budget_reservations.c.state,budget_reservations.c.amount_micros_sgd)
cost_ledger=Table("cost_ledger",metadata,uuid_pk(),Column("reservation_id",String(36),ForeignKey("budget_reservations.id"),nullable=False,unique=True),Column("charged_micros_sgd",Integer,nullable=False),Column("usage_json",Text,nullable=False),Column("conservative_estimate_used",Integer,nullable=False),utc_text("settled_at"),CheckConstraint("charged_micros_sgd >= 0"),CheckConstraint("conservative_estimate_used IN (0,1)"),CheckConstraint("json_valid(usage_json)"))
runtime_settings=Table("runtime_settings",metadata,Column("key",String(128),primary_key=True),Column("value_json",Text,nullable=False),Column("version",Integer,nullable=False),utc_text("updated_at"),CheckConstraint("version >= 1"),CheckConstraint("json_valid(value_json)"))
```

Every UUID is `String(36)`, every timestamp is `String(27)`, money/counts are `Integer`, booleans have `CHECK (value IN (0,1))` using the real column name, JSON columns have `CHECK json_valid(column_name)` using the real column name, and no table contains raw audio, transcript, frame, prompt, memory body, credential, or secret.

```python
# apps/core/migrations/versions/0001_foundation.py
from alembic import op
from tuntun_core.adapters.sqlcipher.models import metadata
revision="0001_foundation"; down_revision=None; branch_labels=None; depends_on=None
def upgrade() -> None:
    bind=op.get_bind(); metadata.create_all(bind=bind)
    op.execute("CREATE TRIGGER audit_receipts_no_update BEFORE UPDATE ON audit_receipts BEGIN SELECT RAISE(ABORT, 'audit receipts are append-only'); END")
    op.execute("CREATE TRIGGER audit_receipts_no_delete BEFORE DELETE ON audit_receipts BEGIN SELECT RAISE(ABORT, 'audit receipts are append-only'); END")
def downgrade() -> None:
    bind=op.get_bind(); metadata.drop_all(bind=bind)
```

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

Expected: PASS with upgrade → downgrade → upgrade completing against SQLCipher and exact table/trigger ownership asserted.

- [ ] **Step 5: Commit exact Task 13 paths**

```bash
git status --short
git add apps/core/pyproject.toml uv.lock apps/core/src/tuntun_core/adapters/sqlcipher/models.py apps/core/src/tuntun_core/adapters/sqlcipher/engine.py apps/core/src/tuntun_core/adapters/sqlcipher/migrations.py apps/core/migrations/env.py apps/core/migrations/script.py.mako apps/core/migrations/versions/0001_foundation.py apps/core/alembic.ini tests/integration/storage/conftest.py tests/integration/storage/test_migrations.py
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
- Create: `apps/core/src/tuntun_core/services/transactions/mutation_scope.py`
- Test: `tests/integration/storage/test_transactions.py`
- Test: `tests/integration/storage/test_async_transactions.py`
- Test: `tests/unit/transactions/test_mutation_scope.py`

**Interfaces:**
- Consumes: SQLAlchemy `Engine`; SQLite busy errors; one application-owned serialized database worker.
- Produces: exact low-level `UnitOfWork` signature from the locked map; `AsyncUnitOfWorkFactory(repository_facades) -> AsyncUnitOfWork`; `AsyncRepositoryFacade`; and `AtomicMutationScope.open()/require_active_uow()`. Both unit-of-work layers use `BEGIN IMMEDIATE`, explicit commit/rollback, no implicit commit on context exit, and bounded busy retry of 3 attempts at 25/50/100 ms. The async facade runs enter, every repository operation, audit append, commit/rollback, and close on the same single worker/connection; it never moves a live transaction between threads. Each bounded context declares a typed structural protocol such as `IdentityUnitOfWork(AsyncUnitOfWork)` listing its async repository properties (`profiles`, `consent_receipts`, and so on); the factory installs matching `AsyncRepositoryFacade` instances, so the plan's `await uow.profiles.insert(...)` notation is typed and every call internally delegates through that exact unit's `run_sync`.

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
from threading import get_ident
import pytest
from sqlalchemy import text
from tuntun_core.adapters.sqlcipher.async_unit_of_work import AsyncUnitOfWorkFactory

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

Use the exact `migrated_database` fixture created by Task 13.

- [ ] **Step 2: Run the red transaction tests**

Run: `uv run pytest tests/integration/storage/test_transactions.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.adapters.sqlcipher.unit_of_work'`.

- [ ] **Step 3: Implement explicit transactions and bounded retry**

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
    def __init__(self, engine, executor, transaction_lock, repository_facades):
        self._engine,self._executor,self._transaction_lock,self._repository_facades=engine,executor,transaction_lock,repository_facades
        self._sync=None
    async def _call(self,operation):
        loop=asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor,operation)
    async def _finish(self,operation):
        task=asyncio.create_task(self._call(operation))
        try: return await asyncio.shield(task)
        except asyncio.CancelledError:
            await task
            raise
    async def __aenter__(self):
        await self._transaction_lock.acquire()
        try:
            self._sync=UnitOfWork(self._engine)
            await self._call(self._sync.__enter__)
        except BaseException:
            self._transaction_lock.release()
            raise
        for name,facade_factory in self._repository_facades.items():
            setattr(self,name,facade_factory.bind(self))
        return self
    async def run_sync(self,operation):
        if self._sync is None: raise RuntimeError("async unit of work is not active")
        return await self._call(lambda: operation(self._sync))
    async def commit(self):
        if self._sync is None: raise RuntimeError("async unit of work is not active")
        await self._finish(self._sync.commit)
    async def rollback(self):
        if self._sync is not None: await self._finish(self._sync.rollback)
    async def __aexit__(self,exc_type,exc,tb):
        try:
            if self._sync is not None:
                await self._finish(lambda: self._sync.__exit__(exc_type,exc,tb))
        finally:
            self._transaction_lock.release()
        return False

class AsyncUnitOfWorkFactory:
    def __init__(self,engine,repository_facades=None):
        self._engine,self._repository_facades=engine,repository_facades or {}
        self._executor=ThreadPoolExecutor(max_workers=1,thread_name_prefix="tuntun-sqlcipher")
        self._transaction_lock=asyncio.Lock()
    def __call__(self): return AsyncUnitOfWork(self._engine,self._executor,self._transaction_lock,self._repository_facades)
```

`AsyncUnitOfWork.__aenter__` binds each registered facade to itself and exposes it under its typed repository property. `AsyncRepositoryFacade` contains no connection of its own: every method executes a synchronous repository operation as `await bound_uow.run_sync(lambda tx: sync_repository(tx).method(...))`. It rejects use before enter or after finish. Bounded-context protocols name every repository method and return type, and strict mypy verifies services against those protocols; there is no dynamic `Any`/string dispatch in application code.

`AtomicMutationScope` is an async context manager backed by a task-local `ContextVar[AsyncUnitOfWork | None]`. `open()` rejects nesting, enters exactly one factory unit, installs it only for the current task, commits only when the coordinator explicitly calls `uow.commit()`, and always clears the context after cancellation, rollback, or close. `require_active_uow()` fails closed outside the scope. Child tasks receive no usable mutation authority: the stored scope token also binds the creating `asyncio.current_task()`, and a different task is rejected even if context variables were copied.

The factory is a single application-lifecycle object and closes its worker only during orderly shutdown after all units of work finish. Its fair application-level async transaction lock is acquired before `BEGIN IMMEDIATE` and held through close, so operations from two live units can never interleave and a second writer waits instead of exhausting SQLite busy retries behind the first. Lock acquisition is cancellable; once acquired, enter failure or context exit always releases it. A transaction may await those local serialized repository/audit operations only; it must never await provider, robot, browser, timer, filesystem, or other unbounded I/O while holding `BEGIN IMMEDIATE`. Commit and rollback are cancellation-shielded and awaited to a terminal state before cancellation propagates.

- [ ] **Step 4: Run the green transaction gate**

Run: `uv run pytest tests/integration/storage/test_transactions.py tests/integration/storage/test_async_transactions.py tests/unit/transactions/test_mutation_scope.py -q && uv run ruff check apps/core/src/tuntun_core/adapters/sqlcipher/unit_of_work.py apps/core/src/tuntun_core/adapters/sqlcipher/async_unit_of_work.py apps/core/src/tuntun_core/adapters/sqlcipher/repository_facade.py apps/core/src/tuntun_core/services/transactions/mutation_scope.py tests/integration/storage/test_transactions.py tests/integration/storage/test_async_transactions.py tests/unit/transactions/test_mutation_scope.py && uv run mypy apps/core/src/tuntun_core/adapters/sqlcipher apps/core/src/tuntun_core/services/transactions`

Expected: PASS with two transaction tests and zero Ruff/mypy errors.

- [ ] **Step 5: Commit exact Task 14 paths**

```bash
git status --short
git add apps/core/src/tuntun_core/adapters/sqlcipher/unit_of_work.py apps/core/src/tuntun_core/adapters/sqlcipher/async_unit_of_work.py apps/core/src/tuntun_core/adapters/sqlcipher/repository_facade.py apps/core/src/tuntun_core/services/transactions/mutation_scope.py tests/integration/storage/test_transactions.py tests/integration/storage/test_async_transactions.py tests/unit/transactions/test_mutation_scope.py
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
- Test: `tests/unit/audit/test_chain.py`
- Test: `tests/security/test_audit_tamper.py`
- Test: `tests/integration/audit/test_concurrency.py`
- Create: `docs/operations/foundation-storage.md`

**Interfaces:**
- Consumes: `AuditDraft`, `AuditReceipt`, `canonical_bytes`, HMAC key ID/key, and active `UnitOfWork` or `AsyncUnitOfWork`.
- Produces: `AuditLedger.append(uow, draft) -> AuditReceipt`; `AsyncAuditLedger.append(uow, draft) -> Awaitable[AuditReceipt]`; `AuditLedger.seal(uow, first_ordinal: int, last_ordinal: int) -> AuditSegment`; `AuditVerifier.verify(connection) -> AuditVerification(valid: bool, count: int, terminal_public_hash_hex: str | None, reason: str)`. `AsyncAuditLedger` delegates through `uow.run_sync` and never opens or commits a transaction. A rotated ledger may append with a new `hmac_key_id`; verification requires every key ID still referenced by a retained receipt/segment.
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
    draft=AuditDraft(event_id=UUID(int=1),occurred_at=datetime(2026,8,27,tzinfo=UTC),actor_pseudonym="synthetic-guest",action_code="foundation.init",outcome="allow",reason_code="initialized",correlation_id=UUID(int=2),payload_commitment=Commitment(algorithm="HMAC-SHA-256",key_id="audit-v1",value_b64="A"*44))
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
```

```python
# tests/integration/audit/test_concurrency.py
from concurrent.futures import ThreadPoolExecutor
def test_parallel_append_assigns_unique_contiguous_ordinals(audit_fixture) -> None:
    with ThreadPoolExecutor(max_workers=8) as pool: receipts=list(pool.map(audit_fixture.append_index, range(32)))
    assert sorted(receipt.ordinal for receipt in receipts) == list(range(1,33))
    assert audit_fixture.verify().valid is True
```

The shared `audited_database`/`audit_fixture` fixture creates and migrates an encrypted temporary DB, instantiates `AuditLedger("audit-v1", b"K"*32)`, appends two synthetic receipts in separate committed units of work, and exposes an `append_index(index: int)` method whose draft uses UUID(int=700+index), correlation UUID(int=800+index), and fixed aware time plus `index` microseconds. Its teardown disposes the engine and removes DB/WAL/SHM.

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
from tuntun_core.adapters.sqlcipher.unit_of_work import UnitOfWork

PURPOSE=b"tuntun:audit:v1\x00"
@dataclass(frozen=True, slots=True)
class ChainValues: public_hash_hex: str; hmac_b64: str; canonical_body_json: str
@dataclass(frozen=True, slots=True)
class AuditSegment:
    segment_id: str; first_ordinal: int; last_ordinal: int; receipt_count: int
    terminal_public_hash_hex: str; terminal_hmac_b64: str; hmac_key_id: str
def compute_chain_values(previous_public_hash_hex: str | None, draft: AuditDraft, key_id: str, key: bytes) -> ChainValues:
    body=canonical_bytes(draft); previous=bytes.fromhex(previous_public_hash_hex) if previous_public_hash_hex else b""
    public=hashlib.sha256(previous+body).digest(); mac=hmac.new(key,PURPOSE+public+body,hashlib.sha256).digest()
    return ChainValues(public.hex(),base64.b64encode(mac).decode("ascii"),body.decode("utf-8"))
class AuditLedger:
    def __init__(self, key_id: str, key: bytes) -> None:
        if len(key)<32: raise ValueError("audit HMAC key must be at least 32 bytes")
        self.key_id=key_id; self.key=key
    def append(self, uow: UnitOfWork, draft: AuditDraft) -> AuditReceipt:
        row=uow.execute(text("SELECT ordinal,public_hash_hex FROM audit_receipts ORDER BY ordinal DESC LIMIT 1")).mappings().first()
        ordinal=1 if row is None else int(row["ordinal"])+1; previous=None if row is None else str(row["public_hash_hex"])
        values=compute_chain_values(previous,draft,self.key_id,self.key); receipt_id=uuid4()
        uow.execute(text("INSERT INTO audit_receipts(id,ordinal,previous_public_hash_hex,public_hash_hex,hmac_key_id,hmac_b64,canonical_body_json,occurred_at) VALUES(:id,:ordinal,:previous,:public,:key_id,:mac,:body,:occurred)"), {"id":str(receipt_id),"ordinal":ordinal,"previous":previous,"public":values.public_hash_hex,"key_id":self.key_id,"mac":values.hmac_b64,"body":values.canonical_body_json,"occurred":draft.occurred_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ")})
        return AuditReceipt(receipt_id=receipt_id,ordinal=ordinal,public_hash_hex=values.public_hash_hex,hmac_key_id=self.key_id,hmac_b64=values.hmac_b64,occurred_at=draft.occurred_at)
    def seal(self, uow: UnitOfWork, first_ordinal: int, last_ordinal: int) -> AuditSegment:
        rows=uow.execute(text("SELECT ordinal,public_hash_hex,hmac_b64,hmac_key_id FROM audit_receipts WHERE ordinal BETWEEN :first AND :last ORDER BY ordinal"),{"first":first_ordinal,"last":last_ordinal}).mappings().all()
        if not rows or rows[0]["ordinal"] != first_ordinal or rows[-1]["ordinal"] != last_ordinal or len(rows) != last_ordinal-first_ordinal+1: raise ValueError("segment range is not contiguous")
        terminal=rows[-1]; segment_id=str(uuid4())
        uow.execute(text("INSERT INTO audit_segments(id,first_ordinal,last_ordinal,receipt_count,terminal_public_hash_hex,terminal_hmac_b64,hmac_key_id,sealed_at,exported_at) VALUES(:id,:first,:last,:count,:public,:mac,:key_id,:sealed,NULL)"),{"id":segment_id,"first":first_ordinal,"last":last_ordinal,"count":len(rows),"public":terminal["public_hash_hex"],"mac":terminal["hmac_b64"],"key_id":terminal["hmac_key_id"],"sealed":datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")})
        return AuditSegment(segment_id,first_ordinal,last_ordinal,len(rows),str(terminal["public_hash_hex"]),str(terminal["hmac_b64"]),str(terminal["hmac_key_id"]))

class AsyncAuditLedger:
    def __init__(self, ledger: AuditLedger) -> None: self._ledger=ledger
    async def append(self, uow, draft: AuditDraft) -> AuditReceipt:
        return await uow.run_sync(lambda transaction: self._ledger.append(transaction,draft))
    async def seal(self, uow, first_ordinal: int, last_ordinal: int) -> AuditSegment:
        return await uow.run_sync(lambda transaction: self._ledger.seal(transaction,first_ordinal,last_ordinal))
```

```python
# apps/core/src/tuntun_core/services/audit/verifier.py
import json
from dataclasses import dataclass
from sqlalchemy import Connection, text
from tuntun_contracts.audit import AuditDraft
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
            draft=AuditDraft.model_validate(json.loads(str(row["canonical_body_json"])))
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
git add apps/core/src/tuntun_core/services/audit/ledger.py apps/core/src/tuntun_core/services/audit/verifier.py tests/unit/audit/test_chain.py tests/security/test_audit_tamper.py tests/integration/audit/test_concurrency.py docs/operations/foundation-storage.md
git diff --cached --name-only
git diff --cached
git commit -m "feat(storage): add tamper-evident foundation audit"
```

## Foundation Completion Checkpoint

Run from a clean checkout on the target Intel Mac:

```bash
make bootstrap
make check
uv run pytest tests/contract tests/unit/config tests/unit/testing tests/security/test_sqlcipher.py tests/security/test_record_crypto.py tests/integration/storage tests/unit/audit tests/security/test_audit_tamper.py tests/integration/audit -q
uv run tuntunctl storage probe --path var/probe/foundation.db --json
uv run python scripts/check_model_manifest.py models/manifest.yaml
uv run python scripts/verify_private_data.py .
git status --short
```

Expected: every test and static gate passes; storage probe reports `sqlcipher3==0.6.2`, a non-empty cipher version, `integrity_ok: true`, mode `0o600`, and no path/key material; model/private-data scans print PASS; `git status --short` is empty. The encrypted DB contains exactly the 13 foundation-owned application tables plus `alembic_version`, rejects audit update/delete, reveals neither the SQLite header nor any sentinel, and downgrades to an empty schema before upgrading again.

## Execution Handoff

Plan complete at master work package 06. Continue only after the target-Mac SQLCipher checkpoint and the encrypted schema/audit verification are accepted. The next master task is Task 07; no conversation, provider, Reachy transport, profile, biometric, auth, memory, API, or UI feature beyond the bootstrap shell belongs in this subplan.
