# Tuntun Phase 1 Packaging, Security, Acceptance, and Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute master work packages 31–34 to package Tuntun reversibly, produce signed security and acceptance evidence, complete the elapsed private-beta gates, and prepare a reproducible `v0.1.0-beta.1` release without automatically publishing it.

**Architecture:** Immutable version directories switch through an atomic `current` symlink while encrypted household state remains outside release artifacts. Strict JSON Schemas, SHA-256 manifests, Keychain-backed Ed25519 signatures, measured elapsed evidence, and an owner P1R0 decision bind release eligibility to one version and Git commit. CI builds and verifies candidates only; publication remains a separate owner action after signed-tag verification.

**Tech Stack:** Python 3.12, `uv`, Pydantic v2, JSON Schema 2020-12, `cryptography`, POSIX shell, ShellCheck, launchd/plistlib, pytest, Hypothesis, pnpm, Gitleaks, Bandit, Semgrep, pip-audit, CycloneDX, SHA-256, signed Git tags, and GitHub Actions attestations.

## Global Constraints

- Scope is master WPs 31–34. Tasks 01–30 and Checkpoint B2 are accepted prerequisites.
- `P1R0` and `P1R1` are Phase 1-only standalone-preview gates. `P1R0` follows the family-ready FB0 private beta; `P1R1` may publish an explicitly labelled Phase 1 preview. Neither gate satisfies, aliases, or makes claims for the whole-program Phase 6 `C0/C1` gates.
- Candidate version is exactly `0.1.0-beta.1`; release tag is exactly `v0.1.0-beta.1`.
- Effort is preserved: WP31 `6` person-days, WP32 `7`, WP33 `8` plus two elapsed eight-hour runs and a four-calendar-day staged trial, WP34 `5`; total `26` engineering days.
- Production requires native Intel `x86_64` macOS, FileVault on, macOS Keychain available, owner-only `0700` roots, installed launchd core limit zero, and no content-bearing crash diagnostic.
- Listener policy is exact: `127.0.0.1:8787`, resolved RFC1918 interface address on `7443`, and optional passkey console on that same address at `8443`. Wildcard, public, unresolved-interface, and other Tuntun listeners fail.
- Every upgrade invokes Privacy Shield, disables new provider attempts, drains in-flight calls to zero, creates/verifies an encrypted backup, verifies DB/audit/model/protocol compatibility, then switches runtime.
- Failed install/upgrade restores the prior symlink and compatible encrypted DB before restart. Uninstall removes runtime/service only; data, models, backups, and Keychain items remain.
- Evidence schemas use `additionalProperties:false` recursively, canonical UTF-8 JSON, 64-character SHA-256 hashes, provenance, exact timestamps, and Keychain-backed Ed25519 signatures. Raw family data and absolute local paths are forbidden.
- Blockers include any secret/real-family fixture, retained media/transcript, unauthorized egress, invalid audit, plaintext fallback, failed isolation/auth/child/privacy/safety gate, incompatible license, or unmitigated high/critical vulnerability.
- Acceptance includes 240+ bilingual/persona cases, 1,000 cross-profile cases, 500 mixed turns, two distinct eight-hour runs, then owner 48 hours followed by second-adult 48 hours. Simulation never replaces elapsed gates.
- P1R0 is an explicit owner approve/reject artifact bound to version, commit, acceptance hash, evidence hashes, and a fresh action-bound owner passkey receipt.
- Tasks 5–10 commit and test evidence tooling only with synthetic fixtures. Official security, acceptance, elapsed soak/trial, P1R0, candidate, installation, and tag outputs are generated once, in that order, after Task 10 on one clean frozen commit; no tracked change may occur during the ceremony.
- Apache-2.0 is added only after owner license approval. Incompatible/non-commercial weights stay outside artifacts.
- `.github/workflows/release.yml` has `contents: read`, never tags or publishes, and only builds/attests/uploads a workflow artifact. Final publication is manual.
- Every task uses red → green → affected/static checks → exact staging → one reviewable commit.

---

## Master Coverage and Dependencies

| Tasks | Master WP | Effort | Required exit |
|---|---:|---:|---|
| 1–3 | 31 | 2 + 2.5 + 1.5 = 6 days | preflight, atomic Mac lifecycle, Reachy reboot |
| 4–5 | 32 | 3.5 + 3.5 = 7 days | reconciled zero-blocker signed evidence |
| 6–8 | 33 | 3 + 2.5 + 2.5 = 8 days plus elapsed gates | signed report, soaks, trial, P1R0 |
| 9–10 | 34 | 3 + 2 = 5 days | reproducible candidate and verified manual publication gate |

### Task 1: Invoke the complete production packaging preflight

**Master package:** 31
**Depends on:** master Tasks 12–14 and 26–30; Checkpoint B2
**Estimated effort:** 2 person-days

**Files:**
- Create: `apps/core/src/tuntun_core/deploy/__init__.py`
- Create: `apps/core/src/tuntun_core/deploy/preflight.py`
- Create: `deploy/macos/preflight.sh`
- Create: `apps/core/src/tuntun_core/cli/commands/doctor.py`
- Modify: `apps/core/src/tuntun_core/cli/main.py`
- Test: `tests/unit/deploy/test_preflight.py`
- Test: `tests/security/test_listener_allowlist.py`

**Interfaces:**
- Consumes: installed LaunchAgent, application roots, `route`, `ipconfig`, `fdesetup`, `security`, `stat`, `plutil`, `lsof`, crash probe, Privacy Shield, and provider drain commands.
- Produces: `CommandRunner.run(argv) -> CommandResult`; `resolve_private_interface(runner) -> ResolvedInterface`; `verify_listeners(rows, interface, lan_console) -> tuple[str,...]`; `run_preflight(mode, home, runner, lan_console) -> PreflightReport`; JSON exit `0` or `78`.

- [ ] **Step 1: Write the failing invocation and listener tests**

```python
# tests/unit/deploy/test_preflight.py
from pathlib import Path
from tuntun_core.deploy.preflight import CommandResult, run_preflight

class Runner:
    def __init__(self): self.calls=[]
    def run(self, argv):
        self.calls.append(argv)
        values={
          ("uname","-m"):"x86_64\n", ("uv","run","python","-c","import platform; print(platform.machine())"):"x86_64\n",
          ("id","-un"):"test\n", ("fdesetup","status"):"FileVault is On.\n",
          ("security","find-generic-password","-s","tuntun.database","-a","root-v1"):"ok\n",
          ("route","-n","get","default"):"interface: en0\n", ("ipconfig","getifaddr","en0"):"192.168.50.10\n",
          ("plutil","-extract","SoftResourceLimits.Core","raw",str(Path("/Users/test/Library/LaunchAgents/com.tuntun.core.plist"))):"0\n",
          ("tuntunctl","service","crash-probe","--json"):'{"core_files":0,"content_diagnostics":0}\n',
          ("tuntunctl","service","pid","--json"):'{"pid":4321}\n',
          ("lsof","-nP","-a","-p","4321","-iTCP","-sTCP:LISTEN"):"Python TCP 127.0.0.1:8787 (LISTEN)\nPython TCP 192.168.50.10:7443 (LISTEN)\n",
          ("tuntunctl","privacy","activate","--reason","packaging","--json"):'{"egress_closed":true}\n',
          ("tuntunctl","providers","disable-new","--json"):'{"disabled":true}\n',
          ("tuntunctl","providers","drain","--timeout-seconds","30","--json"):'{"in_flight":0,"ambiguous":0}\n'}
        if argv[:3]==("stat","-f","%Su:%Lp"): return CommandResult(0,"test:700\n","")
        return CommandResult(0,values[argv],"")

def test_upgrade_invokes_every_check():
    runner=Runner(); report=run_preflight("upgrade",Path("/Users/test"),runner,False)
    assert report.ok
    assert {check.check_id for check in report.checks}=={"architecture","filevault","keychain","resolved_interface","owner_paths","launchd_core_limit","crash_diagnostics","listeners","privacy","provider_drain"}
    assert ("tuntunctl","providers","drain","--timeout-seconds","30","--json") in runner.calls
```

```python
# tests/security/test_listener_allowlist.py
from tuntun_core.deploy.preflight import ResolvedInterface, verify_listeners
def test_wildcard_public_and_wrong_interface_fail():
    interface=ResolvedInterface("en0","192.168.50.10")
    rows=(("127.0.0.1",8787),("192.168.50.10",7443),("0.0.0.0",8443),("[::]",7443),("203.0.113.7",7443))
    assert verify_listeners(rows,interface,True)==("listener:0.0.0.0:8443","listener:[::]:7443","listener:203.0.113.7:7443")
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/unit/deploy/test_preflight.py tests/security/test_listener_allowlist.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tuntun_core.deploy'`.

- [ ] **Step 3: Implement the command-backed preflight**

```python
# apps/core/src/tuntun_core/deploy/preflight.py
import json,re,subprocess
from dataclasses import dataclass
from pathlib import Path
@dataclass(frozen=True,slots=True)
class CommandResult: returncode:int; stdout:str; stderr:str
class CommandRunner:
    def run(self,argv):
        result=subprocess.run(argv,check=False,text=True,capture_output=True)
        return CommandResult(result.returncode,result.stdout,result.stderr)
@dataclass(frozen=True,slots=True)
class ResolvedInterface: name:str; address:str
@dataclass(frozen=True,slots=True)
class Check: check_id:str; passed:bool; reason:str
@dataclass(frozen=True,slots=True)
class PreflightReport: schema_version:str; mode:str; ok:bool; checks:tuple[Check,...]
def required(runner,argv):
    result=runner.run(argv)
    if result.returncode: raise RuntimeError("command failed: "+" ".join(argv))
    return result.stdout
def resolve_private_interface(runner):
    match=re.search(r"^\s*interface:\s*(\S+)",required(runner,("route","-n","get","default")),re.MULTILINE)
    if match is None: raise RuntimeError("private interface unresolved")
    name=match.group(1); address=required(runner,("ipconfig","getifaddr",name)).strip()
    if not address.startswith(("10.","192.168.")) and re.match(r"^172\.(1[6-9]|2\d|3[01])\.",address) is None: raise RuntimeError("interface is not RFC1918")
    return ResolvedInterface(name,address)
def verify_listeners(rows,interface,lan_console):
    allowed={("127.0.0.1",8787),(interface.address,7443)}
    if lan_console: allowed.add((interface.address,8443))
    return tuple(f"listener:{host}:{port}" for host,port in rows if (host,port) not in allowed)
def run_preflight(mode,home,runner,lan_console):
    if mode not in {"install","upgrade","verify-installed"}: raise ValueError("invalid mode")
    interface=resolve_private_interface(runner); plist=home/"Library/LaunchAgents/com.tuntun.core.plist"
    roots=[home/path for path in ("Library/Application Support/Tuntun/runtime","Library/Application Support/Tuntun/data","Library/Application Support/Tuntun/models","Library/Application Support/Tuntun/backups","Library/Logs/Tuntun")]
    owner=required(runner,("id","-un")).strip()
    if mode=="install":
        ports=runner.run(("lsof","-nP","-iTCP:8787","-iTCP:7443","-iTCP:8443","-sTCP:LISTEN"))
        if ports.returncode not in {0,1}: raise RuntimeError("port probe failed")
        listener_ok=not ports.stdout.strip()
    else:
        pid=str(json.loads(required(runner,("tuntunctl","service","pid","--json")))["pid"])
        rows=tuple((host,int(port)) for host,port in re.findall(r"TCP\s+(\[[^\]]+\]|[^\s:]+):(\d+)\s+\(LISTEN\)",required(runner,("lsof","-nP","-a","-p",pid,"-iTCP","-sTCP:LISTEN"))))
        listener_ok=not verify_listeners(rows,interface,lan_console)
    native=required(runner,("uname","-m")).strip()=="x86_64" and required(runner,("uv","run","python","-c","import platform; print(platform.machine())")).strip()=="x86_64"
    values={"architecture":native,"filevault":"FileVault is On." in required(runner,("fdesetup","status")),"keychain":bool(required(runner,("security","find-generic-password","-s","tuntun.database","-a","root-v1"))),"resolved_interface":True,"owner_paths":all(required(runner,("stat","-f","%Su:%Lp",str(path))).strip()==f"{owner}:700" for path in roots),"launchd_core_limit":required(runner,("plutil","-extract","SoftResourceLimits.Core","raw",str(plist))).strip()=="0","crash_diagnostics":json.loads(required(runner,("tuntunctl","service","crash-probe","--json")))=={"core_files":0,"content_diagnostics":0},"listeners":listener_ok,"privacy":True,"provider_drain":True}
    if mode=="upgrade":
        values["privacy"]=json.loads(required(runner,("tuntunctl","privacy","activate","--reason","packaging","--json")))["egress_closed"]
        required(runner,("tuntunctl","providers","disable-new","--json"))
        values["provider_drain"]=json.loads(required(runner,("tuntunctl","providers","drain","--timeout-seconds","30","--json")))=={"in_flight":0,"ambiguous":0}
    checks=tuple(Check(name,bool(value),name+"_failed") for name,value in values.items())
    return PreflightReport("tuntun.preflight.v1",mode,all(item.passed for item in checks),checks)
```

```sh
# deploy/macos/preflight.sh
#!/bin/sh
set -eu
report=$(uv run tuntunctl doctor preflight --mode "${1:-verify-installed}" --json)
printf '%s\n' "$report"
printf '%s' "$report" | uv run python -c 'import json,sys; raise SystemExit(0 if json.load(sys.stdin)["ok"] else 78)'
```

`doctor.py` serializes the report without secrets/absolute paths; `service crash-probe` deliberately crashes a content-free helper and compares `/cores` plus `~/Library/Logs/DiagnosticReports` before/after. No production bypass environment variable is accepted.

- [ ] **Step 4: Run green**

Run: `chmod +x deploy/macos/preflight.sh && shellcheck deploy/macos/preflight.sh && uv run pytest tests/unit/deploy/test_preflight.py tests/security/test_listener_allowlist.py -q && uv run ruff check apps/core/src/tuntun_core/deploy apps/core/src/tuntun_core/cli/commands/doctor.py tests/unit/deploy tests/security/test_listener_allowlist.py && uv run mypy apps/core/src/tuntun_core/deploy apps/core/src/tuntun_core/cli/commands/doctor.py`

Expected: PASS; every required command is observed, exact listeners pass, deliberate bad checks fail with exit `78`, and static checks exit `0`.

- [ ] **Step 5: Commit**

```bash
git status --short
git add apps/core/src/tuntun_core/deploy/__init__.py apps/core/src/tuntun_core/deploy/preflight.py deploy/macos/preflight.sh apps/core/src/tuntun_core/cli/commands/doctor.py apps/core/src/tuntun_core/cli/main.py tests/unit/deploy/test_preflight.py tests/security/test_listener_allowlist.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "build(deploy): enforce complete production preflight"
```

### Task 2: Implement atomic macOS install, upgrade, rollback, and preserving uninstall

**Master package:** 31
**Depends on:** Task 1
**Estimated effort:** 2.5 person-days

**Files:**
- Create: `apps/core/src/tuntun_core/deploy/lifecycle.py`
- Create: `deploy/macos/install.sh`
- Create: `deploy/macos/upgrade.sh`
- Create: `deploy/macos/rollback.sh`
- Create: `deploy/macos/uninstall.sh`
- Create: `deploy/macos/com.tuntun.core.plist`
- Create: `apps/core/src/tuntun_core/cli/commands/service.py`
- Create: `apps/core/src/tuntun_core/cli/commands/update.py`
- Modify: `apps/core/src/tuntun_core/cli/main.py`
- Test: `tests/integration/deploy/test_atomic_install.py`
- Test: `tests/integration/deploy/test_atomic_upgrade.py`
- Test: `tests/integration/deploy/test_atomic_rollback.py`
- Test: `tests/integration/deploy/test_uninstall_preserves_data.py`
- Create: `docs/operations/install-macos.md`
- Create: `docs/operations/upgrade-rollback.md`
- Create: `docs/operations/uninstall.md`

**Interfaces:** `ReleaseLayout.for_home(home: Path) -> ReleaseLayout`; `Installer.install(bundle: Path, version: str, preflight: bool = True, activate: bool = True) -> Path`; `UpgradeCoordinator.apply(bundle: Path, version: str) -> str`; `rollback(layout: ReleaseLayout, ops: LifecycleOps, previous: Path, backup: Path) -> None`; `Installer.uninstall_preserving_state() -> tuple[Path,Path,Path]`; consumes preflight, hash/SBOM verification, encrypted backup, storage/audit/model/protocol verification, migration, readiness; rollback exit `70`.

- [ ] **Step 1: Write separate failing install, upgrade, rollback, and uninstall tests**

```python
# tests/integration/deploy/test_atomic_install.py
import pytest
from tuntun_core.deploy.lifecycle import Installer,ReleaseLayout
def test_clean_install_switches_only_after_verified_unpack(tmp_path,fake_lifecycle_ops):
    layout=ReleaseLayout.for_home(tmp_path)
    installed=Installer(layout,fake_lifecycle_ops).install(tmp_path/"candidate.tar.zst","0.1.0-beta.1")
    assert layout.current.resolve()==installed
    assert fake_lifecycle_ops.events==["launch_agent:install","preflight:install","bundle:verify","bundle:unpack","service:load","readiness:check","preflight:verify-installed"]
def test_failed_clean_install_leaves_no_current_runtime(tmp_path,fake_lifecycle_ops):
    layout=ReleaseLayout.for_home(tmp_path); fake_lifecycle_ops.ready_result=False
    with pytest.raises(RuntimeError,match="installed service readiness failed"): Installer(layout,fake_lifecycle_ops).install(tmp_path/"candidate.tar.zst","0.1.0-beta.1")
    assert not layout.current.exists() and layout.data.exists() and layout.models.exists()
```

```python
# tests/integration/deploy/test_atomic_upgrade.py
from tuntun_core.deploy.lifecycle import ReleaseLayout,UpgradeCoordinator
def test_upgrade_backs_up_verifies_and_switches_atomically(tmp_path,fake_lifecycle_ops):
    layout=ReleaseLayout.for_home(tmp_path); fake_lifecycle_ops.seed(layout,"0.1.0-alpha.1",b"encrypted-old")
    fake_lifecycle_ops.events.clear()
    result=UpgradeCoordinator(layout,fake_lifecycle_ops).apply(tmp_path/"candidate.tar.zst","0.1.0-beta.1")
    assert result=="0.1.0-beta.1" and layout.current.resolve().name=="0.1.0-beta.1"
    assert fake_lifecycle_ops.events[:4]==["preflight:upgrade","backup:create","backup:verify","bundle:verify"]
    assert fake_lifecycle_ops.events[-4:]==["database:migrate","service:start","readiness:check","protocol:verify"]
```

```python
# tests/integration/deploy/test_atomic_rollback.py
import pytest
from tuntun_core.deploy.lifecycle import ReleaseLayout,UpgradeCoordinator
def test_failed_candidate_restores_runtime_and_db(tmp_path,fake_lifecycle_ops):
    layout=ReleaseLayout.for_home(tmp_path); fake_lifecycle_ops.seed(layout,"0.1.0-alpha.1",b"encrypted-old")
    fake_lifecycle_ops.events.clear()
    fake_lifecycle_ops.ready_result=False
    with pytest.raises(RuntimeError,match="candidate readiness failed"): UpgradeCoordinator(layout,fake_lifecycle_ops).apply(tmp_path/"candidate.tar.zst","0.1.0-beta.1")
    assert layout.current.resolve().name=="0.1.0-alpha.1" and layout.database.read_bytes()==b"encrypted-old"
    assert fake_lifecycle_ops.events[-4:]==["service:stop","database:restore","service:start","protocol:verify"]
```

```python
# tests/integration/deploy/test_uninstall_preserves_data.py
from tuntun_core.deploy.lifecycle import Installer,ReleaseLayout
def test_uninstall_preserves_state_and_keychain(tmp_path,fake_lifecycle_ops):
    layout=ReleaseLayout.for_home(tmp_path); fake_lifecycle_ops.seed(layout,"0.1.0-beta.1",b"encrypted")
    preserved=Installer(layout,fake_lifecycle_ops).uninstall_preserving_state()
    assert preserved==(layout.data,layout.models,layout.backups)
    assert not layout.runtime.exists() and fake_lifecycle_ops.keychain_delete_calls==0
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/deploy/test_atomic_install.py tests/integration/deploy/test_atomic_upgrade.py tests/integration/deploy/test_atomic_rollback.py tests/integration/deploy/test_uninstall_preserves_data.py -q`

Expected: FAIL with `ModuleNotFoundError: No module named 'tuntun_core.deploy.lifecycle'`.

- [ ] **Step 3: Implement lifecycle**

```python
# apps/core/src/tuntun_core/deploy/lifecycle.py
import os,shutil
from dataclasses import dataclass
from pathlib import Path
@dataclass(frozen=True,slots=True)
class ReleaseLayout:
    runtime:Path; releases:Path; current:Path; data:Path; database:Path; models:Path; backups:Path; logs:Path; launch_agent:Path
    @classmethod
    def for_home(cls,home):
        root=home/"Library/Application Support/Tuntun"; runtime=root/"runtime"
        return cls(runtime,runtime/"releases",runtime/"current",root/"data",root/"data/tuntun.db",root/"models",root/"backups",home/"Library/Logs/Tuntun",home/"Library/LaunchAgents/com.tuntun.core.plist")
def atomic_link(link,target):
    temporary=link.with_name(".current.next"); temporary.unlink(missing_ok=True); temporary.symlink_to(target); os.replace(temporary,link)
def rollback(layout,ops,previous,backup):
    ops.stop(); atomic_link(layout.current,previous); ops.restore_database(backup); ops.start(); ops.verify_protocol()
class Installer:
    def __init__(self,layout,ops): self.layout,self.ops=layout,ops
    def install(self,bundle,version,preflight=True,activate=True):
        for path in (self.layout.releases,self.layout.data,self.layout.models,self.layout.backups,self.layout.logs): path.mkdir(parents=True,exist_ok=True,mode=0o700); path.chmod(0o700)
        if preflight:
            self.ops.install_launch_agent(self.layout.launch_agent)
            self.ops.preflight("install")
        self.ops.verify_bundle(bundle,version)
        stage=self.layout.releases/("."+version+".staging"); destination=self.layout.releases/version
        self.ops.unpack(bundle,stage); stage.rename(destination); previous=self.layout.current.resolve() if self.layout.current.exists() else None
        if activate: atomic_link(self.layout.current,destination)
        if preflight:
            try:
                self.ops.load(self.layout.launch_agent)
                if not self.ops.ready(): raise RuntimeError("installed service readiness failed")
                self.ops.preflight("verify-installed")
            except BaseException:
                self.ops.unload(self.layout.launch_agent)
                if previous is None: self.layout.current.unlink(missing_ok=True)
                else: atomic_link(self.layout.current,previous)
                shutil.rmtree(destination); raise
        return destination
    def uninstall_preserving_state(self):
        self.ops.unload(self.layout.launch_agent); self.layout.launch_agent.unlink(missing_ok=True)
        if self.layout.runtime.exists(): shutil.rmtree(self.layout.runtime)
        return self.layout.data,self.layout.models,self.layout.backups
class UpgradeCoordinator:
    def __init__(self,layout,ops): self.layout,self.ops=layout,ops
    def apply(self,bundle,version):
        self.ops.preflight("upgrade"); previous=self.layout.current.resolve(); backup=self.ops.backup(); self.ops.verify_backup(backup)
        candidate=Installer(self.layout,self.ops).install(bundle,version,preflight=False,activate=False); self.ops.stop(); atomic_link(self.layout.current,candidate)
        try:
            self.ops.migrate(); self.ops.start()
            if not self.ops.ready(): raise RuntimeError("candidate readiness failed")
            self.ops.verify_protocol(); return version
        except BaseException:
            rollback(self.layout,self.ops,previous,backup); raise
```

Shell files `exec uv run tuntunctl update install|apply|rollback|uninstall "$@"`. The plist sets explicit current/config/log paths, `KeepAlive`, throttle 10, `SoftResourceLimits/Core=0`, files `1024`, processes `128`, and no secret environment. CLI runs exact preflight → backup/verify → storage/audit/models/protocol checks → atomic switch/migrate/readiness. Docs contain exact commands and preserving semantics.

- [ ] **Step 4: Run green**

Run: `chmod +x deploy/macos/{install,upgrade,rollback,uninstall}.sh && shellcheck deploy/macos/*.sh && plutil -lint deploy/macos/com.tuntun.core.plist && uv run pytest tests/integration/deploy/test_atomic_install.py tests/integration/deploy/test_atomic_upgrade.py tests/integration/deploy/test_atomic_rollback.py tests/integration/deploy/test_uninstall_preserves_data.py -q && uv run ruff check apps/core/src/tuntun_core/deploy/lifecycle.py tests/integration/deploy && uv run mypy apps/core/src/tuntun_core/deploy/lifecycle.py`

Expected: PASS for clean install, upgrade, rollback, failure rollback, installed plist/core limit, and preserving uninstall; tools exit `0`.

- [ ] **Step 5: Commit**

```bash
git status --short
git add apps/core/src/tuntun_core/deploy/lifecycle.py deploy/macos/install.sh deploy/macos/upgrade.sh deploy/macos/rollback.sh deploy/macos/uninstall.sh deploy/macos/com.tuntun.core.plist apps/core/src/tuntun_core/cli/commands/service.py apps/core/src/tuntun_core/cli/commands/update.py apps/core/src/tuntun_core/cli/main.py tests/integration/deploy/test_atomic_install.py tests/integration/deploy/test_atomic_upgrade.py tests/integration/deploy/test_atomic_rollback.py tests/integration/deploy/test_uninstall_preserves_data.py docs/operations/install-macos.md docs/operations/upgrade-rollback.md docs/operations/uninstall.md
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "build(deploy): add atomic macOS lifecycle"
```

### Task 3: Package the managed Reachy app and prove reboot recovery

**Master package:** 31
**Depends on:** Tasks 1–2 and master Task 12 compatibility report
**Estimated effort:** 1.5 person-days

**Files:**
- Create: `deploy/reachy/app.toml`
- Create: `deploy/reachy/build_app.sh`
- Create: `deploy/reachy/install_app.sh`
- Create: `deploy/reachy/uninstall_app.sh`
- Create: `deploy/reachy/entrypoint.sh`
- Test: `tests/integration/deploy/test_reachy_package.py`
- Test: `tests/hardware/test_edge_package.py`
- Create: `docs/operations/install-reachy.md`

**Interfaces:** `build_app.sh` requires `REACHY_SDK_VERSION: str`, `REACHY_DAEMON_VERSION: str`, and `SOURCE_DATE_EPOCH: int`, then produces `dist/tuntun-edge-0.1.0-beta.1.tar.gz`, `dist/tuntun-edge-0.1.0-beta.1.sha256`, and `compatibility.json: tuntun.reachy-compatibility.v1`; `install_app.sh <archive: Path> -> exit 0|65`; `uninstall_app.sh -> exit 0|70`; managed app ID is exactly `com.tuntun.edge`.

- [ ] **Step 1: Write failing package/reboot tests**

```python
# tests/integration/deploy/test_reachy_package.py
import tomllib
from pathlib import Path
def test_manifest_is_pinned_managed_and_offline():
    value=tomllib.loads(Path("deploy/reachy/app.toml").read_text())
    assert value["app"]=={"id":"com.tuntun.edge","version":"0.1.0-beta.1","entrypoint":"entrypoint.sh","managed_by":"reachy-mini-app-assistant"}
    assert value["runtime"]=={"python":"3.12","telemetry":False,"network_downloads":False}
```

```python
# tests/hardware/test_edge_package.py
import os,subprocess,pytest
@pytest.mark.reachy_hardware
def test_package_survives_real_reboot():
    if os.getenv("TUNTUN_ALLOW_REACHY_HARDWARE")!="1": pytest.skip("commissioned Reachy required")
    subprocess.run(("deploy/reachy/install_app.sh","dist/tuntun-edge-0.1.0-beta.1.tar.gz"),check=True)
    subprocess.run(("uv","run","tuntunctl","reachy","reboot","--wait-seconds","120"),check=True)
    out=subprocess.run(("uv","run","tuntunctl","reachy","verify-reboot","--synthetic-turn","--json"),check=True,text=True,capture_output=True).stdout
    assert all(token in out for token in ('"managed_app":"running"','"pairing":"restored"','"public_listeners":[]','"offline_essentials":true'))
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/integration/deploy/test_reachy_package.py -q`

Expected: FAIL with `FileNotFoundError: [Errno 2] No such file or directory: 'deploy/reachy/app.toml'`.

- [ ] **Step 3: Implement deterministic package**

```toml
[app]
id="com.tuntun.edge"
version="0.1.0-beta.1"
entrypoint="entrypoint.sh"
managed_by="reachy-mini-app-assistant"
[runtime]
python="3.12"
telemetry=false
network_downloads=false
[compatibility]
sdk_pin_source="uv.lock"
daemon_pin_source="var/hardware/reachy-capabilities.json"
require_exact_match=true
```

```sh
# deploy/reachy/build_app.sh
#!/bin/sh
set -eu
test -n "${SOURCE_DATE_EPOCH:-}"; test -n "${REACHY_SDK_VERSION:-}"; test -n "${REACHY_DAEMON_VERSION:-}"
stage=$(mktemp -d); trap 'rm -rf "$stage"' EXIT INT TERM
cp deploy/reachy/app.toml deploy/reachy/entrypoint.sh "$stage"/
uv run python -c 'import json,os,pathlib,sys; pathlib.Path(sys.argv[1]).write_text(json.dumps({"schema_version":"tuntun.reachy-compatibility.v1","sdk":os.environ["REACHY_SDK_VERSION"],"daemon":os.environ["REACHY_DAEMON_VERSION"],"exact_match":True},sort_keys=True,separators=(",",":"))+"\n")' "$stage/compatibility.json"
cp -R apps/edge "$stage/apps-edge"; find "$stage" -exec touch -h -t 197001010000.00 {} +; mkdir -p dist
tar --sort=name --owner=0 --group=0 --numeric-owner -czf dist/tuntun-edge-0.1.0-beta.1.tar.gz -C "$stage" .
shasum -a 256 dist/tuntun-edge-0.1.0-beta.1.tar.gz > dist/tuntun-edge-0.1.0-beta.1.sha256
```

Install verifies hash and exact compatibility before the pinned managed-app command; uninstall removes only this app. Entrypoint is `exec uv run tuntun-edge managed`. Docs state daemon remains official, unmanaged clients are detected rather than claimed impossible, and SSH stays key-only/restricted.

- [ ] **Step 4: Run green**

Run: `chmod +x deploy/reachy/*.sh && shellcheck deploy/reachy/*.sh && REACHY_SDK_VERSION=$(uv run tuntunctl reachy compatibility --field sdk) REACHY_DAEMON_VERSION=$(uv run tuntunctl reachy compatibility --field daemon) SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD) deploy/reachy/build_app.sh && shasum -a 256 -c dist/tuntun-edge-0.1.0-beta.1.sha256 && uv run pytest tests/integration/deploy/test_reachy_package.py -q && TUNTUN_ALLOW_REACHY_HARDWARE=1 uv run pytest -m reachy_hardware tests/hardware/test_edge_package.py -q`

Expected: PASS after a real Reachy reboot, pairing restoration, exact listener check, offline essentials, and synthetic turn.

- [ ] **Step 5: Commit**

```bash
git status --short
git add deploy/reachy/app.toml deploy/reachy/build_app.sh deploy/reachy/install_app.sh deploy/reachy/uninstall_app.sh deploy/reachy/entrypoint.sh tests/integration/deploy/test_reachy_package.py tests/hardware/test_edge_package.py docs/operations/install-reachy.md
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "build(reachy): package managed edge app and reboot gate"
```

### Task 4: Reconcile privacy/security boundaries and freeze blocker policy

**Master package:** 32
**Depends on:** Task 3 and all master Tasks 01–31
**Estimated effort:** 3.5 person-days

**Files:**
- Modify: `docs/privacy/threat-model.md`
- Modify: `docs/privacy/data-flow-inventory.md`
- Create: `docs/privacy/provider-boundaries.md`
- Create: `docs/privacy/residual-risks.md`
- Create: `security/policy-v1.yaml`
- Create: `security/policy-v1.schema.json`
- Create: `scripts/security_gate.py`
- Modify: `packages/contracts/src/tuntun_contracts/provider.py`
- Modify: `apps/core/src/tuntun_core/api/middleware.py`
- Test: `tests/security/test_security_policy.py`
- Test: `tests/security/test_network_surface.py`
- Test: `tests/security/test_egress_surface.py`
- Test: `tests/property/test_event_parser_fuzz.py`
- Test: `tests/property/test_media_header_fuzz.py`
- Test: `tests/property/test_model_output_fuzz.py`
- Test: `tests/property/test_memory_proposal_fuzz.py`
- Test: `tests/property/test_openapi_input_fuzz.py`
- Test: `tests/property/test_provider_usage_fuzz.py`
- Test: `tests/property/test_backup_parser_fuzz.py`
- Test: `tests/property/test_import_export_fuzz.py`

**Interfaces:** `SecurityPolicy.load(schema_path: Path, policy_path: Path) -> SecurityPolicy`; `await SecurityPolicy.evaluate(findings: tuple[Finding,...], receipt_verifier: SuppressionReceiptVerifier, now: datetime | None = None) -> SecurityDecision`; `await SuppressionReceiptVerifier.verify(suppression: FindingSuppression, finding: Finding, policy_version: str, now: datetime) -> AuthContext`; `reconcile_listeners(observed: set[str], resolved_interface: str, lan_console: bool) -> tuple[str,...]`; `reconcile_egress(phase: str, observed: tuple[str,...]) -> tuple[str,...]`; strict `tuntun.security-policy.v1`. A suppression is a high-risk, owner-passkey-authorized `security.finding.suppress` action, not a caller-authored expiry timestamp.

- [ ] **Step 1: Write failing policy/network/fuzz tests**

```python
# tests/security/test_security_policy.py
import pytest
from datetime import timedelta
from pathlib import Path
from scripts.security_gate import Finding,FindingSuppression,SecurityPolicy

@pytest.mark.asyncio
async def test_unsigned_wrong_finding_expired_and_revoked_suppressions_block(rejecting_receipt_verifier,suppression_factory,now):
    policy=SecurityPolicy.load(Path("security/policy-v1.schema.json"),Path("security/policy-v1.yaml"))
    cases=(
        None,
        suppression_factory(finding_id="S-18"),
        suppression_factory(expires_at=now),
        suppression_factory(revoked_at=now),
        suppression_factory(receipt_id=None),
        suppression_factory(issued_at=now+timedelta(seconds=1)),
        suppression_factory(expires_at=now+timedelta(days=31)),
    )
    for suppression in cases:
        finding=Finding("S-17","f"*64,"high","failed_authentication",suppression)
        decision=await policy.evaluate((finding,),rejecting_receipt_verifier,now)
        assert not decision.allowed and decision.blockers==("S-17",)

@pytest.mark.asyncio
async def test_exact_finding_bound_owner_passkey_receipt_can_suppress_for_at_most_30_days(valid_receipt_verifier,suppression_factory,now):
    policy=SecurityPolicy.load(Path("security/policy-v1.schema.json"),Path("security/policy-v1.yaml"))
    finding=Finding("S-17","f"*64,"high","failed_authentication",suppression_factory())
    decision=await policy.evaluate((finding,),valid_receipt_verifier,now)
    assert decision.allowed and decision.suppressed==("S-17",)
```

```python
# tests/property/test_event_parser_fuzz.py
from hypothesis import given,strategies as st
from tuntun_edge.transport.protocol import parse_event
@given(st.binary(max_size=131072))
def test_event_parser_returns_or_typed_reject(data):
    try: parse_event(data)
    except (ValueError,TypeError): return
```

```python
# tests/property/test_media_header_fuzz.py
from hypothesis import given, strategies as st
from tuntun_edge.transport.media import MAX_CAMERA_PAYLOAD,MAX_HEADER,parse_prefix
@given(st.binary(max_size=131072))
def test_media_prefix_is_bounded(data):
    try:
        _,_,header_bytes,payload_bytes=parse_prefix(data[:12])
        assert header_bytes<=MAX_HEADER and payload_bytes<=MAX_CAMERA_PAYLOAD
    except (ValueError,TypeError,UnicodeError):
        return
```

```python
# tests/property/test_model_output_fuzz.py
from hypothesis import given, strategies as st
from pydantic import ValidationError
from tuntun_core.services.providers.output_validator import AssistantTurn
@given(st.binary(max_size=1048576))
def test_assistant_turn_is_typed_or_rejected(data):
    try:
        value=AssistantTurn.model_validate_json(data)
        assert value.model_dump(mode="json")
    except (ValidationError,ValueError,UnicodeError):
        return
```

```python
# tests/property/test_memory_proposal_fuzz.py
import pytest
from hypothesis import given, strategies as st
from pydantic import TypeAdapter,ValidationError
from tuntun_core.services.providers.output_validator import ProviderMemoryIntent,ProposalMapper
from tuntun_contracts.memory import MemoryProposalDraft

adapter=TypeAdapter(ProviderMemoryIntent)
forbidden={"proposal_id","household_id","subject_id","target_memory_id","source_receipt_ids","parameters_commitment","idempotency_key"}
@given(st.binary(max_size=262144))
def test_provider_memory_intent_is_closed_pseudonymous_or_rejected(data):
    try:
        value=adapter.validate_json(data)
        assert forbidden.isdisjoint(value.model_dump(mode="json"))
    except (ValidationError,ValueError,UnicodeError):
        return

@given(st.from_regex(r"subject:[a-z0-9_-]{1,32}",fullmatch=True).filter(lambda value:value!="subject:issued"))
def test_mapper_rejects_every_unissued_subject_reference(unknown_ref,proposal_mapper:ProposalMapper,turn_context):
    intent=adapter.validate_python({"kind":"remember_preference","subject_ref":unknown_ref,"category":"food","key":"spice","value":"mild","confidence_micros":900000,"reason":"asked"})
    with pytest.raises((LookupError,PermissionError)):
        proposal_mapper.map_memory(intent,turn_context.household_id,turn_context.session_id,turn_context.turn_id)

def test_mapper_is_the_only_internal_draft_boundary(proposal_mapper,turn_context):
    intent=adapter.validate_python({"kind":"remember_preference","subject_ref":"subject:issued","category":"food","key":"spice","value":"mild","confidence_micros":900000,"reason":"asked"})
    value=proposal_mapper.map_memory(intent,turn_context.household_id,turn_context.session_id,turn_context.turn_id)
    assert isinstance(value,MemoryProposalDraft) and value.household_id==turn_context.household_id
```

```python
# tests/property/test_openapi_input_fuzz.py
from hypothesis import given,strategies as st
@given(st.binary(max_size=1048576),st.sampled_from(("application/json","application/cbor","text/plain")))
def test_openapi_body_is_bounded_or_typed_reject(api_client,data,content_type):
    response=api_client.post("/api/v1/actions/prepare",content=data,headers={"content-type":content_type})
    assert response.status_code in {400,401,403,413,415,422,428,429}
    assert len(response.content)<=65536
```

```python
# tests/property/test_provider_usage_fuzz.py
from hypothesis import given,strategies as st
from pydantic import ValidationError
from tuntun_contracts.provider import Usage
@given(st.binary(max_size=262144))
def test_provider_usage_is_nonnegative_bounded_or_rejected(data):
    try:
        value=Usage.model_validate_json(data)
        assert 0<=value.input_units<=1000000 and 0<=value.output_units<=1000000
        assert 0<=value.audio_millis<=90000
    except (ValidationError,ValueError,UnicodeError):
        return
```

```python
# tests/property/test_backup_parser_fuzz.py
from pathlib import Path
from hypothesis import given, strategies as st
from tuntun_core.services.data_lifecycle.backup_format import BackupReader,BackupFormatError,MAX_HEADER
@given(st.binary(max_size=1048576))
def test_backup_header_is_bounded(data):
    try:
        prefix=BackupReader(Path("/unreachable")).parse_prefix(data[:9])
        assert 1<=prefix.header_length<=MAX_HEADER
    except (BackupFormatError,ValueError,TypeError,UnicodeError):
        return
```

```python
# tests/property/test_import_export_fuzz.py
from hypothesis import given, strategies as st
from pydantic import ValidationError
from tuntun_core.services.data_lifecycle.export import ProfileTransferManifest
@given(st.binary(max_size=1048576))
def test_import_manifest_is_typed_or_rejected(data):
    try:
        value=ProfileTransferManifest.model_validate_json(data)
        assert value.schema_version=="tuntun.profile-transfer.v1"
    except (ValidationError,ValueError,UnicodeError):
        return
```

```python
# tests/security/test_network_surface.py
from scripts.security_gate import reconcile_listeners
def test_physical_listener_set_is_exact():
    observed={"127.0.0.1:8787","192.168.50.10:7443"}
    assert reconcile_listeners(observed,resolved_interface="192.168.50.10",lan_console=False)==()
    assert reconcile_listeners(observed|{"0.0.0.0:7443"},resolved_interface="192.168.50.10",lan_console=False)==("0.0.0.0:7443",)
```

```python
# tests/security/test_egress_surface.py
from scripts.security_gate import reconcile_egress
def test_startup_has_zero_egress_and_explicit_flows_are_allowlisted():
    assert reconcile_egress("startup",())==()
    provider=("api.openai.com:443",)
    assert reconcile_egress("provider_turn",provider)==()
    assert reconcile_egress("provider_turn",provider+("telemetry.example:443",))==("telemetry.example:443",)
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/test_security_policy.py tests/security/test_network_surface.py tests/security/test_egress_surface.py tests/property/test_event_parser_fuzz.py tests/property/test_media_header_fuzz.py tests/property/test_model_output_fuzz.py tests/property/test_memory_proposal_fuzz.py tests/property/test_openapi_input_fuzz.py tests/property/test_provider_usage_fuzz.py tests/property/test_backup_parser_fuzz.py tests/property/test_import_export_fuzz.py -q`

Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.security_gate'`.

- [ ] **Step 3: Implement strict policy/reconciliation**

```yaml
schema_version: tuntun.security-policy.v1
policy_version: "1.0"
block_severities: [critical, high]
block_codes: [secret, real_family_fixture, raw_media, verbatim_transcript, unauthorized_egress, invalid_audit_chain, plaintext_fallback, failed_isolation, failed_authentication, failed_child_safety, failed_privacy_or_stop, unsafe_motion, incompatible_license]
suppression: {action_name: security.finding.suppress, owner_passkey_required: true, maximum_days: 30}
required_boundaries: [reachy_hardware_daemon_edge, lan_pairing_ssh, mac_account_keychain_filesystem_process, browser_admin_session, sqlcipher_backup, model_weights, openai, qwen_disabled, prompts_model_outputs, source_supply_chain_ci]
```

```python
# scripts/security_gate.py
from dataclasses import dataclass
from datetime import UTC,datetime,timedelta
from uuid import UUID
import json,jsonschema,yaml
def reconcile_listeners(observed,resolved_interface,lan_console):
    allowed={"127.0.0.1:8787",f"{resolved_interface}:7443"}
    if lan_console: allowed.add(f"{resolved_interface}:8443")
    return tuple(sorted(set(observed)-allowed))
def reconcile_egress(phase,observed):
    allowed={"startup":set(),"model_install":{"huggingface.co:443"},"provider_turn":{"api.openai.com:443"}}
    if phase not in allowed: return tuple(sorted(observed))
    return tuple(sorted(set(observed)-allowed[phase]))
@dataclass(frozen=True,slots=True)
class FindingSuppression:
    finding_id:str; finding_fingerprint:str; receipt_id:UUID|None
    issued_at:datetime; expires_at:datetime; revoked_at:datetime|None
@dataclass(frozen=True,slots=True)
class Finding:
    finding_id:str; fingerprint:str; severity:str; code:str
    suppression:FindingSuppression|None
@dataclass(frozen=True,slots=True)
class SecurityDecision: allowed:bool; blockers:tuple[str,...]; suppressed:tuple[str,...]
class SecurityPolicy:
    def __init__(self,schema,raw): self.schema,self.raw=schema,raw
    @classmethod
    def load(cls,schema_path,policy_path):
        schema=json.loads(schema_path.read_text()); raw=yaml.safe_load(policy_path.read_text()); jsonschema.Draft202012Validator(schema).validate(raw); return cls(schema,raw)
    async def evaluate(self,findings,receipt_verifier,now=None):
        current=now or datetime.now(UTC); blocked=[]; suppressed=[]
        for finding in findings:
            if finding.severity not in self.raw["block_severities"] and finding.code not in self.raw["block_codes"]: continue
            item=finding.suppression
            structurally_valid=item is not None and item.receipt_id is not None and item.finding_id==finding.finding_id and item.finding_fingerprint==finding.fingerprint and item.revoked_at is None and item.issued_at<=current<item.expires_at and item.expires_at-item.issued_at<=timedelta(days=self.raw["suppression"]["maximum_days"])
            if structurally_valid:
                try:
                    auth=await receipt_verifier.verify(item,finding,self.raw["policy_version"],current)
                    if auth.assurance.value!="passkey_verified" or auth.assurance_source!="passkey": raise PermissionError("owner passkey required")
                    suppressed.append(finding.finding_id); continue
                except (PermissionError,ValueError,RuntimeError): pass
            blocked.append(finding.finding_id)
        return SecurityDecision(not blocked,tuple(sorted(blocked)),tuple(sorted(suppressed)))
```

Schema is draft 2020-12, recursively strict, and fixes all values above. `SuppressionReceiptVerifier` reopens the tamper-evident authorization receipt and verifies an unexpired, exactly-once-consumed owner passkey grant whose complete `ActionBinding` has `action_name="security.finding.suppress"`, `resource_type="security_finding"`, a stable resource UUID for the finding ID, and a parameter commitment over policy version + finding ID + finding fingerprint + issue/expiry; any missing receipt, mismatched finding, future issue time, duration above 30 days, expiry, revocation, non-owner subject, wrong factor, changed binding, or failed receipt MAC/signature blocks. Suppressions and their revocations remain in the audit chain and release evidence. Threat model covers every required boundary with asset/attacker/abuse/control/residual-risk/owner/proof. Inventory columns are `Flow ID | Source | Consent/purpose | Processor | Location | Egress | Retention | Deletion/backups | Encryption/key custody | Access | Audit | Residual risk`; observed unknown flow blocks. Provider/residual docs record exact endpoints, disabled Qwen, redirects, no startup download, `store=false` limitation, FileVault/swap, software mic privacy, unmanaged Reachy, provider retention, exported backups, liveness, and account compromise. The memory fuzz target validates only the closed provider-facing pseudonymous union and then exercises `ProposalMapper` against issued/unissued references before accepting an internal `tuntun_contracts.memory.MemoryProposalDraft`; fuzz bytes never supply internal IDs, receipts, or commitments. The hardened `Usage` contract caps each text-unit count at `1,000,000` and audio at `90,000ms`, while the OpenAPI middleware rejects bodies above `1MiB` before parsing and caps typed error bodies at `64KiB`.

- [ ] **Step 4: Run green**

Run: `uv run pytest tests/security/test_security_policy.py tests/security/test_network_surface.py tests/security/test_egress_surface.py tests/property/test_event_parser_fuzz.py tests/property/test_media_header_fuzz.py tests/property/test_model_output_fuzz.py tests/property/test_memory_proposal_fuzz.py tests/property/test_openapi_input_fuzz.py tests/property/test_provider_usage_fuzz.py tests/property/test_backup_parser_fuzz.py tests/property/test_import_export_fuzz.py -q && uv run python scripts/security_gate.py --policy security/policy-v1.yaml --schema security/policy-v1.schema.json --findings var/security/findings.json --flows var/security/observed-flows.json`

Expected: PASS with all eight master-required bounded fuzz suites, exact physical listener/egress proof, every flow documented, zero blocker, valid strict policy, and no suppression accepted without a live exact owner-passkey receipt.

- [ ] **Step 5: Commit**

```bash
git status --short
git add docs/privacy/threat-model.md docs/privacy/data-flow-inventory.md docs/privacy/provider-boundaries.md docs/privacy/residual-risks.md security/policy-v1.yaml security/policy-v1.schema.json scripts/security_gate.py packages/contracts/src/tuntun_contracts/provider.py apps/core/src/tuntun_core/api/middleware.py tests/security/test_security_policy.py tests/security/test_network_surface.py tests/security/test_egress_surface.py tests/property/test_event_parser_fuzz.py tests/property/test_media_header_fuzz.py tests/property/test_model_output_fuzz.py tests/property/test_memory_proposal_fuzz.py tests/property/test_openapi_input_fuzz.py tests/property/test_provider_usage_fuzz.py tests/property/test_backup_parser_fuzz.py tests/property/test_import_export_fuzz.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "security: reconcile boundaries and freeze blocker policy"
```

### Task 5: Generate signed supply-chain and reproducibility evidence

**Master package:** 32
**Depends on:** Task 4
**Estimated effort:** 3.5 person-days

**Files:**
- Create: `security/schemas/security-evidence-v1.schema.json`
- Create: `security/schemas/evidence-signers-v1.schema.json`
- Create: `security/evidence-signers-v1.json`
- Create: `security/tool-versions-v1.json`
- Create: `security/license-policy-v1.yaml`
- Create: `scripts/evidence.py`
- Create: `scripts/collect_release_evidence.py`
- Create: `scripts/verify_release_evidence.py`
- Modify: `scripts/verify_private_data.py`
- Modify: `Makefile`
- Create: `.github/workflows/security.yml`
- Create: `.github/workflows/release.yml`
- Test: `tests/security/test_evidence_signature.py`
- Test: `tests/security/test_supply_chain_evidence.py`
- Test: `tests/release/test_reproducible_build.py`

**Interfaces:** `EvidenceSigner(key_id: str, purpose: EvidencePurpose, private_key: Ed25519PrivateKey, clock: Clock).sign(payload: dict) -> SignedEvidence`; `SignerRegistry.load(schema_path: Path, registry_path: Path) -> SignerRegistry`; `open_signed_evidence(envelope: SignedEvidence, schema: dict, registry: SignerRegistry, expected_purpose: EvidencePurpose, now: datetime) -> dict`; `signed_envelope_sha256(envelope: SignedEvidence) -> str`; `collect(candidate: Candidate, runner: ReleaseRunner, signer: EvidenceSigner) -> SignedEvidence`. Every signature covers a protected header and payload; strict signed `tuntun.security-evidence.v1` uses purpose `security`.

- [ ] **Step 1: Write failing signature/tool tests**

```python
# tests/security/test_supply_chain_evidence.py
from scripts.collect_release_evidence import REQUIRED_PREFIXES,collect
def test_every_required_tool_and_two_builds_run(fake_release_runner,fake_signer,candidate):
    envelope=collect(candidate,fake_release_runner,fake_signer); calls=(" ".join(call) for call in fake_release_runner.calls)
    calls=tuple(calls); assert all(any(call.startswith(prefix) for call in calls) for prefix in REQUIRED_PREFIXES)
    assert envelope.payload["history_scan"]["scope"]=="all_reachable_history"
    assert envelope.payload["reproducibility"]=={"build_count":2,"identical":True,"manifest_sha256":"a"*64}
```

```python
# tests/security/test_evidence_signature.py
import pytest
from datetime import timedelta
from scripts.evidence import open_signed_evidence

def test_payload_and_every_protected_header_field_are_signed(valid_security_envelope,security_schema,signer_registry,now):
    mutations=(
        {"payload":{**valid_security_envelope.payload,"commit":"b"*40}},
        {"protected":valid_security_envelope.protected.model_copy(update={"key_id":"other-security-v1"})},
        {"protected":valid_security_envelope.protected.model_copy(update={"purpose":"acceptance"})},
        {"protected":valid_security_envelope.protected.model_copy(update={"signed_at":now+timedelta(seconds=1)})},
        {"protected":valid_security_envelope.protected.model_copy(update={"algorithm":"Ed25519ph"})},
    )
    for change in mutations:
        with pytest.raises(ValueError):
            open_signed_evidence(valid_security_envelope.model_copy(update=change),security_schema,signer_registry,"security",now)

@pytest.mark.parametrize("registry_kind",("wrong_purpose","wrong_key_role","wrong_algorithm","expired","revoked","duplicate_public_key_alias"))
def test_registry_policy_rejects_purpose_role_algorithm_lifecycle_and_key_aliases(valid_security_envelope,security_schema,registry_factory,registry_kind,now):
    with pytest.raises(ValueError):
        open_signed_evidence(valid_security_envelope,security_schema,registry_factory(registry_kind),"security",now)
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/test_evidence_signature.py tests/security/test_supply_chain_evidence.py tests/release/test_reproducible_build.py -q`

Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.evidence'`.

- [ ] **Step 3: Implement signed evidence and pinned tool execution**

```python
# scripts/evidence.py
import base64,json,jsonschema,rfc8785
from dataclasses import dataclass
from datetime import UTC,datetime,timedelta
from hashlib import sha256
from pathlib import Path
from typing import Literal
from pydantic import BaseModel,ConfigDict
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
EvidencePurpose=Literal["security","acceptance","soak_run","soak_bundle","latency_deviation","family_stage","family_review","family_trial","p1r0_approval","publication"]
OWNER_PURPOSES=frozenset({"latency_deviation","family_review","p1r0_approval","publication"})
AUTOMATION_PURPOSES=frozenset({"security","acceptance","soak_run","soak_bundle","family_stage","family_trial"})
class ProtectedEvidenceHeader(BaseModel):
    model_config=ConfigDict(extra="forbid",frozen=True)
    envelope_version:Literal["tuntun.signed-evidence.v1"]="tuntun.signed-evidence.v1"
    key_id:str
    algorithm:Literal["Ed25519"]="Ed25519"
    purpose:EvidencePurpose
    signed_at:datetime
class SignedEvidence(BaseModel):
    model_config=ConfigDict(extra="forbid",frozen=True)
    protected:ProtectedEvidenceHeader; payload:dict; signature_b64:str
@dataclass(frozen=True,slots=True)
class SignerRecord:
    key_id:str; algorithm:str; public_key:Ed25519PublicKey; public_key_bytes:bytes
    key_role:Literal["automation","owner"]; purposes:frozenset[str]
    not_before:datetime; not_after:datetime; revoked_at:datetime|None
class SignerRegistry:
    def __init__(self,records): self.records=records
    @classmethod
    def load(cls,schema_path:Path,registry_path:Path):
        schema=json.loads(schema_path.read_text()); raw=json.loads(registry_path.read_text())
        jsonschema.Draft202012Validator(schema,format_checker=jsonschema.FormatChecker()).validate(raw)
        records={}; seen_material=set()
        for item in raw["signers"]:
            material=base64.b64decode(item["public_key_b64"],validate=True)
            if material in seen_material: raise ValueError("duplicate evidence public-key alias")
            seen_material.add(material)
            purposes=frozenset(item["purposes"])
            if len(purposes)!=1: raise ValueError("one evidence purpose per key")
            role=item["key_role"]
            if (role=="owner" and not purposes<=OWNER_PURPOSES) or (role=="automation" and not purposes<=AUTOMATION_PURPOSES): raise ValueError("evidence purpose/key-role mismatch")
            record=SignerRecord(item["key_id"],item["algorithm"],Ed25519PublicKey.from_public_bytes(material),material,role,purposes,datetime.fromisoformat(item["not_before"]),datetime.fromisoformat(item["not_after"]),None if item["revoked_at"] is None else datetime.fromisoformat(item["revoked_at"]))
            if record.not_before>=record.not_after: raise ValueError("invalid evidence key validity window")
            if record.key_id in records: raise ValueError("duplicate evidence key id")
            records[record.key_id]=record
        return cls(records)
def canonical(value): return rfc8785.dumps(value)
def signed_body(envelope): return canonical({"protected":envelope.protected.model_dump(mode="json"),"payload":envelope.payload})
class EvidenceSigner:
    def __init__(self,key_id,purpose,private_key,clock): self.key_id,self.purpose,self.private_key,self.clock=key_id,purpose,private_key,clock
    def sign(self,payload):
        header=ProtectedEvidenceHeader(key_id=self.key_id,purpose=self.purpose,signed_at=self.clock.now())
        unsigned=SignedEvidence(protected=header,payload=payload,signature_b64="")
        signature=self.private_key.sign(b"tuntun:release-evidence:v1\0"+signed_body(unsigned))
        return unsigned.model_copy(update={"signature_b64":base64.b64encode(signature).decode("ascii")})
def open_signed_evidence(envelope,schema,registry,expected_purpose,now):
    record=registry.records.get(envelope.protected.key_id)
    if record is None or envelope.protected.algorithm!=record.algorithm: raise ValueError("unauthorized evidence key or algorithm")
    if envelope.protected.purpose!=expected_purpose or expected_purpose not in record.purposes: raise ValueError("wrong evidence purpose")
    signed_at=envelope.protected.signed_at
    if signed_at.tzinfo is None or not record.not_before<=signed_at<=record.not_after or signed_at>now+timedelta(minutes=5): raise ValueError("evidence outside signer validity")
    if record.revoked_at is not None: raise ValueError("revoked evidence key")
    try: record.public_key.verify(base64.b64decode(envelope.signature_b64,validate=True),b"tuntun:release-evidence:v1\0"+signed_body(envelope.model_copy(update={"signature_b64":""})))
    except (InvalidSignature,ValueError) as error: raise ValueError("invalid evidence signature") from error
    jsonschema.Draft202012Validator(schema,format_checker=jsonschema.FormatChecker()).validate(envelope.payload)
    return envelope.payload
def signed_envelope_sha256(envelope): return sha256(canonical(envelope.model_dump(mode="json"))).hexdigest()
```

```python
# scripts/collect_release_evidence.py
REQUIRED_PREFIXES=("uv run pip-audit","pnpm audit --prod --json","gitleaks git --log-opts=--all","uv run bandit","uv run semgrep","uv run cyclonedx-py","pnpm exec cyclonedx-npm","uv run pip-licenses","pnpm licenses list --json","uv run python scripts/check_model_manifest.py","uv run python scripts/verify_private_data.py")
def collect(candidate,runner,signer):
    if signer.purpose!="security": raise ValueError("security signer required")
    results={prefix:runner.run(tuple(prefix.split())) for prefix in REQUIRED_PREFIXES}
    if any(item.returncode for item in results.values()): raise RuntimeError("release tool failed")
    first=runner.build(candidate,"build-a"); second=runner.build(candidate,"build-b")
    if first.manifest!=second.manifest: raise RuntimeError("reproducibility mismatch")
    payload={"schema_version":"tuntun.security-evidence.v1","candidate_version":candidate.version,"commit":candidate.commit,"source_date_epoch":candidate.source_date_epoch,"tool_versions":runner.tool_versions(),"scan_results":runner.scan_results(results),"history_scan":{"scope":"all_reachable_history","clean":True},"sboms":runner.sboms(),"licenses":runner.licenses(),"model_manifest_sha256":runner.sha256("models/manifest.yaml"),"reproducibility":{"build_count":2,"identical":True,"manifest_sha256":first.sha256},"artifacts":first.artifacts,"provenance":runner.provenance(),"generated_at":runner.now()}
    return signer.sign(payload)
```

Both schemas recursively forbid extras. Security evidence requires exact version/commit/hashes, nonempty Python/npm SBOMs, source/dependency/model licenses, tool version/hash/source, zero blockers, all-reachable-history clean, the complete non-evidence release artifact inventory (`role`, relative path, SHA-256, size), and two identical builds using `SOURCE_DATE_EPOCH` from commit. The signer registry fixes `algorithm="Ed25519"`, exact base64 public-key length, one purpose per key, an explicit `automation` or `owner` key role, validity window, nullable revocation timestamp, and unique key IDs; the loader additionally rejects the same public-key bytes under multiple aliases and rejects any purpose/role mismatch. Revoked records are fail-closed even for older signatures during release authorization. Separate Keychain keys are provisioned for security, acceptance, soak run, soak bundle, latency deviation, family stage, family review, family trial, P1R0, and publication; only owner-role keys may sign latency deviations, family reviews, P1R0, or publication records, and automation-role keys cannot hold those purposes. License policy allow/review/deny lists and model hash/provenance are exact. Make targets cover security/model/SBOM/license/listener/egress/fuzz/verify. Security CI pins actions/tools. Release workflow is manual `workflow_dispatch`, `contents: read`, `id-token: write`, build/attest/upload-artifact only—no tag or publication.

- [ ] **Step 4: Run green**

Run: `uv run pytest tests/security/test_evidence_signature.py tests/security/test_supply_chain_evidence.py tests/release/test_reproducible_build.py -q && make security-scan model-manifest-check sbom license-check listener-scan egress-scan fuzz`

Expected: PASS with complete SBOM/licenses/history scan coverage, hashes/provenance, zero blockers, identical fixture builds, protected-header/signature policy, and no release evidence signed before this implementation is committed.

- [ ] **Step 5: Commit**

```bash
git status --short
git add security/schemas/security-evidence-v1.schema.json security/schemas/evidence-signers-v1.schema.json security/evidence-signers-v1.json security/tool-versions-v1.json security/license-policy-v1.yaml scripts/evidence.py scripts/collect_release_evidence.py scripts/verify_release_evidence.py scripts/verify_private_data.py Makefile .github/workflows/security.yml .github/workflows/release.yml tests/security/test_evidence_signature.py tests/security/test_supply_chain_evidence.py tests/release/test_reproducible_build.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "security(release): sign supply-chain and reproducibility evidence"
```

### Task 6: Freeze and execute the complete synthetic acceptance matrix

**Master package:** 33
**Depends on:** Task 5
**Estimated effort:** 3 person-days

**Files:**
- Create: `evals/reports/acceptance-report-v1.schema.json`
- Create: `evals/reports/phase1-baseline.md`
- Create: `scripts/run_acceptance.py`
- Create: `docs/operations/acceptance-runbook.md`
- Test: `tests/acceptance/test_acceptance_schema.py`
- Test: `tests/acceptance/test_report_gate.py`
- Test: `tests/e2e/test_full_conversation.py`
- Test: `tests/e2e/test_memory_approval.py`
- Test: `tests/e2e/test_identity_guest_fallback.py`
- Test: `tests/e2e/test_budget_offline.py`

**Interfaces:** `run_matrix(candidate: Candidate, runner: AcceptanceRunner, signer: EvidenceSigner) -> SignedEvidence`; `gate(report: dict, version: str, commit: str, expected_security_hash: str) -> AcceptanceDecision`; strict content-free `tuntun.acceptance-report.v1` with frozen component hashes, per-suite counts/result hashes, and measured aggregate thresholds. Acceptance uses the purpose-separated `acceptance` signer and contains no caller-authored pass boolean.

- [ ] **Step 1: Write failing gate/schema tests**

```python
# tests/acceptance/test_report_gate.py
from scripts.run_acceptance import gate
def test_failed_count_or_unexecuted_minimum_blocks_even_when_report_is_signed(valid_acceptance_report):
    row=valid_acceptance_report["suite_results"]["privacy_interrupt_all_states"]
    row.update(executed=1,passed=0,failed=1)
    decision=gate(valid_acceptance_report,"0.1.0-beta.1","a"*40,"b"*64)
    assert not decision.allowed and "privacy_interrupt_all_states:failed" in decision.failures

def test_semantically_failing_metrics_cannot_be_replaced_by_true_labels(valid_acceptance_report):
    valid_acceptance_report["metrics"]["memory_recall_at_6_micros"]=899999
    valid_acceptance_report["metrics"]["identity_false_personalization_count"]=1
    decision=gate(valid_acceptance_report,"0.1.0-beta.1","a"*40,"b"*64)
    assert {"memory_recall_at_6_micros","identity_false_personalization_count"}<=set(decision.failures)
```

```python
# tests/acceptance/test_acceptance_schema.py
import json,jsonschema
from pathlib import Path
def test_content_and_unknown_fields_rejected(valid_acceptance_report):
    valid_acceptance_report["transcript"]="forbidden"
    schema=json.loads(Path("evals/reports/acceptance-report-v1.schema.json").read_text())
    assert tuple(jsonschema.Draft202012Validator(schema).iter_errors(valid_acceptance_report))
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/acceptance/test_acceptance_schema.py tests/acceptance/test_report_gate.py -q`

Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.run_acceptance'`.

- [ ] **Step 3: Implement matrix and strict report**

```python
# scripts/run_acceptance.py
import re
from dataclasses import dataclass
MIN_CASES={"bilingual_persona_240":240,"cross_profile_isolation_1000":1000,"guest_ambiguity":1,"child_safety":1,"identity_presentation_attacks":1,"memory_all_kinds":7,"memory_retrieval_thresholds":1,"authorization_binding":1,"pin_passkey_recovery":1,"budget_boundaries_singapore":1,"backup_restore_corruption":1,"fresh_mac_empty_keychain":1,"audit_rotation":1,"profile_deletion_no_resurrection":1,"provider_consent_revoke":1,"no_prewake_cloud_bytes":1,"second_tts_dlp":1,"ai_voice_disclosure":1,"offline_commands_zero_cloud":1,"privacy_interrupt_all_states":1,"restart_disconnect_all_states":1,"upgrade_rollback_reboot_uninstall":1,"private_data_sentinel_scan":1}
LOWER_BOUNDS={"language_follow_rate_micros":950000,"identity_genuine_accept_rate_micros":900000,"memory_recall_at_6_micros":900000,"memory_mrr_at_6_micros":750000}
UPPER_BOUNDS={"stop_privacy_p95_ms":250,"wake_ack_p95_ms":500,"reachy_reconnect_p95_ms":30000,"memory_max_items":6,"memory_context_tokens":8000}
ZERO_FIELDS=("identity_false_personalization_count","cross_profile_leak_count","unsafe_action_count","duplicate_effect_count","private_data_finding_count")
HASH64=re.compile(r"^[0-9a-f]{64}$")
@dataclass(frozen=True,slots=True)
class AcceptanceDecision: allowed:bool; failures:tuple[str,...]
def gate(report,version,commit,expected_security_hash):
    failures=[]
    candidate=report.get("candidate",{})
    if candidate.get("version")!=version: failures.append("candidate_version")
    if candidate.get("commit")!=commit: failures.append("candidate_commit")
    suites=report.get("suite_results",{})
    if set(suites)!=set(MIN_CASES): failures.append("suite_set")
    for name,minimum in MIN_CASES.items():
        row=suites.get(name,{})
        executed=row.get("executed",-1); passed=row.get("passed",-1); failed=row.get("failed",-1)
        if executed<minimum: failures.append(name+":minimum")
        if failed!=0 or passed!=executed or passed+failed!=executed: failures.append(name+":failed")
        if HASH64.fullmatch(str(row.get("result_manifest_sha256",""))) is None: failures.append(name+":result_hash")
    if report.get("severity_0_count")!=0 or report.get("severity_1_count")!=0: failures.append("severity_0_or_1")
    metrics=report.get("metrics",{})
    failures.extend(name for name,limit in LOWER_BOUNDS.items() if metrics.get(name,-1)<limit)
    failures.extend(name for name,limit in UPPER_BOUNDS.items() if metrics.get(name,limit+1)>limit)
    failures.extend(name for name in ZERO_FIELDS if metrics.get(name,-1)!=0)
    frozen=report.get("frozen_component_hashes",{})
    if not frozen or any(HASH64.fullmatch(str(value)) is None for value in frozen.values()): failures.append("frozen_component_hashes")
    if report.get("security_evidence_sha256")!=expected_security_hash: failures.append("security_evidence_sha256")
    return AcceptanceDecision(not failures,tuple(dict.fromkeys(failures)))
```

Schema requires the exact candidate, security hash, frozen component hashes, all 23 named suite rows, aggregate metrics, severity counts, evidence hashes, and start/end timestamps, recursively strict and without free text or any `passed`/`allowed` summary field outside the mathematically reconciled counts. Each suite result manifest is content-free, hashes the exact test IDs and outcomes, and is retained beside the report for audit; `run_matrix` refuses a non-`acceptance` signer, builds the report from runner-owned immutable result objects rather than caller JSON, calls `gate`, refuses a failed decision, and only then signs. `scripts/run_acceptance.py run` creates the envelope; its `verify` subcommand opens purpose `acceptance`, validates the strict schema, binds exact version/commit/security envelope hash, and reruns `gate`. Runner executes the complete master matrix; e2e files cover conversation, seven memories, conflict-to-Guest, S$100/S$150/Singapore/offline, zero false personalization, identity genuine-accept rate, language, memory retrieval, stop/privacy, wake, reconnect, duplicate effects, and private-data findings. Runbook gives exact prerequisites, commands, severity 0–3, correction/re-run, and content-free evidence rules.

- [ ] **Step 4: Run green**

Run: `uv run pytest tests/acceptance/test_acceptance_schema.py tests/acceptance/test_report_gate.py tests/e2e/test_full_conversation.py tests/e2e/test_memory_approval.py tests/e2e/test_identity_guest_fallback.py tests/e2e/test_budget_offline.py -q`

Expected: PASS with every suite count and aggregate threshold recomputed, zero severity 0/1, frozen hashes, and no official acceptance envelope signed before the implementation commit.

- [ ] **Step 5: Commit**

```bash
git status --short
git add evals/reports/acceptance-report-v1.schema.json evals/reports/phase1-baseline.md scripts/run_acceptance.py tests/acceptance/test_acceptance_schema.py tests/acceptance/test_report_gate.py tests/e2e/test_full_conversation.py tests/e2e/test_memory_approval.py tests/e2e/test_identity_guest_fallback.py tests/e2e/test_budget_offline.py docs/operations/acceptance-runbook.md
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(acceptance): freeze complete synthetic matrix"
```

### Task 7: Record and validate 500 turns and two elapsed eight-hour soaks

**Master package:** 33
**Depends on:** Task 6 implementation; the installed physical candidate is required only after Task 10 in the frozen-commit ceremony
**Estimated effort:** 2.5 person-days plus two elapsed eight-hour runs

**Files:**
- Create: `evals/reports/soak-evidence-v1.schema.json`
- Create: `evals/reports/soak-bundle-v1.schema.json`
- Create: `evals/reports/latency-deviation-v1.schema.json`
- Create: `scripts/run_soak.py`
- Create: `scripts/verify_soak_evidence.py`
- Create: `scripts/approve_latency_deviation.py`
- Consume: foundation `packages/contracts/src/tuntun_contracts/actions.py` (`LatencyDeviationActionDraft`, `ActionBinding`)
- Consume: foundation `apps/core/src/tuntun_core/services/policy/action_registry.py` (`release.latency.accept` high-risk owner-passkey entry)
- Test: `tests/acceptance/test_soak_evidence.py`
- Test: `tests/acceptance/test_soak_thresholds.py`
- Modify: `docs/operations/acceptance-runbook.md`

**Interfaces:** `run_soak(kind: Literal["mixed_500_turns","representative_noise_8h","thermal_memory_8h"], version: str, commit: str, limits: SoakLimits, signer: EvidenceSigner) -> SignedEvidence`; `verify_soaks(envelopes: tuple[SignedEvidence,...], schema: dict, registry: SignerRegistry, version: str, commit: str, now: datetime, deviations: Mapping[str,SignedEvidence], receipt_verifier: LatencyDeviationReceiptVerifier) -> SoakDecision`; `verify_soak_bundle(envelope: SignedEvidence, bundle_schema: dict, run_schema: dict, deviation_schema: dict, registry: SignerRegistry, version: str, commit: str, now: datetime, receipt_verifier: LatencyDeviationReceiptVerifier) -> SoakDecision`; `build_soak_bundle(verified_runs, verified_deviations, signer) -> SignedEvidence`. Runs use purpose `soak_run`, the self-contained bundle uses a distinct `soak_bundle` key, and a latency exception uses an owner-only `latency_deviation` key plus an exact action-bound passkey receipt.

- [ ] **Step 1: Write failing elapsed/provenance tests**

```python
# tests/acceptance/test_soak_evidence.py
from scripts.verify_soak_evidence import verify_soak_bundle,verify_soaks
def test_nominal_label_cannot_replace_elapsed_time(valid_soak_envelopes,resign_soak,soak_schema,signer_registry,now,no_latency_deviations,receipt_verifier):
    envelopes=list(valid_soak_envelopes); envelopes[1]=resign_soak(envelopes[1],monotonic_elapsed_seconds=28799)
    decision=verify_soaks(tuple(envelopes),soak_schema,signer_registry,"0.1.0-beta.1","a"*40,now,no_latency_deviations,receipt_verifier)
    assert not decision.allowed and "representative_noise_8h:elapsed" in decision.failures
def test_exactly_three_unique_kinds_ids_and_commits_are_bound(valid_soak_envelopes,resign_soak,soak_schema,signer_registry,now,no_latency_deviations,receipt_verifier):
    envelopes=list(valid_soak_envelopes); duplicate=envelopes[1].payload["run_id"]
    envelopes[2]=resign_soak(envelopes[2],commit="b"*40,run_id=duplicate)
    decision=verify_soaks(tuple(envelopes),soak_schema,signer_registry,"0.1.0-beta.1","a"*40,now,no_latency_deviations,receipt_verifier)
    assert {"thermal_memory_8h:commit","duplicate_run_id"}<=set(decision.failures)
    decision=verify_soaks(tuple(valid_soak_envelopes)+(valid_soak_envelopes[0],),soak_schema,signer_registry,"0.1.0-beta.1","a"*40,now,no_latency_deviations,receipt_verifier)
    assert "run_count" in decision.failures and "duplicate_kind" in decision.failures
def test_forged_verified_true_cannot_hide_payload_mutation(valid_soak_envelopes,soak_schema,signer_registry,now,no_latency_deviations,receipt_verifier):
    envelope=valid_soak_envelopes[0]
    forged=envelope.model_copy(update={"payload":{**envelope.payload,"completed_turns":1,"signature_verified":True}})
    decision=verify_soaks((forged,*valid_soak_envelopes[1:]),soak_schema,signer_registry,"0.1.0-beta.1","a"*40,now,no_latency_deviations,receipt_verifier)
    assert not decision.allowed and "envelope:0:invalid" in decision.failures
def test_signed_but_failing_thresholds_are_rejected(valid_soak_envelopes,resign_soak,soak_schema,signer_registry,now,no_latency_deviations,receipt_verifier):
    mutations=(
        (0,{"stop_privacy_p95_ms":251},"mixed_500_turns:stop_privacy_p95_ms"),
        (0,{"language_follow_rate_micros":949999},"mixed_500_turns:language_follow_rate"),
        (1,{"false_wake_count":2},"representative_noise_8h:false_wakes"),
        (2,{"unbounded_resource_growth":True},"thermal_memory_8h:resource_growth"),
        (2,{"duplicate_effect_count":1},"thermal_memory_8h:duplicate_effects"),
        (0,{"identity_false_personalization_count":1},"mixed_500_turns:false_personalization"),
    )
    for index,values,reason in mutations:
        rows=list(valid_soak_envelopes); rows[index]=resign_soak(rows[index],**values)
        decision=verify_soaks(tuple(rows),soak_schema,signer_registry,"0.1.0-beta.1","a"*40,now,no_latency_deviations,receipt_verifier)
        assert not decision.allowed and reason in decision.failures
def test_bundle_recomputes_complete_child_envelope_hashes(valid_soak_bundle,resign_bundle,bundle_schema,soak_schema,deviation_schema,signer_registry,now,receipt_verifier):
    forged=resign_bundle(valid_soak_bundle,run_sha256_by_kind={"mixed_500_turns":"0"*64,"representative_noise_8h":"1"*64,"thermal_memory_8h":"2"*64})
    decision=verify_soak_bundle(forged,bundle_schema,soak_schema,deviation_schema,signer_registry,"0.1.0-beta.1","a"*40,now,receipt_verifier)
    assert not decision.allowed and "bundle_child_hashes" in decision.failures
def test_latency_boolean_cannot_replace_owner_signed_deviation(valid_soak_envelopes,resign_soak,soak_schema,signer_registry,now,no_latency_deviations,receipt_verifier):
    rows=list(valid_soak_envelopes); rows[0]=resign_soak(rows[0],first_audio_p95_ms=4001)
    decision=verify_soaks(tuple(rows),soak_schema,signer_registry,"0.1.0-beta.1","a"*40,now,no_latency_deviations,receipt_verifier)
    assert not decision.allowed and "mixed_500_turns:latency_deviation" in decision.failures
def test_latency_receipt_cannot_be_reused_after_notes_or_expiry_change(valid_latency_case,resign_deviation,one_minute_later_iso,soak_schema,deviation_schema,signer_registry,now,receipt_verifier):
    runs,deviation=valid_latency_case; run_id=runs[0].payload["run_id"]
    other_digest=("f"*64 if deviation.payload["release_notes_sha256"]!="f"*64 else "e"*64)
    for mutation in ({"release_notes_sha256":other_digest},{"expires_at":one_minute_later_iso(deviation.payload["expires_at"])}):
        forged=resign_deviation(deviation,**mutation)
        decision=verify_soaks(runs,soak_schema,signer_registry,"0.1.0-beta.1","a"*40,now,{run_id:forged},receipt_verifier,deviation_schema)
        assert not decision.allowed and "mixed_500_turns:latency_deviation" in decision.failures
def test_latency_release_notes_digest_must_be_lowercase_hex(valid_latency_case,resign_deviation,soak_schema,deviation_schema,signer_registry,now,receipt_verifier):
    runs,deviation=valid_latency_case; run_id=runs[0].payload["run_id"]
    forged=resign_deviation(deviation,release_notes_sha256="A"*64)
    decision=verify_soaks(runs,soak_schema,signer_registry,"0.1.0-beta.1","a"*40,now,{run_id:forged},receipt_verifier,deviation_schema)
    assert not decision.allowed and "mixed_500_turns:latency_deviation" in decision.failures
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/acceptance/test_soak_evidence.py tests/acceptance/test_soak_thresholds.py tests/unit/policy/test_risk_matrix.py tests/contract/test_contract_models.py -q`

Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.verify_soak_evidence'`.

- [ ] **Step 3: Implement measured verification**

```python
# scripts/verify_soak_evidence.py
from dataclasses import dataclass
from datetime import datetime
from jsonschema import ValidationError
import re
from scripts.evidence import SignedEvidence,open_signed_evidence,signed_envelope_sha256
from typing import Protocol
from uuid import UUID
from tuntun_contracts.actions import ActionBinding,LatencyDeviationActionDraft
from tuntun_contracts.base import Commitment
from tuntun_contracts.policy import AssuranceLevel,AuthContext
KINDS=("mixed_500_turns","representative_noise_8h","thermal_memory_8h")
class LatencyDeviationReceiptVerifier(Protocol):
    def commitment(self,purpose:str,parameters:dict)->Commitment: raise NotImplementedError
    def verify_owner(self,receipt_id:UUID,expected_binding:ActionBinding,approved_at:datetime)->AuthContext: raise NotImplementedError
@dataclass(frozen=True,slots=True)
class SoakDecision: allowed:bool; failures:tuple[str,...]
def reconstruct_latency_binding(item,receipt_verifier):
    raw=item["auth_binding"]
    parameters={
        "candidate_version":item["candidate_version"],"candidate_commit":item["candidate_commit"],
        "run_id":item["run_id"],"metric":item["metric"],"observed_ms":item["observed_ms"],
        "limit_ms":item["limit_ms"],"release_notes_sha256":item["release_notes_sha256"],
        "expires_at":item["expires_at"],
    }
    draft=LatencyDeviationActionDraft.model_validate({
        "proposal_id":raw["proposal_id"],"schema_version":"1.0","resource_type":"soak_run",
        "resource_id":item["run_id"],"parameters_commitment":receipt_verifier.commitment("release.latency.accept",parameters),
        "uncertainty_micros":0,"idempotency_key":raw["idempotency_key"],"action_name":"release.latency.accept",
        **parameters,
    })
    expected=ActionBinding(
        household_id=UUID(raw["household_id"]),proposal_id=draft.proposal_id,turn_id=UUID(raw["turn_id"]),
        idempotency_key=draft.idempotency_key,action_name=draft.action_name,resource_type=draft.resource_type,
        resource_id=draft.resource_id,parameter_commitment=draft.parameters_commitment,
        policy_version=raw["policy_version"],session_id=UUID(raw["session_id"]),subject_id=UUID(raw["subject_id"]),
    )
    if raw!=expected.model_dump(mode="json"): raise ValueError("latency action binding mismatch")
    return expected
def verify_latency_deviation(envelope,schema,registry,version,commit,run,now,receipt_verifier):
    try: item=open_signed_evidence(envelope,schema,registry,"latency_deviation",now)
    except (ValueError,ValidationError): return False
    expected={"candidate_version":version,"candidate_commit":commit,"run_id":run["run_id"],"metric":"first_audio_p95_ms","observed_ms":run["first_audio_p95_ms"],"limit_ms":4000}
    if any(item.get(key)!=value for key,value in expected.items()): return False
    if re.fullmatch(r"[0-9a-f]{64}",item["release_notes_sha256"]) is None: return False
    try:
        expires_at=datetime.fromisoformat(item["expires_at"]); approved_at=datetime.fromisoformat(item["approved_at"])
        binding=reconstruct_latency_binding(item,receipt_verifier)
        context=receipt_verifier.verify_owner(UUID(item["auth_receipt_id"]),binding,approved_at)
    except (KeyError,TypeError,ValueError,PermissionError,RuntimeError): return False
    return approved_at<=envelope.protected.signed_at<=now<expires_at and context.assurance is AssuranceLevel.PASSKEY_VERIFIED and context.assurance_source=="passkey" and context.subject_id==binding.subject_id and context.binding==binding
def verify_soaks(envelopes,schema,registry,version,commit,now,deviations,receipt_verifier,deviation_schema=None):
    failures=[]; reports=[]
    if len(envelopes)!=3: failures.append("run_count")
    for index,envelope in enumerate(envelopes):
        try: reports.append(open_signed_evidence(envelope,schema,registry,"soak_run",now))
        except (ValueError,ValidationError): failures.append(f"envelope:{index}:invalid")
    by_kind={item["kind"]:item for item in reports}
    if len(by_kind)!=len(reports): failures.append("duplicate_kind")
    for kind in set(KINDS)-set(by_kind): failures.append("missing:"+kind)
    if set(by_kind)-set(KINDS): failures.append("unexpected_kind")
    if len({item["run_id"] for item in reports})!=len(reports): failures.append("duplicate_run_id")
    for kind,item in by_kind.items():
        if item["version"]!=version: failures.append(kind+":version")
        if item["commit"]!=commit: failures.append(kind+":commit")
        started=datetime.fromisoformat(item["started_at"]); ended=datetime.fromisoformat(item["ended_at"])
        elapsed=(ended-started).total_seconds()
        if started>=ended or ended>now: failures.append(kind+":time_window")
        if kind.endswith("_8h") and (elapsed<28800 or item["monotonic_elapsed_seconds"]<28800): failures.append(kind+":elapsed")
        if kind=="mixed_500_turns" and item["completed_turns"]<500: failures.append(kind+":turns")
        if item["sample_count"]<(480 if kind.endswith("_8h") else 500): failures.append(kind+":samples")
        if len(item["sample_chain_sha256"])!=64 or len(item["installed_artifact_sha256"])!=64: failures.append(kind+":provenance")
        if item["stop_privacy_p95_ms"]>250: failures.append(kind+":stop_privacy_p95_ms")
        if item["wake_ack_p95_ms"]>500: failures.append(kind+":wake_ack_p95_ms")
        if item["reconnect_p95_ms"]>30000: failures.append(kind+":reconnect_p95_ms")
        if item["language_follow_rate_micros"]<950000: failures.append(kind+":language_follow_rate")
        if item["identity_false_reject_rate_micros"]>50000: failures.append(kind+":identity_false_reject_rate")
        if item["identity_false_personalization_count"]!=0: failures.append(kind+":false_personalization")
        if kind=="representative_noise_8h" and item["false_wake_count"]>1: failures.append(kind+":false_wakes")
        if item["unbounded_resource_growth"] is not False: failures.append(kind+":resource_growth")
        if item["duplicate_effect_count"]!=0: failures.append(kind+":duplicate_effects")
        if item["private_data_finding_count"]!=0 or item["safety_failure_count"]!=0: failures.append(kind+":critical_finding")
        if item["first_audio_p95_ms"]>4000:
            deviation=deviations.get(item["run_id"])
            if deviation is None or deviation_schema is None or not verify_latency_deviation(deviation,deviation_schema,registry,version,commit,item,now,receipt_verifier): failures.append(kind+":latency_deviation")
    return SoakDecision(not failures,tuple(failures))
def verify_soak_bundle(envelope,bundle_schema,run_schema,deviation_schema,registry,version,commit,now,receipt_verifier):
    try: bundle=open_signed_evidence(envelope,bundle_schema,registry,"soak_bundle",now)
    except (ValueError,ValidationError): return SoakDecision(False,("bundle_envelope",))
    if bundle.get("candidate_version")!=version or bundle.get("candidate_commit")!=commit: return SoakDecision(False,("bundle_candidate",))
    try:
        runs=tuple(SignedEvidence.model_validate(value) for value in bundle["runs"])
        deviations=tuple(SignedEvidence.model_validate(value) for value in bundle["latency_deviations"])
    except Exception: return SoakDecision(False,("bundle_runs",))
    actual={run.payload.get("kind",""):signed_envelope_sha256(run) for run in runs}
    deviation_by_run={item.payload.get("run_id",""):item for item in deviations}
    deviation_hashes={run_id:signed_envelope_sha256(item) for run_id,item in deviation_by_run.items()}
    prefix=() if actual==bundle.get("run_sha256_by_kind") else ("bundle_child_hashes",)
    if len(deviation_by_run)!=len(deviations) or deviation_hashes!=bundle.get("latency_deviation_sha256_by_run"): prefix+=("bundle_deviation_hashes",)
    expected_deviations={run.payload.get("run_id") for run in runs if run.payload.get("first_audio_p95_ms",0)>4000}
    if set(deviation_by_run)!=expected_deviations: prefix+=("bundle_deviation_set",)
    decision=verify_soaks(runs,run_schema,registry,version,commit,now,deviation_by_run,receipt_verifier,deviation_schema)
    failures=prefix+decision.failures
    return SoakDecision(not failures,failures)
```

Runner records UTC/monotonic times, random run ID, version/commit, one sample/minute or turn, sample hash chain, all measured threshold fields, and a `soak_run` signature. Schemas are strict and content-free and explicitly forbid `accepted_latency_deviation`, `passed`, and `signature_verified`; `release_notes_sha256` is exactly lowercase hexadecimal. Thresholds: stop/privacy P95 `<=250ms`, wake ack `<=500ms`, reconnect `<=30s`, language `>=95%`, false rejects `<=5%`, zero false personalization, false wakes `<=1/eight hours`, zero safety/private-data findings, and no unbounded resources/duplicate effects. Instantiate the foundation-owned closed `LatencyDeviationActionDraft`—including its inherited expiry—and consume the foundation registry's high-risk owner-passkey rule; this task does not redefine that DTO, extend `ActionProposalDraft`, or add a parallel registry entry. `approve_latency_deviation.py` commits candidate version/commit, run UUID, metric, observed and allowed P95, release-notes digest, and expiry under purpose `release.latency.accept`, then stores the exact resulting `ActionBinding` and freshly consumed receipt in a separately signed `latency_deviation` envelope. Verification reconstructs that typed draft and complete binding, recomputes the purpose-separated commitment, compares the embedded binding, and reopens the receipt as a live, unreplayed, unrevoked owner-passkey authorization; therefore changing the notes digest or expiry while retaining a receipt fails. First-audio P50/P95 is published, and P95 over 4s blocks without that deviation. `build_soak_bundle` requires exactly three unique kinds/run IDs, calls `verify_soaks`, refuses failure, embeds exactly the required latency-deviation envelopes, stores full-envelope hashes for every run and deviation, and signs with a distinct `soak_bundle` key. Every later gate is self-contained: it calls `verify_soak_bundle`, recomputes all hashes, and rejects missing, unused, duplicated, or external-only deviations.

- [ ] **Step 4: Run the green semantic/CLI gate before committing**

Run: `uv run pytest tests/acceptance/test_soak_evidence.py tests/acceptance/test_soak_thresholds.py tests/unit/policy/test_risk_matrix.py tests/contract/test_contract_models.py -q`

Expected: PASS for exact run cardinality, purpose-separated signatures, full-envelope child hashes, every threshold, and owner-bound latency exceptions. The official 500-turn/two-eight-hour evidence is deliberately deferred until all release code is committed and the final candidate commit is frozen.

- [ ] **Step 5: Commit**

```bash
git status --short
git add evals/reports/soak-evidence-v1.schema.json evals/reports/soak-bundle-v1.schema.json evals/reports/latency-deviation-v1.schema.json scripts/run_soak.py scripts/verify_soak_evidence.py scripts/approve_latency_deviation.py tests/acceptance/test_soak_evidence.py tests/acceptance/test_soak_thresholds.py docs/operations/acceptance-runbook.md
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(acceptance): require measured release soaks"
```

### Task 8: Enforce the four-day trial and signed owner P1R0 decision

**Master package:** 33
**Depends on:** Task 7 implementation; its production soak bundle is supplied later by the frozen-commit ceremony
**Estimated effort:** 2.5 person-days plus four elapsed calendar days

**Files:**
- Create: `evals/reports/family-stage-v1.schema.json`
- Create: `evals/reports/family-review-v1.schema.json`
- Create: `evals/reports/family-trial-v1.schema.json`
- Create: `evals/reports/p1r0-approval-v1.schema.json`
- Create: `scripts/record_family_stage.py`
- Create: `scripts/approve_family_review.py`
- Create: `scripts/release_evidence_gate.py`
- Create: `scripts/approve_p1r0.py`
- Create: `scripts/verify_p1r0.py`
- Consume: foundation `packages/contracts/src/tuntun_contracts/actions.py` (`FamilyStageReviewActionDraft`, `ReleaseP1R0ActionDraft`, `ActionBinding`)
- Consume: foundation `apps/core/src/tuntun_core/services/policy/action_registry.py` (`release.family_stage.review` and `release.p1r0` high-risk owner-passkey entries)
- Test: `tests/acceptance/test_family_trial.py`
- Test: `tests/acceptance/test_release_evidence_gate.py`
- Test: `tests/acceptance/test_p1r0_approval.py`
- Create: `docs/operations/family-beta-checklist.md`
- Modify: `docs/operations/acceptance-runbook.md`

**Interfaces:** `verify_trial(envelope: SignedEvidence, schemas: Mapping[str,dict], registry: SignerRegistry, version: str, commit: str, now: datetime, review_receipt_verifier: FamilyReviewReceiptVerifier, consent_receipt_verifier: FamilyConsentReceiptVerifier) -> TrialDecision`; `verify_evidence_set(paths: Mapping[str,Path], schemas: Mapping[str,dict], registry: SignerRegistry, version: str, commit: str, now: datetime, dependencies: VerificationDependencies) -> VerifiedEvidenceSet`; `P1R0PasskeyReceiptVerifier.verify(receipt_id: UUID, expected_binding: ActionBinding, approved_at: datetime) -> Awaitable[AuthContext]`; `async verify_p1r0(..., receipt_verifier: P1R0PasskeyReceiptVerifier, binding_context: P1R0BindingContext) -> P1R0Decision`. The verifier reconstructs the exact release binding internally from verified version/commit/evidence hashes and trusted household owner/session/policy context; no caller-supplied `ActionBinding` is accepted. Stages, reviews, trial, and P1R0 use distinct purposes/keys; all payloads are strict and signed.

- [ ] **Step 1: Write failing order/binding tests**

```python
# tests/acceptance/test_family_trial.py
from scripts.record_family_stage import verify_trial
def test_family_stage_discriminator_is_not_a_profile_role(family_schemas):
    properties=family_schemas["family_stage"]["properties"]
    assert properties["stage_kind"]["enum"]==["owner","second_adult","child_trial"]
    assert "role" not in properties
def test_owner_stage_must_finish_48_hours(valid_trial_envelope,resign_trial_stage,family_schemas,signer_registry,now,review_receipt_verifier,consent_receipt_verifier):
    envelope=resign_trial_stage(valid_trial_envelope,0,monotonic_elapsed_seconds=172799)
    result=verify_trial(envelope,family_schemas,signer_registry,"0.1.0-beta.1","a"*40,now,review_receipt_verifier,consent_receipt_verifier)
    assert result.failures==("owner_stage:elapsed",)
def test_review_must_be_owner_signed_bound_to_exact_prior_stage(valid_trial_envelope,resign_family_review,family_schemas,signer_registry,now,review_receipt_verifier,consent_receipt_verifier):
    envelope=resign_family_review(valid_trial_envelope,0,reviewed_stage_sha256="0"*64)
    result=verify_trial(envelope,family_schemas,signer_registry,"0.1.0-beta.1","a"*40,now,review_receipt_verifier,consent_receipt_verifier)
    assert not result.allowed and "owner_review:stage_binding" in result.failures
def test_forged_stage_verified_true_is_rejected(valid_trial_envelope,resign_trial,family_schemas,signer_registry,now,review_receipt_verifier,consent_receipt_verifier):
    stage=valid_trial_envelope.payload["stages"][0]
    stage["payload"]={**stage["payload"],"monotonic_elapsed_seconds":1,"signature_verified":True}
    forged_outer=resign_trial(valid_trial_envelope,stages=valid_trial_envelope.payload["stages"])
    result=verify_trial(forged_outer,family_schemas,signer_registry,"0.1.0-beta.1","a"*40,now,review_receipt_verifier,consent_receipt_verifier)
    assert not result.allowed and "stage:0:invalid" in result.failures
def test_validly_signed_but_failed_stage_cannot_pass(valid_trial_envelope,resign_trial_stage,family_schemas,signer_registry,now,review_receipt_verifier,consent_receipt_verifier):
    mutations=(
        ({"severity_1_count":1},"owner_stage:severity"),
        ({"cross_profile_leak_count":1},"owner_stage:privacy_or_safety"),
        ({"unapproved_memory_write_count":1},"owner_stage:privacy_or_safety"),
    )
    for values,reason in mutations:
        envelope=resign_trial_stage(valid_trial_envelope,0,**values)
        result=verify_trial(envelope,family_schemas,signer_registry,"0.1.0-beta.1","a"*40,now,review_receipt_verifier,consent_receipt_verifier)
        assert not result.allowed and reason in result.failures
def test_child_requires_exact_live_guardian_consent(valid_child_trial,family_schemas,signer_registry,now,review_receipt_verifier,rejecting_consent_receipt_verifier):
    result=verify_trial(valid_child_trial,family_schemas,signer_registry,"0.1.0-beta.1","a"*40,now,review_receipt_verifier,rejecting_consent_receipt_verifier)
    assert not result.allowed and "child_stage:guardian_consent" in result.failures
def test_child_stage_requires_one_hour_and_exact_provenance(valid_child_trial,resign_child_stage,family_schemas,signer_registry,now,review_receipt_verifier,consent_receipt_verifier):
    for mutation,reason in (
        ({"monotonic_elapsed_seconds":3599},"child_stage:elapsed"),
        ({"ended_at":"2026-08-27T10:59:59+00:00"},"child_stage:elapsed"),
        ({"sample_chain_sha256":"not-a-digest"},"child_stage:provenance"),
        ({"installed_artifact_sha256":"f"*63},"child_stage:provenance"),
    ):
        envelope=resign_child_stage(valid_child_trial,**mutation)
        result=verify_trial(envelope,family_schemas,signer_registry,"0.1.0-beta.1","a"*40,now,review_receipt_verifier,consent_receipt_verifier)
        assert not result.allowed and reason in result.failures
```

```python
# tests/acceptance/test_release_evidence_gate.py
import pytest
from scripts.release_evidence_gate import ReleaseEvidenceError,verify_evidence_set
@pytest.mark.parametrize("role,mutation",(
    ("security",{"scan_results.pip_audit.status":"fail"}),
    ("acceptance",{"metrics.memory_recall_at_6_micros":899999}),
    ("soak_bundle",{"runs.0.payload.stop_privacy_p95_ms":251}),
    ("family_trial",{"stages.0.payload.cross_profile_leak_count":1}),
))
def test_every_validly_resigned_but_semantically_failing_role_blocks(role,mutation,release_evidence_fixture,resign_role):
    paths,schemas,registry,dependencies=release_evidence_fixture
    resign_role(paths,role,mutation)
    with pytest.raises(ReleaseEvidenceError,match=role):
        verify_evidence_set(paths,schemas,registry,"0.1.0-beta.1","a"*40,dependencies.now,dependencies)
```

```python
# tests/acceptance/test_p1r0_approval.py
import pytest
from scripts.verify_p1r0 import verify_p1r0
@pytest.mark.asyncio
async def test_forged_signature_true_and_expired_receipt_are_rejected(valid_p1r0_envelope,p1r0_schema,signer_registry,expired_receipt_verifier,p1r0_binding_context):
    forged=valid_p1r0_envelope.model_copy(update={"payload":{**valid_p1r0_envelope.payload,"signature_verified":True}})
    hashes={"acceptance_report_sha256":"d"*64,"security_evidence_sha256":"e"*64,"soak_evidence_sha256":"f"*64,"family_trial_sha256":"1"*64}
    result=await verify_p1r0(forged,p1r0_schema,signer_registry,hashes,"0.1.0-beta.1","a"*40,valid_p1r0_envelope.protected.signed_at,expired_receipt_verifier,p1r0_binding_context)
    assert not result.allowed and "approval_envelope" in result.failures
    result=await verify_p1r0(valid_p1r0_envelope,p1r0_schema,signer_registry,hashes,"0.1.0-beta.1","a"*40,valid_p1r0_envelope.protected.signed_at,expired_receipt_verifier,p1r0_binding_context)
    assert not result.allowed and "passkey_receipt" in result.failures

@pytest.mark.asyncio
async def test_permission_error_and_wrong_returned_binding_fail_closed(valid_p1r0_envelope,p1r0_schema,signer_registry,permission_denied_receipt_verifier,wrong_binding_receipt_verifier,p1r0_binding_context):
    hashes={"acceptance_report_sha256":"d"*64,"security_evidence_sha256":"e"*64,"soak_evidence_sha256":"f"*64,"family_trial_sha256":"1"*64}
    now=valid_p1r0_envelope.protected.signed_at
    denied=await verify_p1r0(valid_p1r0_envelope,p1r0_schema,signer_registry,hashes,"0.1.0-beta.1","a"*40,now,permission_denied_receipt_verifier,p1r0_binding_context)
    transplanted=await verify_p1r0(valid_p1r0_envelope,p1r0_schema,signer_registry,hashes,"0.1.0-beta.1","a"*40,now,wrong_binding_receipt_verifier,p1r0_binding_context)
    assert denied.failures == ("passkey_receipt",)
    assert transplanted.failures == ("passkey_receipt",)

@pytest.mark.asyncio
async def test_auth_binding_for_another_release_key_is_rejected_even_with_valid_owner_receipt(valid_p1r0_envelope,resign_p1r0_with_other_release_binding,p1r0_schema,signer_registry,valid_receipt_verifier,p1r0_binding_context):
    hashes={"acceptance_report_sha256":"d"*64,"security_evidence_sha256":"e"*64,"soak_evidence_sha256":"f"*64,"family_trial_sha256":"1"*64}
    substituted=resign_p1r0_with_other_release_binding(valid_p1r0_envelope,other_commit="b"*40)
    result=await verify_p1r0(substituted,p1r0_schema,signer_registry,hashes,"0.1.0-beta.1","a"*40,substituted.protected.signed_at,valid_receipt_verifier,p1r0_binding_context)
    assert not result.allowed and "auth_binding" in result.failures
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/acceptance/test_family_trial.py tests/acceptance/test_p1r0_approval.py -q`

Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.record_family_stage'`.

- [ ] **Step 3: Implement ordered trial and approval**

```python
# scripts/record_family_stage.py
from dataclasses import dataclass
from datetime import datetime
from jsonschema import ValidationError as JSONSchemaError
from pydantic import ValidationError as PydanticError
import re
from scripts.evidence import SignedEvidence,open_signed_evidence,signed_envelope_sha256
from typing import Protocol
from uuid import NAMESPACE_URL,UUID,uuid5
from tuntun_contracts.actions import ActionBinding,FamilyStageReviewActionDraft
from tuntun_contracts.base import Commitment
from tuntun_contracts.policy import AssuranceLevel,AuthContext
class FamilyReviewReceiptVerifier(Protocol):
    def commitment(self,purpose:str,parameters:dict)->Commitment: raise NotImplementedError
    def verify_owner(self,receipt_id:UUID,expected_binding:ActionBinding,approved_at:datetime)->AuthContext: raise NotImplementedError
class FamilyConsentReceiptVerifier(Protocol):
    def verify(self,receipt_id,child_subject_id,guardian_subject_id,purpose,at)->None: raise NotImplementedError
@dataclass(frozen=True,slots=True)
class TrialDecision: allowed:bool; failures:tuple[str,...]
def reconstruct_review_binding(review,expected_stage_sha256,receipt_verifier):
    if review["reviewed_stage_sha256"]!=expected_stage_sha256: raise ValueError("reviewed stage mismatch")
    raw=review["auth_binding"]
    parameters={
        "candidate_version":review["candidate_version"],"candidate_commit":review["candidate_commit"],
        "reviewed_stage_sha256":expected_stage_sha256,"decision":review["decision"],"expires_at":review["expires_at"],
    }
    resource_id=uuid5(NAMESPACE_URL,"tuntun:family-stage:"+expected_stage_sha256)
    draft=FamilyStageReviewActionDraft.model_validate({
        "proposal_id":raw["proposal_id"],"schema_version":"1.0","resource_type":"family_stage",
        "resource_id":resource_id,"parameters_commitment":receipt_verifier.commitment("release.family_stage.review",parameters),
        "uncertainty_micros":0,"idempotency_key":raw["idempotency_key"],"action_name":"release.family_stage.review",
        **parameters,
    })
    expected=ActionBinding(
        household_id=UUID(raw["household_id"]),proposal_id=draft.proposal_id,turn_id=UUID(raw["turn_id"]),
        idempotency_key=draft.idempotency_key,action_name=draft.action_name,resource_type=draft.resource_type,
        resource_id=draft.resource_id,parameter_commitment=draft.parameters_commitment,
        policy_version=raw["policy_version"],session_id=UUID(raw["session_id"]),subject_id=UUID(raw["subject_id"]),
    )
    if raw!=expected.model_dump(mode="json"): raise ValueError("family review action binding mismatch")
    return expected
def verify_review_authorization(review,signed_review,expected_stage_sha256,now,receipt_verifier):
    approved_at=datetime.fromisoformat(review["approved_at"]); expires_at=datetime.fromisoformat(review["expires_at"])
    binding=reconstruct_review_binding(review,expected_stage_sha256,receipt_verifier)
    context=receipt_verifier.verify_owner(UUID(review["auth_receipt_id"]),binding,approved_at)
    if not approved_at<=signed_review.protected.signed_at<=now<expires_at: raise PermissionError("family review timing")
    if context.assurance is not AssuranceLevel.PASSKEY_VERIFIED or context.assurance_source!="passkey" or context.subject_id!=binding.subject_id or context.binding!=binding: raise PermissionError("family review owner passkey")
def verify_trial(envelope,schemas,registry,version,commit,now,review_receipt_verifier,consent_receipt_verifier):
    failures=[]
    try: report=open_signed_evidence(envelope,schemas["family_trial"],registry,"family_trial",now)
    except (ValueError,JSONSchemaError): return TrialDecision(False,("trial_envelope",))
    if report.get("candidate_version")!=version: failures.append("candidate_version")
    if report.get("candidate_commit")!=commit: failures.append("candidate_commit")
    stages=[]; signed_stages=[]
    for index,raw in enumerate(report.get("stages",[])):
        try:
            signed=SignedEvidence.model_validate(raw)
            stage=open_signed_evidence(signed,schemas["family_stage"],registry,"family_stage",now)
            signed_stages.append(signed); stages.append(stage)
        except (ValueError,JSONSchemaError,PydanticError): failures.append(f"stage:{index}:invalid")
    if [item.get("stage_kind") for item in stages]!=["owner","second_adult"]: failures.append("stage_order")
    else:
        for stage in stages:
            stage_kind=stage["stage_kind"]
            wall=(datetime.fromisoformat(stage["ended_at"])-datetime.fromisoformat(stage["started_at"])).total_seconds()
            if wall<172800 or stage["monotonic_elapsed_seconds"]<172800: failures.append(stage_kind+"_stage:elapsed")
            if len(stage["sample_chain_sha256"])!=64 or len(stage["installed_artifact_sha256"])!=64: failures.append(stage_kind+"_stage:provenance")
            if stage["candidate_version"]!=version or stage["candidate_commit"]!=commit: failures.append(stage_kind+"_stage:candidate")
            if stage["severity_0_count"]!=0 or stage["severity_1_count"]!=0: failures.append(stage_kind+"_stage:severity")
            if any(stage[name]!=0 for name in ("privacy_failure_count","stop_failure_count","cross_profile_leak_count","unapproved_memory_write_count","unsafe_action_count","private_data_finding_count")): failures.append(stage_kind+"_stage:privacy_or_safety")
        if datetime.fromisoformat(stages[1]["started_at"])<datetime.fromisoformat(stages[0]["ended_at"]): failures.append("stage_overlap")
        if stages[0]["writes_queued_at_start"] is not True or stages[0]["interaction_gated_identity_only"] is not True or stages[0]["unknown_candidate_storage_absent"] is not True: failures.append("owner_stage:safe_start")
    signed_reviews=[]; reviews=[]
    for index,raw in enumerate(report.get("reviews",[])):
        try:
            signed=SignedEvidence.model_validate(raw)
            review=open_signed_evidence(signed,schemas["family_review"],registry,"family_review",now)
            signed_reviews.append(signed); reviews.append(review)
        except (ValueError,JSONSchemaError,PydanticError): failures.append(f"review:{index}:invalid")
    expected_review_count=2 if report.get("children_enrolled") else 1
    if len(reviews)!=expected_review_count: failures.append("review_count")
    if len(stages)==2 and reviews:
        if reviews[0].get("reviewed_stage_sha256")!=signed_envelope_sha256(signed_stages[0]): failures.append("owner_review:stage_binding")
        if reviews[0].get("decision")!="proceed" or reviews[0].get("candidate_version")!=version or reviews[0].get("candidate_commit")!=commit: failures.append("owner_review:decision")
        try: verify_review_authorization(reviews[0],signed_reviews[0],signed_envelope_sha256(signed_stages[0]),now,review_receipt_verifier)
        except (KeyError,TypeError,ValueError,PermissionError,RuntimeError): failures.append("owner_review:auth_receipt")
        if stages[1].get("prior_review_sha256")!=signed_envelope_sha256(signed_reviews[0]): failures.append("second_adult_stage:prior_review")
    if report.get("children_enrolled"):
        try:
            child_signed=SignedEvidence.model_validate(report["child_stage"])
            child=open_signed_evidence(child_signed,schemas["family_stage"],registry,"family_stage",now)
        except (KeyError,ValueError,JSONSchemaError,PydanticError): failures.append("child_stage:invalid")
        else:
            if child.get("stage_kind")!="child_trial" or child.get("candidate_version")!=version or child.get("candidate_commit")!=commit: failures.append("child_stage:candidate")
            try:
                child_wall=(datetime.fromisoformat(child["ended_at"])-datetime.fromisoformat(child["started_at"])).total_seconds()
                if child_wall<3600 or child["monotonic_elapsed_seconds"]<3600: failures.append("child_stage:elapsed")
            except (KeyError,TypeError,ValueError): failures.append("child_stage:elapsed")
            if re.fullmatch(r"[0-9a-f]{64}",child.get("sample_chain_sha256", "")) is None or re.fullmatch(r"[0-9a-f]{64}",child.get("installed_artifact_sha256", "")) is None: failures.append("child_stage:provenance")
            if len(stages)!=2 or len(reviews)!=2: failures.append("child_stage:prior_review")
            else:
                if reviews[1].get("reviewed_stage_sha256")!=signed_envelope_sha256(signed_stages[1]) or reviews[1].get("decision")!="proceed" or reviews[1].get("candidate_version")!=version or reviews[1].get("candidate_commit")!=commit or child.get("prior_review_sha256")!=signed_envelope_sha256(signed_reviews[1]): failures.append("child_stage:prior_review")
                if datetime.fromisoformat(child["started_at"])<datetime.fromisoformat(stages[1]["ended_at"]): failures.append("child_stage:order")
                try: verify_review_authorization(reviews[1],signed_reviews[1],signed_envelope_sha256(signed_stages[1]),now,review_receipt_verifier)
                except (KeyError,TypeError,ValueError,PermissionError,RuntimeError): failures.append("child_stage:review_auth")
            children=child.get("children",())
            if not children or len({item.get("child_subject_id") for item in children})!=len(children): failures.append("child_stage:guardian_consent")
            for item in children:
                try: consent_receipt_verifier.verify(item["guardian_consent_receipt_id"],item["child_subject_id"],item["guardian_subject_id"],"private_beta_child_trial",datetime.fromisoformat(child["started_at"]))
                except (KeyError,ValueError,PermissionError): failures.append("child_stage:guardian_consent")
            if any(child.get(name)!=0 for name in ("severity_0_count","severity_1_count","privacy_failure_count","stop_failure_count","cross_profile_leak_count","unapproved_memory_write_count","unsafe_action_count","private_data_finding_count")): failures.append("child_stage:privacy_or_safety")
    return TrialDecision(not failures,tuple(failures))
```

All three family schemas require every metric above with integer bounds, forbid unknown fields recursively, and prohibit transcript/free-text content and embedded verification booleans. `family-stage-v1` uses the required closed evidence discriminator `stage_kind: owner|second_adult|child_trial` and forbids a `role` field, so rollout audience/stage labels cannot be mistaken for canonical profile roles. Instantiate the foundation-owned closed `FamilyStageReviewActionDraft`—including its inherited expiry—and consume the foundation registry's high-risk owner-passkey rule; this task does not redefine that DTO, extend `ActionProposalDraft`, or add a parallel registry entry. `approve_family_review.py` reopens the exact prior stage, constructs that typed action over candidate version/commit, the complete prior-stage hash, proceed/stop decision, and expiry, obtains the fresh exact owner-passkey receipt, and signs a `family_review` envelope containing the binding and `decision="proceed"`. The verifier reconstructs and compares that foundation `ActionBinding` before reopening the receipt. The second-adult stage binds the complete owner-review envelope hash; a child-trial stage binds a second signed adult-review envelope and a live guardian consent receipt exactly scoped to child subject, guardian, `private_beta_child_trial`, policy version, and stage start. `record_family_stage assemble` calls `verify_trial`; it cannot sign an aggregate around a failed stage, unauthenticated review, or unverified consent ID.

```python
# scripts/release_evidence_gate.py
from dataclasses import dataclass
from datetime import datetime
from typing import Mapping
from scripts.evidence import SignedEvidence,open_signed_evidence,signed_envelope_sha256
from scripts.run_acceptance import gate as gate_acceptance
from scripts.verify_soak_evidence import verify_soak_bundle
from scripts.record_family_stage import verify_trial
class ReleaseEvidenceError(ValueError): pass
@dataclass(frozen=True,slots=True)
class VerificationDependencies:
    now:datetime; latency_receipt_verifier:object
    family_review_receipt_verifier:object; family_consent_receipt_verifier:object
@dataclass(frozen=True,slots=True)
class VerifiedEvidenceSet:
    version:str; commit:str; evidence_hashes:dict[str,str]; security:dict; acceptance:dict
    artifact_inventory:dict[str,dict]; frozen_component_hashes:dict[str,str]
def verify_evidence_set(paths,schemas,registry,version,commit,now,dependencies):
    if set(paths)!={"security","acceptance","soak_bundle","family_trial"}: raise ReleaseEvidenceError("evidence path roles")
    envelopes={name:SignedEvidence.model_validate_json(path.read_bytes()) for name,path in paths.items()}
    try: security=open_signed_evidence(envelopes["security"],schemas["security"],registry,"security",now)
    except Exception as error: raise ReleaseEvidenceError("security envelope") from error
    if security["candidate_version"]!=version or security["commit"]!=commit or security["history_scan"]!={"scope":"all_reachable_history","clean":True}: raise ReleaseEvidenceError("security candidate/history")
    if any(value["status"]!="pass" for value in security["scan_results"].values()) or security["reproducibility"]["build_count"]!=2 or security["reproducibility"]["identical"] is not True: raise ReleaseEvidenceError("security semantic gate")
    security_hash=signed_envelope_sha256(envelopes["security"])
    try: acceptance=open_signed_evidence(envelopes["acceptance"],schemas["acceptance"],registry,"acceptance",now)
    except Exception as error: raise ReleaseEvidenceError("acceptance envelope") from error
    decision=gate_acceptance(acceptance,version,commit,security_hash)
    if not decision.allowed: raise ReleaseEvidenceError("acceptance semantic gate: "+",".join(decision.failures))
    soak=verify_soak_bundle(envelopes["soak_bundle"],schemas["soak_bundle"],schemas["soak_run"],schemas["latency_deviation"],registry,version,commit,now,dependencies.latency_receipt_verifier)
    if not soak.allowed: raise ReleaseEvidenceError("soak_bundle semantic gate: "+",".join(soak.failures))
    trial=verify_trial(envelopes["family_trial"],schemas,registry,version,commit,now,dependencies.family_review_receipt_verifier,dependencies.family_consent_receipt_verifier)
    if not trial.allowed: raise ReleaseEvidenceError("family_trial semantic gate: "+",".join(trial.failures))
    hashes={"security_evidence_sha256":security_hash,"acceptance_report_sha256":signed_envelope_sha256(envelopes["acceptance"]),"soak_evidence_sha256":signed_envelope_sha256(envelopes["soak_bundle"]),"family_trial_sha256":signed_envelope_sha256(envelopes["family_trial"])}
    inventory={item["role"]:item for item in security["artifacts"]}
    if len(inventory)!=len(security["artifacts"]): raise ReleaseEvidenceError("security duplicate artifact role")
    if inventory.get("model_manifest",{}).get("sha256")!=security["model_manifest_sha256"]: raise ReleaseEvidenceError("security model-manifest binding")
    frozen=acceptance["frozen_component_hashes"]
    if any(role not in inventory or inventory[role]["sha256"]!=digest for role,digest in frozen.items()): raise ReleaseEvidenceError("acceptance frozen components")
    return VerifiedEvidenceSet(version,commit,hashes,security,acceptance,inventory,frozen)
```

```python
# scripts/verify_p1r0.py
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from jsonschema import ValidationError
import re
from typing import Protocol
from uuid import NAMESPACE_URL,UUID,uuid5
from scripts.evidence import canonical,open_signed_evidence
from tuntun_contracts.actions import ActionBinding
from tuntun_contracts.base import Commitment
from tuntun_contracts.policy import AssuranceLevel,AuthContext
class P1R0PasskeyReceiptVerifier(Protocol):
    def commitment(self,purpose:str,parameters:dict)->Commitment: raise NotImplementedError
    async def verify(self,receipt_id:UUID,expected_binding:ActionBinding,approved_at:datetime)->AuthContext: raise NotImplementedError
@dataclass(frozen=True,slots=True)
class P1R0BindingContext:
    household_id:UUID; policy_version:str; owner_session_id:UUID; owner_subject_id:UUID
@dataclass(frozen=True,slots=True)
class P1R0Decision:
    allowed:bool; failures:tuple[str,...]; candidate_version:str|None=None; candidate_commit:str|None=None; evidence_hashes:dict[str,str]|None=None
def build_p1r0_binding(version,commit,evidence_hashes,context,commitment_service):
    release_key={"version":version,"commit":commit,"decision":"approve","evidence_hashes":evidence_hashes}
    release_key_hash=sha256(canonical(release_key)).hexdigest()
    def stable(kind): return uuid5(NAMESPACE_URL,"tuntun:release:p1r0:"+kind+":"+release_key_hash)
    return ActionBinding(
        household_id=context.household_id,proposal_id=stable("proposal"),turn_id=stable("turn"),
        idempotency_key=stable("idempotency"),action_name="release.p1r0",
        resource_type="release_candidate",resource_id=stable("resource"),
        parameter_commitment=commitment_service.commitment("release.p1r0",release_key),
        policy_version=context.policy_version,session_id=context.owner_session_id,subject_id=context.owner_subject_id,
    )
async def verify_p1r0(envelope,schema,registry,evidence_hashes,version,commit,now,receipt_verifier,binding_context):
    required_hashes={"acceptance_report_sha256","security_evidence_sha256","soak_evidence_sha256","family_trial_sha256"}
    if set(evidence_hashes)!=required_hashes or any(re.fullmatch(r"[0-9a-f]{64}",value) is None for value in evidence_hashes.values()): return P1R0Decision(False,("evidence_hashes",))
    expected_binding=build_p1r0_binding(version,commit,evidence_hashes,binding_context,receipt_verifier)
    try: approval=open_signed_evidence(envelope,schema,registry,"p1r0_approval",now)
    except (ValueError,ValidationError): return P1R0Decision(False,("approval_envelope",))
    expected={"schema_version":"tuntun.p1r0-approval.v1","decision":"approve","candidate_version":version,"candidate_commit":commit,**evidence_hashes}
    failures=[key for key,value in expected.items() if approval.get(key)!=value]
    if approval.get("auth_binding")!=expected_binding.model_dump(mode="json"): failures.append("auth_binding")
    try:
        approved_at=datetime.fromisoformat(approval["approved_at"])
        if approved_at.tzinfo is None or approved_at>envelope.protected.signed_at or envelope.protected.signed_at>now: failures.append("approval_time")
    except (KeyError,TypeError,ValueError):
        failures.append("approval_time")
        approved_at=now
    try: context=await receipt_verifier.verify(UUID(approval["auth_receipt_id"]),expected_binding,approved_at)
    except (KeyError,TypeError,ValueError,PermissionError,RuntimeError): failures.append("passkey_receipt")
    else:
        if context.assurance is not AssuranceLevel.PASSKEY_VERIFIED or context.assurance_source!="passkey" or context.subject_id!=expected_binding.subject_id or context.binding!=expected_binding: failures.append("passkey_receipt")
    return P1R0Decision(not failures,tuple(failures),version,commit,evidence_hashes if not failures else None)
```

```python
# scripts/approve_p1r0.py
from scripts.verify_p1r0 import P1R0BindingContext,build_p1r0_binding
```

Before offering the P1R0 ceremony, `approve_p1r0.py` calls the concrete `verify_evidence_set` above, so valid signatures with failed scans, acceptance metrics, soak thresholds/hashes, family stages/reviews, or child consent cannot be approved. It hashes the four complete verified envelopes returned by that function, never decoded payloads. Consume the foundation-owned `ReleaseP1R0ActionDraft` and its existing `release.p1r0` high-risk `passkey_verified` registry entry; do not create another union member or registry row here. Build the deterministic UUID namespace from `release_key_hash=sha256(canonical(release_key)).hexdigest()` and use string names such as `"tuntun:release:p1r0:proposal:"+release_key_hash`; never concatenate the canonical bytes directly. Construct the exact foundation `ActionBinding`, obtain and atomically consume one fresh owner passkey `AuthGrant`, persist the authenticated receipt, and store only its receipt ID plus binding in the `p1r0_approval` envelope. `P1R0PasskeyReceiptVerifier` reopens the receipt signature/MAC, exact owner/binding, and proves the passkey grant was unexpired and unused at its recorded consumption time. All schemas forbid unknown fields, including `signature_verified`.

- [ ] **Step 4: Run the green family/evidence/P1R0 implementation gate**

Run: `uv run pytest tests/acceptance/test_family_trial.py tests/acceptance/test_release_evidence_gate.py tests/acceptance/test_p1r0_approval.py tests/unit/policy/test_risk_matrix.py tests/contract/test_contract_models.py -q`

Expected: PASS for ordered-stage/review/guardian-consent verification, every signed-but-semantically-failing regression, exact P1R0 binding, and expired/replayed receipt denial. The real four-day trial and P1R0 ceremony run only after Task 10 is committed and HEAD is frozen.

- [ ] **Step 5: Commit**

```bash
git status --short
git add evals/reports/family-stage-v1.schema.json evals/reports/family-review-v1.schema.json evals/reports/family-trial-v1.schema.json evals/reports/p1r0-approval-v1.schema.json scripts/record_family_stage.py scripts/approve_family_review.py scripts/release_evidence_gate.py scripts/approve_p1r0.py scripts/verify_p1r0.py tests/acceptance/test_family_trial.py tests/acceptance/test_release_evidence_gate.py tests/acceptance/test_p1r0_approval.py docs/operations/family-beta-checklist.md docs/operations/acceptance-runbook.md
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "test(acceptance): bind four-day trial to owner P1R0"
```

### Task 9: Assemble reproducible public artifacts and simulator-first docs

**Master package:** 34
**Depends on:** Task 8 implementation/tests and owner Apache-2.0 approval; production P1R0 is intentionally deferred until the post-Task-10 frozen-commit ceremony
**Estimated effort:** 3 person-days

**Files:**
- Modify: `README.md`
- Create: `SECURITY.md`
- Create: `PRIVACY.md`
- Create: `CONTRIBUTING.md`
- Create: `LICENSE`
- Create: `NOTICE`
- Create: `CHANGELOG.md`
- Create: `CODE_OF_CONDUCT.md`
- Create: `docs/architecture/overview.md`
- Create: `docs/operations/quickstart-simulator.md`
- Create: `docs/operations/provider-setup.md`
- Create: `docs/operations/model-installation.md`
- Create: `docs/operations/troubleshooting.md`
- Create: `release/schemas/release-candidate-v1.schema.json`
- Create: `scripts/assemble_release.py`
- Test: `tests/release/test_public_docs.py`
- Test: `tests/release/test_candidate_assembly.py`
- Test: `tests/release/test_clean_account_install.py`

**Interfaces:** `async assemble(inputs: ReleaseInputs, output: Path) -> ReleaseCandidate`; `digest(path: Path) -> str`; strict `tuntun.release-candidate.v1` with four evidence hashes plus the exact contained P1R0 envelope hash; sorted `SHA256SUMS`, exact unique artifact roles/paths, signed build-artifact binding, and no publication.

- [ ] **Step 1: Write failing docs/candidate tests**

```python
# tests/release/test_public_docs.py
from pathlib import Path
def test_privacy_limits_and_simulator_are_explicit():
    privacy=Path("PRIVACY.md").read_text().lower(); readme=Path("README.md").read_text().lower()
    assert "software privacy is not a physical microphone disconnect" in privacy
    assert "store=false is not contractual zero data retention" in privacy
    assert "biometrics provide personalization evidence, not sensitive authorization" in privacy
    assert "qwen is disabled by default" in privacy
    assert "make bootstrap" in readme and "make check" in readme and "simulator" in readme
```

```python
# tests/release/test_candidate_assembly.py
import pytest
from scripts.assemble_release import REQUIRED_ROLES,assemble,digest
@pytest.mark.asyncio
async def test_candidate_is_complete_clean_and_bound(release_inputs,tmp_path):
    candidate=await assemble(release_inputs,tmp_path/"candidate")
    assert {item.role for item in candidate.artifacts}==REQUIRED_ROLES
    assert candidate.version=="0.1.0-beta.1" and candidate.commit==release_inputs.commit
    assert candidate.schema_version=="tuntun.release-candidate.v1" and set(candidate.evidence_hashes)=={"acceptance_report_sha256","security_evidence_sha256","soak_evidence_sha256","family_trial_sha256"}
    assert candidate.p1r0_approval_sha256==digest(release_inputs.p1r0_path)

@pytest.mark.asyncio
async def test_build_role_must_equal_signed_security_inventory(release_inputs,tmp_path):
    release_inputs.role_paths["python_wheels"].write_bytes(b"different but self-consistent")
    with pytest.raises(RuntimeError,match="signed artifact mismatch"):
        await assemble(release_inputs,tmp_path/"candidate")
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/release/test_public_docs.py tests/release/test_candidate_assembly.py tests/release/test_clean_account_install.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'scripts.assemble_release'`.

- [ ] **Step 3: Implement candidate assembly/docs**

```python
# scripts/assemble_release.py
import hashlib,json,shutil
from dataclasses import asdict,dataclass
from datetime import datetime
from pathlib import Path
from typing import Mapping
from scripts.evidence import SignedEvidence
from scripts.release_evidence_gate import VerificationDependencies,verify_evidence_set
from scripts.verify_p1r0 import P1R0BindingContext,verify_p1r0
REQUIRED_ROLES={"source_archive","python_wheels","admin_assets","reachy_package","python_sbom","npm_sbom","license_inventory","model_manifest","security_evidence","acceptance_evidence","soak_evidence","family_trial_evidence","p1r0_approval","provenance"}
SIGNED_BUILD_ROLES={"source_archive","python_wheels","admin_assets","reachy_package","python_sbom","npm_sbom","license_inventory","model_manifest","provenance"}
EVIDENCE_ROLE_FIELDS={"security_evidence":"security_evidence_sha256","acceptance_evidence":"acceptance_report_sha256","soak_evidence":"soak_evidence_sha256","family_trial_evidence":"family_trial_sha256"}
@dataclass(frozen=True,slots=True)
class ReleaseInputs:
    version:str; commit:str; evidence_paths:Mapping[str,Path]; schemas:Mapping[str,dict]; registry:object
    now:datetime; dependencies:VerificationDependencies; p1r0_path:Path; p1r0_receipt_verifier:object
    p1r0_binding_context:P1R0BindingContext; role_paths:Mapping[str,Path]
@dataclass(frozen=True,slots=True)
class Artifact: role:str; path:str; sha256:str; size:int
@dataclass(frozen=True,slots=True)
class ReleaseCandidate:
    schema_version:str; version:str; commit:str; evidence_hashes:dict[str,str]
    p1r0_approval_sha256:str; artifacts:tuple[Artifact,...]
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
async def assemble(inputs,output):
    verified=verify_evidence_set(inputs.evidence_paths,inputs.schemas,inputs.registry,inputs.version,inputs.commit,inputs.now,inputs.dependencies)
    p1r0_envelope=SignedEvidence.model_validate_json(inputs.p1r0_path.read_bytes())
    p1r0=await verify_p1r0(p1r0_envelope,inputs.schemas["p1r0_approval"],inputs.registry,verified.evidence_hashes,inputs.version,inputs.commit,inputs.now,inputs.p1r0_receipt_verifier,inputs.p1r0_binding_context)
    if not p1r0.allowed: raise RuntimeError("P1R0 blocked")
    if set(inputs.role_paths)!=REQUIRED_ROLES: raise RuntimeError("artifact roles incomplete")
    if any(not source.is_file() or source.is_symlink() for source in inputs.role_paths.values()): raise RuntimeError("all artifact inputs must be regular non-symlink files")
    for role in SIGNED_BUILD_ROLES:
        source=inputs.role_paths[role]; expected=verified.artifact_inventory.get(role)
        if expected is None or digest(source)!=expected["sha256"] or source.stat().st_size!=expected["size"]: raise RuntimeError("signed artifact mismatch: "+role)
    for role,field in EVIDENCE_ROLE_FIELDS.items():
        if digest(inputs.role_paths[role])!=verified.evidence_hashes[field]: raise RuntimeError("evidence file is not canonical: "+role)
    if inputs.role_paths["p1r0_approval"].resolve()!=inputs.p1r0_path.resolve(): raise RuntimeError("P1R0 input differs from contained P1R0")
    output.mkdir(parents=True,exist_ok=False); artifacts=[]
    for role,source in sorted(inputs.role_paths.items()):
        if not source.is_file() or source.is_symlink(): raise RuntimeError("artifact must be a regular non-symlink file: "+role)
        target=output/"artifacts"/role/source.name; target.parent.mkdir(parents=True,exist_ok=False)
        shutil.copy2(source,target); artifacts.append(Artifact(role,str(target.relative_to(output)),digest(target),target.stat().st_size))
    (output/"SHA256SUMS").write_text("".join(f"{item.sha256}  {item.path}\n" for item in sorted(artifacts,key=lambda value:value.path)))
    p1r0_sha=digest(inputs.p1r0_path)
    result=ReleaseCandidate("tuntun.release-candidate.v1",inputs.version,inputs.commit,verified.evidence_hashes,p1r0_sha,tuple(artifacts))
    (output/"release-candidate.json").write_text(json.dumps(asdict(result),sort_keys=True,separators=(",",":"))+"\n")
    return result
```

All evidence writers emit RFC 8785 canonical envelope bytes without trailing whitespace, so the complete-envelope hashes returned by `verify_evidence_set` equal the copied evidence-file hashes. Assembly calls that concrete verifier and `verify_p1r0`; no input-owned verifier method or pass boolean exists. Each non-evidence artifact must byte-match the role/hash/size signed by security evidence, and every frozen acceptance component hash must already have matched that same inventory. Evidence artifacts must match the four verified complete-envelope hashes. The exact verified P1R0 file is copied into the candidate and its separate SHA-256 is fixed in the manifest. The schema recursively forbids extras, requires every role exactly once with unique relative path, fixes version/commit/evidence/P1R0/artifact hashes/sizes, and has no publication URL. README documents architecture/hardware/costs/simulator/commissioning/UI/limits. PRIVACY/SECURITY include tested claims and private reporting/no content logs. LICENSE is exact Apache-2.0 only after approval; NOTICE excludes weights and lists governed downloads. Clean-account tests use synthetic signed fixtures; production assembly occurs only in the frozen-commit ceremony.

- [ ] **Step 4: Run green**

Run: `uv run pytest tests/release/test_public_docs.py tests/release/test_candidate_assembly.py tests/release/test_clean_account_install.py -q && make bootstrap && make check`

Expected: PASS with fixture P1R0/evidence semantics, signed artifact binding, clean-account proof, simulator without secrets, and no production candidate or upload before the implementation commit.

- [ ] **Step 5: Commit**

```bash
git status --short
git add README.md SECURITY.md PRIVACY.md CONTRIBUTING.md LICENSE NOTICE CHANGELOG.md CODE_OF_CONDUCT.md docs/architecture/overview.md docs/operations/quickstart-simulator.md docs/operations/provider-setup.md docs/operations/model-installation.md docs/operations/troubleshooting.md release/schemas/release-candidate-v1.schema.json scripts/assemble_release.py tests/release/test_public_docs.py tests/release/test_candidate_assembly.py tests/release/test_clean_account_install.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "docs(release): assemble reproducible phase1 preview candidate"
```

### Task 10: Verify signed tag identity and authorize manual publication

**Master package:** 34
**Depends on:** Task 9 implementation/tests; accepted installation on the approved commit is a production-ceremony prerequisite, not a pre-commit implementation dependency
**Estimated effort:** 2 person-days

**Files:**
- Create: `release/authorized-signers-v1.json`
- Create: `release/schemas/authorized-signers-v1.schema.json`
- Create: `release/evidence-schema-paths-v1.json`
- Create: `release/schemas/evidence-schema-paths-v1.schema.json`
- Create: `release/schemas/publication-record-v1.schema.json`
- Create: `scripts/verify_tag.py`
- Create: `scripts/release_gate.py`
- Create: `docs/operations/publish-release.md`
- Modify: `.github/workflows/release.yml`
- Test: `tests/release/test_tag_verification.py`
- Test: `tests/release/test_release_gate.py`
- Test: `tests/release/test_no_auto_publication.py`

**Interfaces:** `verify_tag(tag: str, version: str, commit: str, registry: TagSignerRegistry, now: datetime, runner: GitRunner) -> TagVerification`; `async verify_candidate(manifest_path: Path, schema: dict, evidence_schemas: Mapping[str,dict], registry: SignerRegistry, now: datetime, dependencies: VerificationDependencies, p1r0_receipt_verifier: P1R0PasskeyReceiptVerifier, p1r0_binding_context: P1R0BindingContext) -> tuple[VerifiedCandidate,P1R0Decision]`; `decide(candidate: VerifiedCandidate, p1r0: P1R0Decision, tag: TagVerification, installed_commit: str) -> ReleaseDecision`. The CLI loads trusted owner/household/session/policy context—not a prebuilt binding—plus a strict explicit evidence-schema-path registry, verifies the candidate-contained P1R0, signs purpose `publication`, and never publishes.

- [ ] **Step 1: Write failing tag/gate/workflow tests**

```python
# tests/release/test_tag_verification.py
from dataclasses import dataclass
from scripts.verify_tag import verify_tag
@dataclass(frozen=True)
class Result: returncode:int; stdout:str=""; stderr:str=""
class FakeGit:
    def run(self,argv):
        if argv[:3]==("git","verify-tag","--raw"): return Result(0,stderr="[GNUPG:] VALIDSIG "+"B"*40+" 2026-08-27 0 4 0 1 10 00\n")
        if argv[:2]==("git","rev-parse"): return Result(0,stdout="b"*40+"\n")
        raise AssertionError(argv)
def test_signer_lifecycle_and_commit_must_match(tag_signer_registry,now):
    fake_git=FakeGit()
    result=verify_tag("v0.1.0-beta.1","0.1.0-beta.1","a"*40,tag_signer_registry,now,fake_git)
    assert not result.valid and set(result.failures)=={"signer_fingerprint","tag_commit"}
def test_revoked_or_expired_tag_signer_is_rejected(fake_git,revoked_tag_signer_registry,now):
    result=verify_tag("v0.1.0-beta.1","0.1.0-beta.1","b"*40,revoked_tag_signer_registry,now,fake_git)
    assert not result.valid and "signer_lifecycle" in result.failures
```

```python
# tests/release/test_no_auto_publication.py
from pathlib import Path
def test_workflow_cannot_publish():
    text=Path(".github/workflows/release.yml").read_text().lower(); assert "contents: read" in text
    for forbidden in ("contents: write","gh release create","git tag","npm publish","pages: write"): assert forbidden not in text
```

```python
# tests/release/test_release_gate.py
import json,pytest
from jsonschema import ValidationError
from types import SimpleNamespace
from scripts.release_gate import VerifiedCandidate,decide,load_evidence_schemas,verify_candidate
from scripts.verify_p1r0 import P1R0Decision
def test_p1r0_and_all_evidence_hashes_must_match_candidate():
    hashes={"acceptance_report_sha256":"a"*64,"security_evidence_sha256":"b"*64,"soak_evidence_sha256":"c"*64,"family_trial_sha256":"d"*64}
    candidate=VerifiedCandidate("0.1.0-beta.1","e"*40,"9"*64,hashes,"8"*64)
    p1r0=P1R0Decision(True,(),"0.1.0-beta.1","e"*40,{**hashes,"soak_evidence_sha256":"f"*64})
    result=decide(candidate,p1r0,SimpleNamespace(valid=True,commit="e"*40),"e"*40)
    assert not result.allowed and result.failures==("p1r0_binding",)
@pytest.mark.asyncio
async def test_forged_true_fields_and_rehashed_artifact_still_cannot_pass(candidate_tree,verification_args):
    manifest=json.loads(candidate_tree.manifest.read_text()); manifest["artifact_hashes_verified"]=True
    candidate_tree.manifest.write_text(json.dumps(manifest))
    with pytest.raises(ValidationError): await verify_candidate(candidate_tree.manifest,**verification_args)
    candidate_tree.restore_manifest(); candidate_tree.replace_artifact_and_rehash("python_wheels",b"mutated"); candidate_tree.rehash_manifest_and_sums()
    with pytest.raises(ValueError,match="signed artifact mismatch"): await verify_candidate(candidate_tree.manifest,**verification_args)
@pytest.mark.asyncio
async def test_validly_signed_but_failed_evidence_cannot_pass(candidate_tree,verification_args,resign_candidate_evidence):
    mutations=(
        ("acceptance_evidence",{"severity_1_count":1},"acceptance evidence gate failed"),
        ("soak_evidence",{"runs.0.payload.stop_privacy_p95_ms":251},"soak_bundle evidence gate failed"),
        ("family_trial_evidence",{"stages.0.payload.cross_profile_leak_count":1},"family_trial evidence gate failed"),
    )
    for role,values,reason in mutations:
        tree=candidate_tree.fresh_copy(); resign_candidate_evidence(tree,role,values); tree.rehash_manifest_and_sums()
        with pytest.raises(ValueError,match=reason): await verify_candidate(tree.manifest,**verification_args)
@pytest.mark.asyncio
async def test_external_or_different_p1r0_cannot_replace_contained_p1r0(candidate_tree,verification_args,other_valid_p1r0):
    candidate_tree.replace_contained_p1r0_and_rehash(other_valid_p1r0)
    with pytest.raises(ValueError,match="contained P1R0"):
        await verify_candidate(candidate_tree.manifest,**verification_args)
def test_schema_path_registry_rejects_escape_missing_role_and_hash_drift(repo_root,schema_paths_file,schema_paths_schema,mutate_schema_paths):
    for mutation in ("escape","missing_role","hash_drift"):
        path=mutate_schema_paths(schema_paths_file,mutation)
        with pytest.raises(ValueError): load_evidence_schemas(repo_root,path,schema_paths_schema)
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/release/test_tag_verification.py tests/release/test_release_gate.py tests/release/test_no_auto_publication.py -q`

Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.verify_tag'`.

- [ ] **Step 3: Implement tag and release verification**

```python
# scripts/verify_tag.py
import json,re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import jsonschema
@dataclass(frozen=True,slots=True)
class TagSignerRecord:
    fingerprint:str; algorithm:str; purpose:str; approved_at:datetime; not_before:datetime; not_after:datetime; revoked_at:datetime|None
class TagSignerRegistry:
    def __init__(self,by_fingerprint): self.by_fingerprint=by_fingerprint
    @classmethod
    def load(cls,schema_path:Path,registry_path:Path):
        schema=json.loads(schema_path.read_text()); raw=json.loads(registry_path.read_text())
        jsonschema.Draft202012Validator(schema,format_checker=jsonschema.FormatChecker()).validate(raw)
        rows={}
        for item in raw["signers"]:
            fingerprint=item["fingerprint"].upper()
            if fingerprint in rows: raise ValueError("duplicate tag signer fingerprint")
            row=TagSignerRecord(fingerprint,item["algorithm"],item["purpose"],datetime.fromisoformat(item["approved_at"]),datetime.fromisoformat(item["not_before"]),datetime.fromisoformat(item["not_after"]),None if item["revoked_at"] is None else datetime.fromisoformat(item["revoked_at"]))
            if row.not_before>=row.not_after: raise ValueError("invalid tag signer validity window")
            rows[fingerprint]=row
        return cls(rows)
@dataclass(frozen=True,slots=True)
class TagVerification: valid:bool; tag:str; commit:str; signer_fingerprint:str; failures:tuple[str,...]
def verify_tag(tag,version,commit,registry,now,runner):
    failures=[]
    verification=runner.run(("git","verify-tag","--raw",tag))
    valid=re.search(r"^\[GNUPG:\] VALIDSIG ([0-9A-Fa-f]{40,64}) ",verification.stderr,re.MULTILINE)
    if verification.returncode or valid is None: failures.append("cryptographic_signature")
    fingerprint="" if valid is None else valid.group(1).upper()
    actual_commit=runner.run(("git","rev-parse",f"{tag}^{{}}")).stdout.strip()
    if tag!="v"+version: failures.append("tag_name")
    record=registry.by_fingerprint.get(fingerprint)
    if record is None or record.algorithm!="OpenPGP" or record.purpose!="release_tag": failures.append("signer_fingerprint")
    elif record.revoked_at is not None or record.approved_at>now or not record.not_before<=now<=record.not_after: failures.append("signer_lifecycle")
    if actual_commit!=commit: failures.append("tag_commit")
    return TagVerification(not failures,tag,actual_commit,fingerprint,tuple(failures))
```

```python
# scripts/release_gate.py
import hashlib,json
from dataclasses import dataclass
from pathlib import Path
import jsonschema
from scripts.assemble_release import REQUIRED_ROLES,SIGNED_BUILD_ROLES
from scripts.evidence import SignedEvidence
from scripts.release_evidence_gate import verify_evidence_set
from scripts.verify_p1r0 import verify_p1r0
EVIDENCE_PATH_ROLES={"security":"security_evidence","acceptance":"acceptance_evidence","soak_bundle":"soak_evidence","family_trial":"family_trial_evidence"}
EVIDENCE_SCHEMA_ROLES={"security","acceptance","soak_run","soak_bundle","latency_deviation","family_stage","family_review","family_trial","p1r0_approval"}
def sha256(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def load_evidence_schemas(repo_root,paths_file,paths_schema):
    root=repo_root.resolve(); registry_schema=json.loads(paths_schema.read_text()); raw=json.loads(paths_file.read_text())
    jsonschema.Draft202012Validator(registry_schema,format_checker=jsonschema.FormatChecker()).validate(raw)
    if {item["role"] for item in raw["schemas"]}!=EVIDENCE_SCHEMA_ROLES or len(raw["schemas"])!=len(EVIDENCE_SCHEMA_ROLES): raise ValueError("evidence schema roles are not exact")
    result={}
    for item in raw["schemas"]:
        path=(root/item["path"]).resolve()
        if not path.is_relative_to(root) or sha256(path)!=item["sha256"]: raise ValueError("evidence schema path/hash invalid")
        schema=json.loads(path.read_text()); jsonschema.Draft202012Validator.check_schema(schema); result[item["role"]]=schema
    return result
@dataclass(frozen=True,slots=True)
class VerifiedCandidate: version:str; commit:str; manifest_sha256:str; evidence_hashes:dict[str,str]; p1r0_approval_sha256:str
async def verify_candidate(manifest_path,schema,evidence_schemas,registry,now,dependencies,p1r0_receipt_verifier,p1r0_binding_context):
    manifest=json.loads(manifest_path.read_text()); jsonschema.Draft202012Validator(schema,format_checker=jsonschema.FormatChecker()).validate(manifest)
    root=manifest_path.parent.resolve(); by_role={item["role"]:item for item in manifest["artifacts"]}
    if set(by_role)!=REQUIRED_ROLES or len(by_role)!=len(manifest["artifacts"]): raise ValueError("artifact roles are not exact and unique")
    if len({item["path"] for item in manifest["artifacts"]})!=len(manifest["artifacts"]): raise ValueError("artifact paths are not unique")
    for item in manifest["artifacts"]:
        path=(root/item["path"]).resolve()
        if not path.is_relative_to(root): raise ValueError("artifact path escapes candidate")
        if not path.is_file() or path.is_symlink(): raise ValueError("artifact is not a regular non-symlink file")
        if path.stat().st_size!=item["size"] or sha256(path)!=item["sha256"]: raise ValueError("artifact sha256 mismatch")
    expected_sums="".join(f'{item["sha256"]}  {item["path"]}\n' for item in sorted(manifest["artifacts"],key=lambda value:value["path"]))
    if (root/"SHA256SUMS").read_text()!=expected_sums: raise ValueError("SHA256SUMS mismatch")
    evidence_paths={name:(root/by_role[role]["path"]).resolve() for name,role in EVIDENCE_PATH_ROLES.items()}
    try: verified=verify_evidence_set(evidence_paths,evidence_schemas,registry,manifest["version"],manifest["commit"],now,dependencies)
    except ValueError as error: raise ValueError(str(error).replace("semantic gate","evidence gate failed")) from error
    if verified.evidence_hashes!=manifest["evidence_hashes"]: raise ValueError("evidence hash binding mismatch")
    for role in SIGNED_BUILD_ROLES:
        item=by_role[role]; signed=verified.artifact_inventory.get(role)
        if signed is None or item["sha256"]!=signed["sha256"] or item["size"]!=signed["size"]: raise ValueError("signed artifact mismatch: "+role)
    p1r0_item=by_role["p1r0_approval"]; p1r0_path=(root/p1r0_item["path"]).resolve()
    if sha256(p1r0_path)!=manifest["p1r0_approval_sha256"]: raise ValueError("contained P1R0 hash mismatch")
    p1r0_envelope=SignedEvidence.model_validate_json(p1r0_path.read_bytes())
    p1r0=await verify_p1r0(p1r0_envelope,evidence_schemas["p1r0_approval"],registry,verified.evidence_hashes,manifest["version"],manifest["commit"],now,p1r0_receipt_verifier,p1r0_binding_context)
    if not p1r0.allowed: raise ValueError("contained P1R0 verification failed: "+",".join(p1r0.failures))
    return VerifiedCandidate(manifest["version"],manifest["commit"],sha256(manifest_path),verified.evidence_hashes,manifest["p1r0_approval_sha256"]),p1r0
@dataclass(frozen=True,slots=True)
class ReleaseDecision: allowed:bool; failures:tuple[str,...]
def decide(candidate,p1r0,tag,installed_commit):
    failures=[]
    if candidate.version!="0.1.0-beta.1": failures.append("candidate_version")
    if not p1r0.allowed or p1r0.candidate_version!=candidate.version or p1r0.candidate_commit!=candidate.commit or p1r0.evidence_hashes!=candidate.evidence_hashes: failures.append("p1r0_binding")
    if not tag.valid or tag.commit!=candidate.commit: failures.append("signed_tag")
    if installed_commit!=candidate.commit: failures.append("accepted_install_commit")
    return ReleaseDecision(not failures,tuple(failures))
```

`release/authorized-signers-v1.json` is schema-validated and records exact tag fingerprints, fixed `algorithm="OpenPGP"`, purpose `release_tag`, approval/not-before/not-after, and nullable revocation; verification rejects absent, expired, future, wrong-algorithm/purpose, or revoked records. `release/evidence-schema-paths-v1.json` is separately schema-validated and names every Task 5–9 payload schema; the CLI requires both `--evidence-schema-paths` and `--evidence-schema-paths-schema`, resolves paths beneath the repository, and refuses missing/extra roles or schema hash drift. `verify_candidate` reruns the one shared verifier, checks every package role against the signed security inventory, validates the frozen acceptance components, reopens exact soak-bundle child hashes, verifies reviews/guardian consent, and verifies the P1R0 envelope physically contained in the candidate. No external P1R0 path is accepted. The CLI reconstructs the exact `release.p1r0` binding, confirms the installed commit, and signs `authorized_for_manual_publication` with the distinct `publication` evidence key; that strict payload contains version, commit, tag/fingerprint, candidate-manifest hash, contained-P1R0 hash, all four evidence hashes, installed commit, and authorization time. No network call occurs. Workflow remains manual build/attest/artifact only.

- [ ] **Step 4: Run the green pre-publication implementation gate**

Run: `uv run pytest tests/release/test_tag_verification.py tests/release/test_release_gate.py tests/release/test_no_auto_publication.py -q`

Expected: PASS for tag lifecycle, replace-and-rehash artifact attacks, schema registry, semantic evidence, exact contained P1R0, and no automatic publication. No real tag or publication record is created before Task 10 is committed.

- [ ] **Step 5: Commit exact paths before any production evidence ceremony**

```bash
git status --short
git add release/authorized-signers-v1.json release/schemas/authorized-signers-v1.schema.json release/evidence-schema-paths-v1.json release/schemas/evidence-schema-paths-v1.schema.json release/schemas/publication-record-v1.schema.json scripts/verify_tag.py scripts/release_gate.py .github/workflows/release.yml docs/operations/publish-release.md tests/release/test_tag_verification.py tests/release/test_release_gate.py tests/release/test_no_auto_publication.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "release: require verified owner-controlled publication"
```

## Frozen-Commit Evidence Ceremony and P1R1 Manual Publication Checkpoint

Tasks 5–10 commit implementation and synthetic fixtures only. After Task 10, freeze one clean commit and generate all official evidence below without changing tracked files. All outputs live under ignored `var/` or `dist/`; every writer emits canonical JSON bytes. If any source, policy, schema, test, documentation, or release script changes, commit it, remove any unpublished tag, discard the candidate/evidence for the old commit, and restart this entire ceremony. Old elapsed evidence may not be relabeled or merely re-signed for a new commit.

### Ceremony A: freeze and build the signed security artifact set

```bash
test -z "$(git status --porcelain)"
test -z "$(git tag --list v0.1.0-beta.1)"
make bootstrap
make check
make security-scan model-manifest-check sbom license-check listener-scan egress-scan fuzz
uv run python scripts/collect_release_evidence.py --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --artifact-output var/release/frozen-artifacts --role-paths-output var/release/role-paths.json --signer-service tuntun.release.security --output var/release/security-evidence.json
uv run python scripts/verify_release_evidence.py var/release/security-evidence.json --schema security/schemas/security-evidence-v1.schema.json --signer-registry security/evidence-signers-v1.json --signer-registry-schema security/schemas/evidence-signers-v1.schema.json --expected-purpose security --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)"
```

Expected: the worktree is clean, no beta tag exists, scans pass, two builds from the frozen commit are byte-identical, and the signed security inventory names every non-evidence candidate role/hash/size.

### Ceremony B: run and sign the semantic acceptance matrix

```bash
uv run python scripts/run_acceptance.py run --mode synthetic --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --security-evidence var/release/security-evidence.json --signer-service tuntun.release.acceptance --output var/acceptance/synthetic.json
uv run python scripts/run_acceptance.py verify var/acceptance/synthetic.json --schema evals/reports/acceptance-report-v1.schema.json --signer-registry security/evidence-signers-v1.json --signer-registry-schema security/schemas/evidence-signers-v1.schema.json --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --security-evidence var/release/security-evidence.json
uv run python scripts/verify_private_data.py var/acceptance/synthetic.json var/acceptance/result-manifests
```

Expected: all 23 suite counts reconcile, every numeric threshold passes, severity 0/1 and false personalization are zero, frozen component hashes match signed build roles, and no content is retained.

### Ceremony C: run 500 turns and the two non-compressible eight-hour soaks

```bash
uv run python scripts/run_soak.py --kind mixed_500_turns --turns 500 --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --signer-service tuntun.release.soak-run --output var/acceptance/soak-500.json
uv run python scripts/run_soak.py --kind representative_noise_8h --duration-seconds 28800 --sample-seconds 60 --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --signer-service tuntun.release.soak-run --output var/acceptance/soak-noise-8h.json
uv run python scripts/run_soak.py --kind thermal_memory_8h --duration-seconds 28800 --sample-seconds 60 --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --signer-service tuntun.release.soak-run --output var/acceptance/soak-thermal-8h.json
mkdir -p var/acceptance/latency-deviations
uv run python scripts/verify_soak_evidence.py bundle --run-schema evals/reports/soak-evidence-v1.schema.json --bundle-schema evals/reports/soak-bundle-v1.schema.json --latency-deviation-schema evals/reports/latency-deviation-v1.schema.json --signer-registry security/evidence-signers-v1.json --signer-registry-schema security/schemas/evidence-signers-v1.schema.json --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --latency-deviation-dir var/acceptance/latency-deviations --bundle-signer-service tuntun.release.soak-bundle --bundle-output var/acceptance/soak-bundle.json var/acceptance/soak-500.json var/acceptance/soak-noise-8h.json var/acceptance/soak-thermal-8h.json
```

Expected: exactly three unique run kinds/IDs pass, both eight-hour runs have wall and monotonic elapsed `>=28,800`, the mixed run has `>=500` turns, every threshold passes, and the bundle hashes the complete three child envelopes. If verification reports only `first_audio_p95_ms>4000`, run the exact owner ceremony below and repeat only the bundle command; no other failure is suppressible:

```bash
uv run python scripts/approve_latency_deviation.py --failed-verification var/acceptance/soak-verification.json --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --release-notes CHANGELOG.md --signer-service tuntun.release.latency-deviation --output-dir var/acceptance/latency-deviations
```

Expected: a fresh owner passkey authorizes only the exact reported run/metric/observed value/limit/release-note hash, with a bounded expiry; the re-run bundle gate verifies that receipt and signature.

### Ceremony D: run the ordered household trial, signed reviews, and child consent gate

```bash
uv run python scripts/record_family_stage.py run --stage-kind owner --duration-seconds 172800 --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --signer-service tuntun.release.family-stage --output var/acceptance/trial-owner.json
uv run python scripts/approve_family_review.py --stage var/acceptance/trial-owner.json --decision proceed --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --signer-service tuntun.release.family-review --output var/acceptance/trial-owner-review.json
uv run python scripts/record_family_stage.py run --stage-kind second_adult --duration-seconds 172800 --prior-review var/acceptance/trial-owner-review.json --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --signer-service tuntun.release.family-stage --output var/acceptance/trial-adult.json
uv run python scripts/approve_family_review.py --stage var/acceptance/trial-adult.json --decision proceed --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --signer-service tuntun.release.family-review --output var/acceptance/trial-adult-review.json
uv run tuntunctl consent export-release-trial-receipts --purpose private_beta_child_trial --output var/acceptance/child-trial-consents.json
uv run python scripts/record_family_stage.py run --stage-kind child_trial --duration-seconds 3600 --prior-review var/acceptance/trial-adult-review.json --guardian-consents var/acceptance/child-trial-consents.json --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --signer-service tuntun.release.family-stage --output var/acceptance/trial-child.json
uv run python scripts/record_family_stage.py assemble --owner var/acceptance/trial-owner.json --owner-review var/acceptance/trial-owner-review.json --adult var/acceptance/trial-adult.json --adult-review var/acceptance/trial-adult-review.json --child var/acceptance/trial-child.json --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --signer-service tuntun.release.family-trial --output var/acceptance/family-trial.json
uv run python scripts/record_family_stage.py verify var/acceptance/family-trial.json --evidence-schema-paths release/evidence-schema-paths-v1.json --evidence-schema-paths-schema release/schemas/evidence-schema-paths-v1.schema.json --signer-registry security/evidence-signers-v1.json --signer-registry-schema security/schemas/evidence-signers-v1.schema.json --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)"
```

Expected: owner and second-adult stages each have two ordered real days, each transition uses a separately signed owner review bound to the prior complete stage envelope, and the child stage begins later with cryptographically verified child/guardian/purpose-specific consent. Deployments with no enrolled children use `--children-not-enrolled` instead of the final three child commands; this household uses the child path above.

### Ceremony E: approve P1R0, assemble the exact contained-P1R0 candidate, install, tag, and gate

```bash
uv run python scripts/approve_p1r0.py --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --security var/release/security-evidence.json --acceptance var/acceptance/synthetic.json --soak-bundle var/acceptance/soak-bundle.json --trial var/acceptance/family-trial.json --evidence-schema-paths release/evidence-schema-paths-v1.json --evidence-schema-paths-schema release/schemas/evidence-schema-paths-v1.schema.json --signer-registry security/evidence-signers-v1.json --signer-registry-schema security/schemas/evidence-signers-v1.schema.json --signer-service tuntun.release.p1r0 --decision approve --output var/acceptance/p1r0-approval.json
uv run python scripts/verify_p1r0.py var/acceptance/p1r0-approval.json --schema evals/reports/p1r0-approval-v1.schema.json --signer-registry security/evidence-signers-v1.json --signer-registry-schema security/schemas/evidence-signers-v1.schema.json --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --security var/release/security-evidence.json --acceptance var/acceptance/synthetic.json --soak-bundle var/acceptance/soak-bundle.json --trial var/acceptance/family-trial.json
SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" uv run python scripts/assemble_release.py --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --role-paths var/release/role-paths.json --security var/release/security-evidence.json --acceptance var/acceptance/synthetic.json --soak-bundle var/acceptance/soak-bundle.json --trial var/acceptance/family-trial.json --p1r0 var/acceptance/p1r0-approval.json --evidence-schema-paths release/evidence-schema-paths-v1.json --evidence-schema-paths-schema release/schemas/evidence-schema-paths-v1.schema.json --signer-registry security/evidence-signers-v1.json --signer-registry-schema security/schemas/evidence-signers-v1.schema.json --output dist/release-candidate
shasum -a 256 -c dist/release-candidate/SHA256SUMS
uv run python scripts/verify_private_data.py . dist/release-candidate
uv run tuntunctl update apply --candidate dist/release-candidate --require-p1r0
uv run tuntunctl service status --field commit
test -z "$(git status --porcelain)"
git tag -s v0.1.0-beta.1 -m "Tuntun v0.1.0-beta.1"
uv run python scripts/verify_tag.py v0.1.0-beta.1 --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --signers release/authorized-signers-v1.json --signers-schema release/schemas/authorized-signers-v1.schema.json
uv run python scripts/release_gate.py --candidate dist/release-candidate/release-candidate.json --candidate-schema release/schemas/release-candidate-v1.schema.json --evidence-schema-paths release/evidence-schema-paths-v1.json --evidence-schema-paths-schema release/schemas/evidence-schema-paths-v1.schema.json --signer-registry security/evidence-signers-v1.json --signer-registry-schema security/schemas/evidence-signers-v1.schema.json --tag v0.1.0-beta.1 --tag-signers release/authorized-signers-v1.json --tag-signers-schema release/schemas/authorized-signers-v1.schema.json --installed-commit "$(uv run tuntunctl service status --field commit)" --publication-signer-service tuntun.release.publication --output var/release/publication-record.json
uv run python scripts/verify_private_data.py dist/release-candidate var/release/publication-record.json
```

Expected: P1R0 follows the shared semantic verifier and exact passkey binding; assembly copies the same P1R0 envelope and fixes its hash in the candidate; every packaged byte matches signed security/frozen acceptance evidence; the installed commit, signed tag, candidate, P1R0, and publication record all name the same frozen commit. Nothing is published automatically.

The owner may then run the single manual `gh release create` command from `docs/operations/publish-release.md`, re-download every artifact, verify `SHA256SUMS`, and sign the final `tuntun.publication-record.v1` containing verified URLs/hashes. Checkpoint P1R1 requires reproducible published bytes, a no-secret simulator, clean scans, exact signer lifecycles/tag/commit/evidence/P1R0/artifact hashes, verified re-download, and the private installation remaining on the approved commit or a separately approved later upgrade. The release title, README, manifest, and publication record must all label it a Phase 1 preview and explicitly state that Phase 2–6 support and the program C0/C1 gates are not included.

## Execution Handoff

Execute and commit Tasks 1–10 sequentially using only synthetic fixtures for Tasks 5–10. Then freeze the clean commit and execute Ceremonies A–E in order; the two eight-hour runs and four-day trial occur exactly once against that frozen commit. Stop for the signed reviews, latency deviation if needed, P1R0 passkey, tag signing, and manual publication. Automatic publication is forbidden.
