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
- Production household validation requires the independently owner-approved opaque Core inventory target from ADR 0001, currently verified as native Darwin `arm64`, plus FileVault on, macOS Keychain available, owner-only `0700` roots, installed launchd core limit zero, and no content-bearing crash diagnostic. Architecture/model/product/year observations cannot authorize a target. Intel macOS remains a mandatory supported-distribution target; moving household deployment back to Intel requires fresh trusted owner approval and real-host probes before any live-household claim.
- Listener policy is exact: `127.0.0.1:8787`, resolved RFC1918 interface address on `7443`, and optional passkey console on that same address at `8443`. Wildcard, public, unresolved-interface, and other Tuntun listeners fail.
- Every upgrade invokes Privacy Shield, disables new provider attempts, drains in-flight calls to zero, creates/verifies an encrypted backup, verifies DB/audit/model/protocol compatibility, then switches runtime.
- Failed install/upgrade restores the prior symlink and compatible encrypted DB before restart. Uninstall removes runtime/service only; data, models, backups, and Keychain items remain.
- Evidence schemas use `additionalProperties:false` recursively, canonical UTF-8 JSON, 64-character SHA-256 hashes, provenance, exact timestamps, and Keychain-backed Ed25519 signatures. Raw family data and absolute local paths are forbidden.
- Blockers include any secret/real-family fixture, retained media/transcript, unauthorized egress, invalid audit, plaintext fallback, failed isolation/auth/child/privacy/safety gate, incompatible license, or unmitigated high/critical vulnerability.
- Acceptance includes 240+ bilingual/persona cases, 1,000 cross-profile cases, 500 mixed turns, two distinct eight-hour runs, then owner 48 hours followed by second-adult 48 hours. Simulation never replaces elapsed gates.
- P1R0 is an explicit owner approve/reject artifact bound to version, commit, acceptance hash, evidence hashes, and a fresh action-bound owner passkey receipt.
- Tasks 5–10 commit and test evidence tooling only with synthetic fixtures. After Task 10, one clean frozen commit is qualified by two byte-identical builds; a clean target is locally commissioned and evidence-pending-installed from those exact bytes. Official security, acceptance, elapsed soak/trial, P1R0, candidate assembly without rebuild, accepted installation, and tag outputs are then generated once, in that order; no tracked change may occur during the ceremony.
- `Clean target` does not assume a second Mac. For this household it is the same independently owner-approved opaque Core inventory target, whose current Darwin `arm64` observation is a compatibility gate rather than authority, entered through an owner-approved maintenance window only after a verified encrypted backup and recovery-key check. The clean-target probe means no installed Tuntun runtime, core leaf/private key, launchd registration, listener, or unfinished lifecycle journal remains; it does not require erasing unrelated office data. Qualified bytes are retained on owner-controlled immutable storage while the managed Tuntun namespace is cleaned, and rollback restores the previously verified backup/runtime if commissioning or evidence-pending installation fails. A VM, hosted runner, synthetic receipt, or diagnostic Keychain receipt cannot replace the independent trusted owner-approval binding and real-host lifecycle evidence. Intel distribution receipts remain separate and do not promote Intel to household target without new real-host qualification.
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
- Create: `packages/contracts/src/tuntun_contracts/host_approval.py`
- Create: `packages/contracts/src/tuntun_contracts/bootstrap_authorization.py`
- Create: `packages/contracts/src/tuntun_contracts/preflight_runtime.py`
- Create: `docs/evidence/trusted-host-approval.schema.json`
- Create: `docs/evidence/bootstrap-authorization.schema.json`
- Create: `docs/evidence/preflight-runtime-manifest.schema.json`
- Create: `security/phase1-preflight-source-policy-v1.json`
- Create: `security/schemas/phase1-preflight-source-policy.schema.json`
- Create: `scripts/build_preflight_runtime.py`
- Create: `native/preflight-bootstrap/main.c`
- Create: `native/preflight-spawn/preflight_spawn.c`
- Create: `apps/core/src/tuntun_core/deploy/__init__.py`
- Create: `apps/core/src/tuntun_core/deploy/bootstrap_preflight.py`
- Create: `apps/core/src/tuntun_core/deploy/host_approval.py`
- Create: `apps/core/src/tuntun_core/deploy/native_bootstrap.py`
- Create: `apps/core/src/tuntun_core/deploy/native_spawn.py`
- Create: `apps/core/src/tuntun_core/deploy/runtime_materialization.py`
- Create: `apps/core/src/tuntun_core/deploy/trusted_commands.py`
- Create: `apps/core/src/tuntun_core/deploy/preflight.py`
- Create: `apps/core/src/tuntun_core/cli/commands/doctor.py`
- Modify: `apps/core/pyproject.toml`
- Modify: `apps/core/src/tuntun_core/cli/main.py`
- Test: `tests/contract/test_host_approval_contract.py`
- Test: `tests/contract/test_bootstrap_authorization_contract.py`
- Test: `tests/contract/test_preflight_runtime_contract.py`
- Test: `tests/integration/deploy/test_clean_bootstrap_preflight.py`
- Test: `tests/integration/deploy/test_descriptor_stable_spawn.py`
- Test: `tests/integration/deploy/test_preflight_runtime_build.py`
- Test: `tests/unit/deploy/test_host_approval.py`
- Test: `tests/unit/deploy/test_trusted_commands.py`
- Test: `tests/unit/deploy/test_preflight.py`
- Test: `tests/security/test_listener_allowlist.py`

**Interfaces:**
- Clean bootstrap consumes only the candidate's signed, closed bootstrap manifest, a prior owner-present `SignedBootstrapAuthorization`, the separately ceremony-pinned owner public key, a fresh proof from the authorization-bound target-held P-256 key, secure time, and the fixed system executables. The authorization purpose is exactly `phase1.household-core.bootstrap.v1`, is valid for at most 15 minutes, is one-use, and binds the opaque target ID, target public-key digest, candidate-manifest digest, source-policy digest, selected-platform runtime-manifest and runtime-tar digests, owner-approval commitment, positive generation, and random nonce. The prior ceremony exports the authorization, public key, and its owner-passkey/WebAuthn authentication receipt to an owner-controlled read-only bootstrap kit; the verifier validates that receipt against the already enrolled external owner credential before trusting the supplied key. The bootstrap path requires no Tuntun managed root, Tuntun Keychain item, installed manifest, installed CLI, LaunchAgent, database, CA, backup record, or `tuntunctl`.
- Installed `verify-installed`, `upgrade`, and `repair` consume only the closed `TrustedHostAuthorityRecord`, the commissioned Keychain owner-authority pin at service/account `tuntun.trust.owner-authority/current-v1`, a fresh target-key proof, and the installed signed release/runtime manifests. They reject bootstrap authorizations. After clean host checks pass, lifecycle initialization creates the managed roots and target Keychain key, then atomically publishes and reopens the installed authority record and Keychain pin before any installed preflight or service start.
- Produces: `SignedBootstrapAuthorization.signing_bytes() -> bytes`; `BootstrapAuthorizationVerifier.verify_candidate_target(...) -> VerifiedBootstrapApproval`; `production_clean_bootstrap_preflight(...) -> VerifiedBootstrapPreflight`; `SignedTrustedHostAuthorityRecord.signing_bytes() -> bytes`; `SignedTrustedHostApprovalVerifier.verify_current_target(expected_target_id=...) -> VerifiedHostApproval`; `TrustedCommandRegistry.open(...) -> TrustedCommandRegistry`; `TrustedCommandRegistry.prepare(argv) -> PreparedCommand`; `CommandRunner.run(argv) -> CommandResult`; `run_clean_bootstrap_preflight(...) -> PreflightReport`; `run_installed_preflight(mode, ...) -> PreflightReport`; JSON exit `0` or `78`. `VerifiedBootstrapPreflight` is one closed exact-type result containing both the successful `PreflightReport` and the full `VerifiedBootstrapApproval`; it is passed unchanged into `Installer.install_verified` and is never reduced to a nonce or tuple.
- Authority is executable rather than structural. The candidate's signed release manifest names the exact nofollow descriptor-verified native bootstrap launcher, deterministic platform runtime tar, and closed runtime manifest. Before any Python import, the native launcher verifies the candidate signature and manifest, safely materializes the exact tar inventory into a fresh root-owned non-writable ephemeral runtime tree outside every Tuntun managed root, reopens every entry nofollow, and retains the tree/entry descriptors. Production clean install then constructs `BootstrapAuthorizationVerifier` directly from descriptor-held artifacts inside that tree; production installed preflight constructs `SignedTrustedHostApprovalVerifier` directly from the exact owner-only installed authority path, Keychain pin, `MacOSTargetKeySampler`, secure clock, and CSPRNG. No `Protocol`, arbitrary string, architecture/model/product/year observation, diagnostic receipt, caller-created approval object, environment variable, or CLI override can satisfy either production path.
- Both authority records bind `source_policy_sha256` and a platform-specific signed `TrustedExecutionClosure`: exact system-binary content/execution identities, the materialized Python identity/digest, native spawn bridge digest, deterministic runtime-tar digest, and closed runtime-manifest digest. The runtime inventory contains the complete Tuntun and third-party closure, including the selected platform's CPython standard library, `pydantic_core` extension, `cryptography` native extension and every linked non-system library; native/dynamic modules are required to match their platform tag and manifest entry rather than being rejected. The registry exact-compares the actual policy digest and every closure field and retains the root and all executable/runtime descriptors.
- `TrustedCommandRegistry.prepare` returns an opaque `PreparedCommand`, never a pathname. On Linux the C bridge executes the retained executable descriptor with `execveat(..., AT_EMPTY_PATH)` in a new process group. Darwin has no `fexecve`; there the bridge uses `posix_spawn` with `POSIX_SPAWN_START_SUSPENDED`, compares the suspended child's `csops` CodeDirectory hash and executable-vnode identity with the retained manifest-bound executable, kills on mismatch before any child instruction can run, and only then sends `SIGCONT`. The same bridge governs the materialized Python and fixed system binaries. A resolve-to-exec pathname replacement therefore either runs the retained Linux descriptor or is rejected while suspended on Darwin; replacement bytes never execute.
- `install` performs host-only checks and never assumes initialized state. `verify-installed` checks initialized assets and the live process. `upgrade` and `repair` add Privacy Shield/provider drain and cannot fall back to the bootstrap path.

- [ ] **Step 1: Write the failing invocation and listener tests**

```python
# tests/unit/deploy/test_preflight.py
from pathlib import Path

import pytest
from tuntun_contracts.host_approval import TrustedExecutionClosure
from tuntun_core.deploy.bootstrap_preflight import VerifiedBootstrapApproval
from tuntun_core.deploy.host_approval import VerifiedHostApproval
from tuntun_core.deploy.preflight import (
    CommandResult, required, run_clean_bootstrap_preflight, run_installed_preflight,
)

SYSTEM_DIGESTS={name:"c"*64 for name in (
    "uname","id","fdesetup","security","route","ipconfig","stat","plutil","lsof",
)}
CLOSURE=TrustedExecutionClosure(
    system_executable_sha256=SYSTEM_DIGESTS,python_sha256="c"*64,
    runtime_manifest_sha256="d"*64,
    preflight_runtime_tar_sha256="e"*64,native_spawn_bridge_sha256="f"*64,
)
APPROVAL=VerifiedHostApproval("target:opaque-01","a"*64,"b"*64,CLOSURE)
BOOTSTRAP=VerifiedBootstrapApproval(
    "target:opaque-01","a"*64,"b"*64,CLOSURE,"nonce:opaque-01",
)

class Runner:
    def __init__(self): self.calls=[]
    def run(self, argv):
        self.calls.append(argv)
        values={
          ("uname","-m"):"arm64\n", ("tuntunctl","system","architecture","--json"):'{"machine":"arm64"}\n',
          ("id","-un"):"test\n", ("fdesetup","status"):"FileVault is On.\n",
          ("security","list-keychains","-d","user"):'    "/Users/test/Library/Keychains/login.keychain-db"\n',
          ("security","find-generic-password","-s","tuntun.database","-a","root-v1"):"ok\n",
          ("route","-n","get","default"):"interface: en0\n", ("ipconfig","getifaddr","en0"):"192.168.50.10\n",
          ("plutil","-extract","SoftResourceLimits.Core","raw",str(Path("/Users/test/Library/LaunchAgents/com.tuntun.core.plist"))):"0\n",
          ("tuntunctl","service","crash-probe","--json"):'{"core_files":0,"content_diagnostics":0}\n',
          ("tuntunctl","service","pid","--json"):'{"pid":4321}\n',
          ("tuntunctl","lan","verify-commissioning","--json"):'{"verified":true,"private_dns":true,"certificate_match":true,"all_admin_devices":true,"drift":false}\n',
          ("lsof","-nP","-a","-p","4321","-iTCP","-sTCP:LISTEN"):"Python TCP 127.0.0.1:8787 (LISTEN)\nPython TCP 192.168.50.10:7443 (LISTEN)\n",
          ("tuntunctl","privacy","activate","--reason","packaging","--json"):'{"egress_closed":true}\n',
          ("tuntunctl","providers","disable-new","--json"):'{"disabled":true}\n',
          ("tuntunctl","providers","drain","--timeout-seconds","30","--json"):'{"in_flight":0,"ambiguous":0}\n'}
        if argv[:3]==("stat","-f","%Su:%Lp"): return CommandResult(0,"test:700\n","")
        if argv[:3]==("lsof","-nP","-iTCP:8787"): return CommandResult(1,"","")
        return CommandResult(0,values[argv],"")

def test_upgrade_invokes_every_check():
    runner=Runner(); report=run_installed_preflight("upgrade",Path("/Users/test"),runner,False,APPROVAL)
    assert report.ok
    assert {check.check_id for check in report.checks}=={"trusted_owner_target","architecture","filevault","keychain_available","resolved_interface","database_key","owner_paths","launchd_core_limit","crash_diagnostics","listeners","privacy","provider_drain"}
    assert ("tuntunctl","providers","drain","--timeout-seconds","30","--json") in runner.calls

def test_clean_install_runs_host_checks_without_assuming_initialized_state():
    runner=Runner(); report=run_clean_bootstrap_preflight(Path("/Users/test"),runner,BOOTSTRAP)
    assert report.ok
    assert {check.check_id for check in report.checks}=={
        "trusted_owner_target","architecture","filevault","keychain_available","resolved_interface","existing_runtime_absent","ports_available",
    }
    forbidden={"find-generic-password","stat","plutil","crash-probe","service"}
    assert all(not forbidden.intersection(call) for call in runner.calls)


def test_clean_install_preflight_rejects_existing_or_broken_current_link(tmp_path):
    current=tmp_path/"Library/Application Support/Tuntun/runtime/current"
    current.parent.mkdir(parents=True)
    current.symlink_to(current.parent/"releases/0.1.0-alpha.1")
    report=run_clean_bootstrap_preflight(tmp_path,Runner(),BOOTSTRAP)
    check=next(item for item in report.checks if item.check_id=="existing_runtime_absent")
    assert report.ok is False
    assert check.reason=="existing_runtime_detected_use_upgrade"

def test_lan_listener_allowance_requires_current_commissioning_receipt():
    runner=Runner()
    runner.run=lambda argv: (
        CommandResult(0,'{"verified":false,"private_dns":false,"certificate_match":false,"all_admin_devices":false,"drift":true}\n',"")
        if argv==("tuntunctl","lan","verify-commissioning","--json") else Runner().run(argv)
    )
    report=run_installed_preflight("verify-installed",Path("/Users/test"),runner,True,APPROVAL)
    assert not report.ok
    assert next(item for item in report.checks if item.check_id=="lan_commissioning").passed is False

def test_architecture_match_cannot_replace_trusted_owner_target():
    with pytest.raises(RuntimeError, match="trusted owner target unavailable"):
        run_clean_bootstrap_preflight(Path("/Users/test"),Runner(),object())
    with pytest.raises(RuntimeError, match="trusted owner target unavailable"):
        run_installed_preflight("upgrade",Path("/Users/test"),Runner(),False,object())

def test_command_failure_does_not_disclose_arguments_or_output():
    class Failing:
        def run(self,argv): return CommandResult(1,"private-stdout","private-stderr")
    with pytest.raises(RuntimeError,match="^preflight command failed$") as caught:
        required(Failing(),("stat","-f","%Su:%Lp","/Users/private-path-sentinel"))
    assert "private" not in str(caught.value) and "/Users" not in str(caught.value)
```

```python
# tests/unit/deploy/test_host_approval.py
import base64
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tuntun_contracts.base import canonical_bytes
from tuntun_contracts.host_approval import SignedTrustedHostAuthorityRecord, TrustedHostAuthorityRecord
from tuntun_core.deploy.host_approval import SignedTrustedHostApprovalVerifier, TargetKeySample

NOW=datetime(2026,8,30,12,0,tzinfo=UTC)
OWNER_PRIVATE=Ed25519PrivateKey.generate()
OWNER_PUBLIC=OWNER_PRIVATE.public_key()
TARGET_DER=b"sampled-target-public-key-der"

class Sampler:
    def __init__(self, *, present=True, public_key_der=TARGET_DER, valid=True):
        self.present=present; self.public_key_der=public_key_der; self.valid=valid
    def sample(self, challenge):
        if not self.present: raise RuntimeError("trusted target key unavailable")
        return TargetKeySample(self.public_key_der,challenge,b"signature",self.valid)

def signed_record(*, target_id="target:opaque-01", target_key_sha256=sha256(TARGET_DER).hexdigest(),
                  generation=7, valid_from=NOW-timedelta(minutes=1),
                  valid_until=NOW+timedelta(days=30)):
    record=TrustedHostAuthorityRecord(
        schema_version="1.0",purpose="phase1.household-core.preflight.v1",
        authority_generation=generation,
        target_id=target_id,approval_commitment_sha256="a"*64,
        target_public_key_sha256=target_key_sha256,valid_from=valid_from,
        valid_until=valid_until,source_policy_sha256="b"*64,
        execution_closure={
            "system_executable_sha256":{name:"c"*64 for name in (
                "uname","id","fdesetup","security","route","ipconfig","stat","plutil","lsof",
            )},
            "python_sha256":"c"*64,"runtime_manifest_sha256":"d"*64,
            "preflight_runtime_tar_sha256":"e"*64,
            "native_spawn_bridge_sha256":"f"*64,
        },
    )
    signature=OWNER_PRIVATE.sign(b"tuntun:trusted-host-authority:v1\0"+canonical_bytes(record))
    return SignedTrustedHostAuthorityRecord(record=record,owner_key_id="owner:authority:v7",
        signature_b64=base64.b64encode(signature).decode("ascii"))

def verifier(envelope, sampler=None):
    return SignedTrustedHostApprovalVerifier(
        envelope=envelope,pinned_owner_public_key=OWNER_PUBLIC,
        expected_owner_key_id="owner:authority:v7",expected_generation=7,
        target_sampler=sampler or Sampler(),now=lambda:NOW,random_bytes=lambda size:b"r"*size,
    )

def test_signed_current_target_is_bound_to_sampled_target_key():
    approval=verifier(signed_record()).verify_current_target(expected_target_id="target:opaque-01")
    assert approval.target_id=="target:opaque-01"
    assert approval.approval_commitment_sha256=="a"*64

@pytest.mark.parametrize("case",("forged","stale","target_mismatch","wrong_key","no_target","purpose","generation"))
def test_forged_stale_mismatched_wrong_key_or_missing_target_is_rejected(case):
    envelope=signed_record()
    sampler=Sampler()
    if case=="forged": envelope=envelope.model_copy(update={"signature_b64":base64.b64encode(b"x"*64).decode("ascii")})
    elif case=="stale": envelope=signed_record(valid_from=NOW-timedelta(days=31),valid_until=NOW)
    elif case=="target_mismatch": envelope=signed_record(target_id="target:opaque-02")
    elif case=="wrong_key": sampler=Sampler(public_key_der=b"different-target-key")
    elif case=="no_target": sampler=Sampler(present=False)
    elif case=="purpose":
        record=envelope.record.model_copy(update={"purpose":"diagnostic.host-probe"})
        signature=OWNER_PRIVATE.sign(b"tuntun:trusted-host-authority:v1\0"+canonical_bytes(record))
        envelope=envelope.model_copy(update={"record":record,"signature_b64":base64.b64encode(signature).decode("ascii")})
    else: envelope=signed_record(generation=6)
    with pytest.raises(RuntimeError,match="trusted owner target unavailable"):
        verifier(envelope,sampler).verify_current_target(expected_target_id="target:opaque-01")

def test_diagnostic_probe_receipt_is_rejected_before_authority_verification(tmp_path):
    path=tmp_path/"authority.json"
    path.write_text('{"$schema":"https://tuntun.local/schemas/evidence/phase1-host-probe.schema.json"}'); path.chmod(0o600)
    with pytest.raises(RuntimeError,match="trusted host authority schema rejected"):
        SignedTrustedHostApprovalVerifier.load_envelope(path)
```

```python
# tests/integration/deploy/test_clean_bootstrap_preflight.py
import pytest
from tuntun_core.deploy.bootstrap_preflight import (
    VerifiedBootstrapPreflight,production_clean_bootstrap_preflight,
)
from tuntun_core.deploy.host_approval import production_installed_approval

class ProtocolApprovalFake:
    target_id="target:opaque-01"
    approval_commitment_sha256="a"*64

def test_clean_home_uses_descriptor_verified_candidate_and_external_owner_kit(
    clean_home, signed_candidate, fresh_owner_bootstrap_kit,
):
    assert clean_home.managed_roots == ()
    assert clean_home.tuntun_keychain_items == ()
    assert clean_home.installed_manifest is None
    assert clean_home.command_exists("tuntunctl") is False
    with signed_candidate.real_native_bootstrap_context(
        fresh_owner_bootstrap_kit,
    ):
        verified=production_clean_bootstrap_preflight(
            candidate_dir=signed_candidate.path,
            authorization_path=fresh_owner_bootstrap_kit.authorization_path,
            owner_trust_path=fresh_owner_bootstrap_kit.external_owner_trust_path,
            owner_presence_receipt_path=fresh_owner_bootstrap_kit.presence_receipt_path,
            home=clean_home.path,
        )
    assert type(verified) is VerifiedBootstrapPreflight
    assert verified.report.ok
    assert verified.authority_kind=="one_use_bootstrap"
    assert verified.approval.one_use_nonce==fresh_owner_bootstrap_kit.one_use_nonce

@pytest.mark.parametrize("mutation",(
    "forged","stale","future","replayed_nonce","wrong_generation","wrong_purpose",
    "wrong_target","wrong_target_key","no_target","wrong_candidate","wrong_source_policy",
    "wrong_bootstrap_runtime","untrusted_owner_credential","bad_owner_presence",
    "authorization_swap","candidate_manifest_swap","candidate_runtime_swap",
))
def test_clean_bootstrap_rejects_every_unbound_or_changed_input_before_mutation(
    clean_home, mutated_bootstrap_case, mutation,
):
    case=mutated_bootstrap_case(mutation)
    with pytest.raises(RuntimeError,match="^trusted bootstrap unavailable$"):
        with case.real_native_bootstrap_context():
            production_clean_bootstrap_preflight(**case.production_kwargs)
    assert clean_home.mutations == ()

@pytest.mark.parametrize("fake",("target:opaque-01",object(),ProtocolApprovalFake()))
def test_production_bootstrap_does_not_accept_strings_objects_or_protocol_fakes(
    signed_candidate, clean_home, fake,
):
    with pytest.raises(TypeError):
        production_clean_bootstrap_preflight(
            candidate_dir=signed_candidate.path,verified_approval=fake,home=clean_home.path,
        )
    with pytest.raises(TypeError):
        production_clean_bootstrap_preflight(
            candidate_dir=signed_candidate.path,target_sampler=fake,home=clean_home.path,
        )

def test_restart_upgrade_and_repair_reject_bootstrap_authority(
    initialized_home, fresh_owner_bootstrap_kit,
):
    for mode in ("verify-installed","upgrade","repair"):
        with pytest.raises(RuntimeError,match="^trusted owner target unavailable$"):
            production_installed_approval(
                mode=mode,home=initialized_home.path,
                authority_path=fresh_owner_bootstrap_kit.authorization_path,
            )

def test_upgrade_requires_reopened_installed_record_pin_and_current_target_key(
    initialized_home,
):
    initialized_home.remove_owner_authority_pin()
    with pytest.raises(RuntimeError,match="^trusted owner target unavailable$"):
        production_installed_approval(mode="upgrade",home=initialized_home.path)
```

`tests/contract/test_bootstrap_authorization_contract.py` generates `bootstrap-authorization.schema.json` byte-for-byte and rejects extra/missing fields, validity intervals over 15 minutes, a nonpositive or mismatched generation, noncanonical timestamps/signature/nonce, the installed or diagnostic purpose, and malformed target/candidate/source/runtime digests. The fixture ceremony signs the domain-separated canonical record with the externally enrolled owner credential only after an owner-presence assertion and a fresh challenge to a purpose-separated external hardware target credential; its private key never enters the kit or a Mac Keychain. `BootstrapAuthorizationVerifier` opens the authorization, external-owner/target credential trust record, owner-presence receipt, signed candidate manifest, source-policy file, runtime tar, and runtime manifest through retained nofollow descriptors with owner/type/mode/link/count/byte/deadline bounds; the concrete production wiring opens the authorization-bound CTAP2 credential directly and validates its fresh proof, the external credential chain, exact candidate/policy/runtime hashes, one-use nonce ledger, and descriptor/path identity before and after verification. No schema validator returns authority: the native-launched production entry constructs `VerifiedBootstrapApproval` only inside this concrete verifier and wraps it with the successful report and native one-use seal as `VerifiedBootstrapPreflight`. Tests obtain a capability only from the real verifier under a signed synthetic ceremony/native-context harness; they do not construct or inject one through a fixture-only production seam.

```python
# tests/unit/deploy/test_trusted_commands.py
import pytest
from tuntun_core.deploy import trusted_commands
from tuntun_core.deploy.trusted_commands import (
    CLOSED_COMMAND_ENV,CommandResult,CommandRunner,PreparedCommand,
    TrustedCommandRegistry,bounded_wait,
)

def registry_fixture(materialized_runtime):
    return TrustedCommandRegistry.open(
        materialized_runtime.expected_closure,
        materialized_runtime.root_path,
        materialized_runtime.manifest_path,
        expected_source_policy_sha256=materialized_runtime.source_policy_sha256,
    )

def test_path_bash_env_pythonpath_and_shims_cannot_redirect_commands(
    monkeypatch,tmp_path,materialized_runtime,
):
    registry=registry_fixture(materialized_runtime)
    shim=tmp_path/"uname"; shim.write_text("#!/bin/sh\nexit 99\n"); shim.chmod(0o755)
    monkeypatch.setenv("PATH",str(tmp_path)); monkeypatch.setenv("BASH_ENV",str(shim))
    monkeypatch.setenv("ENV",str(shim)); monkeypatch.setenv("PYTHONPATH",str(tmp_path))
    observed={}
    def spawn(prepared,*,environment,output_limit,timeout_seconds):
        observed.update(prepared=prepared,environment=environment,
                        output_limit=output_limit,timeout_seconds=timeout_seconds)
        return CommandResult(0,"arm64\n","")
    monkeypatch.setattr(trusted_commands.native_spawn,"spawn_verified",spawn)
    result=CommandRunner(registry).run(("uname","-m"))
    assert result.returncode==0
    assert type(observed["prepared"]) is PreparedCommand
    assert observed["environment"]==CLOSED_COMMAND_ENV
    assert "BASH_ENV" not in observed["environment"] and "PYTHONPATH" not in observed["environment"]

@pytest.mark.parametrize("mutation",(
    "system_executable","python","project_module","pydantic_core",
    "cryptography_native","linked_library","policy","runtime_tar","manifest",
))
def test_post_registry_closure_or_source_policy_swap_fails_before_spawn(
    mutation,materialized_runtime,monkeypatch,
):
    registry=registry_fixture(materialized_runtime)
    materialized_runtime.replace_selected_entry(mutation)
    spawned=[]
    monkeypatch.setattr(
        trusted_commands.native_spawn,"spawn_verified",
        lambda *a,**k:spawned.append((a,k)),
    )
    with pytest.raises(RuntimeError,match="trusted executable unavailable"):
        CommandRunner(registry).run(("uname","-m") if mutation=="system_executable" else ("tuntunctl","system","architecture","--json"))
    assert spawned==[]

def test_wrong_source_policy_digest_is_rejected_at_registry_open(materialized_runtime):
    with pytest.raises(RuntimeError,match="trusted executable unavailable"):
        TrustedCommandRegistry.open(
            materialized_runtime.expected_closure,
            materialized_runtime.root_path,
            materialized_runtime.manifest_path,
            expected_source_policy_sha256="0"*64,
        )

def test_timeout_kills_process_group_with_finite_term_and_kill_deadlines_preserving_primary_error(fake_process):
    fake_process.timeout_error=TimeoutError("primary-timeout")
    with pytest.raises(TimeoutError,match="primary-timeout"):
        bounded_wait(fake_process,65_536,30,terminate_seconds=1,kill_seconds=1)
    assert fake_process.events==[
        "killpg:TERM","wait:1","killpg:KILL","wait:1","record_cleanup_failure",
    ]

@pytest.mark.parametrize("cleanup_failure",("term","term_wait","kill","kill_wait","audit"))
def test_cleanup_failure_never_replaces_the_primary_error(fake_process,cleanup_failure):
    fake_process.timeout_error=TimeoutError("primary-timeout")
    fake_process.cleanup_failure=cleanup_failure
    with pytest.raises(TimeoutError,match="^primary-timeout$"):
        bounded_wait(fake_process,65_536,30,terminate_seconds=1,kill_seconds=1)

def test_registry_open_failure_closes_every_held_descriptor(
    materialized_runtime,monkeypatch,
):
    held=materialized_runtime.held_with_wrong_source_policy()
    monkeypatch.setattr(trusted_commands,"open_runtime_closure",lambda *a,**k:held)
    with pytest.raises(RuntimeError,match="^trusted executable unavailable$"):
        TrustedCommandRegistry.open(
            Expected(held.expected),held.release_root,held.manifest_path,
            expected_source_policy_sha256="0"*64,
        )
    assert held.close_calls==1 and held.open_descriptors==()
```

```python
# tests/integration/deploy/test_descriptor_stable_spawn.py
import platform
import pytest
from tuntun_core.deploy import native_spawn
from tuntun_core.deploy.trusted_commands import CommandRunner,TrustedCommandRegistry

def test_resolve_to_exec_replacement_bytes_never_run(
    descriptor_spawn_runtime,tmp_path,monkeypatch,
):
    original=descriptor_spawn_runtime.materialized_python_path
    sentinel=tmp_path/"replacement-ran"
    replacement=descriptor_spawn_runtime.compile_replacement(sentinel)
    registry=TrustedCommandRegistry.open(
        descriptor_spawn_runtime.expected_closure,
        descriptor_spawn_runtime.root_path,
        descriptor_spawn_runtime.manifest_path,
        expected_source_policy_sha256=descriptor_spawn_runtime.source_policy_sha256,
    )
    real_spawn=native_spawn.spawn_verified
    observed=[]
    def replace_after_final_registry_check(prepared,**kwargs):
        replacement.replace(original)
        result=real_spawn(prepared,**kwargs)
        observed.append(result)
        return result
    monkeypatch.setattr(native_spawn,"spawn_verified",replace_after_final_registry_check)
    try:
        with pytest.raises(RuntimeError,match="^trusted executable unavailable$"):
            CommandRunner(registry).run(
                ("tuntunctl","diagnostics","spawn-identity"),
            )
    finally:
        registry.close()
    if platform.system()=="Linux":
        assert len(observed)==1
        assert observed[0].returncode==0 and observed[0].stdout=="original\n"
    else:
        assert observed==[]
    assert not sentinel.exists()

def test_darwin_replacement_is_killed_while_still_suspended(
    darwin_spawn_probe,
):
    if platform.system()!="Darwin": pytest.skip("Darwin-only suspended-spawn proof")
    result=darwin_spawn_probe.replace_after_prepare()
    assert result.child_user_instruction_count==0
    assert result.signal_sent=="SIGKILL"
    assert result.reason=="execution_identity_mismatch"
```

```python
# tests/integration/deploy/test_preflight_runtime_build.py
import importlib.machinery
import json
from pathlib import Path
from scripts.build_preflight_runtime import build_preflight_runtime
from tuntun_core.deploy.runtime_materialization import materialize_verified_runtime
from tuntun_core.deploy.trusted_commands import CommandRunner,TrustedCommandRegistry

def test_two_builds_are_identical_and_production_runtime_imports_native_modules(
    tmp_path,locked_runtime_input,root_owned_runtime_parent,
):
    first=build_preflight_runtime(locked_runtime_input,tmp_path/"first")
    second=build_preflight_runtime(locked_runtime_input,tmp_path/"second")
    assert first.manifest_bytes==second.manifest_bytes
    assert first.tar_bytes==second.tar_bytes
    runtime=materialize_verified_runtime(
        first.runtime_tar,first.runtime_manifest,
        destination_parent=root_owned_runtime_parent,
    )
    registry=TrustedCommandRegistry.open(
        first.expected_closure,runtime.root,runtime.manifest,
        expected_source_policy_sha256=first.source_policy_sha256,
    )
    try:
        result=CommandRunner(registry).run(
            ("tuntunctl","diagnostics","runtime-imports","--json"),
        )
    finally:
        registry.close()
    assert result.returncode==0
    probe=json.loads(result.stdout)
    assert set(probe)=={"imported","module_paths","native_module_paths","sys_path"}
    assert set(probe["imported"])=={
        "pydantic","pydantic_core._pydantic_core","cryptography",
        "cryptography.hazmat.bindings._rust",
    }
    assert all(Path(path).is_relative_to(runtime.root) for path in probe["module_paths"])
    assert all(
        any(path.endswith(suffix) for suffix in importlib.machinery.EXTENSION_SUFFIXES)
        for path in probe["native_module_paths"]
    )
    assert all(Path(path).is_relative_to(runtime.root) for path in probe["sys_path"])

@pytest.mark.parametrize("mutation",(
    "wrong_platform","wrong_abi","missing_pydantic_core","missing_cryptography_rust",
    "extra_native_module","unlisted_linked_library","post_open_native_swap",
))
def test_native_runtime_mutations_fail_before_import_or_spawn(
    mutation,mutated_runtime_case,
):
    with pytest.raises(RuntimeError,match="^trusted runtime unavailable$"):
        materialize_verified_runtime(*mutated_runtime_case(mutation))
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

Run: `uv run pytest tests/contract/test_bootstrap_authorization_contract.py tests/contract/test_host_approval_contract.py tests/contract/test_preflight_runtime_contract.py tests/integration/deploy/test_clean_bootstrap_preflight.py tests/integration/deploy/test_descriptor_stable_spawn.py tests/integration/deploy/test_preflight_runtime_build.py tests/unit/deploy/test_host_approval.py tests/unit/deploy/test_trusted_commands.py tests/unit/deploy/test_preflight.py tests/security/test_listener_allowlist.py -q`

Expected: FAIL during collection because the bootstrap/installed authority contracts, closed schemas, source policy, and `tuntun_core.deploy` production modules do not exist yet.

- [ ] **Step 3: Implement the command-backed preflight**

```python
# packages/contracts/src/tuntun_contracts/bootstrap_authorization.py
from datetime import timedelta
from typing import Annotated, Literal, Self
from pydantic import AwareDatetime, Field, model_validator
from .base import ContractModel,canonical_bytes,validate_canonical_base64

Digest=Annotated[str,Field(pattern=r"^[0-9a-f]{64}$")]
class BootstrapAuthorizationRecord(ContractModel):
    schema_version:Literal["1.0"]
    purpose:Literal["phase1.household-core.bootstrap.v1"]
    authority_generation:Annotated[int,Field(ge=1,le=2**31-1)]
    target_id:Annotated[str,Field(pattern=r"^target:[A-Za-z0-9_-]{8,64}$")]
    target_public_key_sha256:Digest
    candidate_manifest_sha256:Digest
    source_policy_sha256:Digest
    preflight_runtime_manifest_sha256:Digest
    preflight_runtime_tar_sha256:Digest
    approval_commitment_sha256:Digest
    one_use_nonce:Annotated[str,Field(pattern=r"^nonce:[A-Za-z0-9_-]{16,86}$")]
    valid_from:AwareDatetime
    valid_until:AwareDatetime
    @model_validator(mode="after")
    def short_lived(self)->Self:
        if self.valid_until<=self.valid_from or self.valid_until-self.valid_from>timedelta(minutes=15):
            raise ValueError("bootstrap validity invalid")
        return self
class SignedBootstrapAuthorization(ContractModel):
    record:BootstrapAuthorizationRecord
    owner_credential_id:Annotated[str,Field(pattern=r"^owner:external:v[1-9][0-9]{0,8}$")]
    owner_presence_receipt_sha256:Digest
    signature_b64:Annotated[str,Field(pattern=r"^[A-Za-z0-9+/]{86}==$")]
    def signing_bytes(self)->bytes:
        return b"tuntun:bootstrap-authorization:v1\0"+canonical_bytes(self.record)
```

`docs/evidence/bootstrap-authorization.schema.json` is generated byte-for-byte from this contract, carries `$schema: https://json-schema.org/draft/2020-12/schema`, `$id: https://tuntun.local/schemas/evidence/bootstrap-authorization.schema.json`, and sets `additionalProperties:false` on the envelope and record. It has exactly the fields above, RFC 3339 `date-time` formats with runtime format assertion, the literal purpose/version, the positive bounded generation, and the exact digest/target/nonce/signature patterns. The model validator and JSON Schema tests additionally assert the half-open validity interval is no longer than 15 minutes. The concrete `apps/core/src/tuntun_core/deploy/bootstrap_preflight.py` verifier consumes paths, not parsed models; production constructs its exact-type return capability only after cryptographic verification, while unit-only fixtures can construct it directly without becoming a production authority path.

`packages/contracts/src/tuntun_contracts/preflight_runtime.py` defines the closed `PreflightRuntimeManifestV1`: exact schema/version/runtime ID, one literal platform ID (`darwin-arm64`, `darwin-x86_64`, or `linux-x86_64`), CPython ABI/tag, source commit, source-policy digest, deterministic runtime-tar digest, relative materialized Python/native-spawn paths and digests, aggregate inventory digest, required native-module records for `pydantic_core._pydantic_core` and `cryptography.hazmat.bindings._rust`, linked-library identities, and a sorted 1..50,000 tuple of `RuntimeFileV1(path, kind="regular"|"directory", mode=0o444|0o555, size<=268435456, sha256)`. Paths are canonical relative POSIX paths with no empty/dot/dot-dot/backslash/control component, casefold/NFC collision, duplicate, or link/special type. `docs/evidence/preflight-runtime-manifest.schema.json` is generated byte-for-byte with recursive `additionalProperties:false`. `security/schemas/phase1-preflight-source-policy.schema.json` closes the exact source policy fields: schema/version/policy ID, native bootstrap/spawn source digests, entrypoint `tuntun_core.cli`, isolation flags exactly `["-I","-S"]`, exact environment-key/value map, output/deadline/count/byte bounds, and the fixed system-executable map. The checked-in `security/phase1-preflight-source-policy-v1.json` validates canonically against it.

`scripts/build_preflight_runtime.py` is the sole deterministic per-platform builder. From the locked distribution set for the current CI row it builds a relocatable CPython layout, places the complete Tuntun and third-party import roots under that layout's isolated versioned library root, enumerates every importable file, package metadata file, CPython file, native extension, and non-system linked library, and normalizes native-loader references to manifest-listed `$ORIGIN`/`@loader_path` locations. On Darwin it requires a valid final Mach-O code signature for every executable image and records its CodeDirectory hash; the two-build check proves the chosen signing procedure is reproducible. It rejects an ABI/platform mismatch or an unlisted/missing/extra dependency; hashes final descriptor-read bytes/modes into the runtime manifest; then creates a canonical USTAR `preflight-runtime.tar` without links, devices, sparse/PAX/GNU records, ambient ownership, or nondeterministic timestamps. It reopens the tar and manifest to prove the complete member inventory and aggregate digest exactly. The tar is never imported or executed: the native bootstrap launcher extracts only verified entries into a fresh root-owned `0555` directory with `0444|0555` children outside managed Tuntun roots, fsyncs/reopens the tree, and passes retained descriptors to the registry. `tests/integration/deploy/test_preflight_runtime_build.py` performs two byte-identical builds on each fixed CI platform, uses the production materializer and `TrustedCommandRegistry`/native spawn bridge with `-I -S`, and invokes the real closed diagnostic entry. The subprocess must import Pydantic v2, `pydantic_core._pydantic_core`, `cryptography`, and `cryptography.hazmat.bindings._rust` from the materialized root and show that every effective `sys.path` entry remains under that root. The test uses the runner's scoped privileged fixture to create the same root-owned/non-writable layout; it does not relax ownership or use an alternate importer. It also rejects wrong ABI/tag, missing/extra/duplicate module or linked library, path collision, lock/policy/bootstrap mismatch, and module/native-library/tar/manifest mutation before and after registry open. Candidate assembly and Task 2 package every platform artifact without rebuilding; the selected target authorization and installed authority bind the one exact platform closure.

```python
# packages/contracts/src/tuntun_contracts/host_approval.py
from datetime import timedelta
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, Field, field_validator, model_validator

from .base import ContractModel, canonical_bytes, validate_canonical_base64

Digest=Annotated[str,Field(pattern=r"^[0-9a-f]{64}$")]

class TrustedSystemExecutableDigests(ContractModel):
    uname:Digest; id:Digest; fdesetup:Digest; security:Digest; route:Digest
    ipconfig:Digest; stat:Digest; plutil:Digest; lsof:Digest

class TrustedExecutionClosure(ContractModel):
    system_executable_sha256:TrustedSystemExecutableDigests
    python_sha256:Digest
    runtime_manifest_sha256:Digest
    preflight_runtime_tar_sha256:Digest
    native_spawn_bridge_sha256:Digest

class TrustedHostAuthorityRecord(ContractModel):
    schema_version:Literal["1.0"]
    purpose:Literal["phase1.household-core.preflight.v1"]
    authority_generation:Annotated[int,Field(ge=1,le=2**31-1)]
    target_id:Annotated[str,Field(pattern=r"^target:[A-Za-z0-9_-]{8,64}$")]
    approval_commitment_sha256:Digest
    target_public_key_sha256:Digest
    valid_from:AwareDatetime
    valid_until:AwareDatetime
    source_policy_sha256:Digest
    execution_closure:TrustedExecutionClosure

    @model_validator(mode="after")
    def bounded_validity(self)->Self:
        if self.valid_until<=self.valid_from or self.valid_until-self.valid_from>timedelta(days=90):
            raise ValueError("trusted host authority validity invalid")
        return self

class SignedTrustedHostAuthorityRecord(ContractModel):
    record:TrustedHostAuthorityRecord
    owner_key_id:Annotated[str,Field(pattern=r"^owner:authority:v[1-9][0-9]{0,8}$")]
    signature_b64:Annotated[str,Field(pattern=r"^[A-Za-z0-9+/]{86}==$")]

    @field_validator("signature_b64")
    @classmethod
    def canonical_signature(cls,value:str)->str:
        return validate_canonical_base64(value,expected_bytes=64,label="signature")

    def signing_bytes(self)->bytes:
        return b"tuntun:trusted-host-authority:v1\0"+canonical_bytes(self.record)
```

The exact checked-in `docs/evidence/trusted-host-approval.schema.json` artifact is:

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://tuntun.local/schemas/evidence/trusted-host-approval.schema.json",
  "type":"object","additionalProperties":false,
  "required":["record","owner_key_id","signature_b64"],
  "properties":{
    "record":{"$ref":"#/$defs/record"},
    "owner_key_id":{"type":"string","pattern":"^owner:authority:v[1-9][0-9]{0,8}$"},
    "signature_b64":{"type":"string","pattern":"^[A-Za-z0-9+/]{86}==$"}
  },
  "$defs":{
    "digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},
    "system_executables":{"type":"object","additionalProperties":false,
      "required":["uname","id","fdesetup","security","route","ipconfig","stat","plutil","lsof"],
      "properties":{"uname":{"$ref":"#/$defs/digest"},"id":{"$ref":"#/$defs/digest"},"fdesetup":{"$ref":"#/$defs/digest"},"security":{"$ref":"#/$defs/digest"},"route":{"$ref":"#/$defs/digest"},"ipconfig":{"$ref":"#/$defs/digest"},"stat":{"$ref":"#/$defs/digest"},"plutil":{"$ref":"#/$defs/digest"},"lsof":{"$ref":"#/$defs/digest"}}},
    "execution_closure":{"type":"object","additionalProperties":false,
      "required":["system_executable_sha256","python_sha256","runtime_manifest_sha256","preflight_runtime_tar_sha256","native_spawn_bridge_sha256"],
      "properties":{"system_executable_sha256":{"$ref":"#/$defs/system_executables"},"python_sha256":{"$ref":"#/$defs/digest"},"runtime_manifest_sha256":{"$ref":"#/$defs/digest"},"preflight_runtime_tar_sha256":{"$ref":"#/$defs/digest"},"native_spawn_bridge_sha256":{"$ref":"#/$defs/digest"}}},
    "record":{"type":"object","additionalProperties":false,
      "required":["schema_version","purpose","authority_generation","target_id","approval_commitment_sha256","target_public_key_sha256","valid_from","valid_until","source_policy_sha256","execution_closure"],
      "properties":{"schema_version":{"const":"1.0"},"purpose":{"const":"phase1.household-core.preflight.v1"},"authority_generation":{"type":"integer","minimum":1,"maximum":2147483647},"target_id":{"type":"string","pattern":"^target:[A-Za-z0-9_-]{8,64}$"},"approval_commitment_sha256":{"$ref":"#/$defs/digest"},"target_public_key_sha256":{"$ref":"#/$defs/digest"},"valid_from":{"type":"string","format":"date-time"},"valid_until":{"type":"string","format":"date-time"},"source_policy_sha256":{"$ref":"#/$defs/digest"},"execution_closure":{"$ref":"#/$defs/execution_closure"}}}
  }
}
```

`tests/contract/test_host_approval_contract.py` generates this schema from the contract, requires byte-for-byte equality with the checked-in artifact, enables RFC 3339 format assertion, and rejects every missing/extra field, noncanonical signature, validity interval over 90 days, wrong purpose, zero/negative generation, descriptive/invalid target ID, and wrong executable key set.

```python
# apps/core/src/tuntun_core/deploy/host_approval.py
import base64,hashlib,os,secrets,stat
from dataclasses import dataclass
from datetime import UTC,timedelta
from pathlib import Path
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from tuntun_contracts.base import parse_contract_json
from tuntun_contracts.host_approval import SignedTrustedHostAuthorityRecord,TrustedExecutionClosure
from tuntun_core.config.secure_paths import absolute_lexical_path,open_trusted_directory,_require_no_unsafe_acl

TARGET_CHALLENGE_DOMAIN=b"tuntun:trusted-host-target-key:v1\0"
@dataclass(frozen=True,slots=True)
class TargetKeySample:
    public_key_der:bytes; challenge:bytes; signature:bytes; proof_verified:bool
@dataclass(frozen=True,slots=True)
class VerifiedHostApproval:
    target_id:str; approval_commitment_sha256:str; source_policy_sha256:str
    execution_closure:TrustedExecutionClosure
class TargetKeySampler(Protocol):
    def sample(self,challenge:bytes)->TargetKeySample: ...

def read_owner_only_nofollow_bounded(path:Path,max_bytes:int)->bytes:
    absolute=absolute_lexical_path(path)
    with open_trusted_directory(absolute.parent) as parent:
        parent.revalidate()
        fd=os.open(absolute.name,os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=parent.fd)
        try:
            before=os.fstat(fd); named=os.stat(absolute.name,dir_fd=parent.fd,follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or not stat.S_ISREG(named.st_mode)
                or (before.st_dev,before.st_ino)!=(named.st_dev,named.st_ino)
                or before.st_dev!=parent.device or before.st_nlink!=1
                or before.st_uid!=os.geteuid() or stat.S_IMODE(before.st_mode)!=0o600
                or before.st_size>max_bytes): raise PermissionError("unsafe trusted authority file")
            _require_no_unsafe_acl(fd,"unsafe trusted authority file")
            chunks=[]; total=0
            while True:
                chunk=os.read(fd,min(65_536,max_bytes+1-total))
                if not chunk: break
                chunks.append(chunk); total+=len(chunk)
                if total>max_bytes: raise PermissionError("unsafe trusted authority file")
            raw=b"".join(chunks)
            if len(raw)!=before.st_size: raise PermissionError("unsafe trusted authority file")
            after=os.fstat(fd); named_after=os.stat(absolute.name,dir_fd=parent.fd,follow_symlinks=False)
            parent.revalidate()
            stable=lambda row:(row.st_dev,row.st_ino,row.st_size,row.st_mtime_ns,row.st_ctime_ns)
            if stable(before)!=stable(after) or stable(after)!=stable(named_after):
                raise PermissionError("unsafe trusted authority file")
            return raw
        finally: os.close(fd)

class MacOSTargetKeySampler:
    KEY_ID="tuntun.local-presence.target-signing.v1"
    def __init__(self,keychain_signer): self._signer=keychain_signer
    def sample(self,challenge):
        if type(challenge) is not bytes or len(challenge)!=32: raise RuntimeError("trusted target key unavailable")
        public_der=self._signer.public_key_der(self.KEY_ID)
        signature=self._signer.sign(self.KEY_ID,TARGET_CHALLENGE_DOMAIN+challenge)
        public=serialization.load_der_public_key(public_der)
        if not isinstance(public,ec.EllipticCurvePublicKey) or not isinstance(public.curve,ec.SECP256R1):
            raise RuntimeError("trusted target key unavailable")
        try: public.verify(signature,TARGET_CHALLENGE_DOMAIN+challenge,ec.ECDSA(hashes.SHA256()))
        except InvalidSignature: raise RuntimeError("trusted target key unavailable") from None
        return TargetKeySample(public_der,challenge,signature,True)

class SignedTrustedHostApprovalVerifier:
    MAX_BYTES=65_536
    def __init__(self,*,envelope,pinned_owner_public_key,expected_owner_key_id,
                 expected_generation,target_sampler,now,random_bytes):
        self._envelope=envelope; self._owner_key=pinned_owner_public_key
        self._owner_key_id=expected_owner_key_id; self._generation=expected_generation
        self._sampler=target_sampler; self._now=now; self._random=random_bytes
    @classmethod
    def load_envelope(cls,path:Path):
        try:
            raw=read_owner_only_nofollow_bounded(path,cls.MAX_BYTES)
            value=parse_contract_json(SignedTrustedHostAuthorityRecord,raw,max_bytes=cls.MAX_BYTES)
            if value.record.purpose!="phase1.household-core.preflight.v1": raise RuntimeError
            return value
        except BaseException:
            raise RuntimeError("trusted host authority schema rejected") from None
    def verify_current_target(self,*,expected_target_id):
        try:
            signed=self._envelope; record=signed.record; now=self._now().astimezone(UTC)
            if signed.owner_key_id!=self._owner_key_id or record.authority_generation!=self._generation:
                raise RuntimeError
            if record.purpose!="phase1.household-core.preflight.v1" or record.target_id!=expected_target_id:
                raise RuntimeError
            if not record.valid_from<=now<record.valid_until or record.valid_until-record.valid_from>timedelta(days=90):
                raise RuntimeError
            self._owner_key.verify(base64.b64decode(signed.signature_b64,validate=True),signed.signing_bytes())
            challenge=self._random(32)
            if type(challenge) is not bytes or len(challenge)!=32: raise RuntimeError
            sample=self._sampler.sample(challenge)
            if type(sample) is not TargetKeySample or sample.proof_verified is not True:
                raise RuntimeError
            if sample.challenge!=challenge or not 33<=len(sample.public_key_der)<=512:
                raise RuntimeError
            if not secrets.compare_digest(hashlib.sha256(sample.public_key_der).hexdigest(),record.target_public_key_sha256):
                raise RuntimeError
            return VerifiedHostApproval(record.target_id,record.approval_commitment_sha256,
                                        record.source_policy_sha256,record.execution_closure)
        except BaseException:
            raise RuntimeError("trusted owner target unavailable") from None
```

`read_owner_only_nofollow_bounded` is a concrete function in this file: it opens through the existing secure-path descriptor API with `O_RDONLY|O_NOFOLLOW|O_CLOEXEC`, requires an owner-only regular file, reads to the exact asserted size through one descriptor with a 65,536-byte cap, rechecks device/inode/type/size/change timestamps, and returns bytes. A missing record, diagnostic host-probe receipt, symlink, ownership/mode failure, parse error, signature error, stale interval, wrong generation/purpose/target, absent target key, wrong sampled public key, invalid challenge proof, or changed file maps to the one content-free error above. `MacOSTargetKeySampler` consumes the same target-held Keychain P-256 signing key created by the local-presence implementation; it never exports private material.

```python
# apps/core/src/tuntun_core/deploy/trusted_commands.py
import os,selectors,signal,subprocess,time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from tuntun_core.deploy import native_spawn

FIXED_EXECUTABLES={"uname":Path("/usr/bin/uname"),"id":Path("/usr/bin/id"),
 "fdesetup":Path("/usr/bin/fdesetup"),"security":Path("/usr/bin/security"),
 "route":Path("/sbin/route"),"ipconfig":Path("/usr/sbin/ipconfig"),
 "stat":Path("/usr/bin/stat"),"plutil":Path("/usr/bin/plutil"),"lsof":Path("/usr/sbin/lsof")}
CLOSED_COMMAND_ENV={"LANG":"C","LC_ALL":"C","PATH":"/usr/bin:/bin:/usr/sbin:/sbin"}
MAX_COMMAND_OUTPUT_BYTES=65_536
@dataclass(frozen=True,slots=True)
class CommandResult: returncode:int; stdout:str; stderr:str

# Re-export the exact non-serializable C-extension capability. Its constructor is
# not exposed; it owns the executable/runtime descriptors, argv, and policy digest
# and deliberately exposes no executable pathname or raw descriptor integer.
PreparedCommand=native_spawn.PreparedCommand

def terminate_process_group_bounded(process,*,terminate_seconds,kill_seconds):
    cleanup_failed=False
    for selected_signal,timeout in (
        (signal.SIGTERM,terminate_seconds),(signal.SIGKILL,kill_seconds),
    ):
        try: os.killpg(process.pid,selected_signal)
        except ProcessLookupError: return cleanup_failed
        except BaseException: cleanup_failed=True
        try:
            process.wait(timeout=timeout)
            return cleanup_failed
        except subprocess.TimeoutExpired:
            continue
        except BaseException:
            cleanup_failed=True
    return True

def record_cleanup_failure_without_raising():
    with suppress(BaseException):
        record_content_free_cleanup_failure()

def bounded_wait(process,limit,seconds,*,terminate_seconds=1,kill_seconds=1):
    captured={"stdout":bytearray(),"stderr":bytearray()}; deadline=time.monotonic()+seconds
    try:
        with selectors.DefaultSelector() as selector:
            for stream,name in ((process.stdout,"stdout"),(process.stderr,"stderr")):
                if stream is None: raise RuntimeError("preflight command pipe unavailable")
                os.set_blocking(stream.fileno(),False); selector.register(stream,selectors.EVENT_READ,name)
            while selector.get_map():
                remaining=deadline-time.monotonic()
                if remaining<=0: raise TimeoutError("preflight command timeout")
                events=selector.select(remaining)
                if not events: raise TimeoutError("preflight command timeout")
                for key,_ in events:
                    chunk=os.read(key.fileobj.fileno(),16_384)
                    if not chunk: selector.unregister(key.fileobj); continue
                    captured[key.data].extend(chunk)
                    if len(captured["stdout"])+len(captured["stderr"])>limit:
                        raise RuntimeError("preflight command output too large")
        code=process.wait(timeout=max(.001,deadline-time.monotonic()))
        return CommandResult(code,captured["stdout"].decode("utf-8","strict"),captured["stderr"].decode("utf-8","strict"))
    except BaseException:
        # This helper never raises; the active exception remains the public failure.
        if terminate_process_group_bounded(
            process,terminate_seconds=terminate_seconds,kill_seconds=kill_seconds,
        ):
            record_cleanup_failure_without_raising()
        raise

class TrustedCommandRegistry:
    @classmethod
    def open(cls,expected,release_root,manifest_path,*,expected_source_policy_sha256):
        # open_runtime_closure retains the release-root, manifest, policy, Python,
        # every materialized inventory entry, linked library, and fixed-binary
        # descriptor. It never imports or executes the runtime tar.
        # It verifies closed canonical JSON, duplicate keys, owner/type/mode/nlink,
        # shared count/byte/time bounds, descriptor/path identity and every digest.
        held=open_runtime_closure(release_root,manifest_path,FIXED_EXECUTABLES)
        try:
            if held.manifest.source_policy_sha256!=expected_source_policy_sha256:
                raise RuntimeError("trusted executable unavailable")
            if held.policy_sha256!=expected_source_policy_sha256:
                raise RuntimeError("trusted executable unavailable")
            if held.execution_closure!=expected.model_dump():
                raise RuntimeError("trusted executable unavailable")
            return cls(held,expected)
        except BaseException:
            with suppress(BaseException): held.close_all()
            raise
    def __init__(self,held,expected): self._held=held; self._expected=expected
    @property
    def release_root(self): return self._held.release_root
    @property
    def expected_closure(self): return self._expected
    def close(self): self._held.close_all()
    def _revalidate(self):
        if not self._held.revalidate_every_identity_and_digest():
            raise RuntimeError("trusted executable unavailable")
    def prepare(self,argv):
        self._revalidate()
        name,*tail=argv
        if name=="tuntunctl":
            executable=self._held.open_python_handle()
            child_argv=("python","-I","-S","-m","tuntun_core.cli",*tail)
        elif name in FIXED_EXECUTABLES:
            executable=self._held.open_system_handle(name)
            child_argv=(name,*tail)
        else:
            raise RuntimeError("trusted executable unavailable")
        self._revalidate()
        return native_spawn.prepare_verified_command(
            executable=executable,argv=tuple(child_argv),
            runtime=self._held.native_runtime_handle(),
            source_policy_sha256=self._held.policy_sha256,
        )

class CommandRunner:
    def __init__(self,registry): self._registry=registry
    def run(self,argv):
        return self.run_prepared(self._registry.prepare(argv))
    def run_prepared(self,prepared):
        try:
            self._registry._revalidate()
            result=native_spawn.spawn_verified(
                prepared,environment=CLOSED_COMMAND_ENV,
                output_limit=MAX_COMMAND_OUTPUT_BYTES,timeout_seconds=30,
            )
            self._registry._revalidate()
            return result
        except BaseException:
            # spawn_verified never raises until any child it created has undergone
            # finite process-group termination and reap; cleanup cannot replace the
            # primary exception.
            raise
```

`open_runtime_closure`, `terminate_process_group_bounded`, and every `HeldRuntimeClosure` method are implemented in full, not left as `Protocol`s. The canonical runtime manifest is a closed, sorted inventory of every project, standard-library, third-party, native-extension, and non-system linked-library byte loaded from the already materialized runtime tree; it binds the exact runtime tar, manifest, Python, native spawn bridge, fixed system executables, and source policy. The registry retains and revalidates the runtime-root descriptor, every inventory descriptor, and every executable descriptor through child completion. It returns only the exact non-constructible C-extension `PreparedCommand`, which binds the executable handle, argv, runtime handles, and source-policy digest; neither the registry nor `CommandRunner` returns an executable path/raw descriptor or calls `subprocess.Popen` on a mutable name. The bridge rejects subclasses, deserialized objects, altered argv/environment, reused handles, or a capability from another registry.

`native/preflight-spawn/preflight_spawn.c` and its thin `native_spawn.py` wrapper are production code, not an interface sketch. On Linux, the bridge creates the pipes and process group, then executes the retained descriptor with `execveat(fd, "", argv, envp, AT_EMPTY_PATH)`. On Darwin, where descriptor execution is unavailable, it calls `posix_spawn` with `POSIX_SPAWN_START_SUSPENDED`; while the child is still suspended it obtains and compares the child's `csops` CodeDirectory hash and executable-vnode identity with the retained manifest-bound descriptor, sends `SIGKILL` and reaps on any mismatch, and sends `SIGCONT` only after both match. A pathname is used only inside that Darwin bridge to ask the kernel to create the suspended image; it is never returned to Python, and replacement bytes cannot execute before attestation. The same bridge governs the materialized Python and fixed system binaries. The materialized tree is root-owned and non-writable for the invoking account, so Python's native-module and shared-library loads cannot be redirected after verification. The bridge rejects an unexpected platform/ABI, missing `execveat`/suspended-spawn guarantee, descriptor/root change, wrong code identity, or unsupported command instead of falling back to path execution.

The environment is exactly `CLOSED_COMMAND_ENV`; inherited `PATH`, `BASH_ENV`, `ENV`, `PYTHONPATH`, `PYTHONHOME`, `VIRTUAL_ENV`, shell functions, Git/Python startup variables, and `GITHUB_ENV`/`GITHUB_PATH` are absent. The native bridge owns the child from creation through bounded output collection and reap. Every spawn, timeout, output, decode, attestation, and registry-revalidation failure runs finite process-group TERM then KILL waits, records a content-free cleanup failure without replacing the primary exception, and has no unbounded `wait()`. Tests compile and execute real original/replacement binaries and import the real native runtime closure; they do not use `find_spec`, a pathname-returning fake, or post-execution attestation.

```python
# apps/core/src/tuntun_core/deploy/preflight.py
import re
from dataclasses import dataclass
from pathlib import Path
from tuntun_contracts.base import parse_bounded_json_value
from .bootstrap_preflight import VerifiedBootstrapApproval
from .host_approval import VerifiedHostApproval
from .trusted_commands import MAX_COMMAND_OUTPUT_BYTES,CommandResult,CommandRunner
@dataclass(frozen=True,slots=True)
class ResolvedInterface: name:str; address:str
@dataclass(frozen=True,slots=True)
class Check: check_id:str; passed:bool; reason:str
@dataclass(frozen=True,slots=True)
class PreflightReport: schema_version:str; mode:str; ok:bool; checks:tuple[Check,...]
def required(runner,argv):
    result=runner.run(argv)
    if result.returncode: raise RuntimeError("preflight command failed")
    if len(result.stdout.encode("utf-8"))>MAX_COMMAND_OUTPUT_BYTES:
        raise RuntimeError("preflight command output too large")
    return result.stdout
def command_json(runner,argv,expected_keys):
    raw=required(runner,argv).encode("utf-8",errors="strict")
    value=parse_bounded_json_value(
        raw,max_bytes=MAX_COMMAND_OUTPUT_BYTES,max_depth=8,
        max_containers=128,max_structure_tokens=512,
    )
    if not isinstance(value,dict) or set(value)!=set(expected_keys):
        raise RuntimeError("invalid tuntunctl receipt")
    return value
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
def _approval_fields_are_closed(approval):
    return (re.fullmatch(r"target:[A-Za-z0-9_-]{8,64}",approval.target_id) is not None
        and re.fullmatch(r"[0-9a-f]{64}",approval.approval_commitment_sha256) is not None
        and re.fullmatch(r"[0-9a-f]{64}",approval.source_policy_sha256) is not None)

def _base_host_values(runner):
    interface=resolve_private_interface(runner)
    return interface,{
        "trusted_owner_target":True,
        "architecture":required(runner,("uname","-m")).strip()=="arm64",
        "filevault":"FileVault is On." in required(runner,("fdesetup","status")),
        "keychain_available":bool(required(runner,("security","list-keychains","-d","user")).strip()),
        "resolved_interface":True,
    }

def run_clean_bootstrap_preflight(home,runner,verified_bootstrap_approval):
    approval=verified_bootstrap_approval
    if type(approval) is not VerifiedBootstrapApproval or not _approval_fields_are_closed(approval):
        raise RuntimeError("trusted owner target unavailable")
    interface,values=_base_host_values(runner); del interface
    current=home/"Library/Application Support/Tuntun/runtime/current"
    values["existing_runtime_absent"]=not (current.exists() or current.is_symlink())
    ports=runner.run(("lsof","-nP","-iTCP:8787","-iTCP:7443","-iTCP:8443","-sTCP:LISTEN"))
    if ports.returncode not in {0,1}: raise RuntimeError("port probe failed")
    values["ports_available"]=not ports.stdout.strip()
    checks=tuple(Check(name,bool(value),("existing_runtime_detected_use_upgrade" if name=="existing_runtime_absent" and not value else name+"_failed")) for name,value in values.items())
    return PreflightReport("tuntun.preflight.v1","install",all(item.passed for item in checks),checks)

def run_installed_preflight(mode,home,runner,lan_console,verified_host_approval):
    if mode not in {"upgrade","repair","verify-installed"}: raise ValueError("invalid mode")
    approval=verified_host_approval
    if type(approval) is not VerifiedHostApproval or not _approval_fields_are_closed(approval):
        raise RuntimeError("trusted owner target unavailable")
    interface,values=_base_host_values(runner); plist=home/"Library/LaunchAgents/com.tuntun.core.plist"
    roots=[home/path for path in ("Library/Application Support/Tuntun/runtime","Library/Application Support/Tuntun/data","Library/Application Support/Tuntun/models","Library/Application Support/Tuntun/backups","Library/Logs/Tuntun")]
    owner=required(runner,("id","-un")).strip()
    python_arch=command_json(runner,("tuntunctl","system","architecture","--json"),{"machine"})
    values["architecture"]=values["architecture"] and python_arch["machine"]=="arm64"
    lan_commissioned=False
    if lan_console:
        lan_receipt=command_json(runner,("tuntunctl","lan","verify-commissioning","--json"),{
            "verified","private_dns","certificate_match","all_admin_devices","drift",
        })
        lan_commissioned=all(lan_receipt[name] is expected for name,expected in {
            "verified":True,"private_dns":True,"certificate_match":True,
            "all_admin_devices":True,"drift":False,
        }.items()); values["lan_commissioning"]=lan_commissioned
    pid_value=command_json(runner,("tuntunctl","service","pid","--json"),{"pid"})["pid"]
    if isinstance(pid_value,bool) or not isinstance(pid_value,int) or not 1<=pid_value<=4_194_304:
        raise RuntimeError("invalid service pid receipt")
    rows=tuple((host,int(port)) for host,port in re.findall(r"TCP\s+(\[[^\]]+\]|[^\s:]+):(\d+)\s+\(LISTEN\)",required(runner,("lsof","-nP","-a","-p",str(pid_value),"-iTCP","-sTCP:LISTEN"))))
    crash=command_json(runner,("tuntunctl","service","crash-probe","--json"),{"core_files","content_diagnostics"})
    values.update({
        "database_key":bool(required(runner,("security","find-generic-password","-s","tuntun.database","-a","root-v1"))),
        "owner_paths":all(required(runner,("stat","-f","%Su:%Lp",str(path))).strip()==f"{owner}:700" for path in roots),
        "launchd_core_limit":required(runner,("plutil","-extract","SoftResourceLimits.Core","raw",str(plist))).strip()=="0",
        "crash_diagnostics":all(type(crash[name]) is int and crash[name]==0 for name in crash),
        "listeners":not verify_listeners(rows,interface,lan_commissioned),
    })
    if mode in {"upgrade","repair"}:
        values["privacy"]=command_json(runner,("tuntunctl","privacy","activate","--reason","packaging","--json"),{"egress_closed"})["egress_closed"] is True
        if command_json(runner,("tuntunctl","providers","disable-new","--json"),{"disabled"})["disabled"] is not True:
            raise RuntimeError("provider disable receipt invalid")
        drained=command_json(runner,("tuntunctl","providers","drain","--timeout-seconds","30","--json"),{"in_flight","ambiguous"})
        values["provider_drain"]=all(type(drained[name]) is int and drained[name]==0 for name in drained)
    checks=tuple(Check(name,bool(value),("existing_runtime_detected_use_upgrade" if name=="existing_runtime_absent" and not value else name+"_failed")) for name,value in values.items())
    return PreflightReport("tuntun.preflight.v1",mode,all(item.passed for item in checks),checks)
```

```python
# apps/core/src/tuntun_core/deploy/bootstrap_preflight.py (clean production path)
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from tuntun_core.deploy import native_bootstrap

@dataclass(frozen=True,slots=True,init=False)
class VerifiedBootstrapPreflight:
    report:"PreflightReport"
    approval:VerifiedBootstrapApproval
    authority_kind:Literal["one_use_bootstrap"]
    _seal:native_bootstrap.VerificationSeal

def _verified_result(report,approval,seal):
    value=object.__new__(VerifiedBootstrapPreflight)
    object.__setattr__(value,"report",report)
    object.__setattr__(value,"approval",approval)
    object.__setattr__(value,"authority_kind","one_use_bootstrap")
    object.__setattr__(value,"_seal",seal)
    return value

def production_clean_bootstrap_preflight(*,candidate_dir,authorization_path,
        owner_trust_path,owner_presence_receipt_path,home):
    from tuntun_core.deploy.preflight import run_clean_bootstrap_preflight

    # Only the signed native bootstrap launcher can establish this descriptor-held
    # context. Direct Python invocation or a caller-created object fails closed.
    context=native_bootstrap.claim_verified_candidate_context(candidate_dir)
    authorization=context.open_owner_kit_file(authorization_path)
    owner_trust=context.open_owner_kit_file(owner_trust_path)
    owner_presence=context.open_owner_kit_file(owner_presence_receipt_path)
    target_sampler=ExternalHardwareBootstrapTargetKeySampler.open_bound_credential(
        owner_trust,
    )
    verifier=BootstrapAuthorizationVerifier.from_descriptors(
        authorization=authorization,owner_trust=owner_trust,
        owner_presence_receipt=owner_presence,
        candidate_manifest=context.candidate_manifest,
        source_policy=context.source_policy,
        runtime_tar=context.runtime_tar,runtime_manifest=context.runtime_manifest,
        target_sampler=target_sampler,now=secure_utc_now,random_bytes=secrets.token_bytes,
    )
    approval=verifier.verify_candidate_target()
    registry=TrustedCommandRegistry.open(
        approval.execution_closure,context.materialized_runtime.root,
        context.materialized_runtime.manifest,
        expected_source_policy_sha256=approval.source_policy_sha256,
    )
    try:
        report=run_clean_bootstrap_preflight(home,CommandRunner(registry),approval)
    finally:
        registry.close()
    if not report.ok:
        raise RuntimeError("clean bootstrap preflight failed")
    seal=context.issue_one_use_preflight_seal(
        approval=approval,report=report,candidate_identity=context.candidate_identity,
    )
    return _verified_result(report,approval,seal)
```

The external clean-install entry is the candidate's exact signed `preflight-bootstrap` native executable, not a Python console script. `install.sh` passes it only the four path arguments above. Before Python starts, the launcher nofollow-opens and verifies the signed candidate manifest, source policy, selected-platform runtime tar and manifest, safely materializes the complete runtime into a fresh root-owned non-writable directory, reopens every entry, and establishes a one-use descriptor context in the native extension. `production_clean_bootstrap_preflight` rejects a process without that context; it has no `verified_approval`, target-sampler, dependency-injection, `Protocol`, environment, installed-container, or materialized-runtime path argument. It constructs the exact external-hardware sampler internally and validates that the sampled credential ID is the one signed into the owner kit.

The successful API result is exactly `VerifiedBootstrapPreflight`, containing the complete successful `PreflightReport`, the complete `VerifiedBootstrapApproval`, literal `authority_kind="one_use_bootstrap"`, and a native, non-serializable, one-use seal bound to candidate identity, nonce, target, report, and retained context. A tuple, nonce, parsed JSON value, subclass, arbitrary strings, or a caller-created dataclass cannot satisfy the lifecycle consumer. The result never crosses a process or JSON boundary: the same native-launched production process passes it unchanged to `Installer.install_verified`. That method consumes the seal while atomically creating the first owner-only managed trust/journal root, exclusively publishes the fail-closed nonce-consumption claim, reopens it, and only then generates the installed target Keychain item. A replay or interrupted prior attempt therefore cannot initialize twice. It derives and atomically publishes the installed-purpose authority and Keychain pin, fsyncs and reopens both, then runs `production_installed_preflight("verify-installed", ...)`. A bootstrap record is never copied into the installed authority location.

```python
# apps/core/src/tuntun_core/cli/commands/doctor.py (production construction path)
import base64,secrets
from datetime import UTC,datetime
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from tuntun_core.deploy.host_approval import MacOSTargetKeySampler,SignedTrustedHostApprovalVerifier
from tuntun_core.deploy.preflight import run_installed_preflight
from tuntun_core.deploy.trusted_commands import CommandRunner,TrustedCommandRegistry

AUTHORITY_RELATIVE_PATH=Path("Library/Application Support/Tuntun/data/trust/trusted-host-authority.json")
OWNER_PIN_SERVICE="tuntun.trust.owner-authority"
OWNER_PIN_ACCOUNT="current-v1"

def production_preflight(mode,home,lan_console,container):
    if mode not in {"verify-installed","upgrade","repair"}: raise ValueError("invalid installed mode")
    authority_path=home/AUTHORITY_RELATIVE_PATH
    trust=container.commissioning_trust_store.open_current(
        service=OWNER_PIN_SERVICE,account=OWNER_PIN_ACCOUNT,
    )
    envelope=SignedTrustedHostApprovalVerifier.load_envelope(authority_path)
    verifier=SignedTrustedHostApprovalVerifier(
        envelope=envelope,
        pinned_owner_public_key=Ed25519PublicKey.from_public_bytes(
            base64.b64decode(trust.owner_public_key_b64,validate=True)
        ),
        expected_owner_key_id=trust.owner_key_id,
        expected_generation=trust.authority_generation,
        target_sampler=MacOSTargetKeySampler(container.local_presence_keychain_signer),
        now=lambda:datetime.now(UTC),random_bytes=secrets.token_bytes,
    )
    approval=verifier.verify_current_target(expected_target_id=trust.opaque_target_id)
    manifest=container.installed_release_manifest.current_descriptor_verified_path()
    registry=TrustedCommandRegistry.open(
        approval.execution_closure,manifest.release_root,manifest.path,
        expected_source_policy_sha256=approval.source_policy_sha256,
    )
    try:
        report=run_installed_preflight(mode,home,CommandRunner(registry),lan_console,approval)
    finally:
        registry.close()
    return serialize_content_safe_report(report),0 if report.ok else 78
```

The Typer `doctor preflight` command has exactly one installed production registration and calls `production_preflight`; it cannot dispatch `install`. Clean install calls only the exact signed native candidate entry, which establishes the descriptor context and calls `production_clean_install`; no standalone Python preflight command is registered. Dependency override is available only through unit-test-only factories that are unreachable from registered CLI paths. The installed launcher invokes the descriptor-stable materialized runtime; no shell, `uv`, console-script shim, ambient package, archive importer, or loose installed module is loaded. `doctor.py` serializes the report without secrets/absolute paths; `service crash-probe` deliberately crashes a content-free helper and compares `/cores` plus `~/Library/Logs/DiagnosticReports` before/after. Port 8443 is allowed only when the strict LAN commissioning verifier reopens a current receipt proving the exact private-DNS mapping, matching local-CA certificate/SAN, every admin-device trust receipt, and no drift. The flag alone never widens loopback, and failure returns the service to loopback-only. No production bypass environment variable is accepted.

- [ ] **Step 4: Run green**

Run: `uv run pytest tests/contract/test_bootstrap_authorization_contract.py tests/contract/test_host_approval_contract.py tests/contract/test_preflight_runtime_contract.py tests/integration/deploy/test_clean_bootstrap_preflight.py tests/integration/deploy/test_descriptor_stable_spawn.py tests/integration/deploy/test_preflight_runtime_build.py tests/unit/deploy/test_host_approval.py tests/unit/deploy/test_trusted_commands.py tests/unit/deploy/test_preflight.py tests/security/test_listener_allowlist.py -q && uv run ruff check packages/contracts/src/tuntun_contracts/bootstrap_authorization.py packages/contracts/src/tuntun_contracts/host_approval.py packages/contracts/src/tuntun_contracts/preflight_runtime.py scripts/build_preflight_runtime.py apps/core/src/tuntun_core/deploy apps/core/src/tuntun_core/cli/commands/doctor.py tests/contract/test_bootstrap_authorization_contract.py tests/contract/test_host_approval_contract.py tests/contract/test_preflight_runtime_contract.py tests/integration/deploy/test_clean_bootstrap_preflight.py tests/integration/deploy/test_descriptor_stable_spawn.py tests/integration/deploy/test_preflight_runtime_build.py tests/unit/deploy tests/security/test_listener_allowlist.py && uv run mypy packages/contracts/src/tuntun_contracts/bootstrap_authorization.py packages/contracts/src/tuntun_contracts/host_approval.py packages/contracts/src/tuntun_contracts/preflight_runtime.py scripts/build_preflight_runtime.py apps/core/src/tuntun_core/deploy apps/core/src/tuntun_core/cli/commands/doctor.py`

Expected: PASS; clean home works without installed state; forged/stale/mismatched/replayed bootstrap artifacts, wrong source/runtime/dependency closures, post-open swaps, and bootstrap use for restart/upgrade/repair fail before mutation/spawn; every required installed command is observed; exact listeners pass; timeout cleanup is finite and preserves the primary error; static checks exit `0`.

- [ ] **Step 5: Commit**

```bash
git status --short
git add packages/contracts/src/tuntun_contracts/bootstrap_authorization.py packages/contracts/src/tuntun_contracts/host_approval.py packages/contracts/src/tuntun_contracts/preflight_runtime.py docs/evidence/bootstrap-authorization.schema.json docs/evidence/preflight-runtime-manifest.schema.json docs/evidence/trusted-host-approval.schema.json security/phase1-preflight-source-policy-v1.json security/schemas/phase1-preflight-source-policy.schema.json scripts/build_preflight_runtime.py native/preflight-bootstrap/main.c native/preflight-spawn/preflight_spawn.c apps/core/pyproject.toml apps/core/src/tuntun_core/deploy/__init__.py apps/core/src/tuntun_core/deploy/bootstrap_preflight.py apps/core/src/tuntun_core/deploy/host_approval.py apps/core/src/tuntun_core/deploy/native_bootstrap.py apps/core/src/tuntun_core/deploy/native_spawn.py apps/core/src/tuntun_core/deploy/runtime_materialization.py apps/core/src/tuntun_core/deploy/trusted_commands.py apps/core/src/tuntun_core/deploy/preflight.py apps/core/src/tuntun_core/cli/commands/doctor.py apps/core/src/tuntun_core/cli/main.py tests/contract/test_bootstrap_authorization_contract.py tests/contract/test_host_approval_contract.py tests/contract/test_preflight_runtime_contract.py tests/integration/deploy/test_clean_bootstrap_preflight.py tests/integration/deploy/test_descriptor_stable_spawn.py tests/integration/deploy/test_preflight_runtime_build.py tests/unit/deploy/test_host_approval.py tests/unit/deploy/test_trusted_commands.py tests/unit/deploy/test_preflight.py tests/security/test_listener_allowlist.py
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

**Interfaces:** `ReleaseLayout.for_home(home: Path) -> ReleaseLayout`; signed-candidate public `install.sh --candidate PATH --bootstrap-authorization PATH --owner-trust PATH --owner-presence-receipt PATH`; same-process `production_clean_install(...) -> Path`; internal `Installer.install_verified(bundle: Path, version: str, preflight: VerifiedBootstrapPreflight) -> Path`; installed-only public `UpgradeCoordinator.apply(bundle: Path, version: str) -> str`; `RecoveryCoordinator.resume(record_id: UUID) -> None`; `Installer.uninstall_preserving_state() -> tuple[Path,Path,Path]`. There is no public preflight/initialization/activation bypass flag and no clean-install `tuntunctl` route. The exact signed native candidate entry establishes Task 1's descriptor context and calls `production_clean_install`; that function obtains one `VerifiedBootstrapPreflight` and passes that same object unchanged to `Installer.install_verified` before the context can close. The installer exact-type/read-only checks reject any unsuccessful report or existing runtime and never rerun preflight or reduce the approval to a nonce. `claim_bootstrap_and_begin_record` then verifies the native seal against the candidate/report without consuming it, creates and fsyncs the exclusive full-binding nonce claim as the first filesystem/Keychain mutation, and only after that durable claim exists atomically consumes the seal and returns the exact approval plus durable install record. A crash before claim publication has made no managed mutation and may retry; a crash or returned failure at/after publication leaves the fail-closed claim, so no second process or restart can reuse the authorization. The owner-only claim binds the full approval nonce, target, candidate, source/runtime closure and report digest; the adjacent journal record is fsynced/reopened and the claim is never removed on failure. Private `_stage_verified` is callable only inside that active record. `LifecycleOps.run_recorded_step(record, name, operation, inverse)` fsyncs a `started` record plus the idempotent inverse before invoking the operation, then fsyncs `completed|failed`; `attempt_all_and_record` never raises, attempts every applicable inverse, records every outcome, and finishes `recovered|needs_owner_recovery`. Its owner-only journal is sufficient to resume after a crash between an operation and its completion record. It consumes host-only bootstrap preflight, hash/SBOM verification, purpose-root/Keychain/installed-authority/SQLCipher/audit-genesis/household-CA/backup-recipient/recovery initialization, encrypted backup, storage/audit/model/protocol verification, migration, readiness; rollback exit `70`. The newly started candidate must pass Privacy Shield, listener, storage, outbound-network, and commissioned-device probes inside the try/rollback boundary; readiness is evaluated only afterward.

- [ ] **Step 1: Write separate failing install, upgrade, rollback, and uninstall tests**

```python
# tests/integration/deploy/test_atomic_install.py
import pytest
from tuntun_core.deploy.lifecycle import Installer,ReleaseLayout,production_clean_install

def test_production_clean_install_composes_one_native_verified_result(
    clean_home,signed_candidate,fresh_owner_bootstrap_kit,
):
    with signed_candidate.real_native_bootstrap_context(
        fresh_owner_bootstrap_kit,
    ) as trace:
        installed=production_clean_install(
            candidate_dir=signed_candidate.path,
            authorization_path=fresh_owner_bootstrap_kit.authorization_path,
            owner_trust_path=fresh_owner_bootstrap_kit.external_owner_trust_path,
            owner_presence_receipt_path=fresh_owner_bootstrap_kit.presence_receipt_path,
            home=clean_home.path,
        )
    record=clean_home.reopen_install_record()
    assert installed==clean_home.current.resolve()
    assert trace.events.count("bootstrap:cryptographic_verify")==1
    assert trace.events.index("bootstrap:result_issued")+1==trace.events.index(
        "bootstrap:result_consumed"
    )
    assert record.bootstrap_authority_kind=="one_use_bootstrap"
    assert record.bootstrap_nonce==fresh_owner_bootstrap_kit.one_use_nonce
    assert record.target_id==fresh_owner_bootstrap_kit.target_id
    assert record.candidate_manifest_sha256==signed_candidate.manifest_sha256
    assert record.preflight_result_sha256==trace.preflight_result_sha256

@pytest.mark.parametrize("forged",(
    "nonce:caller-string",("report","nonce"),object(),
))
def test_installer_rejects_noncapability_results_without_mutation(
    tmp_path,fake_lifecycle_ops,forged,
):
    layout=ReleaseLayout.for_home(tmp_path)
    with pytest.raises(RuntimeError,match="^trusted bootstrap unavailable$"):
        Installer(layout,fake_lifecycle_ops).install_verified(
            tmp_path/"candidate.tar.zst","0.1.0-beta.1",forged,
        )
    assert fake_lifecycle_ops.mutations==[]

def test_preflight_capability_is_bound_to_candidate_and_consumed_once(
    tmp_path,fake_lifecycle_ops,
):
    layout=ReleaseLayout.for_home(tmp_path)
    verified=fake_lifecycle_ops.verified_bootstrap_preflight
    with pytest.raises(RuntimeError,match="trusted bootstrap unavailable"):
        Installer(layout,fake_lifecycle_ops).install_verified(
            tmp_path/"different-candidate.tar.zst","0.1.0-beta.1",verified,
        )
    fake_lifecycle_ops.fail_at="roots:init"
    with pytest.raises(RuntimeError,match="injected roots:init"):
        Installer(layout,fake_lifecycle_ops).install_verified(
            tmp_path/"candidate.tar.zst","0.1.0-beta.1",verified,
        )
    fake_lifecycle_ops.fail_at=None
    assert not layout.current.exists()
    with pytest.raises(RuntimeError,match="trusted bootstrap unavailable"):
        Installer(layout,fake_lifecycle_ops).install_verified(
            tmp_path/"candidate.tar.zst","0.1.0-beta.1",verified,
        )

def test_clean_install_switches_only_after_verified_unpack(tmp_path,fake_lifecycle_ops):
    layout=ReleaseLayout.for_home(tmp_path)
    installed=Installer(layout,fake_lifecycle_ops).install_verified(tmp_path/"candidate.tar.zst","0.1.0-beta.1",fake_lifecycle_ops.verified_bootstrap_preflight)
    assert layout.current.resolve()==installed
    assert fake_lifecycle_ops.events==[
        "bootstrap_nonce:claim","bootstrap_result:consume","recovery:begin:install","roots:init","bundle:verify","bundle:unpack","keychain:init",
        "installed_authority:publish","installed_authority:reopen",
        "sqlcipher:init","database:head:verify","audit_genesis:init","household_ca:init","backup_recipient:init",
        "recovery:ceremony","launch_agent:install","service:load","candidate:privacy_probe",
        "candidate:listener_probe","candidate:storage_probe","candidate:network_probe",
        "candidate:device_probe","readiness:check","preflight:verify-installed","recovery:complete",
    ]
def test_failed_clean_install_leaves_no_current_runtime(tmp_path,fake_lifecycle_ops):
    layout=ReleaseLayout.for_home(tmp_path); fake_lifecycle_ops.ready_result=False
    with pytest.raises(RuntimeError,match="installed service readiness failed"): Installer(layout,fake_lifecycle_ops).install_verified(tmp_path/"candidate.tar.zst","0.1.0-beta.1",fake_lifecycle_ops.verified_bootstrap_preflight)
    assert not layout.current.exists() and layout.data.exists() and layout.models.exists()

def test_installed_authority_and_pin_are_reopened_before_any_installed_command_or_service(
    tmp_path,fake_lifecycle_ops,
):
    layout=ReleaseLayout.for_home(tmp_path)
    Installer(layout,fake_lifecycle_ops).install_verified(
        tmp_path/"candidate.tar.zst","0.1.0-beta.1",fake_lifecycle_ops.verified_bootstrap_preflight,
    )
    events=fake_lifecycle_ops.events
    assert events.index("keychain:init") < events.index("installed_authority:publish")
    assert events.index("installed_authority:reopen") < events.index("service:load")
    assert events.index("installed_authority:reopen") < events.index("preflight:verify-installed")

def test_interrupted_authority_publication_leaves_nonce_claim_and_never_starts_service(
    tmp_path,fake_lifecycle_ops,
):
    fake_lifecycle_ops.fail_at="installed_authority:publish"
    layout=ReleaseLayout.for_home(tmp_path)
    with pytest.raises(RuntimeError):
        Installer(layout,fake_lifecycle_ops).install_verified(
            tmp_path/"candidate.tar.zst","0.1.0-beta.1",fake_lifecycle_ops.verified_bootstrap_preflight,
        )
    assert fake_lifecycle_ops.bootstrap_nonce_claim_exists is True
    assert fake_lifecycle_ops.service_load_count==0

def test_clean_install_accepts_exact_independent_search_namespace(
    tmp_path,fake_lifecycle_ops,
):
    fake_lifecycle_ops.search_enabled=True
    fake_lifecycle_ops.database_heads=("0008_prepared_mutations",)
    fake_lifecycle_ops.search_version_table_present=True
    fake_lifecycle_ops.search_database_heads=("search_0001_experimental_search",)
    fake_lifecycle_ops.optional_search_namespace_present=True
    fake_lifecycle_ops.optional_search_revision_present=True
    fake_lifecycle_ops.optional_search_down_revision=None
    layout=ReleaseLayout.for_home(tmp_path)
    installed=Installer(layout,fake_lifecycle_ops).install_verified(
        tmp_path/"candidate.tar.zst","0.1.0-beta.1",fake_lifecycle_ops.verified_bootstrap_preflight,
    )
    assert layout.current.resolve()==installed
    assert fake_lifecycle_ops.observed_database_heads==("0008_prepared_mutations",)
    assert fake_lifecycle_ops.observed_search_database_heads==(
        "search_0001_experimental_search",
    )

def test_bootstrap_claim_failure_never_initializes_or_publishes_readiness(
    tmp_path,fake_lifecycle_ops,
):
    fake_lifecycle_ops.fail_before_side_effect="bootstrap_nonce:claim"
    layout=ReleaseLayout.for_home(tmp_path)
    with pytest.raises(RuntimeError):
        Installer(layout,fake_lifecycle_ops).install_verified(
            tmp_path/"candidate.tar.zst","0.1.0-beta.1",
            fake_lifecycle_ops.verified_bootstrap_preflight,
        )
    assert fake_lifecycle_ops.managed_mutations==[]
    assert fake_lifecycle_ops.readiness_published is False

@pytest.mark.parametrize("failed_step", [
    "roots:init", "bundle:verify", "bundle:unpack",
    "keychain:init", "installed_authority:publish", "installed_authority:reopen",
    "sqlcipher:init", "database:head:verify", "audit_genesis:init", "household_ca:init",
    "backup_recipient:init", "recovery:ceremony", "launch_agent:install",
    "service:load", "candidate:privacy_probe", "readiness:check",
])
def test_clean_install_never_becomes_ready_with_incomplete_security_initialization(
    tmp_path, fake_lifecycle_ops, failed_step,
):
    fake_lifecycle_ops.fail_at=failed_step
    layout=ReleaseLayout.for_home(tmp_path)
    with pytest.raises(RuntimeError):
        Installer(layout,fake_lifecycle_ops).install_verified(tmp_path/"candidate.tar.zst","0.1.0-beta.1",fake_lifecycle_ops.verified_bootstrap_preflight)
    assert not layout.current.exists()
    assert fake_lifecycle_ops.readiness_published is False
    assert fake_lifecycle_ops.recovery_record.completed_steps
    assert fake_lifecycle_ops.recovery_record.state in {"recovered","needs_owner_recovery"}


@pytest.mark.parametrize(("search_enabled","database_heads"),(
    (False,("0007_privacy_post_response_jobs",)),
    (False,("0007_privacy_post_response_jobs","0008_prepared_mutations")),
    (True,("0007_privacy_post_response_jobs",)),
    (True,("0007_privacy_post_response_jobs","0008_prepared_mutations")),
))
def test_clean_install_blocks_wrong_or_multiple_core_migration_heads(
    tmp_path,fake_lifecycle_ops,search_enabled,database_heads,
):
    fake_lifecycle_ops.search_enabled=search_enabled
    fake_lifecycle_ops.database_heads=database_heads
    layout=ReleaseLayout.for_home(tmp_path)
    with pytest.raises(RuntimeError,match="phase1 migration head mismatch"):
        Installer(layout,fake_lifecycle_ops).install_verified(
            tmp_path/"candidate.tar.zst","0.1.0-beta.1",fake_lifecycle_ops.verified_bootstrap_preflight,
        )
    assert fake_lifecycle_ops.facade_registration_count==0
    assert fake_lifecycle_ops.handler_composition_count==0
    assert fake_lifecycle_ops.service_load_count==0
    assert not layout.current.exists()


@pytest.mark.parametrize((
    "search_enabled","namespace_present","optional_present","down_revision",
),(
    (False,True,True,None),
    (False,False,True,None),
    (True,False,False,None),
    (True,True,False,None),
    (True,True,True,"0008_prepared_mutations"),
))
def test_clean_install_blocks_mismatched_search_migration_namespace(
    tmp_path,fake_lifecycle_ops,search_enabled,namespace_present,
    optional_present,down_revision,
):
    fake_lifecycle_ops.search_enabled=search_enabled
    fake_lifecycle_ops.database_heads=("0008_prepared_mutations",)
    fake_lifecycle_ops.search_database_heads=(
        ("search_0001_experimental_search",) if search_enabled else ()
    )
    fake_lifecycle_ops.search_version_table_present=search_enabled
    fake_lifecycle_ops.optional_search_namespace_present=namespace_present
    fake_lifecycle_ops.optional_search_revision_present=optional_present
    fake_lifecycle_ops.optional_search_down_revision=down_revision
    layout=ReleaseLayout.for_home(tmp_path)
    with pytest.raises(RuntimeError,match="phase1 migration graph mismatch"):
        Installer(layout,fake_lifecycle_ops).install_verified(
            tmp_path/"candidate.tar.zst","0.1.0-beta.1",fake_lifecycle_ops.verified_bootstrap_preflight,
        )
    assert fake_lifecycle_ops.facade_registration_count==0
    assert fake_lifecycle_ops.handler_composition_count==0
    assert fake_lifecycle_ops.service_load_count==0
    assert not layout.current.exists()


@pytest.mark.parametrize(("search_enabled","table_present","search_heads"),(
    (False,True,()),
    (False,True,("search_0001_experimental_search",)),
    (True,False,()),
    (True,True,()),
    (True,True,("search_wrong",)),
    (True,True,("search_0001_experimental_search","search_extra")),
))
def test_clean_install_blocks_wrong_search_version_table_or_head(
    tmp_path,fake_lifecycle_ops,search_enabled,table_present,search_heads,
):
    fake_lifecycle_ops.search_enabled=search_enabled
    fake_lifecycle_ops.database_heads=("0008_prepared_mutations",)
    fake_lifecycle_ops.search_version_table_present=table_present
    fake_lifecycle_ops.search_database_heads=search_heads
    fake_lifecycle_ops.optional_search_namespace_present=search_enabled
    fake_lifecycle_ops.optional_search_revision_present=search_enabled
    fake_lifecycle_ops.optional_search_down_revision=None
    layout=ReleaseLayout.for_home(tmp_path)
    with pytest.raises(RuntimeError,match="phase1 migration head mismatch"):
        Installer(layout,fake_lifecycle_ops).install_verified(
            tmp_path/"candidate.tar.zst","0.1.0-beta.1",fake_lifecycle_ops.verified_bootstrap_preflight,
        )
    assert fake_lifecycle_ops.facade_registration_count==0
    assert fake_lifecycle_ops.handler_composition_count==0
    assert fake_lifecycle_ops.service_load_count==0
    assert not layout.current.exists()


@pytest.mark.parametrize("mutation",(
    "extra_feature_revision","duplicate_feature_revision",
    "feature_branch_label","feature_depends_on",
))
def test_clean_install_blocks_nonexact_search_feature_graph(
    tmp_path,fake_lifecycle_ops,mutation,
):
    fake_lifecycle_ops.search_enabled=True
    fake_lifecycle_ops.database_heads=("0008_prepared_mutations",)
    fake_lifecycle_ops.search_version_table_present=True
    fake_lifecycle_ops.search_database_heads=("search_0001_experimental_search",)
    fake_lifecycle_ops.optional_search_namespace_present=True
    fake_lifecycle_ops.optional_search_revision_present=True
    fake_lifecycle_ops.optional_search_down_revision=None
    fake_lifecycle_ops.optional_search_graph_mutation=mutation
    layout=ReleaseLayout.for_home(tmp_path)
    with pytest.raises(RuntimeError,match="phase1 migration graph mismatch"):
        Installer(layout,fake_lifecycle_ops).install_verified(
            tmp_path/"candidate.tar.zst","0.1.0-beta.1",fake_lifecycle_ops.verified_bootstrap_preflight,
        )
    assert fake_lifecycle_ops.service_load_count==0
    assert not layout.current.exists()


@pytest.mark.parametrize(("mandatory_down_revision","privacy_down_revision"),(
    ("0006_timers","0006_timers"),
    ("0007_privacy_post_response_jobs","0005_memory_embeddings"),
))
def test_clean_install_blocks_forked_mandatory_migration_tail(
    tmp_path,fake_lifecycle_ops,mandatory_down_revision,privacy_down_revision,
):
    fake_lifecycle_ops.search_enabled=False
    fake_lifecycle_ops.database_heads=("0008_prepared_mutations",)
    fake_lifecycle_ops.optional_search_revision_present=False
    fake_lifecycle_ops.mandatory_phase1_down_revision=mandatory_down_revision
    fake_lifecycle_ops.privacy_jobs_down_revision=privacy_down_revision
    layout=ReleaseLayout.for_home(tmp_path)
    with pytest.raises(RuntimeError,match="phase1 migration graph mismatch"):
        Installer(layout,fake_lifecycle_ops).install_verified(
            tmp_path/"candidate.tar.zst","0.1.0-beta.1",fake_lifecycle_ops.verified_bootstrap_preflight,
        )
    assert fake_lifecycle_ops.service_load_count==0
    assert not layout.current.exists()


@pytest.mark.parametrize("mutation",(
    "hidden_branch_and_merge","extra_orphan_revision","0003_wrong_parent",
))
def test_clean_install_blocks_nonexact_packaged_migration_graph(
    tmp_path,fake_lifecycle_ops,mutation,
):
    fake_lifecycle_ops.search_enabled=False
    fake_lifecycle_ops.database_heads=("0008_prepared_mutations",)
    fake_lifecycle_ops.optional_search_revision_present=False
    fake_lifecycle_ops.migration_graph_mutation=mutation
    layout=ReleaseLayout.for_home(tmp_path)
    with pytest.raises(RuntimeError,match="phase1 migration graph mismatch"):
        Installer(layout,fake_lifecycle_ops).install_verified(
            tmp_path/"candidate.tar.zst","0.1.0-beta.1",fake_lifecycle_ops.verified_bootstrap_preflight,
        )
    assert fake_lifecycle_ops.service_load_count==0
    assert not layout.current.exists()


def test_public_install_has_no_security_bypass_flags():
    import inspect
    assert tuple(inspect.signature(Installer.install_verified).parameters) == (
        "self","bundle","version","preflight",
    )

def test_forged_preflight_result_never_unlinks_an_existing_runtime(tmp_path,fake_lifecycle_ops):
    layout=ReleaseLayout.for_home(tmp_path)
    fake_lifecycle_ops.seed(layout,"0.1.0-alpha.1",b"encrypted-old")
    with pytest.raises(RuntimeError,match="trusted bootstrap unavailable"):
        Installer(layout,fake_lifecycle_ops).install_verified(
            tmp_path/"candidate.tar.zst","0.1.0-beta.1",object(),
        )
    assert layout.current.resolve().name=="0.1.0-alpha.1"


def test_clean_install_rejects_existing_runtime_without_overwrite(tmp_path,fake_lifecycle_ops):
    layout=ReleaseLayout.for_home(tmp_path)
    fake_lifecycle_ops.seed(layout,"0.1.0-alpha.1",b"encrypted-old")
    prior_link=layout.current.readlink()
    with pytest.raises(RuntimeError,match="existing_runtime_detected_use_upgrade"):
        Installer(layout,fake_lifecycle_ops).install_verified(tmp_path/"candidate.tar.zst","0.1.0-beta.1",fake_lifecycle_ops.verified_bootstrap_preflight)
    assert layout.current.readlink()==prior_link
    assert layout.current.resolve().name=="0.1.0-alpha.1"
    assert fake_lifecycle_ops.bundle_unpack_calls==0

def test_partial_initialization_failure_attempts_every_recorded_inverse_and_keeps_primary_error(
    tmp_path,fake_lifecycle_ops,
):
    layout=ReleaseLayout.for_home(tmp_path)
    fake_lifecycle_ops.fail_after_side_effect="sqlcipher:init"
    fake_lifecycle_ops.cleanup_fault="keychain:rollback"
    with pytest.raises(RuntimeError,match="injected sqlcipher:init") as caught:
        Installer(layout,fake_lifecycle_ops).install_verified(tmp_path/"candidate.tar.zst","0.1.0-beta.1",fake_lifecycle_ops.verified_bootstrap_preflight)
    assert str(caught.value)=="injected sqlcipher:init"
    assert set(fake_lifecycle_ops.recovery_record.attempted_recovery_steps) >= {
        "staging:remove","initialization:rollback","current:restore","service:unload",
    }
    assert fake_lifecycle_ops.recovery_record.state=="needs_owner_recovery"
```

```python
# tests/integration/deploy/test_atomic_upgrade.py
import pytest
from tuntun_core.deploy.lifecycle import ReleaseLayout,UpgradeCoordinator
def test_upgrade_backs_up_verifies_and_switches_atomically(tmp_path,fake_lifecycle_ops):
    layout=ReleaseLayout.for_home(tmp_path); fake_lifecycle_ops.seed(layout,"0.1.0-alpha.1",b"encrypted-old")
    fake_lifecycle_ops.events.clear()
    result=UpgradeCoordinator(layout,fake_lifecycle_ops).apply(tmp_path/"candidate.tar.zst","0.1.0-beta.1")
    assert result=="0.1.0-beta.1" and layout.current.resolve().name=="0.1.0-beta.1"
    assert fake_lifecycle_ops.events[:4]==["preflight:upgrade","backup:create","backup:verify","bundle:verify"]
    assert fake_lifecycle_ops.events[-10:]==[
        "database:migrate","database:head:verify","service:start","candidate:privacy_probe","candidate:listener_probe",
        "candidate:storage_probe","candidate:network_probe","candidate:device_probe","readiness:check",
        "protocol:verify",
    ]

@pytest.mark.parametrize("failed_probe", ["privacy","listener","storage","network","device"])
def test_each_candidate_probe_failure_rolls_back_inside_upgrade_boundary(
    tmp_path, fake_lifecycle_ops, failed_probe,
):
    layout=ReleaseLayout.for_home(tmp_path); fake_lifecycle_ops.seed(layout,"0.1.0-alpha.1",b"encrypted-old")
    fake_lifecycle_ops.candidate_probe_failure=failed_probe
    with pytest.raises(RuntimeError,match="candidate verification failed"):
        UpgradeCoordinator(layout,fake_lifecycle_ops).apply(tmp_path/"candidate.tar.zst","0.1.0-beta.1")
    assert layout.current.resolve().name=="0.1.0-alpha.1"
    assert layout.database.read_bytes()==b"encrypted-old"

def test_absent_to_enabled_search_uses_candidate_namespace_and_keeps_core_head(
    tmp_path,fake_lifecycle_ops,
):
    layout=ReleaseLayout.for_home(tmp_path)
    fake_lifecycle_ops.seed(
        layout,"0.1.0-alpha.1",b"encrypted-old",search_enabled=False,
    )
    fake_lifecycle_ops.search_enabled=True
    fake_lifecycle_ops.database_heads=("0008_prepared_mutations",)
    fake_lifecycle_ops.search_version_table_present=True
    fake_lifecycle_ops.search_database_heads=("search_0001_experimental_search",)
    fake_lifecycle_ops.optional_search_namespace_present=True
    fake_lifecycle_ops.optional_search_revision_present=True
    fake_lifecycle_ops.optional_search_down_revision=None
    UpgradeCoordinator(layout,fake_lifecycle_ops).apply(
        tmp_path/"candidate.tar.zst","0.1.0-beta.1",
    )
    assert layout.current.resolve().name=="0.1.0-beta.1"
    assert fake_lifecycle_ops.observed_database_heads==("0008_prepared_mutations",)
    assert fake_lifecycle_ops.observed_search_database_heads==(
        "search_0001_experimental_search",
    )


@pytest.mark.parametrize(("search_enabled","database_heads"),(
    (False,("0007_privacy_post_response_jobs",)),
    (False,("0007_privacy_post_response_jobs","0008_prepared_mutations")),
    (True,("0007_privacy_post_response_jobs",)),
    (True,("0007_privacy_post_response_jobs","0008_prepared_mutations")),
))
def test_upgrade_restores_prior_runtime_when_core_migration_head_is_not_exact(
    tmp_path,fake_lifecycle_ops,search_enabled,database_heads,
):
    layout=ReleaseLayout.for_home(tmp_path)
    fake_lifecycle_ops.seed(layout,"0.1.0-alpha.1",b"encrypted-old")
    fake_lifecycle_ops.search_enabled=search_enabled
    fake_lifecycle_ops.database_heads=database_heads
    with pytest.raises(RuntimeError,match="phase1 migration head mismatch"):
        UpgradeCoordinator(layout,fake_lifecycle_ops).apply(
            tmp_path/"candidate.tar.zst","0.1.0-beta.1",
        )
    assert layout.current.resolve().name=="0.1.0-alpha.1"
    assert layout.database.read_bytes()==b"encrypted-old"
    assert fake_lifecycle_ops.candidate_start_count==0


@pytest.mark.parametrize((
    "search_enabled","namespace_present","optional_present","down_revision",
),(
    (False,True,True,None),
    (False,False,True,None),
    (True,False,False,None),
    (True,True,False,None),
    (True,True,True,"0008_prepared_mutations"),
))
def test_upgrade_restores_prior_for_search_namespace_packaging_mismatch(
    tmp_path,fake_lifecycle_ops,search_enabled,namespace_present,
    optional_present,down_revision,
):
    layout=ReleaseLayout.for_home(tmp_path)
    fake_lifecycle_ops.seed(layout,"0.1.0-alpha.1",b"encrypted-old")
    fake_lifecycle_ops.search_enabled=search_enabled
    fake_lifecycle_ops.database_heads=("0008_prepared_mutations",)
    fake_lifecycle_ops.search_database_heads=(
        ("search_0001_experimental_search",) if search_enabled else ()
    )
    fake_lifecycle_ops.search_version_table_present=search_enabled
    fake_lifecycle_ops.optional_search_namespace_present=namespace_present
    fake_lifecycle_ops.optional_search_revision_present=optional_present
    fake_lifecycle_ops.optional_search_down_revision=down_revision
    with pytest.raises(RuntimeError,match="phase1 migration graph mismatch"):
        UpgradeCoordinator(layout,fake_lifecycle_ops).apply(
            tmp_path/"candidate.tar.zst","0.1.0-beta.1",
        )
    assert layout.current.resolve().name=="0.1.0-alpha.1"
    assert layout.database.read_bytes()==b"encrypted-old"
    assert fake_lifecycle_ops.candidate_start_count==0


@pytest.mark.parametrize(("search_enabled","table_present","search_heads"),(
    (False,True,()),
    (True,False,()),
    (True,True,()),
    (True,True,("search_wrong",)),
    (True,True,("search_0001_experimental_search","search_extra")),
))
def test_upgrade_restores_prior_for_wrong_search_version_table_or_head(
    tmp_path,fake_lifecycle_ops,search_enabled,table_present,search_heads,
):
    layout=ReleaseLayout.for_home(tmp_path)
    fake_lifecycle_ops.seed(layout,"0.1.0-alpha.1",b"encrypted-old")
    fake_lifecycle_ops.search_enabled=search_enabled
    fake_lifecycle_ops.database_heads=("0008_prepared_mutations",)
    fake_lifecycle_ops.search_version_table_present=table_present
    fake_lifecycle_ops.search_database_heads=search_heads
    fake_lifecycle_ops.optional_search_namespace_present=search_enabled
    fake_lifecycle_ops.optional_search_revision_present=search_enabled
    fake_lifecycle_ops.optional_search_down_revision=None
    with pytest.raises(RuntimeError,match="phase1 migration head mismatch"):
        UpgradeCoordinator(layout,fake_lifecycle_ops).apply(
            tmp_path/"candidate.tar.zst","0.1.0-beta.1",
        )
    assert layout.current.resolve().name=="0.1.0-alpha.1"
    assert layout.database.read_bytes()==b"encrypted-old"
    assert fake_lifecycle_ops.candidate_start_count==0


def test_enabled_to_absent_search_teardown_uses_prior_namespace_before_link_switch(
    tmp_path,fake_lifecycle_ops,
):
    layout=ReleaseLayout.for_home(tmp_path)
    fake_lifecycle_ops.seed(
        layout,"0.1.0-alpha.1",b"encrypted-old",search_enabled=True,
    )
    fake_lifecycle_ops.search_enabled=False
    result=UpgradeCoordinator(layout,fake_lifecycle_ops).apply(
        tmp_path/"candidate.tar.zst","0.1.0-beta.1",
    )
    assert result=="0.1.0-beta.1"
    assert fake_lifecycle_ops.events.index("search_namespace:teardown") < fake_lifecycle_ops.events.index("link:switch")
    assert fake_lifecycle_ops.search_version_table_present is False
    assert fake_lifecycle_ops.search_database_heads==()
    assert fake_lifecycle_ops.feature_dispatch_withdrawn
    assert fake_lifecycle_ops.unconsumed_children_revoked
    assert fake_lifecycle_ops.begun_attempts_settled_once
    assert fake_lifecycle_ops.signed_feature_removal_receipt_verified


def test_mismatched_prior_search_manifest_and_database_blocks_before_link_switch(
    tmp_path,fake_lifecycle_ops,
):
    layout=ReleaseLayout.for_home(tmp_path)
    fake_lifecycle_ops.seed(
        layout,"0.1.0-alpha.1",b"encrypted-old",search_enabled=False,
    )
    fake_lifecycle_ops.search_version_table_present=True
    fake_lifecycle_ops.search_database_heads=("search_0001_experimental_search",)
    fake_lifecycle_ops.search_enabled=False
    with pytest.raises(RuntimeError,match="installed experimental search state mismatch"):
        UpgradeCoordinator(layout,fake_lifecycle_ops).apply(
            tmp_path/"candidate.tar.zst","0.1.0-beta.1",
        )
    assert fake_lifecycle_ops.link_switch_count==0
    assert layout.current.resolve().name=="0.1.0-alpha.1"


@pytest.mark.parametrize("failure",("search_namespace:teardown","database:head:verify"))
def test_enabled_to_absent_search_teardown_failure_or_later_failure_restores_prior(
    tmp_path,fake_lifecycle_ops,failure,
):
    layout=ReleaseLayout.for_home(tmp_path)
    fake_lifecycle_ops.seed(
        layout,"0.1.0-alpha.1",b"encrypted-old",search_enabled=True,
    )
    fake_lifecycle_ops.search_enabled=False; fake_lifecycle_ops.fail_at=failure
    with pytest.raises(RuntimeError):
        UpgradeCoordinator(layout,fake_lifecycle_ops).apply(
            tmp_path/"candidate.tar.zst","0.1.0-beta.1",
        )
    assert layout.current.resolve().name=="0.1.0-alpha.1"
    assert layout.database.read_bytes()==b"encrypted-old"
    assert fake_lifecycle_ops.prior_search_namespace_restored


@pytest.mark.parametrize(("mandatory_down_revision","privacy_down_revision"),(
    ("0006_timers","0006_timers"),
    ("0007_privacy_post_response_jobs","0005_memory_embeddings"),
))
def test_upgrade_restores_prior_for_forked_mandatory_migration_tail(
    tmp_path,fake_lifecycle_ops,mandatory_down_revision,privacy_down_revision,
):
    layout=ReleaseLayout.for_home(tmp_path)
    fake_lifecycle_ops.seed(layout,"0.1.0-alpha.1",b"encrypted-old")
    fake_lifecycle_ops.search_enabled=False
    fake_lifecycle_ops.database_heads=("0008_prepared_mutations",)
    fake_lifecycle_ops.optional_search_revision_present=False
    fake_lifecycle_ops.mandatory_phase1_down_revision=mandatory_down_revision
    fake_lifecycle_ops.privacy_jobs_down_revision=privacy_down_revision
    with pytest.raises(RuntimeError,match="phase1 migration graph mismatch"):
        UpgradeCoordinator(layout,fake_lifecycle_ops).apply(
            tmp_path/"candidate.tar.zst","0.1.0-beta.1",
        )
    assert layout.current.resolve().name=="0.1.0-alpha.1"
    assert layout.database.read_bytes()==b"encrypted-old"
    assert fake_lifecycle_ops.candidate_start_count==0


@pytest.mark.parametrize("mutation",(
    "hidden_branch_and_merge","extra_orphan_revision","0003_wrong_parent",
))
def test_upgrade_restores_prior_for_nonexact_packaged_migration_graph(
    tmp_path,fake_lifecycle_ops,mutation,
):
    layout=ReleaseLayout.for_home(tmp_path)
    fake_lifecycle_ops.seed(layout,"0.1.0-alpha.1",b"encrypted-old")
    fake_lifecycle_ops.search_enabled=False
    fake_lifecycle_ops.database_heads=("0008_prepared_mutations",)
    fake_lifecycle_ops.optional_search_revision_present=False
    fake_lifecycle_ops.migration_graph_mutation=mutation
    with pytest.raises(RuntimeError,match="phase1 migration graph mismatch"):
        UpgradeCoordinator(layout,fake_lifecycle_ops).apply(
            tmp_path/"candidate.tar.zst","0.1.0-beta.1",
        )
    assert layout.current.resolve().name=="0.1.0-alpha.1"
    assert layout.database.read_bytes()==b"encrypted-old"
    assert fake_lifecycle_ops.candidate_start_count==0
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
    assert all(step in fake_lifecycle_ops.events for step in (
        "service:stop","link:restore","database:restore","candidate:remove",
        "staging:remove","service:start","protocol:verify",
    ))
    assert fake_lifecycle_ops.recovery_record.state == "recovered"

@pytest.mark.parametrize("rollback_fault", [
    "service:stop","link:restore","database:restore","candidate:remove",
    "staging:remove","service:start","protocol:verify",
])
def test_rollback_attempts_every_step_and_preserves_primary_failure(
    tmp_path,fake_lifecycle_ops,rollback_fault,
):
    layout=ReleaseLayout.for_home(tmp_path); fake_lifecycle_ops.seed(layout,"0.1.0-alpha.1",b"encrypted-old")
    fake_lifecycle_ops.ready_result=False; fake_lifecycle_ops.rollback_fault=rollback_fault
    with pytest.raises(RuntimeError,match="candidate readiness failed") as caught:
        UpgradeCoordinator(layout,fake_lifecycle_ops).apply(tmp_path/"candidate.tar.zst","0.1.0-beta.1")
    assert str(caught.value) == "candidate readiness failed"
    assert set(fake_lifecycle_ops.recovery_record.attempted_recovery_steps) == {
        "service:stop","link:restore","database:restore","candidate:remove",
        "staging:remove","service:start","protocol:verify",
    }
    assert fake_lifecycle_ops.recovery_record.state == "needs_owner_recovery"
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
from tuntun_core.bootstrap.container import require_final_phase1_migration_state
from tuntun_core.deploy import native_bootstrap
from tuntun_core.deploy.bootstrap_preflight import (
    VerifiedBootstrapPreflight,production_clean_bootstrap_preflight,
)
@dataclass(frozen=True,slots=True)
class ReleaseLayout:
    runtime:Path; releases:Path; current:Path; data:Path; database:Path; models:Path; backups:Path; logs:Path; launch_agent:Path
    @classmethod
    def for_home(cls,home):
        root=home/"Library/Application Support/Tuntun"; runtime=root/"runtime"
        return cls(runtime,runtime/"releases",runtime/"current",root/"data",root/"data/tuntun.db",root/"models",root/"backups",home/"Library/Logs/Tuntun",home/"Library/LaunchAgents/com.tuntun.core.plist")
def atomic_link(link,target):
    temporary=link.with_name(".current.next"); temporary.unlink(missing_ok=True); temporary.symlink_to(target); os.replace(temporary,link)
def _recorded(ops,record,name,operation,inverse):
    return ops.run_recorded_step(record,name,operation,inverse)
def verify_candidate_inside_boundary(ops):
    for probe in ("privacy","listener","storage","network","device"):
        if not ops.candidate_probe(probe):
            raise RuntimeError("candidate verification failed: "+probe)
def require_release_database_head(ops,database):
    with ops.open_migration_connection(database) as connection:
        return require_final_phase1_migration_state(
            connection,ops.alembic_script_directory(),
            ops.experimental_search_script_directory(),
            search_enabled=ops.experimental_search_enabled(),
        )
class Installer:
    def __init__(self,layout,ops): self.layout,self.ops=layout,ops
    def _stage_verified(self,bundle,version,record):
        self.ops.require_active_record(record)
        self.ops.validate_release_version(version)
        stage=self.layout.releases/("."+version+".staging"); destination=self.layout.releases/version
        _recorded(self.ops,record,"bundle_verified",lambda:self.ops.verify_bundle(bundle,version),{"action":"none"})
        _recorded(self.ops,record,"bundle_unpacked",lambda:self.ops.unpack(bundle,stage),{"action":"remove_tree","path":str(stage)})
        _recorded(self.ops,record,"bundle_staged",lambda:stage.rename(destination),{"action":"remove_tree","path":str(destination)})
        return destination
    def _attempt_clean_recovery(self,record,destination):
        stage=self.layout.releases/("."+record.version+".staging")
        steps=(
            ("service:unload",lambda:self.ops.unload(self.layout.launch_agent) if self.ops.was_started(record,"service_loaded") else None),
            ("current:restore",lambda:self.ops.remove_link_if_target(self.layout.current,destination) if self.ops.was_started(record,"link_switched") else None),
            ("candidate:remove",lambda:self.ops.remove_owned_tree(destination,record) if self.ops.was_started(record,"bundle_staged") else None),
            ("staging:remove",lambda:self.ops.remove_owned_tree(stage,record) if self.ops.was_started(record,"bundle_unpacked") else None),
            ("initialization:rollback",lambda:self.ops.rollback_completed_initialization(record)),
            ("launch_agent:remove",lambda:self.ops.remove_owned_launch_agent(self.layout.launch_agent,record) if self.ops.was_started(record,"launch_agent") else None),
        )
        self.ops.attempt_all_and_record(record,steps)
    def install_verified(self,bundle,version,preflight):
        if (type(preflight) is not VerifiedBootstrapPreflight
            or preflight.authority_kind!="one_use_bootstrap"
            or preflight.report.ok is not True):
            raise RuntimeError("trusted bootstrap unavailable")
        native_bootstrap.verify_one_use_preflight_seal_read_only(
            preflight._seal,approval=preflight.approval,report=preflight.report,
            candidate_bundle=bundle,
        )
        if self.layout.current.exists() or self.layout.current.is_symlink():
            raise RuntimeError("existing_runtime_detected_use_upgrade")
        approval,record=self.ops.claim_bootstrap_and_begin_record(
            preflight=preflight,
            mode="install",bundle=bundle,version=version,
        )
        destination=self.layout.releases/version
        try:
            _recorded(self.ops,record,"purpose_roots",lambda:self.ops.initialize_purpose_roots(self.layout,mode=0o700),{"action":"rollback_initialized_roots"})
            destination=self._stage_verified(bundle,version,record)
            _recorded(self.ops,record,"keychain",self.ops.initialize_keychain_items,{"action":"delete_record_owned_keychain_items"})
            _recorded(self.ops,record,"installed_authority",lambda:self.ops.publish_and_reopen_installed_authority(approval,destination),{"action":"remove_record_owned_installed_authority_and_pin"})
            _recorded(self.ops,record,"sqlcipher",lambda:self.ops.initialize_sqlcipher_and_migrate(self.layout.database),{"action":"restore_or_remove_record_owned_database"})
            _recorded(self.ops,record,"migration_head_verified",lambda:require_release_database_head(self.ops,self.layout.database),{"action":"none"})
            _recorded(self.ops,record,"audit_genesis",self.ops.initialize_and_verify_audit_genesis,{"action":"rollback_record_owned_audit_genesis"})
            _recorded(self.ops,record,"household_ca",self.ops.initialize_household_ca,{"action":"delete_record_owned_household_ca"})
            _recorded(self.ops,record,"backup_recipient",self.ops.initialize_backup_recipient,{"action":"delete_record_owned_backup_recipient"})
            _recorded(self.ops,record,"recovery_ceremony",self.ops.complete_and_verify_recovery_ceremony,{"action":"invalidate_record_owned_recovery_material"})
            _recorded(self.ops,record,"launch_agent",lambda:self.ops.install_launch_agent(self.layout.launch_agent),{"action":"remove_record_owned_launch_agent"})
            _recorded(self.ops,record,"link_switched",lambda:atomic_link(self.layout.current,destination),{"action":"remove_link_if_target","target":str(destination)})
            _recorded(self.ops,record,"service_loaded",lambda:self.ops.load(self.layout.launch_agent),{"action":"unload_record_owned_service"})
            verify_candidate_inside_boundary(self.ops)
            if not self.ops.ready(): raise RuntimeError("installed service readiness failed")
            self.ops.preflight("verify-installed")
            self.ops.finish_record(record,"complete")
            return destination
        except BaseException as primary:
            try: self._attempt_clean_recovery(record,destination)
            except BaseException as recovery_error:
                try: self.ops.note_unhandled_recovery_error(record,recovery_error)
                except BaseException: pass
            raise primary.with_traceback(primary.__traceback__)
    def uninstall_preserving_state(self):
        self.ops.unload(self.layout.launch_agent); self.layout.launch_agent.unlink(missing_ok=True)
        if self.layout.runtime.exists(): shutil.rmtree(self.layout.runtime)
        return self.layout.data,self.layout.models,self.layout.backups

def production_clean_install(*,candidate_dir,authorization_path,owner_trust_path,
        owner_presence_receipt_path,home):
    # The native bootstrap context supplies the signed bundle/version identity;
    # neither value is accepted from a caller or environment variable.
    preflight=production_clean_bootstrap_preflight(
        candidate_dir=candidate_dir,authorization_path=authorization_path,
        owner_trust_path=owner_trust_path,
        owner_presence_receipt_path=owner_presence_receipt_path,home=home,
    )
    bundle,version=native_bootstrap.bound_install_inputs(preflight._seal)
    layout=ReleaseLayout.for_home(home)
    return Installer(layout,ProductionLifecycleOps.for_native_context()).install_verified(
        bundle,version,preflight,
    )

class UpgradeCoordinator:
    def __init__(self,layout,ops): self.layout,self.ops=layout,ops
    def apply(self,bundle,version):
        record=self.ops.begin_record("upgrade",bundle=bundle,version=version)
        previous=None; backup=None; candidate=None
        try:
            previous=self.layout.current.resolve(strict=True)
            _recorded(self.ops,record,"preflight",lambda:self.ops.preflight("upgrade"),{"action":"none"})
            backup=self.ops.allocate_backup_path(record)
            _recorded(self.ops,record,"backup_created",lambda:self.ops.backup_to(backup),{"action":"retain_encrypted_backup","path":str(backup)})
            _recorded(self.ops,record,"backup_verified",lambda:self.ops.verify_backup(backup),{"action":"none"})
            candidate=Installer(self.layout,self.ops)._stage_verified(bundle,version,record)
            _recorded(self.ops,record,"prior_service_stopped",self.ops.stop,{"action":"start_prior_service"})
            installed_search=self.ops.require_exact_installed_experimental_search_state(
                previous,self.layout.database,
            )
            candidate_search=self.ops.require_exact_candidate_experimental_search_state(
                candidate,
            )
            if installed_search and not candidate_search:
                def remove_search_namespace():
                    proof=self.ops.require_fresh_local_owner_proof(
                        "remove_experimental_search",
                    )
                    receipt=self.ops.remove_experimental_search_before_artifact_switch(
                        previous,self.layout.database,proof,
                    )
                    self.ops.verify_feature_removal_receipt(
                        receipt,feature="experimental_search",
                        removed_head="search_0001_experimental_search",
                        candidate=candidate,
                    )
                _recorded(
                    self.ops,record,"search_namespace_torn_down",
                    remove_search_namespace,
                    {"action":"restore_database","backup":str(backup)},
                )
                self.ops.verify_experimental_search_namespace_absent(
                    self.layout.database,
                )
            _recorded(self.ops,record,"link_switched",lambda:atomic_link(self.layout.current,candidate),{"action":"restore_link","target":str(previous)})
            _recorded(self.ops,record,"database_migrated",self.ops.migrate,{"action":"restore_database","backup":str(backup)})
            _recorded(self.ops,record,"migration_head_verified",lambda:require_release_database_head(self.ops,self.layout.database),{"action":"none"})
            _recorded(self.ops,record,"candidate_started",self.ops.start,{"action":"stop_candidate"})
            verify_candidate_inside_boundary(self.ops)
            if not self.ops.ready(): raise RuntimeError("candidate readiness failed")
            self.ops.verify_protocol(); self.ops.finish_record(record,"complete"); return version
        except BaseException as primary:
            steps=(
                ("service:stop",lambda:self.ops.stop() if self.ops.was_started(record,"candidate_started") else None),
                ("link:restore",lambda:atomic_link(self.layout.current,previous) if previous is not None and self.ops.was_started(record,"link_switched") else None),
                ("database:restore",lambda:self.ops.restore_database(backup) if backup is not None and (self.ops.was_started(record,"search_namespace_torn_down") or self.ops.was_started(record,"database_migrated")) else None),
                ("candidate:remove",lambda:self.ops.remove_owned_tree(candidate,record) if candidate is not None and self.ops.was_started(record,"bundle_staged") else None),
                ("staging:remove",lambda:self.ops.remove_owned_tree(self.layout.releases/("."+record.version+".staging"),record) if self.ops.was_started(record,"bundle_unpacked") else None),
                ("service:start",lambda:self.ops.start() if self.ops.was_started(record,"prior_service_stopped") else None),
                ("protocol:verify",lambda:self.ops.verify_protocol() if self.ops.was_started(record,"prior_service_stopped") else None),
            )
            try: self.ops.attempt_all_and_record(record,steps)
            except BaseException as recovery_error:
                try: self.ops.note_unhandled_recovery_error(record,recovery_error)
                except BaseException: pass
            raise primary.with_traceback(primary.__traceback__)
```

The signed candidate shell exposes clean `install` only with the four explicit bootstrap-kit/candidate paths above; installed `tuntunctl update` exposes only `apply|repair|resume-recovery|uninstall`. Neither accepts `--skip-preflight`, `--skip-init`, `--stage-only`, `--no-activate`, direct approval strings, serialized preflight results, or equivalent environment variables. The plist sets explicit current/config/log paths, `KeepAlive`, throttle 10, `SoftResourceLimits/Core=0`, files `1024`, processes `128`, and no secret environment. Clean install completes descriptor-verified bootstrap preflight before managed-state mutation and passes the one sealed `VerifiedBootstrapPreflight` unchanged through the same process. The lifecycle consumer verifies it read-only, then its first managed mutation exclusively publishes/fsyncs the full approval/report claim and only afterward consumes the seal and opens its durable record. It never reruns preflight or treats a nonce as sufficient authority; pre-claim crashes may safely retry and post-claim failures can never reuse the authorization. It creates owner-only purpose-separated roots and the target Keychain item, derives/publishes/reopens the installed-purpose authority plus owner pin, and only then provisions and migrates SQLCipher. It queries the actual core and feature-version rows and enumerates both packaged migration namespaces before any facade, handler, service load, installed command, or readiness side effect. Every build packages exactly the linear core revisions `0001_foundation` through sole `alembic_version` head `0008_prepared_mutations`, with every frozen parent edge and no branch label, dependency, extra base, fork, merge, or orphan. An absent-search build omits the search migration namespace and `alembic_version_experimental_search` table. An enabled build adds the independent one-revision namespace `search_0001_experimental_search` (`down_revision=None`) and that exact sole feature-table head; it never extends or forks the core graph. Any inventory, edge, metadata, feature-state, version-table, or head mismatch blocks. Only then does install append and reopen audit genesis, create the household CA, configure the age backup recipient, and complete a restore/recovery ceremony before linking or readiness. Every completed initialization boundary is fsync-recorded and has an idempotent inverse; the nonce claim intentionally survives every failure so the same authorization cannot restart. Upgrade/repair require the reopened installed authority and Keychain pin, invoke Privacy Shield/provider drain, verify an encrypted backup, and stage the candidate; they never invoke bootstrap verification. For enabled-to-absent search they stop the prior service, obtain fresh local owner proof, and invoke the still-installed feature manager to withdraw dispatch, revoke unconsumed children, drain/cancel and conservatively settle begun attempts once, downgrade/remove both feature tables and its version table, and issue a signed content-minimal removal receipt. The deployer verifies that receipt and namespace absence, and records database restoration as the inverse, all before switching the artifact link; a failure during removal or any later candidate step restores the backup and prior runtime. Other transitions migrate only after switching to scripts that actually package their namespace. The same core/feature packaging/head gate runs before starting the candidate, followed by Privacy Shield generation/ack truth, exact listeners, SQLCipher/audit/roots, observed outbound DNS/socket policy, and commissioned Reachy identity/transport probes before readiness and protocol verification. Failure recovery attempts every step even when an earlier step fails, persists each outcome, retains the original exception as the public failure, and ends `needs_owner_recovery` rather than claiming rollback when any inverse failed. `resume-recovery` accepts only the opaque durable record ID and repeats remaining idempotent inverses; it cannot stage or activate a candidate. Docs contain exact commands and preserving semantics.

- [ ] **Step 4: Run green**

Run: `chmod +x deploy/macos/{install,upgrade,rollback,uninstall}.sh && shellcheck deploy/macos/*.sh && plutil -lint deploy/macos/com.tuntun.core.plist && uv run pytest tests/integration/deploy/test_atomic_install.py tests/integration/deploy/test_atomic_upgrade.py tests/integration/deploy/test_atomic_rollback.py tests/integration/deploy/test_uninstall_preserves_data.py -q && uv run ruff check apps/core/src/tuntun_core/deploy/lifecycle.py tests/integration/deploy && uv run mypy apps/core/src/tuntun_core/deploy/lifecycle.py`

Expected: PASS for clean install, upgrade, exact linear core `0001_foundation` through sole head `0008_prepared_mutations`, exact absent/enabled packaging and version-table state for independent `search_0001_experimental_search`, safe enabled-to-absent teardown before artifact switch, no hidden branch/merge/orphan/dependency/label, every graph/head/table mismatch rolling back before candidate start, ordinary/faulted rollback, installed plist/core limit, and preserving uninstall; tools exit `0`.

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
**Depends on:** Tasks 1–2, conversation Task 08's operator-state/core-command owner, master/conversation Task 12's qualified local and assistant lifecycle APIs, and conversation Task 13's concrete managed edge composition
**Estimated effort:** 1.5 person-days

**Files:**
- Create: `deploy/reachy/app.toml`
- Create: `deploy/reachy/build_app.sh`
- Create: `deploy/reachy/install_app.sh`
- Create: `deploy/reachy/install_recovery_hook.sh`
- Create: `deploy/reachy/install_payload.sh`
- Create: `deploy/reachy/recover_install.sh`
- Create: `deploy/reachy/recovery_bootstrap.py`
- Create: `deploy/reachy/uninstall_app.sh`
- Create: `deploy/reachy/entrypoint.sh`
- Create: `ops/services/phase1-reachy-edge.v1.json`
- Modify: `apps/edge/pyproject.toml`
- Modify: `apps/edge/src/tuntun_edge/cli/main.py`
- Create: `apps/edge/src/tuntun_edge/cli/verify_install.py`
- Create: `apps/core/src/tuntun_core/services/reachy/release_qualification.py`
- Modify: `apps/core/src/tuntun_core/cli/commands/reachy.py`
- Modify: `tests/integration/cli/test_reachy_commands.py`
- Modify: `uv.lock`
- Create: `scripts/verify_reachy_wheelhouse.py`
- Create: `scripts/verify_reachy_archive.py`
- Create: `scripts/deterministic_tar.py`
- Test: `tests/integration/deploy/test_reachy_package.py`
- Test: `tests/integration/deploy/test_reachy_service_inventory.py`
- Test: `tests/hardware/test_edge_package.py`
- Create: `docs/operations/install-reachy.md`

**Interfaces:** `build_app.sh` requires `REACHY_SDK_VERSION`, `REACHY_DAEMON_VERSION`, `REACHY_PYTHON_EXECUTABLE=/venvs/apps_venv/bin/python3`, exact probed `REACHY_PYTHON_VERSION`, `REACHY_PYTHON_ABI`, `REACHY_SELECTED_WHEEL_TAG=py3-none-any`, `REACHY_TARGET_TAG_SET_SHA256`, `REACHY_RUNTIME_INVENTORY_SHA256`, and `SOURCE_DATE_EPOCH`. The interpreter pair is only `3.11/cp311` or `3.12/cp312`; all values come from Task 08's accepted owner-only projection and Task 12's current local re-probe. It builds exactly the two Python-3.11/3.12-compatible pure Tuntun project wheels and rejects any tag other than `py3-none-any`; it does not download or pretend to rebuild the Reachy SDK, PyGObject, or other vendor/native dependencies. Those dependencies remain in the accepted onboard `/venvs/apps_venv` environment whose exact closed inventory and target-tag-set digests are bound into the artifact. The repository's pinned 3.12 build-time archive writer runs as `python -m scripts.deterministic_tar`; host build Python is not represented as the target runtime. The build produces `dist/tuntun-edge-0.1.0-beta.1.tar.gz`, its `.sha256`, and its canonical `.manifest.json` sidecar, plus in-archive `compatibility.json: tuntun.reachy-compatibility.v1` bound to the exact target projection, `uv.lock`, and wheelhouse manifest. Public `install_app.sh <archive: Path> -> exit 0|65|70` consumes exactly `$1`, obtains the accepted key-only `<probed-user>@<numeric-IP>` target and target-interpreter path from the no-network operator reader, verifies its adjacent checksum and closed archive manifest, transfers the exact inventory into a fresh owner-only target stage, and extracts only verified bytes. Password/KbdInteractive authentication remain disabled and no literal SSH username exists in release code. Before any `journal/`, `current`, or `releases/` mutation, private `install_payload.sh` re-probes the complete accepted runtime projection, creates and validates one owner-only stable lock, holds it with a 30-second fail-closed interprocess timeout, atomically installs `recovery_bootstrap.py` outside all candidate directories, registers it as the assistant's durable boot-only hook ordered before managed apps, and reopens the durable registration proof. After the payload rename it creates an isolated venv with the accepted interpreter and `--system-site-packages`, installs only the two verified Tuntun wheels with `--no-index --no-deps`, and performs a no-network import/metadata probe of the complete closed edge closure before link switch or registration. Exact `websockets==15.0.1` and the installed Reachy SDK constraint must agree. The same journal installs the Task-11 firewall code and locked runtime as an immutable generation under `base/firewall/releases`, atomically switches `base/firewall/current`, installs the two exact root-owned systemd units, daemon-reloads and enables them only after all bytes/digests/modes match, then proves emergency/normal policy and a current boot receipt before managed-app registration. No `/opt/tuntun/current`, `tuntun-edge.service`, or service drop-in exists. `entrypoint.sh` resolves only the active release beneath `base/releases`, invokes the fixed current `boot_gate.py --require-current-boot-receipt` before importing edge code, executes that final environment, and never invokes `uv`. Installer and boot hook use the same inode/lock protocol; recovery invoked by the installer lock holder receives only the inherited verified lock FD. The boot hook has no dependency on `current` or a candidate and therefore recovers a blank target after a kill before first registration. It is not invoked by ordinary register/start, and `entrypoint.sh` never tries to reacquire the installer lock, so the installer retains the global lock through firewall activation, register, candidate start, health verification, and the durable `complete` write without deadlock or an exposed mutation window. Recovery fsyncs a closed JSON journal and parent around every transition, restores prior-or-absent firewall generation/unit enablement and daemon state with documented idempotency, and treats every other daemon failure as `needs_owner_recovery`. Only after recovery does the installer atomically rename immutable payload bytes to the final release path and create its venv with the accepted interpreter. `uninstall_app.sh -> exit 0|70`; after the managed app and recovery hook are durably absent it disables both exact units, removes only their files/runtime and `inet tuntun` table, verifies restored non-Tuntun connectivity/no Tuntun listener, and never touches another unit/table/app. Managed app ID is exactly `com.tuntun.edge`.

`ops/services/phase1-reachy-edge.v1.json` is the sole signed service-family row for target kind `reachy_managed_app`. It binds the final archive/checksum/manifest roles, `com.tuntun.edge`, stable recovery hook, exact entrypoint/CLI, immutable firewall runtime, both unit digests, effective account, configuration/key/runtime roots and modes, listener/firewall policy, restart/health deadlines and the precise preserve/destroy cleanup sets. Its target is present exactly when Reachy support is enabled in the signed feature manifest; otherwise the archive, registration, hook, units, account/runtime/listener and target row are absent. Later whole-program install/update/uninstall consumes this row and its target-orchestrator receipts rather than pretending the Mac owns Reachy paths.

The release maps public SemVer `0.1.0-beta.1` to Python PEP 440 `0.1.0b1`; `app.toml`, edge wheel metadata, installed distribution, final release basename, and artifact identity must agree before registration. Task 08 owns the sole edge console script, conversation Task 13 owns `managed`, and this task extends the same edge dispatcher with `verify-install --app-root --compatibility --artifact-sha256`; no second edge entry point is allowed. This task also extends Task 08's existing core `tuntunctl reachy` group—without replacing its read commands—with exactly `network-counters --json`, `reboot --wait-seconds 1..300`, and `verify-reboot --synthetic-turn --expected-artifact-sha256 HEX --json`. The concrete `ReachyReleaseQualificationService.from_fixed_commissioning()` uses only the current owner-owned commissioned Reachy-device numeric target, pinned SSH host key, fixed argv (never a shell), bounded stdout/stderr, and Task-12-qualified assistant APIs. Network-counter reads use a ten-second deadline; reboot uses the validated caller bound; verification uses 120 seconds. Counters are a persistent monotonic tuple `(counter_epoch,cumulative_package_download_dns_or_connect_count,boot_uuid)` so reset/epoch drift cannot masquerade as zero network use. Reboot success requires a changed Task-12 boot UUID—not just disconnect/reappearance—and durably writes a nofollow owner-only `RebootWitnessV1` bound to before/after boot UUID, commissioning generation/target/host key, and installed artifact. `verify-reboot` reopens that exact unconsumed witness and current state before its checks. It returns closed canonical projections for managed-app state, restored pairing generation, exact listeners, offline essentials, synthetic-turn result, installed artifact digest, and reboot witness. Timeout, disconnect, host-key/generation drift, counter rollback/reset, malformed/oversized/duplicate/extra output, unchanged boot UUID, stale/missing/consumed witness, or any mismatch exits `70` with no fabricated success JSON.

Master Task 12 must qualify the delivered assistant's exact `recovery-hook verify-absent --require-durable`, `stop|unregister --if-present`, durable hook-unregister, and bounded `inventory --json` semantics. “Absent” is a distinct successful result; timeout, permission, transport, malformed output, or contradictory inventory is never normalized as absence. Production Mac wrappers use `uv run --frozen --offline --no-sync` only to resolve the already-commissioned numeric target and cannot sync or download dependencies.

- [ ] **Step 1: Write failing package/reboot tests**

```python
# tests/integration/deploy/test_reachy_package.py
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path
import pytest
from scripts.verify_reachy_archive import EXECUTABLE_MEMBERS,verify
def test_manifest_is_pinned_managed_and_offline():
    value=tomllib.loads(Path("deploy/reachy/app.toml").read_text())
    assert value["app"]=={"id":"com.tuntun.edge","version":"0.1.0-beta.1","entrypoint":"entrypoint.sh","managed_by":"reachy-mini-app-assistant"}
    assert value["runtime"]=={
        "python_source":"compatibility.json",
        "telemetry":False,"network_downloads":False,
    }

def test_signed_reachy_service_row_matches_managed_app_and_firewall_bundle(service_inventory):
    row=service_inventory.load("ops/services/phase1-reachy-edge.v1.json")
    assert row.service_family_id=="phase1-reachy-edge.v1"
    assert row.target_kind=="reachy_managed_app"
    assert row.managed_app_id=="com.tuntun.edge"
    assert row.systemd_units==(
        "tuntun-reachy-firewall-baseline.service",
        "tuntun-reachy-firewall.service",
    )
    assert "tuntun-edge.service" not in row.packaged_paths
    assert row.entrypoint_first_effect=="require_current_boot_receipt"
    assert row.target_artifact_digest==service_inventory.final_reachy_archive_digest

def test_reachy_target_absence_is_cryptographically_complete(service_inventory):
    absent=service_inventory.build(feature="reachy",enabled=False)
    assert absent.row("phase1-reachy-edge.v1") is None
    assert absent.managed_app_units_accounts_runtime_listeners_for("com.tuntun.edge")==()

def test_public_and_python_release_versions_map_exactly() -> None:
    edge=tomllib.loads(Path("apps/edge/pyproject.toml").read_text())
    app=tomllib.loads(Path("deploy/reachy/app.toml").read_text())
    assert edge["project"]["version"]=="0.1.0b1"
    assert app["app"]["version"]=="0.1.0-beta.1"
    assert {"0.1.0b1":"0.1.0-beta.1"}[edge["project"]["version"]]==app["app"]["version"]

def test_installer_passes_the_exact_release_root_to_verify_install() -> None:
    script=" ".join(Path("deploy/reachy/install_payload.sh").read_text().split())
    assert ('"$destination/.venv/bin/tuntun-edge" verify-install '
            '--app-root "$destination" '
            '--compatibility "$destination/compatibility.json" '
            '--artifact-sha256 "$artifact_sha256"') in script

def test_clean_offline_wheel_exposes_the_one_complete_root_dispatcher(
    clean_target_mac_build,repo_free_edge_venv,
) -> None:
    archive=clean_target_mac_build("edge-cli")
    environment=repo_free_edge_venv.install_archive_wheels(archive,offline=True)
    assert environment.console_scripts()=={"tuntun-edge"}
    assert environment.distribution_version("tuntun-edge")=="0.1.0b1"
    assert environment.tuntun_edge_root_commands()=={
        "reachy","managed","verify-install",
    }
    assert environment.cwd_has_no_repository and environment.pythonpath_is_absent

def test_release_extends_the_one_core_reachy_group_repo_free(
    repo_free_core_cli,qualified_reachy_lifecycle,deny_dns_and_shell,
) -> None:
    assert repo_free_core_cli.reachy_commands()=={
        "compatibility","commissioned-ssh-target","network-counters",
        "reboot","verify-reboot",
    }
    counters=repo_free_core_cli.run(
        "tuntunctl","reachy","network-counters","--json",
        frozen=True,offline=True,no_sync=True,
    )
    assert counters.exit_code==0
    assert json.loads(counters.stdout)=={
        "boot_uuid":"00000000-0000-4000-8000-000000000001",
        "commissioning_generation":1,
        "counter_epoch":"a"*64,
        "cumulative_package_download_dns_or_connect_count":0,
        "firewall_generation":1,
        "sample_sequence":1,
        "schema_version":"tuntun.reachy-network-counters.v1",
    }
    assert deny_dns_and_shell.calls==()

@pytest.mark.parametrize("fault",(
    "ssh_timeout","host_key_drift","generation_drift","oversized",
    "deep_json","duplicate_key","extra_field","counter_rollback",
    "counter_epoch_drift","sample_sequence_rollback",
))
def test_network_counter_faults_are_read_only_and_fail_closed(
    repo_free_core_cli,qualified_reachy_lifecycle,fault,
) -> None:
    qualified_reachy_lifecycle.inject(fault)
    result=repo_free_core_cli.run(
        "tuntunctl","reachy","network-counters","--json",
        frozen=True,offline=True,no_sync=True,
    )
    assert result.exit_code==70 and result.stdout==""
    assert result.mutation_calls==()

@pytest.mark.parametrize(("fault","expected_reboot_attempts"),(
    ("ssh_timeout",0),("host_key_drift",0),("generation_drift",0),
    ("no_reboot_disconnect",1),("no_reboot_reappearance",1),
    ("unchanged_boot_uuid",1),("witness_write_failure",1),
))
def test_reboot_requires_changed_boot_uuid_and_durable_witness(
    repo_free_core_cli,qualified_reachy_lifecycle,fault,expected_reboot_attempts,
) -> None:
    qualified_reachy_lifecycle.inject(fault)
    result=repo_free_core_cli.run(
        "tuntunctl","reachy","reboot","--wait-seconds","120",
        frozen=True,offline=True,no_sync=True,
    )
    assert result.exit_code==70 and result.stdout==""
    assert result.authorized_reboot_attempts==expected_reboot_attempts
    assert result.success_witness_count==0

@pytest.mark.parametrize("fault",(
    "missing_witness","stale_witness","consumed_witness","current_boot_mismatch",
    "artifact_mismatch","listener_mismatch","pairing_mismatch",
    "offline_essentials_failure","synthetic_turn_failure","oversized",
    "deep_json","duplicate_key","extra_field",
))
def test_verify_reboot_faults_are_read_only_and_fail_closed(
    repo_free_core_cli,qualified_reachy_lifecycle,fault,
) -> None:
    qualified_reachy_lifecycle.inject(fault)
    result=repo_free_core_cli.run(
        "tuntunctl","reachy","verify-reboot","--synthetic-turn",
        "--expected-artifact-sha256","a"*64,"--json",
        frozen=True,offline=True,no_sync=True,
    )
    assert result.exit_code==70 and result.stdout==""
    assert result.mutation_calls==()

@pytest.mark.parametrize("mismatch",(
    "unsafe_app_root","artifact_suffix","sdk","daemon","selected_wheel_tag",
    "python_executable","python_version","python_abi","uv_lock_hash",
    "target_tag_set_hash","runtime_inventory_hash","wheelhouse_hash","app_version",
    "edge_distribution_version","malformed_probe","probe_timeout",
))
def test_verify_install_rejects_every_compatibility_or_identity_mismatch_before_mutation(
    clean_target_mac_build,reachy_install_shell,mismatch,
):
    archive=clean_target_mac_build("verify-install-mismatch")
    reachy_install_shell.configure_verify_install_mismatch(mismatch)
    result=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    assert result.exit_code==70
    assert result.current_mutation_count==0
    assert result.managed_register_calls==0
    assert result.listener_count==0

def test_two_clean_target_mac_builds_are_byte_identical(clean_target_mac_build):
    first=clean_target_mac_build("clean-a")
    second=clean_target_mac_build("clean-b")
    assert first.read_bytes()==second.read_bytes()
    assert Path(str(first)+".manifest.json").read_bytes()==Path(str(second)+".manifest.json").read_bytes()
    with tarfile.open(fileobj=io.BytesIO(first.read_bytes()),mode="r:gz") as archive:
        members=archive.getmembers()
    assert [item.name for item in members]==sorted(item.name for item in members)
    assert all((item.uid,item.gid,item.uname,item.gname)==(0,0,"","") for item in members)
    assert all(item.mtime==clean_target_mac_build.source_date_epoch for item in members)
    for item in members:
        path=item.name.rstrip("/")
        expected=0o755 if item.isdir() or path in EXECUTABLE_MEMBERS else 0o644
        assert item.mode==expected

def test_build_does_not_depend_on_gnu_tar():
    script=Path("deploy/reachy/build_app.sh").read_text()
    assert "tar --sort" not in script and "--numeric-owner" not in script
    assert "python -m scripts.deterministic_tar" in script
    assert "python scripts/deterministic_tar.py" not in script

@pytest.mark.parametrize("version,abi",(("3.11","cp311"),("3.12","cp312")))
def test_build_threads_the_exact_accepted_target_tuple(
    clean_target_mac_build,version,abi,
) -> None:
    archive=clean_target_mac_build(
        f"target-{abi}",python_executable="/venvs/apps_venv/bin/python3",
        python_version=version,python_abi=abi,
        selected_wheel_tag="py3-none-any",
        target_tag_set_sha256="a"*64,
        runtime_inventory_sha256="b"*64,
    )
    assert archive.compatibility["python_version"]==version
    assert archive.compatibility["python_abi"]==abi
    assert archive.compatibility["selected_wheel_tag"]=="py3-none-any"
    assert archive.wheelhouse["tags"]==["py3-none-any"]

@pytest.mark.parametrize("mutation",(
    "unknown_python_path","cp310","version_abi_disagreement",
    "non_universal_project_wheel","tag_set_digest_mismatch",
    "runtime_inventory_digest_mismatch","tuple_env_missing",
))
def test_build_rejects_unaccepted_or_incomplete_target_tuple_before_output(
    clean_target_mac_build,mutation,
) -> None:
    with pytest.raises(BuildRejected):
        clean_target_mac_build("bad-target-tuple",tuple_mutation=mutation)
    assert not clean_target_mac_build.output_exists("bad-target-tuple")

def test_every_public_reachy_ssh_and_scp_call_uses_the_commissioned_pin() -> None:
    required=(
        "BatchMode=yes","PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no","StrictHostKeyChecking=yes",
        'UserKnownHostsFile="$known_hosts"',"ConnectTimeout=10",
        "ConnectionAttempts=1",
    )
    for path in (Path("deploy/reachy/install_app.sh"),Path("deploy/reachy/uninstall_app.sh")):
        text=path.read_text()
        assert "known_hosts=/private/var/lib/tuntun/reachy/known_hosts" in text
        assert "^reachy@" not in text and "^pollen@" not in text
        assert "[a-z_][a-z0-9_-]" in text
        transport_lines=[
            line for line in text.splitlines()
            if "ssh " in line or line.lstrip().startswith("scp ")
        ]
        assert transport_lines
        assert all(all(option in line for option in required) for line in transport_lines)

def test_archive_contains_only_pure_project_wheels(clean_target_mac_build):
    archive=clean_target_mac_build("offline-edge")
    with tarfile.open(archive,"r:gz") as value:
        names={item.name.rstrip("/") for item in value.getmembers()}
        entrypoint=value.extractfile("entrypoint.sh").read().decode()
        installer=value.extractfile("install_payload.sh").read().decode()
    assert {"locks/uv.lock","wheelhouse/manifest.json","entrypoint.sh","install_payload.sh","recover_install.sh","install_recovery_hook.sh","recovery_bootstrap.py"} <= names
    assert "requirements.lock" not in names
    assert any(name.startswith("wheelhouse/tuntun_edge-") and name.endswith(".whl") for name in names)
    assert any(name.startswith("wheelhouse/tuntun_contracts-") and name.endswith(".whl") for name in names)
    assert "uv run" not in entrypoint and ".venv/bin/tuntun-edge" in entrypoint
    assert "--system-site-packages" in installer
    assert "--no-index" in installer and "--no-deps" in installer
    assert "verify-install" in installer
    assert all(token not in installer for token in ("curl ","wget ","https://","http://"))

def test_build_never_downloads_or_repackages_vendor_native_dependencies() -> None:
    script=Path("deploy/reachy/build_app.sh").read_text()
    assert "pip download" not in script
    assert "--platform" not in script
    assert "--only-binary" not in script
    assert "uv build --frozen --package tuntun-contracts" in script
    assert "uv build --frozen --package tuntun-edge" in script

@pytest.mark.parametrize("fault",(
    "sdk_websocket_constraint_conflict","websocket_version_drift",
    "native_import_missing","target_tag_set_drift","runtime_inventory_drift",
    "venv_cannot_inherit_vendor_runtime","network_attempt",
))
def test_offline_target_runtime_probe_fails_before_registration(
    clean_target_mac_build,reachy_install_shell,fault,
) -> None:
    archive=clean_target_mac_build("runtime-closure")
    reachy_install_shell.inject_runtime_fault(fault)
    result=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    assert result.exit_code==70
    assert result.managed_register_calls==0
    assert result.current_target_unchanged
    assert result.candidate_rolled_back_or_never_created
    assert result.package_download_dns_or_connect_count==0

def test_extracted_wheelhouse_verifier_has_no_repository_import_dependency(
    clean_target_mac_build,tmp_path,
):
    archive=clean_target_mac_build("self-contained-wheelhouse-verifier")
    extracted=tmp_path/"extracted"
    verify(
        archive,hashlib.sha256(archive.read_bytes()).hexdigest(),
        Path(str(archive)+".manifest.json"),extracted,
    )
    environment=os.environ.copy(); environment.pop("PYTHONPATH",None)
    result=subprocess.run(
        (sys.executable,str(extracted/"verify_reachy_wheelhouse.py"),
         "--verify",str(extracted)),
        cwd=tmp_path,env=environment,text=True,capture_output=True,
    )
    assert result.returncode==0,result.stderr

def test_archive_verifier_cli_executes_write_and_verify_modes(
    clean_target_mac_build,tmp_path,
):
    archive=clean_target_mac_build("verifier-cli-smoke")
    manifest=tmp_path/"fresh.manifest.json"
    expected=hashlib.sha256(archive.read_bytes()).hexdigest()
    verifier=Path("scripts/verify_reachy_archive.py")
    subprocess.run(
        (sys.executable,str(verifier),"--archive",str(archive),
         "--write-manifest",str(manifest)),check=True,
    )
    subprocess.run(
        (sys.executable,str(verifier),"--archive",str(archive),
         "--manifest",str(manifest),"--expected-sha256",expected),check=True,
    )


def test_external_closed_manifest_exactly_equals_every_archive_member(
    clean_target_mac_build,
):
    archive=clean_target_mac_build("closed-inventory")
    manifest_path=Path(str(archive)+".manifest.json")
    manifest=json.loads(manifest_path.read_text())
    assert set(manifest)=={
        "schema_version","archive_sha256","manifest_location","members",
    }
    assert manifest["schema_version"]=="tuntun.reachy-archive-manifest.v1"
    assert manifest["manifest_location"]=={
        "kind":"adjacent_external_sidecar","archive_member":False,
        "suffix":".manifest.json",
    }
    assert manifest["archive_sha256"]==hashlib.sha256(archive.read_bytes()).hexdigest()
    with tarfile.open(archive,"r:gz") as value:
        members=value.getmembers()
    assert [item["path"] for item in manifest["members"]]==[item.name.rstrip("/") for item in members]
    assert all(set(item)=={"path","type","sha256","size","mode"} for item in manifest["members"])
    assert "archive-manifest.json" not in {item.name.rstrip("/") for item in members}


@pytest.mark.parametrize(
    "mutation",
    ("extra","duplicate","path","data_mode_to_executable",
     "executable_mode_to_data","size","boolean_for_zero_size","hash"),
)
def test_closed_manifest_rejects_every_archive_inventory_substitution(
    clean_target_mac_build,mutated_reachy_archive,mutation,
):
    original=clean_target_mac_build("inventory-substitution")
    changed=mutated_reachy_archive(
        original,mutation=mutation,rewrite_outer_checksum=True,
        retain_original_manifest=True,
    )
    with pytest.raises(RuntimeError,match="Reachy archive inventory mismatch|unsafe Reachy archive member"):
        verify(
            changed,changed.expected_sha256,changed.manifest_path,extract=None,
        )


def test_public_installer_transfers_and_installs_the_exact_argument(
    clean_target_mac_build, reachy_install_shell,
):
    archive=clean_target_mac_build("exact-public-installer")
    result=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    assert result.exit_code==0
    assert result.local_verified_archive==archive.resolve()
    assert result.transferred_archive_bytes==archive.read_bytes()
    assert result.transferred_manifest_bytes==Path(str(archive)+".manifest.json").read_bytes()
    assert result.remote_stage_mode==0o700 and result.remote_stage_was_fresh
    assert result.remote_verified_sha256==result.local_verified_sha256
    assert result.registered_app_id=="com.tuntun.edge"
    assert result.registered_artifact_sha256==result.local_verified_sha256


@pytest.mark.parametrize("unsafe_path",(
    "host:archive.tar.gz","-option.tar.gz","line\nbreak.tar.gz",
    "directory:remote/archive.tar.gz","directory/space name.tar.gz",
))
def test_public_installer_rejects_scp_ambiguous_path_before_external_call(
    reachy_install_shell,unsafe_path,
):
    archive=reachy_install_shell.seed_local_named_archive(unsafe_path)
    result=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    assert result.exit_code==65
    assert result.tuntunctl_calls==()
    assert result.ssh_calls==()
    assert result.scp_calls==()


def test_register_start_and_health_run_while_installer_keeps_global_lock(
    clean_target_mac_build,reachy_install_shell,
):
    archive=clean_target_mac_build("register-start-under-lock")
    result=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    assert result.exit_code==0 and result.health_probe_passed
    assert result.installer_lock_held_during_register_start
    assert result.installer_lock_held_during_health_probe
    assert result.entrypoint_recovery_lock_attempts==0
    assert result.boot_recovery_hook_invocations_during_register_start==0


@pytest.mark.parametrize("failed_step", ["venv","wheelhouse","pip","register","health"])
def test_every_target_install_failure_restores_prior_managed_app(
    clean_target_mac_build, reachy_install_shell, failed_step,
):
    archive=clean_target_mac_build("rollback-public-installer")
    prior=reachy_install_shell.seed_prior_managed_app("com.tuntun.edge")
    reachy_install_shell.fail_at=failed_step
    result=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    assert result.exit_code==70
    assert result.current_release==prior.release
    assert result.registered_entrypoint==prior.entrypoint
    assert result.journal_state=="recovered"


def test_venv_is_created_at_final_path_and_survives_stage_deletion_and_reboot(
    clean_target_mac_build,reachy_install_shell,
):
    archive=clean_target_mac_build("final-path-venv")
    result=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    assert result.exit_code==0
    final=result.final_release
    assert result.venv_creation_path==final/".venv"
    assert result.console_script_shebang("tuntun-edge")==f"#!{final}/.venv/bin/python"
    assert str(result.remote_stage) not in result.console_script_shebang("tuntun-edge")
    reachy_install_shell.delete_remote_stage(); reachy_install_shell.reboot()
    assert reachy_install_shell.managed_health()=="running"
    assert reachy_install_shell.synthetic_turn()=="completed"


@pytest.mark.parametrize("failed_step",("payload_move","venv","pip","register","health"))
def test_failure_after_final_move_removes_incomplete_destination_and_restores_prior(
    clean_target_mac_build,reachy_install_shell,failed_step,
):
    archive=clean_target_mac_build("final-path-rollback")
    prior=reachy_install_shell.seed_prior_managed_app("com.tuntun.edge")
    reachy_install_shell.fail_at=failed_step
    result=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    assert result.exit_code==70 and result.journal_state=="recovered"
    assert not result.incomplete_destination.exists()
    assert result.current_release==prior.release


@pytest.mark.parametrize("journal_state",(
    "preparing","payload_moved","venv_created","wheels_installed",
    "link_switched","registered",
))
@pytest.mark.parametrize("loss_mode",("sigkill","power_loss"))
@pytest.mark.parametrize("recovery_entry",("next_invocation","boot"))
def test_sigkill_or_power_loss_at_every_fsynced_state_recovers_idempotently_before_collision_check(
    clean_target_mac_build,reachy_install_shell,journal_state,loss_mode,recovery_entry,
):
    archive=clean_target_mac_build("hard-loss-recovery")
    prior=reachy_install_shell.seed_prior_managed_app("com.tuntun.edge")
    interrupted=reachy_install_shell.interrupt_after_fsynced_state(
        archive,journal_state,loss_mode=loss_mode,
    )
    assert interrupted.destination.exists() or journal_state=="preparing"
    first=reachy_install_shell.resume_via(recovery_entry,archive)
    second=reachy_install_shell.resume_via(recovery_entry,archive)
    assert first.recovery_ran_before_destination_check is True
    assert first.recovered_previous_release==prior.release
    assert second.journal_state in {"recovered","complete"}
    assert reachy_install_shell.incomplete_release_count()==0


def test_truly_completed_journal_is_a_boot_noop(reachy_install_shell,completed_install):
    before=completed_install.snapshot()
    reachy_install_shell.reboot(); reachy_install_shell.reboot()
    assert completed_install.snapshot()==before


def test_retry_after_complete_journal_is_fail_closed_and_preserves_runtime(
    clean_target_mac_build,reachy_install_shell,
):
    archive=clean_target_mac_build("completed-retry")
    first=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    before=first.snapshot()
    retry=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    assert retry.exit_code==65
    assert retry.journal_state=="complete"
    assert retry.snapshot()==before


@pytest.mark.parametrize("journal_state",(
    "preparing","payload_moved","venv_created","wheels_installed",
    "link_switched","registered",
))
@pytest.mark.parametrize("loss_mode",("sigkill","power_loss"))
def test_blank_target_boot_hook_recovers_every_fsynced_state_without_current_app(
    clean_target_mac_build,reachy_install_shell,journal_state,loss_mode,
):
    archive=clean_target_mac_build("blank-hard-loss")
    assert reachy_install_shell.current_release is None
    interrupted=reachy_install_shell.interrupt_after_fsynced_state(
        archive,journal_state,loss_mode=loss_mode,
    )
    assert interrupted.stable_hook_verified_before_first_journal_write
    assert interrupted.stable_hook_registration_fsynced
    assert interrupted.stable_hook_verified_before_first_current_or_release_mutation
    assert interrupted.stable_hook_path.parent.name=="recovery"
    assert str(interrupted.stable_hook_path).startswith(
        "/var/lib/reachy-mini-app-assistant/apps/com.tuntun.edge/"
    )
    reachy_install_shell.reboot_without_registered_app()
    assert reachy_install_shell.stable_boot_hook_invocations==1
    assert reachy_install_shell.current_release is None
    assert reachy_install_shell.registered_app is None
    assert reachy_install_shell.journal_state=="recovered"
    assert reachy_install_shell.incomplete_release_count()==0
    reachy_install_shell.reboot_without_registered_app()
    assert reachy_install_shell.journal_state=="recovered"


@pytest.mark.parametrize("contender",("second_installer","boot_recovery"))
def test_installer_and_recovery_are_serialized_by_one_process_wide_lock(
    clean_target_mac_build,reachy_install_shell,contender,
):
    first=clean_target_mac_build("lock-first")
    held=reachy_install_shell.pause_with_lock(first,state="wheels_installed")
    competing=reachy_install_shell.start_contender(contender,first,timeout_seconds=30)
    assert competing.has_not_mutated_journal_current_or_releases
    held.release(); first_result=held.wait(timeout_seconds=35)
    contender_result=competing.wait(timeout_seconds=35)
    assert first_result.exit_code==0
    assert contender_result.exit_code in {0,65,70}
    assert reachy_install_shell.maximum_simultaneous_lock_holders==1
    assert reachy_install_shell.current_release==first_result.final_release
    assert reachy_install_shell.registered_artifact_sha256==first_result.local_verified_sha256


@pytest.mark.parametrize("lock_fault",("wrong_owner","symlink","timeout"))
def test_lock_ownership_symlink_or_timeout_fails_before_shared_state_mutation(
    clean_target_mac_build,reachy_install_shell,lock_fault,
):
    archive=clean_target_mac_build("unsafe-lock")
    reachy_install_shell.configure_lock_fault(lock_fault)
    result=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    assert result.exit_code==70
    assert result.journal_write_count==0
    assert result.current_mutation_count==0
    assert result.release_mutation_count==0


def test_lock_replacement_race_cannot_follow_or_clobber_symlink_target(
    clean_target_mac_build,reachy_install_shell,tmp_path,
):
    archive=clean_target_mac_build("lock-replacement-race")
    protected=tmp_path/"protected"; protected.write_bytes(b"unchanged")
    reachy_install_shell.replace_lock_with_symlink_before_atomic_open(protected)
    result=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    assert result.exit_code==70
    assert protected.read_bytes()==b"unchanged"
    assert result.journal_write_count==0
    assert result.current_mutation_count==0
    assert result.release_mutation_count==0


@pytest.mark.parametrize("journal_fault",(
    "symlink","oversized","wrong_owner_or_mode","wrong_filename",
    "candidate_hash_mismatch","unsafe_candidate_version","overdepth",
    "excessive_structure_tokens","huge_exponent","wrong_root",
    "previous_false","previous_null","candidate_false","candidate_null",
))
def test_untrusted_recovery_journal_cannot_drive_link_or_delete_operations(
    reachy_install_shell,journal_fault,
):
    reachy_install_shell.seed_recovery_journal_fault(journal_fault)
    result=reachy_install_shell.reboot_without_registered_app()
    assert result.exit_code==70
    assert result.link_mutation_count==0
    assert result.release_delete_count==0
    assert result.daemon_mutation_count==0


def test_upgrade_recovers_incomplete_n_journal_with_verified_n_hook_before_installing_n_plus_1(
    clean_target_mac_build,reachy_install_shell,
):
    old=clean_target_mac_build("hook-n")
    interrupted=reachy_install_shell.interrupt_after_fsynced_state(
        old,"registered",loss_mode="sigkill",
    )
    successor=clean_target_mac_build("hook-n-plus-1")
    result=reachy_install_shell.run("deploy/reachy/install_app.sh",successor)
    assert result.exit_code==0
    assert result.event_order.index("verified_n_hook:recover_incomplete") < result.event_order.index("install_n_plus_1_hook")
    assert result.recovered_artifact_sha256==interrupted.artifact_sha256
    assert result.registered_artifact_sha256==result.local_verified_sha256
    reachy_install_shell.reboot()
    assert reachy_install_shell.journal_states <= {"recovered","complete"}


def test_blank_target_absent_stop_and_unregister_are_idempotent_but_real_failure_blocks(
    clean_target_mac_build,reachy_install_shell,
):
    archive=clean_target_mac_build("blank-rollback")
    reachy_install_shell.fail_at="venv"
    recovered=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    assert recovered.exit_code==70 and recovered.journal_state=="recovered"
    assert recovered.absent_stop_and_unregister_normalized
    reachy_install_shell.reset_blank(); reachy_install_shell.fail_at="venv"
    reachy_install_shell.daemon_failure="unregister_transport_error"
    blocked=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    assert blocked.exit_code==70 and blocked.journal_state=="needs_owner_recovery"


@pytest.mark.parametrize("loss_mode",("sigkill","power_loss"))
def test_blank_target_retry_self_heals_hook_file_rename_before_registration(
    clean_target_mac_build,reachy_install_shell,loss_mode,
):
    archive=clean_target_mac_build("hook-register-crash")
    interrupted=reachy_install_shell.interrupt_after_stable_hook_rename_before_registration(
        archive,loss_mode=loss_mode,
    )
    assert interrupted.stable_hook_file.exists()
    assert interrupted.recovery_hook_registered is False
    assert interrupted.journal_current_release_paths == ()
    rebooted=reachy_install_shell.reboot_without_registered_app()
    assert rebooted.stable_boot_hook_invocations==0
    assert rebooted.journal_current_release_paths==()
    result=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    assert result.exit_code==0
    assert result.recovery_hook_registered is True
    assert result.stable_hook_registration_fsynced is True
    assert result.event_order.index("recovery_hook_registered") < result.event_order.index("first_journal_or_release_mutation")


def test_blank_target_mismatched_orphan_hook_fails_before_state_mutation(
    clean_target_mac_build,reachy_install_shell,
):
    archive=clean_target_mac_build("hook-orphan-mismatch")
    reachy_install_shell.seed_unregistered_orphan_hook(b"not-the-candidate-hook")
    result=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    assert result.exit_code==70
    assert result.journal_write_count==0
    assert result.current_mutation_count==0
    assert result.release_mutation_count==0
    assert result.recovery_hook_registered is False


@pytest.mark.parametrize("daemon_fault",(
    "verify_timeout","verify_permission_denied","verify_malformed_result",
    "verify_contradictory_registration",
))
def test_blank_target_orphan_self_heal_requires_qualified_absent_registration(
    clean_target_mac_build,reachy_install_shell,daemon_fault,
):
    archive=clean_target_mac_build("hook-orphan-daemon-fault")
    reachy_install_shell.seed_matching_unregistered_orphan_hook(archive)
    reachy_install_shell.configure_recovery_hook_verification_fault(daemon_fault)
    result=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    assert result.exit_code==70
    assert result.journal_write_count==0
    assert result.current_mutation_count==0
    assert result.release_mutation_count==0
    assert result.recovery_hook_register_calls==0


def test_reachy_uninstall_is_preserving_idempotent_and_reinstallable(
    clean_target_mac_build,reachy_install_shell,
):
    archive=clean_target_mac_build("uninstall-reinstall")
    installed=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    pairing_before=reachy_install_shell.pairing_and_key_snapshot()
    unrelated_before=reachy_install_shell.unrelated_assistant_snapshot()
    removed=reachy_install_shell.run("deploy/reachy/uninstall_app.sh")
    assert removed.exit_code==0
    assert removed.daemon_attempts==(
        "stop:com.tuntun.edge","unregister:com.tuntun.edge",
        "recovery-hook-unregister:com.tuntun.edge","inventory",
    )
    assert removed.current_release is None
    assert removed.release_and_journal_paths==()
    assert removed.managed_app_registered is False
    assert removed.recovery_hook_registered is False
    assert reachy_install_shell.pairing_and_key_snapshot()==pairing_before
    assert reachy_install_shell.unrelated_assistant_snapshot()==unrelated_before
    reachy_install_shell.reboot_without_registered_app()
    assert reachy_install_shell.managed_process_count==0
    assert reachy_install_shell.run("deploy/reachy/uninstall_app.sh").exit_code==0
    reinstalled=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    assert reinstalled.exit_code==0 and reinstalled.health_probe_passed
    assert reinstalled.registered_artifact_sha256==installed.registered_artifact_sha256


@pytest.mark.parametrize("failed_step",(
    "recover","stop","unregister","first_inventory",
    "recovery_hook_unregister","final_inventory",
))
def test_uninstall_attempts_every_disable_action_and_preserves_state_on_failure(
    clean_target_mac_build,reachy_install_shell,failed_step,
):
    archive=clean_target_mac_build("uninstall-failure")
    reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    code_before=reachy_install_shell.managed_code_snapshot()
    unrelated_before=reachy_install_shell.unrelated_assistant_snapshot()
    reachy_install_shell.fail_uninstall_at=failed_step
    failed=reachy_install_shell.run("deploy/reachy/uninstall_app.sh")
    assert failed.exit_code==70
    assert set(failed.daemon_attempts)>={
        "stop:com.tuntun.edge","unregister:com.tuntun.edge","inventory",
    }
    if failed_step in {"recovery_hook_unregister","final_inventory"}:
        assert "recovery-hook-unregister:com.tuntun.edge" in failed.daemon_attempts
    assert reachy_install_shell.managed_code_snapshot()==code_before
    assert reachy_install_shell.unrelated_assistant_snapshot()==unrelated_before
    reachy_install_shell.fail_uninstall_at=None
    assert reachy_install_shell.run("deploy/reachy/uninstall_app.sh").exit_code==0


@pytest.mark.parametrize("loss_mode",("sigkill","power_loss"))
@pytest.mark.parametrize("boundary",(
    "intent_fsynced","stopped","app_unregistered","first_absence_proved",
    "hook_unregistered","final_absence_proved","current_removed",
    "releases_removed","journal_removed","helper_removed",
))
def test_uninstall_hard_loss_never_restarts_app_and_resumes_idempotently(
    clean_target_mac_build,reachy_install_shell,loss_mode,boundary,
):
    archive=clean_target_mac_build("uninstall-hard-loss")
    reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    interrupted=reachy_install_shell.interrupt_uninstall_after(
        boundary,loss_mode=loss_mode,
    )
    assert interrupted.uninstall_intent_was_fsynced
    rebooted=reachy_install_shell.reboot()
    assert rebooted.managed_process_count==0
    # Before durable hook removal the boot hook completes the intent; after it,
    # the public candidate helper resumes harmless code cleanup under the lock.
    resumed=(
        rebooted if rebooted.uninstall_complete else
        reachy_install_shell.run("deploy/reachy/uninstall_app.sh")
    )
    assert resumed.exit_code==0
    assert resumed.managed_app_registered is False
    assert resumed.recovery_hook_registered is False
    assert resumed.release_and_journal_paths==()


@pytest.mark.parametrize("fault",(
    "oversized_inventory","deep_inventory","duplicate_inventory_key","wrong_inventory_type",
    "contradictory_present_app","contradictory_present_hook",
    "current_symlink_escape","release_symlink","wrong_owner",
))
def test_uninstall_requires_bounded_absence_proof_before_code_deletion(
    clean_target_mac_build,reachy_install_shell,fault,
):
    archive=clean_target_mac_build("uninstall-proof")
    reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    before=reachy_install_shell.managed_code_snapshot()
    reachy_install_shell.configure_uninstall_fault(fault)
    result=reachy_install_shell.run("deploy/reachy/uninstall_app.sh")
    assert result.exit_code==70
    assert reachy_install_shell.managed_code_snapshot()==before
    assert result.unrelated_mutation_count==0


@pytest.mark.parametrize("contender",("installer","boot_recovery"))
def test_uninstall_serializes_with_install_and_boot_recovery(
    clean_target_mac_build,reachy_install_shell,contender,
):
    archive=clean_target_mac_build("uninstall-lock")
    reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    held=reachy_install_shell.pause_uninstall_with_global_lock()
    competing=reachy_install_shell.start_contender(contender,archive,timeout_seconds=30)
    assert competing.has_not_mutated_journal_current_or_releases
    held.release(); held.wait(timeout_seconds=35); competing.wait(timeout_seconds=35)
    assert reachy_install_shell.maximum_simultaneous_lock_holders==1


@pytest.mark.parametrize("inverse",(
    "stop","unlink_or_restore_current","unregister_or_register_prior","delete_candidate",
))
def test_power_loss_after_each_recovery_inverse_retries_before_terminal_record(
    clean_target_mac_build,reachy_install_shell,inverse,
):
    archive=clean_target_mac_build("inverse-durability")
    prior=reachy_install_shell.seed_prior_managed_app("com.tuntun.edge")
    reachy_install_shell.interrupt_after_fsynced_state(
        archive,"registered",loss_mode="sigkill",
    )
    interrupted=reachy_install_shell.power_loss_after_recovery_inverse(inverse)
    assert interrupted.journal_state not in {"recovered","complete"}
    recovered=reachy_install_shell.reboot()
    assert recovered.journal_state=="recovered"
    assert recovered.current_release==prior.release
    assert recovered.registered_entrypoint==prior.entrypoint
    assert recovered.incomplete_release_count()==0


@pytest.mark.parametrize("current_fault",(
    "regular_file","relative_symlink","escape_symlink","dangling_symlink",
    "target_wrong_owner_or_mode","replacement_race",
))
def test_hostile_current_type_or_target_blocks_before_journal_or_release_mutation(
    clean_target_mac_build,reachy_install_shell,current_fault,
):
    archive=clean_target_mac_build("hostile-current")
    reachy_install_shell.configure_current_fault(current_fault)
    result=reachy_install_shell.run("deploy/reachy/install_app.sh",archive)
    assert result.exit_code==70
    assert result.journal_write_count==0
    assert result.current_mutation_count==0
    assert result.release_mutation_count==0


@pytest.mark.parametrize("mutation",(
    "gzip_expansion_bomb","huge_pax_header","huge_gnu_longname",
    "gnu_sparse_member","bad_ustar_checksum","nonzero_tar_trailing_payload",
    "concatenated_gzip_member","gzip_trailing_bytes","nonzero_uid_gid",
    "nonzero_device_fields","nonempty_uname_gname_or_linkname",
    "mixed_member_mtime","nonzero_ustar_reserved_bytes","nul_regular_type",
))
def test_archive_preflight_rejects_metadata_bombs_and_hidden_trailing_payload(
    reachy_archive_fixture,mutation,
):
    archive,manifest,expected=reachy_archive_fixture.mutate_closed_archive(mutation)
    with pytest.raises(RuntimeError,match="USTAR|gzip|expanded|metadata|inventory"):
        reachy_archive_fixture.verify(archive,expected,manifest)
    assert reachy_archive_fixture.extract_write_count==0


@pytest.mark.parametrize(("target","mutation"),(
    ("external_manifest","overdepth"),
    ("external_manifest","excessive_containers"),
    ("external_manifest","excessive_structure_tokens"),
    ("external_manifest","unsafe_integer"),
    ("external_manifest","float"),
    ("compatibility","overdepth"),
    ("compatibility","unknown_field"),
    ("compatibility","wrong_sdk_type"),
    ("compatibility","wrong_daemon_type"),
    ("compatibility","wrong_platform_or_abi"),
))
def test_package_json_ingress_is_bounded_and_compatibility_is_closed_before_extract(
    reachy_archive_fixture,target,mutation,
):
    archive,manifest,expected=reachy_archive_fixture.mutate_json_ingress(
        target=target,mutation=mutation,rewrite_outer_checksum=True,
    )
    with pytest.raises(RuntimeError,match="inventory|compatibility"):
        reachy_archive_fixture.verify(archive,expected,manifest)
    assert reachy_archive_fixture.extract_write_count==0


@pytest.mark.parametrize("mutation",(
    "runtime_boolean_integer_alias","compatibility_boolean_integer_alias",
    "extra_top_level_section","missing_compatibility_section",
))
def test_app_toml_contract_is_exactly_typed_before_extract(
    reachy_archive_fixture,mutation,
):
    archive,manifest,expected=reachy_archive_fixture.mutate_app_manifest(
        mutation=mutation,rewrite_outer_checksum=True,
    )
    with pytest.raises(RuntimeError,match="Reachy app manifest mismatch"):
        reachy_archive_fixture.verify(archive,expected,manifest)
    assert reachy_archive_fixture.extract_write_count==0


@pytest.mark.parametrize("mutation",(
    "overdepth","excessive_containers","excessive_structure_tokens",
    "unsafe_integer","float","duplicate_key","boolean_for_zero_size",
))
def test_self_contained_wheelhouse_parser_rejects_hostile_manifest(
    reachy_wheelhouse_fixture,mutation,
):
    result=reachy_wheelhouse_fixture.run_verifier_with_manifest_fault(mutation)
    assert result.returncode!=0
    assert reachy_wheelhouse_fixture.install_attempt_count==0


def test_manifest_sidecar_symlink_or_create_race_never_overwrites_target(
    reachy_archive_fixture,tmp_path,
):
    archive=reachy_archive_fixture.valid_archive()
    protected=tmp_path/"protected"; protected.write_bytes(b"unchanged")
    output=tmp_path/"archive.manifest.json"; output.symlink_to(protected)
    with pytest.raises(RuntimeError,match="exists or is unsafe"):
        reachy_archive_fixture.write_manifest(archive,output)
    assert protected.read_bytes()==b"unchanged"
    reachy_archive_fixture.replace_manifest_name_during_exclusive_create(output,protected)
    with pytest.raises(RuntimeError,match="exists or is unsafe"):
        reachy_archive_fixture.write_manifest(archive,output)
    assert protected.read_bytes()==b"unchanged"
```

```python
# tests/hardware/test_edge_package.py
import json,os,subprocess,pytest

def run_core(*args):
    return subprocess.run(
        ("uv","run","--frozen","--offline","--no-sync","tuntunctl",*args),
        check=True,text=True,capture_output=True,
    ).stdout

def require_counter_shape(value):
    assert set(value)=={
        "schema_version","commissioning_generation","firewall_generation",
        "counter_epoch","boot_uuid","sample_sequence",
        "cumulative_package_download_dns_or_connect_count",
    }
    assert value["schema_version"]=="tuntun.reachy-network-counters.v1"
    assert type(value["commissioning_generation"]) is int
    assert type(value["firewall_generation"]) is int
    assert type(value["sample_sequence"]) is int
    assert type(value["cumulative_package_download_dns_or_connect_count"]) is int

@pytest.mark.reachy_hardware
def test_package_survives_real_reboot():
    if os.getenv("TUNTUN_ALLOW_REACHY_HARDWARE")!="1": pytest.skip("commissioned Reachy required")
    before=json.loads(run_core("reachy","network-counters","--json"))
    artifact=os.getenv("TUNTUN_REACHY_PACKAGE","dist/tuntun-edge-0.1.0-beta.1.tar.gz")
    assert os.path.isfile(artifact+".sha256") and os.path.isfile(artifact+".manifest.json")
    artifact_sha256=subprocess.run(("shasum","-a","256",artifact),check=True,text=True,capture_output=True).stdout.split()[0]
    subprocess.run(("deploy/reachy/install_app.sh",artifact),check=True,env={**os.environ,"PIP_NO_INDEX":"1"})
    installed=json.loads(run_core("reachy","network-counters","--json"))
    assert run_core("reachy","reboot","--wait-seconds","120")=="reboot_verified\n"
    verified=json.loads(run_core(
        "reachy","verify-reboot","--synthetic-turn",
        "--expected-artifact-sha256",artifact_sha256,"--json",
    ))
    after=json.loads(run_core("reachy","network-counters","--json"))
    for snapshot in (before,installed,after): require_counter_shape(snapshot)
    assert set(verified)=={
        "schema_version","managed_app","pairing","public_listeners",
        "offline_essentials","synthetic_turn","installed_artifact_sha256",
        "before_boot_uuid","after_boot_uuid","reboot_witness_sha256",
    }
    assert verified["schema_version"]=="tuntun.reachy-reboot-verification.v1"
    assert verified["managed_app"]=="running" and verified["pairing"]=="restored"
    assert verified["public_listeners"]==[] and verified["offline_essentials"] is True
    assert verified["synthetic_turn"]=="passed"
    assert verified["installed_artifact_sha256"]==artifact_sha256
    assert verified["before_boot_uuid"]==before["boot_uuid"]==installed["boot_uuid"]
    assert verified["after_boot_uuid"]==after["boot_uuid"]!=before["boot_uuid"]
    assert before["counter_epoch"]==installed["counter_epoch"]==after["counter_epoch"]
    assert before["commissioning_generation"]==installed["commissioning_generation"]==after["commissioning_generation"]
    assert before["firewall_generation"]==installed["firewall_generation"]==after["firewall_generation"]
    assert before["sample_sequence"]<installed["sample_sequence"]<after["sample_sequence"]
    assert before["cumulative_package_download_dns_or_connect_count"]==installed["cumulative_package_download_dns_or_connect_count"]==after["cumulative_package_download_dns_or_connect_count"]
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
python_source="compatibility.json"
telemetry=false
network_downloads=false
[compatibility]
sdk_pin_source="uv.lock"
daemon_pin_source="var/hardware/reachy-capabilities.json"
require_exact_match=true
```

```toml
# apps/edge/pyproject.toml (release transition; retain Task 08's sole script)
[project]
name = "tuntun-edge"
version = "0.1.0b1"
requires-python = ">=3.11,<3.13"

[project.scripts]
tuntun-edge = "tuntun_edge.cli.main:main"
```

```python
# apps/edge/src/tuntun_edge/cli/verify_install.py
import hashlib
import importlib.metadata
import os
import pathlib
import re
import stat
import tomllib

from tuntun_contracts.base import canonical_mapping_bytes,parse_bounded_json_value
from tuntun_edge.reachy.probe import probe_local_runtime_compatibility

BASE=pathlib.Path("/var/lib/reachy-mini-app-assistant/apps/com.tuntun.edge")
SHA256=re.compile(r"[0-9a-f]{64}")
RELEASE=re.compile(r"0[.]1[.]0-beta[.]1-([0-9a-f]{64})")
COMPATIBILITY_KEYS={
    "schema_version","sdk","daemon","python_executable","python_version",
    "python_abi","selected_wheel_tag","target_tag_set_sha256",
    "runtime_inventory_sha256",
    "uv_lock_sha256","wheelhouse_manifest_sha256","exact_match",
}

def _owned_regular_child(root:pathlib.Path,path:pathlib.Path,max_bytes:int) -> bytes:
    if path.parent!=root or path.is_symlink(): raise PermissionError("unsafe install file")
    flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0); fd=os.open(path,flags)
    try:
        opened=os.fstat(fd); named=path.stat(follow_symlinks=False)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid!=os.geteuid()
            or not 1<=opened.st_size<=max_bytes
            or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino)):
            raise PermissionError("unsafe install file")
        chunks=[]; remaining=opened.st_size
        while remaining:
            chunk=os.read(fd,remaining)
            if not chunk: raise ValueError("install file truncated")
            chunks.append(chunk); remaining-=len(chunk)
        if os.read(fd,1): raise ValueError("install file grew")
        raw=b"".join(chunks)
        after=os.fstat(fd); named_after=path.stat(follow_symlinks=False)
        if ((after.st_dev,after.st_ino,after.st_size)!=(opened.st_dev,opened.st_ino,opened.st_size)
            or (named_after.st_dev,named_after.st_ino)!=(opened.st_dev,opened.st_ino)):
            raise PermissionError("install file changed during read")
        return raw
    finally: os.close(fd)

def verify_install(app_root:pathlib.Path,compatibility_path:pathlib.Path,artifact_sha256:str) -> None:
    if (not app_root.is_absolute() or app_root.parent!=BASE/"releases"
        or SHA256.fullmatch(artifact_sha256) is None):
        raise PermissionError("unsafe install root")
    metadata=app_root.stat(follow_symlinks=False); match=RELEASE.fullmatch(app_root.name)
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=os.geteuid()
        or stat.S_IMODE(metadata.st_mode)!=0o700 or match is None
        or match.group(1)!=artifact_sha256):
        raise PermissionError("install identity mismatch")
    if compatibility_path!=app_root/"compatibility.json":
        raise PermissionError("compatibility must be exact app-root child")
    raw=_owned_regular_child(app_root,compatibility_path,4096)
    value=parse_bounded_json_value(raw,max_bytes=4096)
    if (type(value) is not dict or set(value)!=COMPATIBILITY_KEYS
        or any(type(value[key]) is not str for key in COMPATIBILITY_KEYS-{"exact_match"})
        or value["exact_match"] is not True
        or raw!=canonical_mapping_bytes(value)+b"\n"):
        raise ValueError("closed compatibility manifest invalid")
    observed=probe_local_runtime_compatibility(timeout_seconds=5,network=False)
    if (value["schema_version"]!="tuntun.reachy-compatibility.v1"
        or (value["sdk"],value["daemon"],value["python_executable"],
            value["python_version"],value["python_abi"],
            value["selected_wheel_tag"],value["target_tag_set_sha256"],
            value["runtime_inventory_sha256"])
        !=(observed.sdk,observed.daemon,observed.python_executable,
           observed.python_version,observed.python_abi,
           observed.selected_wheel_tag,observed.target_tag_set_sha256,
           observed.runtime_inventory_sha256)
        or value["python_executable"]!="/venvs/apps_venv/bin/python3"
        or (value["python_version"],value["python_abi"])
           not in {("3.11","cp311"),("3.12","cp312")}
        or value["selected_wheel_tag"]!="py3-none-any"
        or SHA256.fullmatch(value["target_tag_set_sha256"]) is None
        or SHA256.fullmatch(value["runtime_inventory_sha256"]) is None):
        raise RuntimeError("Reachy runtime compatibility mismatch")
    expected_hashes={
        "uv_lock_sha256":app_root/"locks/uv.lock",
        "wheelhouse_manifest_sha256":app_root/"wheelhouse/manifest.json",
    }
    for field,path in expected_hashes.items():
        body=_owned_regular_child(path.parent,path,8_388_608)
        if SHA256.fullmatch(value[field]) is None or hashlib.sha256(body).hexdigest()!=value[field]:
            raise RuntimeError("Reachy locked content mismatch")
    app=tomllib.loads(_owned_regular_child(app_root,app_root/"app.toml",4096).decode("utf-8"))
    if (app.get("app",{}).get("version")!="0.1.0-beta.1"
        or importlib.metadata.version("tuntun-edge")!="0.1.0b1"):
        raise RuntimeError("Reachy release version mismatch")

def add_parser(subparsers) -> None:
    parser=subparsers.add_parser("verify-install",allow_abbrev=False)
    parser.add_argument("--app-root",type=pathlib.Path,required=True)
    parser.add_argument("--compatibility",type=pathlib.Path,required=True)
    parser.add_argument("--artifact-sha256",required=True)
    parser.set_defaults(command_handler=execute)

def execute(args) -> int:
    verify_install(args.app_root,args.compatibility,args.artifact_sha256)
    return 0
```

```python
# apps/edge/src/tuntun_edge/cli/main.py (final Task 3 extension)
from tuntun_edge.cli import managed,reachy_commission,verify_install

def build_parser() -> argparse.ArgumentParser:
    parser=ClosedArgumentParser(prog="tuntun-edge",allow_abbrev=False)
    subparsers=parser.add_subparsers(dest="command",required=True)
    reachy_commission.add_parser(subparsers)
    managed.add_parser(subparsers)
    verify_install.add_parser(subparsers)
    return parser
```

```python
# apps/core/src/tuntun_core/cli/commands/reachy.py (Release Task 3 additions)
import re

from tuntun_core.services.reachy.release_qualification import (
    ReachyReleaseQualificationService,
)

ARTIFACT_SHA256=re.compile(r"[0-9a-f]{64}")


def _release_service() -> ReachyReleaseQualificationService:
    return ReachyReleaseQualificationService.from_fixed_commissioning()


@app.command("network-counters")
def network_counters(
    json_output: bool=typer.Option(False,"--json"),
) -> None:
    if not json_output:
        raise typer.BadParameter("--json is required")
    _emit(_release_service().network_counters_canonical_json)


@app.command("reboot")
def reboot(
    wait_seconds: int=typer.Option(...,"--wait-seconds",min=1,max=300),
) -> None:
    _emit(lambda:_release_service().reboot_and_wait(wait_seconds))


@app.command("verify-reboot")
def verify_reboot(
    synthetic_turn: bool=typer.Option(False,"--synthetic-turn"),
    expected_artifact_sha256: str=typer.Option(...,"--expected-artifact-sha256"),
    json_output: bool=typer.Option(False,"--json"),
) -> None:
    if (not synthetic_turn or not json_output
        or ARTIFACT_SHA256.fullmatch(expected_artifact_sha256) is None):
        raise typer.BadParameter("closed reboot verification arguments required")
    _emit(lambda:_release_service().verify_reboot_canonical_json(
        expected_artifact_sha256=expected_artifact_sha256,
        require_synthetic_turn=True,
    ))
```

`apps/core/src/tuntun_core/services/reachy/release_qualification.py` is the concrete adapter behind these handlers. It composes Task 08's `ReachyOperatorReader` with the pinned, argv-only commissioned SSH runner; captures every assistant response through the foundation bounded duplicate-safe canonical parser (32 KiB, depth 4, 32 containers, 256 structural tokens); accepts only the named Task-12-qualified schemas; and freezes commissioning generation/target/host-key identity across each operation. `reboot_and_wait` returns the constant string `reboot_verified` only after disconnect, a changed boot UUID, same commissioning/host-key identity, and durable witness publication within the caller's bound. `network_counters_canonical_json` and `verify_reboot_canonical_json` return canonical JSON text without a trailing newline; Task 08's `_emit` adds exactly one. It is a production implementation, not a Protocol, fixture, environment lookup, shell wrapper, or test-supplied service. The test builder must instantiate it with a local fake fixed-argv runner and then with the explicit real-hardware flag; direct constructor injection is allowed only in tests.

Regenerate `uv.lock` after the exact PEP 440 version transition. `probe_local_runtime_compatibility` is Task 12-qualified, uses only the fixed local SDK/daemon interfaces, enforces its five-second bound, and performs no DNS, WAN, listener, registration, or write. The handler runs before `current` or daemon registration and returns through the root dispatcher's closed `65|70` error mapping.

```sh
# deploy/reachy/build_app.sh
#!/bin/sh
set -eu
test -n "${SOURCE_DATE_EPOCH:-}"; test -n "${REACHY_SDK_VERSION:-}"; test -n "${REACHY_DAEMON_VERSION:-}"
test "${REACHY_PYTHON_EXECUTABLE:-}" = "/venvs/apps_venv/bin/python3"
case "${REACHY_PYTHON_VERSION:-}:${REACHY_PYTHON_ABI:-}" in 3.11:cp311|3.12:cp312) :;; *) exit 65;; esac
test "${REACHY_SELECTED_WHEEL_TAG:-}" = "py3-none-any"
for digest in "${REACHY_TARGET_TAG_SET_SHA256:-}" "${REACHY_RUNTIME_INVENTORY_SHA256:-}"; do
  test "${#digest}" -eq 64 || exit 65
  case "$digest" in *[!0-9a-f]*) exit 65;; esac
done
stage=$(mktemp -d); trap 'rm -rf "$stage"' EXIT INT TERM
mkdir -p "$stage/locks" "$stage/wheelhouse" dist
cp deploy/reachy/app.toml deploy/reachy/entrypoint.sh deploy/reachy/install_payload.sh deploy/reachy/recover_install.sh deploy/reachy/install_recovery_hook.sh deploy/reachy/recovery_bootstrap.py "$stage"/
cp scripts/verify_reachy_wheelhouse.py "$stage"/
cp uv.lock "$stage/locks/uv.lock"
uv build --frozen --package tuntun-contracts --wheel --out-dir "$stage/wheelhouse"
uv build --frozen --package tuntun-edge --wheel --out-dir "$stage/wheelhouse"
uv run python scripts/verify_reachy_wheelhouse.py --write "$stage" --tag "$REACHY_SELECTED_WHEEL_TAG"
uv run python -c 'import hashlib,json,os,pathlib,sys; root=pathlib.Path(sys.argv[1]); digest=lambda path:hashlib.file_digest(path.open("rb"),"sha256").hexdigest(); value={"schema_version":"tuntun.reachy-compatibility.v1","sdk":os.environ["REACHY_SDK_VERSION"],"daemon":os.environ["REACHY_DAEMON_VERSION"],"python_executable":os.environ["REACHY_PYTHON_EXECUTABLE"],"python_version":os.environ["REACHY_PYTHON_VERSION"],"python_abi":os.environ["REACHY_PYTHON_ABI"],"selected_wheel_tag":os.environ["REACHY_SELECTED_WHEEL_TAG"],"target_tag_set_sha256":os.environ["REACHY_TARGET_TAG_SET_SHA256"],"runtime_inventory_sha256":os.environ["REACHY_RUNTIME_INVENTORY_SHA256"],"uv_lock_sha256":digest(root/"locks/uv.lock"),"wheelhouse_manifest_sha256":digest(root/"wheelhouse/manifest.json"),"exact_match":True}; (root/"compatibility.json").write_text(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n")' "$stage"
uv run python -m scripts.deterministic_tar --root "$stage" --output dist/tuntun-edge-0.1.0-beta.1.tar.gz --mtime "$SOURCE_DATE_EPOCH"
uv run python scripts/verify_reachy_archive.py \
  --archive dist/tuntun-edge-0.1.0-beta.1.tar.gz \
  --write-manifest dist/tuntun-edge-0.1.0-beta.1.tar.gz.manifest.json
archive_sha256=$(shasum -a 256 dist/tuntun-edge-0.1.0-beta.1.tar.gz | awk '{print $1}')
printf '%s  %s\n' "$archive_sha256" 'tuntun-edge-0.1.0-beta.1.tar.gz' > dist/tuntun-edge-0.1.0-beta.1.tar.gz.sha256
uv run python scripts/verify_reachy_archive.py \
  --archive dist/tuntun-edge-0.1.0-beta.1.tar.gz \
  --manifest dist/tuntun-edge-0.1.0-beta.1.tar.gz.manifest.json \
  --expected-sha256 "$archive_sha256"
```

```sh
# deploy/reachy/entrypoint.sh (inside the extracted managed app; never recovery authority)
#!/bin/sh
set -eu
base=/var/lib/reachy-mini-app-assistant/apps/com.tuntun.edge
app_root=$(CDPATH= cd -P -- "$base/current" && pwd -P)
case "$app_root" in "$base"/releases/*) :;; *) exit 70;; esac
export PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 UV_NO_SYNC=1
exec "$app_root/.venv/bin/tuntun-edge" managed --app-root "$app_root"
```

```sh
# deploy/reachy/install_app.sh (Mac-side public installer)
#!/bin/sh
set -eu
[ "$#" -eq 1 ] || { printf '%s\n' 'usage: install_app.sh <archive>' >&2; exit 65; }
archive=$1
case "$archive" in -*|*[!A-Za-z0-9._/-]*|'') printf '%s\n' 'unsafe local archive path' >&2; exit 65;; esac
archive_name=${archive##*/}
case "$archive_name" in -*|*[!A-Za-z0-9._-]*|'') printf '%s\n' 'unsafe local archive basename' >&2; exit 65;; esac
[ -f "$archive" ] && [ ! -L "$archive" ] || { printf '%s\n' 'archive must be a regular non-symlink file' >&2; exit 65; }
checksum="$archive.sha256"
[ -f "$checksum" ] && [ ! -L "$checksum" ] || { printf '%s\n' 'adjacent checksum missing' >&2; exit 65; }
manifest="$archive.manifest.json"
manifest_name=${manifest##*/}
case "$manifest_name" in -*|*[!A-Za-z0-9._-]*|'') printf '%s\n' 'unsafe local manifest basename' >&2; exit 65;; esac
[ -f "$manifest" ] && [ ! -L "$manifest" ] || { printf '%s\n' 'adjacent archive manifest missing' >&2; exit 65; }
expected=$(awk 'NR==1 {print $1} NR>1 {exit 65}' "$checksum")
case "$expected" in *[!0-9a-f]*|'') exit 65;; esac
[ "${#expected}" -eq 64 ] || exit 65
actual=$(shasum -a 256 "$archive" | awk '{print $1}')
[ "$actual" = "$expected" ] || { printf '%s\n' 'archive checksum mismatch' >&2; exit 65; }
script_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
python3 "$script_root/scripts/verify_reachy_archive.py" \
  --archive "$archive" --manifest "$manifest" --expected-sha256 "$expected"
target=$(uv run --frozen --offline --no-sync tuntunctl reachy commissioned-ssh-target --numeric --plain)
printf '%s\n' "$target" | grep -Eq '^[a-z_][a-z0-9_-]{0,31}@([0-9]{1,3}[.]){3}[0-9]{1,3}$' || { printf '%s\n' 'invalid commissioned numeric target' >&2; exit 65; }
target_python=$(uv run --frozen --offline --no-sync tuntunctl reachy compatibility --field python-executable)
[ "$target_python" = /venvs/apps_venv/bin/python3 ] || exit 70
known_hosts=/private/var/lib/tuntun/reachy/known_hosts
[ -f "$known_hosts" ] && [ ! -L "$known_hosts" ] || { printf '%s\n' 'commissioned known-hosts file unavailable' >&2; exit 70; }
remote_stage=$(ssh -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts" -o ConnectTimeout=10 -o ConnectionAttempts=1 -- "$target" 'umask 077; mktemp -d /var/lib/reachy-mini-app-assistant/staging/com.tuntun.edge.XXXXXXXX')
printf '%s\n' "$remote_stage" | grep -Eq '^/var/lib/reachy-mini-app-assistant/staging/com[.]tuntun[.]edge[.][A-Za-z0-9]{8}$' || exit 65
cleanup() { ssh -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts" -o ConnectTimeout=10 -o ConnectionAttempts=1 -- "$target" rm -rf -- "$remote_stage" >/dev/null 2>&1 || :; }
trap cleanup EXIT HUP INT TERM
scp -q -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts" -o ConnectTimeout=10 -o ConnectionAttempts=1 -- "$archive" "$manifest" "$script_root/scripts/verify_reachy_archive.py" "$target:$remote_stage/"
ssh -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts" -o ConnectTimeout=10 -o ConnectionAttempts=1 -- "$target" "$target_python" "$remote_stage/verify_reachy_archive.py" \
  --archive "$remote_stage/$archive_name" --expected-sha256 "$expected" \
  --manifest "$remote_stage/$manifest_name" \
  --extract "$remote_stage/payload"
set +e
ssh -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts" -o ConnectTimeout=10 -o ConnectionAttempts=1 -- "$target" "$remote_stage/payload/install_payload.sh" \
  "$remote_stage/payload" "$expected"
status=$?
set -e
[ "$status" -eq 0 ] || exit 70
trap - EXIT HUP INT TERM
cleanup
```

```sh
# deploy/reachy/install_recovery_hook.sh (candidate-to-stable bootstrap; caller holds lock FD 9)
#!/bin/sh
set -eu
[ "$#" -eq 2 ] || exit 65
target_python=/venvs/apps_venv/bin/python3
[ -x "$target_python" ] || exit 70
source=$1
base=$2
[ "$base" = /var/lib/reachy-mini-app-assistant/apps/com.tuntun.edge ] || exit 65
[ "${TUNTUN_RECOVERY_LOCK_FD:-}" = 9 ] || exit 70
[ -f "$source" ] && [ ! -L "$source" ] || exit 70
"$target_python" - "$base/lock/install.lock" <<'PY'
import fcntl,os,pathlib,stat,sys
fd=9; path=pathlib.Path(sys.argv[1])
try: opened=os.fstat(fd); named=path.stat(follow_symlinks=False)
except OSError as error: raise SystemExit(70) from error
if (not stat.S_ISREG(named.st_mode) or named.st_uid!=os.geteuid()
    or stat.S_IMODE(named.st_mode)!=0o600
    or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino)):
    raise SystemExit(70)
try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError as error: raise SystemExit(70) from error
PY
recovery_dir="$base/recovery"
destination="$recovery_dir/recovery_bootstrap.py"
if [ -e "$recovery_dir" ] || [ -L "$recovery_dir" ]; then
  [ -d "$recovery_dir" ] && [ ! -L "$recovery_dir" ] || exit 70
else
  mkdir -m 700 -- "$recovery_dir"
fi
[ ! -e "$destination" ] && [ ! -L "$destination" ] || {
  [ -f "$destination" ] && [ ! -L "$destination" ] || exit 70
}
[ "$(stat -c '%u:%a' "$recovery_dir")" = "$(id -u):700" ] || exit 70
temporary=$(mktemp "$recovery_dir/.recovery_bootstrap.py.new.XXXXXXXX") || exit 70
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
umask 077
cp "$source" "$temporary"
chmod 600 "$temporary"
"$target_python" - "$temporary" "$recovery_dir" <<'PY'
import os,pathlib,sys
path=pathlib.Path(sys.argv[1]); directory=pathlib.Path(sys.argv[2])
with path.open("rb") as stream: os.fsync(stream.fileno())
fd=os.open(directory,os.O_RDONLY)
try: os.fsync(fd)
finally: os.close(fd)
PY
mv -f "$temporary" "$destination"
hook_sha256=$("$target_python" - "$destination" "$recovery_dir" <<'PY'
import hashlib,os,pathlib,stat,sys
path=pathlib.Path(sys.argv[1]); directory=pathlib.Path(sys.argv[2])
flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0); source=os.open(path,flags)
try:
    metadata=os.fstat(source); named=path.stat(follow_symlinks=False)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=os.geteuid()
        or stat.S_IMODE(metadata.st_mode)!=0o600
        or (metadata.st_dev,metadata.st_ino)!=(named.st_dev,named.st_ino)):
        raise SystemExit(70)
    hook_sha256=hashlib.file_digest(os.fdopen(os.dup(source),"rb"),"sha256").hexdigest()
    after=os.fstat(source); named_after=path.stat(follow_symlinks=False)
    if ((after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
        !=(metadata.st_dev,metadata.st_ino,metadata.st_size,metadata.st_mtime_ns,metadata.st_ctime_ns)
        or (named_after.st_dev,named_after.st_ino)!=(after.st_dev,after.st_ino)):
        raise SystemExit(70)
finally: os.close(source)
fd=os.open(directory,os.O_RDONLY)
try: os.fsync(fd)
finally: os.close(fd)
print(hook_sha256)
PY
)
source_sha256=$(shasum -a 256 "$source" | awk '{print $1}')
[ "$source_sha256" = "$hook_sha256" ] || exit 70
reachy-mini-app-assistant recovery-hook register \
  --id com.tuntun.edge --entrypoint "$target_python $destination recover --base $base --timeout-seconds 30" \
  --trigger boot --order before-managed-apps --atomic --durable
reachy-mini-app-assistant recovery-hook verify \
  --id com.tuntun.edge --entrypoint-sha256 "$hook_sha256" --order before-managed-apps \
  --trigger boot --require-durable
trap - EXIT HUP INT TERM
```

```sh
# deploy/reachy/install_payload.sh (private target-side installer)
#!/bin/sh
set -eu
[ "$#" -eq 2 ] || exit 65
target_python=/venvs/apps_venv/bin/python3
[ -x "$target_python" ] || exit 70
payload=$1
artifact_sha256=$2
[ "$(stat -c '%a' "$(dirname -- "$payload")")" = 700 ] || exit 65
base=/var/lib/reachy-mini-app-assistant/apps/com.tuntun.edge
secure_owner_dir() {
  directory=$1
  if [ -e "$directory" ] || [ -L "$directory" ]; then
    [ -d "$directory" ] && [ ! -L "$directory" ] || exit 70
  else
    mkdir -m 700 -- "$directory"
  fi
  [ "$(stat -c '%u:%a' "$directory")" = "$(id -u):700" ] || exit 70
}
secure_owner_dir "$base"
secure_owner_dir "$base/lock"
[ "${TUNTUN_RECOVERY_LOCK_FD:-}" = 9 ] || exec "$target_python" "$payload/recovery_bootstrap.py" \
  supervise-install --base "$base" --timeout-seconds 30 \
  --installer "$0" --payload "$payload" --artifact-sha256 "$artifact_sha256"
export TUNTUN_RECOVERY_LOCK_FD=9
current_recovery="$base/recovery/recovery_bootstrap.py"
install_successor_hook=1
if [ -e "$current_recovery" ] || [ -L "$current_recovery" ]; then
  [ -f "$current_recovery" ] && [ ! -L "$current_recovery" ] || exit 70
  [ "$(stat -c '%u:%a' "$current_recovery")" = "$(id -u):600" ] || exit 70
  current_sha256=$(shasum -a 256 "$current_recovery" | awk '{print $1}')
  if reachy-mini-app-assistant recovery-hook verify --id com.tuntun.edge \
      --entrypoint-sha256 "$current_sha256" --trigger boot \
      --order before-managed-apps --require-durable; then
    # The currently registered hook owns all already-durable journal versions.
    "$target_python" "$current_recovery" recover --base "$base" --lock-fd 9
  elif reachy-mini-app-assistant recovery-hook verify-absent \
      --id com.tuntun.edge --require-durable; then
    # The only repairable missing-registration state is a blank target killed
    # after the owner-only stable-file rename and before durable registration.
    # Any durable install state makes an unverifiable hook an owner incident.
    for path in "$base/journal" "$base/current" "$base/releases"; do
      [ ! -e "$path" ] && [ ! -L "$path" ] || exit 70
    done
    candidate_hook_sha256=$(shasum -a 256 "$payload/recovery_bootstrap.py" | awk '{print $1}')
    [ "$current_sha256" = "$candidate_hook_sha256" ] || exit 70
    "$payload/install_recovery_hook.sh" "$payload/recovery_bootstrap.py" "$base"
    install_successor_hook=0
  else
    exit 70
  fi
else
  for path in "$base/journal" "$base/current" "$base/releases"; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || exit 70
  done
fi
previous=$("$target_python" - "$base" <<'PY'
import os,pathlib,stat,sys
base=pathlib.Path(sys.argv[1]); current=base/"current"
try: link=os.lstat(current)
except FileNotFoundError: print(""); raise SystemExit(0)
if not stat.S_ISLNK(link.st_mode) or link.st_uid!=os.geteuid(): raise SystemExit(70)
target=pathlib.Path(os.readlink(current))
if not target.is_absolute() or target.parent!=base/"releases": raise SystemExit(70)
try: release=os.stat(target,follow_symlinks=False); final_link=os.lstat(current)
except OSError as error: raise SystemExit(70) from error
if (not stat.S_ISDIR(release.st_mode) or release.st_uid!=os.geteuid()
    or stat.S_IMODE(release.st_mode)!=0o700
    or (link.st_dev,link.st_ino)!=(final_link.st_dev,final_link.st_ino)):
    raise SystemExit(70)
print(target)
PY
) || exit 70
if [ "$install_successor_hook" -eq 1 ]; then
  "$payload/install_recovery_hook.sh" "$payload/recovery_bootstrap.py" "$base"
fi
stable_recovery="$base/recovery/recovery_bootstrap.py"
reachy-mini-app-assistant recovery-hook verify --id com.tuntun.edge \
  --entrypoint-sha256 "$(shasum -a 256 "$stable_recovery" | awk '{print $1}')" \
  --trigger boot --order before-managed-apps --require-durable
# journal/current/releases do not exist or change until the durable stable hook,
# its registration proof, and the process-wide lock are all established.
secure_owner_dir "$base/releases"
secure_owner_dir "$base/journal"
# The successor keeps the v1 reader indefinitely; this validates that any
# completed/recovered predecessor records remain readable before mutation.
"$target_python" "$stable_recovery" recover --base "$base" --lock-fd 9
version=$("$target_python" -c 'import sys,tomllib; print(tomllib.load(open(sys.argv[1],"rb"))["app"]["version"])' "$payload/app.toml")
case "$version" in *[!A-Za-z0-9._-]*|'') exit 65;; esac
destination="$base/releases/$version-$artifact_sha256"
journal="$base/journal/$artifact_sha256.state"
umask 077
[ ! -e "$destination" ] || exit 65
"$target_python" "$stable_recovery" write --base "$base" --lock-fd 9 --journal "$journal" --state preparing --previous "$previous" --candidate "$destination" --artifact-sha256 "$artifact_sha256"
restore() {
  trap - EXIT HUP INT TERM
  # One state machine owns inverse ordering and durability. It fsyncs BASE and
  # releases after namespace inverses and only then writes terminal `recovered`.
  "$target_python" "$stable_recovery" recover --base "$base" --lock-fd 9 >/dev/null 2>&1 || exit 70
  exit 70
}
trap restore EXIT HUP INT TERM
export PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1
test "$(stat -c '%d' "$payload")" = "$(stat -c '%d' "$base/releases")" || exit 65
test "$(stat -c '%u' "$payload")" = "$(id -u)" && [ -d "$payload" ] && [ ! -L "$payload" ] || exit 70
chmod 700 "$payload"
mv "$payload" "$destination"
payload=$destination
sync "$base/releases"
"$target_python" "$stable_recovery" write --base "$base" --lock-fd 9 --journal "$journal" --state payload_moved --previous "$previous" --candidate "$destination" --artifact-sha256 "$artifact_sha256"
"$target_python" -m venv --system-site-packages "$destination/.venv"
"$target_python" "$stable_recovery" write --base "$base" --lock-fd 9 --journal "$journal" --state venv_created --previous "$previous" --candidate "$destination" --artifact-sha256 "$artifact_sha256"
"$destination/.venv/bin/python" "$destination/verify_reachy_wheelhouse.py" --verify "$destination"
contracts_wheel=$(find "$payload/wheelhouse" -maxdepth 1 -name 'tuntun_contracts-*.whl' -print)
edge_wheel=$(find "$payload/wheelhouse" -maxdepth 1 -name 'tuntun_edge-*.whl' -print)
test "$(printf '%s\n' "$contracts_wheel" | sed '/^$/d' | wc -l | tr -d ' ')" = 1
test "$(printf '%s\n' "$edge_wheel" | sed '/^$/d' | wc -l | tr -d ' ')" = 1
"$destination/.venv/bin/python" -m pip install --no-index --no-deps "$contracts_wheel" "$edge_wheel"
"$target_python" "$stable_recovery" write --base "$base" --lock-fd 9 --journal "$journal" --state wheels_installed --previous "$previous" --candidate "$destination" --artifact-sha256 "$artifact_sha256"
# This command re-probes the accepted base inventory from inside the isolated
# venv and imports the complete closed edge/native closure with networking denied.
"$destination/.venv/bin/tuntun-edge" verify-install --app-root "$destination" --compatibility "$destination/compatibility.json" --artifact-sha256 "$artifact_sha256"
ln -s "$destination" "$base/current.next"
mv -Tf "$base/current.next" "$base/current"
sync "$base"
"$target_python" "$stable_recovery" write --base "$base" --lock-fd 9 --journal "$journal" --state link_switched --previous "$previous" --candidate "$destination" --artifact-sha256 "$artifact_sha256"
reachy-mini-app-assistant register --id com.tuntun.edge --manifest "$base/current/app.toml" --entrypoint "$base/current/entrypoint.sh" --atomic
"$target_python" "$stable_recovery" write --base "$base" --lock-fd 9 --journal "$journal" --state registered --previous "$previous" --candidate "$destination" --artifact-sha256 "$artifact_sha256"
reachy-mini-app-assistant verify --id com.tuntun.edge --artifact-sha256 "$artifact_sha256" --health-timeout 20
"$target_python" "$stable_recovery" write --base "$base" --lock-fd 9 --journal "$journal" --state complete --previous "$previous" --candidate "$destination" --artifact-sha256 "$artifact_sha256"
trap - EXIT HUP INT TERM
```

```sh
# deploy/reachy/recover_install.sh (compatibility wrapper; never recovery authority)
#!/bin/sh
set -eu
[ "$#" -ge 1 ] || exit 65
base=/var/lib/reachy-mini-app-assistant/apps/com.tuntun.edge
stable="$base/recovery/recovery_bootstrap.py"
[ -f "$stable" ] && [ ! -L "$stable" ] || exit 70
exec /venvs/apps_venv/bin/python3 "$stable" "$@" --base "$base"
```

```sh
# deploy/reachy/uninstall_app.sh (Mac-side, preserving commissioning and user state)
#!/bin/sh
set -eu
[ "$#" -eq 0 ] || { printf '%s\n' 'usage: uninstall_app.sh' >&2; exit 65; }
script_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
helper="$script_root/deploy/reachy/recovery_bootstrap.py"
[ -f "$helper" ] && [ ! -L "$helper" ] || exit 70
helper_sha256=$(shasum -a 256 "$helper" | awk '{print $1}')
case "$helper_sha256" in *[!0-9a-f]*|'') exit 70;; esac
[ "${#helper_sha256}" -eq 64 ] || exit 70
target=$(uv run --frozen --offline --no-sync tuntunctl reachy commissioned-ssh-target --numeric --plain)
printf '%s\n' "$target" | grep -Eq '^[a-z_][a-z0-9_-]{0,31}@([0-9]{1,3}[.]){3}[0-9]{1,3}$' || exit 65
target_python=$(uv run --frozen --offline --no-sync tuntunctl reachy compatibility --field python-executable)
[ "$target_python" = /venvs/apps_venv/bin/python3 ] || exit 70
known_hosts=/private/var/lib/tuntun/reachy/known_hosts
[ -f "$known_hosts" ] && [ ! -L "$known_hosts" ] || exit 70
remote_stage=$(ssh -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts" -o ConnectTimeout=10 -o ConnectionAttempts=1 -- "$target" 'umask 077; mktemp -d /var/lib/reachy-mini-app-assistant/staging/com.tuntun.edge-uninstall.XXXXXXXX')
printf '%s\n' "$remote_stage" | grep -Eq '^/var/lib/reachy-mini-app-assistant/staging/com[.]tuntun[.]edge-uninstall[.][A-Za-z0-9]{8}$' || exit 70
cleanup() { ssh -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts" -o ConnectTimeout=10 -o ConnectionAttempts=1 -- "$target" rm -rf -- "$remote_stage" >/dev/null 2>&1 || :; }
trap cleanup EXIT HUP INT TERM
scp -q -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts" -o ConnectTimeout=10 -o ConnectionAttempts=1 -- "$helper" "$target:$remote_stage/recovery_bootstrap.py"
set +e
ssh -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts" -o ConnectTimeout=10 -o ConnectionAttempts=1 -- "$target" "$target_python" "$remote_stage/recovery_bootstrap.py" \
  supervise-uninstall \
  --base /var/lib/reachy-mini-app-assistant/apps/com.tuntun.edge \
  --timeout-seconds 30 --bootstrap-sha256 "$helper_sha256"
status=$?
set -e
[ "$status" -eq 0 ] || exit 70
trap - EXIT HUP INT TERM
cleanup
```

```python
# deploy/reachy/recovery_bootstrap.py (durable host hook, installed outside releases)
import argparse,fcntl,hashlib,json,os,pathlib,re,shutil,stat,subprocess,tempfile,time
from contextlib import contextmanager

BASE=pathlib.Path("/var/lib/reachy-mini-app-assistant/apps/com.tuntun.edge")
LOCK=BASE/"lock/install.lock"
STATES={"preparing","payload_moved","venv_created","wheels_installed","link_switched","registered","complete","recovered","needs_owner_recovery"}
REQUIRED_JOURNAL_KEYS=frozenset({"state","previous","candidate","artifact_sha256"})
MAX_JOURNAL_BYTES=4096
MAX_JOURNALS=128
ARTIFACT_SHA256=re.compile(r"[0-9a-f]{64}")
RELEASE_BASENAME=re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}-([0-9a-f]{64})")
APP_ID="com.tuntun.edge"
UNINSTALL_MARKER=BASE/"uninstall.state"
MAX_DAEMON_INVENTORY_BYTES=32_768

def _require_bounded_journal_shape(text):
    depth=containers=0; tokens=1; in_string=escaped=False
    for character in text:
        if in_string:
            if escaped: escaped=False
            elif character=="\\": escaped=True
            elif character=='"': in_string=False
            continue
        if character=='"': in_string=True
        elif character in "[{":
            depth+=1; containers+=1
            if depth>1 or containers>1: raise ValueError("invalid Reachy recovery journal")
        elif character in "]}":
            depth-=1
            if depth<0: raise ValueError("invalid Reachy recovery journal")
        elif character in ",:":
            tokens+=1
            if tokens>8: raise ValueError("invalid Reachy recovery journal")
    if in_string or depth!=0: raise ValueError("invalid Reachy recovery journal")

def decode_journal_record(data):
    # This stable pre-app hook is deliberately self-contained; importing the
    # candidate contracts would make blank-target recovery circular.
    def no_duplicates(pairs):
        result={}
        for key,value in pairs:
            if not isinstance(key,str) or key in result:
                raise ValueError("invalid Reachy recovery journal")
            result[key]=value
        return result
    try:
        text=data.decode("utf-8",errors="strict")
        _require_bounded_journal_shape(text)
        value=json.loads(
            text,object_pairs_hook=no_duplicates,
            parse_int=lambda _: (_ for _ in ()).throw(ValueError()),
            parse_float=lambda _: (_ for _ in ()).throw(ValueError()),
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError,ValueError,json.JSONDecodeError,RecursionError) as error:
        raise ValueError("invalid Reachy recovery journal") from error
    if (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()!=data:
        raise ValueError("invalid Reachy recovery journal")
    return value

def durable_write(path, value):
    path=pathlib.Path(path)
    value=validate_record(value,path)
    data=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
    descriptor,tmp_name=tempfile.mkstemp(prefix=".journal-",dir=path.parent)
    tmp=pathlib.Path(tmp_name)
    with os.fdopen(descriptor,"wb") as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    try: os.replace(tmp,path)
    finally: tmp.unlink(missing_ok=True)
    directory=os.open(path.parent,os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)

def fsync_dir(path):
    directory=os.open(path,os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)

def validate_record(value,path=None):
    if (
        type(value) is not dict
        or set(value)!=REQUIRED_JOURNAL_KEYS
        or any(type(value[key]) is not str for key in REQUIRED_JOURNAL_KEYS)
        or value["state"] not in STATES
    ):
        raise ValueError("invalid Reachy recovery journal")
    artifact=value["artifact_sha256"]
    if not isinstance(artifact,str) or ARTIFACT_SHA256.fullmatch(artifact) is None:
        raise ValueError("invalid Reachy recovery journal")
    candidate=pathlib.Path(value["candidate"])
    candidate_name=RELEASE_BASENAME.fullmatch(candidate.name)
    if (candidate.parent!=BASE/"releases" or candidate_name is None
        or candidate_name.group(1)!=artifact):
        raise ValueError("invalid Reachy recovery journal")
    if value["previous"]:
        previous=pathlib.Path(value["previous"])
        if (previous.parent!=BASE/"releases"
            or RELEASE_BASENAME.fullmatch(previous.name) is None):
            raise ValueError("invalid Reachy recovery journal")
    if path is not None:
        journal=pathlib.Path(path)
        if journal.parent!=BASE/"journal" or journal.name!=artifact+".state":
            raise ValueError("invalid Reachy recovery journal")
    return value

def checked_record(path):
    path=pathlib.Path(path); flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)
    try: fd=os.open(path,flags)
    except OSError as error: raise ValueError("invalid Reachy recovery journal") from error
    try:
        opened=os.fstat(fd); named=path.stat(follow_symlinks=False)
        if (not stat.S_ISREG(named.st_mode) or named.st_uid!=os.geteuid()
            or stat.S_IMODE(named.st_mode)!=0o600
            or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino)):
            raise ValueError("invalid Reachy recovery journal")
        chunks=[]; remaining=MAX_JOURNAL_BYTES+1
        while remaining:
            chunk=os.read(fd,remaining)
            if not chunk: break
            chunks.append(chunk); remaining-=len(chunk)
        data=b"".join(chunks)
        if len(data)>MAX_JOURNAL_BYTES: raise ValueError("invalid Reachy recovery journal")
        final=os.fstat(fd); renamed=path.stat(follow_symlinks=False)
        if ((final.st_dev,final.st_ino)!=(opened.st_dev,opened.st_ino)
            or (renamed.st_dev,renamed.st_ino)!=(opened.st_dev,opened.st_ino)):
            raise ValueError("invalid Reachy recovery journal")
    except (OSError,UnicodeError) as error:
        raise ValueError("invalid Reachy recovery journal") from error
    finally: os.close(fd)
    return validate_record(decode_journal_record(data),path)

def require_lock_file(fd):
    file_stat=os.fstat(fd); path_stat=LOCK.stat(follow_symlinks=False)
    if (not stat.S_ISREG(path_stat.st_mode) or path_stat.st_uid!=os.geteuid()
        or stat.S_IMODE(path_stat.st_mode)!=0o600
        or (file_stat.st_dev,file_stat.st_ino)!=(path_stat.st_dev,path_stat.st_ino)):
        raise SystemExit(70)

@contextmanager
def process_lock(inherited_fd,timeout_seconds,*,create=False):
    if LOCK.is_symlink(): raise SystemExit(70)
    if inherited_fd is not None:
        fd=int(inherited_fd)
        try: require_lock_file(fd)
        except OSError as error: raise SystemExit(70) from error
        try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as error: raise SystemExit(70) from error
        require_lock_file(fd); yield fd; return
    flags=os.O_RDWR|getattr(os,"O_NOFOLLOW",0)
    try:
        if create:
            try:
                fd=os.open(LOCK,flags|os.O_CREAT|os.O_EXCL,0o600)
                os.fchmod(fd,0o600)
            except FileExistsError:
                fd=os.open(LOCK,flags)
        else: fd=os.open(LOCK,flags)
    except OSError as error: raise SystemExit(70) from error
    try:
        try: require_lock_file(fd)
        except OSError as error: raise SystemExit(70) from error
        deadline=time.monotonic()+timeout_seconds
        while True:
            try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB); break
            except BlockingIOError:
                if time.monotonic()>=deadline: raise SystemExit(70)
                time.sleep(0.1)
        require_lock_file(fd)
        yield fd
    finally:
        os.close(fd)

def run_daemon(*args):
    # Compatibility qualification proves `--if-present` returns zero only for
    # the exact absent-app state; transport/permission/daemon errors stay nonzero.
    subprocess.run(("reachy-mini-app-assistant",*args),check=True,timeout=10)

def _require_bounded_inventory_shape(text):
    depth=containers=0; tokens=1; in_string=escaped=False
    for character in text:
        if in_string:
            if escaped: escaped=False
            elif character=="\\": escaped=True
            elif character=='"': in_string=False
            continue
        if character=='"': in_string=True
        elif character in "[{":
            depth+=1; containers+=1
            if depth>2 or containers>3:
                raise ValueError("invalid Reachy assistant inventory")
        elif character in "]}":
            depth-=1
            if depth<0: raise ValueError("invalid Reachy assistant inventory")
        elif character in ",:":
            tokens+=1
            if tokens>520: raise ValueError("invalid Reachy assistant inventory")
    if in_string or depth!=0:
        raise ValueError("invalid Reachy assistant inventory")

def daemon_inventory():
    def no_duplicates(pairs):
        value={}
        for key,item in pairs:
            if type(key) is not str or key in value:
                raise ValueError("invalid Reachy assistant inventory")
            value[key]=item
        return value
    try:
        completed=subprocess.run(
            ("reachy-mini-app-assistant","inventory","--json"),check=True,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            timeout=10,
        )
        raw=completed.stdout
        if not 1<=len(raw)<=MAX_DAEMON_INVENTORY_BYTES:
            raise ValueError("invalid Reachy assistant inventory")
        text=raw.decode("utf-8",errors="strict")
        _require_bounded_inventory_shape(text)
        value=json.loads(
            text,object_pairs_hook=no_duplicates,
            parse_int=lambda _: (_ for _ in ()).throw(ValueError()),
            parse_float=lambda _: (_ for _ in ()).throw(ValueError()),
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError,ValueError,json.JSONDecodeError,RecursionError,
            subprocess.SubprocessError) as error:
        raise ValueError("invalid Reachy assistant inventory") from error
    if type(value) is not dict or set(value)!={"managed_app_ids","recovery_hook_ids"}:
        raise ValueError("invalid Reachy assistant inventory")
    for key in ("managed_app_ids","recovery_hook_ids"):
        items=value[key]
        if (type(items) is not list or len(items)>256
            or any(type(item) is not str or len(item)>128 for item in items)
            or len(items)!=len(set(items))):
            raise ValueError("invalid Reachy assistant inventory")
    return value

def _durable_control_write(path,data):
    descriptor,tmp_name=tempfile.mkstemp(prefix=".control-",dir=path.parent)
    tmp=pathlib.Path(tmp_name)
    try:
        os.fchmod(descriptor,0o600)
        with os.fdopen(descriptor,"wb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(tmp,path); fsync_dir(path.parent)
    finally:
        tmp.unlink(missing_ok=True)

def write_uninstall_marker():
    data=b'{"schema_version":"tuntun.reachy-uninstall.v1","state":"requested"}\n'
    _durable_control_write(UNINSTALL_MARKER,data)
    require_uninstall_marker()

def require_uninstall_marker():
    flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)
    try: fd=os.open(UNINSTALL_MARKER,flags)
    except OSError as error: raise ValueError("invalid Reachy uninstall marker") from error
    try:
        opened=os.fstat(fd); named=UNINSTALL_MARKER.stat(follow_symlinks=False)
        raw=os.read(fd,257)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid!=os.geteuid()
            or stat.S_IMODE(opened.st_mode)!=0o600 or len(raw)>256
            or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino)
            or raw!=b'{"schema_version":"tuntun.reachy-uninstall.v1","state":"requested"}\n'):
            raise ValueError("invalid Reachy uninstall marker")
    finally: os.close(fd)

def _path_present(path):
    return path.exists() or path.is_symlink()

def validate_uninstall_tree():
    require_owned_directory(BASE); require_owned_directory(BASE/"lock")
    allowed={"lock","recovery","current","releases","journal","uninstall.state"}
    if any(path.name not in allowed for path in BASE.iterdir()):
        raise ValueError("unexpected Reachy app state")
    releases=BASE/"releases"; journal=BASE/"journal"; recovery_dir=BASE/"recovery"
    if _path_present(releases):
        require_owned_directory(releases)
        for path in releases.iterdir(): require_owned_release(path)
    current=BASE/"current"
    if _path_present(current):
        link=os.lstat(current)
        if not stat.S_ISLNK(link.st_mode) or link.st_uid!=os.geteuid():
            raise ValueError("unsafe Reachy current link")
        target=pathlib.Path(os.readlink(current))
        if not target.is_absolute() or target.parent!=releases:
            raise ValueError("unsafe Reachy current link")
        require_owned_release(target)
    if _path_present(journal):
        require_owned_directory(journal)
        for path in journal.iterdir(): checked_record(path)
    if _path_present(recovery_dir):
        require_owned_directory(recovery_dir)
        children=tuple(recovery_dir.iterdir())
        if {path.name for path in children}!={"recovery_bootstrap.py"}:
            raise ValueError("unexpected Reachy recovery state")
        helper=children[0]; metadata=helper.stat(follow_symlinks=False)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=os.geteuid()
            or stat.S_IMODE(metadata.st_mode)!=0o600):
            raise ValueError("unsafe Reachy recovery helper")

def cleanup_uninstalled_code_state():
    validate_uninstall_tree()
    for name in ("current",):
        path=BASE/name
        if _path_present(path): path.unlink()
    fsync_dir(BASE)
    for name in ("releases","journal"):
        path=BASE/name
        if _path_present(path): shutil.rmtree(path); fsync_dir(BASE)
    recovery_dir=BASE/"recovery"
    if _path_present(recovery_dir):
        (recovery_dir/"recovery_bootstrap.py").unlink()
        fsync_dir(recovery_dir); recovery_dir.rmdir(); fsync_dir(BASE)
    UNINSTALL_MARKER.unlink(missing_ok=True); fsync_dir(BASE)

def finish_uninstall():
    require_uninstall_marker()
    failures=[]
    for args in (
        ("stop","--id",APP_ID,"--if-present"),
        ("unregister","--id",APP_ID,"--if-present"),
    ):
        try: run_daemon(*args)
        except (OSError,subprocess.SubprocessError) as error: failures.append(error)
    try: first=daemon_inventory()
    except ValueError as error: failures.append(error); first=None
    if first is not None and APP_ID in first["managed_app_ids"]:
        failures.append(ValueError("managed app still registered"))
    # Keep the boot recovery hook registered whenever app stop/unregister or
    # the first absence proof failed, so a power loss retries the intent.
    if failures: raise SystemExit(70)
    try:
        run_daemon(
            "recovery-hook","unregister","--id",APP_ID,
            "--if-present","--durable",
        )
        final=daemon_inventory()
        if APP_ID in final["managed_app_ids"] or APP_ID in final["recovery_hook_ids"]:
            raise ValueError("Reachy registrations still present")
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        raise SystemExit(70) from error
    cleanup_uninstalled_code_state()

def require_owned_directory(path):
    metadata=path.stat(follow_symlinks=False)
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=os.geteuid()
        or stat.S_IMODE(metadata.st_mode)!=0o700):
        raise ValueError("unsafe Reachy recovery directory")

def require_owned_release(path):
    metadata=path.stat(follow_symlinks=False)
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=os.geteuid()
        or stat.S_IMODE(metadata.st_mode)!=0o700
        or path.parent!=BASE/"releases" or RELEASE_BASENAME.fullmatch(path.name) is None):
        raise ValueError("unsafe Reachy recovery release")

def prepare_base_and_lock_directories():
    for path in (BASE,BASE/"lock"):
        try: path.mkdir(mode=0o700,parents=False,exist_ok=True)
        except OSError as error: raise ValueError("unsafe Reachy app root") from error
        require_owned_directory(path)

def require_bootstrap_hash(expected):
    if ARTIFACT_SHA256.fullmatch(expected) is None:
        raise ValueError("invalid recovery bootstrap digest")
    path=pathlib.Path(__file__); flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)
    try: fd=os.open(path,flags)
    except OSError as error: raise ValueError("unsafe recovery bootstrap") from error
    try:
        opened=os.fstat(fd); named=path.stat(follow_symlinks=False)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid!=os.geteuid()
            or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino)):
            raise ValueError("unsafe recovery bootstrap")
        actual=hashlib.file_digest(os.fdopen(os.dup(fd),"rb"),"sha256").hexdigest()
    finally: os.close(fd)
    if actual!=expected: raise ValueError("recovery bootstrap digest mismatch")

def _attempt_blank_disable():
    failures=[]
    for args in (
        ("stop","--id",APP_ID,"--if-present"),
        ("unregister","--id",APP_ID,"--if-present"),
        ("recovery-hook","unregister","--id",APP_ID,"--if-present","--durable"),
    ):
        try: run_daemon(*args)
        except (OSError,subprocess.SubprocessError) as error: failures.append(error)
    try:
        value=daemon_inventory()
        if APP_ID in value["managed_app_ids"] or APP_ID in value["recovery_hook_ids"]:
            failures.append(ValueError("Reachy registrations still present"))
    except ValueError as error: failures.append(error)
    if failures: raise SystemExit(70)

def _attempt_app_disable_keep_hook():
    failures=[]
    for args in (
        ("stop","--id",APP_ID,"--if-present"),
        ("unregister","--id",APP_ID,"--if-present"),
    ):
        try: run_daemon(*args)
        except (OSError,subprocess.SubprocessError) as error: failures.append(error)
    try:
        value=daemon_inventory()
        if APP_ID in value["managed_app_ids"]:
            failures.append(ValueError("Reachy managed app still present"))
    except ValueError as error: failures.append(error)
    if failures: raise SystemExit(70)

def supervise_uninstall():
    marker_present=_path_present(UNINSTALL_MARKER)
    stable=BASE/"recovery/recovery_bootstrap.py"
    runtime_present=any(_path_present(BASE/name) for name in ("current","releases","journal"))
    if marker_present:
        require_uninstall_marker(); finish_uninstall(); return
    if not runtime_present and not _path_present(stable):
        _attempt_blank_disable(); return
    if not _path_present(stable):
        _attempt_app_disable_keep_hook(); raise SystemExit(70)
    metadata=stable.stat(follow_symlinks=False)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=os.geteuid()
        or stat.S_IMODE(metadata.st_mode)!=0o600):
        _attempt_app_disable_keep_hook(); raise SystemExit(70)
    stable_sha=hashlib.file_digest(stable.open("rb"),"sha256").hexdigest()
    try:
        run_daemon(
            "recovery-hook","verify","--id",APP_ID,
            "--entrypoint-sha256",stable_sha,"--trigger","boot",
            "--order","before-managed-apps","--require-durable",
        )
        recover()
        validate_uninstall_tree()
    except (OSError,ValueError,subprocess.SubprocessError,SystemExit):
        _attempt_app_disable_keep_hook(); raise SystemExit(70)
    write_uninstall_marker()
    finish_uninstall()

def recover():
    if _path_present(UNINSTALL_MARKER):
        finish_uninstall(); return
    journal_dir=BASE/"journal"
    if not journal_dir.exists() and not journal_dir.is_symlink():
        if any(path.exists() or path.is_symlink() for path in (BASE/"current",BASE/"releases")):
            raise ValueError("missing Reachy recovery journal directory")
        return
    require_owned_directory(BASE); require_owned_directory(journal_dir)
    require_owned_directory(BASE/"releases")
    paths=[]
    with os.scandir(journal_dir) as entries:
        for entry in entries:
            paths.append(journal_dir/entry.name)
            if len(paths)>MAX_JOURNALS: raise ValueError("too many Reachy recovery journals")
    for path in sorted(paths):
        value=checked_record(path)
        if value["state"] in {"complete","recovered"}: continue
        if value["state"]=="needs_owner_recovery": raise SystemExit(70)
        failed=False
        previous=pathlib.Path(value["previous"]) if value["previous"] else None
        candidate=pathlib.Path(value["candidate"])
        if previous is not None: require_owned_release(previous)
        if candidate.exists() or candidate.is_symlink(): require_owned_release(candidate)
        current=BASE/"current"; next_link=BASE/"current.recovery"
        try:
            run_daemon("stop","--id","com.tuntun.edge","--if-present")
            next_link.unlink(missing_ok=True)
            (BASE/"current.next").unlink(missing_ok=True)
            if previous is None:
                current.unlink(missing_ok=True)
                run_daemon("unregister","--id","com.tuntun.edge","--if-present")
            else:
                next_link.symlink_to(previous); os.replace(next_link,current)
                run_daemon("register","--id","com.tuntun.edge","--manifest",str(current/"app.toml"),"--entrypoint",str(current/"entrypoint.sh"),"--atomic")
            fsync_dir(BASE)
            if candidate!=previous and candidate.exists(): shutil.rmtree(candidate)
            fsync_dir(BASE/"releases")
        except (OSError,subprocess.SubprocessError): failed=True
        value["state"]="needs_owner_recovery" if failed else "recovered"; durable_write(path,value)
        if failed: raise SystemExit(70)

def main():
    parser=argparse.ArgumentParser(); parser.add_argument(
        "mode",choices=("write","recover","supervise-install","supervise-uninstall"),
    )
    parser.add_argument("--base",type=pathlib.Path,required=True)
    parser.add_argument("--lock-fd",type=int); parser.add_argument("--timeout-seconds",type=int,default=30)
    parser.add_argument("--journal",type=pathlib.Path); parser.add_argument("--state",choices=tuple(sorted(STATES)))
    parser.add_argument("--previous",default=""); parser.add_argument("--candidate",type=pathlib.Path)
    parser.add_argument("--artifact-sha256")
    parser.add_argument("--bootstrap-sha256")
    parser.add_argument("--installer",type=pathlib.Path); parser.add_argument("--payload",type=pathlib.Path)
    args=parser.parse_args()
    if args.base!=BASE or not 1<=args.timeout_seconds<=30: raise SystemExit(65)
    if args.mode=="supervise-uninstall":
        if (args.lock_fd is not None or args.journal is not None or args.state is not None
            or args.previous or args.candidate is not None or args.artifact_sha256 is not None
            or args.installer is not None or args.payload is not None
            or args.bootstrap_sha256 is None):
            raise SystemExit(65)
        try:
            require_bootstrap_hash(args.bootstrap_sha256)
            prepare_base_and_lock_directories()
            with process_lock(None,args.timeout_seconds,create=True): supervise_uninstall()
        except (OSError,ValueError,subprocess.SubprocessError) as error:
            raise SystemExit(70) from error
        return
    if args.mode=="supervise-install":
        if (args.lock_fd is not None or args.journal is not None or args.state is not None
            or args.previous or args.candidate is not None or args.installer is None
            or args.payload is None or args.installer!=args.payload/"install_payload.sh"
            or args.artifact_sha256 is None
            or ARTIFACT_SHA256.fullmatch(args.artifact_sha256) is None
            or args.bootstrap_sha256 is not None):
            raise SystemExit(65)
        with process_lock(None,args.timeout_seconds,create=True) as fd:
            os.dup2(fd,9); os.set_inheritable(9,True)
            environment={**os.environ,"TUNTUN_RECOVERY_LOCK_FD":"9"}
            completed=subprocess.run(
                (str(args.installer),str(args.payload),args.artifact_sha256),
                env=environment,pass_fds=(9,),check=False,
            )
        raise SystemExit(completed.returncode)
    with process_lock(args.lock_fd,args.timeout_seconds):
        if args.mode=="recover":
            if any(value is not None for value in (args.journal,args.state,args.candidate,args.artifact_sha256,args.bootstrap_sha256,args.installer,args.payload)) or args.previous:
                raise SystemExit(65)
            try: recover()
            except (OSError,ValueError,subprocess.SubprocessError) as error:
                raise SystemExit(70) from error
            return
        if (args.journal is None or args.journal.parent!=BASE/"journal"
            or args.state is None or args.candidate is None or args.artifact_sha256 is None
            or args.installer is not None or args.payload is not None
            or args.bootstrap_sha256 is not None):
            raise SystemExit(65)
        checked=validate_record({"state":args.state,"previous":args.previous,"candidate":str(args.candidate),"artifact_sha256":args.artifact_sha256})
        durable_write(args.journal,checked); checked_record(args.journal)

if __name__=="__main__": main()
```

```python
# scripts/verify_reachy_archive.py
import argparse
import hashlib
import json
import os
import re
import stat
import struct
import tomllib
import zlib
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_BYTES=4*1024*1024*1024
MAX_MEMBER_BYTES=2*1024*1024*1024
MAX_EXPANDED_BYTES=12*1024*1024*1024
MAX_MEMBERS=50_000
MAX_MANIFEST_BYTES=8*1024*1024
EMPTY_SHA256=hashlib.sha256(b"").hexdigest()
PATH_PATTERN=re.compile(r"[A-Za-z0-9._+/-]{1,240}")
REQUIRED = frozenset({
    "app.toml", "compatibility.json", "entrypoint.sh", "install_payload.sh", "recover_install.sh",
    "install_recovery_hook.sh", "recovery_bootstrap.py",
    "locks/uv.lock", "verify_reachy_wheelhouse.py",
    "wheelhouse/manifest.json",
})
EXECUTABLE_MEMBERS=frozenset({"entrypoint.sh","install_payload.sh","recover_install.sh","install_recovery_hook.sh"})
CONTROL_MEMBERS=frozenset({"app.toml","compatibility.json","locks/uv.lock","wheelhouse/manifest.json"})
STREAM_BYTES=1024*1024
MAX_TAR_TRAILING_PADDING_BYTES=1024*1024
MAX_JSON_CONTAINERS=MAX_MEMBERS+8
MAX_JSON_STRUCTURE_TOKENS=MAX_MEMBERS*12+128

class _JSONInputError(Exception): pass

def _canonical_json(value) -> bytes:
    return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()

def _no_duplicate_keys(pairs):
    value={}
    for key,item in pairs:
        if key in value: raise _JSONInputError("duplicate JSON key")
        value[key]=item
    return value

def _bounded_json(raw,reason):
    try:
        text=raw.decode("utf-8",errors="strict")
        depth=containers=0; tokens=1; in_string=escaped=False
        for character in text:
            if in_string:
                if escaped: escaped=False
                elif character=="\\": escaped=True
                elif character=='"': in_string=False
                continue
            if character=='"': in_string=True
            elif character in "[{":
                depth+=1; containers+=1
                if depth>4 or containers>MAX_JSON_CONTAINERS: raise _JSONInputError()
            elif character in "]}":
                depth-=1
                if depth<0: raise _JSONInputError()
            elif character in ",:":
                tokens+=1
                if tokens>MAX_JSON_STRUCTURE_TOKENS: raise _JSONInputError()
        if in_string or depth!=0: raise _JSONInputError()
        def bounded_int(value):
            if len(value.removeprefix("-"))>20: raise _JSONInputError()
            return int(value)
        def reject_noninteger(_value): raise _JSONInputError()
        return json.loads(
            text,object_pairs_hook=_no_duplicate_keys,parse_int=bounded_int,
            parse_float=reject_noninteger,parse_constant=reject_noninteger,
        )
    except (UnicodeError,json.JSONDecodeError,RecursionError,_JSONInputError) as error:
        raise RuntimeError(reason) from error

def _canonical_member_path(raw:str) -> str:
    if "\\" in raw or PATH_PATTERN.fullmatch(raw) is None:
        raise RuntimeError("unsafe Reachy archive member")
    path=PurePosixPath(raw.rstrip("/"))
    canonical=path.as_posix()
    if path.is_absolute() or not canonical or canonical=="." or ".." in path.parts:
        raise RuntimeError("unsafe Reachy archive member")
    if raw.rstrip("/")!=canonical:
        raise RuntimeError("unsafe Reachy archive member")
    return canonical

class FrozenArchive:
    def __init__(self,path):
        self.path=Path(path); named=self.path.stat(follow_symlinks=False)
        if not stat.S_ISREG(named.st_mode) or named.st_size>MAX_ARCHIVE_BYTES:
            raise RuntimeError("invalid Reachy archive")
        self.fd=os.open(self.path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
        opened=os.fstat(self.fd)
        if (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino):
            os.close(self.fd); raise RuntimeError("Reachy archive changed")
        self.identity=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
    def __enter__(self): return self
    def __exit__(self,*_args): os.close(self.fd)
    def rewind(self): os.lseek(self.fd,0,os.SEEK_SET)
    def verify_unchanged(self):
        opened=os.fstat(self.fd); named=self.path.stat(follow_symlinks=False)
        current=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
        if current!=self.identity or (named.st_dev,named.st_ino)!=(opened.st_dev,opened.st_ino):
            raise RuntimeError("Reachy archive changed")
    def digest(self):
        self.rewind(); hasher=hashlib.sha256(); remaining=self.identity[2]
        while remaining:
            chunk=os.read(self.fd,min(STREAM_BYTES,remaining))
            if not chunk: raise RuntimeError("Reachy archive changed")
            hasher.update(chunk); remaining-=len(chunk)
        if os.read(self.fd,1): raise RuntimeError("Reachy archive changed")
        self.verify_unchanged(); return hasher.hexdigest()
    def stream(self):
        self.rewind(); return os.fdopen(os.dup(self.fd),"rb")

class StrictGzipReader:
    def __init__(self,source):
        self.source=source; self.pending=b""; self.finished=False
        self.decompressor=zlib.decompressobj(-zlib.MAX_WBITS)
        self.crc=0; self.size=0
        fixed=self._compressed(10)
        if (len(fixed)!=10 or fixed[:4]!=b"\x1f\x8b\x08\x00"
            or fixed[8:10]!=b"\x02\xff"):
            raise RuntimeError("noncanonical gzip header")
        self.mtime=struct.unpack("<I",fixed[4:8])[0]
    def _compressed(self,size):
        result=self.pending[:size]; self.pending=self.pending[len(result):]
        if len(result)<size: result+=self.source.read(size-len(result))
        return result
    def _finish(self):
        trailer=self._compressed(8)
        if len(trailer)!=8: raise RuntimeError("truncated gzip trailer")
        expected_crc,expected_size=struct.unpack("<II",trailer)
        if expected_crc!=self.crc or expected_size!=(self.size&0xFFFFFFFF):
            raise RuntimeError("invalid gzip trailer")
        if self._compressed(1):
            raise RuntimeError("trailing or concatenated gzip payload")
        self.finished=True
    def read(self,size=-1):
        if size is None or size<0: raise ValueError("bounded gzip read required")
        output=bytearray()
        while len(output)<size and not self.finished:
            if self.decompressor.eof:
                self._finish(); break
            if not self.pending:
                self.pending=self.source.read(64*1024)
                if not self.pending: raise RuntimeError("truncated deflate stream")
            compressed=self.pending; self.pending=b""
            try: decoded=self.decompressor.decompress(compressed,size-len(output))
            except zlib.error as error: raise RuntimeError("invalid deflate stream") from error
            if self.decompressor.eof: self.pending=self.decompressor.unused_data
            elif self.decompressor.unconsumed_tail: self.pending=self.decompressor.unconsumed_tail
            output.extend(decoded); self.crc=zlib.crc32(decoded,self.crc); self.size+=len(decoded)
        return bytes(output)

class ExpandedReader:
    def __init__(self,source): self.source=source; self.expanded=0
    def read(self,size):
        value=self.source.read(size); self.expanded+=len(value)
        if self.expanded>MAX_EXPANDED_BYTES: raise RuntimeError("Reachy expanded-byte limit")
        return value

class TarMemberReader:
    def __init__(self,source,size): self.source=source; self.remaining=size
    def read(self,size):
        if not self.remaining: return b""
        value=self.source.read(min(size,self.remaining)); self.remaining-=len(value)
        return value

def _read_exact(source,size):
    chunks=[]; remaining=size
    while remaining:
        chunk=source.read(remaining)
        if not chunk: raise RuntimeError("truncated USTAR archive")
        chunks.append(chunk); remaining-=len(chunk)
    return b"".join(chunks)

def _tar_octal(field):
    if len(field)<2 or field[-1:]!=b"\0" or re.fullmatch(rb"[0-7]+",field[:-1]) is None:
        raise RuntimeError("invalid USTAR number")
    return int(field[:-1],8)

def _tar_device(field):
    return 0 if field==b"\0"*len(field) else _tar_octal(field)

def _tar_text(field,allow_full):
    if b"\0" in field:
        value,padding=field.split(b"\0",1)
        if any(padding): raise RuntimeError("noncanonical USTAR text field")
        return value
    if not allow_full: raise RuntimeError("noncanonical USTAR text field")
    return field

def _ustar_name(header,is_directory):
    name=_tar_text(header[:100],True); prefix=_tar_text(header[345:500],True)
    try:
        raw=((prefix+b"/") if prefix else b"")+name; decoded=raw.decode("utf-8")
        if decoded.endswith("/")!=is_directory:
            raise RuntimeError("noncanonical USTAR member name")
        return _canonical_member_path(decoded)
    except UnicodeDecodeError as error: raise RuntimeError("invalid USTAR name") from error

def _read_archive(source:FrozenArchive,extract:Path|None=None,expected_rows=None):
    rows=[]; controls={}; seen=set(); member_count=0; trailing=0; archive_mtime=None
    with source.stream() as compressed:
        gzip_stream=StrictGzipReader(compressed); stream=ExpandedReader(gzip_stream)
        while True:
            header=_read_exact(stream,512)
            if header==b"\0"*512:
                if _read_exact(stream,512)!=b"\0"*512:
                    raise RuntimeError("invalid USTAR end marker")
                expected_trailing=(-stream.expanded)%10_240
                while chunk:=stream.read(512):
                    trailing+=len(chunk)
                    if (trailing>expected_trailing or len(chunk)!=512 or any(chunk)):
                        raise RuntimeError("trailing USTAR payload")
                if trailing!=expected_trailing: raise RuntimeError("noncanonical USTAR padding")
                break
            if header[257:265]!=b"ustar\x0000":
                raise RuntimeError("only canonical USTAR is accepted")
            if (re.fullmatch(rb"[0-7]{6}\0 ",header[148:156]) is None
                or any(header[157:257]) or any(header[265:329])
                or any(header[500:512])):
                raise RuntimeError("noncanonical USTAR header")
            stored=int(header[148:154],8)
            checksum=sum(header[:148])+8*ord(" ")+sum(header[156:])
            if stored!=checksum: raise RuntimeError("invalid USTAR checksum")
            kind_flag=header[156:157]
            if kind_flag in {b"x",b"g",b"L",b"K",b"S"}:
                raise RuntimeError("PAX/GNU/sparse metadata is forbidden")
            if kind_flag not in {b"0",b"5"}:
                raise RuntimeError("unsafe Reachy archive member")
            kind="directory" if kind_flag==b"5" else "file"
            path=_ustar_name(header,kind=="directory")
            mode=_tar_octal(header[100:108]); uid=_tar_octal(header[108:116])
            gid=_tar_octal(header[116:124]); size=_tar_octal(header[124:136])
            mtime=_tar_octal(header[136:148]); devmajor=_tar_device(header[329:337])
            devminor=_tar_device(header[337:345])
            if uid or gid or devmajor or devminor:
                raise RuntimeError("noncanonical USTAR ownership/device fields")
            if archive_mtime is None: archive_mtime=mtime
            elif mtime!=archive_mtime: raise RuntimeError("noncanonical USTAR mtime")
            member_count+=1
            if member_count>MAX_MEMBERS or path in seen: raise RuntimeError("Reachy archive inventory mismatch")
            seen.add(path)
            required_mode=0o755 if kind=="directory" or path in EXECUTABLE_MEMBERS else 0o644
            if mode!=required_mode or size>MAX_MEMBER_BYTES or (kind=="directory" and size):
                raise RuntimeError("unsafe Reachy archive member")
            member=TarMemberReader(stream,size); hasher=hashlib.sha256(); actual_size=0; control=[]
            output=None; target=None
            if extract is not None:
                target=extract.joinpath(*PurePosixPath(path).parts)
                if kind=="directory": target.mkdir(mode=required_mode,parents=True,exist_ok=True)
                else:
                    target.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
                    output=target.open("xb")
            try:
                while chunk:=member.read(STREAM_BYTES):
                    actual_size+=len(chunk); hasher.update(chunk)
                    if path in CONTROL_MEMBERS:
                        if actual_size>MAX_MANIFEST_BYTES: raise RuntimeError("Reachy control member limit")
                        control.append(chunk)
                    if output is not None: output.write(chunk)
                if member.remaining or actual_size!=size: raise RuntimeError("truncated Reachy member")
                if output is not None: output.flush(); os.fsync(output.fileno())
            finally:
                if output is not None: output.close()
            if target is not None: target.chmod(required_mode)
            padding=(-size)%512
            if padding and _read_exact(stream,padding)!=b"\0"*padding:
                raise RuntimeError("invalid USTAR member padding")
            if path in CONTROL_MEMBERS: controls[path]=b"".join(control)
            row={"path":path,"type":kind,"sha256":hasher.hexdigest(),"size":actual_size,"mode":required_mode}
            if expected_rows is not None:
                index=len(rows)
                if index>=len(expected_rows) or row!=expected_rows[index]:
                    raise RuntimeError("Reachy archive changed between inventory and extract")
            rows.append(row)
    if (not member_count or archive_mtime!=gzip_stream.mtime
        or (expected_rows is not None and rows!=expected_rows)):
        raise RuntimeError("Reachy archive inventory mismatch")
    if [item["path"] for item in rows]!=sorted(item["path"] for item in rows):
        raise RuntimeError("Reachy archive inventory mismatch")
    if not REQUIRED<=seen or not CONTROL_MEMBERS<=set(controls) or "archive-manifest.json" in seen:
        raise RuntimeError("Reachy archive inventory mismatch")
    source.verify_unchanged(); return rows,controls

def _load_manifest(path:Path):
    named=path.stat(follow_symlinks=False)
    if not stat.S_ISREG(named.st_mode) or named.st_size>MAX_MANIFEST_BYTES:
        raise RuntimeError("Reachy archive inventory mismatch")
    fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    try:
        opened=os.fstat(fd)
        if (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino):
            raise RuntimeError("Reachy archive inventory mismatch")
        chunks=[]; remaining=opened.st_size
        while remaining:
            chunk=os.read(fd,min(STREAM_BYTES,remaining))
            if not chunk: raise RuntimeError("Reachy archive inventory mismatch")
            chunks.append(chunk); remaining-=len(chunk)
        if os.read(fd,1): raise RuntimeError("Reachy archive inventory mismatch")
        final=os.fstat(fd); renamed=path.stat(follow_symlinks=False)
        if ((final.st_dev,final.st_ino,final.st_size,final.st_mtime_ns,final.st_ctime_ns)
            !=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
            or (renamed.st_dev,renamed.st_ino)!=(opened.st_dev,opened.st_ino)):
            raise RuntimeError("Reachy archive inventory mismatch")
        raw=b"".join(chunks)
    finally: os.close(fd)
    value=_bounded_json(raw,"Reachy archive inventory mismatch")
    if raw!=_canonical_json(value): raise RuntimeError("Reachy archive inventory mismatch")
    return value

def write_manifest(archive:Path,output:Path) -> None:
    with FrozenArchive(archive) as source:
        actual_sha256=source.digest(); rows,_=_read_archive(source)
        value={
            "schema_version":"tuntun.reachy-archive-manifest.v1",
            "archive_sha256":actual_sha256,
            "manifest_location":{
                "kind":"adjacent_external_sidecar","archive_member":False,
                "suffix":".manifest.json",
            },
            "members":rows,
        }
    data=_canonical_json(value); parent=output.parent
    directory=os.open(
        parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0),
    )
    try:
        descriptor=os.open(
            output.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),
            0o644,dir_fd=directory,
        )
        try:
            view=memoryview(data)
            while view:
                written=os.write(descriptor,view); view=view[written:]
            os.fchmod(descriptor,0o644); os.fsync(descriptor)
        finally: os.close(descriptor)
        os.fsync(directory)
    except OSError as error:
        raise RuntimeError("manifest output exists or is unsafe") from error
    finally: os.close(directory)

def verify(
    archive:Path,expected_sha256:str,manifest:Path,extract:Path|None,
) -> None:
    if re.fullmatch(r"[0-9a-f]{64}",expected_sha256) is None:
        raise RuntimeError("Reachy archive digest mismatch")
    with FrozenArchive(archive) as source:
        actual_sha256=source.digest()
        # Reject substituted transfer bytes before entering any archive parser.
        if actual_sha256!=expected_sha256: raise RuntimeError("Reachy archive digest mismatch")
        rows,controls=_read_archive(source); value=_load_manifest(manifest)
        expected_manifest={
            "schema_version":"tuntun.reachy-archive-manifest.v1",
            "archive_sha256":actual_sha256,
            "manifest_location":{
                "kind":"adjacent_external_sidecar","archive_member":False,
                "suffix":".manifest.json",
            },
            "members":rows,
        }
        if _canonical_json(value)!=_canonical_json(expected_manifest):
            raise RuntimeError("Reachy archive inventory mismatch")
        try: app=tomllib.loads(controls["app.toml"].decode("utf-8"))
        except (UnicodeError,tomllib.TOMLDecodeError,RecursionError) as error:
            raise RuntimeError("Reachy app manifest mismatch") from error
        expected_app={
            "id":"com.tuntun.edge", "version":"0.1.0-beta.1",
            "entrypoint":"entrypoint.sh", "managed_by":"reachy-mini-app-assistant",
        }
        expected_runtime_keys={"python_source","telemetry","network_downloads"}
        expected_app_compatibility_keys={
            "sdk_pin_source","daemon_pin_source","require_exact_match",
        }
        if (
            type(app) is not dict or set(app)!={"app","runtime","compatibility"}
            or type(app["app"]) is not dict or app["app"]!=expected_app
            or type(app["runtime"]) is not dict
            or set(app["runtime"])!=expected_runtime_keys
            or app["runtime"]["python_source"]!="compatibility.json"
            or app["runtime"]["telemetry"] is not False
            or app["runtime"]["network_downloads"] is not False
            or type(app["compatibility"]) is not dict
            or set(app["compatibility"])!=expected_app_compatibility_keys
            or app["compatibility"]["sdk_pin_source"]!="uv.lock"
            or app["compatibility"]["daemon_pin_source"]!="var/hardware/reachy-capabilities.json"
            or app["compatibility"]["require_exact_match"] is not True
        ):
            raise RuntimeError("Reachy app manifest mismatch")
        compatibility_raw=controls["compatibility.json"]
        compatibility=_bounded_json(compatibility_raw,"Reachy compatibility manifest mismatch")
        if compatibility_raw!=_canonical_json(compatibility):
            raise RuntimeError("Reachy compatibility manifest is not canonical")
        expected_compatibility_keys={
            "schema_version","sdk","daemon","python_executable","python_version",
            "python_abi","selected_wheel_tag","target_tag_set_sha256",
            "runtime_inventory_sha256",
            "uv_lock_sha256","wheelhouse_manifest_sha256","exact_match",
        }
        version_pattern=r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}"
        if (
            not isinstance(compatibility,dict)
            or set(compatibility)!=expected_compatibility_keys
            or compatibility["schema_version"]!="tuntun.reachy-compatibility.v1"
            or not isinstance(compatibility["sdk"],str)
            or re.fullmatch(version_pattern,compatibility["sdk"]) is None
            or not isinstance(compatibility["daemon"],str)
            or re.fullmatch(version_pattern,compatibility["daemon"]) is None
            or compatibility["python_executable"]!="/venvs/apps_venv/bin/python3"
            or (compatibility["python_version"],compatibility["python_abi"])
               not in {("3.11","cp311"),("3.12","cp312")}
            or compatibility["selected_wheel_tag"]!="py3-none-any"
            or re.fullmatch(r"[0-9a-f]{64}",compatibility["target_tag_set_sha256"]) is None
            or re.fullmatch(r"[0-9a-f]{64}",compatibility["runtime_inventory_sha256"]) is None
            or compatibility["exact_match"] is not True
        ):
            raise RuntimeError("Reachy compatibility manifest mismatch")
        if compatibility.get("wheelhouse_manifest_sha256") != hashlib.sha256(controls["wheelhouse/manifest.json"]).hexdigest():
            raise RuntimeError("Reachy wheel manifest binding mismatch")
        if compatibility.get("uv_lock_sha256") != hashlib.sha256(controls["locks/uv.lock"]).hexdigest():
            raise RuntimeError("Reachy lock binding mismatch")
        if extract is not None:
            extract.mkdir(mode=0o700,parents=False,exist_ok=False)
            _read_archive(source,extract=extract,expected_rows=rows)
        source.verify_unchanged()

if __name__ == "__main__":
    parser=argparse.ArgumentParser(); parser.add_argument("--archive",type=Path,required=True)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--manifest",type=Path); mode.add_argument("--write-manifest",type=Path)
    parser.add_argument("--expected-sha256"); parser.add_argument("--extract",type=Path)
    args=parser.parse_args()
    if args.write_manifest is not None:
        if args.expected_sha256 is not None or args.extract is not None: parser.error("write mode accepts only archive/output")
        write_manifest(args.archive,args.write_manifest)
    else:
        if args.expected_sha256 is None: parser.error("verify mode requires expected SHA-256")
        verify(args.archive,args.expected_sha256,args.manifest,args.extract)
```

```python
# scripts/verify_reachy_wheelhouse.py (also copied into the app root)
import argparse, hashlib, json, os, stat
from pathlib import Path
MAX_MANIFEST_BYTES=8*1024*1024
MAX_WHEELS=4096

class _JSONInputError(Exception): pass

def no_duplicates(pairs):
    value={}
    for key,item in pairs:
        if key in value: raise _JSONInputError("duplicate wheelhouse manifest key")
        value[key]=item
    return value
def bounded_json(raw):
    try:
        text=raw.decode("utf-8",errors="strict")
        depth=containers=0;tokens=1;in_string=escaped=False
        for character in text:
            if in_string:
                if escaped: escaped=False
                elif character=="\\": escaped=True
                elif character=='"': in_string=False
                continue
            if character=='"': in_string=True
            elif character in "[{":
                depth+=1;containers+=1
                if depth>3 or containers>MAX_WHEELS+4: raise _JSONInputError()
            elif character in "]}":
                depth-=1
                if depth<0: raise _JSONInputError()
            elif character in ",:":
                tokens+=1
                if tokens>MAX_WHEELS*8+64: raise _JSONInputError()
        if in_string or depth!=0: raise _JSONInputError()
        def bounded_int(value):
            if len(value.removeprefix("-"))>20: raise _JSONInputError()
            return int(value)
        def reject_noninteger(_value): raise _JSONInputError()
        return json.loads(
            text,object_pairs_hook=no_duplicates,parse_int=bounded_int,
            parse_float=reject_noninteger,parse_constant=reject_noninteger,
        )
    except (UnicodeError,json.JSONDecodeError,RecursionError,_JSONInputError) as error:
        raise RuntimeError("invalid wheelhouse manifest JSON") from error
def canonical(value): return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def frozen_bytes(path,limit):
    named=path.stat(follow_symlinks=False)
    if not stat.S_ISREG(named.st_mode) or named.st_size>limit: raise RuntimeError("wheelhouse control limit")
    fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    try:
        opened=os.fstat(fd)
        if (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino): raise RuntimeError("wheelhouse control changed")
        chunks=[];remaining=opened.st_size
        while remaining:
            chunk=os.read(fd,min(1024*1024,remaining))
            if not chunk: raise RuntimeError("wheelhouse control changed")
            chunks.append(chunk);remaining-=len(chunk)
        if os.read(fd,1): raise RuntimeError("wheelhouse control changed")
        final=os.fstat(fd);renamed=path.stat(follow_symlinks=False)
        if ((final.st_dev,final.st_ino,final.st_size,final.st_mtime_ns,final.st_ctime_ns)
            !=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
            or (renamed.st_dev,renamed.st_ino)!=(opened.st_dev,opened.st_ino)):
            raise RuntimeError("wheelhouse control changed")
        return b"".join(chunks)
    finally: os.close(fd)

def frozen_digest(path):
    named=path.stat(follow_symlinks=False)
    if not stat.S_ISREG(named.st_mode): raise RuntimeError("wheel input is not regular")
    fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)); hasher=hashlib.sha256()
    try:
        opened=os.fstat(fd)
        if (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino): raise RuntimeError("wheel input changed")
        remaining=opened.st_size
        while remaining:
            chunk=os.read(fd,min(1024*1024,remaining))
            if not chunk: raise RuntimeError("wheel input changed")
            hasher.update(chunk); remaining-=len(chunk)
        if os.read(fd,1): raise RuntimeError("wheel input changed")
        final=os.fstat(fd); renamed=path.stat(follow_symlinks=False)
        if ((final.st_dev,final.st_ino,final.st_size,final.st_mtime_ns,final.st_ctime_ns)
            !=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
            or (renamed.st_dev,renamed.st_ino)!=(opened.st_dev,opened.st_ino)):
            raise RuntimeError("wheel input changed")
        return hasher.hexdigest(),opened.st_size
    finally: os.close(fd)
def digest(path): return frozen_digest(path)[0]
def exclusive_bytes(path,data):
    parent=os.open(
        path.parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0),
    )
    try:
        fd=os.open(
            path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),
            0o644,dir_fd=parent,
        )
        try:
            view=memoryview(data)
            while view:
                written=os.write(fd,view); view=view[written:]
            os.fsync(fd)
        finally: os.close(fd)
        os.fsync(parent)
    finally: os.close(parent)
def manifest(root,platform,abi):
    wheels=sorted(root.joinpath("wheelhouse").glob("*.whl"))
    if not wheels or len(wheels)>MAX_WHEELS: raise RuntimeError("invalid Reachy wheelhouse size")
    wheel_rows=[]
    for item in wheels:
        sha256,size=frozen_digest(item)
        wheel_rows.append({"name":item.name,"sha256":sha256,"size":size})
    return {"schema_version":"tuntun.reachy-wheelhouse.v1","platform":platform,"abi":abi,
            "uv_lock_sha256":digest(root/"locks/uv.lock"),
            "wheels":wheel_rows}
def main():
    parser=argparse.ArgumentParser(); mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write",action="store_true"); mode.add_argument("--verify",action="store_true")
    parser.add_argument("root",type=Path); parser.add_argument("--platform",required=True); parser.add_argument("--abi",required=True)
    args=parser.parse_args(); path=args.root/"wheelhouse/manifest.json"
    actual=manifest(args.root,args.platform,args.abi)
    if args.write: exclusive_bytes(path,canonical(actual))
    else:
        raw=frozen_bytes(path,MAX_MANIFEST_BYTES)
        loaded=bounded_json(raw)
        if raw!=canonical(loaded) or raw!=canonical(actual):
            raise RuntimeError("Reachy wheelhouse manifest mismatch")
if __name__=="__main__": main()
```

```python
# scripts/deterministic_tar.py
import argparse
import gzip
import os
import stat
import tarfile
from pathlib import Path
from scripts.verify_reachy_archive import EXECUTABLE_MEMBERS,MAX_MEMBERS

WRITER_VERSION = "tuntun-deterministic-tar-v1"

def write_archive(root: Path, output: Path, mtime: int) -> None:
    paths=[]
    for path in root.rglob("*"):
        paths.append(path)
        if len(paths)>MAX_MEMBERS: raise ValueError("package entry limit")
    paths.sort(key=lambda item:item.relative_to(root).as_posix().encode("utf-8"))
    names={path.relative_to(root).as_posix() for path in paths if stat.S_ISREG(path.stat(follow_symlinks=False).st_mode)}
    if not EXECUTABLE_MEMBERS<=names: raise ValueError("executable inventory incomplete")
    parent=os.open(
        output.parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0),
    )
    output_fd=os.open(
        output.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),
        0o644,dir_fd=parent,
    )
    completed=False
    try:
        with os.fdopen(output_fd,"wb") as raw:
            output_fd=-1
            with gzip.GzipFile(filename="",mode="wb",compresslevel=9,fileobj=raw,mtime=mtime) as compressed:
              with tarfile.open(fileobj=compressed,mode="w",format=tarfile.USTAR_FORMAT) as archive:
                for path in paths:
                    if path.is_symlink(): raise ValueError("package symlinks are forbidden")
                    name=path.relative_to(root).as_posix()
                    info=tarfile.TarInfo(name + ("/" if path.is_dir() else ""))
                    info.uid=info.gid=0; info.uname=info.gname=""; info.mtime=mtime
                    if path.is_dir():
                        info.type=tarfile.DIRTYPE; info.mode=0o755; archive.addfile(info)
                    elif path.is_file():
                        named=path.stat(follow_symlinks=False)
                        if not stat.S_ISREG(named.st_mode): raise ValueError("unsupported package entry")
                        input_fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
                        opened=os.fstat(input_fd)
                        if (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino):
                            os.close(input_fd); raise ValueError("package input changed")
                        identity=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
                        info.size=opened.st_size
                        info.mode=0o755 if name in EXECUTABLE_MEMBERS else 0o644
                        with os.fdopen(input_fd,"rb") as source:
                            archive.addfile(info,source)
                            final=os.fstat(source.fileno()); renamed=path.stat(follow_symlinks=False)
                            if ((final.st_dev,final.st_ino,final.st_size,final.st_mtime_ns,final.st_ctime_ns)!=identity
                                or (renamed.st_dev,renamed.st_ino)!=(opened.st_dev,opened.st_ino)):
                                raise ValueError("package input changed")
                    else: raise ValueError("unsupported package entry")
            raw.flush(); os.fsync(raw.fileno())
        os.fsync(parent)
        completed=True
    finally:
        if output_fd>=0: os.close(output_fd)
        if not completed:
            try: os.unlink(output.name,dir_fd=parent); os.fsync(parent)
            except FileNotFoundError: pass
        os.close(parent)

if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,required=True); parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--mtime",type=int,required=True)
    args=parser.parse_args(); write_archive(args.root,args.output,args.mtime)
```

The build copies the stable recovery source and installer beside the private target installer before archiving; the host transfers `verify_reachy_archive.py` separately so archive safety is checked before extraction, while the copied wheelhouse verifier is self-contained and imports nothing from the absent repository `scripts` package. Deterministic packaging bounds the entry inventory and streams every nofollow, identity-frozen file descriptor into USTAR without `read_bytes()`. After archive creation, the verifier creates its adjacent canonical manifest through a parent-directory descriptor with `O_EXCL|O_NOFOLLOW`, fsyncs the file and directory, and never follows an existing/raced sidecar. The closed manifest binds the whole archive and each normalized path/type/hash/size/mode. Verification hashes the frozen archive descriptor first, rejects a transferred digest mismatch before parsing, then uses its own bounded deflate reader and 512-byte canonical-USTAR parser for inventory and same-descriptor extraction. Header checksum/type/name/mode/size, zero numeric ownership/device fields, empty link/owner names, reserved bytes, canonical regular/directory type, and one common member/GZip mtime are validated before payload; PAX/global-PAX, GNU longname/longlink/sparse, links/devices, duplicate names, bad or noncanonical record padding, nonzero TAR trailing payload, concatenated GZip members, and any bytes after the GZip trailer are blocked. Every decompressed header, body, padding, and end block is charged to the 12-GiB expansion ceiling, at most 50,000 members are admitted, and only four canonical, duplicate-key-free, byte/depth/container/token/number-bounded controls are retained, so no archive, wheel, metadata, or member-sized allocation is permitted. The compatibility control has one exact field set, bounded SDK/daemon version syntax, the fixed accepted interpreter path, one closed version/ABI pair, the universal project-wheel tag, exact accepted target-tag-set/runtime-inventory digests, and exact lock/wheelhouse hashes; neither verifier supplies tuple defaults. The wheelhouse verifier requires exactly one `tuntun-edge` and one `tuntun-contracts` wheel, parses their `WHEEL` metadata, requires only `py3-none-any`, and rejects every third-party/native wheel. The target's `verify-install` independently re-probes and compares every recorded field and imports the closed runtime from the `--system-site-packages` venv before registration; network counters around that probe must remain unchanged. The standalone archive-verifier CLI exercises both manifest-write and verify modes in tests, and the standalone wheelhouse verifier applies the same closed JSON properties before comparing the complete locally reconstructed manifest. `EXECUTABLE_MEMBERS` is the closed set `entrypoint.sh|install_payload.sh|recover_install.sh|install_recovery_hook.sh`; those files are exactly `0755`, other files including `recovery_bootstrap.py` are `0644`, and directories are `0755`. The installer first atomically opens/creates one nofollow owner/mode/inode-checked lock and holds it across old-hook recovery, stable-hook install, journal writes, link switch, registration, candidate health verification, and rollback. Before successor-hook or journal mutation, an existing `current` must be the same owner-owned symlink throughout validation and target an exact owner-only directory directly under `releases`; regular, relative, escaping, dangling, replaced, or wrong-mode targets block. The assistant atomically registers and durably verifies the stable file under `base/recovery/` as a boot-only `before-managed-apps` hook before `journal/`, `current`, or `releases/` changes. Consequently a completely blank target killed at any fsynced state still invokes recovery on reboot without a registered/current candidate. Boot and concurrent installers use the same 30-second lock and cannot interleave; ordinary register/start does not invoke the boot hook, and the candidate entrypoint performs no recovery or lock acquisition, so health can pass while the installer retains the lock. A symlink, owner/mode/inode mismatch, tuple/inventory drift, offline-import failure, or timeout exits `70`; an already-created candidate is rolled back before the prior `current` can change. Shell failure handling calls the same stable recovery state machine as boot: it fsyncs `BASE` after current restoration/removal, fsyncs `releases` after candidate removal, and only then durably writes terminal `recovered`; a power cut after any inverse therefore retries rather than trusting a prematurely terminal record. Each journal snapshot and directory entry is fsynced; every journal is canonical, duplicate-free and structurally/numerically bounded before parsing; all incomplete states roll back idempotently to `recovered`, `complete` is a no-op, and `needs_owner_recovery` blocks. `stop|unregister --if-present` normalizes only the assistant's qualified absent-app condition; any real daemon failure records `needs_owner_recovery`. A same-device rename places owner-only payload bytes at the final path before venv creation, so interpreter paths never name staging. Hard SIGKILL/power loss with prior and blank targets, power loss after every recovery inverse, hostile `current`, concurrent installer/boot recovery, register-start/health under the held lock, ordinary failures, lock faults, completed retry, and repeated resume are tested. Uninstall deregisters only this app's recovery hook and managed app while preserving unrelated assistant state.

- [ ] **Step 4: Run green**

The only automatic hook self-heal is the pre-registration crash window: `journal`, `current`, and `releases` must all be absent, and the unregistered owner-only mode-`0600` stable helper must be byte-identical to the verified candidate. An unmatched orphan, daemon fault, or nonblank state exits `70` before mutation; successful repair is durably registered and re-verified before the first journal or release change.

Write `docs/operations/install-reachy.md` with the exact offline build/install command, numeric-target commissioning prerequisite, exit-code meanings, stable-hook ordering, retry rules, and `uninstall_app.sh` ceremony. The uninstall section states that the durable intent is written before stop, the boot hook resumes only while it remains registered, code/journal/current/helper cleanup begins only after bounded inventories prove both registrations absent, and a hard loss after hook removal may require rerunning the public uninstaller but cannot restart the app. It lists preserved state explicitly: Reachy commissioning, TLS/signing/HMAC keys, household pairing, user data outside the managed-app code root, and every unrelated assistant app/hook. It lists removed state explicitly: only validated `com.tuntun.edge` managed code, `current`, install journals, and its recovery helper. A nonzero result means retry or owner recovery; it never authorizes manual recursive deletion.

Run: `chmod +x deploy/reachy/*.sh && shellcheck deploy/reachy/*.sh && uv run ruff check apps/edge/src/tuntun_edge/cli/main.py apps/edge/src/tuntun_edge/cli/verify_install.py apps/core/src/tuntun_core/cli/commands/reachy.py apps/core/src/tuntun_core/services/reachy/release_qualification.py tests/integration/cli/test_reachy_commands.py tests/integration/deploy/test_reachy_package.py tests/integration/deploy/test_reachy_service_inventory.py && uv run mypy apps/edge/src/tuntun_edge/cli apps/core/src/tuntun_core/cli/commands/reachy.py apps/core/src/tuntun_core/services/reachy/release_qualification.py && REACHY_SDK_VERSION=$(uv run --frozen --offline --no-sync tuntunctl reachy compatibility --field sdk) REACHY_DAEMON_VERSION=$(uv run --frozen --offline --no-sync tuntunctl reachy compatibility --field daemon) REACHY_PYTHON_EXECUTABLE=$(uv run --frozen --offline --no-sync tuntunctl reachy compatibility --field python-executable) REACHY_PYTHON_VERSION=$(uv run --frozen --offline --no-sync tuntunctl reachy compatibility --field python-version) REACHY_PYTHON_ABI=$(uv run --frozen --offline --no-sync tuntunctl reachy compatibility --field python-abi) REACHY_SELECTED_WHEEL_TAG=$(uv run --frozen --offline --no-sync tuntunctl reachy compatibility --field selected-wheel-tag) REACHY_TARGET_TAG_SET_SHA256=$(uv run --frozen --offline --no-sync tuntunctl reachy compatibility --field target-tag-set-sha256) REACHY_RUNTIME_INVENTORY_SHA256=$(uv run --frozen --offline --no-sync tuntunctl reachy compatibility --field runtime-inventory-sha256) SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD) deploy/reachy/build_app.sh && shasum -a 256 -c dist/tuntun-edge-0.1.0-beta.1.tar.gz.sha256 && uv run pytest tests/integration/cli/test_reachy_commands.py tests/integration/deploy/test_reachy_package.py tests/integration/deploy/test_reachy_service_inventory.py -q && TUNTUN_ALLOW_REACHY_HARDWARE=1 uv run pytest -m reachy_hardware tests/hardware/test_edge_package.py -q`

Expected: PASS for stable-hook/firewall-before-state ordering, exact service-row/package/unit/entrypoint agreement, blank-target SIGKILL/power-loss recovery at every fsynced state, power loss after each inverse, hostile-current rejection, completed-journal boot/retry idempotency, installer/boot-recovery serialization and lock faults, register-start/health while the global lock remains held without entrypoint re-lock, absent-app versus real daemon failures, bounded streaming package verification, then a real Reachy reboot with pairing restoration, current firewall receipt, exact listener check, offline essentials, and a synthetic turn.

- [ ] **Step 5: Commit**

```bash
git status --short
git add deploy/reachy/app.toml deploy/reachy/build_app.sh deploy/reachy/install_app.sh deploy/reachy/install_recovery_hook.sh deploy/reachy/install_payload.sh deploy/reachy/recover_install.sh deploy/reachy/recovery_bootstrap.py deploy/reachy/uninstall_app.sh deploy/reachy/entrypoint.sh ops/services/phase1-reachy-edge.v1.json apps/edge/pyproject.toml apps/edge/src/tuntun_edge/cli/main.py apps/edge/src/tuntun_edge/cli/verify_install.py apps/core/src/tuntun_core/cli/commands/reachy.py apps/core/src/tuntun_core/services/reachy/release_qualification.py tests/integration/cli/test_reachy_commands.py uv.lock scripts/deterministic_tar.py scripts/verify_reachy_archive.py scripts/verify_reachy_wheelhouse.py tests/integration/deploy/test_reachy_package.py tests/integration/deploy/test_reachy_service_inventory.py tests/hardware/test_edge_package.py docs/operations/install-reachy.md
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
- Create: `scripts/control_files.py`
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


@pytest.mark.parametrize("mutation",(
    "duplicate_key","alias","explicit_tag","overdeep","oversize",
    "schema_symlink","policy_symlink","change_during_read",
))
def test_security_policy_controls_are_bounded_duplicate_safe_and_frozen(
    security_policy_files,mutate_control_file,mutation,
) -> None:
    schema_path,policy_path=mutate_control_file(security_policy_files,mutation)
    with pytest.raises((PermissionError,TypeError,ValueError)):
        SecurityPolicy.load(schema_path,policy_path)
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
from tuntun_contracts.base import parse_contract_json
@given(st.binary(max_size=1048576))
def test_assistant_turn_is_typed_or_rejected(data):
    try:
        value=parse_contract_json(
            AssistantTurn,data,max_bytes=1_048_576,require_canonical=False,
        )
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
# scripts/control_files.py
import os,stat
from pathlib import Path

import rfc8785

from tuntun_contracts.base import JSONValue,parse_bounded_json_value
from tuntun_core.config.loader import read_bounded_strict_yaml

def read_frozen_control(path:Path,*,max_bytes:int)->bytes:
    path=Path(path)
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|getattr(os,"O_NOFOLLOW",0))
    try:
        before=os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_uid not in {0,os.geteuid()}
            or before.st_mode&0o022 or not 1<=before.st_size<=max_bytes
        ): raise PermissionError("unsafe control file")
        chunks=[]; total=0
        while True:
            chunk=os.read(fd,min(65_536,max_bytes+1-total))
            if not chunk: break
            chunks.append(chunk); total+=len(chunk)
            if total>max_bytes: raise ValueError("control file too large")
        after=os.fstat(fd); named=os.lstat(path)
        if (
            total!=before.st_size
            or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
            !=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
            or (after.st_dev,after.st_ino)!=(named.st_dev,named.st_ino)
        ): raise PermissionError("control file changed during read")
        return b"".join(chunks)
    finally: os.close(fd)

def parse_control_json(
    path:Path,*,max_bytes:int,require_canonical:bool,
) -> JSONValue:
    raw=read_frozen_control(path,max_bytes=max_bytes)
    return parse_control_json_bytes(
        raw,max_bytes=max_bytes,require_canonical=require_canonical,
    )

def parse_control_json_bytes(
    raw:bytes,*,max_bytes:int,require_canonical:bool,
) -> JSONValue:
    value=parse_bounded_json_value(
        raw,max_bytes=max_bytes,max_depth=32,max_containers=4_096,
        max_structure_tokens=16_384,
    )
    if require_canonical and raw not in {rfc8785.dumps(value),rfc8785.dumps(value)+b"\n"}:
        raise ValueError("control JSON is not canonical")
    return value

def parse_control_yaml(path:Path,*,max_bytes:int):
    return read_bounded_strict_yaml(path,max_bytes=max_bytes)
```

```python
# scripts/security_gate.py
from dataclasses import dataclass
from datetime import UTC,datetime,timedelta
from uuid import UUID
import jsonschema
from scripts.control_files import parse_control_json,parse_control_yaml
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
        schema=parse_control_json(
            schema_path,max_bytes=262_144,require_canonical=False,
        )
        raw=parse_control_yaml(policy_path,max_bytes=65_536)
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(raw)
        return cls(schema,raw)
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
git add docs/privacy/threat-model.md docs/privacy/data-flow-inventory.md docs/privacy/provider-boundaries.md docs/privacy/residual-risks.md security/policy-v1.yaml security/policy-v1.schema.json scripts/control_files.py scripts/security_gate.py packages/contracts/src/tuntun_contracts/provider.py apps/core/src/tuntun_core/api/middleware.py tests/security/test_security_policy.py tests/security/test_network_surface.py tests/security/test_egress_surface.py tests/property/test_event_parser_fuzz.py tests/property/test_media_header_fuzz.py tests/property/test_model_output_fuzz.py tests/property/test_memory_proposal_fuzz.py tests/property/test_openapi_input_fuzz.py tests/property/test_provider_usage_fuzz.py tests/property/test_backup_parser_fuzz.py tests/property/test_import_export_fuzz.py
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
- Create: `security/schemas/collection-request-v1.schema.json`
- Create: `security/schemas/target-runtime-receipt-v1.schema.json`
- Create: `security/schemas/target-network-scan-receipt-v1.schema.json`
- Create: `security/schemas/target-commissioning-receipt-v1.schema.json`
- Create: `security/schemas/qualification-artifact-manifest-v1.schema.json`
- Create: `security/evidence-signers-v1.json`
- Create: `security/tool-versions-v1.json`
- Create: `security/license-policy-v1.yaml`
- Create: `scripts/evidence.py`
- Create: `scripts/collect_release_evidence.py`
- Create: `scripts/commission_release_target.py`
- Create: `scripts/qualify_release_artifacts.py`
- Create: `scripts/collect_target_runtime.py`
- Create: `scripts/run_network_vantage_scan.py`
- Create: `scripts/verify_release_evidence.py`
- Modify: `scripts/verify_private_data.py`
- Modify: `Makefile`
- Create: `.github/workflows/security.yml`
- Create: `.github/workflows/release.yml`
- Test: `tests/security/test_evidence_signature.py`
- Test: `tests/security/test_supply_chain_evidence.py`
- Test: `tests/security/test_target_host_evidence.py`
- Test: `tests/security/test_target_collectors.py`
- Test: `tests/security/test_release_qualification.py`
- Test: `tests/release/test_reproducible_build.py`
- Test (consume): `tests/ci/test_workflow_policy.py`
- Test (consume): `tests/security/test_private_data_scanner.py`

**Interfaces:** `EvidenceSigner(key_id: str, purpose: EvidencePurpose, private_key: Ed25519PrivateKey, clock: Clock).sign(payload: dict) -> SignedEvidence`; `SignerRegistry.load(schema_path: Path, registry_path: Path) -> SignerRegistry`; `parse_signed_evidence(raw: bytes) -> SignedEvidence`; `open_signed_evidence(envelope: SignedEvidence, schema: dict, registry: SignerRegistry, expected_purpose: EvidencePurpose, now: datetime) -> dict`; `signed_envelope_sha256(envelope: SignedEvidence) -> str`; `commission_target(runner: CommissioningRunner, owner_signer: EvidenceSigner, scanner_identities: Mapping[str, tuple[str, ...]], scan_targets: Mapping[str, str], valid_until: datetime, qualification_manifest_sha256: str) -> SignedEvidence` (exactly six positional parameters); `collect_target_runtime(commissioning, request_envelope, request_schema, registry, runner, signer, *, runtime_root=DEFAULT_RUNTIME_ROOT, config_root=DEFAULT_CONFIG_ROOT) -> SignedEvidence`; `scan_target(commissioning, request_envelope, request_schema, runtime_envelope, runtime_schema, registry, vantage: Literal["lan","outer"], scanner, signer) -> SignedEvidence`; `verify_target_receipts(candidate, envelopes, requests, brackets, schemas, registry, commissioning_envelope, expected_config_sha256, verification_now, verification_monotonic_ns) -> VerifiedTargetReceipts`; `collect(candidate: Candidate, qualification_envelope: SignedEvidence, commissioning_envelope: SignedEvidence, runner: ReleaseRunner, signer: EvidenceSigner) -> SignedEvidence`. `parse_signed_evidence` is the sole outer-wire/file ingress: it caps canonical duplicate-free JSON at 2 MiB and validates the strict bounded header/signature/payload container before any semantic payload field is read. `open_signed_evidence` then revalidates a detached copy and applies the exact purpose schema before signature/binding checks or returning another detached payload copy. Commissioning provisions or idempotently reopens an owner-controlled evidence key/certificate in namespace `tuntun.release.qualification-target.v1`, bound to the independently read hardware hash and qualification-manifest hash; a clean target has no runtime release, core certificate, or core key. Collectors authenticate that separate evidence identity. Only the later installed-runtime receipt binds the actual core-leaf fingerprint and installed release-manifest hash. `Candidate` is comparison-only and supplies frozen expected values; no target or network collector accepts it. The orchestrator invokes runtime→LAN→outer sequentially. For each call it samples one monotonic send tick, writes that exact integer into both the signed `collection_request` and its local bracket, and binds a unique UUID request ID, 256-bit nonce, run/role/ordinal, request commitment, request-envelope SHA-256, and maximum RTT. The receipt echoes the exact signed-request hash in addition to the request fields. Final order, total window, RTT, and evidence age derive only from authenticated orchestrator brackets; remote wall time is never used for cross-host ordering. `collect` consumes a previously signed qualification manifest and commissioning receipt and samples authoritative wall and monotonic verification time only after all three calls complete.

- [ ] **Step 1: Write failing signature/tool tests**

```python
# tests/security/test_supply_chain_evidence.py
import pytest
from scripts.collect_release_evidence import REQUIRED_PREFIXES,REQUIRED_REACHY_ARTIFACT_ROLES,collect
def test_every_required_tool_consumes_qualified_bytes_without_rebuild(
    fake_release_runner,fake_signer,candidate,qualification_envelope,
    commissioning_envelope,
):
    envelope=collect(
        candidate,qualification_envelope,commissioning_envelope,
        fake_release_runner,fake_signer,
    ); calls=(" ".join(call) for call in fake_release_runner.calls)
    calls=tuple(calls); assert all(any(call.startswith(prefix) for call in calls) for prefix in REQUIRED_PREFIXES)
    assert envelope.payload["history_scan"]["scope"]=="all_reachable_history"
    assert envelope.payload["reproducibility"]=={"build_count":2,"identical":True,"manifest_sha256":"a"*64}
    assert fake_release_runner.build_calls==()
    assert fake_release_runner.evidence_pending_install_verified
    assert fake_release_runner.private_scan_roots == (".", "dist", "var")
    assert set(envelope.payload["target_receipt_hashes"]) == {
        "target_commissioning", "target_runtime", "lan_scan", "outer_scan",
        "request_target_runtime", "request_lan_scan", "request_outer_scan",
    }
    assert fake_release_runner.target_execution_requests == (
        "target_runtime", "lan_scan", "outer_scan",
    )
    assert not hasattr(fake_release_runner,"target_receipts")
    artifacts={item["role"] for item in envelope.payload["artifacts"]}
    assert REQUIRED_REACHY_ARTIFACT_ROLES<=artifacts


@pytest.mark.parametrize(
    "role",("reachy_package","reachy_package_sha256","reachy_package_manifest"),
)
def test_security_evidence_rejects_missing_reachy_package_sidecar(
    fake_release_runner,fake_signer,candidate,qualification_envelope,
    commissioning_envelope,resign_qualification_without,role,
):
    qualification_envelope=resign_qualification_without(qualification_envelope,role)
    with pytest.raises(RuntimeError,match="Reachy artifact roles incomplete"):
        collect(
            candidate,qualification_envelope,commissioning_envelope,
            fake_release_runner,fake_signer,
        )
```

```python
# tests/security/test_release_qualification.py
import inspect
import pytest
from scripts.commission_release_target import commission_target
from scripts.qualify_release_artifacts import prepare_evidence_target,qualify

def test_clean_target_is_qualified_commissioned_and_installed_before_evidence(
    candidate,qualification_runner,qualification_signer,commissioning_signer,
):
    prepared=prepare_evidence_target(
        candidate,qualification_runner,qualification_signer,
        commissioning_signer,qualification_runner.scanner_identities,
        qualification_runner.scan_targets,qualification_runner.valid_until,
    )
    assert qualification_runner.calls == (
        "assert_clean_frozen_commit","build_qualification_a",
        "build_qualification_b","assert_clean_uncommissioned_target",
        "commission_target","provision_target_evidence_identity",
        "install_evidence_pending_exact_bytes",
        "verify_evidence_pending_install",
    )
    assert prepared.qualification.payload["reproducibility"]["build_count"]==2
    assert prepared.commissioning.payload["qualification_manifest_sha256"] == (
        qualification_runner.sha256_envelope(prepared.qualification)
    )
    assert prepared.commissioning.payload["target_evidence_namespace"] == (
        "tuntun.release.qualification-target.v1"
    )
    assert qualification_runner.current_core_leaf_fingerprint_calls==0


def test_commissioning_starts_from_truly_blank_runtime_target(
    blank_qualification_target,qualification_runner,owner_commissioning_signer,
):
    assert blank_qualification_target.runtime_release is None
    assert blank_qualification_target.current_link is None
    assert blank_qualification_target.core_certificate is None
    assert blank_qualification_target.core_private_key is None
    receipt=commission_target(
        qualification_runner,owner_commissioning_signer,
        qualification_runner.scanner_identities,qualification_runner.scan_targets,
        qualification_runner.valid_until,"a"*64,
    )
    assert receipt.payload["target_evidence_key_id"]
    assert receipt.payload["target_evidence_cert_fingerprint"]
    assert blank_qualification_target.core_certificate is None
    assert blank_qualification_target.core_private_key is None

@pytest.mark.parametrize("omission",("commissioning","evidence_pending_install"))
def test_evidence_cannot_start_without_preparation_step(
    qualified_target,qualification_runner,omission,
):
    qualification_runner.omit_preparation(omission)
    with pytest.raises(RuntimeError,match="qualification ceremony incomplete"):
        qualification_runner.collect_security_evidence(qualified_target)

@pytest.mark.parametrize("mutation",("wrong_installed_bytes","later_rebuild"))
def test_wrong_or_rebuilt_bytes_never_replace_qualification(
    qualified_target,qualification_runner,mutation,
):
    qualification_runner.mutate_after_qualification(mutation)
    with pytest.raises(RuntimeError,match="qualified artifact mismatch"):
        qualification_runner.collect_or_assemble(qualified_target)

def test_commission_target_interface_matches_implementation():
    assert tuple(inspect.signature(commission_target).parameters)==(
        "runner","owner_signer","scanner_identities","scan_targets",
        "valid_until","qualification_manifest_sha256",
    )
    assert tuple(inspect.signature(qualify).parameters)==(
        "candidate","runner","signer",
    )
```

```python
# tests/security/test_target_host_evidence.py
import pytest
from scripts.collect_release_evidence import collect,verify_target_receipts

REQUIRED_RUNTIME_FACTS={"process_tree","dns","listeners","sockets","packet_egress"}

def test_target_receipts_cover_runtime_and_both_network_vantages(
    candidate, valid_target_receipts, target_receipt_schemas, signer_registry,
    commissioned_target_identity, valid_collection_requests,
    valid_collection_brackets, verification_monotonic_ns, now,
):
    result=verify_target_receipts(
        candidate, valid_target_receipts, valid_collection_requests,
        valid_collection_brackets, target_receipt_schemas,
        signer_registry, commissioned_target_identity,
        expected_config_sha256="c"*64, verification_now=now,
        verification_monotonic_ns=verification_monotonic_ns,
    )
    assert set(result.runtime.fact_artifacts)==REQUIRED_RUNTIME_FACTS
    assert {result.lan_scan.vantage,result.outer_scan.vantage}=={"lan","outer"}
    assert result.runtime.unexpected_endpoint_count==0
    assert result.lan_scan.unexpected_open_ports==()
    assert result.outer_scan.unexpected_open_ports==()

@pytest.mark.parametrize("changed", [
    "candidate_version","commit","installed_artifact_sha256","target_host_id",
    "target_evidence_namespace","target_evidence_key_id","target_evidence_cert_fingerprint",
    "installed_manifest_sha256","installed_core_leaf_fingerprint",
    "config_sha256","boot_id","observed_from","observed_until","fact_artifact_sha256",
])
def test_resigned_target_receipt_with_wrong_binding_is_rejected(
    candidate, valid_target_receipts, target_receipt_schemas, signer_registry,
    commissioned_target_identity, valid_collection_requests,
    valid_collection_brackets, verification_monotonic_ns,
    resign_target_receipt, changed, now,
):
    receipts=resign_target_receipt(valid_target_receipts,role="target_runtime",changed=changed)
    with pytest.raises(ValueError,match="target receipt binding|commissioned target identity"):
        verify_target_receipts(candidate,receipts,valid_collection_requests,valid_collection_brackets,target_receipt_schemas,signer_registry,commissioned_target_identity,"c"*64,now,verification_monotonic_ns)


@pytest.mark.parametrize("changed", ["runtime_receipt_sha256","boot_id","commit","installed_artifact_sha256","installed_manifest_sha256","installed_core_leaf_fingerprint","target_evidence_namespace","target_evidence_key_id","target_evidence_cert_fingerprint","config_sha256","scan_target","observed_from","observed_until","collection_request_id","collection_nonce_b64","request_bracket_commitment","collection_request_sha256"])
def test_resigned_scan_cannot_substitute_runtime_binding(
    candidate, valid_target_receipts, target_receipt_schemas, signer_registry,
    commissioned_target_identity, valid_collection_requests,
    valid_collection_brackets, verification_monotonic_ns,
    resign_target_receipt, changed, now,
):
    receipts=resign_target_receipt(valid_target_receipts,role="lan_scan",changed=changed)
    with pytest.raises(ValueError,match="target receipt binding|commissioned target identity"):
        verify_target_receipts(
            candidate,receipts,valid_collection_requests,valid_collection_brackets,
            target_receipt_schemas,signer_registry,
            commissioned_target_identity,"c"*64,now,verification_monotonic_ns,
        )

@pytest.mark.parametrize("missing", ["process_tree","dns","listeners","sockets","packet_egress","lan_scan","outer_scan"])
def test_missing_target_fact_or_scan_blocks_release(valid_target_receipts,missing,verify_target_fixture):
    with pytest.raises(ValueError,match="target evidence incomplete"):
        verify_target_fixture(valid_target_receipts.without(missing))


def test_cross_consistent_receipts_for_uncommissioned_target_are_rejected(
    candidate, valid_target_receipts, target_receipt_schemas, signer_registry,
    commissioned_target_identity, valid_collection_requests,
    valid_collection_brackets, verification_monotonic_ns,
    resign_all_target_receipts, now,
):
    substituted=resign_all_target_receipts(
        valid_target_receipts,target_host_id="uncommissioned-host",
    )
    with pytest.raises(ValueError,match="commissioned target identity"):
        verify_target_receipts(
            candidate,substituted,valid_collection_requests,valid_collection_brackets,
            target_receipt_schemas,signer_registry,
            commissioned_target_identity,"c"*64,now,verification_monotonic_ns,
        )


def test_target_or_scan_evidence_older_than_thirty_minutes_is_rejected(
    candidate, valid_target_receipts, stale_collection_brackets,
    valid_collection_requests, target_receipt_schemas, signer_registry,
    commissioned_target_identity, verification_monotonic_ns, now,
):
    with pytest.raises(ValueError,match="target evidence age"):
        verify_target_receipts(
            candidate,valid_target_receipts,valid_collection_requests,
            stale_collection_brackets,target_receipt_schemas,signer_registry,
            commissioned_target_identity,"c"*64,now,verification_monotonic_ns,
        )


@pytest.mark.parametrize("remote_skew_seconds",(-180,180))
def test_attested_positive_or_negative_remote_wall_skew_does_not_define_order(
    valid_target_receipts,remote_skew_seconds,skew_target_receipt_clocks,
    verify_target_fixture,
):
    receipts=skew_target_receipt_clocks(
        valid_target_receipts,seconds=remote_skew_seconds,uncertainty_us=250_000,
    )
    result=verify_target_fixture(receipts)
    assert result.runtime.clock_attestation["uncertainty_us"]==250_000


@pytest.mark.parametrize(
    "mutation",("excessive_clock_uncertainty","replayed_nonce",
                "replayed_request_id","overlapping_brackets","rtt_exceeded"),
)
def test_clock_replay_and_orchestrator_bracket_failures_are_rejected(
    valid_target_receipts,valid_collection_requests,valid_collection_brackets,
    mutate_target_collection,verify_target_fixture,mutation,
):
    receipts,requests,brackets=mutate_target_collection(
        valid_target_receipts,valid_collection_requests,
        valid_collection_brackets,mutation,
    )
    with pytest.raises(
        ValueError,
        match="clock attestation|collection replay|collection bracket|target evidence age",
    ):
        verify_target_fixture(receipts,requests=requests,brackets=brackets)


def test_old_signed_request_and_receipt_cannot_be_given_fresh_brackets(
    valid_target_receipts,valid_collection_requests,valid_collection_brackets,
    fresh_rebracket,verify_target_fixture,
):
    brackets=fresh_rebracket(valid_collection_brackets,role="lan_scan")
    with pytest.raises(ValueError,match="collection bracket"):
        verify_target_fixture(
            valid_target_receipts,requests=valid_collection_requests,
            brackets=brackets,
        )


def test_advancing_clock_is_sampled_only_after_outer_collection(
    candidate,qualification_envelope,commissioning_envelope,
    advancing_release_runner,security_signer,
):
    envelope=collect(
        candidate,qualification_envelope,commissioning_envelope,
        advancing_release_runner,security_signer,
    )
    assert advancing_release_runner.verification_now_samples == (
        advancing_release_runner.instant_after_outer_scan,
    )
    assert advancing_release_runner.verification_monotonic_samples == (
        advancing_release_runner.tick_after_outer_scan,
    )
    brackets=envelope.payload["target_collection_brackets"]
    assert [item["role"] for item in brackets]==["target_runtime","lan_scan","outer_scan"]
    assert all(left["received_monotonic_ns"]<=right["sent_monotonic_ns"] for left,right in zip(brackets,brackets[1:]))
    assert envelope.payload["target_receipt_hashes"]
```

```python
# tests/security/test_target_collectors.py
import inspect

from scripts.collect_target_runtime import BOOT_ID_COMMAND,HARDWARE_ID_COMMAND,collect_target_runtime
from scripts.run_network_vantage_scan import scan_target

def test_target_collector_executes_real_process_dns_socket_and_packet_sources(
    recording_target_runner, installed_target_state, commissioning,
    signed_runtime_collection_request, collection_request_schema,
    signer_registry, target_runtime_signer,
):
    receipt=collect_target_runtime(
        commissioning,signed_runtime_collection_request,collection_request_schema,
        signer_registry,recording_target_runner,target_runtime_signer,
        runtime_root=installed_target_state.runtime_root,
        config_root=installed_target_state.config_root,
    )
    assert set(recording_target_runner.commands) >= {
        ("ps","-axo","pid=,ppid=,uid=,comm="),
        ("scutil","--dns"),
        ("lsof","-nP","-iTCP","-sTCP:LISTEN"),
        ("lsof","-nP","-i"),
        HARDWARE_ID_COMMAND,
        BOOT_ID_COMMAND,
    }
    assert any(call[:2]==("openssl","x509") for call in recording_target_runner.commands)
    assert recording_target_runner.packet_header_capture_started
    assert receipt.payload["fact_artifacts"].keys() == {
        "process_tree","dns","listeners","sockets","packet_egress",
    }
    assert recording_target_runner.packet_payload_bytes_retained == 0
    assert receipt.payload["commit"]==installed_target_state.commit
    assert receipt.payload["candidate_version"]==installed_target_state.version
    assert receipt.payload["installed_artifact_sha256"]==installed_target_state.artifact_sha256
    assert receipt.payload["config_sha256"]==installed_target_state.config_sha256
    assert receipt.payload["boot_id"]==installed_target_state.boot_id
    assert receipt.payload["collection_nonce_b64"]==signed_runtime_collection_request.payload["nonce_b64"]


def test_runtime_collector_has_no_candidate_or_caller_fact_payload_seam():
    assert tuple(inspect.signature(collect_target_runtime).parameters) == (
        "commissioning","request_envelope","request_schema","registry",
        "runner","signer","runtime_root","config_root",
    )
    assert tuple(inspect.signature(scan_target).parameters) == (
        "commissioning","request_envelope","request_schema","runtime_envelope",
        "runtime_schema","registry","vantage","scanner","signer",
    )

def test_lan_and_outer_scanners_execute_from_distinct_commissioned_nodes(
    scan_runner, commissioning, signed_runtime_receipt, target_receipt_schemas,
    signer_registry, network_scan_signer, signed_lan_collection_request,
    signed_outer_collection_request,
):
    lan=scan_target(
        commissioning,signed_lan_collection_request,
        target_receipt_schemas["collection_request"],signed_runtime_receipt,
        target_receipt_schemas["target_runtime"],
        signer_registry,"lan",scan_runner.for_vantage("lan"),network_scan_signer,
    )
    outer=scan_target(
        commissioning,signed_outer_collection_request,
        target_receipt_schemas["collection_request"],signed_runtime_receipt,
        target_receipt_schemas["target_runtime"],
        signer_registry,"outer",scan_runner.for_vantage("outer"),network_scan_signer,
    )
    assert lan.payload["scanner_identity"] != outer.payload["scanner_identity"]
    assert {lan.payload["vantage"],outer.payload["vantage"]} == {"lan","outer"}
    assert lan.payload["runtime_receipt_sha256"]==outer.payload["runtime_receipt_sha256"]
    assert lan.payload["boot_id"]==outer.payload["boot_id"]==signed_runtime_receipt.payload["boot_id"]
    assert all(call[:3] == ("nmap","-sT","-Pn") for call in scan_runner.calls)
```

```python
# tests/security/test_evidence_signature.py
import pytest
from datetime import timedelta
import scripts.evidence as evidence
from scripts.evidence import (
    MAX_SIGNED_EVIDENCE_BYTES,open_signed_evidence,parse_signed_evidence,
)


def test_signed_evidence_outer_bytes_are_bounded_duplicate_free_and_canonical(
    valid_security_envelope,
) -> None:
    canonical=evidence.canonical(valid_security_envelope.model_dump(mode="json"))
    assert parse_signed_evidence(canonical)==valid_security_envelope
    duplicate=canonical.replace(b'"payload":',b'"payload":{},"payload":',1)
    for raw in (
        duplicate,b" "+canonical,
        b"["+b",".join((b"0",)*16_385)+b"]",
        b" "*(MAX_SIGNED_EVIDENCE_BYTES+1),
    ):
        with pytest.raises((TypeError,ValueError)):
            parse_signed_evidence(raw)

def test_local_signing_is_bounded_and_opened_payload_is_recursively_immutable(
    security_signer,valid_security_payload,valid_security_envelope,
    security_schema,signer_registry,now,
) -> None:
    nested={"value":0}
    for _ in range(33): nested={"value":nested}
    with pytest.raises(ValueError): security_signer.sign(nested)
    opened=open_signed_evidence(
        valid_security_envelope,security_schema,signer_registry,"security",now,
    )
    with pytest.raises(TypeError): opened["new_field"]="late mutation"
    nested_sequence=next((value for value in opened.values() if isinstance(value,tuple)),None)
    if nested_sequence is not None:
        with pytest.raises(AttributeError): nested_sequence.append("late mutation")

def test_signer_registry_is_bounded_duplicate_safe_and_canonical(
    signer_registry_files,mutate_control_file,
) -> None:
    for mutation in ("duplicate_key","noncanonical","overdeep","flat_overflow","oversize"):
        schema_path,registry_path=mutate_control_file(signer_registry_files,mutation)
        with pytest.raises((PermissionError,TypeError,ValueError)):
            evidence.SignerRegistry.load(schema_path,registry_path)

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


@pytest.mark.parametrize("mutation",(
    "short_key_id","long_key_id","bad_key_id","short_signature",
    "noncanonical_signature","too_many_payload_keys","payload_not_json",
))
def test_evidence_outer_envelope_is_closed_bounded_and_revalidated(
    valid_security_envelope,security_schema,signer_registry,now,mutation,
    mutate_outer_envelope_without_validation,
):
    malformed=mutate_outer_envelope_without_validation(valid_security_envelope,mutation)
    with pytest.raises((TypeError,ValueError)):
        open_signed_evidence(malformed,security_schema,signer_registry,"security",now)


def test_payload_schema_validation_precedes_semantic_payload_use(
    valid_security_envelope,invalid_security_payload,security_schema,
    signer_registry,now,monkeypatch,resign_evidence,
):
    malformed=resign_evidence(valid_security_envelope,invalid_security_payload)
    def forbidden_signature_payload_access(_envelope):
        raise AssertionError("payload reached signature/semantic use before schema validation")
    monkeypatch.setattr(evidence,"signed_body",forbidden_signature_payload_access)
    with pytest.raises(ValueError):
        evidence.open_signed_evidence(
            malformed,security_schema,signer_registry,"security",now,
        )
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/security/test_evidence_signature.py tests/security/test_release_qualification.py tests/security/test_supply_chain_evidence.py tests/security/test_target_host_evidence.py tests/release/test_reproducible_build.py -q`

Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.evidence'`.

- [ ] **Step 3: Implement signed evidence and pinned tool execution**

```python
# scripts/evidence.py
import base64,binascii,jsonschema,rfc8785
from dataclasses import dataclass
from datetime import UTC,datetime,timedelta
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Literal
from pydantic import (
    AwareDatetime,BaseModel,ConfigDict,Field,JsonValue,field_validator,
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from tuntun_contracts.base import parse_bounded_json_value,parse_contract_json
from scripts.control_files import parse_control_json
EvidencePurpose=Literal["qualification","security","collection_request","target_commissioning","target_runtime","network_scan","acceptance","soak_run","soak_bundle","latency_deviation","family_stage","family_review","family_trial","p1r0_approval","publication"]
MAX_SIGNED_EVIDENCE_BYTES=2_097_152
OWNER_PURPOSES=frozenset({"target_commissioning","latency_deviation","family_review","p1r0_approval","publication"})
AUTOMATION_PURPOSES=frozenset({"qualification","security","collection_request","target_runtime","network_scan","acceptance","soak_run","soak_bundle","family_stage","family_trial"})
class ProtectedEvidenceHeader(BaseModel):
    model_config=ConfigDict(
        extra="forbid",frozen=True,strict=True,revalidate_instances="always",
    )
    envelope_version:Literal["tuntun.signed-evidence.v1"]="tuntun.signed-evidence.v1"
    key_id:str=Field(min_length=8,max_length=128,pattern=r"^[A-Za-z0-9_.:-]+$")
    algorithm:Literal["Ed25519"]="Ed25519"
    purpose:EvidencePurpose
    signed_at:AwareDatetime
class SignedEvidence(BaseModel):
    model_config=ConfigDict(
        extra="forbid",frozen=True,strict=True,revalidate_instances="always",
    )
    protected:ProtectedEvidenceHeader
    payload:dict[str,JsonValue]=Field(max_length=4_096)
    signature_b64:str=Field(
        min_length=88,max_length=88,pattern=r"^[A-Za-z0-9+/]{86}==$",
    )
    @field_validator("payload")
    @classmethod
    def bounded_payload_keys(cls,value):
        if any(type(key) is not str or not 1<=len(key)<=128 for key in value):
            raise ValueError("evidence payload key invalid")
        return dict(value)
    @field_validator("signature_b64")
    @classmethod
    def canonical_ed25519_signature(cls,value):
        try: decoded=base64.b64decode(value,validate=True)
        except (ValueError,binascii.Error) as error:
            raise ValueError("evidence signature is not canonical base64") from error
        if len(decoded)!=64 or base64.b64encode(decoded).decode("ascii")!=value:
            raise ValueError("evidence signature must encode exactly 64 bytes")
        return value
@dataclass(frozen=True,slots=True)
class SignerRecord:
    key_id:str; algorithm:str; public_key:Ed25519PublicKey; public_key_bytes:bytes
    key_role:Literal["automation","owner"]; purposes:frozenset[str]
    not_before:datetime; not_after:datetime; revoked_at:datetime|None
class SignerRegistry:
    def __init__(self,records): self.records=records
    @classmethod
    def load(cls,schema_path:Path,registry_path:Path):
        schema=parse_control_json(
            schema_path,max_bytes=262_144,require_canonical=False,
        )
        raw=parse_control_json(
            registry_path,max_bytes=131_072,require_canonical=True,
        )
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
        encoded=canonical(payload)
        payload=parse_bounded_json_value(
            encoded,max_bytes=MAX_SIGNED_EVIDENCE_BYTES,max_depth=32,
            max_containers=4_096,max_structure_tokens=16_384,
        )
        if not isinstance(payload,dict): raise ValueError("evidence payload must be an object")
        header=ProtectedEvidenceHeader(key_id=self.key_id,purpose=self.purpose,signed_at=self.clock.now())
        body=canonical({"protected":header.model_dump(mode="json"),"payload":payload})
        signature=self.private_key.sign(b"tuntun:release-evidence:v1\0"+body)
        return SignedEvidence(
            protected=header,payload=payload,
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )
def open_signed_evidence(envelope,schema,registry,expected_purpose,now):
    try:
        envelope=SignedEvidence.model_validate(envelope.model_dump(mode="python"))
        jsonschema.Draft202012Validator(
            schema,format_checker=jsonschema.FormatChecker(),
        ).validate(envelope.payload)
    except (AttributeError,TypeError,ValueError,jsonschema.ValidationError) as error:
        raise ValueError("invalid evidence envelope or payload schema") from error
    record=registry.records.get(envelope.protected.key_id)
    if record is None or envelope.protected.algorithm!=record.algorithm: raise ValueError("unauthorized evidence key or algorithm")
    if envelope.protected.purpose!=expected_purpose or expected_purpose not in record.purposes: raise ValueError("wrong evidence purpose")
    signed_at=envelope.protected.signed_at
    if signed_at.tzinfo is None or not record.not_before<=signed_at<=record.not_after or signed_at>now+timedelta(minutes=5): raise ValueError("evidence outside signer validity")
    if record.revoked_at is not None: raise ValueError("revoked evidence key")
    try: record.public_key.verify(base64.b64decode(envelope.signature_b64,validate=True),b"tuntun:release-evidence:v1\0"+signed_body(envelope))
    except (InvalidSignature,ValueError) as error: raise ValueError("invalid evidence signature") from error
    # No caller may read envelope.payload directly. This schema-validated
    # detached copy is the sole semantic evidence value.
    payload=parse_bounded_json_value(
        canonical(envelope.payload),max_bytes=MAX_SIGNED_EVIDENCE_BYTES,
        max_depth=32,max_containers=4_096,max_structure_tokens=16_384,
    )
    def freeze(value):
        if isinstance(value,dict):
            return MappingProxyType({key:freeze(item) for key,item in value.items()})
        if isinstance(value,list): return tuple(freeze(item) for item in value)
        return value
    return freeze(payload)
def signed_envelope_sha256(envelope): return sha256(canonical(envelope.model_dump(mode="json"))).hexdigest()
def parse_signed_evidence(raw:bytes) -> SignedEvidence:
    return parse_contract_json(
        SignedEvidence,raw,max_bytes=MAX_SIGNED_EVIDENCE_BYTES,
        require_canonical=True,
    )
```

```python
# scripts/qualify_release_artifacts.py
import os,stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path,PurePosixPath
from types import SimpleNamespace
from scripts.commission_release_target import commission_target
from scripts.evidence import canonical,open_signed_evidence,signed_envelope_sha256
from scripts.control_files import parse_control_json_bytes

QUALIFIED_DISTRIBUTABLE_ROLES=frozenset({
    "source_archive","python_wheels","admin_assets","reachy_package",
    "reachy_package_sha256","reachy_package_manifest","python_sbom",
    "npm_sbom","license_inventory","model_manifest","provenance",
})

@dataclass(frozen=True,slots=True)
class PreparedEvidenceTarget:
    qualification:object; commissioning:object

def _frozen_digest(path):
    named=path.stat(follow_symlinks=False)
    if not stat.S_ISREG(named.st_mode): raise RuntimeError("qualified artifact path invalid")
    fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)); hasher=sha256()
    try:
        opened=os.fstat(fd)
        if (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino): raise RuntimeError("qualified artifact changed")
        remaining=opened.st_size
        while remaining:
            chunk=os.read(fd,min(1024*1024,remaining))
            if not chunk: raise RuntimeError("qualified artifact changed")
            hasher.update(chunk);remaining-=len(chunk)
        if os.read(fd,1): raise RuntimeError("qualified artifact changed")
        final=os.fstat(fd);renamed=path.stat(follow_symlinks=False)
        if ((final.st_dev,final.st_ino,final.st_size,final.st_mtime_ns,final.st_ctime_ns)
            !=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
            or (renamed.st_dev,renamed.st_ino)!=(opened.st_dev,opened.st_ino)):
            raise RuntimeError("qualified artifact changed")
        return hasher.hexdigest(),opened.st_size
    finally: os.close(fd)

def qualify(candidate,runner,signer):
    if signer.purpose!="qualification": raise ValueError("qualification signer required")
    runner.assert_clean_frozen_commit(candidate.commit)
    first=runner.build_qualification(candidate,"qualification-a")
    second=runner.build_qualification(candidate,"qualification-b")
    if first.manifest!=second.manifest or first.bytes_by_role!=second.bytes_by_role:
        raise RuntimeError("qualification reproducibility mismatch")
    artifacts=tuple(sorted(first.artifacts,key=lambda item:item["role"]))
    if {item["role"] for item in artifacts}!=QUALIFIED_DISTRIBUTABLE_ROLES:
        raise RuntimeError("qualified artifact roles incomplete")
    if len({item["path"] for item in artifacts})!=len(artifacts):
        raise RuntimeError("qualified artifact paths duplicate")
    payload={
        "schema_version":"tuntun.qualification-artifact-manifest.v1",
        "candidate_version":candidate.version,"commit":candidate.commit,
        "source_date_epoch":candidate.source_date_epoch,
        "reproducibility":{
            "build_count":2,"identical":True,
            "manifest_sha256":sha256(canonical(artifacts)).hexdigest(),
        },
        "artifacts":artifacts,
    }
    return signer.sign(payload)

def open_qualified_artifacts(envelope,schema,registry,now,root):
    payload=open_signed_evidence(envelope,schema,registry,"qualification",now)
    if payload["reproducibility"]["build_count"]!=2 or not payload["reproducibility"]["identical"]:
        raise RuntimeError("qualification reproducibility missing")
    items=payload["artifacts"]
    if {item["role"] for item in items}!=QUALIFIED_DISTRIBUTABLE_ROLES:
        raise RuntimeError("qualified artifact roles incomplete")
    resolved_root=Path(root).resolve(); paths={}
    for item in items:
        relative=PurePosixPath(item["path"])
        if (relative.is_absolute() or relative.as_posix()!=item["path"]
            or any(part in {"",".",".."} for part in relative.parts)):
            raise RuntimeError("qualified artifact path invalid")
        path=resolved_root.joinpath(*relative.parts)
        actual_sha256,actual_size=_frozen_digest(path)
        if actual_size!=item["size"] or actual_sha256!=item["sha256"]:
            raise RuntimeError("qualified artifact mismatch")
        paths[item["role"]]=path
    return SimpleNamespace(
        payload=payload,artifacts=items,role_paths=paths,
        sha256=signed_envelope_sha256(envelope),
    )

def prepare_evidence_target(
    candidate,runner,qualification_signer,commissioning_signer,
    scanner_identities,scan_targets,valid_until,
):
    qualification=qualify(candidate,runner,qualification_signer)
    qualification_sha=signed_envelope_sha256(qualification)
    commissioning=commission_target(
        runner,commissioning_signer,scanner_identities,scan_targets,
        valid_until,qualification_sha,
    )
    runner.install_evidence_pending_exact_bytes(
        qualification,commissioning,expected_manifest_sha256=qualification_sha,
    )
    runner.verify_evidence_pending_install(
        qualification,commissioning,expected_manifest_sha256=qualification_sha,
    )
    return PreparedEvidenceTarget(qualification,commissioning)
```

```python
# scripts/collect_release_evidence.py
import base64
import re
from dataclasses import asdict,dataclass
from datetime import datetime,timedelta
from hashlib import sha256
from types import SimpleNamespace
from uuid import UUID
from scripts.collect_target_runtime import collect_target_runtime
from scripts.evidence import canonical,open_signed_evidence,signed_envelope_sha256
from scripts.qualify_release_artifacts import open_qualified_artifacts
from scripts.run_network_vantage_scan import scan_target

REQUIRED_PREFIXES=("uv run pip-audit","pnpm audit --prod --json","gitleaks git --log-opts=--all","uv run bandit","uv run semgrep","uv run cyclonedx-py","pnpm exec cyclonedx-npm","uv run pip-licenses","pnpm licenses list --json","uv run python scripts/check_model_manifest.py","uv run python scripts/verify_private_data.py . dist var")
REQUIRED_RUNTIME_FACTS=frozenset({"process_tree","dns","listeners","sockets","packet_egress"})
REQUIRED_REACHY_ARTIFACT_ROLES=frozenset({
    "reachy_package","reachy_package_sha256","reachy_package_manifest",
})
COLLECTION_ROLES=("target_runtime","lan_scan","outer_scan")
MAX_RTT_NS=30_000_000_000
MAX_OBSERVATION_NS=15*60*1_000_000_000
MAX_TARGET_EVIDENCE_AGE_NS=30*60*1_000_000_000
MAX_CLOCK_UNCERTAINTY_US=2_000_000

@dataclass(frozen=True,slots=True)
class CollectionBracket:
    role:str; ordinal:int; run_id:str; request_id:str; nonce_b64:str
    request_bracket_commitment:str; request_envelope_sha256:str
    sent_monotonic_ns:int; received_monotonic_ns:int; max_rtt_ns:int
    sent_at:str; received_at:str; receipt_sha256:str

@dataclass(frozen=True,slots=True)
class VerifiedTargetReceipts:
    runtime:object; lan_scan:object; outer_scan:object
    envelope_hashes:dict[str,str]; brackets:tuple[CollectionBracket,...]

def _request_commitment(payload): return sha256(canonical(payload)).hexdigest()

def _verify_remote_clock(item,envelope,bracket):
    att=item.get("clock_attestation",{})
    if set(att)!={"source","offset_us","uncertainty_us","attested_at"} or att.get("source")!="signed_ntp_v1": raise ValueError("clock attestation")
    offset=att.get("offset_us"); uncertainty=att.get("uncertainty_us")
    if not isinstance(offset,int) or not isinstance(uncertainty,int) or not 0<=uncertainty<=MAX_CLOCK_UNCERTAINTY_US: raise ValueError("clock attestation")
    remote_from=datetime.fromisoformat(item["observed_from"]); remote_until=datetime.fromisoformat(item["observed_until"])
    attested_at=datetime.fromisoformat(att["attested_at"])
    if not remote_from<remote_until or remote_until-remote_from>timedelta(minutes=15): raise ValueError("clock attestation")
    correction=timedelta(microseconds=offset); tolerance=timedelta(microseconds=uncertainty)
    sent=datetime.fromisoformat(bracket.sent_at); received=datetime.fromisoformat(bracket.received_at)
    adjusted=(remote_from-correction,remote_until-correction,attested_at-correction,envelope.protected.signed_at-correction)
    if any(value<sent-tolerance or value>received+tolerance for value in adjusted): raise ValueError("clock attestation")

def verify_target_receipts(
    candidate,envelopes,requests,brackets,schemas,registry,commissioning_envelope,
    expected_config_sha256,verification_now,verification_monotonic_ns,
):
    if set(envelopes)!=set(requests) or set(requests)!=set(brackets) or set(envelopes)!=set(COLLECTION_ROLES): raise ValueError("target evidence incomplete")
    commissioned=open_signed_evidence(commissioning_envelope,schemas["target_commissioning"],registry,"target_commissioning",verification_now)
    if commissioned.get("target_evidence_namespace")!="tuntun.release.qualification-target.v1":
        raise ValueError("commissioned target identity")
    valid_from=datetime.fromisoformat(commissioned["valid_from"]); valid_until=datetime.fromisoformat(commissioned["valid_until"])
    if not valid_from<=verification_now<valid_until or valid_until-valid_from>timedelta(days=30): raise ValueError("commissioned target identity")
    ordered=tuple(brackets[role] for role in COLLECTION_ROLES)
    if tuple((item.role,item.ordinal) for item in ordered)!=tuple(zip(COLLECTION_ROLES,range(3))): raise ValueError("collection bracket")
    if any(item.sent_monotonic_ns>=item.received_monotonic_ns or item.received_monotonic_ns-item.sent_monotonic_ns>item.max_rtt_ns or item.max_rtt_ns!=MAX_RTT_NS for item in ordered): raise ValueError("collection bracket")
    if any(left.received_monotonic_ns>right.sent_monotonic_ns for left,right in zip(ordered,ordered[1:])): raise ValueError("collection bracket")
    if ordered[-1].received_monotonic_ns-ordered[0].sent_monotonic_ns>MAX_OBSERVATION_NS: raise ValueError("collection bracket")
    if any(not item.received_monotonic_ns<=verification_monotonic_ns or verification_monotonic_ns-item.received_monotonic_ns>MAX_TARGET_EVIDENCE_AGE_NS for item in ordered): raise ValueError("target evidence age")
    request_payloads={}; request_ids=set(); nonces=set(); run_ids=set()
    for role,bracket in zip(COLLECTION_ROLES,ordered):
        request=open_signed_evidence(requests[role],schemas["collection_request"],registry,"collection_request",verification_now)
        try: UUID(request["request_id"]); nonce=base64.b64decode(request["nonce_b64"],validate=True)
        except (KeyError,ValueError) as error: raise ValueError("collection replay") from error
        if len(nonce)!=32 or request["role"]!=role or request["ordinal"]!=bracket.ordinal or request["run_id"]!=bracket.run_id: raise ValueError("collection replay")
        commitment=_request_commitment(request)
        if request["request_id"]!=bracket.request_id or request["nonce_b64"]!=bracket.nonce_b64 or request["sent_monotonic_ns"]!=bracket.sent_monotonic_ns or request["max_rtt_ns"]!=bracket.max_rtt_ns or commitment!=bracket.request_bracket_commitment or signed_envelope_sha256(requests[role])!=bracket.request_envelope_sha256: raise ValueError("collection bracket")
        request_ids.add(request["request_id"]); nonces.add(request["nonce_b64"]); run_ids.add(request["run_id"]); request_payloads[role]=request
    if len(request_ids)!=3 or len(nonces)!=3 or len(run_ids)!=1: raise ValueError("collection replay")
    payloads={}
    for role,bracket in zip(COLLECTION_ROLES,ordered):
        envelope=envelopes[role]
        # Remote signer time is not an ordering source. Verify signature/key
        # lifecycle, then validate its wall time only via bounded attestation.
        item=open_signed_evidence(envelope,schemas[role],registry,"target_runtime" if role=="target_runtime" else "network_scan",max(verification_now,envelope.protected.signed_at))
        request=request_payloads[role]
        binding={"collection_run_id":request["run_id"],"collection_request_id":request["request_id"],"collection_nonce_b64":request["nonce_b64"],"request_bracket_commitment":bracket.request_bracket_commitment,"collection_request_sha256":bracket.request_envelope_sha256}
        if any(item.get(key)!=value for key,value in binding.items()) or signed_envelope_sha256(envelope)!=bracket.receipt_sha256: raise ValueError("collection replay")
        _verify_remote_clock(item,envelope,bracket); payloads[role]=item
    runtime=payloads["target_runtime"]
    commissioned_scope={
        "target_host_id":commissioned["target_host_id"],
        "hardware_identity_sha256":commissioned["hardware_identity_sha256"],
        "target_evidence_namespace":commissioned["target_evidence_namespace"],
        "target_evidence_key_id":commissioned["target_evidence_key_id"],
        "target_evidence_cert_fingerprint":commissioned["target_evidence_cert_fingerprint"],
    }
    if any(runtime.get(name)!=value for name,value in commissioned_scope.items()):
        raise ValueError("commissioned target identity")
    if any(
        not isinstance(runtime.get(name),str) or re.fullmatch(r"[0-9a-f]{64}",runtime[name]) is None
        for name in ("installed_manifest_sha256","installed_core_leaf_fingerprint")
    ):
        raise ValueError("target receipt binding")
    expected={"candidate_version":candidate.version,"commit":candidate.commit,"installed_artifact_sha256":candidate.installed_artifact_sha256,"config_sha256":expected_config_sha256}
    if any(runtime.get(name)!=value for name,value in expected.items()): raise ValueError("target receipt binding")
    if set(runtime["fact_artifacts"])!=REQUIRED_RUNTIME_FACTS or runtime["unexpected_endpoint_count"]!=0: raise ValueError("target evidence incomplete")
    if any(candidate.target_fact_sha256(name)!=record["sha256"] for name,record in runtime["fact_artifacts"].items()): raise ValueError("target receipt binding")
    scans={}; runtime_sha=signed_envelope_sha256(envelopes["target_runtime"])
    for role,vantage in (("lan_scan","lan"),("outer_scan","outer")):
        item=payloads[role]
        shared={
            **expected,**commissioned_scope,
            "installed_manifest_sha256":runtime["installed_manifest_sha256"],
            "installed_core_leaf_fingerprint":runtime["installed_core_leaf_fingerprint"],
            "boot_id":runtime["boot_id"],"runtime_receipt_sha256":runtime_sha,
        }
        if item.get("vantage")!=vantage or any(item.get(name)!=value for name,value in shared.items()): raise ValueError("target receipt binding")
        if item.get("scan_target")!=commissioned["scan_targets"][vantage] or item["scanner_identity"] not in commissioned["scanner_identities"][vantage]: raise ValueError("commissioned target identity")
        if candidate.target_fact_sha256(role)!=item["scan_artifact_sha256"]: raise ValueError("target receipt binding")
        if item["unexpected_open_ports"]: raise ValueError("target evidence incomplete")
        scans[role]=SimpleNamespace(**item)
    hashes={"target_commissioning":signed_envelope_sha256(commissioning_envelope)}
    hashes.update({role:signed_envelope_sha256(envelope) for role,envelope in envelopes.items()})
    hashes.update({"request_"+role:signed_envelope_sha256(envelope) for role,envelope in requests.items()})
    return VerifiedTargetReceipts(SimpleNamespace(**runtime),scans["lan_scan"],scans["outer_scan"],hashes,ordered)

def collect(candidate,qualification_envelope,commissioning_envelope,runner,signer):
    if signer.purpose!="security": raise ValueError("security signer required")
    results={prefix:runner.run(tuple(prefix.split())) for prefix in REQUIRED_PREFIXES}
    if any(item.returncode for item in results.values()): raise RuntimeError("release tool failed")
    schemas=runner.target_receipt_schemas(); registry=runner.signer_registry()
    qualification_now=runner.now()
    qualified=open_qualified_artifacts(
        qualification_envelope,schemas["qualification_artifact"],registry,
        qualification_now,runner.qualification_root(),
    )
    qualification=qualified.payload
    if qualification["candidate_version"]!=candidate.version or qualification["commit"]!=candidate.commit or qualification["source_date_epoch"]!=candidate.source_date_epoch:
        raise RuntimeError("qualified artifact mismatch")
    first_roles=[item["role"] for item in qualified.artifacts]
    if len(first_roles)!=len(set(first_roles)) or not REQUIRED_REACHY_ARTIFACT_ROLES<=set(first_roles):
        raise RuntimeError("Reachy artifact roles incomplete")
    commissioning_now=runner.now()
    commissioning=open_signed_evidence(commissioning_envelope,schemas["target_commissioning"],registry,"target_commissioning",commissioning_now)
    if commissioning["qualification_manifest_sha256"]!=qualified.sha256:
        raise RuntimeError("qualification ceremony incomplete")
    runner.require_evidence_pending_install(
        commissioning["target_host_id"],qualified.sha256,qualified.role_paths,
    )
    run_id=str(runner.new_uuid()); request_signer=runner.evidence_signer("collection_request")
    envelopes={}; requests={}; brackets={}
    def invoke(role,ordinal,operation):
        sent_tick=runner.monotonic_ns(); sent_at=runner.now()
        payload={"schema_version":"tuntun.collection-request.v1","run_id":run_id,"request_id":str(runner.new_uuid()),"nonce_b64":base64.b64encode(runner.random_bytes(32)).decode(),"role":role,"ordinal":ordinal,"sent_monotonic_ns":sent_tick,"max_rtt_ns":MAX_RTT_NS}
        request=request_signer.sign(payload); commitment=_request_commitment(payload)
        receipt=operation(request)
        received_tick=runner.monotonic_ns(); received_at=runner.now()
        brackets[role]=CollectionBracket(role,ordinal,run_id,payload["request_id"],payload["nonce_b64"],commitment,signed_envelope_sha256(request),sent_tick,received_tick,MAX_RTT_NS,sent_at.isoformat(),received_at.isoformat(),signed_envelope_sha256(receipt))
        requests[role]=request; envelopes[role]=receipt
    invoke("target_runtime",0,lambda request: collect_target_runtime(commissioning,request,schemas["collection_request"],registry,runner.target_collector(),runner.evidence_signer("target_runtime")))
    invoke("lan_scan",1,lambda request: scan_target(commissioning,request,schemas["collection_request"],envelopes["target_runtime"],schemas["target_runtime"],registry,"lan",runner.network_scanner("lan"),runner.evidence_signer("network_scan")))
    invoke("outer_scan",2,lambda request: scan_target(commissioning,request,schemas["collection_request"],envelopes["target_runtime"],schemas["target_runtime"],registry,"outer",runner.network_scanner("outer"),runner.evidence_signer("network_scan")))
    verification_now=runner.now(); verification_monotonic_ns=runner.monotonic_ns()
    target_receipts=verify_target_receipts(candidate,envelopes,requests,brackets,schemas,registry,commissioning_envelope,runner.config_sha256(),verification_now,verification_monotonic_ns)
    artifacts=tuple(qualified.artifacts)+(runner.qualification_manifest_artifact(qualification_envelope),)
    payload={"schema_version":"tuntun.security-evidence.v1","candidate_version":candidate.version,"commit":candidate.commit,"source_date_epoch":candidate.source_date_epoch,"tool_versions":runner.tool_versions(),"scan_results":runner.scan_results(results),"history_scan":{"scope":"all_reachable_history","clean":True},"sboms":runner.sboms(),"licenses":runner.licenses(),"model_manifest_sha256":runner.sha256("models/manifest.yaml"),"reproducibility":qualification["reproducibility"],"qualification_manifest_sha256":qualified.sha256,"target_receipt_hashes":target_receipts.envelope_hashes,"target_collection_brackets":[asdict(item) for item in target_receipts.brackets],"artifacts":artifacts,"provenance":runner.provenance(),"generated_at":verification_now.isoformat()}
    return signer.sign(payload)
```

```python
# scripts/commission_release_target.py
from hashlib import sha256

HARDWARE_ID_COMMAND=("ioreg","-rd1","-c","IOPlatformExpertDevice")
TARGET_EVIDENCE_NAMESPACE="tuntun.release.qualification-target.v1"

def commission_target(
    runner,owner_signer,scanner_identities,scan_targets,valid_until,
    qualification_manifest_sha256,
):
    if owner_signer.purpose!="target_commissioning": raise ValueError("target commissioning owner signer required")
    runner.require_clean_uncommissioned_target()
    observed=runner.run_checked(HARDWARE_ID_COMMAND)
    hardware_uuid=runner.parse_single_platform_uuid(observed.stdout)
    hardware_sha256=sha256(hardware_uuid.encode()).hexdigest()
    evidence=runner.provision_target_evidence_identity(
        namespace=TARGET_EVIDENCE_NAMESPACE,
        hardware_identity_sha256=hardware_sha256,
        qualification_manifest_sha256=qualification_manifest_sha256,
    )
    target_host_id=sha256((
        TARGET_EVIDENCE_NAMESPACE+":"+hardware_sha256+":"+
        evidence.key_id+":"+evidence.cert_fingerprint+":"+
        qualification_manifest_sha256
    ).encode()).hexdigest()
    payload={
        "schema_version":"tuntun.target-commissioning.v1",
        "target_host_id":target_host_id,
        "hardware_identity_sha256":hardware_sha256,
        "target_evidence_namespace":TARGET_EVIDENCE_NAMESPACE,
        "target_evidence_key_id":evidence.key_id,
        "target_evidence_cert_fingerprint":evidence.cert_fingerprint,
        "qualification_manifest_sha256":qualification_manifest_sha256,
        "scanner_identities":scanner_identities,
        "scan_targets":scan_targets,
        "valid_from":runner.now().isoformat(),"valid_until":valid_until.isoformat(),
    }
    runner.require_local_owner_passkey_review(payload)
    return owner_signer.sign(payload)
```

```python
# scripts/collect_target_runtime.py
import hashlib
import json
import os
import re
import stat
from hashlib import sha256
from datetime import timedelta
from pathlib import Path
from scripts.evidence import canonical,open_signed_evidence,signed_envelope_sha256

COMMANDS={
    "process_tree":("ps","-axo","pid=,ppid=,uid=,comm="),
    "dns":("scutil","--dns"),
    "listeners":("lsof","-nP","-iTCP","-sTCP:LISTEN"),
    "sockets":("lsof","-nP","-i"),
}
PACKET_FACT_COMMAND=("/usr/sbin/tcpdump","-q","-n","-tt","-l")
HARDWARE_ID_COMMAND=("ioreg","-rd1","-c","IOPlatformExpertDevice")
BOOT_ID_COMMAND=("sysctl","-n","kern.boottime")
DEFAULT_RUNTIME_ROOT=Path.home()/"Library/Application Support/Tuntun/runtime"
DEFAULT_CONFIG_ROOT=Path.home()/"Library/Application Support/Tuntun/config"
STREAM_BYTES=1024*1024
MAX_CONFIG_FILES=100_000
MAX_CONTROL_BYTES=1_048_576

def _read_frozen_bytes(path:Path,limit:int=MAX_CONTROL_BYTES)->bytes:
    named=path.stat(follow_symlinks=False)
    flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0); fd=os.open(path,flags)
    try:
        opened=os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_size>limit
            or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino)):
            raise RuntimeError("target control file invalid")
        identity=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
        chunks=[]; remaining=opened.st_size
        while remaining:
            chunk=os.read(fd,min(STREAM_BYTES,remaining))
            if not chunk: raise RuntimeError("target control file changed")
            chunks.append(chunk); remaining-=len(chunk)
        if os.read(fd,1): raise RuntimeError("target control file changed")
        after=os.fstat(fd); named_after=path.stat(follow_symlinks=False)
        if ((after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)!=identity
            or (named_after.st_dev,named_after.st_ino)!=(after.st_dev,after.st_ino)):
            raise RuntimeError("target control file changed")
        return b"".join(chunks)
    finally: os.close(fd)

def _hash_frozen_file(path:Path,relative:bytes,digest)->None:
    named=path.stat(follow_symlinks=False)
    flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0); fd=os.open(path,flags)
    try:
        opened=os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino)):
            raise RuntimeError("target config file invalid")
        identity=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
        digest.update(len(relative).to_bytes(4,"big")+relative+opened.st_size.to_bytes(8,"big"))
        remaining=opened.st_size
        while remaining:
            chunk=os.read(fd,min(STREAM_BYTES,remaining))
            if not chunk: raise RuntimeError("target config file changed")
            digest.update(chunk); remaining-=len(chunk)
        if os.read(fd,1): raise RuntimeError("target config file changed")
        after=os.fstat(fd); named_after=path.stat(follow_symlinks=False)
        if ((after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)!=identity
            or (named_after.st_dev,named_after.st_ino)!=(after.st_dev,after.st_ino)):
            raise RuntimeError("target config file changed")
    finally: os.close(fd)

def _tree_sha256(root:Path)->str:
    if root.is_symlink() or not root.is_dir(): raise RuntimeError("target config root invalid")
    paths=[]
    for path in root.rglob("*"):
        paths.append(path)
        if len(paths)>MAX_CONFIG_FILES: raise RuntimeError("target config entry limit")
    paths.sort(key=lambda item:item.relative_to(root).as_posix())
    digest=hashlib.sha256()
    for path in paths:
        if path.is_symlink(): raise RuntimeError("target config symlink forbidden")
        if path.is_file():
            _hash_frozen_file(path,path.relative_to(root).as_posix().encode(),digest)
        elif not path.is_dir(): raise RuntimeError("target config special file forbidden")
    return digest.hexdigest()

def _platform_uuid(raw:str)->str:
    match=re.search(r'"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"',raw)
    if match is None: raise RuntimeError("single target platform UUID required")
    return match.group(1).lower()

def _leaf_sha256(raw:str)->str:
    match=re.search(r"(?:sha256 )?Fingerprint=([0-9A-Fa-f:]{95})",raw,re.IGNORECASE)
    if match is None: raise RuntimeError("target core leaf fingerprint required")
    value=match.group(1).replace(":","").lower()
    if len(value)!=64: raise RuntimeError("target core leaf fingerprint required")
    return value

def _installed_binding(runtime_root:Path,config_root:Path,runner,commissioning):
    releases=(runtime_root/"releases").resolve(strict=True)
    current_link=runtime_root/"current"
    if not current_link.is_symlink(): raise RuntimeError("installed release link invalid")
    current=current_link.resolve(strict=True)
    if not current.is_relative_to(releases): raise RuntimeError("installed release link invalid")
    manifest_path=current/"release-manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file(): raise RuntimeError("installed release manifest invalid")
    manifest_bytes=_read_frozen_bytes(manifest_path)
    manifest=parse_control_json_bytes(
        manifest_bytes,max_bytes=65_536,require_canonical=True,
    )
    if set(manifest)!={"schema_version","version","commit","installed_artifact_sha256"} or manifest["schema_version"]!="tuntun.installed-release.v1":
        raise RuntimeError("installed release manifest invalid")
    if re.fullmatch(r"[A-Za-z0-9._-]{1,64}",manifest["version"]) is None or re.fullmatch(r"[0-9a-f]{40}",manifest["commit"]) is None or re.fullmatch(r"[0-9a-f]{64}",manifest["installed_artifact_sha256"]) is None:
        raise RuntimeError("installed release manifest invalid")
    hardware_uuid=_platform_uuid(runner.run_checked(HARDWARE_ID_COMMAND).stdout)
    hardware_sha256=hashlib.sha256(hardware_uuid.encode()).hexdigest()
    runner.require_target_evidence_identity(
        namespace=commissioning["target_evidence_namespace"],
        key_id=commissioning["target_evidence_key_id"],
        cert_fingerprint=commissioning["target_evidence_cert_fingerprint"],
        hardware_identity_sha256=hardware_sha256,
        qualification_manifest_sha256=commissioning["qualification_manifest_sha256"],
    )
    leaf=_leaf_sha256(runner.run_checked(
        ("openssl","x509","-in",str(config_root/"tls/core-cert.pem"),"-noout","-fingerprint","-sha256")
    ).stdout)
    boot_raw=runner.run_checked(BOOT_ID_COMMAND).stdout.strip()
    return {
        "candidate_version":manifest["version"],"commit":manifest["commit"],
        "installed_artifact_sha256":manifest["installed_artifact_sha256"],
        "installed_manifest_sha256":hashlib.sha256(manifest_bytes).hexdigest(),
        "installed_core_leaf_fingerprint":leaf,
        "target_host_id":commissioning["target_host_id"],
        "hardware_identity_sha256":hardware_sha256,
        "target_evidence_namespace":commissioning["target_evidence_namespace"],
        "target_evidence_key_id":commissioning["target_evidence_key_id"],
        "target_evidence_cert_fingerprint":commissioning["target_evidence_cert_fingerprint"],
        "config_sha256":_tree_sha256(config_root),
        "boot_id":hashlib.sha256(boot_raw.encode()).hexdigest(),
    }

def collect_target_runtime(
    commissioning,request_envelope,request_schema,registry,runner,signer,
    *,runtime_root=DEFAULT_RUNTIME_ROOT,config_root=DEFAULT_CONFIG_ROOT,
):
    if signer.purpose!="target_runtime": raise ValueError("target runtime signer required")
    clock_attestation=runner.read_clock_attestation()
    runner.verify_clock_attestation(clock_attestation,source="signed_ntp_v1",max_uncertainty_us=2_000_000)
    corrected_now=runner.now()-timedelta(microseconds=clock_attestation["offset_us"])
    request=open_signed_evidence(request_envelope,request_schema,registry,"collection_request",corrected_now)
    if request["role"]!="target_runtime" or request["ordinal"]!=0 or request["max_rtt_ns"]!=30_000_000_000: raise RuntimeError("collection request binding")
    request_commitment=sha256(canonical(request)).hexdigest()
    binding=_installed_binding(runtime_root,config_root,runner,commissioning)
    if binding["target_host_id"]!=commissioning["target_host_id"] or binding["hardware_identity_sha256"]!=commissioning["hardware_identity_sha256"]:
        raise RuntimeError("commissioned target identity mismatch")
    observed_from=runner.now(); raw={}
    for role,command in COMMANDS.items():
        raw[role]=runner.run_checked(command).stdout
    # The collector starts tcpdump as a pipe only: `-q` emits packet-header
    # summaries to stdout, no pcap is written, and the parser retains only
    # protocol, direction, address class, port, length, and timestamp.
    with runner.packet_header_observation(PACKET_FACT_COMMAND) as observation:
        runner.run_content_free_controlled_turn()
    raw["packet_egress"]=observation.stdout
    artifacts={role:runner.write_minimized_fact(role,raw_value) for role,raw_value in raw.items()}
    observed_until=runner.now()
    if observed_until-observed_from>timedelta(minutes=15): raise RuntimeError("target observation window too long")
    return signer.sign({
        "schema_version":"tuntun.target-runtime.v1",**binding,
        "collection_run_id":request["run_id"],"collection_request_id":request["request_id"],
        "collection_nonce_b64":request["nonce_b64"],"request_bracket_commitment":request_commitment,
        "collection_request_sha256":signed_envelope_sha256(request_envelope),
        "observed_from":observed_from.isoformat(),"observed_until":observed_until.isoformat(),
        "clock_attestation":clock_attestation,
        "collector_version":runner.collector_version(),
        "fact_artifacts":artifacts,
        "unexpected_endpoint_count":runner.unexpected_endpoint_count(artifacts),
    })
```

```python
# scripts/run_network_vantage_scan.py
from datetime import timedelta
from hashlib import sha256
from typing import Literal
from scripts.evidence import canonical,open_signed_evidence,signed_envelope_sha256

MAX_OBSERVATION_DURATION=timedelta(minutes=15)

def scan_target(
    commissioning,request_envelope,request_schema,runtime_envelope,runtime_schema,registry,
    vantage:Literal["lan","outer"],scanner,signer,
):
    if signer.purpose!="network_scan": raise ValueError("network scan signer required")
    scanner.require_identity_in(commissioning["scanner_identities"][vantage])
    clock_attestation=scanner.read_clock_attestation()
    scanner.verify_clock_attestation(clock_attestation,source="signed_ntp_v1",max_uncertainty_us=2_000_000)
    corrected_now=scanner.now()-timedelta(microseconds=clock_attestation["offset_us"])
    request=open_signed_evidence(request_envelope,request_schema,registry,"collection_request",corrected_now)
    expected_role="lan_scan" if vantage=="lan" else "outer_scan"
    expected_ordinal=1 if vantage=="lan" else 2
    if request["role"]!=expected_role or request["ordinal"]!=expected_ordinal or request["max_rtt_ns"]!=30_000_000_000: raise RuntimeError("collection request binding")
    request_commitment=sha256(canonical(request)).hexdigest()
    observed_from=scanner.now()
    runtime=open_signed_evidence(
        runtime_envelope,runtime_schema,registry,"target_runtime",corrected_now,
    )
    target=commissioning["scan_targets"][vantage]
    scanner.require_target_evidence_peer(
        namespace=commissioning["target_evidence_namespace"],
        key_id=commissioning["target_evidence_key_id"],
        cert_fingerprint=commissioning["target_evidence_cert_fingerprint"],
        target=target,
    )
    command=("nmap","-sT","-Pn","-p-","--reason","-oX","-",target)
    completed=scanner.run_checked(command)
    result=scanner.parse_nmap_xml(completed.stdout)
    artifact=scanner.write_minimized_scan_fact(vantage,result)
    observed_until=scanner.now()
    if not observed_from < observed_until or observed_until-observed_from>MAX_OBSERVATION_DURATION:
        raise RuntimeError("network scan observation window invalid")
    return signer.sign({
        "schema_version":"tuntun.target-network-scan.v1",
        **{name:runtime[name] for name in (
            "candidate_version","commit","installed_artifact_sha256",
            "installed_manifest_sha256","installed_core_leaf_fingerprint",
            "target_host_id","hardware_identity_sha256","target_evidence_namespace","target_evidence_key_id",
            "target_evidence_cert_fingerprint","config_sha256","boot_id",
        )},
        "collection_run_id":request["run_id"],"collection_request_id":request["request_id"],
        "collection_nonce_b64":request["nonce_b64"],"request_bracket_commitment":request_commitment,
        "collection_request_sha256":signed_envelope_sha256(request_envelope),
        "runtime_receipt_sha256":signed_envelope_sha256(runtime_envelope),
        "vantage":vantage,"scanner_identity":scanner.identity(),"scan_target":target,
        "observed_from":observed_from.isoformat(),
        "observed_until":observed_until.isoformat(),"scanner_version":scanner.version(),
        "clock_attestation":clock_attestation,
        "scan_artifact_sha256":artifact.sha256,"scan_artifact_size":artifact.size,
        "unexpected_open_ports":result.unexpected_open_ports,
    })
```

All qualification/target/security/signer schemas recursively forbid extras. The commissioning schema requires the exact evidence namespace, evidence key ID/certificate fingerprint, hardware hash, qualification hash, scanner identities, targets, and validity window; it has no pre-install runtime/core-leaf field. The runtime and network schemas separately require the actual `installed_manifest_sha256` and `installed_core_leaf_fingerprint` plus the evidence key/certificate identity. `QualificationArtifactManifestV1` is a signed, nonpublic, frozen-commit manifest containing exact version, commit, `SOURCE_DATE_EPOCH`, two-build reproducibility proof, and the unique role/path/SHA-256/size inventory produced before target commissioning. Security collection never invokes a build: it reopens that manifest, hashes the exact files, verifies their evidence-pending installation, and adds the qualification envelope itself as `qualification_manifest` to the signed security inventory. Security evidence otherwise requires exact version/commit/hashes, nonempty Python/npm SBOMs, source/dependency/model licenses, tool version/hash/source, zero blockers, all-reachable-history clean, the complete non-evidence release artifact inventory, and explicit private-data scan roots `.`, `dist`, and `var`. The artifact inventory must include three separately named and hash-bound roles—`reachy_package`, `reachy_package_sha256`, and `reachy_package_manifest`; omission, duplication, or substitution of any role blocks signing. Because the three files are independently inventoried under the explicit `dist` scan root, the private-data scanner scans each sidecar as well as every archive member. An explicit root is never ignored even if generated or gitignored. One mutable scan-wide budget spans `.`, `dist`, and `var`, all traversed regular files, every archive input/member at every nesting level, and actual bytes produced by decompression. It caps lazy path traversal and regular-file counts at 100,000 each, total physical input at 16 GiB, each raw or compressed filesystem input at 4 GiB, each expanded member at 2 GiB, all nested archive members at 50,000, nesting depth at three, and cumulative actual expansion at 12 GiB. Filesystem symlinks/FIFOs/devices/sockets and archive symlink/hardlink/device/special members block; nested archives recurse under the same counters. Thus a realistic locked ARM64 Reachy wheelhouse passes while traversal, nested-secret, special-entry, multi-archive cumulative, and decompression-bomb cases fail for distinct reason codes without an unbounded sort or extraction.

`commission_release_target.py` is run locally before evidence collection and reads the clean Mac platform UUID itself. The clean-target assertion proves there is no current runtime, core leaf certificate, or core private key; commissioning provisions or reopens only an owner-controlled target-evidence identity in the separate `tuntun.release.qualification-target.v1` namespace, bound to hardware and qualification. After physical owner/passkey review it signs that evidence key/certificate identity, permitted scanner certificate identities, exact LAN/outer scan targets, and qualification-manifest hash. It accepts no caller-authored `target_host_id` and never calls a pre-install `current_core_leaf_fingerprint`. The target-runtime collector executes on that independently commissioned host after the exact qualified bytes are locally installed in evidence-pending state, authenticates the target-evidence identity, and accepts no `Candidate` or caller fact payload: it resolves the installed release symlink, hashes the actual closed release manifest, reads the newly installed core-leaf fingerprint, hashes actual config files, reads hardware/boot facts, and emits minimized process/DNS/listener/socket/packet facts. Separate signed scanners authenticate the same target-evidence certificate before executing pinned `nmap` from commissioned LAN and isolated outer nodes, and bind the signed runtime receipt including the actual installed manifest/core leaf. Before each call, the release orchestrator samples one monotonic send tick and signs a strict `tuntun.collection-request.v1` containing that exact tick, a unique run/request ID, 256-bit nonce, role, ordinal, and maximum RTT; it copies the same tick into the bracket without a second clock read. The request-payload hash is the bracket commitment and every signed remote receipt also echoes the complete signed-request SHA-256. Runtime, LAN, and outer calls are invoked sequentially, and the final signed security envelope carries their request/receipt hashes and local brackets. The verifier requires the request send tick and maximum RTT to equal the bracket fields, unique request IDs/nonces, exact role/ordinal/run/commitment/request-hash echoes, receipt hashes, non-overlapping monotonic brackets, RTT `<=30s`, total window `<=15m`, and every receipt bracket no older than 30 minutes at the post-collection monotonic verification sample. An old signed request/receipt pair therefore cannot be relabeled with fresh unsigned bracket times. It never compares remote clocks to order hosts. Remote `observed_from|observed_until|signed_at` are accepted only after the receipt's `signed_ntp_v1` attestation proves an uncertainty `<=2s`, applies its signed offset, and places all remote times inside that call's local wall bracket plus uncertainty; positive and negative skew are tested. The strict request/runtime/network/security schemas forbid extras and bind these fields. Raw packet payloads, query/page content, secrets, and command arguments are never captured. Official receipts are generated only on the frozen qualified target; synthetic fixtures test tooling before freeze.

The signer registry fixes `algorithm="Ed25519"`, exact base64 public-key length, one purpose per key, an explicit `automation` or `owner` key role, validity window, nullable revocation timestamp, and unique key IDs; the loader additionally rejects the same public-key bytes under multiple aliases and rejects any purpose/role mismatch. Revoked records are fail-closed even for older signatures during release authorization. Separate Keychain keys are provisioned for qualification, target commissioning, collection requests, security, target runtime, network scan, acceptance, soak run, soak bundle, latency deviation, family stage, family review, family trial, P1R0, and publication; only owner-role keys may sign target commissioning, latency deviations, family reviews, P1R0, or publication records, and automation-role keys cannot hold those purposes. License policy allow/review/deny lists and model hash/provenance are exact. Make targets cover security/model/SBOM/license/listener/egress/fuzz/verify. Both workflows pass the repository workflow-policy test: every third-party action is a full commit SHA and every runner label is fixed. Release is manual `workflow_dispatch`, `contents: read`, `id-token: write`, build/attest/upload-artifact only—no tag or publication. Hosted CI is portability evidence, never a substitute for the signed physical target-host lifecycle receipts.

- [ ] **Step 4: Run green**

Run: `uv run pytest tests/ci/test_workflow_policy.py tests/security/test_private_data_scanner.py tests/security/test_evidence_signature.py tests/security/test_release_qualification.py tests/security/test_supply_chain_evidence.py tests/security/test_target_host_evidence.py tests/security/test_target_collectors.py tests/release/test_reproducible_build.py -q && uv run python scripts/verify_private_data.py . dist var && make security-scan model-manifest-check sbom license-check listener-scan egress-scan fuzz`

Expected: PASS with complete SBOM/licenses/history/private-data scan coverage, hashes/provenance, zero blockers, identical fixture builds, protected-header/signature policy, exact candidate/config/time/host-bound process/DNS/socket/packet and LAN/outer receipts, and no official release evidence signed before this implementation is committed.

- [ ] **Step 5: Commit**

```bash
git status --short
git add security/schemas/security-evidence-v1.schema.json security/schemas/evidence-signers-v1.schema.json security/schemas/qualification-artifact-manifest-v1.schema.json security/schemas/collection-request-v1.schema.json security/schemas/target-commissioning-receipt-v1.schema.json security/schemas/target-runtime-receipt-v1.schema.json security/schemas/target-network-scan-receipt-v1.schema.json security/evidence-signers-v1.json security/tool-versions-v1.json security/license-policy-v1.yaml scripts/evidence.py scripts/qualify_release_artifacts.py scripts/commission_release_target.py scripts/collect_target_runtime.py scripts/run_network_vantage_scan.py scripts/collect_release_evidence.py scripts/verify_release_evidence.py scripts/verify_private_data.py Makefile .github/workflows/security.yml .github/workflows/release.yml tests/security/test_evidence_signature.py tests/security/test_release_qualification.py tests/security/test_supply_chain_evidence.py tests/security/test_target_host_evidence.py tests/security/test_target_collectors.py tests/release/test_reproducible_build.py
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
from scripts.evidence import open_signed_evidence,signed_envelope_sha256
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
from scripts.evidence import open_signed_evidence,signed_envelope_sha256
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
import os,stat
from scripts.evidence import (
    MAX_SIGNED_EVIDENCE_BYTES,open_signed_evidence,parse_signed_evidence,
    signed_envelope_sha256,
)
from scripts.run_acceptance import gate as gate_acceptance
from scripts.verify_soak_evidence import verify_soak_bundle
from scripts.record_family_stage import verify_trial
class ReleaseEvidenceError(ValueError): pass
MAX_EVIDENCE_BYTES=MAX_SIGNED_EVIDENCE_BYTES
def _read_frozen_evidence(path):
    named=path.stat(follow_symlinks=False); flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)
    fd=os.open(path,flags)
    try:
        opened=os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_size>MAX_EVIDENCE_BYTES
            or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino)):
            raise ReleaseEvidenceError("evidence file invalid")
        identity=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
        chunks=[]; remaining=opened.st_size
        while remaining:
            chunk=os.read(fd,min(1024*1024,remaining))
            if not chunk: raise ReleaseEvidenceError("evidence file changed")
            chunks.append(chunk); remaining-=len(chunk)
        if os.read(fd,1): raise ReleaseEvidenceError("evidence file changed")
        after=os.fstat(fd); named_after=path.stat(follow_symlinks=False)
        if ((after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)!=identity
            or (named_after.st_dev,named_after.st_ino)!=(after.st_dev,after.st_ino)):
            raise ReleaseEvidenceError("evidence file changed")
        return b"".join(chunks)
    finally: os.close(fd)
@dataclass(frozen=True,slots=True)
class VerificationDependencies:
    now:datetime; latency_receipt_verifier:object
    family_review_receipt_verifier:object; family_consent_receipt_verifier:object
@dataclass(frozen=True,slots=True)
class VerifiedEvidenceSet:
    version:str; commit:str; evidence_hashes:dict[str,str]; security:dict; acceptance:dict
    artifact_inventory:dict[str,dict]; frozen_component_hashes:dict[str,str]
    qualification_manifest_sha256:str
def verify_evidence_set(paths,schemas,registry,version,commit,now,dependencies):
    if set(paths)!={"security","acceptance","soak_bundle","family_trial"}: raise ReleaseEvidenceError("evidence path roles")
    envelopes={
        name:parse_signed_evidence(_read_frozen_evidence(path))
        for name,path in paths.items()
    }
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
    qualification_sha=security.get("qualification_manifest_sha256")
    if inventory.get("qualification_manifest",{}).get("sha256")!=qualification_sha:
        raise ReleaseEvidenceError("security qualification binding")
    return VerifiedEvidenceSet(
        version,commit,hashes,security,acceptance,inventory,frozen,
        qualification_sha,
    )
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
from scripts.assemble_release import REACHY_PACKAGE_ROLES,REQUIRED_ROLES,assemble,digest
@pytest.mark.asyncio
async def test_candidate_is_complete_clean_and_bound(release_inputs,tmp_path):
    candidate=await assemble(release_inputs,tmp_path/"candidate")
    assert {item.role for item in candidate.artifacts}==REQUIRED_ROLES
    assert candidate.version=="0.1.0-beta.1" and candidate.commit==release_inputs.commit
    assert candidate.schema_version=="tuntun.release-candidate.v1" and set(candidate.evidence_hashes)=={"acceptance_report_sha256","security_evidence_sha256","soak_evidence_sha256","family_trial_sha256"}
    assert candidate.p1r0_approval_sha256==digest(release_inputs.p1r0_path)
    by_role={item.role:item for item in candidate.artifacts}
    paths=[(tmp_path/"candidate"/by_role[role].path) for role in REACHY_PACKAGE_ROLES]
    assert len({path.parent for path in paths})==1

@pytest.mark.asyncio
@pytest.mark.parametrize("role",tuple(sorted(REACHY_PACKAGE_ROLES)))
async def test_missing_reachy_installer_sidecar_blocks_assembly(
    release_inputs,tmp_path,role,
):
    del release_inputs.role_paths[role]
    with pytest.raises(RuntimeError,match="artifact roles incomplete"):
        await assemble(release_inputs,tmp_path/"candidate")

@pytest.mark.asyncio
@pytest.mark.parametrize("role",("reachy_package_sha256","reachy_package_manifest"))
async def test_substituted_reachy_installer_sidecar_blocks_assembly(
    release_inputs,tmp_path,role,
):
    release_inputs.role_paths[role].write_bytes(b"substituted")
    with pytest.raises(RuntimeError,match="signed artifact mismatch"):
        await assemble(release_inputs,tmp_path/"candidate")

@pytest.mark.asyncio
async def test_build_role_must_equal_signed_security_inventory(release_inputs,tmp_path):
    release_inputs.role_paths["python_wheels"].write_bytes(b"different but self-consistent")
    with pytest.raises(RuntimeError,match="signed artifact mismatch"):
        await assemble(release_inputs,tmp_path/"candidate")

@pytest.mark.asyncio
@pytest.mark.parametrize("mutation",("omit_qualification","wrong_qualified_bytes","later_rebuild"))
async def test_candidate_must_consume_exact_qualification_without_rebuild(
    release_inputs,tmp_path,mutation,
):
    release_inputs.mutate_qualification_boundary(mutation)
    with pytest.raises(RuntimeError,match="qualification|qualified artifact mismatch"):
        await assemble(release_inputs,tmp_path/"candidate")

@pytest.mark.asyncio
@pytest.mark.parametrize("role",(
    "python_wheels","qualification_manifest","security_evidence",
    "acceptance_evidence","p1r0_approval",
))
@pytest.mark.parametrize("mutation",("replace","grow","truncate"))
async def test_source_mutation_during_frozen_copy_never_enters_candidate(
    release_inputs,tmp_path,role,mutation,
):
    release_inputs.mutate_source_during_copy(role,mutation)
    with pytest.raises(RuntimeError,match="source changed|artifact mismatch"):
        await assemble(release_inputs,tmp_path/"candidate")
    assert not (tmp_path/"candidate").exists()
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/release/test_public_docs.py tests/release/test_candidate_assembly.py tests/release/test_clean_account_install.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'scripts.assemble_release'`.

- [ ] **Step 3: Implement candidate assembly/docs**

```python
# scripts/assemble_release.py
import hashlib,json,os,shutil,stat,tempfile
from contextlib import ExitStack
from dataclasses import asdict,dataclass
from datetime import datetime
from pathlib import Path
from typing import Mapping
from scripts.evidence import (
    MAX_SIGNED_EVIDENCE_BYTES,open_signed_evidence,parse_signed_evidence,
    signed_envelope_sha256,
)
from scripts.qualify_release_artifacts import QUALIFIED_DISTRIBUTABLE_ROLES
from scripts.release_evidence_gate import VerificationDependencies,verify_evidence_set
from scripts.verify_reachy_archive import verify as verify_reachy_archive
from scripts.verify_p1r0 import P1R0BindingContext,verify_p1r0
REACHY_PACKAGE_ROLES=frozenset({"reachy_package","reachy_package_sha256","reachy_package_manifest"})
REQUIRED_ROLES={"source_archive","python_wheels","admin_assets",*REACHY_PACKAGE_ROLES,"python_sbom","npm_sbom","license_inventory","model_manifest","qualification_manifest","security_evidence","acceptance_evidence","soak_evidence","family_trial_evidence","p1r0_approval","provenance"}
SIGNED_BUILD_ROLES={"source_archive","python_wheels","admin_assets",*REACHY_PACKAGE_ROLES,"python_sbom","npm_sbom","license_inventory","model_manifest","qualification_manifest","provenance"}
EVIDENCE_ROLE_FIELDS={"security_evidence":"security_evidence_sha256","acceptance_evidence":"acceptance_report_sha256","soak_evidence":"soak_evidence_sha256","family_trial_evidence":"family_trial_sha256"}
STREAM_BYTES=1024*1024
MAX_CONTROL_BYTES=16*1024*1024
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

class FrozenInput:
    def __init__(self,path):
        self.path=Path(path); named=self.path.stat(follow_symlinks=False)
        if not stat.S_ISREG(named.st_mode): raise RuntimeError("artifact source is not regular")
        flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)
        self.fd=os.open(self.path,flags); opened=os.fstat(self.fd)
        if (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino):
            os.close(self.fd); raise RuntimeError("artifact source changed")
        self.identity=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
    def close(self): os.close(self.fd)
    def __enter__(self): return self
    def __exit__(self,*_args): self.close()
    def _rewind(self): os.lseek(self.fd,0,os.SEEK_SET)
    def _verify_unchanged(self):
        opened=os.fstat(self.fd); named=self.path.stat(follow_symlinks=False)
        current=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
        if (current!=self.identity
            or (named.st_dev,named.st_ino)!=(opened.st_dev,opened.st_ino)):
            raise RuntimeError("artifact source changed")
    def digest(self):
        self._rewind(); hasher=hashlib.sha256(); remaining=self.identity[2]
        while remaining:
            chunk=os.read(self.fd,min(STREAM_BYTES,remaining))
            if not chunk: raise RuntimeError("artifact source changed")
            hasher.update(chunk); remaining-=len(chunk)
        if os.read(self.fd,1): raise RuntimeError("artifact source changed")
        self._verify_unchanged(); return hasher.hexdigest()
    def bytes(self,limit=MAX_CONTROL_BYTES):
        if self.identity[2]>limit: raise RuntimeError("control file size limit")
        self._rewind(); chunks=[]; remaining=self.identity[2]
        while remaining:
            chunk=os.read(self.fd,min(STREAM_BYTES,remaining))
            if not chunk: raise RuntimeError("artifact source changed")
            chunks.append(chunk); remaining-=len(chunk)
        if os.read(self.fd,1): raise RuntimeError("artifact source changed")
        self._verify_unchanged(); return b"".join(chunks)
    def copy_to(self,target):
        target=Path(target); flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)
        output=os.open(target,flags,0o600); self._rewind(); remaining=self.identity[2]
        try:
            while remaining:
                chunk=os.read(self.fd,min(STREAM_BYTES,remaining))
                if not chunk: raise RuntimeError("artifact source changed")
                view=memoryview(chunk)
                while view:
                    written=os.write(output,view); view=view[written:]
                remaining-=len(chunk)
            if os.read(self.fd,1): raise RuntimeError("artifact source changed")
            os.fsync(output)
        finally: os.close(output)
        self._verify_unchanged()

def digest(path):
    with FrozenInput(path) as source: return source.digest()

def read_frozen_bytes(path,limit=MAX_CONTROL_BYTES):
    with FrozenInput(path) as source: return source.bytes(limit)

def verify_reachy_package_set(paths):
    if set(paths)!=REACHY_PACKAGE_ROLES: raise RuntimeError("Reachy artifact roles incomplete")
    archive=paths["reachy_package"]
    checksum=paths["reachy_package_sha256"]
    manifest=paths["reachy_package_manifest"]
    if checksum.name!=archive.name+".sha256" or manifest.name!=archive.name+".manifest.json":
        raise RuntimeError("Reachy sidecar names mismatch")
    lines=read_frozen_bytes(checksum).decode("utf-8").splitlines()
    expected=digest(archive)
    if lines!=[expected+"  "+archive.name]: raise RuntimeError("Reachy checksum sidecar mismatch")
    verify_reachy_archive(archive,expected,manifest,extract=None)
async def assemble(inputs,output):
    if set(inputs.role_paths)!=REQUIRED_ROLES: raise RuntimeError("artifact roles incomplete")
    source_names={os.path.abspath(path):role for role,path in inputs.role_paths.items()}
    evidence_roles={}
    for name,path in inputs.evidence_paths.items():
        role=source_names.get(os.path.abspath(path))
        if role is None: raise RuntimeError("evidence input differs from candidate role")
        evidence_roles[name]=role
    if source_names.get(os.path.abspath(inputs.p1r0_path))!="p1r0_approval":
        raise RuntimeError("P1R0 input differs from contained P1R0")
    output=Path(output)
    if output.exists() or output.is_symlink(): raise FileExistsError(output)
    output.parent.mkdir(parents=True,exist_ok=True)
    stage=Path(tempfile.mkdtemp(prefix=".release-candidate-",dir=output.parent)); os.chmod(stage,0o700)
    try:
        with ExitStack() as stack:
            frozen={role:stack.enter_context(FrozenInput(path)) for role,path in inputs.role_paths.items()}
            copied={}
            for role,source in sorted(frozen.items()):
                family="reachy" if role in REACHY_PACKAGE_ROLES else role
                target=stage/"artifacts"/family/source.path.name
                target.parent.mkdir(parents=True,exist_ok=True); source.copy_to(target); copied[role]=target
            staged_evidence={name:copied[role] for name,role in evidence_roles.items()}
            for path in {*staged_evidence.values(),copied["qualification_manifest"],copied["p1r0_approval"]}:
                if path.stat(follow_symlinks=False).st_size>MAX_CONTROL_BYTES:
                    raise RuntimeError("control file size limit")
            verified=verify_evidence_set(staged_evidence,inputs.schemas,inputs.registry,inputs.version,inputs.commit,inputs.now,inputs.dependencies)
            qualification_path=copied["qualification_manifest"]
            qualification_envelope=parse_signed_evidence(
                read_frozen_bytes(
                    qualification_path,MAX_SIGNED_EVIDENCE_BYTES,
                ),
            )
            qualification=open_signed_evidence(
                qualification_envelope,inputs.schemas["qualification_artifact"],
                inputs.registry,"qualification",inputs.now,
            )
            if qualification["candidate_version"]!=inputs.version or qualification["commit"]!=inputs.commit:
                raise RuntimeError("qualification binding mismatch")
            if signed_envelope_sha256(qualification_envelope)!=verified.qualification_manifest_sha256:
                raise RuntimeError("qualification binding mismatch")
            qualified={item["role"]:item for item in qualification["artifacts"]}
            if set(qualified)!=QUALIFIED_DISTRIBUTABLE_ROLES or len(qualified)!=len(qualification["artifacts"]):
                raise RuntimeError("qualification artifact roles invalid")
            artifacts=[]
            for role,target in sorted(copied.items()):
                target_digest=digest(target); target_size=target.stat(follow_symlinks=False).st_size
                artifacts.append(Artifact(role,str(target.relative_to(stage)),target_digest,target_size))
            by_role={item.role:item for item in artifacts}
            for role,item in qualified.items():
                copied_item=by_role.get(role)
                if copied_item is None or copied_item.sha256!=item["sha256"] or copied_item.size!=item["size"]:
                    raise RuntimeError("qualified artifact mismatch: "+role)
            for role in SIGNED_BUILD_ROLES:
                item=by_role[role]; expected=verified.artifact_inventory.get(role)
                if expected is None or item.sha256!=expected["sha256"] or item.size!=expected["size"]:
                    raise RuntimeError("signed artifact mismatch: "+role)
            verify_reachy_package_set({role:copied[role] for role in REACHY_PACKAGE_ROLES})
            for role,field in EVIDENCE_ROLE_FIELDS.items():
                if by_role[role].sha256!=verified.evidence_hashes[field]:
                    raise RuntimeError("evidence file is not canonical: "+role)
            p1r0_path=copied["p1r0_approval"]
            p1r0_envelope=parse_signed_evidence(
                read_frozen_bytes(p1r0_path,MAX_SIGNED_EVIDENCE_BYTES),
            )
            p1r0=await verify_p1r0(p1r0_envelope,inputs.schemas["p1r0_approval"],inputs.registry,verified.evidence_hashes,inputs.version,inputs.commit,inputs.now,inputs.p1r0_receipt_verifier,inputs.p1r0_binding_context)
            if not p1r0.allowed: raise RuntimeError("P1R0 blocked")
            if (len({item.path for item in artifacts})!=len(artifacts)
                or len({Path(item.path).name for item in artifacts})!=len(artifacts)):
                raise RuntimeError("artifact paths/basenames are not unique")
            sums=stage/"SHA256SUMS"; sums.write_text("".join(f"{item.sha256}  {item.path}\n" for item in sorted(artifacts,key=lambda value:value.path)))
            with sums.open("rb") as stream: os.fsync(stream.fileno())
            p1r0_sha=by_role["p1r0_approval"].sha256
            result=ReleaseCandidate("tuntun.release-candidate.v1",inputs.version,inputs.commit,verified.evidence_hashes,p1r0_sha,tuple(artifacts))
            manifest=stage/"release-candidate.json"; manifest.write_text(json.dumps(asdict(result),sort_keys=True,separators=(",",":"))+"\n")
            with manifest.open("rb") as stream: os.fsync(stream.fileno())
            for item in artifacts:
                target=stage/item.path
                if digest(target)!=item.sha256 or target.stat(follow_symlinks=False).st_size!=item.size:
                    raise RuntimeError("staged artifact changed before publication")
            for source in frozen.values(): source._verify_unchanged()
            directories={stage,stage/"artifacts",*(path.parent for path in copied.values())}
            for path in directories:
                descriptor=os.open(path,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
                try: os.fsync(descriptor)
                finally: os.close(descriptor)
        os.replace(stage,output)
        directory=os.open(output.parent,os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
        return result
    except BaseException:
        shutil.rmtree(stage,ignore_errors=True); raise
```

All evidence writers emit RFC 8785 canonical envelope bytes without trailing whitespace, so the complete-envelope hashes returned by `verify_evidence_set` equal the copied evidence-file hashes. Assembly opens exactly one nofollow regular-file descriptor for every role, freezes its device/inode/size/mtime/ctime, and streams the opened size into a private same-parent staging candidate while hashing; early EOF, growth, named-path replacement, or metadata change blocks and removes the stage. It fsyncs each target, reopens every staged target with the same bounded streaming verifier, and compares the post-copy size/hash to the exact qualification, signed security inventory, evidence, and P1R0 bindings before an atomic candidate rename. Qualification, P1R0, and all evidence inputs must be the same named role inputs; only their private staged copies reach semantic verification. General control documents are capped at 16 MiB; every signed-evidence role uses the stricter canonical 2 MiB envelope limit before schema validation or semantic access. Assembly calls the concrete verifier and `verify_p1r0`; no input-owned verifier method or pass boolean exists. It reopens the signed nonpublic qualification envelope, requires its hash to equal the security evidence binding, and compares every qualified distributable role byte-for-byte and size-for-size with the candidate inputs. There is no build method in assembly, so a later rebuild—even one substituted into a newly self-consistent role map—cannot replace the qualified bytes. The qualification manifest itself is a separately required candidate role and must match the security inventory. Each other non-evidence artifact must byte-match the role/hash/size signed by security evidence, and every frozen acceptance component hash must already have matched that same inventory. `reachy_package`, `reachy_package_sha256`, and `reachy_package_manifest` are required distinct roles; assembly reopens the closed archive manifest, requires the canonical checksum line, and copies all three to one `artifacts/reachy/` directory so `install_app.sh` can consume the packaged archive with both adjacent sidecars. Evidence artifacts must match the four verified complete-envelope hashes. The exact verified P1R0 file is copied into the candidate and its separate SHA-256 is fixed in the manifest. The schema recursively forbids extras, requires every role exactly once with unique relative path, fixes version/commit/evidence/P1R0/artifact hashes/sizes, and has no publication URL. README documents architecture/hardware/costs/simulator/commissioning/UI/limits. PRIVACY/SECURITY include tested claims and private reporting/no content logs. LICENSE is exact Apache-2.0 only after approval; NOTICE excludes weights and lists governed downloads. Clean-account tests use synthetic signed fixtures; production assembly occurs only in the frozen-commit ceremony.

- [ ] **Step 4: Run green**

Run: `uv run pytest tests/release/test_public_docs.py tests/release/test_candidate_assembly.py tests/release/test_clean_account_install.py -q && make bootstrap && make check`

Expected: PASS with fixture P1R0/evidence semantics, signed artifact binding, replace/grow/truncate races rejected for distributable, qualification, evidence, and P1R0 inputs, clean-account proof, simulator without secrets, and no production candidate or upload before the implementation commit.

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
- Create: `scripts/verify_published_download.py`
- Create: `docs/operations/publish-release.md`
- Modify: `.github/workflows/release.yml`
- Test: `tests/release/test_tag_verification.py`
- Test: `tests/release/test_release_gate.py`
- Test: `tests/release/test_no_auto_publication.py`
- Test: `tests/release/test_published_download.py`

**Interfaces:** `verify_tag(tag: str, version: str, commit: str, registry: TagSignerRegistry, now: datetime, runner: GitRunner) -> TagVerification`; `async verify_candidate(manifest_path: Path, schema: dict, evidence_schemas: Mapping[str,dict], registry: SignerRegistry, now: datetime, dependencies: VerificationDependencies, p1r0_receipt_verifier: P1R0PasskeyReceiptVerifier, p1r0_binding_context: P1R0BindingContext) -> tuple[VerifiedCandidate,P1R0Decision]`; `decide(candidate: VerifiedCandidate, p1r0: P1R0Decision, tag: TagVerification, installed_commit: str) -> ReleaseDecision`; `verify_published_download(root: Path, candidate_schema: dict, expected_candidate_manifest_sha256: str) -> Mapping[str,str]`; `merge_verified_draft_assets(api_rows: list[dict], verified_assets: Mapping[str,dict]) -> Mapping[str,dict]`; `record_verified_draft(authorization: SignedEvidence, draft_release_id: int, draft_tag: str, hashes: Mapping[str,str], asset_inventory: Mapping[str,dict], signer: EvidenceSigner, now: datetime) -> SignedEvidence`. The CLI loads trusted owner/household/session/policy context—not a prebuilt binding—plus a strict explicit evidence-schema-path registry, verifies the candidate-contained P1R0, and signs purpose `publication`; it has no GitHub mutation capability. The manual draft re-download harness requires `release-candidate.json`, `SHA256SUMS`, and one direct canonical-basename file for every candidate-manifest artifact in a fresh directory. It rejects missing/extra files, unsafe or duplicate paths/roles/basenames/sums, verifies every size/hash/sum, reopens the adjacent Reachy triple with the closed-inventory verifier, writes its hashes and downloaded-asset inventory through exclusive nofollow fsynced descriptors, then requires GitHub's exact `sha256:` digest/size/name/ID inventory to equal those frozen downloads before signing the draft receipt and executing the separate publish command.

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

def test_manual_runbook_keeps_assets_draft_until_redownload_and_signed_receipt():
    text=Path("docs/operations/publish-release.md").read_text()
    create=text.index("gh release create")
    download=text.index("gh release download",create)
    verify=text.index("scripts/verify_published_download.py",download)
    assets_output=text.index("--assets-output",verify)
    merge=text.index("merge-draft-assets",assets_output)
    receipt=text.index("record-verified-draft",merge)
    inventory_after=text.index("assets-after.json",receipt)
    compare=text.index("cmp ",inventory_after)
    publish=text.index("gh release edit",receipt)
    assert "--draft" in text[create:download]
    assert "--draft=false" in text[publish:]
    assert create<download<verify<assets_output<merge<receipt<inventory_after<compare<publish
    assert "draft remains private" in text.lower()
```

```python
# tests/release/test_published_download.py
import json,pytest
from scripts.assemble_release import REQUIRED_ROLES
from scripts.verify_published_download import main,verify_published_download

def test_mocked_download_verifies_every_role_then_reopens_adjacent_reachy_triple(
    published_download_fixture,candidate_schema_file,publication_record,tmp_path,
):
    root=published_download_fixture.download_all_to_fresh_directory()
    hashes_output=tmp_path/"hashes.json"; assets_output=tmp_path/"assets.json"
    result=main((
        "--root",str(root),"--candidate-schema",str(candidate_schema_file),
        "--expected-candidate-manifest-sha256",
        publication_record.candidate_manifest_sha256,
        "--hashes-output",str(hashes_output),
        "--assets-output",str(assets_output),
    ))
    assert set(result)==REQUIRED_ROLES
    assert set(json.loads(hashes_output.read_text()))==REQUIRED_ROLES
    assert set(json.loads(assets_output.read_text()))=={
        "release-candidate.json","SHA256SUMS",*REQUIRED_ROLES,
    }
    assert published_download_fixture.closed_archive_verify_calls==1

def test_published_verification_output_never_follows_existing_symlink(
    published_download_fixture,candidate_schema_file,publication_record,tmp_path,
):
    root=published_download_fixture.download_all_to_fresh_directory()
    protected=tmp_path/"protected"; protected.write_bytes(b"unchanged")
    output=tmp_path/"hashes.json"; output.symlink_to(protected)
    with pytest.raises(OSError):
        main((
            "--root",str(root),"--candidate-schema",str(candidate_schema_file),
            "--expected-candidate-manifest-sha256",
            publication_record.candidate_manifest_sha256,
            "--hashes-output",str(output),
        ))
    assert protected.read_bytes()==b"unchanged"

@pytest.mark.parametrize("role",tuple(sorted(REQUIRED_ROLES)))
@pytest.mark.parametrize("mutation",("missing","renamed","moved","substituted"))
def test_every_published_role_omission_location_or_substitution_blocks(
    published_download_fixture,candidate_schema_file,publication_record,role,mutation,
):
    root=published_download_fixture.download_mutated(mutation,role=role)
    with pytest.raises(ValueError,match="published artifact set|published artifact mismatch|SHA256SUMS"):
        verify_published_download(
            root,json.loads(candidate_schema_file.read_text()),
            publication_record.candidate_manifest_sha256,
        )


@pytest.mark.parametrize("mutation",(
    "extra_file","extra_sum","missing_sum","duplicate_sum",
    "duplicate_role","duplicate_path","duplicate_basename","path_escape",
))
def test_published_layout_and_sum_set_are_closed(
    published_download_fixture,candidate_schema_file,mutation,
):
    root,expected_manifest_sha256=published_download_fixture.download_layout_mutation(
        mutation,
    )
    with pytest.raises(ValueError,match="published|SHA256SUMS|candidate artifact"):
        verify_published_download(
            root,json.loads(candidate_schema_file.read_text()),
            expected_manifest_sha256,
        )


@pytest.mark.parametrize("role",tuple(sorted(REQUIRED_ROLES)))
@pytest.mark.parametrize("mutation",("replace","grow","truncate"))
def test_download_mutation_during_hash_or_closed_verification_blocks(
    published_download_fixture,candidate_schema_file,publication_record,role,mutation,
):
    root=published_download_fixture.download_all_to_fresh_directory()
    published_download_fixture.mutate_during_frozen_verification(root,role,mutation)
    with pytest.raises((RuntimeError,ValueError),match="source changed|published artifact"):
        verify_published_download(
            root,json.loads(candidate_schema_file.read_text()),
            publication_record.candidate_manifest_sha256,
        )


@pytest.mark.parametrize("control",("release-candidate.json","SHA256SUMS"))
def test_download_control_file_replacement_between_parse_and_verify_blocks(
    published_download_fixture,candidate_schema_file,publication_record,control,
):
    root=published_download_fixture.download_all_to_fresh_directory()
    published_download_fixture.replace_control_during_verification(root,control)
    with pytest.raises((RuntimeError,ValueError),match="source changed|manifest|SHA256SUMS"):
        verify_published_download(
            root,json.loads(candidate_schema_file.read_text()),
            publication_record.candidate_manifest_sha256,
        )
```

```python
# tests/release/test_release_gate.py
import json,pytest
from jsonschema import ValidationError
from types import SimpleNamespace
from scripts.assemble_release import REQUIRED_ROLES
from scripts.release_gate import VerifiedCandidate,decide,load_evidence_schemas,merge_verified_draft_assets,record_verified_draft,verify_candidate
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
def test_verified_draft_receipt_binds_authorization_release_assets_and_every_role(
    publication_authorization,publication_signer,now,
):
    hashes={role:"a"*64 for role in REQUIRED_ROLES}
    keys=("release-candidate.json","SHA256SUMS",*sorted(REQUIRED_ROLES))
    asset_inventory={
        key:{"id":index+1,"name":key,"size":1,"sha256":(
            publication_authorization.payload["candidate_manifest_sha256"]
            if key=="release-candidate.json" else hashes.get(key,"b"*64)
        )}
        for index,key in enumerate(keys)
    }
    receipt=record_verified_draft(
        publication_authorization,123,"v0.1.0-beta.1",hashes,asset_inventory,
        publication_signer,now,
    )
    assert receipt.payload["decision"]=="draft_assets_verified"
    assert receipt.payload["artifact_hashes"]==hashes
    assert receipt.payload["draft_release_id"]==123

def test_github_asset_inventory_must_exactly_match_frozen_download_inventory():
    verified={
        key:{"name":key+".bin" if key in REQUIRED_ROLES else key,
             "size":index+1,"sha256":f"{index+1:064x}"}
        for index,key in enumerate(("release-candidate.json","SHA256SUMS",*sorted(REQUIRED_ROLES)))
    }
    api=[
        {"id":index+100,"name":item["name"],"size":item["size"],
         "digest":"sha256:"+item["sha256"]}
        for index,item in enumerate(verified.values())
    ]
    merged=merge_verified_draft_assets(api,verified)
    assert set(merged)==set(verified)
    assert all(set(item)=={"id","name","size","sha256"} for item in merged.values())
    for mutation in ("missing","extra","duplicate_name","duplicate_id","null_digest","wrong_size","wrong_digest"):
        changed=[dict(item) for item in api]
        if mutation=="missing": changed.pop()
        elif mutation=="extra": changed.append({"id":9999,"name":"extra","size":0,"digest":"sha256:"+"0"*64})
        elif mutation=="duplicate_name": changed[-1]["name"]=changed[0]["name"]
        elif mutation=="duplicate_id": changed[-1]["id"]=changed[0]["id"]
        elif mutation=="null_digest": changed[0]["digest"]=None
        elif mutation=="wrong_size": changed[0]["size"]+=1
        else: changed[0]["digest"]="sha256:"+"f"*64
        with pytest.raises(ValueError,match="draft asset"):
            merge_verified_draft_assets(changed,verified)
```

- [ ] **Step 2: Run red**

Run: `uv run pytest tests/ci/test_workflow_policy.py tests/release/test_tag_verification.py tests/release/test_release_gate.py tests/release/test_published_download.py tests/release/test_no_auto_publication.py -q`

Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.verify_tag'`.

- [ ] **Step 3: Implement tag and release verification**

```python
# scripts/verify_tag.py
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import jsonschema
from scripts.control_files import parse_control_json
@dataclass(frozen=True,slots=True)
class TagSignerRecord:
    fingerprint:str; algorithm:str; purpose:str; approved_at:datetime; not_before:datetime; not_after:datetime; revoked_at:datetime|None
class TagSignerRegistry:
    def __init__(self,by_fingerprint): self.by_fingerprint=by_fingerprint
    @classmethod
    def load(cls,schema_path:Path,registry_path:Path):
        schema=parse_control_json(
            schema_path,max_bytes=262_144,require_canonical=False,
        )
        raw=parse_control_json(
            registry_path,max_bytes=131_072,require_canonical=True,
        )
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
import json,os,re,tempfile
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path,PurePosixPath
import jsonschema
from scripts.assemble_release import FrozenInput,MAX_CONTROL_BYTES,REACHY_PACKAGE_ROLES,REQUIRED_ROLES,SIGNED_BUILD_ROLES,digest,read_frozen_bytes,verify_reachy_package_set
from scripts.control_files import parse_control_json,parse_control_json_bytes
from scripts.evidence import (
    MAX_SIGNED_EVIDENCE_BYTES,parse_signed_evidence,signed_envelope_sha256,
)
from scripts.release_evidence_gate import verify_evidence_set
from scripts.verify_p1r0 import verify_p1r0
EVIDENCE_PATH_ROLES={"security":"security_evidence","acceptance":"acceptance_evidence","soak_bundle":"soak_evidence","family_trial":"family_trial_evidence"}
EVIDENCE_SCHEMA_ROLES={"qualification_artifact","security","acceptance","soak_run","soak_bundle","latency_deviation","family_stage","family_review","family_trial","p1r0_approval"}
def sha256(path): return digest(path)
def _candidate_artifact_path(value):
    if (not isinstance(value,str) or not value or "\\" in value
        or any(ord(char)<32 or ord(char)==127 for char in value)):
        raise ValueError("artifact path invalid")
    path=PurePosixPath(value)
    if (path.is_absolute() or not path.parts
        or any(part in ("",".","..") for part in path.parts)
        or path.as_posix()!=value):
        raise ValueError("artifact path invalid")
    return path
def load_evidence_schemas(repo_root,paths_file,paths_schema):
    root=repo_root.resolve()
    registry_schema=parse_control_json(
        paths_schema,max_bytes=262_144,require_canonical=False,
    )
    raw=parse_control_json(
        paths_file,max_bytes=131_072,require_canonical=True,
    )
    jsonschema.Draft202012Validator(registry_schema,format_checker=jsonschema.FormatChecker()).validate(raw)
    if {item["role"] for item in raw["schemas"]}!=EVIDENCE_SCHEMA_ROLES or len(raw["schemas"])!=len(EVIDENCE_SCHEMA_ROLES): raise ValueError("evidence schema roles are not exact")
    result={}
    for item in raw["schemas"]:
        path=(root/item["path"]).resolve()
        if not path.is_relative_to(root) or sha256(path)!=item["sha256"]: raise ValueError("evidence schema path/hash invalid")
        schema=parse_control_json(
            path,max_bytes=1_048_576,require_canonical=False,
        )
        jsonschema.Draft202012Validator.check_schema(schema); result[item["role"]]=schema
    return result
@dataclass(frozen=True,slots=True)
class VerifiedCandidate: version:str; commit:str; manifest_sha256:str; evidence_hashes:dict[str,str]; p1r0_approval_sha256:str
async def verify_candidate(manifest_path,schema,evidence_schemas,registry,now,dependencies,p1r0_receipt_verifier,p1r0_binding_context):
    manifest_path=Path(manifest_path); root=manifest_path.parent.resolve()
    if manifest_path.parent.is_symlink() or not root.is_dir(): raise ValueError("candidate root invalid")
    with ExitStack() as stack:
        manifest_source=stack.enter_context(FrozenInput(manifest_path))
        sums_source=stack.enter_context(FrozenInput(root/"SHA256SUMS"))
        manifest=parse_control_json_bytes(
            manifest_source.bytes(1_048_576),max_bytes=1_048_576,
            require_canonical=True,
        )
        jsonschema.Draft202012Validator(schema,format_checker=jsonschema.FormatChecker()).validate(manifest)
        by_role={item["role"]:item for item in manifest["artifacts"]}
        if set(by_role)!=REQUIRED_ROLES or len(by_role)!=len(manifest["artifacts"]): raise ValueError("artifact roles are not exact and unique")
        artifact_paths=[_candidate_artifact_path(item["path"]) for item in manifest["artifacts"]]
        if (len(set(artifact_paths))!=len(artifact_paths)
            or len({path.name for path in artifact_paths})!=len(artifact_paths)):
            raise ValueError("artifact paths/basenames are not unique")
        sources={}
        for role,item in by_role.items():
            candidate_path=_candidate_artifact_path(item["path"]); lexical=root/candidate_path
            parent=lexical.parent.resolve()
            if not parent.is_relative_to(root) or lexical.parent.is_symlink():
                raise ValueError("artifact path escapes candidate")
            source=stack.enter_context(FrozenInput(lexical)); sources[role]=source
            if source.identity[2]!=item["size"] or source.digest()!=item["sha256"]:
                raise ValueError("artifact sha256 mismatch")
        expected_sums="".join(f'{item["sha256"]}  {item["path"]}\n' for item in sorted(manifest["artifacts"],key=lambda value:value["path"]))
        if sums_source.bytes(MAX_CONTROL_BYTES).decode("utf-8")!=expected_sums:
            raise ValueError("SHA256SUMS mismatch")
        with tempfile.TemporaryDirectory(prefix="tuntun-release-gate-") as temporary:
            snapshot=Path(temporary); os.chmod(snapshot,0o700); copied={}
            for role,source in sources.items():
                target=snapshot/source.path.name; source.copy_to(target); copied[role]=target
            evidence_paths={name:copied[role] for name,role in EVIDENCE_PATH_ROLES.items()}
            try: verified=verify_evidence_set(evidence_paths,evidence_schemas,registry,manifest["version"],manifest["commit"],now,dependencies)
            except ValueError as error: raise ValueError(str(error).replace("semantic gate","evidence gate failed")) from error
            if verified.evidence_hashes!=manifest["evidence_hashes"]: raise ValueError("evidence hash binding mismatch")
            for role in SIGNED_BUILD_ROLES:
                item=by_role[role]; signed=verified.artifact_inventory.get(role)
                if signed is None or item["sha256"]!=signed["sha256"] or item["size"]!=signed["size"]: raise ValueError("signed artifact mismatch: "+role)
            reachy_paths={role:copied[role] for role in REACHY_PACKAGE_ROLES}
            try: verify_reachy_package_set(reachy_paths)
            except RuntimeError as error: raise ValueError("Reachy package verification failed") from error
            p1r0_item=by_role["p1r0_approval"]; p1r0_path=copied["p1r0_approval"]
            if sha256(p1r0_path)!=manifest["p1r0_approval_sha256"]: raise ValueError("contained P1R0 hash mismatch")
            p1r0_envelope=parse_signed_evidence(
                read_frozen_bytes(p1r0_path,MAX_SIGNED_EVIDENCE_BYTES),
            )
            p1r0=await verify_p1r0(p1r0_envelope,evidence_schemas["p1r0_approval"],registry,verified.evidence_hashes,manifest["version"],manifest["commit"],now,p1r0_receipt_verifier,p1r0_binding_context)
            if not p1r0.allowed: raise ValueError("contained P1R0 verification failed: "+",".join(p1r0.failures))
        manifest_sha256=manifest_source.digest()
        manifest_source._verify_unchanged(); sums_source._verify_unchanged()
        for source in sources.values(): source._verify_unchanged()
        return VerifiedCandidate(manifest["version"],manifest["commit"],manifest_sha256,verified.evidence_hashes,manifest["p1r0_approval_sha256"]),p1r0
@dataclass(frozen=True,slots=True)
class ReleaseDecision: allowed:bool; failures:tuple[str,...]
def decide(candidate,p1r0,tag,installed_commit):
    failures=[]
    if candidate.version!="0.1.0-beta.1": failures.append("candidate_version")
    if not p1r0.allowed or p1r0.candidate_version!=candidate.version or p1r0.candidate_commit!=candidate.commit or p1r0.evidence_hashes!=candidate.evidence_hashes: failures.append("p1r0_binding")
    if not tag.valid or tag.commit!=candidate.commit: failures.append("signed_tag")
    if installed_commit!=candidate.commit: failures.append("accepted_install_commit")
    return ReleaseDecision(not failures,tuple(failures))

def merge_verified_draft_assets(api_rows,verified_assets):
    expected={"release-candidate.json","SHA256SUMS",*REQUIRED_ROLES}
    if set(verified_assets)!=expected or not isinstance(api_rows,list):
        raise ValueError("draft asset inventory is not exact")
    by_name={}; ids=set()
    for item in api_rows:
        if (not isinstance(item,dict) or set(item)!={"id","name","size","digest"}
            or not isinstance(item["id"],int) or item["id"]<=0
            or not isinstance(item["name"],str) or Path(item["name"]).name!=item["name"]
            or not isinstance(item["size"],int) or item["size"]<0
            or not isinstance(item["digest"],str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}",item["digest"]) is None
            or item["name"] in by_name or item["id"] in ids):
            raise ValueError("draft asset API inventory is invalid")
        by_name[item["name"]]=item; ids.add(item["id"])
    merged={}
    for key,verified in verified_assets.items():
        if (not isinstance(verified,dict) or set(verified)!={"name","size","sha256"}
            or not isinstance(verified["name"],str)
            or Path(verified["name"]).name!=verified["name"]
            or not isinstance(verified["size"],int) or verified["size"]<0
            or re.fullmatch(r"[0-9a-f]{64}",verified["sha256"]) is None):
            raise ValueError("draft asset frozen inventory is invalid")
        api=by_name.get(verified["name"])
        if (api is None or api["size"]!=verified["size"]
            or api["digest"]!="sha256:"+verified["sha256"]):
            raise ValueError("draft asset download/API mismatch")
        merged[key]={"id":api["id"],**verified}
    verified_names=[item["name"] for item in verified_assets.values()]
    if set(by_name)!=set(verified_names) or len(set(verified_names))!=len(verified_names):
        raise ValueError("draft asset inventory is not exact")
    return merged

def record_verified_draft(authorization,draft_release_id,draft_tag,hashes,asset_inventory,signer,now):
    if (authorization.protected.purpose!="publication"
        or authorization.payload.get("decision")!="authorized_for_manual_publication"):
        raise ValueError("invalid publication authorization")
    if set(hashes)!=REQUIRED_ROLES or any(re.fullmatch(r"[0-9a-f]{64}",value) is None for value in hashes.values()):
        raise ValueError("draft artifact hashes are not exact")
    expected_assets={"release-candidate.json","SHA256SUMS",*REQUIRED_ROLES}
    if (not isinstance(draft_release_id,int) or draft_release_id<=0
        or draft_tag!="v"+authorization.payload["version"]
        or set(asset_inventory)!=expected_assets):
        raise ValueError("draft release identity is not exact")
    ids=[]; names=[]
    for key,item in asset_inventory.items():
        if (set(item)!={"id","name","size","sha256"}
            or not isinstance(item["id"],int) or item["id"]<=0
            or not isinstance(item["size"],int) or item["size"]<0
            or not isinstance(item["name"],str) or Path(item["name"]).name!=item["name"]
            or re.fullmatch(r"[0-9a-f]{64}",item["sha256"]) is None):
            raise ValueError("draft asset inventory is invalid")
        ids.append(item["id"]); names.append(item["name"])
        if key in {"release-candidate.json","SHA256SUMS"} and item["name"]!=key:
            raise ValueError("draft control asset name mismatch")
        if key in REQUIRED_ROLES and item["sha256"]!=hashes[key]:
            raise ValueError("draft asset digest mismatch")
    if len(set(ids))!=len(ids) or len(set(names))!=len(names):
        raise ValueError("draft asset IDs/names are not unique")
    if asset_inventory["release-candidate.json"]["sha256"]!=authorization.payload["candidate_manifest_sha256"]:
        raise ValueError("draft candidate manifest mismatch")
    return signer.sign({
        "schema_version":"tuntun.publication-record.v1",
        "decision":"draft_assets_verified",
        "authorization_sha256":signed_envelope_sha256(authorization),
        "candidate_manifest_sha256":authorization.payload["candidate_manifest_sha256"],
        "version":authorization.payload["version"],"commit":authorization.payload["commit"],
        "draft_release_id":draft_release_id,"draft_tag":draft_tag,
        "assets":dict(sorted(asset_inventory.items())),
        "artifact_hashes":dict(sorted(hashes.items())),
        "verified_at":now.isoformat(),
    })
```

```python
# scripts/verify_published_download.py
import argparse,json,os,re,tempfile
from contextlib import ExitStack
from pathlib import Path,PurePosixPath
import jsonschema
from scripts.assemble_release import FrozenInput,MAX_CONTROL_BYTES,REQUIRED_ROLES,REACHY_PACKAGE_ROLES,digest,read_frozen_bytes,verify_reachy_package_set
from scripts.control_files import parse_control_json,parse_control_json_bytes

def _canonical_candidate_path(value):
    if (not isinstance(value,str) or not value or "\\" in value
        or any(ord(char)<32 or ord(char)==127 for char in value)):
        raise ValueError("candidate artifact path invalid")
    path=PurePosixPath(value)
    if (path.is_absolute() or not path.parts
        or any(part in ("",".","..") for part in path.parts)):
        raise ValueError("candidate artifact path escapes candidate")
    if path.as_posix()!=value or path.name in ("release-candidate.json","SHA256SUMS"):
        raise ValueError("candidate artifact path invalid")
    return path

def _parse_sums(raw):
    result={}
    for line in raw.decode("utf-8").splitlines():
        digest,separator,name=line.partition("  ")
        if separator!="  " or re.fullmatch(r"[0-9a-f]{64}",digest) is None:
            raise ValueError("SHA256SUMS invalid")
        _canonical_candidate_path(name)
        if name in result: raise ValueError("SHA256SUMS duplicate entry")
        result[name]=digest
    return result

def _verify_published_download(root,candidate_schema,expected_candidate_manifest_sha256):
    supplied_root=Path(root)
    if supplied_root.is_symlink() or not supplied_root.is_dir(): raise ValueError("published Reachy directory")
    root=supplied_root.resolve()
    manifest_path=root/"release-candidate.json"; sums_path=root/"SHA256SUMS"
    with ExitStack() as stack:
        manifest_source=stack.enter_context(FrozenInput(manifest_path))
        sums_source=stack.enter_context(FrozenInput(sums_path))
        manifest_bytes=manifest_source.bytes(MAX_CONTROL_BYTES)
        manifest_digest=manifest_source.digest()
        if manifest_digest!=expected_candidate_manifest_sha256:
            raise ValueError("candidate manifest mismatch")
        manifest=parse_control_json_bytes(
            manifest_bytes,max_bytes=1_048_576,require_canonical=True,
        )
        jsonschema.Draft202012Validator(
            candidate_schema,format_checker=jsonschema.FormatChecker(),
        ).validate(manifest)
        by_role={item["role"]:item for item in manifest["artifacts"]}
        if set(by_role)!=REQUIRED_ROLES or len(by_role)!=len(manifest["artifacts"]):
            raise ValueError("candidate artifact roles are not exact and unique")
        by_path={}; by_basename={}
        for item in manifest["artifacts"]:
            candidate_path=_canonical_candidate_path(item["path"])
            if item["path"] in by_path: raise ValueError("candidate artifact path duplicate")
            if candidate_path.name in by_basename:
                raise ValueError("candidate artifact basename duplicate")
            by_path[item["path"]]=item; by_basename[candidate_path.name]=item
        sums=_parse_sums(sums_source.bytes(MAX_CONTROL_BYTES))
        if set(sums)!=set(by_path): raise ValueError("SHA256SUMS artifact set mismatch")
        expected_names={"release-candidate.json","SHA256SUMS",*by_basename}
        actual_names=set()
        for path in root.iterdir():
            if path.name not in expected_names:
                raise ValueError("published artifact set mismatch")
            actual_names.add(path.name)
        if actual_names!=expected_names: raise ValueError("published artifact set mismatch")
        sources={
            name:stack.enter_context(FrozenInput(root/name))
            for name in by_basename
        }
        with tempfile.TemporaryDirectory(prefix="tuntun-published-verify-") as temporary:
            snapshot=Path(temporary); os.chmod(snapshot,0o700)
            manifest_source.copy_to(snapshot/"release-candidate.json")
            sums_source.copy_to(snapshot/"SHA256SUMS")
            for name,source in sources.items(): source.copy_to(snapshot/name)
            downloaded={}; hashes={}
            assets={
                "release-candidate.json":{
                    "name":"release-candidate.json","size":manifest_source.identity[2],
                    "sha256":manifest_digest,
                },
                "SHA256SUMS":{
                    "name":"SHA256SUMS","size":sums_source.identity[2],
                    "sha256":sums_source.digest(),
                },
            }
            for role in sorted(REQUIRED_ROLES):
                item=by_role[role]; basename=PurePosixPath(item["path"]).name
                path=snapshot/basename; artifact_digest=digest(path)
                if (path.name!=basename or artifact_digest!=item["sha256"]
                    or path.stat(follow_symlinks=False).st_size!=item["size"]):
                    raise ValueError("published artifact mismatch")
                if sums[item["path"]]!=artifact_digest: raise ValueError("SHA256SUMS mismatch")
                downloaded[role]=path; hashes[role]=artifact_digest
                assets[role]={"name":basename,"size":item["size"],"sha256":artifact_digest}
            reachy_downloaded={role:downloaded[role] for role in REACHY_PACKAGE_ROLES}
            try: verify_reachy_package_set(reachy_downloaded)
            except RuntimeError as error: raise ValueError("published Reachy archive verification") from error
            manifest_source._verify_unchanged(); sums_source._verify_unchanged()
            for source in sources.values(): source._verify_unchanged()
            return hashes,assets

def verify_published_download(root,candidate_schema,expected_candidate_manifest_sha256):
    return _verify_published_download(
        root,candidate_schema,expected_candidate_manifest_sha256,
    )[0]

def _write_exclusive_json(path,value):
    path=Path(path); data=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
    parent=os.open(
        path.parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0),
    )
    try:
        descriptor=os.open(
            path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),
            0o600,dir_fd=parent,
        )
        try:
            view=memoryview(data)
            while view:
                written=os.write(descriptor,view); view=view[written:]
            os.fsync(descriptor)
        finally: os.close(descriptor)
        os.fsync(parent)
    finally: os.close(parent)

def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,required=True)
    parser.add_argument("--candidate-schema",type=Path,required=True)
    parser.add_argument("--expected-candidate-manifest-sha256",required=True)
    parser.add_argument("--hashes-output",type=Path)
    parser.add_argument("--assets-output",type=Path)
    args=parser.parse_args(argv)
    result,assets=_verify_published_download(
        args.root,parse_control_json(
            args.candidate_schema,max_bytes=262_144,require_canonical=False,
        ),
        args.expected_candidate_manifest_sha256,
    )
    if args.hashes_output is not None: _write_exclusive_json(args.hashes_output,result)
    if args.assets_output is not None: _write_exclusive_json(args.assets_output,assets)
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
    return result

if __name__=="__main__": main()
```

```bash
# docs/operations/publish-release.md (manual owner shell; workflows never run this)
set -euo pipefail
tag=v0.1.0-beta.1
candidate=dist/release-candidate
authorization=var/release/publication-authorization.json
test "$(git rev-parse HEAD)" = "$(git rev-list -n 1 "$tag")"
test ! -e var/release/publication-receipt.json
mapfile -d '' assets < <(python3 - "$candidate" <<'PY'
import pathlib,sys
from scripts.control_files import parse_control_json
root=pathlib.Path(sys.argv[1]); manifest=parse_control_json(
    root/"release-candidate.json",max_bytes=1_048_576,require_canonical=True,
)
paths=[root/"release-candidate.json",root/"SHA256SUMS",*(root/item["path"] for item in manifest["artifacts"])]
for path in paths: sys.stdout.buffer.write(str(path).encode()+b"\0")
PY
)
gh release create "$tag" --draft --verify-tag \
  --title "Tuntun v0.1.0-beta.1 — Phase 1 preview" \
  --notes "Phase 1 preview only; Phase 2–6 and program C0/C1 are not included." \
  "${assets[@]}"
draft_id=$(gh api "repos/{owner}/{repo}/releases/tags/$tag" --jq 'select(.draft == true) | .id')
test -n "$draft_id"
fresh=$(mktemp -d); published=0
cleanup() {
  status=$?; trap - EXIT; rm -rf -- "$fresh"
  if [ "$status" -ne 0 ] && [ "$published" -eq 0 ]; then
    echo "Verification failed; draft remains private for diagnosis." >&2
  fi
  exit "$status"
}
trap cleanup EXIT HUP INT TERM
gh api "repos/{owner}/{repo}/releases/$draft_id/assets" --paginate \
  --jq 'sort_by(.id)|map({id,name,size,digest})' > "$fresh/assets-before.json"
gh release download "$tag" --dir "$fresh/download"
uv run python scripts/verify_published_download.py \
  --root "$fresh/download" \
  --candidate-schema release/schemas/release-candidate-v1.schema.json \
  --expected-candidate-manifest-sha256 "$(uv run python scripts/release_gate.py publication-field --authorization "$authorization" --field candidate_manifest_sha256)" \
  --hashes-output "$fresh/verified-hashes.json" \
  --assets-output "$fresh/verified-assets.json"
uv run python scripts/release_gate.py merge-draft-assets \
  --api-inventory "$fresh/assets-before.json" \
  --verified-assets "$fresh/verified-assets.json" \
  --output "$fresh/merged-assets.json"
uv run python scripts/release_gate.py record-verified-draft \
  --authorization "$authorization" --draft-release-id "$draft_id" --draft-tag "$tag" \
  --asset-inventory "$fresh/merged-assets.json" --verified-hashes "$fresh/verified-hashes.json" \
  --publication-signer-service tuntun.release.publication \
  --output var/release/publication-receipt.json
uv run python scripts/release_gate.py verify-publication-record \
  --authorization "$authorization" --record var/release/publication-receipt.json \
  --schema release/schemas/publication-record-v1.schema.json
uv run python scripts/verify_private_data.py "$fresh/download" var/release/publication-receipt.json
gh api "repos/{owner}/{repo}/releases/$draft_id/assets" --paginate \
  --jq 'sort_by(.id)|map({id,name,size,digest})' > "$fresh/assets-after.json"
cmp "$fresh/assets-before.json" "$fresh/assets-after.json"
test "$(gh api "repos/{owner}/{repo}/releases/$draft_id" --jq '.draft')" = true
gh release edit "$tag" --draft=false
published=1
trap - EXIT HUP INT TERM
rm -rf -- "$fresh"
```

On any verification or receipt failure the trap removes only the fresh download and deliberately leaves the GitHub release as a private draft. After diagnosis, the owner either reruns verification against that unchanged draft or deletes it explicitly with `gh release delete "$tag" --yes` and restarts from draft creation. The frozen download verifier exclusively creates canonical hashes and verified-asset inventories; `merge-draft-assets` requires the API inventory to contain exactly `release-candidate.json`, `SHA256SUMS`, and every canonical manifest basename once, rejects a null/non-`sha256:` digest or duplicate/extra ID/name, and requires every GitHub digest and size to equal the frozen downloaded bytes. `record-verified-draft` then binds that merged inventory, every asset ID, and the authorization-envelope hash and exclusively writes/fsyncs the signed receipt before publication. A byte-identical second API inventory comparison immediately precedes the sole `--draft=false` transition.

`release/authorized-signers-v1.json` is schema-validated and records exact tag fingerprints, fixed `algorithm="OpenPGP"`, purpose `release_tag`, approval/not-before/not-after, and nullable revocation; verification rejects absent, expired, future, wrong-algorithm/purpose, or revoked records. `release/evidence-schema-paths-v1.json` is separately schema-validated and names every Task 5–9 payload schema; the CLI requires both `--evidence-schema-paths` and `--evidence-schema-paths-schema`, resolves paths beneath the repository, and refuses missing/extra roles or schema hash drift. `verify_candidate` reruns the one shared verifier, checks every package role against the signed security inventory, validates the frozen acceptance components, reopens exact soak-bundle child hashes, verifies reviews/guardian consent, and verifies the P1R0 envelope physically contained in the candidate. It also requires all three Reachy roles in one directory, rechecks the checksum-to-archive binding, and invokes the closed-inventory verifier before publication authorization. No external P1R0 path is accepted. The CLI reconstructs the exact `release.p1r0` binding, confirms the installed commit, and signs `authorized_for_manual_publication` with the distinct `publication` evidence key; that strict payload contains version, commit, tag/fingerprint, candidate-manifest hash, contained-P1R0 hash, all four evidence hashes, installed commit, and authorization time. The draft-download harness pins that candidate-manifest hash, opens one nofollow identity-frozen descriptor for every downloaded file, copies those descriptors into a private verification snapshot, requires the root file and `SHA256SUMS` sets to be exact and duplicate-free, verifies every size/hash/sum, and only then invokes the closed Reachy triple verifier against the snapshot. Replace/grow/truncate races on controls or any role block. The separately signed `draft_assets_verified` receipt binds the authorization, draft release ID/tag, exact asset IDs/API digests, and all role hashes; only its durable verification permits the manual draft-to-public transition. Workflow remains manual build/attest/artifact only.

- [ ] **Step 4: Run the green pre-publication implementation gate**

Run: `uv run pytest tests/ci/test_workflow_policy.py tests/release/test_tag_verification.py tests/release/test_release_gate.py tests/release/test_published_download.py tests/release/test_no_auto_publication.py -q`

Expected: PASS for tag lifecycle, replace-and-rehash artifact attacks, schema registry, semantic evidence, exact contained P1R0, every-role mocked published-download verification including closed root/sum sets and the adjacent Reachy triple, and no automatic publication. No real tag or publication record is created before Task 10 is committed.

- [ ] **Step 5: Commit exact paths before any production evidence ceremony**

```bash
git status --short
git add release/authorized-signers-v1.json release/schemas/authorized-signers-v1.schema.json release/evidence-schema-paths-v1.json release/schemas/evidence-schema-paths-v1.schema.json release/schemas/publication-record-v1.schema.json scripts/verify_tag.py scripts/release_gate.py scripts/verify_published_download.py .github/workflows/release.yml docs/operations/publish-release.md tests/release/test_tag_verification.py tests/release/test_release_gate.py tests/release/test_published_download.py tests/release/test_no_auto_publication.py
git diff --cached --name-only
git diff --cached --check
git diff --cached
git commit -m "release: require verified owner-controlled publication"
```

## Frozen-Commit Evidence Ceremony and P1R1 Manual Publication Checkpoint

Tasks 5–10 commit implementation and synthetic fixtures only. After Task 10, freeze one clean commit and generate all official evidence below without changing tracked files. All outputs live under ignored `var/` or `dist/`; every writer emits canonical JSON bytes. If any source, policy, schema, test, documentation, or release script changes, commit it, remove any unpublished tag, discard the candidate/evidence for the old commit, and restart this entire ceremony. Old elapsed evidence may not be relabeled or merely re-signed for a new commit.

### Ceremony A: qualify exact bytes, commission a clean target, then collect evidence

For the initial household release, this ceremony runs on the independently owner-approved opaque Core inventory target, currently verified as Darwin `arm64`, during the declared maintenance window above. The trusted preflight must authenticate that approval and match the current target before architecture compatibility is considered. Before the first command, verify the encrypted backup and recovery key, stop ordinary office use, and record the prior managed-runtime state (normally absent on first install). After qualification, preserve the exact signed role bytes outside the Tuntun managed runtime roots before the clean-target check. A later upgrade that cannot prove a clean evidence target on this same Mac remains an upgrade candidate only; it cannot mint fresh clean-install evidence from a VM or CI runner. Hosted or physical Intel macOS evidence remains a supported-distribution row until the owner supplies a new trusted target approval and repeats the household real-host probes for an Intel target.

```bash
test -z "$(git status --porcelain)"
test -z "$(git tag --list v0.1.0-beta.1)"
make bootstrap
make check
make security-scan model-manifest-check sbom license-check listener-scan egress-scan fuzz
SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" uv run python scripts/qualify_release_artifacts.py --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --artifact-output var/release/frozen-artifacts --role-paths-output var/release/role-paths.json --signer-service tuntun.release.qualification --output var/release/qualification-manifest.json
uv run tuntunctl qualification target-status --require-clean-uncommissioned
uv run python scripts/commission_release_target.py --qualification-manifest var/release/qualification-manifest.json --require-clean-uncommissioned --signer-service tuntun.release.target-commissioning --output var/release/target-commissioning.json
uv run tuntunctl qualification install-evidence-pending --local-only --qualification-manifest var/release/qualification-manifest.json --commissioning-receipt var/release/target-commissioning.json --role-paths var/release/role-paths.json
uv run tuntunctl qualification verify-evidence-pending --qualification-manifest var/release/qualification-manifest.json --commissioning-receipt var/release/target-commissioning.json
uv run python scripts/collect_release_evidence.py --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --qualification-manifest var/release/qualification-manifest.json --commissioning-receipt var/release/target-commissioning.json --role-paths var/release/role-paths.json --signer-service tuntun.release.security --output var/release/security-evidence.json
uv run python scripts/verify_release_evidence.py var/release/security-evidence.json --schema security/schemas/security-evidence-v1.schema.json --signer-registry security/evidence-signers-v1.json --signer-registry-schema security/schemas/evidence-signers-v1.schema.json --expected-purpose security --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)"
```

Expected: the worktree is clean, no beta tag exists, and qualification reproducibly builds the exact distributable bytes twice. The independently probed target has no current runtime before commissioning; the owner-signed commissioning receipt binds that qualification hash; the local-only evidence-pending install uses those exact bytes. Only then do runtime, LAN, and outer collectors run. Security collection performs no build and its inventory names the same qualification manifest and every qualified role/hash/size. Omitted commissioning/install, wrong bytes, or any later rebuild fails closed.

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
SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" uv run python scripts/assemble_release.py --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --qualification-manifest var/release/qualification-manifest.json --role-paths var/release/role-paths.json --security var/release/security-evidence.json --acceptance var/acceptance/synthetic.json --soak-bundle var/acceptance/soak-bundle.json --trial var/acceptance/family-trial.json --p1r0 var/acceptance/p1r0-approval.json --evidence-schema-paths release/evidence-schema-paths-v1.json --evidence-schema-paths-schema release/schemas/evidence-schema-paths-v1.schema.json --signer-registry security/evidence-signers-v1.json --signer-registry-schema security/schemas/evidence-signers-v1.schema.json --output dist/release-candidate
shasum -a 256 -c dist/release-candidate/SHA256SUMS
uv run python scripts/verify_private_data.py . dist/release-candidate
TUNTUN_REACHY_PACKAGE=dist/release-candidate/artifacts/reachy/tuntun-edge-0.1.0-beta.1.tar.gz TUNTUN_ALLOW_REACHY_HARDWARE=1 uv run pytest -m reachy_hardware tests/hardware/test_edge_package.py -q
uv run tuntunctl update apply --candidate dist/release-candidate --require-p1r0
uv run tuntunctl service status --field commit
test -z "$(git status --porcelain)"
git tag -s v0.1.0-beta.1 -m "Tuntun v0.1.0-beta.1"
uv run python scripts/verify_tag.py v0.1.0-beta.1 --version 0.1.0-beta.1 --commit "$(git rev-parse HEAD)" --signers release/authorized-signers-v1.json --signers-schema release/schemas/authorized-signers-v1.schema.json
uv run python scripts/release_gate.py --candidate dist/release-candidate/release-candidate.json --candidate-schema release/schemas/release-candidate-v1.schema.json --evidence-schema-paths release/evidence-schema-paths-v1.json --evidence-schema-paths-schema release/schemas/evidence-schema-paths-v1.schema.json --signer-registry security/evidence-signers-v1.json --signer-registry-schema security/schemas/evidence-signers-v1.schema.json --tag v0.1.0-beta.1 --tag-signers release/authorized-signers-v1.json --tag-signers-schema release/schemas/authorized-signers-v1.schema.json --installed-commit "$(uv run tuntunctl service status --field commit)" --publication-signer-service tuntun.release.publication --output var/release/publication-authorization.json
uv run python scripts/verify_private_data.py dist/release-candidate var/release/publication-authorization.json
```

Expected: P1R0 follows the shared semantic verifier and exact passkey binding; assembly copies the same P1R0 envelope and fixes its hash in the candidate. Assembly does not rebuild: it consumes the exact qualification envelope and byte-identical qualified role paths already used for target evidence, plus the later evidence files. Every packaged byte matches qualification, signed security, and frozen acceptance evidence; the installed commit, signed tag, candidate, P1R0, and publication record all name the same frozen commit. Nothing is published automatically.

The owner may then execute `docs/operations/publish-release.md`; no workflow has publication authority. The runbook first creates a private GitHub draft with every candidate asset, then downloads the entire draft into a fresh directory. Its frozen-download harness rejects any extra, missing, duplicate, escaping, renamed, moved, substituted, or concurrently changed manifest/sum/download entry, matches every artifact's basename, size, and hash to both the candidate manifest and its exact `SHA256SUMS` entry, and invokes `verify_reachy_archive.py` on the adjacent Reachy triple. It persists and reopens a signed `tuntun.publication-record.v1` binding the authorization, draft ID/tag, asset IDs/API SHA-256 digests, and all-role verified hashes, rechecks that the draft asset inventory did not change, and only then runs the separate `gh release edit ... --draft=false` command. Failure leaves a recoverable private draft and never exposes unverified bytes. Task 10's all-role mocked-download/race tests and runbook-order policy test exercise this boundary; `test_no_auto_publication.py` still proves automatic publication is absent. Checkpoint P1R1 requires reproducible published bytes, a no-secret simulator, clean scans, exact signer lifecycles/tag/commit/evidence/P1R0/artifact hashes, verified draft re-download and receipt, and the private installation remaining on the approved commit or a separately approved later upgrade. The release title, README, manifest, and publication record must all label it a Phase 1 preview and explicitly state that Phase 2–6 support and the program C0/C1 gates are not included.

## Execution Handoff

Execute and commit Tasks 1–10 sequentially using only synthetic fixtures for Tasks 5–10. Then freeze the clean commit and execute Ceremonies A–E in order; the two eight-hour runs and four-day trial occur exactly once against that frozen commit. Stop for the signed reviews, latency deviation if needed, P1R0 passkey, tag signing, and manual publication. Automatic publication is forbidden.
