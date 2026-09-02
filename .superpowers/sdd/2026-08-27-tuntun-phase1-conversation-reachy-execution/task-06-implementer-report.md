# Task 06 Implementer Report — Master WP10 Retry Owner and OpenAI Adapters

Branch: `feat/openai-retry-owner`

Worktree:
`/Users/smishra9/Applications/funProj/Projec_TunTun/Project_TunTun/.worktrees/openai-retry-owner`

Base SHA: `7f4d7061766c792db9367490bb379e4401cf717b`

## Implementation summary

Implemented Task 06's retry owner and OpenAI adapter surface with the current
Task04 privacy/wire/gateway seams and Task05 budget/usage evidence.

- Added the public frozen `OfflineSynthesisRequest` contract and contract
  coverage, and regenerated contract fixtures, JSON schema, and Admin OpenAPI.
- Promoted `BudgetAccountingContext` into the public contracts package and added
  `BudgetPort.require_accounting_context` so production and fakes share the
  typed gateway accounting seam.
- Added `AttemptRunner` as the per-attempt owner for reservation, route
  authorization, retry decisions, cancellation cleanup, stream terminal ordering,
  budget settlement/release, and synchronous turn completion.
- Added strict assistant output validation with `AssistantTurn`, provider intent
  DTOs, proposal mapping helpers, and action execution parameter extraction.
- Added provider response receipt recording/verification against the
  foundation-owned `provider_response_receipts` table with exact route scope,
  exact response HMAC, exact provider usage receipt id, succeeded/finished call
  requirements, and same-UoW audit/CAS/insert ordering.
- Added `OutputPipeline` validation and TTS synthesis gating that requires a
  verified provider-response receipt before downstream output, sanitizes before
  segmentation, re-authorizes per TTS segment, constructs a fresh validated
  `AuthorizedSynthesisRequest`, and sends TTS only through `AttemptRunner.stream`.
- Added OpenAI client construction pinned to no telemetry/no ambient network
  state: `AsyncHTTPTransport(retries=0, limits=httpx.Limits(4, 2))`,
  `AsyncClient(trust_env=False, follow_redirects=False, event_hooks={...})`,
  and SDK `max_retries=0`.
- Added OpenAI Responses, transcription, and TTS adapters. Reasoning request
  committed bytes and SDK kwargs are both built solely through
  `build_openai_reasoning_wire_request` with `AssistantTurn.model_json_schema()`.
- Added macOS offline TTS fallback using an allowlisted `say` voice and
  `/usr/bin/afconvert`; it validates exact WAV PCM/mono/24kHz/byte-rate/
  block-align/16-bit/nonempty-even-data structure and returns raw PCM bytes.
- Added dependency pins `openai==2.54.0` and exact retained `httpx==0.28.1`.

## Files changed

Contracts and generated artifacts:

- `packages/contracts/src/tuntun_contracts/provider.py`
- `packages/contracts/src/tuntun_contracts/speech.py`
- `packages/contracts/src/tuntun_contracts/budget.py`
- `packages/contracts/src/tuntun_contracts/ports.py`
- `packages/contracts/src/tuntun_contracts/__init__.py`
- `packages/contracts/fixtures/v1/budget.json`
- `packages/contracts/fixtures/v1/speech.json`
- `packages/contracts/schema/v1/contracts.schema.json`
- `packages/contracts/openapi/admin-v1.yaml`
- `scripts/contract_fixture_builders.py`
- `tests/contract/test_v1_types_and_ports.py`
- `tests/contract/test_v1_fixtures.py`

Core services and adapters:

- `apps/core/src/tuntun_core/services/providers/attempts.py`
- `apps/core/src/tuntun_core/services/providers/output_validator.py`
- `apps/core/src/tuntun_core/services/providers/response_receipts.py`
- `apps/core/src/tuntun_core/services/providers/output_pipeline.py`
- `apps/core/src/tuntun_core/services/providers/tts_activation.py`
- `apps/core/src/tuntun_core/adapters/openai/__init__.py`
- `apps/core/src/tuntun_core/adapters/openai/client.py`
- `apps/core/src/tuntun_core/adapters/openai/errors.py`
- `apps/core/src/tuntun_core/adapters/openai/sol.py`
- `apps/core/src/tuntun_core/adapters/openai/transcribe.py`
- `apps/core/src/tuntun_core/adapters/openai/tts.py`
- `apps/core/src/tuntun_core/adapters/tts/__init__.py`
- `apps/core/src/tuntun_core/adapters/tts/macos_say.py`
- `apps/core/src/tuntun_core/services/budget/guard.py`
- `packages/testing/src/tuntun_testing/fake_providers.py`
- `tests/fixtures/provider_egress.py`

Task 06 tests and eval fixtures:

- `tests/integration/providers/test_attempt_runner.py`
- `tests/integration/providers/test_response_receipts.py`
- `tests/integration/providers/test_output_pipeline.py`
- `tests/integration/providers/test_tts_activation.py`
- `tests/unit/providers/test_output_validator.py`
- `tests/unit/providers/test_openai_error_translation.py`
- `tests/contract/openai/conftest.py`
- `tests/contract/openai/test_authorized_signatures.py`
- `tests/contract/openai/test_responses_request.py`
- `tests/contract/openai/test_transcribe_request.py`
- `tests/contract/openai/test_tts_request.py`
- `tests/contract/tts/test_macos_say_offline.py`
- `tests/evals/tts/fixtures/en-hi-hinglish-v1.json`
- `tests/evals/tts/test_bilingual_quality.py`
- `tests/security/test_no_external_telemetry.py`
- `tests/security/test_openai_local_non_retention.py`

Dependencies:

- `apps/core/pyproject.toml`
- `uv.lock`

Report:

- `.superpowers/sdd/2026-08-27-tuntun-phase1-conversation-reachy-execution/task-06-implementer-report.md`

## RED evidence

Initial focused RED command with the required task environment:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run pytest \
  tests/integration/providers/test_attempt_runner.py \
  tests/integration/providers/test_response_receipts.py \
  tests/security/test_no_external_telemetry.py \
  tests/unit/providers/test_openai_error_translation.py \
  tests/unit/providers/test_output_validator.py \
  tests/integration/providers/test_output_pipeline.py \
  tests/contract/openai/test_authorized_signatures.py \
  tests/contract/openai/test_responses_request.py \
  tests/contract/openai/test_transcribe_request.py \
  tests/contract/openai/test_tts_request.py \
  tests/contract/tts/test_macos_say_offline.py \
  tests/integration/providers/test_tts_activation.py \
  tests/evals/tts/test_bilingual_quality.py \
  tests/security/test_openai_local_non_retention.py \
  -q
```

Expected RED result before implementation:

```text
ImportError while loading conftest ...
ModuleNotFoundError: No module named 'tuntun_core.adapters.openai.sol'
```

Earlier scaffold checks also failed on the intentionally missing Task06 modules
such as `tuntun_core.services.providers.attempts`,
`tuntun_core.services.providers.output_validator`, and
`tuntun_core.adapters.openai.client`.

Dependency resolution attempt:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv add --project apps/core openai==2.54.0 httpx==0.28.1
```

Sandbox result: DNS/network resolution failed. I reran the same dependency
mutation with normal sandbox escalation, keeping the exact requested versions.
Result: success; `apps/core/pyproject.toml` and `uv.lock` updated.

## GREEN evidence

Focused Task06 suite:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run pytest \
  tests/integration/providers/test_attempt_runner.py \
  tests/integration/providers/test_output_pipeline.py \
  tests/integration/providers/test_response_receipts.py \
  tests/integration/providers/test_tts_activation.py \
  tests/unit/providers/test_output_validator.py \
  tests/unit/providers/test_openai_error_translation.py \
  tests/contract/openai \
  tests/contract/tts/test_macos_say_offline.py \
  tests/evals/tts/test_bilingual_quality.py \
  tests/security/test_openai_local_non_retention.py \
  tests/security/test_no_external_telemetry.py \
  -q
```

Result:

```text
127 passed, 1 warning in 3.70s
```

The warning was:

```text
PytestAssertRewriteWarning: Module already imported so cannot be rewritten;
tests.fixtures.provider_routes
```

Contract fixture/type focused suite:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run pytest tests/contract/test_v1_types_and_ports.py \
  tests/contract/test_v1_fixtures.py -q --tb=short
```

Result:

```text
102 passed in 11.63s
```

Affected Task03-Task05/provider/budget regression gate:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run pytest \
  tests/security/test_log_redaction.py \
  tests/security/test_provider_review_freshness.py \
  tests/security/test_provider_boundary.py \
  tests/unit/budget \
  tests/integration/budget \
  tests/contract/test_budget_port.py \
  tests/contract/test_provider_route_binding.py \
  tests/unit/providers \
  tests/integration/providers \
  -q
```

Result:

```text
694 passed, 1 warning in 33.11s
```

The warning was the same pytest plugin rewrite warning for
`tests.fixtures.provider_routes`.

Full non-live suite attempt:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run pytest -m 'not live_cloud and not reachy_hardware' -q
```

Result:

```text
52 failed, 3162 passed, 8 skipped in 409.66s
```

Triage of the failures:

- `tests/ci/test_web_command_contract.py`: local admin Node prerequisites are
  absent, including `@playwright/test`/`eslint`.
- Socket-parameter tests in the private-data scanner and SQLCipher suites:
  macOS sandbox denies AF_UNIX socket binding with `PermissionError: [Errno 1]
  Operation not permitted`.
- Scenario guard/CLI tests: the child runtime's no-symlink open policy rejects
  the mandated temporary env layout because `.venv` is a symlink to
  `/private/tmp/tuntun-task06-venv`. I confirmed the scenario build itself works
  in-process; the failure is the child runtime layout check, not ProviderResponse
  or scenario content semantics.

Full non-live sweep excluding only those triaged environment-only surfaces:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python -m pytest -m 'not live_cloud and not reachy_hardware' \
  --ignore=tests/ci/test_web_command_contract.py \
  --ignore=tests/security/test_scenario_guard.py \
  --ignore=tests/unit/testing/test_scenario_cli.py \
  -k 'not socket' \
  -q
```

Result:

```text
3032 passed, 3 skipped, 12 deselected in 254.05s (0:04:14)
```

## Static and generation verification

Python compile sanity check:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python -m py_compile \
  packages/contracts/src/tuntun_contracts/provider.py \
  packages/contracts/src/tuntun_contracts/speech.py \
  apps/core/src/tuntun_core/adapters/openai/client.py \
  apps/core/src/tuntun_core/adapters/openai/errors.py \
  apps/core/src/tuntun_core/adapters/openai/sol.py \
  apps/core/src/tuntun_core/adapters/openai/transcribe.py \
  apps/core/src/tuntun_core/adapters/openai/tts.py \
  apps/core/src/tuntun_core/adapters/tts/macos_say.py \
  apps/core/src/tuntun_core/services/providers/attempts.py \
  apps/core/src/tuntun_core/services/providers/output_validator.py \
  apps/core/src/tuntun_core/services/providers/output_pipeline.py \
  apps/core/src/tuntun_core/services/providers/response_receipts.py \
  apps/core/src/tuntun_core/services/providers/tts_activation.py \
  packages/testing/src/tuntun_testing/fake_providers.py
```

Result: exit 0.

Ruff:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run ruff check \
  packages/contracts/src/tuntun_contracts/provider.py \
  packages/contracts/src/tuntun_contracts/speech.py \
  packages/contracts/src/tuntun_contracts/budget.py \
  packages/contracts/src/tuntun_contracts/ports.py \
  apps/core/src/tuntun_core/adapters/openai \
  apps/core/src/tuntun_core/adapters/tts \
  apps/core/src/tuntun_core/services/providers \
  packages/testing/src/tuntun_testing/fake_providers.py \
  tests/fixtures/provider_egress.py \
  tests/integration/providers/test_response_receipts.py \
  tests/integration/providers/test_attempt_runner.py \
  tests/integration/providers/test_output_pipeline.py \
  tests/integration/providers/test_tts_activation.py \
  tests/unit/providers/test_output_validator.py \
  tests/unit/providers/test_openai_error_translation.py \
  tests/contract/openai \
  tests/contract/tts/test_macos_say_offline.py \
  tests/evals/tts/test_bilingual_quality.py \
  tests/security/test_openai_local_non_retention.py \
  tests/security/test_no_external_telemetry.py
```

Result:

```text
All checks passed!
```

Mypy:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run mypy \
  packages/contracts/src/tuntun_contracts/provider.py \
  packages/contracts/src/tuntun_contracts/speech.py \
  packages/contracts/src/tuntun_contracts/budget.py \
  packages/contracts/src/tuntun_contracts/ports.py \
  apps/core/src/tuntun_core/adapters/openai \
  apps/core/src/tuntun_core/adapters/tts \
  apps/core/src/tuntun_core/services/providers \
  packages/testing/src/tuntun_testing/fake_providers.py
```

Result:

```text
Success: no issues found in 28 source files
```

Contract fixtures:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python scripts/generate_contract_fixtures.py --check
```

Result: exit 0.

JSON schemas:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python scripts/generate_schemas.py --check
```

Result: exit 0.

Admin OpenAPI:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python scripts/generate_openapi.py --check
```

Result: exit 0.

Lock verification:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv lock --check
```

Result:

```text
Resolved 71 packages in 45ms
```

Whitespace diff check:

```bash
git diff --check
```

Result: exit 0.

## Self-review

Spec completeness:

- Confirmed the new public contract is `OfflineSynthesisRequest`; no private dict
  substitute is used for offline TTS.
- Confirmed `tests/contract/openai/test_authorized_signatures.py` is included.
- Confirmed `provider_response_receipts` uses the existing foundation table only;
  no migration or shadow table was added.
- Confirmed `build_openai_reasoning_wire_request` constructs both committed
  bytes and exact SDK kwargs for reasoning. `OpenAISol` passes
  `AssistantTurn.model_json_schema()` into that builder.
- Confirmed OpenAI adapters do not register search tools.
- Confirmed `ProviderResponse` remains a bounded transport envelope; POC/scenario
  prose consumers are not globally migrated in Task06.

Cancellation and terminal ordering:

- `AttemptRunner.run` and `AttemptRunner.stream` shield release/settle paths so
  cancellation does not leave a claimed attempt open.
- Every attempt gets a new reservation, turn-attempt reservation tracking, and
  route authorization.
- Unsent failures release; sent/unknown failures settle. Stream retries only
  before the first payload when the failure is retryable and definitely unsent.
- Stream terminal chunks are yielded only after gateway usage finalization
  inside the adapter and budget settlement plus synchronous turn completion in
  `AttemptRunner.stream`.
- Empty final semantics are enforced by the attempt owner/adapter boundary, not
  by the global `SpeechChunk` DTO.

Receipt/settlement races:

- Provider response receipt recording verifies route household/subject/session/
  turn/provider/model scope separately from the foundation FK.
- It parses persisted `provider_usage_json` through `BudgetEvidenceService` and
  compares the resulting `receipt_id` to the exact
  `ProviderResponse.provider_usage_receipt_id`.
- Succeeded call requirements include `outcome='succeeded'`,
  `transport_phase='finished'`, `finished_at IS NOT NULL`, and the complete
  provider usage receipt material.
- CAS of the provider call response HMAC, audit append, and child receipt insert
  share one UoW.
- Concurrent replay validates the existing receipt's own HMAC, route scope, and
  response commitment without requiring a fresh receipt id/produced timestamp.

Content leakage and local validation:

- STT buffers only after validating each chunk is exact `bytes` and fits the
  remaining capacity, so the 8 MiB cap is never transiently exceeded.
- STT zeroes and clears its local audio buffer in a `finally` block.
- Reasoning and TTS adapters translate only SDK/network exceptions at the
  invocation boundary; local validation errors remain local validation errors.
- OpenAI client disables ambient proxies, redirects, SDK retries, transport
  retries, and request/response hooks.
- macOS offline TTS uses explicit argv only, an allowlisted voice map, text on
  stdin, temporary files in a private temp dir, process-group cleanup on
  timeout/cancellation, exact WAV structural validation, and returns raw PCM.

Test quality:

- Added behavioral tests around retry attempts, cancellation, stream sequence/
  terminal ordering, output receipt preconditions, response HMAC/replay/
  persisted usage exactness, OpenAI SDK request shapes, local non-retention,
  telemetry blocking, and offline WAV validation.
- Added regression tests for the newly public contracts and port protocol.
- Regenerated contract schemas/fixtures and verified them with the repository
  generators.

## Concerns

- Full non-live suite cannot be completely green in this sandbox with the
  mandated temporary env because unrelated environment prerequisites fail:
  missing admin Node tooling, sandbox-denied AF_UNIX socket tests, and child
  scenario runtime rejection of the `.venv` symlink to
  `/private/tmp/tuntun-task06-venv`. The narrowed full non-live sweep excluding
  only those triaged environment-only surfaces passed with `3032 passed`.
- A harmless pytest assert-rewrite warning appears when provider route fixtures
  are imported before plugin rewrite. It does not indicate a test failure.
- `.venv` is present as an untracked environment symlink in the worktree and was
  intentionally not staged.

## Fix Round 1 — Review fixes

Base reviewed: `5f86d0b`

### Fix summary

- Restricted `AttemptRunner.run` retry decisions to retryable
  `TransientProviderError` failures with disposition exactly `never_sent`, a
  successful proof-based release, and attempts remaining.
- Enforced locked per-purpose attempt ceilings before reserve/authorization:
  `cloud_stt=1`, `cloud_reasoning=2`, and `cloud_tts=2`. `RetryPolicy` now also
  rejects global attempt counts above 2.
- Added active reservation/attempt validation for `ProviderNotSentError` and
  `ProviderNotSentCancellation`; mismatched proof scopes conservatively settle
  the active attempt and fail with `provider_unsent_scope_mismatch`.
- Made OpenAI STT/TTS adapters fail closed before gateway/network unless STT uses
  exactly `gpt-transcribe` and TTS uses exactly `tts-1`.
- Passed `SanitizedProviderRequest.timeout_ms` to `responses.stream` as local
  SDK timeout seconds without adding it to the committed semantic JSON body.
- Added exact subject binding to `VerifiedProviderResponseReceipt.require_scope`
  and updated output/proposal call sites so cross-subject contexts fail before
  DLP, consent, reservation, or TTS.
- Strengthened TTS activation evidence with frozen cloud/offline evidence DTOs.
  Offline macOS evidence now checks exact `/usr/bin/say` and
  `/usr/bin/afconvert` identities, owner-license proof, binary hashes, fixed
  hash match, installed English/Hindi voice IDs, exact raw s16le mono 24kHz PCM
  shape, bilingual and Hinglish quality, no-network observation, cold restart
  voice presence, latency bounds, valid SHA-256 base64 hash encodings, and
  current/fresh evidence. Cloud evidence now requires `character_limit == 4096`
  exactly.

### RED evidence

Attempt retry disposition and per-purpose ceilings:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run pytest \
  tests/integration/providers/test_attempt_runner.py::test_retry_policy_rejects_global_attempt_counts_above_two \
  tests/integration/providers/test_attempt_runner.py::test_stt_attempt_policy_above_one_fails_before_reservation \
  tests/integration/providers/test_attempt_runner.py::test_reasoning_retry_has_distinct_authorization_and_reservation \
  tests/integration/providers/test_attempt_runner.py::test_reasoning_sent_or_unknown_retryable_failure_never_retries \
  -q
```

Result before fix:

```text
5 failed, 1 passed in 1.08s
```

Expected failures showed:

- `RetryPolicy(max_attempts=3)` did not raise.
- STT policy with 2 attempts reached reservation/invocation instead of failing
  before reserve.
- Sent/unknown 503 failures retried and invoked twice.

OpenAI adapter model/timeout fail-closed behavior:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run pytest \
  tests/contract/openai/test_responses_request.py::test_reasoning_timeout_is_transmitted_but_not_committed \
  tests/contract/openai/test_transcribe_request.py::test_transcriber_rejects_non_gpt_transcribe_model_before_gateway \
  tests/contract/openai/test_tts_request.py::test_tts_rejects_non_tts_1_model_before_gateway \
  -q
```

Result before fix:

```text
3 failed in 0.17s
```

Expected failures showed the missing Responses `timeout` kwarg, STT accepting a
non-`gpt-transcribe` model through the gateway, and TTS failing later at
commitment mismatch instead of fail-closed model authorization.

Subject binding:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run pytest \
  tests/integration/providers/test_output_pipeline.py::test_cross_subject_context_fails_before_dlp_consent_or_tts_reservation \
  tests/unit/providers/test_output_validator.py::test_mapper_rejects_cross_subject_scope_before_resolving_refs \
  -q
```

Result before fix:

```text
2 failed in 0.80s
```

Expected failures showed output synthesis reached DLP/TTS under a wrong subject
and proposal mapping lacked a subject-scoped receipt API.

Offline activation evidence:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run pytest tests/integration/providers/test_tts_activation.py -q
```

Result before fix:

```text
1 error in 0.31s
```

Expected collection error was the missing frozen evidence DTOs:
`CloudRequestBoundTtsEvidence` and `OfflineMacOSSayEvidence`.

Supplemental audit items:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run pytest \
  tests/integration/providers/test_attempt_runner.py::test_run_provider_not_sent_scope_mismatch_settles_active_without_retry \
  tests/integration/providers/test_attempt_runner.py::test_stream_provider_not_sent_scope_mismatch_settles_active_without_retry \
  tests/integration/providers/test_tts_activation.py::test_cloud_tts_evidence_requires_exact_contract_limit \
  -q
```

Result before supplemental fix:

```text
5 failed, 1 passed in 0.47s
```

Expected failures showed mismatched `ProviderNotSent*` proof IDs released the
active attempt and re-raised the underlying cause instead of settling with
`provider_unsent_scope_mismatch`, and cloud TTS evidence accepted 4097
characters.

### GREEN evidence

Amended review-fix focused group:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run pytest \
  tests/integration/providers/test_attempt_runner.py::test_retry_policy_rejects_global_attempt_counts_above_two \
  tests/integration/providers/test_attempt_runner.py::test_stt_attempt_policy_above_one_fails_before_reservation \
  tests/integration/providers/test_attempt_runner.py::test_reasoning_retry_has_distinct_authorization_and_reservation \
  tests/integration/providers/test_attempt_runner.py::test_reasoning_sent_or_unknown_retryable_failure_never_retries \
  tests/contract/openai/test_responses_request.py::test_reasoning_timeout_is_transmitted_but_not_committed \
  tests/contract/openai/test_transcribe_request.py::test_transcriber_rejects_non_gpt_transcribe_model_before_gateway \
  tests/contract/openai/test_tts_request.py::test_tts_rejects_non_tts_1_model_before_gateway \
  tests/integration/providers/test_output_pipeline.py::test_cross_subject_context_fails_before_dlp_consent_or_tts_reservation \
  tests/unit/providers/test_output_validator.py::test_mapper_rejects_cross_subject_scope_before_resolving_refs \
  tests/integration/providers/test_tts_activation.py \
  -q
```

Result:

```text
35 passed in 1.80s
```

Supplemental focused group after patch:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run pytest \
  tests/integration/providers/test_attempt_runner.py::test_run_provider_not_sent_scope_mismatch_settles_active_without_retry \
  tests/integration/providers/test_attempt_runner.py::test_stream_provider_not_sent_scope_mismatch_settles_active_without_retry \
  tests/integration/providers/test_tts_activation.py::test_cloud_tts_evidence_requires_exact_contract_limit \
  -q
```

Result:

```text
6 passed in 0.44s
```

Full Task06 suite:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run pytest \
  tests/integration/providers/test_attempt_runner.py \
  tests/integration/providers/test_output_pipeline.py \
  tests/integration/providers/test_response_receipts.py \
  tests/integration/providers/test_tts_activation.py \
  tests/unit/providers/test_output_validator.py \
  tests/unit/providers/test_openai_error_translation.py \
  tests/contract/openai \
  tests/contract/tts/test_macos_say_offline.py \
  tests/evals/tts/test_bilingual_quality.py \
  tests/security/test_openai_local_non_retention.py \
  tests/security/test_no_external_telemetry.py \
  -q
```

Result:

```text
158 passed, 1 warning in 3.86s
```

Affected Task03-Task06/provider/budget regression gate:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run pytest \
  tests/security/test_log_redaction.py \
  tests/security/test_provider_review_freshness.py \
  tests/security/test_provider_boundary.py \
  tests/unit/budget \
  tests/integration/budget \
  tests/contract/test_budget_port.py \
  tests/contract/test_provider_route_binding.py \
  tests/unit/providers \
  tests/integration/providers \
  -q
```

Result:

```text
722 passed, 1 warning in 34.89s
```

The warning in both suites remains the existing pytest assert-rewrite warning for
`tests.fixtures.provider_routes`.

Static/generated/lock gates:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run ruff check \
  packages/contracts/src/tuntun_contracts/provider.py \
  packages/contracts/src/tuntun_contracts/speech.py \
  packages/contracts/src/tuntun_contracts/budget.py \
  packages/contracts/src/tuntun_contracts/ports.py \
  apps/core/src/tuntun_core/adapters/openai \
  apps/core/src/tuntun_core/adapters/tts \
  apps/core/src/tuntun_core/services/providers \
  packages/testing/src/tuntun_testing/fake_providers.py \
  tests/fixtures/provider_egress.py \
  tests/integration/providers/test_response_receipts.py \
  tests/integration/providers/test_attempt_runner.py \
  tests/integration/providers/test_output_pipeline.py \
  tests/integration/providers/test_tts_activation.py \
  tests/unit/providers/test_output_validator.py \
  tests/unit/providers/test_openai_error_translation.py \
  tests/contract/openai \
  tests/contract/tts/test_macos_say_offline.py \
  tests/evals/tts/test_bilingual_quality.py \
  tests/security/test_openai_local_non_retention.py \
  tests/security/test_no_external_telemetry.py
```

Result: exit 0.

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run mypy \
  packages/contracts/src/tuntun_contracts/provider.py \
  packages/contracts/src/tuntun_contracts/speech.py \
  packages/contracts/src/tuntun_contracts/budget.py \
  packages/contracts/src/tuntun_contracts/ports.py \
  apps/core/src/tuntun_core/adapters/openai \
  apps/core/src/tuntun_core/adapters/tts \
  apps/core/src/tuntun_core/services/providers \
  packages/testing/src/tuntun_testing/fake_providers.py
```

Result:

```text
Success: no issues found in 28 source files
```

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python scripts/generate_contract_fixtures.py --check
```

Result: exit 0.

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python scripts/generate_schemas.py --check
```

Result: exit 0.

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python scripts/generate_openapi.py --check
```

Result: exit 0.

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv lock --check
```

Result:

```text
Resolved 71 packages in 12ms
```

### Fix-round self-review

- Retry is now possible only for unsent proof-released attempts. Sent/unknown
  attempts settle and surface the provider error without retrying.
- Policy limits are enforced before reserve/authorization, so rejected STT
  two-attempt policies do not create budget or route state.
- Mismatched unsent proofs cannot release the active reservation under a forged
  or stale id; they settle the active reservation and complete the turn attempt.
- STT/TTS model checks happen before buffering/commitment/gateway work.
- Responses timeout is an SDK kwarg only and is absent from the canonical request
  body.
- Subject scope is checked before output DLP, consent, reservations, TTS, ref
  resolution, or provenance attachment.
- Cloud/offline activation evidence now has explicit accepted fields and exact
  contract checks; cloud `character_limit` is exact, not a lower bound.

## Final whole-branch review fix wave

### Implementation summary

- Moved invalid/oversized STT provider response-body evidence across the
  adapter/gateway boundary as a bounded `_TranscriptionEnvelope` with
  `body_error`. The gateway now sees the provider response as returned, then
  the STT `observe()` path fails accounting evidence, so provider calls
  terminalize as `succeeded` with null usage receipt and BudgetGuard freezes on
  unknown overage. Declared oversized bodies read zero chunks; chunked overflow
  clears the partial buffer before returning a body-free invalid envelope.
- Changed cloud and offline TTS text limits from UTF-8 bytes to NFC character
  counts, while retaining a separate cloud TTS serialized-body byte cap against
  the route authorization.
- Reworked macOS `say` WAV ingestion to reject non-regular/oversized output by
  no-follow stat/open/fstat checks before bounded chunked reads, then validate
  exact WAV PCM format and bounded container overhead.
- Made macOS process kill/reap cleanup cancellation-safe by shielding the
  `process.wait()` drain and preserving the original cancellation.
- Removed optimistic default construction from cloud/offline TTS readiness
  evidence. Both branches now require explicit reviewed/provenance UUIDs,
  timezone-aware measurement time, freshness, and the existing exact cloud or
  offline capability dimensions.
- Closed provider-facing proposal references at the `AssistantTurn` schema
  boundary with anchored `subject:...`, `memory:...`, and `timer:...` resolver
  patterns.
- Added a narrow source typing fix in `BudgetGuard.require_accounting_context`
  discovered by the source-focused mypy gate.

### Files changed

- `apps/core/src/tuntun_core/adapters/openai/transcribe.py`
- `apps/core/src/tuntun_core/adapters/openai/tts.py`
- `apps/core/src/tuntun_core/adapters/tts/macos_say.py`
- `apps/core/src/tuntun_core/services/budget/guard.py`
- `apps/core/src/tuntun_core/services/providers/output_validator.py`
- `apps/core/src/tuntun_core/services/providers/tts_activation.py`
- `packages/contracts/src/tuntun_contracts/speech.py`
- `tests/contract/openai/conftest.py`
- `tests/contract/openai/test_transcribe_request.py`
- `tests/contract/openai/test_tts_request.py`
- `tests/contract/tts/test_macos_say_offline.py`
- `tests/integration/providers/test_tts_activation.py`
- `tests/integration/providers/test_usage_receipt_repository.py`
- `tests/unit/providers/test_output_validator.py`

### RED evidence

STT response-body boundary:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python -m pytest \
  tests/contract/openai/test_transcribe_request.py::test_transcription_transport_is_bounded_before_json_projection \
  -q
```

Result:

```text
2 failed in 0.16s
E       assert False is True
E        +  where False = <conftest.RecordingSendGateway object ...>.observe_attempted
```

TTS readiness explicit evidence:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python -m pytest \
  tests/integration/providers/test_tts_activation.py::test_tts_readiness_evidence_requires_explicit_reviewed_provenance \
  tests/integration/providers/test_tts_activation.py::test_family_voice_requires_one_verified_branch \
  -q
```

Result:

```text
ERROR tests/integration/providers/test_tts_activation.py
TypeError: CloudRequestBoundTtsEvidence.__init__() got an unexpected keyword argument 'review_receipt_id'
```

Remaining regression slice:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python -m pytest \
  tests/contract/openai/test_tts_request.py::test_tts_accepts_4096_multibyte_nfc_characters \
  tests/contract/openai/test_tts_request.py::test_tts_rejects_4097_characters_before_network \
  tests/contract/tts/test_macos_say_offline.py::test_offline_synthesis_request_is_frozen_bounded_nfc_contract \
  tests/contract/tts/test_macos_say_offline.py::test_offline_tts_rejects_oversized_wav_before_unbounded_read \
  tests/contract/tts/test_macos_say_offline.py::test_process_cleanup_wait_is_shielded_from_repeated_cancellation \
  tests/unit/providers/test_output_validator.py::test_provider_memory_refs_accept_only_resolver_prefixes \
  tests/unit/providers/test_output_validator.py::test_provider_memory_refs_reject_unanchored_or_unregistered_shapes \
  tests/unit/providers/test_output_validator.py::test_provider_timer_refs_accept_resolver_prefix \
  tests/unit/providers/test_output_validator.py::test_provider_timer_refs_reject_unanchored_or_unregistered_shapes \
  tests/integration/providers/test_usage_receipt_repository.py::test_observe_body_validation_failure_is_succeeded_null_usage_then_freezes \
  -q
```

Result:

```text
13 failed, 7 passed, 1 warning in 0.96s
```

Top failures matched the review findings: 4096 Hindi TTS rejected by byte count,
offline 4096 Hindi rejected by byte count, oversized WAV called
`Path.read_bytes()`, cancellation escaped before wait completion, and invalid
provider refs did not raise `ValidationError`.

### GREEN and verification evidence

Focused final-review regression slice:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python -m pytest \
  tests/contract/openai/test_transcribe_request.py::test_transcription_transport_is_bounded_before_json_projection \
  tests/contract/openai/test_tts_request.py::test_tts_accepts_4096_multibyte_nfc_characters \
  tests/contract/openai/test_tts_request.py::test_tts_rejects_4097_characters_before_network \
  tests/contract/tts/test_macos_say_offline.py::test_offline_synthesis_request_is_frozen_bounded_nfc_contract \
  tests/contract/tts/test_macos_say_offline.py::test_offline_tts_rejects_oversized_wav_before_unbounded_read \
  tests/contract/tts/test_macos_say_offline.py::test_process_cleanup_wait_is_shielded_from_repeated_cancellation \
  tests/integration/providers/test_tts_activation.py::test_tts_readiness_evidence_requires_explicit_reviewed_provenance \
  tests/integration/providers/test_tts_activation.py::test_family_voice_requires_one_verified_branch \
  tests/integration/providers/test_tts_activation.py::test_cloud_tts_evidence_requires_reviewed_current_provenance \
  tests/integration/providers/test_tts_activation.py::test_unproved_cloud_and_bad_offline_voice_block_stage_one \
  tests/unit/providers/test_output_validator.py::test_provider_memory_refs_accept_only_resolver_prefixes \
  tests/unit/providers/test_output_validator.py::test_provider_memory_refs_reject_unanchored_or_unregistered_shapes \
  tests/unit/providers/test_output_validator.py::test_provider_timer_refs_accept_resolver_prefix \
  tests/unit/providers/test_output_validator.py::test_provider_timer_refs_reject_unanchored_or_unregistered_shapes \
  tests/integration/providers/test_usage_receipt_repository.py::test_observe_body_validation_failure_is_succeeded_null_usage_then_freezes \
  -q
```

Result:

```text
57 passed, 1 warning in 4.32s
```

Amended Task 06 suite:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python -m pytest \
  tests/integration/providers/test_attempt_runner.py \
  tests/unit/providers/test_output_validator.py \
  tests/unit/providers/test_openai_error_translation.py \
  tests/integration/providers/test_output_pipeline.py \
  tests/integration/providers/test_response_receipts.py \
  tests/integration/providers/test_usage_receipt_repository.py \
  tests/contract/openai/test_authorized_signatures.py \
  tests/contract/openai/test_transcribe_request.py \
  tests/contract/openai/test_responses_request.py \
  tests/contract/openai/test_tts_request.py \
  tests/contract/tts/test_macos_say_offline.py \
  tests/integration/providers/test_tts_activation.py \
  tests/evals/tts/test_bilingual_quality.py \
  tests/security/test_openai_local_non_retention.py \
  tests/security/test_no_external_telemetry.py \
  -q
```

Result:

```text
208 passed, 1 warning in 53.21s
```

Affected Task03-05/provider/budget regression gate:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python -m pytest \
  tests/contract \
  tests/unit/providers \
  tests/integration/providers \
  tests/unit/budget \
  tests/integration/budget \
  tests/security/test_model_governance.py \
  tests/unit/poc/test_voice_turn.py \
  -q
```

Result:

```text
1056 passed, 3 skipped in 247.75s (0:04:07)
```

Static/generated/lock/diff gates:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run ruff check .
```

Result:

```text
All checks passed!
```

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run mypy \
  apps/core/src/tuntun_core/adapters/openai \
  apps/core/src/tuntun_core/adapters/tts \
  apps/core/src/tuntun_core/services/providers \
  apps/core/src/tuntun_core/services/budget \
  packages/contracts/src/tuntun_contracts \
  packages/testing/src/tuntun_testing
```

Result:

```text
Success: no issues found in 52 source files
```

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python scripts/generate_contract_fixtures.py --check
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python scripts/generate_schemas.py --check
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python scripts/generate_openapi.py --check
git diff --check
```

Result: all exited 0.

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv lock --check
```

Result:

```text
Resolved 71 packages in 32ms
```

Full non-live attempt:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python -m pytest -m 'not live_cloud and not reachy_hardware' -q
```

Result:

```text
68 failed, 3205 passed, 8 skipped in 480.27s (0:08:00)
```

Observed failure buckets were environment/tooling-only for this fix wave:
missing `apps/admin/node_modules`/Playwright binaries, macOS sandbox denial for
UNIX-domain socket tests, and scenario isolated-child guard tests reporting
`scenario-gate: failed`. The required focused, Task06, affected
provider/budget, static, generated, lock, and diff gates all passed.

### Final-wave self-review

- STT invalid/oversized body handling is localized to the adapter boundary and
  still preserves true SDK/network invocation exceptions as gateway-ambiguous.
- No STT or TTS path transiently buffers beyond its configured cap before
  rejecting; oversized STT declared lengths read no chunks, and macOS WAV output
  is stat-capped before file reads.
- Gateway/budget terminal ordering remains foundation-owned; the production
  observe-failure regression proves `succeeded`/null usage, no cost ledger row,
  and unknown-overage freeze.
- TTS text validation now uses NFC character count for both cloud and offline
  contracts, while cloud body bytes remain separately route-bound.
- TTS readiness can no longer pass from synthetic default construction; every
  accepted branch now carries explicit review/provenance/currentness evidence.
- Provider-facing refs are closed to the resolver formats named in the plan and
  do not add broader syntax.
- Process cleanup shields only the reap/drain and re-raises the original
  cancellation after the child has been waited.

### Concerns

- Full non-live suite is not clean on this host due to the environment/tooling
  buckets listed above. I did not install Node dependencies or broaden this
  wave into unrelated scenario/sandbox work.

## CI repair

### Scope and root cause

PR 18 CI failed in the scenario typecheck guard because
`packages/testing/src/tuntun_testing/fake_providers.py` `FakeBudget` no longer
satisfied the frozen `BudgetPort` protocol after Task06 added
`require_accounting_context`. `RecordingBudget` already implemented the method;
the scripted fake had reserve/mark_sent/settle/release/reconcile only.

Implementation was intentionally narrow:

- Added `FakeBudget.require_accounting_context(route, consumption)` using the
  existing `_ScriptedFake._take(...)` convention.
- Locked the operation name and argument tuple as
  `budget.require_accounting_context`, `(route, consumption)`.
- Added a focused behavior regression while keeping the static
  `_accept_exact_ports(...)` gate.

### RED evidence

Initial scenario guard reproduction:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python -m pytest \
  'tests/security/test_scenario_guard.py::test_make_scenario_gate_uses_offline_no_sync_isolated_python[scenario-typecheck]' \
  tests/security/test_scenario_guard.py::test_isolated_launcher_owns_mypy_path_instead_of_trusting_the_caller \
  -q
```

Result:

```text
2 failed in 2.22s
test_make_scenario_gate_uses_offline_no_sync_isolated_python[scenario-typecheck]:
  make: *** [scenario-typecheck] Error 97
test_isolated_launcher_owns_mypy_path_instead_of_trusting_the_caller:
  FileNotFoundError: .../.venv/bin/python
```

The local second failure was the worktree harness layout: `.venv/bin/python`
was absent while this work used `UV_PROJECT_ENVIRONMENT=/private/tmp/...`.
The exact mypy slice exposed the CI root cause directly:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run mypy tests/unit/testing/test_scenario.py \
  packages/testing/src/tuntun_testing/fake_providers.py \
  packages/contracts/src/tuntun_contracts/ports.py
```

Result:

```text
tests/unit/testing/test_scenario.py:120: error: Argument 12 to "_accept_exact_ports" has incompatible type "FakeBudget"; expected "BudgetPort"  [arg-type]
tests/unit/testing/test_scenario.py:120: note: "FakeBudget" is missing following "BudgetPort" protocol member:
tests/unit/testing/test_scenario.py:120: note:     require_accounting_context
Found 1 error in 1 file (checked 3 source files)
```

New focused behavior regression before implementation:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python -m pytest \
  tests/unit/testing/test_scenario.py::test_fake_budget_scripts_accounting_context \
  -q
```

Result:

```text
1 failed in 2.22s
AttributeError: 'FakeBudget' object has no attribute 'require_accounting_context'
```

### GREEN evidence

Focused behavior/static/guard verification:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python -m pytest \
  tests/unit/testing/test_scenario.py::test_scripted_fake_checks_arguments_faults_and_exhaustion \
  tests/unit/testing/test_scenario.py::test_fake_budget_scripts_accounting_context \
  tests/unit/testing/test_scenario.py::test_all_fakes_satisfy_the_frozen_task_5_ports \
  -q
```

Result:

```text
3 passed in 0.88s
```

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run mypy tests/unit/testing/test_scenario.py \
  packages/testing/src/tuntun_testing/fake_providers.py \
  packages/contracts/src/tuntun_contracts/ports.py
```

Result:

```text
Success: no issues found in 3 source files
```

For the security guard nodes, I temporarily restored the expected local wrapper
layout with `.venv -> /private/tmp/tuntun-task06-venv`, ran with
`UV_PROJECT_ENVIRONMENT` unset so `sys.executable` was under `.venv/bin`, then
removed the untracked symlink before staging.

```bash
env -u UV_PROJECT_ENVIRONMENT \
  UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
  uv run python -m pytest \
  'tests/security/test_scenario_guard.py::test_make_scenario_gate_uses_offline_no_sync_isolated_python[scenario-typecheck]' \
  tests/security/test_scenario_guard.py::test_isolated_launcher_owns_mypy_path_instead_of_trusting_the_caller \
  -q
```

Result:

```text
2 passed in 27.97s
```

Relevant fake/unit tests:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python -m pytest tests/unit/testing/test_scenario.py -q
```

Result:

```text
19 passed in 0.62s
```

Amended Task06 suite:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python -m pytest \
  tests/integration/providers/test_attempt_runner.py \
  tests/unit/providers/test_output_validator.py \
  tests/unit/providers/test_openai_error_translation.py \
  tests/integration/providers/test_output_pipeline.py \
  tests/integration/providers/test_response_receipts.py \
  tests/integration/providers/test_usage_receipt_repository.py \
  tests/contract/openai/test_authorized_signatures.py \
  tests/contract/openai/test_transcribe_request.py \
  tests/contract/openai/test_responses_request.py \
  tests/contract/openai/test_tts_request.py \
  tests/contract/tts/test_macos_say_offline.py \
  tests/integration/providers/test_tts_activation.py \
  tests/evals/tts/test_bilingual_quality.py \
  tests/security/test_openai_local_non_retention.py \
  tests/security/test_no_external_telemetry.py \
  -q
```

Result:

```text
208 passed, 1 warning in 50.15s
```

Affected provider/budget regression slice:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python -m pytest tests/contract tests/unit/providers \
  tests/integration/providers tests/unit/budget tests/integration/budget \
  tests/security/test_model_governance.py tests/unit/poc/test_voice_turn.py \
  -q
```

Result:

```text
1056 passed, 3 skipped in 168.07s (0:02:48)
```

Static and artifact gates:

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run ruff check .
```

Result:

```text
All checks passed!
```

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run mypy apps/core/src apps/edge/src packages/contracts/src \
  packages/testing/src tests/unit/testing/test_scenario.py
```

Result:

```text
Success: no issues found in 100 source files
```

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python scripts/generate_contract_fixtures.py --check
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python scripts/generate_schemas.py --check
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv run python scripts/generate_openapi.py --check
git diff --check
```

Result: all exited 0.

```bash
UV_CACHE_DIR=/private/tmp/tuntun-task06-uv-cache \
UV_PROJECT_ENVIRONMENT=/private/tmp/tuntun-task06-venv \
uv lock --check
```

Result:

```text
Resolved 71 packages in 9ms
```

### CI-repair self-review

- The production budget ports and semantics are untouched.
- `FakeBudget` now matches the Task06 `BudgetPort` surface and remains purely
  scripted; it does not synthesize accounting contexts.
- The new regression fails if the method disappears, records the wrong
  operation name, or passes a different argument tuple.
- The static scenario port gate now includes `FakeBudget` successfully.
