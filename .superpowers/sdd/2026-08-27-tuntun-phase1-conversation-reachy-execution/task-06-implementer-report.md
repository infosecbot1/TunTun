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
