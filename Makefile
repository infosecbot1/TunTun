.PHONY: bootstrap format lint typecheck test test-security test-contract web-test web-build web-e2e scenario-typecheck scenario-check core-wheel-smoke check verify-private-data
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
	uv run python scripts/verify_private_data.py apps/admin/dist
web-e2e:
	pnpm --filter @tuntun/admin e2e
verify-private-data:
	uv run python scripts/verify_private_data.py .
scenario-typecheck:
	uv run --offline --no-sync python -I -S scripts/run_isolated_module.py mypy
scenario-check:
	uv run --offline --no-sync python -I -S scripts/run_scenarios.py --turns 2 --assert-resource-bounds --json
# Resolve the highest versions allowed by the wheel's current dependency ranges; do not use uv.lock.
core-wheel-smoke:
	@set -eu; \
	base="$${TMPDIR:-/tmp}"; \
	case "$$base" in /*) ;; *) exit 97 ;; esac; \
	base="$$(cd "$$base" && pwd -P)"; \
	while [ "$$base" != / ] && [ "$${base%/}" != "$$base" ]; do base="$${base%/}"; done; \
	prefix="$${base%/}/tuntun-core-wheel."; \
	smoke="$$(mktemp -d "$${prefix}XXXXXX")"; \
	cleanup() { case "$$smoke" in "$$prefix"*) rm -rf -- "$$smoke" ;; *) exit 97 ;; esac; }; \
	trap cleanup 0; \
	export UV_CACHE_DIR="$$smoke/uv-cache"; \
	uv build --package tuntun-contracts --wheel --out-dir "$$smoke/dist"; \
	uv build --package tuntun-core --out-dir "$$smoke/dist"; \
	set -- "$$smoke"/dist/tuntun_core-*.whl; \
	[ "$$#" -eq 1 ] && [ -f "$$1" ]; \
	core_wheel="$$1"; \
	uv venv --python 3.12 "$$smoke/venv"; \
	uv pip install --resolution highest --find-links "$$smoke/dist" --python "$$smoke/venv/bin/python" "$$core_wheel"; \
	mkdir -m 700 "$$smoke/private-db"; \
	TUNTUN_CORE_WHEEL_DB="$$smoke/private-db/identity.db" env -u PYTHONPATH "$$smoke/venv/bin/python" -c 'import importlib.util as u, json, os; from importlib.metadata import requires, version; from pathlib import Path; from uuid import UUID; assert u.find_spec("tuntun_testing") is None; from typer.testing import CliRunner; from tuntun_core.cli.main import app; import tuntun_core.cli.commands.simulate; from tuntun_core.adapters.sqlcipher import migrations as migration_module; from tuntun_core.adapters.sqlcipher.connection import open_sqlcipher; from tuntun_core.adapters.sqlcipher.crypto import RecordCipher, RecordContext; assert "tuntun-contracts==0.1.0.dev0" in (requires("tuntun-core") or []); assert version("tuntun-contracts") == "0.1.0.dev0"; config_path = migration_module._migration_config_path(); assert "_migration_assets" in config_path.parts; assert (config_path.parent / "migrations" / "versions" / "0003_biometric_template_enrollment_binding.py").is_file(); key = bytes(range(32)); db_path = Path(os.environ["TUNTUN_CORE_WHEEL_DB"]); migration_module.upgrade_encrypted(db_path, key, None); db = open_sqlcipher(db_path, key); assert db.execute("SELECT version_num FROM alembic_version").fetchall() == [("0003_biometric_template_enrollment_binding",)]; enrollment_columns = {row[1] for row in db.execute("PRAGMA table_info(enrollment_sessions)")}; template_columns = {row[1] for row in db.execute("PRAGMA table_info(biometric_templates)")}; assert "synthetic_template_id" in enrollment_columns; assert "enrollment_session_id" in template_columns; db.close(); context = RecordContext(household_id=UUID(int=1), table="biometric_templates", row_id=UUID(int=2), purpose="voice-template", schema_version="1.0"); cipher = RecordCipher(bytes(range(32))); encrypted = cipher.encrypt(b"isolated-wheel-record-sentinel", context); assert cipher.decrypt(encrypted, context) == b"isolated-wheel-record-sentinel"; result = CliRunner().invoke(app, ["version"]); assert result.exit_code == 0 and result.stdout == "0.1.0.dev0\n"; missing = CliRunner().invoke(app, ["simulate", "--scenario", "missing.yaml"]); assert missing.exit_code == 2 and missing.stdout == "" and missing.stderr == "simulation-extra-required\n"; models = CliRunner().invoke(app, ["models", "list"]); assert models.exit_code == 0; model_payload = json.loads(models.stdout); assert [entry["id"] for entry in model_payload] == ["vosk-small-en-us-0.15", "vosk-small-hi-0.22"]'
check: lint typecheck test test-security test-contract web-test web-build verify-private-data scenario-typecheck scenario-check core-wheel-smoke
