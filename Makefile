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
	MYPYPATH="$(CURDIR)/packages/contracts/src:$(CURDIR)/packages/testing/src:$(CURDIR)/apps/core/src" uv run --offline --no-sync python -I -S scripts/run_isolated_module.py mypy --python-version 3.12 --config-file "$(CURDIR)/pyproject.toml" --no-incremental --cache-dir /dev/null --no-fast-exit "$(CURDIR)/packages/testing/src" "$(CURDIR)/scripts/run_scenarios.py" "$(CURDIR)/tests/unit/testing/test_scenario.py" "$(CURDIR)/tests/unit/testing/test_scenario_cli.py" "$(CURDIR)/tests/integration/test_deterministic_turn.py" "$(CURDIR)/tests/security/test_scenario_guard.py"
scenario-check:
	uv run --offline --no-sync python -I -S scripts/run_scenarios.py --turns 2 --assert-resource-bounds --json
# Resolve the highest versions allowed by the wheel's current dependency ranges; do not use uv.lock.
core-wheel-smoke:
	@set -eu; base="$${TMPDIR:-/tmp}"; case "$$base" in /*) ;; *) exit 97 ;; esac; while [ "$$base" != / ] && [ "$${base%/}" != "$$base" ]; do base="$${base%/}"; done; prefix="$${base%/}/tuntun-core-wheel."; smoke="$$(mktemp -d "$${prefix}XXXXXX")"; cleanup() { case "$$smoke" in "$$prefix"*) rm -rf -- "$$smoke" ;; *) exit 97 ;; esac; }; trap cleanup 0; export UV_CACHE_DIR="$$smoke/uv-cache"; uv build --package tuntun-core --wheel --out-dir "$$smoke/dist"; set -- "$$smoke"/dist/tuntun_core-*.whl; [ "$$#" -eq 1 ] && [ -f "$$1" ]; uv venv --python 3.12 "$$smoke/venv"; uv pip install --resolution highest --python "$$smoke/venv/bin/python" "$$1"; env -u PYTHONPATH "$$smoke/venv/bin/python" -c 'import importlib.util as u; assert u.find_spec("tuntun_testing") is None; from typer.testing import CliRunner; from tuntun_core.cli.main import app; import tuntun_core.cli.commands.simulate; result = CliRunner().invoke(app, ["version"]); assert result.exit_code == 0 and result.stdout == "0.1.0.dev0\n"; missing = CliRunner().invoke(app, ["simulate", "--scenario", "missing.yaml"]); assert missing.exit_code == 2 and missing.stdout == "" and missing.stderr == "simulation-extra-required\n"'
check: lint typecheck test test-security test-contract web-test web-build verify-private-data scenario-typecheck scenario-check core-wheel-smoke
