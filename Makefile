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
	uv run python scripts/verify_private_data.py apps/admin/dist
web-e2e:
	pnpm --filter @tuntun/admin e2e
verify-private-data:
	uv run python scripts/verify_private_data.py .
check: lint typecheck test test-security test-contract web-test web-build verify-private-data
