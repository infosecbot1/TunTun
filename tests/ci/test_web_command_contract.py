import json
import os
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
        "../../tests/e2e/**/*.ts",
        "../../tests/e2e/**/*.tsx",
        "../../tests/ui/**/*.ts",
        "../../tests/ui/**/*.tsx",
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


def test_web_build_scans_dist_only_after_a_successful_build(tmp_path: Path) -> None:
    commands = tmp_path / "bin"
    commands.mkdir()
    log = tmp_path / "commands.log"
    pnpm = commands / "pnpm"
    pnpm.write_text(
        "#!/bin/sh\n"
        "printf 'build\\n' >> \"$COMMAND_LOG\"\n"
        'if test "${FAIL_BUILD:-0}" = 1; then exit 7; fi\n'
        "mkdir -p apps/admin/dist\n",
        encoding="utf-8",
    )
    scanner = commands / "uv"
    scanner.write_text(
        "#!/bin/sh\n"
        "test -d apps/admin/dist || exit 9\n"
        'test "$*" = '
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
