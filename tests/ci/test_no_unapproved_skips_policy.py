from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.materialize_conversation_plan import materialize_document, parse_plan_text
from scripts.validate_conversation_plan import approved_skip_marker_names, validate_plan_document

PLAN_PATH = Path(
    "docs/superpowers/plans/2026-08-27-tuntun-phase1-conversation-reachy-execution.md"
)


def test_only_exact_hardware_or_live_cloud_markers_authorize_a_skip() -> None:
    assert approved_skip_marker_names(("reachy_hardware",))
    assert approved_skip_marker_names(("live_cloud",))
    assert not approved_skip_marker_names(())
    assert not approved_skip_marker_names(("skip",))
    assert not approved_skip_marker_names(("reachy_hardware", "live_cloud"))
    assert not approved_skip_marker_names(("reachy_hardware", "owner_only"))


def test_miniature_plan_rejects_skip_in_non_hardware_fixture() -> None:
    plan = """### Task 01: skip

**Depends on:** Foundation contracts

**Files:**
- Create: `tests/fixtures/cases.py`
- Test: `tests/test_case.py`

```python
# tests/fixtures/cases.py
import pytest
@pytest.fixture
def case():
    pytest.skip("missing production dependency")
```

```python
# tests/test_case.py
def test_case(case):
    assert case
```

```bash
git add tests/fixtures/cases.py tests/test_case.py
```
"""

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any("unapproved pytest skip" in error for error in errors), errors


def test_extra_authorization_marker_cannot_smuggle_an_approved_skip() -> None:
    plan = """### Task 01: skip

**Depends on:** Foundation contracts

**Files:**
- Test: `tests/hardware/test_case.py`

```python
# tests/hardware/test_case.py
import pytest
@pytest.mark.reachy_hardware
@pytest.mark.owner_only
def test_case():
    pytest.skip("not actual hardware evidence")
```

```bash
git add tests/hardware/test_case.py
```
"""

    errors = validate_plan_document(parse_plan_text(plan), foundation_files={})

    assert any("unapproved pytest skip" in error for error in errors), errors


def test_task_02_materializes_global_skip_to_failure_hook() -> None:
    document = parse_plan_text(PLAN_PATH.read_text())
    task_02 = document.only_tasks({2})
    files = materialize_document(task_02, foundation_files={})
    source = files["tests/conftest.py"].decode()
    tree = ast.parse(source)
    names = {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    assert "pytest_runtest_makereport" in names
    assert "reachy_hardware" in source
    assert "live_cloud" in source
    assert "report.outcome = \"failed\"" in source


def test_materialized_hook_fails_runtime_and_extra_marker_skips(
    tmp_path: Path,
) -> None:
    document = parse_plan_text(PLAN_PATH.read_text())
    files = materialize_document(document.only_tasks({2}), foundation_files={})
    (tmp_path / "conftest.py").write_bytes(files["tests/conftest.py"])
    (tmp_path / "test_skip_policy.py").write_text(
        """import pytest

def test_runtime_skip():
    pytest.skip("not approved")

@pytest.mark.reachy_hardware
def test_hardware_skip():
    pytest.skip("physical hardware is external")

@pytest.mark.reachy_hardware
@pytest.mark.owner_only
def test_extra_marker_skip():
    pytest.skip("not exactly one approved lane")
"""
    )

    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    output = result.stdout + result.stderr

    assert result.returncode == 1, output
    assert "2 failed, 1 skipped" in output


def test_authoritative_plan_exposes_each_residual_unapproved_skip() -> None:
    errors = validate_plan_document(parse_plan_text(PLAN_PATH.read_text()), foundation_files={})

    skip_errors = [error for error in errors if "unapproved pytest skip" in error]
    assert len(skip_errors) == 3
    assert any("cancellation_barrier_case" in error for error in skip_errors)
    assert any("task_factory_failure_case" in error for error in skip_errors)
    assert any("qwen_route_case" in error for error in skip_errors)
