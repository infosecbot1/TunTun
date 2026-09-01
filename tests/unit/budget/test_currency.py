from __future__ import annotations

import pytest
from tuntun_core.services.budget.pricing import ceil_div, checked_add, checked_mul


def test_fx_rounds_up_without_float() -> None:
    assert ceil_div(1 * 1_500_000, 1_000_000) == 2
    assert ceil_div(2 * 1_500_000, 1_000_000) == 3


@pytest.mark.parametrize(
    "operation",
    (
        lambda: checked_add(-1, 1),
        lambda: checked_add(9_000_000_000_000_000, 1),
        lambda: checked_mul(-1, 1),
        lambda: checked_mul(9_000_000_000_000_000, 2),
    ),
)
def test_negative_or_overflowed_budget_arithmetic_fails_closed(operation) -> None:
    with pytest.raises(OverflowError, match="budget_arithmetic_out_of_bounds"):
        operation()
