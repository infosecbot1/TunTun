from __future__ import annotations

import inspect

from tuntun_contracts.ports import BudgetPort


def test_one_budget_port_has_exact_async_operations() -> None:
    assert tuple(
        name
        for name in ("reserve", "mark_sent", "settle", "release_unsent", "reconcile_turn")
        if inspect.iscoroutinefunction(getattr(BudgetPort, name))
    ) == ("reserve", "mark_sent", "settle", "release_unsent", "reconcile_turn")
