from __future__ import annotations

from datetime import UTC, datetime

from tuntun_core.services.budget.month import singapore_month_key


def test_singapore_month_boundary_is_not_utc_month_boundary() -> None:
    assert singapore_month_key(datetime(2026, 8, 31, 15, 59, 59, tzinfo=UTC)) == "2026-08"
    assert singapore_month_key(datetime(2026, 8, 31, 16, 0, 0, tzinfo=UTC)) == "2026-09"
