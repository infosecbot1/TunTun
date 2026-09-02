from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

SINGAPORE = ZoneInfo("Asia/Singapore")


def singapore_month_key(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("aware time required")
    return value.astimezone(SINGAPORE).strftime("%Y-%m")
