from __future__ import annotations

from datetime import UTC, datetime


def utc_storage(value: datetime) -> str:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise TypeError("stored timestamp must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_utc_storage(value: str) -> datetime:
    if type(value) is not str:
        raise TypeError("stored timestamp must be an exact UTC string")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise ValueError("stored timestamp must be canonical UTC") from error
    if utc_storage(parsed) != value:
        raise ValueError("stored timestamp must be canonical UTC")
    return parsed
