from __future__ import annotations

import asyncio
import heapq
import math
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from itertools import count


@dataclass(order=True, slots=True)
class _ScheduledCall:
    deadline: float
    sequence: int
    callback: Callable[[], None] = field(compare=False, repr=False)
    cancelled: bool = field(default=False, compare=False)

    def cancel(self) -> None:
        self.cancelled = True


class FakeClock:
    def __init__(self, start: datetime) -> None:
        if start.tzinfo is None or start.utcoffset() is None:
            raise ValueError("start must be timezone-aware")
        self._start = start
        self._monotonic = 0.0
        self._sequence = count()
        self._scheduled: list[_ScheduledCall] = []
        self._calls: list[str] = []

    @property
    def calls(self) -> tuple[str, ...]:
        return tuple(self._calls)

    def now(self) -> datetime:
        self._calls.append("now")
        return self._start + timedelta(seconds=self._monotonic)

    def monotonic(self) -> float:
        self._calls.append("monotonic")
        return self._monotonic

    def call_later(
        self,
        delay: float | timedelta,
        callback: Callable[[], None],
    ) -> _ScheduledCall:
        delay_seconds = self._seconds(delay)
        handle = _ScheduledCall(
            self._monotonic + delay_seconds,
            next(self._sequence),
            callback,
        )
        heapq.heappush(self._scheduled, handle)
        return handle

    def advance(self, delay: float | timedelta) -> None:
        seconds = self._seconds(delay)
        target = self._monotonic + seconds
        while self._scheduled and self._scheduled[0].deadline <= target:
            handle = heapq.heappop(self._scheduled)
            self._monotonic = handle.deadline
            if not handle.cancelled:
                handle.callback()
        self._monotonic = max(self._monotonic, target)

    async def sleep(self, seconds: float) -> None:
        self.advance(seconds)
        await asyncio.sleep(0)

    @staticmethod
    def _seconds(delay: float | timedelta) -> float:
        seconds = delay.total_seconds() if isinstance(delay, timedelta) else delay
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError("delay must be finite and non-negative")
        return seconds
