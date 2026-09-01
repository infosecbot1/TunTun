from __future__ import annotations

import re
import threading

_OPERATION_PATTERN = re.compile(r"[a-z][a-z0-9_.:-]{0,63}\Z")
_KEY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")


class IdempotencyCapacityError(RuntimeError):
    pass


class IdempotencyStore:
    """Bounded same-process duplicate guard; durable receipts replace it later."""

    def __init__(self, *, max_entries: int = 4_096) -> None:
        if type(max_entries) is not int or not 1 <= max_entries <= 65_536:
            raise ValueError("invalid idempotency capacity")
        self._max_entries = max_entries
        self._keys: set[tuple[str, str]] = set()
        self._lock = threading.Lock()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._keys)

    def claim(self, operation: str, key: str) -> bool:
        if (
            type(operation) is not str
            or _OPERATION_PATTERN.fullmatch(operation) is None
            or type(key) is not str
            or _KEY_PATTERN.fullmatch(key) is None
        ):
            raise ValueError("invalid idempotency claim")
        item = (operation, key)
        with self._lock:
            if item in self._keys:
                return False
            if len(self._keys) >= self._max_entries:
                raise IdempotencyCapacityError("idempotency_store_full")
            self._keys.add(item)
            return True
