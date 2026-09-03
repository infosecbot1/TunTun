from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(slots=True)
class _Lifecycle:
    start_attempted: bool = False
    played: bool = False


class TurnLifecycleRegistry:
    """Process-local control flags; neither content nor checkpoint state."""

    def __init__(self) -> None:
        self._items: dict[UUID, _Lifecycle] = {}

    def begin(self, turn_id: UUID) -> None:
        _require_uuid(turn_id)
        if turn_id in self._items:
            raise RuntimeError("turn lifecycle already exists")
        self._items[turn_id] = _Lifecycle()

    def mark_start_attempted(self, turn_id: UUID) -> None:
        self._require(turn_id).start_attempted = True

    def mark_played(self, turn_id: UUID) -> None:
        self._require(turn_id).played = True

    def snapshot(self, turn_id: UUID) -> tuple[bool, bool]:
        item = self._require(turn_id)
        return item.start_attempted, item.played

    def clear(self, turn_id: UUID) -> None:
        _require_uuid(turn_id)
        self._items.pop(turn_id, None)

    def discard(self, turn_id: UUID) -> None:
        """Independent terminal-cleanup fallback for content-free flags."""

        _require_uuid(turn_id)
        self._items.pop(turn_id, None)

    def contains(self, turn_id: UUID) -> bool:
        _require_uuid(turn_id)
        return turn_id in self._items

    def count(self) -> int:
        return len(self._items)

    def _require(self, turn_id: UUID) -> _Lifecycle:
        _require_uuid(turn_id)
        try:
            return self._items[turn_id]
        except KeyError:
            raise RuntimeError("turn lifecycle missing") from None

    def __repr__(self) -> str:
        return f"{type(self).__name__}(active={len(self._items)})"


def _require_uuid(value: object) -> None:
    if type(value) is not UUID:
        raise TypeError("turn_id must be an exact UUID")


__all__ = ["TurnLifecycleRegistry"]
