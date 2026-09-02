from __future__ import annotations

from uuid import UUID


class EphemeralTurnContext[T]:
    """Bounded in-process turn scratchpad; callers must clear terminal content."""

    def __init__(self) -> None:
        self._items: dict[UUID, T] = {}

    def put(self, turn_id: UUID, value: T) -> None:
        _require_uuid(turn_id, name="turn_id")
        self._items[turn_id] = value

    def get(self, turn_id: UUID) -> T:
        _require_uuid(turn_id, name="turn_id")
        return self._items[turn_id]

    def pop(self, turn_id: UUID) -> T:
        _require_uuid(turn_id, name="turn_id")
        return self._items.pop(turn_id)

    def clear(self, turn_id: UUID) -> None:
        _require_uuid(turn_id, name="turn_id")
        self._items.pop(turn_id, None)

    def contains(self, turn_id: UUID) -> bool:
        _require_uuid(turn_id, name="turn_id")
        return turn_id in self._items


def _require_uuid(value: object, *, name: str) -> None:
    if type(value) is not UUID:
        raise TypeError(f"{name} must be an exact UUID")
