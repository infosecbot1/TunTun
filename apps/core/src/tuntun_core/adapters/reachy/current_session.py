from __future__ import annotations

import asyncio
import math
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from uuid import UUID

from tuntun_contracts.reachy_wire import FramePurpose


@dataclass(frozen=True, slots=True)
class _CurrentAuthenticatedSession:
    device_id: UUID
    session: object


class CoreDisconnectSafetyFacade:
    """Concrete Core facade used by the transport when a Reachy session drops."""

    def __init__(
        self,
        *,
        active_turn_id: Callable[[], UUID | None],
        cancel_turn: Callable[[UUID, str], Awaitable[None]],
    ) -> None:
        self._active_turn_id = active_turn_id
        self._cancel_turn = cancel_turn
        self._latched_reasons: tuple[str, ...] = ()
        self.error_safe_latched = False

    @property
    def latched_reasons(self) -> tuple[str, ...]:
        return self._latched_reasons

    def latch_error_safe(self, reason: str) -> None:
        if type(reason) is not str or not reason:
            raise ValueError("disconnect_safety_reason_required")
        self.error_safe_latched = True
        self._latched_reasons = tuple(dict.fromkeys((*self._latched_reasons, reason)))

    async def close_media_stop_playback_motion_and_forget_turn(self) -> None:
        self.latch_error_safe("disconnect")
        turn_id = self._active_turn_id()
        if turn_id is None:
            return
        if type(turn_id) is not UUID:
            raise TypeError("active_turn_id must be an exact UUID")
        try:
            await self._cancel_turn(turn_id, "disconnect")
        except BaseException as error:
            if isinstance(error, Exception):
                self.latch_error_safe(f"disconnect_safety:{type(error).__name__}")
            raise


class CurrentReachySessionChannel:
    """Single authenticated Reachy session pointer, with no stale replay."""

    def __init__(self, *, safety: CoreDisconnectSafetyFacade) -> None:
        if type(safety) is not CoreDisconnectSafetyFacade:
            raise TypeError("core disconnect safety facade required")
        self._safety = safety
        self._lock = asyncio.Lock()
        self._ready = asyncio.Event()
        self._current: _CurrentAuthenticatedSession | None = None
        self._readiness_withdrawn = True
        self._publication_open = True
        self._draining = False
        self._generation = 0

    @property
    def safety(self) -> CoreDisconnectSafetyFacade:
        return self._safety

    def require_ready(self) -> None:
        if self._current is None or self._readiness_withdrawn or self._draining:
            raise RuntimeError("reachy_authenticated_session_unavailable")

    def withdraw_readiness(self) -> None:
        self._readiness_withdrawn = True
        self._ready.clear()

    async def open_publication_generation(self) -> None:
        async with self._lock:
            self._current = None
            self._readiness_withdrawn = True
            self._publication_open = True
            self._draining = False
            self._generation += 1
            self._ready.clear()

    async def begin_shutdown_drain(self) -> None:
        async with self._lock:
            self._publication_open = False
            self._draining = True
            self._readiness_withdrawn = True
            self._ready.clear()

    async def withdraw_authority(self) -> None:
        async with self._lock:
            self._current = None
            self._readiness_withdrawn = True
            self._publication_open = False
            self._draining = False
            self._generation += 1
            self._ready.clear()

    async def publish(self, device_id: UUID, session: object) -> None:
        if type(device_id) is not UUID:
            raise TypeError("device_id must be an exact UUID")
        if session is None:
            raise TypeError("authenticated Reachy session required")
        async with self._lock:
            if not self._publication_open or self._draining:
                raise RuntimeError("reachy_session_publication_closed")
            current = self._current
            if current is not None:
                if current.device_id == device_id and current.session is session:
                    self._readiness_withdrawn = False
                    self._ready.set()
                    return
                raise RuntimeError("reachy_authenticated_session_already_published")
            self._current = _CurrentAuthenticatedSession(device_id=device_id, session=session)
            self._readiness_withdrawn = False
            self._ready.set()

    async def clear(self, device_id: UUID, session: object) -> None:
        if type(device_id) is not UUID:
            raise TypeError("device_id must be an exact UUID")
        async with self._lock:
            current = self._current
            if current is None:
                return
            if current.device_id != device_id or current.session is not session:
                raise RuntimeError("reachy_authenticated_session_identity_mismatch")
            self._current = None
            self._readiness_withdrawn = True
            self._generation += 1
            self._ready.clear()

    async def current_session(self) -> object | None:
        async with self._lock:
            current = self._current
            if current is None:
                return None
            if self._readiness_withdrawn or self._draining:
                return None
            return current.session

    async def wait_authenticated(self, timeout: float) -> None:
        timeout_seconds = _bounded_timeout(timeout)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_seconds
        while True:
            async with self._lock:
                if (
                    self._current is not None
                    and not self._readiness_withdrawn
                    and not self._draining
                ):
                    return
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise RuntimeError("reachy_authenticated_session_unavailable")
            try:
                await asyncio.wait_for(self._ready.wait(), timeout=remaining)
            except TimeoutError as error:
                raise RuntimeError("reachy_authenticated_session_unavailable") from error

    async def exchange_signed(self, *, purpose: FramePurpose, payload: bytes) -> bytes:
        async with self._lock:
            current = self._current
            if current is None:
                raise RuntimeError("reachy_authenticated_session_unavailable")
            final_stop = purpose == "reachy.stop_all.v1"
            if self._draining and not final_stop:
                raise RuntimeError("reachy_authenticated_session_unavailable")
            if self._readiness_withdrawn and not (self._draining and final_stop):
                raise RuntimeError("reachy_authenticated_session_unavailable")
            session = current.session
            generation = self._generation
        exchange = getattr(session, "exchange_signed", None)
        if not callable(exchange):
            raise TypeError("authenticated Reachy session exchange unavailable")
        body = await exchange(purpose=purpose, payload=payload)
        async with self._lock:
            current = self._current
            if current is None or current.session is not session or self._generation != generation:
                raise RuntimeError("reachy_authenticated_session_unavailable")
            if self._draining and purpose != "reachy.stop_all.v1":
                raise RuntimeError("reachy_authenticated_session_unavailable")
            if self._readiness_withdrawn and not (
                self._draining and purpose == "reachy.stop_all.v1"
            ):
                raise RuntimeError("reachy_authenticated_session_unavailable")
        if type(body) is not bytes:
            raise TypeError("authenticated Reachy session response must be bytes")
        return body


def _bounded_timeout(value: float) -> float:
    if type(value) not in {float, int}:
        raise TypeError("reachy_session_ready_timeout_invalid")
    timeout = float(value)
    if not math.isfinite(timeout) or timeout <= 0 or timeout > 30:
        raise ValueError("reachy_session_ready_timeout_invalid")
    return timeout


__all__ = ("CoreDisconnectSafetyFacade", "CurrentReachySessionChannel")
