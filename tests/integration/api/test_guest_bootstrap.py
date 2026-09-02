from __future__ import annotations

from uuid import UUID, uuid4

import httpx
import pytest
from fastapi.routing import APIRoute
from tuntun_contracts.ports import TurnInput, TurnOutput
from tuntun_core.api.app import create_app
from tuntun_core.api.dependencies import SimulatedGuestAppDependencies
from tuntun_core.services.sessions.manager import SessionAdmission, SessionRejected


class _Readiness:
    def __init__(self) -> None:
        self.calls = 0
        self.error: BaseException | None = None

    def require_ready(self) -> None:
        self.calls += 1
        if self.error is not None:
            raise self.error


class _SessionManager:
    def __init__(self) -> None:
        self.opens: list[tuple[UUID, UUID]] = []
        self.rejection: SessionRejected | None = None

    async def open(self, household_id: UUID, turn_id: UUID) -> SessionAdmission:
        self.opens.append((household_id, turn_id))
        if self.rejection is not None:
            raise self.rejection
        return SessionAdmission(household_id=household_id, turn_id=turn_id)


class _Workflow:
    def __init__(self) -> None:
        self.turns: list[TurnInput] = []
        self.outcome = "completed"

    async def run(self, turn: TurnInput) -> TurnOutput:
        self.turns.append(turn)
        return TurnOutput(turn_id=turn.turn_id, outcome=self.outcome)


def _dependencies() -> tuple[SimulatedGuestAppDependencies, _SessionManager, _Workflow, _Readiness]:
    readiness = _Readiness()
    session = _SessionManager()
    workflow = _Workflow()
    deps = SimulatedGuestAppDependencies(
        session_manager=session,
        workflow=workflow,
        household_id=uuid4(),
        device_id=uuid4(),
        loopback_host="127.0.0.1",
        readiness_dependencies=(readiness,),
    )
    return deps, session, workflow, readiness


def _owned_route_names(app) -> set[str]:
    return {route.name for route in app.router.routes if isinstance(route, APIRoute)}


@pytest.mark.asyncio
async def test_installed_guest_app_has_only_first_owned_routes() -> None:
    deps, _session, _workflow, _readiness = _dependencies()
    app = create_app(deps)

    assert _owned_route_names(app) == {"health.ready", "session.simulated_turn"}
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 42_000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        assert (await client.get("/openapi.json")).status_code == 404
        assert (await client.get("/docs")).status_code == 404


@pytest.mark.asyncio
async def test_ready_route_checks_dependencies_each_time_and_never_caches() -> None:
    deps, _session, _workflow, readiness = _dependencies()
    transport = httpx.ASGITransport(app=create_app(deps), client=("127.0.0.1", 42_000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        first = await client.get("/health/ready")
        readiness.error = RuntimeError("private unhealthy detail")
        second = await client.get("/health/ready")

    assert first.status_code == 200
    assert first.json() == {"status": "ready"}
    assert first.headers["Cache-Control"] == "no-store"
    assert second.status_code == 503
    assert second.json() == {"status": "unavailable"}
    assert "private unhealthy detail" not in second.text
    assert readiness.calls == 2


@pytest.mark.asyncio
async def test_simulated_turn_is_empty_loopback_only_and_uses_server_side_identity() -> None:
    deps, session, workflow, _readiness = _dependencies()
    transport = httpx.ASGITransport(app=create_app(deps), client=("127.0.0.1", 42_000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        rejected = await client.post(
            "/session/simulated-turn",
            json={"household_id": str(uuid4()), "audio": "synthetic-user-content"},
        )
        accepted = await client.post("/session/simulated-turn", json={})

    assert rejected.status_code == 422
    assert accepted.status_code == 200
    assert accepted.headers["Cache-Control"] == "no-store"
    body = accepted.json()
    assert body == {"turn_id": str(workflow.turns[0].turn_id), "outcome": "completed"}
    assert session.opens == [(deps.household_id, workflow.turns[0].turn_id)]
    assert workflow.turns == [
        TurnInput(
            turn_id=workflow.turns[0].turn_id,
            household_id=deps.household_id,
            device_id=deps.device_id,
        )
    ]


@pytest.mark.asyncio
async def test_simulated_turn_ignores_forwarded_headers_and_requires_exact_loopback_peer() -> None:
    deps, session, workflow, _readiness = _dependencies()
    transport = httpx.ASGITransport(app=create_app(deps), client=("192.0.2.10", 42_000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/session/simulated-turn",
            json={},
            headers={"X-Forwarded-For": "127.0.0.1"},
        )

    assert response.status_code == 403
    assert response.json() == {"status": "forbidden"}
    assert session.opens == []
    assert workflow.turns == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("reason", "status_code", "body"),
    (
        ("busy", 409, {"status": "busy"}),
        ("safety_blocked", 503, {"status": "unavailable"}),
    ),
)
async def test_simulated_turn_maps_admission_rejections_to_content_free_bodies(
    reason: str,
    status_code: int,
    body: dict[str, str],
) -> None:
    deps, session, workflow, _readiness = _dependencies()
    session.rejection = SessionRejected(reason=reason, retry_after_ms=None)  # type: ignore[arg-type]
    transport = httpx.ASGITransport(app=create_app(deps), client=("127.0.0.1", 42_000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/session/simulated-turn", json={})

    assert response.status_code == status_code
    assert response.json() == body
    assert response.headers["Cache-Control"] == "no-store"
    assert workflow.turns == []
