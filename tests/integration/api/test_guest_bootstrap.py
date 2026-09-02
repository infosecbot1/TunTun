from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi.routing import APIRoute
from tuntun_contracts.budget import BudgetReconciliationRequest
from tuntun_contracts.ports import TurnInput, TurnOutput
from tuntun_contracts.reachy import SafetyReceipt
from tuntun_core.api.app import create_app
from tuntun_core.api.dependencies import SimulatedGuestAppDependencies
from tuntun_core.bootstrap.container import ProductionContainer
from tuntun_core.services.sessions.manager import SessionAdmission, SessionRejected
from tuntun_core.services.sessions.manager import SessionManager as RealSessionManager
from tuntun_core.services.sessions.turn_coordinator import TurnCoordinator
from tuntun_testing.fake_clock import FakeClock


class _Readiness:
    def __init__(self) -> None:
        self.calls = 0
        self.error: BaseException | None = None

    def require_ready(self) -> None:
        self.calls += 1
        if self.error is not None:
            raise self.error


class _Budget:
    def __init__(self) -> None:
        self.reconciliations: list[BudgetReconciliationRequest] = []

    async def reconcile_turn(
        self,
        request: BudgetReconciliationRequest,
    ) -> tuple[()]:
        self.reconciliations.append(request)
        return ()


class _Reachy:
    def __init__(self) -> None:
        self.stopped_turns: list[UUID | None] = []

    async def stop_all(self, turn_id: UUID | None) -> SafetyReceipt:
        self.stopped_turns.append(turn_id)
        return SafetyReceipt(
            turn_id=turn_id,
            playback_stopped=True,
            motion_stopped=True,
            buffers_cleared=True,
        )


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


class _CompletedAudio:
    async def consume_once(self, turn: TurnInput) -> bytes:
        del turn
        return b"RIFFsynthetic"


class _Ports:
    def __init__(self) -> None:
        self.events: list[str] = []

    async def start(self, turn_id: UUID) -> None:
        del turn_id
        self.events.append("ports.start")

    async def transcribe(self, wav_bytes: bytes) -> str:
        assert wav_bytes == b"RIFFsynthetic"
        self.events.append("ports.transcribe")
        return "namaste"

    async def guest_identity(self) -> str:
        self.events.append("ports.identity")
        return "Guest"

    async def generate(self, transcript: str, identity: str) -> str:
        assert (transcript, identity) == ("namaste", "Guest")
        self.events.append("ports.generate")
        return "namaste ji"

    async def synthesize(self, answer: str) -> bytes:
        assert answer == "namaste ji"
        self.events.append("ports.synthesize")
        return b"pcm"

    async def play(self, turn_id: UUID, pcm: bytes) -> None:
        del turn_id
        assert pcm == b"pcm"
        self.events.append("ports.play")

    async def finish(self, turn_id: UUID) -> None:
        del turn_id
        self.events.append("ports.finish")


class _Startup:
    def __init__(self, process_lease: object) -> None:
        self.process_lease = process_lease


class _Lifecycle:
    def __init__(self, reconciler: object, startup_recovery: _Startup) -> None:
        self.reconciler = reconciler
        self.startup_recovery = startup_recovery
        self.ready = True
        self.calls = 0

    def require_ready(self) -> None:
        self.calls += 1
        if not self.ready:
            raise RuntimeError("private lifecycle detail")


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
        openapi = await client.get("/openapi.json")
        docs = await client.get("/docs")
        slash_redirect = await client.get("/health/ready/")

    assert openapi.status_code == 404
    assert openapi.headers["Cache-Control"] == "no-store"
    assert docs.status_code == 404
    assert docs.headers["Cache-Control"] == "no-store"
    assert slash_redirect.status_code == 404
    assert slash_redirect.headers["Cache-Control"] == "no-store"


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
async def test_validation_errors_are_bounded_no_store_and_never_echo_private_input() -> None:
    deps, session, workflow, _readiness = _dependencies()
    transport = httpx.ASGITransport(app=create_app(deps), client=("127.0.0.1", 42_000))
    private = "private-audio-transcript-prompt-sentinel"
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/session/simulated-turn",
            json={"audio": private, "transcript": private, "prompt": private},
        )

    assert response.status_code == 422
    assert response.json() == {"status": "invalid"}
    assert response.headers["Cache-Control"] == "no-store"
    assert private not in response.text
    assert session.opens == []
    assert workflow.turns == []


@pytest.mark.asyncio
async def test_oversized_empty_request_is_rejected_before_fastapi_body_parsing() -> None:
    deps, session, workflow, _readiness = _dependencies()
    transport = httpx.ASGITransport(app=create_app(deps), client=("127.0.0.1", 42_000))
    private = "private-large-body-sentinel"
    body = ('{"audio":"' + private + ("x" * 5_000) + '"}').encode("utf-8")
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/session/simulated-turn",
            content=body,
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 413
    assert response.json() == {"status": "too_large"}
    assert response.headers["Cache-Control"] == "no-store"
    assert private not in response.text
    assert session.opens == []
    assert workflow.turns == []


@pytest.mark.asyncio
async def test_non_loopback_invalid_body_is_rejected_before_validation_or_readiness() -> None:
    deps, session, workflow, readiness = _dependencies()
    transport = httpx.ASGITransport(app=create_app(deps), client=("192.0.2.10", 42_000))
    private = "private-invalid-body-sentinel"
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/session/simulated-turn",
            json={"audio": private},
            headers={"X-Forwarded-For": "127.0.0.1"},
        )

    assert response.status_code == 403
    assert response.json() == {"status": "forbidden"}
    assert response.headers["Cache-Control"] == "no-store"
    assert private not in response.text
    assert readiness.calls == 0
    assert session.opens == []
    assert workflow.turns == []


@pytest.mark.asyncio
async def test_non_loopback_health_is_rejected_before_readiness() -> None:
    deps, _session, _workflow, readiness = _dependencies()
    transport = httpx.ASGITransport(app=create_app(deps), client=("192.0.2.10", 42_000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/health/ready")

    assert response.status_code == 403
    assert response.json() == {"status": "forbidden"}
    assert response.headers["Cache-Control"] == "no-store"
    assert readiness.calls == 0


@pytest.mark.asyncio
async def test_simulated_turn_checks_readiness_before_session_admission() -> None:
    deps, session, workflow, readiness = _dependencies()
    readiness.error = RuntimeError("private readiness detail")
    transport = httpx.ASGITransport(app=create_app(deps), client=("127.0.0.1", 42_000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/session/simulated-turn", json={})

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}
    assert response.headers["Cache-Control"] == "no-store"
    assert "private readiness detail" not in response.text
    assert readiness.calls == 1
    assert session.opens == []
    assert workflow.turns == []


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
    assert response.headers["Cache-Control"] == "no-store"
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


@pytest.mark.asyncio
async def test_production_container_installs_single_guest_app_with_existing_roots() -> None:
    reachy = _Reachy()
    coordinator = TurnCoordinator(
        budget=_Budget(),
        reachy=reachy,
        clock=FakeClock(datetime(2026, 8, 27, tzinfo=UTC)),
    )
    session_manager = RealSessionManager(coordinator)
    process_lease = object()
    startup = _Startup(process_lease)
    reconciler = object()
    lifecycle = _Lifecycle(reconciler, startup)
    container = ProductionContainer(
        core=object(),  # type: ignore[arg-type]
        core_process_lease=process_lease,  # type: ignore[arg-type]
        budget_reconciler=reconciler,  # type: ignore[arg-type]
        startup_turn_recovery=startup,  # type: ignore[arg-type]
        budget_lifecycle=lifecycle,  # type: ignore[arg-type]
        turn_coordinator=coordinator,
        session_manager=session_manager,
    )
    ports = _Ports()
    installed = container.install_simulated_guest_app(
        ports=ports,
        completed_audio=_CompletedAudio(),
        household_id=uuid4(),
        device_id=uuid4(),
        loopback_host="127.0.0.1",
    )

    assert installed.composition.workflow is installed.composition.dependencies.workflow
    assert installed.coordinator is coordinator
    assert installed.session_manager is session_manager
    assert installed.readiness_dependencies == (lifecycle,)
    assert installed.route_ids == ("health.ready", "session.simulated_turn")
    assert installed.duplicate_route_ids == frozenset()
    assert installed.listener_bindings == frozenset({"loopback"})

    transport = httpx.ASGITransport(
        app=installed.composition.app,
        client=("127.0.0.1", 42_000),
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/session/simulated-turn", json={})

    assert response.status_code == 200
    assert response.json()["outcome"] == "completed"
    assert reachy.stopped_turns
    assert ports.events == [
        "ports.start",
        "ports.transcribe",
        "ports.identity",
        "ports.generate",
        "ports.synthesize",
        "ports.play",
        "ports.finish",
    ]
    with pytest.raises(RuntimeError, match="simulated_guest_app_already_installed"):
        container.install_simulated_guest_app(
            ports=ports,
            completed_audio=_CompletedAudio(),
            household_id=uuid4(),
            device_id=uuid4(),
            loopback_host="127.0.0.1",
        )
