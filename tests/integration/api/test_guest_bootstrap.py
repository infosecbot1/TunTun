from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi.routing import APIRoute
from tuntun_contracts.budget import BudgetReconciliationRequest
from tuntun_contracts.identity import IdentityDecision, IdentityStatus, PersonaProjection
from tuntun_contracts.ports import TurnInput, TurnOutput
from tuntun_contracts.reachy import SafetyReceipt
from tuntun_core.api.app import create_app
from tuntun_core.api.dependencies import SimulatedGuestAppDependencies
from tuntun_core.bootstrap.container import ProductionContainer
from tuntun_core.services.personalized_turn_context import ProviderTurnContext, TranscribedTurn
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
        self.error: BaseException | None = None

    async def run(self, turn: TurnInput) -> TurnOutput:
        self.turns.append(turn)
        if self.error is not None:
            raise self.error
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

    async def transcribe(self, wav_bytes: bytes) -> TranscribedTurn:
        assert wav_bytes == b"RIFFsynthetic"
        self.events.append("ports.transcribe")
        return TranscribedTurn(text="namaste", stt_language="hi")

    async def guest_identity(self) -> str:
        raise AssertionError("production route must not use legacy guest identity")

    async def generate(self, context: ProviderTurnContext) -> str:
        assert "Reply in Romanized Hindi" in context.messages[0]["content"]
        assert context.messages[1]["content"] == "namaste"
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


class _Core:
    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock


class _Identity:
    def __init__(self, subject_id: UUID) -> None:
        self.subject_id = subject_id

    async def require_current_for_turn(self, turn_id: UUID) -> IdentityDecision:
        del turn_id
        return IdentityDecision(
            status=IdentityStatus.VERIFIED,
            subject_id=self.subject_id,
            reason_code="test-verified",
            expires_at=datetime(2026, 8, 27, 0, 5, tzinfo=UTC),
        )


class _Profiles:
    async def get_persona_projection(
        self,
        household_id: UUID,
        subject_id: UUID | None,
        observed_at: datetime,
    ) -> PersonaProjection:
        assert type(household_id) is UUID
        assert type(subject_id) is UUID
        assert observed_at == datetime(2026, 8, 27, tzinfo=UTC)
        return PersonaProjection(
            role="guest",
            context="general",
            tone="neutral",
            depth="brief",
            learning_level="none",
        )


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


_PRIVATE_INVALID_BODY = b'{"audio":"private"}'
_MAX_ASGI_BODY_BYTES = 4096


async def _asgi_exchange(
    app,
    *,
    client_host: str,
    headers: tuple[tuple[bytes, bytes], ...],
    messages: tuple[dict[str, object], ...],
    raw_headers: object | None = None,
) -> tuple[int, dict[bytes, bytes], bytes, int]:
    sent: list[dict[str, object]] = []
    receive_calls = 0
    pending = list(messages)

    async def receive() -> dict[str, object]:
        nonlocal receive_calls
        receive_calls += 1
        if pending:
            return pending.pop(0)
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/session/simulated-turn",
            "raw_path": b"/session/simulated-turn",
            "query_string": b"",
            "headers": raw_headers if raw_headers is not None else list(headers),
            "client": (client_host, 42_000),
            "server": ("testserver", 80),
        },
        receive,
        send,
    )
    start = next(message for message in sent if message["type"] == "http.response.start")
    body = b"".join(
        message.get("body", b"") for message in sent if message["type"] == "http.response.body"
    )
    return int(start["status"]), dict(start["headers"]), body, receive_calls


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
@pytest.mark.parametrize(
    ("headers", "messages", "expected_status", "expected_body", "expected_receive_calls"),
    (
        (
            (),
            ({"type": "http.request", "body": _PRIVATE_INVALID_BODY},),
            422,
            b'{"status":"invalid"}',
            1,
        ),
        (
            ((b"transfer-encoding", b"chunked"),),
            (
                {"type": "http.request", "body": b'{"audio":"pri', "more_body": True},
                {"type": "http.request", "body": b'vate"}', "more_body": False},
            ),
            422,
            b'{"status":"invalid"}',
            2,
        ),
        (
            ((b"content-length", str(_MAX_ASGI_BODY_BYTES).encode("ascii")),),
            ({"type": "http.request", "body": b"x" * _MAX_ASGI_BODY_BYTES},),
            422,
            b'{"status":"invalid"}',
            1,
        ),
        (
            (),
            (
                {"type": "http.request", "body": b"x" * _MAX_ASGI_BODY_BYTES, "more_body": True},
                {"type": "http.request", "body": b"y", "more_body": False},
            ),
            413,
            b'{"status":"too_large"}',
            2,
        ),
        (
            ((b"content-length", b"2"),),
            (
                {"type": "http.request", "body": b"x" * 2048, "more_body": True},
                {"type": "http.request", "body": b"y" * 2049, "more_body": False},
            ),
            413,
            b'{"status":"too_large"}',
            2,
        ),
        (
            (
                (b"CoNtEnT-LeNgTh", str(len(_PRIVATE_INVALID_BODY)).encode("ascii")),
                (
                    b"content-length",
                    str(len(_PRIVATE_INVALID_BODY)).zfill(3).encode("ascii"),
                ),
            ),
            ({"type": "http.request", "body": _PRIVATE_INVALID_BODY},),
            422,
            b'{"status":"invalid"}',
            1,
        ),
    ),
)
async def test_asgi_boundary_counts_actual_received_body_bytes_before_validation(
    headers: tuple[tuple[bytes, bytes], ...],
    messages: tuple[dict[str, object], ...],
    expected_status: int,
    expected_body: bytes,
    expected_receive_calls: int,
) -> None:
    deps, session, workflow, _readiness = _dependencies()

    status, response_headers, body, receive_calls = await _asgi_exchange(
        create_app(deps),
        client_host="127.0.0.1",
        headers=((b"content-type", b"application/json"), *headers),
        messages=messages,
    )

    assert status == expected_status
    assert response_headers[b"cache-control"] == b"no-store"
    assert body == expected_body
    assert b"private" not in body
    assert receive_calls == expected_receive_calls
    assert session.opens == []
    assert workflow.turns == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content_length_headers",
    (
        ((b"content-length", b""),),
        ((b"content-length", b"not-an-integer"),),
        ((b"content-length", b"+2"),),
        ((b"content-length", b"-1"),),
        ((b"content-length", b"2 0"),),
        ((b"content-length", b"2,"),),
        ((b"content-length", b",2"),),
        ((b"content-length", b"2,,2"),),
        ((b"content-length", b"2,3"),),
        ((b"Content-Length", b"2"), (b"content-length", b"3")),
        ((b"content-length", str(_MAX_ASGI_BODY_BYTES + 1).encode("ascii")),),
        ((b"content-length", b"\t4097 "),),
        ((b"content-length", b"9" * 128),),
    ),
)
async def test_content_length_declaration_rejections_happen_before_body_read(
    content_length_headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    deps, session, workflow, _readiness = _dependencies()

    status, response_headers, body, receive_calls = await _asgi_exchange(
        create_app(deps),
        client_host="127.0.0.1",
        headers=((b"content-type", b"application/json"), *content_length_headers),
        messages=({"type": "http.request", "body": _PRIVATE_INVALID_BODY},),
    )

    assert status == 413
    assert response_headers[b"cache-control"] == b"no-store"
    assert body == b'{"status":"too_large"}'
    assert b"private" not in body
    assert receive_calls == 0
    assert session.opens == []
    assert workflow.turns == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw_headers",
    (
        ((b"content-length", b"2"),),
        [(b"content-length",)],
        [(b"content-length", "2")],
    ),
)
async def test_malformed_asgi_headers_fail_closed_before_body_read(raw_headers: object) -> None:
    deps, session, workflow, _readiness = _dependencies()

    status, response_headers, body, receive_calls = await _asgi_exchange(
        create_app(deps),
        client_host="127.0.0.1",
        headers=(),
        raw_headers=raw_headers,
        messages=({"type": "http.request", "body": _PRIVATE_INVALID_BODY},),
    )

    assert status == 413
    assert response_headers[b"cache-control"] == b"no-store"
    assert body == b'{"status":"too_large"}'
    assert receive_calls == 0
    assert session.opens == []
    assert workflow.turns == []


@pytest.mark.asyncio
async def test_content_length_allows_equal_numeric_duplicates_and_sp_htab_ows() -> None:
    deps, session, workflow, _readiness = _dependencies()
    body_bytes = b"{}"

    status, response_headers, body, receive_calls = await _asgi_exchange(
        create_app(deps),
        client_host="127.0.0.1",
        headers=(
            (b"content-type", b"application/json"),
            (b"CoNtEnT-LeNgTh", b" 2,\t002 "),
            (b"content-length", b"2"),
        ),
        messages=({"type": "http.request", "body": body_bytes},),
    )

    assert status == 200
    assert response_headers[b"cache-control"] == b"no-store"
    expected_body = (
        b'{"turn_id":"'
        + str(workflow.turns[0].turn_id).encode("ascii")
        + b'","outcome":"completed"}'
    )
    assert body == expected_body
    assert receive_calls == 1
    assert session.opens == [(deps.household_id, workflow.turns[0].turn_id)]


@pytest.mark.asyncio
async def test_non_loopback_asgi_boundary_rejects_before_any_body_read() -> None:
    deps, session, workflow, readiness = _dependencies()
    status, response_headers, body, receive_calls = await _asgi_exchange(
        create_app(deps),
        client_host="192.0.2.10",
        headers=((b"content-type", b"application/json"), (b"content-length", b"2,3")),
        messages=({"type": "http.request", "body": b'{"audio":"private"}'},),
    )

    assert status == 403
    assert response_headers[b"cache-control"] == b"no-store"
    assert body == b'{"status":"forbidden"}'
    assert receive_calls == 0
    assert readiness.calls == 0
    assert session.opens == []
    assert workflow.turns == []


@pytest.mark.asyncio
async def test_unexpected_workflow_failure_is_bounded_no_store_500() -> None:
    deps, _session, workflow, _readiness = _dependencies()
    workflow.error = RuntimeError("private workflow failure sentinel")
    transport = httpx.ASGITransport(
        app=create_app(deps),
        client=("127.0.0.1", 42_000),
        raise_app_exceptions=False,
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/session/simulated-turn", json={})

    assert response.status_code == 500
    assert response.headers["Cache-Control"] == "no-store"
    assert "private workflow failure sentinel" not in response.text


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
    clock = FakeClock(datetime(2026, 8, 27, tzinfo=UTC))
    coordinator = TurnCoordinator(
        budget=_Budget(),
        reachy=reachy,
        clock=clock,
    )
    session_manager = RealSessionManager(coordinator)
    process_lease = object()
    startup = _Startup(process_lease)
    reconciler = object()
    lifecycle = _Lifecycle(reconciler, startup)
    container = ProductionContainer(
        core=_Core(clock),  # type: ignore[arg-type]
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
        identity=_Identity(uuid4()),
        profiles=_Profiles(),
    )

    assert installed.composition.workflow is installed.composition.dependencies.workflow
    assert installed.composition.context_provider is not None
    assert installed.composition.linear_engine is not None
    assert (
        installed.composition.linear_engine.context_provider
        is installed.composition.context_provider
    )
    assert not hasattr(installed.composition, "langgraph_engine")
    assert installed.coordinator is coordinator
    assert installed.session_manager is session_manager
    assert installed.readiness_dependencies == (lifecycle,)
    assert type(installed.route_ids) is set
    assert installed.route_ids == {"health.ready", "session.simulated_turn"}
    assert type(installed.duplicate_route_ids) is tuple
    assert installed.duplicate_route_ids == ()
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
            identity=_Identity(uuid4()),
            profiles=_Profiles(),
        )
