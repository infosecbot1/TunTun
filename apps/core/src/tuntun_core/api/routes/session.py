from __future__ import annotations

from uuid import uuid4

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from tuntun_contracts.ports import TurnInput
from tuntun_core.api.dependencies import SimulatedGuestAppDependencies
from tuntun_core.services.sessions.manager import SessionRejected


class SimulatedTurnRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SimulatedEndRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _no_store_json(content: dict[str, str], *, status_code: int) -> JSONResponse:
    return JSONResponse(
        content,
        status_code=status_code,
        headers={"Cache-Control": "no-store"},
    )


def register_session_route(app: FastAPI, dependencies: SimulatedGuestAppDependencies) -> None:
    async def simulated_turn(
        payload: SimulatedTurnRequest,
    ) -> JSONResponse:
        del payload
        try:
            dependencies.require_ready()
        except BaseException:
            return _no_store_json({"status": "unavailable"}, status_code=503)
        turn_id = uuid4()
        try:
            admission = await dependencies.session_manager.open(
                dependencies.household_id,
                turn_id,
                context_session_id=dependencies.context_session_id,
            )
        except SessionRejected as error:
            if error.reason == "busy":
                return _no_store_json({"status": "busy"}, status_code=409)
            return _no_store_json({"status": "unavailable"}, status_code=503)
        if (
            admission.household_id != dependencies.household_id
            or admission.turn_id != turn_id
            or admission.context_session_id != dependencies.context_session_id
        ):
            return _no_store_json({"status": "unavailable"}, status_code=503)
        output = await dependencies.workflow.run(
            TurnInput(
                turn_id=turn_id,
                household_id=dependencies.household_id,
                device_id=dependencies.device_id,
            )
        )
        return _no_store_json(
            {"turn_id": str(output.turn_id), "outcome": output.outcome},
            status_code=200,
        )

    async def simulated_end(
        payload: SimulatedEndRequest,
    ) -> JSONResponse:
        del payload
        try:
            dependencies.require_ready()
            await dependencies.end_context_session()
        except Exception:
            return _no_store_json({"status": "unavailable"}, status_code=503)
        return _no_store_json({"status": "ended"}, status_code=200)

    app.add_api_route(
        "/session/simulated-turn",
        simulated_turn,
        methods=["POST"],
        name="session.simulated_turn",
    )
    app.add_api_route(
        "/session/simulated-end",
        simulated_end,
        methods=["POST"],
        name="session.simulated_end",
    )
