from __future__ import annotations

from fastapi import FastAPI, Response
from tuntun_core.api.dependencies import SimulatedGuestAppDependencies


def register_health_route(app: FastAPI, dependencies: SimulatedGuestAppDependencies) -> None:
    async def ready(response: Response) -> dict[str, str]:
        response.headers["Cache-Control"] = "no-store"
        try:
            for dependency in dependencies.readiness_dependencies:
                dependency.require_ready()
        except BaseException:
            response.status_code = 503
            return {"status": "unavailable"}
        return {"status": "ready"}

    app.add_api_route("/health/ready", ready, methods=["GET"], name="health.ready")
