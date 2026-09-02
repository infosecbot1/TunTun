from __future__ import annotations

from fastapi import FastAPI
from tuntun_core.api.dependencies import SimulatedGuestAppDependencies
from tuntun_core.api.routes.health import register_health_route
from tuntun_core.api.routes.session import register_session_route


def create_app(dependencies: SimulatedGuestAppDependencies) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    register_health_route(app, dependencies)
    register_session_route(app, dependencies)
    return app
