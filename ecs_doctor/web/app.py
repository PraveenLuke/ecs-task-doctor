
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

_HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(_HERE / "templates"))


def create_app() -> FastAPI:
    app = FastAPI(title="ECS Doctor", version="0.3.0", docs_url="/api/docs")

    app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")

    from ecs_doctor.web.routes import diagnose as diagnose_router
    from ecs_doctor.web.routes import health as health_router
    from ecs_doctor.web.routes import stream as stream_router

    app.include_router(health_router.router)
    app.include_router(diagnose_router.router)
    app.include_router(stream_router.router)

    return app
