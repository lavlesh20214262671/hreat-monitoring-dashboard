from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .routes import alerts_router, logs_router, metrics_router

app = FastAPI(title="Threat Monitoring Dashboard")

app.include_router(metrics_router)
app.include_router(alerts_router)
app.include_router(logs_router)

_STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(_STATIC_DIR / "index.html")
