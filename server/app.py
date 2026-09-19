"""
server/app.py
Central Telemetry Server entrypoint. Wires REST routers + WebSocket
gateway, initializes the database on startup, and serves the static
SecOps dashboard.

Run:
    uvicorn server.app:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .database import init_db
from .routes import alerts, endpoints, ws

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("edr.server")

# Propagate the enrollment token from env into the ws module so agent
# connections can be authenticated against it.
ws.VALID_ENROLLMENT_TOKEN = os.environ.get("EDR_ENROLLMENT_TOKEN", "change-me-in-production")

app = FastAPI(
    title="Micro-EDR Central Telemetry Server",
    description="Ingestion, correlation, and SecOps dashboard backend for the "
                "Autonomous Micro-EDR & Automated Incident Response Engine.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(endpoints.router)
app.include_router(alerts.router)
app.include_router(ws.router)

_dashboard_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard")
if os.path.isdir(_dashboard_dir):
    app.mount("/dashboard", StaticFiles(directory=_dashboard_dir, html=True), name="dashboard")


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    logger.info("Micro-EDR Telemetry Server started. DB initialized.")


@app.get("/")
def root():
    return {
        "service": "Micro-EDR Central Telemetry Server",
        "status": "operational",
        "dashboard": "/dashboard",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {"status": "ok"}
