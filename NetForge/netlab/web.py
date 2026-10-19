"""Minimal FastAPI backend for NetLab."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from netlab.core import Engine, require_admin

app = FastAPI(
    title="NetLab",
    description="Educational network attack lab platform",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = Engine()


class RunRequest(BaseModel):
    module: str
    parameters: dict[str, Any] = {}
    rate_limit_pps: float | None = None


@app.get("/api/modules")
def list_modules() -> list[dict[str, Any]]:
    return engine.list_modules()


@app.get("/api/modules/{name}")
def get_module(name: str) -> dict[str, Any]:
    modules = {m["name"]: m for m in engine.list_modules()}
    if name not in modules:
        raise HTTPException(status_code=404, detail="Module not found")
    return modules[name]


@app.post("/api/run")
def run_module(req: RunRequest) -> dict[str, Any]:
    # Note: in production this should be background task + job id
    require_admin()
    try:
        logger = engine.run_module(
            req.module,
            req.parameters,
            rate_limit_pps=req.rate_limit_pps,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {
        "status": logger.status,
        "packets_sent": logger.packets_sent,
        "bytes_sent": logger.bytes_sent,
        "log_file": str(logger.path) if logger.path else None,
    }


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
