from __future__ import annotations

import ipaddress
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel


class Runtime:
    service: Any = None
    config: dict[str, Any] = {}


runtime = Runtime()
app = FastAPI(title="DoS Detection and Mitigation API", version="1.0.0")


class ActionRequest(BaseModel):
    reason: str = "Dashboard administrator action"


def require_token(authorization: str | None = Header(default=None)) -> None:
    expected = runtime.config.get("api", {}).get("token", "")
    if not expected:
        return
    if authorization != f"Bearer {expected}":
        raise HTTPException(status_code=401, detail="Invalid or missing API token")


def valid_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid IP address") from exc


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/status")
def status(_: None = Depends(require_token)) -> dict[str, Any]:
    if runtime.service is None:
        return {"running": False, "detail": "Detector runtime has not been initialised"}
    return runtime.service.status()


@app.get("/api/metrics")
def metrics(limit: int = Query(60, ge=1, le=500), _: None = Depends(require_token)) -> list[dict[str, Any]]:
    return runtime.service.database.latest_metrics(limit) if runtime.service else []


@app.get("/api/alerts")
def alerts(limit: int = Query(50, ge=1, le=500), _: None = Depends(require_token)) -> list[dict[str, Any]]:
    return runtime.service.database.alerts(limit) if runtime.service else []


@app.get("/api/blocks")
def blocks(active_only: bool = True, _: None = Depends(require_token)) -> list[dict[str, Any]]:
    return runtime.service.database.blocks(active_only) if runtime.service else []


@app.get("/api/events")
def events(limit: int = Query(100, ge=1, le=500), _: None = Depends(require_token)) -> list[dict[str, Any]]:
    return runtime.service.database.events(limit) if runtime.service else []


@app.post("/api/blocks/{ip}/unblock")
def unblock(ip: str, _: ActionRequest | None = None, __: None = Depends(require_token)) -> dict[str, Any]:
    address = valid_ip(ip)
    if runtime.service is None:
        raise HTTPException(status_code=503, detail="Detector runtime unavailable")
    return runtime.service.manual_unblock(address)


@app.post("/api/blocks/{ip}/permanent")
def permanent(ip: str, request: ActionRequest | None = None, _: None = Depends(require_token)) -> dict[str, Any]:
    address = valid_ip(ip)
    if runtime.service is None:
        raise HTTPException(status_code=503, detail="Detector runtime unavailable")
    return runtime.service.permanent_block(address, request.reason if request else "Dashboard administrator action")


@app.post("/api/blocks/unblock-all")
def unblock_all(_: None = Depends(require_token)) -> dict[str, Any]:
    if runtime.service is None:
        raise HTTPException(status_code=503, detail="Detector runtime unavailable")
    return runtime.service.unblock_all()
