from __future__ import annotations

import hmac
import ipaddress
from typing import Any, Callable

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel

from mitigation.block_policy import ProtectedAddressError


class Runtime:
    service: Any = None
    config: dict[str, Any] = {}


runtime = Runtime()
app = FastAPI(title="DoS Detection and Mitigation API", version="1.0.0")


class ActionRequest(BaseModel):
    reason: str = "Dashboard administrator action"


def require_token(authorization: str | None = Header(default=None)) -> None:
    expected = runtime.config.get("api", {}).get("token", "")
    if not expected:  # fail closed: an unset token must never mean "no authentication"
        raise HTTPException(status_code=503, detail="API token is not configured on the server")
    if not hmac.compare_digest((authorization or "").encode(), f"Bearer {expected}".encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing API token")


def valid_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid IP address") from exc
    if address.version != 4:
        raise HTTPException(status_code=400, detail="Only IPv4 addresses are supported")
    return str(address)


def _call(action: Callable[..., dict[str, Any]], *args: Any) -> dict[str, Any]:
    if runtime.service is None:
        raise HTTPException(status_code=503, detail="Detector runtime unavailable")
    try:
        return action(*args)
    except ProtectedAddressError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


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


@app.get("/api/incidents")
def incidents(active_only: bool = False, limit: int = Query(100, ge=1, le=500), _: None = Depends(require_token)) -> list[dict[str, Any]]:
    return runtime.service.database.incidents(active_only, limit) if runtime.service else []


@app.post("/api/blocks/{ip}/unblock")
def unblock(ip: str, _: ActionRequest | None = None, __: None = Depends(require_token)) -> dict[str, Any]:
    address = valid_ip(ip)
    return _call(lambda: runtime.service.manual_unblock(address))


@app.post("/api/blocks/{ip}/permanent")
def permanent(ip: str, request: ActionRequest | None = None, _: None = Depends(require_token)) -> dict[str, Any]:
    address = valid_ip(ip)
    reason = request.reason if request else "Dashboard administrator action"
    return _call(lambda: runtime.service.permanent_block(address, reason))


@app.post("/api/blocks/unblock-all")
def unblock_all(_: None = Depends(require_token)) -> dict[str, Any]:
    return _call(lambda: runtime.service.unblock_all())
