from __future__ import annotations

from typing import Any

import requests


class ApiClient:
    def __init__(self, base_url: str, token: str, timeout: float = 3.0):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.timeout = timeout

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        response = requests.request(method, f"{self.base_url}{path}", headers=self.headers, timeout=self.timeout, **kwargs)
        response.raise_for_status()
        return response.json()

    def status(self) -> dict[str, Any]:
        return self._request("GET", "/api/status")

    def metrics(self, limit: int = 60) -> list[dict[str, Any]]:
        return self._request("GET", f"/api/metrics?limit={limit}")

    def alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._request("GET", f"/api/alerts?limit={limit}")

    def blocks(self) -> list[dict[str, Any]]:
        return self._request("GET", "/api/blocks?active_only=true")

    def unblock(self, ip: str) -> dict[str, Any]:
        return self._request("POST", f"/api/blocks/{ip}/unblock", json={})

    def permanent_block(self, ip: str) -> dict[str, Any]:
        return self._request("POST", f"/api/blocks/{ip}/permanent", json={"reason": "Windows dashboard administrator action"})
