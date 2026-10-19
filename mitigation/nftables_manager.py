from __future__ import annotations

import ipaddress
import logging
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


class NftablesManager:
    TABLE = "dos_guard"
    SET = "blocked_ipv4"

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self._dry_run_blocks: set[str] = set()

    @staticmethod
    def validate_ip(ip: str) -> str:
        address = ipaddress.ip_address(ip)
        if address.version != 4:
            raise ValueError("Only IPv4 addresses are supported by this laboratory MVP")
        return str(address)

    def _run(self, args: list[str]) -> dict[str, Any]:
        logger.info("nft command: %s", " ".join(args))
        if self.dry_run:
            return {"success": True, "dry_run": True, "command": args}
        completed = subprocess.run(args, capture_output=True, text=True, check=False)
        return {
            "success": completed.returncode == 0,
            "dry_run": False,
            "returncode": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
            "command": args,
        }

    def ensure_ruleset(self) -> dict[str, Any]:
        commands = [
            ["nft", "add", "table", "inet", self.TABLE],
            ["nft", "add", "set", "inet", self.TABLE, self.SET, "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}"],
            ["nft", "add", "chain", "inet", self.TABLE, "input", "{", "type", "filter", "hook", "input", "priority", "-100", ";", "policy", "accept", ";", "}"],
            ["nft", "add", "rule", "inet", self.TABLE, "input", "ip", "saddr", "@" + self.SET, "drop"],
        ]
        results = [self._run(command) for command in commands]
        # Existing ruleset objects may return errors; this is idempotent enough for the lab.
        return {"success": all(result.get("success", False) or "File exists" in result.get("stderr", "") for result in results), "results": results}

    def block(self, ip: str, timeout_seconds: int | None = None) -> dict[str, Any]:
        address = self.validate_ip(ip)
        if self.dry_run:
            self._dry_run_blocks.add(address)
            return {"success": True, "dry_run": True, "action": "block", "ip": address, "timeout_seconds": timeout_seconds}
        result = self._run(["nft", "add", "element", "inet", self.TABLE, self.SET, "{", address, "}"])
        result.update({"action": "block", "ip": address, "timeout_seconds": timeout_seconds})
        return result

    def unblock(self, ip: str) -> dict[str, Any]:
        address = self.validate_ip(ip)
        if self.dry_run:
            self._dry_run_blocks.discard(address)
            return {"success": True, "dry_run": True, "action": "unblock", "ip": address}
        result = self._run(["nft", "delete", "element", "inet", self.TABLE, self.SET, "{", address, "}"])
        result.update({"action": "unblock", "ip": address})
        return result

    def unblock_all(self) -> dict[str, Any]:
        if self.dry_run:
            self._dry_run_blocks.clear()
            return {"success": True, "dry_run": True, "action": "unblock-all"}
        return self._run(["nft", "flush", "set", "inet", self.TABLE, self.SET])

    def is_blocked(self, ip: str) -> bool:
        address = self.validate_ip(ip)
        if self.dry_run:
            return address in self._dry_run_blocks
        completed = subprocess.run(["nft", "list", "set", "inet", self.TABLE, self.SET], capture_output=True, text=True, check=False)
        return completed.returncode == 0 and address in completed.stdout
