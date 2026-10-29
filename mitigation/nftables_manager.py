from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_ABSENT_MARKERS = ("No such file or directory", "does not exist")


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
            return {"success": True, "dry_run": True, "simulated": True, "command": args}
        completed = subprocess.run(args, capture_output=True, text=True, check=False)
        return {
            "success": completed.returncode == 0,
            "dry_run": False,
            "simulated": False,
            "returncode": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
            "command": args,
        }

    def ensure_ruleset(self) -> dict[str, Any]:
        """Create table/set/chain and the drop rule exactly once (safe to call on every start)."""
        base = [
            ["nft", "add", "table", "inet", self.TABLE],
            ["nft", "add", "set", "inet", self.TABLE, self.SET, "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}"],
            ["nft", "add", "chain", "inet", self.TABLE, "input", "{", "type", "filter", "hook", "input", "priority", "-100", ";", "policy", "accept", ";", "}"],
        ]
        results = [self._run(command) for command in base]
        listing = self._run(["nft", "list", "chain", "inet", self.TABLE, "input"])
        results.append(listing)
        # `nft add rule` always appends, so only add the drop rule when it is missing.
        if "@" + self.SET not in listing.get("stdout", ""):
            results.append(self._run(["nft", "add", "rule", "inet", self.TABLE, "input", "ip", "saddr", "@" + self.SET, "drop"]))
        return {"success": all(result.get("success", False) or "File exists" in result.get("stderr", "") for result in results), "results": results}

    def block(self, ip: str, timeout_seconds: int | None = None) -> dict[str, Any]:
        address = self.validate_ip(ip)
        if self.dry_run:
            self._dry_run_blocks.add(address)
            return {"success": True, "dry_run": True, "simulated": True, "action": "block", "ip": address, "timeout_seconds": timeout_seconds}
        element = [address] if not timeout_seconds else [address, "timeout", f"{int(timeout_seconds)}s"]
        result = self._run(["nft", "add", "element", "inet", self.TABLE, self.SET, "{", *element, "}"])
        result.update({"action": "block", "ip": address, "timeout_seconds": timeout_seconds})
        return result

    def unblock(self, ip: str) -> dict[str, Any]:
        address = self.validate_ip(ip)
        if self.dry_run:
            self._dry_run_blocks.discard(address)
            return {"success": True, "dry_run": True, "simulated": True, "action": "unblock", "ip": address}
        result = self._run(["nft", "delete", "element", "inet", self.TABLE, self.SET, "{", address, "}"])
        # nft expires timed elements itself, and a reboot/flush empties the set: an
        # element that is already gone is the desired end state, not a failure.
        if not result["success"] and any(marker in result.get("stderr", "") for marker in _ABSENT_MARKERS):
            result.update({"success": True, "already_absent": True})
        result.update({"action": "unblock", "ip": address})
        return result

    def unblock_all(self) -> dict[str, Any]:
        if self.dry_run:
            self._dry_run_blocks.clear()
            return {"success": True, "dry_run": True, "simulated": True, "action": "unblock-all"}
        return self._run(["nft", "flush", "set", "inet", self.TABLE, self.SET])

    def is_blocked(self, ip: str) -> bool:
        address = self.validate_ip(ip)
        if self.dry_run:
            return address in self._dry_run_blocks
        completed = subprocess.run(["nft", "list", "set", "inet", self.TABLE, self.SET], capture_output=True, text=True, check=False)
        # Exact element match: "192.0.2.5" must not match "192.0.2.55".
        return completed.returncode == 0 and address in set(_IPV4.findall(completed.stdout))
