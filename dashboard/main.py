from __future__ import annotations

import argparse
import threading
import tkinter.messagebox as messagebox
from queue import Empty, Queue
from typing import Any

import customtkinter as ctk

from dashboard.api_client import ApiClient


class Dashboard(ctk.CTk):
    def __init__(self, client: ApiClient):
        super().__init__()
        self.client = client
        self.title("DoS Detection and Mitigation Dashboard")
        self.geometry("1100x720")
        self.queue: Queue[tuple[str, Any]] = Queue()
        self.refresh_ms = 2000
        self._refresh_in_progress = False
        self._build_ui()
        self.after(100, self._consume_queue)
        self.after(200, self.refresh)

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        header = ctk.CTkFrame(self)
        header.grid(row=0, column=0, padx=12, pady=12, sticky="ew")
        header.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(header, text="Real-Time DoS Detection and Mitigation", font=ctk.CTkFont(size=22, weight="bold")).grid(row=0, column=0, padx=12, pady=10)
        self.status_label = ctk.CTkLabel(header, text="Connecting…")
        self.status_label.grid(row=0, column=1, padx=12, pady=10, sticky="e")

        self.metrics_label = ctk.CTkLabel(self, text="No metrics yet", justify="left", anchor="w")
        self.metrics_label.grid(row=1, column=0, padx=12, pady=(0, 8), sticky="ew")

        tabs = ctk.CTkTabview(self)
        tabs.grid(row=2, column=0, padx=12, pady=8, sticky="nsew")
        tabs.add("Active Incidents")
        tabs.add("Historical Alerts")
        tabs.add("Active Blocks")
        tabs.add("Events")
        for name in ("Active Incidents", "Historical Alerts", "Active Blocks", "Events"):
            tabs.tab(name).grid_rowconfigure(0, weight=1)
            tabs.tab(name).grid_columnconfigure(0, weight=1)
        self.incidents_box = ctk.CTkTextbox(tabs.tab("Active Incidents"), font=("Consolas", 12))
        self.incidents_box.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")
        self.alerts_box = ctk.CTkTextbox(tabs.tab("Historical Alerts"), font=("Consolas", 12))
        self.alerts_box.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")
        self.blocks_box = ctk.CTkTextbox(tabs.tab("Active Blocks"), font=("Consolas", 12))
        self.blocks_box.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")
        self.events_box = ctk.CTkTextbox(tabs.tab("Events"), font=("Consolas", 12))
        self.events_box.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")

        controls = ctk.CTkFrame(self)
        controls.grid(row=3, column=0, padx=12, pady=8, sticky="ew")
        self.ip_entry = ctk.CTkEntry(controls, placeholder_text="IPv4 address")
        self.ip_entry.grid(row=0, column=0, padx=8, pady=8)
        ctk.CTkButton(controls, text="Unblock IP", command=self.unblock_ip).grid(row=0, column=1, padx=8, pady=8)
        ctk.CTkButton(controls, text="Permanent Block", command=self.permanent_block).grid(row=0, column=2, padx=8, pady=8)
        ctk.CTkButton(controls, text="Refresh Now", command=self.refresh).grid(row=0, column=3, padx=8, pady=8)

    def refresh(self) -> None:
        if not self._refresh_in_progress:
            self._refresh_in_progress = True
            threading.Thread(target=self._load_data, daemon=True).start()
        self.after(self.refresh_ms, self.refresh)

    def _load_data(self) -> None:
        try:
            self.queue.put(("data", {"status": self.client.status(), "metrics": self.client.metrics(), "incidents": self.client.incidents(active_only=True), "alerts": self.client.alerts(), "blocks": self.client.blocks(), "events": self.client.events()}))
        except Exception as exc:
            self.queue.put(("error", str(exc)))
        finally:
            self._refresh_in_progress = False

    def _consume_queue(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "error":
                    self.status_label.configure(text=f"Disconnected: {payload}", text_color="#d9534f")
                else:
                    self._render(payload)
        except Empty:
            pass
        self.after(100, self._consume_queue)

    def _render(self, data: dict[str, Any]) -> None:
        status = data["status"]
        self.status_label.configure(text=f"Connected | capture={status.get('capture_running')} | dry-run={status.get('dry_run')}", text_color="#2e8b57")
        window = status.get("latest_window") or (data["metrics"][-1] if data["metrics"] else {})
        detection = status.get("latest_detection", {})
        self.metrics_label.configure(text=(
            f"Packets/s: {window.get('total_packets', 0)}    Bytes/s: {window.get('total_bytes', 0)}    "
            f"SYN: {window.get('syn_packets', 0)}    UDP: {window.get('udp_packets', 0)}    ICMP: {window.get('icmp_packets', 0)}    "
            f"HTTP incomplete: {window.get('http_incomplete_connections', 0)}\n"
            f"Latest detection: {detection.get('attack_type') or 'Normal'}    Source: {detection.get('source_ip') or '-'}    Reason: {detection.get('reason') or '-'}"
        ))
        self._replace(self.incidents_box, "\n".join(self._format_incident(row) for row in data["incidents"]) or "No active incidents.")
        self._replace(self.alerts_box, "\n".join(self._format_alert(row) for row in data["alerts"]) or "No historical alerts recorded.")
        self._replace(self.blocks_box, "\n".join(self._format_block(row) for row in data["blocks"]) or "No active blocks.")
        self._replace(self.events_box, "\n".join(str(row) for row in data.get("events", [])) or "No events recorded.")

    @staticmethod
    def _replace(widget: ctk.CTkTextbox, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    @staticmethod
    def _format_alert(row: dict[str, Any]) -> str:
        return f"[{row.get('timestamp')}] {row.get('severity')} {row.get('attack_type')} from {row.get('source_ip')} | {row.get('reason')}"

    @staticmethod
    def _format_incident(row: dict[str, Any]) -> str:
        return f"{row.get('status', 'active').upper()} | {row.get('attack_type')} | source={row.get('source_ip') or 'uncertain'} | first={row.get('first_seen')} | last={row.get('last_seen')}"

    @staticmethod
    def _format_block(row: dict[str, Any]) -> str:
        if row.get("dry_run"):
            state = "SIMULATED (dry-run; no real firewall change)"
        elif row.get("status") == "active":
            state = "REAL FIREWALL BLOCK ACTIVE"
        else:
            state = f"REAL FIREWALL {str(row.get('status', 'unknown')).upper()}"
        return f"{row.get('ip')} | {state} | mode={row.get('mode')} | expires={row.get('expires_at')} | reason={row.get('reason')}"

    def _get_ip(self) -> str | None:
        value = self.ip_entry.get().strip()
        if not value:
            messagebox.showwarning("Missing IP", "Enter an IPv4 address first.")
            return None
        return value

    def unblock_ip(self) -> None:
        ip = self._get_ip()
        if ip and messagebox.askyesno("Confirm unblock", f"Unblock {ip}?"):
            try:
                result = self.client.unblock(ip)
                self._show_action_result("Unblock", ip, result)
                self.refresh()
            except Exception as exc:
                messagebox.showerror("Unblock failed", str(exc))

    def permanent_block(self) -> None:
        ip = self._get_ip()
        if ip and messagebox.askyesno("Confirm permanent block", f"Keep {ip} blocked until manually unblocked?"):
            try:
                result = self.client.permanent_block(ip)
                self._show_action_result("Permanent block", ip, result)
                self.refresh()
            except Exception as exc:
                messagebox.showerror("Block failed", str(exc))

    @staticmethod
    def _show_action_result(action: str, ip: str, result: dict[str, Any]) -> None:
        if not result.get("success"):
            messagebox.showerror(f"{action} failed", result.get("stderr") or result.get("error") or "The API reported failure.")
        elif result.get("dry_run") or result.get("simulated"):
            messagebox.showwarning("Simulation only", f"{action} for {ip} was simulated (dry-run); no nftables change was made.")
        else:
            messagebox.showinfo("Success", f"{action} succeeded for {ip}.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Windows CustomTkinter dashboard")
    parser.add_argument("--api-url", required=True, help="Ubuntu API URL, e.g. http://192.168.56.20:8000")
    parser.add_argument("--token", required=True, help="API bearer token")
    args = parser.parse_args()
    app = Dashboard(ApiClient(args.api_url, args.token))
    app.mainloop()


if __name__ == "__main__":
    main()
