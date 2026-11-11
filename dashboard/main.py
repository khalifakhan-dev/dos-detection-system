from __future__ import annotations

import argparse
import threading
import tkinter.messagebox as messagebox
from queue import Empty, Queue
from typing import Any

import customtkinter as ctk

from dashboard.api_client import ApiClient
from dashboard.time_format import format_timestamp


class Dashboard(ctk.CTk):
    def __init__(self, client: ApiClient):
        super().__init__()
        self.client = client
        self.title("DoS Detection and Mitigation Dashboard")
        self.geometry("1100x720")
        self.queue: Queue[tuple[str, Any]] = Queue()
        self.refresh_ms = 2000
        self._refresh_in_progress = False
        self._closing = False
        self._shown_alerts: set[tuple[str, str]] = set()
        self._popup: ctk.CTkToplevel | None = None
        self._popup_key: tuple[str, str] | None = None
        self._poll_timer = None
        self._queue_timer = None
        self._build_ui()
        self._queue_timer = self.after(100, self._consume_queue)
        self._poll_timer = self.after(200, self._poll)
        self.protocol("WM_DELETE_WINDOW", self._close)

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
        tabs.add("Active Blocks")
        for name in ("Active Incidents", "Active Blocks"):
            tabs.tab(name).grid_rowconfigure(0, weight=1)
            tabs.tab(name).grid_columnconfigure(0, weight=1)
        self.incidents_box = ctk.CTkTextbox(tabs.tab("Active Incidents"), font=("Consolas", 12))
        self.incidents_box.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")
        self.blocks_box = ctk.CTkTextbox(tabs.tab("Active Blocks"), font=("Consolas", 12))
        self.blocks_box.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")

        controls = ctk.CTkFrame(self)
        controls.grid(row=3, column=0, padx=12, pady=8, sticky="ew")
        self.mode_label = ctk.CTkLabel(controls, text="Mitigation: MANUAL", font=ctk.CTkFont(weight="bold"))
        self.mode_label.grid(row=0, column=0, padx=8, pady=8)
        self.mode_switch = ctk.CTkSwitch(controls, text="Automatic mode", command=self._toggle_mode)
        self.mode_switch.grid(row=0, column=1, padx=8, pady=8)
        self.ip_entry = ctk.CTkEntry(controls, placeholder_text="IPv4 address")
        self.ip_entry.grid(row=1, column=0, padx=8, pady=8)
        ctk.CTkButton(controls, text="Unblock IP", command=self.unblock_ip).grid(row=1, column=1, padx=8, pady=8)
        ctk.CTkButton(controls, text="Permanent Block", command=self.permanent_block).grid(row=1, column=2, padx=8, pady=8)
        ctk.CTkButton(controls, text="Refresh Now", command=self.refresh).grid(row=1, column=3, padx=8, pady=8)

    def _poll(self) -> None:
        if self._closing:
            return
        self.refresh()
        self._poll_timer = self.after(self.refresh_ms, self._poll)

    def refresh(self) -> None:
        if self._closing or self._refresh_in_progress:
            return
        self._refresh_in_progress = True
        threading.Thread(target=self._load_data, daemon=True).start()

    def _close(self) -> None:
        self._closing = True
        for timer in (self._poll_timer, self._queue_timer):
            if timer is not None:
                self.after_cancel(timer)
        self.destroy()

    def _load_data(self) -> None:
        try:
            self.queue.put(("data", {"status": self.client.status(), "incidents": self.client.incidents(active_only=True), "blocks": self.client.blocks(), "live_alerts": self.client.live_alerts()}))
        except Exception as exc:
            self.queue.put(("error", str(exc)))
        finally:
            self._refresh_in_progress = False

    def _consume_queue(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "mode":
                    if payload[1]:
                        messagebox.showerror("Mode change failed", payload[1])
                        self.refresh()
                    else:
                        self.refresh()
                elif kind == "action":
                    action, ip, result, error = payload
                    if error:
                        messagebox.showerror(f"{action} failed", error)
                    else:
                        self._show_action_result(action, ip, result)
                        self.refresh()
                elif kind == "error":
                    self.status_label.configure(text=f"Disconnected: {payload}", text_color="#d9534f")
                else:
                    self._render(payload)
        except Empty:
            pass
        if not self._closing:
            self._queue_timer = self.after(100, self._consume_queue)

    def _render(self, data: dict[str, Any]) -> None:
        status = data["status"]
        health = status.get("capture_health") or {}
        capture_state = health.get("state", "UNKNOWN")
        self.status_label.configure(text=f"Connected | capture={capture_state} | dry-run={status.get('dry_run')}",
                                    text_color="#d9534f" if capture_state == "ERROR" else "#2e8b57")
        mode = status.get("mitigation_mode", "manual")
        self.mode_label.configure(text=f"Mitigation: {mode.upper()}")
        if mode == "automatic":
            self.mode_switch.select()
        else:
            self.mode_switch.deselect()
        window = status.get("latest_window") or {}
        detection = status.get("latest_detection", {})
        self.metrics_label.configure(text=(
            f"Packets/s: {window.get('total_packets', 0)}    Bytes/s: {window.get('total_bytes', 0)}    "
            f"SYN: {window.get('syn_packets', 0)}    UDP: {window.get('udp_packets', 0)}    ICMP: {window.get('icmp_packets', 0)}    "
            f"HTTP incomplete: {window.get('http_incomplete_connections', 0)}\n"
            f"Latest detection: {detection.get('attack_type') or 'Normal'}    Source: {detection.get('source_ip') or '-'}    Reason: {detection.get('reason') or '-'}"
        ))
        self._replace(self.incidents_box, "\n".join(self._format_incident(row) for row in data["incidents"]) or "No active incidents.")
        self._replace(self.blocks_box, "\n".join(self._format_block(row) for row in data["blocks"]) or "No active blocks.")
        alerts = data.get("live_alerts", [])
        keys = {(a.get("source_ip"), a.get("attack_type")) for a in alerts}
        self._shown_alerts.intersection_update(keys)
        if self._popup is None or not self._popup.winfo_exists():
            for alert in alerts:
                key = (alert.get("source_ip"), alert.get("attack_type"))
                if key not in self._shown_alerts and key[0]:
                    self._shown_alerts.add(key)
                    self._show_alert_popup(alert)
                    break


    def _toggle_mode(self) -> None:
        new_mode = "automatic" if self.mode_switch.get() else "manual"
        if new_mode == "automatic" and not messagebox.askyesno(
            "Enable automatic mitigation?",
            "Automatically block detected attacking IPs for 5 minutes?\n"
            "Dry-run mode will only simulate blocks."):
            self.mode_switch.deselect()
            return
        def worker() -> None:
            try:
                self.client.set_mode(new_mode)
                self.queue.put(("mode", (new_mode, None)))
            except Exception as exc:
                self.queue.put(("mode", (new_mode, str(exc))))
        threading.Thread(target=worker, daemon=True).start()

    def _show_alert_popup(self, alert: dict[str, Any]) -> None:
        ip, attack_type = alert["source_ip"], alert["attack_type"]
        self._popup_key = (ip, attack_type)
        popup = ctk.CTkToplevel(self)
        self._popup = popup
        popup.title("Potential attack detected")
        popup.geometry("520x345")
        popup.transient(self)  # Non-modal: the dashboard continues refreshing.
        popup.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(popup, text="POTENTIAL ATTACK DETECTED", font=ctk.CTkFont(size=19, weight="bold"), text_color="#f59e0b").grid(row=0, column=0, padx=18, pady=(18, 8))
        details = (f"Attack: {attack_type}\nSource IP: {ip}\nSeverity: {alert.get('severity', '-')}\n"
                   f"Reason: {alert.get('reason', '-')}\nObserved: {alert.get('observed', {})}\n"
                   f"Threshold: {alert.get('threshold', {})}")
        ctk.CTkLabel(popup, text=details, justify="left", wraplength=475).grid(row=1, column=0, padx=18, pady=12, sticky="w")
        buttons = ctk.CTkFrame(popup)
        buttons.grid(row=2, column=0, pady=12)
        def take_action(action: str) -> None:
            popup.destroy()
            self._popup = None
            if action == "block":
                self._admin_action("Permanent block", ip, lambda: self.client.permanent_block(ip))
            else:
                self._admin_action("Ignore alert", ip, lambda: self.client.ignore_alert(ip, attack_type))
        ctk.CTkButton(buttons, text="Block IP", fg_color="#b91c1c", command=lambda: take_action("block")).grid(row=0, column=0, padx=10, pady=10)
        ctk.CTkButton(buttons, text="Ignore", command=lambda: take_action("ignore")).grid(row=0, column=1, padx=10, pady=10)
        popup.protocol("WM_DELETE_WINDOW", lambda: take_action("ignore"))

    @staticmethod
    def _replace(widget: ctk.CTkTextbox, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    @staticmethod
    def _format_alert(row: dict[str, Any]) -> str:
        return f"[{format_timestamp(row.get('timestamp'))}] {row.get('severity')} {row.get('attack_type')} from {row.get('source_ip')} | {row.get('reason')}"

    @staticmethod
    def _format_incident(row: dict[str, Any]) -> str:
        return f"{row.get('status', 'active').upper()} | {row.get('attack_type')} | source={row.get('source_ip') or 'uncertain'} | first={format_timestamp(row.get('first_seen'))} | last={format_timestamp(row.get('last_seen'))}"

    @staticmethod
    def _format_block(row: dict[str, Any]) -> str:
        if row.get("dry_run"):
            state = "SIMULATED (dry-run; no real firewall change)"
        elif row.get("status") == "active":
            state = "REAL FIREWALL BLOCK ACTIVE"
        else:
            state = f"REAL FIREWALL {str(row.get('status', 'unknown')).upper()}"
        return f"{row.get('ip')} | {state} | mode={row.get('mode')} | expires={format_timestamp(row.get('expires_at'))} | reason={row.get('reason')}"

    def _get_ip(self) -> str | None:
        value = self.ip_entry.get().strip()
        if not value:
            messagebox.showwarning("Missing IP", "Enter an IPv4 address first.")
            return None
        return value

    def _admin_action(self, action: str, ip: str, operation: Any) -> None:
        def worker() -> None:
            try:
                result = operation()
                self.queue.put(("action", (action, ip, result, None)))
            except Exception as exc:
                self.queue.put(("action", (action, ip, None, str(exc))))
        threading.Thread(target=worker, daemon=True).start()

    def unblock_ip(self) -> None:
        ip = self._get_ip()
        if ip and messagebox.askyesno("Confirm unblock", f"Unblock {ip}?"):
            self._admin_action("Unblock", ip, lambda: self.client.unblock(ip))

    def permanent_block(self) -> None:
        ip = self._get_ip()
        if ip and messagebox.askyesno("Confirm permanent block", f"Keep {ip} blocked until manually unblocked?"):
            self._admin_action("Permanent block", ip, lambda: self.client.permanent_block(ip))

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
