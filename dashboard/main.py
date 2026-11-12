from __future__ import annotations

import argparse
import threading
import tkinter as tk
import tkinter.messagebox as messagebox
from collections import deque
from datetime import datetime
from queue import Empty, Queue
from typing import Any

import customtkinter as ctk

from dashboard.api_client import ApiClient
from dashboard.time_format import format_timestamp

BG = '#0b1020'
PANEL = '#151e31'
INNER = '#10192b'
TEXT = '#e6edf8'
MUTED = '#94a3b8'
ACCENT = '#38bdf8'
GREEN = '#34d399'
RED = '#fb7185'
AMBER = '#fbbf24'


class Sparkline(ctk.CTkFrame):
    """Tk canvas plot: no extra chart dependency and no synthetic traffic data."""
    def __init__(self, parent: Any, title: str, unit: str, color: str):
        super().__init__(parent, fg_color=PANEL, corner_radius=14)
        self.color, self.unit = color, unit
        self.samples: deque[float] = deque(maxlen=90)
        ctk.CTkLabel(self, text=title, font=ctk.CTkFont(size=14, weight='bold'), text_color=TEXT).pack(anchor='w', padx=16, pady=(12, 0))
        self.value = ctk.CTkLabel(self, text=f'0 {unit}', font=ctk.CTkFont(size=24, weight='bold'), text_color=color)
        self.value.pack(anchor='w', padx=16)
        self.canvas = tk.Canvas(self, height=112, bg=PANEL, highlightthickness=0)
        self.canvas.pack(fill='both', expand=True, padx=12, pady=(0, 10))
        self.canvas.bind('<Configure>', lambda _e: self.draw())

    def append(self, value: float) -> None:
        self.samples.append(max(0.0, value))
        self.value.configure(text=f'{value:,.0f} {self.unit}')
        self.draw()

    def draw(self) -> None:
        c = self.canvas
        c.delete('all')
        w, h = max(c.winfo_width(), 20), max(c.winfo_height(), 20)
        for fraction in (0.25, 0.5, 0.75):
            y = int(h * fraction)
            c.create_line(0, y, w, y, fill='#253148', dash=(3, 5))
        vals = list(self.samples)
        if not vals:
            return
        max_value = max(max(vals) * 1.15, 1.0)
        points = []
        for i, value in enumerate(vals):
            x = 3 + (w - 6) * i / max(1, len(vals) - 1)
            y = h - 7 - (h - 16) * value / max_value
            points.extend((x, y))
        if len(points) >= 4:
            c.create_line(*points, fill=self.color, width=2.5, smooth=True)
        else:
            c.create_oval(points[0]-2, points[1]-2, points[0]+2, points[1]+2, fill=self.color, outline='')


class Dashboard(ctk.CTk):
    def __init__(self, client: ApiClient):
        super().__init__(fg_color=BG)
        self.client = client
        self.title('Sentinel | DoS Detection & Mitigation')
        self.geometry('1330x850')
        self.minsize(1060, 720)
        self.queue: Queue[tuple[str, Any]] = Queue()
        self._closing = False
        self._busy = False
        self._poll_id = None
        self._queue_id = None
        self._popup: ctk.CTkToplevel | None = None
        self._popup_key: tuple[str, str] | None = None
        self._seen: set[tuple[str, str]] = set()
        self._last_timestamp: str | None = None
        self._last_detection: dict[str, Any] = {}
        self._mode_change_pending = False
        self._build()
        self._queue_id = self.after(100, self._consume)
        self._poll_id = self.after(200, self._poll)
        self.protocol('WM_DELETE_WINDOW', self._close)

    def _label(self, parent: Any, text: str, size: int = 13, color: str = TEXT, bold: bool = False) -> ctk.CTkLabel:
        return ctk.CTkLabel(parent, text=text, text_color=color, font=ctk.CTkFont(size=size, weight='bold' if bold else 'normal'), anchor='w')

    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        head = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=12)
        head.grid(row=0, column=0, sticky='ew', padx=16, pady=(14, 8))
        head.grid_columnconfigure(0, weight=1)
        self._label(head, '◈  SENTINEL   /   DoS Detection & Mitigation', 22, TEXT, True).grid(row=0, column=0, sticky='w', padx=20, pady=(14, 0))
        self._label(head, 'LIVE SECURITY OPERATIONS  •  AUTHORIZED LAB MONITORING', 11, MUTED).grid(row=1, column=0, sticky='w', padx=20, pady=(0, 14))
        self.connection = self._label(head, 'CONNECTING', 12, AMBER, True)
        self.connection.grid(row=0, column=1, rowspan=2, padx=20)

        body = ctk.CTkScrollableFrame(self, fg_color='transparent')
        body.grid(row=1, column=0, sticky='nsew', padx=10)
        body.grid_columnconfigure((0, 1), weight=1)

        cards = ctk.CTkFrame(body, fg_color='transparent')
        cards.grid(row=0, column=0, columnspan=2, sticky='ew', padx=6, pady=6)
        for col in range(4):
            cards.grid_columnconfigure(col, weight=1)
        self.cards = {}
        for col, (key, title, color) in enumerate((('capture','CAPTURE STATUS', GREEN), ('attack','THREAT STATUS', AMBER), ('mode','MITIGATION MODE', ACCENT), ('sources','SOURCE IPs', TEXT))):
            frame = ctk.CTkFrame(cards, fg_color=PANEL, corner_radius=12)
            frame.grid(row=0, column=col, sticky='ew', padx=5)
            self._label(frame, title, 11, MUTED, True).pack(anchor='w', padx=16, pady=(12, 0))
            value = self._label(frame, '—', 19, color, True)
            value.pack(anchor='w', padx=16, pady=(4, 14))
            self.cards[key] = value

        self.packet_plot = Sparkline(body, 'PACKET RATE  •  last 90 samples', 'pkt/s', ACCENT)
        self.packet_plot.grid(row=1, column=0, sticky='nsew', padx=10, pady=8)
        self.byte_plot = Sparkline(body, 'BANDWIDTH  •  last 90 samples', 'B/s', GREEN)
        self.byte_plot.grid(row=1, column=1, sticky='nsew', padx=10, pady=8)

        proto = ctk.CTkFrame(body, fg_color=PANEL, corner_radius=12)
        proto.grid(row=2, column=0, columnspan=2, sticky='ew', padx=10, pady=8)
        proto.grid_columnconfigure((0,1,2,3), weight=1)
        self.protocols = {}
        for col, (key, title) in enumerate((('syn_packets','TCP SYN'), ('udp_packets','UDP'), ('icmp_packets','ICMP'), ('http_incomplete_connections','HTTP INCOMPLETE'))):
            cell = ctk.CTkFrame(proto, fg_color=INNER, corner_radius=10)
            cell.grid(row=0, column=col, sticky='ew', padx=8, pady=10)
            self._label(cell, title, 11, MUTED, True).pack(anchor='w', padx=14, pady=(9, 0))
            value = self._label(cell, '0', 23, TEXT, True)
            value.pack(anchor='w', padx=14, pady=(0, 9))
            self.protocols[key] = value

        self.detection = self._label(body, 'LATEST DETECTION   •   Awaiting live traffic', 13, MUTED)
        self.detection.grid(row=3, column=0, columnspan=2, sticky='ew', padx=18, pady=(8, 5))

        left = ctk.CTkFrame(body, fg_color=PANEL, corner_radius=12)
        right = ctk.CTkFrame(body, fg_color=PANEL, corner_radius=12)
        left.grid(row=4, column=0, sticky='nsew', padx=10, pady=8)
        right.grid(row=4, column=1, sticky='nsew', padx=10, pady=8)
        for panel in (left, right):
            panel.grid_columnconfigure(0, weight=1)
        self._label(left, 'TOP LIVE SOURCES  •  current capture window', 14, TEXT, True).grid(row=0, column=0, sticky='w', padx=14, pady=(12, 4))
        self.sources_box = ctk.CTkTextbox(left, height=154, fg_color=INNER, text_color=TEXT, font=('Consolas', 12))
        self.sources_box.grid(row=1, column=0, sticky='nsew', padx=12, pady=(0, 12))
        self._label(right, 'ACTIVE INCIDENTS  •  automatically resolve', 14, TEXT, True).grid(row=0, column=0, sticky='w', padx=14, pady=(12, 4))
        self.incidents_box = ctk.CTkTextbox(right, height=154, fg_color=INNER, text_color=TEXT, font=('Consolas', 12))
        self.incidents_box.grid(row=1, column=0, sticky='nsew', padx=12, pady=(0, 12))

        blocks = ctk.CTkFrame(body, fg_color=PANEL, corner_radius=12)
        blocks.grid(row=5, column=0, columnspan=2, sticky='ew', padx=10, pady=8)
        blocks.grid_columnconfigure(0, weight=1)
        self._label(blocks, 'ACTIVE BLOCKS  •  simulated blocks are explicitly marked', 14, TEXT, True).grid(row=0, column=0, sticky='w', padx=14, pady=(12, 4))
        self.blocks_box = ctk.CTkTextbox(blocks, height=86, fg_color=INNER, text_color=TEXT, font=('Consolas', 12))
        self.blocks_box.grid(row=1, column=0, sticky='ew', padx=12, pady=(0, 12))

        footer = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=12)
        footer.grid(row=2, column=0, sticky='ew', padx=16, pady=(8, 14))
        self.mode_switch = ctk.CTkSwitch(footer, text='AUTOMATIC MITIGATION', command=self._toggle, progress_color=ACCENT)
        self.mode_switch.grid(row=0, column=0, padx=16, pady=14)
        self.dry_run = self._label(footer, 'DRY-RUN UNKNOWN', 11, AMBER, True)
        self.dry_run.grid(row=0, column=1, padx=12)
        self.ip_entry = ctk.CTkEntry(footer, placeholder_text='IPv4 address', width=170)
        self.ip_entry.grid(row=0, column=2, padx=(12, 5))
        ctk.CTkButton(footer, text='Block IP', width=100, fg_color='#b91c1c', command=self.permanent_block).grid(row=0, column=3, padx=5)
        ctk.CTkButton(footer, text='Unblock IP', width=100, command=self.unblock_ip).grid(row=0, column=4, padx=5)
        ctk.CTkButton(footer, text='Refresh', width=90, fg_color='#334155', command=self.refresh).grid(row=0, column=5, padx=(5, 16))
        footer.grid_columnconfigure(1, weight=1)

    @staticmethod
    def _replace(widget: ctk.CTkTextbox, text: str) -> None:
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('1.0', text)
        widget.configure(state='disabled')

    def _poll(self) -> None:
        if not self._closing:
            self.refresh()
            self._poll_id = self.after(1500, self._poll)

    def refresh(self) -> None:
        if self._closing or self._busy:
            return
        self._busy = True
        threading.Thread(target=self._fetch, daemon=True).start()

    def _fetch(self) -> None:
        try:
            data = {'status': self.client.status(), 'incidents': self.client.incidents(active_only=True),
                    'blocks': self.client.blocks(), 'alerts': self.client.live_alerts()}
            self.queue.put(('data', data))
        except Exception as exc:
            self.queue.put(('error', str(exc)))
        finally:
            self._busy = False

    def _consume(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == 'data':
                    self._render(payload)
                elif kind == 'error':
                    self.connection.configure(text='DISCONNECTED', text_color=RED)
                elif kind == 'mode':
                    self._mode_change_pending = False
                    if payload:
                        messagebox.showerror('Mode change failed', payload)
                    self.refresh()
                elif kind == 'action':
                    action, ip, result, error, popup_key = payload
                    if popup_key and not error and result and result.get('success'):
                        if self._popup_key == popup_key:
                            self._dismiss_popup()
                    if error:
                        messagebox.showerror(f'{action} failed', error)
                        if popup_key and self._popup_key == popup_key:
                            for button in self._popup_buttons:
                                button.configure(state='normal')
                    elif result.get('expired'):
                        pass  # Stale alert was already resolved; not an operational failure.
                    elif not result.get('success'):
                        messagebox.showerror(f'{action} failed', str(result.get('error') or result.get('stderr') or 'Server rejected action'))
                        if popup_key and self._popup_key == popup_key:
                            for button in self._popup_buttons:
                                button.configure(state='normal')
                    elif result.get('simulated') or result.get('dry_run'):
                        messagebox.showwarning('Simulation only', f'{action}: {ip}\nNo firewall changes were made.')
                    else:
                        messagebox.showinfo('Success', f'{action}: {ip}')
                    self.refresh()
        except Empty:
            pass
        if not self._closing:
            self._queue_id = self.after(100, self._consume)

    def _render(self, data: dict[str, Any]) -> None:
        status = data['status']
        health = status.get('capture_health') or {}
        state = health.get('state', 'UNKNOWN')
        self.connection.configure(text=f"●  API CONNECTED  /  {state}", text_color=RED if state == 'ERROR' else GREEN)
        self.cards['capture'].configure(text=state)
        mode = status.get('mitigation_mode', 'manual')
        self.cards['mode'].configure(text=mode.upper())
        if not self._mode_change_pending:
            self.mode_switch.select() if mode == 'automatic' else self.mode_switch.deselect()
        dry_run = bool(status.get('dry_run', True))
        self.dry_run.configure(text='● SIMULATION ONLY' if dry_run else '● REAL FIREWALL ACTIVE', text_color=AMBER if dry_run else GREEN)
        window = status.get('latest_window') or {}
        timestamp = window.get('timestamp')
        self.cards['sources'].configure(text=str(window.get('unique_source_ips', 0)))
        if timestamp and timestamp != self._last_timestamp:
            self._last_timestamp = timestamp
            duration = max(float(window.get('duration_seconds') or 1), 0.001)
            self.packet_plot.append(float(window.get('total_packets') or 0) / duration)
            self.byte_plot.append(float(window.get('total_bytes') or 0) / duration)
        for key, label in self.protocols.items():
            label.configure(text=f"{int(window.get(key) or 0):,}")
        detection = status.get('latest_detection') or {}
        if detection.get('detected'):
            self._last_detection = {**detection, 'timestamp': timestamp}
        threat = 'ATTACK DETECTED' if detection.get('detected') else 'NORMAL'
        self.cards['attack'].configure(text=threat, text_color=RED if detection.get('detected') else GREEN)
        last = self._last_detection
        if last:
            self.detection.configure(text=f"LAST DETECTED  •  {last.get('attack_type')}  •  {last.get('source_ip') or 'source uncertain'}  •  {format_timestamp(last.get('timestamp'))}", text_color=AMBER)
        else:
            self.detection.configure(text='LATEST DETECTION  •  No attacks observed in this session', text_color=MUTED)
        stats = window.get('source_stats') or {}
        ranked = sorted(stats.items(), key=lambda row: row[1].get('packets', 0), reverse=True)[:12]
        lines = ['SOURCE IP                 PKTS     SYN     UDP    ICMP']
        for ip, row in ranked:
            lines.append(f"{ip:<23} {int(row.get('packets',0)):>5} {int(row.get('syn_packets',0)):>7} {int(row.get('udp_packets',0)):>7} {int(row.get('icmp_packets',0)):>7}")
        self._replace(self.sources_box, '\n'.join(lines) if ranked else 'No packets in the current capture window.')
        incidents = data['incidents']
        self._replace(self.incidents_box, '\n'.join(f"{r.get('attack_type')}  |  {r.get('source_ip') or 'uncertain'}\n  last: {format_timestamp(r.get('last_seen'))}" for r in incidents) or 'No active incidents.')
        blocks = data['blocks']
        self._replace(self.blocks_box, '\n'.join(f"{r.get('ip')}  |  {'SIMULATED' if r.get('dry_run') else 'REAL BLOCK'}  |  {r.get('mode')}  |  expires: {format_timestamp(r.get('expires_at')) if r.get('expires_at') else 'manual unblock'}" for r in blocks) or 'No active blocks.')
        blocked_ips = {row.get('ip') for row in blocks}
        alerts = [a for a in (data.get('alerts') or []) if a.get('source_ip') not in blocked_ips]
        keys = {(a.get('source_ip'), a.get('attack_type')) for a in alerts}
        self._seen.intersection_update(keys)
        if self._popup and self._popup.winfo_exists() and self._popup_key not in keys:
            self._dismiss_popup()  # Explicitly resolved elsewhere, blocked, or mode changed.
        if self._popup and self._popup.winfo_exists() and self._popup_key in keys:
            current = next(a for a in alerts if (a.get('source_ip'), a.get('attack_type')) == self._popup_key)
            self._popup_state.configure(text='● ATTACK ONGOING' if current.get('ongoing', True) else '● ATTACK ENDED — decision still pending',
                                        text_color=RED if current.get('ongoing', True) else AMBER)
        if mode == 'automatic':
            if self._popup and self._popup.winfo_exists():
                self._dismiss_popup()
            return  # Automatic mode reports via incidents/blocks; no manual-decision popups.
        if not self._popup or not self._popup.winfo_exists():
            for alert in alerts:
                key = (alert.get('source_ip'), alert.get('attack_type'))
                if key[0] and key not in self._seen:
                    self._seen.add(key)
                    self._show_popup(alert)
                    break

    def _dismiss_popup(self) -> None:
        if self._popup and self._popup.winfo_exists():
            self._popup.destroy()
        self._popup = None
        self._popup_key = None

    def _show_popup(self, alert: dict[str, Any]) -> None:
        ip, attack_type = alert['source_ip'], alert['attack_type']
        self._popup_key = (ip, attack_type)
        pop = ctk.CTkToplevel(self, fg_color=PANEL)
        self._popup = pop
        pop.title('Sentinel | Potential attack')
        pop.geometry('530x420')
        pop.transient(self)
        pop.grid_columnconfigure(0, weight=1)
        self._label(pop, '⚠  POTENTIAL ATTACK DETECTED', 20, AMBER, True).grid(row=0, column=0, padx=20, pady=(22, 12), sticky='w')
        observed = alert.get('observed') or {}
        threshold = alert.get('threshold') or {}
        lines = [f'Attack: {attack_type}', f'Source: {ip}', f'Severity: {alert.get("severity", "unknown")}',
                 f'Reason: {alert.get("reason", "-")}', '', 'OBSERVED TRAFFIC']
        lines.extend(f'  {key}: {value}' for key, value in list(observed.items())[:6])
        lines.extend(['', 'THRESHOLDS'])
        lines.extend(f'  {key}: {value}' for key, value in list(threshold.items())[:3])
        box = ctk.CTkTextbox(pop, fg_color=INNER, text_color=TEXT, font=('Consolas', 12), height=225)
        box.grid(row=1, column=0, sticky='nsew', padx=18)
        self._replace(box, '\n'.join(lines))
        buttons = ctk.CTkFrame(pop, fg_color='transparent')
        buttons.grid(row=2, column=0, pady=14)
        self._popup_state = self._label(pop, '● ATTACK ONGOING', 12, RED, True)
        self._popup_state.grid(row=3, column=0, padx=18, pady=(0, 3), sticky='w')
        self._label(pop, 'Pending until Block, Ignore or Close (Close = Ignore)', 11, MUTED).grid(row=4, column=0, padx=18, pady=(0, 8), sticky='w')
        def action(block: bool) -> None:
            if block and not messagebox.askyesno('Confirm manual block', f'Block {ip} until manually unblocked?'):
                return  # A cancelled confirmation must not discard the alert.
            block_button.configure(state='disabled')
            ignore_button.configure(state='disabled')
            if block:
                self._run_action('Block IP', ip, lambda: self.client.permanent_block(ip), popup_key=(ip, attack_type))
            else:
                self._run_action('Ignore alert', ip, lambda: self.client.ignore_alert(ip, attack_type), popup_key=(ip, attack_type))
        block_button = ctk.CTkButton(buttons, text='Block IP', fg_color='#b91c1c', command=lambda: action(True))
        block_button.pack(side='left', padx=10)
        ignore_button = ctk.CTkButton(buttons, text='Ignore', command=lambda: action(False))
        ignore_button.pack(side='left', padx=10)
        # Closing the window is an explicit dismissal, equivalent to Ignore.
        pop.protocol('WM_DELETE_WINDOW', lambda: action(False))
        self._popup_buttons = (block_button, ignore_button)

    def _toggle(self) -> None:
        mode = 'automatic' if self.mode_switch.get() else 'manual'
        if mode == 'automatic' and not messagebox.askyesno('Enable automatic mitigation?', 'Automatically block detected sources for 5 minutes?\nIn dry-run mode no firewall rules change.'):
            self.mode_switch.deselect()
            return
        self._mode_change_pending = True
        def worker() -> None:
            try:
                self.client.set_mode(mode)
                self.queue.put(('mode', None))
            except Exception as exc:
                self.queue.put(('mode', str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def _run_action(self, action: str, ip: str, fn: Any, popup_key: tuple[str, str] | None = None) -> None:
        def worker() -> None:
            try:
                self.queue.put(('action', (action, ip, fn(), None, popup_key)))
            except Exception as exc:
                self.queue.put(('action', (action, ip, None, str(exc), popup_key)))
        threading.Thread(target=worker, daemon=True).start()

    def _ip(self) -> str | None:
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning('Missing IP', 'Enter an IPv4 address.')
        return ip or None

    def permanent_block(self) -> None:
        ip = self._ip()
        if ip and messagebox.askyesno('Confirm block', f'Block {ip} until manually unblocked?'):
            self._run_action('Block IP', ip, lambda: self.client.permanent_block(ip))

    def unblock_ip(self) -> None:
        ip = self._ip()
        if ip and messagebox.askyesno('Confirm unblock', f'Unblock {ip}?'):
            self._run_action('Unblock IP', ip, lambda: self.client.unblock(ip))

    def _close(self) -> None:
        self._closing = True
        for timer in (self._poll_id, self._queue_id):
            if timer is not None:
                self.after_cancel(timer)
        self._dismiss_popup()
        self.destroy()


def main() -> None:
    parser = argparse.ArgumentParser(description='Sentinel Windows dashboard')
    parser.add_argument('--api-url', required=True)
    parser.add_argument('--token', required=True)
    args = parser.parse_args()
    ctk.set_appearance_mode('dark')
    Dashboard(ApiClient(args.api_url, args.token)).mainloop()


if __name__ == '__main__':
    main()
