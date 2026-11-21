"""
Web Dashboard for Network Sniffer (Flask + Scapy)
Serves a real-time browser dashboard at http://127.0.0.1:5000 (or auto-picked port).
"""

from __future__ import annotations

import collections
import os
import socket
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, render_template_string, request

# Import our existing packet analyzer and utilities
from analyzer import parse_scapy_packet, ParsedPacket
from utils import (
    console,
    display_startup_banner,
    format_hex_ascii_dump,
    verify_system_privileges,
)

# Optional Scapy import with defensive error catching
try:
    from scapy.all import sniff
    from scapy.packet import Packet
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

app = Flask(__name__)

# In-memory thread-safe packet storage (buffer of latest 250 packets)
MAX_PACKET_BUFFER = 250
packet_buffer: collections.deque[Dict[str, Any]] = collections.deque(maxlen=MAX_PACKET_BUFFER)
packet_lock = threading.Lock()

# Thread-safe sniffer state
class SnifferState:
    def __init__(self) -> None:
        self.is_running = True
        self.is_paused = False
        self.packet_count = 0
        self.error_message: Optional[str] = None
        self.status: str = "Initializing..."
        self.interface: Optional[str] = None
        self.filter_exp: Optional[str] = None

state = SnifferState()


def find_available_port(preferred_port: int = 5000, host: str = "127.0.0.1") -> int:
    """Check if the preferred port is open; if busy, locate the next available free port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, preferred_port))
            return preferred_port
        except OSError:
            # Preferred port is occupied, ask the OS for a free ephemeral port
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_free:
                s_free.bind((host, 0))
                return s_free.getsockname()[1]


def background_sniffer_loop() -> None:
    """Worker thread that executes Scapy packet capture and stores results."""
    global state

    if not HAS_SCAPY:
        state.error_message = "Scapy library is missing. Install with: pip install scapy"
        state.status = "Error"
        print(f"\n[!] Sniffer Thread Error: {state.error_message}", file=sys.stderr)
        return

    # Check privileges
    has_admin = verify_system_privileges()
    if not has_admin:
        state.error_message = (
            "Missing Administrator / root privileges! "
            "Packet capture cannot access raw network interfaces. "
            "Please restart with Administrator or sudo rights."
        )
        state.status = "Permission Warning"
        print(f"\n[!] Sniffer Thread Warning: {state.error_message}", file=sys.stderr)

    def packet_callback(raw_pkt: Packet) -> None:
        if state.is_paused or not state.is_running:
            return

        try:
            parsed: ParsedPacket = parse_scapy_packet(raw_pkt)
            
            # Format payload preview (first 64 bytes)
            payload_hex = ""
            if parsed.payload:
                payload_hex = format_hex_ascii_dump(parsed.payload, max_bytes=64)

            record = {
                "id": state.packet_count + 1,
                "timestamp": parsed.formatted_time,
                "protocol": parsed.protocol,
                "src": parsed.src_endpoint,
                "dst": parsed.dst_endpoint,
                "length": parsed.length,
                "flags": " ".join(parsed.tcp_flags) if parsed.tcp_flags else "-",
                "summary": parsed.summary,
                "payload": payload_hex,
            }

            with packet_lock:
                state.packet_count += 1
                packet_buffer.append(record)

        except Exception as ex:
            print(f"[!] Error analyzing packet: {ex}", file=sys.stderr)

    state.status = "Listening for traffic"

    while state.is_running:
        try:
            sniff(
                prn=packet_callback,
                store=False,
                stop_filter=lambda _: not state.is_running,
            )
        except RuntimeError as rt_err:
            msg = str(rt_err)
            if "winpcap is not installed" in msg.lower():
                state.error_message = (
                    "Npcap / WinPcap is not detected on Windows! "
                    "Install Npcap from https://npcap.com/#download with WinPcap API-compatible mode enabled."
                )
            else:
                state.error_message = f"Scapy Runtime Error: {rt_err}"
            state.status = "Capture Failed"
            print(f"\n[!] Sniffer Thread Error: {state.error_message}\n", file=sys.stderr)
            break
        except PermissionError:
            state.error_message = (
                "Permission Denied: Raw packet capture requires elevated root/admin privileges."
            )
            state.status = "Access Denied"
            print(f"\n[!] Sniffer Thread Error: {state.error_message}\n", file=sys.stderr)
            break
        except Exception as e:
            state.error_message = f"Capture loop error: {e}"
            state.status = "Error"
            print(f"\n[!] Sniffer Thread Exception: {e}\n", file=sys.stderr)
            time.sleep(2)


# =====================================================================
# HTML Dashboard Template (Single-file, responsive, with dark mode)
# =====================================================================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PyNetSniffer - Live Web Dashboard</title>
    <style>
        :root {
            --bg-main: #0f172a;
            --bg-card: #1e293b;
            --border: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-blue: #38bdf8;
            --accent-green: #4ade80;
            --accent-yellow: #facc15;
            --accent-red: #f87171;
            --accent-purple: #c084fc;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }

        body {
            background-color: var(--bg-main);
            color: var(--text-main);
            padding: 20px;
            font-size: 14px;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 15px;
            margin-bottom: 20px;
        }

        .header h1 {
            font-size: 20px;
            color: var(--accent-blue);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .badge-live {
            background-color: rgba(74, 222, 128, 0.15);
            color: var(--accent-green);
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            text-transform: uppercase;
            font-weight: bold;
            border: 1px solid rgba(74, 222, 128, 0.3);
        }

        .banner-warning {
            background-color: rgba(248, 113, 113, 0.12);
            border: 1px solid var(--accent-red);
            color: #fca5a5;
            padding: 12px 16px;
            border-radius: 6px;
            margin-bottom: 18px;
            display: none;
            font-size: 13px;
            line-height: 1.5;
        }

        .stats-bar {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }

        .stat-card {
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
        }

        .stat-label {
            font-size: 11px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .stat-val {
            font-size: 22px;
            font-weight: bold;
            margin-top: 4px;
            color: var(--text-main);
        }

        .controls {
            display: flex;
            gap: 10px;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }

        button, select {
            background-color: var(--bg-card);
            color: var(--text-main);
            border: 1px solid var(--border);
            padding: 8px 14px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.2s;
        }

        button:hover { background-color: var(--border); }
        button.btn-danger { border-color: var(--accent-red); color: var(--accent-red); }
        button.btn-danger:hover { background-color: rgba(248, 113, 113, 0.2); }

        .table-container {
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow-x: auto;
            max-height: calc(100vh - 280px);
            position: relative;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }

        th {
            background-color: #1e293b;
            color: var(--text-muted);
            font-weight: 600;
            padding: 12px 14px;
            border-bottom: 1px solid var(--border);
            position: sticky;
            top: 0;
            z-index: 10;
        }

        td {
            padding: 10px 14px;
            border-bottom: 1px solid rgba(51, 65, 85, 0.4);
            white-space: nowrap;
        }

        tr:hover { background-color: rgba(255, 255, 255, 0.02); cursor: pointer; }

        .proto-badge {
            display: inline-block;
            padding: 2px 7px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
        }

        .proto-TCP { background: rgba(56, 189, 248, 0.2); color: var(--accent-blue); }
        .proto-UDP { background: rgba(192, 132, 252, 0.2); color: var(--accent-purple); }
        .proto-ICMP { background: rgba(250, 204, 21, 0.2); color: var(--accent-yellow); }
        .proto-DNS { background: rgba(251, 146, 60, 0.2); color: #fb923c; }
        .proto-HTTP { background: rgba(74, 222, 128, 0.2); color: var(--accent-green); }
        .proto-ARP { background: rgba(244, 114, 182, 0.2); color: #f472b6; }
        .proto-OTHER { background: rgba(148, 163, 184, 0.2); color: var(--text-muted); }

        .empty-state {
            padding: 50px 20px;
            text-align: center;
            color: var(--text-muted);
        }

        .empty-state h3 {
            font-size: 16px;
            margin-bottom: 8px;
            color: var(--text-main);
        }

        .empty-state code {
            background: #0f172a;
            padding: 3px 8px;
            border-radius: 4px;
            color: var(--accent-green);
        }

        .payload-preview {
            background-color: #0b0f19;
            padding: 8px;
            border-radius: 4px;
            font-size: 11px;
            color: #38bdf8;
            white-space: pre;
            margin-top: 5px;
            display: none;
        }
    </style>
</head>
<body>

    <div class="header">
        <h1>
            PyNetSniffer Live Dashboard
            <span class="badge-live" id="live-badge">Live</span>
        </h1>
        <div style="font-size: 12px; color: var(--text-muted);" id="status-text">
            Status: Connecting...
        </div>
    </div>

    <!-- Error Banner for Missing Admin / Missing Npcap -->
    <div class="banner-warning" id="error-banner"></div>

    <!-- Metrics Bar -->
    <div class="stats-bar">
        <div class="stat-card">
            <div class="stat-label">Total Packets</div>
            <div class="stat-val" id="stat-total">0</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Buffer Capacity</div>
            <div class="stat-val" id="stat-buffer">0 / 250</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Active Filter</div>
            <div class="stat-val" style="font-size: 16px; margin-top: 8px;" id="stat-filter">All Traffic</div>
        </div>
    </div>

    <!-- Controls -->
    <div class="controls">
        <button id="btn-pause" onclick="togglePause()">Pause Feed</button>
        <button class="btn-danger" onclick="clearPackets()">Clear Buffer</button>
        <select id="protocol-filter" onchange="renderPackets()">
            <option value="ALL">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
            <option value="DNS">DNS</option>
            <option value="HTTP">HTTP</option>
            <option value="ARP">ARP</option>
        </select>
    </div>

    <!-- Table Container -->
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th style="width: 50px;">#</th>
                    <th style="width: 100px;">Time</th>
                    <th style="width: 70px;">Proto</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th style="width: 80px;">Flags</th>
                    <th style="width: 80px;">Len</th>
                    <th>Summary</th>
                </tr>
            </thead>
            <tbody id="packet-tbody">
                <tr>
                    <td colspan="8">
                        <div class="empty-state">
                            <h3>No packets yet</h3>
                            <p>Generate test traffic by running <code>ping 8.8.8.8</code> or <code>curl http://neverssl.com</code> in another terminal.</p>
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>

    <script>
        let isPaused = false;
        let cachedPackets = [];

        async function fetchState() {
            try {
                const res = await fetch('/api/packets');
                const data = await res.json();

                // Update status & error banner
                document.getElementById('status-text').textContent = 'Status: ' + data.status;
                const banner = document.getElementById('error-banner');
                if (data.error) {
                    banner.style.display = 'block';
                    banner.innerHTML = '<strong>Warning:</strong> ' + data.error;
                } else {
                    banner.style.display = 'none';
                }

                document.getElementById('stat-total').textContent = data.total_captured.toLocaleString();
                document.getElementById('stat-buffer').textContent = data.packets.length + ' / 250';

                if (!isPaused) {
                    cachedPackets = data.packets;
                    renderPackets();
                }
            } catch (err) {
                document.getElementById('status-text').textContent = 'Status: Disconnected';
            }
        }

        function renderPackets() {
            const filter = document.getElementById('protocol-filter').value;
            const tbody = document.getElementById('packet-tbody');
            
            const filtered = filter === 'ALL' 
                ? cachedPackets 
                : cachedPackets.filter(p => p.protocol.toUpperCase() === filter);

            if (filtered.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="8">
                            <div class="empty-state">
                                <h3>No packets match current view</h3>
                                <p>Generate traffic with <code>ping 8.8.8.8</code> or <code>curl http://neverssl.com</code></p>
                            </div>
                        </td>
                    </tr>
                `;
                return;
            }

            // Display in reverse order (newest first)
            const rows = filtered.slice().reverse().map(p => {
                const protoClass = 'proto-' + (['TCP','UDP','ICMP','DNS','HTTP','ARP'].includes(p.protocol) ? p.protocol : 'OTHER');
                return `
                    <tr onclick="togglePayload(this)">
                        <td style="color: var(--text-muted);">${p.id}</td>
                        <td style="color: var(--text-muted);">${p.timestamp}</td>
                        <td><span class="proto-badge ${protoClass}">${p.protocol}</span></td>
                        <td><code>${escapeHtml(p.src)}</code></td>
                        <td><code>${escapeHtml(p.dst)}</code></td>
                        <td style="color: var(--accent-yellow);">${escapeHtml(p.flags)}</td>
                        <td>${p.length} B</td>
                        <td>
                            <div>${escapeHtml(p.summary)}</div>
                            ${p.payload ? `<div class="payload-preview">${escapeHtml(p.payload)}</div>` : ''}
                        </td>
                    </tr>
                `;
            }).join('');

            tbody.innerHTML = rows;
        }

        function togglePayload(row) {
            const preview = row.querySelector('.payload-preview');
            if (preview) {
                preview.style.display = preview.style.display === 'block' ? 'none' : 'block';
            }
        }

        function togglePause() {
            isPaused = !isPaused;
            const btn = document.getElementById('btn-pause');
            const badge = document.getElementById('live-badge');
            if (isPaused) {
                btn.textContent = 'Resume Feed';
                badge.textContent = 'Paused';
                badge.style.color = '#facc15';
                badge.style.borderColor = 'rgba(250, 204, 21, 0.4)';
            } else {
                btn.textContent = 'Pause Feed';
                badge.textContent = 'Live';
                badge.style.color = '#4ade80';
                badge.style.borderColor = 'rgba(74, 222, 128, 0.3)';
            }
        }

        async function clearPackets() {
            await fetch('/api/clear', { method: 'POST' });
            cachedPackets = [];
            renderPackets();
        }

        function escapeHtml(str) {
            if (!str) return '';
            return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        // Poll every 1000ms
        setInterval(fetchState, 1000);
        fetchState();
    </script>
</body>
</html>
"""

# =====================================================================
# Flask Endpoints
# =====================================================================

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/packets")
def get_packets():
    with packet_lock:
        packets_list = list(packet_buffer)
        
    return jsonify({
        "status": state.status,
        "error": state.error_message,
        "is_paused": state.is_paused,
        "total_captured": state.packet_count,
        "packets": packets_list,
    })


@app.route("/api/clear", methods=["POST"])
def clear_buffer():
    with packet_lock:
        packet_buffer.clear()
    return jsonify({"success": True})


def start_server(port: int = 5000) -> None:
    """Initialize sniffer thread and start local HTTP server."""
    display_startup_banner()

    target_port = find_available_port(preferred_port=port, host="127.0.0.1")
    url = f"http://127.0.0.1:{target_port}"

    if console:
        console.print(f"[bold green][*] Starting Network Sniffer Web Server...[/bold green]")
        if target_port != port:
            console.print(f"[bold yellow][!] Port {port} was busy. Switched to free port: {target_port}[/bold yellow]")
        console.print(f"[bold cyan][✓] Web Dashboard available at:[/bold cyan] [bold underline white]{url}[/bold underline white]\n")
        console.print("[dim]Press Ctrl+C to terminate web dashboard server.[/dim]\n")
    else:
        print(f"[*] Starting Web Server on {url}")

    # Launch background capture thread
    sniff_thread = threading.Thread(target=background_sniffer_loop, daemon=True)
    sniff_thread.start()

    # Bind strictly to 127.0.0.1 (never 0.0.0.0)
    try:
        app.run(host="127.0.0.1", port=target_port, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("\n[*] Shutting down Web Dashboard...")
    finally:
        state.is_running = False


if __name__ == "__main__":
    start_server(port=5000)
