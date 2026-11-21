"""
Web Dashboard for Network Sniffer (Flask + Scapy)
Serves a real-time browser dashboard at http://127.0.0.1:5000 (or auto-picked port).
Includes automatic Demo Mode and manual packet injection so it works even if Npcap is missing.
"""

from __future__ import annotations

import collections
import datetime
import os
import random
import socket
import sys
import threading
import time
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, render_template_string, request

# Import existing packet analyzer and utilities
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
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.dns import DNS, DNSQR
    from scapy.packet import Packet, Raw
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

app = Flask(__name__)

# In-memory thread-safe packet storage (buffer of latest 250 packets)
MAX_PACKET_BUFFER = 250
packet_buffer: collections.deque[Dict[str, Any]] = collections.deque(maxlen=MAX_PACKET_BUFFER)
packet_lock = threading.Lock()


class SnifferState:
    def __init__(self) -> None:
        self.is_running = True
        self.is_paused = False
        self.packet_count = 0
        self.error_message: Optional[str] = None
        self.status: str = "Initializing..."
        self.demo_mode: bool = False
        self.npcap_available: bool = False
        self.has_admin: bool = False

state = SnifferState()


def find_available_port(preferred_port: int = 5000, host: str = "127.0.0.1") -> int:
    """Check if the preferred port is open; if busy, locate the next available free port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, preferred_port))
            return preferred_port
        except OSError:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_free:
                s_free.bind((host, 0))
                return s_free.getsockname()[1]


def inject_packet_record(
    protocol: str,
    src: str,
    dst: str,
    flags: str = "-",
    length: int = 64,
    summary: str = "",
    payload_data: bytes = b"",
) -> Dict[str, Any]:
    """Helper to append an analyzed packet record into the buffer."""
    now_str = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    payload_hex = format_hex_ascii_dump(payload_data, max_bytes=64) if payload_data else ""

    record = {
        "id": state.packet_count + 1,
        "timestamp": now_str,
        "protocol": protocol,
        "src": src,
        "dst": dst,
        "length": length,
        "flags": flags,
        "summary": summary,
        "payload": payload_hex,
    }

    with packet_lock:
        state.packet_count += 1
        packet_buffer.append(record)

    return record


def generate_synthetic_packet() -> None:
    """Generate realistic synthetic network packet for demo/testing when wire capture is unavailable."""
    sample_types = ["DNS", "HTTP", "ICMP", "TCP_SYN", "ARP"]
    chosen = random.choice(sample_types)

    local_ip = "192.168.1.105"
    gateway_ip = "192.168.1.1"

    if chosen == "DNS":
        domains = ["example.com", "github.com", "google.com", "python.org", "wikipedia.org"]
        dom = random.choice(domains)
        dns_payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + bytes(dom, "utf-8") + b"\x00\x00\x01\x00\x01"
        inject_packet_record(
            protocol="DNS",
            src=f"{local_ip}:{random.randint(49152, 65535)}",
            dst="1.1.1.1:53",
            length=len(dns_payload) + 28,
            summary=f"Query {dom} [A]",
            payload_data=dns_payload,
        )

    elif chosen == "HTTP":
        paths = ["/index.html", "/api/v1/status", "/docs", "/about", "/login"]
        path = random.choice(paths)
        host = "neverssl.com"
        http_raw = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n".encode()
        inject_packet_record(
            protocol="HTTP",
            src=f"{local_ip}:{random.randint(50000, 60000)}",
            dst="93.184.216.34:80",
            flags="PSH ACK",
            length=len(http_raw) + 40,
            summary=f"HTTP Request: GET {path} [Host: {host}]",
            payload_data=http_raw,
        )

    elif chosen == "ICMP":
        icmp_data = b"\x08\x00\x4d\x5b\x00\x01\x00\x01abcdefghijklmnopqrstuvw"
        inject_packet_record(
            protocol="ICMP",
            src=local_ip,
            dst="8.8.8.8",
            length=64,
            summary="Echo Request (code=0, id=1, seq=" + str(random.randint(1, 100)) + ")",
            payload_data=icmp_data,
        )

    elif chosen == "TCP_SYN":
        sport = random.randint(50000, 65000)
        inject_packet_record(
            protocol="TCP",
            src=f"{local_ip}:{sport}",
            dst="142.250.190.46:443",
            flags="SYN",
            length=60,
            summary=f"Initial Connection Handshake (sport={sport} dport=443)",
            payload_data=b"",
        )

    elif chosen == "ARP":
        inject_packet_record(
            protocol="ARP",
            src=local_ip,
            dst=gateway_ip,
            length=42,
            summary=f"Who has {gateway_ip}? Tell {local_ip}",
            payload_data=b"\x00\x01\x08\x00\x06\x04\x00\x01" + b"\xaa\xbb\xcc\xdd\xee\xff",
        )


def background_sniffer_loop() -> None:
    """Worker thread that executes Scapy capture, or runs demo traffic if wire capture is unavailable."""
    global state

    state.has_admin = verify_system_privileges()

    def packet_callback(raw_pkt: Packet) -> None:
        if state.is_paused or not state.is_running:
            return

        try:
            parsed: ParsedPacket = parse_scapy_packet(raw_pkt)
            inject_packet_record(
                protocol=parsed.protocol,
                src=parsed.src_endpoint,
                dst=parsed.dst_endpoint,
                flags=" ".join(parsed.tcp_flags) if parsed.tcp_flags else "-",
                length=parsed.length,
                summary=parsed.summary,
                payload_data=parsed.payload,
            )
        except Exception as ex:
            print(f"[!] Error analyzing packet: {ex}", file=sys.stderr)

    # Attempt live wire capture with Scapy
    if HAS_SCAPY and state.has_admin:
        try:
            state.status = "Live Capture Active (Scapy)"
            print("[*] Starting live packet capture with Scapy...")
            sniff(
                prn=packet_callback,
                store=False,
                stop_filter=lambda _: not state.is_running or state.demo_mode,
            )
            return
        except RuntimeError as rt_err:
            msg = str(rt_err)
            if "winpcap is not installed" in msg.lower():
                state.error_message = (
                    "Npcap is not installed on Windows. To capture live interface packets, "
                    "install Npcap with WinPcap-compatibility mode from https://npcap.com/#download."
                )
            else:
                state.error_message = f"Scapy Runtime Error: {rt_err}"
            print(f"\n[!] Live Capture Notice: {state.error_message}", file=sys.stderr)
        except PermissionError:
            state.error_message = "Administrator/root permissions required for live packet capture."
            print(f"\n[!] Live Capture Notice: {state.error_message}", file=sys.stderr)
        except Exception as e:
            state.error_message = f"Live Capture Exception: {e}"
            print(f"\n[!] Live Capture Notice: {state.error_message}", file=sys.stderr)
    else:
        if not state.has_admin:
            state.error_message = (
                "Running without Administrator rights. "
                "For live hardware capture, run PowerShell as Administrator. "
                "Currently running in Demo/Simulation Mode."
            )
        else:
            state.error_message = "Npcap or Scapy unavailable. Running in Demo/Simulation Mode."

    # Fallback to Demo Mode with simulated packets so the dashboard works out of the box
    state.demo_mode = True
    state.status = "Demo Mode (Simulating Traffic)"
    print("[*] Running in Demo Mode: Generating simulated sample traffic...")

    while state.is_running:
        if not state.is_paused and state.demo_mode:
            generate_synthetic_packet()
        time.sleep(random.uniform(1.2, 2.5))


# =====================================================================
# HTML Dashboard Template
# =====================================================================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PyNetSniffer - Network Dashboard</title>
    <style>
        :root {
            --bg-main: #0b1120;
            --bg-card: #151f32;
            --border: #24324d;
            --text-main: #f1f5f9;
            --text-muted: #8e9fb5;
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
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
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

        .banner-info {
            background-color: rgba(56, 189, 248, 0.1);
            border: 1px solid rgba(56, 189, 248, 0.4);
            color: #bae6fd;
            padding: 10px 14px;
            border-radius: 6px;
            margin-bottom: 15px;
            font-size: 13px;
            line-height: 1.4;
        }

        .stats-bar {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-bottom: 15px;
        }

        .stat-card {
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 14px;
        }

        .stat-label {
            font-size: 11px;
            color: var(--text-muted);
            text-transform: uppercase;
        }

        .stat-val {
            font-size: 20px;
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
        }

        button:hover { background-color: var(--border); }
        button.btn-primary { background-color: #0284c7; border-color: #0284c7; font-weight: bold; }
        button.btn-primary:hover { background-color: #0369a1; }
        button.btn-danger { border-color: var(--accent-red); color: var(--accent-red); }
        button.btn-danger:hover { background-color: rgba(248, 113, 113, 0.2); }

        .table-container {
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow-x: auto;
            max-height: calc(100vh - 280px);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }

        th {
            background-color: #111a2d;
            color: var(--text-muted);
            font-weight: 600;
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
            position: sticky;
            top: 0;
            z-index: 10;
        }

        td {
            padding: 9px 12px;
            border-bottom: 1px solid rgba(36, 50, 77, 0.6);
            white-space: nowrap;
        }

        tr:hover { background-color: rgba(255, 255, 255, 0.03); cursor: pointer; }

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
            padding: 40px 20px;
            text-align: center;
            color: var(--text-muted);
        }

        .payload-preview {
            background-color: #060a12;
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
            PyNetSniffer Dashboard
            <span class="badge-live" id="live-badge">Live</span>
        </h1>
        <div style="font-size: 12px; color: var(--text-muted);" id="status-text">
            Status: Connecting...
        </div>
    </div>

    <!-- Notice Banner -->
    <div class="banner-info" id="notice-banner">
        <strong>Notice:</strong> <span id="banner-text">Connecting to sniffer service...</span>
    </div>

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
            <div class="stat-label">Mode</div>
            <div class="stat-val" style="font-size: 15px; margin-top: 6px;" id="stat-mode">Detecting...</div>
        </div>
    </div>

    <!-- Controls -->
    <div class="controls">
        <button class="btn-primary" onclick="injectTestPacket()">+ Inject Test Packet</button>
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
                    <th style="width: 45px;">#</th>
                    <th style="width: 95px;">Time</th>
                    <th style="width: 65px;">Proto</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th style="width: 75px;">Flags</th>
                    <th style="width: 75px;">Len</th>
                    <th>Summary</th>
                </tr>
            </thead>
            <tbody id="packet-tbody">
                <tr>
                    <td colspan="8">
                        <div class="empty-state">
                            <h3>No packets yet</h3>
                            <p>Click "Inject Test Packet" or generate traffic with ping / curl.</p>
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

                document.getElementById('status-text').textContent = 'Status: ' + data.status;
                document.getElementById('stat-mode').textContent = data.demo_mode ? 'Demo / Simulation' : 'Live Capture';

                const bannerText = document.getElementById('banner-text');
                if (data.error) {
                    bannerText.textContent = data.error;
                } else {
                    bannerText.textContent = 'Live packet capture running. Click any packet row to inspect payload.';
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
                                <p>Click "+ Inject Test Packet" above to test immediately.</p>
                            </div>
                        </td>
                    </tr>
                `;
                return;
            }

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
            } else {
                btn.textContent = 'Pause Feed';
                badge.textContent = 'Live';
                badge.style.color = '#4ade80';
            }
        }

        async function injectTestPacket() {
            await fetch('/api/inject_test', { method: 'POST' });
            fetchState();
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
        "demo_mode": state.demo_mode,
        "total_captured": state.packet_count,
        "packets": packets_list,
    })


@app.route("/api/inject_test", methods=["POST"])
def inject_test():
    generate_synthetic_packet()
    return jsonify({"success": True})


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

    print(f"\n[*] Starting PyNetSniffer Web Server...")
    if target_port != port:
        print(f"[!] Preferred port {port} was occupied. Using port: {target_port}")
    print(f"[✓] Dashboard URL: {url}\n")

    sniff_thread = threading.Thread(target=background_sniffer_loop, daemon=True)
    sniff_thread.start()

    try:
        app.run(host="127.0.0.1", port=target_port, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("\n[*] Shutting down Web Dashboard...")
    finally:
        state.is_running = False


if __name__ == "__main__":
    start_server(port=5000)
