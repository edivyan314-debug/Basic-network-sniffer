"""
Real-Time Network Sniffer Web Dashboard & Terminal Monitor
Captures live, authentic network traffic from the computer's network interface,
prints each packet directly to the command line, and simultaneously streams it
to the web dashboard at http://127.0.0.1:5000.

Zero simulated/demo packets: captures 100% real physical network traffic.
"""

from __future__ import annotations

import argparse
import collections
import datetime
import os
import signal
import socket
import sys
import threading
import time
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, render_template_string, request

# Import packet analyzer and utilities
from analyzer import parse_scapy_packet, ParsedPacket
from utils import (
    console,
    display_startup_banner,
    format_hex_ascii_dump,
    verify_system_privileges,
)

# Scapy packet parsing
try:
    from scapy.all import sniff
    from scapy.layers.inet import IP
    from scapy.packet import Packet
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

app = Flask(__name__)

# Thread-safe buffer of recent real packets (latest 500 packets)
MAX_PACKET_BUFFER = 500
packet_buffer: collections.deque[Dict[str, Any]] = collections.deque(maxlen=MAX_PACKET_BUFFER)
packet_lock = threading.Lock()

PROTOCOL_COLORS = {
    "TCP": "bold cyan",
    "UDP": "bold blue",
    "ICMP": "bold yellow",
    "ARP": "bold magenta",
    "DNS": "bold bright_yellow",
    "HTTP": "bold bright_green",
    "IP": "cyan",
    "IPv6": "bright_cyan",
    "OTHER": "white",
}


class SnifferEngineState:
    def __init__(self) -> None:
        self.is_running = True
        self.is_paused = False
        self.packet_count = 0
        self.total_bytes = 0
        self.error_message: Optional[str] = None
        self.status: str = "Initializing..."
        self.capture_method: str = "Unknown"
        self.bound_ip: str = "127.0.0.1"
        self.verbose: bool = False
        self.filter_proto: Optional[str] = None

engine_state = SnifferEngineState()


def get_primary_host_ip() -> str:
    """Detect the active local IPv4 address connected to the local network/internet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip


def find_available_port(preferred_port: int = 5000, host: str = "127.0.0.1") -> int:
    """Verify preferred port availability; if busy, allocate a free port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, preferred_port))
            return preferred_port
        except OSError:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_free:
                s_free.bind((host, 0))
                return s_free.getsockname()[1]


def process_and_display_packet(parsed: ParsedPacket) -> None:
    """
    Core handler called for every real captured packet.
    1. Prints directly to the command line terminal.
    2. Buffers for the web dashboard stream.
    """
    if engine_state.is_paused or not engine_state.is_running:
        return

    # Check protocol filter
    if engine_state.filter_proto and parsed.protocol.upper() != engine_state.filter_proto.upper():
        return

    # 1. Print directly to terminal (command line)
    proto_style = PROTOCOL_COLORS.get(parsed.protocol, "white")
    tag = f"[{proto_style}]{parsed.protocol:<5}[/{proto_style}]"
    flags_str = f"[[yellow]{' '.join(parsed.tcp_flags)}[/yellow]] " if parsed.tcp_flags else ""
    flow = f"{parsed.src_endpoint} [bold green]->[/bold green] {parsed.dst_endpoint}"
    
    line = (
        f"[dim]{parsed.formatted_time}[/dim]  {tag}  "
        f"{flow:<45}  {flags_str}"
        f"[dim]len={parsed.length}[/dim]  "
        f"[italic white]{parsed.summary}[/italic white]"
    )

    if console:
        console.print(line)
        if engine_state.verbose and parsed.payload:
            dump = format_hex_ascii_dump(parsed.payload, max_bytes=64)
            for dline in dump.splitlines():
                console.print(f"       [dim]{dline}[/dim]")
    else:
        plain_line = f"{parsed.formatted_time}  {parsed.protocol:<5}  {parsed.src_endpoint} -> {parsed.dst_endpoint}  len={parsed.length}  {parsed.summary}"
        print(plain_line)

    # 2. Store in thread-safe buffer for Web Dashboard
    payload_hex = format_hex_ascii_dump(parsed.payload, max_bytes=64) if parsed.payload else ""
    record = {
        "id": engine_state.packet_count + 1,
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
        engine_state.packet_count += 1
        engine_state.total_bytes += parsed.length
        packet_buffer.append(record)


def start_live_capture(bind_ip: str) -> None:
    """
    Continuous real-packet capture engine.
    Uses Scapy Layer 2 capture if available, or native Windows Raw Sockets (SIO_RCVALL).
    """
    engine_state.bound_ip = bind_ip
    is_windows = os.name == "nt"

    # Strategy 1: Attempt Scapy Native Layer 2 Sniffer (requires Npcap on Windows or root on Linux)
    if HAS_SCAPY:
        try:
            engine_state.status = "Live Capture (Scapy L2)"
            engine_state.capture_method = "Scapy L2 Driver"
            if console:
                console.print(f"[bold green][*] Initiating Scapy packet capture on network hardware...[/bold green]")
            
            sniff(
                prn=lambda pkt: process_and_display_packet(parse_scapy_packet(pkt)),
                store=False,
                stop_filter=lambda _: not engine_state.is_running,
            )
            return
        except RuntimeError as rt_err:
            msg = str(rt_err)
            if "winpcap is not installed" not in msg.lower():
                engine_state.error_message = f"Scapy Capture Error: {rt_err}"
                if console:
                    console.print(f"[bold red][!] Scapy L2 capture unavailable: {rt_err}[/bold red]")
        except PermissionError:
            engine_state.error_message = "Administrator privileges required to access raw network interface."
            if console:
                console.print("[bold red][X] Permission Denied: Please run terminal as Administrator.[/bold red]")
            return

    # Strategy 2: Windows Native Layer 3 Raw Socket (Captures real IP packets on bind_ip without Npcap)
    if is_windows:
        engine_state.status = f"Live Capture (Windows Raw Socket: {bind_ip})"
        engine_state.capture_method = f"Windows SIO_RCVALL ({bind_ip})"
        if console:
            console.print(
                f"[bold cyan][*] Activating Windows Raw Socket promiscuous mode on adapter IP: {bind_ip}...[/bold cyan]"
            )

        sock: Optional[socket.socket] = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((bind_ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # Enable promiscuous mode to receive all incoming & outgoing host traffic
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            if console:
                console.print(f"[bold green][✓] Real-time promiscuous capture active on {bind_ip}![/bold green]")
                console.print("[dim]Streaming all physical computer packets to terminal and dashboard...[/dim]\n" + "-" * 75)

            while engine_state.is_running:
                raw_data, _ = sock.recvfrom(65535)
                # Parse raw IPv4 packet directly
                try:
                    scapy_pkt = IP(raw_data)
                    parsed = parse_scapy_packet(scapy_pkt)
                    process_and_display_packet(parsed)
                except Exception:
                    pass

        except PermissionError:
            err = (
                "Windows strictly requires elevated Administrator rights to open raw network sockets.\n"
                "Please close this terminal, open PowerShell as Administrator ('Run as Administrator'),\n"
                "and execute: python web_dashboard.py"
            )
            engine_state.error_message = err
            engine_state.status = "Error: Admin Rights Required"
            if console:
                console.print(f"\n[bold red][X] Permission Denied:[/bold red]\n{err}\n")
            else:
                print(f"\n[X] Permission Denied: {err}\n", file=sys.stderr)
        except Exception as e:
            engine_state.error_message = f"Raw socket error: {e}"
            engine_state.status = f"Socket Error ({e})"
            if console:
                console.print(f"[bold red][X] Raw socket error on {bind_ip}:[/bold red] {e}")
            else:
                print(f"[X] Raw socket error: {e}", file=sys.stderr)
        finally:
            if sock:
                try:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    sock.close()
                except Exception:
                    pass
    else:
        # Strategy 3: Linux AF_PACKET raw socket
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            engine_state.status = "Live Capture (Linux AF_PACKET)"
            engine_state.capture_method = "Linux AF_PACKET"
            while engine_state.is_running:
                raw_data, _ = sock.recvfrom(65535)
                from scapy.layers.l2 import Ether
                parsed = parse_scapy_packet(Ether(raw_data))
                process_and_display_packet(parsed)
        except PermissionError:
            engine_state.error_message = "Root permissions required (run with: sudo python web_dashboard.py)"
            engine_state.status = "Error: Root Required"
            print("[X] Permission Denied: Run with sudo", file=sys.stderr)
        except Exception as e:
            engine_state.error_message = str(e)
            engine_state.status = f"Socket Error: {e}"


# =====================================================================
# Modern Web Dashboard HTML
# =====================================================================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PyNetSniffer - Real Network Traffic Monitor</title>
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

        .banner-warning {
            background-color: rgba(248, 113, 113, 0.12);
            border: 1px solid var(--accent-red);
            color: #fca5a5;
            padding: 12px 16px;
            border-radius: 6px;
            margin-bottom: 15px;
            display: none;
            font-size: 13px;
            line-height: 1.5;
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
            letter-spacing: 0.5px;
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
            padding: 45px 20px;
            text-align: center;
            color: var(--text-muted);
        }

        .empty-state code {
            background: #060a12;
            padding: 3px 8px;
            border-radius: 4px;
            color: var(--accent-green);
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
            PyNetSniffer - Real Network Traffic Monitor
            <span class="badge-live" id="live-badge">Live</span>
        </h1>
        <div style="font-size: 12px; color: var(--text-muted);" id="status-text">
            Connecting...
        </div>
    </div>

    <!-- Error/Warning Banner -->
    <div class="banner-warning" id="error-banner"></div>

    <!-- Metrics Bar -->
    <div class="stats-bar">
        <div class="stat-card">
            <div class="stat-label">Real Packets Captured</div>
            <div class="stat-val" id="stat-total">0</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Total Volume</div>
            <div class="stat-val" id="stat-bytes">0 KB</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Capture Adapter / IP</div>
            <div class="stat-val" style="font-size: 15px; margin-top: 6px;" id="stat-ip">Detecting...</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Capture Engine</div>
            <div class="stat-val" style="font-size: 14px; margin-top: 6px; color: var(--accent-blue);" id="stat-engine">Initializing</div>
        </div>
    </div>

    <!-- Controls -->
    <div class="controls">
        <button id="btn-pause" onclick="togglePause()">Pause Web View</button>
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
        <span style="font-size: 12px; color: var(--text-muted); margin-left: auto;">
            ⚡ Traffic displays simultaneously in command line terminal & browser
        </span>
    </div>

    <!-- Table Container -->
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th style="width: 50px;">#</th>
                    <th style="width: 100px;">Time</th>
                    <th style="width: 65px;">Proto</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th style="width: 80px;">Flags</th>
                    <th style="width: 75px;">Len</th>
                    <th>Summary</th>
                </tr>
            </thead>
            <tbody id="packet-tbody">
                <tr>
                    <td colspan="8">
                        <div class="empty-state">
                            <h3>Listening for computer traffic...</h3>
                            <p>Browse a website or run <code>ping 8.8.8.8</code> to see live traffic appear.</p>
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
                document.getElementById('stat-ip').textContent = data.bound_ip;
                document.getElementById('stat-engine').textContent = data.capture_method;

                const banner = document.getElementById('error-banner');
                if (data.error) {
                    banner.style.display = 'block';
                    banner.innerHTML = '<strong>Permission / Setup Notice:</strong> ' + data.error;
                } else {
                    banner.style.display = 'none';
                }

                document.getElementById('stat-total').textContent = data.total_captured.toLocaleString();
                const kb = (data.total_bytes / 1024).toFixed(1);
                document.getElementById('stat-bytes').textContent = kb + ' KB';

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
                                <h3>No matching packets in view</h3>
                                <p>Generate traffic with <code>ping 8.8.8.8</code> or open a site in your browser.</p>
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
                btn.textContent = 'Resume Web View';
                badge.textContent = 'Paused';
                badge.style.color = '#facc15';
            } else {
                btn.textContent = 'Pause Web View';
                badge.textContent = 'Live';
                badge.style.color = '#4ade80';
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
        "status": engine_state.status,
        "error": engine_state.error_message,
        "capture_method": engine_state.capture_method,
        "bound_ip": engine_state.bound_ip,
        "is_paused": engine_state.is_paused,
        "total_captured": engine_state.packet_count,
        "total_bytes": engine_state.total_bytes,
        "packets": packets_list,
    })


@app.route("/api/clear", methods=["POST"])
def clear_buffer():
    with packet_lock:
        packet_buffer.clear()
    return jsonify({"success": True})


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Real-Time Network Sniffer: Simultaneous Command-Line Output & Web Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--port", type=int, default=5000, help="Web Dashboard port (default: 5000)")
    parser.add_argument("--ip", help="Host interface IP to bind (defaults to active host IP e.g. 192.168.1.9)")
    parser.add_argument("-p", "--protocol", choices=["tcp", "udp", "icmp", "arp", "dns", "http"], help="Filter by protocol")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print full payload hex dump in terminal")

    args = parser.parse_args()

    engine_state.verbose = args.verbose
    engine_state.filter_proto = args.protocol

    display_startup_banner()

    # Determine host IP to capture real traffic from
    capture_ip = args.ip or get_primary_host_ip()
    target_port = find_available_port(preferred_port=args.port, host="127.0.0.1")
    url = f"http://127.0.0.1:{target_port}"

    if console:
        console.print("[bold green][*] Starting PyNetSniffer Real Traffic Capture...[/bold green]")
        console.print(f"[*] Bound Network Adapter IP: [bold cyan]{capture_ip}[/bold cyan]")
        console.print(f"[bold cyan][✓] Web Dashboard available at:[/bold cyan] [bold underline white]{url}[/bold underline white]")
        console.print("[*] Packets will display live below in the command line AND on the dashboard.\n" + "-" * 75)
    else:
        print(f"[*] Capturing real traffic on {capture_ip}")
        print(f"[*] Web Dashboard: {url}")

    # Start Flask in background thread so command-line is dedicated to live packet printing
    def run_flask():
        import logging
        log = logging.getLogger("werkzeug")
        log.setLevel(logging.ERROR)
        app.run(host="127.0.0.1", port=target_port, debug=False, use_reloader=False)

    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    # Graceful exit handler
    def sig_handler(sig, frame):
        engine_state.is_running = False
        print("\n[*] Stopping sniffer and web server...")
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)

    # Run the live packet capture on the main thread (streaming directly to terminal)
    start_live_capture(bind_ip=capture_ip)


if __name__ == "__main__":
    main()
