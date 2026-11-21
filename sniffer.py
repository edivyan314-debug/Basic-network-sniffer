"""
Main Scapy-based Network Sniffer CLI
Part of the Basic Network Sniffer educational toolkit.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from typing import Any, List, Optional

from scapy.all import conf, get_if_list, sniff, wrpcap
from scapy.packet import Packet

from analyzer import PacketStatistics, ParsedPacket, parse_scapy_packet
from utils import (
    console,
    display_startup_banner,
    format_hex_ascii_dump,
    verify_system_privileges,
)

# Color mapping for protocol tags in Rich
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


class SnifferEngine:
    """Manages packet capture execution, filtering, and live terminal rendering."""

    def __init__(
        self,
        interface: Optional[str] = None,
        packet_count: int = 0,
        bpf_filter: Optional[str] = None,
        proto_filter: Optional[str] = None,
        output_file: Optional[str] = None,
        verbose: bool = False,
    ) -> None:
        self.interface = interface
        self.packet_count = packet_count
        self.bpf_filter = bpf_filter
        self.proto_filter = proto_filter.upper() if proto_filter else None
        self.output_file = output_file
        self.verbose = verbose

        self.stats = PacketStatistics()
        self.raw_captured_packets: List[Packet] = []
        self._is_terminating = False

    def handle_incoming_packet(self, raw_pkt: Packet) -> None:
        """Callback invoked by Scapy for every captured packet."""
        if self._is_terminating:
            return

        parsed = parse_scapy_packet(raw_pkt)

        # Apply high-level protocol filter if specified
        if self.proto_filter and parsed.protocol != self.proto_filter:
            return

        # Record for statistics and potential export
        self.stats.record_packet(parsed, store_record=bool(self.output_file and self.output_file.endswith(".csv")))
        
        if self.output_file and self.output_file.endswith((".pcap", ".pcapng", ".cap")):
            self.raw_captured_packets.append(raw_pkt)

        self._render_packet_output(parsed)

    def _render_packet_output(self, pkt: ParsedPacket) -> None:
        """Render packet details to the console."""
        proto_style = PROTOCOL_COLORS.get(pkt.protocol, "white")
        tag = f"[{proto_style}]{pkt.protocol:<5}[/{proto_style}]"
        
        flags_str = f"[[yellow]{' '.join(pkt.tcp_flags)}[/yellow]] " if pkt.tcp_flags else ""
        flow = f"{pkt.src_endpoint} [bold green]->[/bold green] {pkt.dst_endpoint}"
        
        line = (
            f"[dim]{pkt.formatted_time}[/dim]  {tag}  "
            f"{flow:<45}  {flags_str}"
            f"[dim]len={pkt.length}[/dim]  "
            f"[italic white]{pkt.summary}[/italic white]"
        )

        if console:
            console.print(line)
            
            if self.verbose:
                # Detailed layer view
                if pkt.layer_details:
                    details_str = ", ".join(f"{k}={v}" for k, v in pkt.layer_details.items())
                    console.print(f"       [dim cyan]└─ Layers:[/dim cyan] [dim]{details_str}[/dim]")
                
                # Full payload hex/ASCII dump
                if pkt.payload:
                    dump = format_hex_ascii_dump(pkt.payload, max_bytes=128, show_full=self.verbose)
                    console.print("       [dim yellow]└─ Payload:[/dim yellow]")
                    for dump_line in dump.splitlines():
                        console.print(f"          [dim]{dump_line}[/dim]")
            elif pkt.payload:
                # Standard preview (first 64 bytes)
                dump = format_hex_ascii_dump(pkt.payload, max_bytes=64, show_full=False)
                console.print(f"       [dim]Payload (first 64B):[/dim]")
                for dump_line in dump.splitlines():
                    console.print(f"          [dim]{dump_line}[/dim]")
        else:
            print(f"{pkt.formatted_time}  {pkt.protocol:<5}  {pkt.src_endpoint} -> {pkt.dst_endpoint}  len={pkt.length}  {pkt.summary}")

    def run(self) -> None:
        """Start the live capture loop."""
        display_startup_banner()

        if console:
            console.print("[bold green][*] Initializing network capture engine...[/bold green]")
            if self.interface:
                console.print(f"[*] Binding to interface: [cyan]{self.interface}[/cyan]")
            if self.bpf_filter:
                console.print(f"[*] Applying BPF Filter: [yellow]{self.bpf_filter}[/yellow]")
            if self.proto_filter:
                console.print(f"[*] Protocol Filter: [magenta]{self.proto_filter}[/magenta]")
            if self.packet_count > 0:
                console.print(f"[*] Target packet limit: [cyan]{self.packet_count}[/cyan]")
            else:
                console.print("[*] Continuous mode. Press [bold red]Ctrl+C[/bold red] to stop capture.")
            console.print("-" * 75)

        # Register interrupt handler for graceful shutdown
        def sig_handler(sig, frame):
            self._is_terminating = True
            if console:
                console.print("\n[bold red][!] Interrupted by user. Finalizing capture...[/bold red]")
            sys.exit(0)

        signal.signal(signal.SIGINT, sig_handler)

        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self.handle_incoming_packet,
                count=self.packet_count,
                store=False,
            )
        except RuntimeError as err:
            err_msg = str(err)
            if "winpcap is not installed" in err_msg.lower():
                if console:
                    console.print(
                        "\n[bold red][X] Capture Engine Error: Npcap / WinPcap is not detected![/bold red]\n"
                        "[yellow]To capture packets with Scapy on Windows, please install Npcap:[/yellow]\n"
                        "  1. Download Npcap from: [link=https://npcap.com/#download]https://npcap.com/#download[/link]\n"
                        "  2. During installation, check: '[bold]Install Npcap in WinPcap API-compatible Mode[/bold]'\n"
                        "  3. Restart your terminal as Administrator.\n\n"
                        "[cyan]Tip: You can also try running [bold]python sniffer_socket.py[/bold] for our raw socket mode.[/cyan]\n"
                    )
                else:
                    print("Error: Npcap or WinPcap is required on Windows: https://npcap.com/#download")
                return
            else:
                raise
        except PermissionError:
            if console:
                console.print(
                    "\n[bold red][X] Permission Denied: Elevated privileges required![/bold red]\n"
                    "  - On Windows: Right-click PowerShell/CMD and select 'Run as Administrator'.\n"
                    "  - On Linux / macOS: Run with sudo: 'sudo python sniffer.py'\n"
                )
            else:
                print("Error: Administrator or root permissions required to sniff packets.")
            return
        except Exception as e:
            if console:
                console.print(f"\n[bold red][X] Unexpected error during capture:[/bold red] {e}")
            else:
                print(f"Error during capture: {e}")
            return
        finally:
            self._finalize()

    def _finalize(self) -> None:
        """Save outputs and display session statistics."""
        # 1. Export outputs
        if self.output_file:
            if self.output_file.endswith(".csv"):
                try:
                    self.stats.export_to_csv(self.output_file)
                    if console:
                        console.print(f"[bold green][✓] Captured packet log exported to CSV: {self.output_file}[/bold green]")
                except Exception as e:
                    if console:
                        console.print(f"[bold red][X] Failed to export CSV:[/bold red] {e}")
            elif self.output_file.endswith((".pcap", ".pcapng", ".cap")):
                try:
                    wrpcap(self.output_file, self.raw_captured_packets)
                    if console:
                        console.print(f"[bold green][✓] Raw PCAP file saved: {self.output_file}[/bold green]")
                except Exception as e:
                    if console:
                        console.print(f"[bold red][X] Failed to save PCAP:[/bold red] {e}")

        # 2. Render summary dashboard
        if console:
            self.stats.display_rich_summary(console)


def list_available_interfaces() -> None:
    """Print all detectable network adapters."""
    display_startup_banner()
    ifaces = get_if_list()
    
    if console:
        from rich.table import Table
        tbl = Table(title="Available Network Interfaces", show_header=True, header_style="bold cyan")
        tbl.add_column("Index", style="dim", justify="right")
        tbl.add_column("Interface Identifier", style="bold green")
        
        for idx, iface in enumerate(ifaces, start=1):
            tbl.add_row(str(idx), str(iface))
        
        console.print(tbl)
        console.print(
            "\n[dim cyan]Usage tip:[/dim cyan] Pass an interface name using [bold]-i <name>[/bold]. "
            "Leave blank to use default."
        )
    else:
        print("Available Interfaces:")
        for idx, iface in enumerate(ifaces, start=1):
            print(f"  [{idx}] {iface}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer - Educational Packet Inspection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python sniffer.py -c 10\n"
            "  python sniffer.py -f 'tcp port 80' -v\n"
            "  python sniffer.py -p dns -o dns_capture.csv\n"
            "  python sniffer.py -o traffic.pcap\n"
            "  python sniffer.py --list-interfaces\n"
        ),
    )
    parser.add_argument("-i", "--interface", help="Network interface to capture from")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = indefinite)")
    parser.add_argument("-f", "--filter", help="BPF capture filter (e.g., 'tcp port 80', 'icmp', 'udp port 53')")
    parser.add_argument("-p", "--protocol", choices=["tcp", "udp", "icmp", "arp", "dns", "http"], help="Filter by high-level protocol")
    parser.add_argument("-o", "--output", help="Save output to a .pcap file or .csv summary")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose layer details and full payload hex dump")
    parser.add_argument("-l", "--list-interfaces", action="store_true", help="List detectable network adapters and exit")

    args = parser.parse_args()

    if args.list_interfaces:
        list_available_interfaces()
        return

    # Check privileges warning
    if not verify_system_privileges():
        if console:
            console.print(
                "[bold yellow][!] Warning:[/bold yellow] You are running without administrator/root privileges.\n"
                "    Packet capturing will fail unless your account has raw socket permissions.\n"
            )

    engine = SnifferEngine(
        interface=args.interface,
        packet_count=args.count,
        bpf_filter=args.filter,
        proto_filter=args.protocol,
        output_file=args.output,
        verbose=args.verbose,
    )
    engine.run()


if __name__ == "__main__":
    main()
