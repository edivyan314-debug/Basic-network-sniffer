"""
Network Utility and Formatting Helpers
Part of the Basic Network Sniffer educational toolkit.
"""

from __future__ import annotations

import ctypes
import os
import sys
from typing import List, Dict, Any, Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None

ETHICAL_WARNING_TEXT = (
    "[bold red]=== EDUCATIONAL AND AUTHORIZED USE ONLY ===[/bold red]\n\n"
    "[yellow]This software is created strictly for academic research, defensive network "
    "engineering, and personal network diagnostics.[/yellow]\n\n"
    "[white]Capturing or analyzing network traffic on networks without explicit, written "
    "authorization from the network owner is strictly prohibited by law (e.g., Computer "
    "Fraud and Abuse Act, GDPR, and international electronic communications regulations).\n"
    "Only run this tool on local loopback, lab environments, or hardware you personally own.[/white]"
)


def display_startup_banner() -> None:
    """Print the educational warning banner to the terminal."""
    if HAS_RICH and console:
        console.print(
            Panel(
                ETHICAL_WARNING_TEXT,
                title="[bold cyan]PyNetSniffer - Packet Inspection Tool[/bold cyan]",
                border_style="bright_blue",
                padding=(1, 2),
            )
        )
    else:
        plain_banner = (
            "=" * 70 + "\n"
            "PyNetSniffer - Packet Inspection Tool (Educational)\n"
            "=" * 70 + "\n"
            "NOTICE: Strictly for authorized lab diagnostics and education.\n"
            "Do not inspect unauthorized networks.\n"
            "=" * 70 + "\n"
        )
        print(plain_banner)


def verify_system_privileges() -> bool:
    """
    Check whether the running process has elevated privileges (root or administrator).
    Raw packet capture typically requires administrative rights.
    """
    if os.name == "nt":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            return False
    else:
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False


def format_hex_ascii_dump(data: bytes, max_bytes: int = 64, show_full: bool = False) -> str:
    """
    Create a canonical side-by-side hexadecimal and printable ASCII visualization.
    
    Args:
        data: The raw payload byte sequence.
        max_bytes: Truncation threshold for preview mode (default 64 bytes).
        show_full: When True, dumps the entire payload regardless of length.
        
    Returns:
        A multi-line formatted string showing offsets, hex values, and ASCII text.
    """
    if not data:
        return "<Empty Payload>"

    target_bytes = data if show_full else data[:max_bytes]
    output_lines: List[str] = []
    
    for offset in range(0, len(target_bytes), 16):
        chunk = target_bytes[offset:offset + 16]
        hex_parts = [f"{byte:02x}" for byte in chunk]
        
        # Split into two 8-byte groups for readability
        first_half = " ".join(hex_parts[:8])
        second_half = " ".join(hex_parts[8:])
        hex_display = f"{first_half:<23}  {second_half:<23}"
        
        # ASCII representation (printables only, dot for unprintable)
        ascii_chars = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        
        output_lines.append(f"{offset:04x}   {hex_display}  |{ascii_chars}|")

    if not show_full and len(data) > max_bytes:
        remaining = len(data) - max_bytes
        output_lines.append(f"... [{remaining} additional bytes omitted from preview]")

    return "\n".join(output_lines)


def format_mac_address(raw_bytes: bytes) -> str:
    """Format 6 raw bytes into standard colon-separated MAC notation."""
    if len(raw_bytes) != 6:
        return raw_bytes.hex()
    return ":".join(f"{b:02x}" for b in raw_bytes)


def safe_decode_string(data: bytes) -> str:
    """
    Safely decode raw bytes to printable text without throwing decoding errors.
    """
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("latin-1")
        except Exception:
            return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)
