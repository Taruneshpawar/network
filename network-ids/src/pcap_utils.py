"""Optional PCAP utilities using Scapy (offline analysis only)."""
from __future__ import annotations
import warnings
from pathlib import Path
from typing import Any

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    rdpcap = None


def pcap_summary(pcap_path: str | Path, max_packets: int = 100000) -> dict[str, Any]:
    """Generate a summary of a PCAP file (offline analysis only)."""
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy not installed. Install with: pip install scapy")

    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    packets = rdpcap(str(pcap_path))
    if len(packets) > max_packets:
        warnings.warn(f"PCAP has {len(packets):,} packets; analyzing first {max_packets:,}")
        packets = packets[:max_packets]

    summary = {
        "file": str(pcap_path),
        "total_packets": len(packets),
        "protocols": {},
        "top_talkers": {},
        "tcp_flags": {},
    }

    ip_src_counts = {}
    ip_dst_counts = {}

    for pkt in packets:
        # Protocol breakdown
        if IP in pkt:
            ip_layer = pkt[IP]
            proto_name = "OTHER"
            if TCP in pkt:
                proto_name = "TCP"
                flags = pkt[TCP].flags
                flag_str = str(flags)
                summary["tcp_flags"][flag_str] = summary["tcp_flags"].get(flag_str, 0) + 1
            elif UDP in pkt:
                proto_name = "UDP"
            elif ICMP in pkt:
                proto_name = "ICMP"
            summary["protocols"][proto_name] = summary["protocols"].get(proto_name, 0) + 1

            # Top talkers
            src = ip_layer.src
            dst = ip_layer.dst
            ip_src_counts[src] = ip_src_counts.get(src, 0) + 1
            ip_dst_counts[dst] = ip_dst_counts.get(dst, 0) + 1

    summary["top_talkers"]["source"] = dict(sorted(ip_src_counts.items(), key=lambda x: -x[1])[:10])
    summary["top_talkers"]["destination"] = dict(sorted(ip_dst_counts.items(), key=lambda x: -x[1])[:10])

    return summary


def pcap_to_flow_csv_notice() -> str:
    """Return notice about PCAP to flow conversion."""
    return """
PCAP to Flow Conversion
=======================

This tool does NOT convert PCAP to CIC-IDS2017 flow features directly.
For flow feature extraction, use CICFlowMeter:

1. Install Java (required for CICFlowMeter)
2. Download CICFlowMeter from: https://www.unb.ca/cic/flowmeter.html
3. Run CICFlowMeter on your PCAP file to generate flow CSV
4. Upload the resulting CSV to the Traffic Analysis page

CICFlowMeter produces CIC-IDS2017-compatible features including:
- Flow duration, packet/byte counts, rates
- Flag counts (SYN, ACK, PSH, RST, URG, FIN, etc.)
- Inter-arrival times, packet length statistics
- Forward/backward flow separation

Note: Different flow exporters compute features differently (timeouts,
bidirectional handling, units). Results on non-CICFlowMeter exports
may be unreliable.
"""


def check_live_capture_requirements() -> dict[str, Any]:
    """Check if live capture requirements are met."""
    import platform
    import subprocess
    import sys

    result = {
        "platform": platform.system(),
        "scapy_available": SCAPY_AVAILABLE,
        "npcap_or_libpcap": False,
        "privileges": False,
        "enabled": False,
    }

    if not SCAPY_AVAILABLE:
        return result

    system = platform.system()
    if system == "Windows":
        # Check for Npcap
        try:
            subprocess.run(["reg", "query", "HKLM\\SOFTWARE\\Npcap"], capture_output=True, check=True)
            result["npcap_or_libpcap"] = True
        except Exception:
            pass
        # Check admin
        try:
            import ctypes
            result["privileges"] = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            pass
    elif system in ("Linux", "Darwin"):
        # Check libpcap
        try:
            subprocess.run(["which", "tcpdump"], capture_output=True, check=True)
            result["npcap_or_libpcap"] = True
        except Exception:
            pass
        # Check capabilities or root
        result["privileges"] = hasattr(sys, "getuid") and sys.getuid() == 0

    result["enabled"] = result["npcap_or_libpcap"] and result["privileges"]
    return result