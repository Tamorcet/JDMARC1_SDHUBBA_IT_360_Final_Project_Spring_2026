# monitor.py
# Captures packets, hashes packet payloads, and checks them against known bad hashes.

import hashlib
import time
from collections import deque
from typing import Callable

from scapy.all import IP, TCP, UDP, Raw, sniff


# Maximum TCP stream data saved per connection.
MAX_FLOW_BUFFER = 1024 * 1024  # 1 MB

# Remove inactive TCP flows after 300 seconds.
FLOW_TIMEOUT = 300


class FlowTracker:
    """
    Tracks TCP stream data.

    Some malicious payloads may be split across multiple TCP packets.
    This class stores recent chunks from the same TCP flow so the program
    can also hash the combined stream buffer.
    """

    def __init__(self) -> None:
        self._flows: dict[tuple, dict] = {}

    def add_payload(self, flow_key: tuple, payload: bytes) -> bytes:
        """
        Adds payload data to a TCP flow and returns the current stream buffer.
        """

        now = time.time()

        if flow_key not in self._flows:
            self._flows[flow_key] = {
                "last_seen": now,
                "chunks": deque(),
                "size": 0,
            }

        flow = self._flows[flow_key]
        flow["last_seen"] = now
        flow["chunks"].append(payload)
        flow["size"] += len(payload)

        # Keep memory usage controlled.
        while flow["size"] > MAX_FLOW_BUFFER and flow["chunks"]:
            removed = flow["chunks"].popleft()
            flow["size"] -= len(removed)

        return b"".join(flow["chunks"])

    def cleanup(self) -> None:
        """
        Removes old inactive TCP flows.
        """

        now = time.time()

        expired = [
            key
            for key, value in self._flows.items()
            if now - value["last_seen"] > FLOW_TIMEOUT
        ]

        for key in expired:
            del self._flows[key]


def sha256_bytes(data: bytes) -> str:
    """
    Returns the SHA-256 hash of bytes.
    """

    return hashlib.sha256(data).hexdigest()


def build_flow_key(packet) -> tuple | None:
    """
    Builds a unique key for a TCP connection.
    """

    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return None

    return (
        packet[IP].src,
        packet[TCP].sport,
        packet[IP].dst,
        packet[TCP].dport,
        "TCP",
    )


def extract_packet_metadata(packet) -> dict:
    """
    Extracts useful packet details for alert reporting.
    """

    metadata = {
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": "OTHER",
    }

    if packet.haslayer(IP):
        metadata["src_ip"] = packet[IP].src
        metadata["dst_ip"] = packet[IP].dst

    if packet.haslayer(TCP):
        metadata["src_port"] = packet[TCP].sport
        metadata["dst_port"] = packet[TCP].dport
        metadata["protocol"] = "TCP"

    elif packet.haslayer(UDP):
        metadata["src_port"] = packet[UDP].sport
        metadata["dst_port"] = packet[UDP].dport
        metadata["protocol"] = "UDP"

    return metadata


def start_live_monitor(
    malicious_hashes: set[str],
    interface: str | None,
    bpf_filter: str | None,
    alert_callback: Callable[[dict], None],
) -> None:
    """
    Starts live packet monitoring.

    For each packet with payload data:
    1. Hash the packet payload.
    2. Compare it against the malicious hash list.
    3. If TCP, also hash the rolling stream buffer.
    4. Send alert data to the callback function.
    """

    flow_tracker = FlowTracker()

    # Prevents the same alert from printing repeatedly.
    seen_alerts: set[tuple[str, str, str, str]] = set()

    def process(packet) -> None:
        flow_tracker.cleanup()

        # Ignore packets without IP or raw payload data.
        if not packet.haslayer(IP):
            return

        if not packet.haslayer(Raw):
            return

        payload = bytes(packet[Raw].load)

        if not payload:
            return

        meta = extract_packet_metadata(packet)

        # Check single packet payload hash.
        payload_hash = sha256_bytes(payload)

        alert_key = (
            "packet",
            str(meta["src_ip"] or ""),
            str(meta["dst_ip"] or ""),
            payload_hash,
        )

        if payload_hash in malicious_hashes and alert_key not in seen_alerts:
            seen_alerts.add(alert_key)

            alert_callback(
                {
                    **meta,
                    "match_type": "packet_payload",
                    "sha256": payload_hash,
                    "size": len(payload),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "description": "Matched SHA-256 hash from packet payload.",
                }
            )

        # Check rolling TCP stream hash.
        if packet.haslayer(TCP):
            flow_key = build_flow_key(packet)

            if flow_key is not None:
                stream_data = flow_tracker.add_payload(flow_key, payload)
                stream_hash = sha256_bytes(stream_data)

                stream_alert_key = (
                    "stream",
                    str(meta["src_ip"] or ""),
                    str(meta["dst_ip"] or ""),
                    stream_hash,
                )

                if stream_hash in malicious_hashes and stream_alert_key not in seen_alerts:
                    seen_alerts.add(stream_alert_key)

                    alert_callback(
                        {
                            **meta,
                            "match_type": "tcp_stream_buffer",
                            "sha256": stream_hash,
                            "size": len(stream_data),
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "description": "Matched SHA-256 hash from rolling TCP stream buffer.",
                        }
                    )

    sniff(
        iface=interface,
        filter=bpf_filter,
        prn=process,
        store=False,
    )
