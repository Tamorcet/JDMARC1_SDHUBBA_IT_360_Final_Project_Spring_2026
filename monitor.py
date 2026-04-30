import hashlib
import time
from collections import deque
from typing import Callable

from scapy.all import IP, TCP, UDP, Raw, sniff

MAX_FLOW_BUFFER = 1024 * 1024  # 1 MB
FLOW_TIMEOUT = 300  # seconds


class FlowTracker:
    """Track rolling TCP payload buffers by flow."""

    def __init__(self) -> None:
        self._flows: dict[tuple, dict] = {}

    def add_payload(self, flow_key: tuple, payload: bytes) -> bytes:
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

        while flow["size"] > MAX_FLOW_BUFFER and flow["chunks"]:
            removed = flow["chunks"].popleft()
            flow["size"] -= len(removed)

        return b"".join(flow["chunks"])

    def cleanup(self) -> None:
        now = time.time()
        expired = [
            key
            for key, value in self._flows.items()
            if now - value["last_seen"] > FLOW_TIMEOUT
        ]
        for key in expired:
            del self._flows[key]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_flow_key(packet) -> tuple | None:
    if not packet.haslayer(IP):
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        proto = "TCP"
    else:
        return None

    return (src_ip, src_port, dst_ip, dst_port, proto)


def extract_packet_metadata(packet) -> dict:
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
    flow_tracker = FlowTracker()
    seen_alerts: set[tuple[str, str, str, str]] = set()

    def process(packet) -> None:
        flow_tracker.cleanup()

        if not packet.haslayer(IP):
            return

        if not packet.haslayer(Raw):
            return

        payload = bytes(packet[Raw].load)
        if not payload:
            return

        meta = extract_packet_metadata(packet)

        # Check raw packet payload hash
        payload_hash = sha256_bytes(payload)
        alert_key_1 = (
            "packet",
            str(meta["src_ip"] or ""),
            str(meta["dst_ip"] or ""),
            payload_hash,
        )

        if payload_hash in malicious_hashes and alert_key_1 not in seen_alerts:
            seen_alerts.add(alert_key_1)
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

        # Check rolling TCP stream buffer hash
        if packet.haslayer(TCP):
            flow_key = build_flow_key(packet)
            if flow_key is not None:
                stream_data = flow_tracker.add_payload(flow_key, payload)
                stream_hash = sha256_bytes(stream_data)

                alert_key_2 = (
                    "stream",
                    str(meta["src_ip"] or ""),
                    str(meta["dst_ip"] or ""),
                    stream_hash,
                )

                if stream_hash in malicious_hashes and alert_key_2 not in seen_alerts:
                    seen_alerts.add(alert_key_2)
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
