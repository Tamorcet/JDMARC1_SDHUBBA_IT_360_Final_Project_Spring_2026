import hashlib
import time
from collections import deque
from typing import Callable

# Scapy is used to capture and inspect packets.
from scapy.all import IP, TCP, UDP, Raw, sniff


# Maximum amount of TCP payload data saved per connection.
# This prevents the program from using too much memory.
MAX_FLOW_BUFFER = 1024 * 1024  # 1 MB

# If a TCP flow is inactive for 300 seconds, it is removed.
FLOW_TIMEOUT = 300


class FlowTracker:
    """
    Tracks TCP traffic streams.

    Network traffic is often split across many packets.
    This class stores recent packet payloads from the same TCP connection
    so the program can also hash a rolling stream buffer.
    """

    def __init__(self) -> None:
        # Dictionary where each key is a TCP flow and each value stores payload chunks.
        self._flows: dict[tuple, dict] = {}

    def add_payload(self, flow_key: tuple, payload: bytes) -> bytes:
        """
        Adds packet payload data to a TCP flow.
        Returns the current rolling stream data for that flow.
        """

        now = time.time()

        # If this is a new TCP flow, create a new entry for it.
        if flow_key not in self._flows:
            self._flows[flow_key] = {
                "last_seen": now,
                "chunks": deque(),
                "size": 0,
            }

        flow = self._flows[flow_key]

        # Update last seen time.
        flow["last_seen"] = now

        # Add the new payload chunk.
        flow["chunks"].append(payload)
        flow["size"] += len(payload)

        # If the buffer gets too large, remove old chunks.
        while flow["size"] > MAX_FLOW_BUFFER and flow["chunks"]:
            removed = flow["chunks"].popleft()
            flow["size"] -= len(removed)

        # Return all saved chunks as one byte string.
        return b"".join(flow["chunks"])

    def cleanup(self) -> None:
        """
        Removes old inactive TCP flows from memory.
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
    Takes bytes of data and returns the SHA-256 hash.
    """

    return hashlib.sha256(data).hexdigest()


def build_flow_key(packet) -> tuple | None:
    """
    Builds a unique identifier for a TCP connection.

    A flow key includes:
    - source IP
    - source port
    - destination IP
    - destination port
    - protocol
    """

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
    """
    Pulls useful information from a packet for alert reporting.
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
    Starts packet sniffing.

    Every packet is checked for payload data.
    If payload data exists, the program hashes it and compares it
    against the known malicious SHA-256 hash database.
    """

    # Tracks rolling TCP stream buffers.
    flow_tracker = FlowTracker()

    # Prevents the same alert from printing repeatedly.
    seen_alerts: set[tuple[str, str, str, str]] = set()

    def process(packet) -> None:
        """
        This function runs automatically for every captured packet.
        """

        # Remove old inactive flows.
        flow_tracker.cleanup()

        # Ignore packets that do not have an IP layer.
        if not packet.haslayer(IP):
            return

        # Ignore packets with no raw payload.
        if not packet.haslayer(Raw):
            return

        payload = bytes(packet[Raw].load)

        # Ignore empty payloads.
        if not payload:
            return

        # Extract source/destination IPs, ports, and protocol.
        meta = extract_packet_metadata(packet)

        # -----------------------------
        # Check individual packet hash
        # -----------------------------

        # Hash the packet payload.
        payload_hash = sha256_bytes(payload)

        # Create a unique alert key to avoid duplicate alerts.
        alert_key_1 = (
            "packet",
            str(meta["src_ip"] or ""),
            str(meta["dst_ip"] or ""),
            payload_hash,
        )

        # If the hash is in the malicious hash database, create an alert.
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

        # ------------------------------------
        # Check rolling TCP stream buffer hash
        # ------------------------------------

        # Only TCP traffic is stream-tracked.
        if packet.haslayer(TCP):
            flow_key = build_flow_key(packet)

            if flow_key is not None:
                # Add this packet payload to the TCP flow buffer.
                stream_data = flow_tracker.add_payload(flow_key, payload)

                # Hash the rolling stream buffer.
                stream_hash = sha256_bytes(stream_data)

                alert_key_2 = (
                    "stream",
                    str(meta["src_ip"] or ""),
                    str(meta["dst_ip"] or ""),
                    stream_hash,
                )

                # Alert if the rolling stream hash matches.
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

    # This starts the actual packet capture.
    # prn=process means every packet is sent to the process() function.
    # store=False means packets are not saved in memory.
    sniff(
        iface=interface,
        filter=bpf_filter,
        prn=process,
        store=False,
    )
    Network traffic is often split across many packets.
    This class stores recent packet payloads from the same TCP connection
    so the program can also hash a rolling stream buffer.
    """

    def __init__(self) -> None:
        # Dictionary where each key is a TCP flow and each value stores payload chunks.
        self._flows: dict[tuple, dict] = {}

    def add_payload(self, flow_key: tuple, payload: bytes) -> bytes:
        """
        Adds packet payload data to a TCP flow.
        Returns the current rolling stream data for that flow.
        """

        now = time.time()

        # If this is a new TCP flow, create a new entry for it.
        if flow_key not in self._flows:
            self._flows[flow_key] = {
                "last_seen": now,
                "chunks": deque(),
                "size": 0,
            }

        flow = self._flows[flow_key]

        # Update last seen time.
        flow["last_seen"] = now

        # Add the new payload chunk.
        flow["chunks"].append(payload)
        flow["size"] += len(payload)

        # If the buffer gets too large, remove old chunks.
        while flow["size"] > MAX_FLOW_BUFFER and flow["chunks"]:
            removed = flow["chunks"].popleft()
            flow["size"] -= len(removed)

        # Return all saved chunks as one byte string.
        return b"".join(flow["chunks"])

    def cleanup(self) -> None:
        """
        Removes old inactive TCP flows from memory.
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
    Takes bytes of data and returns the SHA-256 hash.
    """

    return hashlib.sha256(data).hexdigest()


def build_flow_key(packet) -> tuple | None:
    """
    Builds a unique identifier for a TCP connection.

    A flow key includes:
    - source IP
    - source port
    - destination IP
    - destination port
    - protocol
    """

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
    """
    Pulls useful information from a packet for alert reporting.
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
    Starts packet sniffing.

    Every packet is checked for payload data.
    If payload data exists, the program hashes it and compares it
    against the known malicious SHA-256 hash database.
    """

    # Tracks rolling TCP stream buffers.
    flow_tracker = FlowTracker()

    # Prevents the same alert from printing repeatedly.
    seen_alerts: set[tuple[str, str, str, str]] = set()

    def process(packet) -> None:
        """
        This function runs automatically for every captured packet.
        """

        # Remove old inactive flows.
        flow_tracker.cleanup()

        # Ignore packets that do not have an IP layer.
        if not packet.haslayer(IP):
            return

        # Ignore packets with no raw payload.
        if not packet.haslayer(Raw):
            return

        payload = bytes(packet[Raw].load)

        # Ignore empty payloads.
        if not payload:
            return

        # Extract source/destination IPs, ports, and protocol.
        meta = extract_packet_metadata(packet)

        # -----------------------------
        # Check individual packet hash
        # -----------------------------

        # Hash the packet payload.
        payload_hash = sha256_bytes(payload)

        # Create a unique alert key to avoid duplicate alerts.
        alert_key_1 = (
            "packet",
            str(meta["src_ip"] or ""),
            str(meta["dst_ip"] or ""),
            payload_hash,
        )

        # If the hash is in the malicious hash database, create an alert.
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

        # ------------------------------------
        # Check rolling TCP stream buffer hash
        # ------------------------------------

        # Only TCP traffic is stream-tracked.
        if packet.haslayer(TCP):
            flow_key = build_flow_key(packet)

            if flow_key is not None:
                # Add this packet payload to the TCP flow buffer.
                stream_data = flow_tracker.add_payload(flow_key, payload)

                # Hash the rolling stream buffer.
                stream_hash = sha256_bytes(stream_data)

                alert_key_2 = (
                    "stream",
                    str(meta["src_ip"] or ""),
                    str(meta["dst_ip"] or ""),
                    stream_hash,
                )

                # Alert if the rolling stream hash matches.
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

    # This starts the actual packet capture.
    # prn=process means every packet is sent to the process() function.
    # store=False means packets are not saved in memory.
    sniff(
        iface=interface,
        filter=bpf_filter,
        prn=process,
        store=False,
    )
