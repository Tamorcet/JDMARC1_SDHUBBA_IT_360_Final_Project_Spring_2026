# ai_recommendations.py
# Sends alert details to OpenAI for specific remediation advice.
# If OpenAI fails, it falls back to local rule-based recommendations.

from openai import OpenAI
from config import OPENAI_MODEL, USE_OPENAI


client = OpenAI()


def get_fallback_recommendations(alert: dict) -> str:
    """
    Local fallback recommendations.
    This works even without internet, API credits, or an API key.
    """

    src_ip = alert.get("src_ip", "unknown")
    dst_ip = alert.get("dst_ip", "unknown")
    src_port = alert.get("src_port", "unknown")
    dst_port = alert.get("dst_port", "unknown")
    protocol = alert.get("protocol", "unknown")
    match_type = alert.get("match_type", "unknown")
    sha256 = alert.get("sha256", "unknown")
    size = alert.get("size", "unknown")

    lines = []

    lines.append(f"1. Malicious payload detected over {protocol} from {src_ip}:{src_port} to {dst_ip}:{dst_port}.")

    if dst_ip in ["127.0.0.1", "localhost"]:
        lines.append("2. Destination is localhost. This is likely test traffic or a local process communicating internally.")
    else:
        lines.append(f"2. Investigate destination host {dst_ip}, because it received the suspicious payload.")

    lines.append(f"3. Check what service is listening on destination port {dst_port}:")
    lines.append(f"   sudo ss -tulnp | grep {dst_port}")

    lines.append(f"4. If port {dst_port} is not required, temporarily block it:")
    lines.append(f"   sudo ufw deny {dst_port}/{str(protocol).lower()}")

    if match_type == "packet_payload":
        lines.append("5. Match type was packet_payload, meaning the malicious content was visible in one packet.")
    elif match_type == "tcp_stream_buffer":
        lines.append("5. Match type was tcp_stream_buffer, meaning the suspicious data may have been split across packets.")

    lines.append(f"6. Search logs for source IP {src_ip}, destination IP {dst_ip}, port {dst_port}, and hash {sha256}.")
    lines.append(f"7. Preserve evidence: timestamp, packet capture, source/destination IPs, ports, protocol, payload size {size}, and hash.")
    lines.append("8. Run a malware scan and check processes, startup services, scheduled tasks, and recent file changes.")
    lines.append("9. After cleanup, keep monitoring for repeat connections using the same IPs, port, or hash.")

    return "\n".join(lines)


def get_ai_recommendations(alert: dict) -> str:
    """
    Gets AI recommendations from OpenAI.

    If OpenAI is disabled or the API request fails, the function returns fallback recommendations.
    """

    if not USE_OPENAI:
        return get_fallback_recommendations(alert)

    prompt = f"""
A network malware detector found a malicious SHA-256 hash match.

Alert details:
- Source IP: {alert.get("src_ip")}
- Source port: {alert.get("src_port")}
- Destination IP: {alert.get("dst_ip")}
- Destination port: {alert.get("dst_port")}
- Protocol: {alert.get("protocol")}
- Match type: {alert.get("match_type")}
- SHA-256: {alert.get("sha256")}
- Payload size: {alert.get("size")}
- Timestamp: {alert.get("timestamp")}
- Description: {alert.get("description")}

Give specific remediation recommendations based on the IPs, ports, protocol, and match type.

Include:
1. What likely happened
2. What system or service to check
3. Ubuntu commands the admin can run
4. Firewall or isolation steps
5. Evidence to preserve

Keep it practical, specific, and concise.
"""

    try:
        response = client.responses.create(
            model=OPENAI_MODEL,
            input=prompt,
        )

        return response.output_text

    except Exception as error:
        return (
            "AI recommendation request failed.\n"
            f"Error: {error}\n\n"
            "Fallback recommendations:\n"
            + get_fallback_recommendations(alert)
        )
