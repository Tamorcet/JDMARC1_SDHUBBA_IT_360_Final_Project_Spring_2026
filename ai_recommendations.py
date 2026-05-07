import os
from typing import Any


def build_basic_recommendation(alert: dict[str, Any]) -> str:
    """
    Offline fallback recommendation.
    This does not require internet or an API key.
    It gives safe incident-response steps based on the alert metadata.
    """
    src_ip = alert.get("src_ip", "unknown")
    dst_ip = alert.get("dst_ip", "unknown")
    src_port = alert.get("src_port", "unknown")
    dst_port = alert.get("dst_port", "unknown")
    protocol = alert.get("protocol", "unknown")
    match_type = alert.get("match_type", "unknown")
    sha256_hash = alert.get("sha256", "unknown")

    return f"""
AI/Rule-Based Recommendation:
1. Treat this as a confirmed indicator match because network payload data matched a known malicious SHA-256 hash.
2. Identify the affected host: source {src_ip}:{src_port} -> destination {dst_ip}:{dst_port} over {protocol}.
3. Isolate or block the suspicious traffic path temporarily while investigating.
4. Check both endpoints for malware, suspicious processes, new files, strange scheduled tasks, and recent login activity.
5. Search firewall, DNS, proxy, and endpoint logs for the hash {sha256_hash} and both IP addresses.
6. If the source is an internal host, disconnect it from the network or place it in a quarantine VLAN.
7. If the destination is external, block the destination IP/domain at the firewall and review other hosts that contacted it.
8. Update antivirus/EDR signatures and run a full scan on the affected endpoint.
9. Preserve evidence: packet capture, alert timestamp, hash, source/destination IPs, and user logged into the host.
10. After cleanup, patch the system, reset exposed credentials, and monitor for repeated connections.

Alert Context:
- Match Type: {match_type}
- SHA-256: {sha256_hash}
""".strip()


def build_openai_recommendation(alert: dict[str, Any], model: str = "gpt-5.5") -> str:
    """
    Sends the alert details to the OpenAI API and asks for defensive remediation advice.
    Requires:
      pip install openai
      export OPENAI_API_KEY="your_api_key_here"
    """
    try:
        from openai import OpenAI
    except ImportError:
        return "OpenAI package is not installed. Using offline recommendation instead.\n\n" + build_basic_recommendation(alert)

    if not os.getenv("OPENAI_API_KEY"):
        return "OPENAI_API_KEY is not set. Using offline recommendation instead.\n\n" + build_basic_recommendation(alert)

    client = OpenAI()

    prompt = f"""
You are a defensive cybersecurity assistant for a student network-monitoring project.
A packet monitoring tool detected a malicious SHA-256 hash match.
Give clear, practical, defensive remediation steps.
Do not provide exploit instructions.

Alert details:
{alert}

Format your answer with:
- Likely meaning
- Immediate containment steps
- Investigation steps
- Recovery steps
- Prevention steps
""".strip()

    try:
        response = client.responses.create(
            model=model,
            input=prompt,
        )
        return response.output_text
    except Exception as error:
        return f"AI request failed: {error}\n\nUsing offline recommendation instead.\n\n" + build_basic_recommendation(alert)


def get_recommendation(alert: dict[str, Any], use_openai: bool = False, model: str = "gpt-5.5") -> str:
    """
    Main function called by the alert system.
    If OpenAI is enabled, it asks the AI for recommendations.
    Otherwise, it uses the safe offline recommendation.
    """
    if use_openai:
        return build_openai_recommendation(alert, model=model)

    return build_basic_recommendation(alert)
