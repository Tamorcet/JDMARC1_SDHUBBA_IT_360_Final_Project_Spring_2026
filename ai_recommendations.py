from openai import OpenAI

client = OpenAI()

def get_ai_recommendations(alert: dict) -> str:
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

Give specific remediation recommendations based on the IPs, ports, protocol, and match type.
Include:
1. What likely happened
2. What system/service to check
3. Commands the admin can run on Ubuntu
4. Firewall or isolation steps
5. Evidence to preserve
Keep it practical and concise.
"""

    try:
        response = client.responses.create(
            model="gpt-5.2",
            input=prompt,
        )
        return response.output_text

    except Exception as e:
        return (
            "AI recommendation request failed.\n"
            f"Error: {e}\n\n"
            "Fallback recommendation: isolate the affected host, check the service on the destination port, "
            "review logs, preserve evidence, and run a malware scan."
        )
