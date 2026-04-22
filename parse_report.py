import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any


REPORTS_DIR = Path("reports")


def sanitize_name(target: str) -> str:
    """Convert a target string into a filesystem-safe name."""
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in target)


def _parse_open_services(xml_data: str) -> tuple[list[dict[str, Any]], list[int]]:
    """Extract open services and open ports from Nmap XML output."""
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as exc:
        raise RuntimeError("Unable to parse Nmap XML output.") from exc

    services: list[dict[str, Any]] = []
    open_ports: set[int] = set()
    for host in root.findall("host"):
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue

            port_id_raw = port.attrib.get("portid")
            if port_id_raw is None:
                continue

            try:
                port_id = int(port_id_raw)
            except ValueError:
                continue

            service = port.find("service")
            attrs = service.attrib if service is not None else {}
            open_ports.add(port_id)

            services.append(
                {
                    "port": port_id,
                    "protocol": port.attrib.get("protocol", ""),
                    "service_name": attrs.get("name", "unknown") or "unknown",
                    "product": attrs.get("product", ""),
                    "version": attrs.get("version", ""),
                    "extra_info": attrs.get("extrainfo", ""),
                }
            )
    return services, sorted(open_ports)


def _build_report_text(target: str, services: list[dict[str, Any]], open_ports: list[int]) -> str:
    """Generate a readable text report from parsed services."""
    timestamp = datetime.now().isoformat(timespec="seconds")

    lines = [
        "=== Nmap Recon Report ===",
        f"Target: {target}",
        f"Timestamp: {timestamp}",
        f"Open Ports ({len(open_ports)}): {', '.join(str(p) for p in open_ports) if open_ports else 'None'}",
        "",
        "Open Services:",
    ]

    if not services:
        lines.append("- No open services detected.")
    else:
        for entry in services:
            details = " ".join(part for part in [entry.get("product"), entry.get("version")] if part).strip()
            detail_text = details or "unknown version"
            extra_info = entry.get("extra_info", "")
            if extra_info:
                detail_text = f"{detail_text} ({extra_info})"
            lines.append(
                f"- Port {entry.get('port')}/{entry.get('protocol')}: "
                f"{entry.get('service_name')} - {detail_text}"
            )

    return "\n".join(lines).strip() + "\n"


def parse_and_save_text_report(target: str, raw_xml: str) -> tuple[str, str]:
    """
    Parse Nmap XML and save a readable text report.

    Returns:
        tuple[path, report_text]
    """
    services, open_ports = _parse_open_services(raw_xml)
    report_text = _build_report_text(target, services, open_ports)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORTS_DIR / f"{sanitize_name(target)}_report.txt"
    report_path.write_text(report_text, encoding="utf-8")

    return str(report_path), report_text
