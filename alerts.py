from pathlib import Path


class AlertLogger:
    def __init__(self, log_path: str) -> None:
        self.log_path = Path(log_path)

    def handle_alert(self, event: dict) -> None:
        message = self._format_alert(event)
        print(message)
        self._write_to_log(message)

    def _format_alert(self, event: dict) -> str:
        return (
            "\n[!!!] MALICIOUS HASH MATCH DETECTED\n"
            f"Time:            {event.get('timestamp')}\n"
            f"Type:            {event.get('match_type')}\n"
            f"Source IP:       {event.get('src_ip')}\n"
            f"Source Port:     {event.get('src_port')}\n"
            f"Destination IP:  {event.get('dst_ip')}\n"
            f"Destination Port:{event.get('dst_port')}\n"
            f"Protocol:        {event.get('protocol')}\n"
            f"SHA-256:         {event.get('sha256')}\n"
            f"Bytes:           {event.get('size')}\n"
            f"Description:     {event.get('description')}\n"
        )

    def _write_to_log(self, message: str) -> None:
        with self.log_path.open("a", encoding="utf-8") as file:
            file.write(message)
            file.write("\n")
