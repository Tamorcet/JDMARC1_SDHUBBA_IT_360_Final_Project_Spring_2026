import json
import os
import urllib.error
import urllib.request
from typing import Optional

HOSTED_OLLAMA_URL = "http://sushi.it.ilstu.edu:8080"
HOSTED_OLLAMA_MODEL = "llama3.2-vision:latest"
HOSTED_OLLAMA_API_KEY = "<API_KEY>"
HOSTED_OLLAMA_AUTH_SCHEME = "Bearer"
HOSTED_OLLAMA_TIMEOUT_SECONDS = 45.0
FAILED_SUMMARY = "failed to get ai summary"


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _clean_value(value: str) -> str:
    """Trim whitespace and accidental quote characters from pasted values."""
    return value.strip().strip("\"'“”")


OLLAMA_TIMEOUT_SECONDS = _env_float("OLLAMA_TIMEOUT_SECONDS", HOSTED_OLLAMA_TIMEOUT_SECONDS)
OLLAMA_URL = _clean_value(os.getenv("OLLAMA_URL", HOSTED_OLLAMA_URL))
OLLAMA_MODEL = _clean_value(os.getenv("OLLAMA_MODEL", HOSTED_OLLAMA_MODEL))
OLLAMA_API_KEY = _clean_value(os.getenv("OLLAMA_API_KEY", HOSTED_OLLAMA_API_KEY))
OLLAMA_AUTH_SCHEME = _clean_value(os.getenv("OLLAMA_AUTH_SCHEME", HOSTED_OLLAMA_AUTH_SCHEME))


def analyze_text_with_ai(report_text: str) -> str:
    prompt = (
        "You are a security analyst. Read this Nmap text report and provide concise security insight.\n"
        "Include: overall risk, likely weak points, and immediate next steps.\n"
        "Keep it short and practical.\n\n"
        f"Report:\n{report_text}"
    )
    headers = {"Content-Type": "application/json"}
    if OLLAMA_API_KEY:
        headers["Authorization"] = (
            f"{OLLAMA_AUTH_SCHEME} {OLLAMA_API_KEY}" if OLLAMA_AUTH_SCHEME else OLLAMA_API_KEY
        )

    body = {
        "model": OLLAMA_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "stream": True,
    }

    req = urllib.request.Request(
        url=f"{OLLAMA_URL.rstrip('/')}/ollama/api/chat",
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    try:
        full_response = ""
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT_SECONDS) as response:
            for raw_line in response:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                chunk = json.loads(line)
                message = chunk.get("message")
                if isinstance(message, dict):
                    content = message.get("content", "")
                    if isinstance(content, str):
                        full_response += content
                if chunk.get("done"):
                    break

        if full_response.strip():
            return full_response.strip()
        return FAILED_SUMMARY
    except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError, KeyError):
        return FAILED_SUMMARY


def _prompt_for_ai() -> bool:
    """Prompt the user to decide whether to send report text to AI."""
    while True:
        choice = input("Send report to AI for insight? (yes/no): ").strip().lower()
        if choice in {"yes", "y"}:
            return True
        if choice in {"no", "n"}:
            return False
        print("Please type 'yes' or 'no'.")


def get_optional_ai_insight(report_text: str) -> Optional[str]:
    """Ask user if AI should be used, then return AI insight or None."""
    should_send = _prompt_for_ai()
    if not should_send:
        return None

    return analyze_text_with_ai(report_text)
