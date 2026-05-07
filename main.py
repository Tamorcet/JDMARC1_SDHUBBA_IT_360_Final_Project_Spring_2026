# main.py
# Main entry point for the malware detector.

from config import INTERFACE, BPF_FILTER, HASH_DB_PATH
from hash_db import load_hashes
from monitor import start_live_monitor
from ai_recommendations import get_ai_recommendations


def print_alert(alert: dict) -> None:
    """
    Prints alert details and AI remediation recommendations.
    """

    print("\n" + "=" * 70)
    print("MALICIOUS HASH DETECTED")
    print("=" * 70)

    for key, value in alert.items():
        print(f"{key}: {value}")

    print("\n" + "-" * 70)
    print("RECOMMENDED FIXES")
    print("-" * 70)

    recommendations = get_ai_recommendations(alert)
    print(recommendations)

    print("=" * 70 + "\n")


def main() -> None:
    """
    Loads the malicious hash database and starts live network monitoring.
    """

    print("Loading malicious hash database...")
    malicious_hashes = load_hashes(HASH_DB_PATH)

    print(f"Loaded {len(malicious_hashes)} SHA-256 hashes.")
    print("Starting live network monitor...")
    print("Press Ctrl+C to stop.")

    start_live_monitor(
        malicious_hashes=malicious_hashes,
        interface=INTERFACE,
        bpf_filter=BPF_FILTER,
        alert_callback=print_alert,
    )


if __name__ == "__main__":
    main()
