from ai_recommendations import get_recommendation
from config import BPF_FILTER, HASH_DB_PATH, INTERFACE, OPENAI_MODEL, USE_OPENAI_AI
from hash_db import load_hashes
from monitor import start_live_monitor


def print_alert(alert: dict) -> None:
    """
    This function runs every time the monitor detects a malicious hash match.
    It prints the alert and then asks the AI/recommendation module for fixes.
    """
    print("\n" + "=" * 70)
    print("MALICIOUS HASH DETECTED")
    print("=" * 70)

    for key, value in alert.items():
        print(f"{key}: {value}")

    print("\n" + "-" * 70)
    print("RECOMMENDED FIXES")
    print("-" * 70)

    recommendation = get_recommendation(
        alert,
        use_openai=USE_OPENAI_AI,
        model=OPENAI_MODEL,
    )
    print(recommendation)
    print("=" * 70 + "\n")


def main() -> None:
    print("Loading malicious hash database...")
    malicious_hashes = load_hashes(HASH_DB_PATH)
    print(f"Loaded {len(malicious_hashes)} SHA-256 hashes.")

    print("Starting live network monitor...")
    print("Press Ctrl+C to stop.\n")

    start_live_monitor(
        malicious_hashes=malicious_hashes,
        interface=INTERFACE,
        bpf_filter=BPF_FILTER,
        alert_callback=print_alert,
    )


if __name__ == "__main__":
    main()
