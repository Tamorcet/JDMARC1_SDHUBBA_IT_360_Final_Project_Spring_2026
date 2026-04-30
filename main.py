from alerts import AlertLogger
from config import BPF_FILTER, HASH_DB_PATH, INTERFACE
from hash_db import load_hash_database
from monitor import start_live_monitor


def main() -> int:
    print("=== Live Malware Traffic Monitor ===")

    try:
        malicious_hashes = load_hash_database(HASH_DB_PATH)
        print(f"[+] Loaded {len(malicious_hashes)} SHA-256 hashes.")

        logger = AlertLogger("alerts.log")

        print("[+] Starting live capture...")
        print(f"    Interface: {INTERFACE or 'default'}")
        print(f"    Filter:    {BPF_FILTER or 'none'}")
        print("    Press Ctrl+C to stop.\n")

        start_live_monitor(
            malicious_hashes=malicious_hashes,
            interface=INTERFACE,
            bpf_filter=BPF_FILTER,
            alert_callback=logger.handle_alert,
        )

    except KeyboardInterrupt:
        print("\n[!] Monitor stopped by user.")
        return 130
    except Exception as exc:
        print(f"\n[!] Error: {exc}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
