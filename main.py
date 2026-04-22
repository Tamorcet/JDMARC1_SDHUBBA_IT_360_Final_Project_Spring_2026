from ai_stage import get_optional_ai_insight
from parse_report import parse_and_save_text_report
from scanner import run_nmap_scan


def _get_target() -> str:
    """Prompt for and validate a scan target."""
    target = input("Enter target domain or IP: ").strip()
    if not target:
        raise ValueError("Target cannot be empty.")
    return target


def main() -> int:
    """Run the full recon pipeline and return a process exit code."""
    print("=== Recon Pipeline ===")

    try:
        target = _get_target()

        print("\n[1/3] Running Nmap scan...")
        raw_xml = run_nmap_scan(target)

        print("[2/3] Parsing output and writing readable text report...")
        report_path, report_text = parse_and_save_text_report(target, raw_xml)

        print("[3/3] Optional AI insight...")
        ai_insight = get_optional_ai_insight(report_text)

    except KeyboardInterrupt:
        print("\n[!] Cancelled by user.")
        return 130
    except Exception as exc:
        print(f"\n[!] Error: {exc}")
        return 1

    print("\n========== COMPLETE ==========")
    print(f"Text Report Path: {report_path}")
    print("\nReport Output:\n")
    print(report_text.rstrip())
    if ai_insight is not None:
        print("\nAI Insight:")
        print(ai_insight)
    else:
        print("\nAI Insight: Skipped by user.")
    print("================================\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
