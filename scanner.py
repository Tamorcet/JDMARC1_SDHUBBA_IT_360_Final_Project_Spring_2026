import shutil
import subprocess


def run_nmap_scan(target: str, timeout_seconds: int = 300) -> str:
    """Run an Nmap service scan and return raw XML output."""
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        raise RuntimeError(
            "Nmap is not installed"
        )

    cmd = [nmap_path, "-sV", "-Pn", "-T4", "-oX", "-", target]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "Failed to launch Nmap."
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Nmap scan timed out after {timeout_seconds} seconds.")

    if result.returncode != 0:
        stderr = result.stderr.strip() or "No error output provided."
        raise RuntimeError(f"Nmap scan failed:\n{stderr}")

    if not result.stdout.strip():
        raise RuntimeError("Nmap ran but did not return any XML output.")

    return result.stdout
