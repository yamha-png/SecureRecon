"""
SecureRecon - Host Availability Check Module
Determines whether a target host is reachable before scanning begins.
Tries ICMP ping first, falls back to a TCP probe on a common port.
"""

import subprocess
import socket
import platform


def icmp_ping(target, timeout=2):
    """
    Attempt an ICMP ping using the OS ping command.
    Returns True if the host responds, False otherwise.
    """
    param = "-n" if platform.system().lower() == "windows" else "-c"
    count = "1"
    timeout_flag = "-w" if platform.system().lower() == "windows" else "-W"

    command = ["ping", param, count, timeout_flag, str(timeout), target]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def tcp_probe(target, port=22, timeout=2):
    """
    Fallback reachability check: attempt a raw TCP connection
    to a common port (default 22/SSH). Used when ICMP is blocked
    or unavailable (common on hardened systems/firewalls).
    Returns True if the connection succeeds, False otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            return result == 0
    except (socket.gaierror, socket.timeout, OSError):
        return False


def check_host(target, tcp_fallback_port=22):
    """
    Determine host availability. Tries ICMP first; if that fails,
    falls back to a TCP probe on tcp_fallback_port.

    Returns a dict:
        {
            "reachable": bool,
            "method": "ICMP" | f"TCP Probe (Port {port})" | "None",
        }
    """
    if icmp_ping(target):
        return {"reachable": True, "method": "ICMP"}

    if tcp_probe(target, tcp_fallback_port):
        return {"reachable": True, "method": f"TCP Probe (Port {tcp_fallback_port})"}

    return {"reachable": False, "method": "None"}


def print_host_status(target, status):
    """Pretty-print the host check result to console."""
    print("=" * 50)
    print("HOST AVAILABILITY CHECK")
    print("=" * 50)
    print(f"Target: {target}")
    if status["reachable"]:
        print("Status: Host Reachable")
        print(f"Method Used: {status['method']}")
    else:
        print("Status: Host Unreachable")
        print("No response via ICMP or TCP probe.")
    print("=" * 50)
    print()
