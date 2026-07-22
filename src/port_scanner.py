"""
SecureRecon - Multi-threaded TCP Port Scanner
Scans a target for open TCP ports using a thread pool for speed.
Supports predefined profiles (quick/standard/full) and custom ranges.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Top 100 "commonly used" ports (a practical, well-known subset)
TOP_100_PORTS = [
    7, 20, 21, 22, 23, 25, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119,
    135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1434, 1720, 1723, 1755, 1900, 2000, 2001,
    2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646,
    7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
    49152, 49153, 49154, 49155, 49156, 49157
]

# Top 1000 is approximated here by extending the range logically;
# for this project we use a broader curated set for "standard" profile.
TOP_1000_RANGE = list(range(1, 1025)) + TOP_100_PORTS


def get_port_list(profile="quick", custom_ports=None):
    """
    Build the list of ports to scan based on profile or custom input.

    profile: "quick" (top 100), "standard" (top 1000-ish), "full" (1-65535)
    custom_ports: string like "20-25" or "80,443,8080" (overrides profile)
    """
    if custom_ports:
        ports = set()
        parts = custom_ports.split(",")
        for part in parts:
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(part))
        return sorted(ports)

    if profile == "quick":
        return sorted(set(TOP_100_PORTS))
    elif profile == "standard":
        return sorted(set(TOP_1000_RANGE))
    elif profile == "full":
        return list(range(1, 65536))
    else:
        return sorted(set(TOP_100_PORTS))


def scan_port(target, port, timeout=1):
    """
    Attempt a TCP connect to a single port.
    Returns (port, is_open: bool).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            return (port, result == 0)
    except (socket.gaierror, socket.timeout, OSError):
        return (port, False)


def scan_ports(target, profile="quick", custom_ports=None, timeout=1, max_threads=100):
    """
    Scan the target across the resolved port list using a thread pool.
    Returns a sorted list of open ports.
    """
    ports = get_port_list(profile, custom_ports)
    open_ports = []

    print(f"[*] Scanning {len(ports)} ports on {target} (profile: {profile})...")

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, target, port, timeout): port for port in ports}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)

    return sorted(open_ports)


def print_scan_results(target, open_ports):
    """Pretty-print the port scan results to console."""
    print("=" * 50)
    print("PORT SCAN RESULTS")
    print("=" * 50)
    print(f"Target: {target}")
    if open_ports:
        print(f"Open Ports Found: {len(open_ports)}")
        for port in open_ports:
            print(f"  - Port {port}: OPEN")
    else:
        print("No open ports found.")
    print("=" * 50)
    print()
