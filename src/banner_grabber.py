"""
SecureRecon - Service & Banner Detection Module
Attempts to identify the service running on each open port by
grabbing its banner (the initial data a service sends on connect,
or the response to a simple probe for protocols that stay silent).
"""

import socket

# Common port -> likely service name mapping, used as a fallback label
# when no banner is retrieved.
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
}


def grab_banner(target, port, timeout=2):
    """
    Attempt to grab a service banner from an open port.

    Strategy:
      1. Connect and try to passively read (many services like SSH/FTP/SMTP
         greet immediately).
      2. If nothing is received, send a minimal probe (HTTP HEAD-style)
         since some services (like HTTP) only respond after a request.

    Returns a dict:
        {
            "port": int,
            "service_guess": str,
            "banner": str or None
        }
    Never raises - all failures are handled gracefully.
    """
    service_guess = COMMON_SERVICES.get(port, "Unknown")
    banner = None

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target, port))

            try:
                # Passive read first
                sock.settimeout(timeout)
                data = sock.recv(1024)
                if data:
                    banner = data.decode(errors="ignore").strip()
            except socket.timeout:
                data = None

            # If nothing came back passively, try a minimal active probe
            if not banner:
                try:
                    probe = b"HEAD / HTTP/1.0\r\n\r\n"
                    sock.sendall(probe)
                    sock.settimeout(timeout)
                    data = sock.recv(1024)
                    if data:
                        banner = data.decode(errors="ignore").strip()
                except (socket.timeout, OSError):
                    pass

    except (socket.timeout, ConnectionRefusedError, OSError):
        banner = None

    return {
        "port": port,
        "service_guess": service_guess,
        "banner": banner if banner else None
    }


def grab_all_banners(target, open_ports, timeout=2):
    """
    Grab banners for a list of open ports.
    Returns a list of banner result dicts, one per port.
    """
    results = []
    print(f"[*] Grabbing service banners on {len(open_ports)} open port(s)...")
    for port in open_ports:
        result = grab_banner(target, port, timeout)
        results.append(result)
    return results


def print_banner_results(results):
    """Pretty-print banner grabbing results to console."""
    print("=" * 50)
    print("SERVICE & BANNER DETECTION")
    print("=" * 50)
    if not results:
        print("No open ports to inspect.")
    for r in results:
        print(f"Port {r['port']} ({r['service_guess']}):")
        if r["banner"]:
            # Trim long/multiline banners for clean console output
            clean_banner = r["banner"].splitlines()[0][:120]
            print(f"  Banner Retrieved: {clean_banner}")
        else:
            print("  Banner Not Retrieved")
    print("=" * 50)
    print()
