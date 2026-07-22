"""
SecureRecon - HTTP Security Header Analyzer
Checks common web security headers on discovered HTTP(S) ports and
reports missing/weak configurations with severity and remediation.
"""

import http.client
import ssl

# Ports we consider worth an HTTP-level check
HTTP_PORTS = {80: False, 8080: False, 443: True, 8443: True}  # value = use_https

# Header -> (severity, reason, recommendation)
HEADER_CHECKS = {
    "Strict-Transport-Security": (
        "Medium",
        "Without HSTS, browsers may connect over unencrypted HTTP, exposing traffic.",
        "Implement the Strict-Transport-Security header to enforce HTTPS."
    ),
    "Content-Security-Policy": (
        "Medium",
        "Missing CSP increases risk of Cross-Site Scripting (XSS) attacks.",
        "Implement a Content-Security-Policy header."
    ),
    "X-Frame-Options": (
        "Low",
        "Without this header, the site may be vulnerable to clickjacking.",
        "Set X-Frame-Options to DENY or SAMEORIGIN."
    ),
    "X-Content-Type-Options": (
        "Low",
        "Missing this header allows MIME-type sniffing, which can lead to content injection.",
        "Set X-Content-Type-Options to nosniff."
    ),
}


def fetch_headers(target, port, use_https, timeout=3):
    """
    Connect to target:port and issue a HEAD request to retrieve headers.
    Returns a dict of headers (lowercased keys) or None on failure.
    """
    try:
        if use_https:
            context = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(target, port, timeout=timeout, context=context)
        else:
            conn = http.client.HTTPConnection(target, port, timeout=timeout)

        conn.request("HEAD", "/")
        response = conn.getresponse()
        headers = {k.lower(): v for k, v in response.getheaders()}
        conn.close()
        return headers
    except (http.client.HTTPException, OSError, ssl.SSLError):
        return None


def analyze_headers(target, open_ports, timeout=3):
    """
    For each open port that looks like an HTTP(S) service, fetch headers
    and evaluate them against HEADER_CHECKS.

    Returns a list of dicts, one per checked port:
        {
            "port": int,
            "reachable": bool,
            "server_header": str or None,
            "findings": [ {header, status, severity, reason, recommendation} ]
        }
    """
    results = []
    candidate_ports = [p for p in open_ports if p in HTTP_PORTS]

    for port in candidate_ports:
        use_https = HTTP_PORTS[port]
        headers = fetch_headers(target, port, use_https, timeout)

        if headers is None:
            results.append({
                "port": port,
                "reachable": False,
                "server_header": None,
                "findings": []
            })
            continue

        findings = []
        for header_name, (severity, reason, recommendation) in HEADER_CHECKS.items():
            if header_name.lower() not in headers:
                findings.append({
                    "header": header_name,
                    "status": "Missing",
                    "severity": severity,
                    "reason": reason,
                    "recommendation": recommendation
                })

        # Server header exposure is its own informational finding
        server_header = headers.get("server")
        if server_header:
            findings.append({
                "header": "Server",
                "status": f"Exposed: {server_header}",
                "severity": "Low",
                "reason": "Revealing server/software version can help attackers target known vulnerabilities.",
                "recommendation": "Suppress or generalize the Server header."
            })

        results.append({
            "port": port,
            "reachable": True,
            "server_header": server_header,
            "findings": findings
        })

    return results


def print_http_analysis(results):
    """Pretty-print HTTP header analysis results to console."""
    print("=" * 50)
    print("HTTP SECURITY HEADER ANALYSIS")
    print("=" * 50)
    if not results:
        print("No HTTP/HTTPS ports found to analyze.")
        print("=" * 50)
        print()
        return

    for r in results:
        print(f"Port {r['port']}:")
        if not r["reachable"]:
            print("  Could not retrieve HTTP headers (connection failed).")
            continue
        if not r["findings"]:
            print("  All checked security headers are present. No issues found.")
        for f in r["findings"]:
            print(f"  [{f['severity']}] {f['header']}: {f['status']}")
            print(f"      Reason: {f['reason']}")
            print(f"      Recommendation: {f['recommendation']}")
        print()
    print("=" * 50)
    print()
