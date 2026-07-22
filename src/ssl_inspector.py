"""
SecureRecon - SSL/TLS Certificate Inspector
Connects to HTTPS-capable ports and inspects the presented certificate
and negotiated TLS version, flagging expired certs and weak protocols.

Certificate field parsing uses the system `openssl` binary via subprocess,
since Python's ssl module only populates getpeercert() fields when full
chain verification succeeds - which fails by design for self-signed or
untrusted certs commonly found in lab/test environments.
"""

import ssl
import socket
import subprocess
from datetime import datetime

TLS_PORTS = [443, 8443]
WEAK_TLS_VERSIONS = ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]


def get_raw_certificate(target, port, timeout=3):
    """
    Retrieve the raw PEM certificate and negotiated TLS version
    from target:port without requiring trust chain validation.
    Returns (pem_cert: str or None, tls_version: str or None).
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()
                pem_cert = ssl.DER_cert_to_PEM_cert(der_cert) if der_cert else None
                return pem_cert, tls_version
    except (socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError):
        return None, None


def parse_certificate_fields(pem_cert):
    """
    Use the openssl CLI to extract subject, issuer, and expiry date
    from a PEM certificate string. Returns a dict with those fields,
    or None values if parsing fails.
    """
    fields = {"subject": None, "issuer": None, "expiry_date": None, "days_remaining": None}

    if not pem_cert:
        return fields

    try:
        result = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-enddate"],
            input=pem_cert,
            capture_output=True,
            text=True,
            timeout=5
        )
        output = result.stdout

        for line in output.splitlines():
            if line.startswith("subject="):
                fields["subject"] = line.replace("subject=", "").strip()
            elif line.startswith("issuer="):
                fields["issuer"] = line.replace("issuer=", "").strip()
            elif line.startswith("notAfter="):
                date_str = line.replace("notAfter=", "").strip()
                try:
                    expiry_date = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
                    fields["expiry_date"] = expiry_date.strftime("%Y-%m-%d")
                    fields["days_remaining"] = (expiry_date - datetime.utcnow()).days
                except ValueError:
                    pass

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return fields


def inspect_certificate(target, port, timeout=3):
    """
    Full inspection of a single port: retrieves cert + TLS version,
    parses fields, and evaluates findings (expiry, weak TLS).
    Never raises - all failures handled gracefully.
    """
    result = {
        "port": port,
        "reachable": False,
        "subject": None,
        "issuer": None,
        "expiry_date": None,
        "days_remaining": None,
        "tls_version": None,
        "findings": []
    }

    pem_cert, tls_version = get_raw_certificate(target, port, timeout)

    if tls_version is None:
        return result  # unreachable / TLS handshake failed

    result["reachable"] = True
    result["tls_version"] = tls_version

    fields = parse_certificate_fields(pem_cert)
    result["subject"] = fields["subject"]
    result["issuer"] = fields["issuer"]
    result["expiry_date"] = fields["expiry_date"]
    result["days_remaining"] = fields["days_remaining"]

    days_remaining = fields["days_remaining"]
    if days_remaining is not None:
        if days_remaining < 0:
            result["findings"].append({
                "issue": "Certificate Expired",
                "severity": "High",
                "recommendation": "Renew the SSL/TLS certificate immediately."
            })
        elif days_remaining < 30:
            result["findings"].append({
                "issue": f"Certificate Expiring Soon ({days_remaining} days)",
                "severity": "Medium",
                "recommendation": "Renew the SSL/TLS certificate before it expires."
            })

    if tls_version in WEAK_TLS_VERSIONS:
        result["findings"].append({
            "issue": f"Weak/Deprecated TLS Version ({tls_version})",
            "severity": "High",
            "recommendation": "Upgrade to TLS 1.2 or TLS 1.3 and disable older protocols."
        })

    return result


def inspect_all(target, open_ports, timeout=3):
    """Run SSL/TLS inspection on all open ports that are TLS candidates."""
    candidates = [p for p in open_ports if p in TLS_PORTS]
    return [inspect_certificate(target, port, timeout) for port in candidates]


def print_ssl_results(results):
    """Pretty-print SSL/TLS inspection results to console."""
    print("=" * 50)
    print("SSL/TLS CERTIFICATE INSPECTION")
    print("=" * 50)
    if not results:
        print("No HTTPS/TLS ports found to inspect.")
        print("=" * 50)
        print()
        return

    for r in results:
        print(f"Port {r['port']}:")
        if not r["reachable"]:
            print("  Could not establish TLS connection.")
            print()
            continue
        print(f"  Subject: {r['subject']}")
        print(f"  Issuer: {r['issuer']}")
        print(f"  Expiry Date: {r['expiry_date']}")
        print(f"  Days Remaining: {r['days_remaining']}")
        print(f"  TLS Version: {r['tls_version']}")
        if r["findings"]:
            for f in r["findings"]:
                print(f"  [{f['severity']}] {f['issue']}")
                print(f"      Recommendation: {f['recommendation']}")
        else:
            print("  No certificate/TLS issues found.")
        print()
    print("=" * 50)
    print()
