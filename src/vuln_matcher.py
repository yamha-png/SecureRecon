"""
SecureRecon - Rule-Based Vulnerability Assessment Engine
Correlates results from banner grabbing, HTTP analysis, and SSL/TLS
inspection against a curated local signature database, and applies
protocol-risk heuristics (e.g. plaintext protocols).

IMPORTANT: This engine performs heuristic version/pattern matching,
not live CVE database verification. Every match is reported as a
"Potential Match" with the source reference included, and is NOT a
confirmed exploit or verified vulnerability.
"""

import json
import os

SIGNATURES_PATH = os.path.join(os.path.dirname(__file__), "vuln_signatures.json")

# Protocols considered inherently risky if found running (plaintext credentials/data)
RISKY_PROTOCOLS = {
    21: ("FTP", "Medium", "FTP transmits credentials and data in plaintext.",
         "Replace FTP with SFTP or FTPS."),
    23: ("Telnet", "High", "Telnet transmits credentials and session data in plaintext.",
         "Replace Telnet with SSH."),
}


def load_signatures():
    """Load the local vulnerability signature database."""
    try:
        with open(SIGNATURES_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def match_banner_signatures(banner_results, signatures):
    """
    Compare each grabbed banner against the signature database for
    version-pattern substring matches. Returns a list of finding dicts.
    """
    findings = []
    for result in banner_results:
        banner = result.get("banner")
        port = result.get("port")
        service_guess = result.get("service_guess")

        if not banner:
            continue

        for sig in signatures:
            if sig["version_pattern"] in banner:
                findings.append({
                    "type": "Signature Match",
                    "port": port,
                    "service": service_guess,
                    "matched_pattern": sig["version_pattern"],
                    "cve": sig["cve"],
                    "severity": sig["severity"],
                    "confidence": "Medium",
                    "description": sig["description"],
                    "recommendation": sig["recommendation"],
                    "source": sig["source"],
                    "note": "Potential Match - based on banner/version pattern only, not a confirmed exploit."
                })
    return findings


def check_risky_protocols(open_ports):
    """Flag inherently risky plaintext protocols if their default ports are open."""
    findings = []
    for port, (name, severity, reason, recommendation) in RISKY_PROTOCOLS.items():
        if port in open_ports:
            findings.append({
                "type": "Risky Protocol",
                "port": port,
                "service": name,
                "matched_pattern": None,
                "cve": None,
                "severity": severity,
                "confidence": "High",
                "description": reason,
                "recommendation": recommendation,
                "source": None,
                "note": "Protocol-level risk, independent of version."
            })
    return findings


def aggregate_http_and_ssl_findings(http_results, ssl_results):
    """
    Fold HTTP header findings and SSL/TLS findings into the same
    unified finding format used by the assessment engine, so the
    report generator has one consistent structure to work with.
    """
    findings = []
    for r in http_results:
        for f in r.get("findings", []):
            findings.append({
                "type": "HTTP Header Finding",
                "port": r["port"],
                "service": "HTTP(S)",
                "matched_pattern": None,
                "cve": None,
                "severity": f["severity"],
                "confidence": "High",
                "description": f["reason"],
                "recommendation": f["recommendation"],
                "source": None,
                "note": f"{f['header']}: {f['status']}"
            })

    for r in ssl_results:
        for f in r.get("findings", []):
            findings.append({
                "type": "SSL/TLS Finding",
                "port": r["port"],
                "service": "TLS",
                "matched_pattern": None,
                "cve": None,
                "severity": f["severity"],
                "confidence": "High",
                "description": f["issue"],
                "recommendation": f["recommendation"],
                "source": None,
                "note": "Certificate/protocol-level finding."
            })

    return findings


def run_assessment(open_ports, banner_results, http_results, ssl_results):
    """
    Run the full rule-based assessment engine, combining:
      - signature-based banner matches
      - risky plaintext protocol checks
      - HTTP header findings
      - SSL/TLS findings

    Returns a single list of unified finding dicts.
    """
    signatures = load_signatures()

    all_findings = []
    all_findings.extend(match_banner_signatures(banner_results, signatures))
    all_findings.extend(check_risky_protocols(open_ports))
    all_findings.extend(aggregate_http_and_ssl_findings(http_results, ssl_results))

    return all_findings


def print_assessment_results(findings):
    """Pretty-print the unified vulnerability assessment findings."""
    print("=" * 50)
    print("RULE-BASED VULNERABILITY ASSESSMENT")
    print("=" * 50)
    if not findings:
        print("No heuristic findings identified based on current signatures and rules.")
        print("=" * 50)
        print()
        return

    for f in findings:
        print(f"[{f['severity']}] {f['type']} - Port {f['port']} ({f['service']})")
        if f["cve"]:
            print(f"  Possible CVE: {f['cve']}")
        print(f"  Description: {f['description']}")
        print(f"  Recommendation: {f['recommendation']}")
        if f["source"]:
            print(f"  Reference: {f['source']}")
        print(f"  Note: {f['note']}")
        print()
    print("=" * 50)
    print()
