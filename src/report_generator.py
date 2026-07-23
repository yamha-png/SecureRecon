"""
SecureRecon - Report Generator
Consolidates all scan results into structured TXT and JSON report
files saved under reports/, timestamped per scan run.
"""

import json
import os
from datetime import datetime

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")


def build_report_data(target, host_status, open_ports, banner_results,
                       http_results, ssl_results, findings, risk_data,
                       remediation_plan, profile):
    """
    Assemble all scan results into a single structured dict,
    ready to be serialized as JSON or formatted as text.
    """
    return {
        "scan_info": {
            "target": target,
            "scan_profile": profile,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "host_status": host_status,
        "open_ports": open_ports,
        "banner_results": banner_results,
        "http_analysis": http_results,
        "ssl_analysis": ssl_results,
        "vulnerability_findings": findings,
        "risk_summary": risk_data,
        "remediation_plan": remediation_plan,
        "ethics_statement": (
            "This assessment was performed only against systems the operator "
            "has explicit authorization to test. Unauthorized scanning may "
            "violate laws or organizational policies."
        )
    }


def _timestamp_filename():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def save_json_report(report_data):
    """Write the report as a JSON file. Returns the file path."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    filename = f"report_{_timestamp_filename()}.json"
    path = os.path.join(REPORTS_DIR, filename)
    with open(path, "w") as f:
        json.dump(report_data, f, indent=2)
    return path


def save_text_report(report_data):
    """Write the report as a human-readable TXT file. Returns the file path."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    filename = f"report_{_timestamp_filename()}.txt"
    path = os.path.join(REPORTS_DIR, filename)

    lines = []
    lines.append("=" * 60)
    lines.append("SecureRecon - Vulnerability Assessment Report")
    lines.append("=" * 60)
    info = report_data["scan_info"]
    lines.append(f"Target: {info['target']}")
    lines.append(f"Scan Profile: {info['scan_profile']}")
    lines.append(f"Timestamp: {info['timestamp']}")
    lines.append("")

    lines.append("--- HOST AVAILABILITY ---")
    hs = report_data["host_status"]
    lines.append(f"Reachable: {hs['reachable']} (Method: {hs['method']})")
    lines.append("")

    lines.append("--- OPEN PORTS ---")
    if report_data["open_ports"]:
        for p in report_data["open_ports"]:
            lines.append(f"  Port {p}: OPEN")
    else:
        lines.append("  None found.")
    lines.append("")

    lines.append("--- SERVICE BANNERS ---")
    for r in report_data["banner_results"]:
        banner = r["banner"] if r["banner"] else "Not Retrieved"
        lines.append(f"  Port {r['port']} ({r['service_guess']}): {banner}")
    lines.append("")

    lines.append("--- HTTP SECURITY HEADER ANALYSIS ---")
    if report_data["http_analysis"]:
        for r in report_data["http_analysis"]:
            lines.append(f"  Port {r['port']}:")
            for f in r.get("findings", []):
                lines.append(f"    [{f['severity']}] {f['header']}: {f['status']}")
    else:
        lines.append("  No HTTP/HTTPS ports found.")
    lines.append("")

    lines.append("--- SSL/TLS INSPECTION ---")
    if report_data["ssl_analysis"]:
        for r in report_data["ssl_analysis"]:
            if r["reachable"]:
                lines.append(f"  Port {r['port']}: {r['subject']}, expires {r['expiry_date']}, TLS {r['tls_version']}")
            else:
                lines.append(f"  Port {r['port']}: unreachable")
    else:
        lines.append("  No HTTPS/TLS ports found.")
    lines.append("")

    lines.append("--- VULNERABILITY FINDINGS ---")
    if report_data["vulnerability_findings"]:
        for f in report_data["vulnerability_findings"]:
            lines.append(f"  [{f['severity']}] {f['type']} - Port {f['port']} ({f['service']})")
            if f.get("cve"):
                lines.append(f"      Possible CVE: {f['cve']}")
            lines.append(f"      {f['description']}")
    else:
        lines.append("  No heuristic findings identified.")
    lines.append("")

    lines.append("--- RISK SUMMARY ---")
    counts = report_data["risk_summary"]["counts"]
    lines.append(f"  Critical: {counts['Critical']}  High: {counts['High']}  "
                  f"Medium: {counts['Medium']}  Low: {counts['Low']}  Info: {counts['Informational']}")
    lines.append(f"  Overall Risk Rating: {report_data['risk_summary']['overall_risk']}")
    lines.append("")

    lines.append("--- REMEDIATION PLAN ---")
    if report_data["remediation_plan"]:
        for i, item in enumerate(report_data["remediation_plan"], start=1):
            lines.append(f"  {i}. [{item['severity']}] {item['recommendation']}")
            lines.append(f"     Affected: {', '.join(item['affected'])}")
    else:
        lines.append("  No remediation actions required.")
    lines.append("")

    lines.append("--- SCOPE & ETHICS ---")
    lines.append(f"  {report_data['ethics_statement']}")
    lines.append("=" * 60)

    with open(path, "w") as f:
        f.write("\n".join(lines))

    return path


def generate_reports(target, host_status, open_ports, banner_results,
                      http_results, ssl_results, findings, risk_data,
                      remediation_plan, profile):
    """
    Build report data and save both JSON and TXT versions.
    Returns (json_path, txt_path).
    """
    report_data = build_report_data(
        target, host_status, open_ports, banner_results,
        http_results, ssl_results, findings, risk_data,
        remediation_plan, profile
    )
    json_path = save_json_report(report_data)
    txt_path = save_text_report(report_data)
    return json_path, txt_path
