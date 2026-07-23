#!/usr/bin/env python3
"""
SecureRecon - An Automated Reconnaissance and Vulnerability Assessment Assistant
Entry point: handles CLI arguments, displays the ethics banner, and will
orchestrate all scan modules as they are built.
"""

import argparse
import sys
from host_check import check_host, print_host_status
from port_scanner import scan_ports, print_scan_results
from banner_grabber import grab_all_banners, print_banner_results
from http_analyzer import analyze_headers, print_http_analysis
from ssl_inspector import inspect_all, print_ssl_results
from vuln_matcher import run_assessment, print_assessment_results
from risk_scorer import calculate_risk_score, print_risk_summary
from remediation_engine import build_remediation_plan, print_remediation_plan
from report_generator import generate_reports

ETHICS_BANNER = """
========================================================
                     SecureRecon
   Authorized Security Assessment Tool
========================================================
This tool is intended solely for authorized security
assessments. Unauthorized scanning may violate laws or
organizational policies.

Proceed only if you have explicit permission to test
the target system.
========================================================
"""


def print_banner():
    print(ETHICS_BANNER)


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog="SecureRecon",
        description="An Automated Reconnaissance and Vulnerability Assessment Assistant"
    )
    parser.add_argument(
        "target",
        help="Target IP address or hostname to assess (must be authorized)"
    )
    parser.add_argument(
        "--i-agree",
        action="store_true",
        help="Confirm you have explicit authorization to scan the target"
    )
    parser.add_argument(
        "--profile",
        choices=["quick", "standard", "full"],
        default="quick",
        help="Port scan profile: quick (top 100), standard (top 1000), full (1-65535)"
    )
    parser.add_argument(
        "--ports",
        help="Custom port range, e.g. 20-25 or 80,443,8080"
    )
    parser.add_argument(
        "--live-check",
        action="store_true",
        help="Enable live NVD API lookup (falls back to local DB if unavailable)"
    )
    return parser.parse_args()


def main():
    print_banner()
    args = parse_arguments()

    if not args.i_agree:
        print("[!] You must confirm authorization to proceed.")
        print("    Re-run with the --i-agree flag once you have permission")
        print("    to assess this target.\n")
        sys.exit(1)

    print(f"[*] Target: {args.target}")
    print(f"[*] Scan profile: {args.profile}")
    if args.ports:
        print(f"[*] Custom port range: {args.ports}")
    if args.live_check:
        print("[*] Live NVD lookup: ENABLED")
    print()

    host_status = check_host(args.target)
    print_host_status(args.target, host_status)

    if not host_status["reachable"]:
        print("[!] Target is unreachable. Aborting scan.")
        sys.exit(1)

    open_ports = scan_ports(args.target, profile=args.profile, custom_ports=args.ports)
    print_scan_results(args.target, open_ports)

    banner_results = grab_all_banners(args.target, open_ports)
    print_banner_results(banner_results)

    http_results = analyze_headers(args.target, open_ports)
    print_http_analysis(http_results)

    ssl_results = inspect_all(args.target, open_ports)
    print_ssl_results(ssl_results)

    findings = run_assessment(open_ports, banner_results, http_results, ssl_results)
    print_assessment_results(findings)

    risk_data = calculate_risk_score(findings)
    print_risk_summary(risk_data)

    remediation_plan = build_remediation_plan(findings)
    print_remediation_plan(remediation_plan)

    json_path, txt_path = generate_reports(
        args.target, host_status, open_ports, banner_results,
        http_results, ssl_results, findings, risk_data,
        remediation_plan, args.profile
    )

    print("=" * 50)
    print("REPORT FILES SAVED")
    print("=" * 50)
    print(f"JSON Report: {json_path}")
    print(f"Text Report: {txt_path}")
    print("=" * 50)


if __name__ == "__main__":
    main()
