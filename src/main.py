#!/usr/bin/env python3
"""
SecureRecon - An Automated Reconnaissance and Vulnerability Assessment Assistant
Entry point: handles CLI arguments, displays the ethics banner, and will
orchestrate all scan modules as they are built.
"""

import argparse
import sys

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

    # Modules will be called here as they are built:
    # host_check -> port_scanner -> banner_grabber -> http_analyzer
    # -> ssl_inspector -> vuln_matcher -> report_generator
    print("[*] SecureRecon skeleton is running. Modules will be added next.")


if __name__ == "__main__":
    main()
