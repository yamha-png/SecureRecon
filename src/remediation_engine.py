"""
SecureRecon - Remediation Recommendation Engine
Consolidates recommendations from all findings into a single,
deduplicated, severity-prioritized action list.
"""

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


def build_remediation_plan(findings):
    """
    Take the unified findings list (from vuln_matcher.run_assessment)
    and produce a deduplicated, severity-sorted remediation plan.

    Findings with identical recommendation text are merged, listing
    all affected ports/services under one action item.

    Returns a list of dicts:
        {
            "recommendation": str,
            "severity": str,
            "affected": [ "Port 22 (SSH)", "Port 8080 (HTTP(S))", ... ]
        }
    """
    grouped = {}

    for f in findings:
        rec_text = f.get("recommendation", "").strip()
        if not rec_text or rec_text == "N/A":
            continue

        severity = f.get("severity", "Informational")
        port = f.get("port")
        service = f.get("service", "Unknown")
        affected_label = f"Port {port} ({service})"

        key = rec_text  # dedupe by exact recommendation text

        if key not in grouped:
            grouped[key] = {
                "recommendation": rec_text,
                "severity": severity,
                "affected": set()
            }
        else:
            # Keep the highest severity seen for this recommendation
            if SEVERITY_ORDER.get(severity, 4) < SEVERITY_ORDER.get(grouped[key]["severity"], 4):
                grouped[key]["severity"] = severity

        grouped[key]["affected"].add(affected_label)

    plan = []
    for item in grouped.values():
        plan.append({
            "recommendation": item["recommendation"],
            "severity": item["severity"],
            "affected": sorted(item["affected"])
        })

    plan.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 4))
    return plan


def print_remediation_plan(plan):
    """Pretty-print the consolidated remediation plan to console."""
    print("=" * 50)
    print("REMEDIATION RECOMMENDATIONS")
    print("=" * 50)
    if not plan:
        print("No remediation actions required.")
        print("=" * 50)
        print()
        return

    for i, item in enumerate(plan, start=1):
        print(f"{i}. [{item['severity']}] {item['recommendation']}")
        print(f"   Affected: {', '.join(item['affected'])}")
        print()
    print("=" * 50)
    print()
