"""
SecureRecon - Risk Scoring Engine
Aggregates all findings from the assessment engine into severity
counts and calculates an overall risk rating for the target.
"""

# Severity ranking used to determine overall risk (higher = worse)
SEVERITY_WEIGHT = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Informational": 0
}


def calculate_risk_score(findings):
    """
    Count findings by severity and determine an overall risk rating.

    Overall rating logic:
      - Any Critical finding          -> CRITICAL
      - Any High finding (no Critical) -> HIGH
      - Any Medium finding (no High/Critical) -> MEDIUM
      - Only Low/Informational findings -> LOW
      - No findings at all             -> MINIMAL

    Returns a dict:
        {
            "counts": {"Critical": int, "High": int, "Medium": int,
                       "Low": int, "Informational": int},
            "total_findings": int,
            "overall_risk": str
        }
    """
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}

    for f in findings:
        severity = f.get("severity", "Informational")
        if severity in counts:
            counts[severity] += 1
        else:
            counts["Informational"] += 1

    total = sum(counts.values())

    if counts["Critical"] > 0:
        overall = "CRITICAL"
    elif counts["High"] > 0:
        overall = "HIGH"
    elif counts["Medium"] > 0:
        overall = "MEDIUM"
    elif counts["Low"] > 0:
        overall = "LOW"
    else:
        overall = "MINIMAL"

    return {
        "counts": counts,
        "total_findings": total,
        "overall_risk": overall
    }


def print_risk_summary(risk_data):
    """Pretty-print the risk scoring summary to console."""
    print("=" * 50)
    print("RISK SCORING SUMMARY")
    print("=" * 50)
    counts = risk_data["counts"]
    print(f"Critical Findings:      {counts['Critical']}")
    print(f"High Findings:          {counts['High']}")
    print(f"Medium Findings:        {counts['Medium']}")
    print(f"Low Findings:           {counts['Low']}")
    print(f"Informational Findings: {counts['Informational']}")
    print(f"Total Findings:         {risk_data['total_findings']}")
    print()
    print(f"Overall Risk Rating: {risk_data['overall_risk']}")
    print("=" * 50)
    print()
