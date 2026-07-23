"""
SecureRecon - Live NVD Lookup Module (Optional Bonus Feature)
Queries the National Vulnerability Database (NVD) REST API for a given
CVE ID to confirm/enrich local signature matches with live data.
Falls back gracefully to local signature data on any failure
(network error, timeout, rate limit) - never crashes the scan.
"""

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def query_nvd(cve_id, timeout=5):
    """
    Query the NVD API for a single CVE ID.

    Returns a dict on success:
        {
            "cve_id": str,
            "published": str or None,
            "description": str or None,
            "cvss_score": float or None,
            "source": "NVD Live API"
        }
    Returns None on any failure (network error, timeout, no results,
    rate limiting, malformed response) - caller must handle fallback.
    """
    if not cve_id or cve_id.startswith("TEST") or cve_id.startswith("DEMO"):
        return None  # never query the live API for demo/test entries

    try:
        response = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            timeout=timeout,
            headers={"User-Agent": "SecureRecon-VA-Tool/1.0"}
        )

        if response.status_code != 200:
            return None

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        cve_data = vulnerabilities[0].get("cve", {})
        published = cve_data.get("published")

        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            None
        )

        cvss_score = None
        metrics = cve_data.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metric_key in metrics and metrics[metric_key]:
                cvss_score = metrics[metric_key][0].get("cvssData", {}).get("baseScore")
                break

        return {
            "cve_id": cve_id,
            "published": published,
            "description": description,
            "cvss_score": cvss_score,
            "source": "NVD Live API"
        }

    except (requests.exceptions.RequestException, ValueError, KeyError):
        return None


def enrich_findings_with_live_data(findings, enabled=False):
    """
    For each finding that has an associated real CVE ID, attempt a live
    NVD lookup if --live-check is enabled. Adds a 'live_status' field to
    every finding so the report can show whether live data was used,
    unavailable, or not requested. Never raises; always safe to call.
    """
    for finding in findings:
        cve_id = finding.get("cve")

        if not enabled or not cve_id:
            finding["live_status"] = "Not Requested" if not enabled else "N/A (no CVE)"
            continue

        live_data = query_nvd(cve_id)
        if live_data:
            finding["live_status"] = "Live-Verified (NVD API)"
            finding["live_published"] = live_data["published"]
            finding["live_cvss_score"] = live_data["cvss_score"]
        else:
            finding["live_status"] = "Live Lookup Failed - Using Local Signature Data"

    return findings
