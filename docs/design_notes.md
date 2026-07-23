# SecureRecon - Design Notes

## Architecture
Modular pipeline: each feature is an independent Python module with a single
responsibility, orchestrated sequentially by main.py.

## Workflow
Target -> Host Discovery -> Port Scanning -> Service Enumeration ->
HTTP Security Analysis -> SSL/TLS Inspection -> Rule-Based Vulnerability
Assessment -> Risk Scoring -> Remediation Recommendations -> Report Generation

## Key Design Decisions
- Heuristic (not live-verified) vulnerability matching, clearly labeled as
  "Potential Match" to avoid overclaiming detection accuracy.
- Production/test signature separation: vuln_signatures.json (real, sourced
  CVEs) vs vuln_signatures_demo.json (gitignored, used only to validate the
  matching engine).
- Certificate parsing uses the openssl CLI via subprocess rather than
  Python's ssl module directly, since ssl.getpeercert() does not populate
  fields when verify_mode=CERT_NONE (required for self-signed/unverified
  certs common in lab environments).
- All findings carry a severity, human-readable reason, and remediation
  recommendation so the tool produces actionable output, not just raw data.

## Challenges Encountered
1. ufw blocking test ports (8080/8443) during HTTP/SSL module testing -
   diagnosed via ss -tuln and ufw status, resolved with ufw allow.
2. Python ssl module CERT_NONE limitation - certificate fields returned
   empty; resolved by parsing PEM certs via openssl subprocess instead.
3. JSON schema mismatch (KeyError) and JSON syntax error (JSONDecodeError)
   while building a demo validation signature file - resolved by aligning
   schema and validating with python3 -m json.tool.
