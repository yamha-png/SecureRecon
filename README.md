# SecureRecon

**An Automated Reconnaissance and Vulnerability Assessment Assistant**

SecureRecon is a modular Python 3 command-line tool that performs authorized
reconnaissance, security configuration analysis, heuristic vulnerability
assessment, risk scoring, and professional report generation to assist
security analysts during vulnerability assessment engagements.

Developed as part of a PKCERT Vulnerability Assessment internship project.

---

## ⚠ Authorized Use Only

This tool is intended **solely for authorized security assessments**.
Unauthorized scanning of systems you do not own or have explicit permission
to test may violate computer misuse laws and organizational policies.
SecureRecon enforces this with a mandatory `--i-agree` confirmation flag
before any scan will run.

---
## Features

| # | Feature | Description |
|---|---|---|
| 1 | Host Availability Check | ICMP ping with automatic TCP fallback |
| 2 | Multi-threaded Port Scanner | Configurable profiles (quick/standard/full) or custom port ranges |
| 3 | Service & Banner Detection | Identifies running services via banner grabbing |
| 4 | HTTP Security Header Analyzer | Checks HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Server exposure |
| 5 | SSL/TLS Certificate Inspector | Certificate subject/issuer/expiry, weak TLS version detection |
| 6 | Heuristic Vulnerability Assessment | Curated local signature database (real CVEs with NVD references) matched against detected banners |
| 7 | Risk Scoring Engine | Aggregates findings into Critical/High/Medium/Low counts + overall rating |
| 8 | Remediation Recommendation Engine | Deduplicated, severity-sorted action plan |
| 9 | Report Generation | Structured TXT and JSON reports saved per scan |
| 10 | Logging | Timestamped scan logs (start/end/errors) |

---

## Important Design Note

SecureRecon's vulnerability detection is **heuristic and signature-based**,
not a live CVE database lookup. It compares detected service banners against
a small, manually curated set of known CVE patterns (each with a real NVD
source link). Findings are reported as **"Potential Matches"**, not confirmed
or verified vulnerabilities — this mirrors how real-world tools like Nmap's
`--script vuln` or Nessus's version-detection plugins operate at their core.

---
## Tech Stack

- **Language:** Python 3
- **Core libraries:** `socket`, `ssl`, `http.client`, `threading`
  (`concurrent.futures.ThreadPoolExecutor`), `argparse`, `json`, `logging`,
  `subprocess` (for `openssl`-based certificate parsing)
- **External tool dependency:** `openssl` CLI (used for reliable cert field
  parsing, since Python's `ssl` module doesn't expose certificate fields for
  unverified/self-signed certs)

---

## Installation

```bash
git clone https://github.com/yamha-png/SecureRecon.git
cd SecureRecon
pip install -r requirements.txt
```

No other dependencies are required beyond Python 3.8+ and the system
`openssl` binary (pre-installed on most Linux distributions, including Kali).

---
## Usage

```bash
python3 src/main.py <target> --i-agree [options]
```

### Required
- `target` — IP address or hostname of the system you are authorized to assess
- `--i-agree` — confirms you have explicit authorization to scan the target

### Optional
- `--profile {quick,standard,full}` — port scan depth (default: `quick`)
  - `quick` — top ~100 common ports
  - `standard` — ports 1–1024 plus common high ports
  - `full` — all 65535 ports
- `--ports <range>` — custom port specification, overrides `--profile`
  (e.g. `--ports 20-25` or `--ports 80,443,8080`)
- `--live-check` — (optional/bonus) enable live NVD API lookup with fallback
  to the local signature database

### Examples

```bash
# Quick scan with default profile
python3 src/main.py 192.168.1.10 --i-agree

# Standard scan
python3 src/main.py 192.168.1.10 --i-agree --profile standard

# Custom port range
python3 src/main.py 192.168.1.10 --i-agree --ports 22,80,443,8080
```

---
## Output

Each scan produces:
- **Console output** — full pipeline results printed live
- **`reports/report_<timestamp>.txt`** — human-readable report
- **`reports/report_<timestamp>.json`** — structured report for further processing
- **`logs/<timestamp>_scan.log`** — scan event log (start, end, errors)

---

## Project Structure
SecureRecon/
├── src/
│ ├── main.py # CLI entry point & orchestration
│ ├── host_check.py # Feature 1: host availability
│ ├── port_scanner.py # Feature 2: TCP port scanning
│ ├── banner_grabber.py # Feature 3: service/banner detection
│ ├── http_analyzer.py # Feature 4: HTTP security headers
│ ├── ssl_inspector.py # Feature 5: SSL/TLS inspection
│ ├── vuln_matcher.py # Feature 6: vulnerability assessment engine
│ ├── vuln_signatures.json # Curated CVE signature database
│ ├── risk_scorer.py # Feature 7: risk scoring
│ ├── remediation_engine.py # Feature 8: remediation planning
│ ├── report_generator.py # Feature 9: TXT/JSON report generation
│ └── logger.py # Feature 10: logging
├── reports/ # Generated scan reports (gitignored)
├── logs/ # Generated scan logs (gitignored)
├── screenshots/ # Demo screenshots for project report
├── docs/ # Sample report/log, design notes
├── requirements.txt
├── LICENSE
└── README.md


---
## Known Limitations

- Vulnerability signature database is intentionally small (~8 entries) and
  curated for common services (SSH, Apache, nginx, FTP, OpenSSL) — it is not
  a comprehensive CVE database.
- Banner-based fingerprinting can be defeated by banner spoofing or hardened
  configurations that suppress version strings.
- The local signature database is static and can become outdated; the
  optional `--live-check` flag mitigates this by querying NVD live.
- `--profile full` (all 65535 ports) can take significant time depending on
  network conditions and thread count.

---

## Future Enhancements

- Expand the signature database with a larger, regularly updated CVE set
- Add UDP port scanning support
- Add OS fingerprinting
- Web-based dashboard for report viewing

---

## Author

Developed by Yamha as part of a PKCERT Vulnerability Assessment internship.

## License

See [LICENSE](LICENSE).
