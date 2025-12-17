# Aegis: Security Event Triage

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Aegis is a small Python project for parsing security event logs, scoring events for risk, optionally enriching with threat intelligence, and generating a triage report.

**Quick Overview**
- **Purpose:** Parse JSON-formatted event logs, detect suspicious activity (failed logins, brute-force patterns, off-hours access), and produce a Markdown triage report.
- **Output:** A report written to [reports/report.md](reports/report.md).

**Prerequisites**
- Python 3.10 or newer
- Recommended: Create a virtual environment
- Dependencies: listed in `requirements.txt` (install with `pip install -r requirements.txt`)

**Run**
- Ensure you are in the project root
- Place your JSON log file at `data/events.log`
- Execute:

```bash
python -m agent.agent
```

**Configuration**
- Runtime options are mostly controlled in [agent/config.py](agent/config.py): business hours, thresholds, and scoring weights.
- The `ABUSEIPDB_API_KEY` environment variable enables external IP reputation lookups used by [agent/enrichment.py](agent/enrichment.py).

**Project structure (key files)**
- [agent/agent.py](agent/agent.py): entry point that wires parsing, risk assessment, enrichment and report generation.
- [agent/parser.py](agent/parser.py): reads JSON log lines and returns `Event` objects.
- [agent/risk_engine.py](agent/risk_engine.py): scoring, brute-force detection, and enrichment integration.
- [agent/reporter.py](agent/reporter.py): writes the Markdown triage report.
- [agent/config.py](agent/config.py): tuning constants and thresholds.
- [agent/enrichment.py](agent/enrichment.py): enriches event scoring with data from AbuseIPDB

**How it works (brief)**
- The parser reads `data/events.log` (one JSON event per line).
- The risk engine assigns scores using configured weights, detects brute-force windows, and marks off-hours activity.
- If the AbuseIPDB API is configured, IP reputation enrichment updates scores and reasons.
- The reporter outputs counts, the top risky events, and suggested actions.

**Example output**
- The example generated report includes a summary, the top 3 highest-risk events, and categorized event sections with suggested actions: see [reports/report.md](reports/report.md).

**Sample report snippet**

```bash
- Timestamp: 2025-12-16T08:12:34Z
  - Event Type: failed_login
  - Source IP: 185.231.45.12
  - Risk Score: 80
  - Reasons: Failed login attempt, Brute-force login pattern detected
  - Suggested Action: Investigate immediately and consider blocking source IP
```

**Contributing**
- Improvements and bugfixes are welcome — open a PR with tests or a short description of the change.
