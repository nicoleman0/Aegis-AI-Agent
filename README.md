# Aegis — Security Event Triage

Aegis is a small Python project for parsing security event logs, scoring events for risk, optionally enriching with threat intelligence, and generating a triage report.

**Quick Overview**
- **Purpose:** Parse JSON-formatted event logs, detect suspicious activity (failed logins, brute-force patterns, off-hours access), and produce a Markdown triage report.
- **Output:** A report written to [reports/report.md](reports/report.md).

**Prerequisites**
- **Python:** 3.10 or newer
- **Optional API key:** Set `ABUSEIPDB_API_KEY` to enable AbuseIPDB enrichment.

**Run**
- From the project root run:

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

**How it works (brief)**
- The parser reads `data/events.log` (one JSON event per line).
- The risk engine assigns scores using configured weights, detects brute-force windows, and marks off-hours activity.
- If configured, IP reputation enrichment updates scores and reasons.
- The reporter outputs counts, the top risky events, and suggested actions.

**Example output**
- The generated report includes a summary, the top 3 highest-risk events, and categorized event sections with suggested actions: see [reports/report.md](reports/report.md).

**Contributing**
- Improvements and bugfixes are welcome — open a PR with tests or a short description of the change.

**License**
- MIT-style; add your preferred license file if required.
