from agent.parser import parse_events
from agent.risk_engine import assess_risk, enrich_assessments
from agent.reporter import generate_report
import os

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

events = parse_events("data/events.log")
assessments = assess_risk(events)

if ABUSEIPDB_API_KEY:
    enrich_assessments(assessments, ABUSEIPDB_API_KEY)

generate_report(assessments, "reports/report.md")
print("Aegis security report generated at reports/report.md")
