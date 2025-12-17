from typing import List
from datetime import datetime
from agent.risk_engine import RiskAssessment


def generate_report(assessments: List[RiskAssessment], output_path: str):
    high = [a for a in assessments if a.risk_level == "HIGH"]
    medium = [a for a in assessments if a.risk_level == "MEDIUM"]
    low = [a for a in assessments if a.risk_level == "LOW"]

    timestamps = [a.event.timestamp for a in assessments]
    time_range = f"{min(timestamps)} → {max(timestamps)}" if timestamps else "N/A"

    with open(output_path, "w") as f:
        f.write("# Security Event Triage Report\n\n")

        # Summary
        f.write("## Summary\n")
        f.write(f"- Total events processed: {len(assessments)}\n")
        f.write(f"- High risk events: {len(high)}\n")
        f.write(f"- Medium risk events: {len(medium)}\n")
        f.write(f"- Low risk events: {len(low)}\n")
        f.write(f"- Time range: {time_range}\n\n")

        # Executive: top 3 highest risk events
        f.write("## Top 3 Riskiest Events\n")
        top_events = sorted(assessments, key=lambda x: x.score, reverse=True)[:3]
        if top_events:
            for a in top_events:
                f.write(f"- **Timestamp:** {a.event.timestamp}, **Source IP:** {a.event.source_ip}, **Score:** {a.score}, **Reasons:** {', '.join(a.reasons)}\n")
        else:
            f.write("_No events detected._\n")
        f.write("\n")

        # Sections
        write_section(f, "High Risk Events", high)
        write_section(f, "Medium Risk Events", medium)
        write_section(f, "Low Risk Events", low)



def write_section(file, title: str, assessments: List[RiskAssessment]):
    file.write(f"## {title}\n")

    if not assessments:
        file.write("_No events in this category._\n\n")
        return

    for a in assessments:
        file.write(f"- **Timestamp:** {a.event.timestamp}\n")
        file.write(f"  - **Event Type:** {a.event.event_type}\n")
        file.write(f"  - **Source IP:** {a.event.source_ip}\n")
        file.write(f"  - **Risk Score:** {a.score}\n")
        file.write(f"  - **Reasons:** {', '.join(a.reasons) if a.reasons else 'None'}\n")

        # Suggested action (same as before)
        action = suggest_action(a.risk_level)
        file.write(f"  - **Suggested Action:** {action}\n\n")



def suggest_action(risk_level: str) -> str:
    if risk_level == "HIGH":
        return "Investigate immediately and consider blocking source IP"
    if risk_level == "MEDIUM":
        return "Review event and monitor for escalation"
    return "No action required"

