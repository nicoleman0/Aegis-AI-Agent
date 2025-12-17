from collections import defaultdict
from datetime import datetime, timedelta
from typing import List
from agent.parser import Event
from agent.enrichment import lookup_ip
from agent import config


class RiskAssessment:
    def __init__(self, event, risk_level, reasons, score, intel=None):
        self.event = event
        self.risk_level = risk_level
        self.reasons = reasons
        self.score = score
        self.intel = intel


def parse_timestamp(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", ""))


# Helper function to determine if a timestamp is within business hours
def is_business_hours(timestamp: str) -> bool:
    dt = datetime.fromisoformat(timestamp.replace("Z", ""))
    return (
        config.BUSINESS_HOURS_START
        <= dt.hour
        < config.BUSINESS_HOURS_END
    )
    

# Helper function to check for brute-force login attempts
def is_bruteforce(ip: str, event_time: datetime, failed_logins_by_ip) -> bool:
    window_start = event_time - timedelta(
        minutes=config.FAILED_LOGIN_TIME_WINDOW_MINUTES
    )

    attempts = [
        t for t in failed_logins_by_ip.get(ip, [])
        if window_start <= t <= event_time
    ]

    return len(attempts) >= config.FAILED_LOGIN_THRESHOLD


def score_to_risk_level(score: int) -> str:
    score = max(0, min(score, 100))
    if score >= config.RISK_SCORE_HIGH:
        return "HIGH"
    if score >= config.RISK_SCORE_MEDIUM:
        return "MEDIUM"
    return "LOW"


# Main risk assessment function
def assess_risk(events: List[Event]) -> List[RiskAssessment]:
    assessments = []

    failed_logins_by_ip = defaultdict(list)

# First pass: collect failed login timestamps per IP
    for event in events:
        if event.event_type == "failed_login":
            failed_logins_by_ip[event.source_ip].append(
                parse_timestamp(event.timestamp)
            )

    # Second pass: assess each event
    for event in events:
        score = 0
        reasons = []

        event_time = parse_timestamp(event.timestamp)

        # Failed login
        if event.event_type == "failed_login":
            score += config.WEIGHT_FAILED_LOGIN
            reasons.append("Failed login attempt")

            # Brute-force detection
            if is_bruteforce(event.source_ip, event_time, failed_logins_by_ip):
                score += config.WEIGHT_BRUTE_FORCE
                reasons.append(
                    f"{config.FAILED_LOGIN_THRESHOLD}+ failed logins within "
                    f"{config.FAILED_LOGIN_TIME_WINDOW_MINUTES} minutes"
                )

        # Off-hours activity
        if not is_business_hours(event.timestamp):
            score += config.WEIGHT_OFF_HOURS
            reasons.append("Activity occurred outside business hours")

        risk_level = score_to_risk_level(score)

        assessments.append(
            RiskAssessment(
                event=event,
                risk_level=risk_level,
                reasons=reasons,
                score=score
            )
        )

    return assessments

def enrich_assessments(assessments, api_key):
    for a in assessments:
        intel = lookup_ip(a.event.source_ip, api_key)
        if intel:
            a.intel = intel

            if intel["abuse_score"] >= config.ABUSEIPDB_HIGH_RISK_SCORE:
                a.score += config.WEIGHT_BAD_IP_REPUTATION
                a.reasons.append(
                    f"Source IP has high abuse confidence score ({intel['abuse_score']})"
                )

                a.risk_level = score_to_risk_level(a.score)
