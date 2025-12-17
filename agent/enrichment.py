import requests
from typing import Optional

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"

def lookup_ip(ip: str, api_key: str) -> Optional[dict]:
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(
            ABUSEIPDB_API_URL,
            headers=headers,
            params=params,
            timeout=10
        )

        response.raise_for_status()
        data = response.json()["data"]

        return {
            "abuse_score": data["abuseConfidenceScore"],
            "total_reports": data["totalReports"],
            "last_reported": data["lastReportedAt"]
        }

    except Exception as e:
        print(f"[Enrichment] Failed lookup for {ip}: {e}")
        return None