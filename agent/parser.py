import json
from dataclasses import dataclass
from typing import List

# This is a parser for security event logs in JSON format.

@dataclass
class Event:
    timestamp: str
    event_type: str
    source_ip: str
    message: str
    raw: dict


def parse_events(log_path: str) -> List[Event]:
    events = []

    with open(log_path, "r") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)

                # Validate required fields
                required_fields = ["timestamp", "event_type", "source_ip", "message"]
                for field in required_fields:
                    if field not in data:
                        raise ValueError(f"Missing field: {field}")

                event = Event(
                    timestamp=data["timestamp"],
                    event_type=data["event_type"],
                    source_ip=data["source_ip"],
                    message=data["message"],
                    raw=data
                )

                events.append(event)

            except Exception as e:
                print(f"[Parser] Skipping invalid log entry at line {line_number}: {e}")

    return events
