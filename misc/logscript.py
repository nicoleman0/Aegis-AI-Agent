import json
import random
from datetime import datetime, timedelta

# Config
NUM_EVENTS = 80
BUSINESS_HOURS_START = 9
BUSINESS_HOURS_END = 17
OFFICE_IPS = ["192.168.1.10", "192.168.1.11"]
EXTERNAL_IPS = [
    "185.231.45.12",
    "91.203.145.77",
    "203.0.113.5",
    "198.51.100.23",
    "172.16.0.5",
]

EVENT_TYPES = ["failed_login", "successful_login"]

def random_timestamp():
    """Generate random timestamp within the past 7 days."""
    now = datetime.utcnow()
    delta = timedelta(days=random.randint(0, 6), hours=random.randint(0, 23), minutes=random.randint(0, 59))
    return (now - delta).strftime("%Y-%m-%dT%H:%M:%SZ")

def random_ip():
    """Randomly pick office or external IP"""
    if random.random() < 0.6:
        return random.choice(EXTERNAL_IPS)
    else:
        return random.choice(OFFICE_IPS)

def random_username():
    return random.choice(["admin", "root", "nicholas", "user1", "user2"])

events = []
for _ in range(NUM_EVENTS):
    etype = random.choices(EVENT_TYPES, weights=[0.6, 0.4])[0]  # more failed_logins
    ip = random_ip()
    events.append({
        "timestamp": random_timestamp(),
        "event_type": etype,
        "source_ip": ip,
        "username": random_username(),
        "message": "Failed SSH login attempt" if etype == "failed_login" else "User logged in successfully"
    })

with open("events.log", "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")

print(f"Generated {NUM_EVENTS} events in events.log")
