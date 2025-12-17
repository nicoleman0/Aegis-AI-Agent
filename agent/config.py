# Business hours (24h clock)
BUSINESS_HOURS_START = 8
BUSINESS_HOURS_END = 18

# Failed login detection
FAILED_LOGIN_THRESHOLD = 3

# Brute-force detection window (minutes)
FAILED_LOGIN_TIME_WINDOW_MINUTES = 10

# Threat intelligence thresholds
ABUSEIPDB_HIGH_RISK_SCORE = 75

# Risk scoring weights
WEIGHT_FAILED_LOGIN = 10
WEIGHT_OFF_HOURS = 10
WEIGHT_BRUTE_FORCE = 40
WEIGHT_BAD_IP_REPUTATION = 30

# Risk score thresholds
RISK_SCORE_MEDIUM = 40
RISK_SCORE_HIGH = 70