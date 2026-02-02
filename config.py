import os
from dataclasses import dataclass


# runtime / app
PORT = int(os.getenv("PORT", "5000"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")


# scoring policy
@dataclass(frozen=True)
class ScoringConfig:

    # scoring + thresholds configuration

    phishing_threshold: int = int(os.getenv("PHISHING_THRESHOLD", "80"))
    suspicious_threshold: int = int(os.getenv("SUSPICIOUS_THRESHOLD", "50"))

    ml_weight: float = float(os.getenv("ML_WEIGHT", "0.6"))
    heuristic_weight: float = float(os.getenv("HEURISTIC_WEIGHT", "0.4"))

    min_score: int = int(os.getenv("MIN_SCORE", "0"))
    max_score: int = int(os.getenv("MAX_SCORE", "100"))

SCORING = ScoringConfig()


# heuristics data (data-driven)
SUSPICIOUS_KEYWORDS = ["urgent", "verify", "password", "bank", "suspended","click here", "immediate action", "security alert"]

PUBLIC_DOMAINS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]

COMMON_BRANDS = ["paypal", "google", "amazon", "facebook", "apple"]

SENSITIVE_URL_KEYWORDS = ["login", "signin", "verify", "account", "password","security", "update", "billing"]

URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "rebrand.ly", "cutt.ly", "rb.gy"]

SUSPICIOUS_TLDS = ["zip", "top", "xyz", "click", "cam", "country", "gq", "tk"]

# if a critical heuristic triggers, enforce a minimum final score.
CRITICAL_FLOORS: dict[str, int] = {
    "misleading_domain": 90,    # sensitive link mismatch with sender domain
    "punycode": 85,             # xn-- domains often indicate spoofing
    "reply_to_mismatch": 80,    # can be legit sometimes, but still suspicious
    "unusual_sender": 75,       # brand impersonation patterns
}