from enum import Enum

class Classification(str, Enum):
    # high level outcome shown to the user

    PHISHING = "Phishing"
    SUSPICIOUS = "Suspicious"
    SAFE = "Safe"

class Severity(str, Enum):
    # severity level used for UI and prioritization
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class MLStatus(str, Enum):
    # ML stsus (techincal)
    SUCCESS = "SUCCESS"   # model and vectorizer available + prediction succeeded
    ERROR = "ERROR"       # model exists but prediction failed (runtime error)
    ML_UNAVAILABLE = "ML_UNAVAILABLE"   # missing artifacts, use heuristics-only
