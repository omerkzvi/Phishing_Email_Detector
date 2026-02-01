from enum import Enum

class Classification(str, Enum):
    PHISHING = "Phishing"
    SUSPICIOUS = "Suspicious"
    SAFE = "Safe"

class Severity(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class MLStatus(str, Enum):
    SUCCESS = "SUCCESS"
    ERROR = "ERROR"
    ML_UNAVAILABLE = "ML_UNAVAILABLE"
