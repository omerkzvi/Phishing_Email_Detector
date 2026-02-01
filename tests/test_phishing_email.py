import requests
from app.parser import extract_sender_domain, extract_urls
from app.heuristics import PhishingHeuristics
from ml.ml_classifier import ml_instance

def test_extract_domain_logic():
    assert extract_sender_domain("user@example.com") == "example.com"
    assert extract_sender_domain("Invalid-Email") == ""
    assert extract_sender_domain("support@GOOGle.com") == "google.com"

def test_extract_links_regex():
    text = "Visit http://malicious.com and https://secure-bank.py"
    links = extract_urls(text)
    assert len(links) == 2
    assert "https://secure-bank.py" in links

def test_heuristic_keyword_scoring():
    h = PhishingHeuristics()
    result = h.keyword_score("urgent verify password bank suspended urgent")
    assert result["score"] <= 30

def test_ml_prediction_format():
    result = ml_instance.predict("Please click here to update your billing information")
    assert "status" in result
    if result["status"] == "SUCCESS":
        assert result["ml_score"] is not None
        assert 0 <= result["ml_score"] <= 100
    else:
        assert result["ml_score"] is None

# Integration test (requires server running)
def test_api_full_flow():
    url = "http://127.0.0.1:5000/scan-email"
    payload = {
        "sender": "attacker@phish.net",
        "subject": "Account Alert",
        "body": "Your account is locked. Click here: http://phish.net/login",
        "headers": {"Reply-To": "evil@evil.com"}
    }
    response = requests.post(url, json=payload)
    assert response.status_code == 200
    assert response.json()["classification"] in ["Phishing", "Suspicious"]

def test_empty_input_handling():
    h = PhishingHeuristics()
    result = h.misleading_domain_score("google.com", [])
    assert result["score"] == 0
    assert result["reason"] == ""

def test_very_long_body():
    long_text = "Free money! " * 1000
    result = ml_instance.predict(long_text)
    assert "status" in result
