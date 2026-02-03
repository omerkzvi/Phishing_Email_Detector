import pytest
from unittest.mock import patch
from service.phishing_service import PhishingClassifier
from models import EmailRequest


@pytest.fixture
def service():
    return PhishingClassifier()


def test_full_analysis_integration(service):
    with patch("service.phishing_service.ml_instance.predict") as mock_ml:
        mock_ml.return_value = {
            "ml_score": 40,
            "confidence": 0.8,
            "status": "SUCCESS"
        }
        req = EmailRequest(
            sender="attacker@phish.net",
            subject="Account Alert",
            body="Your account is locked. Click here: http://phish.net/login",
            headers={"Reply-To": "evil@evil.com"}
        )
        result = service.analyze_email(req)
        assert result.score >= 40
        assert result.metadata.links_found > 0
        assert result.metadata.ml_status == "SUCCESS"


def test_service_with_very_long_body(service):
    with patch("service.phishing_service.ml_instance.predict") as mock_ml:
        mock_ml.return_value = {"ml_score": 10, "confidence": 0.9, "status": "SUCCESS"}

        long_text = "Urgent! " * 500 + " https://bit.ly/fake"
        req = EmailRequest(
            sender="test@example.com",
            subject="Long mail",
            body=long_text,
            headers={}
        )
        result = service.analyze_email(req)
        assert result.metadata.ml_status == "SUCCESS"
        assert result.score > 10