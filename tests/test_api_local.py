import requests


def test_api_scan_email_flow():
    url = "http://127.0.0.1:5000/scan-email"
    payload = {
        "sender": "support@paypal-security-alert.com",
        "subject": "URGENT: Your account has been suspended",
        "body": "Please click here: http://bit.ly/fake-link"
    }

    print(f"\nSending request to {url}...")
    response = requests.post(url, json=payload)

    assert response.status_code == 200, f"Expected 200 but got {response.status_code}"

    data = response.json()
    assert "classification" in data
    print("Success! Server responded correctly.")