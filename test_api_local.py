import requests
import json

# הכתובת של השרת המקומי שלך
url = "http://127.0.0.1:5000/scan-email"

# המידע שאנחנו שולחים לבדיקה (סימולציה של מייל פישינג)
payload = {
    "sender": "support@paypal-security-alert.com",
    "subject": "URGENT: Your account has been suspended",
    "body": "Please click here to verify your identity immediately or your account will be closed. http://bit.ly/fake-link"
}

try:
    print(f"Sending request to {url}...")
    response = requests.post(url, json=payload)

    if response.status_code == 200:
        print("\n✅ Success! Server responded:")
        print(json.dumps(response.json(), indent=4))
    else:
        print(f"\n❌ Error: Server returned status {response.status_code}")
        print(response.text)

except Exception as e:
    print(f"\n❌ Connection failed. Is the server running? Error: {e}")