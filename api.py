from flask import Flask, request, jsonify
from classifier import PhishingClassifier

app = Flask(__name__)

classifier = PhishingClassifier()

@app.route("/scan-email", methods=["POST"])

def scan_email():
    data = request.get_json()

    if not data:
        return jsonify({"error": "No data provided"}), 400

    sender = data.get("sender", "")
    subject = data.get("subject", "")
    body = data.get("body", "")

    result = classifier.analyze_email(sender,subject,body)

    return jsonify(result)

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)