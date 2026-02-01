import logging
import config
from flask import Flask, request, jsonify
from flask_cors import CORS
from pydantic import ValidationError
from service.phishing_service import PhishingClassifier
from models import EmailRequest
from ml.ml_classifier import ml_instance

logging.basicConfig(level=getattr(logging, config.LOG_LEVEL, logging.INFO))
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # לפי הבקשה שלך: לא מוסיף security עכשיו
service = PhishingClassifier()

@app.route("/scan-email", methods=["POST"])
def scan_email():
    try:
        payload = request.get_json(silent=True)
        if not payload:
            return jsonify({"error": "Empty payload"}), 400

        email_req = EmailRequest(**payload)
        result = service.analyze_email(email_req)

        return jsonify(result.model_dump()), 200

    except ValidationError as e:
        logger.warning("Validation error: %s", e.errors())
        return jsonify({"error": "Validation Error", "details": e.errors()}), 422

    except Exception:
        logger.exception("Unhandled error in /scan-email")
        # חשוב: לא להחזיר פרטי exception ללקוח
        return jsonify({"error": "Internal Server Error"}), 500

@app.route("/health", methods=["GET"])
def health_check():
    status = ml_instance.predict("")["status"]
    return jsonify({"status": "ok", "ml_status": status}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=config.PORT)
