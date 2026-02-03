import logging
import config
from flask import Flask, request, jsonify
from pydantic import ValidationError
from service.phishing_service import PhishingClassifier
from models import EmailRequest
from ml.ml_classifier import ml_instance

logging.basicConfig(level=getattr(logging, config.LOG_LEVEL, logging.INFO))
logger = logging.getLogger(__name__)

app = Flask(__name__)
service = PhishingClassifier()

@app.route("/scan-email", methods=["POST"])
def scan_email():
    """
    Main API endpoint
    Input: JSON payload that matches EmailRequest model
    Output: ScanResult JSON (score/classification/severity/reasons/metadata)
    """
    try:
        # silent=True prevents Flask from throwing if JSON is malformed.
        payload = request.get_json(silent=True)
        if not payload:
            return jsonify({"error": "Empty payload"}), 400


        # Validate and normalize input using Pydantic
        email_req = EmailRequest(**payload)
        result = service.analyze_email(email_req)

        # Convert Pydantic model to JSON dict for response.
        return jsonify(result.model_dump()), 200

    except ValidationError as e:
        # Client error: request doesn't match the expected schema.
        logger.warning("Validation error: %s", e.errors())
        return jsonify({"error": "Validation Error", "details": e.errors()}), 422


    except Exception:
        # Server error: unexpected crash. Log full trace internally.
        logger.exception("Unhandled error in /scan-email")
        return jsonify({"error": "Internal Server Error"}), 500


@app.route("/health", methods=["GET"])
def health_check():
    """
       Simple health check for uptime monitoring.
       Also reports ML availability status (SUCCESS / ERROR / ML_UNAVAILABLE).
       """
    status = ml_instance.predict("")["status"]
    return jsonify({"status": "ok", "ml_status": status}), 200


# Local run (dev)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=config.PORT)
