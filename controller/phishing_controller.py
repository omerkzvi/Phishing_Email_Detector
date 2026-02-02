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
CORS(app)  # CORS enabled for development / add-on calls
service = PhishingClassifier()

# Routes
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
            return jsonify({"error": "Empty payload"}), 400 # 400 Bad Request -> Invalid request at a basic level: missing/empty JSON payload or unable to parse JSON.


        # Validate and normalize input using Pydantic
        email_req = EmailRequest(**payload)
        result = service.analyze_email(email_req)

        # Convert Pydantic model to JSON dict for response.
        return jsonify(result.model_dump()), 200   # 200 OK -> Success: the request was processed and a valid scan result was returned.


    except ValidationError as e:
        # Client error: request doesn't match the expected schema.
        logger.warning("Validation error: %s", e.errors())
        return jsonify({"error": "Validation Error", "details": e.errors()}), 422 # 422 Unprocessable Entity -> JSON is valid, but the payload does not match the API schema (validation failed / missing required fields / invalid values).


    except Exception:
        # Server error: unexpected crash. Log full trace internally.
        logger.exception("Unhandled error in /scan-email")
        return jsonify({"error": "Internal Server Error"}), 500 # 500 Internal Server Error -> Unexpected server-side failure. Do not expose internal exception details to the client.


@app.route("/health", methods=["GET"])
def health_check():
    """
       Simple health check for uptime monitoring.
       Also reports ML availability status (SUCCESS / ERROR / ML_UNAVAILABLE).
       """
    status = ml_instance.predict("")["status"]
    return jsonify({"status": "ok", "ml_status": status}), 200  # 200 OK -> Success: the request was processed and a valid scan result was returned.


# Local run (dev)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=config.PORT)
