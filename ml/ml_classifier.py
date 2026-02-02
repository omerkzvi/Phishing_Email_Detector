import joblib
import os
import logging
from enums import MLStatus

logger = logging.getLogger(__name__)

# Absolute paths to model artifacts (keeps it stable no matter where you run from)
BASE_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "vectorizer.pkl")


class MLClassifier:
    """
      Loads a pre-trained ML model + vectorizer from disk and provides a predict() method.

      Purpose:
      - If artifacts exist: run ML classification and return a 0..100 score (phishing probability).
      - If artifacts are missing/broken: fallback gracefully to heuristics-only mode.
      """
    def __init__(self):
        # Model artifacts are optional. If loading fails, these remain None.

        self.model = None
        self.vectorizer = None
        self._load_artifacts()

    def _load_artifacts(self):
        """
        Loads model.pkl and vectorizer.pkl if they exist.

        Why:
        - Keeps service robust: the API can still work even if ML artifacts are not deployed.
        """
        try:
            if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
                self.model = joblib.load(MODEL_PATH)
                self.vectorizer = joblib.load(VECTORIZER_PATH)
                logger.info("ML Model and Vectorizer loaded successfully.")
            else:
                # Not an error — it simply means ML is unavailable in this deployment.
                logger.warning("Model files not found. Running in heuristic-only mode.")
        except Exception as e:
            # Any load failure -> ML unavailable; do not crash the server.
            logger.error(f"Error loading ML model: {e}")
            self.model = None
            self.vectorizer = None

    def predict(self, text: str) -> dict:
        """
        Predicts phishing probability for the given text.

        Input:
        - text: usually `subject + body`

        Output dict:
        - ml_score: int 0..100 (phishing probability * 100), or None if ML unavailable
        - confidence: float 0..1 (raw probability), or 0.0 if ML unavailable/error
        - status: MLStatus (SUCCESS / ERROR / ML_UNAVAILABLE)

        Notes:
        - This method never raises; it returns a status instead.
        """
        # If artifacts are missing/unloaded -> heuristics-only mode.
        if not self.model or not self.vectorizer:
            return {"ml_score": None, "confidence": 0.0, "status": MLStatus.ML_UNAVAILABLE.value}

        try:
            # Ensure we always vectorize a string
            safe_text = text or ""

            # Vectorize text (same vectorizer used during training)
            vec = self.vectorizer.transform([safe_text])

            # predict_proba returns [[P(class=0), P(class=1)]]
            # We assume class=1 is "phishing"
            proba = float(self.model.predict_proba(vec)[0][1])

            # Convert probability to 0..100 score (integer)
            score = int(proba * 100)
            return {"ml_score": score, "confidence": round(proba, 2), "status": MLStatus.SUCCESS.value}

        except Exception as e:
            # Prediction failed unexpectedly -> return ERROR but do not crash.
            logger.error(f"Error during prediction: {e}")
            return {"ml_score": None, "confidence": 0.0, "status": MLStatus.ERROR.value}

# Singleton instance used by the service layer
# (Loads artifacts once at startup instead of reloading per request)
ml_instance = MLClassifier()
