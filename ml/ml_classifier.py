import joblib
import os
import logging
from enums import MLStatus

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "vectorizer.pkl")


class MLClassifier:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self._load_artifacts()

    def _load_artifacts(self):
        try:
            if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
                self.model = joblib.load(MODEL_PATH)
                self.vectorizer = joblib.load(VECTORIZER_PATH)
                logger.info("ML Model and Vectorizer loaded successfully.")
            else:
                logger.warning("Model files not found. Running in heuristic-only mode.")
        except Exception as e:
            logger.error(f"Error loading ML model: {e}")
            self.model = None
            self.vectorizer = None

    def predict(self, text: str) -> dict:
        if not self.model or not self.vectorizer:
            return {"ml_score": None, "confidence": 0.0, "status": MLStatus.ML_UNAVAILABLE.value}

        try:
            safe_text = text or ""
            vec = self.vectorizer.transform([safe_text])
            proba = float(self.model.predict_proba(vec)[0][1])
            score = int(proba * 100)
            return {"ml_score": score, "confidence": round(proba, 2), "status": MLStatus.SUCCESS.value}
        except Exception as e:
            logger.error(f"Error during prediction: {e}")
            return {"ml_score": None, "confidence": 0.0, "status": MLStatus.ERROR.value}


ml_instance = MLClassifier()
