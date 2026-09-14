"""
ai_ml_analyzer.py
Stage 8: AI/ML Analysis (Risk Classification, Anomaly Detection, Risk Scoring 0-100)

Three complementary techniques, gracefully layered:

  1. Rule-weighted risk scoring (always available, no training needed):
     converts static-rule findings (Stage 7) into a 0-100 numeric score.

  2. Unsupervised anomaly detection (always available, no training needed):
     IsolationForest fit fresh on each batch's session features -- flags
     streams that look statistically unusual relative to the rest of the
     batch (e.g. outlier packet count, unusual duration).

  3. OPTIONAL trained supervised classifiers (only used if model files
     exist under models_store/ -- produced by train_model.py on a labeled
     dataset): a binary malicious/normal classifier and a multiclass
     risk-category classifier. If present, their predictions are blended
     into the final verdict; if absent, the engine falls back to (1)+(2)
     only -- nothing breaks without training.
"""

import os
from typing import List, Dict, Any
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

from models import TCPStream, CryptoFeatures, SecurityFinding
from feature_schema import vectorize, FEATURE_NAMES

SEVERITY_WEIGHTS = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 0}

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models_store")
BINARY_MODEL_PATH = os.path.join(MODELS_DIR, "binary_classifier.joblib")
RISK_MODEL_PATH = os.path.join(MODELS_DIR, "risk_classifier.joblib")


class AIMLAnalyzer:
    _binary_model = None
    _risk_model = None
    _models_loaded = False

    # ---------- Rule-weighted scoring (no training needed) ----------

    @staticmethod
    def compute_risk_score(findings: List[SecurityFinding]) -> int:
        score = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
        return min(score, 100)

    @staticmethod
    def classify(risk_score: int) -> str:
        if risk_score >= 70:
            return "Critical"
        if risk_score >= 45:
            return "High"
        if risk_score >= 20:
            return "Medium"
        if risk_score > 0:
            return "Low"
        return "Safe"

    # ---------- Unsupervised anomaly detection (no training needed) ----------

    @classmethod
    def detect_anomalies(cls, streams: List[TCPStream],
                          features_list: List[CryptoFeatures]) -> Dict[str, bool]:
        if not SKLEARN_AVAILABLE or len(streams) < 4:
            return {s.stream_id: False for s in streams}

        vectors = np.array([vectorize(s, f) for s, f in zip(streams, features_list)])
        model = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
        preds = model.fit_predict(vectors)  # -1 = anomaly, 1 = normal

        return {s.stream_id: bool(p == -1) for s, p in zip(streams, preds)}

    # ---------- OPTIONAL trained supervised classifiers ----------

    @classmethod
    def _load_trained_models(cls):
        if cls._models_loaded:
            return
        cls._models_loaded = True
        if not JOBLIB_AVAILABLE:
            return
        if os.path.exists(BINARY_MODEL_PATH):
            cls._binary_model = joblib.load(BINARY_MODEL_PATH)
            print(f"[AI/ML] Loaded trained binary classifier from {BINARY_MODEL_PATH}")
        if os.path.exists(RISK_MODEL_PATH):
            cls._risk_model = joblib.load(RISK_MODEL_PATH)
            print(f"[AI/ML] Loaded trained risk classifier from {RISK_MODEL_PATH}")

    @classmethod
    def models_available(cls) -> bool:
        cls._load_trained_models()
        return cls._binary_model is not None or cls._risk_model is not None

    @classmethod
    def predict_with_trained_models(cls, stream: TCPStream,
                                     features: CryptoFeatures) -> Dict[str, Any]:
        """
        Returns {} if no trained model is available (safe no-op).
        Otherwise returns e.g.:
          {"ml_malicious_probability": 0.83, "ml_risk_category": "High"}
        """
        cls._load_trained_models()
        result = {}
        if cls._binary_model is None and cls._risk_model is None:
            return result

        import pandas as pd
        vector = pd.DataFrame([vectorize(stream, features)], columns=FEATURE_NAMES)

        if cls._binary_model is not None:
            try:
                proba = cls._binary_model.predict_proba(vector)[0]
                classes = list(cls._binary_model.classes_)
                if "malicious" in classes:
                    idx = classes.index("malicious")
                    result["ml_malicious_probability"] = round(float(proba[idx]), 3)
            except Exception as e:
                result["ml_binary_error"] = str(e)

        if cls._risk_model is not None:
            try:
                pred = cls._risk_model.predict(vector)[0]
                result["ml_risk_category"] = str(pred)
            except Exception as e:
                result["ml_risk_error"] = str(e)

        return result
