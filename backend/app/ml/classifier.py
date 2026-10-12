import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Optional, Tuple

from app.core.logging import logger
from app.ml.dataset import FEATURE_COLUMNS, CLASSES
from app.detection.threat_scoring import ThreatScoringEngine


class MLFlowClassifier:
    """Loads trained intrusion detection model and performs real-time flow classification."""

    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir
        self.model_path = os.path.join(models_dir, "random_forest_ids.joblib")
        self.scaler_path = os.path.join(models_dir, "scaler.joblib")
        self.metrics_path = os.path.join(models_dir, "ml_metrics.json")

        self.model = None
        self.scaler = None
        self.metrics: Optional[Dict[str, Any]] = None
        self.is_trained = False

        self.load_model()

    def load_model(self) -> bool:
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            try:
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                if os.path.exists(self.metrics_path):
                    with open(self.metrics_path, "r", encoding="utf-8") as f:
                        self.metrics = json.load(f)
                self.is_trained = True
                logger.info("[ML] Random Forest model and scaler loaded successfully.")
                return True
            except Exception as e:
                logger.warning(f"[ML] Failed to load ML model: {e}")
                self.is_trained = False
                return False
        else:
            logger.info("[ML] Model files not found on disk. Operating in rule-only mode until trained.")
            self.is_trained = False
            return False

    def predict_flow(self, flow_features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Run ML inference on a flow feature dictionary."""
        if not self.is_trained or self.model is None or self.scaler is None:
            return None

        try:
            # Construct feature vector in exact order
            vec = [flow_features.get(col, 0.0) for col in FEATURE_COLUMNS]
            vec_arr = np.array(vec).reshape(1, -1)
            scaled = self.scaler.transform(vec_arr)

            pred_class = self.model.predict(scaled)[0]
            probs = self.model.predict_proba(scaled)[0]
            class_idx = list(self.model.classes_).index(pred_class)
            confidence = float(probs[class_idx])

            # Calculate threat score
            risk_score, severity, evidence = ThreatScoringEngine.calculate_ml_anomaly_score(
                predicted_class=pred_class,
                probability=confidence,
                flow_features=flow_features
            )

            return {
                "predicted_class": pred_class,
                "confidence": confidence,
                "risk_score": risk_score,
                "severity": severity,
                "evidence": evidence
            }
        except Exception as e:
            logger.debug(f"[ML] Flow inference error: {e}")
            return None

    def get_metrics(self) -> Dict[str, Any]:
        """Return saved evaluation metrics or fallback defaults if untrained."""
        if self.metrics:
            return self.metrics
        return {
            "is_trained": False,
            "model_type": "RandomForestClassifier",
            "dataset_source": "None",
            "training_set_size": 0,
            "test_set_size": 0,
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "false_positive_rate": 0.0,
            "confusion_matrix": [[0, 0, 0], [0, 0, 0], [0, 0, 0]],
            "per_class_metrics": {},
            "baseline_comparison": {},
            "feature_importances": {}
        }


ml_classifier = MLFlowClassifier()
