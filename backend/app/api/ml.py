from fastapi import APIRouter
from app.ml.classifier import ml_classifier
from app.schemas.ml import MLStatusResponse, MLMetricsResponse

router = APIRouter(prefix="/api/ml", tags=["Machine Learning"])


@router.get("/status", response_model=MLStatusResponse)
def get_ml_status():
    metrics = ml_classifier.get_metrics()
    return {
        "is_trained": ml_classifier.is_trained,
        "model_type": metrics.get("model_type", "RandomForestClassifier"),
        "model_version": metrics.get("model_version", "1.0.0"),
        "dataset_name": metrics.get("dataset_source", "CIC-IDS Standardized Flow Telemetry"),
        "features": metrics.get("features", []),
        "last_trained": metrics.get("trained_at")
    }


@router.get("/metrics", response_model=MLMetricsResponse)
def get_ml_metrics():
    return ml_classifier.get_metrics()
