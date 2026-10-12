from typing import Optional, Dict, Any, List
from pydantic import BaseModel


class MLStatusResponse(BaseModel):
    is_trained: bool
    model_type: str
    model_version: str
    dataset_name: str
    features: List[str]
    last_trained: Optional[str] = None


class MLMetricsResponse(BaseModel):
    is_trained: bool
    model_type: str
    dataset_source: str
    test_set_size: int
    training_set_size: int
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    false_positive_rate: float
    confusion_matrix: List[List[int]]
    per_class_metrics: Dict[str, Dict[str, float]]
    baseline_comparison: Dict[str, Any]
    feature_importances: Dict[str, float]
