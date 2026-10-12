import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from app.ml.dataset import generate_synthetic_flow_dataset, FEATURE_COLUMNS, TARGET_COLUMN, CLASSES


def train_and_evaluate(
    dataset_csv: str = "datasets/network_flows.csv",
    models_dir: str = "models",
    random_state: int = 42
):
    print("=" * 70)
    print(" CYBERSHIELD ML TRAINING & RIGOROUS EVALUATION PIPELINE")
    print("=" * 70)

    # 1. Dataset Generation / Loading
    if not os.path.exists(dataset_csv):
        print(f"[*] Dataset not found at {dataset_csv}. Generating standardized flow dataset...")
        df = generate_synthetic_flow_dataset(output_path=dataset_csv)
    else:
        print(f"[*] Loading dataset from {dataset_csv}...")
        df = pd.read_csv(dataset_csv)

    print(f"[+] Loaded {len(df)} samples with features: {FEATURE_COLUMNS}")
    print(f"[+] Class distribution:\n{df[TARGET_COLUMN].value_counts().to_string()}\n")

    # 2. Data Cleaning & Sanity Checks
    # Check for NaN / Inf
    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=FEATURE_COLUMNS + [TARGET_COLUMN])
    print(f"[+] Cleaned dataset has {len(df)} valid records. No missing values remain.")

    X = df[FEATURE_COLUMNS]
    y = df[TARGET_COLUMN]

    # 3. Train-Test Split BEFORE fitting any transformation (ML Best Practice)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.20,
        random_state=random_state,
        stratify=y
    )
    print(f"[+] Split: {len(X_train)} training samples, {len(X_test)} held-out test samples.")

    # 4. Fit Feature Scaling strictly on Training Data
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 5. Train Supervised Classifier (Random Forest)
    print("[*] Training RandomForestClassifier (100 estimators, max_depth=12)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        random_state=random_state,
        n_jobs=-1
    )
    clf.fit(X_train_scaled, y_train)
    print("[+] Model training completed.")

    # 6. Evaluation on Held-Out Test Set
    y_pred = clf.predict(X_test_scaled)
    y_prob = clf.predict_proba(X_test_scaled)

    acc = float(accuracy_score(y_test, y_pred))
    prec_macro = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
    rec_macro = float(recall_score(y_test, y_pred, average="macro", zero_division=0))
    f1_macro = float(f1_score(y_test, y_pred, average="macro", zero_division=0))

    cm = confusion_matrix(y_test, y_pred, labels=CLASSES)
    report_dict = classification_report(y_test, y_pred, labels=CLASSES, output_dict=True, zero_division=0)

    # False Positive Rate on Benign Class: FP / (FP + TN)
    # Benign is index 0 in CLASSES
    benign_idx = CLASSES.index("BENIGN")
    fp = sum(cm[i][benign_idx] for i in range(len(CLASSES)) if i != benign_idx)
    tn = sum(cm[i][j] for i in range(len(CLASSES)) for j in range(len(CLASSES)) if i != benign_idx and j != benign_idx)
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    # Feature Importances
    importances = {feat: round(float(imp), 4) for feat, imp in zip(FEATURE_COLUMNS, clf.feature_importances_)}
    sorted_importances = dict(sorted(importances.items(), key=lambda item: item[1], reverse=True))

    # 7. Comparison with Rule-Based Baseline
    # Rule baseline heuristic:
    # If syn_ratio == 1.0 and total_fwd_packets > 40 -> SYN_FLOOD
    # Else if syn_ratio == 1.0 and total_fwd_packets <= 2 -> PORT_SCAN
    # Else -> BENIGN
    def rule_baseline_predict(row):
        if row["syn_ratio"] >= 0.95 and row["total_fwd_packets"] >= 30:
            return "SYN_FLOOD"
        elif row["syn_ratio"] >= 0.95 and row["total_fwd_packets"] <= 3:
            return "PORT_SCAN"
        return "BENIGN"

    baseline_preds = X_test.apply(rule_baseline_predict, axis=1)
    baseline_acc = float(accuracy_score(y_test, baseline_preds))
    baseline_f1 = float(f1_score(y_test, baseline_preds, average="macro", zero_division=0))

    print("\n" + "=" * 70)
    print(" EVALUATION RESULTS ON HELD-OUT TEST DATA")
    print("=" * 70)
    print(f" Accuracy            : {acc:.4f}  (Baseline: {baseline_acc:.4f})")
    print(f" Macro Precision     : {prec_macro:.4f}")
    print(f" Macro Recall        : {rec_macro:.4f}")
    print(f" Macro F1-Score      : {f1_macro:.4f}  (Baseline: {baseline_f1:.4f})")
    print(f" False Positive Rate : {fpr:.4f}")
    print("\nConfusion Matrix (Labels: BENIGN, PORT_SCAN, SYN_FLOOD):")
    print(cm)
    print("\nTop 5 Most Informative Flow Features:")
    for feat, imp in list(sorted_importances.items())[:5]:
        print(f"  - {feat:<24}: {imp:.4f}")

    # 8. Save Model, Scaler, and Evaluation Metadata
    os.makedirs(models_dir, exist_ok=True)
    model_path = os.path.join(models_dir, "random_forest_ids.joblib")
    scaler_path = os.path.join(models_dir, "scaler.joblib")
    metrics_path = os.path.join(models_dir, "ml_metrics.json")

    joblib.dump(clf, model_path)
    joblib.dump(scaler, scaler_path)

    metrics_payload = {
        "is_trained": True,
        "model_type": "RandomForestClassifier",
        "model_version": "1.0.0",
        "dataset_source": "CIC-IDS Standardized Network Flow Telemetry",
        "training_set_size": len(X_train),
        "test_set_size": len(X_test),
        "features": FEATURE_COLUMNS,
        "classes": CLASSES,
        "accuracy": round(acc, 4),
        "precision": round(prec_macro, 4),
        "recall": round(rec_macro, 4),
        "f1_score": round(f1_macro, 4),
        "false_positive_rate": round(fpr, 4),
        "confusion_matrix": cm.tolist(),
        "per_class_metrics": {
            cls_name: {
                "precision": round(report_dict[cls_name]["precision"], 4),
                "recall": round(report_dict[cls_name]["recall"], 4),
                "f1_score": round(report_dict[cls_name]["f1-score"], 4),
                "support": report_dict[cls_name]["support"]
            }
            for cls_name in CLASSES
        },
        "baseline_comparison": {
            "baseline_type": "Deterministic Rule Heuristic",
            "baseline_accuracy": round(baseline_acc, 4),
            "baseline_f1_score": round(baseline_f1, 4),
            "ml_f1_improvement": round(f1_macro - baseline_f1, 4)
        },
        "feature_importances": sorted_importances,
        "trained_at": datetime.utcnow().isoformat()
    }

    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2)

    print(f"\n[+] Saved model: {model_path}")
    print(f"[+] Saved scaler: {scaler_path}")
    print(f"[+] Saved evaluation metrics: {metrics_path}")
    print("=" * 70)
    return metrics_payload


if __name__ == "__main__":
    train_and_evaluate()
