# Models Directory

This directory stores the trained ML model artifacts for CyberShield's intrusion detection engine.

## Files (not tracked by git — generated locally)

| File | Description |
|------|-------------|
| `random_forest_ids.joblib` | Trained RandomForestClassifier (CIC-IDS2017, v2) |
| `scaler.joblib` | StandardScaler fitted on training features |
| `ml_metrics.json` | Evaluation metrics, confusion matrix, feature importances |

> **Note:** `.joblib` binary files are excluded from git via `.gitignore` to keep the repo lightweight.

## Generate the model

Run the retrainer from the project root. It downloads CIC-IDS2017 from HuggingFace and trains in ~1 minute:

```bash
# From e:\CyberShield (project root)
.\.venv\Scripts\python.exe retrain_real_data.py --sample 40000
```

This will:
1. Download the CIC-IDS2017 dataset (~800 MB, cached after first run)
2. Map 13 flow features from 2.8M real network flows
3. Train a 200-tree RandomForest with SMOTE class balancing
4. Save `random_forest_ids.joblib`, `scaler.joblib`, and `ml_metrics.json`

## Model Performance (v2.0.0 — CIC-IDS2017)

| Metric | Score |
|--------|-------|
| Accuracy | 99.81% |
| F1 Score | 0.9981 |
| False Positive Rate | 0.07% |
| Classes | BENIGN, PORT_SCAN, DOS_DDOS, BRUTE_FORCE |
| Training samples | 107,068 (after SMOTE) |
| Dataset | CIC-IDS2017 — Canadian Institute for Cybersecurity |
