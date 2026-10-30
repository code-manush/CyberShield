"""
CyberShield — Real-Data ML Retrainer
=====================================
Downloads CIC-IDS2017 dataset from Hugging Face, maps columns to CyberShield's
13-feature schema, expands to 4 attack classes, retrains RandomForest, and
saves the updated model artifacts to models/.

Usage:
    python retrain_real_data.py [--sample N] [--no-download]

Options:
    --sample N      Randomly sample N rows per class for faster iteration (default: all)
    --no-download   Skip download, use already-cached Hugging Face files
"""

import argparse
import json
import os
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path

# Force UTF-8 output on Windows consoles
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import joblib
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

# ── constants ────────────────────────────────────────────────────────────────

MODELS_DIR = Path("models")
DATASETS_DIR = Path("datasets")
HF_REPO_ID = "c01dsnap/CIC-IDS2017"          # public HuggingFace mirror

# Our 13 feature columns (must match app/ml/dataset.py FEATURE_COLUMNS)
FEATURE_COLUMNS = [
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "syn_flag_count",
    "ack_flag_count",
    "syn_ratio",
    "ack_ratio",
    "destination_port",
    "is_well_known_port",
]

# CIC-IDS2017 column names → our feature names
# (CICFlowMeter output has spaces and mixed case)
COLUMN_MAP = {
    "Flow Duration":                "flow_duration",
    "Total Fwd Packets":            "total_fwd_packets",
    "Total Backward Packets":       "total_bwd_packets",
    "Total Length of Fwd Packets":  "total_fwd_bytes",
    "Total Length of Bwd Packets":  "total_bwd_bytes",
    "Flow Bytes/s":                 "flow_bytes_per_sec",
    "Flow Packets/s":               "flow_packets_per_sec",
    "SYN Flag Count":               "syn_flag_count",
    "ACK Flag Count":               "ack_flag_count",
    "Destination Port":             "destination_port",
    " Label":                       "label",   # leading space in original CSV
    "Label":                        "label",
}

# Potential alternative column names from different mirrors / versions
ALT_COLUMN_MAP = {
    "flow_duration":                "flow_duration",
    "total_fwd_packets":            "total_fwd_packets",
    "total_bwd_packets":            "total_bwd_packets",
    "total_length_of_fwd_packets":  "total_fwd_bytes",
    "total_length_of_bwd_packets":  "total_bwd_bytes",
    "flow_bytes/s":                 "flow_bytes_per_sec",
    "flow_packets/s":               "flow_packets_per_sec",
    "syn_flag_count":               "syn_flag_count",
    "ack_flag_count":               "ack_flag_count",
    "destination_port":             "destination_port",
    "label":                        "label",
}

# CIC-IDS2017 label → our unified class
LABEL_MAP = {
    # Normal
    "BENIGN":               "BENIGN",
    "Benign":               "BENIGN",
    # Port scan
    "PortScan":             "PORT_SCAN",
    "Port Scan":            "PORT_SCAN",
    # SYN / DoS / DDoS — all collapse to DOS_DDOS
    "DoS Hulk":             "DOS_DDOS",
    "DoS GoldenEye":        "DOS_DDOS",
    "DoS slowloris":        "DOS_DDOS",
    "DoS Slowhttptest":     "DOS_DDOS",
    "DDoS":                 "DOS_DDOS",
    "Heartbleed":           "DOS_DDOS",
    # Brute force / credential attacks
    "FTP-Patator":          "BRUTE_FORCE",
    "SSH-Patator":          "BRUTE_FORCE",
    "Web Attack  Brute Force":  "BRUTE_FORCE",
    "Web Attack – Brute Force": "BRUTE_FORCE",
    "Web Attack - Brute Force": "BRUTE_FORCE",
    # Misc (bot/web attacks/infiltration — skip or keep as-is)
    "Bot":                  None,   # skip
    "Web Attack  XSS":      None,
    "Web Attack – XSS":     None,
    "Web Attack - XSS":     None,
    "Web Attack  Sql Injection": None,
    "Infiltration":         None,
}

CLASSES = ["BENIGN", "PORT_SCAN", "DOS_DDOS", "BRUTE_FORCE"]


# ── helpers ──────────────────────────────────────────────────────────────────

def _print(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace from column names and apply column map."""
    df.columns = [c.strip() for c in df.columns]

    # Try primary map first
    rename = {}
    for orig, mapped in COLUMN_MAP.items():
        if orig.strip() in df.columns:
            rename[orig.strip()] = mapped
    if rename:
        df = df.rename(columns=rename)
        _print(f"  Mapped {len(rename)} columns via primary map")
        return df

    # Try lowercase alternative map
    df.columns = [c.lower().replace(" ", "_") for c in df.columns]
    rename = {}
    for orig, mapped in ALT_COLUMN_MAP.items():
        if orig in df.columns:
            rename[orig] = mapped
    if rename:
        df = df.rename(columns=rename)
        _print(f"  Mapped {len(rename)} columns via alt map")

    return df


def download_from_huggingface() -> pd.DataFrame:
    """Stream CIC-IDS2017 from Hugging Face and return a plain pandas DataFrame."""
    try:
        from datasets import load_dataset
    except ImportError:
        _print("ERROR: 'datasets' package not found. Run: pip install datasets")
        sys.exit(1)

    _print(f"Streaming dataset from Hugging Face: {HF_REPO_ID}")
    _print("  (This may take a few minutes depending on your connection...)")

    try:
        ds = load_dataset(HF_REPO_ID, split="train", streaming=False)
        # Use the datasets built-in Arrow→numpy conversion (fastest, avoids PyArrow dtypes)
        df = ds.to_pandas()
        # Materialize Arrow-backed columns into native numpy/Python types
        df = df.infer_objects()
        for col in df.select_dtypes(include="object").columns:
            df[col] = df[col].astype(str)
        _print(f"  Downloaded {len(df):,} rows, {len(df.columns)} columns")
        return df
    except Exception as e:
        _print(f"  Primary repo failed: {e}")
        _print("  Trying fallback repo: bvsam/cic-ids-2017 ...")
        try:
            ds = load_dataset("bvsam/cic-ids-2017", split="train", streaming=False)
            df = ds.to_pandas().infer_objects()
            _print(f"  Downloaded {len(df):,} rows, {len(df.columns)} columns")
            return df
        except Exception as e2:
            _print(f"  Fallback also failed: {e2}")
            _print("  Trying raw CSV download from UNB mirror...")
            return download_csv_files()


def download_csv_files() -> pd.DataFrame:
    """Download individual day CSVs from a public mirror and concatenate."""
    import urllib.request

    base = "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/MachineLearningCVE"
    day_files = [
        "Monday-WorkingHours.pcap_ISCX.csv",
        "Tuesday-WorkingHours.pcap_ISCX.csv",
        "Wednesday-workingHours.pcap_ISCX.csv",
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    ]

    DATASETS_DIR.mkdir(exist_ok=True)
    dfs = []

    for fname in day_files:
        local_path = DATASETS_DIR / fname
        if not local_path.exists():
            url = f"{base}/{fname}"
            _print(f"  Downloading {fname}...")
            try:
                urllib.request.urlretrieve(url, local_path)
            except Exception as e:
                _print(f"    Skipped ({e})")
                continue
        else:
            _print(f"  Cached: {fname}")

        try:
            df = pd.read_csv(local_path, encoding="latin1", low_memory=False)
            dfs.append(df)
            _print(f"    Loaded {len(df):,} rows")
        except Exception as e:
            _print(f"    Failed to parse {fname}: {e}")

    if not dfs:
        _print("ERROR: Could not download any data files. Exiting.")
        sys.exit(1)

    return pd.concat(dfs, ignore_index=True)


# ── feature engineering ───────────────────────────────────────────────────────

def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Derive missing features and clean the dataframe.
    After column normalization, we need:
      syn_ratio, ack_ratio, is_well_known_port
    """
    _print("Engineering derived features...")

    # Ensure numeric types
    numeric_cols = [c for c in FEATURE_COLUMNS if c in df.columns]
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # total packets (for ratio calculation)
    if "total_fwd_packets" in df.columns and "total_bwd_packets" in df.columns:
        total_pkts = df["total_fwd_packets"] + df["total_bwd_packets"]
        total_pkts = total_pkts.replace(0, np.nan)

        if "syn_ratio" not in df.columns and "syn_flag_count" in df.columns:
            df["syn_ratio"] = df["syn_flag_count"] / total_pkts
            df["syn_ratio"] = df["syn_ratio"].fillna(0.0).clip(0.0, 1.0)

        if "ack_ratio" not in df.columns and "ack_flag_count" in df.columns:
            df["ack_ratio"] = df["ack_flag_count"] / total_pkts
            df["ack_ratio"] = df["ack_ratio"].fillna(0.0).clip(0.0, 1.0)

    if "is_well_known_port" not in df.columns and "destination_port" in df.columns:
        df["is_well_known_port"] = (df["destination_port"] < 1024).astype(int)

    # flow_duration: CIC-IDS stores microseconds — convert to seconds
    if "flow_duration" in df.columns:
        # Values > 1e6 suggest microseconds
        if df["flow_duration"].median() > 1_000:
            df["flow_duration"] = df["flow_duration"] / 1_000_000.0
        df["flow_duration"] = df["flow_duration"].clip(lower=0.0)

    return df


# ── preprocessing ─────────────────────────────────────────────────────────────

def preprocess(df: pd.DataFrame, sample_per_class: int = None) -> pd.DataFrame:
    """
    Clean, filter, and optionally sample the dataframe.
    Returns a clean dataframe with FEATURE_COLUMNS + 'label'.
    """
    _print(f"Raw dataset shape: {df.shape}")

    # Normalize columns
    df = _normalize_columns(df)

    # Engineer derived features
    df = engineer_features(df)

    # Validate required columns exist
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        _print(f"ERROR: Missing columns after mapping: {missing}")
        _print(f"  Available columns: {list(df.columns)}")
        sys.exit(1)

    if "label" not in df.columns:
        _print("ERROR: 'label' column not found after mapping.")
        sys.exit(1)

    # Map labels
    df["label"] = df["label"].astype(str).str.strip()
    df["class"] = df["label"].map(LABEL_MAP)
    df = df[df["class"].notna()].copy()   # drop rows with unmapped/skipped labels

    _print(f"After label mapping: {len(df):,} rows")
    _print("  Class distribution (raw):")
    for cls, cnt in df["class"].value_counts().items():
        _print(f"    {cls}: {cnt:,}")

    # Select and clean feature columns
    df = df[FEATURE_COLUMNS + ["class"]].copy()
    df = df.rename(columns={"class": "label"})

    # Replace inf values with NaN then fill
    df = df.replace([np.inf, -np.inf], np.nan)

    # Fill NaN with column median
    for col in FEATURE_COLUMNS:
        med = df[col].median()
        df[col] = df[col].fillna(med if not np.isnan(med) else 0.0)

    # Clip extreme outliers to 99.9th percentile per column
    for col in FEATURE_COLUMNS:
        p999 = df[col].quantile(0.999)
        if p999 > 0:
            df[col] = df[col].clip(upper=p999)

    # Remove any remaining NaN rows
    df = df.dropna()
    _print(f"After cleaning: {len(df):,} rows")

    # Optional stratified sampling to cap per-class size
    if sample_per_class:
        parts = []
        for cls in CLASSES:
            subset = df[df["label"] == cls]
            if len(subset) == 0:
                _print(f"  WARNING: Class '{cls}' has no samples!")
                continue
            n = min(len(subset), sample_per_class)
            parts.append(subset.sample(n=n, random_state=42))
        df = pd.concat(parts, ignore_index=True).sample(frac=1, random_state=42)
        _print(f"After sampling ({sample_per_class}/class): {len(df):,} rows")

    _print("  Final class distribution:")
    for cls, cnt in df["label"].value_counts().items():
        _print(f"    {cls}: {cnt:,}")

    return df


# ── training ──────────────────────────────────────────────────────────────────

def train(df: pd.DataFrame) -> dict:
    """
    Train RandomForest with SMOTE class balancing.
    Returns a dict of all evaluation metrics.
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score,
        f1_score, confusion_matrix, classification_report
    )

    try:
        from imblearn.over_sampling import SMOTE
        use_smote = True
    except ImportError:
        _print("  imbalanced-learn not available — skipping SMOTE")
        use_smote = False

    # Force plain numpy arrays — HuggingFace to_pandas() returns PyArrow-backed
    # dtypes that break sklearn's indexing. .to_numpy() always gives a real ndarray.
    X = df[FEATURE_COLUMNS].to_numpy(dtype=np.float64)
    y = df["label"].to_numpy(dtype=str)

    # Train / test split — stratified
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    _print(f"  Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # Scale features
    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc  = scaler.transform(X_test)

    # SMOTE — balance minority classes in training set only
    if use_smote:
        _print("  Applying SMOTE oversampling on training set...")
        from collections import Counter
        counts = Counter(y_train)
        # Only apply SMOTE if a minority class has at least 6 samples
        min_samples = min(counts.values())
        if min_samples >= 6:
            sm = SMOTE(random_state=42, k_neighbors=min(5, min_samples - 1))
            X_train_sc, y_train = sm.fit_resample(X_train_sc, y_train)
            _print(f"  After SMOTE: {len(X_train_sc):,} training samples")
            from collections import Counter
            for cls, cnt in sorted(Counter(y_train).items()):
                _print(f"    {cls}: {cnt:,}")
        else:
            _print(f"  SMOTE skipped: min class has only {min_samples} samples")

    # Train RandomForest
    _print("  Training RandomForestClassifier (n_estimators=200)...")
    t0 = time.time()
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(X_train_sc, y_train)
    elapsed = time.time() - t0
    _print(f"  Training complete in {elapsed:.1f}s")

    # Evaluate
    y_pred = model.predict(X_test_sc)
    acc       = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    recall    = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1        = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    # False positive rate = FP / (FP + TN) — averaged over classes
    cm = confusion_matrix(y_test, y_pred, labels=model.classes_)
    fp_rates = []
    for i, cls in enumerate(model.classes_):
        fp = cm[:, i].sum() - cm[i, i]
        tn = cm.sum() - cm[i, :].sum() - cm[:, i].sum() + cm[i, i]
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fp_rates.append(fpr)
    avg_fpr = float(np.mean(fp_rates))

    # Per-class metrics
    report = classification_report(y_test, y_pred, labels=model.classes_,
                                   output_dict=True, zero_division=0)
    per_class = {}
    for cls in model.classes_:
        if cls in report:
            per_class[cls] = {
                "precision":  round(report[cls]["precision"], 4),
                "recall":     round(report[cls]["recall"], 4),
                "f1_score":   round(report[cls]["f1-score"], 4),
                "support":    report[cls]["support"],
            }

    # Feature importances
    importances = dict(zip(FEATURE_COLUMNS, model.feature_importances_.tolist()))
    importances = dict(sorted(importances.items(), key=lambda x: x[1], reverse=True))
    importances = {k: round(v, 4) for k, v in importances.items()}

    # Confusion matrix as nested list (rows=actual, cols=predicted)
    cm_list = cm.tolist()

    _print("  Results:")
    _print(f"  Accuracy:  {acc:.4f}  ({acc*100:.2f}%)")
    _print(f"  Precision: {precision:.4f}")
    _print(f"  Recall:    {recall:.4f}")
    _print(f"  F1 Score:  {f1:.4f}")
    _print(f"  Avg FPR:   {avg_fpr:.4f}  ({avg_fpr*100:.2f}%)")
    _print("\n  Per-class:")
    for cls, m in per_class.items():
        _print(f"    {cls:15s}  P={m['precision']:.3f}  R={m['recall']:.3f}  F1={m['f1_score']:.3f}  n={int(m['support'])}")

    # Save artifacts
    MODELS_DIR.mkdir(exist_ok=True)
    joblib.dump(model,  MODELS_DIR / "random_forest_ids.joblib")
    joblib.dump(scaler, MODELS_DIR / "scaler.joblib")
    _print(f"\n  Saved model  → {MODELS_DIR / 'random_forest_ids.joblib'}")
    _print(f"  Saved scaler → {MODELS_DIR / 'scaler.joblib'}")

    metrics = {
        "is_trained":         True,
        "model_type":         "RandomForestClassifier",
        "model_version":      "2.0.0",
        "dataset_source":     "CIC-IDS2017 (HuggingFace mirror: c01dsnap/CIC-IDS2017)",
        "training_set_size":  int(len(X_train)),
        "test_set_size":      int(len(X_test)),
        "features":           FEATURE_COLUMNS,
        "classes":            list(model.classes_),
        "accuracy":           round(acc, 4),
        "precision":          round(precision, 4),
        "recall":             round(recall, 4),
        "f1_score":           round(f1, 4),
        "false_positive_rate": round(avg_fpr, 4),
        "confusion_matrix":   cm_list,
        "confusion_matrix_labels": list(model.classes_),
        "per_class_metrics":  per_class,
        "baseline_comparison": {
            "baseline_type":     "Previous synthetic-data RandomForest v1.0.0",
            "baseline_accuracy": 1.0,
            "baseline_f1_score": 1.0,
            "ml_f1_improvement": round(f1 - 1.0, 4),
            "note": "Previous 1.0 accuracy was on synthetic data — unrealistic. Real-world scores are now shown.",
        },
        "feature_importances": importances,
        "trained_at":          datetime.utcnow().isoformat(),
    }

    metrics_path = MODELS_DIR / "ml_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    _print(f"  Saved metrics → {metrics_path}")

    # Also update app/ml/dataset.py CLASSES constant
    _update_dataset_classes(list(model.classes_))

    return metrics


def _update_dataset_classes(classes: list):
    """Patch CLASSES constant in app/ml/dataset.py so the API reflects new labels."""
    dataset_path = Path("backend/app/ml/dataset.py")
    if not dataset_path.exists():
        return
    text = dataset_path.read_text(encoding="utf-8")
    old_line = next((l for l in text.splitlines() if l.startswith("CLASSES = [")), None)
    if old_line:
        new_line = f'CLASSES = {json.dumps(classes)}'
        text = text.replace(old_line, new_line)
        dataset_path.write_text(text, encoding="utf-8")
        _print(f"  Updated CLASSES in {dataset_path} → {classes}")


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CyberShield ML retrainer on CIC-IDS2017")
    parser.add_argument("--sample", type=int, default=None,
                        help="Max rows per class for faster runs (e.g. 30000)")
    parser.add_argument("--no-download", action="store_true",
                        help="Skip download, expect cached HF files")
    args = parser.parse_args()

    _print("=" * 60)
    _print(" CyberShield - ML Retrainer on CIC-IDS2017")
    _print("=" * 60)

    # 1. Download
    _print("\n[1/3] Acquiring dataset...")
    df_raw = download_from_huggingface()

    # 2. Preprocess
    _print("\n[2/3] Preprocessing...")
    df = preprocess(df_raw, sample_per_class=args.sample)

    # 3. Train
    _print("\n[3/3] Training...")
    metrics = train(df)

    _print("\n" + "=" * 60)
    _print(" Done! Restart the backend to load the new model.")
    _print(f"   Accuracy: {metrics['accuracy']*100:.2f}%  |  F1: {metrics['f1_score']:.4f}")
    _print("=" * 60)


if __name__ == "__main__":
    main()
