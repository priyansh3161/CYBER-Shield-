"""
train_model.py
Trains supervised classifiers from the CSV produced by dataset_builder.py
and saves them under models_store/ so ai_ml_analyzer.py picks them up
automatically on the next run (no code change needed to "activate" them).

Trains two models:
  1. Binary classifier  -> "malicious" vs "normal"
  2. Multiclass classifier -> "Critical" / "High" / "Medium" / "Low" / "Safe"

Usage:
    python train_model.py training_data.csv
    python train_model.py training_data.csv --test-size 0.25
"""

import argparse
import os

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from feature_schema import FEATURE_NAMES

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models_store")


def train(csv_path: str, test_size: float = 0.2):
    df = pd.read_csv(csv_path)
    missing = [c for c in FEATURE_NAMES if c not in df.columns]
    if missing:
        raise ValueError(f"Training CSV is missing expected feature columns: {missing}")

    X = df[FEATURE_NAMES]
    os.makedirs(MODELS_DIR, exist_ok=True)

    # --- Binary classifier: malicious vs normal ---
    if "binary_label" in df.columns and df["binary_label"].nunique() > 1:
        y_bin = df["binary_label"]
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_bin, test_size=test_size, random_state=42,
            stratify=y_bin if y_bin.value_counts().min() >= 2 else None,
        )
        bin_model = RandomForestClassifier(
            n_estimators=200, max_depth=8, random_state=42, class_weight="balanced"
        )
        bin_model.fit(X_train, y_train)
        preds = bin_model.predict(X_test)
        print("\n=== Binary classifier (malicious vs normal) ===")
        print(classification_report(y_test, preds, zero_division=0))

        bin_path = os.path.join(MODELS_DIR, "binary_classifier.joblib")
        joblib.dump(bin_model, bin_path)
        print(f"Saved: {bin_path}")
    else:
        print("Skipping binary classifier: 'binary_label' column missing or has <2 classes.")

    # --- Multiclass classifier: risk category ---
    if "risk_category" in df.columns and df["risk_category"].nunique() > 1:
        y_risk = df["risk_category"]
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_risk, test_size=test_size, random_state=42,
            stratify=y_risk if y_risk.value_counts().min() >= 2 else None,
        )
        risk_model = RandomForestClassifier(
            n_estimators=200, max_depth=8, random_state=42, class_weight="balanced"
        )
        risk_model.fit(X_train, y_train)
        preds = risk_model.predict(X_test)
        print("\n=== Multiclass classifier (risk category) ===")
        print(classification_report(y_test, preds, zero_division=0))

        risk_path = os.path.join(MODELS_DIR, "risk_classifier.joblib")
        joblib.dump(risk_model, risk_path)
        print(f"Saved: {risk_path}")
    else:
        print("Skipping risk classifier: 'risk_category' column missing or has <2 classes.")

    print(f"\nDone. Restart main.py -- ai_ml_analyzer.py will auto-load models from {MODELS_DIR}/")


def main():
    parser = argparse.ArgumentParser(description="Train supervised classifiers for the AI/ML stage.")
    parser.add_argument("csv_path", help="Path to labeled training CSV from dataset_builder.py")
    parser.add_argument("--test-size", type=float, default=0.2)
    args = parser.parse_args()
    train(args.csv_path, args.test_size)


if __name__ == "__main__":
    main()
