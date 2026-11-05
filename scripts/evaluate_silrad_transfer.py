from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, balanced_accuracy_score, confusion_matrix,
                             fbeta_score, precision_score, recall_score, roc_auc_score)

from securaai_ml.features import build_features
from securaai_ml.modeling import decision_scores


def main() -> None:
    parser = argparse.ArgumentParser(description="Strict cross-dataset transfer test on SILRAD author test split")
    parser.add_argument("--csv", type=Path, default=Path("data/silrad/fasttext-testmodel.csv"))
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts-radar-family-heldout"))
    parser.add_argument("--output", type=Path, default=Path("reports/silrad_transfer_test.json"))
    args = parser.parse_args()
    model = joblib.load(args.artifacts / "model.joblib")
    metadata = json.loads((args.artifacts / "model_metadata.json").read_text(encoding="utf-8"))
    labels: list[np.ndarray] = []
    scores: list[np.ndarray] = []
    for chunk in pd.read_csv(args.csv, usecols=["event.code", "class"], chunksize=50_000):
        # SILRAD publishes FastText-transformed columns rather than raw Sysmon values.
        # Only event.code has an honest one-to-one mapping to the Wazuh/RADAR contract.
        canonical = pd.DataFrame({"eventId": chunk["event.code"].astype(str)})
        labels.append(chunk["class"].astype(int).to_numpy())
        scores.append(decision_scores(model, build_features(canonical)))
    target = np.concatenate(labels); score = np.concatenate(scores)
    prediction = score >= float(metadata["lockedThreshold"])
    tn, fp, fn, tp = confusion_matrix(target, prediction, labels=[0, 1]).ravel()
    report = {
        "status": "STRICT_CROSS_DATASET_TRANSFER_TEST",
        "trainDataset": "RADAR 2024 raw Sysmon",
        "testDataset": "SILRAD 2025 author test split",
        "mappedFeatures": ["event.code"],
        "rows": int(len(target)), "threshold": float(metadata["lockedThreshold"]),
        "accuracy": float(accuracy_score(target, prediction)),
        "balancedAccuracy": float(balanced_accuracy_score(target, prediction)),
        "precision": float(precision_score(target, prediction, zero_division=0)),
        "recall": float(recall_score(target, prediction, zero_division=0)),
        "f2": float(fbeta_score(target, prediction, beta=2, zero_division=0)),
        "rocAuc": float(roc_auc_score(target, score)),
        "confusionMatrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "limitation": "SILRAD FastText features cannot be reconstructed as raw Wazuh fields; this intentionally harsh test maps event.code only.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
