from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import accuracy_score, balanced_accuracy_score, confusion_matrix
from sklearn.metrics import f1_score, fbeta_score, precision_score, recall_score, roc_auc_score

from securaai_ml.modeling import decision_scores
from securaai_ml.radar import radar_to_model_frame, read_radar_csv


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the deployed model on raw RADAR")
    parser.add_argument("--zip", type=Path, required=True)
    parser.add_argument("--member", default="Dataset-imbalanced-10.csv")
    parser.add_argument("--artifact-dir", type=Path, default=Path("artifacts"))
    parser.add_argument("--output", type=Path, default=Path("reports/radar_external.json"))
    args = parser.parse_args()
    model = joblib.load(args.artifact_dir / "model.joblib")
    metadata = json.loads((args.artifact_dir / "model_metadata.json").read_text(encoding="utf-8"))
    threshold = float(metadata["lockedThreshold"])
    labels, scores = [], []
    for chunk in read_radar_csv(args.zip, args.member):
        labels.append(chunk["target-class"].astype(int).to_numpy())
        scores.append(decision_scores(model, radar_to_model_frame(chunk)))
    y = np.concatenate(labels); score = np.concatenate(scores); pred = (score >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    result = {
        "dataset": "RADAR v0.0.1-beta", "member": args.member, "rows": int(len(y)),
        "threshold": threshold, "accuracy": accuracy_score(y, pred),
        "balanced_accuracy": balanced_accuracy_score(y, pred),
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
        "f2": fbeta_score(y, pred, beta=2, zero_division=0),
        "roc_auc": roc_auc_score(y, score),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "score_mean": {"benign": float(score[y == 0].mean()), "malicious": float(score[y == 1].mean())},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
