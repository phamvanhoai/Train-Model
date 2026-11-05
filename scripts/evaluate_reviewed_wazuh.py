from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd
from sklearn.metrics import confusion_matrix, fbeta_score, precision_score, recall_score

from securaai_ml.wazuh_review import VALID_LABELS


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate frozen model predictions after independent Wazuh review")
    parser.add_argument("review", type=Path)
    parser.add_argument("--output", type=Path, default=Path("reports/wazuh_review_external_test.json"))
    args = parser.parse_args()
    frame = pd.read_csv(args.review, dtype=str, keep_default_na=False, encoding="utf-8-sig")
    required = {"reviewer_label", "include_for_training", "model_prediction", "review_session_id"}
    missing = required.difference(frame.columns)
    if missing:
        raise SystemExit(f"Missing review columns: {sorted(missing)}")
    included = frame["include_for_training"].str.lower().isin({"1", "true", "yes"})
    evaluated = frame.loc[included].copy()
    invalid = ~evaluated["reviewer_label"].str.upper().isin(VALID_LABELS)
    if evaluated.empty or invalid.any():
        raise SystemExit("Review is incomplete: included rows must have BENIGN or MALICIOUS_APT labels")
    if evaluated["reviewer_label"].nunique() < 2:
        raise SystemExit("External evaluation requires at least one included row from each class")
    target = evaluated["reviewer_label"].str.upper().eq("MALICIOUS_APT").astype(int)
    prediction = evaluated["model_prediction"].str.upper().eq("MALICIOUS_APT").astype(int)
    tn, fp, fn, tp = confusion_matrix(target, prediction, labels=[0, 1]).ravel()
    report = {
        "status": "REVIEWED_SIMULATED_EXTERNAL_TEST",
        "events": len(evaluated), "sessions": int(evaluated["review_session_id"].nunique()),
        "precision": float(precision_score(target, prediction, zero_division=0)),
        "recall": float(recall_score(target, prediction, zero_division=0)),
        "f2": float(fbeta_score(target, prediction, beta=2, zero_division=0)),
        "falsePositiveRate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "confusionMatrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
