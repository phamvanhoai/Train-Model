from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, fbeta_score, precision_score, recall_score

from securaai_ml.temporal import add_session_temporal_features, operational_gate


def metric(target: np.ndarray, prediction: np.ndarray) -> dict[str, object]:
    tn, fp, fn, tp = confusion_matrix(target, prediction, labels=[0, 1]).ravel()
    return {
        "events": len(target), "accuracy": float((target == prediction).mean()),
        "precision": float(precision_score(target, prediction, zero_division=0)),
        "recall": float(recall_score(target, prediction, zero_division=0)),
        "f2": float(fbeta_score(target, prediction, beta=2, zero_division=0)),
        "falsePositiveRate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "confusionMatrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate frozen model on a locked SecuraAI challenge")
    parser.add_argument("--data", type=Path, default=Path("data/challenge_v2/securaai_challenge_v2.csv"))
    parser.add_argument("--manifest", type=Path, default=Path("data/challenge_v2/securaai_challenge_v2.manifest.json"))
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts-temporal-candidate"))
    parser.add_argument("--output", type=Path, default=Path("reports/challenge_v2_result.json"))
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    actual = hashlib.sha256(args.data.read_bytes()).hexdigest()
    if actual != manifest["sha256"]:
        raise SystemExit("Challenge checksum mismatch; evaluation refused")
    frame = pd.read_csv(args.data, dtype=str, keep_default_na=False, encoding="utf-8-sig")
    model = joblib.load(args.artifacts / "model.joblib")
    metadata = json.loads((args.artifacts / "model_metadata.json").read_text(encoding="utf-8"))
    features = add_session_temporal_features(frame)
    score = model.predict_proba(features)[:, 1]
    score = np.where(operational_gate(features), score, 0.0)
    target = frame["reviewer_label"].eq("MALICIOUS_APT").astype(int).to_numpy()
    prediction = (score >= float(metadata["lockedThreshold"])).astype(int)
    by_scenario = {}
    for name, indices in frame.groupby("scenario").groups.items():
        positions = frame.index.get_indexer(indices)
        by_scenario[name] = metric(target[positions], prediction[positions])
    report = {
        "status": "LOCKED_CHALLENGE_EVALUATED_ONCE", "challengeVersion": manifest["version"],
        "challengeSha256": actual,
        "modelVersion": metadata["modelVersion"], "threshold": metadata["lockedThreshold"],
        "summary": metric(target, prediction), "byScenario": by_scenario,
        "interpretation": "Synthetic robustness challenge; not production accuracy and never training data.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
