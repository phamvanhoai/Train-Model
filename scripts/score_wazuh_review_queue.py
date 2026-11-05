from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from securaai_ml.modeling import decision_scores
from securaai_ml.temporal import add_session_temporal_features, operational_gate


def assign_review_sessions(frame: pd.DataFrame) -> pd.Series:
    """Group events by principal/family and split sessions after five idle minutes."""
    ordered = frame.sort_values("occurred_at", kind="stable")
    account = ordered["account_identifier"].replace("", pd.NA)
    principal = account.fillna(ordered["source_ip"].replace("", "unknown"))
    key = (
        ordered["agent_name"].replace("", "unknown") + "|" +
        principal.astype(str) + "|" + ordered["event_family"].str.lower()
    )
    timestamps = pd.to_datetime(ordered["occurred_at"], utc=True, errors="raise", format="mixed")
    idle_seconds = timestamps.groupby(key, sort=False).diff().dt.total_seconds()
    new_session = idle_seconds.isna() | idle_seconds.gt(300)
    sequence = new_session.groupby(key, sort=False).cumsum().astype(int)
    sessions = key + "|" + sequence.astype(str)
    return sessions.reindex(frame.index)


def main() -> None:
    parser = argparse.ArgumentParser(description="Score an unlabeled Wazuh review queue without assigning ground truth")
    parser.add_argument("input", type=Path)
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts-temporal-candidate"))
    parser.add_argument("--output", type=Path, default=Path("data/securaai_review/wazuh_review_scored.csv"))
    args = parser.parse_args()

    frame = pd.read_csv(args.input, dtype=str, keep_default_na=False, encoding="utf-8-sig")
    if frame.empty:
        raise SystemExit("Review queue is empty")
    frame["scenario_id"] = assign_review_sessions(frame)
    frame["scenario"] = "UNLABELLED_WAZUH_REVIEW"
    features = add_session_temporal_features(frame)
    model = joblib.load(args.artifacts / "model.joblib")
    metadata = json.loads((args.artifacts / "model_metadata.json").read_text(encoding="utf-8"))
    raw_score = decision_scores(model, features)
    allowed = operational_gate(features)
    score = np.where(allowed, raw_score, 0.0)
    prediction = score >= float(metadata["lockedThreshold"])

    output = frame.drop(columns=["scenario"], errors="ignore").copy()
    output.rename(columns={"scenario_id": "review_session_id"}, inplace=True)
    output["model_score"] = score
    output["model_prediction"] = np.where(prediction, "MALICIOUS_APT", "BENIGN")
    output["operational_gate_allows"] = allowed
    output["locked_threshold"] = float(metadata["lockedThreshold"])
    output["review_priority"] = np.where(
        prediction, "REVIEW_MODEL_POSITIVE",
        np.where(output["review_suggestion"].eq("REVIEW_MALICIOUS_CANDIDATE"), "REVIEW_RULE_POSITIVE", "REVIEW_REMAINDER"),
    )
    output.sort_values(["review_priority", "review_session_id", "occurred_at"], inplace=True, kind="stable")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    output.to_csv(args.output, index=False, encoding="utf-8-sig")
    summary = {
        "events": len(output), "sessions": int(output["review_session_id"].nunique()),
        "modelPositive": int(prediction.sum()), "modelNegative": int((~prediction).sum()),
        "reviewerLabelsAssigned": int(output["reviewer_label"].str.strip().ne("").sum()),
    }
    print(json.dumps(summary, indent=2))
    print(f"Saved blinded review queue to {args.output}")
    print("model_prediction is not ground truth; reviewer_label remains unchanged.")


if __name__ == "__main__":
    main()
