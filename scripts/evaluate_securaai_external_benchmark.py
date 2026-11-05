from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import joblib
import pandas as pd
import psycopg
from psycopg.rows import dict_row
from sklearn.metrics import confusion_matrix, fbeta_score, precision_score, recall_score

from securaai_ml.temporal import add_session_temporal_features, operational_gate
from securaai_ml.wazuh_review import _read_backend_database_url, payload_to_review_row


def libpq_url(value: str) -> str:
    parsed = urlsplit(value)
    query = urlencode([(key, val) for key, val in parse_qsl(parsed.query) if key != "schema"])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate external SecuraAI/Wazuh benchmark")
    parser.add_argument("--runs", type=Path, default=Path("reports/securaai_external_benchmark_runs.json"))
    parser.add_argument("--backend-env", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts-temporal-candidate"))
    parser.add_argument("--output", type=Path, default=Path("reports/securaai_external_benchmark.json"))
    args = parser.parse_args()
    specs = json.loads(args.runs.read_text(encoding="utf-8"))
    if isinstance(specs, dict): specs = [specs]
    query = """
      SELECT e.external_event_id, e.occurred_at::text, e.event_family::text, e.event_type,
             e.severity, e.source_ip, e.destination_ip, e.normalized_payload, s.name source_name
      FROM normalized_events e JOIN event_sources s ON s.id=e.event_source_id
      WHERE e.external_event_id LIKE %s ORDER BY e.occurred_at, e.external_event_id
    """
    rows = []
    with psycopg.connect(libpq_url(_read_backend_database_url(args.backend_env)), row_factory=dict_row) as connection:
        for spec in specs:
            records = list(connection.execute(query, (spec["run_id"] + "%",)).fetchall())
            if not records: raise RuntimeError(f"No events found for {spec['run_id']}")
            for position, record in enumerate(records, start=1):
                row = payload_to_review_row(record)
                threshold = spec.get("decision_threshold")
                malicious = threshold is not None and position >= int(threshold)
                row.update(scenario_id=spec["run_id"], scenario=spec["scenario"],
                           burst_count=spec.get("burst_count"), event_position=position,
                           reviewer_label="MALICIOUS_APT" if malicious else "BENIGN")
                rows.append(row)
    frame = pd.DataFrame(rows)
    model = joblib.load(args.artifacts / "model.joblib")
    metadata = json.loads((args.artifacts / "model_metadata.json").read_text(encoding="utf-8"))
    features = add_session_temporal_features(frame)
    score = model.predict_proba(features)[:, 1]
    score = __import__('numpy').where(operational_gate(features), score, 0.0)
    target = frame["reviewer_label"].eq("MALICIOUS_APT").astype(int).to_numpy()
    prediction = score >= metadata["lockedThreshold"]
    frame["prediction"] = prediction.astype(int); frame["score"] = score
    tn, fp, fn, tp = confusion_matrix(target, prediction, labels=[0, 1]).ravel()
    summary = {
        "modelVersion": metadata["modelVersion"], "lockedThreshold": metadata["lockedThreshold"],
        "runs": len(specs), "events": len(frame),
        "accuracy": float((prediction == target).mean()),
        "precision": precision_score(target, prediction, zero_division=0),
        "recall": recall_score(target, prediction, zero_division=0),
        "f2": fbeta_score(target, prediction, beta=2, zero_division=0),
        "falsePositiveRate": float(fp / (fp + tn)),
        "confusionMatrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    by_case = []
    for keys, group in frame.groupby(["scenario", "burst_count"], dropna=False):
        y = group["reviewer_label"].eq("MALICIOUS_APT").astype(int)
        p = group["prediction"]
        ctn, cfp, cfn, ctp = confusion_matrix(y, p, labels=[0, 1]).ravel()
        by_case.append({"scenario": keys[0], "burstCount": None if pd.isna(keys[1]) else int(keys[1]),
                        "events": len(group), "tn": int(ctn), "fp": int(cfp),
                        "fn": int(cfn), "tp": int(ctp)})
    report = {"summary": summary, "byCase": by_case}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
