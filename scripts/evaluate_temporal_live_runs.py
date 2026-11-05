from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import joblib
import pandas as pd
import psycopg
from psycopg.rows import dict_row
from sklearn.metrics import confusion_matrix

from securaai_ml.temporal import add_session_temporal_features, operational_gate
from securaai_ml.wazuh_review import _read_backend_database_url, payload_to_review_row


def libpq_url(value: str) -> str:
    parsed = urlsplit(value)
    query = urlencode([(key, val) for key, val in parse_qsl(parsed.query) if key != "schema"])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate temporal candidate on labelled live demo runs")
    parser.add_argument("--backend-env", type=Path, required=True)
    parser.add_argument("--benign-run", required=True)
    parser.add_argument("--malicious-run", required=True)
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts-temporal-candidate"))
    args = parser.parse_args()
    query = """
      SELECT e.external_event_id, e.occurred_at::text, e.account_identifier, e.event_family::text, e.event_type,
             e.severity, e.source_ip, e.destination_ip, e.normalized_payload, s.name source_name
      FROM normalized_events e JOIN event_sources s ON s.id=e.event_source_id
      WHERE e.external_event_id LIKE %s ORDER BY e.occurred_at, e.id
    """
    rows = []
    with psycopg.connect(libpq_url(_read_backend_database_url(args.backend_env)), row_factory=dict_row) as connection:
        for run, label in ((args.benign_run, "BENIGN"), (args.malicious_run, "MALICIOUS_APT")):
            for record in connection.execute(query, (run + "%",)).fetchall():
                row = payload_to_review_row(record)
                row.update(scenario_id=run, scenario=run, reviewer_label=label)
                rows.append(row)
    frame = pd.DataFrame(rows)
    model = joblib.load(args.artifacts / "model.joblib")
    metadata = json.loads((args.artifacts / "model_metadata.json").read_text(encoding="utf-8"))
    features = add_session_temporal_features(frame)
    score = model.predict_proba(features)[:, 1]
    score = __import__('numpy').where(operational_gate(features), score, 0.0)
    # External live AuthBurst ground truth follows the same operational
    # decision point as training: the fifth failure and later are malicious.
    position = frame.groupby("scenario_id").cumcount() + 1
    malicious_run = frame["scenario_id"].eq(args.malicious_run)
    target = (malicious_run & position.ge(5)).astype(int).to_numpy()
    prediction = score >= metadata["lockedThreshold"]
    tn, fp, fn, tp = confusion_matrix(target, prediction, labels=[0, 1]).ravel()
    report = pd.DataFrame({
        "run": frame["scenario_id"], "event_type": frame["event_type"],
        "target": target, "prediction": prediction.astype(int), "score": score,
    })
    print(report.to_string(index=False))
    print({"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp), "rows": len(frame)})


if __name__ == "__main__":
    main()
