from __future__ import annotations

import argparse
import json
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from sklearn.metrics import confusion_matrix, fbeta_score, precision_score, recall_score

from securaai_ml.wazuh_review import _read_backend_database_url
from evaluate_securaai_external_benchmark import libpq_url


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate predictions actually persisted by the SecuraAI ML shadow pipeline"
    )
    parser.add_argument("--runs", type=Path, required=True)
    parser.add_argument("--backend-env", type=Path, required=True)
    parser.add_argument("--expected-model-version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    specs = json.loads(args.runs.read_text(encoding="utf-8"))
    query = """
      SELECT e.external_event_id, e.occurred_at::text, f.feature_value
      FROM normalized_events e
      JOIN anomaly_detections d ON d.event_id=e.id
      JOIN anomaly_feature_contributions f ON f.detection_id=d.id
        AND f.feature_name='ml_shadow_prediction'
      WHERE e.external_event_id LIKE %s
      ORDER BY e.occurred_at, e.external_event_id
    """
    rows: list[dict] = []
    with psycopg.connect(
        libpq_url(_read_backend_database_url(args.backend_env)), row_factory=dict_row
    ) as connection:
        for spec in specs:
            records = list(connection.execute(query, (spec["run_id"] + "%",)).fetchall())
            if len(records) != (spec.get("burst_count") or 3):
                raise RuntimeError(
                    f"{spec['run_id']}: expected {spec.get('burst_count') or 3} persisted "
                    f"shadow predictions, found {len(records)}"
                )
            for position, record in enumerate(records, 1):
                shadow = json.loads(record["feature_value"])
                if shadow.get("status") != "PREDICTED":
                    raise RuntimeError(f"{record['external_event_id']}: shadow status={shadow.get('status')}")
                prediction = shadow["prediction"]
                if prediction.get("modelVersion") != args.expected_model_version:
                    raise RuntimeError(
                        f"{record['external_event_id']}: modelVersion={prediction.get('modelVersion')}"
                    )
                boundary = spec.get("decision_threshold")
                expected = int(boundary is not None and position >= int(boundary))
                actual = int(bool(prediction["malicious"]))
                rows.append(
                    {
                        "runId": spec["run_id"],
                        "scenario": spec["scenario"],
                        "burstCount": spec.get("burst_count"),
                        "position": position,
                        "externalEventId": record["external_event_id"],
                        "expected": expected,
                        "actual": actual,
                        "label": prediction["label"],
                        "score": prediction["score"],
                        "threshold": prediction["threshold"],
                        "modelVersion": prediction["modelVersion"],
                    }
                )

    target = [row["expected"] for row in rows]
    predicted = [row["actual"] for row in rows]
    tn, fp, fn, tp = confusion_matrix(target, predicted, labels=[0, 1]).ravel()
    summary = {
        "status": "SECURAAI_PERSISTED_ML_SHADOW_EVALUATED",
        "modelVersion": args.expected_model_version,
        "runs": len(specs),
        "events": len(rows),
        "accuracy": float(sum(a == b for a, b in zip(target, predicted)) / len(rows)),
        "precision": precision_score(target, predicted, zero_division=0),
        "recall": recall_score(target, predicted, zero_division=0),
        "f2": fbeta_score(target, predicted, beta=2, zero_division=0),
        "falsePositiveRate": float(fp / (fp + tn)),
        "confusionMatrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    by_case = []
    keys = sorted({(row["scenario"], row["burstCount"]) for row in rows}, key=str)
    for scenario, burst_count in keys:
        group = [row for row in rows if row["scenario"] == scenario and row["burstCount"] == burst_count]
        y = [row["expected"] for row in group]
        p = [row["actual"] for row in group]
        ctn, cfp, cfn, ctp = confusion_matrix(y, p, labels=[0, 1]).ravel()
        by_case.append(
            {
                "scenario": scenario,
                "burstCount": burst_count,
                "events": len(group),
                "tn": int(ctn), "fp": int(cfp), "fn": int(cfn), "tp": int(ctp),
            }
        )
    report = {"summary": summary, "byCase": by_case, "rows": rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"summary": summary, "byCase": by_case}, indent=2))


if __name__ == "__main__":
    main()
