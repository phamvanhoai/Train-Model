from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import psycopg
from psycopg.rows import dict_row

from securaai_ml.wazuh_review import _read_backend_database_url


def libpq_url(value: str) -> str:
    parsed = urlsplit(value)
    query = urlencode([(key, val) for key, val in parse_qsl(parsed.query) if key != "schema"])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def main() -> None:
    parser = argparse.ArgumentParser(description="Export reviewed real Windows auth lab results")
    parser.add_argument("--backend-env", type=Path, required=True)
    parser.add_argument("--account-prefix", default="SecuraAI_Real2_")
    parser.add_argument("--output", type=Path,
                        default=Path("reports/real_windows_auth_lab_v1.json"))
    args = parser.parse_args()
    query = """
      SELECT e.external_event_id, e.occurred_at::text, e.event_type,
             e.account_identifier, e.source_ip, f.feature_value
      FROM normalized_events e
      JOIN anomaly_detections d ON d.event_id=e.id
      JOIN anomaly_feature_contributions f ON f.detection_id=d.id
        AND f.feature_name='ml_shadow_prediction'
      WHERE e.account_identifier LIKE %s
      ORDER BY e.occurred_at, e.external_event_id
    """
    with psycopg.connect(
        libpq_url(_read_backend_database_url(args.backend_env)), row_factory=dict_row
    ) as connection:
        records = list(connection.execute(query, (args.account_prefix + "%",)).fetchall())
    if not records:
        raise SystemExit("No matching reviewed lab events found")
    events = []
    tn = fp = fn = tp = 0
    for position, record in enumerate(records, 1):
        shadow = json.loads(record["feature_value"])
        prediction = shadow.get("prediction") if shadow.get("status") == "PREDICTED" else None
        expected = "MALICIOUS_APT" if position >= 5 else "BENIGN"
        actual = prediction["label"] if prediction else "UNAVAILABLE"
        if expected == "BENIGN" and actual == "BENIGN": tn += 1
        elif expected == "BENIGN": fp += 1
        elif actual == "MALICIOUS_APT": tp += 1
        else: fn += 1
        events.append({
            "position": position, "externalEventId": record["external_event_id"],
            "occurredAt": record["occurred_at"], "eventType": record["event_type"],
            "account": record["account_identifier"], "sourceIp": record["source_ip"],
            "expectedLabel": expected, "prediction": prediction,
        })
    report = {
        "status": "CONTROLLED_REAL_WINDOWS_LAB_REVIEWED",
        "dataRole": "EXTERNAL_TEST_ONLY_NEVER_TRAIN_UNTIL_INDEPENDENT_REVIEW",
        "groundTruth": "Six controlled SMB authentication failures using distinct nonexistent accounts; operational boundary is the fifth event",
        "pipeline": "Windows Security -> Wazuh Agent -> Wazuh Manager -> SecuraAI Backend -> PostgreSQL -> ML shadow",
        "events": len(events), "confusionMatrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "rows": events,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
