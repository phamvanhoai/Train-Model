from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import psycopg
from psycopg.rows import dict_row

from securaai_ml.wazuh_review import REVIEW_FIELDS, payload_to_review_row


def database_url(env_path: Path) -> str:
    if os.getenv("DATABASE_URL"):
        value = os.environ["DATABASE_URL"]
    else:
        lines = env_path.read_text(encoding="utf-8").splitlines()
        value = next(line.split("=", 1)[1].strip().strip('"').strip("'") for line in lines if line.strip().startswith("DATABASE_URL="))
    parsed = urlsplit(value)
    query = urlencode([(key, val) for key, val in parse_qsl(parsed.query) if key != "schema"])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def main() -> None:
    parser = argparse.ArgumentParser(description="Export one controlled Wazuh lab run")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--backend-env", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8-sig"))
    username_prefix = manifest["invalid_username"] + "_"
    start, end = manifest["attack_started_at"], manifest["attack_ended_at"]
    query = """
      SELECT e.external_event_id, e.occurred_at::text, e.account_identifier, e.event_family::text, e.event_type,
             e.severity, e.source_ip, e.destination_ip, e.normalized_payload, s.name source_name
      FROM normalized_events e JOIN event_sources s ON s.id=e.event_source_id
      WHERE e.occurred_at BETWEEN %s::timestamptz AND %s::timestamptz
        AND e.account_identifier LIKE %s AND s.source_type='WAZUH'
      ORDER BY e.occurred_at, e.id
    """
    with psycopg.connect(database_url(args.backend_env), row_factory=dict_row) as connection:
        records = list(connection.execute(query, (start, end, username_prefix + "%")).fetchall())
    rows = []
    for record in records:
        row = payload_to_review_row(record)
        row["reviewer_label"] = "MALICIOUS_APT"
        row["include_for_training"] = "true"
        row["review_notes"] = f"Ground truth from controlled run {manifest['run_id']}: failed_login_burst"
        rows.append(row)
    output = args.output or args.manifest.with_suffix(".csv")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=REVIEW_FIELDS, extrasaction="ignore")
        writer.writeheader(); writer.writerows(rows)
    print(f"Exported {len(rows)} ground-truth events to {output}")
    if len(rows) != int(manifest["failed_login_attempts"]):
        raise SystemExit("Captured event count differs from manifest; do not use this run for training")


if __name__ == "__main__":
    main()
