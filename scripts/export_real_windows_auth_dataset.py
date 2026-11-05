from __future__ import annotations

import argparse
import csv
import json
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import psycopg
from psycopg.rows import dict_row

from securaai_ml.wazuh_review import REVIEW_FIELDS, _read_backend_database_url, payload_to_review_row


EXTRA_FIELDS = ("scenario_id", "scenario", "session_split", "event_index", "ground_truth_source")


def libpq_url(value: str) -> str:
    parsed = urlsplit(value)
    query = urlencode([(key, val) for key, val in parse_qsl(parsed.query) if key != "schema"])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def main() -> None:
    parser = argparse.ArgumentParser(description="Export controlled real Windows auth sessions")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--backend-env", type=Path, required=True)
    parser.add_argument("--wait-seconds", type=int, default=180)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8-sig"))
    account_map = {}
    for session in manifest["sessions"]:
        for position, account in enumerate(session["accounts"], 1):
            account_map[account] = (session, position)
    query = """
      SELECT e.external_event_id, e.occurred_at::text, e.account_identifier,
             e.event_family::text, e.event_type, e.severity, e.source_ip,
             e.destination_ip, e.normalized_payload, s.name source_name
      FROM normalized_events e JOIN event_sources s ON s.id=e.event_source_id
      WHERE e.account_identifier = ANY(%s)
        AND e.event_type = 'LOGIN_FAILURE'
      ORDER BY e.occurred_at, e.external_event_id
    """
    deadline = time.monotonic() + args.wait_seconds
    records = []
    with psycopg.connect(
        libpq_url(_read_backend_database_url(args.backend_env)), row_factory=dict_row
    ) as connection:
        while True:
            records = list(connection.execute(query, (list(account_map),)).fetchall())
            if len(records) >= len(account_map) or time.monotonic() >= deadline:
                break
            time.sleep(5)
    if len(records) != len(account_map):
        raise SystemExit(f"Expected {len(account_map)} Wazuh events, found {len(records)}")
    observed_accounts = [record["account_identifier"] for record in records]
    if len(set(observed_accounts)) != len(observed_accounts):
        raise SystemExit("Duplicate controlled account observed; refusing ambiguous export")
    rows = []
    for record in records:
        session, position = account_map[record["account_identifier"]]
        review = payload_to_review_row(record)
        malicious = bool(session["maliciousSession"]) and position >= int(session["operationalBoundary"])
        review.update({
            "scenario_id": session["scenarioId"], "scenario": session["scenario"],
            "session_split": session["sessionSplit"], "event_index": position - 1,
            "ground_truth_source": "CONTROLLED_REAL_WINDOWS_AUTH_LAB",
            "reviewer_label": "MALICIOUS_APT" if malicious else "BENIGN",
            "include_for_training": "true" if session["sessionSplit"] != "TEST" else "false",
            "review_notes": f"Controlled real Windows session; position={position}; boundary=5",
        })
        rows.append(review)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=EXTRA_FIELDS + REVIEW_FIELDS, extrasaction="ignore")
        writer.writeheader(); writer.writerows(rows)
    labels = {label: sum(row["reviewer_label"] == label for row in rows)
              for label in ("BENIGN", "MALICIOUS_APT")}
    splits = {split: sum(row["session_split"] == split for row in rows)
              for split in ("TRAIN", "VALIDATION", "TEST")}
    print(json.dumps({"events": len(rows), "labels": labels, "splits": splits,
                      "output": str(args.output)}, indent=2))


if __name__ == "__main__":
    main()
