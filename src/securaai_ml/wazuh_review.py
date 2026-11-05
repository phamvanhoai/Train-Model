from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REVIEW_FIELDS = (
    "external_event_id", "occurred_at", "source_name", "agent_name", "account_identifier", "event_family",
    "event_type", "wazuh_rule_id", "wazuh_rule_level", "wazuh_rule_description",
    "event_id", "provider_name", "channel", "severity_value", "decoder", "location",
    "input_type", "logon_type", "authentication_package", "integrity_level",
    "process_path", "parent_process_path", "command_line_present",
    "parent_command_line_present", "target_file_present", "hashes_present", "source_ip",
    "destination_ip", "source_port", "destination_port", "protocol", "status",
    "sub_status", "review_suggestion", "reviewer_label", "include_for_training",
    "review_notes",
)
VALID_LABELS = {"BENIGN", "MALICIOUS_APT"}


def review_to_model_frame(frame):
    """Map exported review rows to the same canonical inference contract."""
    import pandas as pd
    from .features import build_features

    def present(name: str):
        return frame.get(name, pd.Series("", index=frame.index)).astype(str).str.lower().eq("true")

    canonical = pd.DataFrame(index=frame.index)
    mapping = {
        "timestamp": "occurred_at", "eventId": "event_id", "providerName": "provider_name",
        "channel": "channel", "severityValue": "severity_value", "decoder": "decoder",
        "location": "location", "inputType": "input_type", "logonType": "logon_type",
        "authenticationPackage": "authentication_package", "integrityLevel": "integrity_level",
        "processPath": "process_path", "parentProcessPath": "parent_process_path",
        "sourceIp": "source_ip", "destinationIp": "destination_ip", "sourcePort": "source_port",
        "destinationPort": "destination_port", "protocol": "protocol", "status": "status",
        "subStatus": "sub_status",
    }
    for output, source in mapping.items():
        canonical[output] = frame.get(source, pd.Series("", index=frame.index)).fillna("")
    canonical["commandLine"] = present("command_line_present").map({True: "present", False: ""})
    canonical["parentCommandLine"] = present("parent_command_line_present").map({True: "present", False: ""})
    canonical["targetFilename"] = present("target_file_present").map({True: "present", False: ""})
    canonical["hashes"] = present("hashes_present").map({True: "present", False: ""})
    return build_features(canonical)


def review_suggestion(event: dict[str, Any]) -> str:
    """Suggest review priority; never create a training label."""
    try:
        level = int(event.get("wazuh_rule_level") or 0)
    except (TypeError, ValueError):
        level = 0
    event_id = str(event.get("event_id") or "")
    event_type = str(event.get("event_type") or "").upper()
    if level >= 10:
        return "REVIEW_MALICIOUS_CANDIDATE"
    if level <= 3 and (event_id in {"4624", "4672"} or "SUCCESS" in event_type):
        return "REVIEW_BENIGN_CANDIDATE"
    return "REVIEW_REQUIRED"


def payload_to_review_row(record: dict[str, Any]) -> dict[str, Any]:
    payload = record.get("normalized_payload") or {}
    metadata, rule, agent = payload.get("metadata") or {}, payload.get("rule") or {}, payload.get("agent") or {}
    row = {
        "external_event_id": record.get("external_event_id"), "occurred_at": record.get("occurred_at"),
        "source_name": record.get("source_name"), "agent_name": agent.get("name"),
        "account_identifier": record.get("account_identifier") or payload.get("accountIdentifier"),
        "event_family": record.get("event_family"), "event_type": record.get("event_type"),
        "wazuh_rule_id": rule.get("id"), "wazuh_rule_level": rule.get("level", record.get("severity")),
        "wazuh_rule_description": rule.get("description"), "event_id": metadata.get("eventId"),
        "provider_name": metadata.get("providerName"), "channel": metadata.get("channel"),
        "severity_value": metadata.get("severityValue", record.get("severity")),
        "decoder": metadata.get("decoder"), "location": metadata.get("location"),
        "input_type": metadata.get("inputType"), "logon_type": metadata.get("logonType"),
        "authentication_package": metadata.get("authenticationPackage"),
        "integrity_level": metadata.get("integrityLevel"), "process_path": metadata.get("processName"),
        "parent_process_path": metadata.get("parentProcessName"),
        "command_line_present": bool(metadata.get("commandLine")),
        "parent_command_line_present": bool(metadata.get("parentCommandLine")),
        "target_file_present": bool(metadata.get("targetFilename")), "hashes_present": bool(metadata.get("hashes")),
        "source_ip": payload.get("sourceIp", record.get("source_ip")),
        "destination_ip": payload.get("destinationIp", record.get("destination_ip")),
        "source_port": metadata.get("sourcePort"), "destination_port": metadata.get("destinationPort"),
        "protocol": metadata.get("protocol"), "status": metadata.get("status"),
        "sub_status": metadata.get("subStatus"), "reviewer_label": "",
        "include_for_training": "false", "review_notes": "",
    }
    row["review_suggestion"] = review_suggestion(row)
    return row


def write_review_csv(records: list[dict[str, Any]], output: Path) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = [payload_to_review_row(record) for record in records]
    with output.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=REVIEW_FIELDS, extrasaction="ignore")
        writer.writeheader(); writer.writerows(rows)
    return len(rows)


def validate_review_csv(path: Path) -> tuple[int, int]:
    included = invalid = 0
    with path.open(newline="", encoding="utf-8-sig") as handle:
        for line, row in enumerate(csv.DictReader(handle), start=2):
            if str(row.get("include_for_training", "")).strip().lower() not in {"1", "true", "yes"}:
                continue
            included += 1
            if str(row.get("reviewer_label", "")).strip().upper() not in VALID_LABELS:
                invalid += 1; print(f"Invalid reviewer_label at line {line}")
    return included, invalid


def _read_backend_database_url(backend_env: Path | None) -> str:
    if os.getenv("DATABASE_URL"):
        return os.environ["DATABASE_URL"]
    if backend_env and backend_env.exists():
        for raw_line in backend_env.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line.startswith("DATABASE_URL="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise RuntimeError("DATABASE_URL is missing; pass --backend-env or set it")


def export_from_postgres(database_url: str, source_name: str) -> list[dict[str, Any]]:
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as error:
        raise RuntimeError("Install requirements.txt to enable PostgreSQL export") from error
    # Prisma accepts `?schema=public`; libpq/psycopg doesn't. Preserve all
    # ordinary PostgreSQL connection parameters while removing Prisma's option.
    parsed = urlsplit(database_url)
    query_parameters = [(key, value) for key, value in parse_qsl(parsed.query) if key != "schema"]
    database_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query_parameters), parsed.fragment))
    query = """
        SELECT e.external_event_id, e.occurred_at::text, e.account_identifier, e.event_family::text,
               e.event_type, e.severity, e.source_ip, e.destination_ip,
               e.normalized_payload, s.name AS source_name
        FROM normalized_events e JOIN event_sources s ON s.id = e.event_source_id
        WHERE s.source_type = 'WAZUH' AND s.name = %s
          AND COALESCE(e.external_event_id, '') NOT LIKE 'wazuh-demo-%%'
        ORDER BY e.occurred_at, e.id
    """
    with psycopg.connect(database_url, row_factory=dict_row) as connection:
        records = list(connection.execute(query, (source_name,)).fetchall())
    for record in records:
        if isinstance(record.get("normalized_payload"), str):
            record["normalized_payload"] = json.loads(record["normalized_payload"])
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description="Export non-benchmark simulated Wazuh events for review")
    parser.add_argument("--output", type=Path, default=Path("data/securaai_review/wazuh_review.csv"))
    parser.add_argument("--source-name", default="Wazuh SIEM Ingestion (Default)")
    parser.add_argument("--backend-env", type=Path)
    parser.add_argument("--validate", type=Path)
    args = parser.parse_args()
    if args.validate:
        included, invalid = validate_review_csv(args.validate)
        print(f"Included rows: {included}; invalid labels: {invalid}")
        raise SystemExit(1 if invalid else 0)
    records = export_from_postgres(_read_backend_database_url(args.backend_env), args.source_name)
    count = write_review_csv(records, args.output)
    print(f"Exported {count} non-benchmark simulated Wazuh events to {args.output}")
    print("No training labels were assigned. Review labels manually before training.")


if __name__ == "__main__":
    main()
