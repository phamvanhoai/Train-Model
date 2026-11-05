from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from securaai_ml.wazuh_review import REVIEW_FIELDS

EXTRA = ("scenario_id", "scenario", "event_index", "ground_truth_source")
FIELDS = EXTRA + REVIEW_FIELDS


def row(session: str, scenario: str, index: int, at: datetime, family: str,
        event_type: str, label: str, account: str, source_ip: str) -> dict[str, object]:
    return {
        "scenario_id": session, "scenario": scenario, "event_index": index,
        "ground_truth_source": "LOCKED_CHALLENGE_V2_MANIFEST",
        "external_event_id": f"{session}-{index:03d}", "occurred_at": at.isoformat(),
        "source_name": "SecuraAI Challenge V2", "agent_name": f"CHALLENGE-{int(session[-5:]) % 17:02d}",
        "account_identifier": account, "event_family": family, "event_type": event_type,
        "provider_name": "SecuraAI-Challenge", "channel": "Security", "decoder": "json",
        "location": "challenge-v2", "input_type": family, "source_ip": source_ip,
        "destination_ip": "10.250.0.10", "destination_port": "443", "protocol": "tcp",
        "status": "failure" if "FAIL" in event_type or "DENIED" in event_type else "success",
        "reviewer_label": label, "include_for_training": "false",
        "review_notes": f"Locked Challenge V2 ground truth: {scenario}",
    }


def generate(sessions: int, seed: int) -> list[dict[str, object]]:
    rng = random.Random(seed)
    start = datetime(2027, 3, 1, tzinfo=timezone.utc)
    scenarios = (
        "AUTH_ALIAS_BURST", "VPN_ALIAS_BURST", "APP_ALIAS_BURST",
        "AUTH_SLOW_ATTEMPTS", "AUTH_INTERLEAVED_NOISE", "AUTH_SPRAY",
        "AUTH_DISTRIBUTED", "AUTH_OFFHOURS_SUCCESS", "MISSING_CONTEXT",
        "APP_SUCCESS_AFTER_DENIAL", "VPN_NORMAL", "DUPLICATE_TIMESTAMP_AUTH",
    )
    rows: list[dict[str, object]] = []
    for session_index in range(sessions):
        scenario = scenarios[session_index % len(scenarios)]
        session = f"challenge-v2-{session_index:05d}"
        at = start + timedelta(days=session_index, hours=rng.choice([1, 7, 12, 19, 23]))
        count = {"APP_ALIAS_BURST": 13, "APP_SUCCESS_AFTER_DENIAL": 12}.get(scenario, 7)
        for index in range(count):
            family, event_type, malicious_at = "AUTHENTICATION", "LOGIN_FAILURE", 5
            account, source = f"user-{session_index:04d}", f"198.51.100.{2 + session_index % 240}"
            gap = rng.randint(4, 19)
            if scenario == "AUTH_ALIAS_BURST": event_type = "LOGIN_FAILED"
            elif scenario == "VPN_ALIAS_BURST": family, event_type = "VPN_SSO", "SSO_LOGIN_FAILURE"
            elif scenario == "APP_ALIAS_BURST": family, event_type, malicious_at = "APPLICATION_ACCESS", "APPLICATION_ACCESS_DENIED", 10
            elif scenario == "AUTH_SLOW_ATTEMPTS": gap, malicious_at = 95, 10_000
            elif scenario == "AUTH_INTERLEAVED_NOISE":
                account, source, malicious_at = f"noise-{index:02d}", f"10.50.{index}.5", 10_000
            elif scenario == "AUTH_SPRAY": account = f"spray-{index:02d}"
            elif scenario == "AUTH_DISTRIBUTED": source = f"203.0.113.{20 + index}"
            elif scenario == "AUTH_OFFHOURS_SUCCESS": event_type, malicious_at = "LOGIN_SUCCESS", 10_000
            elif scenario == "MISSING_CONTEXT": account, source, malicious_at = "", "", 10_000
            elif scenario == "APP_SUCCESS_AFTER_DENIAL":
                family, malicious_at = "APPLICATION_ACCESS", 10
                event_type = "APPLICATION_LOGIN" if index == count - 1 else "ACCESS_DENIED"
            elif scenario == "VPN_NORMAL": family, event_type, malicious_at = "VPN_SSO", "VPN_LOGIN_SUCCESS", 10_000
            elif scenario == "DUPLICATE_TIMESTAMP_AUTH": gap = 0 if index in {2, 3} else 8
            if index:
                at += timedelta(seconds=gap)
            label = "MALICIOUS_APT" if index + 1 >= malicious_at else "BENIGN"
            rows.append(row(session, scenario, index, at, family, event_type, label, account, source))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate locked, never-train SecuraAI Challenge V2")
    parser.add_argument("--sessions", type=int, default=600)
    parser.add_argument("--seed", type=int, default=20261103)
    parser.add_argument("--output", type=Path, default=Path("data/challenge_v2/securaai_challenge_v2.csv"))
    args = parser.parse_args()
    rows = generate(args.sessions, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader(); writer.writerows(rows)
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    manifest = {
        "status": "LOCKED_EXTERNAL_CHALLENGE_NEVER_TRAIN",
        "version": "challenge-v2", "seed": args.seed, "sessions": args.sessions,
        "events": len(rows), "sha256": digest,
        "scenarios": sorted({str(item["scenario"]) for item in rows}),
    }
    manifest_path = args.output.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
