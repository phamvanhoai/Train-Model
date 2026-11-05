from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from securaai_ml.wazuh_review import REVIEW_FIELDS


FIELDS = ("scenario_id", "scenario", "event_index", "ground_truth_source") + REVIEW_FIELDS


def generate(sessions: int, seed: int) -> list[dict[str, object]]:
    rng = random.Random(seed)
    scenarios = (
        "AUTH_ACCOUNT_ONLY_ATTACK", "AUTH_ACCOUNT_ONLY_SLOW", "AUTH_IP_ONLY_ATTACK",
        "AUTH_MISSING_CONTEXT_NORMAL", "AUTH_MIXED_BACKGROUND", "VPN_ALIAS_SPRAY",
        "VPN_NORMAL_MIXED_TIME", "APP_DENIAL_ATTACK", "APP_SHORT_BENIGN",
        "APP_STAGGERED_BENIGN",
    )
    rows: list[dict[str, object]] = []
    origin = datetime(2029, 3, 1, tzinfo=timezone.utc)
    for number in range(sessions):
        scenario = scenarios[number % len(scenarios)]
        session = f"challenge-v4-{number:05d}"
        current = origin + timedelta(days=number, hours=rng.choice([1, 7, 12, 19, 23]))
        family, count, threshold, gap = "AUTHENTICATION", 9, 5, rng.randint(5, 19)
        account, source = f"v4-user-{number}", f"203.0.113.{2 + number % 240}"
        if scenario == "AUTH_ACCOUNT_ONLY_ATTACK": source = ""
        elif scenario == "AUTH_ACCOUNT_ONLY_SLOW": source, threshold, gap = "", 10_000, 80
        elif scenario == "AUTH_IP_ONLY_ATTACK": account = ""
        elif scenario == "AUTH_MISSING_CONTEXT_NORMAL":
            account, source, threshold, count = "", "", 10_000, 7
        elif scenario == "AUTH_MIXED_BACKGROUND": threshold, count = 10_000, 11
        elif scenario == "VPN_ALIAS_SPRAY": family, count = "VPN_SSO", 10
        elif scenario == "VPN_NORMAL_MIXED_TIME": family, count, threshold = "VPN_SSO", 7, 10_000
        elif scenario == "APP_DENIAL_ATTACK": family, count, threshold = "APPLICATION_ACCESS", 14, 10
        elif scenario == "APP_SHORT_BENIGN": family, count, threshold = "APPLICATION_ACCESS", 8, 10_000
        elif scenario == "APP_STAGGERED_BENIGN":
            family, count, threshold, gap = "APPLICATION_ACCESS", 12, 10_000, 46

        for index in range(count):
            if index:
                current += timedelta(seconds=gap)
            event_type = "LOGIN_FAILED" if index % 2 else "LOGIN_FAILURE"
            row_account, row_source = account, source
            if scenario == "AUTH_MIXED_BACKGROUND":
                row_account, row_source = f"background-{index}", f"10.77.{index}.4"
            if scenario == "VPN_ALIAS_SPRAY":
                event_type = "SSO_LOGIN_FAILURE" if index % 2 else "VPN_LOGIN_FAILURE"
                row_account = f"vpn-target-{index % 5}"
            elif scenario == "VPN_NORMAL_MIXED_TIME":
                event_type = "VPN_LOGIN_SUCCESS"
                row_source = f"10.66.0.{index + 2}"
            elif family == "APPLICATION_ACCESS":
                event_type = "APPLICATION_ACCESS_DENIED" if index % 2 else "ACCESS_DENIED"
            label = "MALICIOUS_APT" if index + 1 >= threshold else "BENIGN"
            rows.append({
                "scenario_id": session, "scenario": scenario, "event_index": index,
                "ground_truth_source": "LOCKED_CHALLENGE_V4_MANIFEST",
                "external_event_id": f"{session}-{index:03d}", "occurred_at": current.isoformat(),
                "source_name": "SecuraAI Challenge V4", "agent_name": f"V4-{number % 23:02d}",
                "account_identifier": row_account, "event_family": family, "event_type": event_type,
                "provider_name": "SecuraAI-V4", "channel": "Security", "decoder": "json",
                "location": "challenge-v4", "input_type": family, "source_ip": row_source,
                "destination_ip": "10.252.0.10", "destination_port": "443", "protocol": "tcp",
                "status": "success" if "SUCCESS" in event_type else "failure",
                "reviewer_label": label, "include_for_training": "false",
                "review_notes": f"Locked Challenge V4 ground truth: {scenario}",
            })
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the never-train locked Challenge V4")
    parser.add_argument("--sessions", type=int, default=500)
    parser.add_argument("--seed", type=int, default=20290317)
    parser.add_argument("--output", type=Path,
                        default=Path("data/challenge_v4/securaai_challenge_v4.csv"))
    args = parser.parse_args()
    rows = generate(args.sessions, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    manifest = {
        "status": "LOCKED_EXTERNAL_CHALLENGE_NEVER_TRAIN", "version": "challenge-v4",
        "seed": args.seed, "sessions": args.sessions, "events": len(rows), "sha256": digest,
        "scenarios": sorted({str(row["scenario"]) for row in rows}),
    }
    args.output.with_suffix(".manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
