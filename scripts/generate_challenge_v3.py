from __future__ import annotations

import argparse, csv, hashlib, json, random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from securaai_ml.wazuh_review import REVIEW_FIELDS

FIELDS = ("scenario_id", "scenario", "event_index", "ground_truth_source") + REVIEW_FIELDS


def generate(sessions: int, seed: int) -> list[dict[str, object]]:
    rng = random.Random(seed)
    names = ("AUTH_MIXED_ALIAS", "VPN_MIXED_ALIAS", "APP_MIXED_ALIAS", "AUTH_ACCOUNT_ONLY",
             "AUTH_IP_ONLY", "AUTH_WINDOW_EDGE", "AUTH_HIGH_VOLUME_NOISE",
             "APP_SHORT_BURST", "VPN_OFFHOURS_NORMAL", "AUTH_SUCCESS_AFTER_MIXED")
    output = []
    origin = datetime(2028, 2, 1, tzinfo=timezone.utc)
    for number in range(sessions):
        name = names[number % len(names)]; session = f"challenge-v3-{number:05d}"
        current = origin + timedelta(days=number, hours=rng.choice([0, 5, 11, 18, 22]))
        count = 12 if name.startswith("APP_") else 8
        for index in range(count):
            family, event_type, threshold = "AUTHENTICATION", "LOGIN_FAILURE", 5
            account, source = f"v3-user-{number}", f"198.51.100.{2 + number % 240}"
            gap = rng.randint(3, 24)
            if name == "AUTH_MIXED_ALIAS": event_type = "LOGIN_FAILED" if index % 2 else "LOGIN_FAILURE"
            elif name == "VPN_MIXED_ALIAS":
                family = "VPN_SSO"; event_type = "SSO_LOGIN_FAILURE" if index % 2 else "VPN_LOGIN_FAILURE"
            elif name == "APP_MIXED_ALIAS":
                family, threshold = "APPLICATION_ACCESS", 10
                event_type = "APPLICATION_ACCESS_DENIED" if index % 2 else "ACCESS_DENIED"
            elif name == "AUTH_ACCOUNT_ONLY": source = ""
            elif name == "AUTH_IP_ONLY": account = ""
            elif name == "AUTH_WINDOW_EDGE": gap, threshold = 76, 10_000
            elif name == "AUTH_HIGH_VOLUME_NOISE":
                account, source, threshold = f"independent-{index}", f"10.88.{index}.2", 10_000
            elif name == "APP_SHORT_BURST": family, event_type, threshold = "APPLICATION_ACCESS", "ACCESS_DENIED", 10_000
            elif name == "VPN_OFFHOURS_NORMAL": family, event_type, threshold = "VPN_SSO", "VPN_LOGIN_SUCCESS", 10_000
            elif name == "AUTH_SUCCESS_AFTER_MIXED":
                event_type = "LOGIN_SUCCESS" if index == count - 1 else ("LOGIN_FAILED" if index % 2 else "LOGIN_FAILURE")
            if index: current += timedelta(seconds=gap)
            label = "MALICIOUS_APT" if index + 1 >= threshold else "BENIGN"
            output.append({
                "scenario_id": session, "scenario": name, "event_index": index,
                "ground_truth_source": "LOCKED_CHALLENGE_V3_MANIFEST",
                "external_event_id": f"{session}-{index:03d}", "occurred_at": current.isoformat(),
                "source_name": "SecuraAI Challenge V3", "agent_name": f"V3-{number % 19:02d}",
                "account_identifier": account, "event_family": family, "event_type": event_type,
                "provider_name": "SecuraAI-V3", "channel": "Security", "decoder": "json",
                "location": "challenge-v3", "input_type": family, "source_ip": source,
                "destination_ip": "10.251.0.10", "destination_port": "443", "protocol": "tcp",
                "status": "success" if "SUCCESS" in event_type else "failure",
                "reviewer_label": label, "include_for_training": "false",
                "review_notes": f"Locked Challenge V3 ground truth: {name}",
            })
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sessions", type=int, default=500)
    parser.add_argument("--seed", type=int, default=20270119)
    parser.add_argument("--output", type=Path, default=Path("data/challenge_v3/securaai_challenge_v3.csv"))
    args = parser.parse_args(); rows = generate(args.sessions, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, extrasaction="ignore"); writer.writeheader(); writer.writerows(rows)
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    manifest = {"status":"LOCKED_EXTERNAL_CHALLENGE_NEVER_TRAIN", "version":"challenge-v3",
                "seed":args.seed, "sessions":args.sessions, "events":len(rows), "sha256":digest,
                "scenarios":sorted({str(item['scenario']) for item in rows})}
    args.output.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__": main()
