from __future__ import annotations

import argparse
import csv
import ipaddress
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from securaai_ml.wazuh_review import REVIEW_FIELDS


EXTRA_FIELDS = ("scenario_id", "scenario", "session_split", "event_index", "ground_truth_source")
FIELDS = EXTRA_FIELDS + REVIEW_FIELDS


def ip(rng: random.Random, private: bool) -> str:
    if private:
        return f"10.{rng.randint(1, 240)}.{rng.randint(0, 255)}.{rng.randint(2, 250)}"
    networks = [ipaddress.ip_network("198.51.100.0/24"), ipaddress.ip_network("203.0.113.0/24")]
    network = rng.choice(networks)
    return str(network.network_address + rng.randint(2, 250))


def split_for(index: int) -> str:
    bucket = index % 10
    return "TRAIN" if bucket < 6 else "VALIDATION" if bucket < 8 else "TEST"


def base_row(session: str, scenario: str, split: str, index: int, timestamp: datetime,
             family: str, event_type: str, label: str, source_ip: str,
             account: str | None = None) -> dict[str, object]:
    return {
        "scenario_id": session, "scenario": scenario, "session_split": split,
        "event_index": index, "ground_truth_source": "CONTROLLED_SYNTHETIC_SCENARIO",
        "external_event_id": f"{session}-{index:03d}", "occurred_at": timestamp.isoformat(),
        "source_name": "SecuraAI controlled scenario generator", "agent_name": f"SECURAAI-LAB-{int(session[-5:]) % 24:02d}",
        "account_identifier": account if account is not None else f"user-{int(session[-5:]) % 180:03d}",
        "event_family": family, "event_type": event_type, "wazuh_rule_id": "",
        "wazuh_rule_level": "", "wazuh_rule_description": "", "event_id": "",
        "provider_name": "Microsoft-Windows-Security-Auditing", "channel": "Security",
        "severity_value": "", "decoder": "windows_eventchannel", "location": "SECURAAI-LAB-WIN",
        "input_type": family, "logon_type": "3", "authentication_package": "Negotiate",
        "integrity_level": "", "process_path": "", "parent_process_path": "",
        "command_line_present": "false", "parent_command_line_present": "false",
        "target_file_present": "false", "hashes_present": "false", "source_ip": source_ip,
        "destination_ip": "10.0.0.10", "source_port": "", "destination_port": "",
        "protocol": "tcp", "status": "", "sub_status": "", "review_suggestion": "",
        "reviewer_label": label, "include_for_training": "true",
        "review_notes": f"Ground truth from controlled scenario {scenario}; session={session}",
    }


def authentication_session(rng: random.Random, session: str, split: str, start: datetime,
                           malicious: bool) -> list[dict[str, object]]:
    scenario = rng.choice([
        "AUTH_BRUTE_FORCE", "AUTH_PASSWORD_SPRAY", "AUTH_DISTRIBUTED_ATTACK",
        "AUTH_SUCCESS_AFTER_FAILURE", "AUTH_ALIAS_BURST", "AUTH_ACCOUNT_ONLY_ATTACK",
    ]) if malicious else rng.choice(
        ["AUTH_NORMAL", "AUTH_SINGLE_TYPO", "AUTH_SUBTHRESHOLD_BURST",
         "AUTH_MULTI_USER_NOISE", "AUTH_MISSING_CONTEXT"]
    )
    failures = (rng.randint(5, 18) if malicious else
                1 if scenario == "AUTH_SINGLE_TYPO" else
                rng.randint(2, 4) if scenario == "AUTH_SUBTHRESHOLD_BURST" else
                rng.randint(5, 12) if scenario in {"AUTH_MULTI_USER_NOISE", "AUTH_MISSING_CONTEXT"} else 0)
    rows = []
    src = ip(rng, private=not malicious)
    base_account = f"user-{int(session[-5:]) % 180:03d}"
    event_time = start
    for index in range(failures):
        # A single failure is not an attack decision. Label the event that
        # reaches the five-failure burst threshold and subsequent evidence.
        event_label = "MALICIOUS_APT" if malicious and index >= 4 else "BENIGN"
        event_src = ip(rng, private=False) if scenario in {"AUTH_DISTRIBUTED_ATTACK", "AUTH_MULTI_USER_NOISE"} else src
        account = (f"noise-user-{index:02d}" if scenario == "AUTH_MULTI_USER_NOISE" else
                   f"spray-user-{index % 8:02d}" if scenario == "AUTH_PASSWORD_SPRAY" else base_account)
        if scenario == "AUTH_ACCOUNT_ONLY_ATTACK":
            event_src = ""
        if scenario == "AUTH_MISSING_CONTEXT":
            event_src, account = "", ""
        if index:
            event_time += timedelta(seconds=rng.randint(2, 12))
        event_type = "LOGIN_FAILED" if scenario == "AUTH_ALIAS_BURST" else "LOGIN_FAILURE"
        row = base_row(session, scenario, split, index, event_time,
                       "AUTHENTICATION", event_type, event_label, event_src, account)
        row.update(event_id="4625", wazuh_rule_id="60122", wazuh_rule_level="5",
                   wazuh_rule_description="Windows logon failure", status="0xc000006d", sub_status="0xc000006a")
        rows.append(row)
    success_count = (1 if scenario == "AUTH_SUCCESS_AFTER_FAILURE" or rng.random() < .35 else 0) if malicious else rng.randint(4, 10)
    for _ in range(success_count):
        index = len(rows)
        event_time += timedelta(seconds=rng.randint(20, 45))
        success_src = "" if scenario in {"AUTH_MISSING_CONTEXT", "AUTH_ACCOUNT_ONLY_ATTACK"} else src
        success_account = "" if scenario == "AUTH_MISSING_CONTEXT" else base_account
        row = base_row(session, scenario, split, index, event_time,
                       "AUTHENTICATION", "LOGIN_SUCCESS", "MALICIOUS_APT" if malicious and failures >= 5 else "BENIGN",
                       success_src, success_account)
        row.update(event_id="4624", wazuh_rule_id="60106", wazuh_rule_level="3",
                   wazuh_rule_description="Windows logon success", status="success")
        rows.append(row)
    return rows


def application_session(rng: random.Random, session: str, split: str, start: datetime,
                        malicious: bool) -> list[dict[str, object]]:
    scenario = rng.choice(["APP_DENIAL_BURST", "APP_DISTRIBUTED_DENIAL", "APP_SUCCESS_AFTER_DENIAL"]) if malicious else rng.choice(
        ["APP_NORMAL_ACCESS", "APP_SUBTHRESHOLD_DENIAL"]
    )
    count = rng.randint(10, 16) if malicious else (
        rng.randint(2, 9) if scenario == "APP_SUBTHRESHOLD_DENIAL" else rng.randint(4, 10)
    )
    rows = []
    src = ip(rng, private=not malicious)
    event_time = start
    for index in range(count):
        denied = malicious or scenario == "APP_SUBTHRESHOLD_DENIAL" or (
            not malicious and index == 0 and rng.random() < .15
        )
        event_type = "ACCESS_DENIED" if denied else "APPLICATION_LOGIN"
        event_label = "MALICIOUS_APT" if malicious and index >= 9 else "BENIGN"
        event_src = ip(rng, private=False) if scenario == "APP_DISTRIBUTED_DENIAL" else src
        if index:
            event_time += timedelta(seconds=rng.randint(3, 20))
        row = base_row(session, scenario, split, index, event_time,
                       "APPLICATION_ACCESS", event_type, event_label, event_src)
        row.update(event_id="APP-403" if denied else "APP-200", provider_name="SecuraAI-WebApp",
                   channel="Application", decoder="json", location="securaai-web",
                   destination_port="443", status="denied" if denied else "success",
                   wazuh_rule_id="100201" if denied else "100200",
                   wazuh_rule_level="7" if denied else "3",
                   wazuh_rule_description="Application access denied" if denied else "Application login success")
        rows.append(row)
    if scenario == "APP_SUCCESS_AFTER_DENIAL":
        index = len(rows)
        event_time += timedelta(seconds=rng.randint(5, 20))
        row = base_row(session, scenario, split, index, event_time,
                       "APPLICATION_ACCESS", "APPLICATION_LOGIN", "MALICIOUS_APT", src)
        row.update(event_id="APP-200", provider_name="SecuraAI-WebApp", channel="Application",
                   decoder="json", location="securaai-web", destination_port="443",
                   status="success", wazuh_rule_id="100200", wazuh_rule_level="8",
                   wazuh_rule_description="Application success after denial burst")
        rows.append(row)
    return rows


def vpn_session(rng: random.Random, session: str, split: str, start: datetime,
                malicious: bool) -> list[dict[str, object]]:
    scenario = rng.choice(["VPN_FAILURE_BURST", "VPN_PASSWORD_SPRAY", "VPN_DISTRIBUTED_ATTACK", "VPN_ALIAS_BURST"]) if malicious else rng.choice(
        ["VPN_NORMAL", "VPN_SUBTHRESHOLD_BURST"]
    )
    count = rng.randint(5, 14) if malicious else (
        rng.randint(2, 4) if scenario == "VPN_SUBTHRESHOLD_BURST" else rng.randint(4, 9)
    )
    rows = []
    src = ip(rng, private=not malicious)
    event_time = start
    for index in range(count):
        failure = malicious or scenario == "VPN_SUBTHRESHOLD_BURST"
        event_label = "MALICIOUS_APT" if malicious and index >= 4 else "BENIGN"
        event_src = ip(rng, private=False) if scenario == "VPN_DISTRIBUTED_ATTACK" else src
        account = f"vpn-spray-{index % 6:02d}" if scenario == "VPN_PASSWORD_SPRAY" else None
        if index:
            event_time += timedelta(seconds=rng.randint(4, 18))
        failure_type = "SSO_LOGIN_FAILURE" if scenario == "VPN_ALIAS_BURST" else "VPN_LOGIN_FAILURE"
        row = base_row(session, scenario, split, index, event_time,
                       "VPN_SSO", failure_type if failure else "VPN_LOGIN_SUCCESS",
                       event_label, event_src, account)
        row.update(event_id="VPN-AUTH", provider_name="SecuraAI-VPN", channel="VPN",
                   decoder="json", location="vpn-gateway", destination_port="443",
                   status="failure" if failure else "success", wazuh_rule_id="110002" if failure else "110001",
                   wazuh_rule_level="6" if failure else "3",
                   wazuh_rule_description="VPN authentication failure" if failure else "VPN login success")
        rows.append(row)
    return rows


def generate(sessions: int, seed: int) -> list[dict[str, object]]:
    rng = random.Random(seed)
    start = datetime(2026, 1, 1, 8, tzinfo=timezone.utc)
    builders = [authentication_session, application_session, vpn_session]
    rows = []
    for index in range(sessions):
        # Production traffic is mostly benign. A 3:1 benign/malicious session
        # ratio also compensates for malicious burst sessions having more rows.
        malicious = index % 4 == 3
        session = f"securaai-scenario-{index:05d}"
        hour = rng.choice([1, 6, 9, 13, 17, 20, 23])
        rows.extend(rng.choice(builders)(rng, session, split_for(index),
                                         start + timedelta(days=index, hours=hour - 8,
                                                           minutes=rng.randint(0, 59)), malicious))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate session-labelled SecuraAI lab scenarios")
    parser.add_argument("--sessions", type=int, default=3000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path,
                        default=Path("data/securaai_scenarios/securaai_scenarios.csv"))
    args = parser.parse_args()
    if args.sessions < 30:
        parser.error("Use at least 30 sessions so every split contains diverse scenarios")
    rows = generate(args.sessions, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader(); writer.writerows(rows)
    manifest_path = args.output.with_name(args.output.stem + "_manifest.csv")
    frame_by_session: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        frame_by_session.setdefault(str(row["scenario_id"]), []).append(row)
    with manifest_path.open("w", newline="", encoding="utf-8-sig") as handle:
        manifest_fields = ("scenario_id", "scenario", "session_split", "events", "benign_events",
                           "malicious_events", "started_at", "ended_at", "ground_truth_source")
        writer = csv.DictWriter(handle, fieldnames=manifest_fields)
        writer.writeheader()
        for session_rows in frame_by_session.values():
            writer.writerow({
                "scenario_id": session_rows[0]["scenario_id"], "scenario": session_rows[0]["scenario"],
                "session_split": session_rows[0]["session_split"], "events": len(session_rows),
                "benign_events": sum(row["reviewer_label"] == "BENIGN" for row in session_rows),
                "malicious_events": sum(row["reviewer_label"] == "MALICIOUS_APT" for row in session_rows),
                "started_at": session_rows[0]["occurred_at"], "ended_at": session_rows[-1]["occurred_at"],
                "ground_truth_source": "CONTROLLED_SYNTHETIC_SCENARIO",
            })
    labels = {label: sum(row["reviewer_label"] == label for row in rows)
              for label in ("BENIGN", "MALICIOUS_APT")}
    splits = {split: sum(row["session_split"] == split for row in rows)
              for split in ("TRAIN", "VALIDATION", "TEST")}
    print({"sessions": args.sessions, "events": len(rows), "labels": labels, "splits": splits,
           "output": str(args.output), "manifest": str(manifest_path)})


if __name__ == "__main__":
    main()
