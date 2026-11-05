from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from generate_securaai_scenarios import FIELDS, base_row, ip, split_for


OUTPUT = Path("data/securaai_scenarios/securaai_multiwindow_scenarios.csv")


def generate(sessions: int = 300, seed: int = 84) -> list[dict[str, object]]:
    rng = random.Random(seed)
    rows: list[dict[str, object]] = []
    base = datetime(2026, 7, 1, tzinfo=timezone.utc)
    families = [
        ("AUTHENTICATION", "LOGIN_FAILURE", "AUTH_LOW_AND_SLOW"),
        ("VPN_SSO", "VPN_LOGIN_FAILURE", "VPN_LOW_AND_SLOW"),
        ("APPLICATION_ACCESS", "ACCESS_DENIED", "APP_LOW_AND_SLOW"),
    ]
    for number in range(sessions):
        family, event_type, scenario = families[number % len(families)]
        malicious = number % 2 == 0
        scenario = scenario if malicious else scenario.replace("LOW_AND_SLOW", "LEGITIMATE_RETRY")
        session = f"securaai-multiwindow-{number:05d}"
        split = split_for(number)
        start = base + timedelta(hours=number * 2)
        count = rng.randint(8, 14) if malicious else rng.randint(2, 5)
        spacing = rng.randint(180, 270) if malicious else rng.randint(480, 900)
        source = ip(rng, private=not malicious)
        account = f"mw-user-{number:04d}"
        for index in range(count):
            timestamp = start + timedelta(seconds=index * spacing)
            # The scenario manifest supplies attack intent. Early isolated events remain
            # benign until sustained activity is observable in a longer rolling window.
            label = "MALICIOUS_APT" if malicious and index >= 5 else "BENIGN"
            row = base_row(
                session, scenario, split, index, timestamp,
                family, event_type, label, source, account,
            )
            row.update(
                event_id="4625" if family == "AUTHENTICATION" else "VPN-AUTH" if family == "VPN_SSO" else "APP-403",
                status="failure" if family != "APPLICATION_ACCESS" else "denied",
                destination_port="443" if family != "AUTHENTICATION" else "",
                review_notes=f"Controlled multi-window ground truth; scenario={scenario}; session={session}",
            )
            rows.append(row)
    return rows


def main() -> None:
    rows = generate()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} events to {OUTPUT}")


if __name__ == "__main__":
    main()
