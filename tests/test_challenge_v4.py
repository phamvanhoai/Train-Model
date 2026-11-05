from scripts.generate_challenge_v4 import generate


def test_challenge_v4_is_diverse_and_never_training_data():
    rows = generate(100, 20290317)
    assert len({row["scenario"] for row in rows}) == 10
    assert {row["reviewer_label"] for row in rows} == {"BENIGN", "MALICIOUS_APT"}
    assert all(row["include_for_training"] == "false" for row in rows)


def test_short_application_bursts_are_below_the_ten_event_policy_boundary():
    rows = generate(100, 20290317)
    short = [row for row in rows if row["scenario"] == "APP_SHORT_BENIGN"]
    assert short
    assert max(int(row["event_index"]) for row in short) == 7
    assert all(row["reviewer_label"] == "BENIGN" for row in short)
