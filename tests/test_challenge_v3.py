from scripts.generate_challenge_v3 import generate


def test_challenge_v3_is_locked_out_of_training_and_diverse():
    rows = generate(100, 20270119)
    assert len({row["scenario"] for row in rows}) == 10
    assert all(row["include_for_training"] == "false" for row in rows)
    assert {row["reviewer_label"] for row in rows} == {"BENIGN", "MALICIOUS_APT"}
