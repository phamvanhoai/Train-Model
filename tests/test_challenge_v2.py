from scripts.generate_challenge_v2 import generate


def test_challenge_is_diverse_and_never_marked_for_training():
    rows = generate(120, 20261103)
    assert len({row["scenario"] for row in rows}) == 12
    assert all(row["include_for_training"] == "false" for row in rows)
    assert {row["reviewer_label"] for row in rows} == {"BENIGN", "MALICIOUS_APT"}


def test_slow_attempts_and_missing_context_are_benign():
    rows = generate(120, 20261103)
    selected = [row for row in rows if row["scenario"] in {"AUTH_SLOW_ATTEMPTS", "MISSING_CONTEXT"}]
    assert selected
    assert all(row["reviewer_label"] == "BENIGN" for row in selected)
