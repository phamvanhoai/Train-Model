from scripts.generate_securaai_scenarios import generate
from datetime import datetime


def test_generated_scenarios_have_session_isolation_and_both_labels():
    rows = generate(60, 42)
    by_session: dict[str, set[str]] = {}
    for row in rows:
        by_session.setdefault(str(row["scenario_id"]), set()).add(str(row["session_split"]))
    assert all(len(splits) == 1 for splits in by_session.values())
    assert {row["reviewer_label"] for row in rows} == {"BENIGN", "MALICIOUS_APT"}
    assert {row["event_family"] for row in rows} == {
        "AUTHENTICATION", "APPLICATION_ACCESS", "VPN_SSO"
    }


def test_benign_data_contains_single_login_failure():
    rows = generate(300, 42)
    assert any(
        row["scenario"] == "AUTH_SINGLE_TYPO"
        and row["event_type"] == "LOGIN_FAILURE"
        and row["reviewer_label"] == "BENIGN"
        for row in rows
    )


def test_attack_sessions_only_turn_malicious_after_burst_threshold():
    rows = generate(300, 42)
    auth = [row for row in rows if row["scenario"] == "AUTH_BRUTE_FORCE"]
    assert auth
    assert all(row["reviewer_label"] == "BENIGN" for row in auth if int(row["event_index"]) < 4)
    assert any(row["reviewer_label"] == "MALICIOUS_APT" for row in auth if int(row["event_index"]) >= 4)


def test_subthreshold_bursts_are_benign_boundary_examples():
    rows = generate(600, 42)
    expected = {
        "AUTH_SUBTHRESHOLD_BURST", "APP_SUBTHRESHOLD_DENIAL", "VPN_SUBTHRESHOLD_BURST"
    }
    for scenario in expected:
        examples = [row for row in rows if row["scenario"] == scenario]
        assert examples, scenario
        assert all(row["reviewer_label"] == "BENIGN" for row in examples)


def test_diverse_attack_scenarios_are_generated_with_controlled_ground_truth():
    rows = generate(3000, 42)
    scenarios = {str(row["scenario"]) for row in rows}
    assert {
        "AUTH_PASSWORD_SPRAY", "AUTH_DISTRIBUTED_ATTACK", "AUTH_SUCCESS_AFTER_FAILURE",
        "AUTH_ACCOUNT_ONLY_ATTACK",
        "VPN_PASSWORD_SPRAY", "VPN_DISTRIBUTED_ATTACK",
        "APP_DISTRIBUTED_DENIAL", "APP_SUCCESS_AFTER_DENIAL",
    }.issubset(scenarios)
    assert all(row["ground_truth_source"] == "CONTROLLED_SYNTHETIC_SCENARIO" for row in rows)


def test_timestamps_are_monotonic_inside_every_session():
    rows = generate(300, 42)
    by_session: dict[str, list[datetime]] = {}
    for row in rows:
        by_session.setdefault(str(row["scenario_id"]), []).append(
            datetime.fromisoformat(str(row["occurred_at"])))
    assert all(times == sorted(times) for times in by_session.values())


def test_multi_user_background_noise_is_benign_despite_aggregate_failures():
    rows = generate(3000, 42)
    noise = [row for row in rows if row["scenario"] == "AUTH_MULTI_USER_NOISE"]
    assert noise
    assert all(row["reviewer_label"] == "BENIGN" for row in noise)


def test_account_only_attack_has_account_but_no_source_ip():
    rows = generate(3000, 42)
    attack = [row for row in rows if row["scenario"] == "AUTH_ACCOUNT_ONLY_ATTACK"]
    assert attack
    assert all(row["account_identifier"] and not row["source_ip"] for row in attack)
    assert any(row["reviewer_label"] == "MALICIOUS_APT" for row in attack)


def test_missing_context_noise_really_omits_both_identifiers():
    rows = generate(3000, 42)
    noise = [row for row in rows if row["scenario"] == "AUTH_MISSING_CONTEXT"]
    assert noise
    assert all(not row["account_identifier"] and not row["source_ip"] for row in noise)
