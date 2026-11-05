import pandas as pd

from securaai_ml.temporal import add_session_temporal_features, operational_gate


def test_temporal_counts_are_past_only_and_session_scoped():
    frame = pd.DataFrame([
        {"scenario_id": "a", "occurred_at": "2026-01-01T00:00:00Z", "event_type": "LOGIN_FAILURE"},
        {"scenario_id": "a", "occurred_at": "2026-01-01T00:01:00Z", "event_type": "LOGIN_FAILURE"},
        {"scenario_id": "b", "occurred_at": "2026-01-01T00:01:30Z", "event_type": "LOGIN_FAILURE"},
        {"scenario_id": "a", "occurred_at": "2026-01-01T00:02:00Z", "event_type": "LOGIN_SUCCESS"},
    ])
    result = add_session_temporal_features(frame)
    assert result["failed_logins_5m"].tolist() == [1, 2, 1, 2]
    assert result["events_5m"].tolist() == [1, 2, 1, 3]
    assert result["success_after_failure_5m"].tolist() == [0, 0, 0, 1]


def test_old_events_leave_five_minute_window():
    frame = pd.DataFrame([
        {"scenario_id": "a", "occurred_at": "2026-01-01T00:00:00Z", "event_type": "LOGIN_FAILURE"},
        {"scenario_id": "a", "occurred_at": "2026-01-01T00:06:00Z", "event_type": "LOGIN_FAILURE"},
    ])
    result = add_session_temporal_features(frame)
    assert result["failed_logins_5m"].tolist() == [1, 1]
    assert result["failures_1m"].tolist() == [1, 1]
    assert result["failures_15m"].tolist() == [1, 2]
    assert result["failures_60m"].tolist() == [1, 2]
    assert result["seconds_since_previous"].tolist() == [3600, 360]


def test_operational_gate_does_not_impose_global_count_boundaries():
    frame = pd.DataFrame([
        {"event_family_name": "authentication", "event_type_name": "login_failure",
         "failed_logins_5m": 4, "vpn_failures_5m": 0, "access_denials_5m": 0, "distinct_accounts_5m": 1},
        {"event_family_name": "authentication", "event_type_name": "login_failure",
         "failed_logins_5m": 5, "vpn_failures_5m": 0, "access_denials_5m": 0, "distinct_accounts_5m": 1},
        {"event_family_name": "application_access", "event_type_name": "access_denied",
         "failed_logins_5m": 0, "vpn_failures_5m": 0, "access_denials_5m": 9, "distinct_accounts_5m": 1},
        {"event_family_name": "application_access", "event_type_name": "access_denied",
         "failed_logins_5m": 0, "vpn_failures_5m": 0, "access_denials_5m": 10, "distinct_accounts_5m": 1},
        {"event_family_name": "authentication", "event_type_name": "login_success",
         "failed_logins_5m": 0, "vpn_failures_5m": 0, "access_denials_5m": 0,
         "distinct_accounts_5m": 1},
    ])
    assert operational_gate(frame).tolist() == [True, True, True, True, True]


def test_temporal_features_count_distinct_accounts_and_source_ips():
    frame = pd.DataFrame([
        {"scenario_id": "a", "occurred_at": "2026-01-01T00:00:00Z", "event_type": "LOGIN_FAILURE", "account_identifier": "alice", "source_ip": "10.0.0.1"},
        {"scenario_id": "a", "occurred_at": "2026-01-01T00:00:10Z", "event_type": "LOGIN_FAILURE", "account_identifier": "bob", "source_ip": "10.0.0.1"},
        {"scenario_id": "a", "occurred_at": "2026-01-01T00:00:20Z", "event_type": "LOGIN_FAILURE", "account_identifier": "bob", "source_ip": "10.0.0.2"},
    ])
    result = add_session_temporal_features(frame)
    assert result["distinct_accounts_5m"].tolist() == [1, 2, 2]
    assert result["distinct_source_ips_5m"].tolist() == [1, 1, 2]


def test_alias_failures_share_the_canonical_temporal_counters():
    frame = pd.DataFrame([
        {"scenario_id": "auth", "occurred_at": f"2026-01-01T00:00:0{i}Z", "event_type": "LOGIN_FAILED", "account_identifier": "a", "source_ip": "10.0.0.1"}
        for i in range(5)
    ] + [
        {"scenario_id": "vpn", "occurred_at": f"2026-01-01T00:01:0{i}Z", "event_type": "SSO_LOGIN_FAILURE", "account_identifier": "a", "source_ip": "10.0.0.1"}
        for i in range(5)
    ])
    result = add_session_temporal_features(frame)
    assert result.loc[4, "failed_logins_5m"] == 5
    assert result.loc[9, "vpn_failures_5m"] == 5


def test_operational_gate_blocks_failure_decision_without_principal_context():
    frame = pd.DataFrame([{
        "event_family_name": "authentication", "event_type_name": "LOGIN_FAILURE",
        "failed_logins_5m": 8, "vpn_failures_5m": 0, "access_denials_5m": 0,
        "distinct_accounts_5m": 0, "distinct_source_ips_5m": 0,
    }])
    assert operational_gate(frame).tolist() == [False]


def test_operational_gate_blocks_success_without_principal_context():
    frame = pd.DataFrame([{
        "event_family_name": "authentication", "event_type_name": "LOGIN_SUCCESS",
        "failed_logins_5m": 5, "vpn_failures_5m": 0, "access_denials_5m": 0,
        "distinct_accounts_5m": 0, "distinct_source_ips_5m": 0,
    }])
    assert operational_gate(frame).tolist() == [False]
