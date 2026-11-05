import pandas as pd

from scripts.score_wazuh_review_queue import assign_review_sessions


def test_review_sessions_split_by_principal_family_and_idle_gap():
    frame = pd.DataFrame([
        {"occurred_at": "2026-01-01T00:00:00Z", "agent_name": "host", "account_identifier": "alice", "source_ip": "", "event_family": "AUTHENTICATION"},
        {"occurred_at": "2026-01-01T00:01:00Z", "agent_name": "host", "account_identifier": "alice", "source_ip": "", "event_family": "AUTHENTICATION"},
        {"occurred_at": "2026-01-01T00:02:00Z", "agent_name": "host", "account_identifier": "bob", "source_ip": "", "event_family": "AUTHENTICATION"},
        {"occurred_at": "2026-01-01T00:07:00Z", "agent_name": "host", "account_identifier": "alice", "source_ip": "", "event_family": "AUTHENTICATION"},
    ])
    sessions = assign_review_sessions(frame)
    assert sessions.iloc[0] == sessions.iloc[1]
    assert sessions.iloc[0] != sessions.iloc[2]
    assert sessions.iloc[0] != sessions.iloc[3]
