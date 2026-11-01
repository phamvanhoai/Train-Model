import pandas as pd

from securaai_ml.features import build_features, build_training_frame


def test_builds_features_without_inventing_missing_ip():
    raw = pd.DataFrame([{
        "_source.data.win.system.systemTime": "2024-12-01T20:30:00Z",
        "_source.data.win.system.eventID": "1",
        "_source.data.win.eventdata.image": r"C:\Windows\System32\cmd.exe",
        "_source.rule.mitre.id": '["T1059.003"]',
    }])
    result = build_training_frame(raw)
    assert result.loc[0, "process_name"] == "cmd.exe"
    assert result.loc[0, "has_source_ip"] == 0
    assert result.loc[0, "source_ip_private"] == 0
    assert result.loc[0, "is_after_hours"] == 1
    assert result.loc[0, "target"] == 1


def test_mitre_content_never_appears_in_model_features():
    raw = pd.DataFrame([{
        "timestamp": "2024-12-01T10:00:00Z", "eventId": "4624",
        "_source.rule.mitre.technique": "Secret Technique",
    }])
    features = build_features(raw)
    assert not any("mitre" in column.lower() for column in features.columns)
    assert not features.astype(str).apply(
        lambda column: column.str.contains("Secret Technique").any()
    ).any()
