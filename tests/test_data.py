from pathlib import Path

import pandas as pd

from securaai_ml.data import load_training_data


def test_loads_multiple_period_files(tmp_path: Path):
    for index in range(2):
        pd.DataFrame([{
            "_source.@timestamp": f"Oct {28 + index}, 2024 @ 08:51:44.254",
            "_source.data.win.system.eventID": "1",
            "_source.rule.mitre.id": "T1059" if index else "",
        }]).to_csv(tmp_path / f"period-{index}.csv", index=False)
    data, audit = load_training_data(tmp_path)
    assert len(data) == 2
    assert audit.benign == 1
    assert audit.malicious == 1
    assert audit.invalid_timestamps == 0


def test_prefers_combined_export_without_duplicate_rows(tmp_path: Path):
    row = {
        "_source.@timestamp": "Oct 28, 2024 @ 08:51:44.254",
        "_source.data.win.system.eventID": "1",
        "_source.rule.mitre.id": "T1059",
    }
    pd.DataFrame([row]).to_csv(tmp_path / "period.csv", index=False)
    combined = dict(row)
    combined["_source.data.win.system.eventID"] = "combined-only"
    pd.DataFrame([combined]).to_csv(tmp_path / "combined.csv", index=False)

    data, audit = load_training_data(tmp_path)

    assert len(data) == 1
    assert audit.rows == 1
    assert data.iloc[0]["event_id"] == "combined-only"
