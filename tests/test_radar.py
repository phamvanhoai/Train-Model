import pandas as pd

from securaai_ml.radar import radar_to_model_frame
from securaai_ml.schema import MODEL_FEATURES


def test_radar_raw_mapping_uses_sysmon_contract():
    raw = pd.DataFrame([{
        "@timestamp": "Oct 11, 2024 @ 14:23:25.114", "event.code": 1,
        "event.type": "start", "log.level": "information", "event.category": "process",
        "process.executable": r"C:\Windows\cmd.exe",
        "process.parent.executable": r"C:\Windows\explorer.exe",
        "file.path": "-", "process.hash.md5": "abc", "source.port": "-",
        "source.ip": "-", "destination.port": "-", "destination.ip": "-",
        "network.transport": "-", "target-class": 1,
    }])
    mapped = radar_to_model_frame(raw)
    assert list(mapped.columns) == list(MODEL_FEATURES)
    assert mapped.loc[0, "event_id"] == "1"
    assert mapped.loc[0, "provider"] == "microsoft-windows-sysmon"
    assert mapped.loc[0, "process_name"] == "cmd.exe"
    assert mapped.loc[0, "has_hashes"] == 1
