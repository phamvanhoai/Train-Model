from __future__ import annotations

import zipfile
from pathlib import Path

import pandas as pd

from .features import build_features


RADAR_COLUMNS = (
    "@timestamp", "event.code", "event.type", "log.level", "event.category",
    "process.executable", "process.parent.executable", "file.path", "process.hash.md5",
    "winlog.event_data.IntegrityLevel", "source.port", "source.ip", "destination.port",
    "destination.ip", "network.transport", "target-class-name", "target-class",
)


def radar_to_model_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """Map raw RADAR ECS/Sysmon rows to the deployed canonical feature contract."""
    def column(name: str, default: object = "") -> pd.Series:
        if name in frame:
            return frame[name].replace("-", "")
        return pd.Series(default, index=frame.index)

    canonical = pd.DataFrame(index=frame.index)
    canonical["timestamp"] = column("@timestamp")
    canonical["eventId"] = column("event.code")
    canonical["providerName"] = "Microsoft-Windows-Sysmon"
    canonical["channel"] = "Microsoft-Windows-Sysmon/Operational"
    canonical["severityValue"] = column("log.level")
    canonical["decoder"] = "windows_eventchannel"
    canonical["location"] = "EventChannel"
    canonical["inputType"] = column("event.category")
    canonical["integrityLevel"] = column("winlog.event_data.IntegrityLevel")
    canonical["processPath"] = column("process.executable")
    canonical["parentProcessPath"] = column("process.parent.executable")
    canonical["targetFilename"] = column("file.path")
    canonical["hashes"] = column("process.hash.md5")
    canonical["sourceIp"] = column("source.ip")
    canonical["destinationIp"] = column("destination.ip")
    canonical["sourcePort"] = column("source.port")
    canonical["destinationPort"] = column("destination.port")
    canonical["protocol"] = column("network.transport")
    canonical["status"] = column("event.type")
    return build_features(canonical)


def read_radar_csv(zip_path: Path, member: str, chunksize: int = 50_000):
    with zipfile.ZipFile(zip_path) as archive:
        with archive.open(member) as handle:
            yield from pd.read_csv(handle, usecols=lambda name: name in RADAR_COLUMNS,
                                   chunksize=chunksize, low_memory=False)


def read_radar_member(zip_path: Path, member: str) -> pd.DataFrame:
    with zipfile.ZipFile(zip_path) as archive:
        with archive.open(member) as handle:
            return pd.read_csv(handle, usecols=lambda name: name in RADAR_COLUMNS,
                               low_memory=False)


def radar_members(zip_path: Path) -> list[str]:
    with zipfile.ZipFile(zip_path) as archive:
        return sorted(item.filename for item in archive.infolist() if not item.is_dir())
