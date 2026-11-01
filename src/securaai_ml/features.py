from __future__ import annotations

import ipaddress
import ntpath
from collections.abc import Mapping

import pandas as pd

from .schema import GROUP_COLUMN, LABEL_COLUMNS, MODEL_FEATURES, TARGET_COLUMN


def _clean(series: pd.Series) -> pd.Series:
    return series.fillna("").astype(str).str.strip().replace({"nan": "", " ": ""})


def _column(frame: pd.DataFrame, name: str) -> pd.Series:
    return frame[name] if name in frame.columns else pd.Series("", index=frame.index, dtype="object")


def _first(frame: pd.DataFrame, names: tuple[str, ...]) -> pd.Series:
    result = pd.Series("", index=frame.index, dtype="object")
    for name in names:
        candidate = _clean(_column(frame, name))
        result = result.mask(result.eq(""), candidate)
    return result


def _basename(series: pd.Series) -> pd.Series:
    return _clean(series).map(lambda value: ntpath.basename(value).lower() if value else "missing")


def _present(series: pd.Series) -> pd.Series:
    return _clean(series).ne("").astype("int8")


def _private_ip(value: object) -> int:
    text = str(value).strip() if value is not None else ""
    if not text or text in {"-", "nan"}:
        return 0
    try:
        return int(ipaddress.ip_address(text).is_private)
    except ValueError:
        return 0


def _parse_timestamp(series: pd.Series) -> pd.Series:
    # Kibana CSV exports use "Oct 28, 2024 @ 08:51:44.254"; ISO timestamps are
    # also accepted for live SecuraAI inference.
    normalized = _clean(series).str.replace(" @ ", " ", regex=False)
    return pd.to_datetime(normalized, errors="coerce", utc=True, format="mixed")


def derive_target(frame: pd.DataFrame) -> pd.Series:
    tagged = pd.Series(False, index=frame.index)
    for column in LABEL_COLUMNS:
        tagged |= _clean(_column(frame, column)).ne("")
    return tagged.astype("int8").rename(TARGET_COLUMN)


def build_features(frame: pd.DataFrame) -> pd.DataFrame:
    timestamp_raw = _first(frame, (
        "_source.data.win.system.systemTime", "_source.@timestamp", "timestamp",
    ))
    timestamp = _parse_timestamp(timestamp_raw)
    source_ip = _first(frame, (
        "_source.data.win.eventdata.sourceIp", "_source.data.win.eventdata.ipAddress", "sourceIp",
    ))
    destination_ip = _first(frame, ("_source.data.win.eventdata.destinationIp", "destinationIp"))
    process_path = _first(frame, (
        "_source.data.win.eventdata.image", "_source.data.win.eventdata.processName", "processPath",
    ))
    parent_path = _first(frame, (
        "_source.data.win.eventdata.parentImage", "_source.data.win.eventdata.parentProcessName",
        "parentProcessPath",
    ))
    command_line = _first(frame, ("_source.data.win.eventdata.commandLine", "commandLine"))
    parent_command_line = _first(
        frame, ("_source.data.win.eventdata.parentCommandLine", "parentCommandLine")
    )

    result = pd.DataFrame(index=frame.index)
    categorical_mapping = {
        "event_id": ("_source.data.win.system.eventID", "eventId"),
        "provider": ("_source.data.win.system.providerName", "providerName"),
        "channel": ("_source.data.win.system.channel", "channel"),
        "severity_value": ("_source.data.win.system.severityValue", "severityValue"),
        "decoder": ("_source.decoder.name", "decoder"),
        "location": ("_source.location", "location"),
        "input_type": ("_source.input.type", "inputType"),
        "logon_type": ("_source.data.win.eventdata.logonType", "logonType"),
        "auth_package": (
            "_source.data.win.eventdata.authenticationPackageName", "authenticationPackage",
        ),
        "integrity_level": ("_source.data.win.eventdata.integrityLevel", "integrityLevel"),
        "protocol": ("_source.data.win.eventdata.protocol", "protocol"),
        "event_status": ("_source.data.win.eventdata.status", "status"),
        "event_substatus": ("_source.data.win.eventdata.subStatus", "subStatus"),
    }
    for output, candidates in categorical_mapping.items():
        values = _first(frame, candidates).str.lower()
        result[output] = values.mask(values.eq(""), "missing")

    result["process_name"] = _basename(process_path)
    result["parent_process_name"] = _basename(parent_path)
    result["hour"] = timestamp.dt.hour.fillna(0).astype("int8")
    result["day_of_week"] = timestamp.dt.dayofweek.fillna(0).astype("int8")
    result["is_after_hours"] = ((result["hour"] < 8) | (result["hour"] >= 18)).astype("int8")
    result["is_weekend"] = (result["day_of_week"] >= 5).astype("int8")
    result["has_source_ip"] = _present(source_ip)
    result["source_ip_private"] = source_ip.map(_private_ip).astype("int8")
    result["has_destination_ip"] = _present(destination_ip)
    result["destination_ip_private"] = destination_ip.map(_private_ip).astype("int8")
    result["source_port"] = pd.to_numeric(
        _first(frame, ("_source.data.win.eventdata.sourcePort", "sourcePort")), errors="coerce"
    ).fillna(0).clip(0, 65535)
    result["destination_port"] = pd.to_numeric(
        _first(frame, ("_source.data.win.eventdata.destinationPort", "destinationPort")),
        errors="coerce",
    ).fillna(0).clip(0, 65535)
    result["has_command_line"] = _present(command_line)
    result["has_parent_command_line"] = _present(parent_command_line)
    result["has_target_file"] = _present(
        _first(frame, ("_source.data.win.eventdata.targetFilename", "targetFilename"))
    )
    result["has_hashes"] = _present(_first(frame, ("_source.data.win.eventdata.hashes", "hashes")))
    return result.loc[:, MODEL_FEATURES]


def build_training_frame(frame: pd.DataFrame) -> pd.DataFrame:
    features = build_features(frame)
    timestamp = _parse_timestamp(
        _first(frame, (
            "_source.data.win.system.systemTime", "_source.@timestamp",
        )),
    )
    features[TARGET_COLUMN] = derive_target(frame)
    features[GROUP_COLUMN] = timestamp.dt.strftime("%Y-%m-%d").fillna("unknown-date")
    return features


def canonical_event_frame(event: Mapping[str, object]) -> pd.DataFrame:
    return pd.DataFrame([dict(event)])
