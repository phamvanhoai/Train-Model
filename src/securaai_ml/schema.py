from __future__ import annotations

from dataclasses import dataclass

TARGET_COLUMN = "target"
GROUP_COLUMN = "collection_date"

LABEL_COLUMNS = (
    "_source.rule.mitre.id",
    "_source.rule.mitre.technique",
    "_source.rule.mitre.tactic",
    "_source.rule.mitre_techniques",
    "_source.rule.mitre_tactics",
)

# Stable pre-decision fields only. Rule fields, payload text, identities and hashes are absent.
RAW_COLUMNS = (
    "_source.@timestamp", "_source.timestamp", "_source.data.win.system.systemTime",
    "_source.data.win.system.eventID", "_source.data.win.system.providerName",
    "_source.data.win.system.channel", "_source.data.win.system.severityValue",
    "_source.decoder.name", "_source.location", "_source.input.type",
    "_source.data.win.eventdata.logonType",
    "_source.data.win.eventdata.authenticationPackageName",
    "_source.data.win.eventdata.integrityLevel", "_source.data.win.eventdata.image",
    "_source.data.win.eventdata.parentImage", "_source.data.win.eventdata.processName",
    "_source.data.win.eventdata.parentProcessName", "_source.data.win.eventdata.commandLine",
    "_source.data.win.eventdata.parentCommandLine", "_source.data.win.eventdata.targetFilename",
    "_source.data.win.eventdata.hashes", "_source.data.win.eventdata.sourceIp",
    "_source.data.win.eventdata.destinationIp", "_source.data.win.eventdata.ipAddress",
    "_source.data.win.eventdata.sourcePort", "_source.data.win.eventdata.destinationPort",
    "_source.data.win.eventdata.protocol", "_source.data.win.eventdata.status",
    "_source.data.win.eventdata.subStatus",
)

CATEGORICAL_FEATURES = (
    "event_id", "provider", "channel", "severity_value", "decoder", "location",
    "input_type", "logon_type", "auth_package", "integrity_level", "process_name",
    "parent_process_name", "protocol", "event_status", "event_substatus",
)

NUMERIC_FEATURES = (
    "hour", "day_of_week", "is_after_hours", "is_weekend", "has_source_ip",
    "source_ip_private", "has_destination_ip", "destination_ip_private", "source_port",
    "destination_port", "has_command_line", "has_parent_command_line", "has_target_file",
    "has_hashes",
)

MODEL_FEATURES = CATEGORICAL_FEATURES + NUMERIC_FEATURES


@dataclass(frozen=True)
class DatasetAudit:
    rows: int
    malicious: int
    benign: int
    groups: int
    invalid_timestamps: int
