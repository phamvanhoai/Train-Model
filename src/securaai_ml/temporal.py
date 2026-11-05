from __future__ import annotations

import numpy as np
import pandas as pd

from .wazuh_review import review_to_model_frame


TEMPORAL_FEATURES = (
    "events_1m", "failures_1m",
    "events_5m", "failed_logins_5m", "access_denials_5m", "vpn_failures_5m",
    "distinct_accounts_5m", "distinct_source_ips_5m",
    "success_after_failure_5m", "seconds_since_previous",
    "events_15m", "failures_15m", "events_60m", "failures_60m",
)

# Retained for artifact compatibility. Decisions are no longer gated by global counts.
OPERATIONAL_GATES: dict[str, int] = {}
AUTH_FAILURE_TYPES = {"LOGIN_FAILURE", "LOGIN_FAILED"}
VPN_FAILURE_TYPES = {"VPN_LOGIN_FAILURE", "SSO_LOGIN_FAILURE"}
APP_DENIAL_TYPES = {"ACCESS_DENIED", "APPLICATION_ACCESS_DENIED"}


def operational_gate(frame: pd.DataFrame) -> np.ndarray:
    """Require a principal context without imposing a global event-count boundary."""
    family = frame["event_family_name"].astype(str).str.lower()
    accounts = frame.get("distinct_accounts_5m", pd.Series(0, index=frame.index)).astype(float)
    source_ips = frame.get("distinct_source_ips_5m", pd.Series(0, index=frame.index)).astype(float)
    supported = family.isin({"authentication", "vpn_sso", "application_access"})
    return (~supported | accounts.gt(0) | source_ips.gt(0)).to_numpy(dtype=bool)


def add_session_temporal_features(frame: pd.DataFrame) -> pd.DataFrame:
    """Build past-only multi-window features without crossing scenario boundaries."""
    required = {"scenario_id", "occurred_at", "event_type"}
    missing = required.difference(frame.columns)
    if missing:
        raise ValueError(f"Missing temporal columns: {sorted(missing)}")
    result = review_to_model_frame(frame)
    family = frame.get("event_family", pd.Series("", index=frame.index))
    result["event_family_name"] = family.fillna("").astype(str).str.lower()
    result["event_type_name"] = frame["event_type"].fillna("").astype(str).str.lower()
    temporal = pd.DataFrame(0.0, index=frame.index, columns=TEMPORAL_FEATURES)
    timestamps = pd.to_datetime(frame["occurred_at"], utc=True, errors="raise", format="mixed")
    for _, indices in frame.groupby("scenario_id", sort=False).groups.items():
        ordered = sorted(indices, key=lambda index: timestamps.loc[index])
        history: list[object] = []
        previous = None
        for index in ordered:
            now = timestamps.loc[index]
            history = [
                old for old in history
                if (now - timestamps.loc[old]).total_seconds() <= 3_600
            ]
            window = [
                old for old in history
                if (now - timestamps.loc[old]).total_seconds() <= 300
            ]
            event_types = frame.loc[window, "event_type"].astype(str).str.upper()
            current = str(frame.at[index, "event_type"]).upper()
            current_window = [*window, index]
            accounts = frame.loc[current_window].get(
                "account_identifier", pd.Series("", index=current_window)
            ).fillna("").astype(str)
            source_ips = frame.loc[current_window].get(
                "source_ip", pd.Series("", index=current_window)
            ).fillna("").astype(str)
            temporal.at[index, "events_5m"] = len(window) + 1
            temporal.at[index, "failed_logins_5m"] = int(event_types.isin(AUTH_FAILURE_TYPES).sum()) + int(current in AUTH_FAILURE_TYPES)
            temporal.at[index, "access_denials_5m"] = int(event_types.isin(APP_DENIAL_TYPES).sum()) + int(current in APP_DENIAL_TYPES)
            temporal.at[index, "vpn_failures_5m"] = int(event_types.isin(VPN_FAILURE_TYPES).sum()) + int(current in VPN_FAILURE_TYPES)
            temporal.at[index, "distinct_accounts_5m"] = accounts[accounts.ne("")].nunique()
            temporal.at[index, "distinct_source_ips_5m"] = source_ips[source_ips.ne("")].nunique()
            prior_failure = event_types.isin(AUTH_FAILURE_TYPES | VPN_FAILURE_TYPES).any()
            temporal.at[index, "success_after_failure_5m"] = int("SUCCESS" in current and prior_failure)
            temporal.at[index, "seconds_since_previous"] = (
                min((now - previous).total_seconds(), 3600) if previous is not None else 3600
            )
            all_failure_types = AUTH_FAILURE_TYPES | VPN_FAILURE_TYPES | APP_DENIAL_TYPES
            for suffix, seconds in (("1m", 60), ("15m", 900), ("60m", 3_600)):
                horizon = [
                    old for old in history
                    if (now - timestamps.loc[old]).total_seconds() <= seconds
                ]
                horizon_types = frame.loc[horizon, "event_type"].astype(str).str.upper()
                temporal.at[index, f"events_{suffix}"] = len(horizon) + 1
                temporal.at[index, f"failures_{suffix}"] = int(
                    horizon_types.isin(all_failure_types).sum()
                ) + int(current in all_failure_types)
            history.append(index)
            previous = now
    return pd.concat([result, temporal], axis=1)


def temporal_payload_defaults(frame: pd.DataFrame) -> pd.DataFrame:
    """Add safe defaults when callers have no event history."""
    output = frame.copy()
    for feature in TEMPORAL_FEATURES:
        if feature not in output:
            output[feature] = 3600.0 if feature == "seconds_since_previous" else 0.0
    return output
