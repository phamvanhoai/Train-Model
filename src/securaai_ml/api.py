from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

import joblib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .features import build_features, canonical_event_frame
from .modeling import decision_scores
from .temporal import TEMPORAL_FEATURES

ARTIFACT_DIR = Path(os.getenv("SECURAAI_MODEL_ARTIFACT_DIR", "artifacts"))


class PredictionRequest(BaseModel):
    """A normalized security event and its rolling-window context from SecuraAI."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "timestamp": "2026-11-10T09:15:00Z",
                    "eventFamily": "authentication",
                    "eventType": "LOGIN_FAILURE",
                    "eventId": "4625",
                    "providerName": "Microsoft-Windows-Security-Auditing",
                    "channel": "Security",
                    "severityValue": "AUDIT_FAILURE",
                    "sourceIp": "203.0.113.25",
                    "status": "FAILURE",
                    "events5m": 8,
                    "failedLogins5m": 7,
                    "distinctAccounts5m": 1,
                    "distinctSourceIps5m": 1,
                    "events1m": 3,
                    "failures1m": 3,
                    "events15m": 12,
                    "failures15m": 9,
                    "events60m": 20,
                    "failures60m": 12,
                }
            ]
        },
    )
    timestamp: str = Field(
        description="Event occurrence time in ISO 8601 format, normally UTC.",
        examples=["2026-11-10T09:15:00Z"],
    )
    eventFamily: str | None = Field(
        default=None,
        description="Normalized SecuraAI family, such as authentication, app_access, or vpn_sso.",
        examples=["authentication"],
    )
    eventType: str | None = Field(
        default=None,
        description="Normalized event type, for example LOGIN_FAILURE or ACCESS_DENIED.",
        examples=["LOGIN_FAILURE"],
    )
    eventId: str | int | None = Field(
        default=None,
        description="Source event identifier, such as Windows Event ID 4625.",
        examples=["4625"],
    )
    providerName: str | None = None
    channel: str | None = None
    severityValue: str | None = None
    decoder: str | None = None
    location: str | None = None
    inputType: str | None = None
    logonType: str | int | None = None
    authenticationPackage: str | None = None
    integrityLevel: str | None = None
    processPath: str | None = None
    parentProcessPath: str | None = None
    commandLinePresent: bool = False
    parentCommandLinePresent: bool = False
    targetFilePresent: bool = False
    hashesPresent: bool = False
    sourceIp: str | None = Field(default=None, description="Observed source IP address.")
    destinationIp: str | None = Field(default=None, description="Observed destination IP address.")
    sourcePort: int | None = Field(default=None, ge=0, le=65535)
    destinationPort: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    status: str | None = None
    subStatus: str | None = None
    events5m: int = Field(default=1, ge=0, description="All related events in the current 5-minute window.")
    failedLogins5m: int = Field(default=0, ge=0, description="Failed authentication events in the current 5-minute window.")
    accessDenials5m: int = Field(default=0, ge=0, description="Denied application-access events in the current 5-minute window.")
    vpnFailures5m: int = Field(default=0, ge=0, description="Failed VPN or SSO events in the current 5-minute window.")
    distinctAccounts5m: int = Field(default=0, ge=0, description="Distinct accounts observed in the 5-minute window.")
    distinctSourceIps5m: int = Field(default=0, ge=0, description="Distinct source IP addresses observed in the 5-minute window.")
    successAfterFailure5m: bool = Field(default=False, description="Whether a successful sign-in followed failures in the same window.")
    secondsSincePrevious: float = Field(default=3600, ge=0, description="Seconds since the previous related event.")
    events1m: int = Field(default=1, ge=0, description="All related events in the current 1-minute window.")
    failures1m: int = Field(default=0, ge=0, description="Failure events in the current 1-minute window.")
    events15m: int = Field(default=1, ge=0, description="All related events in the current 15-minute window.")
    failures15m: int = Field(default=0, ge=0, description="Failure events in the current 15-minute window.")
    events60m: int = Field(default=1, ge=0, description="All related events in the current 60-minute window.")
    failures60m: int = Field(default=0, ge=0, description="Failure events in the current 60-minute window.")


class PredictionResponse(BaseModel):
    """Decision returned by the trained model for one event context."""

    label: str = Field(description="Model label, normally BENIGN or MALICIOUS_APT.")
    malicious: bool = Field(description="True when score is greater than or equal to threshold.")
    score: float = Field(description="Raw model score. Interpret it using scoreSemantics; it is not automatically attack probability.")
    threshold: float = Field(description="Locked decision threshold used to derive malicious and label.")
    escalationThreshold: float = Field(description="Score at which SecuraAI may prioritize second-stage security-model review.")
    scoreSemantics: str = Field(description="Human-readable definition of what score represents for this model artifact.")
    modelVersion: str = Field(description="Version of the loaded trained-model artifact.")


class HealthResponse(BaseModel):
    status: str = Field(description="Service readiness state.", examples=["ready"])
    modelVersion: str = Field(description="Version of the model currently loaded.")


@lru_cache(maxsize=1)
def load_artifacts():
    model_path = ARTIFACT_DIR / "model.joblib"
    metadata_path = ARTIFACT_DIR / "model_metadata.json"
    if not model_path.exists() or not metadata_path.exists():
        raise FileNotFoundError("Train the model before starting inference")
    return joblib.load(model_path), json.loads(metadata_path.read_text(encoding="utf-8"))


app = FastAPI(
    title="SecuraAI Trained Detection Model API",
    version="0.1.0",
    summary="Inference API for SecuraAI's independently trained Windows security model.",
    description=(
        "This service is called by the SecuraAI backend after Wazuh events are normalized "
        "and rolling 1/5/15/60-minute context is calculated. It returns the trained model's "
        "score and threshold decision. It does not ingest Wazuh directly, create alerts, or "
        "generate the stored natural-language explanation."
    ),
    contact={"name": "SecuraAI Project Team"},
    openapi_tags=[
        {"name": "Service status", "description": "Check whether the trained artifact is available for inference."},
        {"name": "Inference", "description": "Score one normalized event together with its temporal context."},
    ],
)


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Service status"],
    summary="Check model readiness",
    description="Returns 200 only when both the trained model and its metadata can be loaded.",
    responses={503: {"description": "The model artifact has not been trained, exported, or mounted."}},
)
def health() -> HealthResponse:
    try:
        _, metadata = load_artifacts()
    except FileNotFoundError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    return HealthResponse(status="ready", modelVersion=metadata["modelVersion"])


@app.post(
    "/v1/predict",
    response_model=PredictionResponse,
    tags=["Inference"],
    summary="Score a normalized security event",
    description=(
        "Accepts one normalized Wazuh/SecuraAI event plus counters calculated by the backend "
        "for 1, 5, 15 and 60-minute windows. The endpoint builds the same features used during "
        "training, obtains the trained model score, and compares it with the locked threshold. "
        "SecuraAI's backend remains responsible for second-stage review, alert grouping, storage, "
        "retry handling and user-facing explanations."
    ),
    responses={
        422: {"description": "The request is missing required fields or contains an invalid value."},
        503: {"description": "The trained model artifact is unavailable."},
    },
)
def predict(payload: PredictionRequest) -> PredictionResponse:
    try:
        model, metadata = load_artifacts()
    except FileNotFoundError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    values = payload.model_dump()
    values["commandLine"] = "present" if values.pop("commandLinePresent") else None
    values["parentCommandLine"] = "present" if values.pop("parentCommandLinePresent") else None
    values["targetFilename"] = "present" if values.pop("targetFilePresent") else None
    values["hashes"] = "present" if values.pop("hashesPresent") else None
    features = build_features(canonical_event_frame(values))
    if "event_family_name" in metadata.get("features", []):
        features["event_family_name"] = (payload.eventFamily or "missing").lower()
        features["event_type_name"] = (payload.eventType or "missing").lower()
        temporal_values = {
            "events_5m": payload.events5m,
            "failed_logins_5m": payload.failedLogins5m,
            "access_denials_5m": payload.accessDenials5m,
            "vpn_failures_5m": payload.vpnFailures5m,
            "distinct_accounts_5m": payload.distinctAccounts5m,
            "distinct_source_ips_5m": payload.distinctSourceIps5m,
            "success_after_failure_5m": int(payload.successAfterFailure5m),
            "seconds_since_previous": payload.secondsSincePrevious,
            "events_1m": payload.events1m,
            "failures_1m": payload.failures1m,
            "events_15m": payload.events15m,
            "failures_15m": payload.failures15m,
            "events_60m": payload.events60m,
            "failures_60m": payload.failures60m,
        }
        for feature in TEMPORAL_FEATURES:
            features[feature] = temporal_values[feature]
    score = float(decision_scores(model, features)[0])
    threshold = float(metadata.get("lockedThreshold", 0.5 if hasattr(model, "predict_proba") else 0.0))
    escalation_threshold = float(metadata.get("escalationThreshold", threshold))
    prediction = int(score >= threshold)
    return PredictionResponse(
        label=metadata["labels"][str(prediction)], malicious=bool(prediction), score=score,
        threshold=threshold, escalationThreshold=escalation_threshold,
        scoreSemantics=metadata["scoreSemantics"], modelVersion=metadata["modelVersion"],
    )
