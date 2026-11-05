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
    model_config = ConfigDict(extra="forbid")
    timestamp: str
    eventFamily: str | None = None
    eventType: str | None = None
    eventId: str | int | None = None
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
    sourceIp: str | None = None
    destinationIp: str | None = None
    sourcePort: int | None = Field(default=None, ge=0, le=65535)
    destinationPort: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    status: str | None = None
    subStatus: str | None = None
    events5m: int = Field(default=1, ge=0)
    failedLogins5m: int = Field(default=0, ge=0)
    accessDenials5m: int = Field(default=0, ge=0)
    vpnFailures5m: int = Field(default=0, ge=0)
    distinctAccounts5m: int = Field(default=0, ge=0)
    distinctSourceIps5m: int = Field(default=0, ge=0)
    successAfterFailure5m: bool = False
    secondsSincePrevious: float = Field(default=3600, ge=0)
    events1m: int = Field(default=1, ge=0)
    failures1m: int = Field(default=0, ge=0)
    events15m: int = Field(default=1, ge=0)
    failures15m: int = Field(default=0, ge=0)
    events60m: int = Field(default=1, ge=0)
    failures60m: int = Field(default=0, ge=0)


class PredictionResponse(BaseModel):
    label: str
    malicious: bool
    score: float
    threshold: float
    escalationThreshold: float
    scoreSemantics: str
    modelVersion: str


@lru_cache(maxsize=1)
def load_artifacts():
    model_path = ARTIFACT_DIR / "model.joblib"
    metadata_path = ARTIFACT_DIR / "model_metadata.json"
    if not model_path.exists() or not metadata_path.exists():
        raise FileNotFoundError("Train the model before starting inference")
    return joblib.load(model_path), json.loads(metadata_path.read_text(encoding="utf-8"))


app = FastAPI(title="SecuraAI Windows APT Model", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    try:
        _, metadata = load_artifacts()
    except FileNotFoundError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    return {"status": "ready", "modelVersion": metadata["modelVersion"]}


@app.post("/v1/predict", response_model=PredictionResponse)
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
