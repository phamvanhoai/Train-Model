from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import joblib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .features import build_features, canonical_event_frame
from .modeling import decision_scores

ARTIFACT_DIR = Path("artifacts")


class PredictionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timestamp: str
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


class PredictionResponse(BaseModel):
    label: str
    malicious: bool
    score: float
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
    prediction = int(model.predict(features)[0])
    score = float(decision_scores(model, features)[0])
    return PredictionResponse(
        label=metadata["labels"][str(prediction)], malicious=bool(prediction), score=score,
        scoreSemantics=metadata["scoreSemantics"], modelVersion=metadata["modelVersion"],
    )
