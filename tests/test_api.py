import json

import joblib
import numpy as np
from fastapi.testclient import TestClient

from securaai_ml import api
from securaai_ml.api import app, load_artifacts


def test_health_is_explicit_when_model_has_not_been_trained(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "ARTIFACT_DIR", tmp_path)
    load_artifacts.cache_clear()
    response = TestClient(app).get("/health")
    assert response.status_code == 503
    assert response.json()["detail"] == "Train the model before starting inference"


class FixedScoreModel:
    def predict_proba(self, features):
        score = 0.3
        return np.array([[1 - score, score]] * len(features))


def test_predict_uses_locked_threshold_instead_of_model_default(tmp_path, monkeypatch):
    joblib.dump(FixedScoreModel(), tmp_path / "model.joblib")
    (tmp_path / "model_metadata.json").write_text(json.dumps({
        "modelVersion": "test-v1",
        "lockedThreshold": 0.2,
        "labels": {"0": "BENIGN", "1": "MALICIOUS_APT"},
        "scoreSemantics": "test score",
    }), encoding="utf-8")
    monkeypatch.setattr(api, "ARTIFACT_DIR", tmp_path)
    load_artifacts.cache_clear()

    response = TestClient(app).post("/v1/predict", json={
        "timestamp": "2026-11-02T10:00:00Z",
        "eventId": "4625",
    })

    assert response.status_code == 200
    assert response.json() == {
        "label": "MALICIOUS_APT",
        "malicious": True,
        "score": 0.3,
        "threshold": 0.2,
        "escalationThreshold": 0.2,
        "scoreSemantics": "test score",
        "modelVersion": "test-v1",
    }


def test_predict_returns_model_score_without_a_global_count_gate(tmp_path, monkeypatch):
    joblib.dump(FixedScoreModel(), tmp_path / "model.joblib")
    (tmp_path / "model_metadata.json").write_text(json.dumps({
        "modelVersion": "temporal-test-v1",
        "lockedThreshold": 0.2,
        "labels": {"0": "BENIGN", "1": "MALICIOUS_APT"},
        "scoreSemantics": "test score",
        "features": ["event_family_name"],
        "operationalGates": {"authentication": 5},
    }), encoding="utf-8")
    monkeypatch.setattr(api, "ARTIFACT_DIR", tmp_path)
    load_artifacts.cache_clear()

    response = TestClient(app).post("/v1/predict", json={
        "timestamp": "2026-11-02T10:00:00Z",
        "eventFamily": "authentication",
        "eventType": "LOGIN_FAILURE",
        "failedLogins5m": 4,
    })

    assert response.status_code == 200
    assert response.json()["malicious"] is True
    assert response.json()["score"] == 0.3
