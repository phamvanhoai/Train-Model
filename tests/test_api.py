from fastapi.testclient import TestClient

from securaai_ml import api
from securaai_ml.api import app, load_artifacts


def test_health_is_explicit_when_model_has_not_been_trained(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "ARTIFACT_DIR", tmp_path)
    load_artifacts.cache_clear()
    response = TestClient(app).get("/health")
    assert response.status_code == 503
    assert response.json()["detail"] == "Train the model before starting inference"
