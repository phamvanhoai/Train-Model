"""Export the validation-selected Soft Voting experiment for inference."""
from __future__ import annotations

import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPERIMENTS = ROOT / "reports" / "notebook_experiments"
ARTIFACTS = ROOT / "artifacts"
SLUG = "07_soft_voting"


def main() -> None:
    experiment_path = EXPERIMENTS / f"{SLUG}.json"
    model_path = EXPERIMENTS / f"{SLUG}.joblib"
    if not experiment_path.exists() or not model_path.exists():
        raise FileNotFoundError("Run notebooks/07_Soft_Voting.ipynb before exporting")

    experiment = json.loads(experiment_path.read_text(encoding="utf-8"))
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    shutil.copy2(model_path, ARTIFACTS / "model.joblib")
    metadata = {
        "modelVersion": "windows-apt-2025-soft-voting-v1",
        "dataset": "Windows-APT 2025 v4",
        "datasetDoi": "10.17632/b8fmtzvpy8.4",
        "selectedModel": "soft_voting",
        "lockedThreshold": float(experiment["locked_threshold"]),
        "selectionMetric": "validation_f2",
        "splitHash": experiment["split_hash"],
        "labels": {"0": "BENIGN", "1": "MALICIOUS_APT"},
        "scoreSemantics": "experimental classifier score; not calibrated attack probability",
    }
    (ARTIFACTS / "model_metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )
    print(f"Exported {metadata['modelVersion']} at threshold {metadata['lockedThreshold']:.12g}")


if __name__ == "__main__":
    main()
