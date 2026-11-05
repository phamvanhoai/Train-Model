from __future__ import annotations

from pathlib import Path

import pandas as pd

from .features import build_training_frame
from .schema import GROUP_COLUMN, LABEL_COLUMNS, RAW_COLUMNS, TARGET_COLUMN, DatasetAudit


def _dataset_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    # Prefer the consolidated export when present. Apart from preventing row
    # duplication, this avoids opening many security-log CSVs on Windows where
    # endpoint protection may quarantine an individual period file mid-scan.
    combined = path / "combined.csv"
    if combined.is_file():
        return [combined]
    excluded = {
        "scenario_manifest.csv",
        "validation_summary.csv",
        "log_to_scenario_mapping.csv",
    }
    files = sorted(item for item in path.glob("*.csv") if item.name not in excluded)
    if not files:
        raise FileNotFoundError(f"No dataset CSV files found under {path}")
    return files


def available_columns(path: Path) -> list[str]:
    dataset_file = _dataset_files(path)[0]
    return list(pd.read_csv(dataset_file, nrows=0, encoding="utf-8-sig").columns)


def load_training_data(path: Path) -> tuple[pd.DataFrame, DatasetAudit]:
    frames: list[pd.DataFrame] = []
    for dataset_file in _dataset_files(path):
        columns = available_columns(dataset_file)
        wanted = [column for column in RAW_COLUMNS + LABEL_COLUMNS if column in columns]
        if not any(column in columns for column in LABEL_COLUMNS):
            raise ValueError(f"{dataset_file} has no MITRE label columns")
        frames.append(pd.read_csv(
            dataset_file, usecols=wanted, low_memory=False, encoding="utf-8-sig"
        ))
    raw = pd.concat(frames, ignore_index=True)
    prepared = build_training_frame(raw)
    target = prepared[TARGET_COLUMN]
    audit = DatasetAudit(
        rows=len(prepared), malicious=int(target.sum()), benign=int((target == 0).sum()),
        groups=int(prepared[GROUP_COLUMN].nunique()),
        invalid_timestamps=int((prepared[GROUP_COLUMN] == "unknown-date").sum()),
    )
    return prepared, audit
