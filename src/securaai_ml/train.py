from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.ensemble import VotingClassifier
from sklearn.metrics import (
    ConfusionMatrixDisplay, RocCurveDisplay, accuracy_score, average_precision_score,
    balanced_accuracy_score, f1_score, fbeta_score, precision_score, recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GridSearchCV, StratifiedGroupKFold
from sklearn.metrics import make_scorer

from .data import load_training_data
from .modeling import candidate_factories, decision_scores, parameter_grids
from .schema import GROUP_COLUMN, MODEL_FEATURES, TARGET_COLUMN


def metrics(y_true, y_pred, scores) -> dict[str, float]:
    result = {
        "accuracy": accuracy_score(y_true, y_pred),
        "balanced_accuracy": balanced_accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "f2": fbeta_score(y_true, y_pred, beta=2, zero_division=0),
    }
    if len(np.unique(y_true)) == 2:
        result["roc_auc"] = roc_auc_score(y_true, scores)
        result["average_precision"] = average_precision_score(y_true, scores)
    return {key: float(value) for key, value in result.items()}


def temporal_holdout(data: pd.DataFrame, holdout_groups: int) -> tuple[pd.DataFrame, pd.DataFrame]:
    groups = sorted(group for group in data[GROUP_COLUMN].unique() if group != "unknown-date")
    if len(groups) < holdout_groups + 3:
        raise ValueError("Need at least holdout_groups + 3 collection dates")
    held_out = set(groups[-holdout_groups:])
    development = data[~data[GROUP_COLUMN].isin(held_out)].copy()
    holdout = data[data[GROUP_COLUMN].isin(held_out)].copy()
    if development[TARGET_COLUMN].nunique() != 2 or holdout[TARGET_COLUMN].nunique() != 2:
        raise ValueError("Development and holdout sets must both contain both labels")
    return development, holdout


def temporal_train_validation_test(data: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Chronological 60/20/20 split without breaking a collection date across sets."""
    counts = (data[data[GROUP_COLUMN] != "unknown-date"]
              .groupby(GROUP_COLUMN, sort=True).size())
    if len(counts) < 5:
        raise ValueError("Need at least five dated groups for a 60/20/20 temporal split")
    cumulative = counts.cumsum().to_numpy()
    total = int(counts.sum())
    first = int(np.argmin(np.abs(cumulative - total * 0.60))) + 1
    second = int(np.argmin(np.abs(cumulative - total * 0.80))) + 1
    first = min(max(first, 1), len(counts) - 2)
    second = min(max(second, first + 1), len(counts) - 1)
    train_groups = set(counts.index[:first])
    validation_groups = set(counts.index[first:second])
    test_groups = set(counts.index[second:])
    parts = tuple(data[data[GROUP_COLUMN].isin(groups)].copy()
                  for groups in (train_groups, validation_groups, test_groups))
    if any(part[TARGET_COLUMN].nunique() != 2 for part in parts):
        raise ValueError("Every temporal split must contain BENIGN and MALICIOUS_APT labels")
    return parts


def main() -> None:
    parser = argparse.ArgumentParser(description="Train SecuraAI Windows APT classifier")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, default=Path("artifacts"))
    parser.add_argument("--reports-dir", type=Path, default=Path("reports"))
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()
    args.artifacts_dir.mkdir(parents=True, exist_ok=True)
    args.reports_dir.mkdir(parents=True, exist_ok=True)

    data, audit = load_training_data(args.input)
    train, validation, test = temporal_train_validation_test(data)
    X = train.loc[:, MODEL_FEATURES]
    y = train[TARGET_COLUMN]
    groups = train[GROUP_COLUMN]
    splitter = StratifiedGroupKFold(
        n_splits=args.folds, shuffle=True, random_state=args.random_state
    )

    rows: list[dict[str, object]] = []
    factories = candidate_factories(args.random_state)
    tuned = {}
    validation_X = validation.loc[:, MODEL_FEATURES]
    validation_y = validation[TARGET_COLUMN]
    for model_name, factory in factories.items():
        search = GridSearchCV(factory(), parameter_grids()[model_name],
                              scoring=make_scorer(fbeta_score, beta=2, zero_division=0),
                              cv=splitter, n_jobs=1, refit=True, return_train_score=False)
        search.fit(X, y, groups=groups)
        model = search.best_estimator_
        tuned[model_name] = model
        predictions = model.predict(validation_X)
        scores = decision_scores(model, validation_X)
        rows.append({"model": model_name, "best_params": json.dumps(search.best_params_),
                     "cv_best_f2": search.best_score_,
                     **metrics(validation_y, predictions, scores)})

    voting = VotingClassifier(
        estimators=[(name, clone(tuned[name])) for name in
                    ("decision_tree", "random_forest", "naive_bayes", "logistic_regression")],
        voting="soft", n_jobs=1)
    voting.fit(X, y)
    tuned["soft_voting"] = voting
    voting_pred = voting.predict(validation_X)
    voting_scores = voting.predict_proba(validation_X)[:, 1]
    rows.append({"model": "soft_voting", "best_params": "tuned base estimators",
                 "cv_best_f2": np.nan, **metrics(validation_y, voting_pred, voting_scores)})

    comparison = pd.DataFrame(rows).sort_values("f2", ascending=False)
    comparison.to_csv(args.reports_dir / "model_comparison.csv", index=False)
    selected_name = str(comparison.iloc[0]["model"])
    selected = clone(tuned[selected_name])
    train_validation = pd.concat([train, validation], ignore_index=True)
    selected.fit(train_validation.loc[:, MODEL_FEATURES], train_validation[TARGET_COLUMN])

    test_X = test.loc[:, MODEL_FEATURES]
    test_y = test[TARGET_COLUMN]
    test_predictions = selected.predict(test_X)
    test_scores = decision_scores(selected, test_X)
    test_metrics = metrics(test_y, test_predictions, test_scores)

    joblib.dump(selected, args.artifacts_dir / "model.joblib")
    metadata = {
        "modelVersion": "windows-apt-2025-v2", "dataset": "Windows-APT 2025 v4",
        "datasetDoi": "10.17632/b8fmtzvpy8.4", "selectedModel": selected_name,
        "labels": {"0": "BENIGN", "1": "MALICIOUS_APT"},
        "features": list(MODEL_FEATURES), "grouping": "UTC collection date",
        "scoreSemantics": "experimental classifier score; not calibrated attack probability",
    }
    (args.artifacts_dir / "model_metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )
    summary = {
        "datasetAudit": asdict(audit),
        "splitRows": {"train": len(train), "validation": len(validation), "test": len(test)},
        "splitRatios": {name: len(part) / len(data) for name, part in
                        (("train", train), ("validation", validation), ("test", test))},
        "splitGroups": {name: sorted(part[GROUP_COLUMN].unique().tolist()) for name, part in
                        (("train", train), ("validation", validation), ("test", test))},
        "selectedModel": selected_name,
        "validationComparison": comparison.replace({np.nan: None}).to_dict(orient="records"),
        "testMetrics": test_metrics,
        "limitations": [
            "MITRE/Wazuh tags are rule-derived experimental labels, not perfect ground truth.",
            "Simulated Windows APT telemetry does not establish VPN/SSO, web, or Linux performance.",
            "Scores are not calibrated attack probabilities.",
        ],
    }
    (args.reports_dir / "summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    ConfusionMatrixDisplay.from_predictions(
        test_y, test_predictions, labels=[0, 1],
        display_labels=["BENIGN", "MALICIOUS_APT"]
    )
    plt.tight_layout(); plt.savefig(args.reports_dir / "confusion_matrix.png", dpi=160); plt.close()
    RocCurveDisplay.from_predictions(test_y, test_scores)
    plt.tight_layout(); plt.savefig(args.reports_dir / "roc_curve.png", dpi=160); plt.close()
    plot_columns = ["accuracy", "precision", "recall", "f1", "f2", "roc_auc"]
    comparison.set_index("model")[plot_columns].plot(kind="bar", figsize=(12, 6), ylim=(0, 1.05))
    plt.ylabel("Validation score"); plt.xticks(rotation=25, ha="right"); plt.tight_layout()
    plt.savefig(args.reports_dir / "model_comparison.png", dpi=160); plt.close()
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
