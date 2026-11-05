from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.base import clone
from sklearn.ensemble import (AdaBoostClassifier, BaggingClassifier,
                              RandomForestClassifier, VotingClassifier)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, fbeta_score,
                             make_scorer, precision_score, recall_score)
from sklearn.model_selection import GridSearchCV, StratifiedGroupKFold
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier

from securaai_ml.temporal import (OPERATIONAL_GATES, TEMPORAL_FEATURES,
                                  add_session_temporal_features, operational_gate)


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "securaai_scenarios" / "securaai_scenarios.csv"
REAL_DATA = ROOT / "data" / "real_windows_auth_lab" / "real_windows_auth_v1.csv"
MULTIWINDOW_DATA = ROOT / "data" / "securaai_scenarios" / "securaai_multiwindow_scenarios.csv"
OUTPUT = ROOT / "artifacts-temporal-1m5m15m60m-candidate"
ROBUST_CATEGORICAL = ("event_family_name", "event_type_name")
ROBUST_NUMERIC = (
    "hour", "is_after_hours", "is_weekend", "source_ip_private",
    "destination_ip_private", "destination_port",
) + TEMPORAL_FEATURES


def metrics(y, pred) -> dict[str, object]:
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y, pred),
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
        "f2": fbeta_score(y, pred, beta=2, zero_division=0),
        "falsePositiveRate": (fp / (fp + tn)) if (fp + tn) else None,
        "confusionMatrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def select_threshold(y: np.ndarray, score: np.ndarray) -> float:
    # Include a reject-all threshold. A weak candidate must remain reportable
    # with F2=0 instead of aborting the complete model comparison.
    reject_all = np.nextafter(float(np.max(score)), np.inf)
    candidates = np.unique(np.r_[0.5, reject_all, np.quantile(score, np.linspace(0, 1, 1001))])
    accepted = []
    for threshold in candidates:
        pred = score >= threshold
        result = metrics(y, pred)
        if result["falsePositiveRate"] is not None and result["falsePositiveRate"] <= .05:
            accepted.append((result["f2"], result["recall"], result["precision"], float(threshold)))
    if not accepted:
        raise RuntimeError("No threshold meets validation FPR <= 5%")
    return max(accepted)[-1]


def select_escalation_threshold(
    y: np.ndarray, score: np.ndarray, decision_threshold: float, minimum_recall: float = .98,
) -> float:
    """Highest Validation threshold that preserves target recall, minimizing LLM calls."""
    candidates = np.unique(np.r_[0.0, 0.5, np.quantile(score, np.linspace(0, 1, 1001))])
    accepted = []
    for threshold in candidates:
        pred = score >= threshold
        recall = recall_score(y, pred, zero_division=0)
        if recall >= minimum_recall:
            accepted.append((float(threshold), precision_score(y, pred, zero_division=0)))
    if not accepted:
        return 0.0
    return min(max(accepted)[0], decision_threshold)


def pipeline(estimator) -> Pipeline:
    transformer = ColumnTransformer([
        ("categorical", OneHotEncoder(handle_unknown="ignore", min_frequency=2),
         list(ROBUST_CATEGORICAL)),
        # All temporal/numeric fields are non-negative. Passthrough preserves
        # compatibility with ComplementNB and keeps the experiment sparse.
        ("numeric", "passthrough", list(ROBUST_NUMERIC)),
    ], sparse_threshold=1.0)
    return Pipeline([("preprocess", transformer), ("model", estimator)])


def candidate_search_space() -> dict[str, tuple[Pipeline, dict[str, list[object]]]]:
    seed = 42
    return {
        "decision_tree": (
            pipeline(DecisionTreeClassifier(class_weight="balanced", random_state=seed)),
            {"model__max_depth": [8, 16, None], "model__min_samples_leaf": [2, 5, 10]},
        ),
        "naive_bayes": (
            pipeline(ComplementNB()), {"model__alpha": [0.1, 1.0, 5.0]},
        ),
        "bagging": (
            pipeline(BaggingClassifier(
                estimator=DecisionTreeClassifier(class_weight="balanced", random_state=seed),
                n_jobs=1, random_state=seed)),
            {"model__n_estimators": [50, 100], "model__max_samples": [0.7, 1.0]},
        ),
        "random_forest": (
            pipeline(RandomForestClassifier(
                class_weight="balanced_subsample", n_jobs=-1, random_state=seed)),
            {"model__n_estimators": [150, 300], "model__max_depth": [12, 20],
             "model__min_samples_leaf": [2, 5]},
        ),
        "adaboost": (
            pipeline(AdaBoostClassifier(
                estimator=DecisionTreeClassifier(max_depth=2, random_state=seed),
                random_state=seed)),
            {"model__n_estimators": [50, 100], "model__learning_rate": [0.1, 0.5, 1.0]},
        ),
        "linear_svm": (
            pipeline(LinearSVC(class_weight="balanced", dual="auto", random_state=seed)),
            {"model__C": [0.1, 1.0, 5.0]},
        ),
        "logistic_regression": (
            pipeline(LogisticRegression(
                class_weight="balanced", max_iter=2000, solver="liblinear", random_state=seed)),
            {"model__C": [0.1, 1.0, 5.0]},
        ),
    }


def decision_scores(model: Pipeline, frame: pd.DataFrame) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        return model.predict_proba(frame)[:, 1]
    return model.decision_function(frame)


def main() -> None:
    synthetic = pd.read_csv(DATA, dtype=str).fillna("")
    real = pd.read_csv(REAL_DATA, dtype=str).fillna("")
    multiwindow = pd.read_csv(MULTIWINDOW_DATA, dtype=str).fillna("")
    synthetic["dataset_origin"] = "SYNTHETIC_SCENARIO"
    real["dataset_origin"] = "CONTROLLED_REAL_WINDOWS_LAB"
    multiwindow["dataset_origin"] = "CONTROLLED_MULTIWINDOW_SCENARIO"
    raw = pd.concat([synthetic, real, multiwindow], ignore_index=True, sort=False).fillna("")
    # Build counters inside each source frame before concatenation so unrelated
    # sessions and collection clocks can never influence one another.
    features = pd.concat([
        add_session_temporal_features(synthetic),
        add_session_temporal_features(real),
        add_session_temporal_features(multiwindow),
    ], ignore_index=True, sort=False).fillna(0)
    target = raw["reviewer_label"].eq("MALICIOUS_APT").astype(int)
    parts = {name: raw["session_split"].eq(name) for name in ("TRAIN", "VALIDATION", "TEST")}
    groups = raw.loc[parts["TRAIN"], "scenario_id"]
    if groups.nunique() < 5:
        raise RuntimeError("Need at least five independent Train sessions for 5-Fold CV")
    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    scorer = make_scorer(fbeta_score, beta=2, zero_division=0)
    validation_results = {}
    fitted = {}
    cv_results = {}
    for name, (candidate, parameter_grid) in candidate_search_space().items():
        search = GridSearchCV(
            candidate, parameter_grid, scoring=scorer, refit=True, cv=cv,
            n_jobs=1, return_train_score=True,
        )
        search.fit(
            features.loc[parts["TRAIN"]], target.loc[parts["TRAIN"]], groups=groups,
        )
        model = search.best_estimator_
        validation_features = features.loc[parts["VALIDATION"]]
        score = decision_scores(model, validation_features)
        score = np.where(operational_gate(validation_features), score, 0.0)
        threshold = select_threshold(target.loc[parts["VALIDATION"]].to_numpy(), score)
        validation_results[name] = {
            "threshold": threshold,
            **metrics(target.loc[parts["VALIDATION"]], score >= threshold),
        }
        fitted[name] = model
        best_index = int(search.best_index_)
        cv_results[name] = {
            "bestParams": search.best_params_,
            "meanTrainF2": float(search.cv_results_["mean_train_score"][best_index]),
            "meanCvF2": float(search.best_score_),
            "stdCvF2": float(search.cv_results_["std_test_score"][best_index]),
        }

    # Soft Voting mirrors the lecturer's ensemble experiment. LinearSVC is
    # excluded because it does not expose predict_proba without calibration.
    voting_names = [
        "decision_tree", "naive_bayes", "bagging", "random_forest",
        "adaboost", "logistic_regression",
    ]
    voting = VotingClassifier(
        estimators=[(name, clone(fitted[name])) for name in voting_names],
        voting="soft", weights=[max(cv_results[name]["meanCvF2"], 1e-6) for name in voting_names],
        n_jobs=1,
    )
    voting.fit(features.loc[parts["TRAIN"]], target.loc[parts["TRAIN"]])
    voting_score = voting.predict_proba(features.loc[parts["VALIDATION"]])[:, 1]
    voting_score = np.where(
        operational_gate(features.loc[parts["VALIDATION"]]), voting_score, 0.0)
    voting_threshold = select_threshold(
        target.loc[parts["VALIDATION"]].to_numpy(), voting_score)
    validation_results["soft_voting"] = {
        "threshold": voting_threshold,
        **metrics(target.loc[parts["VALIDATION"]], voting_score >= voting_threshold),
    }
    fitted["soft_voting"] = voting
    cv_results["soft_voting"] = {
        "components": voting_names,
        "weightsFromTrainCvF2": {
            name: cv_results[name]["meanCvF2"] for name in voting_names
        },
    }
    selected = max(validation_results, key=lambda name: (
        validation_results[name]["f2"],
        validation_results[name]["recall"],
        validation_results[name]["precision"],
        cv_results[name].get("meanCvF2", max(
            cv_results[name].get("weightsFromTrainCvF2", {"_": 0.0}).values())),
        -cv_results[name].get("stdCvF2", 0.0),
    ))
    model = fitted[selected]
    threshold = validation_results[selected]["threshold"]
    selected_validation_score = decision_scores(model, features.loc[parts["VALIDATION"]])
    selected_validation_score = np.where(
        operational_gate(features.loc[parts["VALIDATION"]]), selected_validation_score, 0.0)
    escalation_threshold = select_escalation_threshold(
        target.loc[parts["VALIDATION"]].to_numpy(), selected_validation_score, threshold)
    test_features = features.loc[parts["TEST"]]
    test_score = decision_scores(model, test_features)
    test_score = np.where(operational_gate(test_features), test_score, 0.0)
    test_pred = test_score >= threshold
    test_result = metrics(target.loc[parts["TEST"]], test_pred)
    test_by_origin = {}
    for origin in ("SYNTHETIC_SCENARIO", "CONTROLLED_REAL_WINDOWS_LAB", "CONTROLLED_MULTIWINDOW_SCENARIO"):
        origin_mask = parts["TEST"] & raw["dataset_origin"].eq(origin)
        origin_features = features.loc[origin_mask]
        origin_score = decision_scores(model, origin_features)
        origin_score = np.where(operational_gate(origin_features), origin_score, 0.0)
        test_by_origin[origin] = metrics(
            target.loc[origin_mask], origin_score >= threshold)
    scenario = raw.loc[parts["TEST"], ["scenario"]].copy()
    scenario["target"] = target.loc[parts["TEST"]].to_numpy()
    scenario["prediction"] = test_pred.astype(int)
    by_scenario = {}
    for name, group in scenario.groupby("scenario"):
        by_scenario[name] = {"rows": len(group), **metrics(group["target"], group["prediction"])}
    metadata = {
        "modelVersion": "securaai-temporal-1m5m15m60m-lab-candidate-v8",
        "status": "EXPERIMENTAL_CONTROLLED_LAB_ONLY",
        "selectedModel": selected,
        "lockedThreshold": threshold,
        "escalationThreshold": escalation_threshold,
        "escalationSelection": {
            "split": "VALIDATION",
            "objective": "highest threshold preserving recall >= 0.98, capped at the locked model decision threshold",
        },
        "operationalGates": OPERATIONAL_GATES,
        "labels": {"0": "BENIGN", "1": "MALICIOUS_APT"},
        "scoreSemantics": "experimental temporal classifier score; not calibrated attack probability",
        "features": list(ROBUST_CATEGORICAL + ROBUST_NUMERIC),
        "validation": validation_results[selected],
        "allValidationCandidates": validation_results,
        "trainCrossValidation": {
            "method": "StratifiedGroupKFold",
            "folds": 5,
            "group": "scenario_id",
            "selectionMetric": "F2",
            "tieBreakPolicy": "validation recall, validation precision, mean Train-CV F2, lower CV std",
            "candidates": cv_results,
        },
        "test": test_result,
        "testByOrigin": test_by_origin,
        "testByScenario": by_scenario,
        "limitations": [
            "trained on controlled synthetic SecuraAI scenarios plus controlled real Windows lab telemetry",
            "labels are scenario-manifest ground truth with rule-defined decision boundaries",
            "high synthetic metrics are not production accuracy",
            "requires past-only 1-minute, 5-minute, 15-minute and 60-minute context at inference",
            "not approved to create alerts",
        ],
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, OUTPUT / "model.joblib")
    (OUTPUT / "model_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
