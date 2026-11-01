from __future__ import annotations

from collections.abc import Callable

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import AdaBoostClassifier, BaggingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier

from .schema import CATEGORICAL_FEATURES, NUMERIC_FEATURES


def preprocessor() -> ColumnTransformer:
    return ColumnTransformer([
        ("categorical", OneHotEncoder(handle_unknown="ignore", min_frequency=2),
         list(CATEGORICAL_FEATURES)),
        ("numeric", "passthrough", list(NUMERIC_FEATURES)),
    ], sparse_threshold=1.0)


def candidate_factories(random_state: int = 42) -> dict[str, Callable[[], Pipeline]]:
    classifiers = {
        "decision_tree": lambda: DecisionTreeClassifier(
            max_depth=20, min_samples_leaf=5, class_weight="balanced", random_state=random_state),
        "random_forest": lambda: RandomForestClassifier(
            n_estimators=250, max_depth=24, min_samples_leaf=3,
            class_weight="balanced_subsample", n_jobs=-1, random_state=random_state),
        "naive_bayes": lambda: ComplementNB(alpha=1.0),
        "linear_svm": lambda: LinearSVC(class_weight="balanced", random_state=random_state),
        "logistic_regression": lambda: LogisticRegression(
            class_weight="balanced", max_iter=1500, solver="liblinear", random_state=random_state),
    }
    return {
        name: (lambda factory=factory: Pipeline([
            ("preprocess", preprocessor()), ("model", factory()),
        ]))
        for name, factory in classifiers.items()
    }


def parameter_grids() -> dict[str, dict[str, list[object]]]:
    """Small, explainable grids suitable for a CPU-based student experiment."""
    return {
        "decision_tree": {
            "model__max_depth": [12, 20, None],
            "model__min_samples_leaf": [3, 8],
        },
        "random_forest": {
            "model__n_estimators": [150, 250],
            "model__max_depth": [16, 24],
            "model__min_samples_leaf": [3],
        },
        "naive_bayes": {"model__alpha": [0.1, 1.0, 5.0]},
        "linear_svm": {"model__C": [0.1, 1.0, 5.0]},
        "logistic_regression": {"model__C": [0.1, 1.0, 5.0]},
    }


def teaching_candidate_factories(random_state: int = 42) -> dict[str, Callable[[], Pipeline]]:
    """Extra estimators used to mirror the lecturer's notebook sequence."""
    factories = candidate_factories(random_state)
    factories.update({
        "bagging": lambda: Pipeline([
            ("preprocess", preprocessor()),
            ("model", BaggingClassifier(
                estimator=DecisionTreeClassifier(class_weight="balanced", random_state=random_state),
                n_estimators=100, n_jobs=1, random_state=random_state)),
        ]),
        "adaboost": lambda: Pipeline([
            ("preprocess", preprocessor()),
            ("model", AdaBoostClassifier(
                estimator=DecisionTreeClassifier(max_depth=2, random_state=random_state),
                n_estimators=100, learning_rate=0.5, random_state=random_state)),
        ]),
    })
    return factories


def teaching_parameter_grids() -> dict[str, dict[str, list[object]]]:
    grids = parameter_grids()
    grids.update({
        "bagging": {
            "model__n_estimators": [50, 100],
            "model__max_samples": [0.7, 1.0],
        },
        "adaboost": {
            "model__n_estimators": [50, 100],
            "model__learning_rate": [0.1, 0.5, 1.0],
        },
    })
    return grids


def decision_scores(model: Pipeline, features):
    if hasattr(model, "predict_proba"):
        return model.predict_proba(features)[:, 1]
    return model.decision_function(features)
