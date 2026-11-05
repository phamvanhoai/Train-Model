from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, balanced_accuracy_score, confusion_matrix,
                             f1_score, fbeta_score, precision_score, recall_score,
                             roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit

from securaai_ml.data import load_training_data
from securaai_ml.modeling import candidate_factories, decision_scores
from securaai_ml.radar import radar_members, radar_to_model_frame, read_radar_member
from securaai_ml.schema import GROUP_COLUMN, MODEL_FEATURES, TARGET_COLUMN
from securaai_ml.train import temporal_train_validation_test
from securaai_ml.wazuh_review import review_to_model_frame

SEED = 42


def split_members(members: list[str]) -> tuple[list[str], list[str], list[str]]:
    families = np.array([Path(member).stem.split("-", 1)[0] for member in members])
    indices = np.arange(len(members))
    first = GroupShuffleSplit(n_splits=1, train_size=0.6, random_state=SEED)
    train_idx, remainder_idx = next(first.split(indices, groups=families))
    second = GroupShuffleSplit(n_splits=1, train_size=0.5, random_state=SEED)
    val_local, test_local = next(second.split(remainder_idx, groups=families[remainder_idx]))
    parts = ([members[i] for i in train_idx], [members[remainder_idx[i]] for i in val_local],
             [members[remainder_idx[i]] for i in test_local])
    family_parts = [{Path(member).stem.split("-", 1)[0] for member in part} for part in parts]
    if any(family_parts[left] & family_parts[right] for left, right in ((0, 1), (0, 2), (1, 2))):
        raise RuntimeError("Ransomware family leakage across RADAR splits")
    return parts


def mapped(frame: pd.DataFrame, target: int, group: str | pd.Series) -> pd.DataFrame:
    result = radar_to_model_frame(frame)
    result[TARGET_COLUMN] = target
    result[GROUP_COLUMN] = group
    return result


def load_radar_splits(goodware_zip: Path, ransomware_zip: Path):
    good_member = radar_members(goodware_zip)[0]
    good_raw = read_radar_member(goodware_zip, good_member)
    timestamps = pd.to_datetime(good_raw["@timestamp"].str.replace(" @ ", " ", regex=False),
                                format="mixed", errors="raise")
    order = np.argsort(timestamps.to_numpy())
    good_raw = good_raw.iloc[order].reset_index(drop=True)
    n = len(good_raw); a, b = int(n * .6), int(n * .8)
    good_parts = [good_raw.iloc[:a], good_raw.iloc[a:b], good_raw.iloc[b:]]
    del good_raw
    ransomware_parts = []
    member_parts = split_members(radar_members(ransomware_zip))
    for members in member_parts:
        frames = []
        for member in members:
            raw = read_radar_member(ransomware_zip, member)
            frames.append(mapped(raw, 1, Path(member).stem))
        ransomware_parts.append(pd.concat(frames, ignore_index=True))
    output = []
    for index, good in enumerate(good_parts):
        good_mapped = mapped(good, 0, f"radar-goodware-part-{index}")
        output.append(pd.concat([good_mapped, ransomware_parts[index]], ignore_index=True))
    return output, member_parts


def metrics(y, pred, score):
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"accuracy": accuracy_score(y, pred),
            "balanced_accuracy": balanced_accuracy_score(y, pred),
            "precision": precision_score(y, pred, zero_division=0),
            "recall": recall_score(y, pred, zero_division=0),
            "f1": f1_score(y, pred, zero_division=0),
            "f2": fbeta_score(y, pred, beta=2, zero_division=0),
            "roc_auc": (roc_auc_score(y, score) if len(np.unique(y)) > 1 else None),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}


def choose_threshold(y, score) -> float:
    benign = score[np.asarray(y) == 0]
    thresholds = np.unique(np.concatenate([
        np.quantile(score, np.linspace(0.001, 0.999, 999)),
        np.quantile(benign, [0.95, 0.975, 0.99, 0.995, 1.0]),
        [np.nextafter(float(score.max()), np.inf)],
    ]))
    best = None
    for threshold in thresholds:
        pred = score >= threshold
        tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
        fpr = fp / (fp + tn)
        row = (fbeta_score(y, pred, beta=2, zero_division=0), -fpr, float(threshold))
        if fpr <= 0.05 and (best is None or row > best): best = row
    if best is None:
        raise RuntimeError("No validation threshold satisfies FPR <= 5%")
    return best[2]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--windows-apt", type=Path, default=Path("data/raw"))
    parser.add_argument("--goodware-zip", type=Path, required=True)
    parser.add_argument("--ransomware-zip", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("artifacts-combined-candidate"))
    parser.add_argument("--radar-only", action="store_true",
                        help="Train without reading Windows-APT raw files")
    parser.add_argument("--wazuh-review", type=Path,
                        help="Review CSV; only BENIGN_CANDIDATE rows are weak train labels")
    parser.add_argument("--wazuh-lab-train", type=Path,
                        help="Controlled malicious lab CSV used only in Train")
    parser.add_argument("--wazuh-lab-test", type=Path,
                        help="Independent controlled lab CSV used only for external reporting")
    args = parser.parse_args()
    radar_parts, member_parts = load_radar_splits(args.goodware_zip, args.ransomware_zip)
    if args.radar_only:
        combined = radar_parts
    else:
        windows, _ = load_training_data(args.windows_apt)
        windows_parts = temporal_train_validation_test(windows)
        combined = [pd.concat([w, r], ignore_index=True) for w, r in zip(windows_parts, radar_parts)]
    train, validation, test = combined
    supplemental = []
    if args.wazuh_review:
        review = pd.read_csv(args.wazuh_review, dtype=str).fillna("")
        weak_benign = review[review["review_suggestion"].eq("REVIEW_BENIGN_CANDIDATE")]
        weak = review_to_model_frame(weak_benign)
        weak[TARGET_COLUMN] = 0; weak[GROUP_COLUMN] = "wazuh-weak-benign"
        supplemental.append(pd.concat([weak] * 50, ignore_index=True))
    if args.wazuh_lab_train:
        lab = pd.read_csv(args.wazuh_lab_train, dtype=str).fillna("")
        lab_frame = review_to_model_frame(lab)
        lab_frame[TARGET_COLUMN] = 1; lab_frame[GROUP_COLUMN] = "wazuh-controlled-malicious"
        supplemental.append(pd.concat([lab_frame] * 200, ignore_index=True))
    if supplemental:
        train = pd.concat([train, *supplemental], ignore_index=True)
    candidates = {name: factory for name, factory in candidate_factories(SEED).items()
                  if name in {"logistic_regression", "decision_tree"}}
    validation_results = {}
    fitted = {}
    for name, factory in candidates.items():
        model = factory(); model.fit(train.loc[:, MODEL_FEATURES], train[TARGET_COLUMN])
        score = decision_scores(model, validation.loc[:, MODEL_FEATURES])
        threshold = choose_threshold(validation[TARGET_COLUMN].to_numpy(), score)
        result = metrics(validation[TARGET_COLUMN], score >= threshold, score)
        validation_results[name] = {"threshold": threshold, **result}; fitted[name] = model
        print(name, json.dumps(validation_results[name]))
    selected = max(validation_results, key=lambda name: (
        validation_results[name]["f2"], validation_results[name]["balanced_accuracy"]))
    model, threshold = fitted[selected], validation_results[selected]["threshold"]
    test_score = decision_scores(model, test.loc[:, MODEL_FEATURES])
    test_result = metrics(test[TARGET_COLUMN], test_score >= threshold, test_score)
    external_lab = None
    if args.wazuh_lab_test:
        lab_test = pd.read_csv(args.wazuh_lab_test, dtype=str).fillna("")
        lab_X = review_to_model_frame(lab_test)
        lab_score = decision_scores(model, lab_X)
        lab_y = np.ones(len(lab_X), dtype=int)
        external_lab = metrics(lab_y, lab_score >= threshold, lab_score)
    split_description = json.dumps(member_parts, sort_keys=True)
    metadata = {"modelVersion": ("radar-wazuh-candidate-v1" if args.radar_only else
                                 "windows-apt-radar-candidate-v1"), "selectedModel": selected,
                "lockedThreshold": threshold, "labels": {"0": "BENIGN", "1": "MALICIOUS_APT"},
                "datasets": (["RADAR v0.0.1-beta"] if args.radar_only else
                             ["Windows-APT 2025 v4", "RADAR v0.0.1-beta"]),
                "radarSampleSplitHash": hashlib.sha256(split_description.encode()).hexdigest(),
                "radarFamilySplits": [sorted({Path(member).stem.split("-", 1)[0]
                                              for member in members}) for members in member_parts],
                "validation": validation_results[selected], "test": test_result,
                "externalWazuhLabTest": external_lab,
                "weakWazuhBenignRows": (int(len(weak_benign)) if args.wazuh_review else 0),
                "scoreSemantics": "experimental classifier score; not calibrated attack probability"}
    args.output.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.output / "model.joblib")
    (args.output / "model_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
