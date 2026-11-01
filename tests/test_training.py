import pandas as pd

from securaai_ml.train import temporal_holdout, temporal_train_validation_test


def test_temporal_holdout_uses_latest_complete_groups():
    rows = []
    for day in range(1, 7):
        rows.extend([
            {"collection_date": f"2024-12-0{day}", "target": 0},
            {"collection_date": f"2024-12-0{day}", "target": 1},
        ])
    development, holdout = temporal_holdout(pd.DataFrame(rows), holdout_groups=2)
    assert set(holdout["collection_date"]) == {"2024-12-05", "2024-12-06"}
    assert set(development["collection_date"]).isdisjoint(set(holdout["collection_date"]))


def test_temporal_three_way_split_keeps_dates_separate():
    rows = []
    for day in range(1, 11):
        rows.extend([{"collection_date": f"2024-12-{day:02d}", "target": 0}] * 3)
        rows.extend([{"collection_date": f"2024-12-{day:02d}", "target": 1}] * 2)
    train, validation, test = temporal_train_validation_test(pd.DataFrame(rows))
    group_sets = [set(part["collection_date"]) for part in (train, validation, test)]
    assert not (group_sets[0] & group_sets[1] or group_sets[0] & group_sets[2] or group_sets[1] & group_sets[2])
    assert [len(part) for part in (train, validation, test)] == [30, 10, 10]
