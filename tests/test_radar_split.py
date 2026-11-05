from pathlib import Path

from scripts.train_combined_candidate import split_members


def test_radar_split_holds_out_complete_ransomware_families():
    members = [f"{family}-{sample}.csv" for family in "ABCDEFG" for sample in range(3)]
    parts = split_members(members)
    family_parts = [
        {Path(member).stem.split("-", 1)[0] for member in part}
        for part in parts
    ]
    assert all(parts)
    assert not family_parts[0] & family_parts[1]
    assert not family_parts[0] & family_parts[2]
    assert not family_parts[1] & family_parts[2]
