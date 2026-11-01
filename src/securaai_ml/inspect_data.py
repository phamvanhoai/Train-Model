from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .data import available_columns, load_training_data


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit Windows-APT 2025 before training")
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    columns = available_columns(args.input)
    _, audit = load_training_data(args.input)
    print(json.dumps({"audit": asdict(audit), "sourceColumns": len(columns)}, indent=2))


if __name__ == "__main__":
    main()
