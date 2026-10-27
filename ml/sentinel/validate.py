"""CLI: validate the Sentinel v0.1 dataset. Usage: python -m sentinel.validate [path]"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.schema import load_dataset  # noqa: E402


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "datasets" / "sentinel" / "v0.1.0" / "samples.jsonl"
    samples, errors = load_dataset(path)
    labels: dict[str, int] = {}
    for s in samples:
        labels[s["label"]] = labels.get(s["label"], 0) + 1
    print(f"samples={len(samples)} labels={labels} errors={len(errors)}")
    for error in errors:
        print(f"ERROR: {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
