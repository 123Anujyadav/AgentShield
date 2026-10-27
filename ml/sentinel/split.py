"""Deterministic group-aware 70/15/15 splitter.

Groups never cross splits. Assignment is stratified by label: within each
label, groups are ordered by sha256(group_id + seed) and allocated
70% train / 15% validation / 15% test (at least one group per non-empty split
when enough groups exist).
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path

SEED = 20261026
RATIOS = (("train", 0.70), ("validation", 0.15), ("test", 0.15))


def _rank(group_id: str) -> str:
    return hashlib.sha256(f"{SEED}:{group_id}".encode()).hexdigest()


def assign_splits(samples: list[dict]) -> dict[str, str]:
    by_label: dict[str, set[str]] = defaultdict(set)
    for sample in samples:
        by_label[sample["label"]].add(sample["group_id"])

    assignment: dict[str, str] = {}
    for groups in by_label.values():
        ordered = sorted(groups, key=_rank)
        n = len(ordered)
        n_train = max(1, round(n * RATIOS[0][1])) if n >= 3 else n
        n_val = max(1, round(n * RATIOS[1][1])) if n - n_train >= 2 else 0
        for i, group in enumerate(ordered):
            if i < n_train:
                assignment[group] = "train"
            elif i < n_train + n_val:
                assignment[group] = "validation"
            else:
                assignment[group] = "test"
    return assignment


def split_dataset(samples: list[dict]) -> dict[str, list[dict]]:
    assignment = assign_splits(samples)
    out: dict[str, list[dict]] = {"train": [], "validation": [], "test": []}
    for sample in samples:
        out[assignment[sample["group_id"]]].append({**sample, "split": assignment[sample["group_id"]]})
    return out


def check_no_group_crossing(splits: dict[str, list[dict]]) -> list[str]:
    seen: dict[str, str] = {}
    errors: list[str] = []
    for split_name, rows in splits.items():
        for row in rows:
            prior = seen.setdefault(row["group_id"], split_name)
            if prior != split_name:
                errors.append(f"group {row['group_id']} appears in {prior} and {split_name}")
    return errors


def normalized_key(text: str) -> str:
    return " ".join("".join(ch.lower() if ch.isalnum() else " " for ch in text).split())


def leakage_checks(samples: list[dict], splits: dict[str, list[dict]]) -> dict:
    """Exact/normalized duplicate and near-duplicate (token Jaccard >= 0.9) cross-split check."""
    errors = check_no_group_crossing(splits)
    by_norm: dict[str, set[str]] = defaultdict(set)
    by_id_norm: dict[str, str] = {}
    for split_name, rows in splits.items():
        for row in rows:
            key = normalized_key(row["text"])
            by_norm[key].add(split_name)
            by_id_norm[row["sample_id"]] = key
    exact_cross = [k for k, v in by_norm.items() if len(v) > 1]

    # Near duplicates across different groups in different splits (same-group variants are expected).
    flat = [(row["sample_id"], row["group_id"], split, set(normalized_key(row["text"]).split()))
            for split, rows in splits.items() for row in rows]
    near_cross: list[tuple[str, str, float]] = []
    for i in range(len(flat)):
        for j in range(i + 1, len(flat)):
            a, b = flat[i], flat[j]
            if a[1] == b[1] or a[2] == b[2]:
                continue
            union = a[3] | b[3]
            if not union:
                continue
            sim = len(a[3] & b[3]) / len(union)
            if sim >= 0.9:
                near_cross.append((a[0], b[0], round(sim, 3)))
    # Character 5-gram Jaccard catches lightly edited copies token checks miss.
    def chargrams(text: str) -> set[str]:
        key = normalized_key(text).replace(" ", "")
        return {key[i:i + 5] for i in range(max(0, len(key) - 4))}

    char_near: list[tuple[str, str, float]] = []
    grams = [(sid, gid, split, chargrams(next(r["text"] for r in samples if r["sample_id"] == sid)))
             for sid, gid, split, _ in flat]
    for i in range(len(flat)):
        for j in range(i + 1, len(flat)):
            if flat[i][1] == flat[j][1] or flat[i][2] == flat[j][2]:
                continue
            a, b = grams[i][3], grams[j][3]
            if a and b and len(a & b) / len(a | b) >= 0.85:
                char_near.append((flat[i][0], flat[j][0], round(len(a & b) / len(a | b), 3)))
    return {"group_crossing_errors": errors, "exact_duplicate_cross_split": exact_cross,
            "near_duplicate_cross_split": near_cross, "char_ngram_near_cross_split": char_near}


def main() -> int:
    import sys
    version = sys.argv[1] if len(sys.argv) > 1 else "v0.1.0"
    root = Path(__file__).resolve().parents[1]
    dataset = root / "datasets" / "sentinel" / version / "samples.jsonl"
    out_dir = dataset.parent / "splits"
    out_dir.mkdir(exist_ok=True)
    samples = [json.loads(line) for line in dataset.read_text(encoding="utf-8").splitlines() if line.strip()]
    splits = split_dataset(samples)
    report = leakage_checks(samples, splits)
    for name, rows in splits.items():
        (out_dir / f"{name}.jsonl").write_text(
            "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    manifest = {
        "dataset": f"sentinel-{version}",
        "seed": SEED,
        "counts": {k: len(v) for k, v in splits.items()},
        "groups": {k: len({r["group_id"] for r in v}) for k, v in splits.items()},
        "leakage": {"group_crossing": len(report["group_crossing_errors"]),
                    "exact_duplicate_cross_split": len(report["exact_duplicate_cross_split"]),
                    "near_duplicate_cross_split": report["near_duplicate_cross_split"],
                    "char_ngram_near_cross_split": report["char_ngram_near_cross_split"]},
    }
    (out_dir / "split_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 1 if report["group_crossing_errors"] or report["exact_duplicate_cross_split"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
