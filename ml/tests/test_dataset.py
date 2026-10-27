import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.schema import load_dataset, validate_sample  # noqa: E402
from sentinel.split import check_no_group_crossing, leakage_checks, split_dataset  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "datasets" / "sentinel" / "v0.1.0" / "samples.jsonl"


def load():
    samples, errors = load_dataset(DATASET)
    assert errors == [], errors
    return samples


def test_dataset_is_valid_and_balanced_enough():
    samples = load()
    assert len(samples) >= 50
    labels = {s["label"] for s in samples}
    assert labels == {"benign", "suspicious"}
    hard_benign = [s for s in samples if s["label"] == "benign" and s["is_quoted_or_discussed"]]
    assert len(hard_benign) >= 8


def test_validator_rejects_bad_samples():
    good = load()[0]
    assert validate_sample({**good, "label": "maybe"}) != []
    assert validate_sample({**good, "label": "suspicious", "attack_category": None}) != []
    assert validate_sample({**good, "text": "x" * 4001}) != []


def test_no_group_crossing_and_no_exact_leakage():
    samples = load()
    splits = split_dataset(samples)
    assert check_no_group_crossing(splits) == []
    report = leakage_checks(samples, splits)
    assert report["exact_duplicate_cross_split"] == []
    assert set(splits) == {"train", "validation", "test"}
    assert all(splits[name] for name in splits)


def test_split_is_deterministic():
    samples = load()
    first = {k: [r["sample_id"] for r in v] for k, v in split_dataset(samples).items()}
    second = {k: [r["sample_id"] for r in v] for k, v in split_dataset(samples).items()}
    assert first == second


V2 = ROOT / "datasets" / "sentinel" / "v0.2.0" / "samples.jsonl"


def test_v02_expansion_integrity():
    if not V2.exists():
        return
    samples, errors = load_dataset(V2)
    assert errors == [], errors[:5]
    assert len(samples) >= 400
    # v0.1 IDs and labels preserved verbatim as a subset.
    v1 = {s["sample_id"]: s for s in load()}
    for sample_id, old in v1.items():
        new = next(s for s in samples if s["sample_id"] == sample_id)
        assert new["text"] == old["text"] and new["label"] == old["label"]
    splits = split_dataset(samples)
    assert check_no_group_crossing(splits) == []
    report = leakage_checks(samples, splits)
    assert report["exact_duplicate_cross_split"] == []
    # Generated samples must be honestly marked unreviewed.
    generated = [s for s in samples if s.get("generation_method")]
    assert generated and all(s["review_status"] == "unreviewed" and s["independent_review"] is False for s in generated)


def test_review_queue_covers_generated_samples():
    queue = V2.parent / "REVIEW_QUEUE.csv"
    if not queue.exists():
        return
    lines = queue.read_text(encoding="utf-8").strip().splitlines()
    samples, _ = load_dataset(V2)
    generated = [s for s in samples if s.get("generation_method")]
    assert len(lines) - 1 == len(generated)


def test_v03_quality_gate():
    v3 = ROOT / "datasets" / "sentinel" / "v0.3.0" / "samples.jsonl"
    if not v3.exists():
        return
    samples, errors = load_dataset(v3)
    assert errors == []
    assert len(samples) == 554
    splits = split_dataset(samples)
    assert check_no_group_crossing(splits) == []
    report = leakage_checks(samples, splits)
    assert report["near_duplicate_cross_split"] == []
    curated = [s for s in samples if s["group_id"].startswith("g3-")]
    assert len(curated) == 50
    assert all(s["review_status"] == "unreviewed" and s["independent_review"] is False for s in curated)
    cats = {s["attack_category"] for s in samples if s["attack_category"]}
    assert {"other_suspicious", "impersonation"} <= cats
    pkg = v3.parent / "REVIEW_PACKAGE"
    blind = (pkg / "review_blind.csv").read_text(encoding="utf-8")
    assert "author_label" not in blind.splitlines()[0]
    assert (pkg / "INSTRUCTIONS.md").exists() and (pkg / "review_key.csv").exists()


def test_frozen_split_files_match_regeneration_when_present():
    manifest_path = DATASET.parent / "splits" / "split_manifest.json"
    if not manifest_path.exists():
        return
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    splits = split_dataset(load())
    assert manifest["counts"] == {k: len(v) for k, v in splits.items()}
