import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.intake import BLIND, validate_completed  # noqa: E402


def _completed(tmp_path: Path, mutate=None) -> Path:
    rows = list(csv.DictReader(BLIND.open(encoding="utf-8")))
    for row in rows:
        row["independent_label"] = "benign"
        row["independent_attack_category"] = ""
        row["confidence_0_1"] = "0.9"
        row["annotator_id"] = "test-reviewer"
        row["reviewed_at"] = "2026-10-26"
    if mutate:
        mutate(rows)
    path = tmp_path / "completed.csv"
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return path


def test_intake_accepts_a_complete_valid_file(tmp_path):
    _, errors = validate_completed(_completed(tmp_path))
    assert errors == []


def test_intake_rejects_missing_unknown_and_invalid(tmp_path):
    def mutate(rows):
        rows.pop()  # incomplete
        rows[0]["independent_label"] = "maybe"
        rows[1]["sample_id"] = "sen-9999"

    _, errors = validate_completed(_completed(tmp_path, mutate))
    joined = " | ".join(errors)
    assert "incomplete" in joined
    assert "independent_label" in joined
    assert "unknown sample_id" in joined


def test_intake_rejects_text_tampering_and_missing_annotator(tmp_path):
    def mutate(rows):
        rows[0]["text"] = "tampered text"
        rows[1]["annotator_id"] = ""

    _, errors = validate_completed(_completed(tmp_path, mutate))
    joined = " | ".join(errors)
    assert "text differs" in joined
    assert "annotator_id" in joined


def test_real_blind_file_is_still_unannotated():
    rows = list(csv.DictReader(BLIND.open(encoding="utf-8")))
    assert rows and all(not r["independent_label"] for r in rows), (
        "Blind package must stay unannotated until a real annotator returns it"
    )
