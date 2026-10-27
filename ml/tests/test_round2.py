import csv
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.intake_round2 import ANN as ANN_FILE, validate_round2  # noqa: E402

ANN = ANN_FILE.parent
PKG = ANN.parent
ADJ = PKG / "ADJUDICATOR_ONLY"


def _annotator_text() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in ANN.iterdir() if p.is_file())


def test_annotator_package_has_no_leaks():
    assert ANN.exists() and ADJ.exists()
    assert not (ANN / "mapping_key.csv").exists()
    blob = _annotator_text()
    assert not re.search(r"sen-\d{4}", blob), "original sample ID leaked into annotator package"
    assert "author_label" not in blob


def test_annotator_package_has_no_split_or_category_columns():
    rows = list(csv.DictReader((ANN / "review_blind_opaque.csv").open(encoding="utf-8")))
    assert rows
    headers = list(rows[0].keys())
    assert not any("split" in h or "author" in h or "sample_id" == h for h in headers)
    assert all(re.fullmatch(r"rv-[a-z0-9]{10}", r["review_id"]) for r in rows)
    assert len({r["review_id"] for r in rows}) == len(rows)
    assert all(not r["independent_label"] for r in rows), "package must ship unannotated"


def test_mapping_key_is_separate_and_complete():
    mapping = list(csv.DictReader((ADJ / "mapping_key.csv").open(encoding="utf-8")))
    rows = list(csv.DictReader((ANN / "review_blind_opaque.csv").open(encoding="utf-8")))
    assert {m["review_id"] for m in mapping} == {r["review_id"] for r in rows}
    assert all(m["sample_id"].startswith("sen-") for m in mapping)


def _completed(tmp_path: Path, mutate=None) -> Path:
    rows = list(csv.DictReader(ANN_FILE.open(encoding="utf-8")))
    for row in rows:
        row["independent_label"] = "benign"
        row["confidence_0_1"] = "0.9"
        row["language_quality"] = "ok"
        row["annotator_id"] = "test-reviewer"
        row["reviewed_at"] = "2026-10-26"
    if mutate:
        mutate(rows)
    path = tmp_path / "done.csv"
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return path


def test_intake_round2_accepts_and_rejects(tmp_path):
    _, errors = validate_round2(_completed(tmp_path))
    assert errors == []

    def mutate(rows):
        rows.pop()
        rows[0]["review_id"] = "rv-unknown00"
        rows[1]["independent_label"] = "maybe"
        rows[2]["text"] = "tampered"

    _, errors = validate_round2(_completed(tmp_path, mutate))
    joined = " | ".join(errors)
    assert "incomplete" in joined and "unknown review_id" in joined
    assert "independent_label" in joined and "text differs" in joined
