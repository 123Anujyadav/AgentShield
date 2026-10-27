"""Intake validator for genuine second-annotator results.

Validates a completed blind review file BEFORE any join/adjudication.
It never creates annotations. Usage:
  python ml/sentinel/intake.py path/to/completed_review.csv
Exit 0 only when the file is complete and valid; a rejected intake changes nothing.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.schema import ATTACK_CATEGORIES, LABELS  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
BLIND = ROOT / "datasets" / "sentinel" / "v0.3.0" / "REVIEW_PACKAGE" / "review_blind.csv"


def validate_completed(completed_path: Path, blind_path: Path = BLIND) -> tuple[list[dict], list[str]]:
    errors: list[str] = []
    blind = {r["sample_id"]: r for r in csv.DictReader(blind_path.open(encoding="utf-8"))}
    rows = list(csv.DictReader(completed_path.open(encoding="utf-8")))
    seen: set[str] = set()
    for i, row in enumerate(rows, start=2):
        sid = row.get("sample_id", "")
        if sid in seen:
            errors.append(f"row {i}: duplicate sample_id {sid}")
        seen.add(sid)
        if sid not in blind:
            errors.append(f"row {i}: unknown sample_id {sid!r} (not in blind package)")
            continue
        if row.get("text") != blind[sid]["text"]:
            errors.append(f"row {i} ({sid}): text differs from blind package; sample identity is not stable")
        label = (row.get("independent_label") or "").strip()
        if label not in LABELS:
            errors.append(f"row {i} ({sid}): independent_label must be one of {sorted(LABELS)}")
        category = (row.get("independent_attack_category") or "").strip()
        if label == "suspicious" and category not in ATTACK_CATEGORIES:
            errors.append(f"row {i} ({sid}): suspicious requires a valid independent_attack_category")
        if label == "benign" and category:
            errors.append(f"row {i} ({sid}): benign must leave attack category empty")
        conf = (row.get("confidence_0_1") or "").strip()
        try:
            if not conf or not 0.0 <= float(conf) <= 1.0:
                errors.append(f"row {i} ({sid}): confidence_0_1 must be a number in [0,1]")
        except ValueError:
            errors.append(f"row {i} ({sid}): confidence_0_1 is not numeric")
        if not (row.get("annotator_id") or "").strip():
            errors.append(f"row {i} ({sid}): annotator_id missing (a self-chosen role/initials is fine)")
        if not (row.get("reviewed_at") or "").strip():
            errors.append(f"row {i} ({sid}): reviewed_at missing")
    missing = sorted(set(blind) - seen)
    if missing:
        errors.append(f"incomplete: {len(missing)} blind samples have no response (first: {missing[:3]})")
    return rows, errors


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python ml/sentinel/intake.py <completed_review.csv>")
        return 2
    rows, errors = validate_completed(Path(sys.argv[1]))
    print(f"rows={len(rows)} errors={len(errors)}")
    for error in errors[:50]:
        print(f"ERROR: {error}")
    if not errors:
        print("INTAKE OK: complete and valid. Next step is adjudication (separate, recorded), not a dataset edit.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
