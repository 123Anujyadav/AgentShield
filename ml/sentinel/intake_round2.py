"""Intake validator for Round-2 (opaque-ID) annotator returns.

Validates against the ANNOTATOR package (not the key). The mapping key is
used only later, by the adjudicator, in a separate controlled join.
Usage: python ml/sentinel/intake_round2.py path/to/completed.csv
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.schema import ATTACK_CATEGORIES, LABELS  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ANN = ROOT / "datasets" / "sentinel" / "v0.3.0" / "REVIEW_ROUND2" / "ANNOTATOR_PACKAGE" / "review_blind_opaque.csv"
LANGUAGE_QUALITY = {"ok", "uncertain", "cannot-judge", ""}


def validate_round2(completed_path: Path, blind_path: Path = ANN) -> tuple[list[dict], list[str]]:
    errors: list[str] = []
    blind = {r["review_id"]: r for r in csv.DictReader(blind_path.open(encoding="utf-8"))}
    rows = list(csv.DictReader(completed_path.open(encoding="utf-8")))
    seen: set[str] = set()
    for i, row in enumerate(rows, start=2):
        rid = row.get("review_id", "")
        if rid in seen:
            errors.append(f"row {i}: duplicate review_id {rid}")
        seen.add(rid)
        if rid not in blind:
            errors.append(f"row {i}: unknown review_id {rid!r}")
            continue
        if row.get("text") != blind[rid]["text"]:
            errors.append(f"row {i} ({rid}): text differs from annotator package; identity is not stable")
        label = (row.get("independent_label") or "").strip()
        if label not in LABELS:
            errors.append(f"row {i} ({rid}): independent_label must be one of {sorted(LABELS)}")
        category = (row.get("independent_attack_category") or "").strip()
        if label == "suspicious" and category not in ATTACK_CATEGORIES:
            errors.append(f"row {i} ({rid}): suspicious requires a valid category")
        if label == "benign" and category:
            errors.append(f"row {i} ({rid}): benign must leave category empty")
        conf = (row.get("confidence_0_1") or "").strip()
        try:
            if not conf or not 0.0 <= float(conf) <= 1.0:
                errors.append(f"row {i} ({rid}): confidence_0_1 must be in [0,1]")
        except ValueError:
            errors.append(f"row {i} ({rid}): confidence_0_1 is not numeric")
        if (row.get("language_quality") or "").strip() not in LANGUAGE_QUALITY:
            errors.append(f"row {i} ({rid}): language_quality must be ok, uncertain, or cannot-judge")
        if not (row.get("annotator_id") or "").strip():
            errors.append(f"row {i} ({rid}): annotator_id missing")
        if not (row.get("reviewed_at") or "").strip():
            errors.append(f"row {i} ({rid}): reviewed_at missing")
    missing = sorted(set(blind) - seen)
    if missing:
        errors.append(f"incomplete: {len(missing)} review rows have no response (first: {missing[:3]})")
    return rows, errors


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python ml/sentinel/intake_round2.py <completed.csv>")
        return 2
    rows, errors = validate_round2(Path(sys.argv[1]))
    # Never log sample text, author labels, or the mapping. Counts and IDs of errors only.
    print(f"rows={len(rows)} errors={len(errors)}")
    for error in errors[:50]:
        print(f"ERROR: {error}")
    if not errors:
        print("INTAKE OK: Round-2 return is complete and valid. Adjudicator may now perform the controlled join.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
