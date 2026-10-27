"""Build an ANNOTATOR-SAFE language-review worklist for Sentinel v0.3.0 Round 2.

Status: DRAFT_NOT_APPROVED. Reads ONLY the blind annotator package CSV:
  ../REVIEW_ROUND2/ANNOTATOR_PACKAGE/review_blind_opaque.csv
It never reads the mapping key, review_key.csv, samples.jsonl, splits, AI_AUDIT, or AI-assisted
proposals. The output therefore carries no author label, category, split, AI label, AI confidence,
or translation — only the opaque review ID, row order, a script/language guess derived from the
visible text, and blank columns for a fluent human reviewer.

The language guess is a heuristic (script + common function words), not an official label.
Output: ./language_review_worklist_ANNOTATOR_SAFE_v0.1.csv

Usage (from repo root): python ml/datasets/sentinel/v0.3.0/POLICY_ADJUDICATION/build_language_worklist.py
"""
from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
BLIND = HERE.parent / "REVIEW_ROUND2" / "ANNOTATOR_PACKAGE" / "review_blind_opaque.csv"
OUT = HERE / "language_review_worklist_ANNOTATOR_SAFE_v0.1.csv"

DEVANAGARI = re.compile(r"[ऀ-ॿ]")
DE = re.compile(r"\b(Sie|Bitte|und|der|die|den|das|niemals|Ihr|Ihre|mit|auf|über|alle|Anhang|enthält|Geben)\b|[äöüß]", re.I)
ES = re.compile(r"\b(el|la|las|los|por|favor|y|nunca|con|para|una|del|este|esta|todas|anteriores|resume|Escribe|Ignora|Revela|Nota)\b|[ñ¿¡áéíóú]", re.I)
EN = re.compile(r"\b(the|and|of|to|your|this|with|for)\b", re.I)

FIELDS = ["review_order", "review_id", "script_language_guess",
          "fluent_reviewer_language_confirmed", "meaning_clear_yes_no", "natural_wording_yes_no",
          "fluent_reviewer_language_quality", "fluent_reviewer_note", "worklist_status"]
FORBIDDEN_HEADER = re.compile(r"label|categor|split|author|sample_id|confidence|proposed|ai_", re.I)


def guess(text: str) -> str | None:
    if DEVANAGARI.search(text):
        return "hi (Devanagari)"
    de, es, en = len(DE.findall(text)), len(ES.findall(text)), len(EN.findall(text))
    if max(de, es) == 0 or en >= max(de, es):
        return None
    return "de" if de > es else "es"


def main() -> int:
    blind = list(csv.DictReader(BLIND.open(encoding="utf-8", newline="")))
    rows = []
    for b in blind:
        g = guess(b["text"])
        if g:
            rows.append({"review_order": b["review_order"], "review_id": b["review_id"],
                         "script_language_guess": g,
                         "fluent_reviewer_language_confirmed": "", "meaning_clear_yes_no": "",
                         "natural_wording_yes_no": "", "fluent_reviewer_language_quality": "",
                         "fluent_reviewer_note": "",
                         "worklist_status": "NEEDS_FLUENT_HUMAN_REVIEW_NOT_APPROVED"})
    # Safety assertions: header and content must not carry labels, splits, or dataset IDs.
    assert not any(FORBIDDEN_HEADER.search(h) for h in FIELDS if h not in {"fluent_reviewer_language_quality"}), "forbidden column"
    blob = "\n".join(",".join(r.values()) for r in rows)
    assert not re.search(r"sen-\d{4}", blob), "dataset sample ID leaked"
    assert not re.search(r"\b(benign|suspicious|train|validation|test)\b", blob), "label/split word leaked"
    with OUT.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"blind_rows={len(blind)} non_english_rows={len(rows)} by_guess={dict(sorted(Counter(r['script_language_guess'] for r in rows).items()))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
