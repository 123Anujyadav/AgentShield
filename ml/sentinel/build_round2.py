"""Build the Round-2 opaque-ID blind review package.

Opaque IDs are CSPRNG-generated (secrets module), encode nothing, and are
mapped to sample IDs only inside ADJUDICATOR_ONLY/. The annotator package
never contains sample IDs, author labels, categories, or split membership.
Selection reuses the Round-1 stratified ID set (no split files are read).
"""
from __future__ import annotations

import csv
import json
import secrets
import string
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "datasets" / "sentinel" / "v0.3.0" / "REVIEW_ROUND2"
ANN = PKG / "ANNOTATOR_PACKAGE"
ADJ = PKG / "ADJUDICATOR_ONLY"
SRC_PKG = ROOT / "datasets" / "sentinel" / "v0.3.0" / "REVIEW_PACKAGE"
DATASET = ROOT / "datasets" / "sentinel" / "v0.3.0" / "samples.jsonl"

samples = {json.loads(l)["sample_id"]: json.loads(l) for l in DATASET.read_text(encoding="utf-8").splitlines() if l.strip()}
selected_ids = [r["sample_id"] for r in csv.DictReader((SRC_PKG / "review_key.csv").open(encoding="utf-8"))]

alphabet = string.ascii_lowercase + string.digits
used: set[str] = set()
def opaque_id() -> str:
    while True:
        candidate = "rv-" + "".join(secrets.choice(alphabet) for _ in range(10))
        if candidate not in used:
            used.add(candidate)
            return candidate

rows = []
for sid in selected_ids:
    rows.append({"opaque_id": opaque_id(), "sample": samples[sid]})
secrets.SystemRandom().shuffle(rows)

ANN.mkdir(parents=True, exist_ok=True)
ADJ.mkdir(parents=True, exist_ok=True)
with (ANN / "review_blind_opaque.csv").open("w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["review_order", "review_id", "text", "independent_label", "independent_attack_category",
                "confidence_0_1", "uncertainty_note", "language_quality", "annotator_id", "reviewed_at"])
    for i, r in enumerate(rows, 1):
        w.writerow([i, r["opaque_id"], r["sample"]["text"], "", "", "", "", "", "", ""])

# Adjudicator-only mapping. Never copy this file into the annotator package.
with (ADJ / "mapping_key.csv").open("w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["review_id", "sample_id", "author_label", "author_attack_category",
                "agreement", "adjudicated_label", "adjudication_rationale"])
    for r in rows:
        w.writerow([r["opaque_id"], r["sample"]["sample_id"], r["sample"]["label"],
                    r["sample"]["attack_category"] or "", "", "", ""])

guide = (SRC_PKG / "REVIEWER_GUIDE.md").read_text(encoding="utf-8")
(ANN / "REVIEWER_GUIDE.md").write_text(guide, encoding="utf-8")
(ANN / "INSTRUCTIONS.md").write_text(
    "# Round 2 — Independent Annotation (Opaque IDs)\n\n"
    "You receive only this folder. Each row has a random review ID that means nothing.\n\n"
    "Rules:\n"
    "- Work from `review_blind_opaque.csv` and `REVIEWER_GUIDE.md` in this folder only.\n"
    "- Do **not** search for these texts online, in any dataset, or in any repository, and do not consult original labels or sample lists. Searching would break the blindness this round exists to protect.\n"
    "- Fill independent_label (benign/suspicious), independent_attack_category (only when suspicious), confidence_0_1, uncertainty_note, language_quality (`ok`, `uncertain`, or `cannot-judge`), annotator_id (initials/role you choose), and reviewed_at (ISO date).\n"
    "- If you cannot judge a row's language, set language_quality to `cannot-judge` and say so in uncertainty_note instead of guessing.\n"
    "- Return the CSV with its structure unchanged. Validation runs before anyone joins your answers to the key.\n",
    encoding="utf-8")
from collections import Counter
print(f"rows={len(rows)} unique_opaque={len(used)}")
print(f"selection is the Round-1 stratified set: {len(selected_ids)} samples (categories/languages held in key only)")
print(f"annotator files: {[p.name for p in ANN.iterdir()]}")
