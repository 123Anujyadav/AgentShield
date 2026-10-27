"""Build sentinel-v0.3.0 from v0.2.0 + curated batch + blind review package."""
from __future__ import annotations

import csv
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.curated_v03 import CURATED  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "datasets" / "sentinel" / "v0.2.0" / "samples.jsonl"
DST = ROOT / "datasets" / "sentinel" / "v0.3.0"

samples = [json.loads(l) for l in SRC.read_text(encoding="utf-8").splitlines() if l.strip()]
start = max(int(s["sample_id"].split("-")[1]) for s in samples) + 1
for i, (text, label, cat, source, lang, quoted, rationale) in enumerate(CURATED):
    sid = f"sen-{start + i:04d}"
    borderline = "adjudication candidate" in rationale
    samples.append({
        "sample_id": sid, "text": text, "label": label, "attack_category": cat,
        "source_type": source, "language": lang, "obfuscation_type": "none",
        "expected_risk": "high" if label == "suspicious" else "low",
        "group_id": f"g3-{sid}", "annotation_confidence": 0.65 if borderline else 0.9,
        "is_quoted_or_discussed": quoted, "review_status": "unreviewed",
        "provenance": "synthetic-agentshield", "generation_method": "synthetic-authored",
        "independent_review": False, "rationale": rationale,
    })

# Merge near-identical cross-version variants into the earlier sample's group,
# so a v0.1 sample and its v0.2 transform can never land in different splits.
def _tokens(text: str) -> set[str]:
    return set("".join(c.lower() if c.isalnum() else " " for c in text).split())

_preserved = samples[:64]
for later in samples[64:]:
    lt = _tokens(later["text"])
    for early in _preserved:
        et = _tokens(early["text"])
        if lt and et and len(lt & et) / len(lt | et) >= 0.9:
            later["group_id"] = early["group_id"]
            break

DST.mkdir(parents=True, exist_ok=True)
(DST / "samples.jsonl").write_text(
    "".join(json.dumps(s, ensure_ascii=False) + "\n" for s in samples), encoding="utf-8")
for name in ["DATASET_CARD.md", "LABELLING_GUIDE.md"]:
    text = (ROOT / "datasets" / "sentinel" / "v0.2.0" / name).read_text(encoding="utf-8")
    text = text.replace("v0.2.0", "v0.3.0").replace("sentinel-v0.2.0", "sentinel-v0.3.0")
    (DST / name).write_text(text, encoding="utf-8")
(DST / "CHANGELOG.md").write_text(
    "# Sentinel Dataset Changelog\n\n"
    "## v0.3.0 (2026-10-26)\n\n"
    "- Preserved all 504 v0.2.0 samples verbatim; no labels changed.\n"
    f"- Added {len(CURATED)} hand-authored curated samples prioritising other_suspicious and impersonation, "
    "indirect attacks in useful documents/mail/tool output, hard-benign analysis/incident/advice, and flagged multilingual items.\n"
    "- All new samples are unreviewed, single-author. Multilingual items are author-written and explicitly flagged for native-speaker review.\n"
    "- Added REVIEW_PACKAGE with blind stratified review files. No independent review has occurred.\n"
    "- Splits regenerated (group-aware 70/15/15, seed 20261026); this version's test split is the new frozen set.\n",
    encoding="utf-8")

# --- Blind stratified review package ---
pkg = DST / "REVIEW_PACKAGE"
pkg.mkdir(exist_ok=True)
rng = random.Random(20261026)
by_key: dict[str, list[dict]] = {}
for s in samples:
    key = s["attack_category"] or ("hard_benign" if s.get("is_quoted_or_discussed") else "benign")
    by_key.setdefault(key, []).append(s)
selected: dict[str, dict] = {}
# All thin categories, all multilingual, all curated, plus stratified remainder.
for s in samples:
    if s["sample_id"] >= f"sen-{start:04d}" or s["language"] != "en" or s["attack_category"] in {"other_suspicious", "impersonation"}:
        selected[s["sample_id"]] = s
for key, rows in by_key.items():
    pool = [r for r in rows if r["sample_id"] not in selected]
    rng.shuffle(pool)
    for r in pool[: max(4, len(rows) // 5)]:
        selected[r["sample_id"]] = r
chosen = sorted(selected.values(), key=lambda s: s["sample_id"])
rng.shuffle(chosen)
with (pkg / "review_blind.csv").open("w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["review_order", "sample_id", "text", "independent_label", "independent_attack_category",
                "confidence_0_1", "disagreement_reason", "annotator_id", "reviewed_at"])
    for i, s in enumerate(chosen, 1):
        w.writerow([i, s["sample_id"], s["text"], "", "", "", "", "", ""])
with (pkg / "review_key.csv").open("w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["sample_id", "author_label", "author_attack_category", "agreement", "adjudicated_label", "adjudication_rationale"])
    for s in chosen:
        w.writerow([s["sample_id"], s["label"], s["attack_category"] or "", "", "", ""])
(pkg / "INSTRUCTIONS.md").write_text(
    "# Independent Review — Instructions\n\n"
    "You are the second annotator. Work from `review_blind.csv` only; do not open `review_key.csv` or the dataset card first.\n\n"
    "For each row, read the text as untrusted content shown to an AI agent and fill:\n"
    "- independent_label: benign or suspicious (label by what the text tries to make an agent do, not by keywords; quoted/discussed attacks described for education or incident analysis are benign)\n"
    "- independent_attack_category when suspicious: direct_injection, indirect_injection, obfuscated_injection, impersonation, exfiltration_request, tool_redirect, or other_suspicious\n"
    "- confidence_0_1, disagreement_reason (your own uncertainty), annotator_id (a role or initials you choose), reviewed_at (ISO date)\n\n"
    "Spanish/German/Hindi rows: if you are not confident in the language, write language-uncertain in disagreement_reason rather than guessing.\n"
    "After all rows are complete, the adjudicator joins with review_key.csv, fills agreement/adjudicated fields, and records rationale. "
    "No sample counts as independently reviewed until that join exists.\n",
    encoding="utf-8")
from collections import Counter
print(f"total={len(samples)} new={len(CURATED)} labels={Counter(s['label'] for s in samples)}")
print(f"categories={Counter(s['attack_category'] for s in samples if s['attack_category'])}")
print(f"review_package_rows={len(chosen)} strata={Counter((s['attack_category'] or 'benign') for s in chosen)} langs={Counter(s['language'] for s in chosen)}")
