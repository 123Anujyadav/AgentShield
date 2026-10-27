"""Build the PROPOSED policy-adjudication report (v0.1) for Sentinel v0.3.0 Round 2.

Status: PROPOSED_NOT_APPROVED. Read-only inputs. Writes only into this folder.
Inputs:
  ../AI_ASSISTED_REVIEW_ROUND2/proposed_review_AI_ASSISTED_NOT_HUMAN_ANNOTATION.csv
     (AI proposals: AI_ASSISTED_NOT_HUMAN_ANNOTATION; IDs and text are copied from the blind package)
  ./report_template_v0.1.md
Outputs:
  ./POLICY_ADJUDICATION_PROPOSAL_v0.1.md
  ./policy_decision_table_v0.1.csv
It never reads the mapping key, review_key.csv, samples.jsonl, splits, or AI_AUDIT files.
Affected-row detection = AI proposal citations + documented text patterns + a short manual list.
It is NOT exhaustive and assigns no labels.

Usage (from repo root): python ml/datasets/sentinel/v0.3.0/POLICY_ADJUDICATION/build_policy_report.py
"""
from __future__ import annotations

import csv
import hashlib
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROPOSED = HERE.parent / "AI_ASSISTED_REVIEW_ROUND2" / "proposed_review_AI_ASSISTED_NOT_HUMAN_ANNOTATION.csv"
TEMPLATE = HERE / "report_template_v0.1.md"
REPORT = HERE / "POLICY_ADJUDICATION_PROPOSAL_v0.1.md"
TABLE = HERE / "policy_decision_table_v0.1.csv"
STATUS = "PROPOSED_NOT_APPROVED"
VERSION = "v0.1"

# Self-described / reported embedded-instruction markers (Q5). Case-insensitive.
Q5_PATTERN = re.compile(
    r"embedded line|injected into|planted|inserted later|buried line|added by an integration|"
    r"repeated in footer|hidden in the footer|footer tells", re.I)
# Manual additions (AI-identified, documented in the report): label could change across Q2 options
# although the AI proposal did not cite Q2.
MANUAL = {
    "Q2": {"rv-5r4xzxuq5j": "secret-disclosure request with a plausible user pretext; provenance decides",
           "rv-xq17dueh3c": "same pattern as rv-5r4xzxuq5j (configuration disclosure)"},
}
DEVANAGARI = re.compile(r"[ऀ-ॿ]")
DE_ES = re.compile(r"\b(Sie|Bitte|und|der|die|den|niemals|Ihr|el|la|las|los|por favor|Por favor|y|nunca|Nunca|Escribe|resume|"
                   r"Ignora|Revela|Nota|ihr|mit|auf|para|una|del)\b|[äöüßñ¿¡]")

ROW_RULES = [  # (question, fields to reconsider)
    ("Q1", "label (decision convention)"),
    ("Q2", "label"),
    ("Q3", "category"),
    ("Q4", "category"),
    ("Q5", "label + category"),
    ("Q6", "label"),
    ("Q7", "category"),
    ("Q8", "uncertainty_note / language_quality form"),
    ("LANG", "language_quality + native-speaker routing"),
]


def lang_of(text: str) -> str:
    if DEVANAGARI.search(text):
        return "hi"
    if DE_ES.search(text):
        return "de/es"
    return "en"


def main() -> int:
    rows = list(csv.DictReader(PROPOSED.open(encoding="utf-8", newline="")))
    assert len(rows) == 196, len(rows)
    by_id = {r["review_id"]: r for r in rows}
    flags: dict[str, dict[str, str]] = {r["review_id"]: {} for r in rows}

    def add(q: str, rid: str, src: str) -> None:
        prev = flags[rid].get(q)
        flags[rid][q] = src if not prev else (prev if src in prev else prev + "+" + src)

    for r in rows:
        rid, cited = r["review_id"], set(filter(None, r["policy_question_ids"].split(";")))
        conf = float(r["proposed_confidence_0_1"])
        nonen = lang_of(r["text"]) != "en"
        if r["adjudication_required"] == "yes":
            add("Q1", rid, "adjudication_required")
        if r["adjudication_required"] == "no" and conf < 0.7:
            add("Q1", rid, "confidence<0.7")
        for q in ("Q2", "Q3", "Q4", "Q5", "Q6", "Q7"):
            if q in cited:
                add(q, rid, "cited")
        if r["proposed_label"] == "suspicious" and r["alternative_categories"]:
            add("Q3", rid, "alternatives")
        if Q5_PATTERN.search(r["text"]):
            add("Q5", rid, "pattern")
        if r["proposed_attack_category"] == "other_suspicious":
            add("Q7", rid, "category=other_suspicious")
        if nonen:
            add("LANG", rid, "non-English")
            add("Q8", rid, "language note convention")
            if r["proposed_label"] == "suspicious" or r["adjudication_required"] == "yes":
                add("Q4", rid, "non-English suspicious")
    for q, m in MANUAL.items():
        for rid in m:
            add(q, rid, "manual")

    def ids(q: str, pred=lambda s: True) -> list[str]:
        return [r["review_id"] for r in rows if q in flags[r["review_id"]] and pred(flags[r["review_id"]][q])]

    def fmt(idl: list[str]) -> str:
        return ", ".join(f"`{i}` (#{by_id[i]['review_order']})" for i in idl) or "_none_"

    def ex(rid: str) -> str:
        t = by_id[rid]["text"]
        t = t if len(t) <= 150 else t[:147] + "…"
        return f"`{rid}` (#{by_id[rid]['review_order']}): “{t}”"

    nonen_ids = ids("LANG")
    q5_all = ids("Q5")
    q5_adj = [i for i in q5_all if by_id[i]["adjudication_required"] == "yes"]
    q5_cited_lab = [i for i in q5_all if "cited" in flags[i]["Q5"] and by_id[i]["adjudication_required"] == "no"]
    q5_pattern_only = [i for i in q5_all if "cited" not in flags[i]["Q5"]]
    adj7 = [r["review_id"] for r in rows if r["adjudication_required"] == "yes"]
    lowconf = ids("Q1", lambda s: "confidence" in s)
    note_flag = [r["review_id"] for r in rows if "language-uncertain" in r["uncertainty_note"].lower()]

    # ---------- per-row decision table ----------
    out = []
    for r in rows:
        f = flags[r["review_id"]]
        qs = [q for q, _ in ROW_RULES if q in f]
        out.append({
            "review_order": r["review_order"], "review_id": r["review_id"],
            "text_excerpt": r["text"][:90],
            "ai_proposed_label": r["proposed_label"] or "(adjudication_required)",
            "ai_proposed_category": r["proposed_attack_category"],
            "ai_alternative_categories": r["alternative_categories"],
            "ai_confidence_0_1": r["proposed_confidence_0_1"],
            "detected_language_group": lang_of(r["text"]),
            **{f"affected_{q}": f.get(q, "") for q, _ in ROW_RULES},
            "reconsider_after_rulings": ";".join(qs),
            "fields_to_reconsider": "; ".join(sorted({fld for q, fld in ROW_RULES if q in f})),
            "label_may_change": "yes" if any(q in f for q in ("Q1", "Q2", "Q5", "Q6")) else "no",
            "status": STATUS,
        })
    with TABLE.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)

    # ---------- decision summary table ----------
    label_change = [o["review_id"] for o in out if o["label_may_change"] == "yes"]
    any_flag = [o["review_id"] for o in out if o["reconsider_after_rulings"]]
    summary = ["| Ruling | Rows to reconsider | Field(s) | Re-review order |", "|---|---|---|---|"]
    order = {"Q8": 1, "LANG": 1, "Q1": 2, "Q2": 3, "Q6": 3, "Q5": 4, "Q3": 5, "Q4": 5, "Q7": 5}
    for q, fld in ROW_RULES:
        summary.append(f"| {q} | {len(ids(q))} | {fld} | step {order[q]} |")
    summary.append(f"| **Any label-affecting ruling (Q1/Q2/Q5/Q6)** | **{len(label_change)}** | label | after steps 2–4 |")
    summary.append(f"| **Any ruling at all** | **{len(any_flag)}** | see CSV | — |")

    with_inputs = {
        "PROPOSED_SHA": hashlib.sha256(PROPOSED.read_bytes()).hexdigest(),
        "N_ROWS": str(len(rows)),
        "ADJ7": fmt(adj7), "LOWCONF": fmt(lowconf),
        "Q1_N": str(len(ids("Q1"))), "Q1": fmt(ids("Q1")),
        "Q2_N": str(len(ids("Q2"))), "Q2": fmt(ids("Q2")),
        "Q2_MANUAL": fmt(list(MANUAL["Q2"])),
        "Q3_N": str(len(ids("Q3"))), "Q3": fmt(ids("Q3")),
        "Q4_N": str(len(ids("Q4"))), "Q4": fmt(ids("Q4")),
        "Q5_N": str(len(q5_all)), "Q5_ADJ_N": str(len(q5_adj)), "Q5_ADJ": fmt(q5_adj),
        "Q5_LAB_N": str(len(q5_cited_lab)), "Q5_LAB": fmt(q5_cited_lab),
        "Q5_PAT_N": str(len(q5_pattern_only)), "Q5_PAT": fmt(q5_pattern_only),
        "Q6_N": str(len(ids("Q6"))), "Q6": fmt(ids("Q6")),
        "Q7_N": str(len(ids("Q7"))), "Q7": fmt(ids("Q7")),
        "NONEN_N": str(len(nonen_ids)), "NONEN": fmt(nonen_ids),
        "NOTE_FLAG_N": str(len(note_flag)),
        "NOTE_MATCH": "yes" if set(note_flag) == set(nonen_ids) else "NO (see CSV)",
        "LANG_OK_N": str(sum(by_id[i]["proposed_language_quality"] == "ok" for i in nonen_ids)),
        "LABEL_CHANGE_N": str(len(label_change)), "ANY_N": str(len(any_flag)),
        "SUMMARY_TABLE": "\n".join(summary),
    }
    text = TEMPLATE.read_text(encoding="utf-8")
    for rid in re.findall(r"\{\{EX:(rv-[a-z0-9]{10})\}\}", text):
        text = text.replace("{{EX:" + rid + "}}", ex(rid))
    for k, v in with_inputs.items():
        text = text.replace("{{" + k + "}}", v)
    left = re.findall(r"\{\{[^}]+\}\}", text)
    assert not left, f"unfilled placeholders: {left}"
    REPORT.write_text(text, encoding="utf-8", newline="\n")
    print(f"rows={len(rows)} non_english={len(nonen_ids)} q5_total={len(q5_all)} (adj={len(q5_adj)} cited_labelled={len(q5_cited_lab)} pattern_only={len(q5_pattern_only)})")
    for q, _ in ROW_RULES:
        print(f"{q}={len(ids(q))}")
    print(f"label_may_change={len(label_change)} any_ruling={len(any_flag)} status={STATUS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
