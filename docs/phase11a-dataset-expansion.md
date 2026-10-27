# Phase 11A-2.5 — Dataset Expansion & Independent Review Preparation

Date: 2026-10-26. Offline only. No weights downloaded, no fine-tuning, no external
API calls, no credits consumed, no production code or `.env` changed.

## Actual final counts (measured, not targets)

Dataset `sentinel-v0.2.0`: **504 samples** — benign 237, suspicious 267.
Languages: English 480, Spanish 8, German 8, Hindi 8.
Attack categories: indirect 92, direct 69, tool_redirect 35, obfuscated 28,
exfiltration 19, impersonation 15, other 9, plus preserved v0.1 distribution.
Splits (group-aware 70/15/15, seed 20261026): train 345, validation 80, test 79
(298 groups total; test is the new frozen held-out set for this version).

The first 64 samples are the v0.1.0 samples with IDs, texts, labels, and
provenance preserved verbatim (an automated test asserts this). No v0.1 label
was changed; `CHANGELOG.md` in the dataset directory records that no label
corrections are proposed yet and that any future correction must be logged
there with rationale first.

## How examples were created and reviewed

440 new samples were produced by the deterministic generator
`ml/sentinel/generate_expansion.py` from curated banks: ordinary tasks across
domains, education/incident/advice hard benign, direct/indirect/impersonation/
exfiltration/tool-redirect/other injections, real base64/leetspeak/spacing/
unicode transforms, context-varied second batches, and hand-written
Spanish/German/Hindi samples.

Honest quality statement: template/combinatorial generation was chosen to reach
several hundred samples in this phase. It produces surface-pattern repetition
across samples. That is a diversity limitation, not hidden: every generated
sample carries `generation_method`, a `rationale`, `review_status=unreviewed`,
and `independent_review=false`.

Review workflow (deliverable, not completed review): `REVIEW_QUEUE.csv` lists
all 440 generated samples with empty second-annotator, agreement, and
adjudication columns. A real second annotator (not the author, not an LLM)
must complete it using the workflow in `LABELLING_GUIDE.md`; disagreements are
adjudicated and recorded before any `review_status` changes. **No independent
review has occurred.** Until it does, labels in v0.2 are single-author.

## Integrity results (actually run)

Commands:

```powershell
python ml/sentinel/generate_expansion.py
python ml/sentinel/validate.py ml/datasets/sentinel/v0.2.0/samples.jsonl
python ml/sentinel/split.py v0.2.0
python -m pytest ml/tests -q
node ml/baselines/scan_dataset.mjs validation v0.2.0
python ml/baselines/run_baselines.py v0.2.0
npm test
```

Results:

- Validator: `samples=504 labels={'benign': 237, 'suspicious': 267} errors=0`.
- Group crossing: **0**. Exact normalized-duplicate cross-split: **0**.
  Token-Jaccard (≥0.9) near-duplicate cross-split: **0** after template
  families were assigned shared `group_id`s (the first split attempt flagged
  many; grouping was fixed in the generator and the check now passes).
- Character 5-gram near cross-split: **15 pairs** remain. These are different
  template slots with high character overlap (for example education frames with
  different quoted payloads). They are reported, not hidden, and are the main
  residual leakage-adjacent risk. Semantic duplicate detection was not used
  because it would require downloading an embedding model (out of scope).
- `python -m pytest ml/tests -q` → **7 passed** (includes v0.2 size ≥400,
  v0.1 preservation, generated-sample honest marking, and review-queue coverage).
- `npm test` → **72 passed** (engine 28, API 44). Production regression intact.

## Baseline re-evaluation on v0.2 (validation only, test untouched)

Rule scanner (validation, n=80): accuracy 0.6375, suspicious precision 0.933,
recall 0.333, F1 0.491, benign FPR 0.026. Indirect and impersonation recall in
this validation slice were 0.0 — the expanded indirect phrasings largely evade
the sentence-anchored rules. This is a scanner finding about expanded coverage,
not a claim that the scanner regressed; the validation set changed.

TF-IDF + Logistic Regression (train-only fit, threshold 0.45 selected on
validation): validation accuracy 0.90, suspicious P/R/F1 0.870/0.952/0.909,
benign FPR 0.158, hard-benign FPR 0.222 (n=18). Better than v0.1's validation
numbers, but the validation set is different and largely template-generated, so
this must not be read as "the model improved" in any general sense. Template
families make TF-IDF's job artificially easier. The frozen test split was not
read (`test_split_used: false`, and the scanner script refuses `test`).

## Remaining limitations

- Single-author labels; independent review is prepared but not done. Borderline
  template samples may contain systematic author bias, and the Spanish/German/
  Hindi slices (8 each) were written by the author, not native-speaker reviewed.
- Template repetition: families share phrasing, so validation metrics overstate
  generalization to genuinely novel attacks. 15 char-level near pairs persist.
- `other_suspicious` (9) and `impersonation` (15) remain thin categories.
- The relation/intent-mismatch task from the Phase 11 taxonomy is still not
  represented in this content-classification dataset.

## Readiness and recommendation

The dataset **is ready for baseline re-evaluation** (done above) and for use as
a development benchmark. It is **not ready to justify fine-tuning claims** until
(1) a real second annotator completes at least a stratified review sample and
disagreements are adjudicated, and (2) a fresh growth batch adds non-template,
authored diversity, especially for thin categories.

Recommended next step (needs approval): commission the second-annotator review
of a stratified sample of the queue (for example all hard-benign plus a random
20% of the rest), adjudicate, publish agreement statistics in a v0.2.1 patch,
and only then decide whether to request Phase 11A-3 (DeBERTa weight download).
