# Phase 11A-2.7 — Dataset Quality Gate & Independent Review Preparation

Date: 2026-10-26. Offline only. No weights downloaded, no training, no external
API calls, no credits consumed, no production code or `.env` changed.

## Decision

**Additional review required — not ready for model-training approval.**

Reasons: (1) no real independent annotator has reviewed anything; the review
gate is prepared but open. (2) TF-IDF benign FPR on the new validation set is
0.182 (hard-benign 0.211), far above the proposed 0.05 target, and template
families still dominate the corpus. Approving fine-tuning now would bake
single-author, partly template-shaped labels into a model and overstate the
result.

## 1. Dataset version and distribution (measured)

`sentinel-v0.3.0`: **554 samples** — benign 252, suspicious 302.
Categories: indirect 103, direct 69, tool_redirect 35, obfuscated 28,
impersonation 27, exfiltration 19, other_suspicious 21.
Languages: English 506, Spanish 16, German 16, Hindi 16 (validation slice:
88/3/1/1 — language results are indicative only at these counts).
Splits (group-aware 70/15/15, seed 20261026, 348 groups): train 375,
validation 93, test 86. The v0.3 test split is frozen; baseline scripts refuse
or never read it (`test_split_used: false`).

All 504 v0.2.0 samples are preserved verbatim (v0.1's 64 inside them). No label
was changed anywhere. `CHANGELOG.md` in the v0.3 directory records this.

## 2. New samples and provenance

50 hand-authored curated samples (`generation_method=synthetic-authored`,
single author, `review_status=unreviewed`, `independent_review=false`):
12 impersonation, 12 other_suspicious, 10 indirect attacks inside useful
documents/emails/tool outputs, 10 hard-benign (quoted attacks, security
analysis, incident reporting, defensive advice), and 6 multilingual items
(2 per es/de/hi) whose rationales explicitly flag them for native-speaker
review. Two items are deliberate borderline/adjudication candidates at
confidence 0.65 (a Spanish sample that describes an embedded exfiltration
instruction while telling the reader not to follow it, and a Hindi discussion
of an embedded attack).

## 3. Independent-review status

**Not completed. No agreement statistics exist, and none are claimed.**

Prepared package at `ml/datasets/sentinel/v0.3.0/REVIEW_PACKAGE/`:

- `review_blind.csv` — 196 stratified rows (all impersonation and
  other_suspicious, all multilingual, all curated samples, all obfuscation
  representatives, and a stratified fifth of the remainder). Contains text and
  empty annotation fields only; author labels are absent from the file (a test
  asserts the header carries no author label).
- `review_key.csv` — author labels and empty agreement/adjudication columns,
  to be joined only after blind labelling.
- `INSTRUCTIONS.md` — task definition (label by intent, quoted/discussed is
  benign), category list, and language-uncertainty handling.

Strata in the package: benign 77, indirect 33, impersonation 27, other 21,
direct 18, tool_redirect 8, exfiltration 7, obfuscated 5; languages en 166,
es/de/hi 10 each. A real second annotator must still do the work.

## 4. Leakage and integrity (actually run)

- Schema validation: `samples=554 errors=0`.
- Group crossing: 0. Exact normalized cross-split duplicates: 0.
  Token-Jaccard (≥0.9) near cross-split: **0** (a cross-version spacing variant
  was merged into its v0.1 group by the build script before splitting).
- Character 5-gram near cross-split: **15 pairs** remain — different template
  slots with high character overlap. Documented residual bias; lexical checks
  cannot detect semantic paraphrase duplication, and no embedding model was
  downloaded to do so.
- Template-family separation is enforced by construction (template slots share
  `group_id`) and re-verified by the checks above.
- `python -m pytest ml/tests -q` → **8 passed**, including v0.3 size,
  group separation, curated honest marking, and blind-file label absence.

## 5. Baseline re-evaluation (validation only; datasets differ across versions)

Rule scanner (v0.3 validation, n=93): accuracy 0.634, suspicious
P/R/F1 0.941/0.327/0.485, benign FPR 0.023. Per-category recall: tool_redirect
1.0, direct 0.308, obfuscated 0.333, exfiltration 0.333, indirect 0.063,
impersonation 0.0, other 0.0. The new naturally written impersonation and
indirect samples almost entirely evade the anchored rules — useful evidence
about rule limits, measured on a changed dataset.

TF-IDF + Logistic Regression (train-only fit, threshold 0.45 on validation):
accuracy 0.893, confusion benign 36/8, suspicious 2/47; suspicious
P/R/F1 0.855/0.959/0.904; benign FPR 0.182; hard-benign FPR 0.211 (n=19).
Per-category recall is high (0.92–1.0 except exfiltration 0.667), but the
corpus remains template-heavy, so these numbers estimate performance on
similar synthetic text, not on novel real attacks. Cross-version comparison
(v0.1 F1 0.727/FPR 0.40 → v0.2 0.909/0.158 → v0.3 0.904/0.182) is confounded
by changing data and must not be read as a generalization trend.

## 6. Exact commands and outcomes

```powershell
python ml/sentinel/build_v03.py
python ml/sentinel/validate.py ml/datasets/sentinel/v0.3.0/samples.jsonl   # 554, 0 errors
python ml/sentinel/split.py v0.3.0                                          # 375/93/86, leakage above
python -m pytest ml/tests -q                                                # 8 passed
node ml/baselines/scan_dataset.mjs validation v0.3.0
python ml/baselines/run_baselines.py v0.3.0
npm test                                                                    # 72 passed (engine 28, API 44)
```

## 7. Limitations

Single-author labels throughout; multilingual samples (48 total) are
author-written and not native-speaker reviewed; template families still
dominate; `exfiltration_request` remains the thinnest suspicious category (19);
the intent-mismatch relation task is still unrepresented; char-level template
similarity (15 pairs) can still inflate lexical-model validation scores.

## 8. Next step

Recruit a real second annotator to complete `review_blind.csv`, adjudicate
disagreements into `review_key.csv`, publish agreement statistics as a v0.3.1
patch, and add a non-template authored batch for exfiltration and indirect
categories. Only after that should Phase 11A-3 (DeBERTa download and
fine-tuning) be requested.
