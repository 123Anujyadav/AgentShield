# Phase 11A-2.8 — Independent Annotation Workflow & Adjudication

Date: 2026-10-26. **Quality gate remains OPEN. Training is not approved.**

No independent annotations have been received. No reviewer identity, agreement
statistic, adjudication outcome, or timestamp has been fabricated. The current
blind package is byte-for-byte the unannotated file from Phase 11A-2.7 (an
automated test asserts every `independent_label` cell is still empty).

## 1. Blind package audit (actually verified)

Package: `ml/datasets/sentinel/v0.3.0/REVIEW_PACKAGE/`

- `review_blind.csv`: 196 rows, columns `review_order, sample_id, text,
  independent_label, independent_attack_category, confidence_0_1,
  disagreement_reason, annotator_id, reviewed_at`. Verified programmatically:
  sample IDs are unique, annotation cells are all empty, and no author-label
  column exists in the file.
- `review_key.csv`: 196 rows with the identical ID set, author labels, and
  empty `agreement`, `adjudicated_label`, `adjudication_rationale` columns.
  The join is one-to-one on `sample_id` and can only be performed after intake
  validation passes.
- Stratification (from build): benign 77, indirect 33, impersonation 27,
  other 21, direct 18, tool_redirect 8, exfiltration 7, obfuscated 5;
  languages en 166, es/de/hi 10 each. Every selected sample has a stable ID
  shared by the dataset, the blind file, and the key.

Residual exposure note: the blind file contains sample IDs that also appear in
the public dataset, so a reviewer who went looking could find author labels.
Mitigation for this round: the instructions require working from the blind
file alone, and intake records the annotator's own ID and date. A future round
should use opaque review IDs with the mapping held by the adjudicator only.

## 2. Reviewer guide and form

Added `REVIEWER_GUIDE.md` in the review package: the benign/suspicious
decision rules, the seven attack categories, hard-benign handling (quoted,
reported, educational, and defensive text is benign), per-row form fields,
confidence guidance (below 0.7 for genuine ambiguity), and explicit
`language-uncertain` handling for Spanish/German/Hindi rows. The form itself
is the blind CSV; no separate app was built.

## 3. Procedure, disagreement analysis, and adjudication policy

Procedure:

1. Dataset author hands the annotator `review_blind.csv`, `REVIEWER_GUIDE.md`,
   and `INSTRUCTIONS.md` — not the key, not the dataset changelog.
2. Annotator labels independently, returns the completed CSV with its
   structure unchanged.
3. Intake validation (`ml/sentinel/intake.py`) must pass before anyone opens
   the key. Intake checks: every blind ID answered exactly once, no unknown
   or duplicated IDs, text unchanged from the blind package (stable identity),
   labels in the permitted sets, category present exactly when suspicious,
   numeric confidence in [0,1], annotator ID and date present.
4. Only then the adjudicator joins with `review_key.csv` and computes agreement.

Agreement methodology (to be applied to real results, none exist yet):

- Primary statistic: **Cohen's kappa** on the binary benign/suspicious labels
  (two raters, nominal categories), reported with raw percent agreement and
  the full 2×2 confusion table. Kappa corrects for chance agreement, which
  matters because the package is imbalanced (77 benign of 196).
- Secondary: per-category agreement on attack subtype among rows where at
  least one rater said suspicious, reported as counts, not a single score,
  because several categories have single-digit support.
- Limitations to state with any result: kappa is prevalence-sensitive (the
  kappa paradox can yield low kappa despite high raw agreement on imbalanced
  data); one annotator gives no inter-annotator variance estimate; subtype
  agreement on tiny strata is unstable. Report the confusion table alongside
  any kappa so readers are not hostage to one number.

Disagreement analysis: group disagreements by category pair, language,
quoted/discussed flag, and author confidence. Recurring patterns (for example
quoted attacks labelled suspicious by the annotator) feed a labelling-guide
clarification in the patch notes, not silent relabelling.

Adjudication policy:

- The adjudicator (author plus, where possible, a third person) reviews each
  disagreement with both rationales. The independent label wins when the
  author's rationale relied on template intent rather than the sample's actual
  context; the author label wins only with a written reason recorded in
  `adjudication_rationale`.
- Adjudicated labels land only in a **new v0.3.1 dataset**: a copy of v0.3.0
  samples with changed rows marked `review_status=adjudicated`,
  `independent_review=true`, and a `CHANGELOG.md` entry per correction
  (sample ID, old label, new label, rationale). v0.1, v0.2, and v0.3.0 files
  are never edited. Splits are regenerated deterministically for v0.3.1 and
  its test split frozen before any baseline reads it.
- Samples neither rater could label confidently stay in the dataset only if
  both agree on the final label; otherwise they are marked for exclusion in
  the patch notes rather than forced.

## 4. Intake mechanism

Implemented: `ml/sentinel/intake.py` (CLI) with tests in
`ml/tests/test_intake.py` (accepts a complete valid file; rejects missing,
unknown, duplicated, tampered-text, invalid-label, and missing-annotator
cases; asserts the real blind file is still unannotated). Running intake on
the current blank package actually produced `rows=196 errors=784` and exit 1 —
the expected open-gate result. Intake writes nothing and joins nothing.

## 5. Exfiltration category audit and proposed plan

`exfiltration_request` is the thinnest suspicious category (19 of 302
suspicious). Existing samples lean on explicit "reveal/send the key" phrasing,
which risks a keyword shortcut. `PROPOSED_EXFILTRATION_BATCH.md` in the review
package drafts eight directions (SaaS-export framing, debugging pretext,
verification scam, analytics bundling, translation laundering, support
handoff, backup pretext, plus mandatory benign counterweights) targeting
12 new suspicious and 6 hard-benign samples. These drafts are **not** dataset
samples: no IDs, no labels in force, and they enter only through a future
versioned patch with `unreviewed` marking and genuine review.

## 6. Test-set isolation

The v0.3.0 test split was not read in this phase. Baseline scripts still
refuse or ignore it, intake never touches dataset splits, and the adjudication
design above freezes a v0.3.1 test split before evaluation. Group-aware
separation is unchanged.

## 7. Files changed and checks run

Added:

- `docs/phase11a-independent-review-workflow.md` (this file)
- `ml/sentinel/intake.py`
- `ml/tests/test_intake.py` (4 tests)
- `ml/datasets/sentinel/v0.3.0/REVIEW_PACKAGE/REVIEWER_GUIDE.md`
- `ml/datasets/sentinel/v0.3.0/REVIEW_PACKAGE/PROPOSED_EXFILTRATION_BATCH.md`

Modified: none. The blind file, key, dataset, and all production code are
untouched.

Checks actually run:

- Blind-package audit script: IDs unique, key IDs match, 0 filled annotations.
- `python -m pytest ml/tests -q` → **12 passed**.
- `python ml/sentinel/intake.py <blank blind file>` → 196 rows, 784 errors,
  exit 1 (correctly rejected; gate open).

## 8. Remaining human actions and gate status

Required from humans before anything else proceeds:

1. A real second annotator completes `review_blind.csv` per the guide.
2. Intake validation passes on their returned file.
3. Adjudication is performed and recorded; v0.3.1 is published with a
   changelog and frozen splits.
4. Agreement statistics are computed from those real results and reviewed
   against the quality gate (including whether benign FPR drivers were label
   problems or model problems).

**Training (Phase 11A-3) is not approved.** The gate stays open until steps
1–4 produce real evidence.
