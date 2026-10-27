# Round 2 — Field-Mapping Errata (DRAFT v0.1)

**Status: `DRAFT_NOT_APPROVED`.** Prepared for project-owner review. It is not in force, and it is **not** part of `REVIEW_ROUND2/ANNOTATOR_PACKAGE/`. It changes no official file, column, label or validator rule.

**Sample-free by design.** This document contains no review IDs, sample text, labels, categories, splits or AI output. If the owner approves it, it may be given to the human annotator **without** breaking blindness.

## Why this errata exists (verified facts)

- `ml/sentinel/build_round2.py` (lines 58–59) copies the Round-1 `REVIEW_PACKAGE/REVIEWER_GUIDE.md` into `REVIEW_ROUND2/ANNOTATOR_PACKAGE/` unchanged.
  - The two files are identical apart from line endings (`diff --strip-trailing-cr`).
- The Round-1 form had `sample_id` and `disagreement_reason` and no `language_quality`. The Round-2 form (`review_blind_opaque.csv`) differs.
  - `INSTRUCTIONS.md` and `ml/sentinel/intake_round2.py` describe and enforce the Round-2 form.

## Mapping (Round-1 wording in REVIEWER_GUIDE.md → Round-2 form)

| REVIEWER_GUIDE.md says | Use in Round 2 | Source of truth |
|---|---|---|
| "Work from `review_blind.csv`" | `review_blind_opaque.csv` | `INSTRUCTIONS.md` ("Rules"), CSV file name |
| `disagreement_reason` | `uncertainty_note` | `review_blind_opaque.csv` header, `INSTRUCTIONS.md` |
| "write `language-uncertain` in `disagreement_reason`" | Set `language_quality` (`ok` / `uncertain` / `cannot-judge`) **and** write `language-uncertain` in `uncertainty_note` when not `ok` | `INSTRUCTIONS.md`; `intake_round2.py` `LANGUAGE_QUALITY` |
| `independent_label`, `independent_attack_category`, `confidence_0_1`, `annotator_id`, `reviewed_at` | unchanged | header + `intake_round2.py` |

## Unchanged

- **Columns:** the column set and order of `review_blind_opaque.csv` stay exactly as shipped.
- **Labels:** `benign` and `suspicious` (`ml/sentinel/schema.py` `LABELS`).
- **Categories:** `direct_injection`, `indirect_injection`, `obfuscated_injection`, `impersonation`, `exfiltration_request`, `tool_redirect`, `other_suspicious` (`schema.py` `ATTACK_CATEGORIES`).
  - Required when the label is suspicious; left empty when it is benign.
- **Decision rules:** everything in `REVIEWER_GUIDE.md` other than the field names above.

## Placeholders — filled only after owner approval

The following stay empty until the owner approves the corresponding rulings in `POLICY_DECISION_BRIEF_v0.2_DRAFT.md`. Unapproved rules must not be sent to the annotator.

- [ ] Uncertainty convention (Q1): ______
- [ ] Form-precedence statement (Q8c): ______
- [ ] Language-quality convention (L): ______
- [ ] Any approved clarifications for Q2–Q7: ______

## Delivery note (owner action, not performed)

If placed inside `ANNOTATOR_PACKAGE/`:
1. Re-run `python -m pytest ml/tests/test_round2.py`, which leak-checks every file in that folder.
2. Record the new package file hashes.

Otherwise, send it to the annotator alongside the package before annotation begins. Either way, give the annotator only the package and this errata — never `AI_AUDIT/`, `AI_ASSISTED_REVIEW_ROUND2/` or `POLICY_ADJUDICATION/`.
