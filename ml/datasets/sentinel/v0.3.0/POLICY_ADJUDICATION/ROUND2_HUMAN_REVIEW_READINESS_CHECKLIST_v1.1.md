# Round-2 Human-Review Readiness Checklist (register v1.1)

| | |
|---|---|
| Status | **Checklist only. Not ready for human review.** No rule is approved; no ratification field exists or is filled; no recommendation or status is changed. Nothing in the validator, tests, schema, dataset, labels, reviewer package or policy documents was modified. |
| Builds on | `REVIEW_SESSION_NOTE_BLOCK0_AD016_READINESS_v1.1.md` §C (sha256 `6ca82626…`) and `VALIDATION_LOG_REVIEW_SESSION_NOTE_v1.1.txt` |
| Prepared | 2026-10-27, by an AI assistant (Claude Code). Not an annotator, adjudicator or project owner. |
| Quality gate | **OPEN.** |
| Audience | Owner/adjudicator only. **Not for the annotator or the language reviewers.** |
| Validation | `VALIDATION_LOG_READINESS_CHECKLIST_v1.1.txt` (same folder) |

**Source tags:**

| Tag | File |
|---|---|
| IN | `REVIEW_ROUND2/ANNOTATOR_PACKAGE/INSTRUCTIONS.md` |
| RG | `REVIEW_ROUND2/ANNOTATOR_PACKAGE/REVIEWER_GUIDE.md` |
| INT | `ml/sentinel/intake_round2.py` |
| TR | `ml/tests/test_round2.py` |
| ER | `POLICY_ADJUDICATION/ROUND2_FIELD_MAPPING_ERRATA_DRAFT_v0.1.md` |
| WL | `POLICY_ADJUDICATION/language_review_worklist_ANNOTATOR_SAFE_v0.1.csv` |
| L02 | `POLICY_ADJUDICATION/VALIDATION_LOG_v0.2.txt` (the worklist's build record) |
| WF | `docs/phase11a-independent-review-workflow.md` |
| LG | `ml/datasets/sentinel/v0.3.0/LABELLING_GUIDE.md` |
| V09 | `POLICY_ADJUDICATION/POLICY_READINESS_REVIEW_v0.9_DRAFT.md` |
| RD | `docs/phase11-sentinel-research.md` |
| P1–P7 | Synthetic intake probes from the note's log (scratchpad files only) |

**Owner approval column:**
- **Yes** — needs an owner approval, naming the register row where one exists.
- **No** — an adjudicator-side check with no policy content.

---

## A. Mechanical submission issues (process fixes; no policy content)

For Round 2, the proposed resolutions use **pre-intake checks and handout wording**, with no code change. Validator changes are deferred to a versioned change (AD-058, pending).

| ID | Path · field or instruction | Observed | Proposed resolution | Owner approval | Verification after approval |
|---|---|---|---|---|---|
| M-1 | INT l.23–24 · the returned file is opened as `utf-8` | A UTF-8 file with a BOM fails on **every** row: the first header becomes unreadable (P2) | Handout line: "save as UTF-8 **without** BOM". Before intake, the adjudicator checks the first 3 bytes are not `EF BB BF`. If they are, ask the annotator to re-save; **never edit** the file. Accepting a BOM in code belongs only in a versioned AD-058 change | **Yes:** handout wording (with AD-055/AD-056). Any code change is AD-058 | `head -c 3 <return> \| od -An -tx1` is not `ef bb bf`; then `python ml/sentinel/intake_round2.py <return>` prints `INTAKE OK` |
| M-2 | INT l.23–24 · encoding | A non-UTF-8 file with a non-ASCII character **crashes** intake (`UnicodeDecodeError`) instead of reporting errors (P7). The Hindi, Spanish and German rows make this likely | As M-1. Pre-check: `python -c "open(r'<return>', encoding='utf-8').read()"` exits 0 | **Yes:** as M-1 | The pre-check exits 0, then intake runs without an exception |
| M-3 | INT l.34–35 · the `text` column must be byte-identical | One trailing space fails identity (P6). Spreadsheet round-trips can trim or re-quote cells | Handout line: "never edit the `text` column". Recommend a tool that preserves cells | **Yes:** handout wording | Intake output contains no `text differs` errors |
| M-4 | INT l.54–55 · `reviewed_at` · IN l.8 asks for an "ISO date" | Only non-empty is checked; "last tuesday" passes (P3) | Before the join, the adjudicator checks that every `reviewed_at` matches `^\d{4}-\d{2}-\d{2}$`. Returns that fail go back to the annotator | **Yes:** the procedure; validator tightening is AD-058 | 0 rows fail the regex |
| M-5 | INT l.18, l.50–51 · `language_quality` · IN l.8–9 | A blank value is accepted for any row (P3) | Before the join, the adjudicator checks there are no blank values, and that the `language-uncertain` note is present whenever the value is not `ok` (policy L, AD-050) | **Yes:** AD-050 ratification; AD-058 for code | 0 blank values; note present on every non-`ok` row |
| M-6 | INT l.21–59 · `uncertainty_note` (IN l.8) | Never read; a missing column passes (P4). `ADJUDICATE:` and other notes are unenforced | The adjudicator checks the column exists and counts flags. Note conventions apply only once ratified (AD-043, AD-050; field name per AD-057) | **Yes:** AD-043, AD-050, AD-057 | Header contains `uncertainty_note`; flag counts are reported in the adjudication record |
| M-7 | IN l.10 "Return the CSV with its structure unchanged" · INT reads columns by name | Extra columns pass (P5). Column order is never checked | Before intake, the adjudicator compares the returned header with the package header (header line only) | No | The returned header equals the package header exactly |
| M-8 | INT l.69–70 · only the first 50 errors are printed | The total is printed (`rows=… errors=…`), but the detail is truncated | None needed. Iterate until `INTAKE OK` | No | `INTAKE OK`, exit code 0 (INT l.71–73) |
| M-9 | RG l.4, l.42–44, l.52–53, l.55 (Round-1 names: `review_blind.csv`, `disagreement_reason`) vs IN l.6, l.8–9 (Round-2 names) | The package gives two sets of field names. ER l.18–21 maps them, but the errata is `DRAFT_NOT_APPROVED` and outside the package (ER l.3). Its placeholders cite v0.2-brief question numbers (ER l.33–38). Its claim about the CSV header (ER l.19) has **not** been re-verified (the CSV was not opened) | The owner decides AD-055 (issue), AD-056 (delivery) and AD-057 (IN prevails on form questions). Re-point the placeholders to AD IDs: Q1 → AD-043/AD-044; Q8c → AD-057; L → AD-050/AD-051; Q2–Q7 → v1.0 §3. Fill them only with ratified rules (ER l.33) | **Yes:** AD-055, AD-056, AD-057 | The issued errata contains no `sen-` IDs, review IDs, labels or sample text. Its header claim matches the package header. If placed in the package: TR passes and new hashes are recorded (ER l.42–44) |
| M-10 | TR l.61–74 · intake test coverage | Tests cover only incomplete, unknown ID, bad label and edited text. **Untested:** BOM, encoding, blank language, date format, columns, duplicate IDs, category rules, confidence bounds, missing `annotator_id` | No change for Round 2. If the owner approves a versioned validator change, add a test for each item | **Yes:** AD-058 | The new tests pass; the existing TR tests still pass |

---

## B. Human-review integrity

| ID | Path · field or instruction | Observed | Proposed resolution | Owner approval | Verification after approval |
|---|---|---|---|---|---|
| H-1 | IN l.8 · `annotator_id` ("initials/role you choose"); INT l.52–53 checks only that it is non-empty | Intake cannot tell a human submission from an AI one. LG l.35 requires a real annotator who is "not the dataset author, not an LLM" | An owner-held **attestation record**, kept outside the dataset and the package. It states that the annotator is a real person, independent of the author, not an LLM, and had no access to `AI_AUDIT/`, `AI_ASSISTED_REVIEW_ROUND2/`, `POLICY_ADJUDICATION/` or the key | **Yes** | The attestation is dated before the join. The `annotator_id` values in the return match the attested role |
| H-2 | `AI_ASSISTED_REVIEW_ROUND2/proposed_review_AI_ASSISTED_NOT_HUMAN_ANNOTATION.csv` (name only; not opened) | An AI-produced proposal file exists. Nothing technical stops it being submitted as a return | The adjudicator confirms the returned file's sha256 differs from every file in `AI_ASSISTED_REVIEW_ROUND2/` and `AI_AUDIT/` — hash comparison only, no content read | No | No hash match is found |
| H-3 | Reviewer assignment · AD-052 (pending) · RG l.42–44 · WL: 10 Hindi, 10 Spanish, 10 German rows (L02 l.7; V09 l.202) | No reviewers are assigned | The owner names the annotator role and one fluent reviewer each for Spanish, German and Hindi — or rules that the annotator uses `cannot-judge` instead | **Yes:** AD-052 | Each language has a recorded reviewer role, or the recorded ruling |
| H-4 | Schedule · AD-053 (pending) · ER l.46 ("before annotation begins") · INT l.71–72 · WF l.51–56 · agenda §6 | No order is fixed | Fix the order: (1) rules and errata approved; (2) handoff; (3) language check before or during annotation, per AD-053; (4) return; (5) M-1–M-7 checks; (6) `INTAKE OK`; (7) AD-044 and AD-047 fixed; (8) controlled join | **Yes:** AD-053; AD-044/AD-047 before the join | Dated records show this order; the join is dated after `INTAKE OK` and after the AD-044/AD-047 records |
| H-5 | Language proficiency · IN l.9 · AD-050 (REC), AD-051 (pending) · RD l.165 | Proficiency is not verified anywhere | Each fluent reviewer confirms proficiency in the attestation (H-1). Only a fluent human sets `ok`; AI output never does (AD-051) | **Yes:** AD-050, AD-051 | Every non-English row's `language_quality` was set by an attested fluent reviewer |
| H-6 | TR l.14–23 · leak test | It checks only for `sen-NNNN` IDs and "author_label" in package files. It would not catch AI-artifact content added to the package | Handoff check: the package holds exactly the three files of §D, and their hashes match L02 l.29–31. (Verified in this step: all three `OK`) | No | `sha256sum -c` against L02 l.29–31 → 3 × `OK`; the listing shows exactly 3 files |
| H-7 | WL handoff (see §D) | WL sits inside `POLICY_ADJUDICATION/`, a folder ER l.46 says never to give the annotator. Its status is `NEEDS_FLUENT_HUMAN_REVIEW_NOT_APPROVED`. It contains **no text**, so a fluent reviewer also needs the package CSV. How WL results feed the annotator's `language_quality` is undefined | A separate, owner-approved handoff of **that single file** to the fluent reviewers. Decide how the results are carried into the return (AD-052, AD-053) | **Yes** | The handed-over copy's sha256 equals the current WL. A leak scan finds 0 `sen-` IDs and 0 label/author/split/AI terms. The WL review IDs are a subset of the package IDs — an owner-run check, because the package CSV was not opened here |

---

## C. Policy decisions (owner rulings; none is chosen or approved here)

| ID | Decision topic | State in v1.1 and the note | Needed before human review? |
|---|---|---|---|
| PD-0 | Whether Round 2 starts with the **shipped guide plus the approved errata only**, or waits for an approved-rules addendum | Not recorded as a register row. V09 l.196 says that without an addendum, rulings are made ad hoc during annotation | **Yes.** This is the gating owner choice for the start date |
| PD-1 | **AD-013** never infer provenance | REC / ES, **unchanged**. The note §A says it needs an owner ruling on reconciliation with RG l.51–53, through the AD-065 reading | Only if an addendum is issued (PD-0) |
| PD-2 | **AD-006** evidence E1–E5 required | REC / ES, **unchanged**. The note §A asks for owner confirmation of two interpretations: the evidence items are *required*, and E3's wording | Only if an addendum is issued |
| PD-3 | **AD-016** "covert", levels L0–L3 (P excluded) | PPOD; v1.1 recommends L1. Dependents: AD-017–AD-019 (derived), AD-024, AD-025, AD-027, AD-028 (conditional). AD-026 is independent. Gaps: agenda OBS-1 (L0) and OBS-2 (L2) | Only if an addendum is issued |
| PD-4 | Other rows the annotator-facing text would use: AD-064, AD-065, AD-002, AD-003, AD-008, AD-038–AD-042 | Pending (agenda Items 2–4) | Only if an addendum is issued |
| PD-5 | Process rows that gate the mechanics above: AD-043, AD-050–AD-053, AD-055–AD-057, AD-058 | AD-043 and AD-050 REC; the rest pending | **Yes:** errata, notes and language handling depend on them |
| PD-6 | **AD-044, AD-047** (confidence ceiling; adjudication trigger) | Pending | Not before annotation, but **before the join** |

---

## D. Safe handoff

**To the annotator — exactly these three files, unchanged** (hashes as recorded in L02 l.29–31 and re-verified in this step):

| File | sha256 |
|---|---|
| `ml/datasets/sentinel/v0.3.0/REVIEW_ROUND2/ANNOTATOR_PACKAGE/INSTRUCTIONS.md` | `3e54c52dc89b8bc9…` |
| `ml/datasets/sentinel/v0.3.0/REVIEW_ROUND2/ANNOTATOR_PACKAGE/REVIEWER_GUIDE.md` | `2c07f2f5885f359c…` |
| `ml/datasets/sentinel/v0.3.0/REVIEW_ROUND2/ANNOTATOR_PACKAGE/review_blind_opaque.csv` | `e663c296489559a5…` |

**Additional items — each only after its own owner approval:**
- the issued errata (AD-055/AD-056), with the handout lines from M-1–M-3;
- an approved-rules addendum, if PD-0 calls for one.

The opaque review IDs inside the package CSV are annotator-visible by design.

**The language worklist needs a separate owner-approved handoff**, to the **fluent reviewers**:
- It is not a package file, and it lives in a folder that is never handed over (ER l.46).
- **Checked in this step:**
  - 30 rows and 9 columns;
  - opaque review IDs only;
  - no sample text;
  - 0 `sen-` IDs and 0 label/author/split/AI terms;
  - language guesses 10 Hindi, 10 Spanish, 10 German, derived from the package's script (L02 l.7);
  - `review_order` is each row's position within the package;
  - all reviewer fields blank.
- **Not yet verified:** that the worklist IDs are a subset of the package IDs (H-7).

**Never handed over:**
- `REVIEW_ROUND2/ADJUDICATOR_ONLY/` (the mapping key);
- `AI_AUDIT/`, `AI_ASSISTED_REVIEW_ROUND2/`, `POLICY_ADJUDICATION/` (except the approved single-file worklist handoff above);
- `samples.jsonl`, `splits/`, `CHANGELOG.md` (WF l.47–48);
- any author label, sample ID, split assignment, or this checklist.

---

## E. Unresolved owner decisions and next action

**Unresolved:**
- PD-0;
- AD-013 (reconciliation);
- AD-006 (two interpretations);
- AD-016 and its dependents;
- AD-043, AD-050–AD-053, AD-055–AD-058;
- AD-044 and AD-047 (before the join);
- the H-1 attestation format;
- the H-7 worklist handoff.

**Next recommended action:** an owner session limited to the **non-label-policy gates** — PD-0, AD-055/AD-056/AD-057 (errata, delivery, form precedence), the M-1–M-7 pre-intake procedure and handout lines, H-1/H-3/H-4/H-5 (attestation, assignment, schedule, proficiency) and the H-7 worklist handoff.
- These do not depend on AD-016 or the other label-policy rows.
- If PD-0 chooses "shipped guide plus errata", the label-policy rows (agenda Items 1–4) can follow before v0.3.1 rather than before annotation.
- The quality gate stays **OPEN** in every case.
