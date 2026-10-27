# Sentinel v0.3.0 Round 2 — Final Consistency & Readiness Review **v0.9 (DRAFT)**

| | |
|---|---|
| Status | **`DRAFT_NOT_APPROVED`.** A review of `POLICY_RESOLUTION_PROPOSAL_v0.8_DRAFT.md` (sha256 `79fd4e41…`) only. **Nothing is ratified, approved or decided.** No register is filled. No policy file is edited. |
| Prepared | 2026-10-27, by an AI assistant (Claude, Cowork). Not an annotator, adjudicator, or project owner. |
| Quality gate | **OPEN.** |
| Audience | Owner/adjudicator only. Not for the independent annotator. |

## 1. Repository status and checks

- **Repository status.** Not a git repository (`git status` → "fatal: not a git repository"). A hash comparison of 238 files against the post-v0.8 snapshot found **no user changes**. The only differences were the assistant's own final v0.8 proposal (`79fd4e41…`) and `VALIDATION_LOG_v0.8.txt` (`3d329ace…`), both as recorded in the v0.8 step.
- **Checks actually run in this step.** Exact output is in `VALIDATION_LOG_v0.9.txt`.

  | ID | Check | Result |
  |---|---|---|
  | C1 | All citation ranges in v0.8 re-read against the sources | 83 ranges checked (covering all 64 regex-extracted ranges plus the section-table ranges); **0 mismatches** |
  | C2 | Structural audit of v0.8 | Markers and statuses per rule; register duplicates, mixed rows and conflict IDs (findings below) |
  | C3 | `python ml/sentinel/intake_round2.py` on the blank package | Still rejected (gate open) |
  | C4 | `python -m pytest ml/tests -q -p no:cacheprovider` | Run |
  | C5 | Hash integrity before and after | Run |

- **Prior reported results (not re-run here):**
  - `npm test` 72 passed (engine 28, API 44), from the AI-assisted-review step;
  - earlier `pytest` runs, 16 passed each time.

---

## 2. Rules vs official sources (task item 1)

**Citations.** All 64 citation ranges used in v0.8 resolve to text that supports the cited point (C1: 0 mismatches). No rule depends on a file that has changed since it was cited.

**Substantive findings** — where the source supports less than v0.8's status implies:

| ID | Rule | Finding | Severity |
|---|---|---|---|
| S1 | R-13a (secrets and credentials always `exfiltration_request`, "literal documented reading") | RG l.28 says "secrets, credentials, **or private data**" in the same clause. v0.8 applies it literally to secrets but **not** to private data (R-13b), so the literal reading is used selectively. It also conflicts with RG l.51–53 (a user's own scoped instruction "is not automatically an injection") and with R-02a ("a sensitive action alone is insufficient"). Example: "send my password to IT". No document says which rule prevails. | **High.** The `RECOMMENDED_FOR_ADOPTION` status is overstated; this is a genuine choice, or at minimum it needs an explicit precedence clause over R-02a |
| S2 | R-11, R-12, R-13a | They lean on SC (`packages/engine/src/scanner/rules.ts`). SC is scanner implementation documentation, not annotation policy; RD l.113 only says the categories "mirror" the scanner rules. SC can corroborate a reading but cannot decide it. | Medium. v0.8 already marks R-11 and R-12 pending; R-13a should not cite SC as decisive |
| S3 | R-14 | The convention follows from RD l.116–121 and WF l.91–93, but the **0.5 confidence ceiling** has no documentary basis. RG l.40–41 uses 0.7; LG l.24–26 uses 0.9. | Medium. Ratifiable, but the number should be confirmed explicitly |
| S4 | R-17 policy L ("AI output never sets `ok`") | v0.8 derives it from G7 (LG l.33–35). G7 concerns who may be the second annotator, not AI language flags, so the link is indirect. It affects only AI-generated artifacts. | Low |
| S5 | R-15c | Excluding `ADJUDICATE:` rows from primary kappa is only meaningful if R-14 is ratified; WF l.60–71 does not mention flagged rows. | Low. Conditional ratification |
| S6 | R-02b | Each E1–E5 maps to a documented behaviour. Making them **necessary** for `tool_redirect` is an interpretation of RG l.29–30 read together with l.51–53. | Low. v0.8 already explains this; ratifiable |

No rule was found to contradict an official document **outright**, apart from the selective literalism in S1.

## 3. Separation of documented policy / interpretation / recommendation / owner decision (task item 2)

C2 shows how consistently the [DOC] / [INT] / [AMD] / [OWNER] markers are applied:

| ID | Finding |
|---|---|
| M1 | **Consistent.** R-01, R-02, R-03, R-07 and R-13 carry the markers that match their content. |
| M2 | **Amendment content without an [AMD] marker:** R-05 (the X2 cue rule C1–C3), R-08 (the interim rule and `alt-category:` note) and R-15 (the R-15b trigger). The status labels are right, but the separation is implicit. |
| M3 | **Interpretation without an [INT] marker:** R-15a (reconciling the two thresholds by field scope) is an interpretation presented under [DOC]. |
| M4 | **No category markers at all:** R-16, R-20 and R-21. They are short and correctly labelled pending, so the risk is low. |
| M5 | **Status overstated:** R-13a (see S1). |

**Effect:** none of these changes a recommended outcome. M2, M3 and M5 should be corrected in any annotator-facing text, so that interpretations are not presented as official policy.

## 4. Section 9 register audit (task item 3)

**Duplicates: none.** There are 33 data rows with 33 unique IDs (C2), and all 33 decision/by/date cells are blank.

### 4.1 Omissions — decisions present in the v0.8 rule bodies but without their own register row

| ID | Missing decision | Where it is in v0.8 |
|---|---|---|
| O1 | The `relation-task:` note convention (`RECOMMENDED_FOR_ADOPTION`) | R-03 body |
| O2 | Future exposure of `source_type` (`PENDING_PROJECT_OWNER_DECISION`) | R-04 body; only "no exposure in Round 2" is in the row text |
| O3 | Future schema extension, a third label value (`PENDING`, future) | R-14 body |
| O4 | The statement that IN prevails over RG for form questions (`PENDING`) | R-18 body; the row shows only "Ratify; handout" |
| O5 | Validator tightening (deferred) | R-18 body |
| O6 | The definition of "private data" — a separate decision from the two-step rule | R-13b body; combined into one row |
| O7 | Detecting an "internal" destination from text (residual X4 risk) | R-13 trade-offs |

### 4.2 Combined rows — one cell holding several decisions or statuses

| ID | Row | Contents |
|---|---|---|
| CB1 | R-06 | Five independent inclusion decisions in one row |
| CB2 | R-08 | Ratify the interim rule + defer the final order |
| CB3 | R-17 | Ratify policy L + three staffing decisions (who reviews, when, what happens to failed rows) |
| CB4 | R-18 | Ratify the errata + delivery method (+ O4, O5 missing) |
| CB5 | R-19 | Ratify the strategy + erratum location + build-script fix |

**Risk:** a single "Ratify" answer in these rows would be ambiguous.

### 4.3 Contradictory or coupled choices — owner must answer jointly

| ID | Coupled items | Problem |
|---|---|---|
| J1 | **R-13a ↔ R-02a** | Ratifying both without a precedence clause yields opposite outcomes for a self-scoped credential request (S1). |
| J2 | **R-05b ↔ R-06** inclusions 2 and 5 | Adopting X2 implies those inclusions. Rejecting them while adopting X2 would be contradictory. |
| J3 | **R-14 → R-15c, R-01c, R-02d** | Three register recommendations route rows to R-14. If R-14 is rejected, those three need a replacement. |
| J4 | **R-03c → R-02 (E7)** | Evidence item E7 exists only if R-03c is adopted. |
| J5 | **R-11 ↔ R-13a** | If hidden instructions are ruled "secrets" (R-11), R-13a makes every prompt-disclosure request `exfiltration_request` regardless of other evidence. Consistent, but the owner should see the combined effect. |
| J6 | **R-02a/b → R-04** | R-04 ("never infer provenance") is only safe once R-02's evidence rule is ratified. |

No register row recommends a choice that contradicts another row's **recommended** choice, except through J1.

### 4.4 Rows whose recommendation lacks sufficient documentary evidence

These are correctly marked `PENDING`, but each recommendation rests on interpretation or project goals rather than documents:
- R-01b
- R-02c (E6, task switch)
- R-03c
- R-05b
- R-06 inclusions 1–5
- R-11
- R-12
- R-13b
- R-15b

Among rows marked `RECOMMENDED_FOR_ADOPTION`, **R-13a** (S1) and the **R-14 0.5 parameter** (S3) lack sufficient evidence for that status.

## 5. Unresolved cross-conflicts in the register (task item 4)

| Conflict | Residual decision | In the register? | Gap |
|---|---|---|---|
| **X1** (sensitive action vs evidence) | R-02c, R-02d, R-03c | Yes — rows R-02c, R-02d, R-03c | None. The conflict ID is not named in those rows, but the residuals are represented |
| **X2** (fake reviews, tracking, summaries) | R-05b: the choice between X2 and X2-alt, and the definition of "covert" | Partly — row R-05b names only "X2" as the recommendation | **X2-alt is not listed as an option**, and the definition of "covert" is not a separate decision. The coupling with R-06 (J2) is not noted |
| **X3** (relayed vs defensive) | R-01b, R-01c | Yes — rows R-01b, R-01c | None |
| **X4** (private data and credentials) | R-13a (with the S1 caveat), R-13b two-step vs literal, "private data" definition (O6), internal-destination detection (O7) | Partly — rows R-13a, R-13b | **Neither row names X4.** O6 and O7 are not separate decisions, and R-13a's precedence over R-02a (J1) is not represented |

**Conclusion:** X2 and X4 are **not fully represented** in the 33-entry register. Before ratification, the owner needs at least these additional decision lines:
- X2 option (X2 / X2-alt);
- definition of "covert";
- X4 "private data" definition;
- R-13a precedence vs R-02a.

## 6. Ratifiable vs genuine policy choice (task item 5)

### 6.1 Can be presented for ratification as-is

There is no genuine alternative in the documents; it is a sign-off only.
- R-01a
- R-02a
- R-02b
- R-03a
- R-03b
- the R-03 `relation-task:` convention (O1)
- R-04 (after R-02a/b — J6)
- R-05a
- R-05c
- R-07
- R-08 interim rule (split from CB2)
- R-09
- R-10
- R-15a
- R-17 policy L (low-evidence caveat S4)
- R-18 errata issuance (split from CB4)
- R-19 correction strategy (split from CB5)

### 6.2 Can be ratified only with an explicit condition

| Item | Condition |
|---|---|
| R-14 | Confirm the 0.5 parameter (S3) |
| R-15c | Only if R-14 is ratified (S5, J3) |
| R-13a | Add a precedence clause relative to R-02a and RG l.51–53 — **or reclassify it as a genuine choice** (S1, J1). This review recommends reclassifying. |

### 6.3 Genuinely need a policy choice

- **Label policy:**
  - R-01b
  - R-01c
  - R-02c
  - R-02d
  - R-03c
  - R-05b — X2 vs X2-alt, plus the definition of "covert"
  - R-06 inclusions 1–5, each separately
  - R-11
  - R-12
  - R-13b — two-step vs literal, plus the definition of "private data"
- **Process:**
  - R-15b
  - R-16
  - R-17 staffing (who, when, what happens to failed rows)
  - R-18 delivery
  - R-18 IN-precedence (O4)
  - R-19 erratum location
  - R-19 build fix
  - R-20
  - R-08 final order (deferred)
  - R-04 future exposure (O2)
  - R-14 future schema (O3)
- **User access:** R-21. The recommendation is not to run it; it is **not a blocker**.

---

## 7. Blockers in priority order (task item 6)

| # | Priority | Blocker | Why it blocks |
|---|---|---|---|
| 1 | **P0** | No independent human annotation exists; intake still rejects the blank package (C3) | The quality gate cannot close; training and implementation stay unauthorised (QG "## Decision"; RD l.116–121; LG l.33–35) |
| 2 | **P1** | Genuine **label-policy** choices are undecided: R-01b, R-01c, R-02c, R-02d, R-03c, R-05b (X2), R-06 (×5), R-11, R-12, R-13b (X4) | The annotator addendum cannot be written until these are decided; otherwise rulings are made ad hoc during annotation |
| 3 | **P1** | Consistency defects J1 (R-13a vs R-02a) and J2 (R-05b vs R-06) | Ratifying the current rows as written could produce contradictory rules |
| 4 | **P2** | Register hygiene: omissions O1–O7 and combined rows CB1–CB5; X2 and X4 not fully represented (§5) | Ratification answers would be ambiguous or incomplete. **Fix by issuing a new versioned register addendum** — not by editing v0.8 |
| 5 | **P2** | Ratification of the §6.1 items and the conditional §6.2 items has not happened | Nothing is policy until the owner signs off |
| 6 | **P2** | Marker and status corrections M2, M3, M5 in any annotator-facing text | Prevents interpretations being presented as official policy |
| 7 | **P3** | Annotator-facing material is not issued: the sample-free errata (R-18) and an approved-rules addendum; delivery method undecided | The annotator cannot apply the rules consistently |
| 8 | **P3** | Fluent Spanish, German and Hindi reviewers are not assigned (R-17 staffing) | 30 non-English rows cannot be annotated reliably (G6) |
| 9 | **P3** | Adjudication parameters are undecided (R-15b trigger; R-14 0.5 value) | Must be fixed **before** the controlled join with the mapping key, to avoid choosing them after seeing results |
| 10 | **P4** | Documentation items before v0.3.1: dataset-card erratum location (R-19), guide-precedence statement (R-16), `is_quoted_or_discussed` review (R-20), build-script fix | Needed before v0.3.1 is built; not before annotation |
| 11 | **P4** (non-blocking) | R-21 user access decision | Recommended "do not run"; no rule depends on it |

## 8. Implementation-readiness checklist (all unchecked — none of these has occurred)

**Policy**
- [ ] Owner decides every genuine choice in §6.3, including X2 (X2 / X2-alt + "covert" definition) and X4 ("private data" definition + R-13b rule).
- [ ] Owner resolves J1 (R-13a precedence or reclassification) and J2 (R-05b ↔ R-06).
- [ ] A new versioned register addendum adds O1–O7, splits CB1–CB5 and names X2 and X4. Prepared only when instructed; v0.8 itself stays unchanged.
- [ ] Owner ratifies, rejects or amends each §6.1 item and each conditional §6.2 item, with name and date.
- [ ] Interpretations are marked as such in any text derived from v0.8 (M2, M3, M5).

**Annotation**
- [ ] A sample-free annotator addendum with only approved rules, plus the R-18 errata, is drafted. It contains no review IDs, sample text, labels or AI output.
- [ ] If the addendum is placed in `ANNOTATOR_PACKAGE/`, `python -m pytest ml/tests/test_round2.py` passes and the new package hashes are recorded.
- [ ] Fluent Spanish, German and Hindi reviewers are assigned. The annotator-safe language worklist is used; the AI artifacts are not shared.
- [ ] A real independent human annotator — not the author and not an LLM — completes `review_blind_opaque.csv`.
- [ ] `python ml/sentinel/intake_round2.py <completed file>` reports `INTAKE OK`.

**Adjudication and dataset**
- [ ] The adjudication trigger (R-15b) and the `ADJUDICATE:` parameter (R-14) are fixed **before** the join.
- [ ] The adjudicator alone performs the controlled join with `ADJUDICATOR_ONLY/mapping_key.csv`. Agreement is reported per R-15: kappa with and without flagged rows, plus confusion tables.
- [ ] Adjudication outcomes are recorded. v0.3.1 is built as a new version with a changelog, a corrected card (R-19), regenerated group-aware splits and a newly frozen test split. v0.3.0 is unchanged.
- [ ] The quality gate is formally re-evaluated against `docs/phase11a-dataset-quality-gate.md` criteria, including the benign false-positive target.

**Only after all of the above**
- [ ] Separate, versioned and owner-approved changes for any validator, schema, scanner or pipeline work: R-14 future schema, R-18 validator tightening, R-19 build fix, any scanner alignment from S2.
- [ ] A separate request for Phase 11A-3 training.

**Readiness verdict:** **not ready for implementation.** The policy set is **ready for owner review** once the register gaps (§5, O1–O7, CB1–CB5) and the two consistency defects (J1, J2) are addressed. Nothing has been ratified, and the quality gate remains **OPEN**.
