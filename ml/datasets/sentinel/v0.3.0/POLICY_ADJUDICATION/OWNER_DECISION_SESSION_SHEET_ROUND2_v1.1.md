# Owner Decision Session Sheet — Sentinel v0.3.0 Round 2 (register v1.1)

| | |
|---|---|
| Status | **Session sheet. Nothing is decided, approved or ratified.** Every owner decision field below is **blank** and is for the project owner only. No register status or recommendation is changed. |
| Builds on | `ROUND2_HUMAN_REVIEW_READINESS_CHECKLIST_v1.1.md` (sha256 `29607881…`) and its log. Checklist IDs (M-, H-, PD-) are referenced, not repeated. |
| Prepared | 2026-10-27, by an AI assistant (Claude Code). Not an annotator, adjudicator or project owner. |
| Quality gate | **OPEN.** |
| Audience | Owner/adjudicator only. **Never** give this sheet to annotators or language reviewers. |
| Validation | `VALIDATION_LOG_OWNER_DECISION_SESSION_SHEET_v1.1.txt` (same folder) |

**Source tags:**

| Tag | File |
|---|---|
| CK | the readiness checklist |
| V09 | `POLICY_READINESS_REVIEW_v0.9_DRAFT.md` |
| V10 | `POLICY_DECISION_REGISTER_ADDENDUM_v1.0_DRAFT.md` |
| V11 | `POLICY_DECISION_REGISTER_ADDENDUM_v1.1_DRAFT.md` |
| ER | `ROUND2_FIELD_MAPPING_ERRATA_DRAFT_v0.1.md` |
| WF | `docs/phase11a-independent-review-workflow.md` |
| RG | the reviewer guide in the annotator package |
| IN | the instructions in the annotator package |
| RD | `docs/phase11-sentinel-research.md` |
| TR | `ml/tests/test_round2.py` |
| INT | `ml/sentinel/intake_round2.py` |
| LG | `ml/datasets/sentinel/v0.3.0/LABELLING_GUIDE.md` |

**Evidence strength:**

| Code | Meaning |
|---|---|
| **DOC** | Stated in an official source |
| **EL** | Evidence-leaning |
| **SIL** | Sources silent |
| **CON** | Sources conflict |
| **PROC** | Process proposal, no policy content |

---

## Section 1 — Decision order

### 1. PD-0 — Round-2 start condition (CK l.72)

The two recorded choices. **Neither is selected here.**

| | **W — Wait** until the relevant approved-rules addendum exists | **G — Start** with the shipped guide plus a separately approved field-mapping errata; label-policy decisions explicitly deferred |
|---|---|---|
| Supporting evidence | V09 l.196: without decided label policy "the annotator addendum cannot be written … otherwise rulings are made ad hoc during annotation". V09 l.201 and V09 l.217 plan for an approved-rules addendum. ER l.33: unapproved rules must not be sent | WF l.47–50: the documented procedure gives the annotator the guide and instructions only. WF l.73–76: recurring disagreement patterns "feed a labelling-guide clarification in the patch notes". WF l.80–84: each disagreement is adjudicated with a rationale. RG l.40–41 and RD l.116–121: low confidence and recorded ambiguity are expected |
| Prerequisites | All G prerequisites, **plus** owner rulings on every label-policy row the addendum would contain (§5; agenda Items 1–4), and a sample-free addendum (V09 l.217). If the addendum is placed in the package, TR must pass and hashes be recorded (V09 l.218) | AD-055, AD-056, AD-057 (§2). The errata placeholders resolved (F-2). The pre-intake procedure (§3). Language decisions (§4). The attestation format (CK H-1) |
| Risks (from existing evidence) | Delay until every included label-policy row is decided (19 agenda rows sit at position O). Adding the addendum to the package changes the hashes and needs the leak test (V09 l.218) | **Ad hoc rulings** by the annotator on undecided questions (V09 l.196), so rows sharing a policy question may be labelled inconsistently (AD-004). It **departs** from V09's own plan (l.201, l.217). [INT] If label policy is decided *after* the join, V09 l.203's reason for fixing adjudication parameters early ("avoid choosing after seeing results") would apply by analogy; the sources state that reason only for adjudication parameters |
| Consequences | Annotation reflects approved rules; fewer ad hoc rulings | Annotation can start once the G prerequisites are met. Label-policy rows are applied at adjudication (WF l.80–84) or in v0.3.1 guide clarifications (WF l.73–76, l.85–90) |
| Same under both | AD-044 and AD-047 are fixed before the join (V09 l.203, l.224). Attestation, the integrity checks and the language requirements apply. The quality gate stays OPEN | |

### 2. Reviewer instructions — AD-055, AD-056, AD-057

- **Dependencies:**
  - AD-056 depends on AD-055.
  - AD-057 is independent, but the errata's placeholder "Form-precedence statement (Q8c)" (ER l.36) needs it.
  - The note conventions depend on AD-055 and AD-057 (V11 D-n, l.528).
- **Approval needed before the errata is distributed:**
  1. AD-055 decided.
  2. AD-056 decided.
  3. AD-057 decided.
  4. An owner instruction on the four placeholders (ER l.31–38), which still cite v0.2-brief question numbers (F-2).
  5. The handout lines from CK M-1–M-3, if they go into the errata.
  6. If AD-056 = (b): TR run **by the adjudicator** (it opens the mapping key, TR l.36–40) and the new package hashes recorded (F-3).
- **F-1:** ER l.20 already tells annotators to write `language-uncertain` whenever the value is not `ok`. That is policy L's token behaviour (AD-050). Issuing the errata as drafted therefore presupposes AD-050.

### 3. Pre-intake and submission integrity (all PROC; details in CK §A and §B)

| Area | Requirement | CK |
|---|---|---|
| File format | UTF-8 **without** BOM. Check the first 3 bytes, then a UTF-8 read check, before intake | M-1, M-2 |
| Immutable text | The `text` column must stay byte-identical; never edit it | M-3 |
| Dates | `reviewed_at` matches `YYYY-MM-DD` (IN l.8), checked by hand | M-4 |
| Required fields | Label, category rule, confidence, `annotator_id`, `reviewed_at` (intake enforces these). `language_quality` must not be blank, and `uncertainty_note` must be present — both checked by hand | M-5, M-6 |
| Columns | The returned header equals the package header | M-7 |
| Validation errors | Iterate until `INTAKE OK` (only the first 50 errors are listed) | M-8 |
| Attestation | An owner-held record: a real person, independent of the author, not an LLM, with no access to AI artifacts or the key | H-1 |
| File integrity | Package = 3 files with matching hashes. The returned file's hash differs from every AI-artifact file | H-6, H-2 |

**F-4:** AD-058's recorded question covers only "reject a blank `language_quality` and validate the ISO date format" (V10 l.613). The checklist also points BOM, encoding and test changes to AD-058 (CK l.41–42, l.50). **No register row covers those code changes.** For Round 2 they rely only on the manual checks.

### 4. Language review — AD-050, AD-051, AD-053 (and AD-052, which AD-053 depends on)

- **AD-050:** `ok` only when a fluent human confirms the language; otherwise `uncertain` or `cannot-judge` plus a note. IN l.9 covers `cannot-judge`.
- **AD-051:** AI output never sets `ok`.
- **AD-053:** when the fluency check happens, before or during annotation. It depends on **AD-052** (who reviews).
- **Worklist handoff:** a **separate owner-approved handoff** of the single worklist file to the fluent reviewers (CK H-7).
  - The worklist contains no text, so the reviewers also receive the package CSV (F-7).
- **Blind-review restrictions stay intact** for annotators *and* language reviewers:
  - only the three package files, plus the approved errata and the approved worklist;
  - never `AI_AUDIT/`, `AI_ASSISTED_REVIEW_ROUND2/`, `POLICY_ADJUDICATION/` (apart from the approved worklist file), `ADJUDICATOR_ONLY/`, author labels, sample IDs or split data (ER l.46; CK §D).

### 5. Deferred policy decisions — what each one blocks

Only distinctions with a source are stated; inferences are marked [INT].

| Decision | Blocks review commencement? | Blocks the join? | Blocks later implementation? | Source |
|---|---|---|---|---|
| AD-013, AD-006, AD-016 (+ AD-017–AD-019, AD-024–AD-028) | **Under W: yes. Under G: no** (deferred by the owner's PD-0 choice) | Not stated by any source. [INT] By analogy with V09 l.203, the owner may choose to decide them before the join | Yes: before the v0.3.1 adjudicated dataset (V09 l.226; WF l.85–90) | V09 l.196, l.201, l.217; WF l.73–76 |
| AD-043 | Only if the `ADJUDICATE:` flag is to be used by annotators: it is the errata's "Uncertainty convention (Q1)" placeholder (ER l.35), and unapproved rules are not sent (ER l.33) | AD-047 (a) and AD-048 reference the flag (V11 D-a, l.515) | — | ER l.33–35 |
| AD-044 | Only if AD-043 is issued to annotators: the convention's text includes the confidence value | **Yes** | — | V09 l.203, l.224 |
| AD-047 | No | **Yes** | — | V09 l.203, l.224; V11 l.505 |
| AD-058 | No: the manual checks M-4 and M-5 cover it | No | Yes: a versioned validator change, only after the gate work | V10 l.616; V09 l.230 |

---

## Section 2 — Decision records

Every decision field is **blank** and is for the owner only. "Recorded" quotes the register, agenda or checklist verbatim.

**PD-0 — Round-2 start condition**
- **Recorded** (CK l.72): "Whether Round 2 starts with the **shipped guide plus the approved errata only**, or waits for an approved-rules addendum"
- **Source and strength:** V09 l.196, l.201, l.217 (for W); WF l.47–50, l.73–76, l.80–84 (for G). Strength: **SIL** — no source chooses between them. Not a register row.
- **Consequences and dependencies:** see §1.1. It determines whether the §5 rows block commencement.
- **Owner decision:** ________ · **By:** ________ · **Date:** ________
- **Follow-up verification:** the chosen path is recorded before any handoff. Under W: the addendum is sample-free (V09 l.217) and, if placed in the package, TR passes and hashes are recorded (V09 l.218).

**AD-055 — Issue the field-mapping errata**
- **Recorded** (V10 l.590): "(a) Issue. (b) Do not issue." v1.1: REC / ES; recommendation (a).
- **Source and strength:** IN l.8 and RG l.42–44 differ on field names; ER l.18–21 maps them. **DOC** for the mismatch.
- **Consequences and dependencies:** feeds AD-056. Presupposes AD-050 (F-1). Placeholders open (F-2).
- **Owner decision:** ________ · **By:** ________ · **Date:** ________
- **Follow-up verification:** the issued errata contains no `sen-` IDs, review IDs, labels or sample text. Its header claim (ER l.19) is checked against the package header by the adjudicator.

**AD-056 — Errata delivery**
- **Recorded** (V10 l.598): "(a) Separate handout. (b) A file in the package." v1.1: PPOD / OJ; recommendation (a).
- **Source and strength:** ER l.40–46; TR l.14–15 leak-checks every package file. **SIL** on delivery.
- **Consequences and dependencies:** depends on AD-055. Option (b) changes the package hashes and needs TR, which opens the mapping key (F-3).
- **Owner decision:** ________ · **By:** ________ · **Date:** ________
- **Follow-up verification:** (a): the package hashes are unchanged (CK H-6). (b): TR passes when run by the adjudicator, and the new hashes are recorded.

**AD-057 — `INSTRUCTIONS.md` prevails on form questions**
- **Recorded** (V10 l.607): "(a) IN prevails for form questions. (b) No statement." v1.1: PPOD / OJ; recommendation (a).
- **Source and strength:** IN l.6, l.8 (Round-2 names) vs RG l.4, l.42–44 (Round-1 names). **SIL**: no precedence statement exists.
- **Consequences and dependencies:** fills the ER l.36 placeholder. Note conventions depend on it (V11 D-n).
- **Owner decision:** ________ · **By:** ________ · **Date:** ________
- **Follow-up verification:** the returned CSV uses the IN field names; intake passes.

**CK M-1 – M-8 — Pre-intake procedure and handout lines**
- **Recorded:** the proposed resolutions in CK l.41–48 (check BOM and encoding; never edit `text`; check date, `language_quality`, `uncertainty_note` and header by hand; iterate to `INTAKE OK`).
- **Source and strength:** INT behaviour and synthetic probes P1–P7. **PROC.**
- **Consequences and dependencies:** the handout lines travel with the errata (AD-055/AD-056). M-5 and M-6 apply policy L and the note conventions only once AD-050 and AD-043 are decided. F-4.
- **Owner decision:** ________ · **By:** ________ · **Date:** ________
- **Follow-up verification:** each M-row's "verification after approval" (CK l.41–48) is recorded for the actual return.

**CK H-1, H-2, H-6 — Attestation and file integrity**
- **Recorded:** CK l.58–59, l.63.
- **Source and strength:** LG l.35 (a real annotator, not the author, not an LLM): **DOC**. The mechanism is PROC.
- **Consequences and dependencies:** must exist before the join (CK H-4).
- **Owner decision:** ________ · **By:** ________ · **Date:** ________
- **Follow-up verification:** the attestation is dated before the join. No hash match with any AI artifact. The package is 3 files with matching hashes.

**AD-050 — Language-quality policy L**
- **Recorded** (V10 l.546): "(a) Ratify. (b) Annotator self-judgment without these tokens." v1.1: REC / ES; recommendation (a).
- **Source and strength:** IN l.9; RG l.42–44. **DOC** for `cannot-judge`; the tokens are a convention.
- **Consequences and dependencies:** presupposed by ER l.20 (F-1). `cannot-judge` triggers AD-043.
- **Owner decision:** ________ · **By:** ________ · **Date:** ________
- **Follow-up verification:** no blank `language_quality` (M-5), and the note is present on every non-`ok` row.

**AD-051 — AI output never sets `ok`**
- **Recorded** (V10 l.555): "(a) Adopt. (b) Allow it." v1.1: PPOD / OJ; recommendation (a).
- **Source and strength:** RD l.165; LG l.35 (indirect). **SIL / weak** (V09 S4).
- **Consequences and dependencies:** affects AI artifacts only. Those artifacts are never shared.
- **Owner decision:** ________ · **By:** ________ · **Date:** ________
- **Follow-up verification:** every non-English `language_quality` value comes from an attested human (CK H-5).

**AD-052 — Who reviews the non-English rows** (a dependency of AD-053)
- **Recorded** (V10 l.563): "(a) Separate fluent reviewers. (b) The annotator, using `cannot-judge` where needed." v1.1: PPOD / OJ; recommendation (a).
- **Source and strength:** RG l.42–44; IN l.9. **SIL** on staffing.
- **Consequences and dependencies:** (a) needs the H-7 worklist handoff and the package CSV for the reviewers (F-7).
- **Owner decision:** ________ · **By:** ________ · **Date:** ________
- **Follow-up verification:** reviewer roles recorded for Spanish, German and Hindi (CK H-3).

**AD-053 — When the fluency check happens**
- **Recorded** (V10 l.571): "(a) Before. (b) During." v1.1: PPOD / OJ; recommendation (a).
- **Source and strength:** RD l.165 only. **SIL** on timing.
- **Consequences and dependencies:** depends on AD-052. (a) puts the H-7 handoff before the package is sent.
- **Owner decision:** ________ · **By:** ________ · **Date:** ________
- **Follow-up verification:** dated records show the check's position in the CK H-4 order.

**CK H-7 — Language-worklist handoff**
- **Recorded:** CK l.64: "A separate, owner-approved handoff of **that single file** to the fluent reviewers".
- **Source and strength:** ER l.46 (the folder is never handed over). **DOC** for the restriction; the handoff is PROC.
- **Consequences and dependencies:** needed only if AD-052 = (a).
- **Owner decision:** ________ · **By:** ________ · **Date:** ________
- **Follow-up verification:** the copy's hash equals the current file; the leak scan is clean; the worklist IDs are a subset of the package IDs (an owner-run check).

**AD-013 — Never infer provenance**
- **Recorded** (V10 l.193): "(a) Ratify. (b) Annotators guess provenance." v1.1: REC / ES, **unchanged**.
- **Source and strength:** RG l.8–9 and IN l.8 support it in part. The prohibition itself is not stated. It is in tension with RG l.51–53 ("in chat"). Effectively **CON**; the review note says an owner ruling is needed (F-8).
- **Consequences and dependencies:** linked to AD-065's reading (agenda §4). Under W it blocks commencement; under G it is deferred.
- **Owner decision:** ________ · **By:** ________ · **Date:** ________
- **Follow-up verification:** if ratified, the reconciliation with RG l.51–53 is recorded with it.

**AD-006 — Evidence E1–E5 required for `tool_redirect`**
- **Recorded** (V10 l.121): "(a) Ratify. (b) Use a different list." v1.1: REC / ES, **unchanged**.
- **Source and strength:** E1, E2, E4 and E5 are **DOC**. Treating them as *required*, and E3's wording, are interpretations (V09 S6; review note §A) (F-8).
- **Consequences and dependencies:** E3 overlaps the undefined "covert" (AD-016). Feeds AD-008, AD-041 and AD-065.
- **Owner decision:** ________ · **By:** ________ · **Date:** ________
- **Follow-up verification:** if ratified, the two interpretations are recorded as accepted.

**AD-016 — Definition of "covert"** (dependents: AD-017–AD-019, AD-024, AD-025, AD-027, AD-028; AD-026 is independent)
- **Recorded** (V11 l.310–314): **L0**, **L1**, **L2**, **L3**; *Excluded* P. v1.1: PPOD / OJ; recommendation L1.
- **Source and strength:** RG l.33–34 does not define the term. **SIL / CON**: the guide's grammar and its examples point different ways.
- **Consequences and dependencies:** the effect on each dependent row is in the review note §B and agenda §3. **Unresolved gaps:** agenda OBS-1 (no option for AD-018/AD-019 at L0) and OBS-2 (no recommendation for AD-024/AD-025 at L2). This sheet resolves neither.
- **Owner decision:** ________ · **By:** ________ · **Date:** ________
- **Dependent rows**, each needing its own field:
  - AD-017: ________
  - AD-018: ________
  - AD-019: ________
  - AD-024: ________
  - AD-025: ________
  - AD-026: ________
  - AD-027: ________
  - AD-028: ________
- **Follow-up verification:** the recorded dependent decisions match the V11 §2.5.4 table, or each mismatch carries a written exception.

**AD-043 — `ADJUDICATE:` convention**
- **Recorded** (V10 l.481): "(a) Adopt. (b) Force a binary label with no flag." v1.1: REC / ES; recommendation (a).
- **Source and strength:** INT l.37–38; RD l.116–121. **DOC** for the need; the token is a convention. Intake does not enforce it (CK M-6).
- **Consequences and dependencies:** the ER l.35 placeholder. Feeds AD-044, AD-047 and AD-048.
- **Owner decision:** ________ · **By:** ________ · **Date:** ________
- **Follow-up verification:** flags are counted by hand at intake (M-6).

**AD-044 — Confidence ceiling for `ADJUDICATE:` rows**
- **Recorded** (V11 l.492): "(a) ≤ 0.5. (b) Below 0.7, as a consistency check against RG l.40–41. (c) No ceiling; the flag plus RG l.40–41 suffice." v1.1: PPOD / OJ; recommendation (b).
- **Source and strength:** RG l.40–41 (0.7). No source gives 0.5. **EL.**
- **Consequences and dependencies:** must be fixed before the join, and before commencement if AD-043 is issued to annotators.
- **Owner decision:** ________ · **By:** ________ · **Date:** ________
- **Follow-up verification:** the decision record is dated before the join; violations are reported, never corrected.

**AD-047 — Adjudication trigger for agreeing rows**
- **Recorded** (V11 l.503): "(a) Annotator < 0.7, OR author < 0.9, OR `ADJUDICATE:`. (b) A single 0.7 threshold. (c) A single 0.9 threshold." v1.1: PPOD / OJ; recommendation (a).
- **Source and strength:** WF l.80–84 (every disagreement is adjudicated) is **DOC**. The agreeing-row rule is **SIL**.
- **Consequences and dependencies:** must be fixed before the join (V09 l.224).
- **Owner decision:** ________ · **By:** ________ · **Date:** ________
- **Follow-up verification:** the queue equals all disagreements plus the agreeing rows the rule selects, computed after `INTAKE OK`.

**AD-058 — Intake validator tightening**
- **Recorded** (V10 l.615): "(a) Defer to a versioned change. (b) Change now." v1.1: PPOD / OJ, `DEFERRED`; recommendation (a).
- **Source and strength:** INT l.18, l.54–55. **PROC.**
- **Consequences and dependencies:** the recorded scope is narrower than the checklist's references (F-4).
- **Owner decision:** ________ · **By:** ________ · **Date:** ________
- **Follow-up verification:** under (a), INT is unchanged and checks M-4/M-5 are performed by hand.

**Inconsistencies surfaced and not resolved:**

| ID | Inconsistency |
|---|---|
| F-1 | ER l.20 presupposes AD-050 |
| F-2 | The ER placeholders cite v0.2 numbers, and no recorded option says how to issue the errata while they are open |
| F-3 | AD-056 (b) needs TR, which opens the mapping key |
| F-4 | AD-058's scope is narrower than the checklist's references |
| F-5 | Option G departs from V09 l.201 and l.217 |
| F-6 | Agenda OBS-1 and OBS-2 |
| F-7 | Fluent reviewers need the package CSV |
| F-8 | AD-013 and AD-006 are marked REC / ES, while the review note says they need an owner ruling or confirmation |

---

## Section 3 — Final readiness checklist

[both] = under either PD-0 choice; [W] / [G] = only under that choice.

**Before sending the package to annotators:**
- [ ] [both] PD-0 recorded.
- [ ] [both] AD-055, AD-056 and AD-057 recorded; owner instruction on the ER placeholders (F-2); if AD-056 = (b), TR run by the adjudicator and hashes recorded.
- [ ] [both] Handout lines from M-1–M-3 approved.
- [ ] [both] AD-050 recorded (F-1).
- [ ] [both] AD-043 and AD-044 recorded, if the flag is to be issued.
- [ ] [both] AD-051, AD-052 and AD-053 recorded; reviewers assigned (H-3); proficiency attested (H-5).
- [ ] [both] The H-7 worklist handoff approved, if AD-052 = (a). It precedes the package if AD-053 = (a).
- [ ] [both] The attestation format agreed (H-1).
- [ ] [both] Package listing and hashes verified (H-6). The never-share list confirmed.
- [ ] [W] Owner rulings on the addendum's label-policy rows; the sample-free addendum approved (V09 l.217–218).

**Before accepting returned annotations:**
- [ ] [both] M-1/M-2 byte and UTF-8 checks.
- [ ] [both] M-7 header equality.
- [ ] [both] `INTAKE OK` (M-8, M-3).
- [ ] [both] M-4 dates, M-5 `language_quality`, M-6 notes column.
- [ ] [both] Attestation completed (H-1).
- [ ] [both] Return hash differs from every AI artifact (H-2).
- [ ] [both] Language results incorporated as AD-052 and AD-053 specify.

**Before joining annotations to hidden data:**
- [ ] [both] AD-044 and AD-047 recorded and dated (V09 l.224).
- [ ] [both] The join follows the CK H-4 order and is performed by the adjudicator alone (V09 l.225).
- [ ] [G] *Owner's option:* decide the deferred label-policy rows before the join. This is [INT], by analogy with V09 l.203, and not required by any source.

**Deferred — does not block the chosen path:**
- [ ] AD-058, and any BOM/encoding code change (no register row; F-4); CK M-10 tests.
- [ ] [G] AD-013, AD-006, AD-016 and dependents, plus the other label-policy rows — until before the v0.3.1 adjudicated dataset at the latest (V09 l.226; WF l.85–90).
- [ ] DEFERRED rows AD-014, AD-032, AD-045, AD-049, AD-054, AD-061, AD-062; the AD-063 user decision.
- [ ] Validator, schema and pipeline changes, and any training request — only after everything above (V09 l.230–231).

---

## Decisions the owner must personally make

PD-0 · AD-055 · AD-056 · AD-057 · the ER placeholder instruction (F-2) · approval of CK M-1–M-8 · approval of CK H-1, H-2 and H-6 · AD-050 · AD-051 · AD-052 · AD-053 · CK H-7 · AD-043 · AD-044 · AD-047 · AD-058 · AD-013 · AD-006 · AD-016 and its eight dependent rows.

**Under W, also:** every other label-policy row the addendum would contain (agenda Items 2–4).

The quality gate stays **OPEN**.
