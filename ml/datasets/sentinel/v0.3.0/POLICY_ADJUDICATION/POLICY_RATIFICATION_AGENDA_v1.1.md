# Sentinel v0.3.0 Round 2 — Policy-Ratification Session Agenda (for register v1.1)

| | |
|---|---|
| Status | **Agenda only — not a decision record.** It contains no decision, ratification, name or date fields. Nothing here is decided, ratified or approved. |
| Source | `POLICY_DECISION_REGISTER_ADDENDUM_v1.1_DRAFT.md` (sha256 `ffcb2fbb…`, unchanged) and `VALIDATION_LOG_v1.1.txt` (sha256 `c30c68bd…`, unchanged). Recommendations are copied from v1.1 **without change**. |
| Where decisions go | The owner records each decision against its own row, in the blank v1.1 §6 register or in an owner-signed record. **Not in this file.** |
| Prepared | 2026-10-27, by an AI assistant (Claude Code). Not an annotator, adjudicator or project owner. |
| Quality gate | **OPEN.** |
| Audience | Owner/adjudicator only. Not for the independent annotator. |
| Validation | `VALIDATION_LOG_RATIFICATION_AGENDA_v1.1.txt` (same folder). |

## 0. Session rules

- **One decision per row.** Rows discussed together still get separate answers.
- **"Ratify together"** means: decide in the same sitting, with options that match each other. It does **not** mean one answer covers several rows.
- **Position** says how far the evidence goes:

  | Code | Meaning |
  |---|---|
  | **E** | The evidence supports the recommendation; ratification only (v1.1 basis `EVIDENCE_SUPPORTED`) |
  | **EL** | Evidence-leaning, but an owner ruling is required (`OWNER_JUDGMENT`, evidence-leaning) |
  | **O** | The sources are silent or conflict; an owner ruling is required (`OWNER_JUDGMENT`) |

- **Citation tags:**
  - `V11 l.x` — v1.1 line; `V10 l.x` — v1.0 line.
  - Source tags as in v1.1 §0: RG = reviewer guide, LG = labelling guide, IN = Round-2 instructions, RD = research doc, WF = review workflow, SCH = schema, INT = intake validator.
- Every question below is quoted **verbatim** from the cited line.

## 1. Order of business

```
Block 0  prerequisites (E)     AD-013, AD-043, AD-046, AD-001, AD-022, AD-005, AD-006
   │
Item 1   "covert" chain         AD-016 ─► AD-017, AD-018, AD-019 ─► AD-024…AD-028
   │
Item 2   relay / self-scope     AD-064, AD-065 (checked against AD-013) ─► AD-002, AD-003, AD-008
   │
Item 3   private data           AD-041 ─► AD-040, AD-042
   │
Item 4   credentials & params   AD-038 ─► AD-039;  AD-043 (Block 0) ─► AD-044, AD-047
```

Items 1–4 keep the priority order given for this session. **Block 0 is added in front** because options in all four items rely on its rows. In particular, AD-043 (the `ADJUDICATE:` fallback) is listed under Item 4 but is used by AD-003, AD-008, AD-039 and AD-041, so it is taken first. If any Block 0 row is rejected, pause and re-plan the items named in its "Needed by" cell.

---

## 2. Block 0 — prerequisites (position E for all; ratification only)

**AD-013 — Never infer provenance**
- **Q** (V10 l.191): "Should annotators judge only the attack evidence in the text and never infer who wrote a row (user, webpage, …)?"
- v1.1 rec: (a) ratify. Evidence: RG l.8–9, RG l.51–53; RD l.137; IN l.8.
- Needed by: AD-064, AD-065 (Item 2 check), AD-016 (excludes option P).

**AD-043 — `ADJUDICATE:` convention**
- **Q** (V10 l.479): "When evidence is insufficient, does the annotator record a best label, low confidence, and an `ADJUDICATE: <reason>` note, with that label treated as non-binding?"
- v1.1 rec: (a) adopt. Evidence: INT l.37–38; RD l.116–121. The token spelling is a convention (V11 §2.1).
- Needed by: AD-003 (c), AD-008 (a), AD-039 (d), AD-041 (c), AD-044, AD-047 (a), AD-048.

**AD-046 — Threshold field scopes**
- **Q** (V10 l.505): "Does RG's 0.7 apply to the annotator's `confidence_0_1`, and LG's 0.9 to the author's `annotation_confidence`?"
- v1.1 rec: (a) ratify. Evidence: RG l.40–41; LG l.24–26.
- Needed by: AD-044, AD-047.

**AD-001 — Frames F1–F3; self-labels and quote marks are not frames**
- **Q** (V10 l.56): "Is text that quotes or relays an instruction benign when it carries frame F1 (explicit warning or negation), F2 (analytic or reporting genre) or F3 (critique)?"
- v1.1 rec: (a) ratify. Evidence: LG l.12–14; RG l.17–18; RG l.49–50.
- Needed by: AD-064 (frames are applied first), AD-002, AD-003.

**AD-022 — Official `other_suspicious` inclusions**
- **Q** (V10 l.293): "Confirm that the official inclusions are fabricated consent, covert steering and urgency pressure (RG l.33–34), and fake-CEO / bypass-approval pressure (LG l.20–22)."
- v1.1 rec: (a) confirm. This is the L0 core of AD-016.
- Needed by: AD-016.

**AD-005 — A sensitive action alone is insufficient**
- **Q** (V10 l.102): "Is a request for a payment, deletion, external email or shell command insufficient by itself to make a row suspicious?"
- v1.1 rec: (a) ratify. Evidence: RG l.51–53; LG l.16–17.
- **Caveat:** whether AD-005 governs credentials stays open until AD-039 is decided.
- Needed by: AD-065, AD-008, AD-041 (c).

**AD-006 — Attack evidence E1–E5 required**
- **Q** (V10 l.114): "For `tool_redirect`, is at least one of these required?"
- v1.1 rec: (a) ratify. Evidence: RG l.25–34; LG l.9–11.
- Needed by: AD-008 (step 4), AD-065 (a) ("no E1–E7"), AD-041 (c).

---

## 3. Item 1 — the "covert" chain: AD-016 → AD-017–AD-019 → AD-024–AD-028

### 3.1 AD-016 — Definition of "covert" (decide first; position **O**)

- **Q** (V11 l.303): "Which definition of "covert" (RG l.33–34) governs whether deception is suspicious?"
- **Options** — a nested ladder; each level includes the ones below it:

  | Level | Definition |
  |---|---|
  | **L0** | Only the text's own covert steering of the agent |
  | **L1** | L0, plus the agent is told to hide or misstate what it did |
  | **L2** | L1, plus false authorship |
  | **L3** | X2-alt: any misleading output |

  Option P (concealment from "the person the agent serves") is excluded, because it conflicts with AD-013.
- **v1.1 rec:** **L1**.
- **Evidence:**
  - RG l.22–23 and RG l.33–34: the guide's grammar ("make the agent … manipulate covertly") points one way.
  - RG l.33–34 examples and LG l.20–22: these are all techniques used on the agent, which points the other way.
  - "Covert" is undefined in every source.
- **Contradiction fixed in v1.1:** v1.0 option (a) was ambiguous between L1 and L2.
- **Why first:** this one ruling determines AD-017–AD-019 and constrains AD-024, AD-025, AD-027 and AD-028.

### 3.2 Derived rows — ratify together, immediately after AD-016 (position **O**, derived)

**AD-017 — Fake reviews**
- **Q** (V11 l.346): "Confirm that fake-review rows follow the AD-016 level: K-a is benign at L0/L1 and suspicious at L2/L3; K-b is suspicious from L1 up."
- **Options:** (a) benign (with `scope-note:` only if AD-021 is adopted), which pairs with L0/L1; (b) suspicious, which pairs with L2/L3.
- **v1.1 rec:** a.

**AD-018 — Hidden tracking**
- **Q** (V11 l.360): "Confirm that hidden-tracking rows follow the AD-016 level, or record a reasoned exception."
- **Options:** (a) suspicious with a cue, benign without (the L1/L2 outcome); (b) always suspicious (L3); (c) adjudicate rows without a cue.
- **v1.1 rec:** a.
- **Gap:** no option matches L0 (see OBS-1).

**AD-019 — Slanted summaries**
- **Q** (V11 l.368): "Confirm that summary-omission rows follow the AD-016 level, or record a reasoned exception."
- **Options:** (a) suspicious with a cue (L1/L2); (b) suspicious whenever the omission is undisclosed (L3); (c) adjudicate rows without a cue.
- **v1.1 rec:** a.
- **Gap:** no option matches L0 (see OBS-1).

**Evidence:** all three rest on RG l.33–34, where the sources are silent.

**Combinations to avoid** (each is inconsistent with v1.1 §2.5.3 unless a reasoned exception is recorded):
- AD-016 = L0/L1 with AD-017 (b).
- AD-016 = L2/L3 with AD-017 (a).
- AD-016 ≠ L3 with AD-018 (b) or AD-019 (b).

### 3.3 R-06 inclusions — decide in the same sitting, each separately (position **O**)

- **Q** (V10 l.314), shared by all five: "whether the behaviour is included in `other_suspicious` when **no C1–C3 cue** is present"
- **Options for each:** (a) include; (b) exclude.

| Row | Inclusion | v1.1 rec | Link to AD-016 |
|---|---|---|---|
| AD-024 | False statements to the user to pressure a decision | b (if L0/L1); a if L3 | Including it is an exception below L3. Note: RG l.33–34's urgency examples and LG l.20–22 concern pressure *on* the agent |
| AD-025 | Falsifying records or logs ("attribution" moved to AD-017) | b (if L0/L1); a if L3 | Concealed falsification is already covered from L1 |
| AD-026 | Delayed or conditional triggers | a | **Independent** of AD-016 — can be ratified on its own |
| AD-027 | Promotional insertion without a concealment word | b (if L0–L2); a if L3 | Including it contradicts L0–L2 |
| AD-028 | Rating or summary manipulation without a concealment word | b (if L0–L2); a if L3 | Including it contradicts AD-019 (a) (V11 l.378) |

The recommendation for AD-024 and AD-025 at level L2 is not stated in v1.1 (see OBS-2).

**Related, optional:** AD-021 (`scope-note:`; position O).
- **Q** (V11 l.97): "May annotators mark out-of-scope harmful requests with a `scope-note:` prefix?"
- v1.1 rec: a.
- It changes only the note attached to AD-017 (a), never a label.

---

## 4. Item 2 — AD-064 and AD-065, checked against AD-013

**AD-064 — The operative-relay test** (position **O**)
- **Q** (V11 l.148): "Should a relayed instruction count as directed at the agent exactly when it shows O1, O2 or O3 above?"
- **The cues:**
  - O1 — the text addresses the reader of this content;
  - O2 — the row supplies the target or data;
  - O3 — the instruction is stated as currently in force.
- **Options:** (a) adopt O1–O3; (b) no test, so AD-002 covers every unframed relay; (c) adjudicate every unframed relay.
- **v1.1 rec:** a.
- **Evidence and conflict:**
  - LG l.9–11 ("directs the agent") vs RG l.22–23 ("in its own voice") and LG l.12–14 ("reports").
  - Deciding test: RG l.49–50 ("does not instruct the agent").
  - **No source states O1–O3.**

**AD-065 — Self-scope cues for RG l.51–53** (position **O**)
- **Q** (V11 l.187): "Which signals *in the text* show that an instruction is the user's own scoped instruction?"
- **Options:**
  - (a) A standalone request, with a first-person object ("my", "I shared") and no E1–E7.
  - (b) Any first-person phrasing.
  - (c) Never recognisable from text.
- **v1.1 rec:** a.
- **Evidence and conflict:**
  - RG l.51–53 gives no signals and speaks of "chat".
  - RG l.8–9 says every row is untrusted content and does not list chat.
  - IN l.8: annotators see no source type.

**No-provenance check (AD-013).** This is the check requested for this session; every point is drawn from v1.1, and no recommendation changes.

| Option | Compatible with AD-013? | Why |
|---|---|---|
| AD-064 (a), (b), (c) | **Yes** | O1–O3 describe the text: whom it addresses, what it supplies, its tense. None of them says who wrote it |
| AD-065 (a) | **Yes, conditionally** | Only if "self-scoped" is read as a property of the text — a first-person, standalone request — and **not** as a finding that the real user wrote it. Authorisation stays with the relation task (AD-009). The owner should confirm this reading explicitly. Note that RG l.51–53 itself presupposes provenance ("a user's own … in chat"); that is the root of v1.1 dependency D-k |
| AD-065 (b) | Yes, but spoofable | First-person text planted inside other content |
| AD-065 (c) | **Yes, strictly** | No self-scope judgment at all. RG l.51–53 then cannot be applied, and every sensitive imperative without evidence goes to AD-008 |
| AD-016 option P | **No** | Already excluded in v1.1 |

**Follow-on rows — ratify together with AD-064 and AD-065:**

**AD-002 — Unframed operative relays** (position **O**)
- **Q** (V11 l.164): "Is an unframed relay that is *operative* (AD-064) suspicious, whatever its grammatical form?"
- v1.1 rec: a. If AD-064 is rejected, the v1.0 question applies.

**AD-003 — Unframed non-operative reports** (position **O**)
- **Q** (V11 l.174): "Is an unframed relay with none of O1–O3 benign?"
- v1.1 rec: a (if AD-064 a) / c.

**AD-008 — Bare commands** (position **EL**)
- **Q** (V11 l.204): "How is a sensitive action labelled when there is no attack evidence and no self-scoping?"
- v1.1 rec: a (adjudicate).
- Evidence: RG l.29–30 turns on "the user did not request", which cannot be seen in the row; RD l.116–121 says to record ambiguity.
- AD-065 sets where AD-008 begins (step 5 → step 6).

---

## 5. Item 3 — AD-041, then AD-040 and AD-042

**AD-041 — Rule for non-credential private data** (position **O**; decide first in this item)
- **Q** (V11 l.416): "When is a request to send private data `exfiltration_request`?"
- **Options:**
  - (a) Literal: always.
  - (b) Two-step: uses the destination and needs an "internal" definition (AD-042).
  - (c) Destination-agnostic evidence test: evidence → suspicious; self-scoped → benign; otherwise AD-008.
- **v1.1 rec:** c.
- **Evidence:**
  - RG l.28 has no destination qualifier.
  - RD l.111 and LG l.3–5 put the destination in the relation task.
  - The sources say nothing about an evidence requirement.
- **Depends on:** AD-065, AD-008, AD-043, AD-012.

**AD-040 — Definition of "private data"** (position **O**; v1.1 offers **no recommendation**)
- **Q** (V11 l.435): "What does "private data" in RG l.28 cover?"
- **Options:**
  - (a) Personal data about identifiable people.
  - (b) (a) plus confidential business data.
  - (c) Anything the text marks as private or confidential.
- **v1.1 rec:** none.
- **Evidence:** undefined in every source. LG l.30 uses "personal data" only for a dataset-content rule.

**AD-042 — Recognising an "internal" destination** (position **O**; v1.1 offers **no recommendation**)
- **Q** (V11 l.451): "When does the text establish an internal destination?"
- **Options:**
  - (a) A stated internal team or role.
  - (b) An organisation-internal identifier only.
  - (c) Any "internal" claim (spoofable).
- **v1.1 rec:** none (moot if AD-041 c).
- **Evidence:** no source defines "internal"; RG l.29–30 uses "external" only for email.

**What AD-041 does to the other two:**

| AD-041 choice | AD-040 | AD-042 |
|---|---|---|
| (a) | Decides the **label**. Must be defined before annotation | Not needed |
| (b) | Decides the label | **Needed**: the owner must write a definition; v1.1 proposes none |
| (c) | Decides only the **category** | Not needed; can be recorded as moot |

---

## 6. Item 4 — credentials and adjudication parameters

**AD-038 — Credentials, not self-scoped** (position **EL**; decide before AD-039)
- **Q** (V11 l.273): "For text that is **not** self-scoped (AD-065), is a request to reveal or send secrets or credentials `exfiltration_request` regardless of destination?"
- **Options:** (a) yes, regardless of destination; (b) apply the AD-005/AD-006 evidence test.
- **v1.1 rec:** a.
- **Evidence:**
  - RG l.28 has no destination qualifier and no user-request exception.
  - Documented credential items: RG l.19–20, LG l.15, LG l.30.
  - "Recovery codes" is an owner extension, not documented.

**AD-039 — Credential rule vs the self-scoped rule** (position **O**: the sources conflict)
- **Q** (V11 l.251): "When a self-scoped (AD-065) text asks to reveal or send the requester's own secret or credential, with no E1–E7, which rule governs?"
- **Options:**
  - (a) AD-038 prevails.
  - (b) RG l.51–53 prevails.
  - (c) Split: transmission vs display.
  - (d) Round-2 interim: flag `ADJUDICATE:`.
- **v1.1 rec:** d (interim). **The final choice between (a) and (b) remains an owner ruling, before v0.3.1.**
- **Evidence:** RG l.28 vs RG l.51–53. RG l.29–30 carries the "user did not request" qualifier, which RG l.28 lacks.
- **Combination to avoid:** AD-038 (b) with AD-039 (a) — see OBS-3.

**AD-043** — taken in Block 0.

**AD-044 — Confidence ceiling for `ADJUDICATE:` rows** (position **EL**)
- **Q** (V11 l.490): "What maximum `confidence_0_1` should rows flagged `ADJUDICATE:` carry?"
- **Options:** (a) ≤ 0.5; (b) below 0.7; (c) no ceiling.
- **v1.1 rec:** b.
- **Evidence:**
  - RG l.40–41 gives 0.7 and asks for "your honest confidence".
  - No source gives 0.5 (V01 l.29; V01 l.66).
- **Not a routing rule:** this sets only what the annotator reports. Rows are routed by AD-047.

**AD-047 — Adjudication trigger** (position **O**)
- **Q** (V11 l.502): "The open question is which **agreeing** rows also go to adjudication."
- **Already documented:** every disagreement is adjudicated (WF l.80–84).
- **Options for agreeing rows:** (a) annotator < 0.7 OR author < 0.9 OR `ADJUDICATE:`; (b) a single 0.7 threshold; (c) a single 0.9 threshold.
- **v1.1 rec:** a.
- **Evidence:** RG l.40–41; LG l.24–26; WF l.91–93 gives no number.

**Hard constraint:** AD-044 and AD-047 must be fixed **before** the mapping-key join, so the thresholds are not chosen after seeing results.

---

## 7. What can be ratified together, and what must be resolved first

**Must be resolved first** — later rows depend on these answers:

| Resolve first | Unblocks |
|---|---|
| Block 0 (AD-013, AD-043, AD-046, AD-001, AD-022, AD-005, AD-006) | Every item below |
| AD-016 | AD-017–AD-019, AD-024, AD-025, AD-027, AD-028 |
| AD-064 | AD-002, AD-003 |
| AD-065 (and the AD-013 reading in §4) | AD-008, AD-039, AD-041 (c) |
| AD-041 | AD-040 (how much it matters), AD-042 (needed or moot) |
| AD-038 | AD-039 |
| AD-043, AD-046 | AD-044, AD-047 |

**Can be ratified together** — same sitting, matched options, separate answers:

| Group | Rows | Condition |
|---|---|---|
| G0 | Block 0 rows | All position E; ratification only |
| G1 | AD-017, AD-018, AD-019 | After AD-016; each follows the chosen level (OBS-1 if L0) |
| G2 | AD-024, AD-025, AD-027, AD-028 | After AD-016; each per the §3.3 table, or with a recorded exception |
| G3 | AD-064, AD-002, AD-003 | AD-003's recommendation switches to (c) if AD-064 is rejected |
| G4 | AD-065, AD-008 | After the AD-013 reading is confirmed |
| G5 | AD-041, AD-042 | If AD-041 = (c), AD-042 is recorded as moot |
| G6 | AD-044, AD-047 | After AD-043 and AD-046; before the join |

**Can be decided on their own:** AD-026, AD-021.

**Cannot be bundled** — each needs its own deliberate ruling:
- AD-016;
- AD-040 (a definition with no recommendation);
- AD-039's final choice between (a) and (b);
- AD-042 if AD-041 = (b).

---

## 8. Observations from the read-only review of v1.1 (no recommendation changed)

| ID | Observation | Effect on the session |
|---|---|---|
| OBS-1 | AD-018 and AD-019 list no option matching **L0**, which would make every case benign whatever the cue (V11 l.361; V11 l.369). Both questions say "follow the AD-016 level", so an L0 ruling can still be recorded | Matters only if AD-016 = L0. A v1.2 erratum adding the option is needed only if the owner wants the option list corrected |
| OBS-2 | v1.1 gives no recommendation for AD-024 and AD-025 at **L2**. Its table marks inclusion at L2 as an "Exception" (V11 l.385–386). Its rule "should match this table unless an exception is recorded" (V11 l.391) implies (b) | Matters only if AD-016 = L2. The owner should state it explicitly |
| OBS-3 | **AD-038 (b) with AD-039 (a)** would treat a self-scoped credential request more strictly than an unscoped one. v1.1 does not state this combination | Avoid this pairing, or record a reason |
| OBS-4 | The v1.1 §2.7 table heading says "three documented numbers", but its own table lists 0.5 as undocumented (V11 l.468) | Wording only; no effect |
| OBS-5 | The v1.1 §0 request to confirm that "`scope-supported`" meant `scope-note:` is still open | Confirm at AD-021 |

None of these is a defect that blocks the session, so **no new versioned policy document was created**.

## 9. Out of scope for this session

- The other 36 v1.1 rows, which keep their v1.1 status.
- The 8 `DEFERRED` rows.
- AD-063, the user's access decision.
- Annotator materials, errata delivery, the dataset-card erratum, and any validator, schema or pipeline change.
- Training stays unauthorised. The quality gate stays **OPEN**.

## 10. Index — v1.1 values for every row on this agenda (copied, unchanged)

| ID | v1.1 status | v1.1 basis | v1.1 rec | Agenda | Position |
|---|---|---|---|---|---|
| AD-001 | REC | ES | a | §2 | E |
| AD-002 | PPOD | OJ | a | §4 | O |
| AD-003 | PPOD | OJ | a (if AD-064 a) / c | §4 | O |
| AD-005 | REC | ES | a | §2 | E |
| AD-006 | REC | ES | a | §2 | E |
| AD-008 | PPOD | OJ | a | §4 | EL |
| AD-013 | REC | ES | a | §2 | E |
| AD-016 | PPOD | OJ | L1 | §3.1 | O |
| AD-017 | PPOD | OJ | a | §3.2 | O |
| AD-018 | PPOD | OJ | a | §3.2 | O |
| AD-019 | PPOD | OJ | a | §3.2 | O |
| AD-021 | PPOD | OJ | a | §3.3 | O |
| AD-022 | REC | ES | a | §2 | E |
| AD-024 | PPOD | OJ | b (if L0/L1) | §3.3 | O |
| AD-025 | PPOD | OJ | b (if L0/L1) | §3.3 | O |
| AD-026 | PPOD | OJ | a | §3.3 | O |
| AD-027 | PPOD | OJ | b (if L0–L2) | §3.3 | O |
| AD-028 | PPOD | OJ | b (if L0–L2) | §3.3 | O |
| AD-038 | PPOD | OJ | a | §6 | EL |
| AD-039 | PPOD | OJ | d (interim) | §6 | O |
| AD-040 | PPOD | OJ | none | §5 | O |
| AD-041 | PPOD | OJ | c | §5 | O |
| AD-042 | PPOD | OJ | none (moot if AD-041 c) | §5 | O |
| AD-043 | REC | ES | a | §2 | E |
| AD-044 | PPOD | OJ | b | §6 | EL |
| AD-046 | REC | ES | a | §2 | E |
| AD-047 | PPOD | OJ | a | §6 | O |
| AD-064 | PPOD | OJ | a | §4 | O |
| AD-065 | PPOD | OJ | a | §4 | O |

**Abbreviations:**
- Status: REC = `RECOMMENDED_FOR_ADOPTION`; PPOD = `PENDING_PROJECT_OWNER_DECISION`.
- Basis: ES = `EVIDENCE_SUPPORTED`; OJ = `OWNER_JUDGMENT`.

29 rows are on the agenda: 7 at position E, 3 at EL and 19 at O. Nothing is ratified.
