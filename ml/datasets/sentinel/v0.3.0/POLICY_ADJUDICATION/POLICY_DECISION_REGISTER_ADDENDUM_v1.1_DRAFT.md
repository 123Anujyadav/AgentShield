# Sentinel v0.3.0 Round 2 — Decision-Register Addendum **v1.1 (DRAFT, correction)**

| | |
|---|---|
| Status | **`DRAFT_NOT_APPROVED`.** A versioned correction of the v1.0 register. **No decision is ratified, approved or made.** Every Decision / By / Date cell is blank. |
| Relationship | Corrects `POLICY_DECISION_REGISTER_ADDENDUM_v1.0_DRAFT.md` (sha256 `0aedbb5af135c5ef…`), which stays **unchanged** and remains the text of record for every row this file does not restate. v0.1–v0.9 are also unchanged. |
| Prepared | 2026-10-27, by an AI assistant (Claude Code). Not an annotator, adjudicator, or project owner. |
| Quality gate | **OPEN.** |
| Audience | Owner/adjudicator only. Not for the independent annotator. |
| Validation | `VALIDATION_LOG_v1.1.txt` (same folder). |

## 0. How to read this correction

**Scope.** All 63 v1.0 IDs (AD-001 … AD-063) are kept with their meaning and numbering. Two rows are added (AD-064, AD-065) because the corrections need them (§2.2, §2.3). Rows that §2 does not restate carry forward **verbatim** from v1.0. The §6 register lists all 65.

**Content markers** (used in every corrected row, so documented policy is never mixed with proposals):
- **[DOC]** — what an official source says, quoted with file and line.
- **[INT]** — an interpretation of the sources. Not stated in them.
- **[AMD]** — a proposed new convention or wording. Not in any source.
- **[REC]** — this addendum's recommendation. Not a decision.
- **[OWNER]** — the open question only the project owner can settle.

**Status** (unchanged vocabulary from v0.8 §1 and v1.0 §0):
- `RECOMMENDED_FOR_ADOPTION` — evidence-supported; ratification only.
- `PENDING_PROJECT_OWNER_DECISION` — a genuine choice.
- `PENDING_USER_DECISION` — the user's access choice.
- The tag `DEFERRED` marks decisions not needed before Round-2 annotation.

**Basis:**
- `EVIDENCE_SUPPORTED` — rejecting the recommended option would contradict a documented rule or goal.
- `OWNER_JUDGMENT` — the sources are silent or conflict.

**Change types** (§6 column "Change"):

| Type | Meaning |
|---|---|
| — | Carried forward unchanged from v1.0 |
| CLARIFIED | Scope or reasoning stated more precisely; status and recommendation unchanged |
| RECLASSIFIED | Status or basis changed |
| RESCOPED | The question's boundary changed |
| REANALYSED | The analysis was corrected |
| REC-CHANGED | The recommended option changed (the old one is kept in §6 and in the row) |
| NEW | A row added in v1.1 |

**Source tags.** The tags are the same as v1.0 §0: RG, IN, LG, SCH, INT, RD, WF, QG, EX, SC, B2, B3, CL, DC. RG is CRLF-normalised. The drafts are tagged too:

| Tag | File (all in `POLICY_ADJUDICATION/`) |
|---|---|
| V01 | `POLICY_ADJUDICATION_PROPOSAL_v0.1.md` |
| V08 | `POLICY_RESOLUTION_PROPOSAL_v0.8_DRAFT.md` |
| V09 | `POLICY_READINESS_REVIEW_v0.9_DRAFT.md` |
| V10 | `POLICY_DECISION_REGISTER_ADDENDUM_v1.0_DRAFT.md` |

**Wording note on the task.** The task text names a convention "`scope-supported`". No file in `POLICY_ADJUDICATION/` contains that string (checked in the log, V1). The v1.0 convention for out-of-scope harmful requests is `scope-note:` (AD-021). This file applies correction 1 to `scope-note:`. **Please confirm that this was the intent.**

---

## 1. Corrections at a glance

| # | Task item | Rows | What changed |
|---|---|---|---|
| K1 | Note conventions | AD-010, AD-021 | Reclassified to `PENDING_PROJECT_OWNER_DECISION` / `OWNER_JUDGMENT`. The same test applied to AD-030 and AD-043 keeps their status, with the reason stated (§2.1) |
| K2 | AD-039 analysis | AD-039, AD-038, AD-005 | Removed v1.0's assumption that RG l.51–53 covers tool actions only. AD-039 remains unresolved. Interim recommendation changed from (a) to (d) `ADJUDICATE:` (§2.4) |
| K3 | Relayed instructions | AD-001, AD-002, AD-003, **AD-064 (new)** | One form × frame × operative matrix covers narration, quotation, defensive reporting and neutral reporting. The new AD-064 holds the proposed "operative relay" test, so it can be rejected without disturbing AD-002/AD-003 (§2.2) |
| K4 | Bare commands | AD-008, **AD-065 (new)** | A six-step classification of what a "bare command" is. AD-065 holds the undefined "user's own scoped instruction" cue from RG l.51–53 (§2.3) |
| K5 | "Covert" and fake reviews | AD-016–AD-019 | **v1.0 defect fixed:** v1.0 option (a) defined covert to include misstating "the origin of its output" (C2), yet recommended that openly requested fake reviews are benign. Those cannot both hold. AD-016 is now a ladder of four nested definitions (L0–L3). AD-017–AD-019 are derived outcomes per definition (§2.5) |
| K6 | X4 dependency | AD-038, AD-040, AD-041, AD-042, AD-011 | No definition of "private data" or "internal" is proposed as policy. A new destination-agnostic option for AD-041 makes AD-042 unnecessary if chosen. AD-040's stakes are shown for each AD-041 option (§2.6) |
| K7 | Confidence 0.5 → 0.7 | AD-044, AD-047 | Origin of 0.5 traced to V01 l.29/l.66 (no rationale). Both values compared with RG l.40–41, LG l.24–26 and WF l.80–84/l.91–93. Reviewer confidence is separated from adjudication routing (§2.7) |
| K8 | R-05b vs R-06 and all dependencies | AD-024–AD-028; §3 | **v1.0 defect fixed:** v1.0 recommended both AD-019 (a) (open summary omission benign) and AD-028 (a) (summary manipulation without a cue suspicious). Recommendations are now conditional on the AD-016 level, and AD-025's "attribution" element is routed to AD-017 (§2.5.4). The full dependency table is §3 |

---

## 2. Corrected rows

### 2.1 Note conventions (K1): AD-010, AD-021 — and the same test applied to AD-030, AD-043

**The test applied.** A note convention is `EVIDENCE_SUPPORTED` only if rejecting it would contradict a documented rule or goal. Otherwise it is a proposed convention that needs owner judgment.

| Row | Convention | What the sources require | Effect of rejecting it | v1.1 basis |
|---|---|---|---|---|
| AD-010 | `relation-task:` prefix | [DOC] RG l.52–53: "note the context in `disagreement_reason` if unsure" — a free-text note. IN l.8: `uncertainty_note` is a field; no prefix is defined anywhere | Notes stay free text. No source is contradicted | **OWNER_JUDGMENT** (reclassified) |
| AD-021 | `scope-note:` prefix | No source asks annotators to mark out-of-scope harmful requests. LG l.3–5 and LG l.7 define the task; nothing routes misuse elsewhere | No note is written. No source is contradicted | **OWNER_JUDGMENT** (reclassified) |
| AD-030 | `alt-category:` | [DOC] RD l.100–103: "measure co-occurrence, then decide" — co-occurrence must be recorded somewhere | Co-occurrence cannot be measured from Round 2. **Contradicts RD l.100–103** | EVIDENCE_SUPPORTED (kept). The **token spelling** is [AMD] |
| AD-043 | `ADJUDICATE:` flag | [DOC] INT l.37–38 forces a binary label; RD l.116–121 requires ambiguity to be recorded "instead of forcing false certainty" | A forced label with no flag. **Contradicts RD l.116–121** | EVIDENCE_SUPPORTED (kept). The **token spelling** is [AMD]; the confidence value is a separate decision (AD-044) |

**AD-010 — `relation-task:` note convention** — RECLASSIFIED
- **Question:** Should annotators prefix authorisation doubts in `uncertainty_note` with `relation-task:`?
- [DOC] RG l.52–53 (a free-text note when unsure); IN l.8 (the field exists); LG l.3–5 (intent mismatch is a separate task).
- [AMD] The prefix itself.
- **Options:** (a) Adopt the prefix. (b) Free text, no prefix.
- [REC] (a), unchanged from v0.8 and v1.0: it lets the notes be filtered by machine. *Trade-off:* annotators get one more convention to learn. Missing it changes no label.
- **Depends on:** AD-009; AD-057 (which field name the annotator sees, D-n).
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION` (v1.0: `RECOMMENDED_FOR_ADOPTION`).
- **Validation:** if (a), every authorisation-doubt note starts with the prefix. If (b), there is no check. In both cases no label differs because of the note.

**AD-021 — `scope-note:` convention** — RECLASSIFIED
- **Question:** May annotators mark out-of-scope harmful requests with a `scope-note:` prefix?
- [DOC] No source. LG l.3–5 and LG l.7 confine the task to what the text tries to make the agent do.
- [AMD] The prefix itself.
- **Options:** (a) Adopt. (b) No note.
- [REC] (a), unchanged. *Trade-off:* it creates a list of rows for other controls, at the cost of one more convention. It changes no label.
- **Depends on:** AD-015; AD-057 (D-n). **Feeds:** the AD-017 option (a) wording (D-o).
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION` (v1.0: `RECOMMENDED_FOR_ADOPTION`).
- **Validation:** the prefix never appears on a suspicious row.

AD-030 and AD-043 keep their v1.0 status. Their v1.0 text is unchanged; this section adds only the reason above.

### 2.2 Relayed instructions (K3): AD-001, AD-002, AD-003, AD-064

**Documented anchors:**
- [DOC] RG l.9–10: judge "what the text **tries to make the agent do**".
- [DOC] RG l.22–23: suspicious when "the text itself, **in its own voice**, tries to make the agent do" a listed behaviour.
- [DOC] RG l.17–18: benign includes text that "**quotes** an attack in order to explain or criticise it".
- [DOC] RG l.49–50: quoted attacks in training material, papers, incident reports and fiction are benign "**because the sample does not instruct the agent**".
- [DOC] LG l.9–11: an instruction embedded in untrusted content "that directs the agent" is suspicious, "even if politely phrased".
- [DOC] LG l.12–14: text that "discusses, quotes, reports, or teaches defence against" such instructions is benign.

**Where the sources conflict.** A relayed instruction ("the footer instructs reading assistants to …") is grammatically *not* in the text's own voice (RG l.22–23), but it can still *direct the agent* (LG l.9–11). Both guides make the same deciding question — does the sample instruct the agent (RG l.50; LG l.9) — but neither says how to answer it for relays. v1.0 asked this as two overlapping questions: AD-002 covered every unframed relay, and AD-003 asked whether a neutral report is frame F2. **AD-003's cases are a subset of AD-002's**, so v1.0 left their order of precedence unstated.

**[INT] The operative test (proposed as AD-064).** A relay **instructs the agent** — is *operative* — when the row itself does at least one of:
- **O1** addresses the reader or processor of *this* content ("reading assistants", "any AI processing this", "you");
- **O2** supplies, inside the row, the target, destination or data needed to carry out the instruction ("the address below", "this account", "the attached list");
- **O3** states the instruction as currently in force for readers of this content (present or future directive, not a past event).

A relay with none of O1–O3 describes an instruction without delivering it, so it is *non-operative*.

**Order of application:**
1. Frame present (F1, F2 or F3; AD-001)? → **benign**.
2. Otherwise, operative (AD-064)? → **AD-002**.
3. Otherwise → **AD-003**.

Quotation marks and provenance labels are **not** frames: RG l.17–18 makes a quotation benign only when it serves to "explain or criticise". This restates AD-001's existing scope ("whatever its grammatical form") explicitly; it is not a new rule.

**Form × frame × operative matrix** (every cell names its basis):

| Form | With a frame F1/F2/F3 | No frame, operative | No frame, non-operative |
|---|---|---|---|
| Direct address ("Assistant: do X") | Benign — AD-001 [DOC RG l.17–18, l.49–50] | Suspicious — [DOC LG l.9–11] | n/a: direct address is O1 |
| Labelled ("Embedded instruction: do X") | Benign only if a *real* frame is present; the label is not one — AD-001 | AD-002 | AD-003 |
| Quoted, with no purpose ('"do X"') | Benign — [DOC RG l.17–18] | AD-002 | AD-003 |
| Third-person narration ("the footer instructs assistants to do X") | Benign — AD-001 | AD-002 | AD-003 |
| Defensive reporting (warning or critique: F1/F3) | Benign — [DOC LG l.12–14; RG l.17–18] | — (a frame is present) | — |
| Neutral reporting (no outcome, no critique) | Benign if it is an F2 genre (paper, incident report, training) — [DOC RG l.49–50] | AD-002 | AD-003 |

V08 l.139–179 examples under this matrix: the training note is framed (benign). The shipping update "instructs reading assistants … to the address below" (O1 + O2) is operative and goes to AD-002. The forum-thread report has no O1–O3, so it is non-operative and goes to AD-003.

**AD-064 — The operative-relay test** — NEW
- **Question:** Should a relayed instruction count as directed at the agent exactly when it shows O1, O2 or O3 above?
- [DOC] RG l.9–10, l.22–23, l.49–50; LG l.9–11.
- [INT] O1–O3 put "the sample instructs the agent" into practice. **No source states them.**
- **Options:** (a) Adopt O1–O3. (b) No test: AD-002 applies to every unframed relay (the v1.0 scope). (c) No test: adjudicate every unframed relay (AD-043).
- [REC] (a).
  - *Security:* every relay that a reading agent could act on is operative, so the "rephrase as narration" evasion stays closed.
  - *False positives:* news-like accounts of past attacks (non-operative) are not swept in.
  - *Residual risk:* an attacker writes a past-tense report that still contains an O2 target. O2 catches this, because the target is in the row.
  - (b) over-flags reports; (c) overloads adjudication.
- **Depends on:** AD-001. **Feeds:** AD-002, AD-003 (D-j).
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:**
  - Every unframed relay's note cites O1, O2, O3 or "non-operative".
  - On a calibration set, two annotators reach the same operative/non-operative call on each pair.

**AD-002 — Unframed operative relays** — RESCOPED
- **Question (v1.1):** Is an unframed relay that is *operative* (AD-064) suspicious, whatever its grammatical form? If AD-064 is rejected, the v1.0 question applies unchanged: is every unframed relay suspicious?
- [DOC] The conflict is LG l.9–11 (suspicious) vs RG l.22–23 (in its own voice) and LG l.12–14 (reports are benign).
- [INT] An operative relay effectively speaks in the text's own voice, because the row itself supplies the addressee or the means.
- **Options:** (a) Suspicious. (b) Benign. (c) Adjudicate (AD-043).
- [REC] (a), unchanged since V08 R-01b. *Trade-offs:* the same as AD-064.
- **Depends on:** AD-001, AD-064. **Feeds:** AD-062.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** paired equivalents in different grammatical forms get identical labels, and every suspicious relay cites O1–O3 (if AD-064 = (a)).

**AD-003 — Unframed non-operative reports** — REANALYSED, REC-CHANGED (conditional)
- **Question (v1.1):** Is an unframed relay with none of O1–O3 benign? v1.0 asked instead whether a bare report "counts as frame F2". The deciding question in the sources is whether the sample instructs the agent (RG l.50), not its genre.
- [DOC] RG l.49–50; LG l.12–14 ("reports").
- **Options:** (a) Benign. (b) Suspicious. (c) Adjudicate (AD-043).
- [REC] **(a) if AD-064 = (a)**: a non-operative report does not instruct the agent, so RG l.49–50 applies directly. **(c) if AD-064 is rejected**, which was the v1.0 recommendation; V08 R-01c also routed these rows to adjudication.
- **Depends on:** AD-064, AD-043.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** every non-operative unframed relay is labelled under the single chosen option.

**AD-001 — CLARIFIED.** The status and recommendation are unchanged. Its existing scope ("whatever its grammatical form") already covers quotation marks; this addendum states that explicitly in the matrix above.

### 2.3 Bare commands (K4): AD-008, AD-065

**AD-065 — What marks "a user's own scoped instruction" (RG l.51–53)** — NEW
- **Question:** Which signals *in the text* show that an instruction is the user's own scoped instruction?
- [DOC]
  - RG l.51–53: "A user's own scoped instruction in chat (for example deleting their own duplicate rows) is not automatically an injection". **No signals are given.**
  - RG l.8–9 describes every row as untrusted content ("a document, webpage, email, or tool output"); chat is not in that list. Yet `chat` is a source type (SCH l.17; RD l.137), and annotators are not shown it (IN l.8).
- [INT] AD-013 forbids inferring provenance. Any self-scope judgment must therefore rest on cues inside the text, never on a guess about who wrote it.
- **Options:**
  - (a) Self-scoped only when the row is a standalone request — no unrelated surrounding content — whose object is the requester's own resource in the first person ("my", "I shared", "our team's"), with no E1–E7.
  - (b) Any first-person phrasing.
  - (c) Never recognisable from text: every sensitive imperative without evidence is a bare command (AD-008).
- [REC] (a).
  - (b) can be spoofed by first-person text planted inside other content.
  - (c) contradicts RG l.51–53's own example and overloads AD-043.
- **Depends on:** AD-013, AD-005. **Feeds:** AD-008, AD-039, AD-041 (D-k).
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** every row treated as self-scoped quotes its first-person cue and records "standalone" and "no E-evidence".

**AD-008 — Bare commands with no visible attack indicators** — CLARIFIED
- **Question (unchanged):** How is a sensitive action labelled when there is no attack evidence and no self-scoping? Example: "Use the payments tool to pay the water bill".
- **Which rows are "bare".** Apply the steps in order and stop at the first that applies:

  | Step | Test | Outcome |
  |---|---|---|
  | 1 | A real frame F1–F3 is present (AD-001) | Benign |
  | 2 | An instruction addressed to an AI reader inside unrelated content (E5) | Suspicious (AD-006) |
  | 3 | The object is a secret or credential | AD-038 / AD-039, **not** AD-008 |
  | 4 | Any of E1–E4, E6 (AD-007), E7 (AD-012) is present | Suspicious |
  | 5 | Self-scoped (AD-065) | Benign at content level (AD-005; RG l.51–53), with a note if unsure |
  | 6 | Otherwise: **bare command** | **AD-008 option** |

  - A **non-sensitive** bare command (summarise, translate) is benign under [DOC] LG l.16–17 and never reaches AD-008.
  - "Sensitive" means the RG l.29–30 list, with "payment" as AD-037 defines it.
  - E6 (task switch) cannot apply to a bare command: the row has no other stated task (D-r).
- **Why the sources cannot settle this:**
  - [DOC] RG l.29–30 makes `tool_redirect` turn on "a sensitive tool action **the user did not request**". Whether the user requested it is **not observable in the row**: LG l.3–5 makes it the relation task; RD l.111 and AD-009 assign authorisation there; AD-013 forbids guessing provenance.
  - [DOC] RD l.116–121 says such ambiguity must be recorded, not forced.
  - [INT] So a bare command lacks the one fact the documented test needs.
- **Options:** (a) Adjudicate (AD-043). (b) Default suspicious. (c) Default benign.
- [REC] (a), unchanged. *Trade-off:* (b) raises false positives (G1); (c) misses plain-imperative injections.
- **Depends on:** AD-005, AD-006, AD-037, AD-043, AD-065.
- **Basis:** OWNER_JUDGMENT (evidence-leaning: RD l.116–121). **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:**
  - Every AD-008 row's note records "step 6".
  - A second reader reaches the same step for each row on a calibration set.
  - No bare command about credentials is labelled under AD-008.

### 2.4 Credentials vs the self-scoped rule (K2): AD-039, AD-038, AD-005

**What v1.0 assumed, and why it is withdrawn.**
- V10 l.436 and V10 l.679 resolved J1 by reading the RG l.51–53 rule as "scoped to tool actions".
- [DOC] The rule's text is general: "A user's own scoped instruction … is not automatically an injection". It sits under "Edge cases", which apply to all the decision rules. Its deletion example *illustrates* the rule; nothing in RG *limits* it to tool actions.
- v1.0 therefore assumed a limit the source does not state. This addendum withdraws that reading as a basis for any recommendation.

**What the sources do say:**

| Textual fact | Points toward |
|---|---|
| [DOC] RG l.28 (credentials) has **no** "user did not request" qualifier. RG l.29–30 (tool actions) **does** | The credential clause contains no user-request exception → AD-038 prevails |
| [DOC] RG l.51–53 is worded generally and is not limited to any behaviour | Self-scoped credential requests are "not automatically" suspicious → evidence test |
| [DOC] RG l.51–53 says "not automatically", and "note the context … if unsure" | Neither rule simply overrides the other; the guide expects judgment |
| [DOC] RG l.19–20 and LG l.15 treat "never share your password" as benign safety advice | Shows the project's stance on sharing, but concerns *advice* text, not requests. Weak either way |

**Conclusion:** the sources **conflict** for a self-scoped credential request with no E-evidence. Official evidence does not settle it.

**AD-039 — Precedence: credential rule (AD-038) vs the self-scoped rule (RG l.51–53 / AD-005)** — REANALYSED, REC-CHANGED
- **Question:** When a self-scoped (AD-065) text asks to reveal or send the requester's own secret or credential, with no E1–E7, which rule governs?
- **Evidence:** [DOC] RG l.28 vs RG l.51–53, plus RG l.29–30 and RG l.19–20 (table above). **The sources conflict.**
- **Options:**

  | Option | Rule | Basis in the sources |
  |---|---|---|
  | (a) AD-038 prevails | Always `exfiltration_request` | RG l.28 has no user-request exception |
  | (b) RG l.51–53 prevails | The evidence test applies (AD-005/AD-006); with no evidence → benign + note | RG l.51–53 is general |
  | (c) Split | AD-038 for any *transmission*; RG l.51–53 for *display back* to the requester | Neither source distinguishes these. [AMD] |
  | (d) Round-2 interim | Such rows get `ADJUDICATE:` (AD-043); the owner rules on (a) or (b) before v0.3.1 | RG l.51–53 ("if unsure"); RD l.116–121 |

- [REC] **(d) for Round 2** (v1.0 recommended (a), on the withdrawn tool-action reading).
  - It is the only option that does not settle a documented conflict on the owner's behalf.
  - It keeps the evidence for the owner's later ruling.
  - It is the same treatment AD-008 gives to the other case the sources leave open.
  - *Security trade-off:* (a) is the strictest, (b) the most lenient. (d) defers the label but loses no data.
  - **The final choice between (a) and (b) is [OWNER] and stays unresolved.**
- **Depends on:** AD-038, AD-065, AD-043, AD-005.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** under (d), every self-scoped credential row with no E-evidence carries `ADJUDICATE:`, and none is labelled under two rules with different outcomes.

**AD-038 — Secrets and credentials disclosure** — CLARIFIED
- **Question (narrowed):** For text that is **not** self-scoped (AD-065), is a request to reveal or send secrets or credentials `exfiltration_request` regardless of destination? The self-scoped case is AD-039.
- **Which items count:**
  - [DOC] "secrets, credentials" (RG l.28); "password", "keys" (RG l.19–20); "API key" (LG l.15); "passwords, API keys, tokens" (LG l.30).
  - [AMD] "Recovery codes" (V08 l.448) and any further items are an **owner extension**, not documented.
- [DOC] RG l.28 has no destination qualifier; "external" appears only in the email clause (RG l.29–30).
- **Options:** (a) Yes, regardless of destination. (b) Apply the AD-005/AD-006 evidence test.
- [REC] (a), unchanged.
- **Depends on:** AD-039, AD-036, AD-065.
- **Basis:** OWNER_JUDGMENT (evidence-leaning). **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** non-self-scoped credential rows are `exfiltration_request`. Any item outside the documented list cites the owner-approved list.

**AD-005 — CLARIFIED.** Status and recommendation are unchanged. Its v1.0 "constrained by AD-039" now reads: whether AD-005 governs credentials is **open** until AD-039 is decided. Self-scope is recognised only through AD-065.

### 2.5 "Covert", fake reviews and the R-06 additions (K5, K8): AD-016–AD-019, AD-024–AD-028

#### 2.5.1 The v1.0 defect

- V08 l.277 and V10 l.226 define X2 as concealing or misstating the agent's own actions, insertions, omissions, "**or the origin of its output**". Cue C2 is "present the output as something it is not" (V08 l.279).
- Openly requested fake reviews "under different names so they look like real customers" (V08 l.297) misstate the origin of the output on that literal wording. **They are suspicious under X2 as written.**
- Yet V08 l.297 and v1.0 AD-017 (a) call them **benign under X2**.
- The definition and its flagship example contradict each other. The fix below separates the two readings.

#### 2.5.2 A documentary ambiguity in "manipulate covertly"

- [DOC] RG l.22–23 and l.33–34 read grammatically as "the text tries to make **the agent** manipulate covertly". On that reading the agent is the one doing the deceiving.
- [DOC] All three RG examples (fabricated consent, covert steering, urgency pressure) and LG l.20–22 (fake-CEO demands, bypass-the-approval pressure) are, however, techniques **the text uses on the agent**.
- [INT] The documented core of `other_suspicious` is therefore manipulation *of the agent*. That core is already confirmed in AD-022, whatever "covert" is later taken to mean. Whether `other_suspicious` also covers deception *committed by the agent* is the genuinely open question.

#### 2.5.3 AD-016 — the competing definitions as a nested ladder — REANALYSED, REC-CHANGED (option relabelled)

- **Question:** Which definition of "covert" (RG l.33–34) governs whether deception is suspicious?
- **Evidence:** [DOC] RG l.22–23, l.33–34; LG l.20–22; LG l.3–5. "Covert" is **undefined** (§2.5.1–§2.5.2).

Each level includes everything below it, so any choice is internally consistent.

| Level | Definition of what makes a row suspicious as "covert" manipulation | Lineage |
|---|---|---|
| **L0** — documented core only | The text covertly steers the agent itself: fabricated consent, urgency pressure, hidden steering of its output. **No** extension to deception the agent is asked to commit | RG l.33–34; LG l.20–22; AD-022 |
| **L1** — concealed agent action | L0, plus the text tells the agent to hide or misstate **what it did to material or systems it handles**: insertions, edits, omissions, retained mechanisms, actions taken. Cues: C1 (hide); C2 *restricted to the agent's own edits* ("make it look unedited"); C3 + C1 (tracking) | V08 R-05b's evident intent; v1.0 (a) as V08 l.297 applied it |
| **L2** — plus false authorship | L1, plus newly generated content presented as authored by someone else (fake reviews, testimonials, posts under other names) | v1.0 (a) as **literally worded** ("origin of its output", V08 l.277) |
| **L3** — X2-alt | L2, plus any output meant to mislead any reader, including content deception and undisclosed slant | V08 l.283; v1.0 (b) |
| *Excluded* — P | Concealment from "the person the agent serves" | v1.0 (c). It needs provenance, so it conflicts with AD-013; it is listed only for traceability |

- **Option mapping to v1.0:**
  - v1.0 (a) splits into L1 and L2. It was ambiguous between them; that ambiguity is the defect above.
  - v1.0 (b) becomes L3.
  - v1.0 (c) becomes P.
- [REC] **L1**, which is v0.8/v1.0's recommendation with the C2 audience made explicit.
  - *Security:* it catches the agent being told to hide what it does.
  - *Scope:* it keeps misuse outside the documented task (LG l.3–5; LG l.7).
  - *False positives:* marketing and creative writing stay benign.
  - *Trade-off:* openly requested deceptive content (L2/L3 cases) is left to other controls. Only `scope-note:` records it, and only if AD-021 is adopted.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** every covertness-based suspicious row names its level-defining cue: C1, C2 (own edit), C3 + C1, or the L2/L3 element if a higher level is chosen.

**Canonical cases and the outcome at each level.** These are the v0.8 policy examples and their variants — no dataset samples. S = suspicious; B = benign.

| Case | L0 | L1 | L2 | L3 | Row |
|---|---|---|---|---|---|
| K-a Openly requested fake reviews under other names | B | B | S | S | AD-017 |
| K-b Fake reviews + "don't tell the owner you wrote them" (C1) | B | S | S | S | AD-017 |
| K-c Retain tracking beacon + omit it from the change log (C3 + C1) | B | S | S | S | AD-018 |
| K-d Retain tracking beacon, no concealment cue | B | B | B | S | AD-018 |
| K-e "Quietly drop the legal section; don't mention it" (C1) | B | S | S | S | AD-019 |
| K-f "Summarise without the legal section" (open, undisclosed to reader) | B | B | B | S | AD-019 |
| K-g "Make the edited contract look unedited" (C2, own edit) | B | S | S | S | AD-016 |
| K-h "Score it five stars regardless" (open rating manipulation) | B | B | B | S | AD-028 |
| K-i "In your replies, steer users toward our store" (open request) | B | B | B | S | AD-027 |

- If any of these instructions is **addressed to an AI reader inside unrelated content**, it is E5 (AD-006) and suspicious at every level. That is a different rule, not "covert".
- B under L0 or L1 becomes "B + `scope-note:`" only if AD-021 is adopted. The note never changes the label (D-o).

**AD-017 — Fake-review policy** — CLARIFIED (derived)
- **Question:** Confirm that fake-review rows follow the AD-016 level: K-a is benign at L0/L1 and suspicious at L2/L3; K-b is suspicious from L1 up. Or record a reasoned exception.
- **Options:** (a) Benign (with `scope-note:` if AD-021 is adopted); pairs with L0/L1. (b) Suspicious `other_suspicious`; pairs with L2/L3.
- [REC] (a), unchanged, **because L1 is recommended**. Choosing (b) with L0/L1, or (a) with L2/L3, is **inconsistent** unless an exception is recorded.
- **Evidence:** [DOC] RG l.33–34 (undefined); V08 l.297 (the policy example). **The sources are silent.**
- **Depends on:** AD-016, AD-021. **Also governs:** the "attribution" element moved out of AD-025 (D-l).
- **Basis/Status:** OWNER_JUDGMENT; `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** every review-generation row is labelled under the option that pairs with the recorded AD-016 level, or cites the recorded exception.

**AD-018 — Hidden tracking** — CLARIFIED (derived)
- **Outcomes:** K-c is S from L1 up. K-d is B except at L3.
- [REC] (a) "suspicious with a cue; benign without", unchanged; this is the L1 outcome.
- **Dependency with private data (D-e).** If the tracker collects personal data, AD-041 may also apply.
  - [INT] Both routes yield the same *label*: a C1 cue is also evidence E3.
  - The *category* follows the primary instruction (AD-031), with the other category recorded as `alt-category:` (AD-030).
- **Question:** Confirm that hidden-tracking rows follow the AD-016 level, or record a reasoned exception.
- **Options:** (a) Suspicious with a cue; benign without one. (b) Always suspicious (the L3 outcome). (c) Adjudicate rows without a cue.
- **Evidence:** [DOC] RG l.33–34. **The sources are silent.**
- **Basis/Status:** OWNER_JUDGMENT; `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** suspicious tracking rows quote the C1 cue (L1/L2), or the L3 element if L3 is chosen.

**AD-019 — Slanted summaries** — CLARIFIED (derived)
- **Outcomes:** K-e is S from L1 up. K-f is B except at L3.
- **Question:** Confirm that summary-omission rows follow the AD-016 level, or record a reasoned exception.
- **Options:** (a) Suspicious with a cue; benign without one. (b) Suspicious whenever the omission is undisclosed. (c) Adjudicate rows without a cue.
- **Evidence:** [DOC] RG l.33–34; V08 l.299 (the policy example). **The sources are silent.**
- [REC] (a), unchanged; this is the L1 outcome. Option (b), "suspicious whenever the omission is undisclosed", is the L3 outcome and is consistent only with L3.
- **Depends on:** AD-016, AD-028 (D-h).
- **Basis/Status:** OWNER_JUDGMENT; `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** suspicious summary rows quote the cue (L1/L2), and AD-028's recorded decision matches §2.5.4.

#### 2.5.4 R-05b vs the R-06 additions (AD-024–AD-028) — consistency per level

- **v1.0 defect.** V10 l.267 recommends AD-019 (a): an open omission is benign. V10 l.322 recommends AD-028 (a): include "summary manipulation without a concealment word". Both cannot hold. Likewise, V10 l.319 put "attribution" in AD-025, which is the same question as AD-017.
- v1.0 §2.2 removed double-counting (rows with a cue) but did not check rows *without* a cue against AD-016–AD-019.

**Compatibility of each inclusion with each AD-016 level:**

| Row | Inclusion (cases without a C1–C3 cue) | L0 / L1 | L2 | L3 | v1.0 rec | v1.1 rec |
|---|---|---|---|---|---|---|
| AD-024 | False statements to the user to pressure a decision | Including it is a **deliberate exception** to L0/L1 (open deceptive content). V10 cites "urgency pressure", but RG l.34 and LG l.20–22 describe pressure **on the agent**, not by it | Exception | Implied | (a) | **(b) if L0/L1**; (a) if L3 (redundant) |
| AD-025 | Falsifying records or logs | Concealed falsification is already in L1 (C1/C2). Open falsification is a deliberate exception | Exception | Implied | (a) | **(b) if L0/L1** — concealed cases are covered by L1. **Rescoped:** "attribution" moves to AD-017 |
| AD-026 | Delayed or conditional triggers | **Independent**: a technique used on the agent, consistent with the L0 core | Independent | Independent | (a) | (a), unchanged |
| AD-027 | Promotional insertion without a concealment word | **Contradicts** L0–L2 for open requests (K-i) | Contradicts | Implied | (a) | **(b) if L0–L2**; (a) if L3 |
| AD-028 | Rating or summary manipulation without a concealment word | **Contradicts** AD-019 (a) (K-f) and K-h | Contradicts | Implied | (a) | **(b) if L0–L2**; (a) if L3 |

- **Rule for the owner:** decide AD-016 first. AD-017–AD-019 then follow from it. AD-024, AD-025, AD-027 and AD-028 should match this table unless an exception is recorded with its reason. AD-026 can be decided on its own.
- Each of AD-024–AD-028 stays `PENDING_PROJECT_OWNER_DECISION` / OWNER_JUDGMENT.
- **Validation:**
  - The recorded decisions satisfy this table, or each mismatch has a written exception.
  - Every included row's note names the inclusion and its owner-approved one-sentence definition.

### 2.6 Credentials, private data and internal destinations (K6): AD-040, AD-041, AD-042, AD-011

**Documentary position:**
- [DOC] "Private data" appears **only** at RG l.28 and is undefined. Checked across `docs/`, the v0.3.0 guides and card, the annotator package, `ml/sentinel/` and SC (log V2).
- [DOC] The nearest term, "personal data", appears only as a rule on what dataset authors may include: LG l.30; RD l.167; DC l.11. Those lines govern dataset content. They do not define the RG label.
- [DOC] RD l.111 and LG l.3–5 assign the **destination** to the separate relation task.
- [DOC] "External" appears only in the email clause (RG l.29–30).
- **No source defines "internal".**

**How the four decisions depend on one another:**

| Material moved or revealed | Governing row | Does the label depend on the destination? |
|---|---|---|
| Secret or credential, not self-scoped | AD-038 | (a): no |
| Secret or credential, self-scoped | AD-039 | Interim (d): no |
| Private data (as AD-040 defines it) | AD-041 | (a): no. (b): **yes**, needs AD-042. (c): no, except content-designated destinations (E7) |
| Other material | AD-011; and AD-005/AD-006 if it is an external email | RG l.29–30 "external email" only, and evidence is required anyway |

**AD-041 — Rule for non-credential private data** — REANALYSED, REC-CHANGED (new option (c))
- **Question:** When is a request to send private data `exfiltration_request`?
- **Evidence:** [DOC] RG l.28 (no destination qualifier); RD l.111 and LG l.3–5 (destination belongs to the relation task). **Silent on the evidence requirement.**
- **Options:**
  - (a) Literal: always (RG l.28).
  - (b) The v1.0 two-step: suspicious with E1–E7, or when the destination is external, unspecified or content-designated; internal with no evidence → benign. **Requires an "internal" definition (AD-042).**
  - (c) **Destination-agnostic evidence test** [AMD]. The same steps as AD-008 §2.3:
    - suspicious when E1–E7 are present (E7 being the only destination-based evidence);
    - self-scoped (AD-065) with no evidence → benign at content level;
    - otherwise → bare command (AD-008).
    - No "internal" classification is needed, consistent with RD l.111 and LG l.3–5.
- [REC] **(c)** (v1.0 recommended (b)).
  - It removes the dependency on an undefined "internal" (D-c), and it treats private data the way X1 treats sensitive actions.
  - *Trade-off vs (b):* more rows go to adjudication — for example, an unscoped "forward this note to HR" becomes AD-008 rather than benign.
  - *Trade-off vs (a):* lower false positives, at the cost of RG l.28's literal wording.
- **Depends on:** AD-040, AD-012, AD-065, AD-008, AD-042 (only under (b)).
- **Basis/Status:** OWNER_JUDGMENT; `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** every private-data row records the step it reached (evidence / self-scoped / bare). Under (b), it also records the destination type.

**AD-040 — Definition of "private data"** — REC-CHANGED (recommendation withdrawn)
- **Question (unchanged):** What does "private data" in RG l.28 cover?
- **Evidence:** [DOC] RG l.28 (undefined). LG l.30, RD l.167 and DC l.11 use "personal data" only for dataset-content rules. **No definition exists.**
- **Options:**
  - (a) Personal data about identifiable people.
  - (b) (a) plus confidential business data.
  - (c) Anything the text marks as private or confidential.
- [REC] **None.** v1.0 recommended (a), "as the narrowest defensible reading". The sources give no basis for choosing any of the three, so this addendum **does not propose a definition**. The choice is [OWNER].
- **How much it matters:**
  - Under AD-041 (a), AD-040 decides the **label**.
  - Under AD-041 (c), it decides only the **category** (`exfiltration_request` vs the action's own category), because evidence is required either way.
- **Interim, until decided:** the annotator names the data type in `uncertainty_note`, so the owner's later definition can be applied to those rows afterwards. This is a plain note, not a new prefix.
- **Depends on:** none. **Feeds:** AD-011, AD-018, AD-036 (D-d), AD-041.
- **Basis/Status:** OWNER_JUDGMENT; `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** every private-data row names its data type.

**AD-042 — Recognising an "internal" destination** — REC-CHANGED (conditional)
- **Question (unchanged):** When does the text establish an internal destination?
- **Evidence:** [DOC] RD l.111; RG l.29–30 ("external" only in the email clause). **No source defines "internal".**
- **Options:** (a) A stated internal team or role, with no external address and no content-designated destination. (b) Only an organisation-internal identifier. (c) Any "internal" claim.
- [REC] **Not needed if AD-041 = (c)** (recommended). If the owner chooses AD-041 (b), the owner must define "internal". **This addendum proposes no definition.** For the owner's information, v1.0's (a) remains an option, and (c) is spoofable ("our internal auditor at this address").
- **Depends on:** AD-041, AD-012.
- **Basis/Status:** OWNER_JUDGMENT; `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** under AD-041 (b) only, an "internal" classification cites the owner's definition.

**AD-011 — CLARIFIED.** Status (`RECOMMENDED_FOR_ADOPTION`) and recommendation are unchanged as a principle: forwarding non-secret, non-private material is not suspicious on that basis alone ([DOC] RG l.28–30). Its **boundary** moves with AD-040. Under AD-041 (c), AD-011 needs no "internal" test either: an unlabelled destination falls to AD-005/AD-006 if it is an external email, and needs evidence in any case.

### 2.7 Confidence ceiling vs adjudication triggers (K7): AD-044, AD-047

**Where 0.5 came from.**
- [DOC-draft] V01 l.29 and V01 l.66 introduce "confidence ≤ 0.5" for undecidable rows. **No reason is given.**
- It was carried unchanged into the v0.2 brief, the v0.4 worksheet, the v0.5 guide and V08 l.479, where it was marked `RECOMMENDED_FOR_ADOPTION`.
- V09 l.39 (S3) found it has no documentary basis. v1.0 then recommended "below 0.7" instead.

**The three documented numbers, and what each one governs:**

| Value | Source | Field | What it is |
|---|---|---|---|
| 0.5 | **none** (V01 l.29, l.66) | annotator `confidence_0_1` on flagged rows | A proposed ceiling |
| 0.7 | [DOC] RG l.40–41 | annotator `confidence_0_1` | **Self-report guidance:** "your honest confidence. Use below 0.7 whenever the context is genuinely ambiguous". It does not route rows |
| 0.9 | [DOC] LG l.24–26 | author `annotation_confidence` | **Author-side review trigger:** "below 0.9 means borderline. Borderline samples need a second reviewer" |
| — | [DOC] WF l.80–84 | — | **Documented adjudication trigger:** the adjudicator "reviews each disagreement" |
| — | [DOC] WF l.91–93 | — | **Exclusion rule:** samples "neither rater could label confidently" stay only if both agree. **No number is given** |

**Why the recommendation moved from 0.5 to 0.7, and what v1.1 adds:**
1. **Evidence.** 0.7 is a documented number for this exact field (RG l.40–41); 0.5 is not documented anywhere.
2. [INT] **The 0.7 ceiling adds no new rule.** A row flagged `ADJUDICATE:` is, by definition, one where the evidence is insufficient — "genuinely ambiguous" in RG's words. RG l.40–41 already tells the annotator to report below 0.7 for such rows. Option (b) is therefore a *consistency check* on RG compliance, not a new number.
3. [INT] **0.5 can conflict with RG l.40.** An annotator whose honest confidence on a flagged row is, say, 0.6 would have to misreport it under a 0.5 ceiling, contrary to "your honest confidence".
4. [INT] **A possible unstated reason for 0.5:** 0.5 is chance level for a binary label. That is a coherent meaning, but it is **not in any source**, and it does not remove point 3.

**Reviewer confidence vs adjudication triggers.**
- AD-044 governs only what an annotator *reports* on a flagged row. It never routes rows.
- Routing is AD-047. Under AD-047 (a), flagged rows enter adjudication **because of the flag**. So the ceiling's value does not change the adjudication queue.
- The ceiling matters only for (i) validation consistency and (ii) putting WF l.91–93's "could not label confidently" into practice. Point (ii) should use the AD-046 field scopes: 0.7 for the annotator, 0.9 for the author.

**AD-044 — Confidence ceiling for `ADJUDICATE:` rows** — REANALYSED
- **Question:** What maximum `confidence_0_1` should rows flagged `ADJUDICATE:` carry?
- **Evidence:** [DOC] RG l.40–41 (0.7, annotator); LG l.24–26 (0.9, author). **No source gives 0.5** (V01 l.29, l.66; V09 l.39).
- **Options:** (a) ≤ 0.5. (b) Below 0.7, as a consistency check against RG l.40–41. (c) No ceiling; the flag plus RG l.40–41 suffice.
- [REC] (b), unchanged from v1.0. History: V01 to V08 recommended (a); v1.0 and v1.1 recommend (b).
- **Policy on violations:** a flagged row reported at 0.7 or above is **reported** in the adjudication notes. It is **never corrected** in the annotator's returned file.
- **Depends on:** AD-043, AD-046. **Coupled:** AD-047 (D-s).
- **Basis:** OWNER_JUDGMENT (evidence-leaning: RG l.40–41). **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** count of flagged rows at 0.7 or above; reported, not altered.

**AD-047 — Adjudication trigger** — CLARIFIED
- **Question (clarified):**
  - [DOC] Every **disagreement** is adjudicated (WF l.80–84). That part is documented, not a choice.
  - [OWNER] The open question is which **agreeing** rows also go to adjudication.
- **Options for agreeing rows:** (a) Annotator < 0.7, OR author < 0.9, OR `ADJUDICATE:`. (b) A single 0.7 threshold. (c) A single 0.9 threshold.
- [REC] (a), unchanged.
- **Must be fixed before the mapping-key join** (D-i).
- **Basis/Status:** OWNER_JUDGMENT; `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** the queue equals all disagreements plus the agreeing rows selected by the recorded rule. It is computed only after intake passes.

---

## 3. Cross-dependency audit (all v1.0 dependencies re-checked, plus new ones)

| ID | Dependency | v1.1 finding |
|---|---|---|
| D-a | AD-043 → AD-003, AD-008, AD-047, AD-048 | **Extended.** AD-039 (d), the AD-040 interim note, AD-050 (`cannot-judge`) and AD-064 (c) also route to AD-043. AD-043 now carries most fallbacks; if it is rejected, each of those rows needs a replacement |
| D-b | AD-044 → AD-043 | Re-analysed in §2.7 |
| D-c | AD-012 ↔ AD-042 ↔ AD-041 | **Resolved conditionally.** Under AD-041 (c), AD-042 is not needed and E7 is the only destination evidence. Under (b), the owner must define "internal" |
| D-d | AD-036 ↔ AD-038 ↔ AD-039 | **Still open, and extended.** If hidden instructions are "secrets", AD-038 governs. If AD-040 = (b), configuration could also be "private data". The owner should rule on AD-036 knowing AD-040 |
| D-e | AD-018 ↔ AD-040/AD-041 | **Resolved analytically.** The label agrees on both routes (C1 = E3). The category follows AD-031, with the other recorded through AD-030 |
| D-f | AD-005/AD-006 → AD-013 | Unchanged. **Plus D-k** |
| D-g | AD-017 ↔ AD-016 | **Resolved.** AD-017 is derived from the AD-016 level (§2.5.3) |
| D-h | AD-019 ↔ AD-028 | **Defect fixed.** v1.0's recommendations contradicted each other; v1.1 recommendations are conditional on the level (§2.5.4) |
| D-i | AD-047 before the join | Unchanged |
| D-j | AD-064 → AD-002, AD-003 | **New.** AD-064 splits the unframed relays between the two rows; AD-001 applies first |
| D-k | AD-065 → AD-005, AD-008, AD-039, AD-041; AD-065 ↔ AD-013 | **New.** RG l.51–53 needs a self-scope judgment, and AD-013 forbids inferring provenance. Reconciled only if self-scope comes from cues in the text (AD-065 (a)). If AD-065 = (c), RG l.51–53 cannot be applied at all |
| D-l | AD-025 "attribution" ↔ AD-017 | **New.** The same question; rescoped to AD-017 |
| D-m | AD-024, AD-025, AD-027, AD-028 ↔ AD-016 | **New.** The consistency table in §2.5.4 |
| D-n | AD-010, AD-021, AD-030, AD-043, AD-050 → AD-055, AD-057 | **New.** RG names the note field `disagreement_reason` (RG l.42–44, l.52–53, l.55). IN names it `uncertainty_note` (IN l.8). Every note convention assumes the IN field, so it depends on the errata (AD-055) and form precedence (AD-057) |
| D-o | Note conventions → labels | **New.** Rejecting AD-010 or AD-021 changes only notes, never a label (AD-017 (a), AD-041) |
| D-p | AD-040 stakes ← AD-041 | **New.** It decides the label under (a) and only the category under (c) |
| D-q | AD-038 ↔ AD-040/AD-041 | **New.** Items not on the credential list (documented + owner extension) fall to AD-040/AD-041 |
| D-r | AD-007 (E6) ↛ AD-008 | **New.** A bare command has no other stated task, so E6 cannot apply |
| D-s | AD-044 ↔ AD-046 ↔ AD-047 | **New.** The ceiling does not route rows. WF l.91–93 should be put into practice with the AD-046 scopes |
| D-t | AD-011 ← AD-040 (boundary); AD-042 not needed by AD-011 under AD-041 (c) | **New** |
| D-u | AD-026 is independent of AD-016 | **New**. It may be decided alone |
| D-v | AD-022 "covert steering" holds at every AD-016 level | **New.** L0 is the documented core |
| D-w | AD-037 (payment) → AD-008 scope | **New.** Defines "sensitive" at step 6 |
| D-x | AD-014, AD-032, AD-045, AD-049, AD-054, AD-058, AD-061, AD-062 (`DEFERRED`) | Re-checked: no Round-2 row depends on them |

---

## 4. Traceability

**4.1 v1.0 → v1.1.** All 63 v1.0 IDs are kept. The "Change" column in §6 gives each one's change type. Rows marked "—" are unchanged and still read from V10.

**4.2 Prior IDs (v0.1–v0.9).** The full mapping in V10 §3 still holds without exception, because every target AD ID still exists. The only additions:

| Prior ID | Now also maps to |
|---|---|
| v0.1 R5; D-Q5b; U-R2; W-01; X3; R-01; R-01b; R-01c | AD-064 |
| X1; X1-a; R-02; R-02a; R-02d; RG l.51–53 (cited in V08 R-02 [DOC]) | AD-065 |
| V09 J1; S1 | AD-039 (re-analysed); AD-065 |
| V09 J2 | §2.5.4 (now including AD-024, AD-027, AD-028 as well as v0.9's inclusions 2 and 5) |
| v0.1 R7; D-Q7b; W-04; R-06 (inclusion 2, "attribution") | AD-017 (via the AD-025 rescope) |

**4.3 Rules R-01–R-21 (V08) → v1.1 rows:**

| Rule | Rows | Rule | Rows |
|---|---|---|---|
| R-01 | AD-001–AD-004, **AD-064** | R-12 | AD-037 |
| R-02 | AD-005–AD-008, **AD-065** | R-13 | AD-038–AD-042 |
| R-03 | AD-009–AD-012 | R-14 | AD-043–AD-045 |
| R-04 | AD-013, AD-014 | R-15 | AD-046–AD-048 |
| R-05 | AD-015–AD-021 | R-16 | AD-049 |
| R-06 | AD-022–AD-028 | R-17 | AD-050–AD-054 |
| R-07 | AD-029, AD-030 | R-18 | AD-055–AD-058 |
| R-08 | AD-031, AD-032 | R-19 | AD-059–AD-061 |
| R-09 | AD-033 | R-20 | AD-062 |
| R-10 | AD-034, AD-035 | R-21 | AD-063 |
| R-11 | AD-036 | | |

**IDs that cannot be mapped unambiguously:** none. The one ambiguity found is **v1.0 AD-016 option (a)**, which has two readings (L1 and L2). It is resolved by splitting it in §2.5.3.

---

## 5. Unresolved decisions

**Every one of the 65 rows is undecided.** The following are open because the sources conflict or are silent, so no evidence can settle them:

| Group | Rows | Nature |
|---|---|---|
| Relayed instructions | AD-002, AD-003, AD-064 | The sources conflict (LG l.9–11 vs RG l.22–23 and LG l.12–14) |
| Bare commands | AD-008, AD-065 | The decisive fact (user request) cannot be observed; self-scope cues are undefined |
| Credentials | AD-038, **AD-039** | The sources conflict (RG l.28 vs RG l.51–53); not settled by any document |
| Private data / internal | AD-040, AD-041, AD-042 | Undefined terms. No definition is proposed for "private data" or "internal" |
| X2 | AD-016 (level L0–L3), AD-017–AD-019 (derived), AD-024, AD-025, AD-027, AD-028 (consistency conditional) | "Covert" is undefined; RG's grammar and examples point different ways (§2.5.2) |
| Other label-policy rows | AD-007, AD-012, AD-036, AD-037 | As in v1.0 |
| Process and parameters | AD-010, AD-021 (now owner judgment), AD-044, AD-047, AD-051–AD-053, AD-056, AD-057, AD-060 | Owner choices |
| Deferred | AD-014, AD-032, AD-045, AD-049, AD-054, AD-058, AD-061, AD-062 | Needed only before v0.3.1 or later |
| User access | AD-063 | User's decision; recommended not to run |

**The owner should decide these first** (they unlock the rest):
1. **AD-016** — it determines AD-017–AD-019 and constrains AD-024–AD-028.
2. **AD-064 and AD-065** — they determine the scopes of AD-002/AD-003 and AD-008/AD-039/AD-041.
3. **AD-041** — it decides whether AD-042 is needed and how much AD-040 matters.
4. **AD-043, AD-044, AD-047** — they must be fixed before the mapping-key join.

---

## 6. Register (intentionally blank decision cells — owner/user only)

Status abbreviations in this table: **REC** = `RECOMMENDED_FOR_ADOPTION`, **PPOD** = `PENDING_PROJECT_OWNER_DECISION`, **PUD** = `PENDING_USER_DECISION`. Basis: **ES** = `EVIDENCE_SUPPORTED`, **OJ** = `OWNER_JUDGMENT`. A "→" shows the v1.0 value before the v1.1 value.

| ID | Short title | Status (v1.0 → v1.1) | Basis | Rec. (v1.0 → v1.1) | Change | Decision | By | Date |
|---|---|---|---|---|---|---|---|---|
| AD-001 | Frames F1–F3; self-labels and quote marks not frames | REC | ES | a | CLARIFIED | | | |
| AD-002 | Unframed operative relays suspicious | PPOD | OJ | a | RESCOPED | | | |
| AD-003 | Unframed non-operative reports | PPOD | OJ | c → a (if AD-064 a) / c | REANALYSED, REC-CHANGED | | | |
| AD-004 | One ruling per shared question | REC | ES | a | — | | | |
| AD-005 | Sensitive action alone insufficient | REC | ES | a | CLARIFIED | | | |
| AD-006 | Evidence E1–E5 required | REC | ES | a | — | | | |
| AD-007 | E6 task switch | PPOD | OJ | a | — | | | |
| AD-008 | Bare commands (X1-a) | PPOD | OJ | a | CLARIFIED | | | |
| AD-009 | Authorisation is relation task | REC | ES | a | — | | | |
| AD-010 | `relation-task:` convention | REC → PPOD | ES → OJ | a | RECLASSIFIED | | | |
| AD-011 | Internal non-secret forwarding | REC | ES | a | CLARIFIED | | | |
| AD-012 | E7 designated destination | PPOD | OJ | a | — | | | |
| AD-013 | Never infer provenance | REC | ES | a | — | | | |
| AD-014 | Future `source_type` exposure (DEFERRED) | PPOD | OJ | a | — | | | |
| AD-015 | Enumerated behaviours only | REC | ES | a | — | | | |
| AD-016 | Definition of "covert" (X2 ladder) | PPOD | OJ | a → L1 | REANALYSED, REC-CHANGED (relabelled) | | | |
| AD-017 | Fake-review policy (derived) | PPOD | OJ | a | CLARIFIED | | | |
| AD-018 | Hidden tracking (derived) | PPOD | OJ | a | CLARIFIED | | | |
| AD-019 | Slanted summaries (derived) | PPOD | OJ | a | CLARIFIED | | | |
| AD-020 | Category for covert cases | REC | ES | a | — | | | |
| AD-021 | `scope-note:` convention | REC → PPOD | ES → OJ | a | RECLASSIFIED | | | |
| AD-022 | Official inclusions | REC | ES | a | — | | | |
| AD-023 | Official exclusions | REC | ES | a | — | | | |
| AD-024 | Inclusion 1: false statements to user | PPOD | OJ | a → b (if L0/L1) | REC-CHANGED | | | |
| AD-025 | Inclusion 2: record/log falsification (attribution → AD-017) | PPOD | OJ | a → b (if L0/L1) | RESCOPED, REC-CHANGED | | | |
| AD-026 | Inclusion 3: delayed triggers | PPOD | OJ | a | — | | | |
| AD-027 | Inclusion 4: ad insertion without cue | PPOD | OJ | a → b (if L0–L2) | REC-CHANGED | | | |
| AD-028 | Inclusion 5: rating/summary manipulation without cue | PPOD | OJ | a → b (if L0–L2) | REC-CHANGED | | | |
| AD-029 | Encoded attacks | REC | ES | a | — | | | |
| AD-030 | Decoded goal as `alt-category:` | REC | ES | a | CLARIFIED | | | |
| AD-031 | Interim category rule | REC | ES | a | — | | | |
| AD-032 | Final precedence (DEFERRED) | PPOD | OJ | a | — | | | |
| AD-033 | Business authority not impersonation | REC | ES | a | — | | | |
| AD-034 | Language not obfuscation | REC | ES | a | — | | | |
| AD-035 | Encoded non-English | REC | ES | a | — | | | |
| AD-036 | System-prompt disclosure | PPOD | OJ | a | — | | | |
| AD-037 | Payment definition | PPOD | OJ | a | — | | | |
| AD-038 | Credentials rule, not self-scoped (ex R-13a) | PPOD | OJ | a | CLARIFIED | | | |
| AD-039 | Credential rule vs self-scoped rule | PPOD | OJ | a → d (interim) | REANALYSED, REC-CHANGED | | | |
| AD-040 | "Private data" definition | PPOD | OJ | a → none | REC-CHANGED | | | |
| AD-041 | Private-data rule (ex R-13b) | PPOD | OJ | b → c | REANALYSED, REC-CHANGED | | | |
| AD-042 | Internal-destination recognition | PPOD | OJ | a → none (moot if AD-041 c) | REC-CHANGED | | | |
| AD-043 | `ADJUDICATE:` convention | REC | ES | a | CLARIFIED | | | |
| AD-044 | `ADJUDICATE:` confidence ceiling | PPOD | OJ | b | REANALYSED | | | |
| AD-045 | Future third label (DEFERRED) | PPOD | OJ | a | — | | | |
| AD-046 | Threshold field scopes | REC | ES | a | — | | | |
| AD-047 | Adjudication trigger (agreeing rows) | PPOD | OJ | a | CLARIFIED | | | |
| AD-048 | Kappa with/without flagged rows | REC | ES | a | — | | | |
| AD-049 | Guide-precedence statement (DEFERRED) | PPOD | OJ | a | — | | | |
| AD-050 | Language policy L | REC | ES | a | — | | | |
| AD-051 | AI never sets `ok` | PPOD | OJ | a | — | | | |
| AD-052 | Who reviews languages | PPOD | OJ | a | — | | | |
| AD-053 | Review timing | PPOD | OJ | a | — | | | |
| AD-054 | Failed-row handling (DEFERRED) | PPOD | OJ | a | — | | | |
| AD-055 | Issue errata | REC | ES | a | — | | | |
| AD-056 | Errata delivery | PPOD | OJ | a | — | | | |
| AD-057 | IN prevails on form questions | PPOD | OJ | a | — | | | |
| AD-058 | Validator tightening (DEFERRED) | PPOD | OJ | a | — | | | |
| AD-059 | Card-correction strategy | REC | ES | a | — | | | |
| AD-060 | Erratum location | PPOD | OJ | a | — | | | |
| AD-061 | Build-script fix (DEFERRED) | PPOD | OJ | a | — | | | |
| AD-062 | `is_quoted_or_discussed` review (DEFERRED) | PPOD | OJ | a | — | | | |
| AD-063 | Aggregate author-label analysis | PUD | OJ | a | — | | | |
| AD-064 | Operative-relay test O1–O3 | PPOD | OJ | — → a | NEW | | | |
| AD-065 | Self-scope cues for RG l.51–53 | PPOD | OJ | — → a | NEW | | | |

**Totals (v1.1):**
- 65 rows: 23 `RECOMMENDED_FOR_ADOPTION`, 41 `PENDING_PROJECT_OWNER_DECISION` (8 of them `DEFERRED`), 1 `PENDING_USER_DECISION`.
- Basis: 23 `EVIDENCE_SUPPORTED`, 42 `OWNER_JUDGMENT`.
- v1.0 had 63 rows: 25 / 37 / 1.
- Nothing is ratified. The quality gate stays **OPEN**.
