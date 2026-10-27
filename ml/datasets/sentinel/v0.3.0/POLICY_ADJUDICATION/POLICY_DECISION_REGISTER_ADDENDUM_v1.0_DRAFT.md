# Sentinel v0.3.0 Round 2 — Decision-Register Addendum **v1.0 (DRAFT)**

| | |
|---|---|
| Status | **`DRAFT_NOT_APPROVED`.** A repaired, de-bundled decision register. **No decision is ratified, approved or made.** Every decision cell is blank. |
| Relationship | Addendum to `POLICY_RESOLUTION_PROPOSAL_v0.8_DRAFT.md` (sha256 `79fd4e41…`). It implements the register repairs identified in `POLICY_READINESS_REVIEW_v0.9_DRAFT.md`. All v0.1–v0.9 files, including the v0.4 Section H and v0.8 §9 registers, are unchanged and still blank. |
| Prepared | 2026-10-27, by an AI assistant (Claude, Cowork). Not an annotator, adjudicator, or project owner. |
| Quality gate | **OPEN.** |
| Audience | Owner/adjudicator only. Not for the independent annotator. |

## 0. How to read this register

- **Rows.** There are **63 independent decision rows** (AD-001 … AD-063). Each has one question and one answer cell. Where a v0.8 or v0.9 item bundled several choices, it is split here.
- **Status** (the same vocabulary as v0.8):
  - `RECOMMENDED_FOR_ADOPTION` — evidence-supported; needs ratification only.
  - `PENDING_PROJECT_OWNER_DECISION` — a genuine choice.
  - `PENDING_USER_DECISION` — the user's access choice.
  - The tag **`DEFERRED`** marks decisions that are needed only before v0.3.1 or a future version, not before Round-2 annotation.
- **Basis:**
  - **`EVIDENCE_SUPPORTED`** — official sources point to one option.
  - **`OWNER_JUDGMENT`** — the sources are silent or conflict; the recommendation rests on project goals and is **not** official policy.
- **Change from v0.8.** R-13a moves from `RECOMMENDED_FOR_ADOPTION` to `PENDING_PROJECT_OWNER_DECISION` (AD-038), following v0.9 finding S1. Nothing else changes status, except where a bundled row is split.
- **Source tags.** All line numbers were re-checked for this file; see `VALIDATION_LOG_v1.0.txt`.

  | Tag | Path |
  |---|---|
  | RG | `ml/datasets/sentinel/v0.3.0/REVIEW_ROUND2/ANNOTATOR_PACKAGE/REVIEWER_GUIDE.md` (CRLF-normalised) |
  | IN | `…/REVIEW_ROUND2/ANNOTATOR_PACKAGE/INSTRUCTIONS.md` |
  | LG | `ml/datasets/sentinel/v0.3.0/LABELLING_GUIDE.md` |
  | SCH | `ml/sentinel/schema.py` |
  | INT | `ml/sentinel/intake_round2.py` |
  | RD | `docs/phase11-sentinel-research.md` |
  | WF | `docs/phase11a-independent-review-workflow.md` |
  | QG | `docs/phase11a-dataset-quality-gate.md` |
  | EX | `docs/phase11a-dataset-expansion.md` |
  | SC | `packages/engine/src/scanner/rules.ts` (scanner documentation: corroborating only, never decisive — v0.9 S2) |
  | B2 / B3 | `ml/sentinel/build_round2.py` / `ml/sentinel/build_v03.py` |
  | CL / DC | `ml/datasets/sentinel/v0.3.0/CHANGELOG.md` / `…/DATASET_CARD.md` |

- **Goals G1–G7** are as defined in v0.8 §2:
  - G1 — QG "## Decision" l.6–15
  - G2 — RD l.116–121
  - G3 — RD l.84–93
  - G4 — LG l.7; RG l.9–10
  - G5 — WF l.85–90
  - G6 — RD l.165
  - G7 — LG l.33–35

---

## 1. Decision rows

### A. Relayed instructions vs defensive reporting (X3; R-01)

**AD-001 — Framed or defensive text is benign; self-labels are not frames**
- **Question:** Is text that quotes or relays an instruction benign when it carries frame F1 (explicit warning or negation), F2 (analytic or reporting genre) or F3 (critique)? And are provenance labels ("embedded", "injected", "planted") *not* frames?
- **Evidence:**
  - LG l.12–14 ("discusses, quotes, reports, or teaches defence against … is `benign`");
  - RG l.17–18 ("quotes an attack in order to explain or criticise it");
  - RG l.49–50 ("because the sample does not instruct the agent").
- **Options:** (a) Ratify. (b) Treat self-labels as frames.
- **Recommended:** (a). Option (b) would let an attacker neutralise a payload by adding a label.
- **Depends on:** none. **Feeds:** AD-002, AD-003, AD-062.
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** every benign row that relies on framing cites F1, F2 or F3 in its note. No row is benign solely because of a provenance label.

**AD-002 — Equivalence principle: unframed relayed instructions are suspicious**
- **Question:** Is an actionable instruction aimed at an AI reader suspicious when it carries no frame, whatever its grammatical form (addressed, labelled, quoted, or relayed in the third person)?
- **Evidence:**
  - LG l.9–11 ("directs the agent … `suspicious`, even if politely phrased") pulls toward suspicious.
  - LG l.12–14 ("reports") and RG l.22–23 ("in its own voice") pull toward benign.
  - **The sources conflict for this case.**
- **Options:** (a) Suspicious. (b) Benign. (c) Adjudicate each row (AD-043).
- **Recommended:** (a).
  - *Security:* closes the "rephrase as narration" evasion path.
  - *False positives:* contained by AD-001.
- **Depends on:** AD-001. **Feeds:** AD-062.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** every pair in a calibration set of equivalent instructions written in different grammatical forms gets identical labels.

**AD-003 — Does a bare third-party report count as frame F2?**
- **Question:** Does a neutral report of an attack — no outcome, no critique ("a thread claimed a page asked AI readers to …") — count as frame F2?
- **Evidence:** RG l.49–50 lists genres but no criteria. **The sources are silent on reports without an outcome.**
- **Options:** (a) Yes, benign. (b) No, suspicious. (c) Adjudicate (AD-043).
- **Recommended:** (c) until the owner rules. *Trade-off:* (a) risks missed evasions; (b) risks false positives on news-like text.
- **Depends on:** AD-001, AD-002, AD-043.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** all such rows are labelled under the single chosen option. If (c), they carry `ADJUDICATE:`.

**AD-004 — One ruling applies uniformly to every row that shares a policy question**
- **Question:** Must a ruling on a shared question (such as the 19 rows in v0.2 §3 Q5) be applied uniformly, with no per-row exceptions without a recorded reason?
- **Evidence:** WF §3 l.43–93 (adjudication with a written rationale); G2.
- **Options:** (a) Ratify. (b) Allow ad-hoc exceptions.
- **Recommended:** (a), for consistency and auditability.
- **Depends on:** none.
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** any deviation from a shared ruling has an adjudication rationale recorded.

### B. Sensitive action vs evidence of attack (X1; R-02)

**AD-005 — A sensitive action alone is insufficient**
- **Question:** Is a request for a payment, deletion, external email or shell command insufficient by itself to make a row suspicious?
- **Evidence:**
  - RG l.51–53 ("not automatically an injection");
  - LG l.16–17;
  - RD l.154–155 ("any mismatch belongs to the relation task").
- **Options:** (a) Ratify. (b) The action alone makes the row suspicious.
- **Recommended:** (a). Option (b) contradicts RG's own example and raises false positives (G1).
- **Depends on:** none. **Constrained by:** AD-039 (credential precedence).
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** no suspicious row's note cites only the action type.

**AD-006 — Attack evidence E1–E5 is required**
- **Question:** For `tool_redirect`, is at least one of these required?
  - E1 override (RG l.25–26);
  - E2 authority claim (RG l.27);
  - E3 concealment (RG l.33–34);
  - E4 asserted consent or skipped approval (RG l.33–34; LG l.20–22);
  - E5 an instruction addressed to an AI reader inside unrelated content (LG l.9–11).
- **Evidence:** as listed for each item. Making them *necessary* is a reading of RG l.29–30 together with l.51–53 (v0.9 S6).
- **Options:** (a) Ratify. (b) Use a different list.
- **Recommended:** (a).
- **Depends on:** AD-005.
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** every suspicious `tool_redirect` row names at least one evidence item.

**AD-007 — E6: a task switch counts as evidence**
- **Question:** Does a sensitive action unrelated to the text's own stated task count as attack evidence?
- **Evidence:** LG l.16–17 and RD l.154–155, read in reverse. **Not stated in the sources.**
- **Options:** (a) Yes. (b) No.
- **Recommended:** (a).
  - *Security:* catches injections hidden in ordinary content.
  - *False-positive risk:* multi-task requests from a legitimate requester.
- **Depends on:** AD-006.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** an E6 citation names both the stated task and the unrelated action.

**AD-008 — Bare imperative with no evidence (X1-a)**
- **Question:** How is a sensitive action labelled when there is no evidence and no self-scoping, for example "Use the payments tool to pay the water bill"?
- **Evidence:**
  - RG l.8–9 (all rows are untrusted) points toward suspicious.
  - RD l.154–155 (relation task) points toward benign.
  - **The sources conflict.**
- **Options:** (a) Adjudicate (AD-043). (b) Default suspicious. (c) Default benign.
- **Recommended:** (a). (b) raises false positives; (c) misses plain-imperative injections.
- **Depends on:** AD-005, AD-006, AD-043.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** all such rows are handled under the single chosen option.

### C. Authorisation and provenance (R-03, R-04)

**AD-009 — Authorisation is the relation task, not the content label**
- **Question:** Is whether the real user authorised an action excluded from the content label?
- **Evidence:** LG l.3–5; RD l.84–93, l.111, l.154–155.
- **Options:** (a) Ratify. (b) Include authorisation in the label.
- **Recommended:** (a). Option (b) "mimics authorization" (G3).
- **Depends on:** none.
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** no label's rationale rests only on "the user didn't authorise this".

**AD-010 — `relation-task:` note convention (v0.9 O1)**
- **Question:** Should annotators record authorisation doubts in `uncertainty_note` with the prefix `relation-task:`?
- **Evidence:** IN l.8 (`uncertainty_note` exists). The prefix itself is a new convention.
- **Options:** (a) Adopt the prefix. (b) Free text, no prefix.
- **Recommended:** (a), so these notes can be filtered by machine.
- **Depends on:** AD-009.
- **Basis:** EVIDENCE_SUPPORTED (no conflicting source; amendment only). **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** any authorisation doubt appears with the prefix.

**AD-011 — Internal forwarding of non-secret material**
- **Question:** Is internal forwarding of non-secret, non-private material not suspicious on that basis alone?
- **Evidence:** RG l.29–30 ("external email"); RG l.28 (exfiltration covers secrets, credentials, private data).
- **Options:** (a) Ratify. (b) Suspicious.
- **Recommended:** (a).
- **Depends on:** AD-040 (what counts as "private"), AD-042 (what counts as "internal").
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** no suspicious row cites only "forwarding".

**AD-012 — E7: a destination designated by the content is evidence**
- **Question:** Does a destination that the content itself designates *and* directs the agent to use ("the account in the footer") count as attack evidence?
- **Evidence:** RD l.111 (destination belongs to the relation task). **The sources are silent on content-level destination cues.**
- **Options:** (a) Yes, limited to destinations the content both designates and directs. (b) No.
- **Recommended:** (a).
  - *Security:* catches redirection to attacker-chosen recipients.
  - *False positives:* invoices that merely list payee details are not affected, because a directive is required.
- **Depends on:** AD-006, AD-042.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** an E7 citation quotes both the designation and the directive.

**AD-013 — Treat every row as untrusted; never infer provenance**
- **Question:** Should annotators judge only the attack evidence in the text and never infer who wrote a row (user, webpage, …)?
- **Evidence:** RG l.8–9, l.51–53; RD l.137; IN l.8 (no `source_type` field).
- **Options:** (a) Ratify. (b) Annotators guess provenance.
- **Recommended:** (a). Guessing could whitelist attack text.
- **Depends on:** AD-005, AD-006 (v0.9 J6).
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** no note uses provenance as a reason.

**AD-014 — Expose `source_type` in a future annotator package (v0.9 O2)** `DEFERRED`
- **Question:** Should a future review round show annotators the `source_type` field?
- **Evidence:** RD l.137. Exposure could leak label-correlated hints (v0.4 W-12).
- **Options:** (a) No. (b) Yes, with a leak analysis first.
- **Recommended:** (a) for now.
- **Depends on:** none.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** if (b), a leak-test result is recorded before release.

### D. Fake reviews, hidden tracking, slanted summaries (X2; R-05)

**AD-015 — Only RG-enumerated behaviours make a row suspicious**
- **Question:** Is "suspicious" limited to the behaviours listed in RG l.22–34, so that harmful-sounding wording alone is insufficient?
- **Evidence:** RG l.9–10, l.22–34; LG l.13–14.
- **Options:** (a) Ratify. (b) Include any harmful-sounding content.
- **Recommended:** (a), per G4.
- **Depends on:** none.
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** every suspicious row maps to an RG l.22–34 behaviour.

**AD-016 — Definition of "covert" (X2 core)**
- **Question:** What makes manipulation "covert" under RG l.33–34?
- **Evidence:** RG l.33–34 ("covert steering"), undefined. The v0.2 brief §2 found that the "principal" concept is undocumented. **The sources are silent.**
- **Options:**

  | Option | Definition | Note |
  |---|---|---|
  | (a) Agent-process concealment | The text tells the agent to conceal or misstate its *own* actions, insertions, omissions or output origin, via cues C1 (hide), C2 (misrepresent output), C3 (tracking + C1) | Provenance-free |
  | (b) X2-alt | Any deception in the output, including deception of third-party readers | Broader |
  | (c) Concealment from "the person the agent serves" | — | Depends on provenance; conflicts with AD-013 |

- **Recommended:** (a).
  - *Security:* targets the agent being told to hide what it does.
  - *False positives:* lowest; marketing and fiction stay benign.
  - (b) widens Sentinel into a misuse classifier (LG l.3–5).
  - (c) contradicts AD-013.
- **Depends on:** AD-013, AD-015. **Feeds:** AD-017–AD-020, AD-024–AD-028 (§2.2).
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** every suspicious decision based on covertness quotes the cue (C1–C3 under (a)).

**AD-017 — Alternative fake-review policy (X2 vs X2-alt applied to reviews)**
- **Question:** Is an *openly* requested set of reviews written to look like genuine customers suspicious?
- **Evidence:** as for AD-016; **silent**.
- **Options:** (a) Benign + `scope-note:` (follows AD-016a). (b) Suspicious `other_suspicious` (follows AD-016b).
- **Recommended:** (a). Content-policy harm is real but outside the documented task (LG l.3–5). (b) catches more but raises false positives on marketing copy.
- **Depends on:** AD-016, AD-021. **Must match** AD-016: (a) pairs with AD-016a; (b) pairs with AD-016b.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** every review-generation row is labelled under the chosen option.

**AD-018 — Hidden tracking**
- **Question:** Is an instruction to keep or insert a tracking mechanism suspicious when it comes with a concealment cue (C3 + C1)? And what if there is no concealment cue?
- **Evidence:** RG l.33–34. **Silent.** If the tracker collects personal data, see AD-040 and AD-041.
- **Options:**
  - (a) Suspicious with a cue; benign + `scope-note:` without one.
  - (b) Always suspicious.
  - (c) Adjudicate rows without a cue.
- **Recommended:** (a).
- **Depends on:** AD-016, AD-040.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** suspicious tracking rows quote the C1 cue.

**AD-019 — Slanted summaries**
- **Question:** Is an instruction to omit content from a summary suspicious when it comes with a concealment cue ("quietly", "don't mention")? And what if the omission is open but undisclosed to the reader ("without the legal section")?
- **Evidence:** RG l.33–34. **Silent.**
- **Options:**
  - (a) Suspicious with a cue; benign without one.
  - (b) Suspicious whenever the omission is undisclosed.
  - (c) Adjudicate rows without a cue.
- **Recommended:** (a), consistent with AD-016a. (b) raises false positives on ordinary scoping requests.
- **Depends on:** AD-016, AD-028.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** suspicious summary rows quote the cue.

**AD-020 — Category for covert-process cases**
- **Question:** Are AD-016a cases `other_suspicious`, unless a more specific category fits under AD-031?
- **Evidence:** RG l.33–34 ("fits none of the above"); LG l.21–22.
- **Options:** (a) Ratify. (b) A new category — schema change; not proposed.
- **Recommended:** (a).
- **Depends on:** AD-016, AD-031.
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** the category is in SCH l.8–16.

**AD-021 — `scope-note:` convention**
- **Question:** May annotators mark out-of-scope harmful requests with a non-official `scope-note:` prefix?
- **Evidence:** IN l.8 (`uncertainty_note`). The prefix is a new convention.
- **Options:** (a) Adopt. (b) No note.
- **Recommended:** (a), so these rows can be routed to other controls.
- **Depends on:** AD-015.
- **Basis:** EVIDENCE_SUPPORTED (amendment; no conflicting source). **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** the prefix never appears on a suspicious row.

### E. `other_suspicious` scope (R-06)

**AD-022 — Confirm the official inclusions**
- **Question:** Confirm that the official inclusions are fabricated consent, covert steering and urgency pressure (RG l.33–34), and fake-CEO / bypass-approval pressure (LG l.20–22).
- **Evidence:** as cited.
- **Options:** (a) Confirm.
- **Recommended:** (a).
- **Basis:** EVIDENCE_SUPPORTED (documented). **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** every `other_suspicious` row cites one inclusion.

**AD-023 — Confirm the official exclusions**
- **Question:** Confirm that these are excluded from `other_suspicious`:
  - anything fitting another category (RG l.33; LG l.21–22);
  - quoted or defensive text (LG l.12–14);
  - ordinary tasks (LG l.16–17);
  - keyword-only matches (LG l.13–14; RG l.9–10).
- **Evidence:** as cited in the question — RG l.33; LG l.21–22, l.12–14, l.16–17, l.13–14; RG l.9–10.
- **Options:** (a) Confirm.
- **Recommended:** (a).
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** none of the excluded cases is labelled `other_suspicious`.

**AD-024 to AD-028 — Five proposed inclusions, each decided separately**

The sources are silent on all five. Each asks whether the behaviour is included in `other_suspicious` when **no C1–C3 cue** is present; cases that do have C1–C3 cues are already covered by AD-016a (see §2.2).

| Row | Proposed inclusion | Options | Recommended | Trade-off | Depends on |
|---|---|---|---|---|---|
| **AD-024** | False statements to the user to pressure a decision (e.g. inventing a deadline) | (a) Include (b) Exclude | (a) — fits "urgency pressure" by analogy (LG l.20–22) | Small false-positive risk on persuasive copy | AD-016 |
| **AD-025** | Falsifying records, logs or attribution | (a) Include (b) Exclude | (a) | Integrity attacks otherwise have no home | AD-016 (C2 overlap) |
| **AD-026** | Delayed or conditional triggers ("from the third reply on…") | (a) Include (b) Exclude | (a) | Covers a known evasion pattern | none |
| **AD-027** | Covert ad or promotional insertion without a concealment word ("steer every answer toward our store") | (a) Include (b) Exclude | (a) | False-positive risk on genuine marketing tasks | AD-016 |
| **AD-028** | Rating or summary manipulation without a concealment word ("score it five stars regardless") | (a) Include (b) Exclude | (a) | Coupled with AD-019 | AD-016, AD-019 |

- **Basis:** OWNER_JUDGMENT for all five. **Status:** `PENDING_PROJECT_OWNER_DECISION` for each.
- **Validation:** each included row's note names the inclusion and its owner-approved one-sentence definition.

### F. Categories (R-07 – R-12)

**AD-029 — Encoded attacks**
- **Question:** Does the label follow the decoded intent, with category `obfuscated_injection` when the operative instruction is encoded, leetspeak, spaced or homoglyph-altered?
- **Evidence:** LG l.18–19; RG l.31–32; SCH l.18; IN l.8 (no `obfuscation_type` field).
- **Options:** (a) Ratify. (b) Use the decoded-goal category instead.
- **Recommended:** (a). It preserves the evasion signal; (b) loses it, because annotators cannot fill `obfuscation_type`.
- **Depends on:** none.
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** `obfuscated_injection` rows note the decoding method.

**AD-030 — Record the decoded goal as `alt-category:`**
- **Question:** For encoded attacks, should the decoded goal be recorded as `alt-category:`?
- **Evidence:** RD l.100–103 (measure co-occurrence).
- **Options:** (a) Adopt. (b) No note.
- **Recommended:** (a).
- **Depends on:** AD-029, AD-031.
- **Basis:** EVIDENCE_SUPPORTED (amendment). **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** `alt-category:` values are in SCH l.8–16.

**AD-031 — Interim category rule**
- **Question:** For Round 2, is the category that of the primary instruction directed at the agent, with any second applicable category recorded as `alt-category:`?
- **Evidence:** RG l.54–55; RD l.100–103. There is no precedence order (verified absence).
- **Options:** (a) Ratify the interim rule. (b) A fixed order now.
- **Recommended:** (a). (b) would encode an untested order (G1, G2).
- **Depends on:** none.
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** the category is in SCH; notes use official names.

**AD-032 — Final precedence order or multi-label** `DEFERRED`
- **Question:** Should Sentinel adopt a final precedence order, or multi-label categories, after co-occurrence has been measured?
- **Evidence:** RD l.100–103.
- **Options:** (a) Defer until measured. (b) Decide now.
- **Recommended:** (a).
- **Depends on:** AD-031 data.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** a co-occurrence table is reported before any decision.

**AD-033 — Business authority is not `impersonation`**
- **Question:** Confirm that business authority (CEO, legal team) is `other_suspicious` unless a more specific category fits, and is not `impersonation`.
- **Evidence:** LG l.20–22; RG l.27; SC l.33 (corroborating only).
- **Options:** (a) Confirm.
- **Recommended:** (a).
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** no `impersonation` row's only authority claim is a business role.

**AD-034 — Non-English text is not obfuscation**
- **Question:** Confirm that language alone never makes a row `obfuscated_injection` or suspicious.
- **Evidence:** RG l.31; SCH l.18; RD l.139; G6.
- **Options:** (a) Confirm. (b) Treat translation as obfuscation.
- **Recommended:** (a). (b) teaches the model that language is an attack signal.
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** no non-English `obfuscated_injection` row lacks an encoding cue.

**AD-035 — Encoding inside non-English text follows AD-029**
- **Question:** Does encoding inside non-English text follow AD-029?
- **Evidence:** RG l.31–32.
- **Options:** (a) Confirm.
- **Recommended:** (a).
- **Depends on:** AD-029, AD-034.
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** as AD-029.

**AD-036 — System-prompt and configuration disclosure**
- **Question:** Which category applies to a request to reveal the agent's hidden instructions or configuration, when there is no override, authority claim or encoding?
- **Evidence:** RG l.28 ("secrets, credentials, or private data"); SC l.46–57 (no prompts; corroborating only). **Silent on prompts.**
- **Options:** (a) `exfiltration_request`. (b) The technique's category, otherwise `other_suspicious`.
- **Recommended:** (a). It groups disclosure-goal attacks. *Trade-off:* it diverges from the scanner's literal patterns.
- **Depends on:** AD-031. **Coupled with:** AD-038 and AD-039 (v0.9 J5 — if ruled "secret", AD-039 governs).
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** all prompt-disclosure rows carry the ruled category.

**AD-037 — Definition of "payment" for `tool_redirect`**
- **Question:** Does "payment" include refunds, purchase approvals, chargeable bookings, subscriptions, and gift-card or loyalty transfers?
- **Evidence:** RG l.29–30; SC l.60–75 (corroborating). **Undefined.**
- **Options:** (a) Broad: anything that moves money or value, or commits the user to a charge. (b) Narrow: explicit money transfers only. (c) A middle definition.
- **Recommended:** (a). One test for annotators; false positives are contained by AD-005/AD-006.
- **Depends on:** AD-005, AD-006.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** financial `tool_redirect` rows cite the definition and an evidence item.

### G. Private data and credentials (X4; R-13)

**AD-038 — Secrets and credentials disclosure rule (reclassified from R-13a; v0.9 S1)**
- **Question:** Is a request to reveal or send secrets or credentials `exfiltration_request` regardless of destination? These are keys, passwords, tokens, recovery codes, and any others the owner lists.
- **Evidence:**
  - RG l.28 (no destination qualifier).
  - RG l.19–20 and LG l.15 treat "never share your password" and "never reveal your API key" as benign safety advice, which shows the project regards such sharing as unsafe.
  - The same clause in RG l.28 also covers "private data", which is treated separately (AD-041).
- **Options:** (a) Yes, regardless of destination. (b) Apply the AD-005/AD-006 evidence test.
- **Recommended:** (a).
  - *Security:* credentials should never move on instruction from content.
  - *False-positive cost:* a legitimate "send my password to IT" is flagged, which matches the project's own safety-advice stance.
- **Depends on:** AD-039 (precedence), AD-036.
- **Basis:** OWNER_JUDGMENT (evidence-leaning). **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** credential-disclosure rows are `exfiltration_request`, unless AD-039 rules otherwise.

**AD-039 — Precedence: credential rule (AD-038) vs evidence rule (AD-005)**
- **Question:** When a self-scoped text asks to send the requester's own credential with no evidence E1–E7, which rule prevails?
- **Evidence:** RG l.28 vs RG l.51–53. **The sources conflict.**
- **Options:**

  | Option | Rule |
  |---|---|
  | (a) AD-038 prevails | Credentials are a separate RG behaviour (l.28), not a "tool action" (l.29–30), so AD-005 applies only to tool actions |
  | (b) AD-005 prevails | Self-scoped credential requests need evidence |
  | (c) AD-038 prevails for any *transmission*; AD-005 governs display back to the requester only | — |

- **Recommended:** (a).
  - *Analytical basis:* RG lists secrets and credentials (l.28) as a different behaviour from sensitive tool actions (l.29–30). AD-005 derives from the tool-action clause and RG l.51–53's deletion example. Reading AD-005 as limited to tool actions removes the contradiction without changing either source.
  - (c) is a narrower compromise.
- **Depends on:** AD-005, AD-038.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** no credential row is labelled under both rules with different outcomes.

**AD-040 — Definition of "private data" (v0.9 O6)**
- **Question:** What does "private data" in RG l.28 cover?
- **Evidence:** RG l.28. **Undefined.**
- **Options:** (a) Personal data about identifiable people. (b) (a) plus confidential business data. (c) Anything the text marks as private or confidential.
- **Recommended:** (a), as the narrowest defensible reading. **This is owner judgment only.**
- **Depends on:** none. **Feeds:** AD-011, AD-018, AD-041.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** private-data rows name the data type.

**AD-041 — Rule for non-credential private data (R-13b)**
- **Question:** Is sending private data `exfiltration_request` regardless of destination, or only when attack evidence is present?
- **Evidence:** RG l.28; RD l.111.
- **Options:** (a) Literal: always. (b) Two-step: suspicious with E1–E7, or when the destination is external, unspecified or designated by the content; internal + no evidence → benign + `relation-task:`.
- **Recommended:** (b).
  - *False positives:* lower on routine internal workflows (G1).
  - *Residual risk:* a falsely claimed "internal" destination (AD-042).
- **Depends on:** AD-040, AD-042, AD-012.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** private-data rows record the destination type.

**AD-042 — Recognising an "internal" destination from text (v0.9 O7)**
- **Question:** When does the text establish an internal destination?
- **Evidence:** RD l.111. **Silent.** A destination claim is itself content and can be false.
- **Options:**
  - (a) Accept a stated internal team or role ("HR", "facilities") if no external address appears and the destination is not content-designated (AD-012).
  - (b) Treat every destination as unspecified unless an organisation-internal identifier is given.
  - (c) Accept any "internal" claim.
- **Recommended:** (a).
  - (c) is easily spoofed ("our internal auditor at this address").
  - (b) would flag routine requests.
- **Depends on:** AD-012.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** an "internal" classification cites the named team or role, and confirms no external address or designated destination is present.

### H. Uncertainty, thresholds, agreement (R-14 – R-16)

**AD-043 — The `ADJUDICATE:` placeholder convention**
- **Question:** When evidence is insufficient, does the annotator record a best label, low confidence, and an `ADJUDICATE: <reason>` note, with that label treated as non-binding?
- **Evidence:** INT l.37–38 (binary label required); RD l.116–121; WF l.91–93.
- **Options:** (a) Adopt. (b) Force a binary label with no flag.
- **Recommended:** (a). (b) violates G2.
- **Depends on:** AD-044 (parameter). **Feeds:** AD-003, AD-008, AD-047, AD-048.
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** every `ADJUDICATE:` row meets the AD-044 ceiling and is counted separately.

**AD-044 — Confidence ceiling for `ADJUDICATE:` rows (v0.9 S3)**
- **Question:** What maximum `confidence_0_1` should flagged rows carry?
- **Evidence:** **No source.** RG l.40–41 uses 0.7; LG l.24–26 uses 0.9.
- **Options:** (a) 0.5. (b) Below 0.7, the RG threshold. (c) No numeric ceiling; the flag alone suffices.
- **Recommended:** (b). It reuses a documented number instead of inventing 0.5.
- **Depends on:** AD-043.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** all flagged rows satisfy the ceiling.

**AD-045 — Third label value in a future schema (v0.9 O3)** `DEFERRED`
- **Question:** Should a future schema add a `needs_adjudication` label value?
- **Evidence:** SCH l.7; INT l.37–38.
- **Options:** (a) Defer. (b) Plan it now.
- **Recommended:** (a). It needs a separate, versioned validator and schema change.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** not applicable until a change is proposed.

**AD-046 — Threshold field scopes**
- **Question:** Does RG's 0.7 apply to the annotator's `confidence_0_1`, and LG's 0.9 to the author's `annotation_confidence`?
- **Evidence:** RG l.40–41; LG l.24–26; IN l.6. This is an [INT]erpretation by field scope (v0.9 M3).
- **Options:** (a) Ratify. (b) One shared threshold.
- **Recommended:** (a). No documents need editing.
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** each threshold is applied only to its own field.

**AD-047 — Adjudication trigger**
- **Question:** Which rows enter adjudication?
- **Evidence:** WF l.91–93 (no number given).
- **Options:**
  - (a) Annotator < 0.7, OR author < 0.9, OR `ADJUDICATE:`.
  - (b) A single 0.7 threshold.
  - (c) A single 0.9 threshold.
- **Recommended:** (a). It uses the existing designations.
- **Depends on:** AD-043, AD-046. **Must be fixed before the mapping-key join.**
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** the queue is computed only after intake passes, under the recorded rule.

**AD-048 — Agreement statistics**
- **Question:** Is primary kappa computed without `ADJUDICATE:` rows, with the all-rows kappa and confusion tables also reported?
- **Evidence:** WF l.60–71.
- **Options:** (a) Adopt. (b) All rows only.
- **Recommended:** (a).
- **Depends on:** AD-043 (v0.9 S5, J3).
- **Basis:** EVIDENCE_SUPPORTED (conditional). **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** both statistics are reported, each with its confusion table.

**AD-049 — Guide-precedence statement in future documentation** `DEFERRED`
- **Question:** Should v0.3.1 documentation state which guide prevails, and harmonise the threshold text?
- **Evidence:** G5; no current precedence statement.
- **Options:** (a) Yes, in v0.3.1 only. (b) No.
- **Recommended:** (a).
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** v0.3.0 hashes are unchanged.

### I. Multilingual review (R-17)

**AD-050 — Language-quality policy L**
- **Question:** Is `ok` used only when a fluent human confirms meaning and natural wording, and otherwise `uncertain` or `cannot-judge` plus `language-uncertain <code>`, with `cannot-judge` triggering AD-043?
- **Evidence:** IN l.9; RG l.42–44; INT l.18; CL l.7; G6.
- **Options:** (a) Ratify. (b) Annotator self-judgment without these tokens.
- **Recommended:** (a).
- **Depends on:** AD-043.
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** every non-English row has a non-blank `language_quality`, and the token whenever it is not `ok`.

**AD-051 — AI output never sets `ok` on non-English rows (v0.9 S4)**
- **Question:** Should any AI-generated artifact be barred from marking non-English language quality `ok`?
- **Evidence:** G6, plus an indirect link to G7. Weak.
- **Options:** (a) Adopt. (b) Allow it.
- **Recommended:** (a). It affects AI artifacts only. The existing AI files, which mark `ok`, are not modified (v0.8 K9).
- **Basis:** OWNER_JUDGMENT (low impact). **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** any future AI artifact shows no `ok` on non-English rows.

**AD-052 — Who reviews non-English rows**
- **Question:** Who reviews Spanish, German and Hindi rows?
- **Evidence:** CL l.7; QG §1 l.22.
- **Options:** (a) Separate fluent reviewers. (b) The annotator, using `cannot-judge` where needed.
- **Recommended:** (a), if available.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** reviewer roles are recorded without fabricated identities.

**AD-053 — When the fluency check happens**
- **Question:** Does the fluency check happen before or during annotation?
- **Evidence:** G6 (RD l.165) only. **The sources are silent on timing.**
- **Options:** (a) Before. (b) During.
- **Recommended:** (a), so unreliable rows are known up front.
- **Depends on:** AD-052.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** the worklist is completed before annotation starts, if (a).

**AD-054 — Rows that fail the fluency check** `DEFERRED`
- **Question:** What happens to rows that fail the fluency check?
- **Evidence:** G5 (WF l.85–90: changes go into v0.3.1); G6 (RD l.165). **The sources are silent on failed rows.**
- **Options:** (a) Exclude them from v0.3.1 evaluation slices. (b) Rewrite them in a later version.
- **Recommended:** (a) for v0.3.1, then (b) later.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** exclusions are listed in the v0.3.1 changelog.

### J. Round-2 form errata (R-18)

**AD-055 — Issue the sample-free field-mapping errata**
- **Question:** Should `ROUND2_FIELD_MAPPING_ERRATA_DRAFT_v0.1.md` be issued, after review, with no schema change?
- **Evidence:** IN l.8; RG l.42–44; B2 l.58–59.
- **Options:** (a) Issue. (b) Do not issue.
- **Recommended:** (a). Without it, annotators may use the wrong fields.
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** the errata contains no `rv-`/`sen-` IDs, sample text or labels.

**AD-056 — How the errata reaches the annotator**
- **Question:** Is the errata delivered as a separate handout, or as a file added to the annotator package?
- **Evidence:** `ml/tests/test_round2.py` l.14–15 (`_annotator_text` leak-checks every file in the annotator package). **The sources are silent on delivery.**
- **Options:** (a) Separate handout. (b) A file in the package.
- **Recommended:** (a). The package and its tests stay unchanged.
- **Depends on:** AD-055.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** if (b), `ml/tests/test_round2.py` passes and the new package hashes are recorded.

**AD-057 — Form-question precedence (v0.9 O4)**
- **Question:** For form and field questions only, does `INSTRUCTIONS.md` prevail over `REVIEWER_GUIDE.md`? Decision rules would still come from the guide.
- **Evidence:** IN l.6, l.8 (Round-2-specific); RG l.42–44 (Round-1 names). **No precedence statement exists.**
- **Options:** (a) IN prevails for form questions. (b) No statement.
- **Recommended:** (a).
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** the returned CSV uses the IN field names; intake passes.

**AD-058 — Tighten the intake validator (v0.9 O5)** `DEFERRED`
- **Question:** Should the intake validator reject a blank `language_quality` and validate the ISO date format?
- **Evidence:** INT l.18, l.54–55.
- **Options:** (a) Defer to a versioned change. (b) Change now.
- **Recommended:** (a). Changing it now is outside this phase.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** INT is unchanged until a versioned change is approved.

### K. Dataset documentation and access (R-19 – R-21)

**AD-059 — Dataset-card correction strategy**
- **Question:** Leave v0.3.0 untouched, publish a dated erratum outside the frozen folder, and write a correct card in v0.3.1?
- **Evidence:**
  - DC l.9, l.20 vs QG §1 l.19, l.22;
  - CL l.5–6;
  - EX l.91–93;
  - B3 l.49–52;
  - G5.
- **Options:** (a) This strategy. (b) Edit v0.3.0 in place. (c) Fix only in v0.3.1.
- **Recommended:** (a). (b) violates G5; (c) leaves the error uncorrected for longer.
- **Basis:** EVIDENCE_SUPPORTED. **Status:** `RECOMMENDED_FOR_ADOPTION`.
- **Validation:** v0.3.0 hashes are unchanged. The erratum states 554 / 252 / 302, 16 per language, the corrected "new samples" sentence, and the stale "v0.1" guide title.

**AD-060 — Where and when the erratum is published**
- **Question:** Where and when is the dataset-card erratum published?
- **Evidence:** G5 (WF l.85–90). **The sources are silent on where an erratum should live.**
- **Options:** (a) A dated file under `docs/`. (b) A file beside v0.3.0, outside its folder. (c) Inside v0.3.1 only.
- **Recommended:** (a).
- **Depends on:** AD-059.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** the erratum file exists, dated, with no edits to v0.3.0.

**AD-061 — Build-script copy step** `DEFERRED`
- **Question:** Should the v0.3.1 build stop copying the previous card and guide verbatim?
- **Evidence:** B3 l.49–52.
- **Options:** (a) Fix it at v0.3.1. (b) Leave it.
- **Recommended:** (a), as a separate pipeline change.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** the v0.3.1 card's counts match the v0.3.1 data.

**AD-062 — `is_quoted_or_discussed` review** `DEFERRED`
- **Question:** After AD-001 to AD-003 are decided, is the author-side `is_quoted_or_discussed` field reviewed for consistency during v0.3.1 adjudication?
- **Evidence:** LG l.12–14; RD l.143.
- **Options:** (a) Yes. (b) No.
- **Recommended:** (a).
- **Depends on:** AD-001 to AD-003.
- **Basis:** OWNER_JUDGMENT. **Status:** `PENDING_PROJECT_OWNER_DECISION`.
- **Validation:** any change is recorded in the v0.3.1 changelog; v0.3.0 is unchanged.

**AD-063 — Aggregate author-label analysis**
- **Question:** Should anyone run aggregate counts over `samples.jsonl`?
  - Fields: `label`, `attack_category`, `obfuscation_type`, `language`, `source_type`, `is_quoted_or_discussed`.
  - Output: counts only — no `text`, no `sample_id`, no split files, no keys.
- **Evidence:** not required by any source.
- **Options:** (a) Do not run. (b) The owner runs it. (c) The AI runs it, with the user's approval.
- **Recommended:** (a). It is not needed to decide any row above.
- **Basis:** OWNER_JUDGMENT (user access). **Status:** `PENDING_USER_DECISION`.
- **Validation:** if ever run, counts only, logged, and never shared with the annotator.

---

## 2. Contradictions and dependencies, resolved analytically (no decisions made)

### 2.1 R-13a vs R-02a (v0.9 J1 → AD-038, AD-039)

The contradiction exists only if AD-005 ("a sensitive action alone is insufficient") is read as covering *all* behaviours. RG lists secrets and credentials (l.28) and sensitive tool actions (l.29–30) as **separate bullets**. AD-005 is derived from the tool-action clause and RG l.51–53's deletion example.

Recommended reading (AD-039 option (a)): AD-005 is scoped to tool actions, and credentials follow AD-038. This removes the contradiction without altering any source text.

If the owner prefers option (b), AD-038 must be rejected or narrowed, for consistency. **Owner decision required.**

### 2.2 R-05b vs the individual R-06 additions (v0.9 J2 → AD-016 and AD-024–AD-028)

Under AD-016 option (a), cases that carry a C1–C3 cue are already `other_suspicious` (AD-020). AD-024 to AD-028 are therefore framed in this addendum to cover only cases **without** such a cue. This removes the double-counting.

**Compatibility constraints:**
- If AD-016 = (a), no inclusion decision may be read as *narrowing* the C1–C3 cases.
- If AD-016 = (b) (X2-alt), AD-017 must be (b), and AD-024, AD-025, AD-027 and AD-028 become largely redundant.
- If AD-016 = (c), it conflicts with AD-013 and should not be combined with AD-013 (a).

### 2.3 Additional dependencies found during this audit

| ID | Dependency | Constraint |
|---|---|---|
| D-a | AD-043 → AD-003, AD-008, AD-047, AD-048 | If AD-043 is rejected, those four need replacement options |
| D-b | AD-044 → AD-043 | v0.8 recommended 0.5; this addendum recommends the documented 0.7 instead. **Flagged as a change of recommendation, not a decision** |
| D-c | AD-012 ↔ AD-042 ↔ AD-041 | "Internal" recognition must exclude content-designated destinations, or E7 and the private-data rule can disagree |
| D-d | AD-036 ↔ AD-038 ↔ AD-039 | If hidden instructions are ruled "secrets", every prompt-disclosure request becomes `exfiltration_request` under AD-038 (a) |
| D-e | AD-018 ↔ AD-040 | A tracker that collects personal data may fall under AD-041, not AD-018; the owner should state which governs |
| D-f | AD-005 / AD-006 → AD-013 | Never inferring provenance is safe only once the evidence rule is ratified |
| D-g | AD-017 ↔ AD-016 | Must be chosen as a matching pair |
| D-h | AD-019 ↔ AD-028 | Must be consistent for summaries without a cue |
| D-i | AD-047 must be fixed **before** the mapping-key join | Avoids choosing thresholds after seeing results |

**Unresolved conflicts** — documents silent or conflicting; owner judgment required:
- AD-002 (sources conflict) and AD-003;
- AD-008 (sources conflict);
- AD-016 and its X2 dependants AD-017 to AD-019;
- AD-038, AD-039 (sources conflict), AD-040, AD-041, AD-042 — X4;
- AD-044.

---

## 3. Mapping of every prior ID to this register

Mapping types:
- **row** — maps to one or more AD rows.
- **DOC** — documented fact, no decision needed.
- **SUPERSEDED** — replaced by the listed rows.
- **EDITORIAL** — a review finding about wording or markers, not a decision.

| Prior ID | → | Prior ID | → |
|---|---|---|---|
| v0.1 R1 | AD-043, AD-044 | v0.1 R5 | SUPERSEDED → AD-001–AD-003 |
| v0.1 R2 (+ Q2b) | SUPERSEDED → AD-009, AD-011, AD-012, AD-013 | v0.1 R6 | SUPERSEDED → AD-015, AD-016 |
| v0.1 R3 | SUPERSEDED → AD-031, AD-032 | v0.1 R7 | AD-022–AD-028 |
| v0.1 R3a | AD-029 | v0.1 R8 | AD-055–AD-057 |
| v0.1 R3b | AD-033 | v0.1 L | AD-050, AD-051 |
| v0.1 R3c | AD-036 | v0.1 C | DOC (7 official categories, SCH l.8–16) → AD-020, AD-031 |
| v0.1 R3d | AD-037 | | |
| v0.1 R4 | AD-034 | | |
| D-Q1a | AD-043 | D-Q5a | AD-001 |
| D-Q1b | AD-046, AD-047 | D-Q5b | AD-002 |
| D-Q1c | AD-048 | D-Q5c | AD-004 |
| D-Q2a | AD-009 | D-Q6a | AD-015 |
| D-Q2b | AD-011 | D-Q6b | AD-016–AD-019 |
| D-Q2c | AD-012 | D-Q6c | AD-021 |
| D-Q3a | AD-031, AD-032 | D-Q7a | AD-022 |
| D-Q3b | AD-029, AD-030 | D-Q7b | AD-024–AD-028 |
| D-Q3c | AD-033 | D-Q7c | AD-023 |
| D-Q3d | AD-036 | D-Q8a | AD-055 |
| D-Q3e | AD-037 | D-Q8b | AD-056 |
| D-Q4a | AD-034 | D-Q8c | AD-057 |
| D-Q4b | AD-035 | D-Q8d | AD-058 |
| D-La | AD-052 | v0.2 doc item D1 | AD-059, AD-060 |
| D-Lb | AD-053 | v0.2 doc item D2 | AD-046, AD-049 |
| D-Lc | AD-054 | | |
| U-E1 | AD-029 | U-T1 | AD-009 |
| U-E2 | AD-030 | U-T2 | AD-011, AD-012 |
| U-E3 | AD-063 | U-T3 | AD-013, AD-014 |
| U-R1 | AD-001 | U-C1 | AD-046 |
| U-R2 | AD-002, AD-003 | U-C2 | AD-047 |
| U-R3 | AD-062 | U-C3 | AD-049 |
| U-D1 | AD-059, AD-060 | U-D2 | AD-061 |
| W-01 | AD-002, AD-003 | W-12 | AD-013, AD-014 |
| W-02 | AD-001 | W-13 | AD-043, AD-044 |
| W-03 | AD-015–AD-021 | W-14 | AD-046, AD-047 |
| W-04 | AD-022–AD-028 | W-15 | AD-048 |
| W-05 | AD-029, AD-030 | W-16 | AD-049 |
| W-06 | AD-031, AD-032 | W-17 | AD-063 |
| W-07 | AD-036 | W-18 | AD-055–AD-058 |
| W-08 | AD-037 | W-19 | AD-050–AD-054 |
| W-09 | AD-033 | W-20 | AD-059, AD-060 |
| W-10 | AD-034, AD-035 | W-21 | AD-061 |
| W-11 | AD-009–AD-012 | W-22 | AD-062 |
| X1 | AD-005–AD-008, AD-012 | X3 | AD-001–AD-003 |
| X1-a | AD-008 | X4 | AD-038–AD-042 |
| X2 | AD-016–AD-021, AD-024–AD-028 | v0.6 new open point (internal private data) | AD-040–AD-042 |
| X2-alt | AD-016 option (b), AD-017 option (b) | | |
| R-01 / R-01a / R-01b / R-01c | AD-001–AD-004 / AD-001 / AD-002 / AD-003 | R-11 | AD-036 |
| R-02 / R-02a / R-02b / R-02c / R-02d | AD-005–AD-008 / AD-005 / AD-006 / AD-007 / AD-008 | R-12 | AD-037 |
| R-03 / R-03a / R-03b / R-03c | AD-009–AD-012 / AD-009 / AD-011 / AD-012 (convention → AD-010) | R-13 / R-13a / R-13b | AD-038–AD-042 / AD-038, AD-039 / AD-040, AD-041 |
| R-04 | AD-013, AD-014 | R-14 | AD-043, AD-044, AD-045 |
| R-05 / R-05a / R-05b / R-05c | AD-015–AD-021 / AD-015 / AD-016–AD-020 / AD-021 | R-15 / R-15a / R-15b / R-15c | AD-046–AD-048 / AD-046 / AD-047 / AD-048 |
| R-06 | AD-022–AD-028 | R-16 | AD-049 |
| R-07 | AD-029, AD-030 | R-17 | AD-050–AD-054 |
| R-08 | AD-031, AD-032 | R-18 | AD-055–AD-058 |
| R-09 | AD-033 | R-19 | AD-059–AD-061 |
| R-10 | AD-034, AD-035 | R-20 | AD-062 |
| | | R-21 | AD-063 |

**v0.9 findings:**

| Finding | → |
|---|---|
| O1 | AD-010 |
| O2 | AD-014 |
| O3 | AD-045 |
| O4 | AD-057 |
| O5 | AD-058 |
| O6 | AD-040 |
| O7 | AD-042 |
| CB1 | AD-024–AD-028 |
| CB2 | AD-031, AD-032 |
| CB3 | AD-050–AD-054 |
| CB4 | AD-055–AD-058 |
| CB5 | AD-059–AD-061 |
| J1 | AD-039 (§2.1) |
| J2 | §2.2 |
| J3 | D-a |
| J4 | D-c and AD-012 |
| J5 | D-d |
| J6 | D-f |
| S1 | AD-038 (reclassified) |
| S2 | EDITORIAL — the SC note in §0 |
| S3 | AD-044 |
| S4 | AD-051 |
| S5 | AD-048 |
| S6 | AD-006 |
| M1–M5 | EDITORIAL — handled by the explicit Basis field on every row |

**IDs that cannot be mapped unambiguously:**
- **None cannot be mapped.**
- **One-to-many mappings** (split decisions — complete, but one prior answer now needs several answers): D-Q1b, D-Q3a, D-Q3b, D-Q6b, D-Q7b, D-Q8 (as a group), W-01, W-03, W-04, W-11, W-12, W-13, W-14, W-18, W-19, U-R2, U-T2, R-13a (split into AD-038 rule + AD-039 precedence), v0.2 doc item D2, and X2.
- **Non-decision IDs**, mapped as DOC or EDITORIAL: v0.1 C; v0.9 S2 and M1–M5.

---

## 4. Register (intentionally blank decision cells — owner/user only)

| ID | Short title | Status | Basis | Rec. | Decision | By | Date |
|---|---|---|---|---|---|---|---|
| AD-001 | Frames F1–F3; self-labels not frames | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-002 | Unframed relays suspicious | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-003 | Bare reports and F2 | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | c | | | |
| AD-004 | One ruling per shared question | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-005 | Sensitive action alone insufficient | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-006 | Evidence E1–E5 required | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-007 | E6 task switch | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-008 | Bare imperatives (X1-a) | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-009 | Authorisation is relation task | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-010 | `relation-task:` convention | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-011 | Internal non-secret forwarding | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-012 | E7 designated destination | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-013 | Never infer provenance | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-014 | Future `source_type` exposure (DEFERRED) | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-015 | Enumerated behaviours only | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-016 | Definition of "covert" (X2) | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-017 | Fake-review policy (X2 vs X2-alt) | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-018 | Hidden tracking | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-019 | Slanted summaries | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-020 | Category for covert cases | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-021 | `scope-note:` convention | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-022 | Official inclusions | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-023 | Official exclusions | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-024 | Inclusion 1: false statements to user | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-025 | Inclusion 2: record falsification | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-026 | Inclusion 3: delayed triggers | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-027 | Inclusion 4: ad insertion without cue | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-028 | Inclusion 5: rating/summary manipulation without cue | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-029 | Encoded attacks | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-030 | Decoded goal as `alt-category:` | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-031 | Interim category rule | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-032 | Final precedence (DEFERRED) | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-033 | Business authority not impersonation | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-034 | Language not obfuscation | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-035 | Encoded non-English | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-036 | System-prompt disclosure | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-037 | Payment definition | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-038 | Credentials rule (ex R-13a) | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-039 | AD-038 vs AD-005 precedence | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-040 | "Private data" definition | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-041 | Private-data rule (ex R-13b) | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | b | | | |
| AD-042 | Internal-destination recognition | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-043 | `ADJUDICATE:` convention | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-044 | `ADJUDICATE:` confidence ceiling | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | b | | | |
| AD-045 | Future third label (DEFERRED) | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-046 | Threshold field scopes | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-047 | Adjudication trigger | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-048 | Kappa with/without flagged rows | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-049 | Guide-precedence statement (DEFERRED) | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-050 | Language policy L | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-051 | AI never sets `ok` | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-052 | Who reviews languages | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-053 | Review timing | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-054 | Failed-row handling (DEFERRED) | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-055 | Issue errata | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-056 | Errata delivery | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-057 | IN prevails on form questions | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-058 | Validator tightening (DEFERRED) | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-059 | Card-correction strategy | RECOMMENDED_FOR_ADOPTION | EVIDENCE_SUPPORTED | a | | | |
| AD-060 | Erratum location | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-061 | Build-script fix (DEFERRED) | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-062 | `is_quoted_or_discussed` review (DEFERRED) | PENDING_PROJECT_OWNER_DECISION | OWNER_JUDGMENT | a | | | |
| AD-063 | Aggregate author-label analysis | PENDING_USER_DECISION | OWNER_JUDGMENT | a | | | |

**Totals:**
- 63 rows: 25 `RECOMMENDED_FOR_ADOPTION`, 37 `PENDING_PROJECT_OWNER_DECISION` (8 of them `DEFERRED`), 1 `PENDING_USER_DECISION`.
- Nothing is ratified. The quality gate stays **OPEN**.
