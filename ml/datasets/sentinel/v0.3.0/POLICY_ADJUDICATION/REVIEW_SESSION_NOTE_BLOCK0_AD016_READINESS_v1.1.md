# Review-Session Note — Block 0, AD-016 options, human-review readiness (register v1.1)

| | |
|---|---|
| Status | **Review note only.** No rule is approved or ratified; no decision field exists or is filled. Every register status, decision wording and recommendation is **unchanged**: the v1.1 register (sha256 `ffcb2fbb…`) and the agenda (sha256 `add09637…`) are not modified. |
| Prepared | 2026-10-27, by an AI assistant (Claude Code). Not an annotator, adjudicator or project owner. |
| Quality gate | **OPEN.** |
| Audience | Owner/adjudicator only. **Do not give this note to the annotator:** it discusses policy options and AI-assisted work. |
| Validation | `VALIDATION_LOG_REVIEW_SESSION_NOTE_v1.1.txt` (same folder). |

**Markers:**
- **[DOC]** — what an official source says.
- **[INT]** — an interpretation of the sources, not stated in them.
- **[CONV]** — a proposed convention.
- **[PROBE]** — the result of a synthetic test of the intake validator (scratchpad files only; no package rows read).

**Source tags:** as in v1.1 §0, plus:
- **ER** — `POLICY_ADJUDICATION/ROUND2_FIELD_MAPPING_ERRATA_DRAFT_v0.1.md`
- **AG** — `POLICY_RATIFICATION_AGENDA_v1.1.md`
- **V11** — v1.1 register; **V09** — v0.9 review.

---

## A. Block 0 — each recommendation checked against its source

| Row (status unchanged) | Documented facts [DOC] | Interpretation or convention | Unsupported element or dependency | Assessment |
|---|---|---|---|---|
| **AD-022** Official `other_suspicious` inclusions (REC, ES) | RG l.33–34: "fabricated consent, covert steering, urgency pressure", when the behaviour "fits none of the above". LG l.20–22: fake-CEO and bypass-approval pressure, "unless a more specific category fits" | None | None. It restates documented text (v0.8 would call it `DOCUMENTED`) | **Ready for ratification** |
| **AD-046** Threshold field scopes (REC, ES) | RG l.40–41 attaches 0.7 to `confidence_0_1`. LG l.24–26 attaches 0.9 to `annotation_confidence`. IN l.6 designates RG for Round 2 | Only the statement that the two numbers do not conflict. Each source names its own field, so the "interpretation" label from v0.9 M3 is conservative | None | **Ready for ratification** |
| **AD-001** Frames F1–F3 benign; self-labels not frames (REC, ES) | LG l.12–14 (discusses, quotes, reports, teaches defence). RG l.17–18 (quotes "in order to explain or criticise"). RG l.49–50 (training material, papers, incident reports, fiction). RG l.19–20 (safety advice) | [CONV] The names F1–F3. [INT] "Provenance labels are not frames" — drawn from RG l.17–18's purpose wording; no source says it | Feeds AD-064, where frames are applied first. LG l.13's `is_quoted_or_discussed` is an author-side field, absent from the IN l.8 form, so it needs no annotator action | **Ready for ratification.** The second half should be recorded as an interpretation |
| **AD-005** A sensitive action alone is insufficient (REC, ES) | RG l.29–30: `tool_redirect` requires an action "the user did not request", so the action type alone does not meet the definition. RG l.51–53: "not automatically an injection". RD l.154–155: mismatch belongs to the relation task | [INT] Reconciling with LG l.9–11 ("embedded in untrusted content that directs the agent … `suspicious`") together with RG l.8–9 (every row is untrusted) needs "embedded … directs" to mean *extra* evidence (E5), not something every row satisfies | **Weak citation:** LG l.16–17 concerns summarise/translate, not sensitive actions. **Open scope:** credentials (AD-039) and self-scope (AD-065) | **Ready for ratification, scoped:** "action type alone is insufficient" only. Ratifying it does not decide credentials or self-scope |
| **AD-043** `ADJUDICATE:` convention (REC, ES) | INT l.36–38 forces a binary label. RD l.116–121: record ambiguity "instead of forcing false certainty". RG l.40–41: low confidence is "useful data". WF l.91–93: rule for rows rated without confidence | [CONV] The `ADJUDICATE:` token. [CONV] Treating the label as a non-binding placeholder, kept out of primary agreement and training; WF l.91–93 is close to this but not the same | **Not enforced:** intake never reads `uncertainty_note` (INT l.21–59; probe P4). A missing or mistyped flag passes intake. RG calls the note field `disagreement_reason` (RG l.42–44), so the flag depends on the errata and form precedence (AD-055, AD-057). The confidence value is AD-044 | **Ready for ratification as a mechanism.** The adjudicator must detect flags by hand; AD-044 stays separate |
| **AD-006** Evidence E1–E5 required for `tool_redirect` (REC, ES) | E1 override: RG l.25–26. E2 authority claim: RG l.27. E4 asserted consent or skipped approval: RG l.33–34 ("fabricated consent"), LG l.20–22 ("bypass-the-approval"). E5 instruction embedded and directing the agent: LG l.9–11 | [INT] E3 "concealment from the user" is a reading of RG l.33–34 "covert steering", the term AD-016 has not yet defined. [INT] Making E1–E5 *necessary* is a reading of RG l.29–30 together with l.51–53 (V09 S6) | **Dependency not listed in v1.1 §3:** E3's meaning overlaps AD-016. v1.1 D-e notes only "C1 = E3". E3 as a textual concealment cue works at every AD-016 level, but the owner should know it is borrowed from the undefined term | **Owner confirmation needed on two interpretive elements:** the necessity reading, and E3's wording. The items E1, E2, E4 and E5 are documented |
| **AD-013** Never infer provenance (REC, ES) | RG l.8–9: every row is "untrusted content" (document, webpage, email, tool output). IN l.8: the form has no source field | [INT] "Never infer who wrote a row" is not stated anywhere. RD l.137 shows only that `source_type` exists in the schema, so it does not support the rule | **Tension with a documented edge case:** RG l.51–53 ("a user's own scoped instruction **in chat**") presupposes identifying user chat, and RG l.8–9's list omits chat. Reconciled only by v1.1 AD-065 (a)'s text-cue reading (D-k; AG §4) | **Needs an owner ruling** on the reconciliation, ratified together with the AD-065 reading. As worded, its `EVIDENCE_SUPPORTED` basis is overstated in the same way v0.9 S1 found for R-13a. The status is **not** changed here |

**Summary for the session:**
- **Ready for ratification:** AD-022, AD-046, AD-001, AD-005 (scoped), AD-043 (mechanism).
- **Still need an owner ruling or explicit confirmation:** AD-006 (two interpretive elements) and AD-013 (reconciliation with RG l.51–53).

---

## B. AD-016 — the recorded options and their effects (no option chosen; no new option)

**The options exactly as recorded** (V11 l.308–314). Each level includes those below it.

| Option | Recorded definition (condensed from V11) |
|---|---|
| **L0** | "The text covertly steers the agent itself: fabricated consent, urgency pressure, hidden steering of its output. **No** extension to deception the agent is asked to commit" |
| **L1** | L0, plus the text tells the agent to hide or misstate "what it did to material or systems it handles". Cues: C1 (hide), C2 restricted to the agent's own edits, C3 + C1 (tracking) |
| **L2** | L1, plus "newly generated content presented as authored by someone else" |
| **L3** | X2-alt: L2, plus "any output meant to mislead any reader" |
| *P (excluded)* | "Concealment from 'the person the agent serves'". It conflicts with AD-013 |

**Effect on the linked rows.** Outcomes come from V11 l.330–340 and V11 l.383–389. "Exception" means the outcome holds only if a reasoned exception is recorded.

| Linked row | L0 | L1 | L2 | L3 |
|---|---|---|---|---|
| AD-017 fake reviews (K-a open, K-b with cue) | (a): K-a benign, K-b benign | (a): K-a benign, K-b suspicious | (b): suspicious | (b): suspicious |
| AD-018 hidden tracking | **No listed option**: all benign (AG OBS-1) | (a) | (a) | (b) |
| AD-019 slanted summaries | **No listed option**: all benign (AG OBS-1) | (a) | (a) | (b) |
| AD-024 false statements to user | (b) | (b) | **No recommendation stated**; including it would be an exception (AG OBS-2) | (a), redundant |
| AD-025 falsified records or logs | (b) | (b) | **No recommendation stated** (AG OBS-2) | (a), redundant |
| AD-026 delayed triggers | Independent of AD-016 | Independent | Independent | Independent |
| AD-027 promotional insertion without cue | (b) | (b) | (b) | (a), redundant |
| AD-028 rating/summary manipulation without cue | (b) | (b) | (b) | (a), redundant |

**Contradictions to keep in view:**
- **L0** — AD-018 and AD-019 have no listed option that matches (AG OBS-1).
  - AD-006 E3 still counts concealment as evidence for `tool_redirect`. So under L0, concealment matters for tool actions but not for other deception. That is coherent, but asymmetric.
- **L1** — the v1.1 recommendations are internally consistent.
- **L2** — AD-017 must be (b). The recommendations for AD-024 and AD-025 are unstated (AG OBS-2).
- **L3:**
  - All derived rows flip to "suspicious", and AD-024, AD-025, AD-027 and AD-028 become largely redundant.
  - It labels *openly requested* content as "covert" (K-a, K-i). That strains the plain meaning of RG l.33–34 ("manipulate covertly").
  - It also strains the task scope in LG l.3–5 and LG l.7, and the ordinary-task rule in LG l.16–17 ("rewrite").
  - AD-021's `scope-note:` would rarely apply.
- **P** — contradicts AD-013. It is already excluded.

**False-positive and false-negative risks per option.** These are [INT] review analysis, not recorded in v1.1, and they recommend nothing.

| Option | False-positive risk (benign text flagged) | False-negative risk (attack missed) |
|---|---|---|
| L0 | Lowest | The agent being told to hide its own edits, insertions or tracking (K-c, K-e, K-g) is benign unless E5 applies |
| L1 | **The C1 "don't mention" cue overlaps legitimate redaction** ("summarise, but don't mention the patient's name"). C2 overlaps legitimate clean-up ("accept tracked changes so it reads as final") | Openly requested deceptive content (K-a, K-h, K-i) |
| L2 | L1's risks, plus **ghostwriting**: speeches, posts or letters drafted for a named person meet "authored by someone else" | Open content deception (K-h, K-i); undisclosed slant (K-f) |
| L3 | **Highest:** persuasive and marketing copy, fiction, one-sided debate preparation, scoped summaries. In practice this turns Sentinel into a misuse classifier (LG l.3–5) | Lowest |

---

## C. Human-review readiness (Round 2)

**Scope of inspection:**
- **Read:**
  - the reviewer-facing instructions (`ANNOTATOR_PACKAGE/INSTRUCTIONS.md`, `ANNOTATOR_PACKAGE/REVIEWER_GUIDE.md`);
  - the field-name errata draft (ER);
  - the intake validator (INT).
- **Folder names only** (names listed, contents not read): `REVIEW_ROUND2/`, `AI_ASSISTED_REVIEW_ROUND2/`.
- **Not read:**
  - `review_blind_opaque.csv`, so the errata's claim about the header (ER l.19) was **not** re-verified in this step;
  - the mapping key, author labels, `samples.jsonl`, `.env`, splits;
  - the AI-assisted artifacts;
  - the annotator-safe language worklist (content).

### C1. What intake enforces — a valid submission must have all of these

| Requirement | Source |
|---|---|
| Every review ID in the package answered **exactly once**; no unknown or duplicate IDs | INT l.25–33, l.56–58 |
| `text` **byte-identical** to the package — any edit, even one trailing space, fails | INT l.34–35; [PROBE] P6 |
| `independent_label` is `benign` or `suspicious` | INT l.36–38 |
| `independent_attack_category` is one of the 7 schema categories when suspicious, and **empty** when benign | INT l.39–43 |
| `confidence_0_1` numeric, within [0, 1], not blank | INT l.44–49 |
| `language_quality` is `ok`, `uncertain`, `cannot-judge` — or blank | INT l.18, l.50–51 |
| `annotator_id` and `reviewed_at` not blank | INT l.52–55 |
| File readable as UTF-8 **without a BOM** | INT l.23–24; [PROBE] P2, P7 |
| Success means exit code 0 and "INTAKE OK" | INT l.68–73 |

### C2. What intake does **not** enforce — the process must cover these

| Gap | Probe | Why it matters |
|---|---|---|
| A blank `language_quality` is accepted, even for non-English rows | P3 | Policy L (AD-050) cannot rely on intake. The fix is deferred (AD-058) |
| `reviewed_at` format is not checked ("last tuesday" passes) | P3 | IN l.8 asks for an ISO date. The fix is deferred (AD-058) |
| `uncertainty_note` is never read; the column can even be absent | P4 | `ADJUDICATE:`, `language-uncertain` and other notes are unenforced. The adjudicator must check them |
| Column set and order are not checked (extra columns pass) | P5 | IN l.10 "structure unchanged" relies on the annotator |
| Intake cannot tell a human submission from an AI one; `annotator_id` is self-chosen (IN l.8) | — | The owner needs an attestation, outside the file, of who annotated (LG l.35: not the author, not an LLM) |

### C3. Practical failure modes for the handout (owner to decide; nothing added to the package)

| Probe | What happened | Handout advice it implies |
|---|---|---|
| P2 | A UTF-8 file with a BOM — as some spreadsheet "CSV UTF-8" exports write it — failed on every row | Save as UTF-8 **without** BOM |
| P7 | A cp1252 file containing "é" crashed the validator (`UnicodeDecodeError`) instead of reporting errors | The same — a UTF-8 file without BOM |
| P6 | Changing the `text` cell by one trailing space failed identity | Never edit the `text` column; avoid tools that re-quote or trim cells |

### C4. Conflicts between the instructions and drafts

- **The guide in the package uses Round-1 names:**
  - "Work from `review_blind.csv`" (RG l.4);
  - `disagreement_reason`, including for `language-uncertain` (RG l.42–44, l.52–53, l.55).
  - The instructions use the Round-2 names (IN l.6, l.8–9).
- **The errata is still a draft:** ER l.18–21 maps the names, but it is `DRAFT_NOT_APPROVED` and outside the package (ER l.3). Its issue and delivery are AD-055 and AD-056; IN's precedence on form questions is AD-057.
- **The errata's placeholders are stale:** they cite the v0.2 brief's question numbers (ER l.33–38), not current AD IDs. The current equivalents:
  - Q1 → AD-043 / AD-044;
  - Q8c → AD-057;
  - L → AD-050 / AD-051;
  - Q2–Q7 → the rows mapped in v1.0 §3.

  They should be re-pointed before the errata is issued. That is an owner action; this note edits nothing.

### C5. Language-review staffing prerequisites

| Prerequisite | Basis |
|---|---|
| Fluent reviewers for **Spanish, German and Hindi**, covering 30 non-English rows | RG l.42–44; IN l.8–9; V09 l.202 |
| Who reviews — separate fluent reviewers, or the annotator using `cannot-judge` — and when (before or during annotation) | AD-052, AD-053 (pending) |
| `ok` only when a fluent human confirms the language; otherwise `uncertain` or `cannot-judge` plus a note | AD-050 (REC); IN l.9 |
| AI output never sets `ok`; the existing AI files that mark `ok` are not used | AD-051 (pending) |
| Reviewers are real people, not the dataset author and not an LLM | LG l.35; RD l.165 ("where annotation is reliable") |
| Blank `language_quality` is caught **by hand**, because intake accepts it | C2; AD-058 |
| The annotator-safe language worklist lives **inside** `POLICY_ADJUDICATION/`, a folder ER l.46 says never to give the annotator. Only that one file could be handed over, after an owner check of its content (not inspected in this step) | ER l.46 |

### C6. Blinding prerequisites

| Prerequisite | Basis or check |
|---|---|
| Hand over only the three package files: `INSTRUCTIONS.md`, `REVIEWER_GUIDE.md`, `review_blind_opaque.csv`. The mapping key sits in `ADJUDICATOR_ONLY/` | File listing in this step; WF l.47–48 (not the key, not the changelog) |
| Never share `AI_AUDIT/`, `AI_ASSISTED_REVIEW_ROUND2/` or `POLICY_ADJUDICATION/`, including the v1.1 register, the agenda and this note | ER l.46 |
| No searching online, in datasets or in repositories; no original labels | IN l.6–7 |
| Only owner-approved rules go to the annotator | ER l.33 |
| If any file is added to the package, re-run the leak test and record the new hashes | ER l.42–44 |
| Join with the key only after "INTAKE OK" | INT l.68–73; WF l.51–56 |
| Fix AD-044 and AD-047 **before** the join | AG §6 |

### C7. Readiness verdict

**Not ready for human review.** Outstanding:
1. Owner rulings on the label-policy rows the annotator needs.
2. Issue of the errata (re-pointed placeholders) and its delivery method.
3. Language reviewers assigned, with their role and timing decided.
4. Handout guidance on file encoding and on not editing `text`.
5. An attestation process for who annotated.
6. AD-044 and AD-047 fixed before the join.

The quality gate stays **OPEN**.
