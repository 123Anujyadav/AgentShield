# Batch 1 & Batch 4 Review Memo — v0.6 (DRAFT)

| | |
|---|---|
| Status | **`DRAFT_NOT_APPROVED`.** A focused review to support the owner's decisions. **No decision is made or inferred.** Section H of the v0.4 worksheet is untouched. |
| Scope | W-01, W-02, W-03 (Batch 1) and W-11, W-12 (Batch 4), as defined in `POLICY_FINAL_DECISION_WORKSHEET_v0.4_DRAFT.md` (sha256 `6964a83f…`). |
| Prepared | 2026-10-27, by an AI assistant (Claude, Cowork). Not an annotator, adjudicator, or project owner. |
| Quality gate | **OPEN.** All five items remain `PENDING_PROJECT_OWNER_DECISION`. |
| Audience | Owner/adjudicator only. Not for the independent annotator. |

**Source tags.** These follow v0.4 §0, and the line numbers were verified there:
- RG = Round-2 `REVIEWER_GUIDE.md`
- LG = v0.3.0 `LABELLING_GUIDE.md`
- RD = `docs/phase11-sentinel-research.md`
- SC = `packages/engine/src/scanner/rules.ts`
- IN = Round-2 `INSTRUCTIONS.md`

**Labels used in each item:**
- **[DOC]** — a documented rule.
- **[INT]** — an interpretation, not stated in the documents.
- **[OPEN]** — an unresolved owner decision.

## Key finding first: three cross-decision conflicts the owner should resolve together

| # | Conflict | Items | Why it matters |
|---|---|---|---|
| **X1** | **W-11 Q1 vs W-12 / RG l.51–53.** v0.3 I3.1 (behind W-11 Q1) reads "the user did not request" as satisfied whenever the request originates in content. Taken literally, any sensitive action in a row — including RG's own benign example of deleting one's own duplicate rows — would become `tool_redirect`. W-12's recommendation (judge by attack signals; ordinary tasks are benign per LG l.16–17) points the other way. | W-11, W-12 | Without a qualifier, the two recommendations give opposite labels to the same row type. **Needed:** state whether a sensitive action *alone* is an attack signal, or whether it must also show a signal such as an external or unspecified recipient, concealment, override, or fabricated consent. |
| **X2** | **W-03's "person it is serving" test vs the v0.2 brief and W-11/W-12.** The v0.2 brief (§2 and §3 Q6, R6-v0.2) recorded the "principal" concept as an **ASSUMPTION** absent from RG, LG and RD, and recommended dropping it. v0.4 W-03 option C reintroduces a version of it ("mislead the person it is serving"). W-12 also forbids guessing who issued a row, yet W-03's outcome for fake reviews was justified partly by treating the request as the user's own. | W-03, W-11, W-12 | The drafts are internally inconsistent here. **Needed:** either an owner-written definition of "covert" that doesn't depend on provenance, or acceptance of a principal concept as new policy. |
| **X3** | **W-01 vs W-02 (evasion symmetry).** If W-02 is confirmed (a self-labelled "embedded line: …" addressed to the agent is suspicious) but W-01 is decided as benign, an attacker can switch from addressing the agent to narrating ("the footer tells AI readers to…") and change the label. | W-01, W-02 | The two rulings should be made together, with an explicit test separating "addressed to the agent" from "relayed". |

**Other dependencies (not conflicts):**
- W-01 and W-03 outcomes feed W-22 (`is_quoted_or_discussed` alignment) and W-13 (`ADJUDICATE:` for borderline rows).
- W-03 (iii) "slanted summary" overlaps W-04's proposed inclusion 5 ("covert rating/summary manipulation") and inclusion 1 ("deceiving the user"). W-03 and W-04 must agree.
- W-11 Q3 (destinations named by content) overlaps W-08 (payment definition) and W-01 (relayed instructions that name a destination).

---

## W-01 — Relayed instructions without defensive framing

**Question (v0.4, verbatim).** "When content relays an instruction for AI readers in the third person ('the footer tells reading models to…', 'a line inserted later reads: assistant, …'), and nothing explains, criticises or warns about it, is the row `benign` or `suspicious`?"

**Evidence and status**

| Type | Content |
|---|---|
| [DOC] | LG l.9–11: an instruction embedded in untrusted content that "directs the agent … is `suspicious`, even if politely phrased". |
| [DOC] | LG l.12–14: text that "discusses, quotes, **reports**, or teaches defence against" such instructions is `benign`. |
| [DOC] | RG l.22–23: suspicious requires the text "in its own voice"; RG l.49–50: quoted attacks are benign "because the sample does not instruct the agent". |
| [INT] | v0.3 I2.1: "reports" is best read as reporting *about* an attack for a reader, not relaying an instruction *to* the agent. |
| [OPEN] | Which reading governs third-person relays with no framing. **Not decided by official documents** (v0.3 I2.3). |

**Recommendation (v0.4): Option A** — suspicious when the relayed text names an action for the agent or AI readers and no defensive framing exists.

| Option | Security | Annotation consistency |
|---|---|---|
| A (recommended) | Closes the "narrate instead of address" evasion path (see X3) | One test ("actionable for the agent + no framing"), but annotators need a written definition of "defensive framing" |
| B | Leaves that evasion path open | Simple, but conflicts with LG l.9–11 whenever the relay plainly directs agents |
| C (adjudicate each row) | Neutral | Lowest consistency; the rows may end up excluded |

**Conflicts.** X3 (with W-02). Depends on W-13 if option C is chosen. Its outcome feeds W-22. Scale: v0.2 §3 Q5 lists 19 rows sharing this question; the same ruling must apply to all of them (D-Q5c).

## W-02 — Confirm the active / defensive split

**Question (v0.4, restated).** Confirm three things:
- (a) an instruction addressed to the agent inside content, without framing, is suspicious even when self-labelled "embedded" or "injected";
- (b) explanatory, critical, warning, teaching or incident-report text is benign;
- v0.1's blanket rule ("reported → suspicious") is withdrawn.

**Evidence and status**

| Type | Content |
|---|---|
| [DOC] | (a) LG l.9–11; RG l.25–26 (`indirect_injection` = embedded in otherwise useful content). |
| [DOC] | (b) LG l.12–14; RG l.17–18 ("quotes an attack in order to explain or criticise it"); RG l.49–50. |
| [INT] | That a provenance label such as "embedded line" is neither explanation nor criticism (v0.3 I2.2). |
| [INT] | That v0.1's blanket rule is unsupported (v0.3 I2.2). |
| [OPEN] | Confirmation only. |

**Recommendation (v0.4): Option A — confirm.**
- *Security:* rejecting (a) lets attackers neutralise a payload by prefixing a self-label.
- *Consistency:* confirming keeps both guides aligned and adds no new rule.

**Conflicts.** X3 (with W-01). No conflict with W-05: encoded embedded instructions follow W-05 for the category, while W-02 still decides the label.

## W-03 — Scope: fake reviews, hidden tracking, slanted summaries

**Questions (v0.4, restated)**
1. Is "suspicious" limited to the behaviours enumerated in RG "Decision rules" l.22–34?
2. Do (i) a request to write deceptive third-party reviews, (ii) an instruction to leave hidden tracking in an exported file, and (iii) an instruction to quietly omit criticism from a summary count as "manipulate covertly … covert steering" (RG l.33–34)?
3. Should a non-official `scope-note:` convention exist?

**Evidence and status**

| Type | Content |
|---|---|
| [DOC] | RG l.22–34 enumerates the suspicious behaviours. RG l.9–10 and LG l.13–14: suspicious words alone are insufficient. |
| [DOC] | RG l.33–34 names "fabricated consent, covert steering, urgency pressure", only when nothing above fits. |
| [INT] | v0.4 option C's criterion: suspicious only when the text directs the agent to hide something from, or mislead, the person it serves, or to override its instructions. |
| [OPEN] | **"Covert" — towards whom — is undefined.** All three sub-cases (i)–(iii) are owner rulings. A `scope-note:` convention would be new and non-official. |

**Recommendation (v0.4): Option C**, conditional on an owner-written definition of "covert". The v0.4 expected outcomes are (i) benign with a scope note, and (ii)/(iii) suspicious when hidden from the person served.

| Option | Security | Annotation consistency |
|---|---|---|
| A (all three in scope) | Broadest coverage | Turns `other_suspicious` into a catch-all; drifts from LG l.3–5's task |
| B (all out of scope) | Misses manipulation aimed at the agent's own user | Clear |
| C (recommended) | Catches the user-directed cases | **Consistent only with a written definition**; without one, annotators diverge |

**Conflicts**
- **X2:** the "person it serves" criterion conflicts with the v0.2 brief's finding that the "principal" concept is an assumption, and partly with W-12's ban on guessing provenance.
  - A provenance-free test would ask only whether the text directs the agent to conceal or misrepresent *its own actions or outputs*, without asking who requested it. On that test (i) is still out of scope and (iii) still in scope. Whether (ii) is in scope then depends on whether "nobody opens the file properties" counts as concealing the agent's own output. That wording is an owner decision, not proposed here as policy.
- **Overlaps W-04:** (iii) matches W-04's proposed inclusion 5. "Mislead" matches proposed inclusion 1. W-03 and W-04 must be decided consistently.

Scale: the v0.1 table flags 4 rows under this question.

---

## W-11 — Content label vs authorisation; internal forwarding; content-designated destinations

**Questions (v0.4, verbatim)**
1. "Confirm that the content label reflects what untrusted content directs, and that whether the user authorised an action is the separate relation task (a note only in Round 2)."
2. "Confirm that internal forwarding of non-secret material is not suspicious on that basis alone."
3. "Does a destination designated by the content itself ('the account in the footer', 'the wallet mentioned in this page') count as an attack signal?"

**Evidence and status**

| Type | Content |
|---|---|
| [DOC] | RG l.8–9: every row is untrusted content. RG l.29–30: `tool_redirect` = "a sensitive tool action the user did not request — payments, deletion, external email, shell commands". |
| [DOC] | LG l.3–5: intent mismatch "is a separate task and is not labelled here". RD §3 l.84–93 and l.111 (relation task over intent, action, destination). RD §4 l.154–155. |
| [DOC] | SC l.60–75: external messages; "Tool actions are decided by intent and policy only". RG l.28: exfiltration = secrets, credentials, private data. |
| [INT] | Q1 (v0.3 I3.1): "the user did not request" is satisfied when the request comes from content. Q2 (v0.3 I3.2): "external" qualifies the email case. |
| [OPEN] | Q3: **not addressed by official documents.** Also open: whether *private data* forwarded internally is `exfiltration_request`. RG l.28 lists private data without any destination test, and Q2 covers only non-secret material. |

**Recommendation (v0.4):** confirm Q1 and Q2; for Q3, option A — yes, limited to destinations the content both designates and directs the agent to use.
- *Security:* Q3-A catches redirection to attacker-chosen recipients from the text alone. Q1 keeps permission questions out of the label, as RD l.89–93 requires.
- *Consistency:* Q1 as worded is under-specified (**X1**). Without a qualifier, sensitive actions in ordinary self-scoped requests could be labelled `tool_redirect`.

**Conflicts**
- **X1** (with W-12 and RG l.51–53).
- **X2** (W-03's provenance assumptions).
- Overlaps W-08 (what counts as a payment destination) and W-01 (relayed instructions that name a destination).

## W-12 — Chat-like samples whose source type is unknown

**Question (v0.4, verbatim).** "How should annotators treat rows that read like a user's own chat request, given that the blind CSV has no `source_type`?"

**Evidence and status**

| Type | Content |
|---|---|
| [DOC] | RG l.8–9: rows are untrusted content (document, webpage, email, tool output). RG l.51–53: "A user's own scoped instruction in chat … is not automatically an injection". |
| [DOC] | RD §4 l.137: `source_type` includes `chat`. IN l.8: there is no `source_type` field for annotators. LG l.16–17: ordinary-task instructions are benign at content level. |
| [INT] | Option A — judging by attack signals makes provenance unnecessary, because ordinary tasks are benign anyway. |
| [OPEN] | How annotators should handle these rows. **The documents never say how to tell chat rows apart.** |

**Recommendation (v0.4): Option A** — treat every row as untrusted content; judge by attack signals; no guessing about provenance. Exposing `source_type` (option C) is deferred because it could leak label-correlated hints.
- *Security:* avoids whitelisting attack text phrased as a user request.
- *Consistency:* labels don't depend on hidden metadata.

**Conflicts**
- **X1:** A is consistent only if W-11 Q1 is qualified so that a sensitive action alone isn't an attack signal.
- **X2:** W-03's reasoning must not assume provenance.

Scale: the v0.1 table flags 10 rows under the related provenance question.

---

## What the owner needs to settle across these five items

- **Decide X1, X2 and X3 explicitly.** Each one-line ruling resolves a conflict in the drafts:
  - X1: is a sensitive action alone an attack signal?
  - X2: a provenance-free definition of "covert", or a new principal concept?
  - X3: decide W-01 and W-02 together.
- **Then rule on the individual questions:** W-01 (A/B/C), W-02 (confirm), W-03 Q1–Q3 and (i)–(iii), W-11 Q1–Q3, and W-12 (A/B/C).
- **New open point** (not listed in v0.4): whether internal forwarding of *private data* is `exfiltration_request` (from W-11).

Record the outcomes only in v0.4 Section H.

**Limitations**
- The author of this memo also produced the earlier AI audit and proposals, and has seen the blind texts.
- The conflicts identified here are AI interpretations of draft wording, not official findings.
- No author labels were consulted.
