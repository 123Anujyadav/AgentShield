# Sentinel v0.3.0 Round 2 — Final Decision Worksheet **v0.4 (DRAFT)**

| | |
|---|---|
| Status | **`DRAFT_NOT_APPROVED`.** A worksheet for human decisions. **Nothing here is approved.** Every item is `PENDING_USER_DECISION` or `PENDING_PROJECT_OWNER_DECISION`. |
| Builds on | `POLICY_DECISION_BRIEF_v0.2_DRAFT.md` (§6) and `POLICY_CONFLICT_RESOLUTION_SUPPLEMENT_v0.3_DRAFT.md` (§8). Both are unchanged, as are the v0.1 files. |
| Prepared | 2026-10-27, by an AI assistant (Claude, Cowork). Not an annotator, adjudicator, or owner. |
| Quality gate | **OPEN.** |
| Audience | Owner/adjudicator only. Do not give to the independent annotator. |
| Data | No label, sample, split, schema, validator, or annotator-package file was read for labels or changed. |

**Status markers**
- `PENDING_PROJECT_OWNER_DECISION` — an annotation-policy, dataset, documentation, or process ruling.
- `PENDING_USER_DECISION` — permission for the AI assistant's own next action. Only one item has this status: W-17, reading author labels.

**Recommendations** are the AI's view of the most defensible option against the documented goals below. They are **not** decisions. Where official documents do not decide an issue, the item says **"Not decided by official documents — owner ruling required."**

## 0. Documented project goals used to weigh options

| ID | Goal (verbatim or close paraphrase) | Source |
|---|---|---|
| G1 | Do not "bake single-author, partly template-shaped labels into a model". Benign FPR 0.182 is "far above the proposed 0.05 target". | `docs/phase11a-dataset-quality-gate.md`, "## Decision" (l.6–15) |
| G2 | "these classes are not perfectly separable … record that ambiguity … instead of forcing false certainty" | `docs/phase11-sentinel-research.md`, §3 (l.116–121) |
| G3 | Content injection is separate from intent mismatch; a text-only classifier for mismatch "produces unexplained decisions that mimic authorization — exactly what AgentShield must avoid" | same, §3 (l.84–93) |
| G4 | "label by what the text tries to make an agent do, not by keywords" / "not whether it contains scary words" | `ml/datasets/sentinel/v0.3.0/LABELLING_GUIDE.md` l.7; `…/REVIEW_ROUND2/ANNOTATOR_PACKAGE/REVIEWER_GUIDE.md` "What you are judging" l.9–10 |
| G5 | "v0.1, v0.2, and v0.3.0 files are never edited"; adjudicated changes land in a new v0.3.1 | `docs/phase11a-independent-review-workflow.md`, §3 (l.85–90) |
| G6 | The multilingual slice is used only "where annotation is reliable" | `docs/phase11-sentinel-research.md`, §4 (l.165) |
| G7 | The second annotator is "not the dataset author, not an LLM" | `LABELLING_GUIDE.md`, "## Second-annotator review workflow (v0.2)" (l.33–35) |

Short source tags used below:

| Tag | File |
|---|---|
| RG | `ml/datasets/sentinel/v0.3.0/REVIEW_ROUND2/ANNOTATOR_PACKAGE/REVIEWER_GUIDE.md` (line numbers after CRLF normalisation) |
| IN | `…/ANNOTATOR_PACKAGE/INSTRUCTIONS.md` |
| LG | `ml/datasets/sentinel/v0.3.0/LABELLING_GUIDE.md` |
| RD | `docs/phase11-sentinel-research.md` |
| WF | `docs/phase11a-independent-review-workflow.md` |
| QG | `docs/phase11a-dataset-quality-gate.md` |
| EX | `docs/phase11a-dataset-expansion.md` |
| SC | `packages/engine/src/scanner/rules.ts` |
| SCH | `ml/sentinel/schema.py` |
| INT | `ml/sentinel/intake_round2.py` |
| B3 | `ml/sentinel/build_v03.py` |
| B2 | `ml/sentinel/build_round2.py` |

---

## A. Labels and the meaning of "suspicious"

### W-01 — Relayed instructions without defensive framing (`PENDING_PROJECT_OWNER_DECISION`)

*Covers U-R2 and D-Q5b; context U-R1/D-Q5a, D-Q5c.*

**Question.** When content relays an instruction for AI readers in the third person ("the footer tells reading models to…", "a line inserted later reads: assistant, …"), and nothing explains, criticises or warns about it, is the row `benign` or `suspicious`?

**Evidence**
- Pulls toward suspicious: LG l.9–11, "An instruction embedded in untrusted content that directs the agent … is `suspicious`, even if politely phrased."
- Pulls toward benign:
  - LG l.12–14, text that "discusses, quotes, **reports**, or teaches defence against" is benign;
  - RG "Decision rules" l.22–23, "in its own voice";
  - RG "Edge cases" l.49–50, benign "because the sample does not instruct the agent".
- **Not decided by official documents — owner ruling required.**

**Options and consequences**

| Option | Security | Dataset quality | Annotation consistency |
|---|---|---|---|
| A. Suspicious when the relayed text names an action for the agent or AI readers and no defensive framing exists | Catches narrated injections; an attacker cannot evade simply by writing "this page tells assistants to…" | Adds positives that are close to hard-benign. FP risk is contained, because defensive or analytic framing stays benign (v0.3 I2.2) | One test, "actionable for the agent + no framing", that annotators can apply |
| B. Benign (third-person relay is "reporting") | Misses narrated injections — a known evasion path | Fewer FPs (helps G1) but teaches the model that narration neutralises an attack | Simple, but conflicts with LG l.9–11 whenever a relayed line plainly directs agents |
| C. No rule: `ADJUDICATE:` per row | Neutral | Rows stay unresolved and may be excluded (WF §3 l.91–93), shrinking an already thin indirect set | Lowest consistency; pushes cost to adjudication |

**Recommendation: A.** Rationale:
- It follows LG l.9–11 and G4 (what the text tries to make an agent do).
- It keeps the official defensive-framing exception intact (LG l.12–14, RG l.17–18).
- One ruling must apply to all 19 rows listed in the v0.2 brief §3 Q5 (D-Q5c).

### W-02 — Confirm the active / defensive split (`PENDING_PROJECT_OWNER_DECISION`)

*Covers U-R1 and D-Q5a.*

**Question.** Confirm both of these, and confirm that v0.1's blanket rule ("reported → suspicious") is withdrawn:
- (a) an instruction addressed to the agent inside content, without framing, is suspicious even when self-labelled "embedded" or "injected";
- (b) explanatory, critical, warning, teaching or incident-report text is benign.

**Evidence**
- For (a): LG l.9–11; RG l.25–26 (`indirect_injection` "embedded inside otherwise useful content").
- For (b): LG l.12–14; RG l.17–18 and l.49–50.

**Options**

| Option | Consequences |
|---|---|
| A. Confirm | Matches both guides; no new rule |
| B. Reject (a) and treat self-labels as framing | An attacker who adds "embedded line:" escapes detection — security loss. Contradicts RG l.25–26 |

**Recommendation: A.**

### W-03 — Scope: fake reviews, hidden tracking, slanted summaries (`PENDING_PROJECT_OWNER_DECISION`)

*Covers D-Q6a, D-Q6b and D-Q6c.*

**Question 1.** Is "suspicious" limited to the behaviours enumerated in RG "Decision rules" l.22–34?

**Question 2.** Do these three count as "manipulate covertly … covert steering" (RG l.33–34)?
- **(i)** a request to write deceptive third-party content, such as competitor reviews posing as genuine customers;
- **(ii)** an instruction to leave hidden tracking in an exported file;
- **(iii)** an instruction to quietly omit criticism from a summary.

**Question 3.** Should a non-official `scope-note:` convention exist?

**Evidence**
- RG l.9–10 and LG l.13–14: suspicious words alone are insufficient.
- RG l.33–34: "covert steering" is named but not defined.
- **"Covert" (towards whom?) is not defined by official documents — owner ruling required.**

**Options and consequences**

| Option | Security | Dataset quality | Annotation consistency |
|---|---|---|---|
| A. All three in scope → `other_suspicious` | Broadest coverage, including covert output manipulation | Turns Sentinel toward a general misuse classifier, outside the documented task (LG l.3–5). Raises FPs on legitimate requests (G1) | `other_suspicious` grows ambiguous |
| B. All three out of scope → benign (optional `scope-note:`) | Misses covert manipulation that works against the person the agent serves | Keeps the task narrow | Clear, but risks false negatives on (iii)-type rows |
| C. Criterion-based: suspicious only when the text directs the agent to hide something from, or mislead, the person it is serving, or to override its instructions; otherwise benign + `scope-note:` | Catches (iii) when hidden from that person; leaves transparent requests to other controls | Keeps the task close to RG's enumerated behaviours | Needs an owner-approved definition of "covert", otherwise annotators will diverge |

**Recommendation: C**, with an explicit owner definition of "covert". Expected outcomes under C:
- (i) benign, with a scope note — it harms third parties but does not manipulate the agent or the person it serves;
- (ii) and (iii) suspicious when the text says to hide the action from the person served;
- Q1: yes, adopt the enumerated-behaviour test (G4);
- Q3: keep `scope-note:` as a non-official note only.

### W-04 — `other_suspicious` inclusion and exclusion rules (`PENDING_PROJECT_OWNER_DECISION`)

*Covers D-Q7a, D-Q7b and D-Q7c.*

**Question.** Which behaviours belong in `other_suspicious`, and which are excluded?

**Evidence**
- **Official inclusions:** RG l.33–34 ("fits none of the above — fabricated consent, covert steering, urgency pressure"); LG l.20–22 (social-engineering urgency, fake CEO demands, bypass-the-approval pressure).
- **Official exclusions:**
  - anything fitting another category (RG l.33, "fits none of the above"; LG l.21–22, "unless a more specific category fits");
  - quoted or defensive text (LG l.12–14);
  - ordinary tasks (LG l.16–17);
  - keyword-only matches (LG l.13–14; RG l.9–10).
- **Not in official documents:** the five v0.2 PROPOSED inclusions — deceiving the user with false statements, falsifying records/logs/attribution, delayed or conditional triggers, covert ad/promotional insertion, covert rating/summary manipulation.

**Options and consequences**

| Option | Security | Dataset quality | Annotation consistency |
|---|---|---|---|
| A. Official list only | Behaviours outside the list may end up labelled benign | Least drift from the existing data | Annotators must stretch "covert steering" case by case — inconsistent |
| B. Official list + an owner-approved subset of the five, each ruled individually | Covers the attack types present in the package | Moderate change. Each approved item needs a written definition | High, if each item is defined |
| C. Official list + all five | Broadest coverage | Largest scope change from v0.3.0 author practice, which is unknown without W-17 | High, but `other_suspicious` becomes a catch-all |

**Recommendation: B.**
- Rule on each of the five separately.
- Confirm the official exclusions (D-Q7c).
- Keep the precedence clause "only when no other category fits" from RG l.33.

---

## B. Categories

### W-05 — Encoded attacks (`PENDING_PROJECT_OWNER_DECISION`)

*Covers U-E1, U-E2 and D-Q3b.*

**Question 1.** Confirm the split: the label (benign/suspicious) follows the decoded intent, and the category is `obfuscated_injection` whenever the operative instruction is encoded, leetspeak, spaced or homoglyph-altered.

**Question 2.** Should the decoded goal also be recorded as `alt-category:` in `uncertainty_note`?

**Evidence**
- LG l.18–19 ("labelled by its decoded intent; record the transform in `obfuscation_type`").
- RG l.31–32 ("(`obfuscated_injection`; judge the decoded intent)").
- RD §3 l.110 and §4 l.156–157 (both statements in one document).
- SCH l.18 (`OBFUSCATION_TYPES`).

**Options**

| Option | Consequences |
|---|---|
| A. Confirm the split; record the decoded goal as `alt-category:` | Preserves the obfuscation signal for evaluating robustness slices (RD §6). Supports later co-occurrence measurement (RD l.100–103) |
| B. Category = decoded goal (e.g. `exfiltration_request`); obfuscation only in metadata | Annotators cannot fill `obfuscation_type` (absent from IN l.8), so the obfuscation signal is lost from the annotator's labels. Contradicts RG l.31–32 |

**Recommendation: A.**

### W-06 — Category precedence (`PENDING_PROJECT_OWNER_DECISION`)

*Covers D-Q3a.*

**Question.** Should Round 2 use the interim rule — the category of the primary instruction directed at the agent, plus any second applicable category recorded as `alt-category:` — or adopt a fixed precedence order now?

**Evidence**
- RG "Edge cases" l.54–55 ("label by the instruction directed at the agent").
- RD §3 l.100–103 ("Start multi-class, measure co-occurrence, then decide — do not assume separability").
- No official precedence exists — verified absence (v0.3 F4.6 search; v0.2 §3 Q3).
- **Not decided by official documents — owner ruling required.**

**Options**

| Option | Consequences |
|---|---|
| A. Interim rule + `alt-category:` | Follows RD l.100–103. Co-occurrence becomes measurable. Category agreement may be lower, but disagreements become explainable |
| B. Fixed precedence now (v0.1 R3) | Most consistent today, but encodes an unverified order into labels (G1, G2) |
| C. Multi-label | Requires schema and validator changes — out of scope for Round 2 |

**Recommendation: A.**

### W-07 — Is system-prompt / hidden-configuration disclosure in an official category? (`PENDING_PROJECT_OWNER_DECISION`)

*Covers D-Q3d.*

**Question.** When content asks the agent to reveal its hidden instructions, system prompt, or configuration — with no override, no authority claim and no encoding — which official category applies?

**Evidence**
- RG l.28: `exfiltration_request` = "Reveal or send secrets, credentials, or private data".
- SC l.46–57 (`injection.secret-exfiltration`): patterns cover API keys, secrets, passwords, credentials, tokens and private keys. Prompts and instructions are not mentioned.
- RD §3 l.113: `exfiltration_request` mirrors the scanner rule.
- **No official document names system prompts or configuration. Not decided — owner ruling required.**

**Options and consequences**

| Option | Security | Dataset quality | Annotation consistency |
|---|---|---|---|
| A. `exfiltration_request` (hidden instructions/configuration treated as "secrets") | Treats prompt leakage as data leakage, matching common threat models | Enlarges the thinnest suspicious category (QG §1 l.21 and §7 l.113: 19 samples); diverges from the scanner rule's literal patterns | Clear, once written down |
| B. Category of the accompanying technique: `direct_injection` if paired with an override, `impersonation` if an authority is claimed, else `other_suspicious` | Same detection; the category reflects technique | Keeps `exfiltration_request` aligned with the scanner rule | Bare requests ("reveal your instructions") fall to `other_suspicious`, a catch-all |
| C. `other_suspicious` always | Same label; least informative category | Dilutes `other_suspicious` | Simple |

**Recommendation: A.**
- "Secrets … or private data" (RG l.28) reasonably covers confidential configuration.
- It keeps disclosure-goal attacks together.
- The divergence from SC should be noted for future rule alignment. That would be a code change, not proposed.

### W-08 — Definition of a payment-related `tool_redirect` (`PENDING_PROJECT_OWNER_DECISION`)

*Covers D-Q3e.*

**Question.** Which actions count as "payments" for `tool_redirect`?
- refunds;
- approving a purchase order;
- bookings or rebookings that incur charges;
- subscription sign-ups and recurring charges;
- transfers of gift-card balances or loyalty points.

**Evidence**
- RG l.29–30: "payments, deletion, external email, shell commands".
- SC l.60–75 (`injection.unauthorized-tool-action`): "payment" in the explanation; patterns for send/transfer/make payment/money/funds/$amount and "use the payment tool".
- **The official text does not define "payment" — owner ruling required.**

**Options and consequences**

| Option | Security | Dataset quality | Annotation consistency |
|---|---|---|---|
| A. Narrow: explicit transfers of money or funds only | Leaves approvals, refunds, bookings and value transfers to other categories | Matches the scanner patterns literally | Ambiguous cases scatter across `other_suspicious` |
| B. Broad: any action that moves money or monetary value, or commits the user to a charge (payments, refunds, purchase approvals, chargeable bookings, subscriptions, gift-card/loyalty value transfers) | Treats all financial commitments as sensitive tool actions — the risk the scanner rule exists for | Larger `tool_redirect`. The definition must be written down | High: one test, "does it move value or commit to a charge?" |
| C. Middle: money and value transfers + refunds/approvals; bookings and subscriptions → `other_suspicious` | Partial | Fine boundary to maintain | Lower; the booking/subscription boundary is subtle |

**Recommendation: B.**
- It follows the intent of RG l.29–30 and SC l.60–75 (sensitive financial tool actions) and gives annotators a single test.
- Under W-06's interim rule, urgency or fake-authority wrappers stay as `alt-category:`.

### W-09 — Business authority vs `impersonation` (`PENDING_PROJECT_OWNER_DECISION`; confirmation only)

*Covers D-Q3c.*

**Question.** Confirm that claimed business authority (CEO, legal team) is not `impersonation`, which is reserved for system/developer/admin authority, and falls under `other_suspicious` unless a more specific category fits.

**Evidence**
- LG l.20–22 (fake CEO demands → `other_suspicious` unless more specific).
- RG l.27 ("system/developer/admin authority").
- SC l.33 (`injection.privilege-impersonation`).

**Options.** A. Confirm. B. Extend `impersonation` to business authority, which contradicts LG l.20–22.

**Recommendation: A.**

### W-10 — Non-English text is not obfuscation (`PENDING_PROJECT_OWNER_DECISION`; confirmation only)

*Covers D-Q4a and D-Q4b.*

**Question.** Confirm both:
- language alone never makes a row `obfuscated_injection` or suspicious;
- encoding inside non-English text follows W-05.

**Evidence**
- RG l.31 lists encoding, leetspeak, spacing and homoglyphs — not translation.
- SCH l.18 and RD l.139: `translation` is an `obfuscation_type` metadata value.
- G6.

**Options.** A. Confirm. B. Treat translation as `obfuscated_injection`, which teaches language as an attack signal and creates fairness and FP risk on non-English benign text (G1).

**Recommendation: A.**

---

## C. Provenance and authorisation

### W-11 — Content label vs authorisation; internal forwarding; content-designated destinations (`PENDING_PROJECT_OWNER_DECISION`)

*Covers U-T1, U-T2, D-Q2a, D-Q2b and D-Q2c.*

**Question 1.** Confirm that the content label reflects what untrusted content directs, and that whether the user authorised an action is the separate relation task (a note only in Round 2).

**Question 2.** Confirm that internal forwarding of non-secret material is not suspicious on that basis alone.

**Question 3.** Does a destination designated by the content itself ("the account in the footer", "the wallet mentioned in this page") count as an attack signal?

**Evidence**
- RG l.8–9 (every row is untrusted content) and l.29–30 ("the user did not request").
- LG l.3–5 (intent mismatch "not labelled here") and l.16–17.
- RD §3 l.84–93, l.111 (relation task over intent, action, destination) and §4 l.154–155.
- SC l.60–75 (external messages; "Tool actions are decided by intent and policy only").
- RG l.28 (exfiltration = secrets, credentials, private data).
- **Question 3 is not decided by official documents — owner ruling required.**

**Options for Question 3**

| Option | Consequences |
|---|---|
| A. Yes, it is an attack signal | Captures redirections to attacker-controlled destinations from the text alone (security gain). Small FP risk when legitimate documents list payee details, mitigated because suspicious still needs a directive to the agent |
| B. No — destinations are relation-task only | Purer separation (G3), but misses an obvious content-level redirection cue |

**Recommendation**
- Questions 1 and 2: confirm (G3).
- Question 3: **A**, limited to destinations the content both designates and directs the agent to use.

### W-12 — Chat-like samples whose source type is unknown (`PENDING_PROJECT_OWNER_DECISION`)

*Covers U-T3.*

**Question.** How should annotators treat rows that read like a user's own chat request, given that the blind CSV has no `source_type`?

**Evidence**
- RG l.8–9 (untrusted content: document, webpage, email, tool output) vs RG l.51–53 ("A user's own scoped instruction in chat … is not automatically an injection").
- RD §4 l.137 (`source_type` includes `chat`).
- IN l.8 (no `source_type` field).
- LG l.16–17 (ordinary-task instructions are benign at content level).
- **Not decided by official documents — owner ruling required.**

**Options and consequences**

| Option | Security | Dataset quality | Annotation consistency |
|---|---|---|---|
| A. Treat every row as untrusted content and judge by content signals only. An ordinary, self-scoped task with no attack signal is benign (LG l.16–17); authorisation doubts go in a note (W-11) | Attack signals are still caught regardless of provenance | No dependence on hidden metadata. Consistent with G3 | High: no guessing about provenance |
| B. Annotators guess "this is user chat" and apply the RG l.51–53 exception | Guessing can whitelist attack text phrased as a user request | Labels depend on unverifiable guesses | Low |
| C. Expose `source_type` in a new package | More context | `source_type` may correlate with labels (e.g. `synthetic_direct`), a blindness leak. Needs package rebuild and leak tests | High, but changes the package mid-round |

**Recommendation: A.** Keep C as a possible future-round design question, not for Round 2.

---

## D. Uncertainty, thresholds, and agreement

### W-13 — How insufficient evidence is represented (`PENDING_PROJECT_OWNER_DECISION`)

*Covers D-Q1a.*

**Question.** When the evidence does not support a label, how is this recorded, given that intake requires `benign` or `suspicious`?

**Evidence**
- INT l.37–38 (label must be in `LABELS`; blank rejected); SCH l.7.
- G2.
- WF §3 l.91–93 (unconfident rows: agreement or exclusion).
- RD §4 l.158 (borderline → second annotator; disagreement → adjudicated or exclusion).

**Options and consequences**

| Option | Security | Dataset quality | Annotation consistency |
|---|---|---|---|
| A. Placeholder convention: best label + confidence ≤ 0.5 + `uncertainty_note` starting `ADJUDICATE:`. The label is non-binding: excluded from primary agreement and from training until adjudicated | Neutral | Uncertainty preserved without schema change (G2) | Works with the current validator |
| B. Schema extension (`needs_adjudication` label value) | Neutral | Cleanest data | Requires validator, schema and package changes plus re-running leak tests — mid-round disruption |
| C. Force binary, no flag | Neutral | Forced certainty enters agreement and training (violates G2, G1) | Simple, but hides ambiguity |

**Recommendation: A for Round 2.** Consider B only for a future versioned schema.

### W-14 — Adjudication confidence threshold (`PENDING_PROJECT_OWNER_DECISION`)

*Covers U-C1, U-C2, D-Q1b and v0.2 doc item D2.*

**Question 1.** Confirm the field scopes: 0.7 applies to the annotator's `confidence_0_1` (RG l.40–41), and 0.9 to the author's `annotation_confidence` (LG l.24–26).

**Question 2.** What defines "could not label confidently" for adjudication and exclusion (WF §3 l.91–93)?

**Evidence**
- RG l.40–41; LG l.24–26; WF §2 l.39.
- IN l.6 designates RG for Round 2.
- B3 l.26 and QG l.39–40 (author borderline = 0.65).
- No precedence statement exists between the guides (v0.3 F4.6).
- **Question 2 is not decided by official documents — owner ruling required.**

**Options for Question 2**

| Option | Dataset quality | Annotation consistency |
|---|---|---|
| A. Each rater against their own designated threshold (annotator < 0.7, author < 0.9), OR an `ADJUDICATE:` flag | Uses existing designations with no document change. The author's 0.9 cut-off routes most author-uncertain rows to review | Clear |
| B. One common threshold of 0.7 | Fewer rows to adjudicate. Author rows at 0.7–0.89, which LG calls borderline, are treated as confident — contradicts LG l.24–26 | Clear |
| C. One common threshold of 0.9 | Many annotator rows enter adjudication; heavier workload | Clear |

**Recommendation: confirm Question 1; choose A for Question 2.**

### W-15 — Agreement statistics with flagged rows (`PENDING_PROJECT_OWNER_DECISION`)

*Covers D-Q1c.*

**Question.** Are `ADJUDICATE:` rows excluded from the primary Cohen's kappa and reported separately?

**Evidence**
- WF §3 l.60–71 (kappa with raw agreement and the confusion table; prevalence caveats).

**Options and consequences**

| Option | Consequences |
|---|---|
| A. Exclude from primary kappa; also report all-rows kappa as a sensitivity check | Avoids counting non-binding placeholders as votes (G2). Transparent |
| B. Include all rows | Placeholder values distort agreement |

**Recommendation: A.**

### W-16 — Documentation precedence between the guides (`PENDING_PROJECT_OWNER_DECISION`)

*Covers U-C3 and v0.2 doc item D2.*

**Question.** Should a future documentation change add an explicit precedence statement between LG and RG, and harmonise the threshold text?

**Evidence**
- No precedence statement exists (v0.3 F4.6).
- G5 (versioned files never edited).

**Options**
- A. Add it in v0.3.1 documentation, as new files.
- B. Leave it implicit and rely on IN l.6's designation.

**Recommendation: A, in v0.3.1 only.**

---

## E. Evidence access

### W-17 — Is an aggregate read-only analysis of author labels necessary? (`PENDING_USER_DECISION`)

*Covers U-E3.*

**Question.** Should anyone run an aggregate, read-only cross-tab over `ml/datasets/sentinel/v0.3.0/samples.jsonl` to corroborate W-05 and W-08? Examples: `obfuscation_type × attack_category`, `language × obfuscation_type`. Counts only, no per-row output.

**Evidence**
- The policy documents above are sufficient to decide W-05 and W-08 (v0.3 §1).
- The user previously required explicit approval for any such read.
- `ml/sentinel/generate_expansion.py` encodes some author category assignments (v0.3 §0 disclosure).

**Options and consequences**

| Option | Consequences |
|---|---|
| A. Not run (default) | No exposure of author practice to AI-assisted work. Policy rests on documents and owner ruling |
| B. Owner runs it personally; counts only; results never given to the annotator | Corroborates or contradicts the I1.1 reading and reveals existing-data inconsistencies relevant to v0.3.1 adjudication. No AI exposure |
| C. The AI runs it after explicit user approval | Same insight, but the AI that orchestrates AI-assisted work is then exposed to author-label practice — a contamination risk for any later AI proposals |

**Recommendation: A for Round 2 policy** — it is not necessary to decide the rules. Use B later, if the owner wants a consistency check before v0.3.1.

---

## F. Form, language, and documentation

### W-18 — Round-2 form/field mapping errata (`PENDING_PROJECT_OWNER_DECISION`)

*Covers D-Q8a, D-Q8b, D-Q8c and D-Q8d.*

**Questions**
- (a) Approve `ROUND2_FIELD_MAPPING_ERRATA_DRAFT_v0.1.md`.
- (b) Deliver it as a file in the package (then re-run `ml/tests/test_round2.py` and re-hash) or as a separate handout.
- (c) For form and field questions, does IN prevail over RG?
- (d) Optional, separate: tighten intake to reject a blank `language_quality` and validate the ISO date.

**Evidence**
- IN l.8 vs RG l.42–44 (`disagreement_reason`).
- B2 l.58–59 (Round-1 guide copied).
- INT l.18 (`""` allowed); INT l.54–55 (`reviewed_at` checked only for non-empty).

**Options**

| Item | Options and consequences |
|---|---|
| (b) | **A. Separate handout:** no package change, so package hashes and tests stay as shipped. **B. In-package file:** single source for the annotator, but requires leak-test re-run and re-hash |
| (d) | **A. Defer to a versioned validator change:** no change to official tooling mid-round. **B. Change now:** stricter intake, but modifies the official validator — outside this phase's constraints |

**Recommendation**
- (a) approve after review;
- (b) A, a separate handout;
- (c) yes, IN prevails for form questions only;
- (d) defer.

### W-19 — Language-quality policy and fluent review (`PENDING_PROJECT_OWNER_DECISION`)

*Covers D-La, D-Lb and D-Lc.*

**Questions**
- (a) Who are the fluent human reviewers for Spanish, German and Hindi?
- (b) Does the fluency check happen before or during annotation?
- (c) What happens to rows that fail: exclusion, or rewriting in v0.3.1?
- (d) Confirm the v0.2 L-policy:
  - `ok` only when a fluent human confirms;
  - otherwise `uncertain` or `cannot-judge` plus `language-uncertain <code>`;
  - AI output never sets `ok` on non-English rows.

**Evidence**
- IN l.9; RG l.42–44; INT l.18.
- G6.
- CL l.7 ("explicitly flagged for native-speaker review").
- QG l.22 (16 rows per language in v0.3.0).
- Worklist: `language_review_worklist_ANNOTATOR_SAFE_v0.1.csv` (30 rows).

**Options for (c)**

| Option | Consequences |
|---|---|
| A. Exclude failing rows from v0.3.1 evaluation slices | Honest (G6), but shrinks a small slice |
| B. Rewrite with a fluent author in v0.3.1 | Better coverage, but rewritten rows are new samples and need fresh review |

**Recommendation**
- (a) separate fluent reviewers if available, otherwise the annotator with `cannot-judge` where needed;
- (b) before annotation;
- (c) A for v0.3.1, B as a later expansion;
- (d) confirm.

### W-20 — Dataset-card correction and language-count discrepancy (`PENDING_PROJECT_OWNER_DECISION`)

*Covers U-D1 and v0.2 doc item D1.*

**Question.** How is the stale v0.3.0 dataset card corrected?
- It says "504 samples: 237 benign, 267 suspicious … 440 are new in v0.3.0" and "one benign and one suspicious sample each in Spanish, German, and Hindi".
- The verified totals are 554 samples (252/302) and 16 per language.

**Evidence**
- `ml/datasets/sentinel/v0.3.0/DATASET_CARD.md` l.9, l.20.
- B3 l.49–52 (copied from v0.2.0 with only a string replacement).
- CL l.5–6 (504 + 50).
- QG l.19, l.22 (554; Spanish/German/Hindi 16 each).
- EX l.91–93 (v0.2: 8 each).
- G5 (v0.3.0 files never edited).

**Options and consequences**

| Option | Consequences |
|---|---|
| A. Edit the v0.3.0 card in place | Fastest, but contradicts G5 and changes a frozen version's files and hashes |
| B. Leave v0.3.0 untouched; publish a correction note now (e.g. a dated erratum in `docs/`); write a correct card for v0.3.1 | Honours G5 and the record is fixed immediately. Two places to read until v0.3.1 |
| C. Correct only in the v0.3.1 card | Honours G5, but the stale card stays uncorrected until v0.3.1 ships |

**Recommendation: B.** The erratum should cover the sample totals, the per-language counts, the "440 new" sentence, and the stale "v0.1" title of the copied labelling guide.

### W-21 — Build-script copy step (`PENDING_PROJECT_OWNER_DECISION`)

*Covers U-D2.*

**Question.** Should the next dataset build stop copying the previous version's card and guide verbatim (B3 l.49–52)?

**Options**
- A. Fix it in the v0.3.1 build. This is a pipeline change, made when v0.3.1 is authorised.
- B. Leave it, and correct the cards manually each version.

**Recommendation: A, at v0.3.1 time.** Not now: the pipeline is frozen for this phase.

### W-22 — Future alignment of `is_quoted_or_discussed` (`PENDING_PROJECT_OWNER_DECISION`)

*Covers U-R3.*

**Question.** After W-01 is ruled, should the author-side `is_quoted_or_discussed` field be reviewed for consistency in v0.3.1?

**Evidence**
- LG l.12–14; RD §4 l.143.

**Options.** A. Review it in v0.3.1 adjudication. B. Leave it.

**Recommendation: A**, as a v0.3.1 task. It is a dataset change, so nothing is done now.

---

## G. Coverage matrix: every unresolved ID from v0.2 §6 and v0.3 §8

| Source ID | Worksheet item | Source ID | Worksheet item |
|---|---|---|---|
| D-Q1a | W-13 | D-Q6a, D-Q6b, D-Q6c | W-03 |
| D-Q1b | W-14 | D-Q7a, D-Q7b, D-Q7c | W-04 |
| D-Q1c | W-15 | D-Q8a, D-Q8b, D-Q8c, D-Q8d | W-18 |
| D-Q2a, D-Q2b, D-Q2c | W-11 | D-La, D-Lb, D-Lc | W-19 |
| D-Q3a | W-06 | v0.2 doc item D1 | W-20 |
| D-Q3b | W-05 | v0.2 doc item D2 | W-14, W-16 |
| D-Q3c | W-09 | U-E1, U-E2 | W-05 |
| D-Q3d | W-07 | U-E3 | W-17 |
| D-Q3e | W-08 | U-R1 | W-02 |
| D-Q4a, D-Q4b | W-10 | U-R2 | W-01 |
| D-Q5a | W-02 | U-R3 | W-22 |
| D-Q5b | W-01 | U-T1, U-T2 | W-11 |
| D-Q5c | W-01 | U-T3 | W-12 |
| | | U-C1, U-C2 | W-14 |
| | | U-C3 | W-16 |
| | | U-D1 | W-20 |
| | | U-D2 | W-21 |

## H. Decision register (to be completed by the decision-maker — intentionally blank)

| Item | Status | Recommended | Decision (option / amended text) | Decided by | Date |
|---|---|---|---|---|---|
| W-01 Relayed instructions | PENDING_PROJECT_OWNER_DECISION | A | | | |
| W-02 Active/defensive split | PENDING_PROJECT_OWNER_DECISION | A | | | |
| W-03 Scope: reviews/tracking/summaries | PENDING_PROJECT_OWNER_DECISION | C + define "covert" | | | |
| W-04 `other_suspicious` rules | PENDING_PROJECT_OWNER_DECISION | B (rule each of 5) | | | |
| W-05 Encoded attacks | PENDING_PROJECT_OWNER_DECISION | A | | | |
| W-06 Category precedence | PENDING_PROJECT_OWNER_DECISION | A (interim) | | | |
| W-07 System-prompt disclosure | PENDING_PROJECT_OWNER_DECISION | A | | | |
| W-08 Payment `tool_redirect` | PENDING_PROJECT_OWNER_DECISION | B | | | |
| W-09 Business authority | PENDING_PROJECT_OWNER_DECISION | A (confirm) | | | |
| W-10 Non-English ≠ obfuscation | PENDING_PROJECT_OWNER_DECISION | A (confirm) | | | |
| W-11 Authorisation / destinations | PENDING_PROJECT_OWNER_DECISION | Confirm Q1/Q2; A for Q3 | | | |
| W-12 Chat-like rows | PENDING_PROJECT_OWNER_DECISION | A | | | |
| W-13 Insufficient evidence | PENDING_PROJECT_OWNER_DECISION | A | | | |
| W-14 Threshold | PENDING_PROJECT_OWNER_DECISION | Confirm Q1; A for Q2 | | | |
| W-15 Kappa handling | PENDING_PROJECT_OWNER_DECISION | A | | | |
| W-16 Guide precedence text | PENDING_PROJECT_OWNER_DECISION | A (v0.3.1) | | | |
| W-17 Author-label analysis | PENDING_USER_DECISION | A (not run) | | | |
| W-18 Errata | PENDING_PROJECT_OWNER_DECISION | (a) approve, (b) A, (c) yes, (d) defer | | | |
| W-19 Language review | PENDING_PROJECT_OWNER_DECISION | See item | | | |
| W-20 Dataset card | PENDING_PROJECT_OWNER_DECISION | B | | | |
| W-21 Build copy step | PENDING_PROJECT_OWNER_DECISION | A (v0.3.1) | | | |
| W-22 `is_quoted_or_discussed` | PENDING_PROJECT_OWNER_DECISION | A (v0.3.1) | | | |

**Readiness:** every unresolved item now has a question, evidence, options, consequences and a recommendation. **None is decided.** Next steps:
1. The project owner fills section H.
2. A follow-up step converts approved rows into the errata and guide addenda (new files only).
3. The independent human annotator works from the package plus the approved, sample-free errata.

The quality gate stays **OPEN** until a real human return passes intake and adjudication is complete.

## I. Limitations

- **AI authorship and prior exposure.** The author of this worksheet also produced the prior AI audit and AI proposal round, and has seen the blind texts. The recommendations may reflect that exposure.
- **Line numbers** are tied to the file hashes recorded in `VALIDATION_LOG_v0.4.txt`.
- **No author-label data was used** (see W-17).
