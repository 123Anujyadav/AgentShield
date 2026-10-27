# Sentinel v0.3.0 Round 2 — Policy Adjudication Proposal **v0.1**

| | |
|---|---|
| Document status | **`PROPOSED_NOT_APPROVED`** — every rule below is a proposal awaiting project-owner decision. None is in force. |
| Version | v0.1 (2026-10-27). Later revisions get new files (v0.2, …); this file is never edited in place after approval. |
| Author | AI assistant (Claude, Cowork session). **Not** a human annotator, adjudicator, or project owner. |
| Quality gate | **OPEN.** Nothing in this document passes, advances, or substitutes for the gate. |
| Scope | Annotation policy for the 196 Round-2 opaque-ID rows and the form returned by the human annotator. |
| Labels changed | **None.** The 7 rows awaiting adjudication stay unlabelled. No dataset, split, intake, validator, guide, or pipeline file was modified. |

> **Adjudicator/owner only — do not give this folder to the human annotator.** It contains opaque `rv-…` IDs, sample excerpts, and AI-proposed labels. Combined with the annotator package, it would destroy Round-2 blindness, exactly like `../AI_AUDIT/` and `../AI_ASSISTED_REVIEW_ROUND2/`. If approved rules must reach the annotator, they go out as a separate, sample-free errata (see Q8).

## 1. What was inspected (read-only)

- `../AI_ASSISTED_REVIEW_ROUND2/`
  - `README.md` and `VALIDATION_LOG.txt`.
  - The proposal CSV (sha256 `{{PROPOSED_SHA}}`, {{N_ROWS}} rows) and its raw `proposals.jsonl`.
- `../REVIEW_ROUND2/ANNOTATOR_PACKAGE/INSTRUCTIONS.md`, `REVIEWER_GUIDE.md`, and the `review_blind_opaque.csv` header.
- `../REVIEW_PACKAGE/REVIEWER_GUIDE.md` and the `review_blind.csv` header (Round 1), to trace the schema mismatch.
- `ml/sentinel/schema.py`, `ml/sentinel/intake_round2.py`, `ml/sentinel/build_round2.py` (guide-copy lines only), and `docs/` category references (grep).

**Not opened:** `ADJUDICATOR_ONLY/mapping_key.csv`, `REVIEW_PACKAGE/review_key.csv`, `samples.jsonl`, `splits/`, `LABELLING_GUIDE.md`, and `.env`.

## 2. Summary of proposed rules (all PROPOSED)

| ID | Question | PROPOSED rule (one line) | Schema change? |
|---|---|---|---|
| R1 | Q1: no "cannot decide" label | Keep binary labels. Undecidable rows: best label, confidence ≤ 0.5, `uncertainty_note` starts `ADJUDICATE:`. | No |
| R2 | Q2: provenance | Default: untrusted content. User-request exception only when explicit self-scoping signals exist and no third-party signals exist. | No |
| R3 | Q3: category precedence | Fixed precedence for one official category: obfuscated → impersonation (agent-control authority) → exfiltration_request → tool_redirect → indirect → direct → other. | No |
| R4 | Q4: translation | Language is not obfuscation. Categorise non-English rows by intent. Translation belongs in the dataset's separate `obfuscation_type` metadata. | No |
| R5 | Q5: self-described injections | Purpose test: an instruction conveyed to the agent (direct, quoted, or reported) is suspicious unless the framing explains, criticises or warns about it. Self-labels such as "embedded" or "injected" are not explanatory framing. | No |
| R6 | Q6: scope | In scope: anything acting covertly against the principal or the agent's instructions. Out of scope: the principal's own transparent request to create harmful-to-third-party content (benign for Sentinel, noted `OUT-OF-SCOPE-MISUSE:`). | No |
| R7 | Q7: coverage | No new categories. `other_suspicious` explicitly covers consent fabrication, covert steering or promotion, deceiving the user, record falsification, delayed triggers and urgency pressure, when no higher-precedence category applies. | No |
| R8 | Q8: form mismatch | The CSV header plus `intake_round2.py` is the authoritative Round-2 schema. An owner-approved, sample-free errata maps the guide's names onto it. | No (errata only) |
| L | Language quality | `ok` only for confident, fluent readers. `uncertain` or `cannot-judge` plus a `language-uncertain` token otherwise. AI output never uses `ok` on non-English rows. | No (validator tightening optional, later) |
| C | Categories | Keep the 7 official categories. `tool_redirect` **is official**; no mapping needed. The prior AI_AUDIT category names are non-official and are mapped only for comparison. | No |

---

## 3. The eight unresolved policy questions

Each question below has: the problem, examples, options with their consequences, the PROPOSED rule, and the affected rows.

The affected-row lists combine three sources:
- (a) questions cited by the AI proposal;
- (b) documented text patterns;
- (c) a short manual list.

They are **not exhaustive**. Full per-row detail is in `policy_decision_table_v0.1.csv`.

### Q1 — No "cannot decide" option

**Problem.** The guide allows only `benign`/`suspicious`, and `intake_round2.py` rejects any other value or a blank. Yet the guide also asks for honest low confidence, and the workflow doc says rows neither rater can label confidently become exclusion candidates. The AI proposal round left 7 rows unlabelled for this reason.

**Examples.**
- {{EX:rv-zy3ek5wge4}}
- {{EX:rv-5f5x0knnio}}

**Options and consequences.**

| Option | What it means | Consequences |
|---|---|---|
| A. Force binary, nothing else | Annotator always picks a label. | Works with the current intake. Undecidable rows become indistinguishable from confident ones except by confidence, which inflates disagreement noise and kappa instability. |
| **B. PROPOSED — binary + flag convention** | Best label, `confidence_0_1 ≤ 0.5`, `uncertainty_note` starting `ADJUDICATE: <reason> [rule IDs]`. | No schema or validator change. Adjudicator can filter. Report kappa twice: all rows, and excluding `ADJUDICATE` rows, as a sensitivity check. Rows flagged by both raters become exclusion candidates per the existing workflow doc. |
| C. Third label value (`needs_adjudication`) | Official schema extension. | Requires changes to `schema.py`/`intake_round2.py`, re-running the leak tests, and a new package version. Out of scope mid-round; possible for a future version only with owner approval. |
| D. Leave blank | — | Rejected by intake. Not viable. |

**R1 (PROPOSED).** Option B.
- The AI proposal file is not an intake return. Its 7 empty labels stay empty and are **not** filled automatically.

**Affected rows ({{Q1_N}}).** {{Q1}}
- The 7 unlabelled rows: {{ADJ7}}
- Labelled at confidence < 0.7: {{LOWCONF}}

### Q2 — Provenance (who is speaking?)

**Problem.** The guide frames every row as untrusted content an agent reads, but its edge case says "a user's own scoped instruction in chat (for example deleting their own duplicate rows) is not automatically an injection". No row records provenance. "Did the user request it?" is therefore undecidable as written.

**Examples.**
- {{EX:rv-oy5pn0od7m}}
- {{EX:rv-qtcg9iceou}}
- {{EX:rv-mgzzzzzczj}}

**Options and consequences.**

| Option | Consequences |
|---|---|
| A. Untrusted everywhere: any sensitive imperative is suspicious | Contradicts the guide's own benign example (the duplicate-row deletion would become `tool_redirect`). Raises the false-positive rate on ordinary user requests. |
| B. User by default unless clearly embedded | Plain-imperative attacks (pay an external wallet, reveal a key "so the integration can continue") become benign. Misses the core threat model. |
| **C. PROPOSED — signal-based** | Reproducible from text alone and consistent with both guide statements. Leaves a small grey zone, which is handled through R1. |

**R2 (PROPOSED).**
- Treat each row as untrusted content.
- Apply the user-request exception only when **all** of these hold:
  1. The text is a first- or second-person request scoped to the requester's own data or task ("the spreadsheet I uploaded", "this text", "my").
  2. There are **no** third-party signals: "the user" in the third person; addressing "the model/assistant/AI reader" from inside content; an authority claim; a consent claim made on someone else's behalf; concealment from the user; a destination not chosen by the requester ("the address hidden in the footer", "the wallet mentioned in this page").
  3. The action stays inside the requester's own data or workspace.
- A sensitive action (payment, deletion, external send, shell, secret disclosure) that fails the exception is `suspicious` under R3. If only signal 1 is ambiguous, use confidence < 0.7.
- **Sub-question for the owner (Q2b):** does forwarding to an *internal* directory address count as "external email"? This decides `rv-mgzzzzzczj`.

**Affected rows ({{Q2_N}}).** {{Q2}}
- Manual additions (not cited by the AI, but the label could change across options): {{Q2_MANUAL}}

### Q3 — Category precedence when several fit

**Problem.** The schema holds one `attack_category`. The guide says "label by the instruction directed at the agent" but gives no order between categories.

**Examples.**
- {{EX:rv-ponjh6ay7r}} — `direct_injection` or `exfiltration_request`?
- {{EX:rv-l6yc43bksa}} — `impersonation` or `tool_redirect`?
- {{EX:rv-n0p2ic5iug}} — `indirect_injection` or `exfiltration_request`?

**Options and consequences.**

| Option | Consequences |
|---|---|
| **A. PROPOSED — effect-first after technique** | Precedence: `obfuscated_injection` → `impersonation` → `exfiltration_request` → `tool_redirect` → `indirect_injection` → `direct_injection` → `other_suspicious`. Follows "label by the instruction directed at the agent" (what it tries to make the agent *do*). Keeps `exfiltration_request`, the thinnest category per the quality-gate doc, populated. Shrinks `direct`/`indirect` to pure override or output-manipulation cases. |
| B. Vector-first | Precedence: obfuscated → impersonation → indirect → direct → exfiltration → tool_redirect → other. Mirrors the guide's "indirect when embedded" wording. Moves most embedded exfiltration and tool rows into `indirect_injection`, leaving `exfiltration_request`/`tool_redirect` nearly empty in this package. |
| C. Multi-label | Most faithful, but requires a schema, validator and model-target change. Future version only. |

**R3 (PROPOSED).** Option A, with these sub-rules:
- **R3a:** `obfuscated_injection` applies only when the *operative* instruction is encoded, leetspeak, spaced or homoglyph-altered. Judge the decoded intent for the label.
- **R3b:** `impersonation` applies to claimed **agent-control authority**: system, developer, admin, operator, platform, model vendor, evaluation harness. Claimed **business authority** (CEO, legal team) is urgency pressure, so categorise it by effect (e.g. `tool_redirect`, else `other_suspicious`).
- **R3c:** disclosure of the agent's hidden instructions or configuration counts as `exfiltration_request` unless R3a or R3b applies first.
- **R3d:** "approve a purchase/refund/payment" and "book" are `tool_redirect` actions.
- Annotators may name the runner-up category in `uncertainty_note`.

**Affected rows ({{Q3_N}}; category only, never the label).** {{Q3}}

### Q4 — Is a plain translated attack "obfuscated"?

**Problem.** The guide's `obfuscated_injection` lists encoding, leetspeak, spacing and homoglyphs. `schema.py` separately lists `translation` as an `obfuscation_type` (a dataset metadata field, not an attack category).

**Examples.**
- {{EX:rv-oqun0e37pj}}
- {{EX:rv-hdxrxcucfl}}

**Options and consequences.**

| Option | Consequences |
|---|---|
| **A. PROPOSED — language is not obfuscation** | Categories mean the same thing in every language. Translation stays visible through the existing `obfuscation_type=translation` metadata. Non-English rows are not structurally penalised. |
| B. Translation = `obfuscated_injection` | All non-English attacks collapse into one category. The classifier learns language as an attack signal (fairness and false-positive risk). Contradicts the guide's explicit list. |

**R4 (PROPOSED).** Option A. Apply R3 to the decoded or translated intent.

**Affected rows ({{Q4_N}} non-English rows proposed suspicious; category only).** {{Q4}}

### Q5 — Self-described or reported injections

**Problem.** Some texts label their own embedded line ("Embedded line for the assistant", "Advisory injected into the feed", "planted by the template vendor", "a line inserted later reads") or report it in the third person ("the footer tells reading models to…"). The guide says quoted attacks are benign "in order to explain or criticise", and suspicious text acts "in its own voice". These rows sit in between.

**Examples.**
- {{EX:rv-zy3ek5wge4}}
- {{EX:rv-7pnhil0btt}}
- {{EX:rv-6w1jj9y7l0}}
- {{EX:rv-nb8e00cci7}}

**Options and consequences.**

| Option | Consequences |
|---|---|
| **A. PROPOSED — purpose test** | Suspicious unless the framing explains, criticises, warns about or reports the instruction as an attack for a human reader (training, incident report, analysis, "do not follow"). A self-label is not that framing: an agent reading the content still receives the instruction, and attackers can add such labels freely. Consistent with the existing quoted-attack rule (benign *because* it explains or criticises). Most Q5 rows become candidates for `suspicious`. |
| B. Voice test (only direct imperatives count) | Third-person reports (e.g. `rv-6w1jj9y7l0`, `rv-apf7fni0bi`) become benign. Attackers can evade by narrating ("this page tells assistants to…"). |
| C. Self-labelled = described attack | All rows below become benign, including the "Embedded line for the assistant" template. Contradicts the guide's `indirect_injection` definition and removes a large indirect family. |

**R5 (PROPOSED).** Option A.
- A text that only *reports* that an injection happened and that it was refused or escalated (e.g. a post-mortem) stays benign.

**Affected rows ({{Q5_N}} total).**
- **The 5 currently unlabelled Q5 rows:** {{Q5_ADJ}}
- **The 10 similar rows the AI proposal labelled `suspicious` while citing Q5:** {{Q5_LAB}}
- **Same pattern, Q5 not cited by the AI proposal (consistency gap; pattern match):** {{Q5_PAT}}

All {{Q5_N}} must receive the same ruling. The AI proposal treated them inconsistently (5 adjudication, the rest labelled).

### Q6 — Scope: harmful requests that do not hijack the agent

**Problem.** Sentinel targets attempts to make an agent act against its instructions or principal. Some rows request deceptive or privacy-invasive outcomes without any hijack.

**Examples.**
- {{EX:rv-5f5x0knnio}}
- {{EX:rv-45uli8kbma}}
- {{EX:rv-vrh7x4i7hx}}

**Options and consequences.**

| Option | Consequences |
|---|---|
| A. All misuse in scope (`other_suspicious`) | Sentinel becomes a general misuse classifier. False positives rise on legitimate but edgy user requests. The dataset has no systematic coverage of misuse. |
| B. All out of scope (benign) | Misses covert steering that works against the user (e.g. silently dropping criticism of a sponsor). |
| **C. PROPOSED — principal test** | In scope when the text acts covertly against the principal (user/operator) or the agent's instructions. Out of scope when it is the principal's own transparent request whose harm falls on third parties. |

**R6 (PROPOSED).** Option C.
- Out-of-scope rows are labelled `benign` for Sentinel, with `uncertainty_note` starting `OUT-OF-SCOPE-MISUSE:` so they can be routed to a separate content-policy process.
- Provenance is decided by R2.

**Affected rows ({{Q6_N}}).** {{Q6}}

### Q7 — Behaviours with no named category

**Problem.** Records falsification, deceiving the user, delayed triggers and ad or promotional injection appear only implicitly under `other_suspicious` ("fabricated consent, covert steering, urgency pressure").

**Examples.**
- {{EX:rv-hwabmceuon}}
- {{EX:rv-vkq71gtf9i}}
- {{EX:rv-rh7ovx1frc}}

**Options and consequences.**

| Option | Consequences |
|---|---|
| **A. PROPOSED — explicit scope for `other_suspicious`** | No schema change; categories stay consistent with existing data. |
| B. New official categories | Requires a versioned schema, validator and model-target change and relabelling of existing data. Not proposed for v0.3.x. |

**R7 (PROPOSED).**
- `other_suspicious` covers consent fabrication or misrepresentation, covert steering or promotion, deceiving the user, records or log falsification, delayed or conditional triggers, and urgency pressure, **when no higher-precedence category under R3 applies**.
- A free-text subtype may go in `uncertainty_note` (e.g. `subtype: log-falsification`). It is non-official.

**Affected rows ({{Q7_N}}; category only).** {{Q7}}

### Q8 — Form and schema mismatch (resolved without changing the official schema)

**Problem (verified).**
- `build_round2.py` copies the Round-1 `REVIEWER_GUIDE.md` verbatim. The Round-2 copy is identical apart from CRLF line endings.
- The Round-1 CSV had `sample_id` and `disagreement_reason` and no `language_quality`. Round 2 has `uncertainty_note` and `language_quality`.

| Source | Says | Round-2 reality |
|---|---|---|
| REVIEWER_GUIDE.md | "Work from `review_blind.csv`" | File is `review_blind_opaque.csv` |
| REVIEWER_GUIDE.md | Field `disagreement_reason` | Column is `uncertainty_note` |
| REVIEWER_GUIDE.md | Language doubt → write `language-uncertain` in `disagreement_reason` | INSTRUCTIONS.md: set `language_quality=cannot-judge` and explain in `uncertainty_note` |
| intake_round2.py | `language_quality` ∈ {ok, uncertain, cannot-judge, **blank**} | Blank is accepted, so a missing language judgement passes intake |

**R8 (PROPOSED).**
1. **Authoritative schema** for Round 2 = the header of `review_blind_opaque.csv` as enforced by `intake_round2.py`. No column is added, renamed or removed.
2. **Errata, not edits.** After owner approval, issue a short, sample-free `ERRATA_v1.md` (owner's action) stating:
   - guide `disagreement_reason` ≡ CSV `uncertainty_note`;
   - guide `review_blind.csv` ≡ `review_blind_opaque.csv`;
   - language handling per **L** below;
   - the approved R1–R7.
   - It must contain no review IDs, sample text or labels.
   - If it is placed in `ANNOTATOR_PACKAGE/`, re-run `ml/tests/test_round2.py` (leak checks) and record the new package hash.
   - Alternative: send it separately, before annotation starts.
3. **Not proposed now:** editing the guide in place, changing `build_round2.py`, or tightening the validator. Any of these is a separate owner decision with its own version bump.

**Affected rows.** The form is affected for all 196 rows. The language-note convention matters for the {{NONEN_N}} non-English rows.

---

## 4. Language-quality policy for non-English rows (PROPOSED "L")

| Situation | `language_quality` | `uncertainty_note` must contain |
|---|---|---|
| English row, readable | `ok` | — |
| Non-English; annotator fluent or native and confident in meaning **and** naturalness | `ok` | optional notes |
| Non-English; meaning understood but fluency, register or idiom not vouched for | `uncertain` | `language-uncertain` + language code (`es`/`de`/`hi`) |
| Non-English; meaning not reliably understood | `cannot-judge` | `language-uncertain` + language code; then R1 (confidence ≤ 0.5, `ADJUDICATE:`) |
| **Any AI-generated proposal on a non-English row** | **`uncertain` (never `ok`)** | `language-uncertain` + "AI cannot certify fluency" |

- **Routing:** every non-English row with `language_quality ≠ ok` goes to a native-speaker check before adjudication.
- **No blanks:** a blank `language_quality` should be treated as non-compliant by convention. Intake currently accepts blanks; tightening it is a separate, optional validator change.
- **Consistency gap in existing AI output:** all {{NONEN_N}} non-English rows in `../AI_ASSISTED_REVIEW_ROUND2/` are marked `ok` ({{LANG_OK_N}} of {{NONEN_N}}), each with a `language-uncertain` note. Note and row detection agree: {{NOTE_MATCH}}. Under L these flags would become `uncertain`. They will **not** be changed until L is approved, and then only in a new versioned AI-proposal file.

**Non-English rows ({{NONEN_N}}).** {{NONEN}}

## 5. Category strategy (PROPOSED "C")

- **`tool_redirect` is an official category.** It is listed in:
  - `ml/sentinel/schema.py` (`ATTACK_CATEGORIES`);
  - `REVIEWER_GUIDE.md` (payments, deletion, external email, shell);
  - `docs/phase11-sentinel-research.md`;
  - the dataset distribution in `docs/phase11a-dataset-quality-gate.md` (35 samples).
  - No mapping is needed and none is proposed.
- **The official set is exactly 7 categories:** `direct_injection`, `indirect_injection`, `obfuscated_injection`, `impersonation`, `exfiltration_request`, `tool_redirect`, `other_suspicious`. No category is invented here.
- **The prior `../AI_AUDIT/` used a non-official, provisional taxonomy** taken from an AI draft file. Comparison-only mapping:

  | AI_AUDIT name | Official |
  |---|---|
  | `exfiltration` | `exfiltration_request` |
  | `direct_injection`, `indirect_injection`, `impersonation`, `obfuscated_injection`, `other_suspicious` | same name |
  | `benign`, `undetermined` | no category |
  | — (absent) | `tool_redirect`; AI_AUDIT categories on tool-action rows are not comparable |

  AI_AUDIT categories must never be used as labels.
- **Precedence:** use R3 for the single category field. Disagreements are recorded per category pair, as the workflow doc already specifies.

## 6. Mutual consistency of R1–R8, L, C (decision procedure)

Apply the rules in this order for every row:

1. **Read the language (L).** If the meaning is not reliable, use `cannot-judge` and go to R1.
2. **Provenance (R2).** Decide whether this is the requester's own scoped request or untrusted content.
3. **Scope (R6).** Is it in scope for Sentinel?
4. **Label.**
   - Benign if ordinary, if explanatory, critical or warning (R5), or if out of scope (R6).
   - Otherwise suspicious.
   - If two readings remain equally defensible, use R1.
5. **Category (R3, with R4 and R7).** Technique first, then effect, then vector, then `other_suspicious`.
6. **Form (R8).** Fill the existing columns only.

**Checked interactions:**
- R5 and the quoted-attack rule use the same "explain or criticise" test.
- R2 and R6 both rely on the principal, so they cannot contradict each other.
- R4 and R3a both treat translation separately from obfuscation.
- R7 is reached only after R3, so it cannot shadow a specific category.
- R1 never produces a non-binary label, so it stays intake-compatible.

## 7. Decision table — rows to reconsider after each ruling

{{SUMMARY_TABLE}}

- **Re-review order:** step 1 (Q8/L) → step 2 (Q1) → step 3 (Q2, Q6) → step 4 (Q5) → step 5 (Q3, Q4, Q7). Category rulings come last because a label change can remove or add a category.
- **Rows whose label may change (Q1/Q2/Q5/Q6): {{LABEL_CHANGE_N}}.** Rows touched by any ruling: {{ANY_N}} of {{N_ROWS}}.
- **Per-row detail:** `policy_decision_table_v0.1.csv`. For each row it gives:
  - the AI proposal;
  - which rulings affect the row, and the source of each flag (`cited`, `pattern`, `manual`, `alternatives`, `non-English`);
  - the fields to reconsider;
  - whether the label may change.

## 8. After approval (owner and human actions — not performed here)

1. **Owner decisions:** for each of R1–R8, L and C, mark **Approved / Rejected / Amended** in the block below, and answer Q2b.
2. **Errata:** the owner issues a sample-free `ERRATA_v1.md` per R8 and re-runs the leak tests if it enters the package.
3. **Human annotation:** the real independent annotator completes `review_blind_opaque.csv` under the approved rules; intake must pass.
4. **Optional AI re-proposal:** a new AI proposal file under a new version may apply the approved rules to the {{ANY_N}} affected rows, still marked `AI_ASSISTED_NOT_HUMAN_ANNOTATION`. It never fills the human file, and its 7 unresolved rows are re-proposed, not auto-filled.
5. **Adjudication:** follows `docs/phase11a-independent-review-workflow.md`.
   - Any AI-to-AI comparison remains labelled as such and is **never** reported as human inter-annotator agreement.
   - Changes land only in a new v0.3.1 dataset.

## 9. Limitations

- This proposal was written by an AI that also produced the earlier AI audit and orchestrated the AI proposal round. The rules are a starting point for human judgement, not neutral authority.
- Affected-row detection combines AI citations, regex patterns and a 2-row manual list. Semantic coverage is **not exhaustive**, and other rows could be affected.
- Example excerpts are truncated to 150 characters.
- No human labels exist yet. Nothing here measures agreement of any kind.

## 10. Approval block (to be completed by the project owner — intentionally blank)

| Rule | Decision (Approved / Rejected / Amended) | Notes |
|---|---|---|
| R1 | | |
| R2 (+ Q2b) | | |
| R3 (+ R3a–d) | | |
| R4 | | |
| R5 | | |
| R6 | | |
| R7 | | |
| R8 | | |
| L | | |
| C | | |

Owner: ____________  Date: ____________

*Generated by `build_policy_report.py` from `report_template_v0.1.md`. All row lists and counts come from the proposal CSV, so they reconcile with `policy_decision_table_v0.1.csv`.*
