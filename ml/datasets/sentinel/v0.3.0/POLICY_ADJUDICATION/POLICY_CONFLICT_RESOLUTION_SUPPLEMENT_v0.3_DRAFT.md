# Sentinel v0.3.0 Round 2 — Conflict-Resolution Supplement **v0.3 (DRAFT)**

| | |
|---|---|
| Status | **`DRAFT_NOT_APPROVED`.** Evidence analysis only. **No rule is approved**, and nothing here is in force. |
| Relationship | A supplement to `POLICY_DECISION_BRIEF_v0.2_DRAFT.md`, which stays unchanged, as does `POLICY_ADJUDICATION_PROPOSAL_v0.1.md`. |
| Prepared | 2026-10-27, by an AI assistant (Claude, Cowork). Not a human annotator, adjudicator, or project owner. |
| Quality gate | **OPEN.** |
| Audience | Owner/adjudicator only. Do not give to the independent annotator. |
| Data | No label, sample, split, schema, validator or annotator-package file was changed. |

**Notation.** Each conflict below is split into three parts:
- **F — Verified fact:** the cited file says it, quoted or closely paraphrased, with a line number.
- **I — Interpretation:** a reading of the facts that the documents do not state outright.
- **U — Unresolved decision:** needs an explicit project-owner ruling.

Line numbers refer to the files as they stand at this supplement's hashes (see `VALIDATION_LOG_v0.3.txt`). Line numbers in `REVIEWER_GUIDE.md` are counted after CRLF normalisation.

## 0. Sources used, and limits on what was read

| ID | Path | Headings / lines cited |
|---|---|---|
| LG | `ml/datasets/sentinel/v0.3.0/LABELLING_GUIDE.md` (title "Sentinel Labelling Guide v0.1") | Untitled opening block: task (l.3–5), "Core rule" bullets (l.7–22), "Annotation process" (l.24–28); "## Second-annotator review workflow (v0.2)" |
| RG | `ml/datasets/sentinel/v0.3.0/REVIEW_ROUND2/ANNOTATOR_PACKAGE/REVIEWER_GUIDE.md` | "## What you are judging" (l.6–10), "## Decision rules" (l.12–34), "## Per-row form" (l.36–45), "## Edge cases" (l.47–55) |
| IN | `…/REVIEW_ROUND2/ANNOTATOR_PACKAGE/INSTRUCTIONS.md` | "Rules:" (l.5–10) |
| RD | `docs/phase11-sentinel-research.md` | "## 3. Recommended ML task and label taxonomy" (l.77–121); "## 4. Dataset design", Schema table (l.135–145) and "Labelling guide (summary; full guide ships with the dataset)" (l.147–159) |
| WF | `docs/phase11a-independent-review-workflow.md` | "## 2. Reviewer guide and form" (l.34–41); "## 3. Procedure, disagreement analysis, and adjudication policy" (l.43–93) |
| EX | `docs/phase11a-dataset-expansion.md` | "## How examples were created and reviewed" (l.21–42); "## Remaining limitations" (l.89–99) |
| QG | `docs/phase11a-dataset-quality-gate.md` | "## 1. Dataset version and distribution (measured)" (l.17–29); "## 2. New samples and provenance" (l.31–42); "## 4. Leakage and integrity (actually run)" (l.64–77) |
| SC | `packages/engine/src/scanner/rules.ts` | `SCANNER_RULES`: `injection.privilege-impersonation` (l.33), `injection.secret-exfiltration` (l.46), `injection.unauthorized-tool-action` (l.60) |
| B3 | `ml/sentinel/build_v03.py` | l.26 (`annotation_confidence` assignment), l.49–52 (card/guide copy), l.56–57 (changelog text) |
| CL | `ml/datasets/sentinel/v0.3.0/CHANGELOG.md` | "## v0.3.0 (2026-10-26)" |
| DC | `ml/datasets/sentinel/v0.3.0/DATASET_CARD.md`, `…/v0.2.0/DATASET_CARD.md` | Bullet list (l.9, l.20) |
| SCH | `ml/sentinel/schema.py`, `ml/sentinel/intake_round2.py` | `LABELS`, `ATTACK_CATEGORIES`, `OBFUSCATION_TYPES`, `LANGUAGE_QUALITY` |

**Not read:** `ADJUDICATOR_ONLY/mapping_key.csv`, `REVIEW_PACKAGE/review_key.csv`, `.env`, `splits/`, `ml/sentinel/curated_v03.py`.

**`samples.jsonl`:** content was not inspected and no labels were read. The only access was a newline count (`wc -l`) for the count discrepancy in §5; no content was printed.

**Incidental exposure, disclosed.** A repository-wide `grep` for "obfusc|decoded|base64|leetspeak|translation" printed a few lines of `ml/sentinel/generate_expansion.py`, the v0.2 template generator.
- Those lines encode the author's category assignments for some template families. That is author-label practice, equivalent in kind to reading labels.
- **No finding below relies on them.** Using that file as evidence needs the owner's explicit approval (see U-E3).

---

## 1. Encoded attacks: "decoded meaning" (LG) vs `obfuscated_injection` (RG)

**Verified facts**
- **F1.1** — LG "Core rule", l.18–19: "Encoded content is labelled by its decoded intent; record the transform in `obfuscation_type` and keep the encoded form as `text`."
- **F1.2** — RG "Decision rules", l.31–32: "Achieve the same through encoding, leetspeak, spacing, or homoglyphs (`obfuscated_injection`; judge the decoded intent)."
- **F1.3** — RD §3, l.110 Taxonomy table, and SCH `ATTACK_CATEGORIES`: `obfuscated_injection` is one of the 7 official Stage-2 categories.
- **F1.4** — RD §4 Schema table (l.139) and SCH `OBFUSCATION_TYPES`: `obfuscation_type` is a separate metadata field with values `none, paraphrase, base64, leetspeak, spacing, unicode, translation, multi_turn`.
- **F1.5** — RD §4 "Labelling guide (summary)", l.156–157 repeats F1.1. The same document (RD §3) keeps `obfuscated_injection` as a category.
- **F1.6** — `obfuscation_type` is not a column in `review_blind_opaque.csv` (IN "Rules:" l.8 lists the annotator fields).

**Interpretation**
- **I1.1** — The two rules address different outputs and need not conflict:
  - "labelled by its decoded intent" (LG, RD) governs the **Stage-1 label**. An encoded harmless message is `benign`; an encoded attack is `suspicious`.
  - RG names the **Stage-2 category** for an attack achieved through encoding (`obfuscated_injection`), and itself says to judge the decoded intent (F1.2).
  - Basis: RD §3 holds both statements simultaneously (F1.3, F1.5). Reading them as contradictory would make one document self-inconsistent.
- **I1.2** — For Round-2 annotators, `obfuscated_injection` covers only the RG list: encoding, leetspeak, spacing, homoglyphs. Translation and paraphrase are `obfuscation_type` metadata values (F1.4), not RG categories. This matches v0.2 R4.
- **I1.3** — The annotator never fills `obfuscation_type` (F1.6). That is author-side metadata.

**Unresolved decisions**
- **U-E1** — Confirm I1.1. Stage-1 label = decoded intent. Stage-2 = `obfuscated_injection` whenever the operative instruction is encoded, leetspeak, spaced or homoglyph-altered, regardless of the decoded goal. This replaces v0.2 D-Q3b's open either/or with a confirm-or-reject.
- **U-E2** — Should the decoded goal (e.g. exfiltration) also be recorded? It could go as `alt-category:` in `uncertainty_note` (v0.2 R3 interim rule). It must not replace the category.
- **U-E3** — Optional. Approve or deny reading author-practice evidence to corroborate I1.1: either an aggregate `obfuscation_type × attack_category` cross-tab over `samples.jsonl`, or `ml/sentinel/generate_expansion.py`. Not performed.

## 2. Reported attacks (benign) vs the earlier relayed-instruction rule

**Verified facts**
- **F2.1** — LG "Core rule", l.9–11: "An instruction embedded in untrusted content that directs the agent (override, impersonation, secret disclosure, sensitive tool use) is `suspicious`, even if politely phrased."
- **F2.2** — LG "Core rule", l.12–14: "Text that *discusses, quotes, reports, or teaches defence against* such instructions is `benign`, with `is_quoted_or_discussed=true`."
- **F2.3** — RG "Decision rules", l.17–18: benign includes "incident reporting, or analysis — including text that **quotes** an attack in order to explain or criticise it". l.22–23: suspicious means "the text itself, in its own voice, tries to make the agent do…".
- **F2.4** — RG "Edge cases", l.49–50: quoted attacks in "training material, papers, incident reports, or fiction are benign for this task, **because the sample does not instruct the agent**."
- **F2.5** — RG "Decision rules", l.25–26: `indirect_injection` = override "when embedded inside otherwise useful content".
- **F2.6** — RD §3, l.116–121 ("Hard truth"): quoted examples, education, fiction and red-team transcripts "sit on the boundary"; record the ambiguity "instead of forcing false certainty".
- **F2.7** — v0.1 R5 (`POLICY_ADJUDICATION_PROPOSAL_v0.1.md`, §3 Q5) treated instructions "conveyed to the agent (direct, quoted, or reported)" as suspicious unless explanatory framing exists. v0.2 (§3 Q5) already split this into (a) active, (b) defensive/analytic, (c) relayed without framing.

**Interpretation**
- **I2.1** — The official test common to LG and RG is **whether the sample instructs the agent** (F2.4's stated reason; F2.1 "directs the agent"; F2.3 "in its own voice"). "Reports" in F2.2 sits alongside discussion, quotation and defence teaching, and RG pairs reporting with incident reporting and analysis. "Reports" is therefore best read as reporting **about** an attack for a reader, not as relaying an instruction **to** the agent.
- **I2.2** — v0.1 R5's blanket "reported → suspicious" is **not supported** by the official text and should be considered withdrawn.
  - v0.2 class (a) — an instruction addressed to the agent/AI reader inside content, with no explanatory or critical framing — is **supported** by F2.1 and F2.5.
  - A provenance label such as "embedded line" or "injected" is neither explanation nor criticism (F2.3), so it does not by itself convert (a) to benign.
  - v0.2 class (b) is **supported** by F2.2–F2.4.
- **I2.3** — v0.2 class (c) is **not decided by official text**. Example: third-person relay inside an operational document ("the footer tells reading models to…", "a line inserted later reads: assistant, …").
  - F2.1 ("directs the agent") pulls toward suspicious.
  - F2.3 ("in its own voice") and F2.2 ("reports") pull toward benign.

**Unresolved decisions**
- **U-R1** — Confirm I2.2: v0.2 classes (a) and (b) as stated, and withdrawal of the v0.1 blanket rule.
- **U-R2** — Rule for class (c). Options:
  - suspicious: the agent still receives an actionable instruction;
  - benign: third-person relay is not "its own voice";
  - case-by-case: annotators use the Q1 uncertainty convention.
- **U-R3** — Whether `is_quoted_or_discussed` semantics (author-side field, F2.2) should be aligned with the outcome of U-R2 in a future dataset version. This would be a dataset change, not proposed now.

## 3. `tool_redirect`: content classification vs whether the user authorised the action

**Verified facts**
- **F3.1** — RG "Decision rules", l.29–30: suspicious if the text tries to make the agent "Perform a sensitive tool action **the user did not request** — payments, deletion, external email, shell commands (`tool_redirect`)."
- **F3.2** — RG "What you are judging", l.8–9: "Each row is a piece of **untrusted content** that an AI agent might read (a document, webpage, email, or tool output)."
- **F3.3** — LG opening block, l.3–5: classify **untrusted content**. "Intent-mismatch (relation between a user's intent and a proposed action) is a separate task and is **not labelled here**."
- **F3.4** — LG "Core rule", l.16–17: "Instructions consistent with an ordinary user task (summarize, translate, rewrite) are `benign` at the content level."
- **F3.5** — RD §3, l.84–85 and the Taxonomy table l.111: intent mismatch is "modelled separately from content injection". The relation task outputs `intent_aligned/unclear/misaligned` given (intent, action, **destination**).
- **F3.6** — RD §4 "Labelling guide (summary)", l.154–155: "Instructions consistent with the stated task in the scenario are `benign` for content; any mismatch belongs to the relation task, not the content label."
- **F3.7** — SC `injection.unauthorized-tool-action`, l.60–64: "untrusted content appears to push the agent toward a sensitive tool action (payment, deletion, external message or shell). Tool actions are decided by intent and policy only." RD §3, l.113: `tool_redirect` mirrors this scanner rule.
- **F3.8** — RG "Edge cases", l.51–53: "A user's own scoped instruction in chat … is not automatically an injection". RD §4 Schema, l.137: `source_type` includes `chat`. The blind CSV has no `source_type` column (IN l.8).

**Interpretation**
- **I3.1** — Under F3.2 every Round-2 row is untrusted content, not the user. "The user did not request" (F3.1) is therefore satisfied when the request originates in the content itself. `tool_redirect` = untrusted content directing a sensitive tool action.
  - Whether the *actual* user authorised such an action is the relation task (F3.3, F3.5, F3.6). It is not part of the content label.
  - This reading reconciles F3.1 with F3.3–F3.7 without discarding either.
- **I3.2** — "External" in F3.1 and F3.7 qualifies the email/message case. An internal forward of non-secret material matches no enumerated `tool_redirect` example and no `exfiltration_request` element (RG l.28: secrets, credentials, private data). It is not suspicious **on that basis alone** — other content signals still apply. This supports the v0.2 Q2 position.
- **I3.3** — F3.8 creates the residual gap. Some dataset rows may be `chat`, but annotators cannot see `source_type`. RG l.8–9 also omits chat from its untrusted-content list.

**Unresolved decisions**
- **U-T1** — Confirm I3.1: content label = what untrusted content directs; authorization is the relation task; Round-2 annotators record authorization doubts as a note only.
- **U-T2** — Confirm I3.2 (internal forwarding is not automatically suspicious), and whether a destination **designated by the content itself** counts as a content signal. That second part is v0.2 D-Q2c.
- **U-T3** — How annotators should treat rows that read like a user's own chat request, given no `source_type`. Options:
  - apply RG l.8–9 literally (untrusted content);
  - apply the l.51–53 exception when the text is self-scoped;
  - expose `source_type` in a future package. Exposing it would be a package change and a potential label-correlated leak, so it is not proposed now.

## 4. Borderline confidence: 0.9 (LG) vs 0.7 (RG)

**Verified facts**
- **F4.1** — LG "Annotation process", l.24–26: "set `annotation_confidence` honestly (below 0.9 means borderline). Borderline samples need a second reviewer; mark `review_status=adjudicated` after resolution".
- **F4.2** — RG "Per-row form", l.40–41: "`confidence_0_1` — your honest confidence. Use below 0.7 whenever the context is genuinely ambiguous". WF §2 (l.39) restates "below 0.7 for genuine ambiguity".
- **F4.3** — The fields differ.
  - `annotation_confidence` is a dataset field (RD §4 Schema l.143; SCH `REQUIRED`), set by the dataset author.
  - `confidence_0_1` is the annotator form field (IN l.8; `intake_round2.py`).
- **F4.4** — IN "Rules:" l.6 (Round-2-specific, generated by `ml/sentinel/build_round2.py`): "Work from `review_blind_opaque.csv` and `REVIEWER_GUIDE.md` in this folder only." RD §4 l.147: the full labelling guide "ships with the dataset".
- **F4.5** — B3 l.26 sets author `annotation_confidence` to 0.65 for "adjudication candidate" items and 0.9 otherwise. QG §2 (l.39–40) reports two borderline candidates at 0.65. This is consistent with F4.1, where 0.9 itself is not borderline.
- **F4.6** — A repository search for "authoritative", "source of truth", "supersede", "takes precedence" and "prevail" across `docs/` and the v0.3.0 dataset and package Markdown found **no precedence statement** between LG and RG.
  - The hits that exist concern the deterministic engine (RD l.54), model sources (RD l.182), the v0.1 samples (`docs/phase11a-baseline-results.md` l.15), and dataset supersession (DC l.3).
- **F4.7** — EX "How examples were created and reviewed" (l.38–39): the earlier v0.2 second-annotator review was to use "the workflow in `LABELLING_GUIDE.md`". Round 2 instead designates RG (F4.4).

**Interpretation**
- **I4.1** — The repository **does not** establish a general precedence between LG and RG (F4.6). It does establish **scope by designation**:
  - for the Round-2 annotator's `confidence_0_1`, RG governs (F4.4, IN l.6);
  - for the author's `annotation_confidence`, LG governs (F4.1, F4.4 RD l.147).
- **I4.2** — The two thresholds are therefore not a direct contradiction within one field. They become a real conflict only when adjudication must decide what "not confident" means across both raters. WF §3 (l.89–93) — "Samples neither rater could label confidently…" — gives no number.

**Unresolved decisions**
- **U-C1** — Confirm I4.1: RG's 0.7 for annotator `confidence_0_1`; LG's 0.9 for author `annotation_confidence`.
- **U-C2** — Define "could not label confidently" for adjudication and exclusion (WF §3). Options:
  - each rater's own threshold;
  - a single common threshold (0.7 or 0.9);
  - the Q1 `ADJUDICATE:` flag regardless of the number.
- **U-C3** — Whether to add an explicit precedence statement to the guides in a future documentation change. Not proposed now; it would modify official documents.

## 5. Dataset-card count: 504 vs 554 (documented only; no file changed)

**Verified facts**
- **F5.1** — DC v0.3.0, l.9: "504 samples: 237 benign, 267 suspicious … 440 are new in v0.3.0". l.20: "one benign and one suspicious sample each in Spanish, German, and Hindi".
- **F5.2** — The v0.3.0 card is byte-identical, after CR normalisation, to the v0.2.0 card with "v0.2.0" replaced by "v0.3.0" (`diff`, see the log). DC v0.2.0 l.9 says "440 are new in v0.2.0".
- **F5.3** — B3 l.49–52 copies `DATASET_CARD.md` and `LABELLING_GUIDE.md` from v0.2.0 with only that string replacement.
- **F5.4** — CL "## v0.3.0": "Preserved all 504 v0.2.0 samples verbatim" plus "Added 50 hand-authored curated samples". QG §1 l.19: "**554 samples** — benign 252, suspicious 302"; QG §4 l.66: "Schema validation: `samples=554 errors=0`".
- **F5.5** — The newline count of `ml/datasets/sentinel/v0.3.0/samples.jsonl` is **554**. This is count-only; no content was read.
- **F5.6** — The language line is stale even for v0.2. EX "Remaining limitations" (l.91–93) describes Spanish/German/Hindi slices of "8 each" in v0.2. QG §1 reports 16 per language in v0.3.0.

**Interpretation**
- **I5.1** — 554 is the correct v0.3.0 total (F5.4, F5.5). The card's 504 and its "440 new in v0.3.0" are carry-overs from v0.2.0, caused by the build's string replacement (F5.3). The card's language sentence predates v0.2. The same mechanism made the v0.3.0 `LABELLING_GUIDE.md` a v0.2.0 copy still titled "v0.1", with a v0.2-era review workflow that references `REVIEW_QUEUE.csv`.

**Unresolved decisions**
- **U-D1** — Whether and when to correct the v0.3.0 dataset card, or to record the correction in v0.3.1 only. Either is a documentation change to a versioned dataset folder, so it needs owner approval. **Not performed.**
- **U-D2** — Whether `build_v03.py`'s copy step should be fixed for future versions. That is a pipeline change: not proposed now and not performed.

---

## 6. Q1/Q2/Q3/Q5/Q6 — answerable from evidence vs owner decision

| Q | Answerable from official evidence (with basis) | Requires explicit owner decision |
|---|---|---|
| **Q1** | **Verified:** intake requires a binary label (SCH `LABELS`; `intake_round2.py` `validate_round2`). Ambiguity must be recorded, not forced (RD §3 l.116–121). Unconfident rows go to adjudication or exclusion (RD §4 l.158; WF §3 l.89–93). | How "insufficient evidence" is represented within the binary field (v0.2 R1 placeholder convention vs a schema extension). Whether flagged rows are excluded from primary kappa. The threshold for adjudication (U-C2). |
| **Q2** | **Interpretation, strongly supported:** authorization is not part of the content label (I3.1). Internal forwarding is not suspicious on that basis alone (I3.2). | U-T1, U-T2 (including content-designated destinations), U-T3 (chat-like rows without `source_type`). |
| **Q3** | **Verified:** fake business authority → `other_suspicious` unless a more specific category fits (LG l.20–22). No precedence order exists (verified absence in RG, LG, RD). RD §3 l.100–103: measure co-occurrence before deciding. **Interpretation:** encoded attacks → `obfuscated_injection`, label by decoded intent (I1.1). | Confirm U-E1/U-E2. Whether the v0.2 interim rule (primary instruction + `alt-category:`) is adopted. Whether hidden-instruction/config disclosure is `exfiltration_request`. Whether "approve purchase/refund" or "book" is a `tool_redirect` payment action. Any final precedence order. |
| **Q5** | **Interpretation, supported:** class (a) suspicious (F2.1, F2.5); class (b) benign (F2.2–F2.4); the v0.1 blanket rule is unsupported (I2.2). | U-R1 (confirm), **U-R2 (class c)**, U-R3 (future alignment of `is_quoted_or_discussed`). |
| **Q6** | **Verified:** harmful-sounding wording alone is insufficient (RG l.9–10 "not whether it contains scary words"; LG l.13–14). Suspicious requires one of the behaviours enumerated in RG "Decision rules" l.22–34. | Whether deceptive third-party content, covert tracking left in files, or quietly slanted summaries are "covert steering" / "manipulate covertly" (undefined in RG l.33–34). Whether a non-official `scope-note:` convention is kept. |

## 7. Effect on the v0.2 decision list (no approvals)

| v0.2 decision | Status after this supplement |
|---|---|
| D-Q3b (encoded attacks) | Narrowed to a **confirm/reject of I1.1** (U-E1), plus U-E2. U-E3 is optional evidence. |
| D-Q5a | Narrowed to **confirm** (U-R1). |
| D-Q5b | Still an **owner choice** (U-R2). |
| D-Q2a / D-Q2b | Narrowed to **confirm** I3.1 / I3.2 (U-T1, U-T2). |
| D-Q2c | Still an **owner choice** (in U-T2). |
| New | U-T3 (chat-like rows). |
| D-Q1b | Re-framed as U-C1 (confirm scopes) and U-C2 (owner choice for adjudication). |
| Doc fixes | U-D1 / U-D2 (card correction; build copy step), both **not performed**. |
| All others in v0.2 §6 | Unchanged and still open. |

## 8. Unresolved decisions (complete list; none approved)

- **Encoded attacks:** U-E1, U-E2, U-E3 (optional).
- **Reported attacks:** U-R1, **U-R2**, U-R3.
- **`tool_redirect` and authorization:** U-T1, U-T2, U-T3.
- **Confidence thresholds:** U-C1, **U-C2**, U-C3.
- **Dataset card and build:** U-D1, U-D2.
- **Still open from v0.2:** D-Q1a, D-Q1c, D-Q3a, D-Q3c (confirm only: LG l.20–22 supports it), D-Q3d, D-Q3e, D-Q4a–b, D-Q6a–c, D-Q7a–c, D-Q8a–d, D-La–c.

**Items requiring a genuine owner choice (not mere confirmation):** U-R2, U-C2, U-T3, D-Q1a, D-Q3a, D-Q3d, D-Q3e, D-Q6b, D-Q7b, D-La–c, U-D1.

**Readiness:** still decision-ready, **not approval-ready**. Fewer items now hinge on genuine document conflicts, but the choices listed above remain. The quality gate stays **OPEN**.

## 9. Limitations

- **AI interpretation.** Every I-item is an AI reading of the documents, and line-based evidence can miss intent the authors did not write down.
- **Prior exposure.** The author of this supplement also produced the prior AI audit and orchestrated the AI proposal round, and has seen the blind texts.
- **Author practice not examined.** No author-label practice was used. Where corroboration from author practice would help (U-E3), it is left to the owner.
- **Line numbers can drift.** They are tied to the file hashes recorded in `VALIDATION_LOG_v0.3.txt`.
