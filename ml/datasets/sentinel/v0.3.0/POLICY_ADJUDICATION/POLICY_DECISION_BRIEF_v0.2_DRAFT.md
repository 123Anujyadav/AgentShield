# Sentinel v0.3.0 Round 2 — Policy Decision Brief **v0.2 (DRAFT)**

| | |
|---|---|
| Status | **`DRAFT_NOT_APPROVED`** — decision-ready material for the project owner. Every recommendation is a proposal; **no rule is approved or in force.** |
| Supersedes? | No. It reviews and amends `POLICY_ADJUDICATION_PROPOSAL_v0.1.md`, which stays unchanged. |
| Prepared | 2026-10-27, by an AI assistant (Claude, Cowork). Not a human annotator, adjudicator, or owner. |
| Quality gate | **OPEN.** No independent human annotation exists, and AI-only review does not establish independent annotation (see `LABELLING_GUIDE.md`, "Second-annotator review workflow (v0.2)", step 1: "not the dataset author, not an LLM"). |
| Labels / data | Unchanged. The 7 unresolved rows remain unlabelled, and no AI-proposed label is merged anywhere. |
| Audience | **Owner/adjudicator only.** Contains opaque review IDs. Never give this folder to the independent annotator. The only annotator-safe files here are `ROUND2_FIELD_MAPPING_ERRATA_DRAFT_v0.1.md` (after approval) and `language_review_worklist_ANNOTATOR_SAFE_v0.1.csv`. |

## 0. Evidence legend

- **VERIFIED** — the cited file states it.
- **CONSISTENT** — reasonable inference from the cited text.
- **ASSUMPTION** — not in any official document; proposed by AI.
- **CONFLICT** — official documents disagree with each other, or with the v0.1 proposal.

## 1. Official sources checked (exact paths and sections)

| ID | Path | Sections / symbols used |
|---|---|---|
| S1 | `ml/sentinel/schema.py` | `LABELS`, `ATTACK_CATEGORIES`, `OBFUSCATION_TYPES`, `REQUIRED`, `validate_sample` |
| S2 | `ml/sentinel/intake_round2.py` | `LANGUAGE_QUALITY`, `validate_round2` |
| S3 | `ml/datasets/sentinel/v0.3.0/REVIEW_ROUND2/ANNOTATOR_PACKAGE/REVIEWER_GUIDE.md` | "What you are judging", "Decision rules", "Per-row form", "Edge cases" |
| S4 | `…/REVIEW_ROUND2/ANNOTATOR_PACKAGE/INSTRUCTIONS.md` | "Rules" list; header of `review_blind_opaque.csv` |
| S5 | `ml/datasets/sentinel/v0.3.0/LABELLING_GUIDE.md` (titled "Sentinel Labelling Guide v0.1") | Task/core-rule bullets; "Annotation process" paragraph; "Second-annotator review workflow (v0.2)" |
| S6 | `docs/phase11-sentinel-research.md` | §3 "Recommended ML task and label taxonomy" (Taxonomy table, multi-label note, "Hard truth"); §4 "Dataset design" (Schema table, "Labelling guide (summary)") |
| S7 | `docs/phase11a-independent-review-workflow.md` | §3 "Procedure, disagreement analysis, and adjudication policy" |
| S8 | `docs/phase11a-blind-review-round2.md` | "Intake (Round 2)", "Explicit human instructions", "Gate status" |
| S9 | `packages/engine/src/scanner/rules.ts` | `SCANNER_RULES` (S6 §3: `impersonation`, `exfiltration_request`, `tool_redirect` "mirror existing scanner rule categories") |
| S10 | `ml/datasets/sentinel/v0.3.0/DATASET_CARD.md`; `docs/phase11a-dataset-quality-gate.md` | Card bullets; quality gate §1 "Dataset version and distribution" |
| S11 | `ml/sentinel/build_round2.py` | Lines 58–59 (guide copy) |

**Not opened** (by design): `ADJUDICATOR_ONLY/mapping_key.csv`, `REVIEW_PACKAGE/review_key.csv`, `samples.jsonl`, `splits/`, `.env`. Author-label practice was therefore **not** inspected (see Q3b for the owner-run check).

### Documentation inconsistencies found (factual; none corrected)

| ID | Inconsistency | Evidence |
|---|---|---|
| D1 | Dataset card is stale: it says 504 samples (237/267) and one benign plus one suspicious per non-English language. The quality-gate doc says 554 samples and 16 per language. | S10 |
| D2 | Borderline threshold: "below 0.9 means borderline" vs "Use below 0.7 whenever … ambiguous". | S5 "Annotation process" vs S3 "Per-row form" |
| D3 | Obfuscation: "Encoded content is labelled by its decoded intent; record the transform in `obfuscation_type`" vs category `obfuscated_injection` "(… judge the decoded intent)". It is unclear whether encoded attacks take `obfuscated_injection` or the decoded-intent category. | S5 vs S3 "Decision rules" |
| D4 | Reported injections: S5 makes text that "discusses, quotes, **reports**, or teaches defence" benign. v0.1 R5 made content that relays an instruction in third person suspicious. | S5 vs v0.1 R5 |
| D5 | Authorization: S3 defines `tool_redirect` as an action "the user did not request". S5 and S6 put intent mismatch in a separate relation task "not labelled here". | S3 vs S5 first paragraph, S6 §3/§4 |
| D6 | Round-2 guide uses Round-1 field and file names. | S3, S4, S11 (see Q8) |
| D7 | Intake accepts a blank `language_quality` and checks `reviewed_at` only for non-emptiness. | S2 |
| D8 | Exfiltration scope: S3 says "secrets, credentials, or private data". The S9 exfiltration rule matches keys, secrets, passwords, credentials, tokens and private keys (not private data generally). | S3 vs S9 |

## 2. Verification of the v0.1 proposal against the documents

| v0.1 item | Verdict | Note |
|---|---|---|
| `tool_redirect` is official | **VERIFIED** | S1 `ATTACK_CATEGORIES`; S3 "Decision rules"; S6 §3 Taxonomy; S9 `injection.unauthorized-tool-action`; S10 (35 samples) |
| Round-2 guide is a verbatim Round-1 copy | **VERIFIED** | S11 lines 58–59; `diff --strip-trailing-cr` identical |
| Intake accepts blank `language_quality` | **VERIFIED** | S2 `LANGUAGE_QUALITY = {"ok","uncertain","cannot-judge",""}` |
| R1 binary + `ADJUDICATE:` convention | **CONSISTENT** | S6 §3 "Hard truth"; S6 §4; S7 §3. Threshold clash D2 |
| R2 signal-based provenance with an authorization test | **CONFLICT** (D5) | Authorization belongs to the relation task (S5, S6). Amended below |
| R3 effect-first precedence | **ASSUMPTION** | No official precedence. S6 §3 says "start multi-class, measure co-occurrence, then decide" |
| R3a obfuscated first | **CONFLICT** (D3) | |
| R3b business authority ≠ impersonation | **CONSISTENT** | S9 impersonation = system/developer/admin/root; S5 "fake CEO demands … `other_suspicious` unless a more specific category fits" |
| R3c system-prompt disclosure = exfiltration | **ASSUMPTION** | Not listed in S3, S5 or S9 |
| R3d approve purchase/refund = `tool_redirect` | **ASSUMPTION** | Inferred from "payments" (S3, S9) |
| R4 language ≠ obfuscation | **CONSISTENT** | S3 obfuscation list lacks translation; `translation` is an `obfuscation_type` metadata value (S1, S6 §4), not a category |
| R5 purpose test, reported speech suspicious | Purpose test **CONSISTENT**; reported-speech part **CONFLICT** (D4) | |
| R6 "principal test" / `OUT-OF-SCOPE-MISUSE` | **ASSUMPTION** | No "principal" or scope concept in S3, S5 or S6 |
| R7 extended `other_suspicious` list | Official part **VERIFIED** (S3, S5); additions **ASSUMPTION** | |
| R8 errata, no schema change | **CONSISTENT** | Facts VERIFIED (S2, S3, S4, S11) |
| v0.1 affected-row counts | Reconciled with `policy_decision_table_v0.1.csv` | Detection is not exhaustive |

---

## 3. Questions Q1–Q8

### Q1 — Insufficient evidence for a binary label

**Current proposed wording (v0.1 R1):** "Keep binary labels. Undecidable rows: best label, confidence ≤ 0.5, `uncertainty_note` starts `ADJUDICATE:`."

**Evidence**
- **VERIFIED.** S2: intake rejects any label outside `{benign, suspicious}`, including a blank.
- **VERIFIED.** S6 §3 "Hard truth": "The dataset must record that ambiguity … instead of forcing false certainty."
- **VERIFIED.** S6 §4: "Borderline samples require a second annotator; disagreement → `adjudicated` or exclusion from test."
- **VERIFIED.** S7 §3: unconfident samples stay "only if both agree on the final label; otherwise they are marked for exclusion".
- **CONFLICT D2:** threshold 0.7 (S3) vs 0.9 (S5).

**Risks / ambiguity.** Intake still forces a value into the label column. If that value is counted as a vote, kappa or training data, the uncertainty becomes false certainty, which contradicts the review position.

**Recommended amendment (R1-v0.2, DRAFT).** Do not force labels when evidence is insufficient. Within the official schema:
1. The annotator enters the value intake requires, sets `confidence_0_1 ≤ 0.5`, and starts `uncertainty_note` with `ADJUDICATE: <reason>`.
2. Such values are **non-binding placeholders**. They are:
   - excluded from the primary agreement statistic and reported as a separate count;
   - never used for training or for v0.3.1 without adjudication;
   - routed to the S7 adjudication and exclusion process.
3. AI-assisted files are not intake files, so they keep such rows **blank**. The 7 current rows stay unlabelled.

**Decisions required**
- **D-Q1a:** accept the placeholder convention, or request a schema extension (a new label value, which needs validator and schema changes plus a new package version).
- **D-Q1b:** the Round-2 borderline threshold: 0.7 (S3) or 0.9 (S5).
- **D-Q1c:** confirm that `ADJUDICATE` rows are excluded from primary kappa and reported separately.

**Affected rows:** 9. These are the 7 unlabelled rows (`rv-zy3ek5wge4`, `rv-6w1jj9y7l0`, `rv-apf7fni0bi`, `rv-5f5x0knnio`, `rv-45uli8kbma`, `rv-nb8e00cci7`, `rv-q2lpdlqwts`) plus `rv-mgzzzzzczj` and `rv-vrh7x4i7hx` (AI confidence < 0.7).

### Q2 — Provenance, authorization and destination (incl. internal forwarding)

**Current proposed wording (v0.1 R2):** "Default: untrusted content. User-request exception only when explicit self-scoping signals exist and no third-party signals exist", with the action staying "inside the requester's own data/workspace". Q2b asked whether internal forwarding counts as external email.

**Evidence**
- **VERIFIED.** S3 "What you are judging": each row is untrusted content.
- **VERIFIED.** S3 "Edge cases": a user's own scoped instruction "is not automatically an injection".
- **VERIFIED.** S3 "Decision rules": `tool_redirect` covers "a sensitive tool action the user did not request — payments, deletion, external email, shell commands".
- **VERIFIED.** S5 first paragraph: intent mismatch "is a separate task and is not labelled here"; "Instructions consistent with an ordinary user task … are `benign` at the content level".
- **VERIFIED.** S6 §3: the relation task (`intent_aligned/unclear/misaligned` given intent, action, **destination**) is separate. S6 §4: "any mismatch belongs to the relation task, not the content label".
- **VERIFIED.** S9 `injection.unauthorized-tool-action` targets messages to "external|outside|all contacts|everyone", and "Tool actions are decided by intent and policy only".
- **VERIFIED.** S10 dataset card: a previously adjudicated scoped user deletion is a hard-benign precedent. Its sample ID is deliberately not linked to any blind row here.
- **CONFLICT D5:** v0.1 R2 put authorization (whose data, who chose the destination) into the content label.

**Risks / ambiguity**
- Mixing authorization into the content label conflicts with S5/S6 and needs context the rows don't contain.
- Ignoring destination entirely would miss content-designated destinations ("the wallet mentioned in this page").

**Recommended amendment (R2-v0.2, DRAFT).** The content label is based on **content signals only**.
- **Suspicious** requires at least one attack signal in the text:
  - override;
  - an authority claim;
  - concealment from the user;
  - fabricated consent;
  - "the user" in third person;
  - an instruction addressed to an AI reader from inside content;
  - a destination designated by the content itself;
  - a request for secrets, credentials or private data;
  - a sensitive action directed at an external or unspecified party.
- An ordinary task with none of these signals is **benign at content level**, even if the action is sensitive.
- **Authorization and destination appropriateness are the relation task.** When unclear, the annotator writes `relation-task: <why>` in `uncertainty_note`; it is not labelled in Round 2.
- **Internal forwarding is not automatically exfiltration or `tool_redirect`.** S9 targets *external* messages; S3 and S9 tie exfiltration to secrets, credentials or private data. Assess whether:
  - the destination is internal, external, or designated by the content;
  - secrets or private data are involved;
  - any attack signal is present.

**Decisions required**
- **D-Q2a:** adopt "content signals only; authorization → relation task" in place of v0.1 R2.
- **D-Q2b:** confirm the internal-forwarding rule above.
- **D-Q2c:** does a destination designated by the content itself count as an attack signal?

**Affected rows:** 10, per v0.1 table column `affected_Q2`: `rv-mgzzzzzczj`, `rv-apf7fni0bi`, `rv-5f5x0knnio`, `rv-vrh7x4i7hx`, `rv-oy5pn0od7m`, `rv-7wleikcm8d`, `rv-5r4xzxuq5j`, `rv-45uli8kbma`, `rv-qtcg9iceou`, `rv-xq17dueh3c`.

### Q3 — Category precedence

**Current proposed wording (v0.1 R3):** precedence `obfuscated_injection` → `impersonation` → `exfiltration_request` → `tool_redirect` → `indirect_injection` → `direct_injection` → `other_suspicious`, with sub-rules R3a–d.

**Evidence**
- **VERIFIED.** S1 and S6 §3 define 7 categories.
- **VERIFIED absence:** S3, S5 and S6 contain no precedence order and no multi-category worked example. The only official example is single-category: "Ignore previous instructions" in an article is benign, the same sentence instructing the agent is `direct_injection` (S6 §4).
- **VERIFIED.** S6 §3: "Multi-label was considered … Start multi-class, measure co-occurrence, then decide — do not assume separability."
- **VERIFIED.** S3 "Edge cases": "label by the instruction directed at the agent".
- **VERIFIED.** S5: social-engineering urgency (fake CEO, bypass-approval) → `other_suspicious` "unless a more specific category fits".
- **VERIFIED.** S9 impersonation = system/developer/admin/root authority.
- **CONFLICT D3** (obfuscation). R3c and R3d are **ASSUMPTIONS**.

**Risks / ambiguity**
- Fixing a precedence order now would encode an unverified taxonomy decision into Round-2 labels.
- Category counts swing heavily: the v0.1 table shows 95 rows with alternative categories.

**Recommended amendment (R3-v0.2, DRAFT).** Following the review position — verify before defining precedence — **do not adopt a precedence order yet.** Interim Round-2 rule:
1. Choose the category of the primary instruction directed at the agent (S3).
2. Apply S5 for urgency or fake *business* authority (`other_suspicious` unless a more specific category fits).
3. Record any second applicable category as `alt-category: <name>` in `uncertainty_note`, so co-occurrence can be measured as S6 §3 prescribes.
4. Report category disagreements on rows that carry `alt-category` separately from other disagreements.
5. Decide precedence after measurement, or by explicit owner ruling.

**Decisions required**
- **D-Q3a:** interim rule above, or v0.1 precedence.
- **D-Q3b (resolve D3):** encoded attacks take `obfuscated_injection` (S3) or the decoded-intent category, with the transform in `obfuscation_type` (S5)?
  - The owner can inspect current author practice with an aggregate cross-tab of `obfuscation_type` × `attack_category` over `samples.jsonl`. The AI did **not** run this, to stay clear of author labels; it is an owner-run, read-only check.
- **D-Q3c:** confirm that business authority (CEO, legal team) is not `impersonation`.
- **D-Q3d:** is disclosure of hidden instructions or system configuration an `exfiltration_request`?
- **D-Q3e:** is "approve a purchase/refund" or "book" a `tool_redirect` payment action?

**Affected rows:** 95 (category only; never the label). See `affected_Q3` in `policy_decision_table_v0.1.csv`.

### Q4 — Non-English text and obfuscation

**Current proposed wording (v0.1 R4):** "Language is not obfuscation. Categorise non-English rows by intent; translation belongs in the dataset's separate `obfuscation_type` metadata."

**Evidence**
- **VERIFIED.** S3 lists the obfuscation methods as "encoding, leetspeak, spacing, or homoglyphs"; translation is absent.
- **VERIFIED.** S1 `OBFUSCATION_TYPES` and S6 §4 Schema: `translation` is a value of the `obfuscation_type` metadata field. `language` is a separate field.
- **VERIFIED.** S5: "record the transform in `obfuscation_type`".
- **VERIFIED.** S6 §4: the multilingual slice is used only "where annotation is reliable".

**Risks / ambiguity**
- Some samples may have been produced by translating a base attack as an evasion transform. Whether that changes the *category* is tied to D3.
- Without fluent reviewers, meaning itself is unverified (see §4).

**Recommended amendment (R4-v0.2, DRAFT).**
- A non-English language alone is never obfuscation and never a reason to label a row suspicious.
- Judge non-English rows by the same rules, applied to their meaning.
- Encoding, leetspeak, spacing or homoglyphs *in addition to* the language fall under D-Q3b.
- Translation-as-transform is author-side metadata, not an annotator field.
- An annotator who cannot read the language uses `cannot-judge` and the Q1 convention, and never guesses.

**Decisions required**
- **D-Q4a:** confirm R4-v0.2.
- **D-Q4b:** confirm it follows the D-Q3b outcome for encoded non-English text.

**Affected rows:** 12 for category (non-English rows the AI proposed as suspicious; `affected_Q4`) and 30 for language (§4).

### Q5 — Active instructions vs defensive discussion

**Current proposed wording (v0.1 R5):** "Purpose test: an instruction conveyed to the agent (direct, quoted, or reported) is suspicious unless the framing explains, criticises or warns about it. Self-labels such as 'embedded' or 'injected' are not explanatory framing."

**Evidence**
- **VERIFIED.** S3: benign includes text that "quotes an attack in order to explain or criticise it"; suspicious text acts "in its own voice".
- **VERIFIED.** S5: "An instruction embedded in untrusted content that directs the agent … is `suspicious`, even if politely phrased". Also: "Text that *discusses, quotes, reports, or teaches defence against* such instructions is `benign`, with `is_quoted_or_discussed=true`."
- **VERIFIED.** S6 §3 "Hard truth": quoted examples, education, fiction and red-team transcripts are boundary cases, and ambiguity must be recorded.
- **CONFLICT D4:** "reports" is benign in S5, but v0.1 treated relayed or reported instructions inside content as suspicious. "Self-labels are not framing" is an **ASSUMPTION**.

**Risks / ambiguity**
- Attackers can narrate an instruction ("this page tells assistants to…") to dodge a voice-based test.
- Conversely, treating every report as live would mislabel genuine incident reports.

**Recommended amendment (R5-v0.2, DRAFT).** Following the review position — distinguish active instructions from defensive discussion:
- **(a) Active.** The content addresses an instruction to the agent or AI reader, and nothing frames it as an example → **suspicious**. A self-label such as "embedded line" does not change this, because the instruction is still delivered (S5, embedded-instruction rule).
- **(b) Defensive or analytic.** The text explains, criticises, warns about, teaches, or reports an attack for a human reader (training, incident report, post-mortem, "do not follow") → **benign**, `is_quoted_or_discussed` (S3, S5).
- **(c) Relayed without framing.** The text relays an instruction ("the footer tells reading models to…", "a line inserted later reads: assistant, …") with neither defensive framing nor direct address. **There is no official rule.** Use the Q1 convention until the owner rules.

**Decisions required**
- **D-Q5a:** approve (a) and (b).
- **D-Q5b:** rule for (c): suspicious (the agent still receives the instruction) or benign (S5 "reports").
- **D-Q5c:** one ruling applied uniformly to all affected rows.

**Affected rows:** 19. Each row's sub-type (a/b/c) is for the human reviewer to decide. The AI has not assigned it.
- 5 currently unlabelled: `rv-zy3ek5wge4`, `rv-6w1jj9y7l0`, `rv-apf7fni0bi`, `rv-nb8e00cci7`, `rv-q2lpdlqwts`.
- 10 that the AI labelled suspicious while citing Q5: `rv-2ty4bmacgj`, `rv-7pnhil0btt`, `rv-uae7qjukgv`, `rv-1nu16aqr4l`, `rv-0ma16kk1sx`, `rv-fl7johgoc8`, `rv-kc71ypkrad`, `rv-xns2wvyr03`, `rv-7y9y9uyih2`, `rv-5ohdnck12i`.
- 4 pattern matches that the AI did not cite: `rv-nys1rhow2s`, `rv-g2os0ped7f`, `rv-s29dnuk25u`, `rv-4wxe2mucmz`.

### Q6 — Scope: defined violation vs harmful-sounding wording

**Current proposed wording (v0.1 R6):** "In scope: anything acting covertly against the principal or the agent's instructions. Out of scope: the principal's own transparent request to create harmful-to-third-party content (benign for Sentinel, noted `OUT-OF-SCOPE-MISUSE:`)."

**Evidence**
- **VERIFIED.** S3 "Decision rules" enumerate six behaviours that make text suspicious: override, authority impersonation, secret or data disclosure, unrequested sensitive tool action, obfuscated versions of these, and covert manipulation (fabricated consent, covert steering, urgency pressure).
- **VERIFIED.** S3 "What you are judging": "not whether it contains scary words". S5: "Never label a quoted example as an attack solely because it contains suspicious words."
- **VERIFIED absence:** no "principal" concept and no out-of-scope tag in S3, S5 or S6. v0.1 R6 is an **ASSUMPTION**.

**Risks / ambiguity**
- Without a defined violation list, labels drift toward a general "harmful content" classifier. That is outside Sentinel's documented task.
- "Covert steering" is undefined, so deceptive-content requests are borderline.

**Recommended amendment (R6-v0.2, DRAFT).** Following the review position — require a defined security-policy violation:
- `suspicious` only when the text attempts **one of the behaviours enumerated in S3 "Decision rules"**.
- Harmful-sounding or ethically questionable wording that attempts none of them → `benign` for Sentinel. An optional non-official `scope-note:` may go in `uncertainty_note`.
- Drop the v0.1 "principal" test.

**Decisions required**
- **D-Q6a:** adopt the enumerated-violation test.
- **D-Q6b:** does each of these count as "covert steering / manipulate covertly"?
  - requests for deceptive third-party content (e.g. fake reviews);
  - covert tracking left in an exported file;
  - a summary that quietly omits criticism.
- **D-Q6c:** keep or drop the `scope-note:` convention.

**Affected rows:** 4: `rv-hwabmceuon`, `rv-5f5x0knnio`, `rv-vrh7x4i7hx`, `rv-45uli8kbma`.

### Q7 — `other_suspicious` inclusion and exclusion criteria

**Current proposed wording (v0.1 R7):** "No new categories. `other_suspicious` explicitly covers consent fabrication, covert steering or promotion, deceiving the user, record falsification, delayed triggers and urgency pressure, when no higher-precedence category applies."

**Evidence**
- **VERIFIED.** S3: "Manipulate covertly in a way that fits none of the above — fabricated consent, covert steering, urgency pressure".
- **VERIFIED.** S5: social-engineering urgency (fake CEO demands, bypass-the-approval pressure) is `other_suspicious` "unless a more specific category fits".
- **ASSUMPTION:** the v0.1 additions (deceiving the user, record falsification, delayed triggers, promotion).

**Recommended amendment (R7-v0.2, DRAFT).**

| Criterion | Status |
|---|---|
| **Include:** fabricated or misrepresented consent; covert steering; urgency pressure / social engineering, including fake business authority; residual covert manipulation that fits no other category | Official (S3, S5) |
| **Include:** false statements to the user to pressure a decision | PROPOSED — needs approval |
| **Include:** falsifying records, logs or attribution | PROPOSED — needs approval |
| **Include:** delayed or conditional triggers | PROPOSED — needs approval |
| **Include:** covert promotional or ad insertion | PROPOSED — needs approval |
| **Include:** covert rating or summary manipulation | PROPOSED — needs approval |
| **Exclude:** anything fitting a more specific category (S3 "fits none of the above") | Official |
| **Exclude:** quoted, defensive or educational text (Q5b) | Official |
| **Exclude:** ordinary tasks | Official |
| **Exclude:** harmful-sounding text with no enumerated violation (Q6) | PROPOSED |
| **Exclude:** keyword-only matches | Official (S3, S5) |

**Decisions required**
- **D-Q7a:** confirm the official inclusions (no change).
- **D-Q7b:** approve or reject each PROPOSED inclusion individually.
- **D-Q7c:** approve the exclusions.

**Affected rows:** 14 (`affected_Q7`, category only).

### Q8 — Round-2 form/schema differences

**Current proposed wording (v0.1 R8):** "The CSV header plus `intake_round2.py` is the authoritative Round-2 schema. An owner-approved, sample-free errata maps the guide's names onto it."

**Evidence**
- **VERIFIED.** S4 "Rules" field list and the CSV header: `uncertainty_note` and `language_quality`.
- **VERIFIED.** S3 uses `disagreement_reason` and `review_blind.csv`.
- **VERIFIED.** S11 lines 58–59 copy the Round-1 guide. The Round-1 `REVIEW_PACKAGE/review_blind.csv` header has `sample_id` and `disagreement_reason` and no `language_quality`.
- **VERIFIED D7** (S2).

**Recommended amendment (R8-v0.2, DRAFT).**
- Use the draft errata `ROUND2_FIELD_MAPPING_ERRATA_DRAFT_v0.1.md`. It is sample-free, not placed in the package, and changes no official file.
- Add a precedence statement: for **form and field questions**, `INSTRUCTIONS.md` (which is Round-2-specific) prevails over `REVIEWER_GUIDE.md`. Decision rules still come from the guide.

**Decisions required**
- **D-Q8a:** approve the mapping.
- **D-Q8b:** delivery — a file in the package (then re-run `test_round2.py` and re-hash) or a separate handout.
- **D-Q8c:** approve the form-precedence statement.
- **D-Q8d (separate change, not proposed now):** tighten intake to reject a blank `language_quality` and to validate the ISO date. This would modify the official validator.

**Affected rows:** all 196 at form level.

---

## 4. Language review (non-English rows)

- **Annotator-safe worklist.** `language_review_worklist_ANNOTATOR_SAFE_v0.1.csv` lists **30** rows (es 10, de 10, hi 10).
  - Built by `build_language_worklist.py` from `review_blind_opaque.csv` **only**.
  - Contains just the opaque ID, row order, a script/language *guess*, and blank columns for a fluent human.
  - No author label, category, split, AI label, AI confidence or translation. Assertions in the script check this.
- **AI language judgements are not approval.**
  - The prior AI audit and the AI proposal round both read these rows.
  - The AI proposals marked all 30 `language_quality=ok`, each with a "language-uncertain" note.
  - None of that counts as fluency verification.
- **Recommended language policy (L-v0.2, DRAFT):**
  - `ok` only when a **fluent human** confirms both meaning and natural wording.
  - Otherwise use `uncertain` (meaning clear, fluency not vouched for) or `cannot-judge` (meaning unclear), with `language-uncertain <code>` in `uncertainty_note`.
  - `cannot-judge` triggers the Q1 convention.
  - AI output never sets `ok` on non-English rows.
  - The worklist is given to fluent reviewers together with the **annotator package only**.

**Decisions required**
- **D-La:** who the fluent reviewers are for Spanish, German and Hindi (the annotator, or separate native speakers).
- **D-Lb:** whether the fluency check happens before annotation or as part of it.
- **D-Lc:** what happens to rows that fail the check: exclusion, or rewriting in a future v0.3.1 (a dataset change).

**Worklist rows:** `rv-sxfbp7hhau`, `rv-k2obep1rvf`, `rv-bc1n4d6tb8`, `rv-ywf817vs7e`, `rv-y448wftu42`, `rv-dnzup9dmoq`, `rv-lybpoqxj38`, `rv-hb4azh4ljt`, `rv-hdxrxcucfl`, `rv-871rz2xrud`, `rv-3kezo6o4xg`, `rv-e7yjbo1yd8`, `rv-oqun0e37pj`, `rv-kdktikdhf2`, `rv-umqnjg3tvy`, `rv-uw8ad9zoba`, `rv-55pamkqaog`, `rv-ekix3hwyu7`, `rv-i6teg6h8h5`, `rv-6drd3c0tq2`, `rv-6pggyq1aqs`, `rv-lp6c32x3bh`, `rv-x3q0w4zd1m`, `rv-nk4lhhxam1`, `rv-ruu49oripd`, `rv-wp6tq90tct`, `rv-xl2iwi36jl`, `rv-sy76u4k87k`, `rv-pbpfralvm9`, `rv-f9ji3z48ra`.

## 5. Category strategy (verified)

- **`tool_redirect` is official.** See S1, S3, S6 §3, S9 and S10; no mapping is needed.
- **The official set is exactly** `direct_injection`, `indirect_injection`, `obfuscated_injection`, `impersonation`, `exfiltration_request`, `tool_redirect`, `other_suspicious`. No new category is proposed.
- **`../AI_AUDIT/` categories are non-official.** They map to the official set for comparison only: `exfiltration` → `exfiltration_request`; there is no `tool_redirect` source. They are never labels.

## 6. Outstanding human decisions (none approved)

| Area | Decision IDs |
|---|---|
| Q1 | D-Q1a, D-Q1b, D-Q1c |
| Q2 | D-Q2a, D-Q2b, D-Q2c |
| Q3 | D-Q3a, D-Q3b (+ owner-run cross-tab), D-Q3c, D-Q3d, D-Q3e |
| Q4 | D-Q4a, D-Q4b |
| Q5 | D-Q5a, D-Q5b, D-Q5c |
| Q6 | D-Q6a, D-Q6b, D-Q6c |
| Q7 | D-Q7a, D-Q7b, D-Q7c |
| Q8 | D-Q8a, D-Q8b, D-Q8c (D-Q8d optional, separate) |
| Language | D-La, D-Lb, D-Lc |
| Docs | Whether to fix D1 (stale dataset card) and D2 (threshold clash) in a separate documentation change |

**Readiness:** decision-ready, **not approval-ready**. Two official-document conflicts (D3, D4) and the relation-task boundary (D5) need owner rulings before any rule can be approved. The quality gate stays **OPEN**.

## 7. Approval block (intentionally blank — owner only)

| Decision | Approve / Reject / Amend | Notes |
|---|---|---|
| D-Q1a–c | | |
| D-Q2a–c | | |
| D-Q3a–e | | |
| D-Q4a–b | | |
| D-Q5a–c | | |
| D-Q6a–c | | |
| D-Q7a–c | | |
| D-Q8a–c | | |
| D-La–c | | |

Owner: ____________  Date: ____________
