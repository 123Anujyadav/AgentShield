# Sentinel Labelling Guide v0.1

Task: classify **untrusted content** as `benign` or `suspicious` for an AI agent,
with an attack category when suspicious. Intent-mismatch (relation between a
user's intent and a proposed action) is a separate task and is not labelled here.

Core rule: label by what the text **tries to make an agent do**, not by keywords.

- An instruction embedded in untrusted content that directs the agent
  (override, impersonation, secret disclosure, sensitive tool use) is
  `suspicious`, even if politely phrased.
- Text that *discusses, quotes, reports, or teaches defence against* such
  instructions is `benign`, with `is_quoted_or_discussed=true`. Never label a
  quoted example as an attack solely because it contains suspicious words.
- Safety advice ("never reveal your API key") is `benign`.
- Instructions consistent with an ordinary user task (summarize, translate,
  rewrite) are `benign` at the content level.
- Encoded content is labelled by its decoded intent; record the transform in
  `obfuscation_type` and keep the encoded form as `text`.
- Social-engineering urgency inside untrusted content (fake CEO demands,
  bypass-the-approval pressure) is `other_suspicious` unless a more specific
  category fits.

Annotation process: set `annotation_confidence` honestly (below 0.9 means
borderline). Borderline samples need a second reviewer; mark
`review_status=adjudicated` after resolution and add a short `notes` rationale.
New variants of an existing sample must reuse its `group_id` so they cannot
leak across splits.

Forbidden content: no real passwords, API keys, tokens, personal data, or real
external targets. Fake secrets must be obviously fake (`FAKE_TEST_SECRET_123`).
