# Phase 11A-2.9 — Opaque-ID Blind Review Round 2

Date: 2026-10-26. **Quality gate remains OPEN. Phase 11A-3 is not approved.**
No independent annotation has been completed. Nothing was fabricated.

## Package created

Location: `ml/datasets/sentinel/v0.3.0/REVIEW_ROUND2/`

```text
REVIEW_ROUND2/
  ANNOTATOR_PACKAGE/          <- give only this folder to the annotator
    review_blind_opaque.csv   196 rows, random opaque review IDs
    INSTRUCTIONS.md
    REVIEWER_GUIDE.md
  ADJUDICATOR_ONLY/
    mapping_key.csv           opaque ID -> sample ID + author labels (never share)
```

Sample count: **196**, the same stratified selection documented in Phase
11A-2.7 (all impersonation/other_suspicious and multilingual samples, all
curated v0.3 samples, obfuscation representatives, and a stratified fifth of
the remainder; language and category composition are recorded only in the
key, not in the annotator package). The original v0.3.0 dataset and the
Round-1 review package are unchanged.

Opaque IDs: `rv-` plus 10 characters from `[a-z0-9]`, generated with the
`secrets` CSPRNG in `ml/sentinel/build_round2.py`, uniqueness-checked, shuffled
order. They encode no sample ID, label, category, language, or split.

## Leakage verification (actually run)

Automated tests (`ml/tests/test_round2.py`, 4 tests) assert:

- The annotator package contains no `sen-####` sample ID anywhere in its
  files, no `author_label` field, no split column, and no mapping file.
- Every review ID matches the opaque format, is unique, and ships unannotated.
- The mapping key lives only under `ADJUDICATOR_ONLY/` and covers exactly the
  annotator ID set.
- Intake accepts a complete valid return and rejects incomplete, unknown-ID,
  invalid-label, and text-tampered returns.

Commands and actual results:

```powershell
python ml/sentinel/build_round2.py
# rows=196 unique_opaque=196
python -m pytest ml/tests -q
# 16 passed (dataset, intake, round2)
python ml/sentinel/intake_round2.py ml/datasets/sentinel/v0.3.0/REVIEW_ROUND2/ANNOTATOR_PACKAGE/review_blind_opaque.csv
# rows=196 errors=784, exit 1 — blank package correctly rejected; gate open
npm test
# 72 passed (engine 28, API 44) — production regression intact
```

After fixing an initial test bug (a file path treated as a directory), the
full Python suite passes. No production code changed.

## Intake (Round 2)

`ml/sentinel/intake_round2.py` validates a returned file against the annotator
package itself: unknown or duplicate review IDs, missing rows, text differing
from the package, label/category validity, confidence range, `language_quality`
in {ok, uncertain, cannot-judge}, annotator ID, and date. It logs only row
counts and error categories — never sample text, author labels, or the mapping.
Only after intake passes may the adjudicator open `mapping_key.csv` and join.

## Explicit human instructions

1. Give the annotator **only** `ANNOTATOR_PACKAGE/`. Do not send the dataset,
   the changelog, Round-1 files, or this document's mapping references.
2. The annotator follows `INSTRUCTIONS.md` inside that folder: label by intent
   using the guide, mark `language_quality=cannot-judge` rather than guessing
   on Spanish/German/Hindi rows, and return the CSV structurally unchanged.
   They must not search for these texts anywhere.
3. Run intake on the return. If it fails, send back only the error summary
   (counts/categories) for completion — not any key information.
4. Only the adjudicator then joins with `mapping_key.csv`, computes agreement
   (Cohen's kappa plus confusion table per Phase 11A-2.8), and records
   adjudication for a future v0.3.1 patch.

Estimated effort: 196 short rows, roughly 1–2 focused hours.

## Limitations

Opaque IDs remove the direct label lookup, but blindness is not perfect:
the text itself can reveal clues (a quoted-attack education sample discusses
attacks; an obvious "SYSTEM:" banner is recognisably an attack pattern — that
recognition is of course the labelling task itself). A determined annotator
with the public dataset could still attempt text matching; the instructions
forbid searching, and intake cannot detect it. True enforcement would require
an annotator with no dataset access, which is a human-process control, not a
file-format one.

Provenance: package generated 2026-10-26 by `build_round2.py` from the frozen
v0.3.0 dataset; mapping generated in the same run and stored only in
`ADJUDICATOR_ONLY/`. No annotations, identities, timestamps, or agreement
values exist yet.

## Gate status

Open. The gate closes only when a real independent annotator returns the
completed file and `intake_round2.py` accepts it. Stop here and wait for that
human result before any adjudication or Phase 11A-3 request.
