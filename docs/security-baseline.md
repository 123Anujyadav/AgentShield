# Security Baseline (Phase E)

Local-first controls that reduce the risk of committing credentials,
protected datasets, or sensitive review artifacts. These controls reduce
risk; they do not guarantee that every secret is detected.

## Commands

All commands run locally. Nothing is uploaded to a third-party service.

| Command | What it does |
| --- | --- |
| `npm run security:scan` | Scan tracked working-tree files for credential shapes |
| `npm run security:scan:history` | The same, plus every commit reachable from any ref |
| `npm run security:self-test` | End-to-end tests of the scanner CLI in temporary repositories |
| `npm run security:verify` | Pre-push verification: history scan plus `git diff --check` |

Run `npm run security:verify` before every push, and `npm run security:self-test`
after any change to `scripts/secret-scan.mjs`.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Every credential-shaped value found is on the reviewed allowlist (or none was found) |
| `1` | At least one credential-shaped value is not on the allowlist |
| `2` | The scan could not complete; it is never reported as a pass |

Exit `2` covers: Git missing or failing, a `git grep` status other than 0
(matches) or 1 (no matches), any Git error output, invalid patterns, missing
or corrupt objects, output too large for the buffer, unexpected or malformed
Git output, and a tracked file that cannot be read.

## What is detected

`scripts/secret-scan.mjs` uses Node only, with no new dependencies. Every
pattern is written so the same text works as a JavaScript regular expression
and as a POSIX extended regular expression for `git grep -E`. If Git and the
scanner ever disagree about a matched line, the scan stops with exit `2`.

| Category | Shape |
| --- | --- |
| `private-key-header` | `BEGIN [RSA/EC/DSA/OPENSSH/ENCRYPTED] PRIVATE KEY` |
| `aws-access-key-id` | `AKIA` or `ASIA` followed by 16 upper-case letters or digits |
| `github-token` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` (30+ characters) or `github_pat_` |
| `gitlab-token` | `glpat-` followed by 20+ characters |
| `sk-style-token` | `sk-`, `sk-proj-`, `sk-ant-` followed by 24+ characters |
| `stripe-live-key` | `sk_live_` or `rk_live_` followed by 24+ characters |
| `slack-token` | `xoxa-`, `xoxb-`, `xoxp-`, `xoxo-`, `xoxs-`, `xoxr-` followed by 10+ characters |
| `google-api-key` | `AIza` followed by 35 characters |
| `bearer-token` | `Bearer` followed by a 24+ character token |
| `model-api-key-assignment` | A non-empty `MODEL_API_KEY=` assignment |

Every match on a line is checked, not only the first.

Not detected: generic `password=` or `api_key=` assignments, JWTs, high-entropy
strings without a known prefix, split or encoded secrets, and any other format
not listed above.

## Coverage

- **Working tree** (`security:scan`): every file listed by `git ls-files -z`,
  read from disk. Paths are NUL-delimited, so spaces and non-ASCII names are
  handled. A tracked file that cannot be read stops the scan with exit `2`.
  Files deleted in the working tree are counted and reported, and binary files
  (containing a NUL byte, which includes UTF-16 text) are counted and skipped.
  Untracked files, including new files that have not been `git add`ed yet,
  are not scanned.
- **History** (`security:scan:history`): `git grep -I -n --null -E` on every
  commit from `git rev-list --all` (local branches, tags, remote-tracking
  refs, and stash). This reads the historical file contents, so a credential
  committed and later deleted is still found. Binary files are skipped by
  `-I`. Commits on other machines or in unfetched remotes are out of scope.
- **Protected datasets**: both scans pass Git exclusion pathspecs for
  `ml/datasets/sentinel/*/samples.jsonl` and `ml/datasets/sentinel/*/splits/`,
  so Git never reads those payloads, and the scan stops with exit `2` if Git
  ever lists one.

## Allowlist

A credential-shaped match fails the scan unless it is on the reviewed
allowlist in `scripts/secret-scan.mjs` (`ALLOWLIST`). There is no allowance
by file name, directory, file type, or word on the line: a value in a
`.test.ts` file, a `fixtures.json` file, or on a line containing `test`,
`fake`, `example`, `latest`, and so on fails like any other.

Each allowlist entry holds one exact value's fingerprint: the SHA-256 of
`category`, a NUL byte, and the matched value. An entry therefore allows that
one invented value wherever it appears and nothing else; a real credential
cannot share the fingerprint. Fingerprints are used instead of per-line
annotations because the existing test values are already in commit history,
which cannot be annotated without rewriting it.

Allowlisted hits are still printed, as `ALLOWLISTED [id] <category> at
<location>`, so the classification is auditable.

The allowlist currently holds seven invented values used by the detector's own
tests and benchmark fixtures (`engine-test-*`, `benchmark-tok-*`, `benchmark-f-*`).

To add an entry:

1. Confirm by reading the source that the value is invented test data.
2. Run `node scripts/secret-scan.mjs --history --fingerprints` locally. It
   prints each finding's fingerprint; values are still never printed.
3. Copy only the fingerprint into `ALLOWLIST` with an id and a reason, and
   have the change reviewed.

Never allowlist a real credential, and never paste a fingerprint of a real
credential anywhere public: for short values, a fingerprint can be guessed.

Output never contains a matched value. Error messages are reduced to one line
and any credential-shaped text in them is replaced with `[REDACTED]`.

## Self-test

`npm run security:self-test` creates temporary repositories in the operating
system's temp directory (never inside this repository), runs the scanner CLI
against them, and removes them. Fake values are built at runtime from
invented characters and are never printed; the test fails if any of them, or
a run of their padding, appears in the scanner's output. It checks that:

- a fake credential fails the scan in a normal file, a `.test.ts` file, a
  `fixtures.json` file, and on lines containing `latest`, `contest`,
  `attestation`, or the old marker words;
- every pattern is detected by both the working-tree scan and the `git grep`
  history scan;
- a private-key header, GitHub token, `sk-` token, and AWS key committed and
  then deleted are found by the history scan only;
- a clean history passes through Git's "no matches" status;
- an invalid pattern, a missing Git object, an unreadable tracked file, a
  missing `git`, and running outside a repository all exit `2`;
- a file name with spaces and non-ASCII characters is scanned in both modes;
- the allowlist matches one exact value only;
- malformed `git grep` output is an error.

## Enhanced scanning with Gitleaks (optional)

The built-in scanner covers the shapes listed above only. For entropy-based
detection, Gitleaks is a possible separately approved enhancement:

1. Install Gitleaks from its official GitHub releases page. Record the exact
   version you install in your local notes; do not commit the binary.
2. Run it locally, for example `gitleaks detect --source . --redact` and
   `gitleaks detect --source . --log-opts="--all" --redact`.
3. Keep `--redact` on so values are never printed.

Gitleaks is not installed in this environment and is not required for the
commands above. No CI workflow is configured; adding one is a separate
decision.

## If a credential is found

1. Stop. Do not push.
2. Treat the credential as compromised if it was ever committed or pushed:
   rotate or revoke it at the provider first.
3. Remove it from the working tree and replace it with an environment
   variable reference.
4. If it exists in Git history, history rewriting is required before the
   repository is safe to share. Rewriting is destructive and needs explicit
   owner approval; it is never done automatically.

## Why .gitignore alone is insufficient

`.gitignore` only prevents untracked files from being staged. It does not
untrack a file that is already committed, it does not stop `git add -f`, and
it does not remove anything from history. That is why this baseline also
scans tracked files and all reachable commits.

## Protected dataset paths

These exact paths are ignored in `.gitignore` and must never be staged,
committed, or pushed:

- `/ml/datasets/sentinel/v0.1.0/samples.jsonl` and `/ml/datasets/sentinel/v0.1.0/splits/`
- `/ml/datasets/sentinel/v0.2.0/samples.jsonl` and `/ml/datasets/sentinel/v0.2.0/splits/`
- `/ml/datasets/sentinel/v0.3.0/samples.jsonl` and `/ml/datasets/sentinel/v0.3.0/splits/`

They contain unreviewed dataset payloads. Approved metadata in the same
directories (dataset cards, labelling guides, changelogs, and
POLICY_ADJUDICATION records) remains trackable. Always stage with explicit
paths; never use `git add -A` or `git add .`.

Blind-review artifacts, mapping keys, adjudicator-only files, and AI audit
artifacts are covered by separate ignore rules and must never be shared with
annotators or pushed as part of unrelated work.

## Limitations

- Pattern-based scanning misses credentials in formats not listed above,
  split or encoded secrets, and high-entropy values without a known shape.
- Untracked files are not scanned until they are tracked; run the scan after
  `git add` and before committing.
- Binary files, including UTF-16 text, are skipped.
- History coverage is limited to commits reachable from refs in this clone.
- An allowlisted fake value is allowed wherever it appears, by design of
  exact-value fingerprints.
