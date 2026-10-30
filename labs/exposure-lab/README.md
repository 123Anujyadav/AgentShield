# Exposure-check lab (M2-F)

An isolated, loopback-only lab for the passive exposure checks. Everything runs
inside one Node process, `run-lab.mjs`; no Docker, no `.env`, no network beyond
`127.0.0.1`.

## Run

From the repository root, after `npm run build`:

```powershell
node labs/exposure-lab/run-lab.mjs [path\to\results.json]
```

It prints one PASS/FAIL line per check (names and counts only, never fixture
bodies or evidence) and exits 0 only when every check passes. The optional
results file holds the same check list and per-scan counts.

## Isolation

Before any application code loads, the runner installs guards in its own
process:

- `listen()` may bind only `127.0.0.1` (anything else throws);
- every outgoing socket must go to `127.0.0.1` (anything else throws);
- every DNS call is refused and recorded. The single exception is Node's own
  local resolution of the literal `127.0.0.1` inside `listen()`, which sends no
  query.

The API instances are built from the compiled app (`apps/api/dist`) with a
configuration object made from a synthetic environment: lab mode on, the lab
origins below, and `SCAN_EXPOSURE_ENABLED` only for the instances whose
scenario needs it. The runner never reads `.env` (only `server.ts` does) and
never changes `process.env`; it checks at start and end that the process has no
`SCAN_*` or `MODEL_*` variables. The scanner uses the real Node transport,
wrapped so that any target other than the lab ports on `127.0.0.1` is refused.
The model provider is the offline mock. For the lab only, the start-scan rate
limit is raised so the scenario matrix fits in one minute.

## Fixture servers

| Server | Origin | Content |
| --- | --- | --- |
| good | `http://127.0.0.1:8081` | the page and `security.txt` from `../passive-scan`, the good nginx header set, a generic HTML status page, an ordinary text file at `/.env`, 410 and 403 paths, 404 elsewhere |
| bad | `http://127.0.0.1:8082` | the bad nginx header set and all nine exposure fixtures (Apache mod_status at `/server-status`) |
| variants | `http://127.0.0.1:8083` | one scenario at a time: nginx `stub_status`; "Active connections" text alone; a catch-all site; a catch-all site with a real `/.env`; a 403 (ambiguous) baseline; transport cases (2 MB bodies that ignore Range, a gzip-encoded body, redirects, 500, 304, 416); slow responses for the deadline |

Fixture servers honour `Range` with 206 responses, like nginx, except where a
scenario deliberately ignores it.

All fixtures in `fixtures/` are tiny and synthetic. Secret-shaped values use
`FAKE_AGENTSHIELD_TEST_SECRET_DO_NOT_USE_*`, host names end in `.invalid`,
addresses are from the documentation range `192.0.2.0/24`, and every file
carries a `LAB_*` sentinel so the runner can prove none of it reaches any API
response, report or audit entry. The three binary files are:

- `DS_Store.bin`: the eight-byte `.DS_Store` signature plus filler;
- `backup.zip`: an empty ZIP archive (end-of-central-directory record with a
  comment);
- `backup.tar.gz`: gzip data with a fixed header.

## Results

M2-F, 2026-10-30: 54 of 54 checks passed, with every service bound to
`127.0.0.1`, every outgoing connection to `127.0.0.1`, no DNS query, no guard
violation, and no fixture sentinel in any API output, report or audit entry.
Covered: the four combinations of the server switch and the per-scan opt-in;
all nine signatures (Apache and nginx status pages separately); severities; the
fixed Range header; the 4 KB limit and early hang-up on 2 MB bodies that ignore
`Range`; compressed, redirect, 500, 304 and 416 responses; catch-all and
ambiguous baselines; the request budget and the time limit; JSON and HTML
reports; and the audit record of the opt-in.

Not covered: real nginx or Apache servers, HTTPS, real DNS, and the Website
Scans screen in a browser. The runner is not part of `npm test`; run it on
purpose.

## Why not the Docker lab

`../passive-scan` publishes its nginx containers on `127.0.0.1`, but nginx
inside each container listens on `0.0.0.0:80`. The M2-F rules allow only
services that bind loopback, so this lab uses Node servers bound to
`127.0.0.1` instead, with the same page, `security.txt` and header sets.
