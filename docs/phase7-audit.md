# Phase 7 security regression and demo-readiness audit

Date: 2026-10-26. Offline only. No live Meta request occurred; no credits consumed.

## Results

- Tests: 70 passed (engine 28, API 42), 0 failed.
- Type-check: passed for engine, API, and web.
- Build: passed for all three packages.
- Seeded API smoke: benign ALLOW executed only `create_summary`; injection
  CONFIRM did not execute before approval; approval executed the exact stored
  `create_summary` (a client-submitted replacement action was ignored);
  duplicate approval returned 409; forbidden payment BLOCK created no approval.
- Provider gate: default and key-alone select mock; flag-without-key fails
  closed to mock; live is selected only with flag plus key; construction and
  `/api/model/status` make no outbound request; request-body fields such as
  `provider`, `MODEL_LIVE_ENABLED`, or a submitted key cannot activate live.
- Secrets: built web bundle contains no `MODEL_API_KEY`, test key, or Bearer
  value (0 matches). `.env.example` contains only an empty placeholder. Model
  logging emits only status and sanitized category.

## Dependency audit (not fixed)

`npm audit` reports 3 vulnerabilities (2 critical, 1 moderate), all in the
Vitest test toolchain: `vitest` (direct dev dependency) via `@vitest/mocker`
(path traversal / arbitrary file read; code injection via mock registration)
and `tinypool` (prototype-pollution gadget to RCE). These affect the local
test runner, not the shipped API/web runtime, but a compromised test process
is still a local risk. Recommended separately reviewed fix: upgrade Vitest to
a patched release in its own change, re-run the full suite, and review the
lockfile diff. Do not run `npm audit fix --force`.

**Remediation (Phase 8, 2026-10-26):** upgraded `vitest` `^3.2.7` (3.2.7) to
`^4.1.12` (4.1.12) in the engine and API workspaces — the 3.x line is
unmaintained for these advisories (GitHub Advisory Database notes older
majors "may or may not have received fixes"; the patched ranges are the 4.1.x
line: `@vitest/mocker` fixed in 4.1.12, `tinypool` fixed at 2.1.2 and removed
from the Vitest 4 tree entirely). `vite@^6.0.0` was added as an explicit
devDependency in both workspaces because Vitest 4 treats Vite as a peer
dependency, and `.npmrc` sets `legacy-peer-deps=true` to work around an npm
10 arborist peer-resolution crash (`edgesOut`). Added `vitest.config.ts` in
both workspaces to exclude `dist/**`, since Vitest 4 otherwise also runs
compiled test copies. Result after remediation: `npm audit` reports
**0 vulnerabilities**, all 70 source tests pass, type-check and build pass.

## Limitations

- Browser clicking was not automated; dashboard behaviour was verified by
  API responses, web-server reachability, production build, and code inspection.
- The live provider transport (global `fetch`) has never run against Meta.
- Approvals and events are in-memory and reset on API restart.
- The local API has no authentication; production approvals need an
  authenticated, authorised identity.
