# Website scanning: passive checks for sites you own

Status: implemented and verified offline and on loopback only.

- Offline: unit and integration tests with fake DNS resolvers and fake transports.
- M1 passive-scan lab (`labs/passive-scan/`, two Docker nginx sites published
  on `127.0.0.1`): run once locally; both sites matched the expected results in
  its README. The real HTTPS transport was also exercised against local test
  servers (`packages/websec/src/loopback-tls.test.ts`).
- M2 exposure lab (`labs/exposure-lab/`, Node fixture servers bound to
  `127.0.0.1`): 54 of 54 checks passed on 2026-10-30.

**Not tested:** any public website, any real DNS record (the system resolver and
TXT lookup have never run), any public HTTPS server, and the Website Scans
screen in a browser. Offline and loopback results are not a certification of
the scanner or of any site.

## What it does

For one exact host name that you have proved you control, the passive checks
make three requests, plus any same-host redirect hops they follow. Every hop is
a separate request. All requests in a scan share one request budget (30) and one
time limit (120 seconds):

1. `GET https://<host>/`: TLS certificate and protocol, and the response headers.
   Same-host redirects are followed, up to five hops.
2. `GET http://<host>/`: whether plain HTTP redirects to HTTPS. Never followed.
3. `GET https://<host>/.well-known/security.txt`: RFC 9116 file (read up to
   32 KB). Same-host redirects are followed, up to five hops.

A lab origin gets two requests: its root (over plain HTTP) and its
`security.txt`, each following redirects within the exact lab origin, up to
five hops. Exposure checks (below), when requested and allowed, add up to ten
more requests, none of which follows a redirect.

Checks: TLS certificate trust, host-name match and validity period; legacy TLS
if negotiated; HTTP to HTTPS redirect; HSTS; Content-Security-Policy;
X-Content-Type-Options; Referrer-Policy; Permissions-Policy; framing protection
(CSP `frame-ancestors` / `X-Frame-Options`); CORS (wildcard with credentials,
and whether a fixed probe Origin, `https://agentshield-cors-probe.invalid`, is
reflected); `Server` / `X-Powered-By` version disclosure; cookie `Secure`,
`HttpOnly` and `SameSite` flags; `security.txt` presence and validity.

It does not crawl, follow links, enumerate paths or subdomains, submit forms,
log in, send attack payloads, or test for exploitable vulnerabilities.

## Switches (all off by default, all server-side)

| Setting | Effect | Default |
| --- | --- | --- |
| `SCAN_NETWORK_ENABLED=true` | Allows DNS ownership checks and scans of real targets | off |
| `SCAN_LAB_MODE=true` | Allows scans of the exact origins in `SCAN_LAB_ORIGINS` only | off |
| `SCAN_LAB_ORIGINS` | Comma-separated `http://127.0.0.1:PORT` or `http://[::1]:PORT`, port 8080-8099 only (the lab uses 8081 and 8082), never the API's own `PORT`; any other entry is ignored | empty |
| `SCAN_EXPOSURE_ENABLED=true` | Allows exposure checks (see below) for scans that ask for them; on its own it scans nothing | off |

Only the exact text `true` turns a switch on; unset, empty, `TRUE`, `1` or
`yes` leave it off. The switches are independent: lab mode never enables
real targets, and enabling real targets never enables lab origins. No API
request can change any switch. Set them in the git-ignored `.env` and
restart the API; to disable scanning, remove them (or set `false`) and restart.

## Exposure checks (M2): opt-in, off by default

Status: verified offline and in the loopback-only exposure lab
(`labs/exposure-lab/`, 54 of 54 checks, 2026-10-30). Not run against any real
site, real DNS or public HTTPS server, and the screen has not been tested in a
browser.

Exposure checks look for nine commonly exposed files, each by a strict content
signature in the first 4 KB of the response, never by status code alone:
`/.git/HEAD`, `/.git/config`, `/.env`, `/.DS_Store`, `/server-status`,
`/backup.zip`, `/backup.tar.gz`, `/database.sql`, `/dump.sql`. One request to a
random missing path (`/agentshield-baseline-<64 hex>`) is made first, so a site
that answers every path with the same page is not reported. The list is fixed
in code; no request can add, change or remove a path.

They run only when **both** controls allow it:

1. **Server switch (administrator):** `SCAN_EXPOSURE_ENABLED=true` in `.env`,
   then restart the API. To disable them, remove it (or set `false`) and
   restart. While it is off, a request for exposure checks is refused with
   409 `exposure-checks-disabled` and nothing is sent.
2. **Per scan (user):** tick **Include exposure checks** before **Start scan**,
   which sends `POST /api/scans` with `{"targetId": "tgt-1",
   "includeExposureChecks": true}`. The field is optional and defaults to
   `false`; any value other than `true` or `false` is refused with 400
   `invalid-scan-options`. The tick clears after each scan.

Each opted-in scan adds at most 10 requests (the baseline plus nine paths) to
the same budget of 30 and the same time limit, one at a time, with the same
ownership re-check, address guard, pinned connections and timeouts. They are GET
requests with `Range: bytes=0-4095`, read at most 4,096 bytes, and never follow
redirects or decode compressed bodies. A path is not started unless enough time
(20 seconds) and budget remain. The site's own security tools or firewall may
log these requests.

**The 4 KB limit.** A file is recognized only if its signature appears in the
first 4,096 bytes. Whole-file signatures (`/.git/HEAD`, nginx `stub_status`)
are not trusted when the body continues past 4 KB. A server that ignores
`Range` may send more, but at most 4,096 bytes are kept and the connection is
closed; the operating system may already have buffered more by then.
Compressed responses are not decoded and are reported as inconclusive.

**Outcomes per path.** *Exposed*: the signature matched, and the baseline does
not explain it. *Not exposed*: 404, 410, 401 or 403, no matching signature, or
the same page the site returns for a random missing path. *Inconclusive*
(amber): a redirect (including 304), 416, a server error, an unexpected status,
a timeout, a connection error, a compressed response, or a signature match
that an unavailable or ambiguous baseline cannot confirm. *Not checked* (amber):
the time limit or request budget ran out first, or the scan did not finish.
Neither inconclusive nor not checked is ever shown as a pass.

**Incomplete exposure checks (M2-H).** When the time limit or the request budget
stops the exposure stage before every path is checked, the scan still completes:
the passive results and every finished path are kept. It is shown everywhere as
"completed — exposure checks incomplete": scan objects carry
`exposureIncomplete: true` and `exposureIncompleteReason` (`time-limit` or
`request-budget`), the scan detail and JSON report carry `exposure.incomplete`,
and the HTML report's Status row says so. The JSON `status` field stays
`completed`. An individual inconclusive result never makes a scan incomplete,
and failed or rejected scans keep their own state.

**For JSON report consumers.** The top-level `status` can be `"completed"` even
when the exposure checks stopped early, so a consumer that reads only `status`
can miss incomplete exposure coverage. Always check `exposure.incomplete` as
well: it is `null` when every requested path was checked, and otherwise an
object whose `reason` (`time-limit` or `request-budget`) says why the checks
stopped and whose `summary` is a fixed sentence. When exposure checks were not
requested, `exposure` is `{"requested": false, "state": "not-requested"}` and
has no `incomplete` field. The API's scan objects carry the same reason as
`exposureIncompleteReason`.

Findings carry only fixed text, the path, counts and secret kinds: never file
contents, variable names, secret values, Git remote URLs, addresses from a
status page, SQL or archive contents, or the baseline response. The scan
records whether exposure checks were requested (`options.exposureChecks`); an
opted-out scan shows "not requested" and has no exposure rows. Opted-in results
include one baseline diagnostic row (`exposure-baseline`), which is never a
finding.

**Reports and audit (M2-E).** The JSON report's `generator` is "AgentShield
passive website scanner (passive configuration checks, opt-in exposure
checks)". Exposure rows carry a typed `group`
(`exposure`, or `exposure-baseline` for the diagnostic); M1 checks have none.
The JSON report keeps every M1 field, lists only the passive checks under
`checks`, and adds `options` (the recorded choice) and an `exposure` section:
`{"requested": false, "state": "not-requested"}`, or the nine fixed paths in
order, each with an outcome of `exposed`, `not-exposed`, `inconclusive` or
`not-checked`, plus the baseline as a separate diagnostic (its outcome and fixed
summary only, never its path or response). A path with no recorded result is
`not-checked`. The HTML report shows the same section, with inconclusive and not
checked in amber. The API's scan detail returns the same `exposure` section.
The scan audit log records the user's choice once per scan, on the
`scan-queued` entry (or the `scan-rejected` entry when the request is refused):
`exposureChecks: {"requested": true|false, "allowed": true|false|null}`, where
`allowed` is whether the server switch permitted it (`null` when not
requested). Refused requests (400 and 409) still count toward the start-scan
rate limit, as before.

## Ownership verification (DNS TXT only)

1. **Website Scans → Add target** with the exact host name, e.g.
   `https://www.example.com`. Each host name is a separate target.
2. Publish the TXT record the screen shows, at your DNS provider:
   - Name: `_agentshield-verification.<host>`
   - Value: `agentshield-verification=<challenge>` (random, per target)
3. Click **Verify ownership**. AgentShield queries DNS only; it never contacts
   the website to verify ownership.

Verification lasts 30 days, and the TXT record is checked again when every
scan starts: if it is missing, changed or cannot be checked, the scan is
rejected before any request is sent to the site, and the target returns to
"failed". The challenge is shown only while the target is not verified (so you
can set up or restore the record); it never appears in reports or the audit
log. Deleting a target removes its challenge and stops any of its active scans.

## Safety controls

- **Target rules:** http/https only; default ports only (443 for https, 80 for
  http); no credentials, paths, queries or fragments; no IP addresses in any
  notation (decimal, octal, hex, short forms, IPv6, IPv4-mapped); no trailing
  dots; internationalized names converted to Punycode and validated; special-use
  and internal names (`localhost`, `.local`, `.internal`, `.home.arpa`, `.test`,
  `.lan` and similar) refused.
- **Address guard:** every address a host name resolves to must be public.
  Loopback, private, link-local, carrier-grade NAT, multicast, reserved,
  benchmarking and documentation ranges, cloud metadata endpoints
  (169.254.169.254, 168.63.129.16, 100.100.100.200, fd00:ec2::254), IPv4-mapped
  and IPv4-compatible IPv6, 6to4, Teredo and NAT64 addresses embedding a blocked
  IPv4 address are refused. If any one resolved address is blocked, the whole
  host name is refused.
- **Connection pinning:** the connection is made to the address that was just
  checked; the host name is not resolved again at connect time, so DNS
  rebinding cannot swap in a private address. The original host name is kept for
  the `Host` header and TLS SNI/certificate checks.
- **Redirects:** followed manually, at most five, same exact host and default
  ports only, each hop re-resolved and re-checked.
- **Limits:** 10 s per request, 1 MB maximum body (decompressed size capped
  too), 30 requests per scan, 2 minutes per scan, one active request per host,
  two concurrent scans overall and one per target.
- **Requests carry no credentials:** no cookies, no `Authorization`, fixed
  headers only, `Accept-Encoding: identity`, and Node's HTTP stack ignores
  `HTTP_PROXY`/`HTTPS_PROXY`, so no ambient proxy is used.
- **Rate limits (per minute):** add target 20, verify 10, start scan 5, plus the
  API-wide limit. All scan routes require the API token or a session.

## Results, reports and storage

Scan states: `queued`, `running`, `completed`, `failed` (stopped after
requests were sent: timeout, deletion, internal error) and `rejected` (refused
before any request reached the site: scanning disabled, not verified, expired,
proof failed, blocked address). A rejected scan is recorded so the history
shows the attempt, with `requestsUsed: 0`.

Each finding has a stable `findingId`, `severity`
(`info`/`low`/`medium`/`high`/`critical`), `confidence` (`low`/`medium`/`high`),
title, explanation, redacted evidence (at most 200 characters, secret-shaped
values removed), remediation and CWE/OWASP references. A finding is evidence of
a weaker configuration, not proof that the site is exploitable; for example a
missing CSP is reported with medium confidence because a policy in an HTML meta
tag is not checked. Reports never contain verification challenges, cookie
values, response bodies or credentials. The HTML report escapes every value and
is served as a download with a restrictive Content-Security-Policy.

Targets (at most 50), scans (the newest 50) and the scan audit log (the newest
500 entries) are kept in memory and lost when the API restarts. The scan audit
log is separate from the agent activity log.

## Limitations

- Exposure checks have run only against loopback Node fixture servers, not against
  real nginx or Apache servers, over HTTPS, or with real DNS. Known misses include
  customized or `?auto` Apache status pages, pg_dump's binary format, compressed
  responses, `.env` files that are mostly not assignments, and HTTP-only sites
  (exposure probes for real sites use HTTPS only).
- The Website Scans screen is covered by unit tests only; it has not been tested
  in a browser.
- Not validated against real sites yet. The real transport has been exercised over
  loopback only: plain HTTP in the local labs, and HTTPS in
  `packages/websec/src/loopback-tls.test.ts` (trusted, self-signed and mismatched
  certificates, SNI and Host, connection pinning against a rebinding DNS answer,
  cancellation). The guard refuses loopback for real targets, so the full
  fetcher-to-transport success path is proven only with fake transports, and the
  system resolvers (`systemResolver`, `systemTxtResolver`) have not been run.
- Node's TLS client offers TLS 1.2 and 1.3 only, so a server that still accepts
  TLS 1.0/1.1 is not detected unless it negotiates them.
- One address (the first public one returned) is used per request; there is no
  IPv4/IPv6 fallback.
- Host-name resolution uses the operating system resolver (including the hosts
  file); results are still subject to the address guard.
- One shared API credential; no per-user ownership of targets.
- Rate limits and storage are per API process and in memory.

## Validation order

1. Offline tests (done): `npm test`.
2. Local labs, loopback only, each run after explicit authorization (done):
   - M1 passive checks: `labs/passive-scan/` (Docker nginx), run once; both sites
     matched the expected results.
   - M2 exposure checks: `labs/exposure-lab/` (`node labs/exposure-lab/run-lab.mjs`
     after `npm run build`), 54 of 54 checks on 2026-10-30.
3. One domain you own, only after separate explicit authorization, with
   `SCAN_NETWORK_ENABLED=true` set for that session and removed afterwards
   (not done).
