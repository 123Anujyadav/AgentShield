# Website scanning (M1): passive checks for sites you own

Status: implemented and tested offline with fake DNS resolvers and fake
transports only. **No real website and no real DNS record has been scanned or
checked.** The local lab in `labs/passive-scan/` is prepared but has not been
run. Offline tests are not a certification of the scanner or of any site.

## What it does

For one exact host name that you have proved you control, a scan makes at most
three passive requests (plus same-host redirects, within a budget of 30):

1. `GET https://<host>/`: TLS certificate and protocol, and the response headers.
2. `GET http://<host>/`: whether plain HTTP redirects to HTTPS (not followed).
3. `GET https://<host>/.well-known/security.txt`: RFC 9116 file (read up to 32 KB).

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

Only the exact text `true` turns a switch on; unset, empty, `TRUE`, `1` or
`yes` leave it off. The two switches are independent: lab mode never enables
real targets, and enabling real targets never enables lab origins. No API
request can change either switch. Set them in the git-ignored `.env` and
restart the API; to disable scanning, remove them (or set `false`) and restart.

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

- Not validated against real sites yet. The real transport has been exercised over
  loopback only: plain HTTP in the local lab, and HTTPS in
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
2. Local lab (`labs/passive-scan/`), only after explicit authorization.
3. One domain you own, only after separate explicit authorization, with
   `SCAN_NETWORK_ENABLED=true` set for that session and removed afterwards.
