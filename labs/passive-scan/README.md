# Passive-scan lab (M1)

Two static nginx sites for checking AgentShield's passive website checks
locally. **Prepared, not run.** Nothing here starts on its own; run it only
after you have authorized a local lab run.

| Site | Origin | Configuration |
| --- | --- | --- |
| Good | `http://127.0.0.1:8081` | `nginx/good.conf`: hardened headers, cookie flags, valid `security.txt` |
| Bad | `http://127.0.0.1:8082` | `nginx/bad.conf`: version disclosure, weak CSP, obsolete framing header, leaky Referrer-Policy, malformed Permissions-Policy, wildcard CORS with credentials, unflagged cookie, no `security.txt` |

Both containers publish their port on `127.0.0.1` only, run read-only, and
serve one static page (`site/index.html`) that holds no data.

## Requirements

- Docker (Docker Desktop on Windows). Docker Desktop's licence terms depend on
  your organization's size and type; check them before use. Price: unknown
  here, check Docker's current terms.
- The first `docker compose up` downloads the `nginx:1.27-alpine` image
  (network access, about 20 MB).
- `security/security.txt` has `Expires: 2027-12-31T23:59:59Z`; after that date
  the good site will report an expired `security.txt`, so update it.

## Run (only when authorized)

```powershell
cd labs/passive-scan
docker compose up -d
```

Configure the API for lab mode in the git-ignored `.env` (lab mode is
independent of `SCAN_NETWORK_ENABLED`, which can stay `false`). Lab origins
must be loopback IP origins on ports 8080-8099; anything else is ignored:

```text
SCAN_LAB_MODE=true
SCAN_LAB_ORIGINS=http://127.0.0.1:8081,http://127.0.0.1:8082
```

Restart the API (`npm run start -w @agentshield/api`), sign in, open
**Website Scans**, add `http://127.0.0.1:8081`, click **Verify ownership**
(lab targets are proved by the server configuration above, not by DNS), then
**Start scan**. Repeat for `http://127.0.0.1:8082`.

Stop and clean up:

```powershell
docker compose down
```

Then set `SCAN_LAB_MODE=false` (or remove both lines) and restart the API.

## Expected results

Lab sites are plain HTTP, so TLS, HTTP-to-HTTPS redirect and HSTS checks are
reported as not applicable, and cookies are not required to be `Secure`.

**Good site (8081):** every applicable check passes. Expected informational
notes: none.

**Bad site (8082):**

| Check | Expected finding | Severity |
| --- | --- | --- |
| Content-Security-Policy | `header.csp.unsafe-script-sources` | low |
| X-Content-Type-Options | `header.x-content-type-options.missing` | low |
| Referrer-Policy | `header.referrer-policy.leaky` | low |
| Permissions-Policy | `header.permissions-policy.malformed` | low |
| Framing | `header.framing.invalid-x-frame-options` | low |
| CORS | `cors.wildcard-with-credentials` | medium |
| Version disclosure | `header.version-disclosure.server`, `header.version-disclosure.x-powered-by` | low |
| Cookies | `cookies.samesite-missing`, `cookies.httponly-missing` | low |
| security.txt | `security-txt.missing` | info |

Any difference from these tables is a result worth recording, not something to
"fix" by changing the lab.
