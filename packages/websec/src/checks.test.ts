import { describe, expect, it } from "vitest";
import {
  checkContentTypeOptions,
  checkCookies,
  checkCors,
  checkCsp,
  checkDisclosure,
  checkFraming,
  checkHsts,
  checkPermissionsPolicy,
  checkReferrerPolicy,
  parseCookieFlags,
} from "./checks/headers.js";
import { checkSecurityTxt } from "./checks/security-txt.js";
import { checkHttpsRedirect, checkTls } from "./checks/transport-security.js";
import type { FetchResult, TlsDetails } from "./fetcher.js";
import type { CheckResult, PassiveObservations } from "./findings.js";
import { CORS_PROBE_ORIGIN } from "./scan.js";
import { parseLabOrigin, type DnsTarget } from "./target.js";

/** Pass, fail and misconfiguration fixtures for every passive check. */

const target: DnsTarget = { kind: "dns", hostname: "example.com", displayHostname: "example.com" };
const NOW = new Date("2026-10-29T12:00:00Z");

const GOOD_TLS: TlsDetails = {
  protocol: "TLSv1.3",
  authorized: true,
  authorizationError: null,
  hostnameMatches: true,
  certificate: {
    subjectCN: "example.com",
    issuerCN: "Example CA",
    subjectAltNames: ["DNS:example.com"],
    validFrom: "2026-06-01T00:00:00Z",
    validTo: "2027-06-01T00:00:00Z",
  },
};

function ok(headers: Record<string, string | string[]> = {}, extra: Partial<Extract<FetchResult, { ok: true }>> = {}): FetchResult {
  const normalized: Record<string, string[]> = {};
  for (const [name, value] of Object.entries(headers)) normalized[name.toLowerCase()] = Array.isArray(value) ? value : [value];
  return { ok: true, url: new URL("https://example.com/"), status: 200, headers: normalized, body: null, tls: GOOD_TLS, hops: [], ...extra };
}

function failed(reason: Extract<FetchResult, { ok: false }>["reason"]): FetchResult {
  return { ok: false, reason, url: new URL("https://example.com/"), hops: [] };
}

function obs(overrides: Partial<PassiveObservations> = {}): PassiveObservations {
  return { target, https: ok(), http: null, securityTxt: null, probeOrigin: CORS_PROBE_ORIGIN, now: NOW, ...overrides };
}

const ids = (check: CheckResult) => check.findings.map((f) => f.findingId);

describe("TLS check", () => {
  it("passes a valid, matching, current certificate on TLS 1.3", () => {
    expect(checkTls(obs())).toMatchObject({ status: "pass", findings: [] });
  });
  it.each([
    [{ hostnameMatches: false }, "tls.hostname-mismatch"],
    [{ authorized: false, authorizationError: "CERT_HAS_EXPIRED" }, "tls.certificate-expired"],
    [{ authorized: false, authorizationError: "DEPTH_ZERO_SELF_SIGNED_CERT" }, "tls.certificate-untrusted"],
    [{ authorized: false, authorizationError: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" }, "tls.certificate-untrusted"],
    [{ authorized: false, authorizationError: "CERT_NOT_YET_VALID" }, "tls.certificate-not-yet-valid"],
    [{ authorized: false, authorizationError: "SOME_OTHER_ERROR" }, "tls.certificate-invalid"],
    [{ protocol: "TLSv1.1" }, "tls.legacy-protocol"],
  ])("reports %j as %s", (tls, findingId) => {
    const check = checkTls(obs({ https: ok({}, { tls: { ...GOOD_TLS, ...tls } }) }));
    expect(check.status).toBe("fail");
    expect(ids(check)).toContain(findingId);
  });
  it("reports one host-name mismatch once, as Node signals it (P1 regression)", () => {
    // Node with rejectUnauthorized:false: authorized=false and ERR_TLS_CERT_ALTNAME_INVALID.
    const mismatch = { ...GOOD_TLS, hostnameMatches: false, authorized: false, authorizationError: "ERR_TLS_CERT_ALTNAME_INVALID" };
    const check = checkTls(obs({ https: ok({}, { tls: mismatch }) }));
    expect(ids(check)).toEqual(["tls.hostname-mismatch"]);
    expect(check.status).toBe("fail");
  });

  it("still reports a mismatch when only Node's verification code signals it (fail closed)", () => {
    const codeOnly = { ...GOOD_TLS, hostnameMatches: true, authorized: false, authorizationError: "ERR_TLS_CERT_ALTNAME_INVALID" };
    expect(ids(checkTls(obs({ https: ok({}, { tls: codeOnly }) })))).toEqual(["tls.hostname-mismatch"]);
  });

  it("keeps separate findings for genuinely separate certificate problems", () => {
    const selfSignedWrongHost = { ...GOOD_TLS, hostnameMatches: false, authorized: false, authorizationError: "DEPTH_ZERO_SELF_SIGNED_CERT" };
    expect(ids(checkTls(obs({ https: ok({}, { tls: selfSignedWrongHost }) }))).sort()).toEqual(["tls.certificate-untrusted", "tls.hostname-mismatch"]);
    const expiredWrongHost = {
      ...GOOD_TLS,
      hostnameMatches: false,
      authorized: false,
      authorizationError: "CERT_HAS_EXPIRED",
      certificate: { ...GOOD_TLS.certificate!, validTo: "2026-01-01T00:00:00Z" },
    };
    expect(ids(checkTls(obs({ https: ok({}, { tls: expiredWrongHost }) }))).sort()).toEqual(["tls.certificate-expired", "tls.hostname-mismatch"]);
    const otherWithWrongHost = { ...GOOD_TLS, hostnameMatches: false, authorized: false, authorizationError: "SOME_OTHER_ERROR" };
    expect(ids(checkTls(obs({ https: ok({}, { tls: otherWithWrongHost }) }))).sort()).toEqual(["tls.certificate-invalid", "tls.hostname-mismatch"]);
  });

  it("uses the certificate dates as well as the verifier's verdict", () => {
    const expired = { ...GOOD_TLS, certificate: { ...GOOD_TLS.certificate!, validTo: "2026-10-01T00:00:00Z" } };
    expect(ids(checkTls(obs({ https: ok({}, { tls: expired }) })))).toContain("tls.certificate-expired");
    const soon = { ...GOOD_TLS, certificate: { ...GOOD_TLS.certificate!, validTo: "2026-11-05T00:00:00Z" } };
    expect(checkTls(obs({ https: ok({}, { tls: soon }) })).findings[0]).toMatchObject({ findingId: "tls.certificate-expiring", severity: "medium" });
    const month = { ...GOOD_TLS, certificate: { ...GOOD_TLS.certificate!, validTo: "2026-11-20T00:00:00Z" } };
    expect(checkTls(obs({ https: ok({}, { tls: month }) })).findings[0]).toMatchObject({ findingId: "tls.certificate-expiring", severity: "low" });
  });
  it("reports HTTPS as unavailable on connection failure, and errors on other problems", () => {
    expect(ids(checkTls(obs({ https: failed("connection-failed") })))).toEqual(["tls.unavailable"]);
    expect(checkTls(obs({ https: failed("blocked-address") })).status).toBe("error");
    expect(checkTls(obs({ https: ok({}, { tls: null }) })).status).toBe("error");
  });
  it("is not applicable to lab targets", () => {
    expect(checkTls(obs({ target: parseLabOrigin("http://127.0.0.1:8081")! })).status).toBe("not-applicable");
  });
});

describe("HTTP to HTTPS redirect check", () => {
  const http = (status: number, location?: string) =>
    ok(location ? { location } : {}, { url: new URL("http://example.com/"), status, tls: null });
  it("passes a permanent redirect to HTTPS on the same host", () => {
    expect(checkHttpsRedirect(obs({ http: http(301, "https://example.com/") }))).toMatchObject({ status: "pass", findings: [] });
    expect(checkHttpsRedirect(obs({ http: failed("connection-failed") })).status).toBe("pass");
  });
  it("notes a temporary redirect without failing", () => {
    const check = checkHttpsRedirect(obs({ http: http(302, "https://example.com/") }));
    expect([check.status, ids(check)]).toEqual(["pass", ["https-redirect.temporary"]]);
  });
  it("fails plain-HTTP content and misdirected redirects", () => {
    expect(ids(checkHttpsRedirect(obs({ http: http(200) })))).toEqual(["https-redirect.missing"]);
    expect(ids(checkHttpsRedirect(obs({ http: http(301, "https://elsewhere.example/") })))).toEqual(["https-redirect.not-to-https"]);
    expect(ids(checkHttpsRedirect(obs({ http: http(301, "http://example.com/other") })))).toEqual(["https-redirect.not-to-https"]);
  });
});

describe("header checks", () => {
  it("HSTS: pass, missing, short, disabled, malformed, duplicate", () => {
    expect(checkHsts(obs({ https: ok({ "strict-transport-security": "max-age=31536000; includeSubDomains" }) })).status).toBe("pass");
    expect(ids(checkHsts(obs()))).toEqual(["header.hsts.missing"]);
    expect(ids(checkHsts(obs({ https: ok({ "strict-transport-security": "max-age=600" }) })))).toEqual(["header.hsts.short-max-age"]);
    expect(ids(checkHsts(obs({ https: ok({ "strict-transport-security": "max-age=0" }) })))).toEqual(["header.hsts.disabled"]);
    expect(ids(checkHsts(obs({ https: ok({ "strict-transport-security": "includeSubDomains" }) })))).toEqual(["header.hsts.malformed"]);
    expect(ids(checkHsts(obs({ https: ok({ "strict-transport-security": ["max-age=31536000", "max-age=0"] }) })))).toEqual(["header.hsts.duplicate"]);
    expect(checkHsts(obs({ https: failed("timeout") })).status).toBe("error");
  });

  it("CSP: pass, missing, report-only, unsafe sources, no script restriction", () => {
    expect(checkCsp(obs({ https: ok({ "content-security-policy": "default-src 'self'; script-src 'self' 'nonce-abc'" }) })).status).toBe("pass");
    expect(checkCsp(obs({ https: ok({ "content-security-policy": "script-src 'self' 'unsafe-inline' 'nonce-abc'" }) })).status).toBe("pass");
    const missing = checkCsp(obs());
    expect([ids(missing), missing.findings[0]!.confidence]).toEqual([["header.csp.missing"], "medium"]);
    expect(ids(checkCsp(obs({ https: ok({ "content-security-policy-report-only": "default-src 'self'" }) })))).toEqual(["header.csp.report-only"]);
    expect(ids(checkCsp(obs({ https: ok({ "content-security-policy": "default-src * 'unsafe-inline'" }) })))).toEqual(["header.csp.unsafe-script-sources"]);
    expect(ids(checkCsp(obs({ https: ok({ "content-security-policy": "img-src 'self'" }) })))).toEqual(["header.csp.no-script-restriction"]);
  });

  it("X-Content-Type-Options: pass, missing, invalid", () => {
    expect(checkContentTypeOptions(obs({ https: ok({ "x-content-type-options": "nosniff" }) })).status).toBe("pass");
    expect(ids(checkContentTypeOptions(obs()))).toEqual(["header.x-content-type-options.missing"]);
    expect(ids(checkContentTypeOptions(obs({ https: ok({ "x-content-type-options": "sniff-please" }) })))).toEqual(["header.x-content-type-options.invalid"]);
  });

  it("Referrer-Policy: pass, missing (info), leaky, invalid; the last valid token applies", () => {
    expect(checkReferrerPolicy(obs({ https: ok({ "referrer-policy": "no-referrer, strict-origin-when-cross-origin" }) })).status).toBe("pass");
    const missing = checkReferrerPolicy(obs());
    expect([missing.status, missing.findings[0]?.severity]).toEqual(["pass", "info"]);
    expect(ids(checkReferrerPolicy(obs({ https: ok({ "referrer-policy": "strict-origin, unsafe-url" }) })))).toEqual(["header.referrer-policy.leaky"]);
    expect(ids(checkReferrerPolicy(obs({ https: ok({ "referrer-policy": "everything" }) })))).toEqual(["header.referrer-policy.invalid"]);
  });

  it("Permissions-Policy: pass, missing (info), malformed", () => {
    expect(checkPermissionsPolicy(obs({ https: ok({ "permissions-policy": "camera=(), geolocation=(self)" }) })).status).toBe("pass");
    expect(checkPermissionsPolicy(obs()).findings[0]).toMatchObject({ findingId: "header.permissions-policy.missing", severity: "info" });
    expect(ids(checkPermissionsPolicy(obs({ https: ok({ "permissions-policy": "camera 'none'" }) })))).toEqual(["header.permissions-policy.malformed"]);
  });

  it("framing: frame-ancestors or X-Frame-Options pass; missing, permissive and obsolete values fail", () => {
    expect(checkFraming(obs({ https: ok({ "content-security-policy": "frame-ancestors 'none'" }) })).status).toBe("pass");
    expect(checkFraming(obs({ https: ok({ "x-frame-options": "SAMEORIGIN" }) })).status).toBe("pass");
    expect(ids(checkFraming(obs()))).toEqual(["header.framing.missing"]);
    expect(ids(checkFraming(obs({ https: ok({ "content-security-policy": "frame-ancestors *" }) })))).toEqual(["header.framing.permissive-frame-ancestors"]);
    expect(ids(checkFraming(obs({ https: ok({ "x-frame-options": "ALLOW-FROM https://a.example" }) })))).toEqual(["header.framing.invalid-x-frame-options"]);
    expect(ids(checkFraming(obs({ https: ok({ "x-frame-options": ["DENY", "SAMEORIGIN"] }) })))).toEqual(["header.framing.invalid-x-frame-options"]);
  });

  it("CORS: none or a fixed origin pass; wildcard with credentials and reflected probe origin fail", () => {
    expect(checkCors(obs()).status).toBe("pass");
    expect(checkCors(obs({ https: ok({ "access-control-allow-origin": "*" }) })).status).toBe("pass");
    expect(checkCors(obs({ https: ok({ "access-control-allow-origin": "https://app.example.com", "access-control-allow-credentials": "true" }) })).status).toBe("pass");
    expect(ids(checkCors(obs({ https: ok({ "access-control-allow-origin": "*", "access-control-allow-credentials": "true" }) })))).toEqual([
      "cors.wildcard-with-credentials",
    ]);
    const reflected = checkCors(obs({ https: ok({ "access-control-allow-origin": CORS_PROBE_ORIGIN, "access-control-allow-credentials": "true" }) }));
    expect(reflected.findings[0]).toMatchObject({ findingId: "cors.reflected-origin-with-credentials", severity: "high" });
    expect(ids(checkCors(obs({ https: ok({ "access-control-allow-origin": CORS_PROBE_ORIGIN }) })))).toEqual(["cors.reflected-origin"]);
  });

  it("version disclosure: plain names pass; versions in Server or X-Powered-By fail", () => {
    expect(checkDisclosure(obs({ https: ok({ server: "nginx" }) })).status).toBe("pass");
    expect(ids(checkDisclosure(obs({ https: ok({ server: "nginx/1.27.0", "x-powered-by": "PHP/7.4.3" }) })))).toEqual([
      "header.version-disclosure.server",
      "header.version-disclosure.x-powered-by",
    ]);
    expect(ids(checkDisclosure(obs({ https: ok({ server: "Apache/2.4.62 (Unix)" }) })))).toEqual(["header.version-disclosure.server"]);
  });
});

describe("cookie check", () => {
  const SECRET_VALUE = "sess_value_VERY_SECRET_9f8e7d6c5b4a";

  it("passes well-flagged cookies and reports missing flags by name only", () => {
    expect(checkCookies(obs({ https: ok({ "set-cookie": `sid=${SECRET_VALUE}; Secure; HttpOnly; SameSite=Lax; Path=/` }) })).status).toBe("pass");
    const check = checkCookies(obs({ https: ok({ "set-cookie": [`sid=${SECRET_VALUE}`, "pref=dark; Secure; SameSite=Strict", "x=1; SameSite=None"] }) }));
    expect(ids(check).sort()).toEqual(["cookies.httponly-missing", "cookies.samesite-missing", "cookies.samesite-none-without-secure", "cookies.secure-missing"]);
    expect(JSON.stringify(check)).not.toContain(SECRET_VALUE);
    expect(JSON.stringify(check)).toContain("sid");
  });

  it("parses names and flags but never values; odd names are masked", () => {
    const parsed = parseCookieFlags([`sid=${SECRET_VALUE}; secure; HTTPONLY; samesite=strict`, "<script>=x", "a=b; SameSite=Weird"]);
    expect(parsed).toEqual([
      { name: "sid", secure: true, httpOnly: true, sameSite: "strict" },
      { name: "[unusual name]", secure: false, httpOnly: false, sameSite: null },
      { name: "a", secure: false, httpOnly: false, sameSite: "invalid" },
    ]);
    expect(JSON.stringify(parsed)).not.toContain(SECRET_VALUE);
  });

  it("does not require Secure on a plain-HTTP lab target", () => {
    const lab = parseLabOrigin("http://127.0.0.1:8081")!;
    const check = checkCookies(obs({ target: lab, http: ok({ "set-cookie": "sid=1; HttpOnly; SameSite=Lax" }) }));
    expect(check.status).toBe("pass");
  });
});

describe("security.txt check", () => {
  const txt = (body: string, headers: Record<string, string> = { "content-type": "text/plain; charset=utf-8" }, status = 200) =>
    ok(headers, { status, body: Buffer.from(body) });

  it("passes a valid file and never echoes its contents", () => {
    const check = checkSecurityTxt(obs({ securityTxt: txt("Contact: mailto:security@example.com\nExpires: 2027-06-01T00:00:00Z\n") }));
    expect(check).toMatchObject({ status: "pass", findings: [] });
    expect(JSON.stringify(check)).not.toContain("security@example.com");
  });
  it("reports a missing file (404 or an HTML page) as informational", () => {
    expect(checkSecurityTxt(obs({ securityTxt: txt("not found", {}, 404) })).findings[0]).toMatchObject({ findingId: "security-txt.missing", severity: "info" });
    expect(ids(checkSecurityTxt(obs({ securityTxt: txt("<html>", { "content-type": "text/html" }) })))).toEqual(["security-txt.missing"]);
  });
  it("reports missing fields and expiry as misconfiguration", () => {
    expect(ids(checkSecurityTxt(obs({ securityTxt: txt("Expires: 2027-06-01T00:00:00Z\n") })))).toEqual(["security-txt.no-contact"]);
    expect(ids(checkSecurityTxt(obs({ securityTxt: txt("Contact: mailto:a@example.com\n") })))).toEqual(["security-txt.expires-count"]);
    expect(ids(checkSecurityTxt(obs({ securityTxt: txt("Contact: mailto:a@example.com\nExpires: 2020-01-01T00:00:00Z\n") })))).toEqual(["security-txt.expired"]);
    expect(ids(checkSecurityTxt(obs({ securityTxt: txt("Contact: mailto:a@example.com\nExpires: someday\n") })))).toEqual(["security-txt.expires-invalid"]);
  });
  it("errors when the request itself failed", () => {
    expect(checkSecurityTxt(obs({ securityTxt: failed("timeout") })).status).toBe("error");
  });
});

describe("evidence hygiene", () => {
  it("redacts secret-shaped header values and strips control characters", () => {
    // Built at runtime so the source holds no credential-shaped literal for the repository secret scan.
    const fakeKey = `sk-proj-${"A".repeat(28)}`;
    const check = checkDisclosure(obs({ https: ok({ server: `nginx/1.27.0 token=${fakeKey}\r\nInjected: 1` }) }));
    const evidenceText = check.findings[0]!.evidence;
    expect(evidenceText).not.toContain("sk-proj-AAAA");
    expect(evidenceText).not.toMatch(/[\r\n]/);
    expect(evidenceText.length).toBeLessThanOrEqual(200);
  });
});
