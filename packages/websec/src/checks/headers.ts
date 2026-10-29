import { redactSecretValue } from "@agentshield/engine";
import {
  errored,
  evidence,
  headerValues,
  notApplicable,
  primaryResponse,
  result,
  type CheckResult,
  type Finding,
  type PassiveObservations,
} from "../findings.js";
import type { FetchResult } from "../fetcher.js";

const MISCONFIG = "OWASP A05:2021 Security Misconfiguration";

/** Shared preamble: the check needs a successful primary response. */
function primary(obs: PassiveObservations, id: string, title: string): FetchResult | CheckResult {
  const response = primaryResponse(obs);
  if (!response) return errored(id, title, "The site was not fetched.");
  if (!response.ok) return errored(id, title, `The site could not be fetched (${response.reason}).`);
  return response;
}

function isCheckResult(value: FetchResult | CheckResult): value is CheckResult {
  return "checkId" in value;
}

/** Directive name to value for a CSP-style header ("a b; c d"). Later duplicates are ignored, as browsers do. */
function directives(policy: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const part of policy.split(";")) {
    const [name, ...values] = part.trim().split(/\s+/);
    if (name && !out.has(name.toLowerCase())) out.set(name.toLowerCase(), values.map((v) => v.toLowerCase()));
  }
  return out;
}

export function checkHsts(obs: PassiveObservations): CheckResult {
  const id = "header.hsts";
  const title = "Strict-Transport-Security (HSTS)";
  if (obs.target.kind === "lab") return notApplicable(id, title, "Browsers ignore HSTS over plain HTTP.");
  const response = primary(obs, id, title);
  if (isCheckResult(response)) return response;
  const values = headerValues(response, "strict-transport-security");
  const base = { checkId: id, references: ["CWE-319", "CWE-693", MISCONFIG] };
  const findings: Finding[] = [];
  if (values.length === 0) {
    findings.push({
      ...base,
      findingId: "header.hsts.missing",
      severity: "medium",
      confidence: "high",
      title: "HSTS header missing",
      explanation: "Without HSTS, a browser's first request can be made over plain HTTP and downgraded by an attacker on the network path. This is a hardening gap, not a demonstrated attack.",
      evidence: "No Strict-Transport-Security header on the HTTPS response.",
      remediation: "Send Strict-Transport-Security: max-age=31536000; includeSubDomains on HTTPS responses.",
    });
    return result(id, title, findings, "");
  }
  if (values.length > 1) {
    findings.push({
      ...base,
      findingId: "header.hsts.duplicate",
      severity: "low",
      confidence: "high",
      title: "Multiple HSTS headers",
      explanation: "Browsers use only the first Strict-Transport-Security header; duplicates usually mean conflicting configuration.",
      evidence: evidence(`${values.length} headers: ${values.join(" | ")}`),
      remediation: "Send exactly one Strict-Transport-Security header.",
    });
  }
  const maxAge = /(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?:;|$)/i.exec(values[0]!);
  if (!maxAge) {
    findings.push({
      ...base,
      findingId: "header.hsts.malformed",
      severity: "low",
      confidence: "high",
      title: "HSTS header has no valid max-age",
      explanation: "A Strict-Transport-Security header without a valid max-age is ignored by browsers.",
      evidence: evidence(values[0]!),
      remediation: "Use Strict-Transport-Security: max-age=31536000; includeSubDomains.",
    });
  } else if (Number(maxAge[1]) === 0) {
    findings.push({
      ...base,
      findingId: "header.hsts.disabled",
      severity: "medium",
      confidence: "high",
      title: "HSTS is switched off (max-age=0)",
      explanation: "max-age=0 tells browsers to forget the site's HSTS policy.",
      evidence: evidence(values[0]!),
      remediation: "Set max-age to at least 31536000 (one year) unless you are deliberately retiring HTTPS.",
    });
  } else if (Number(maxAge[1]) < 15_552_000) {
    findings.push({
      ...base,
      findingId: "header.hsts.short-max-age",
      severity: "low",
      confidence: "high",
      title: "HSTS max-age is short",
      explanation: "A max-age under 180 days leaves gaps in protection between visits.",
      evidence: evidence(values[0]!),
      remediation: "Use a max-age of at least 31536000 (one year).",
    });
  }
  return result(id, title, findings, "HSTS is enabled with a long max-age.");
}

const UNSAFE_SOURCES = ["'unsafe-inline'", "'unsafe-eval'", "*", "http:", "https:", "data:"];

export function checkCsp(obs: PassiveObservations): CheckResult {
  const id = "header.csp";
  const title = "Content-Security-Policy";
  const response = primary(obs, id, title);
  if (isCheckResult(response)) return response;
  const base = { checkId: id, references: ["CWE-693", "CWE-79", MISCONFIG] };
  const enforced = headerValues(response, "content-security-policy");
  const reportOnly = headerValues(response, "content-security-policy-report-only");
  if (enforced.length === 0) {
    return result(
      id,
      title,
      [
        {
          ...base,
          findingId: reportOnly.length > 0 ? "header.csp.report-only" : "header.csp.missing",
          severity: reportOnly.length > 0 ? "low" : "medium",
          confidence: "medium",
          title: reportOnly.length > 0 ? "CSP is only in report-only mode" : "Content-Security-Policy header missing",
          explanation:
            "Without an enforced CSP, an injected script runs with the page's privileges. A policy set in an HTML meta tag is not checked here, hence medium confidence. This is a hardening gap, not proof of a cross-site scripting flaw.",
          evidence: reportOnly.length > 0 ? evidence(`report-only: ${reportOnly[0]}`) : "No Content-Security-Policy header on the response.",
          remediation: "Send an enforced Content-Security-Policy that restricts script-src to trusted sources (nonces or hashes instead of 'unsafe-inline').",
        },
      ],
      "",
    );
  }
  const policy = directives(enforced[0]!);
  const scriptSources = policy.get("script-src") ?? policy.get("default-src");
  const findings: Finding[] = [];
  if (!scriptSources) {
    findings.push({
      ...base,
      findingId: "header.csp.no-script-restriction",
      severity: "low",
      confidence: "high",
      title: "CSP does not restrict scripts",
      explanation: "The policy has neither script-src nor default-src, so scripts from any source are allowed.",
      evidence: evidence(enforced[0]!),
      remediation: "Add a script-src (or default-src) directive limited to trusted sources.",
    });
  } else {
    const usesNonceOrHash = scriptSources.some((s) => /^'(nonce-|sha256-|sha384-|sha512-)/.test(s));
    const unsafe = scriptSources.filter((s) => UNSAFE_SOURCES.includes(s) && !(s === "'unsafe-inline'" && usesNonceOrHash));
    if (unsafe.length > 0) {
      findings.push({
        ...base,
        findingId: "header.csp.unsafe-script-sources",
        severity: "low",
        confidence: "high",
        title: "CSP allows unsafe script sources",
        explanation: `The script policy allows ${unsafe.join(", ")}, which weakens the protection CSP gives against injected scripts.`,
        evidence: evidence(enforced[0]!),
        remediation: "Remove 'unsafe-inline', 'unsafe-eval' and wildcard or scheme-only sources; use nonces or hashes.",
      });
    }
  }
  return result(id, title, findings, "An enforced CSP restricts script sources.");
}

export function checkContentTypeOptions(obs: PassiveObservations): CheckResult {
  const id = "header.x-content-type-options";
  const title = "X-Content-Type-Options";
  const response = primary(obs, id, title);
  if (isCheckResult(response)) return response;
  const values = headerValues(response, "x-content-type-options");
  if (values.length === 1 && values[0]!.trim().toLowerCase() === "nosniff") return result(id, title, [], "nosniff is set.");
  const missing = values.length === 0;
  return result(
    id,
    title,
    [
      {
        checkId: id,
        findingId: missing ? "header.x-content-type-options.missing" : "header.x-content-type-options.invalid",
        severity: "low",
        confidence: "high",
        title: missing ? "X-Content-Type-Options header missing" : "X-Content-Type-Options has an invalid value",
        explanation: "Without nosniff, some browsers may guess a response's content type, which can turn uploaded or reflected content into script.",
        evidence: missing ? "No X-Content-Type-Options header." : evidence(values.join(" | ")),
        remediation: "Send exactly X-Content-Type-Options: nosniff.",
        references: ["CWE-693", MISCONFIG],
      },
    ],
    "",
  );
}

const REFERRER_POLICIES = new Set([
  "no-referrer",
  "no-referrer-when-downgrade",
  "origin",
  "origin-when-cross-origin",
  "same-origin",
  "strict-origin",
  "strict-origin-when-cross-origin",
  "unsafe-url",
]);

export function checkReferrerPolicy(obs: PassiveObservations): CheckResult {
  const id = "header.referrer-policy";
  const title = "Referrer-Policy";
  const response = primary(obs, id, title);
  if (isCheckResult(response)) return response;
  const base = { checkId: id, references: ["CWE-200", MISCONFIG] };
  const values = headerValues(response, "referrer-policy");
  if (values.length === 0) {
    return result(
      id,
      title,
      [
        {
          ...base,
          findingId: "header.referrer-policy.missing",
          severity: "info",
          confidence: "high",
          title: "Referrer-Policy header missing",
          explanation: "Modern browsers default to strict-origin-when-cross-origin, so the impact is small; an explicit policy documents intent and covers older browsers.",
          evidence: "No Referrer-Policy header.",
          remediation: "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
        },
      ],
      "",
    );
  }
  // Browsers apply the last token they recognize.
  const tokens = values.join(",").split(",").map((t) => t.trim().toLowerCase()).filter(Boolean);
  const effective = [...tokens].reverse().find((t) => REFERRER_POLICIES.has(t));
  if (!effective) {
    return result(
      id,
      title,
      [
        {
          ...base,
          findingId: "header.referrer-policy.invalid",
          severity: "low",
          confidence: "high",
          title: "Referrer-Policy has no valid value",
          explanation: "Browsers ignore unrecognized policies and fall back to their default.",
          evidence: evidence(values.join(" | ")),
          remediation: "Use a valid policy such as strict-origin-when-cross-origin.",
        },
      ],
      "",
    );
  }
  if (effective === "unsafe-url" || effective === "no-referrer-when-downgrade") {
    return result(
      id,
      title,
      [
        {
          ...base,
          findingId: "header.referrer-policy.leaky",
          severity: "low",
          confidence: "high",
          title: "Referrer-Policy sends full URLs to other sites",
          explanation: `The effective policy ${effective} sends the full page URL, including paths and query strings, to other sites.`,
          evidence: evidence(values.join(" | ")),
          remediation: "Use strict-origin-when-cross-origin or a stricter policy.",
        },
      ],
      "",
    );
  }
  return result(id, title, [], `Effective policy: ${effective}.`);
}

export function checkPermissionsPolicy(obs: PassiveObservations): CheckResult {
  const id = "header.permissions-policy";
  const title = "Permissions-Policy";
  const response = primary(obs, id, title);
  if (isCheckResult(response)) return response;
  const values = headerValues(response, "permissions-policy");
  const base = { checkId: id, references: [MISCONFIG] };
  if (values.length === 0) {
    return result(
      id,
      title,
      [
        {
          ...base,
          findingId: "header.permissions-policy.missing",
          severity: "info",
          confidence: "high",
          title: "Permissions-Policy header missing",
          explanation: "A Permissions-Policy limits powerful browser features (camera, microphone, geolocation) to the origins that need them. Its absence is a hardening opportunity.",
          evidence: "No Permissions-Policy header.",
          remediation: "Send a Permissions-Policy that disables features the site does not use, e.g. camera=(), microphone=(), geolocation=().",
        },
      ],
      "",
    );
  }
  const wellFormed = values.every((value) => value.split(",").every((entry) => /^\s*[a-z0-9-]+=(\*|\(.*\)|self|"[^"]*")\s*$/i.test(entry)));
  if (!wellFormed) {
    return result(
      id,
      title,
      [
        {
          ...base,
          findingId: "header.permissions-policy.malformed",
          severity: "low",
          confidence: "medium",
          title: "Permissions-Policy is malformed",
          explanation: "Browsers ignore a Permissions-Policy they cannot parse, so the intended restrictions may not apply. Feature-Policy syntax (spaces instead of =) is a common cause.",
          evidence: evidence(values.join(" | ")),
          remediation: "Use structured-header syntax: feature=(allowlist), e.g. geolocation=().",
        },
      ],
      "",
    );
  }
  return result(id, title, [], "A Permissions-Policy is set.");
}

export function checkFraming(obs: PassiveObservations): CheckResult {
  const id = "header.framing";
  const title = "Framing protection (frame-ancestors / X-Frame-Options)";
  const response = primary(obs, id, title);
  if (isCheckResult(response)) return response;
  const base = { checkId: id, references: ["CWE-1021", MISCONFIG] };
  const csp = headerValues(response, "content-security-policy")[0];
  const frameAncestors = csp ? directives(csp).get("frame-ancestors") : undefined;
  if (frameAncestors && frameAncestors.length > 0) {
    const permissive = frameAncestors.includes("*") || frameAncestors.includes("https:") || frameAncestors.includes("http:");
    return permissive
      ? result(
          id,
          title,
          [
            {
              ...base,
              findingId: "header.framing.permissive-frame-ancestors",
              severity: "medium",
              confidence: "high",
              title: "frame-ancestors allows any site to frame the page",
              explanation: "Any site can embed this page in a frame, which enables clickjacking against logged-in users.",
              evidence: evidence(`frame-ancestors ${frameAncestors.join(" ")}`),
              remediation: "Use frame-ancestors 'none' or 'self' (plus specific trusted origins if needed).",
            },
          ],
          "",
        )
      : result(id, title, [], "CSP frame-ancestors restricts framing.");
  }
  const xfo = headerValues(response, "x-frame-options");
  const value = xfo[0]?.trim().toUpperCase();
  if (xfo.length === 1 && (value === "DENY" || value === "SAMEORIGIN")) return result(id, title, [], `X-Frame-Options: ${value}.`);
  if (xfo.length === 0) {
    return result(
      id,
      title,
      [
        {
          ...base,
          findingId: "header.framing.missing",
          severity: "medium",
          confidence: "medium",
          title: "No framing protection",
          explanation: "Neither CSP frame-ancestors nor X-Frame-Options is set, so other sites can frame this page. That matters for pages with actions a user could be tricked into clicking (clickjacking); static pages are less affected.",
          evidence: "No frame-ancestors directive and no X-Frame-Options header.",
          remediation: "Send Content-Security-Policy: frame-ancestors 'none' (or 'self'), optionally with X-Frame-Options: DENY for older browsers.",
        },
      ],
      "",
    );
  }
  return result(
    id,
    title,
    [
      {
        ...base,
        findingId: "header.framing.invalid-x-frame-options",
        severity: "low",
        confidence: "high",
        title: "X-Frame-Options value is not effective",
        explanation: "Only DENY and SAMEORIGIN are supported by current browsers; ALLOW-FROM, unknown values and duplicates are ignored, leaving the page frameable.",
        evidence: evidence(xfo.join(" | ")),
        remediation: "Use CSP frame-ancestors for allowlists, or X-Frame-Options: DENY or SAMEORIGIN.",
      },
    ],
    "",
  );
}

/** CORS: a wildcard with credentials, or our probe Origin reflected back. */
export function checkCors(obs: PassiveObservations): CheckResult {
  const id = "cors";
  const title = "Cross-origin resource sharing (CORS)";
  const response = primary(obs, id, title);
  if (isCheckResult(response)) return response;
  const base = { checkId: id, references: ["CWE-942", MISCONFIG] };
  const allowOrigin = headerValues(response, "access-control-allow-origin")[0]?.trim();
  const credentials = headerValues(response, "access-control-allow-credentials")[0]?.trim().toLowerCase() === "true";
  if (!allowOrigin) return result(id, title, [], "No CORS headers on the landing page.");
  const findings: Finding[] = [];
  if (allowOrigin === obs.probeOrigin) {
    findings.push({
      ...base,
      findingId: credentials ? "cors.reflected-origin-with-credentials" : "cors.reflected-origin",
      severity: credentials ? "high" : "low",
      confidence: credentials ? "high" : "medium",
      title: credentials ? "Arbitrary Origin reflected with credentials allowed" : "Arbitrary Origin reflected",
      explanation: credentials
        ? "The server echoed an unrelated test Origin and allowed credentials, so any website could read this response with a visitor's cookies. Confirm on authenticated endpoints before acting."
        : "The server echoed an unrelated test Origin. Without credentials the impact is limited to public data.",
      evidence: evidence(`Access-Control-Allow-Origin echoed the probe origin; Allow-Credentials ${credentials}`),
      remediation: "Allow only an explicit list of trusted origins; never reflect the request's Origin.",
    });
  } else if (allowOrigin === "*" && credentials) {
    findings.push({
      ...base,
      findingId: "cors.wildcard-with-credentials",
      severity: "medium",
      confidence: "high",
      title: "Wildcard origin combined with credentials",
      explanation: "Browsers refuse this combination, so it does not leak data by itself, but it shows an intent to allow credentialed cross-origin access that is easy to turn into origin reflection.",
      evidence: evidence("Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true"),
      remediation: "Remove Access-Control-Allow-Credentials or replace * with an explicit trusted origin.",
    });
  }
  return result(id, title, findings, `CORS allows ${allowOrigin === "*" ? "any origin without credentials" : "a fixed origin"}.`);
}

/** Server / X-Powered-By headers that reveal software versions. */
export function checkDisclosure(obs: PassiveObservations): CheckResult {
  const id = "header.version-disclosure";
  const title = "Software version disclosure";
  const response = primary(obs, id, title);
  if (isCheckResult(response)) return response;
  const findings: Finding[] = [];
  for (const name of ["server", "x-powered-by"]) {
    const values = headerValues(response, name);
    const versioned = values.filter((value) => /\d+\.\d+|\/\s*\d/.test(value));
    if (versioned.length > 0) {
      findings.push({
        checkId: id,
        findingId: `header.version-disclosure.${name}`,
        severity: "low",
        confidence: "high",
        title: `${name === "server" ? "Server" : "X-Powered-By"} header reveals a version`,
        explanation: "Version numbers help attackers match known vulnerabilities to the site. Hiding them is defence in depth, not a fix for outdated software.",
        evidence: evidence(`${name}: ${versioned.join(" | ")}`),
        remediation: name === "server" ? "Remove the version from the Server header (e.g. nginx server_tokens off)." : "Remove the X-Powered-By header.",
        references: ["CWE-497", MISCONFIG],
      });
    }
  }
  return result(id, title, findings, "No version numbers in Server or X-Powered-By.");
}

interface CookieFlags {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
}

/** Parses Set-Cookie headers to names and flags only. Cookie values are discarded here and never stored. */
export function parseCookieFlags(headers: string[]): CookieFlags[] {
  return headers.slice(0, 50).map((header) => {
    const [pair = "", ...attributes] = header.split(";");
    const rawName = pair.split("=")[0]!.trim();
    const safeName = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/.test(rawName) ? redactSecretValue(rawName) : "[unusual name]";
    let secure = false;
    let httpOnly = false;
    let sameSite: string | null = null;
    for (const attribute of attributes) {
      const [key = "", value = ""] = attribute.split("=").map((s) => s.trim());
      const lower = key.toLowerCase();
      if (lower === "secure") secure = true;
      else if (lower === "httponly") httpOnly = true;
      else if (lower === "samesite") sameSite = /^(strict|lax|none)$/i.test(value) ? value.toLowerCase() : "invalid";
    }
    return { name: safeName, secure, httpOnly, sameSite };
  });
}

export function checkCookies(obs: PassiveObservations): CheckResult {
  const id = "cookies";
  const title = "Cookie security flags";
  const response = primary(obs, id, title);
  if (isCheckResult(response)) return response;
  const cookies = parseCookieFlags(headerValues(response, "set-cookie"));
  if (cookies.length === 0) return result(id, title, [], "The landing page sets no cookies.");
  const https = obs.target.kind === "dns";
  const names = (list: CookieFlags[]) => list.map((c) => c.name).join(", ");
  const findings: Finding[] = [];
  const noSecure = https ? cookies.filter((c) => !c.secure) : [];
  if (noSecure.length > 0) {
    findings.push({
      checkId: id,
      findingId: "cookies.secure-missing",
      severity: "medium",
      confidence: "high",
      title: "Cookies without the Secure flag",
      explanation: "These cookies can be sent over plain HTTP, where they can be intercepted.",
      evidence: evidence(`cookies: ${names(noSecure)}`),
      remediation: "Set the Secure attribute on every cookie served over HTTPS.",
      references: ["CWE-614", "OWASP A05:2021 Security Misconfiguration"],
    });
  }
  const noneWithoutSecure = cookies.filter((c) => c.sameSite === "none" && !c.secure);
  if (noneWithoutSecure.length > 0) {
    findings.push({
      checkId: id,
      findingId: "cookies.samesite-none-without-secure",
      severity: "medium",
      confidence: "high",
      title: "SameSite=None without Secure",
      explanation: "Current browsers reject SameSite=None cookies that lack Secure, so these cookies may silently not work.",
      evidence: evidence(`cookies: ${names(noneWithoutSecure)}`),
      remediation: "Add Secure to SameSite=None cookies, or use SameSite=Lax.",
      references: ["CWE-1275", "OWASP A05:2021 Security Misconfiguration"],
    });
  }
  const noSameSite = cookies.filter((c) => c.sameSite === null || c.sameSite === "invalid");
  if (noSameSite.length > 0) {
    findings.push({
      checkId: id,
      findingId: "cookies.samesite-missing",
      severity: "low",
      confidence: "high",
      title: "Cookies without a valid SameSite attribute",
      explanation: "Browsers then apply their own default (usually Lax). An explicit value documents the intended cross-site behaviour.",
      evidence: evidence(`cookies: ${names(noSameSite)}`),
      remediation: "Set SameSite=Lax or Strict (or None with Secure where cross-site use is needed).",
      references: ["CWE-1275", "OWASP A05:2021 Security Misconfiguration"],
    });
  }
  const noHttpOnly = cookies.filter((c) => !c.httpOnly);
  if (noHttpOnly.length > 0) {
    findings.push({
      checkId: id,
      findingId: "cookies.httponly-missing",
      severity: "low",
      confidence: "low",
      title: "Cookies readable by scripts (no HttpOnly)",
      explanation: "Scripts on the page, including injected ones, can read these cookies. Some cookies must be readable by scripts, so confirm whether any of them hold session data.",
      evidence: evidence(`cookies: ${names(noHttpOnly)}`),
      remediation: "Set HttpOnly on session and authentication cookies.",
      references: ["CWE-1004", "OWASP A05:2021 Security Misconfiguration"],
    });
  }
  return result(id, title, findings, `${cookies.length} cookie(s) set with appropriate flags.`);
}
