import {
  errored,
  evidence,
  notApplicable,
  result,
  type CheckResult,
  type Finding,
  type PassiveObservations,
} from "../findings.js";

const DAY_MS = 86_400_000;
/** Node's verification code when the certificate is not valid for the requested host name. */
export const HOSTNAME_MISMATCH_CODE = "ERR_TLS_CERT_ALTNAME_INVALID";
const UNTRUSTED_CODES = new Set([
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "CERT_UNTRUSTED",
  "CERT_REVOKED",
  "CERT_SIGNATURE_FAILURE",
]);

/** TLS: certificate trust, host-name match, validity period, and the negotiated protocol. */
export function checkTls(obs: PassiveObservations): CheckResult {
  const id = "tls";
  const title = "TLS certificate and protocol";
  if (obs.target.kind === "lab") return notApplicable(id, title, "Lab targets are plain HTTP.");
  const https = obs.https;
  if (!https) return errored(id, title, "HTTPS was not attempted.");
  const findings: Finding[] = [];
  const base = { checkId: id, references: ["CWE-295", "OWASP A02:2021 Cryptographic Failures"] };

  if (!https.ok) {
    if (https.reason !== "connection-failed" && https.reason !== "timeout") {
      return errored(id, title, `HTTPS could not be checked (${https.reason}).`);
    }
    findings.push({
      ...base,
      findingId: "tls.unavailable",
      severity: "high",
      confidence: "medium",
      title: "HTTPS is not available",
      explanation:
        "No HTTPS response was received on port 443. Visitors cannot use an encrypted connection. A temporary outage gives the same result, so confidence is medium.",
      evidence: evidence(`https://${obs.target.hostname}/ ${https.reason}`),
      remediation: "Serve the site over HTTPS on port 443 with a certificate from a trusted authority.",
      references: ["CWE-319", "OWASP A02:2021 Cryptographic Failures"],
    });
    return result(id, title, findings, "");
  }
  const tls = https.tls;
  if (!tls || !tls.certificate) return errored(id, title, "No certificate details were available.");
  const cert = tls.certificate;

  // One condition, one finding: Node reports a host-name mismatch both through our
  // own identity check and as the verification code ERR_TLS_CERT_ALTNAME_INVALID.
  // Either signal alone is enough to report it (fail closed).
  const hostnameMismatch = !tls.hostnameMatches || tls.authorizationError === HOSTNAME_MISMATCH_CODE;
  if (hostnameMismatch) {
    findings.push({
      ...base,
      findingId: "tls.hostname-mismatch",
      severity: "high",
      confidence: "high",
      title: "Certificate does not match the host name",
      explanation: "Browsers reject this certificate for this host name, and users who click through are exposed to interception.",
      evidence: evidence(`host ${obs.target.hostname}; certificate CN ${cert.subjectCN ?? "none"}; SAN ${cert.subjectAltNames.join(", ") || "none"}`),
      remediation: "Issue a certificate whose subject alternative names include this exact host name.",
      references: ["CWE-297", "OWASP A02:2021 Cryptographic Failures"],
    });
  }

  const validTo = cert.validTo ? Date.parse(cert.validTo) : Number.NaN;
  const validFrom = cert.validFrom ? Date.parse(cert.validFrom) : Number.NaN;
  const now = obs.now.getTime();
  const expired = tls.authorizationError === "CERT_HAS_EXPIRED" || (!Number.isNaN(validTo) && validTo < now);
  if (expired) {
    findings.push({
      ...base,
      findingId: "tls.certificate-expired",
      severity: "high",
      confidence: "high",
      title: "Certificate has expired",
      explanation: "Browsers show a security error for expired certificates.",
      evidence: evidence(`valid to ${cert.validTo ?? "unknown"}`),
      remediation: "Renew the certificate and automate renewal.",
    });
  } else if (tls.authorizationError === "CERT_NOT_YET_VALID" || (!Number.isNaN(validFrom) && validFrom > now)) {
    findings.push({
      ...base,
      findingId: "tls.certificate-not-yet-valid",
      severity: "high",
      confidence: "high",
      title: "Certificate is not yet valid",
      explanation: "The certificate's validity period has not started, so browsers reject it.",
      evidence: evidence(`valid from ${cert.validFrom ?? "unknown"}`),
      remediation: "Check the server clock and the certificate's validity dates.",
    });
  } else if (!Number.isNaN(validTo) && validTo - now < 30 * DAY_MS) {
    const days = Math.max(0, Math.floor((validTo - now) / DAY_MS));
    findings.push({
      ...base,
      findingId: "tls.certificate-expiring",
      severity: days < 14 ? "medium" : "low",
      confidence: "high",
      title: "Certificate expires soon",
      explanation: `The certificate expires in ${days} day(s). Without renewal, browsers will start rejecting it.`,
      evidence: evidence(`valid to ${cert.validTo}`),
      remediation: "Renew the certificate before it expires and automate renewal.",
    });
  }

  if (tls.authorizationError && UNTRUSTED_CODES.has(tls.authorizationError)) {
    findings.push({
      ...base,
      findingId: "tls.certificate-untrusted",
      severity: "high",
      confidence: "high",
      title: "Certificate is not trusted",
      explanation: "The certificate chain does not lead to a trusted authority (for example, it is self-signed or an intermediate is missing).",
      evidence: evidence(`verification error ${tls.authorizationError}; issuer ${cert.issuerCN ?? "unknown"}`),
      remediation: "Use a certificate from a publicly trusted authority and serve the full intermediate chain.",
    });
  } else if (
    !tls.authorized &&
    !expired &&
    tls.authorizationError !== null &&
    tls.authorizationError !== "CERT_NOT_YET_VALID" &&
    // Already reported above as tls.hostname-mismatch.
    tls.authorizationError !== HOSTNAME_MISMATCH_CODE
  ) {
    findings.push({
      ...base,
      findingId: "tls.certificate-invalid",
      severity: "high",
      confidence: "medium",
      title: "Certificate failed verification",
      explanation: "The certificate chain failed verification for a reason other than expiry or trust.",
      evidence: evidence(`verification error ${tls.authorizationError}`),
      remediation: "Review the certificate and chain with your certificate authority's tooling.",
    });
  }

  if (tls.protocol === "TLSv1" || tls.protocol === "TLSv1.1") {
    findings.push({
      ...base,
      findingId: "tls.legacy-protocol",
      severity: "medium",
      confidence: "high",
      title: "Legacy TLS version negotiated",
      explanation: "TLS 1.0 and 1.1 are deprecated (RFC 8996).",
      evidence: evidence(`negotiated ${tls.protocol}`),
      remediation: "Disable TLS 1.0 and 1.1; offer TLS 1.2 and 1.3 only.",
    });
  }
  return result(id, title, findings, `Valid certificate for this host name; ${tls.protocol ?? "unknown protocol"} negotiated.`);
}

/** HTTP to HTTPS: a plain-HTTP request should be redirected to HTTPS on the same host. */
export function checkHttpsRedirect(obs: PassiveObservations): CheckResult {
  const id = "https-redirect";
  const title = "HTTP to HTTPS redirect";
  if (obs.target.kind === "lab") return notApplicable(id, title, "Lab targets are plain HTTP.");
  const http = obs.http;
  if (!http) return errored(id, title, "HTTP was not attempted.");
  if (!http.ok) {
    if (http.reason === "connection-failed" || http.reason === "timeout") {
      return { checkId: id, title, status: "pass", summary: "Port 80 did not answer, so nothing is served over plain HTTP.", findings: [] };
    }
    return errored(id, title, `HTTP could not be checked (${http.reason}).`);
  }
  const base = { checkId: id, references: ["CWE-319", "OWASP A02:2021 Cryptographic Failures"] };
  const location = http.headers.location?.[0];
  if ([301, 302, 303, 307, 308].includes(http.status) && location) {
    let next: URL | null = null;
    try {
      next = new URL(location, http.url);
    } catch {
      next = null;
    }
    if (next?.protocol === "https:" && next.hostname === obs.target.hostname) {
      const permanent = http.status === 301 || http.status === 308;
      return result(
        id,
        title,
        permanent
          ? []
          : [
              {
                ...base,
                findingId: "https-redirect.temporary",
                severity: "info",
                confidence: "high",
                title: "Redirect to HTTPS is temporary",
                explanation: "A permanent redirect (301 or 308) lets browsers and caches remember to use HTTPS.",
                evidence: evidence(`HTTP ${http.status} to ${next.origin}`),
                remediation: "Use a 301 or 308 redirect, and HSTS.",
              },
            ],
        `Plain HTTP redirects to HTTPS (${http.status}).`,
      );
    }
    return result(
      id,
      title,
      [
        {
          ...base,
          findingId: "https-redirect.not-to-https",
          severity: "low",
          confidence: "medium",
          title: "HTTP does not redirect to HTTPS on this host",
          explanation: "The plain-HTTP response redirects somewhere other than HTTPS on the same host. The destination was not followed or checked.",
          evidence: evidence(`HTTP ${http.status} to ${next ? next.origin : "an invalid location"}`),
          remediation: "Redirect every plain-HTTP request to the same path over HTTPS on this host.",
        },
      ],
      "",
    );
  }
  if (http.status >= 200 && http.status < 300) {
    return result(
      id,
      title,
      [
        {
          ...base,
          findingId: "https-redirect.missing",
          severity: "medium",
          confidence: "high",
          title: "Content served over plain HTTP",
          explanation: "The site answers plain-HTTP requests with content instead of redirecting to HTTPS, so traffic can be read or altered in transit.",
          evidence: evidence(`http://${obs.target.hostname}/ answered HTTP ${http.status}`),
          remediation: "Redirect all plain-HTTP requests to HTTPS with a 301 or 308, and enable HSTS.",
        },
      ],
      "",
    );
  }
  return notApplicable(id, title, `Plain HTTP answered ${http.status}; no content and no redirect.`);
}
