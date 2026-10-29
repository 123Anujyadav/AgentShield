import { errored, evidence, headerValues, result, type CheckResult, type Finding, type PassiveObservations } from "../findings.js";

/** RFC 9116: /.well-known/security.txt, served as text/plain, with Contact and a future Expires. */
export function checkSecurityTxt(obs: PassiveObservations): CheckResult {
  const id = "security-txt";
  const title = "security.txt (RFC 9116)";
  const response = obs.securityTxt;
  if (!response) return errored(id, title, "security.txt was not requested.");
  if (!response.ok && response.reason !== "body-too-large") {
    return errored(id, title, `security.txt could not be fetched (${response.reason}).`);
  }
  const base = { checkId: id, references: ["RFC 9116"] };
  const missing = (explanation: string, observed: string): CheckResult =>
    result(
      id,
      title,
      [
        {
          ...base,
          findingId: "security-txt.missing",
          severity: "info",
          confidence: "high",
          title: "No security.txt",
          explanation: `${explanation} security.txt tells researchers how to report vulnerabilities; it is recommended, not required.`,
          evidence: evidence(observed),
          remediation: "Publish /.well-known/security.txt (text/plain) with at least one Contact and an Expires date within a year.",
        },
      ],
      "",
    );
  if (!response.ok) return missing("The file is larger than the read limit, so it was not read.", "Response exceeded the 32 KB read limit.");
  if (response.status !== 200) return missing("The file was not found.", `HTTP ${response.status}`);
  const contentType = headerValues(response, "content-type")[0]?.toLowerCase() ?? "";
  if (!contentType.startsWith("text/plain")) {
    // Many sites answer every path with an HTML page; that is not a security.txt file.
    return missing("The server returned a page that is not text/plain.", `content-type: ${contentType || "none"}`);
  }
  const text = (response.body ?? Buffer.alloc(0)).toString("utf8");
  const fields = text
    .split(/\r?\n/)
    .map((line) => /^([A-Za-z-]+):\s*(.*)$/.exec(line.trim()))
    .filter((match): match is RegExpExecArray => match !== null)
    .map((match) => [match[1]!.toLowerCase(), match[2]!.trim()] as const);
  const contacts = fields.filter(([name]) => name === "contact");
  const expires = fields.filter(([name]) => name === "expires");
  const findings: Finding[] = [];
  const invalid = (findingId: string, titleText: string, explanation: string, observed: string) =>
    findings.push({
      ...base,
      findingId,
      severity: "low",
      confidence: "high",
      title: titleText,
      explanation,
      evidence: evidence(observed),
      remediation: "Fix security.txt so it has at least one Contact and exactly one future Expires date (RFC 9116).",
    });
  if (contacts.length === 0) invalid("security-txt.no-contact", "security.txt has no Contact", "Contact is required by RFC 9116.", "No Contact field.");
  if (expires.length !== 1) {
    invalid("security-txt.expires-count", "security.txt must have exactly one Expires", "Expires is required exactly once by RFC 9116.", `${expires.length} Expires field(s).`);
  } else {
    const at = Date.parse(expires[0]![1]);
    if (Number.isNaN(at)) invalid("security-txt.expires-invalid", "security.txt Expires is not a valid date", "Expires must be an RFC 3339 date-time.", "Expires is not a date.");
    else if (at < obs.now.getTime()) invalid("security-txt.expired", "security.txt has expired", "An expired security.txt should be treated as stale by researchers.", `Expires ${new Date(at).toISOString()}`);
  }
  // Only field counts and dates are reported; the file's text is not stored.
  return result(id, title, findings, `security.txt present with ${contacts.length} contact(s).`);
}
