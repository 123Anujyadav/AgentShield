import type { Finding } from "../types.js";
import { SCANNER_RULES } from "./rules.js";

export type ScannerStatus = "clean" | "suspicious" | "empty";

export interface ScannerResult {
  status: ScannerStatus;
  findings: Finding[];
  contentLength: number;
}

export const MAX_SCAN_LENGTH = 8000;

/** Explicit credential labels: a plausible value after one of these is a secret. */
const STRONG_LABEL =
  "(?:aws[-_ ]?secret[-_ ]?access[-_ ]?key|db[-_ ]?password|client[-_ ]?secret|secret[-_ ]?key|private[-_ ]?key|api[-_ ]?key|x-api-key|access[-_ ]?token|refresh[-_ ]?token|session[-_ ]?token|auth[-_ ]?token|password|passwd)";
/** Generic labels: the value must also look like a credential. */
const WEAK_LABEL = "(?:secret|token)";

/**
 * Email addresses. The lookbehind anchors the local part at the start of its
 * character run, so each run is tried once and matching stays linear in the
 * input length. The earlier `\b`-anchored form restarted inside long dotted
 * runs and backtracked quadratically.
 */
const EMAIL_SOURCE = "(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b";

/**
 * Evidence redaction. Uses the same label family as the outbound detector,
 * but redacts any labelled value regardless of shape: evidence is display
 * text, so over-redacting a count is harmless while leaking a value is not.
 * A value that opens with a quote is redacted through its matching closing
 * quote, or to the end of the text when the quote is never closed, so a
 * multi-word quoted secret cannot leak its later words. A quote preceded
 * by a backslash is escaped and does not terminate the value; an escaped
 * backslash (\\) before a quote leaves that quote terminating.
 */
const SECRET_VALUE_PATTERNS: RegExp[] = [
  new RegExp(
    `["']?(?:${STRONG_LABEL}|${WEAK_LABEL})["']?\\s*[:=]\\s*(?:"(?:\\\\.|[^"\\\\])*(?:"|$)|'(?:\\\\.|[^'\\\\])*(?:'|$)|\\S+)`,
    "gi",
  ),
  /\bBearer\s+\S+/gi,
  /\bsk-[A-Za-z0-9_-]{6,}/gi,
  /\bFAKE_[A-Z0-9_]*SECRET[A-Z0-9_]*\b/g,
  new RegExp(EMAIL_SOURCE, "g"),
];

export interface OutboundSecretMatch {
  /** Which supported pattern matched, e.g. "labelled-secret-assignment". */
  kind: string;
  /** Field that carried the value, e.g. "action.payload.note" or "action.summary". */
  field: string;
}

/**
 * Maximum characters per outbound field that can be fully inspected.
 * Fields up to this length are scanned in full (no silent truncation);
 * longer fields are reported as uninspectable and hard-BLOCKed instead of
 * being silently allowed. Aligns with MAX_SCAN_LENGTH for untrusted content.
 */
export const MAX_OUTBOUND_FIELD_LENGTH = 8000;

const NON_SECRET_VALUES = new Set(["true", "false", "null", "none", "remaining", "redacted"]);

function cleanValue(value: string): string {
  return value.replace(/^["']|["']$/g, "");
}

/**
 * Longest labelled value captured at once. Bounds per-match work; a value that
 * fills the whole capture is an unbroken run of at least this length and is
 * treated as credential-shaped (fail closed).
 */
const LABELLED_VALUE_CAPTURE_LIMIT = 256;

/** Generic labels (token, secret): the value must look like a credential, not a count, boolean, or tier name. */
function isSecretShapedValue(value: string): boolean {
  if (value.length >= LABELLED_VALUE_CAPTURE_LIMIT) return true;
  const v = cleanValue(value);
  if (v.length < 8) return false;
  if (/^\d+$/.test(v)) return false;
  if (NON_SECRET_VALUES.has(v.toLowerCase())) return false;
  if (!/[A-Za-z]/.test(v)) return false;
  // Prose-like values (e.g. "unlimited-tier") carry no digit, separator-run, or dot.
  return /\d/.test(v) || /_/.test(v) || /\./.test(v);
}

/**
 * Strong credential labels (password, key, client_secret, ...): an explicit
 * credential label is enough with a plausible value, so short or purely
 * numeric passwords such as password=abc1234 or password=12345678 count.
 * Counts and booleans (token: 42, secret: false) still do not, because those
 * use generic labels or non-credential values.
 */
function isStrongLabelValue(value: string): boolean {
  const v = cleanValue(value);
  if (v.length < 6) return false;
  if (NON_SECRET_VALUES.has(v.toLowerCase())) return false;
  return /[A-Za-z0-9]/.test(v);
}

const LABELLED_SECRET_SOURCE = `["']?(?:(${STRONG_LABEL})|(${WEAK_LABEL}))["']?\\s*[:=]\\s*(["']?)`;
const UNQUOTED_VALUE_PATTERN = new RegExp(`^[^\\s"']{1,${LABELLED_VALUE_CAPTURE_LIMIT}}`);
/**
 * Quote-tolerant reading of the same unquoted value: a quote character inside
 * the value (password=O'Brien...) must not end it early. It stops at structural
 * delimiters instead, so JSON/dict neighbours ({"password":null,"user":...})
 * still read as the short value null rather than swallowing the next field.
 */
const QUOTE_TOLERANT_VALUE_PATTERN = new RegExp(`^[^\\s,;)\\]}]{1,${LABELLED_VALUE_CAPTURE_LIMIT}}`);

/** Index of the next unescaped occurrence of `quote` at or after `from`, or -1. */
function findUnescapedQuote(text: string, quote: string, from: number): number {
  for (let i = from; i < text.length; i += 1) {
    if (text[i] === "\\") {
      i += 1; // Skip the escaped character (also handles \\ before a quote).
      continue;
    }
    if (text[i] === quote) return i;
  }
  return -1;
}

/**
 * Checks every labelled occurrence, including labels nested inside a previous
 * value. A value capture can swallow a later assignment ("token:password=...",
 * "secret=api-key:..."), so after a non-secret match the scan resumes at the
 * start of that value rather than after it, and the swallowed label is then
 * judged on its own.
 *
 * Quoted values are judged on their complete contents through the matching
 * unescaped closing quote, using the same quote boundaries as the evidence
 * redactor. An unclosed quoted value fails closed: it is treated as a
 * credential so it can neither bypass detection nor leak through public
 * approval or evidence output.
 */
function hasLabelledSecret(text: string): boolean {
  const pattern = new RegExp(LABELLED_SECRET_SOURCE, "gi");
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    const [whole, strongLabel, , openingQuote = ""] = match;
    const valueStart = match.index + whole.length;
    if (openingQuote) {
      const closing = findUnescapedQuote(text, openingQuote, valueStart);
      if (closing === -1) return true; // Unclosed quote: fail closed.
      const contents = text.slice(valueStart, closing);
      if (contents.length > 0 && (strongLabel ? isStrongLabelValue(contents) : isSecretShapedValue(contents))) {
        return true;
      }
      pattern.lastIndex = valueStart; // Rescan inside for a nested label.
      continue;
    }
    const rest = text.slice(valueStart);
    const judge = strongLabel ? isStrongLabelValue : isSecretShapedValue;
    const value = UNQUOTED_VALUE_PATTERN.exec(rest)?.[0] ?? "";
    if (judge(value)) return true;
    const tolerant = QUOTE_TOLERANT_VALUE_PATTERN.exec(rest)?.[0] ?? "";
    if (tolerant !== value && judge(tolerant)) return true;
    // The label and separator are non-empty, so this always moves forward.
    pattern.lastIndex = valueStart;
  }
  return false;
}

/** Bearer credentials must carry a digit, underscore, or dot; ordinary prose after "bearer" does not match. */
function hasBearerSecret(text: string): boolean {
  const pattern = /\bBearer\s+([A-Za-z0-9.__\-]{8,})/gi;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    const token = match[1] ?? "";
    if (token.length >= 16 || /\d/.test(token) || /_/.test(token) || /\./.test(token)) return true;
  }
  return false;
}

/**
 * Realistic sk-style tokens: separators after the prefix are allowed
 * (sk-proj-..., sk-ant-api03-..., sk-FAKE_FAKE_...), but the suffix must be
 * long and contain a digit, so sk-learn-pipeline stays benign.
 */
function hasSkStyleSecret(text: string): boolean {
  const pattern = /\bsk-([A-Za-z0-9_-]{12,})/gi;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    const suffix = match[1] ?? "";
    if (/[A-Za-z]/.test(suffix) && /\d/.test(suffix)) return true;
  }
  return false;
}

const SIMPLE_SECRET_DETECTORS: { kind: string; pattern: RegExp }[] = [
  { kind: "seeded-fake-secret", pattern: /\bFAKE_[A-Z0-9_]*SECRET[A-Z0-9_]*\b/ },
  { kind: "email-address", pattern: new RegExp(EMAIL_SOURCE) },
];

/**
 * Secret-shaped patterns the outbound Data-Leak Guard can recognize: the
 * redactor's family plus labelled variants (access_token, client_secret,
 * auth_token, private_key, refresh_token, session_token, secret_key,
 * db_password, aws_secret_access_key, x-api-key, JSON-style quoted keys).
 * It is not comprehensive secret detection. Unlabelled high-entropy values,
 * split or encoded secrets, and formats outside this list are not recognized.
 */

/**
 * Builds the labelled form of one flat payload entry. The value is quoted (and
 * its quotes/backslashes escaped) so the whole field is judged as one value: a
 * multi-word or quote-containing value cannot end early at its first space or
 * quote. Nested labels inside the value are still rescanned. Used by both the
 * evaluator and public redaction so they agree on every payload entry.
 */
export function payloadAssignment(key: string, value: string): string {
  return `${key}=${JSON.stringify(value)}`;
}

/**
 * Inspects one outbound field for a recognized secret-shaped value.
 * Fields up to MAX_OUTBOUND_FIELD_LENGTH are scanned in full. A longer
 * field returns kind "field-too-long-to-inspect" so callers hard-BLOCK it
 * instead of silently truncating the scan. Non-string input never throws
 * and never matches. Returns only the pattern kind and field name.
 */
export function detectOutboundSecret(field: string, text: unknown): OutboundSecretMatch | null {
  if (typeof text !== "string" || text.length === 0) return null;
  if (text.length > MAX_OUTBOUND_FIELD_LENGTH) {
    return { kind: "field-too-long-to-inspect", field };
  }
  if (hasLabelledSecret(text)) return { kind: "labelled-secret-assignment", field };
  if (hasBearerSecret(text)) return { kind: "bearer-token", field };
  if (hasSkStyleSecret(text)) return { kind: "sk-style-token", field };
  for (const detector of SIMPLE_SECRET_DETECTORS) {
    if (detector.pattern.test(text)) return { kind: detector.kind, field };
  }
  return null;
}

/** Redact seeded-secret-shaped values and addresses. Applied to all evidence. */
export function redactEvidence(text: string): string {
  let out = text.replace(/\s+/g, " ").trim();
  for (const pattern of SECRET_VALUE_PATTERNS) out = out.replace(pattern, "[REDACTED]");
  return out.length > 160 ? `${out.slice(0, 157)}...` : out;
}

function sentenceAround(text: string, index: number): string {
  const start = Math.max(text.lastIndexOf(".", index - 1), text.lastIndexOf("\n", index - 1)) + 1;
  const endDot = text.indexOf(".", index);
  const end = endDot === -1 ? Math.min(text.length, index + 160) : endDot + 1;
  return text.slice(start, end).trim();
}

/** Character ranges of every secret-shaped span the redactor recognizes. */
function secretSpans(text: string): [number, number][] {
  const spans: [number, number][] = [];
  for (const pattern of SECRET_VALUE_PATTERNS) {
    for (const m of text.matchAll(pattern)) {
      const at = m.index ?? 0;
      spans.push([at, at + m[0].length]);
    }
  }
  return spans;
}

function evidenceAround(text: string, index: number, matchLength: number, spans: [number, number][]): string {
  let start = Math.max(0, index - 30);
  let end = Math.min(text.length, index + matchLength + 50);
  // Never cut a secret-shaped span in half: a window edge inside a span is
  // widened to cover it, so the redactor sees the whole label and value.
  let widened = true;
  while (widened) {
    widened = false;
    for (const [s, e] of spans) {
      if (s < start && e > start) {
        start = s;
        widened = true;
      }
      if (s < end && e > end) {
        end = e;
        widened = true;
      }
    }
  }
  return redactEvidence(text.slice(start, end));
}

/**
 * Scan explicitly labelled untrusted content. The content is treated as data:
 * it is never executed, evaluated as code, or followed as instruction.
 * Malformed input (non-string, null) returns an empty result, never throws.
 */
export function scanUntrustedContent(input: unknown): ScannerResult {
  if (typeof input !== "string" || input.trim().length === 0) {
    return { status: "empty", findings: [], contentLength: 0 };
  }
  const text = input.slice(0, MAX_SCAN_LENGTH);
  const findings: Finding[] = [];
  let spans: [number, number][] | null = null;

  for (const rule of SCANNER_RULES) {
    let matched: RegExpExecArray | null = null;
    for (const pattern of rule.patterns) {
      pattern.lastIndex = 0;
      matched = pattern.exec(text);
      if (matched) break;
    }
    if (!matched) continue;

    const sentence = sentenceAround(text, matched.index);
    if (rule.suppressIfSentenceMatches?.some((guard) => guard.test(sentence))) continue;

    findings.push({
      ruleId: rule.ruleId,
      category: "injection",
      severity: rule.severity,
      title: rule.title,
      explanation: `${rule.explanation} (rule-based matching, not an ML classifier)`,
      evidence: evidenceAround(text, matched.index, matched[0].length, (spans ??= secretSpans(text))),
    });
  }

  return { status: findings.length > 0 ? "suspicious" : "clean", findings, contentLength: text.length };
}
