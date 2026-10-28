import type { Finding } from "../types.js";
import { SCANNER_RULES, type ScannerRule } from "./rules.js";

export type ScannerStatus = "clean" | "suspicious" | "empty";

export interface ScannerResult {
  status: ScannerStatus;
  findings: Finding[];
  contentLength: number;
}

export const MAX_SCAN_LENGTH = 8000;

/** Explicit credential labels: a plausible value after one of these is a secret. */
const STRONG_LABEL =
  "(?:aws[-_ ]?secret[-_ ]?access[-_ ]?key|db[-_ ]?password|client[-_ ]?secret|secret[-_ ]?key|private[-_ ]?key|api[-_ ]?key|x-api-key|access[-_ ]?token|refresh[-_ ]?token|session[-_ ]?token|auth[-_ ]?token|passphrase|password|passwd)";
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
 * Phase H provider credential formats. Prefixes are case-sensitive, and a
 * prefix glued to a preceding letter, digit, or underscore (`my_ghp_...`) is
 * not matched, the same rule as for `sk-` tokens. `accept` adds a digit check
 * where the prefix also starts ordinary words: `ASIA...` (ASIAPACIFIC...) and
 * Slack's `xox` (xoxo is excluded from the prefix set entirely).
 */
interface ProviderTokenFormat {
  kind: string;
  pattern: RegExp;
  accept?: (token: string) => boolean;
}

const PROVIDER_TOKEN_FORMATS: ProviderTokenFormat[] = [
  {
    kind: "aws-access-key-id",
    pattern: /(?<![A-Za-z0-9_])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9_])/g,
    accept: (token) => token.startsWith("AKIA") || /\d/.test(token.slice(4)),
  },
  { kind: "github-token", pattern: /(?<![A-Za-z0-9_])(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})/g },
  { kind: "gitlab-token", pattern: /(?<![A-Za-z0-9_])glpat-[A-Za-z0-9_-]{20,}/g },
  { kind: "stripe-live-key", pattern: /(?<![A-Za-z0-9_])(?:sk|rk)_live_[A-Za-z0-9]{24,}/g },
  { kind: "slack-token", pattern: /(?<![A-Za-z0-9_])xox[abprs]-[A-Za-z0-9-]{10,}/g, accept: (token) => /\d/.test(token.slice(5)) },
  { kind: "google-api-key", pattern: /(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/g },
];

/**
 * PEM private-key armor header for the RSA, EC, DSA, OPENSSH, ENCRYPTED, and
 * plain PKCS#8 forms only. Public keys, certificates, and PGP key blocks are
 * different armor labels and are not matched.
 */
const PEM_PRIVATE_KEY_HEADER = "-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----";

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
  // Phase H provider formats run first, so a labelled pattern below cannot
  // split a private-key header (private_key=-----BEGIN ...) before it is seen.
  // A private-key header is redacted through its END line, or to the end of
  // the text when there is none, even when no key material follows (display
  // text: over-redacting documentation is harmless). Token formats are
  // redacted without the detector's digit checks for the same reason.
  new RegExp(`${PEM_PRIVATE_KEY_HEADER}[\\s\\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`, "g"),
  ...PROVIDER_TOKEN_FORMATS.map((format) => format.pattern),
  // Backslash-escaped JSON form ({\"api_key\": \"...\"} as literal text).
  // The value runs to just before its escaped closing quote (or the end of
  // the text). The closing boundary is a lookahead, not consumed: consuming
  // it would swallow the next field's opening quote when fields are adjacent
  // or a value ends in an escaped backslash, and that field's credential
  // would then never match. A bare quote inside the value does not stop it,
  // and a lone trailing backslash is left behind by the lookahead, so
  // malformed and truncated values are still redacted in full (fail closed).
  new RegExp(
    `\\\\"[^"\\\\]*?(?:${STRONG_LABEL}|${WEAK_LABEL})\\\\"\\s*:\\s*\\\\"[\\s\\S]*?(?=\\\\"|\\\\?$)`,
    "gi",
  ),
  new RegExp(
    `["']?(?:${STRONG_LABEL}|${WEAK_LABEL})["']?\\s*(?:=>|[:=])\\s*(?:"(?:\\\\.|[^"\\\\])*(?:"|$)|'(?:\\\\.|[^'\\\\])*(?:'|$)|\\S+)`,
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

const LABELLED_SECRET_SOURCE = `["']?(?:(${STRONG_LABEL})|(${WEAK_LABEL}))["']?\\s*(=>|[:=])\\s*(["']?)`;

/**
 * A call or method call: `name(`, `a.b.c(`, `name (`, `a ?.b(`. Each chain
 * step needs a dot, so the identifier runs cannot backtrack into each other.
 */
const ARROW_CALL_BODY = /^[A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$][\w$]*)*\s*\(/;
/** After the label: `.x`, `?.x`, or `[`, optionally after whitespace (`token ["x"]`). */
const LABEL_ACCESS = /^\s*(?:\??\.|\[)/;

/**
 * `=>` is also JavaScript arrow-function syntax. `token => token.trim()` or
 * `password => hash(password)` names a parameter; it does not assign a value.
 * An unquoted `=>` value that is a call, or a member access on the label
 * itself, is read as code rather than a credential. A literal value such as
 * `token => abc123` or a dotted JWT-like value is still judged normally.
 */
function isArrowFunctionBody(rest: string, label: string): boolean {
  if (ARROW_CALL_BODY.test(rest)) return true;
  return rest.slice(0, label.length).toLowerCase() === label.toLowerCase() && LABEL_ACCESS.test(rest.slice(label.length));
}

/** A character that can end an expression piece: a name, a dot, or a closing bracket. */
const EXPRESSION_TAIL = /[A-Za-z0-9_$.)\]]/;
/** After a quote glued to an expression, these show it closes enclosing text instead. */
const CLOSING_QUOTE_FOLLOWER = /[\s,.;:!?)\]}]/;
/** Top-level whitespace followed by one of these continues the expression (`x .then(...)`). */
const EXPRESSION_CONTINUATION = /^\s*(?:\?\.|[.[(])/;

interface ArrowBodyWord {
  text: string;
  start: number;
  end: number;
}

interface ArrowBody {
  /** Index just past the arrow expression. */
  end: number;
  /** False when the expression ran past the capture limit or a quote never closed. */
  inspectable: boolean;
  words: ArrowBodyWord[];
  strings: { text: string; start: number }[];
}

const OPENERS = "([{";
const CLOSERS = ")]}";

/**
 * Reads one arrow-function expression starting at `start`. It follows nested
 * brackets and quoted strings, and stops where the expression ends: `,` or
 * `;` at the top level, a closing bracket that belongs to an enclosing call,
 * or top-level whitespace not followed by `.`, `?.`, `[`, or `(` (so
 * `send(x) .then(...)` and multi-line chains stay one expression).
 *
 * Quotes: a quote glued to the expression (after a name, `.`, `)`, or `]`)
 * is not valid code. It only ends the expression when whitespace, punctuation,
 * or the end of the text follows it, which is how quoted prose or a
 * JSON-quoted payload value closes; otherwise (`token.x"value`) the expression
 * fails closed. A quote that starts an operand (after `(`, `,`, `+`, `[`) is
 * read as a string. Escaped quotes (\" in a JSON-quoted value) follow the same
 * rules. The expression must end within LABELLED_VALUE_CAPTURE_LIMIT
 * characters and every string must close, or it is reported as not
 * inspectable (fail closed).
 */
function readArrowBody(text: string, start: number): ArrowBody {
  const limit = start + LABELLED_VALUE_CAPTURE_LIMIT;
  const words: ArrowBodyWord[] = [];
  const strings: { text: string; start: number }[] = [];
  const failClosed = (): ArrowBody => ({ end: text.length, inspectable: false, words, strings });
  let depth = 0;
  let i = start;
  while (i < text.length) {
    if (i >= limit) return { end: i, inspectable: false, words, strings };
    const c = text[i] ?? "";
    const next = text[i + 1] ?? "";
    const escapedQuote = c === "\\" && (next === '"' || next === "'");
    if (escapedQuote || c === '"' || c === "'" || c === "`") {
      const quote = escapedQuote ? next : c;
      const width = escapedQuote ? 2 : 1;
      const glued = i > start && EXPRESSION_TAIL.test(text[i - 1] ?? "");
      if (glued) {
        const follower = text[i + width];
        if (depth === 0 && (follower === undefined || CLOSING_QUOTE_FOLLOWER.test(follower))) break;
        return failClosed();
      }
      const close = escapedQuote ? text.indexOf(`\\${quote}`, i + 2) : findUnescapedQuote(text, quote, i + 1);
      if (close === -1 || close >= limit) {
        // An unclosed top-level quote that ends the text closes the enclosing value.
        if (depth === 0 && i + width >= text.length) break;
        return failClosed();
      }
      strings.push({ text: text.slice(i + width, close), start: i });
      i = close + width;
      continue;
    }
    if (OPENERS.includes(c)) {
      depth += 1;
    } else if (CLOSERS.includes(c)) {
      if (depth === 0) break;
      depth -= 1;
    } else if (depth === 0 && (c === "," || c === ";")) {
      break;
    } else if (depth === 0 && /\s/.test(c)) {
      // Whitespace continues the expression when a member access is still open
      // (`token . name`, `token ?. name`, a dot on its own line) or when the
      // next token continues it (`x .then(...)`); otherwise the expression ends.
      const previous = previousNonSpace(text, i - 1);
      const afterDot = previous >= start && text[previous] === ".";
      if (!afterDot && !EXPRESSION_CONTINUATION.test(text.slice(i, limit))) break;
    } else if (/[A-Za-z0-9_$]/.test(c)) {
      let j = i + 1;
      while (j < text.length && /[A-Za-z0-9_$]/.test(text[j] ?? "")) j += 1;
      words.push({ text: text.slice(i, j), start: i, end: j });
      i = j;
      continue;
    }
    i += 1;
  }
  return { end: i, inspectable: true, words, strings };
}

function longestDigitRun(word: string): number {
  return Math.max(0, ...(word.match(/\d+/g) ?? []).map((run) => run.length));
}

function letterDigitSwitches(word: string): number {
  return (word.match(/[A-Za-z](?=\d)|\d(?=[A-Za-z])/g) ?? []).length;
}

/**
 * Credential evidence that holds wherever a word sits in code: a run of 5+
 * digits (identifiers carry versions, sizes, and years of at most 4 digits),
 * or 4+ letter/digit switches (a1b2c3...). Bare numbers of 8+ digits count too.
 */
function isCredentialShapedWord(word: string): boolean {
  if (/^\d+$/.test(word)) return word.length >= 8;
  return longestDigitRun(word) >= 5 || letterDigitSwitches(word) >= 4;
}

/**
 * A property name read (not called) from the labelled parameter must be an
 * ordinary lowercase-first name of at most 20 characters; a longer read-only
 * name keeps the original D-1 member rule and counts as a disguised value.
 */
const PLAIN_PROPERTY_NAME = /^[a-z][A-Za-z_]{0,19}$/;
/** A long capitalised letters-only word in a value position reads as a passphrase, not a name. */
const PASSPHRASE_WORD = /^[A-Z][A-Za-z]{19,}$/;

/**
 * M-2 policy for string literals inside a labelled arrow body: a single token
 * of 8+ letters and digits that mixes upper case, lower case, and a digit has
 * the shape of a password ('Hunter2024x') and counts as a credential. Codec,
 * algorithm, and format names ('base64url', 'aes256gcm', 'HS256', 'utf8') do
 * not mix all three. Lower-case-only or symbol-split credentials in a literal
 * are a documented residual.
 */
function isPasswordShapedLiteral(literal: string): boolean {
  return /^[A-Za-z0-9]{8,}$/.test(literal) && /[a-z]/.test(literal) && /[A-Z]/.test(literal) && /\d/.test(literal);
}

/**
 * Policy for labelled `=>` arrow bodies (Phase D-1 remediation): names are
 * code, values are evidence. The whole expression is inspected, and any of
 * the following is a credential:
 * - any word or string literal with a 5+ digit run or 4+ letter/digit switches;
 * - a property read on the labelled parameter (`password.x.y`, `token[...]`,
 *   `send(token.y)`) that is not invoked and is not a plain lowercase-first
 *   name, so `password.Hunter2024x` or `password.CorrectHorseBatter` block
 *   while `secret.isActive` and `token.length` do not;
 * - a capitalised letters-only word of 20+ characters in a value position
 *   (a passphrase such as `CorrectHorseBatteryStaple` passed as an argument);
 * - a string literal used as a key on the parameter that is not a plain name,
 *   or any string literal containing a 12+ letter-and-digit run.
 * Called names (`toBase64String()`, `getAuthorizationHeaderValue()`,
 * `hashPasswordV2(...)`) are judged only by the digit rules above.
 */
function arrowBodyHasCredential(text: string, body: ArrowBody, label: string): boolean {
  const lowerLabel = label.toLowerCase();
  const byEnd = new Map(body.words.map((w) => [w.end, w]));
  // Member and bracket links tolerate whitespace (`password .x`, `token ?. x`,
  // `token [ "k" ]`), matching how readArrowBody keeps spaced chains together.
  const memberOwner = (word: ArrowBodyWord): ArrowBodyWord | undefined => {
    const dot = previousNonSpace(text, word.start - 1);
    if (text[dot] !== ".") return undefined;
    const beforeDot = text[dot - 1] === "?" ? dot - 2 : dot - 1;
    return byEnd.get(previousNonSpace(text, beforeDot) + 1);
  };
  const bracketOwner = (start: number): ArrowBodyWord | undefined => {
    const bracket = previousNonSpace(text, start - 1);
    if (text[bracket] !== "[") return undefined;
    return byEnd.get(previousNonSpace(text, bracket - 1) + 1);
  };
  const chainRoot = (word: ArrowBodyWord): ArrowBodyWord => {
    let current = word;
    for (let owner = memberOwner(current); owner; owner = memberOwner(current)) current = owner;
    return current;
  };
  const isParam = (word: ArrowBodyWord | undefined) => word !== undefined && word.text.toLowerCase() === lowerLabel;

  for (const word of body.words) {
    if (isCredentialShapedWord(word.text)) return true;
    if (isParam(word)) continue;
    // Only a call written directly against the name (`x()`) exempts it; a
    // spaced `(` keeps the stricter property-name rules.
    const invoked = text[word.end] === "(";
    if (invoked) continue;
    const root = chainRoot(word);
    const isParamProperty = root !== word && isParam(root);
    // A bare word inside brackets directly on the parameter (token[x]) is a key read.
    const isParamIndex = isParam(bracketOwner(word.start));
    if ((isParamProperty || isParamIndex) && !PLAIN_PROPERTY_NAME.test(word.text) && !/^\d+$/.test(word.text)) return true;
    if (PASSPHRASE_WORD.test(word.text)) return true;
  }

  for (const literal of body.strings) {
    const owner = bracketOwner(literal.start);
    if (owner && (isParam(owner) || isParam(chainRoot(owner))) && !PLAIN_PROPERTY_NAME.test(literal.text)) return true;
    for (const run of literal.text.match(/[A-Za-z0-9]{12,}/g) ?? []) {
      if (/[A-Za-z]/.test(run) && /\d/.test(run)) return true;
    }
    if (isPasswordShapedLiteral(literal.text)) return true;
    for (const word of literal.text.match(/[A-Za-z0-9_$]+/g) ?? []) {
      if (isCredentialShapedWord(word) || PASSPHRASE_WORD.test(word)) return true;
    }
  }
  return false;
}

/** Spans [label start, expression end) of every labelled unquoted `=>` value, for evidence redaction. */
function arrowValueSpans(text: string): [number, number][] {
  const spans: [number, number][] = [];
  const pattern = new RegExp(LABELLED_SECRET_SOURCE, "gi");
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    const [whole, , , separator, openingQuote = ""] = match;
    const valueStart = match.index + whole.length;
    if (separator === "=>" && !openingQuote) {
      const body = readArrowBody(text, valueStart);
      if (!body.inspectable) {
        // Fail closed: redact to the end, which already covers every later match.
        spans.push([match.index, text.length]);
        break;
      }
      spans.push([match.index, body.end]);
    }
    pattern.lastIndex = valueStart;
  }
  return spans;
}
const UNQUOTED_VALUE_PATTERN = new RegExp(`^[^\\s"']{1,${LABELLED_VALUE_CAPTURE_LIMIT}}`);
/**
 * Quote-tolerant reading of the same unquoted value: a quote character inside
 * the value (password=O'Brien...) must not end it early. It stops at structural
 * delimiters instead, so JSON/dict neighbours ({"password":null,"user":...})
 * still read as the short value null rather than swallowing the next field.
 */
const QUOTE_TOLERANT_VALUE_PATTERN = new RegExp(`^[^\\s,;)\\]}]{1,${LABELLED_VALUE_CAPTURE_LIMIT}}`);

/** Index of the last non-whitespace character at or before `index`, or -1. */
function previousNonSpace(text: string, index: number): number {
  let i = index;
  while (i >= 0 && /\s/.test(text[i] ?? "")) i -= 1;
  return i;
}

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
 * Owner-approved Phase G (Option A): only the exact backslash-escaped
 * JSON-style labelled assignment shape ({\"api_key\": \"...\"} written as
 * literal text) is normalized, by judging the value inside its escaped
 * quotes with the existing label rules. No general unescaping is performed:
 * Windows paths, regex examples, and other backslash text are untouched.
 * An unclosed escaped value fails closed, like an unclosed quoted value.
 */
function hasEscapedJsonLabelledSecret(text: string): boolean {
  // The label may sit inside a longer quoted key (`user_password`), matching
  // how the ordinary JSON form finds the label as a substring of the key.
  const pattern = new RegExp(`\\\\"[^"\\\\]*?(?:(${STRONG_LABEL})|(${WEAK_LABEL}))\\\\"\\s*:\\s*\\\\"`, "gi");
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    const [, strongLabel] = match;
    const valueStart = match.index + match[0].length;
    const closing = text.indexOf('\\"', valueStart);
    if (closing === -1) return true; // Unclosed escaped quote: fail closed.
    const contents = text.slice(valueStart, closing);
    if (contents.length > 0 && (strongLabel ? isStrongLabelValue(contents) : isSecretShapedValue(contents))) {
      return true;
    }
    pattern.lastIndex = valueStart; // Keep scanning for a later escaped label.
  }
  return false;
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
  if (hasEscapedJsonLabelledSecret(text)) return true;
  const pattern = new RegExp(LABELLED_SECRET_SOURCE, "gi");
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    const [whole, strongLabel, weakLabel, separator, openingQuote = ""] = match;
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
    const arrowLabel = strongLabel ?? weakLabel ?? "";
    if (separator === "=>" && isArrowFunctionBody(rest, arrowLabel)) {
      // Judge the whole arrow expression and decide here: evidence of a
      // credential (or an expression too long to inspect) is a BLOCK, never a
      // fall-through to reading only the first token of the value.
      const body = readArrowBody(text, valueStart);
      if (!body.inspectable || arrowBodyHasCredential(text, body, arrowLabel)) return true;
      pattern.lastIndex = valueStart; // Ordinary code; keep scanning for later labels.
      continue;
    }
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

/**
 * A private-key header blocks only when key material follows it: after
 * optional whitespace or literal \n / \r escapes (a key inside a JSON string),
 * either a legacy encrypted-PEM `Proc-Type:` line or a run of 32+ base64
 * characters mixing upper case, lower case, and a digit. A header on its own,
 * or followed by an elided or placeholder body (`MIIEvQ...`, `<your key>`,
 * `XXXX...`), is documentation and does not block.
 */
function hasPrivateKeyBlock(text: string): boolean {
  for (const header of text.matchAll(new RegExp(PEM_PRIVATE_KEY_HEADER, "g"))) {
    const rest = text.slice((header.index ?? 0) + header[0].length);
    const body = rest.slice(/^(?:\s|\\[nr])*/.exec(rest)?.[0].length ?? 0);
    if (body.startsWith("Proc-Type:")) return true;
    const run = /^[A-Za-z0-9+/]{32,}/.exec(body)?.[0];
    if (run && /[a-z]/.test(run) && /[A-Z]/.test(run) && /\d/.test(run)) return true;
  }
  return false;
}

/** The kind of the first provider credential format found, or null. */
function providerCredentialKind(text: string): string | null {
  if (hasPrivateKeyBlock(text)) return "private-key-block";
  for (const format of PROVIDER_TOKEN_FORMATS) {
    for (const match of text.matchAll(format.pattern)) {
      if (!format.accept || format.accept(match[0])) return format.kind;
    }
  }
  return null;
}

const SIMPLE_SECRET_DETECTORS: { kind: string; pattern: RegExp }[] = [
  { kind: "seeded-fake-secret", pattern: /\bFAKE_[A-Z0-9_]*SECRET[A-Z0-9_]*\b/ },
  { kind: "email-address", pattern: new RegExp(EMAIL_SOURCE) },
];

/**
 * Secret-shaped patterns the outbound Data-Leak Guard can recognize: the
 * redactor's family plus labelled variants (access_token, client_secret,
 * auth_token, private_key, refresh_token, session_token, secret_key,
 * db_password, aws_secret_access_key, x-api-key, JSON-style quoted keys), and
 * since Phase H seven provider formats: PEM private-key blocks, AWS access key
 * IDs, GitHub, GitLab, Stripe live, Slack, and Google API key tokens.
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
  const providerKind = providerCredentialKind(text);
  if (providerKind) return { kind: providerKind, field };
  for (const detector of SIMPLE_SECRET_DETECTORS) {
    if (detector.pattern.test(text)) return { kind: detector.kind, field };
  }
  return null;
}

/**
 * Whole-value display redaction for echoed request metadata (Phase I): a value
 * the Data-Leak Guard recognizes (detectOutboundSecret) is shown as
 * [REDACTED], and any other value is returned unchanged. Display only: it
 * never affects a decision, and a redacted value is not thereby safe to send.
 */
export function redactSecretValue(value: string): string {
  return detectOutboundSecret("display", value) ? "[REDACTED]" : value;
}

/** Replaces each span (merged where they overlap) with [REDACTED]. */
function redactSpans(text: string, spans: [number, number][]): string {
  const merged: [number, number][] = [];
  for (const [s, e] of [...spans].sort((a, b) => a[0] - b[0])) {
    const last = merged[merged.length - 1];
    if (last && s <= last[1]) last[1] = Math.max(last[1], e);
    else merged.push([s, e]);
  }
  let out = text;
  for (const [s, e] of merged.reverse()) out = `${out.slice(0, s)}[REDACTED]${out.slice(e)}`;
  return out;
}

/**
 * Redact seeded-secret-shaped values and addresses. Applied to all evidence.
 * A labelled `=>` value is redacted through the end of its arrow expression,
 * the same extent the detector judges, so `token => send(a, <value>)` cannot
 * leak the part after the first space.
 */
export function redactEvidence(text: string): string {
  let out = text.replace(/\s+/g, " ").trim();
  out = redactSpans(out, arrowValueSpans(out));
  for (const pattern of SECRET_VALUE_PATTERNS) out = out.replace(pattern, "[REDACTED]");
  out = redactSpans(out, credentialWordSpans(out));
  return out.length > 160 ? `${out.slice(0, 157)}...` : out;
}

/**
 * Evidence-only: spans of unlabelled credential-shaped words (12+ letters and
 * digits with a 5+ digit run, 4+ letter/digit switches, or 8+ bare digits),
 * such as `token.x"fakeValue123456` outside any assignment. Over-redacting a
 * build or order number in display text is harmless; leaking a value is not.
 * This never affects BLOCK decisions.
 */
function credentialWordSpans(text: string): [number, number][] {
  const spans: [number, number][] = [];
  for (const m of text.matchAll(/[A-Za-z0-9_]{12,}/g)) {
    if (isCredentialShapedWord(m[0])) spans.push([m.index ?? 0, (m.index ?? 0) + m[0].length]);
  }
  return spans;
}

/**
 * What a rule match may start with before its risky verb: punctuation,
 * whitespace, and the connectives the patterns allow ("\n", ". Please",
 * ", then", "and").
 */
const VERB_PREFIX = /^(?:[^A-Za-z]*\b(?:please|and|then)\b)*[^A-Za-z]*/i;
/** How far back from the risky verb a governing negation is looked for. */
const NEGATION_WINDOW = 32;

/** True when the rule's negation guard ends immediately before the match's risky verb. */
function isVerbNegated(text: string, match: RegExpMatchArray, negation: RegExp): boolean {
  const verbStart = (match.index ?? 0) + (VERB_PREFIX.exec(match[0])?.[0].length ?? 0);
  return negation.test(text.slice(Math.max(0, verbStart - NEGATION_WINDOW), verbStart));
}

/**
 * The rule's first match that is not suppressed (Phase K). Every match of
 * every pattern is considered, so a negated match (safety advice) never hides
 * a later request that is not negated.
 */
function firstUnsuppressedMatch(text: string, rule: ScannerRule): RegExpMatchArray | null {
  for (const pattern of rule.patterns) {
    const all = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
    for (const match of text.matchAll(all)) {
      if (!rule.suppressIfVerbNegatedBy || !isVerbNegated(text, match, rule.suppressIfVerbNegatedBy)) return match;
    }
  }
  return null;
}

/** Character ranges of every secret-shaped span the redactor recognizes. */
function secretSpans(text: string): [number, number][] {
  const spans: [number, number][] = [...arrowValueSpans(text), ...credentialWordSpans(text)];
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
    const matched = firstUnsuppressedMatch(text, rule);
    if (!matched) continue;

    findings.push({
      ruleId: rule.ruleId,
      category: "injection",
      severity: rule.severity,
      title: rule.title,
      explanation: `${rule.explanation} (rule-based matching, not an ML classifier)`,
      evidence: evidenceAround(text, matched.index ?? 0, matched[0].length, (spans ??= secretSpans(text))),
    });
  }

  return { status: findings.length > 0 ? "suspicious" : "clean", findings, contentLength: text.length };
}
