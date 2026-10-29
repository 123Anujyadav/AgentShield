import type { Finding } from "../types.js";
import { SCANNER_RULES, type ScannerRule } from "./rules.js";

export type ScannerStatus = "clean" | "suspicious" | "empty";

export interface ScannerResult {
  status: ScannerStatus;
  findings: Finding[];
  contentLength: number;
}

export const MAX_SCAN_LENGTH = 8000;

/**
 * Invisible format characters removed from untrusted content before scanner
 * rules are matched (Phase L), so "Ign\u200Bore all previous instructions"
 * cannot slip past a rule. A fixed, documented set only; other Unicode format
 * characters, variation selectors, Hangul fillers, and look-alike letters are
 * not covered. Bidi controls are removed too, so evidence shows the logical
 * (stored) character order, not the visually reordered display.
 */
const INVISIBLE_FORMAT_CHARACTERS = new RegExp(
  `[${[
    "\\u00AD", // soft hyphen
    "\\u180E", // Mongolian vowel separator
    "\\u200B-\\u200F", // zero-width space, non-joiner, joiner; left-to-right and right-to-left marks
    "\\u202A-\\u202E", // bidi embeddings, pop formatting, and overrides
    "\\u2060-\\u2064", // word joiner and invisible operators
    "\\u2066-\\u2069", // bidi isolates
    "\\uFEFF", // byte-order mark (zero-width no-break space)
  ].join("")}]`,
  "g",
);

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
 * Inspects one outbound field, exactly as written, for a recognized
 * secret-shaped value. Fields up to MAX_OUTBOUND_FIELD_LENGTH are scanned in
 * full. A longer field returns kind "field-too-long-to-inspect" so callers
 * hard-BLOCK it instead of silently truncating the scan. Non-string input
 * never throws and never matches. Returns only the pattern kind and field name.
 */
function detectRawOutboundSecret(field: string, text: unknown): OutboundSecretMatch | null {
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
 * Inspects one outbound field for a recognized secret-shaped value, used by
 * every decision and every public-output redaction. The field is first
 * inspected exactly as written, and a match there is returned unchanged.
 * Only when that finds nothing is a copy with the Phase L invisible format
 * characters (INVISIBLE_FORMAT_CHARACTERS) removed inspected too, so a label
 * or prefix split by one of them ("api" + zero-width space + "_key=...") is
 * still recognized. Raw first means nothing detected today is lost: removing
 * characters can shorten a value below a minimum length. The size bound
 * applies to the raw field, so a raw field over MAX_OUTBOUND_FIELD_LENGTH is
 * reported as uninspectable before any normalization.
 */
export function detectOutboundSecret(field: string, text: unknown): OutboundSecretMatch | null {
  const raw = detectRawOutboundSecret(field, text);
  if (raw || typeof text !== "string") return raw;
  const normalized = text.replace(INVISIBLE_FORMAT_CHARACTERS, "");
  return normalized === text ? null : detectRawOutboundSecret(field, normalized);
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

/**
 * Second matching text for invisible format characters used in place of
 * spaces (Design B3). Deleting them (Phase L) joins "Ignore", a zero-width
 * space, and "all" into "Ignoreall", which no rule matches. Here each run of
 * approved invisible characters becomes one space when it sits between two
 * visible characters, and is deleted at the start or end of the text or next
 * to whitespace, so padding cannot move a sentence-start pattern off its
 * anchor. `toRaw` maps each character of `text` to its index in the bounded
 * raw input; the input itself is never modified.
 */
interface SeparatedText {
  text: string;
  toRaw: number[];
}

/** One character of the Phase L set (INVISIBLE_FORMAT_CHARACTERS without the global flag). */
const INVISIBLE_FORMAT_CHARACTER = new RegExp(INVISIBLE_FORMAT_CHARACTERS.source);
const WHITESPACE_CHARACTER = /\s/;

function separateInvisibleRuns(bounded: string): SeparatedText {
  const chars: string[] = [];
  const toRaw: number[] = [];
  let index = 0;
  while (index < bounded.length) {
    const char = bounded.charAt(index);
    if (!INVISIBLE_FORMAT_CHARACTER.test(char)) {
      chars.push(char);
      toRaw.push(index);
      index += 1;
      continue;
    }
    let end = index + 1;
    while (end < bounded.length && INVISIBLE_FORMAT_CHARACTER.test(bounded.charAt(end))) end += 1;
    const before = chars[chars.length - 1];
    const after = bounded.charAt(end);
    if (before !== undefined && after !== "" && !WHITESPACE_CHARACTER.test(before) && !WHITESPACE_CHARACTER.test(after)) {
      chars.push(" ");
      toRaw.push(index);
    }
    index = end;
  }
  return { text: chars.join(""), toRaw };
}

/** The last `length` visible characters of the raw input before `rawEnd`, with invisible characters removed. */
function joinedTextBefore(bounded: string, rawEnd: number, length: number): string {
  let out = "";
  for (let index = rawEnd - 1; index >= 0 && out.length < length; index -= 1) {
    const char = bounded.charAt(index);
    if (!INVISIBLE_FORMAT_CHARACTER.test(char)) out = char + out;
  }
  return out;
}

/**
 * The rule's first unsuppressed match in the separated text. Besides the
 * Phase K guard on the separated text itself, a match is suppressed when the
 * joined text (what a reader sees) shows the guard's negation directly before
 * the same verb, so an invisible character inside "never", "not", or "ever"
 * cannot turn safety advice into a finding. When the verb is preceded by an
 * invisible run, that run is the separator, so the joined text is also tested
 * with a space in its place ("Ne", word joiner, "ver", zero-width space, "send").
 */
function firstUnsuppressedSeparatedMatch(separated: SeparatedText, bounded: string, rule: ScannerRule): RegExpMatchArray | null {
  const negation = rule.suppressIfVerbNegatedBy;
  for (const pattern of rule.patterns) {
    const all = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
    for (const match of separated.text.matchAll(all)) {
      if (!negation) return match;
      if (isVerbNegated(separated.text, match, negation)) continue;
      const verbStart = (match.index ?? 0) + (VERB_PREFIX.exec(match[0])?.[0].length ?? 0);
      const rawVerbStart = separated.toRaw[verbStart] ?? bounded.length;
      const joinedBefore = joinedTextBefore(bounded, rawVerbStart, NEGATION_WINDOW);
      if (negation.test(joinedBefore)) continue;
      if (INVISIBLE_FORMAT_CHARACTER.test(bounded.charAt(rawVerbStart - 1)) && negation.test(`${joinedBefore} `)) continue;
      return match;
    }
  }
  return null;
}

/**
 * A secret-shaped span: start, end, and whether it is unanchored. An anchored
 * span starts at something its format fixes (a label, a provider prefix, a
 * key header); a credential-shaped word or an email address has no such
 * start, so in text whose words are glued together it can run over them.
 */
type ClassifiedSpan = [start: number, end: number, unanchored: boolean];

/** Every secret-shaped span the redactor recognizes, classified as above (only the anchored ones when `anchoredOnly`). */
function classifiedSecretSpans(text: string, anchoredOnly = false): ClassifiedSpan[] {
  const spans: ClassifiedSpan[] = arrowValueSpans(text).map(([s, e]): ClassifiedSpan => [s, e, false]);
  if (!anchoredOnly) for (const [s, e] of credentialWordSpans(text)) spans.push([s, e, true]);
  for (const pattern of SECRET_VALUE_PATTERNS) {
    const unanchored = pattern.source === EMAIL_SOURCE;
    if (anchoredOnly && unanchored) continue;
    for (const m of text.matchAll(pattern)) {
      const at = m.index ?? 0;
      spans.push([at, at + m[0].length, unanchored]);
    }
  }
  return spans;
}

/** Character ranges of every secret-shaped span the redactor recognizes. */
function secretSpans(text: string): [number, number][] {
  return classifiedSecretSpans(text).map(([s, e]): [number, number] => [s, e]);
}

/** Evidence shows this many characters before and after a match. */
const EVIDENCE_BEFORE = 30;
const EVIDENCE_AFTER = 50;
/**
 * How far before the evidence window (in joined-text characters) a secret
 * glued to the word before it, or a label split by an invisible character,
 * is looked for. Larger than any value the evidence window can need from a
 * nearer start, and fixed so the work per scan stays bounded.
 */
const SPLIT_SECRET_LOOKBACK = 1024;
/** Length of each joined slice read from such a start; an anchored value reaching its end continues to the end of its word. */
const SPLIT_SECRET_READ = 128;
/**
 * Longest joined slice between two ambiguous runs, for formats whose end is
 * anchored (AWS key ids and Google API keys, 20 and 39 characters, and
 * FAKE_..._SECRET seeds), which a word glued after them hides.
 */
const SPLIT_SECRET_PAIR = 64;
/** Longest label read before a run taken as the whitespace a format requires (`Bearer`). */
const SPLIT_SECRET_LABEL = 16;
/** Length of a label reading: the label, the space, and enough of the value to recognize it (it then continues to the end of its word). */
const SPLIT_SECRET_LABEL_READ = 32;
/**
 * A plain word: letters only, all lowercase, Capitalized, or all capitals.
 * Released from the edges of an unanchored span (with surrounding punctuation
 * in a word the raw bound cut); a piece with a digit, a symbol, or mixed case
 * (QzvK) never is.
 */
const PLAIN_WORD = /^(?:[a-z]+|[A-Z][a-z]+|[A-Z]+)$/;
const PLAIN_WORD_WITH_PUNCTUATION = /^["'(]?(?:[a-z]+|[A-Z][a-z]+|[A-Z]+)[.,;:!?'")\]]*$/;

/** Raw index of each joined-text character (the bounded input without the Phase L set). */
function joinedToRawIndex(bounded: string): number[] {
  const joinedToRaw: number[] = [];
  for (let index = 0; index < bounded.length; index += 1) {
    if (!INVISIBLE_FORMAT_CHARACTER.test(bounded.charAt(index))) joinedToRaw.push(index);
  }
  return joinedToRaw;
}

/** First index of an increasing index array whose value is at least `value`. */
function firstIndexAtOrAfter(values: number[], value: number): number {
  let low = 0;
  let high = values.length;
  while (low < high) {
    const mid = (low + high) >> 1;
    if ((values[mid] ?? Infinity) < value) low = mid + 1;
    else high = mid;
  }
  return low;
}

/** For each index of `text`, the index of the first whitespace at or after it (or the length). */
function nextWhitespaceIndex(text: string, isWhitespace: (index: number) => boolean): number[] {
  const next: number[] = new Array<number>(text.length + 1);
  next[text.length] = text.length;
  for (let index = text.length - 1; index >= 0; index -= 1) next[index] = isWhitespace(index) ? index : (next[index + 1] ?? text.length);
  return next;
}

/**
 * Secret patterns that need whitespace inside a match (`Bearer`, then a
 * space): the only ones a space read into a label can complete.
 */
const WHITESPACE_SECRET_PATTERNS = SECRET_VALUE_PATTERNS.filter((pattern) => pattern.source.includes("\\s+"));
/**
 * Secret patterns anchored at their end (a lookahead or a closing word
 * boundary: AWS key ids, Google API keys, FAKE_..._SECRET seeds), which a
 * word glued after them hides. An email address ends in its own domain and
 * is not one.
 */
const END_ANCHORED_SECRET_PATTERNS = SECRET_VALUE_PATTERNS.filter(
  (pattern) => pattern.source !== EMAIL_SOURCE && (pattern.source.includes("(?!") || pattern.source.endsWith("\\b")),
);

/** Spans of the given patterns only (all anchored). */
function patternSpans(text: string, patterns: RegExp[]): ClassifiedSpan[] {
  const spans: ClassifiedSpan[] = [];
  for (const pattern of patterns) {
    for (const m of text.matchAll(pattern)) {
      const at = m.index ?? 0;
      spans.push([at, at + m[0].length, false]);
    }
  }
  return spans;
}

/**
 * Free-text gaps in the scanner rules. Every rule writes free text as
 * [^.\n]{0,N}; every other part of a match is the rule's own words and
 * punctuation (a test checks this).
 */
const RULE_GAP = /\[\^\.\\n\]\{0,\d+\}/g;
const LETTERS_ONLY = /^[A-Za-z]+$/;
const LETTERS_WITH_PUNCTUATION = /^["'(]?[A-Za-z]+[.,;:!?'")\]]*$/;

/**
 * The parts of a rule match outside its free-text gaps, in `text`
 * coordinates. The rule matched them case-insensitively as its own words
 * ("ReVeAl tHe PaSsWoRdS"), so they are request words in any case, while gap
 * content can be anything, a secret included. The pattern is run again at the
 * match, sticky and with each gap captured, which matches the same text.
 */
function ruleWordRanges(rule: ScannerRule, text: string, index: number, length: number): [number, number][] {
  for (const pattern of rule.patterns) {
    // Any failure (a pattern that cannot be rebuilt or run) releases no words:
    // the evidence then keeps its conservative redaction, and scanning goes on.
    try {
      const ranges = patternWordRanges(pattern, text, index, length);
      if (ranges) return ranges;
    } catch {
      return [];
    }
  }
  return [];
}

/**
 * True when a rule's own words cannot be verified, so none are released:
 * - a construct outside the free-text gaps that can match arbitrary letters:
 *   an unescaped dot, \w \W \S \D, a Unicode property (\p{...}, \P{...}), or a
 *   character class that is negated, holds a letter or digit range, several
 *   letters, or any of those escapes (free text that is not a [^.\n]{0,N} gap);
 * - a gap the match indices cannot map (hasUnmappableGap).
 */
function hasUnverifiedFreeText(source: string): boolean {
  const rest = source.replace(RULE_GAP, "");
  const classes = rest.match(/\[(?:\\.|[^\]\\])*\]/g) ?? [];
  if (classes.some((cls) => /^\[\^|[A-Za-z0-9]-[A-Za-z0-9]|[a-zA-Z]{2,}|\\[pPwWSD]/.test(cls.replace(/\\[nrtfv]/g, "")))) return true;
  if (/(^|[^\\])\.|\\[pPwWSD]/.test(rest.replace(/\[(?:\\.|[^\]\\])*\]/g, ""))) return true;
  return hasUnmappableGap(source);
}

/**
 * True when the match indices cannot show where a rule's free text lies:
 * - a backreference outside a character class (\1 to \9, \k<name>), which
 *   repeats captured text, a gap's included, outside the gap;
 * - a gap inside a quantified group (*, +, ?, {n}, {n,m}), whose indices give
 *   only the last iteration, so earlier iterations' gap text would read as the
 *   rule's own words;
 * - a gap inside a lookaround, whose text the rest of the match consumes.
 * One pass over the source, tracking escapes, classes, and open groups.
 */
function hasUnmappableGap(source: string): boolean {
  const gapStarts = [...source.matchAll(RULE_GAP)].map((match) => match.index ?? 0);
  const groups: { start: number; lookaround: boolean }[] = [];
  let inClass = false;
  for (let i = 0; i < source.length; i += 1) {
    const char = source.charAt(i);
    if (char === "\\") {
      if (!inClass && /[1-9k]/.test(source.charAt(i + 1))) return true;
      i += 1;
    } else if (inClass) {
      if (char === "]") inClass = false;
    } else if (char === "[") {
      inClass = true;
    } else if (char === "(") {
      groups.push({ start: i, lookaround: /^\(\?<?[=!]/.test(source.slice(i, i + 4)) });
    } else if (char === ")") {
      const group = groups.pop();
      if (!group) continue;
      const holdsGap = gapStarts.some((gapStart) => gapStart > group.start && gapStart < i);
      if (holdsGap && (group.lookaround || /^(?:[*+?]|\{\d+(?:,\d*)?\})/.test(source.slice(i + 1)))) return true;
    }
  }
  return false;
}

/**
 * The rule's own words for one pattern: null when the pattern does not match
 * the same text at `index`, [] when it does but its words cannot be verified.
 * Gap groups get a name prefix found nowhere in the pattern, so they never
 * collide with its own named groups, and only those groups are read back. The
 * flags are the pattern's, without d, g, or y, plus d and y once each.
 */
function patternWordRanges(pattern: RegExp, text: string, index: number, length: number): [number, number][] | null {
  let prefix = "b3gap";
  while (pattern.source.includes(prefix)) prefix = `${prefix}_`;
  let gaps = 0;
  const source = pattern.source.replace(RULE_GAP, (gap) => `(?<${prefix}${gaps++}>${gap})`);
  const flags = `${[...new Set(pattern.flags.replace(/[dgy]/g, ""))].join("")}dy`;
  const sticky = new RegExp(source, flags);
  sticky.lastIndex = index;
  const match = sticky.exec(text);
  if (!match || match[0].length !== length) return null;
  if (hasUnverifiedFreeText(pattern.source)) return [];
  const gapRanges = Object.entries(match.indices?.groups ?? {})
    .filter((entry): entry is [string, [number, number]] => entry[0].startsWith(prefix) && entry[1] !== undefined)
    .map(([, range]) => range)
    .sort((a, b) => a[0] - b[0]);
  const ranges: [number, number][] = [];
  let at = index;
  for (const [start, end] of gapRanges) {
    if (start > at) ranges.push([at, start]);
    at = Math.max(at, end);
  }
  if (index + length > at) ranges.push([at, index + length]);
  return ranges;
}

/** Per-scan state for separated-text evidence (Design B3); built once, shared by every finding. */
interface SplitSecretContext {
  bounded: string;
  joined: string;
  separated: SeparatedText;
  joinedToRaw: number[];
  /** Joined index of the next whitespace at or after each joined index. */
  joinedWordEnd: number[];
  /** Per joined index: 1 an ambiguous run sits before it, 2 a word starts at it, 4 a word ends at it. */
  boundaries: Uint8Array;
  /** Secret spans of the whole joined text. */
  joinedSpans: ClassifiedSpan[];
  /** Spans read from each start (joined coordinates), shared by overlapping windows. */
  readings: Map<number, ClassifiedSpan[]>;
  /** Each unanchored span narrowed (keyed by start and end, plus the request's words when they apply). */
  narrowed: Map<string, [number, number]>;
  /** Anchored spans of the separated text that stop at an invisible run, extended to the end of their word. */
  separatedValues: [number, number][];
}

const AMBIGUOUS = 1;
const WORD_START = 2;
const WORD_END = 4;

function splitSecretContext(bounded: string, joined: string, separated: SeparatedText): SplitSecretContext {
  const text = separated.text;
  // A space the separated text inserted for an invisible run, not one the input held.
  const inserted = (index: number): boolean => text.charAt(index) === " " && INVISIBLE_FORMAT_CHARACTER.test(bounded.charAt(separated.toRaw[index] ?? -1));
  const separatedWordEnd = nextWhitespaceIndex(text, (index) => WHITESPACE_CHARACTER.test(text.charAt(index)) && !inserted(index));
  // A value the separated text ends at an invisible run (`Bearer QzvKw`, then a
  // zero-width space, then the rest) may continue past it: to the end of its
  // word, however far from the evidence window its label is.
  const separatedValues: [number, number][] = [];
  for (const [s, e, unanchored] of classifiedSecretSpans(text)) {
    if (!unanchored && inserted(e)) separatedValues.push([s, separatedWordEnd[e] ?? text.length]);
  }
  const joinedToRaw = joinedToRawIndex(bounded);
  const length = joined.length;
  const blank = (index: number): boolean => index < 0 || index >= length || WHITESPACE_CHARACTER.test(joined.charAt(index));
  const boundaries = new Uint8Array(length + 1);
  for (let j = 0; j <= length; j += 1) {
    const before = blank(j - 1);
    const at = blank(j);
    if (!before && !at && (joinedToRaw[j] ?? 0) - (joinedToRaw[j - 1] ?? 0) > 1) boundaries[j] |= AMBIGUOUS;
    if (before && !at) boundaries[j] |= WORD_START;
    if (!before && at) boundaries[j] |= WORD_END;
  }
  return {
    bounded,
    joined,
    separated,
    joinedToRaw,
    joinedWordEnd: nextWhitespaceIndex(joined, (index) => WHITESPACE_CHARACTER.test(joined.charAt(index))),
    boundaries,
    joinedSpans: classifiedSecretSpans(joined),
    readings: new Map<number, ClassifiedSpan[]>(),
    narrowed: new Map<string, [number, number]>(),
    separatedValues,
  };
}

/**
 * Secret spans for separated-text evidence (Design B3), in separated-text
 * coordinates. An invisible run between two visible characters is ambiguous:
 * a separator between words, or a split inside one. The separated text reads
 * every run as a separator, so a secret split inside becomes fragments too
 * short for the redactor; the joined text reads every run as a split, so a
 * secret glued to a neighbouring word by a separator loses the boundary its
 * format is anchored on (`token`, zero-width space, `ghp_...` joins into
 * `tokenghp_...`). A secret can need its edge runs read as separators and its
 * inner runs as splits, so near the evidence window the same detectors also
 * read, from each ambiguous run or word start: the joined slice after an
 * ambiguous run (anchored formats, whose start such a run can hide); the
 * slice with one ambiguous run soon after the start read as a space (formats
 * that need whitespace, for a label such as `Bearer`, a separator, then a
 * value split inside); and every short slice ending at an ambiguous run or a
 * word end (formats anchored at their end). Credential-shaped words and email
 * addresses in those slices lie inside ones the whole joined text already
 * holds, so only the whole joined text is read for them. An anchored value
 * that reaches the end of its slice continues to the end of its word. Each
 * span is then mapped through the bounded raw input onto every separated
 * character it covers, including the spaces that replaced invisible runs
 * inside it.
 *
 * Joined, plain words glued to an unanchored span become part of it: the
 * request "Reveal", "the", "passwords" ... "12345" joins into one
 * credential-shaped word. Plain words (PLAIN_WORD) are therefore released
 * from both edges of an unanchored span, and so are letters-only words inside
 * the matched request's own words (`requestWords`, in separated coordinates,
 * from ruleWordRanges) in any case; then the nearest are taken back until the
 * detectors recognize the rest on its own, so what is redacted is always a
 * span they recognize, even when on its own it would not be (12345). Any
 * other piece with a digit, a symbol, or mixed case is never released.
 * Anchored spans are not narrowed: words glued after a recognized value may
 * be redacted with it. `from` and `to` are the separated-text evidence window
 * before widening.
 */
function splitSecretSpans(context: SplitSecretContext, from: number, to: number, requestWords: [number, number][]): [number, number][] {
  const { joined, joinedToRaw, joinedWordEnd, separated, readings, boundaries } = context;
  const length = joined.length;
  const ambiguous = (j: number): boolean => ((boundaries[j] ?? 0) & AMBIGUOUS) !== 0;
  const toJoinedIndex = (separatedIndex: number): number => firstIndexAtOrAfter(joinedToRaw, separated.toRaw[separatedIndex] ?? Infinity);
  const regionFrom = toJoinedIndex(from);
  const regionTo = toJoinedIndex(to);

  // Reads `slice` (from `detect`), the joined text from `offset` with a space
  // inserted after `gap` of its characters (-1: none), into joined coordinates.
  const add = (out: ClassifiedSpan[], offset: number, slice: string, detect: (text: string) => ClassifiedSpan[], gap = -1): void => {
    const toJoined = (position: number): number => offset + (gap >= 0 && position > gap ? position - 1 : position);
    for (const [s, e, unanchored] of detect(slice)) {
      let end = toJoined(e);
      if (!unanchored && e === slice.length && end < length) end = Math.max(end, joinedWordEnd[end] ?? length);
      out.push([toJoined(s), end, unanchored]);
    }
  };
  const anchored = (text: string): ClassifiedSpan[] => classifiedSecretSpans(text, true);
  const needingWhitespace = (text: string): ClassifiedSpan[] => patternSpans(text, WHITESPACE_SECRET_PATTERNS);
  const endAnchored = (text: string): ClassifiedSpan[] => patternSpans(text, END_ANCHORED_SECRET_PATTERNS);
  // Long readings are keyed by start; short (pair) readings by -(start + 1).
  const read = (key: number, compute: (out: ClassifiedSpan[]) => void): ClassifiedSpan[] => {
    let out = readings.get(key);
    if (!out) {
      out = [];
      compute(out);
      readings.set(key, out);
    }
    return out;
  };
  const found: ClassifiedSpan[] = [...context.joinedSpans];
  for (let j = Math.max(0, regionFrom - SPLIT_SECRET_LOOKBACK); j < regionTo; j += 1) {
    const flags = boundaries[j] ?? 0;
    const split = (flags & AMBIGUOUS) !== 0;
    if (!split && (flags & WORD_START) === 0) continue;
    found.push(
      ...read(j, (out) => {
        if (split) add(out, j, joined.slice(j, j + SPLIT_SECRET_READ), anchored);
        // A label that needs whitespace before its value ends in a letter (`Bearer`).
        for (let r = j + 1; r <= Math.min(length - 1, j + SPLIT_SECRET_LABEL); r += 1) {
          if (ambiguous(r) && /[A-Za-z]/.test(joined.charAt(r - 1))) {
            add(out, j, `${joined.slice(j, r)} ${joined.slice(r, j + SPLIT_SECRET_LABEL_READ)}`, needingWhitespace, r - j);
          }
        }
      }),
    );
    if (j < regionFrom - SPLIT_SECRET_PAIR) continue;
    found.push(
      ...read(-(j + 1), (out) => {
        for (let end = j + 1; end <= Math.min(length, j + SPLIT_SECRET_PAIR); end += 1) {
          // A slice from a word start to a word end is what the joined text already read.
          const endFlags = boundaries[end] ?? 0;
          if ((endFlags & AMBIGUOUS) !== 0 || (split && (endFlags & WORD_END) !== 0)) add(out, j, joined.slice(j, end), endAnchored);
        }
      }),
    );
  }

  // The request's own words, in joined coordinates.
  const words = requestWords.map(([a, b]): [number, number] => [toJoinedIndex(a), toJoinedIndex(b)]);
  const wordsKey = words.map(([a, b]) => `${a}-${b}`).join(";");
  const plain = (a: number, b: number): boolean => PLAIN_WORD.test(joined.slice(a, b));
  const plainOrRequestWord = (a: number, b: number): boolean =>
    plain(a, b) || (LETTERS_ONLY.test(joined.slice(a, b)) && words.some(([ws, we]) => a >= ws && b <= we));
  // The detectors still recognize all of joined[start, end) as one unanchored span.
  const recognized = (start: number, end: number): boolean => {
    const piece = joined.slice(start, end);
    return classifiedSecretSpans(piece).some(([s, e, unanchored]) => unanchored && s === 0 && e === piece.length);
  };
  // Releases pieces `release` allows from both edges of an unanchored span,
  // then takes the nearest back (left first, then alternating) until the
  // detectors recognize the rest on its own.
  const narrow = (s: number, e: number, release: (a: number, b: number) => boolean): [number, number] => {
    let start = s;
    let end = e;
    for (let k = start + 1; k < end; k += 1) {
      if (!ambiguous(k)) continue;
      if (!release(start, k)) break;
      start = k;
    }
    for (let k = end - 1; k > start; k -= 1) {
      if (!ambiguous(k)) continue;
      if (!release(k, end)) break;
      end = k;
    }
    for (let left = true; !recognized(start, end) && (start > s || end < e); left = !left) {
      if (left ? start > s : end >= e) {
        do start -= 1;
        while (start > s && !ambiguous(start));
      } else {
        do end += 1;
        while (end < e && !ambiguous(end));
      }
    }
    return [start, end];
  };
  const narrowed = (s: number, e: number): [number, number] => {
    // The request's words only matter for a span that overlaps them.
    const overlaps = words.some(([ws, we]) => s < we && e > ws);
    const key = overlaps ? `${s},${e},${wordsKey}` : `${s},${e}`;
    let result = context.narrowed.get(key);
    if (!result) {
      result = narrow(s, e, overlaps ? plainOrRequestWord : plain);
      context.narrowed.set(key, result);
    }
    return result;
  };
  const spans: [number, number][] = [];
  const seen = new Set<number>();
  for (const [s0, e0, unanchored] of found) {
    const key = (s0 * (length + 1) + e0) * 2 + (unanchored ? 1 : 0);
    if (seen.has(key)) continue;
    seen.add(key);
    const [s, e] = unanchored ? narrowed(s0, e0) : [s0, e0];
    const rawStart = joinedToRaw[s];
    const rawLast = joinedToRaw[e - 1];
    if (e <= s || rawStart === undefined || rawLast === undefined) continue;
    spans.push([firstIndexAtOrAfter(separated.toRaw, rawStart), firstIndexAtOrAfter(separated.toRaw, rawLast + 1)]);
  }
  return spans;
}

/**
 * When the raw bound cuts the input inside a word, that last word is only a
 * fragment: a secret cut short may be too short for any detector, in either
 * text, so no secret span can be mapped for it. For separated-text evidence it
 * is redacted rather than shown, from the last raw whitespace so every
 * invisible-split chunk of it is covered. Only words inside the matched
 * request (`matchEnd` is its end in the separated text) are released: plain
 * words, and letters-only words of any case inside the request's own words
 * (`requestWords`); anything after the match may belong to the fragment. Its
 * last piece, the one the bound cut, is always redacted.
 */
function cutWordOnSeparated(
  input: string,
  bounded: string,
  separated: SeparatedText,
  matchEnd: number,
  requestWords: [number, number][],
): [number, number][] {
  if (input.length <= bounded.length || WHITESPACE_CHARACTER.test(input.charAt(bounded.length))) return [];
  let rawStart = bounded.length;
  while (rawStart > 0 && !WHITESPACE_CHARACTER.test(bounded.charAt(rawStart - 1))) rawStart -= 1;
  const text = separated.text;
  let start = firstIndexAtOrAfter(separated.toRaw, rawStart);
  // The cut word holds no input whitespace, so each space in it replaced an invisible run.
  for (let k = start; k < text.length && k <= matchEnd; k += 1) {
    if (text.charAt(k) !== " ") continue;
    const piece = text.slice(start, k);
    const requestWord = LETTERS_WITH_PUNCTUATION.test(piece) && requestWords.some(([ws, we]) => start >= ws && k <= we);
    if (!PLAIN_WORD_WITH_PUNCTUATION.test(piece) && !requestWord) break;
    start = k + 1;
  }
  return start < text.length ? [[start, text.length]] : [];
}

/**
 * `spans` widen the window so no secret-shaped span is cut in half; the part
 * of each `forced` span inside the window is redacted whether or not the
 * redactor recognizes it there, for secrets found in another representation.
 */
function evidenceAround(
  text: string,
  index: number,
  matchLength: number,
  spans: [number, number][],
  forced: [number, number][] = [],
): string {
  let start = Math.max(0, index - EVIDENCE_BEFORE);
  let end = Math.min(text.length, index + matchLength + EVIDENCE_AFTER);
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
  const inWindow = forced
    .filter(([s, e]) => s < end && e > start)
    .map(([s, e]): [number, number] => [Math.max(s, start) - start, Math.min(e, end) - start]);
  return redactEvidence(redactSpans(text.slice(start, end), inWindow));
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
  // The size bound applies to the raw input first, so normalization only ever
  // processes at most MAX_SCAN_LENGTH characters; rules and evidence then use
  // the normalized text (Phase L).
  const bounded = input.slice(0, MAX_SCAN_LENGTH);
  const text = bounded.replace(INVISIBLE_FORMAT_CHARACTERS, "");
  const findings: Finding[] = [];
  let spans: [number, number][] | null = null;
  // Built only when a rule finds nothing in the joined text and the input
  // contains invisible characters (Design B3).
  let separated: SeparatedText | null = null;
  let separatedSpans: [number, number][] | null = null;
  let splitContext: SplitSecretContext | null = null;

  for (const rule of SCANNER_RULES) {
    // The joined text is matched first, so every existing finding and its
    // evidence are unchanged; the separated text is a fallback per rule.
    let evidence: string | null = null;
    const matched = firstUnsuppressedMatch(text, rule);
    if (matched) {
      evidence = evidenceAround(text, matched.index ?? 0, matched[0].length, (spans ??= secretSpans(text)));
    } else if (text !== bounded) {
      separated ??= separateInvisibleRuns(bounded);
      const fallback = separated.text === text ? null : firstUnsuppressedSeparatedMatch(separated, bounded, rule);
      if (fallback) {
        // Secrets split or glued by invisible characters are found by reading
        // the joined text around the window, and redacted in it; so are values
        // the separated text stops at an invisible run, and a word the raw
        // bound cut short.
        const separatedText = separated.text;
        const index = fallback.index ?? 0;
        const from = Math.max(0, index - EVIDENCE_BEFORE);
        const to = Math.min(separatedText.length, index + fallback[0].length + EVIDENCE_AFTER);
        splitContext ??= splitSecretContext(bounded, text, separated);
        const requestWords = ruleWordRanges(rule, separatedText, index, fallback[0].length);
        const forced = [
          ...splitSecretSpans(splitContext, from, to, requestWords),
          ...splitContext.separatedValues,
          ...cutWordOnSeparated(input, bounded, separated, index + fallback[0].length, requestWords),
        ];
        separatedSpans ??= secretSpans(separatedText);
        evidence = evidenceAround(separatedText, index, fallback[0].length, separatedSpans, forced);
      }
    }
    if (evidence === null) continue;

    findings.push({
      ruleId: rule.ruleId,
      category: "injection",
      severity: rule.severity,
      title: rule.title,
      explanation: `${rule.explanation} (rule-based matching, not an ML classifier)`,
      evidence,
    });
  }

  return { status: findings.length > 0 ? "suspicious" : "clean", findings, contentLength: bounded.length };
}
