import { randomBytes } from "node:crypto";
import { detectOutboundSecret, payloadAssignment } from "@agentshield/engine";
import type { FetchResult } from "../fetcher.js";
import { errored, evidence, result, type CheckResult, type Confidence, type Finding, type Severity } from "../findings.js";
import { FATAL_REASONS, ScanStopped } from "../scan.js";
import { NOT_CHECKED_SUMMARIES, type PlannedProbe, type ProbeContext } from "../stages.js";
import type { ScanTarget } from "../target.js";

/**
 * Passive exposure checks (M2-C). One request to a random missing path (the
 * soft-404 baseline), then one request to each of nine fixed paths, in order,
 * through the M2-A probe stage. Every request uses the guarded fetcher in prefix
 * mode: at most the first 4,096 bytes, the fixed Range header, no redirects, no
 * decoding. A path is reported only when its bytes match a strict signature for
 * that file; a status code or a file name alone never is.
 *
 * Nothing read here leaves this module: findings carry fixed text, counts and
 * engine-defined secret kinds only. Bodies, including the baseline's, are
 * never quoted, stored on the scan, logged or reported.
 *
 * Nothing in production schedules these probes yet (no planner is registered).
 */

export type ExposurePath =
  | "/.git/HEAD"
  | "/.git/config"
  | "/.env"
  | "/.DS_Store"
  | "/server-status"
  | "/backup.zip"
  | "/backup.tar.gz"
  | "/database.sql"
  | "/dump.sql";

/** A matched signature: fixed evidence text and how certain the signature is. */
interface Detection {
  evidence: string;
  confidence: Confidence;
}

interface ExposureSpec {
  readonly checkId: string;
  readonly path: ExposurePath;
  readonly title: string;
  readonly severity: Severity;
  readonly findingTitle: string;
  readonly explanation: string;
  readonly remediation: string;
  readonly references: readonly string[];
  /** Judges the response prefix; `truncated` means more bytes followed and were never read. */
  readonly detect: (bytes: Buffer, truncated: boolean) => Detection | null;
}

export const BASELINE_CHECK_ID = "exposure-baseline";
const BASELINE_TITLE = "Missing-path baseline";
const MISCONFIG = "OWASP A05:2021 Security Misconfiguration";

/** Fixed result summaries. No summary ever includes anything the target sent. */
export const EXPOSURE_SUMMARIES = Object.freeze({
  notFound: "Not exposed: the path was not found.",
  denied: "Not exposed: access to the path was denied.",
  noSignature: "Not exposed: the response does not match this file's signature.",
  likeBaseline: "Not exposed: the response matches the site's answer for a random missing path.",
  redirect: "Inconclusive: the server answered with a redirect, which is not followed.",
  rangeNotSatisfiable: "Inconclusive: the server could not serve the requested byte range.",
  serverError: "Inconclusive: the server returned an error.",
  unexpectedStatus: "Inconclusive: the server returned an unexpected status.",
  encoded: "Inconclusive: the response was compressed and is not decoded for inspection.",
  timeout: "Inconclusive: the request timed out.",
  failed: "Inconclusive: the request could not be completed.",
  baselineUnknown: "Inconclusive: the response matches this file's signature, but the site's answer for a random missing path could not be established.",
  baselineMatches: "Inconclusive: the site's answer for a random missing path matches this signature too.",
  baselineNotFound: "The site answers a random missing path with not found.",
  baselineCatchAll: "The site answers a random missing path with content; exposure results are compared with it.",
  baselineUnavailable: "Inconclusive: the site's answer for a random missing path could not be established.",
  baselineAmbiguous: "Inconclusive: the site's answer for a random missing path is ambiguous.",
});

// ---------------------------------------------------------------------------
// Signature helpers. They only test the bytes; nothing is extracted from them.

/** Text for text signatures, or null for content with NUL bytes (binary). */
function asText(bytes: Buffer): string | null {
  return bytes.includes(0) ? null : bytes.toString("utf8");
}

const HTML_MARKER = /<\s*(?:!doctype\b|html\b|head\b|body\b|script\b|meta\b|title\b|style\b|link\b|div\b)/i;

/** An HTML marker in the first 512 bytes: a page, not the file. */
function looksLikeHtml(text: string): boolean {
  return HTML_MARKER.test(text.slice(0, 512));
}

/** Lines of a prefix; when it was cut off, the final partial line is dropped. */
function completeLines(text: string, truncated: boolean): string[] {
  const lines = text.split(/\r?\n/);
  if (truncated) lines.pop();
  return lines;
}

function startsWith(bytes: Buffer, signature: readonly number[]): boolean {
  return bytes.length >= signature.length && signature.every((byte, i) => bytes[i] === byte);
}

/** A ref name as Git allows it: refs/<components>, no "..", no empty or dot-led component, no ".lock" ending. */
function isValidRef(ref: string): boolean {
  if (ref.includes("..") || ref.includes("//") || ref.endsWith("/") || ref.endsWith(".")) return false;
  const parts = ref.split("/");
  return parts[0] === "refs" && parts.length >= 2 && parts.slice(1).every((p) => p !== "" && !p.startsWith(".") && !p.endsWith(".lock"));
}

function detectGitHead(bytes: Buffer, truncated: boolean): Detection | null {
  const text = asText(bytes);
  if (text === null || truncated) return null;
  const trimmed = text.trim();
  if (/^[0-9a-f]{40}$/.test(trimmed) || /^[0-9a-f]{64}$/.test(trimmed)) {
    return { evidence: "The body is a bare Git object ID (a detached HEAD).", confidence: "high" };
  }
  const ref = /^ref: (refs\/[A-Za-z0-9._/-]{1,240})$/.exec(trimmed)?.[1];
  if (ref !== undefined && isValidRef(ref)) {
    return { evidence: "The body is a Git symbolic reference (ref: refs/...). The reference name is not recorded.", confidence: "high" };
  }
  return null;
}

function detectGitConfig(bytes: Buffer, truncated: boolean): Detection | null {
  const text = asText(bytes);
  if (text === null || looksLikeHtml(text)) return null;
  const lines = completeLines(text, truncated);
  const core = lines.some((line) => /^\s*\[core\]\s*$/i.test(line));
  const version = lines.some((line) => /^\s*repositoryformatversion\s*=\s*\d+\s*$/i.test(line));
  if (!core || !version) return null;
  return { evidence: "The body has a [core] section with repositoryformatversion. No line of the file is recorded.", confidence: "high" };
}

const ENV_ASSIGNMENT = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/;
/** At most this many lines are inspected for secrets; a 4 KB prefix rarely holds more. */
const MAX_ENV_LINES = 256;
/** Engine kinds that are not credentials, or that mean "not inspected", are never counted as secrets. */
const NOT_SECRET_KINDS = new Set(["email-address", "field-too-long-to-inspect"]);

/** The engine's kind for one assignment's value, judged in memory only; null when none is recognized. */
function secretKindOf(name: string, value: string): string | null {
  const field = "exposure.env.value";
  const match =
    detectOutboundSecret(field, payloadAssignment(name, value)) ?? detectOutboundSecret(field, `${name}=${value}`) ?? detectOutboundSecret(field, value);
  if (!match || NOT_SECRET_KINDS.has(match.kind)) return null;
  // Kinds are engine identifiers; anything else is reported generically.
  return /^[a-z0-9-]{1,40}$/.test(match.kind) ? match.kind : "other-secret";
}

function detectEnv(bytes: Buffer, truncated: boolean): Detection | null {
  const text = asText(bytes);
  if (text === null || looksLikeHtml(text)) return null;
  const meaningful = completeLines(text, truncated)
    .slice(0, MAX_ENV_LINES)
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));
  const assignments = meaningful.map((line) => ENV_ASSIGNMENT.exec(line)).filter((m): m is RegExpExecArray => m !== null);
  // At least two NAME=value lines, and the file is mostly assignments (not prose quoting one or two).
  if (assignments.length < 2 || assignments.length < meaningful.length * 0.8) return null;

  const kinds = new Map<string, number>();
  for (const [, name, value] of assignments) {
    const kind = secretKindOf(name!, value!);
    if (kind !== null) kinds.set(kind, (kinds.get(kind) ?? 0) + 1);
  }
  const secrets = [...kinds.values()].reduce((sum, n) => sum + n, 0);
  if (secrets === 0) return { evidence: `${assignments.length} assignments; no secret-shaped value recognized`, confidence: "medium" };
  // Compact enough for the evidence length limit: at most three kinds by name, the rest counted.
  const ranked = [...kinds.entries()].sort(([a, x], [b, y]) => y - x || a.localeCompare(b));
  const named = ranked.slice(0, 3).map(([kind, n]) => `${kind} x${n}`);
  const more = ranked.length > 3 ? ` +${ranked.length - 3} more` : "";
  return { evidence: `${assignments.length} assignments; ${secrets} secret-shaped (${named.join(", ")}${more})`, confidence: "high" };
}

const DS_STORE_MAGIC = [0x00, 0x00, 0x00, 0x01, 0x42, 0x75, 0x64, 0x31] as const;

function detectDsStore(bytes: Buffer): Detection | null {
  return startsWith(bytes, DS_STORE_MAGIC)
    ? { evidence: "The body starts with the .DS_Store signature (00 00 00 01 Bud1). File names are not read.", confidence: "high" }
    : null;
}

const NGINX_STUB_STATUS =
  /^Active connections:[ \t]*\d+[ \t]*\r?\nserver accepts handled requests[ \t]*\r?\n[ \t]*\d+[ \t]+\d+[ \t]+\d+[ \t]*\r?\nReading:[ \t]*\d+[ \t]+Writing:[ \t]*\d+[ \t]+Waiting:[ \t]*\d+[ \t]*$/;

function detectServerStatus(bytes: Buffer, truncated: boolean): Detection | null {
  const text = asText(bytes);
  if (text === null) return null;
  const apache =
    /<title>\s*Apache Status\s*<\/title>/i.test(text) && /<h1>\s*Apache Server Status for\b/i.test(text) && /\bServer Version:/.test(text);
  if (apache) return { evidence: "The body has the Apache mod_status page signature. The page is not recorded.", confidence: "high" };
  // stub_status is a fixed four-line format; the whole body must be exactly that.
  if (!truncated && NGINX_STUB_STATUS.test(text.trim())) {
    return { evidence: "The body is in the nginx stub_status format. The figures are not recorded.", confidence: "high" };
  }
  return null;
}

function detectZip(bytes: Buffer): Detection | null {
  if (startsWith(bytes, [0x50, 0x4b, 0x03, 0x04])) return { evidence: "The body starts with a ZIP local-file signature (PK 03 04). The archive is not opened.", confidence: "high" };
  if (startsWith(bytes, [0x50, 0x4b, 0x05, 0x06])) return { evidence: "The body starts with an empty-ZIP signature (PK 05 06). The archive is not opened.", confidence: "high" };
  return null;
}

function detectGzip(bytes: Buffer): Detection | null {
  return startsWith(bytes, [0x1f, 0x8b, 0x08])
    ? { evidence: "The body starts with the gzip signature (1F 8B 08). It is not decompressed.", confidence: "high" }
    : null;
}

const SQL_DUMP_MARKERS: ReadonlyArray<readonly [RegExp, string]> = [
  [/^-- MySQL dump \d+\.\d+/m, "MySQL"],
  [/^-- MariaDB dump \d+\.\d+/m, "MariaDB"],
  [/^-- PostgreSQL database dump\s*$/m, "PostgreSQL"],
];

function detectSqlDump(bytes: Buffer): Detection | null {
  const text = asText(bytes);
  if (text === null || looksLikeHtml(text)) return null;
  for (const [marker, product] of SQL_DUMP_MARKERS) {
    if (marker.test(text)) return { evidence: `The body starts like a ${product} dump (dump header marker). No statement is recorded.`, confidence: "high" };
  }
  if (/\bCREATE\s+TABLE\b/i.test(text) && /\bINSERT\s+INTO\b/i.test(text)) {
    return { evidence: "The body contains both CREATE TABLE and INSERT INTO statements. No statement is recorded.", confidence: "medium" };
  }
  return null;
}

// ---------------------------------------------------------------------------
// The fixed allowlist: these nine paths, in this order, and nothing else.

const BACKUP_REMEDIATION = "Remove backup and dump files from the web root, or deny access to them, and rotate any credentials they contain.";

const SPECS: readonly ExposureSpec[] = [
  {
    checkId: "exposure-git-head",
    path: "/.git/HEAD",
    title: "Git metadata (/.git/HEAD)",
    severity: "high",
    findingTitle: "The Git repository metadata is publicly readable",
    explanation: "/.git/HEAD is served, which usually means the whole .git directory is, and with it the site's source code and history.",
    remediation: "Deny web access to /.git (or remove it from the deployment) and review the history for committed secrets.",
    references: ["CWE-527", MISCONFIG],
    detect: detectGitHead,
  },
  {
    checkId: "exposure-git-config",
    path: "/.git/config",
    title: "Git configuration (/.git/config)",
    severity: "high",
    findingTitle: "The Git repository configuration is publicly readable",
    explanation: "/.git/config is served. It can name remote repositories, sometimes with embedded credentials, and signals that the .git directory is exposed.",
    remediation: "Deny web access to /.git (or remove it from the deployment) and rotate any credential that appears in a remote URL.",
    references: ["CWE-527", MISCONFIG],
    detect: detectGitConfig,
  },
  {
    checkId: "exposure-env",
    path: "/.env",
    title: "Environment file (/.env)",
    severity: "high",
    findingTitle: "An environment file is publicly readable",
    explanation:
      "/.env is served as plain NAME=value lines. Environment files usually hold configuration and credentials for the application. Only counts and secret kinds are recorded, never variable names or values.",
    remediation: "Remove .env from the web root or deny access to it, and rotate every credential it contains.",
    references: ["CWE-538", MISCONFIG],
    detect: detectEnv,
  },
  {
    checkId: "exposure-ds-store",
    path: "/.DS_Store",
    title: "macOS folder metadata (/.DS_Store)",
    severity: "low",
    findingTitle: "A .DS_Store file is publicly readable",
    explanation: "/.DS_Store is served. It can list the names of files in the folder, including ones that are not linked anywhere.",
    remediation: "Remove .DS_Store files from the deployment and deny access to them.",
    references: ["CWE-538", MISCONFIG],
    detect: detectDsStore,
  },
  {
    checkId: "exposure-server-status",
    path: "/server-status",
    title: "Server status page (/server-status)",
    severity: "medium",
    findingTitle: "The web server's status page is publicly readable",
    explanation: "/server-status is served. Status pages can show client addresses, requested URLs and server internals.",
    remediation: "Restrict the status page to trusted addresses or disable it.",
    references: ["CWE-200", MISCONFIG],
    detect: detectServerStatus,
  },
  {
    checkId: "exposure-backup-zip",
    path: "/backup.zip",
    title: "Backup archive (/backup.zip)",
    severity: "high",
    findingTitle: "A backup archive is publicly downloadable",
    explanation: "/backup.zip is served as a ZIP archive. Backups often contain source code, configuration and data.",
    remediation: BACKUP_REMEDIATION,
    references: ["CWE-530", MISCONFIG],
    detect: detectZip,
  },
  {
    checkId: "exposure-backup-tar-gz",
    path: "/backup.tar.gz",
    title: "Backup archive (/backup.tar.gz)",
    severity: "high",
    findingTitle: "A backup archive is publicly downloadable",
    explanation: "/backup.tar.gz is served as gzip data. Backups often contain source code, configuration and data.",
    remediation: BACKUP_REMEDIATION,
    references: ["CWE-530", MISCONFIG],
    detect: detectGzip,
  },
  {
    checkId: "exposure-database-sql",
    path: "/database.sql",
    title: "Database dump (/database.sql)",
    severity: "high",
    findingTitle: "A database dump is publicly downloadable",
    explanation: "/database.sql is served as an SQL dump. Dumps can contain every record in the database, including personal data and password hashes.",
    remediation: BACKUP_REMEDIATION,
    references: ["CWE-530", MISCONFIG],
    detect: detectSqlDump,
  },
  {
    checkId: "exposure-dump-sql",
    path: "/dump.sql",
    title: "Database dump (/dump.sql)",
    severity: "high",
    findingTitle: "A database dump is publicly downloadable",
    explanation: "/dump.sql is served as an SQL dump. Dumps can contain every record in the database, including personal data and password hashes.",
    remediation: BACKUP_REMEDIATION,
    references: ["CWE-530", MISCONFIG],
    detect: detectSqlDump,
  },
].map((spec) => Object.freeze({ ...spec, references: Object.freeze([...spec.references]) }) as ExposureSpec);
Object.freeze(SPECS);

/** The nine probed paths, in probe order. Frozen; there is no way to add to it. */
export const EXPOSURE_PATHS: readonly ExposurePath[] = Object.freeze(SPECS.map((spec) => spec.path));
export const EXPOSURE_CHECK_IDS: readonly string[] = Object.freeze(SPECS.map((spec) => spec.checkId));

/** A fresh, unguessable missing path: 32 bytes from the system's CSPRNG. Separate from the allowlist. */
export function baselinePath(): string {
  return `/agentshield-baseline-${randomBytes(32).toString("hex")}`;
}

// ---------------------------------------------------------------------------
// The baseline and classification.

/**
 * How the site answers a random missing path. Only "catch-all" keeps bytes:
 * the baseline's 4 KB prefix, in memory, for comparison during this scan only.
 */
export type BaselineState =
  | { kind: "not-found" }
  | { kind: "catch-all"; bytes: Buffer }
  | { kind: "unavailable" }
  | { kind: "ambiguous" };

/** Requests that ended without a usable response. Fatal (safety) failures stop the scan, exactly as in M1. */
function unusable(fetched: Extract<FetchResult, { ok: false }>): string {
  if (fetched.reason === "request-budget-exceeded") return NOT_CHECKED_SUMMARIES["request-budget"];
  return fetched.reason === "timeout" ? EXPOSURE_SUMMARIES.timeout : EXPOSURE_SUMMARIES.failed;
}

function stopOnFatal(fetched: FetchResult): FetchResult {
  if (!fetched.ok && FATAL_REASONS.has(fetched.reason)) throw new ScanStopped(fetched.reason);
  return fetched;
}

/** The baseline outcome: the state the probes compare against, and its own result row. */
export function classifyBaseline(fetched: FetchResult): { state: BaselineState; check: CheckResult } {
  const row = (state: BaselineState, summary: string, pass: boolean) => ({
    state,
    check: {
      ...(pass ? result(BASELINE_CHECK_ID, BASELINE_TITLE, [], summary) : errored(BASELINE_CHECK_ID, BASELINE_TITLE, summary)),
      group: "exposure-baseline" as const,
    },
  });
  if (!fetched.ok) return row({ kind: "unavailable" }, fetched.reason === "request-budget-exceeded" ? unusable(fetched) : EXPOSURE_SUMMARIES.baselineUnavailable, false);
  const { status, prefix } = fetched;
  if (status === 404 || status === 410) return row({ kind: "not-found" }, EXPOSURE_SUMMARIES.baselineNotFound, true);
  // Redirects, a refused range, server errors and compressed bodies give nothing to compare with.
  if ((status >= 300 && status < 400) || status === 416 || status >= 500 || !prefix || prefix.kind !== "read") {
    return row({ kind: "unavailable" }, EXPOSURE_SUMMARIES.baselineUnavailable, false);
  }
  if ((status === 200 || status === 206) && prefix.bytes.length > 0) {
    return row({ kind: "catch-all", bytes: prefix.bytes }, EXPOSURE_SUMMARIES.baselineCatchAll, true);
  }
  // 401, 403, other 4xx, other 2xx, or an empty 200: the site's answer cannot be relied on either way.
  return row({ kind: "ambiguous" }, EXPOSURE_SUMMARIES.baselineAmbiguous, false);
}

function commonPrefixLength(a: Buffer, b: Buffer): number {
  const limit = Math.min(a.length, b.length);
  let i = 0;
  while (i < limit && a[i] === b[i]) i += 1;
  return i;
}

/** The same bytes as the baseline, or the same page with small differences (a timestamp, a token). */
function behavesLikeBaseline(bytes: Buffer, baseline: Buffer): boolean {
  if (bytes.equals(baseline)) return true;
  const longer = Math.max(bytes.length, baseline.length);
  return commonPrefixLength(bytes, baseline) >= 512 && Math.abs(bytes.length - baseline.length) <= longer * 0.1;
}

function exposed(spec: ExposureSpec, detection: Detection): CheckResult {
  const finding: Finding = {
    findingId: `${spec.checkId.replace(/^exposure-/, "exposure.")}.exposed`,
    checkId: spec.checkId,
    severity: spec.severity,
    confidence: detection.confidence,
    title: spec.findingTitle,
    explanation: spec.explanation,
    evidence: evidence(`${spec.path}: ${detection.evidence}`),
    remediation: spec.remediation,
    references: [...spec.references],
  };
  return result(spec.checkId, spec.title, [finding], "");
}

/** Classifies one probe response, as an exposure row. */
function classifyExposure(spec: ExposureSpec, fetched: FetchResult, baseline: BaselineState): CheckResult {
  return { ...classifyExposureRow(spec, fetched, baseline), group: "exposure" };
}

/** Only a strict signature match, with the baseline ruling out a catch-all, is a finding. */
function classifyExposureRow(spec: ExposureSpec, fetched: FetchResult, baseline: BaselineState): CheckResult {
  const pass = (summary: string) => result(spec.checkId, spec.title, [], summary);
  const inconclusive = (summary: string) => errored(spec.checkId, spec.title, summary);
  if (!fetched.ok) return inconclusive(unusable(fetched));
  const { status, prefix } = fetched;
  if (status >= 300 && status < 400) return inconclusive(EXPOSURE_SUMMARIES.redirect); // includes 304
  if (status === 416) return inconclusive(EXPOSURE_SUMMARIES.rangeNotSatisfiable);
  if (status >= 500) return inconclusive(EXPOSURE_SUMMARIES.serverError);
  if (status === 404 || status === 410) return pass(EXPOSURE_SUMMARIES.notFound);
  if (status === 401 || status === 403) return pass(EXPOSURE_SUMMARIES.denied);
  if (status !== 200 && status !== 206) return inconclusive(EXPOSURE_SUMMARIES.unexpectedStatus);
  if (!prefix || prefix.kind === "not-read") return inconclusive(EXPOSURE_SUMMARIES.failed);
  if (prefix.kind === "encoded") return inconclusive(EXPOSURE_SUMMARIES.encoded);

  const { bytes, truncated } = prefix;
  if (baseline.kind === "catch-all" && behavesLikeBaseline(bytes, baseline.bytes)) return pass(EXPOSURE_SUMMARIES.likeBaseline);
  const detection = spec.detect(bytes, truncated);
  if (detection === null) return pass(EXPOSURE_SUMMARIES.noSignature);
  switch (baseline.kind) {
    case "not-found":
      return exposed(spec, detection);
    case "catch-all":
      // If a random path also matches, the signature proves nothing on this site.
      return spec.detect(baseline.bytes, false) === null ? exposed(spec, detection) : inconclusive(EXPOSURE_SUMMARIES.baselineMatches);
    default:
      return inconclusive(EXPOSURE_SUMMARIES.baselineUnknown);
  }
}

/** Classifies a response for one of the nine fixed paths (exported for tests; it sends nothing). */
export function classifyExposureResponse(path: ExposurePath, fetched: FetchResult, baseline: BaselineState): CheckResult {
  const spec = SPECS.find((s) => s.path === path);
  if (!spec) throw new Error("not an exposure path");
  return classifyExposure(spec, fetched, baseline);
}

// ---------------------------------------------------------------------------
// Probes for the M2-A stage.

function urlFor(target: ScanTarget, path: string): URL {
  return target.kind === "lab" ? new URL(`${target.origin}${path}`) : new URL(`https://${target.hostname}${path}`);
}

async function fetchPrefix(context: ProbeContext, path: string): Promise<FetchResult> {
  const fetched = await context.fetcher.fetch(context.target, urlFor(context.target, path), {
    budget: context.budget,
    signal: context.signal,
    readPrefix: true,
    followRedirects: false,
  });
  return stopOnFatal(fetched);
}

/**
 * The exposure stage: the baseline probe, then one probe per fixed path, each
 * allowed exactly one request (10 in all). Takes no paths and no options. The
 * baseline state lives only in this closure, for this one scan.
 */
export function createExposureProbes(): PlannedProbe[] {
  let baseline: BaselineState = { kind: "unavailable" };
  const probes: PlannedProbe[] = [
    {
      checkId: BASELINE_CHECK_ID,
      title: BASELINE_TITLE,
      maxRequests: 1,
      group: "exposure-baseline",
      async run(context) {
        const outcome = classifyBaseline(await fetchPrefix(context, baselinePath()));
        baseline = outcome.state;
        return outcome.check;
      },
    },
    ...SPECS.map(
      (spec): PlannedProbe => ({
        checkId: spec.checkId,
        title: spec.title,
        maxRequests: 1,
        group: "exposure",
        async run(context) {
          return classifyExposure(spec, await fetchPrefix(context, spec.path), baseline);
        },
      }),
    ),
  ];
  return probes;
}
