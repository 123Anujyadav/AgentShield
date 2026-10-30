import { redactEvidence } from "@agentshield/engine";
import type { FetchResult } from "./fetcher.js";
import type { ScanTarget } from "./target.js";

/**
 * Findings schema (M1). A passive check reports what it measured; a finding is
 * evidence of a weaker configuration, not proof that the site is exploitable.
 */

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type CheckStatus = "pass" | "fail" | "error" | "not-applicable";
/**
 * Which part of a scan a result belongs to (M2-E). Absent means a passive M1
 * check, so every M1 result and stored record stays valid as it is.
 */
export type CheckGroup = "passive" | "exposure" | "exposure-baseline";

export interface Finding {
  /** Stable identifier, e.g. "header.hsts.missing". */
  findingId: string;
  checkId: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  explanation: string;
  /** Redacted, bounded description of what was observed. Never cookie values or response bodies. */
  evidence: string;
  remediation: string;
  /** CWE and OWASP Top 10 (2021) references where they apply. */
  references: string[];
}

export interface CheckResult {
  checkId: string;
  title: string;
  status: CheckStatus;
  /** Short, fixed-text summary of the outcome. */
  summary: string;
  findings: Finding[];
  /** Set on exposure rows ("exposure") and the baseline diagnostic ("exposure-baseline"); absent on M1 checks. */
  group?: CheckGroup;
}

/** The result's group; a result without one is a passive M1 check. */
export function checkGroup(check: Pick<CheckResult, "group">): CheckGroup {
  return check.group ?? "passive";
}

/** What a passive scan observed. Each fetch is null when it was not attempted. */
export interface PassiveObservations {
  target: ScanTarget;
  /** GET https://host/ following same-host redirects (DNS targets). */
  https: FetchResult | null;
  /** GET http://host/ without following redirects (DNS targets), or the lab origin's root. */
  http: FetchResult | null;
  /** GET /.well-known/security.txt on the primary origin. */
  securityTxt: FetchResult | null;
  /** The Origin sent with the root request to observe CORS reflection. */
  probeOrigin: string;
  now: Date;
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const MAX_EVIDENCE = 200;

/** Evidence text: control characters removed, secret-shaped values redacted, length bounded. */
export function evidence(text: string): string {
  const cleaned = text.replace(/[\u0000-\u001f\u007f]/g, " ");
  const redacted = redactEvidence(cleaned);
  return redacted.length > MAX_EVIDENCE ? `${redacted.slice(0, MAX_EVIDENCE - 3)}...` : redacted;
}

export function headerValues(result: FetchResult | null, name: string): string[] {
  return result?.ok ? (result.headers[name.toLowerCase()] ?? []) : [];
}

/** The response whose headers describe the site: HTTPS for DNS targets, the lab origin otherwise. */
export function primaryResponse(observations: PassiveObservations): FetchResult | null {
  return observations.target.kind === "lab" ? observations.http : observations.https;
}

export function result(checkId: string, title: string, findings: Finding[], passSummary: string): CheckResult {
  return {
    checkId,
    title,
    status: findings.some((f) => f.severity !== "info") ? "fail" : "pass",
    summary: findings.length === 0 ? passSummary : `${findings.length} finding(s)`,
    findings,
  };
}

export function notApplicable(checkId: string, title: string, summary: string): CheckResult {
  return { checkId, title, status: "not-applicable", summary, findings: [] };
}

export function errored(checkId: string, title: string, summary: string): CheckResult {
  return { checkId, title, status: "error", summary, findings: [] };
}

export function summarizeFindings(checks: CheckResult[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const check of checks) for (const finding of check.findings) counts[finding.severity] += 1;
  return counts;
}
