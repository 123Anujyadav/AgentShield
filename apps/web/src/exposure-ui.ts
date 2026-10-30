/**
 * Exposure checks in the Website Scans view (M2-D). Pure helpers, so the rules
 * the screen follows can be tested without a browser.
 *
 * Availability always comes from the server's settings (GET /api/targets);
 * nothing here assumes it. The request body carries only the target and a
 * real boolean.
 */

/** As reported by GET /api/targets → settings.exposureChecks. */
export interface ExposureCapability {
  enabled: boolean;
  paths: string[];
}

export type ExposureAvailability = "enabled" | "disabled" | "unknown";

interface CheckLike {
  checkId: string;
  status: "pass" | "fail" | "error" | "not-applicable";
  summary: string;
  findings: unknown[];
  /** The server's typed group (M2-E); absent on passive M1 checks. */
  group?: "passive" | "exposure" | "exposure-baseline";
}

/** The server's exposure outcome codes (GET /api/scans/:id → exposure.paths[].outcome). */
export type ExposureOutcome = "exposed" | "not-exposed" | "inconclusive" | "not-checked";

/** The same words as the reports (EXPOSURE_OUTCOME_LABELS in @agentshield/websec). */
export const EXPOSURE_OUTCOME_LABELS: Readonly<Record<ExposureOutcome, string>> = Object.freeze({
  exposed: "Exposed",
  "not-exposed": "Not exposed",
  inconclusive: "Inconclusive",
  "not-checked": "Not checked",
});
export const NOT_REQUESTED_LABEL = "Not requested";

/** The same words as the reports (INCOMPLETE_STATUS_LABEL in @agentshield/websec). */
export const INCOMPLETE_STATUS_LABEL = "completed \u2014 exposure checks incomplete";

/**
 * A scan's state in words (M2-H). A completed scan whose exposure stage the server
 * reports as stopped early is never shown as just "completed".
 */
export function scanStateLabel(scan: { status: string; exposureIncomplete?: unknown }): string {
  return scan.status === "completed" && scan.exposureIncomplete === true ? INCOMPLETE_STATUS_LABEL : scan.status;
}

export const BASELINE_OUTCOME_LABELS = Object.freeze({
  "not-found": "Missing paths return not found",
  "catch-all": "Missing paths return content (compared)",
  inconclusive: "Inconclusive",
  "not-checked": "Not checked",
} as const);

/** Colour tone for an outcome: amber for inconclusive and not checked, never the pass colour. */
export function exposureOutcomeTone(outcome: ExposureOutcome): "block" | "allow" | "confirm" {
  if (outcome === "exposed") return "block";
  if (outcome === "not-exposed") return "allow";
  return "confirm";
}

export const BASELINE_CHECK_ID = "exposure-baseline";
export const EXPOSURE_OPT_IN_LABEL = "Include exposure checks";

/** Whether the server allows exposure checks; "unknown" until it has said so. */
export function exposureAvailability(settings: { exposureChecks?: ExposureCapability } | null): ExposureAvailability {
  const capability = settings?.exposureChecks;
  if (!capability || typeof capability.enabled !== "boolean") return "unknown";
  return capability.enabled ? "enabled" : "disabled";
}

/** The POST /api/scans body. includeExposureChecks is true only when ticked and the server allows it. */
export function scanRequestBody(targetId: string, optedIn: boolean, availability: ExposureAvailability): { targetId: string; includeExposureChecks: boolean } {
  return { targetId, includeExposureChecks: optedIn === true && availability === "enabled" };
}

/** Help text beside the checkbox: what is sent, what is not, and who may notice. */
export function exposureOptInHelp(paths: readonly string[]): string {
  return (
    `Also sends one passive GET request to each of ${paths.length} fixed paths (${paths.join(", ")}) ` +
    "and to one random missing path for comparison. Only the first 4 KB of each response is read. " +
    "Nothing is exploited, changed or downloaded in full. The site's security tools or firewall (WAF) may log these requests."
  );
}

/** The scan's recorded request, never inferred from its results. */
export function exposureRequestLabel(scan: { options?: { exposureChecks?: unknown } }): string {
  const requested = scan.options?.exposureChecks;
  if (requested === true) return "Exposure checks: requested";
  if (requested === false) return "Exposure checks: not requested";
  return "Exposure checks: not recorded";
}

export function isExposureCheck(checkId: string): boolean {
  return checkId.startsWith("exposure-") && checkId !== BASELINE_CHECK_ID;
}

type Group = NonNullable<CheckLike["group"]>;

/**
 * A result's group. The server's typed group decides; the ID convention is only
 * a fallback for a result recorded without one.
 */
export function resultGroup(check: { checkId: string; group?: Group }): Group {
  if (check.group === "passive" || check.group === "exposure" || check.group === "exposure-baseline") return check.group;
  if (check.checkId === BASELINE_CHECK_ID) return "exposure-baseline";
  return isExposureCheck(check.checkId) ? "exposure" : "passive";
}

/** Splits results into the passive checks, the baseline diagnostic and the path checks. */
export function groupChecks<T extends { checkId: string; group?: Group }>(checks: readonly T[]): { passive: T[]; baseline: T | null; exposure: T[] } {
  return {
    passive: checks.filter((c) => resultGroup(c) === "passive"),
    baseline: checks.find((c) => resultGroup(c) === "exposure-baseline") ?? null,
    exposure: checks.filter((c) => resultGroup(c) === "exposure"),
  };
}

/** Findings from the path checks only; the baseline never counts. */
export function exposureFindingCount(checks: readonly CheckLike[]): number {
  return groupChecks(checks).exposure.reduce((sum, check) => sum + check.findings.length, 0);
}

/** Badge text for a path check. An error is inconclusive or not checked, never a pass. */
export function exposureRowLabel(check: CheckLike): string {
  if (check.status === "fail") return "exposed";
  if (check.status === "pass") return "not exposed";
  if (check.status === "error") return check.summary.startsWith("Not checked") ? "not checked" : "inconclusive";
  return check.status;
}
