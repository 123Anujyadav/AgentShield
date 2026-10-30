import { EXPOSURE_CHECK_IDS, EXPOSURE_PATHS, EXPOSURE_SUMMARIES, type ExposurePath } from "./checks/exposure.js";
import { checkGroup, SEVERITY_ORDER, summarizeFindings, type CheckResult, type CheckStatus, type Finding, type Severity } from "./findings.js";
import { NOT_CHECKED_SUMMARIES, type NotCheckedReason } from "./stages.js";

/**
 * Scan reports (M1, extended in M2-E). A report contains only the target's host
 * name, scan status and timing, the scan's recorded options, and the check
 * results (already redacted, bounded evidence). It never contains verification
 * challenges, cookie values, response bodies, the baseline path or credentials.
 * Every dynamic value in the HTML report is escaped.
 */

export type ScanStatus = "queued" | "running" | "completed" | "failed" | "rejected";

export interface ScanReport {
  scanId: string;
  target: { hostname: string; displayHostname: string; kind: "dns" | "lab" };
  status: ScanStatus;
  /** Fixed reason code for failed or rejected scans. */
  reason: string | null;
  requestedAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  requestsUsed: number;
  requestBudget: number;
  /** As recorded when the scan was created (M2-D). */
  options: { exposureChecks: boolean };
  /**
   * M2-H: why the exposure stage stopped scheduling before every path was checked,
   * exactly as the scheduler reported it; null or absent when it did not stop early.
   */
  exposureStoppedEarly?: NotCheckedReason | null;
  /** Every result of the scan: passive checks, and for opted-in scans the exposure rows and baseline diagnostic. */
  checks: CheckResult[];
}

export const REPORT_GENERATOR = "AgentShield passive website scanner (passive configuration checks, opt-in exposure checks)";

export const REPORT_DISCLAIMER =
  "Passive configuration checks only: no crawling, no payloads. The passive checks fetch the site's root (over HTTPS and plain HTTP for a real site, once for a lab site) and /.well-known/security.txt. Same-host redirects from the HTTPS (or lab) root and from security.txt are followed, up to five hops each, and every hop is a separate request; the plain-HTTP root is never followed. All requests in a scan share one request budget and one time limit. A finding is evidence of a weaker configuration, not proof that the site is exploitable, and a clean report is not a certification.";

export const EXPOSURE_REPORT_NOTE =
  "Exposure checks were requested: one GET request to a random missing path for comparison, then one to each of nine fixed paths, never following redirects and reading at most the first 4 KB of each. They count against the same request budget and time limit; any path not reached is reported as not checked. Only fixed text, counts and secret kinds are reported, never file contents.";

/** Fixed text for an exposure stage that stopped before every path was checked (M2-H). */
export const EXPOSURE_INCOMPLETE_SUMMARIES: Readonly<Record<NotCheckedReason, string>> = Object.freeze({
  "time-limit": "Exposure checks incomplete: the scan reached its time limit before every path was checked.",
  "request-budget": "Exposure checks incomplete: the scan's request budget ran out before every path was checked.",
  stopped: "Exposure checks incomplete: the scan was stopped before every path was checked.",
});

export const INCOMPLETE_STATUS_LABEL = "completed \u2014 exposure checks incomplete";

// ---------------------------------------------------------------------------
// Exposure section: one shared reading of the results for the JSON report, the
// HTML report and the API, so all three always agree.

export type ExposureOutcome = "exposed" | "not-exposed" | "inconclusive" | "not-checked";
export type BaselineOutcome = "not-found" | "catch-all" | "inconclusive" | "not-checked";

export const EXPOSURE_OUTCOME_LABELS: Readonly<Record<ExposureOutcome, string>> = Object.freeze({
  exposed: "Exposed",
  "not-exposed": "Not exposed",
  inconclusive: "Inconclusive",
  "not-checked": "Not checked",
});

export const BASELINE_OUTCOME_LABELS: Readonly<Record<BaselineOutcome, string>> = Object.freeze({
  "not-found": "Missing paths return not found",
  "catch-all": "Missing paths return content (compared)",
  inconclusive: "Inconclusive",
  "not-checked": "Not checked",
});

/** Fixed summaries for paths with no recorded result. */
export const EXPOSURE_GAP_SUMMARIES = Object.freeze({
  missing: "Not checked: no result was recorded for this path.",
  baselineMissing: "Not checked: no baseline result was recorded.",
  incomplete: "Not checked: the scan did not complete.",
  pending: "Not checked yet: the scan has not finished.",
});

export interface ExposurePathResult {
  path: ExposurePath;
  checkId: string;
  title: string;
  outcome: ExposureOutcome;
  status: CheckStatus;
  summary: string;
  findings: Finding[];
}

export type ExposureSection =
  | { requested: false; state: "not-requested" }
  | {
      requested: true;
      /** "completed": the scan finished and these are its results; "not-run": it did not, so nothing was checked. */
      state: "completed" | "not-run";
      /**
       * M2-H: set when the scan completed but the scheduler stopped the exposure stage
       * before every path was checked (time limit or request budget). Never set by an
       * individual inconclusive result.
       */
      incomplete: { reason: NotCheckedReason; summary: string } | null;
      /** How the site answered a random missing path. Never its path or bytes; never a finding. */
      baseline: { outcome: BaselineOutcome; summary: string };
      /** Always the nine fixed paths, in order. */
      paths: ExposurePathResult[];
      counts: Record<ExposureOutcome, number>;
      /** Exposure findings only; the baseline never contributes. */
      findings: Record<Severity, number>;
    };

const NOT_CHECKED = new Set<string>(Object.values(NOT_CHECKED_SUMMARIES));

/** How one exposure row reads. An error is inconclusive or not checked; it is never a pass. */
export function exposureOutcome(check: Pick<CheckResult, "status" | "summary" | "findings">): ExposureOutcome {
  if (check.status === "fail" && check.findings.length > 0) return "exposed";
  if (check.status === "pass" && check.findings.length === 0) return "not-exposed";
  if (check.status === "error" && NOT_CHECKED.has(check.summary)) return "not-checked";
  return "inconclusive";
}

function baselineOutcome(check: CheckResult): BaselineOutcome {
  if (check.status === "pass" && check.summary === EXPOSURE_SUMMARIES.baselineNotFound) return "not-found";
  if (check.status === "pass" && check.summary === EXPOSURE_SUMMARIES.baselineCatchAll) return "catch-all";
  if (check.status === "error" && NOT_CHECKED.has(check.summary)) return "not-checked";
  return "inconclusive";
}

/** The passive (M1) checks of a scan: everything that is not an exposure row or the baseline. */
export function passiveChecks(checks: readonly CheckResult[]): CheckResult[] {
  return checks.filter((check) => checkGroup(check) === "passive");
}

/**
 * The exposure section of a scan. Requested comes only from the recorded
 * option, never from results. Rows are found by their typed group; only the
 * nine fixed paths are listed, and a path without a result is not checked.
 */
export function exposureSection(
  options: { exposureChecks: boolean },
  status: ScanStatus,
  checks: readonly CheckResult[],
  stoppedEarly: NotCheckedReason | null = null,
): ExposureSection {
  if (options.exposureChecks !== true) return { requested: false, state: "not-requested" };
  const completed = status === "completed";
  const gap = completed ? EXPOSURE_GAP_SUMMARIES.missing : status === "queued" || status === "running" ? EXPOSURE_GAP_SUMMARIES.pending : EXPOSURE_GAP_SUMMARIES.incomplete;
  const rows = completed ? checks.filter((check) => checkGroup(check) === "exposure") : [];
  const baselineRow = completed ? checks.find((check) => checkGroup(check) === "exposure-baseline") : undefined;

  const paths: ExposurePathResult[] = EXPOSURE_PATHS.map((path, index) => {
    const checkId = EXPOSURE_CHECK_IDS[index]!;
    const row = rows.find((check) => check.checkId === checkId);
    if (!row) return { path, checkId, title: path, outcome: "not-checked", status: "error", summary: gap, findings: [] };
    return { path, checkId, title: row.title, outcome: exposureOutcome(row), status: row.status, summary: row.summary, findings: row.findings };
  });
  const counts: Record<ExposureOutcome, number> = { exposed: 0, "not-exposed": 0, inconclusive: 0, "not-checked": 0 };
  for (const row of paths) counts[row.outcome] += 1;
  return {
    requested: true,
    state: completed ? "completed" : "not-run",
    incomplete: completed && stoppedEarly !== null ? { reason: stoppedEarly, summary: EXPOSURE_INCOMPLETE_SUMMARIES[stoppedEarly] } : null,
    baseline: baselineRow
      ? { outcome: baselineOutcome(baselineRow), summary: baselineRow.summary }
      : { outcome: "not-checked", summary: completed ? EXPOSURE_GAP_SUMMARIES.baselineMissing : gap },
    paths,
    counts,
    findings: summarizeFindings(paths.map((row) => ({ checkId: row.checkId, title: row.title, status: row.status, summary: row.summary, findings: row.findings }))),
  };
}

/** Findings counted for the report: passive checks plus the nine exposure rows. The baseline never counts. */
function reportSummary(report: ScanReport, section: ExposureSection): Record<Severity, number> {
  const passive = summarizeFindings(passiveChecks(report.checks));
  if (!section.requested) return passive;
  const total = { ...passive };
  for (const severity of SEVERITY_ORDER) total[severity] += section.findings[severity];
  return total;
}

/** The scan's state in words: a completed scan whose exposure stage stopped early is never just "completed". */
export function scanStatusLabel(status: ScanStatus, section: ExposureSection): string {
  return status === "completed" && section.requested && section.incomplete !== null ? INCOMPLETE_STATUS_LABEL : status;
}

function sectionFor(report: ScanReport): ExposureSection {
  return exposureSection(report.options, report.status, report.checks, report.exposureStoppedEarly ?? null);
}

function disclaimerFor(report: ScanReport): string {
  return report.options.exposureChecks ? `${REPORT_DISCLAIMER} ${EXPOSURE_REPORT_NOTE}` : REPORT_DISCLAIMER;
}

export function renderJsonReport(report: ScanReport): string {
  const exposure = sectionFor(report);
  return JSON.stringify(
    {
      generator: REPORT_GENERATOR,
      disclaimer: disclaimerFor(report),
      scanId: report.scanId,
      target: report.target,
      status: report.status,
      reason: report.reason,
      requestedAt: report.requestedAt,
      startedAt: report.startedAt,
      finishedAt: report.finishedAt,
      requestsUsed: report.requestsUsed,
      requestBudget: report.requestBudget,
      options: { exposureChecks: report.options.exposureChecks },
      // The passive checks, exactly as in M1 reports; exposure rows and the baseline are under "exposure".
      checks: passiveChecks(report.checks),
      exposure,
      summary: reportSummary(report, exposure),
    },
    null,
    2,
  );
}

// ---------------------------------------------------------------------------
// HTML

const HTML_ESCAPES: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" };

export function escapeHtml(value: unknown): string {
  return String(value ?? "").replace(/[&<>"'`]/g, (ch) => HTML_ESCAPES[ch]!);
}

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#7f1d1d",
  high: "#b91c1c",
  medium: "#b45309",
  low: "#1d4ed8",
  info: "#4b5563",
};

const e = escapeHtml;

function renderFinding(f: Finding): string {
  return `<div class="finding">
  <p><span class="sev" style="background:${SEVERITY_COLORS[f.severity]}">${e(f.severity)}</span> <strong>${e(f.title)}</strong> <span class="muted">(${e(f.findingId)}, confidence ${e(f.confidence)})</span></p>
  <p>${e(f.explanation)}</p>
  <p><strong>Evidence:</strong> <code>${e(f.evidence)}</code></p>
  <p><strong>Remediation:</strong> ${e(f.remediation)}</p>
  ${f.references.length > 0 ? `<p class="muted">References: ${f.references.map(e).join(", ")}</p>` : ""}
</div>`;
}

function sortedFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}

function renderCheck(check: CheckResult): string {
  return `<section>
  <h3>${e(check.title)} <span class="status status-${e(check.status)}">${e(check.status)}</span></h3>
  <p class="muted">${e(check.summary)}</p>
  ${sortedFindings(check.findings).map(renderFinding).join("\n")}
</section>`;
}

/** Outcome classes come from a fixed set; they are never built from result text. */
function outcomeBadge(outcome: ExposureOutcome): string {
  return `<span class="outcome outcome-${outcome}">${e(EXPOSURE_OUTCOME_LABELS[outcome])}</span>`;
}

function baselineBadge(outcome: BaselineOutcome): string {
  const tone = outcome === "inconclusive" || outcome === "not-checked" ? "outcome-inconclusive" : "outcome-neutral";
  return `<span class="outcome ${tone}">${e(BASELINE_OUTCOME_LABELS[outcome])}</span>`;
}

function renderExposure(section: ExposureSection): string {
  if (!section.requested) {
    return `<section class="exposure">
<h2>Exposure checks</h2>
<p class="muted">Not requested for this scan. No exposure request was sent.</p>
</section>`;
  }
  const rows = section.paths
    .map((row) => {
      const top = sortedFindings(row.findings)[0];
      return `<tr><td><code>${e(row.path)}</code></td><td>${outcomeBadge(row.outcome)}</td><td>${top ? `<span class="sev" style="background:${SEVERITY_COLORS[top.severity]}">${e(top.severity)}</span>` : "&mdash;"}</td><td>${e(row.summary)}</td></tr>`;
    })
    .join("\n");
  const details = section.paths
    .filter((row) => row.outcome === "exposed")
    .map((row) => `<section>
  <h3><code>${e(row.path)}</code> ${outcomeBadge(row.outcome)}</h3>
  ${sortedFindings(row.findings).map(renderFinding).join("\n")}
</section>`)
    .join("\n");
  const counts = (Object.keys(EXPOSURE_OUTCOME_LABELS) as ExposureOutcome[]).map((o) => `${e(EXPOSURE_OUTCOME_LABELS[o])} ${section.counts[o]}`).join(", ");
  return `<section class="exposure">
<h2>Exposure checks</h2>
<p>Requested. ${section.state === "not-run" ? "The scan did not complete, so no path was checked." : e(counts)}</p>
${section.incomplete ? `<p class="incomplete"><span class="outcome outcome-not-checked">${e(INCOMPLETE_STATUS_LABEL)}</span> ${e(section.incomplete.summary)}</p>` : ""}
<p class="muted">Baseline diagnostic (a random missing path, used only for comparison; never a finding): ${baselineBadge(section.baseline.outcome)} ${e(section.baseline.summary)}</p>
<table class="exposure-table">
<tr><th>Path</th><th>Result</th><th>Severity</th><th>Summary</th></tr>
${rows}
</table>
${details}
</section>`;
}

export function renderHtmlReport(report: ScanReport): string {
  const exposure = sectionFor(report);
  const summary = reportSummary(report, exposure);
  const checks = passiveChecks(report.checks).map(renderCheck).join("\n");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentShield scan report: ${e(report.target.displayHostname)}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#111;background:#fff}
code{background:#f3f4f6;padding:0 .25rem;word-break:break-all}
.muted{color:#4b5563;font-size:.9em}
.sev{color:#fff;border-radius:4px;padding:0 .4rem;font-size:.8em;text-transform:uppercase}
.status{font-size:.75em;border:1px solid #9ca3af;border-radius:4px;padding:0 .3rem;text-transform:uppercase}
.finding{border-left:3px solid #d1d5db;padding-left:.75rem;margin:.75rem 0}
table{border-collapse:collapse}td,th{border:1px solid #d1d5db;padding:.25rem .5rem;text-align:left}
.outcome{border-radius:4px;padding:0 .35rem;font-size:.8em;font-weight:600;white-space:nowrap}
.outcome-exposed{background:#fee2e2;color:#7f1d1d;border:1px solid #b91c1c}
.outcome-not-exposed{background:#ecfdf5;color:#065f46;border:1px solid #059669}
.outcome-inconclusive{background:#fffbeb;color:#92400e;border:1px solid #d97706}
.outcome-not-checked{background:#fffbeb;color:#92400e;border:1px dashed #d97706}
.outcome-neutral{background:#f3f4f6;color:#374151;border:1px solid #9ca3af}
</style>
</head>
<body>
<h1>AgentShield passive scan report</h1>
<p class="muted">${e(disclaimerFor(report))}</p>
<table>
<tr><th>Target</th><td>${e(report.target.displayHostname)} (${e(report.target.hostname)}, ${e(report.target.kind)})</td></tr>
<tr><th>Scan</th><td>${e(report.scanId)}</td></tr>
<tr><th>Status</th><td>${e(scanStatusLabel(report.status, exposure))}${report.reason ? ` (${e(report.reason)})` : ""}</td></tr>
<tr><th>Requested</th><td>${e(report.requestedAt)}</td></tr>
<tr><th>Started</th><td>${e(report.startedAt ?? "not started")}</td></tr>
<tr><th>Finished</th><td>${e(report.finishedAt ?? "not finished")}</td></tr>
<tr><th>Requests</th><td>${e(report.requestsUsed)} of ${e(report.requestBudget)}</td></tr>
<tr><th>Exposure checks</th><td>${report.options.exposureChecks ? "Requested" : "Not requested"}</td></tr>
<tr><th>Findings</th><td>${SEVERITY_ORDER.map((s) => `${e(s)} ${summary[s]}`).join(", ")}</td></tr>
</table>
${report.status === "completed" ? checks : "<p><strong>No checks ran for this scan.</strong></p>"}
${renderExposure(exposure)}
</body>
</html>
`;
}
