import { SEVERITY_ORDER, summarizeFindings, type CheckResult, type Severity } from "./findings.js";

/**
 * Scan reports (M1). A report contains only the target's host name, scan
 * status and timing, and the check results (already redacted, bounded
 * evidence). It never contains verification challenges, cookie values,
 * response bodies or credentials. Every dynamic value in the HTML report is escaped.
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
  checks: CheckResult[];
}

export const REPORT_DISCLAIMER =
  "Passive configuration checks only: three requests to the site's root and security.txt, no crawling, no payloads. A finding is evidence of a weaker configuration, not proof that the site is exploitable, and a clean report is not a certification.";

export function renderJsonReport(report: ScanReport): string {
  return JSON.stringify(
    {
      generator: "AgentShield passive website scanner (M1)",
      disclaimer: REPORT_DISCLAIMER,
      ...report,
      summary: summarizeFindings(report.checks),
    },
    null,
    2,
  );
}

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

export function renderHtmlReport(report: ScanReport): string {
  const summary = summarizeFindings(report.checks);
  const e = escapeHtml;
  const checks = report.checks
    .map((check) => {
      const findings = [...check.findings]
        .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
        .map(
          (f) => `<div class="finding">
  <p><span class="sev" style="background:${SEVERITY_COLORS[f.severity]}">${e(f.severity)}</span> <strong>${e(f.title)}</strong> <span class="muted">(${e(f.findingId)}, confidence ${e(f.confidence)})</span></p>
  <p>${e(f.explanation)}</p>
  <p><strong>Evidence:</strong> <code>${e(f.evidence)}</code></p>
  <p><strong>Remediation:</strong> ${e(f.remediation)}</p>
  ${f.references.length > 0 ? `<p class="muted">References: ${f.references.map(e).join(", ")}</p>` : ""}
</div>`,
        )
        .join("\n");
      return `<section>
  <h3>${e(check.title)} <span class="status status-${e(check.status)}">${e(check.status)}</span></h3>
  <p class="muted">${e(check.summary)}</p>
  ${findings}
</section>`;
    })
    .join("\n");
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
</style>
</head>
<body>
<h1>AgentShield passive scan report</h1>
<p class="muted">${e(REPORT_DISCLAIMER)}</p>
<table>
<tr><th>Target</th><td>${e(report.target.displayHostname)} (${e(report.target.hostname)}, ${e(report.target.kind)})</td></tr>
<tr><th>Scan</th><td>${e(report.scanId)}</td></tr>
<tr><th>Status</th><td>${e(report.status)}${report.reason ? ` (${e(report.reason)})` : ""}</td></tr>
<tr><th>Requested</th><td>${e(report.requestedAt)}</td></tr>
<tr><th>Started</th><td>${e(report.startedAt ?? "not started")}</td></tr>
<tr><th>Finished</th><td>${e(report.finishedAt ?? "not finished")}</td></tr>
<tr><th>Requests</th><td>${e(report.requestsUsed)} of ${e(report.requestBudget)}</td></tr>
<tr><th>Findings</th><td>${SEVERITY_ORDER.map((s) => `${e(s)} ${summary[s]}`).join(", ")}</td></tr>
</table>
${report.status === "completed" ? checks : "<p><strong>No checks ran for this scan.</strong></p>"}
</body>
</html>
`;
}
