import { describe, expect, it } from "vitest";
import { BASELINE_CHECK_ID, createExposureProbes, EXPOSURE_CHECK_IDS, EXPOSURE_PATHS } from "./checks/exposure.js";
import { GuardedFetcher, RequestBudget, type Transport, type TransportRequest } from "./fetcher.js";
import type { CheckResult } from "./findings.js";
import {
  EXPOSURE_GAP_SUMMARIES,
  EXPOSURE_OUTCOME_LABELS,
  exposureOutcome,
  exposureSection,
  passiveChecks,
  renderHtmlReport,
  renderJsonReport,
  type ScanReport,
} from "./report.js";
import { PASSIVE_CHECKS, runPassiveScan } from "./scan.js";
import { NOT_CHECKED_SUMMARIES } from "./stages.js";
import type { DnsTarget } from "./target.js";

/**
 * Reports with exposure checks (M2-E). The opted-in scan below is produced by
 * the real probes against a fake site (generated in-memory bodies); nothing
 * touches the network. Credential-shaped values are assembled at runtime.
 */

const target: DnsTarget = { kind: "dns", hostname: "example.com", displayHostname: "example.com" };
const PUBLIC = [{ address: "93.184.215.14", family: 4 }];
const T0 = Date.parse("2026-10-30T00:00:00Z");

const AWS_KEY = ["AKIA", "Z7Q4K2M9", "R5T8W3X6"].join("");
const GIT_CRED = ["deploy", ":", "Pw7", "Kq2", "Zr9"].join("");
const BASELINE_SENTINEL = "BASELINE-SENTINEL-5e21";
const HOSTILE = `<img src=x onerror=alert(1)>"'\``;
const BODIES: Record<string, { status: number; body?: string | Buffer }> = {
  baseline: { status: 200, body: `<html><body>${BASELINE_SENTINEL}</body></html>` },
  "/.git/config": { status: 200, body: `[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://${GIT_CRED}@git.example.net/acme/site.git\n` },
  "/.env": { status: 200, body: `APP_NAME=shopfront\nAWS_ACCESS_KEY_ID=${AWS_KEY}\nNOTE=${HOSTILE}\n` },
  "/.DS_Store": { status: 500, body: "server error" },
  "/server-status": {
    status: 200,
    body: "<html><head><title>Apache Status</title></head><body><h1>Apache Server Status for shop (via 10.20.30.40)</h1><dl><dt>Server Version: Apache/2.4.58</dt></dl><td>203.0.113.77</td><td>GET /admin/payroll?id=7</td></body></html>",
  },
  "/backup.zip": { status: 200, body: Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.from("customer-list.csv")]) },
  "/database.sql": { status: 200, body: "-- MySQL dump 10.13  Distrib 8.0.36\nINSERT INTO `customers` VALUES ('alice@shop.example');\n" },
};
const NEVER_IN_REPORTS = [
  BASELINE_SENTINEL,
  "agentshield-baseline-",
  AWS_KEY,
  "AWS_ACCESS_KEY_ID",
  "APP_NAME",
  "shopfront",
  GIT_CRED,
  "git.example.net",
  "10.20.30.40",
  "203.0.113.77",
  "/admin/payroll",
  "customer-list",
  "customers",
  "alice@shop.example",
  "onerror=alert",
];

/** A completed opted-in scan: budget 12 = 3 passive + baseline + 8 paths, so /dump.sql is not checked. */
async function optedInReport(): Promise<ScanReport> {
  const transport: Transport = async (request: TransportRequest) => {
    const path = request.url.pathname;
    const reply = path.startsWith("/agentshield-baseline-") ? BODIES.baseline! : (BODIES[path] ?? { status: 404 });
    const bytes = reply.body === undefined ? null : Buffer.from(reply.body);
    return {
      status: reply.status,
      headers: {},
      body: bytes === null ? null : (async function* () { yield new Uint8Array(bytes); })(),
      tls: null,
      close: () => {},
    };
  };
  const fetcher = new GuardedFetcher({ resolver: async () => PUBLIC, transport });
  const scan = await runPassiveScan({
    target,
    fetcher,
    budget: new RequestBudget(12),
    now: () => new Date(T0),
    probeStage: { probes: createExposureProbes(), deadline: T0 + 120_000 },
  });
  return report({ options: { exposureChecks: true }, checks: scan.checks, requestsUsed: scan.requestsUsed });
}

function report(overrides: Partial<ScanReport>): ScanReport {
  return {
    scanId: "scan-7",
    target: { hostname: "example.com", displayHostname: "example.com", kind: "dns" },
    status: "completed",
    reason: null,
    requestedAt: "2026-10-30T00:00:00.000Z",
    startedAt: "2026-10-30T00:00:01.000Z",
    finishedAt: "2026-10-30T00:00:02.000Z",
    requestsUsed: 3,
    requestBudget: 30,
    options: { exposureChecks: false },
    checks: [],
    ...overrides,
  };
}

const passiveOnly: CheckResult[] = [
  { checkId: "hsts", title: "HSTS", status: "fail", summary: "1 finding(s)", findings: [{ findingId: "header.hsts.missing", checkId: "hsts", severity: "medium", confidence: "high", title: "No HSTS", explanation: "x", evidence: "none", remediation: "y", references: [] }] },
  { checkId: "security-txt", title: "security.txt", status: "pass", summary: "present", findings: [] },
];

const EXPECTED_OUTCOMES = {
  "/.git/HEAD": "not-exposed",
  "/.git/config": "exposed",
  "/.env": "exposed",
  "/.DS_Store": "inconclusive",
  "/server-status": "exposed",
  "/backup.zip": "exposed",
  "/backup.tar.gz": "not-exposed",
  "/database.sql": "exposed",
  "/dump.sql": "not-checked",
} as const;

// --- A. JSON ---------------------------------------------------------------------

describe("A. JSON report: exposure section", () => {
  it("an opted-out report says not requested and keeps the M1 checks and summary exactly", () => {
    const json = JSON.parse(renderJsonReport(report({ checks: passiveOnly }))) as Record<string, unknown>;
    expect(json.options).toEqual({ exposureChecks: false });
    expect(json.exposure).toEqual({ requested: false, state: "not-requested" });
    expect(json.checks).toEqual(passiveOnly);
    expect(json.summary).toEqual({ critical: 0, high: 0, medium: 1, low: 0, info: 0 });
    expect(String(json.disclaimer)).not.toContain("Exposure checks were requested");
  });

  it("requested is taken from the recorded option, never from the results", () => {
    // Exposure-looking rows without the option: not requested, and the rows are not reported as exposure results.
    const stray: CheckResult = { checkId: "exposure-env", title: "x", status: "fail", summary: "1 finding(s)", findings: passiveOnly[0]!.findings, group: "exposure" };
    const json = JSON.parse(renderJsonReport(report({ checks: [...passiveOnly, stray] }))) as { exposure: unknown; checks: CheckResult[] };
    expect(json.exposure).toEqual({ requested: false, state: "not-requested" });
    expect(json.checks.map((c) => c.checkId)).toEqual(["hsts", "security-txt"]);
    // The option without any exposure findings: still requested.
    const quiet = exposureSection({ exposureChecks: true }, "completed", passiveOnly);
    expect(quiet.requested).toBe(true);
  });

  it("an opted-in report lists the nine fixed paths with their actual outcomes; the baseline is separate", async () => {
    const json = JSON.parse(renderJsonReport(await optedInReport())) as {
      options: unknown;
      checks: CheckResult[];
      exposure: { requested: true; state: string; baseline: { outcome: string; summary: string }; paths: Array<{ path: string; outcome: string; status: string }>; counts: Record<string, number>; findings: Record<string, number> };
      summary: Record<string, number>;
    };
    expect(json.options).toEqual({ exposureChecks: true });
    expect(json.exposure.state).toBe("completed");
    expect(json.exposure.paths.map((p) => p.path)).toEqual([...EXPOSURE_PATHS]);
    expect(Object.fromEntries(json.exposure.paths.map((p) => [p.path, p.outcome]))).toEqual(EXPECTED_OUTCOMES);
    expect(json.exposure.counts).toEqual({ exposed: 5, "not-exposed": 2, inconclusive: 1, "not-checked": 1 });
    expect(json.exposure.baseline).toEqual({ outcome: "catch-all", summary: "The site answers a random missing path with content; exposure results are compared with it." });
    // The passive list is exactly the twelve M1 checks: no exposure row and no baseline row.
    expect(json.checks.map((c) => c.checkId)).toEqual(PASSIVE_CHECKS.map((_, i) => json.checks[i]!.checkId));
    expect(json.checks).toHaveLength(PASSIVE_CHECKS.length);
    expect(json.checks.some((c) => c.checkId === BASELINE_CHECK_ID || EXPOSURE_CHECK_IDS.includes(c.checkId))).toBe(false);
  });

  it("baseline is never counted: exposure findings come from the nine paths only, and the summary is passive + exposure", async () => {
    const r = await optedInReport();
    const json = JSON.parse(renderJsonReport(r)) as { exposure: { findings: Record<string, number> }; summary: Record<string, number> };
    const exposedFindings = r.checks.filter((c) => c.group === "exposure").flatMap((c) => c.findings);
    const passiveFindings = passiveChecks(r.checks).flatMap((c) => c.findings);
    expect(Object.values(json.exposure.findings).reduce((a, b) => a + b, 0)).toBe(exposedFindings.length);
    expect(Object.values(json.summary).reduce((a, b) => a + b, 0)).toBe(exposedFindings.length + passiveFindings.length);
    // Even a corrupted baseline row carrying a finding would not be counted.
    const tainted = r.checks.map((c) => (c.group === "exposure-baseline" ? { ...c, findings: passiveOnly[0]!.findings } : c));
    const again = JSON.parse(renderJsonReport({ ...r, checks: tainted })) as { summary: Record<string, number> };
    expect(again.summary).toEqual(json.summary);
  });

  it("inconclusive and not checked never read as a pass", () => {
    expect(exposureOutcome({ status: "error", summary: "Inconclusive: the server returned an error.", findings: [] })).toBe("inconclusive");
    for (const summary of Object.values(NOT_CHECKED_SUMMARIES)) expect(exposureOutcome({ status: "error", summary, findings: [] })).toBe("not-checked");
    expect(exposureOutcome({ status: "not-applicable", summary: "", findings: [] })).toBe("inconclusive");
    expect(exposureOutcome({ status: "fail", summary: "", findings: [] })).toBe("inconclusive");
    expect(exposureOutcome({ status: "pass", summary: "Not exposed: the path was not found.", findings: [] })).toBe("not-exposed");
  });

  it("a requested scan that did not complete lists nine paths, all not checked", () => {
    for (const [status, summary] of [
      ["failed", EXPOSURE_GAP_SUMMARIES.incomplete],
      ["rejected", EXPOSURE_GAP_SUMMARIES.incomplete],
      ["running", EXPOSURE_GAP_SUMMARIES.pending],
    ] as const) {
      const section = exposureSection({ exposureChecks: true }, status, []);
      expect(section).toMatchObject({ requested: true, state: "not-run", counts: { exposed: 0, "not-exposed": 0, inconclusive: 0, "not-checked": 9 } });
      if (section.requested) {
        expect(section.paths.every((p) => p.outcome === "not-checked" && p.summary === summary)).toBe(true);
        expect(section.baseline).toEqual({ outcome: "not-checked", summary });
      }
    }
  });

  it("a completed scan missing a path's row reports that path as not checked, never as not exposed", () => {
    const section = exposureSection({ exposureChecks: true }, "completed", passiveOnly);
    if (!section.requested) throw new Error("expected requested");
    expect(section.paths.map((p) => [p.outcome, p.summary])).toEqual(Array(9).fill(["not-checked", EXPOSURE_GAP_SUMMARIES.missing]));
    expect(section.baseline).toEqual({ outcome: "not-checked", summary: EXPOSURE_GAP_SUMMARIES.baselineMissing });
  });

  it("secret values, the baseline path and bytes, and target-controlled content are absent", async () => {
    const json = renderJsonReport(await optedInReport());
    for (const leaked of NEVER_IN_REPORTS) expect(json, leaked).not.toContain(leaked);
  });

  it("outcome labels are the fixed words shared with the UI", () => {
    expect(EXPOSURE_OUTCOME_LABELS).toEqual({ exposed: "Exposed", "not-exposed": "Not exposed", inconclusive: "Inconclusive", "not-checked": "Not checked" });
  });
});

// --- B. HTML ---------------------------------------------------------------------

describe("B. HTML report: exposure section", () => {
  it("says not requested for an opted-out scan, with no exposure table", () => {
    const html = renderHtmlReport(report({ checks: passiveOnly }));
    expect(html).toContain("<tr><th>Exposure checks</th><td>Not requested</td></tr>");
    expect(html).toContain("Not requested for this scan. No exposure request was sent.");
    expect(html).not.toContain('class="exposure-table"');
  });

  it("lists exactly the nine paths with their outcomes; the baseline is a diagnostic note, not a tenth row", async () => {
    const html = renderHtmlReport(await optedInReport());
    expect(html).toContain("<tr><th>Exposure checks</th><td>Requested</td></tr>");
    const table = html.slice(html.indexOf('<table class="exposure-table">'), html.indexOf("</table>", html.indexOf('<table class="exposure-table">')));
    const rows = [...table.matchAll(/<tr><td><code>([^<]+)<\/code><\/td><td><span class="outcome outcome-([a-z-]+)">([^<]+)<\/span>/g)];
    expect(rows.map((r) => r[1])).toEqual([...EXPOSURE_PATHS]);
    expect(Object.fromEntries(rows.map((r) => [r[1], r[2]]))).toEqual(EXPECTED_OUTCOMES);
    expect(rows.map((r) => r[3])).toEqual(EXPOSURE_PATHS.map((p) => EXPOSURE_OUTCOME_LABELS[EXPECTED_OUTCOMES[p]]));
    expect(table).not.toContain("baseline");
    expect(html).toContain("Baseline diagnostic (a random missing path, used only for comparison; never a finding)");
    // The M1 section has no exposure or baseline rows either.
    expect(html).not.toContain("Missing-path baseline");
  });

  it("styles inconclusive and not checked in amber, never with the pass colours", () => {
    const html = renderHtmlReport(report({ options: { exposureChecks: true }, checks: [] }));
    const css = html.slice(html.indexOf("<style>"), html.indexOf("</style>"));
    const rule = (name: string) => css.slice(css.indexOf(`.outcome-${name}{`), css.indexOf("}", css.indexOf(`.outcome-${name}{`)));
    for (const amber of ["inconclusive", "not-checked"]) {
      expect(rule(amber)).toContain("#fffbeb");
      expect(rule(amber)).not.toMatch(/#ecfdf5|#065f46|#059669/);
    }
    expect(rule("not-exposed")).toContain("#059669");
    expect(rule("not-checked")).toContain("dashed");
  });

  it("escapes injection payloads in every exposure field and contains no script or external asset", () => {
    const hostileRow: CheckResult = {
      checkId: "exposure-env",
      title: `Env ${HOSTILE}`,
      status: "fail",
      summary: `<script>alert("s")</script>`,
      group: "exposure",
      findings: [{ findingId: `id${HOSTILE}`, checkId: "exposure-env", severity: "high", confidence: "high", title: `<svg onload=alert(2)>`, explanation: "</td><script>alert(3)</script>", evidence: `<iframe src=//evil>`, remediation: "javascript:alert(4)", references: [`<b>${HOSTILE}</b>`] }],
    };
    const baselineRow: CheckResult = { checkId: BASELINE_CHECK_ID, title: "Missing-path baseline", status: "error", summary: `<img src=y onerror=alert(5)>`, findings: [], group: "exposure-baseline" };
    const html = renderHtmlReport(report({ target: { hostname: "example.com", displayHostname: `ex${HOSTILE}`, kind: "dns" }, options: { exposureChecks: true }, checks: [hostileRow, baselineRow] }));
    expect(html).not.toMatch(/<script>alert|<img src=|<svg onload|<iframe|<b><img/);
    expect(html).toContain("&lt;script&gt;alert(&quot;s&quot;)&lt;/script&gt;");
    expect(html).toContain("&lt;img src=y onerror=alert(5)&gt;");
    // No live tag can load or run anything (escaped payload text is inert and allowed).
    expect(html).not.toMatch(/<(script|link|img|iframe|svg|object|embed)\b|<[a-z][^>]*\s(src|href)=|@import|url\(/i);
  });

  it("contains no secret value, Git credential, status-page address or URL, SQL or archive content, or baseline detail", async () => {
    const html = renderHtmlReport(await optedInReport());
    for (const leaked of NEVER_IN_REPORTS) expect(html, leaked).not.toContain(leaked);
  });

  it("a requested scan that did not complete says so in the exposure section", () => {
    const html = renderHtmlReport(report({ status: "failed", reason: "scan-timeout", options: { exposureChecks: true } }));
    expect(html).toContain("No checks ran for this scan.");
    expect(html).toContain("The scan did not complete, so no path was checked.");
    expect(html.match(/outcome-not-checked/g)!.length).toBeGreaterThanOrEqual(9);
  });
});
