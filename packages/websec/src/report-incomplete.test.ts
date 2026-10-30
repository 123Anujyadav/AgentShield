import { describe, expect, it } from "vitest";
import { createExposureProbes, EXPOSURE_PATHS } from "./checks/exposure.js";
import { DEFAULT_MAX_REDIRECTS, GuardedFetcher, RequestBudget, type Transport } from "./fetcher.js";
import type { CheckResult } from "./findings.js";
import {
  EXPOSURE_INCOMPLETE_SUMMARIES,
  escapeHtml,
  EXPOSURE_REPORT_NOTE,
  exposureSection,
  INCOMPLETE_STATUS_LABEL,
  renderHtmlReport,
  renderJsonReport,
  REPORT_DISCLAIMER,
  REPORT_GENERATOR,
  scanStatusLabel,
  type ScanReport,
} from "./report.js";
import { runPassiveScan } from "./scan.js";
import type { DnsTarget } from "./target.js";

/**
 * M2-H: a completed scan whose exposure stage stopped early (time limit or request
 * budget) is reported as incomplete, from the scheduler's own signal. Fake site,
 * in-memory bodies; nothing touches the network.
 */

const target: DnsTarget = { kind: "dns", hostname: "example.com", displayHostname: "example.com" };
const T0 = Date.parse("2026-10-30T00:00:00Z");

/** Every path answers 404 except /.env, which is exposed. */
const transport: Transport = async (request) => {
  const exposed = request.url.pathname === "/.env";
  const body = exposed ? Buffer.from("A_NAME=one\nB_NAME=two\n") : null;
  return {
    status: exposed ? 200 : 404,
    headers: {},
    body: body === null ? null : (async function* () { yield new Uint8Array(body); })(),
    tls: null,
    close: () => {},
  };
};

async function scanWith(budget: number, deadlineMs = 120_000) {
  const fetcher = new GuardedFetcher({ resolver: async () => [{ address: "93.184.215.14", family: 4 }], transport });
  return runPassiveScan({ target, fetcher, budget: new RequestBudget(budget), now: () => new Date(T0), probeStage: { probes: createExposureProbes(), deadline: T0 + deadlineMs } });
}

function report(overrides: Partial<ScanReport>): ScanReport {
  return {
    scanId: "scan-9",
    target: { hostname: "example.com", displayHostname: "example.com", kind: "dns" },
    status: "completed",
    reason: null,
    requestedAt: "2026-10-30T00:00:00.000Z",
    startedAt: "2026-10-30T00:00:01.000Z",
    finishedAt: "2026-10-30T00:00:02.000Z",
    requestsUsed: 3,
    requestBudget: 30,
    options: { exposureChecks: true },
    checks: [],
    ...overrides,
  };
}

const statusRow = (html: string) => /<tr><th>Status<\/th><td>([^<]*)<\/td><\/tr>/.exec(html)?.[1];

describe("M2-H: incomplete exposure stage", () => {
  it("the scheduler's own signal marks a budget stop; the report says incomplete while M1 and finished rows are kept", async () => {
    const scan = await scanWith(7); // 3 passive + baseline + 3 paths
    expect(scan.probesStoppedEarly).toBe("request-budget");
    const r = report({ checks: scan.checks, requestsUsed: scan.requestsUsed, exposureStoppedEarly: scan.probesStoppedEarly });
    const json = JSON.parse(renderJsonReport(r));
    expect(json.status).toBe("completed");
    expect(json.exposure.incomplete).toEqual({ reason: "request-budget", summary: EXPOSURE_INCOMPLETE_SUMMARIES["request-budget"] });
    expect(json.checks).toHaveLength(12);
    expect(json.exposure.paths.map((p: { outcome: string }) => p.outcome)).toEqual([
      "not-exposed",
      "not-exposed",
      "exposed",
      ...Array(6).fill("not-checked"),
    ]);
    const html = renderHtmlReport(r);
    expect(statusRow(html)).toBe(INCOMPLETE_STATUS_LABEL);
    // Escaped like every other value ("scan's" becomes "scan&#39;s").
    expect(html).toContain(escapeHtml(EXPOSURE_INCOMPLETE_SUMMARIES["request-budget"]));
  });

  it("a time-limit stop is reported as incomplete for time", async () => {
    const scan = await scanWith(30, 1); // less than the reserve: nothing in the stage starts
    expect(scan.probesStoppedEarly).toBe("time-limit");
    const section = exposureSection({ exposureChecks: true }, "completed", scan.checks, scan.probesStoppedEarly);
    expect(section.requested && section.incomplete).toEqual({ reason: "time-limit", summary: EXPOSURE_INCOMPLETE_SUMMARIES["time-limit"] });
    expect(section.requested && section.paths.every((p) => p.outcome === "not-checked")).toBe(true);
  });

  it("a stage that ran every path is complete, and the report says plain completed", async () => {
    const scan = await scanWith(30);
    expect(scan.probesStoppedEarly).toBeNull();
    const r = report({ checks: scan.checks, exposureStoppedEarly: scan.probesStoppedEarly });
    expect(JSON.parse(renderJsonReport(r)).exposure.incomplete).toBeNull();
    expect(statusRow(renderHtmlReport(r))).toBe("completed");
  });

  it("inconclusive rows alone never make the stage incomplete", () => {
    const inconclusive: CheckResult[] = EXPOSURE_PATHS.map((_, i) => ({
      checkId: ["exposure-git-head", "exposure-git-config", "exposure-env", "exposure-ds-store", "exposure-server-status", "exposure-backup-zip", "exposure-backup-tar-gz", "exposure-database-sql", "exposure-dump-sql"][i]!,
      title: "x",
      status: "error",
      summary: "Inconclusive: the server returned an error.",
      findings: [],
      group: "exposure",
    }));
    const section = exposureSection({ exposureChecks: true }, "completed", inconclusive, null);
    expect(section.requested && [section.incomplete, section.counts.inconclusive]).toEqual([null, 9]);
    expect(scanStatusLabel("completed", section)).toBe("completed");
  });

  it("not requested, failed and rejected scans keep their own state and are never marked incomplete", () => {
    expect(exposureSection({ exposureChecks: false }, "completed", [], "time-limit")).toEqual({ requested: false, state: "not-requested" });
    for (const status of ["failed", "rejected", "running"] as const) {
      const section = exposureSection({ exposureChecks: true }, status, [], "time-limit");
      expect(section.requested && [section.state, section.incomplete]).toEqual(["not-run", null]);
      expect(scanStatusLabel(status, section)).toBe(status);
    }
    const html = renderHtmlReport(report({ status: "failed", reason: "scan-timeout", exposureStoppedEarly: "time-limit" }));
    expect(statusRow(html)).toBe("failed (scan-timeout)");
    expect(html).not.toContain(INCOMPLETE_STATUS_LABEL);
  });

  it("missing rows in an incomplete stage stay not checked, never not exposed", () => {
    const section = exposureSection({ exposureChecks: true }, "completed", [], "request-budget");
    expect(section.requested && section.paths.every((p) => p.outcome === "not-checked")).toBe(true);
    expect(section.requested && section.counts["not-exposed"]).toBe(0);
  });
});

describe("M2-H: report naming and request wording", () => {
  it("the generator names the current capability, not M1, and claims nothing active", () => {
    const json = JSON.parse(renderJsonReport(report({ options: { exposureChecks: false } })));
    expect(json.generator).toBe(REPORT_GENERATOR);
    expect(REPORT_GENERATOR).not.toContain("M1");
    expect(REPORT_GENERATOR).toMatch(/passive/i);
    expect(REPORT_GENERATOR).not.toMatch(/active scan|exploit|attack/i);
  });

  it("the disclaimer matches the code: five redirect hops, each a request, no redirect on the plain-HTTP root, one shared budget and time limit", () => {
    expect(DEFAULT_MAX_REDIRECTS).toBe(5);
    expect(REPORT_DISCLAIMER).toContain("up to five hops each, and every hop is a separate request");
    expect(REPORT_DISCLAIMER).toContain("the plain-HTTP root is never followed");
    expect(REPORT_DISCLAIMER).toContain("share one request budget and one time limit");
    expect(REPORT_DISCLAIMER).not.toMatch(/three requests/i);
  });

  it("the exposure note describes the baseline, the nine fixed paths, no redirects, the 4 KB limit and early stopping", () => {
    expect(EXPOSURE_PATHS).toHaveLength(9);
    for (const phrase of ["random missing path for comparison", "nine fixed paths", "never following redirects", "first 4 KB", "not checked"]) {
      expect(EXPOSURE_REPORT_NOTE).toContain(phrase);
    }
  });
});
