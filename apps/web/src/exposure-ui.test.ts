import { describe, expect, it } from "vitest";
import view from "./components/views/WebsiteScansView.tsx?raw";
import {
  BASELINE_CHECK_ID,
  EXPOSURE_OUTCOME_LABELS,
  exposureOutcomeTone,
  INCOMPLETE_STATUS_LABEL,
  NOT_REQUESTED_LABEL,
  resultGroup,
  scanStateLabel,
  exposureAvailability,
  exposureFindingCount,
  exposureOptInHelp,
  exposureRequestLabel,
  exposureRowLabel,
  groupChecks,
  scanRequestBody,
} from "./exposure-ui.js";

/** Exposure checks in the Website Scans view (M2-D). No browser: pure helpers plus the view's source. */

const PATHS = ["/.git/HEAD", "/.git/config", "/.env", "/.DS_Store", "/server-status", "/backup.zip", "/backup.tar.gz", "/database.sql", "/dump.sql"];

const check = (checkId: string, status: "pass" | "fail" | "error" | "not-applicable", summary = "", findings: unknown[] = []) => ({ checkId, title: checkId, status, summary, findings });

describe("exposure availability comes only from the server", () => {
  it("is unknown until the server reports a real boolean", () => {
    expect(exposureAvailability(null)).toBe("unknown");
    expect(exposureAvailability({})).toBe("unknown");
    expect(exposureAvailability({ exposureChecks: { enabled: "true", paths: PATHS } as never })).toBe("unknown");
    expect(exposureAvailability({ exposureChecks: { enabled: false, paths: PATHS } })).toBe("disabled");
    expect(exposureAvailability({ exposureChecks: { enabled: true, paths: PATHS } })).toBe("enabled");
  });

  it("the view shows the checkbox only when the server says exposure checks are enabled", () => {
    expect(view).toContain("const exposure = exposureAvailability(settings);");
    expect(view).toMatch(/\{exposure === "enabled" && settings\?\.exposureChecks && \(\s*<label/);
    expect(view).toContain('{exposure === "disabled" && " Exposure checks are disabled on this server."}');
  });
});

describe("the scan request", () => {
  it("is the target plus a real boolean, true only when ticked and allowed by the server", () => {
    expect(scanRequestBody("tgt-1", false, "enabled")).toEqual({ targetId: "tgt-1", includeExposureChecks: false });
    expect(scanRequestBody("tgt-1", true, "enabled")).toEqual({ targetId: "tgt-1", includeExposureChecks: true });
    expect(scanRequestBody("tgt-1", true, "disabled")).toEqual({ targetId: "tgt-1", includeExposureChecks: false });
    expect(scanRequestBody("tgt-1", true, "unknown")).toEqual({ targetId: "tgt-1", includeExposureChecks: false });
    expect(Object.keys(scanRequestBody("tgt-1", true, "enabled"))).toEqual(["targetId", "includeExposureChecks"]);
  });

  it("the view builds every scan request with scanRequestBody and clears the tick on each submission", () => {
    expect(view).not.toMatch(/post\("\/api\/scans", \{/);
    expect(view).toContain("const body = scanRequestBody(target.id, exposureOptIn[target.id] === true, exposure);");
    const submit = view.slice(view.indexOf("async function onStartScan"), view.indexOf("async function onStartScan") + 400);
    expect(submit.indexOf("[target.id]: false")).toBeGreaterThan(-1);
    expect(submit.indexOf("[target.id]: false")).toBeLessThan(submit.indexOf('await post("/api/scans", body'));
  });

  it("the checkbox starts unticked, is per target and is disabled whenever a scan cannot start", () => {
    expect(view).toContain("useState<Record<string, boolean>>({})");
    expect(view).toContain("checked={exposureOptIn[target.id] === true}");
    expect(view).toContain("disabled={busy !== null || !canScan(target)}");
    // Two inputs only: the site address and this checkbox. No path, URL or header fields.
    expect(view.match(/<input\b/g)).toHaveLength(2);
    expect(view).toContain('type="checkbox"');
  });
});

describe("wording", () => {
  it("explains the fixed paths, the baseline, the read limit and that a WAF may log it, without claiming to exploit", () => {
    const help = exposureOptInHelp(PATHS);
    expect(help).toContain("9 fixed paths");
    for (const path of PATHS) expect(help).toContain(path);
    expect(help).toContain("one random missing path");
    expect(help).toContain("first 4 KB");
    expect(help).toContain("Nothing is exploited, changed or downloaded in full");
    expect(help).toMatch(/firewall \(WAF\) may log/);
    expect(help).not.toMatch(/attack|payload|vulnerab/i);
  });
});

describe("results and history", () => {
  it("history shows the recorded request: requested, not requested, or not recorded", () => {
    expect(exposureRequestLabel({ options: { exposureChecks: true } })).toBe("Exposure checks: requested");
    expect(exposureRequestLabel({ options: { exposureChecks: false } })).toBe("Exposure checks: not requested");
    expect(exposureRequestLabel({})).toBe("Exposure checks: not recorded");
    expect(view).toContain("{exposureRequestLabel(scan)}");
    expect(view).toContain("Not requested for this scan.");
  });

  it("the baseline is kept apart from the path checks and never counted as a finding", () => {
    const checks = [
      check("tls", "pass"),
      check(BASELINE_CHECK_ID, "pass", "The site answers a random missing path with content.", ["not a real finding"]),
      check("exposure-env", "fail", "1 finding(s)", [{}]),
      check("exposure-dump-sql", "error", "Inconclusive: the request timed out."),
    ];
    const groups = groupChecks(checks);
    expect(groups.passive.map((c) => c.checkId)).toEqual(["tls"]);
    expect(groups.baseline?.checkId).toBe(BASELINE_CHECK_ID);
    expect(groups.exposure.map((c) => c.checkId)).toEqual(["exposure-env", "exposure-dump-sql"]);
    expect(exposureFindingCount(checks)).toBe(1);
  });

  it("an opted-out scan shows no exposure rows at all", () => {
    expect(groupChecks([check("tls", "pass"), check("security-txt", "fail", "", [{}])]).exposure).toEqual([]);
    expect(view).toMatch(/selected\.options\?\.exposureChecks !== true \? \(/);
  });

  it("an error is shown as inconclusive or not checked, never as a pass", () => {
    expect(exposureRowLabel(check("exposure-env", "fail"))).toBe("exposed");
    expect(exposureRowLabel(check("exposure-env", "pass"))).toBe("not exposed");
    expect(exposureRowLabel(check("exposure-env", "error", "Inconclusive: the server returned an error."))).toBe("inconclusive");
    expect(exposureRowLabel(check("exposure-env", "error", "Not checked: the scan reached its time limit before this check could finish."))).toBe("not checked");
  });
});

describe("M2-E: typed grouping and consistent outcome labels", () => {
  it("the server's typed group decides; the ID is only a fallback for results without one", () => {
    expect(resultGroup({ checkId: "exposure-env", group: "passive" })).toBe("passive");
    expect(resultGroup({ checkId: "tls", group: "exposure" })).toBe("exposure");
    expect(resultGroup({ checkId: "anything", group: "exposure-baseline" })).toBe("exposure-baseline");
    expect(resultGroup({ checkId: "tls" })).toBe("passive");
    expect(resultGroup({ checkId: BASELINE_CHECK_ID })).toBe("exposure-baseline");
    const groups = groupChecks([
      { checkId: "exposure-env", group: "passive" as const },
      { checkId: "row-1", group: "exposure" as const },
      { checkId: "diag", group: "exposure-baseline" as const },
    ]);
    expect([groups.passive.map((c) => c.checkId), groups.exposure.map((c) => c.checkId), groups.baseline?.checkId]).toEqual([["exposure-env"], ["row-1"], "diag"]);
  });

  it("labels match the reports exactly, and not requested is its own label", () => {
    expect(EXPOSURE_OUTCOME_LABELS).toEqual({ exposed: "Exposed", "not-exposed": "Not exposed", inconclusive: "Inconclusive", "not-checked": "Not checked" });
    expect(NOT_REQUESTED_LABEL).toBe("Not requested");
  });

  it("inconclusive and not checked are amber, never the pass colour", () => {
    expect(exposureOutcomeTone("exposed")).toBe("block");
    expect(exposureOutcomeTone("not-exposed")).toBe("allow");
    expect(exposureOutcomeTone("inconclusive")).toBe("confirm");
    expect(exposureOutcomeTone("not-checked")).toBe("confirm");
  });

  it("the view renders the server's nine path outcomes and keeps the baseline as a diagnostic line", () => {
    expect(view).toContain("const section = selected.exposure;");
    expect(view).toContain("{section.paths.map((row) => (");
    expect(view).toContain("label={EXPOSURE_OUTCOME_LABELS[row.outcome]}");
    expect(view).toContain("color={TONE_COLOR[exposureOutcomeTone(row.outcome)]}");
    expect(view).toContain("Baseline diagnostic (a random missing path, used only for comparison; never a finding):");
    // The baseline is never drawn as a check row, and passive rows come from the typed grouping.
    expect(view).not.toMatch(/groups\.baseline/);
    expect(view).not.toMatch(/groups\.exposure/);
    expect(view).toContain("{groups.passive.map((check) => (");
  });

  it("requested or not comes from the persisted option; a missing option is 'not recorded', never 'not requested'", () => {
    expect(view).toMatch(/selected\.options\?\.exposureChecks !== true \? \(\s*selected\.options\?\.exposureChecks === false \? \(/);
    expect(view).toContain("Whether exposure checks were requested was not recorded for this scan.");
    expect(view).toContain("Exposure checks were requested, but no exposure results were returned.");
  });
});

describe("M2-H: a completed scan with an incomplete exposure stage", () => {
  it("is labelled from the server's typed flag, in the reports' words, and only when completed", () => {
    expect(INCOMPLETE_STATUS_LABEL).toBe("completed — exposure checks incomplete");
    expect(scanStateLabel({ status: "completed", exposureIncomplete: true })).toBe(INCOMPLETE_STATUS_LABEL);
    expect(scanStateLabel({ status: "completed", exposureIncomplete: false })).toBe("completed");
    expect(scanStateLabel({ status: "completed" })).toBe("completed");
    expect(scanStateLabel({ status: "completed", exposureIncomplete: "true" })).toBe("completed");
    for (const status of ["failed", "rejected", "running", "queued"]) expect(scanStateLabel({ status, exposureIncomplete: true })).toBe(status);
  });

  it("history and detail use the label, in amber, and the detail explains what was not tested", () => {
    expect(view).toContain('<Badge label={scanStateLabel(scan)} color={scan.exposureIncomplete === true ? "var(--confirm)"');
    expect(view).toContain("{selected.id} · {selected.displayHostname} · {scanStateLabel(selected)}");
    expect(view).toContain("{section.incomplete && (");
    expect(view).toContain("{section.incomplete.summary} The paths marked not checked were not tested.");
    expect(view).not.toMatch(/<Badge label=\{scan\.status\}/);
  });
});
