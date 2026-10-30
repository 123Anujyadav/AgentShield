import { describe, expect, it } from "vitest";
import { GuardedFetcher, RequestBudget, type Resolver, type Transport, type TransportRequest } from "./fetcher.js";
import { result, type CheckResult } from "./findings.js";
import { PASSIVE_CHECKS, runPassiveScan, ScanStopped } from "./scan.js";
import { NOT_CHECKED_SUMMARIES, PROBE_TIME_RESERVE_MS, type PlannedProbe, type ProbeContext } from "./stages.js";
import type { DnsTarget } from "./target.js";

const target: DnsTarget = { kind: "dns", hostname: "example.com", displayHostname: "example.com" };
const PUBLIC = [{ address: "93.184.215.14", family: 4 }];
const T0 = Date.parse("2026-10-30T00:00:00Z");
const M1_PATHS = ["https://example.com/", "http://example.com/", "https://example.com/.well-known/security.txt"];

/** A site that answers every request; `onRequest` can move the clock or interrupt the scan. */
function harness(options: { onRequest?: (request: TransportRequest) => void; resolver?: Resolver } = {}) {
  const requests: TransportRequest[] = [];
  const clock = { ms: T0 };
  const transport: Transport = async (request) => {
    requests.push(request);
    options.onRequest?.(request);
    return { status: 404, headers: {}, body: null, tls: null, close: () => {} };
  };
  const fetcher = new GuardedFetcher({ resolver: options.resolver ?? (async () => PUBLIC), transport });
  return { requests, clock, fetcher, now: () => new Date(clock.ms) };
}

/** A synthetic probe: one fixed path, no redirects. Real exposure probes arrive in M2-B. */
function probe(n: number, extra: Partial<PlannedProbe> = {}): PlannedProbe {
  const checkId = `probe-${n}`;
  return {
    checkId,
    title: `Probe ${n}`,
    maxRequests: 1,
    async run(context: ProbeContext): Promise<CheckResult> {
      const fetched = await context.fetcher.fetch(context.target, new URL(`https://example.com/${checkId}`), {
        budget: context.budget,
        signal: context.signal,
        followRedirects: false,
      });
      if (!fetched.ok && fetched.reason === "blocked-address") throw new ScanStopped(fetched.reason);
      return result(checkId, `Probe ${n}`, [], "Probe ran.");
    },
    ...extra,
  };
}

const probes = (count: number) => Array.from({ length: count }, (_, i) => probe(i + 1));
const passiveIds = PASSIVE_CHECKS.length;
const tail = (checks: CheckResult[]) => checks.slice(passiveIds).map((c) => [c.checkId, c.status, c.summary]);

describe("deadline-aware probe stage (M2-A)", () => {
  it("without a probe stage, or with an empty one, the scan is exactly the M1 passive scan", async () => {
    const plain = harness();
    const baseline = await runPassiveScan({ target, fetcher: plain.fetcher, budget: new RequestBudget(30), now: plain.now });
    const empty = harness();
    const withEmpty = await runPassiveScan({
      target,
      fetcher: empty.fetcher,
      budget: new RequestBudget(30),
      now: empty.now,
      probeStage: { probes: [], deadline: T0 + 120_000 },
    });
    for (const { requests } of [plain, empty]) expect(requests.map((r) => r.url.href)).toEqual(M1_PATHS);
    expect(withEmpty).toEqual(baseline);
    expect(baseline.checks).toHaveLength(passiveIds);
    expect([baseline.requestsUsed, baseline.probesStoppedEarly]).toEqual([3, null]);
  });

  it("runs every planned probe, in order and after the passive requests, when time and budget allow", async () => {
    const h = harness();
    const scan = await runPassiveScan({
      target,
      fetcher: h.fetcher,
      budget: new RequestBudget(30),
      now: h.now,
      probeStage: { probes: probes(3), deadline: T0 + 120_000 },
    });
    expect(h.requests.map((r) => r.url.href)).toEqual([...M1_PATHS, "https://example.com/probe-1", "https://example.com/probe-2", "https://example.com/probe-3"]);
    expect(scan.checks.slice(0, passiveIds).map((c) => c.checkId)).toEqual(
      (await runPassiveScan({ target, fetcher: harness().fetcher, budget: new RequestBudget(30), now: h.now })).checks.map((c) => c.checkId),
    );
    expect(tail(scan.checks).map(([id, status]) => [id, status])).toEqual([
      ["probe-1", "pass"],
      ["probe-2", "pass"],
      ["probe-3", "pass"],
    ]);
    expect([scan.requestsUsed, scan.probesStoppedEarly]).toEqual([6, null]);
  });

  it("time exhaustion before the stage: no probe request is sent, the passive results are kept", async () => {
    const h = harness();
    const scan = await runPassiveScan({
      target,
      fetcher: h.fetcher,
      budget: new RequestBudget(30),
      now: h.now,
      // Less than one probe's worst case remains.
      probeStage: { probes: probes(3), deadline: T0 + PROBE_TIME_RESERVE_MS - 1 },
    });
    expect(h.requests.map((r) => r.url.href)).toEqual(M1_PATHS);
    expect(scan.checks).toHaveLength(passiveIds + 3);
    expect(scan.checks.slice(0, passiveIds).every((c) => c.status !== "error" || !c.summary.startsWith("Not checked"))).toBe(true);
    expect(tail(scan.checks)).toEqual([1, 2, 3].map((n) => [`probe-${n}`, "error", NOT_CHECKED_SUMMARIES["time-limit"]]));
    expect(scan.checks.slice(passiveIds).every((c) => c.findings.length === 0)).toBe(true);
    expect([scan.requestsUsed, scan.probesStoppedEarly]).toEqual([3, "time-limit"]);
  });

  it("time exhaustion mid-stage: stops scheduling once less than the reserve remains, keeping finished probes", async () => {
    // Every request takes 15 s on the scan clock. The passive requests end at +45 s.
    const h = harness({ onRequest: () => (h.clock.ms += 15_000) });
    const scan = await runPassiveScan({
      target,
      fetcher: h.fetcher,
      budget: new RequestBudget(30),
      now: h.now,
      // probe-1 starts with 45 s left, probe-2 with 30 s, probe-3 would start with 15 s (< 20 s reserve).
      probeStage: { probes: probes(4), deadline: T0 + 90_000 },
    });
    expect(h.requests.map((r) => r.url.pathname).slice(3)).toEqual(["/probe-1", "/probe-2"]);
    expect(tail(scan.checks)).toEqual([
      ["probe-1", "pass", "Probe ran."],
      ["probe-2", "pass", "Probe ran."],
      ["probe-3", "error", NOT_CHECKED_SUMMARIES["time-limit"]],
      ["probe-4", "error", NOT_CHECKED_SUMMARIES["time-limit"]],
    ]);
    expect(scan.probesStoppedEarly).toBe("time-limit");
  });

  it("budget exhaustion: stops scheduling when the shared budget cannot cover the next probe", async () => {
    const h = harness();
    const budget = new RequestBudget(5);
    const scan = await runPassiveScan({
      target,
      fetcher: h.fetcher,
      budget,
      now: h.now,
      probeStage: { probes: probes(4), deadline: T0 + 120_000 },
    });
    expect(h.requests.map((r) => r.url.pathname).slice(3)).toEqual(["/probe-1", "/probe-2"]);
    expect(tail(scan.checks).map(([id, status, summary]) => [id, status, summary])).toEqual([
      ["probe-1", "pass", "Probe ran."],
      ["probe-2", "pass", "Probe ran."],
      ["probe-3", "error", NOT_CHECKED_SUMMARIES["request-budget"]],
      ["probe-4", "error", NOT_CHECKED_SUMMARIES["request-budget"]],
    ]);
    expect([budget.spent, budget.remaining, scan.requestsUsed, scan.probesStoppedEarly]).toEqual([5, 0, 5, "request-budget"]);
  });

  it("a probe that needs more requests than remain is not started, and nothing after it is scheduled", async () => {
    const h = harness();
    const scan = await runPassiveScan({
      target,
      fetcher: h.fetcher,
      budget: new RequestBudget(4),
      now: h.now,
      probeStage: { probes: [probe(1, { maxRequests: 2 }), probe(2)], deadline: T0 + 120_000 },
    });
    expect(h.requests).toHaveLength(3);
    expect(tail(scan.checks).map(([id, , summary]) => [id, summary])).toEqual([
      ["probe-1", NOT_CHECKED_SUMMARIES["request-budget"]],
      ["probe-2", NOT_CHECKED_SUMMARIES["request-budget"]],
    ]);
  });

  it("a probe can never send more requests than it declared, even with shared budget left", async () => {
    const h = harness();
    const greedy: PlannedProbe = {
      checkId: "greedy",
      title: "Greedy",
      maxRequests: 1,
      async run(context) {
        const outcomes = [];
        for (const path of ["/a", "/b", "/c"]) {
          const fetched = await context.fetcher.fetch(context.target, new URL(`https://example.com${path}`), { budget: context.budget, followRedirects: false });
          outcomes.push(fetched.ok ? "sent" : fetched.reason);
        }
        return result("greedy", "Greedy", [], outcomes.join(","));
      },
    };
    const budget = new RequestBudget(30);
    const scan = await runPassiveScan({ target, fetcher: h.fetcher, budget, now: h.now, probeStage: { probes: [greedy], deadline: T0 + 120_000 } });
    expect(h.requests.map((r) => r.url.pathname).slice(3)).toEqual(["/a"]);
    expect(scan.checks.at(-1)?.summary).toBe("sent,request-budget-exceeded,request-budget-exceeded");
    expect(budget.spent).toBe(4);
  });

  it("interrupted by the time limit mid-probe: that probe and later ones are not checked, earlier results are kept", async () => {
    const controller = new AbortController();
    const h = harness({
      onRequest: (request) => {
        if (request.url.pathname === "/probe-2") controller.abort(new DOMException("The scan reached its time limit.", "TimeoutError"));
      },
    });
    const scan = await runPassiveScan({
      target,
      fetcher: h.fetcher,
      budget: new RequestBudget(30),
      signal: controller.signal,
      now: h.now,
      // The deadline itself has not passed on the scan clock; the abort reason alone marks the time limit.
      probeStage: { probes: probes(3), deadline: T0 + 120_000 },
    });
    expect(h.requests.map((r) => r.url.pathname).slice(3)).toEqual(["/probe-1", "/probe-2"]);
    expect(scan.checks.slice(0, passiveIds)).toHaveLength(passiveIds);
    expect(tail(scan.checks)).toEqual([
      ["probe-1", "pass", "Probe ran."],
      // probe-2 returned "pass", but from a cancelled request: never trusted.
      ["probe-2", "error", NOT_CHECKED_SUMMARIES["time-limit"]],
      ["probe-3", "error", NOT_CHECKED_SUMMARIES["time-limit"]],
    ]);
    expect(scan.probesStoppedEarly).toBe("time-limit");
  });

  it("a probe that throws because the scan was cancelled is reported as stopped, not as a failure", async () => {
    const controller = new AbortController();
    const h = harness();
    const throwing: PlannedProbe = {
      ...probe(1),
      async run() {
        controller.abort(); // a plain abort: stopped from outside, not the time limit
        throw new ScanStopped("cancelled");
      },
    };
    const scan = await runPassiveScan({
      target,
      fetcher: h.fetcher,
      budget: new RequestBudget(30),
      signal: controller.signal,
      now: h.now,
      probeStage: { probes: [throwing, probe(2)], deadline: T0 + 120_000 },
    });
    expect(h.requests).toHaveLength(3);
    expect(tail(scan.checks).map(([id, , summary]) => [id, summary])).toEqual([
      ["probe-1", NOT_CHECKED_SUMMARIES.stopped],
      ["probe-2", NOT_CHECKED_SUMMARIES.stopped],
    ]);
    expect(scan.probesStoppedEarly).toBe("stopped");
  });

  it("a safety refusal during the probe stage still stops the whole scan, as in M1", async () => {
    let lookups = 0;
    const h = harness({
      resolver: async () => {
        lookups += 1;
        // The name moves to a private address after the passive requests (a rebinding attempt).
        return lookups <= 3 ? PUBLIC : [{ address: "10.0.0.5", family: 4 }];
      },
    });
    await expect(
      runPassiveScan({ target, fetcher: h.fetcher, budget: new RequestBudget(30), now: h.now, probeStage: { probes: probes(2), deadline: T0 + 120_000 } }),
    ).rejects.toBeInstanceOf(ScanStopped);
    expect(h.requests).toHaveLength(3);
  });

  it("not-checked results carry only the fixed summaries", () => {
    expect(Object.values(NOT_CHECKED_SUMMARIES).every((s) => s.startsWith("Not checked: "))).toBe(true);
    expect(new Set(Object.values(NOT_CHECKED_SUMMARIES)).size).toBe(3);
  });
});
