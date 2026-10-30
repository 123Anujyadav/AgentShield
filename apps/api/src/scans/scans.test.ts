import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import supertest from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  BASELINE_CHECK_ID,
  createExposureProbes,
  errored,
  EXPOSURE_CHECK_IDS,
  EXPOSURE_PATHS,
  EXPOSURE_SUMMARIES,
  NOT_CHECKED_SUMMARIES,
  PASSIVE_CHECKS,
  PREFIX_RANGE_HEADER,
  result,
  type PlannedProbe,
  type Resolver,
  type Transport,
  type TransportRequest,
  type TxtResolver,
} from "@agentshield/websec";
import { createTestApp, request } from "../test-support.js";
import { loadScanConfig, type ScanConfig } from "./config.js";
import { messageFor, refusalMessage, scanMessage, ScanService, TARGET_REJECTION_MESSAGES, verificationRefusal, type ScanServiceDeps } from "./service.js";
import { checkDnsProof, verificationRecordName } from "./verification.js";

/**
 * Website-scan API tests (M1). Every resolver, TXT resolver and transport here
 * is a fake that records its calls; no test sends a DNS query or an HTTP request.
 */

const DAY = 86_400_000;
const COOKIE_SECRET = "COOKIE_VALUE_MUST_NOT_LEAK_7c1f";

interface Fakes {
  transportCalls: TransportRequest[];
  resolverCalls: string[];
  txtCalls: string[];
  txt: Map<string, string[][]>;
  resolve: (hostname: string) => unknown;
  respond: (request: TransportRequest) => Promise<{ status: number; headers: Record<string, string | string[]>; body?: string | Buffer }>;
}

type FakeKit = Fakes & { resolver: Resolver; txtResolver: TxtResolver; transport: Transport };

/** One object: tests may replace resolve/respond at any time and the fakes use the new behaviour. */
function fakes(): FakeKit {
  const f: FakeKit = {
    transportCalls: [],
    resolverCalls: [],
    txtCalls: [],
    txt: new Map(),
    resolve: () => [{ address: "93.184.215.14", family: 4 }],
    respond: async (req): Promise<{ status: number; headers: Record<string, string | string[]> }> =>
      req.url.protocol === "http:" && req.port === 80
        ? { status: 301, headers: { location: `https://${req.url.hostname}/` } }
        : { status: 200, headers: { server: "nginx/1.27.0 <script>alert(1)</script>", "set-cookie": `sid=${COOKIE_SECRET}` } },
    resolver: async (hostname) => {
      f.resolverCalls.push(hostname);
      return f.resolve(hostname);
    },
    txtResolver: async (name) => {
      f.txtCalls.push(name);
      const records = f.txt.get(name);
      if (!records) throw Object.assign(new Error("no data"), { code: "ENODATA" });
      return records;
    },
    transport: async (req) => {
      f.transportCalls.push(req);
      const { status, headers, body } = await f.respond(req);
      const bytes = body === undefined ? null : Buffer.from(body);
      const stream = bytes === null ? null : (async function* () { yield new Uint8Array(bytes); })();
      return { status, headers, body: stream, tls: null, close: () => {} };
    },
  };
  return f;
}

function setup(configOverrides: Partial<ScanConfig> = {}, env: NodeJS.ProcessEnv = {}, deps: Pick<ScanServiceDeps, "probePlanner"> = {}) {
  const f = fakes();
  let clock = Date.parse("2026-10-29T00:00:00Z");
  const config = { ...loadScanConfig(env), ...configOverrides };
  const service = new ScanService({ config, resolver: f.resolver, txtResolver: f.txtResolver, transport: f.transport, now: () => clock, ...deps });
  const app = createTestApp({ scanService: service });
  return {
    f,
    service,
    app,
    advance: (ms: number) => (clock += ms),
    /** Publishes the target's challenge as the owner would. */
    publish(target: { hostname: string; dnsRecord: { name: string; value: string } | null }) {
      f.txt.set(target.dnsRecord!.name, [[target.dnsRecord!.value]]);
    },
  };
}

async function register(app: ReturnType<typeof createTestApp>, url: string) {
  const res = await request(app).post("/api/targets").send({ url });
  return res;
}

afterEach(() => {
  vi.useRealTimers();
});

describe("M1 scan configuration fails closed", () => {
  it("outbound scanning and lab mode are off unless set to exactly 'true'", () => {
    for (const value of [undefined, "", "TRUE", "True", "1", "yes", "on", " true", "true ", "false"]) {
      const config = loadScanConfig({ SCAN_NETWORK_ENABLED: value, SCAN_LAB_MODE: value, SCAN_LAB_ORIGINS: "http://127.0.0.1:8081" });
      expect([config.networkEnabled, config.lab.enabled, config.lab.origins.size], String(value)).toEqual([false, false, 0]);
    }
    const on = loadScanConfig({ SCAN_NETWORK_ENABLED: "true" });
    expect([on.networkEnabled, on.lab.enabled]).toEqual([true, false]);
  });

  it("lab mode accepts only exact loopback origins on ports 8080-8099, never AgentShield's own port", () => {
    const config = loadScanConfig({
      SCAN_LAB_MODE: "true",
      SCAN_LAB_ORIGINS: [
        "http://127.0.0.1:8081",
        "http://[::1]:8082",
        "http://localhost:8083",
        "http://10.0.0.1:8084",
        "https://127.0.0.1:8085",
        "http://127.0.0.1:8090", // the API's own PORT below
        "http://127.0.0.1:4000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8100",
        "http://127.0.0.1:6379",
      ].join(","),
      PORT: "8090",
    });
    expect([...config.lab.origins.keys()]).toEqual(["http://127.0.0.1:8081", "http://[::1]:8082"]);
    expect(config.lab.rejectedEntries).toBe(8);
    expect(config.networkEnabled).toBe(false);
  });

  it("the defaults are the documented limits", () => {
    expect(loadScanConfig({})).toMatchObject({
      verificationTtlMs: 30 * DAY,
      maxTargets: 50,
      maxScans: 50,
      maxConcurrentScans: 2,
      requestBudget: 30,
      scanTimeoutMs: 120_000,
      probeReserveMs: 20_000,
      rateLimits: { verify: 10, startScan: 5 },
    });
  });
});

describe("M1 routes require authentication", () => {
  it("every scan route refuses unauthenticated requests", async () => {
    const { app, f } = setup({ networkEnabled: true });
    const calls: Array<[string, string]> = [
      ["get", "/api/targets"],
      ["post", "/api/targets"],
      ["delete", "/api/targets/tgt-1"],
      ["post", "/api/targets/tgt-1/verify"],
      ["post", "/api/scans"],
      ["get", "/api/scans"],
      ["get", "/api/scans/scan-1"],
      ["get", "/api/scans/scan-1/report.json"],
      ["get", "/api/scans/scan-1/report.html"],
    ];
    for (const [method, url] of calls) {
      const res = await (supertest(app) as unknown as Record<string, (u: string) => supertest.Test>)[method]!(url);
      expect(res.status, `${method} ${url}`).toBe(401);
    }
    expect([f.transportCalls.length, f.resolverCalls.length, f.txtCalls.length]).toEqual([0, 0, 0]);
  });
});

describe("M1 with outbound scanning disabled (the default)", () => {
  it("registers targets but never verifies or scans them, and sends nothing", async () => {
    const { app, f } = setup();
    const created = await register(app, "https://Example.com/");
    expect(created.status).toBe(201);
    expect(created.body.target).toMatchObject({
      id: "tgt-1",
      kind: "dns",
      hostname: "example.com",
      verification: { method: "dns-txt", status: "pending" },
      dnsRecord: { type: "TXT", name: "_agentshield-verification.example.com", value: expect.stringMatching(/^agentshield-verification=[A-Za-z0-9_-]{32}$/) },
    });

    const verify = await request(app).post("/api/targets/tgt-1/verify").send({});
    expect([verify.status, verify.body.reason]).toEqual([409, "outbound-scanning-disabled"]);

    // A client cannot switch scanning on: unknown body fields are ignored.
    const scan = await request(app).post("/api/scans").send({ targetId: "tgt-1", networkEnabled: true, SCAN_NETWORK_ENABLED: "true", force: true });
    expect([scan.status, scan.body.reason, scan.body.scan.status]).toEqual([409, "outbound-scanning-disabled", "rejected"]);
    expect(scan.body.scan.message).toMatch(/disabled/);

    const list = await request(app).get("/api/scans");
    expect(list.body.settings).toMatchObject({ outboundScanningEnabled: false, labModeEnabled: false });
    expect(list.body.scans[0]).toMatchObject({ status: "rejected", requestsUsed: 0 });
    expect([f.transportCalls.length, f.resolverCalls.length, f.txtCalls.length]).toEqual([0, 0, 0]);
  });

  it("refuses invalid targets with fixed reasons", async () => {
    const { app } = setup();
    for (const [url, reason] of [
      ["http://127.0.0.1:8081", "port-not-allowed"],
      ["http://127.0.0.1", "ip-literal-not-allowed"],
      ["https://169.254.169.254", "ip-literal-not-allowed"],
      ["https://example.com:8443", "port-not-allowed"],
      ["https://user@example.com", "credentials-not-allowed"],
      ["https://intranet.local", "special-use-hostname"],
      ["file:///etc/passwd", "unsupported-scheme"],
    ]) {
      const res = await register(app, url!);
      expect([res.status, res.body.reason], url).toEqual([400, reason]);
    }
    expect((await request(app).post("/api/targets").send({ url: 42 })).body.reason).toBe("invalid-input");
  });

  it("explains every target-validation refusal accurately, never as a scan (D1 regression)", async () => {
    const { app } = setup();
    const cases: Array<[unknown, string]> = [
      [42, "invalid-input"],
      ["https://exam\tple.com", "invalid-characters"],
      ["ftp://example.com", "unsupported-scheme"],
      ["https://exa%mple.com", "invalid-url"],
      ["https://user:pass@example.com", "credentials-not-allowed"],
      ["https://example.com/path", "path-not-allowed"],
      ["https://example.com:8443", "port-not-allowed"],
      ["https://127.0.0.1", "ip-literal-not-allowed"],
      ["https://example.com.", "trailing-dot"],
      ["https://under_score.example.com", "invalid-hostname"],
      ["https://printer.local", "special-use-hostname"],
    ];
    expect(new Set(cases.map(([, reason]) => reason)).size).toBe(Object.keys(TARGET_REJECTION_MESSAGES).length);
    for (const [url, reason] of cases) {
      const res = await request(app).post("/api/targets").send({ url });
      expect([res.status, res.body.reason], String(url)).toEqual([400, reason]);
      expect(res.body.error).toBe(TARGET_REJECTION_MESSAGES[reason]);
      expect(res.body.error).not.toMatch(/\bscan\b/i); // the word "scan", not the SCAN_LAB_ORIGINS setting name
      expect(res.body).not.toHaveProperty("scan");
    }
  });

  it("uses a generic fallback for unknown refusal reasons, and a scan-specific one only for scans", () => {
    expect(refusalMessage("some-new-reason")).toBe("Request refused.");
    expect(scanMessage("some-new-reason")).toBe("The scan did not complete.");
    expect(scanMessage(null)).toBeNull();
    expect(messageFor("some-new-reason")).toBeNull();
    for (const reason of Object.keys(TARGET_REJECTION_MESSAGES)) expect(refusalMessage(reason)).toBe(TARGET_REJECTION_MESSAGES[reason]);
    expect(refusalMessage("outbound-scanning-disabled")).toMatch(/Nothing was sent/);
  });
});

describe("M1 DNS TXT ownership verification", () => {
  it("verifies a published challenge, hides it afterwards, and expires after 30 days", async () => {
    const { app, f, publish, advance } = setup({ networkEnabled: true });
    const target = (await register(app, "example.com")).body.target;
    const missing = await request(app).post(`/api/targets/${target.id}/verify`).send({});
    expect([missing.status, missing.body.reason, missing.body.target.verification.status]).toEqual([409, "record-missing", "failed"]);

    publish(target);
    const ok = await request(app).post(`/api/targets/${target.id}/verify`).send({});
    expect(ok.status).toBe(200);
    expect(ok.body.target.verification).toMatchObject({ status: "verified", verifiedAt: "2026-10-29T00:00:00.000Z", expiresAt: "2026-11-28T00:00:00.000Z" });
    expect(ok.body.target.dnsRecord).toBeNull();
    const listed = JSON.stringify((await request(app).get("/api/targets")).body);
    expect(listed).not.toContain(target.dnsRecord.value);
    expect(f.txtCalls).toEqual(["_agentshield-verification.example.com", "_agentshield-verification.example.com"]);

    advance(30 * DAY);
    const expired = (await request(app).get("/api/targets")).body.targets[0];
    expect(expired.verification.status).toBe("expired");
    expect(expired.dnsRecord).toMatchObject({ value: target.dnsRecord.value });
    const scan = await request(app).post("/api/scans").send({ targetId: target.id });
    expect([scan.status, scan.body.reason]).toEqual([409, "verification-expired"]);
    expect(f.transportCalls).toHaveLength(0);
  });

  it("checkDnsProof: exact match (also across split strings), mismatch, absence, resolver failure and timeout", async () => {
    const answer = (records: string[][] | Error): TxtResolver => async () => {
      if (records instanceof Error) throw records;
      return records;
    };
    expect(await checkDnsProof(answer([["agentshield-verification=abc"]]), "example.com", "abc")).toEqual({ ok: true });
    expect(await checkDnsProof(answer([["v=spf1 -all"], ["agentshield-verif", "ication=abc"]]), "example.com", "abc")).toEqual({ ok: true });
    expect(await checkDnsProof(answer([["agentshield-verification=abd"]]), "example.com", "abc")).toEqual({ ok: false, reason: "record-mismatch" });
    expect(await checkDnsProof(answer([["agentshield-verification=abc-extra"]]), "example.com", "abc")).toEqual({ ok: false, reason: "record-mismatch" });
    expect(await checkDnsProof(answer([]), "example.com", "abc")).toEqual({ ok: false, reason: "record-missing" });
    expect(await checkDnsProof(answer(Object.assign(new Error("x"), { code: "ENOTFOUND" })), "example.com", "abc")).toEqual({ ok: false, reason: "record-missing" });
    expect(await checkDnsProof(answer(Object.assign(new Error("x"), { code: "ESERVFAIL" })), "example.com", "abc")).toEqual({ ok: false, reason: "resolver-error" });
    expect(await checkDnsProof((async () => "nope") as unknown as TxtResolver, "example.com", "abc")).toEqual({ ok: false, reason: "resolver-error" });
    vi.useFakeTimers();
    let aborted = false;
    const hanging: TxtResolver = (_name, signal) =>
      new Promise(() => {
        signal.addEventListener("abort", () => (aborted = true));
      });
    const pending = checkDnsProof(hanging, "example.com", "abc");
    await vi.advanceTimersByTimeAsync(5000);
    expect(await pending).toEqual({ ok: false, reason: "timeout" });
    expect([aborted, vi.getTimerCount()]).toEqual([true, 0]);
    expect(verificationRecordName("example.com")).toBe("_agentshield-verification.example.com");
  });

  it("each target gets its own random challenge; deleting a target invalidates it", async () => {
    const { app, publish } = setup({ networkEnabled: true });
    const first = (await register(app, "example.com")).body.target;
    const other = (await register(app, "example.org")).body.target;
    expect(first.dnsRecord.value).not.toBe(other.dnsRecord.value);
    publish(first);
    await request(app).post(`/api/targets/${first.id}/verify`).send({});
    expect((await request(app).delete(`/api/targets/${first.id}`)).status).toBe(200);
    expect((await request(app).post("/api/scans").send({ targetId: first.id })).status).toBe(404);
    expect((await request(app).post(`/api/targets/${first.id}/verify`).send({})).status).toBe(404);
    const again = (await register(app, "example.com")).body.target;
    expect([again.id, again.verification.status]).toEqual(["tgt-3", "pending"]);
    expect(again.dnsRecord.value).not.toBe(first.dnsRecord.value);
    expect((await register(app, "example.com")).body.reason).toBe("target-already-registered");
  });
});

describe("M1 scanning with fakes", () => {
  async function verifiedTarget(ctx: ReturnType<typeof setup>, host = "example.com") {
    const target = (await register(ctx.app, host)).body.target;
    ctx.publish(target);
    expect((await request(ctx.app).post(`/api/targets/${target.id}/verify`).send({})).status).toBe(200);
    return target as { id: string; dnsRecord: { value: string } };
  }

  it("a verified target is scanned through the guard: 202, then completed with three requests", async () => {
    const ctx = setup({ networkEnabled: true });
    const target = await verifiedTarget(ctx);
    const res = await request(ctx.app).post("/api/scans").send({ targetId: target.id });
    expect([res.status, res.body.scan.status]).toEqual([202, "queued"]);
    await ctx.service.whenIdle();
    const scan = (await request(ctx.app).get(`/api/scans/${res.body.scan.id}`)).body.scan;
    expect(scan).toMatchObject({ status: "completed", reason: null, requestsUsed: 3, requestBudget: 30 });
    expect(scan.checks.length).toBeGreaterThan(5);
    expect(ctx.f.transportCalls.map((c) => [c.url.href, c.address])).toEqual([
      ["https://example.com/", "93.184.215.14"],
      ["http://example.com/", "93.184.215.14"],
      ["https://example.com/.well-known/security.txt", "93.184.215.14"],
    ]);
    // The DNS proof was checked again at scan start (verify + scan = 2 lookups).
    expect(ctx.f.txtCalls).toHaveLength(2);
    expect(JSON.stringify(scan)).not.toContain(COOKIE_SECRET);
  });

  it("re-checks the DNS proof before every scan: a removed record stops the scan before any request", async () => {
    const ctx = setup({ networkEnabled: true });
    const target = await verifiedTarget(ctx);
    ctx.f.txt.clear();
    const res = await request(ctx.app).post("/api/scans").send({ targetId: target.id });
    expect(res.status).toBe(202);
    await ctx.service.whenIdle();
    const scan = (await request(ctx.app).get(`/api/scans/${res.body.scan.id}`)).body.scan;
    expect(scan).toMatchObject({ status: "rejected", reason: "ownership-proof-failed", requestsUsed: 0 });
    expect(ctx.f.transportCalls).toHaveLength(0);
    expect((await request(ctx.app).get("/api/targets")).body.targets[0].verification.status).toBe("failed");
  });

  it.each([
    ["a private address", [{ address: "10.1.2.3", family: 4 }], "blocked-address"],
    ["cloud metadata", [{ address: "169.254.169.254", family: 4 }], "blocked-address"],
    ["a public plus a loopback address", [{ address: "93.184.215.14", family: 4 }, { address: "127.0.0.1", family: 4 }], "blocked-address"],
    ["an empty answer", [], "malformed-resolution"],
  ])("a target resolving to %s is rejected with no request sent", async (_label, answers, reason) => {
    const ctx = setup({ networkEnabled: true });
    const target = await verifiedTarget(ctx);
    ctx.f.resolve = () => answers;
    const res = await request(ctx.app).post("/api/scans").send({ targetId: target.id });
    await ctx.service.whenIdle();
    const scan = (await request(ctx.app).get(`/api/scans/${res.body.scan.id}`)).body.scan;
    expect(scan).toMatchObject({ status: "rejected", reason, requestsUsed: 0 });
    expect(ctx.f.transportCalls).toHaveLength(0);
  });

  it("maps each verification state to its own refusal reason (D3)", () => {
    expect(verificationRefusal("verified")).toBeNull();
    expect(verificationRefusal("expired")).toBe("verification-expired");
    expect(verificationRefusal("failed")).toBe("verification-failed");
    expect(verificationRefusal("pending")).toBe("target-not-verified");
  });

  it("refuses at request time with the reason that matches the target's state (D3)", async () => {
    const ctx = setup({ networkEnabled: true });
    const pending = (await register(ctx.app, "example.com")).body.target;
    expect((await request(ctx.app).post("/api/scans").send({ targetId: pending.id })).body.reason).toBe("target-not-verified");
    await request(ctx.app).post(`/api/targets/${pending.id}/verify`).send({}); // no record published: fails
    expect((await request(ctx.app).post("/api/scans").send({ targetId: pending.id })).body.reason).toBe("verification-failed");
    const expiring = await verifiedTarget(ctx, "example.org");
    ctx.advance(30 * DAY);
    expect((await request(ctx.app).post("/api/scans").send({ targetId: expiring.id })).body.reason).toBe("verification-expired");
    expect(ctx.f.transportCalls).toHaveLength(0);
  });

  it("a queued scan reports expiry that happened before it started (D3)", async () => {
    const ctx = setup({ networkEnabled: true });
    const target = await verifiedTarget(ctx);
    ctx.advance(30 * DAY - 1);
    const started = ctx.service.startScan(target.id);
    expect(started.ok).toBe(true);
    ctx.advance(1); // expires before the queued job runs (same tick)
    await ctx.service.whenIdle();
    expect(started.ok && ctx.service.getScan(started.value.id)).toMatchObject({ status: "rejected", reason: "verification-expired", requestsUsed: 0 });
    expect(ctx.f.transportCalls).toHaveLength(0);
  });

  it("a queued scan reports a verification that failed before it started, not expiry (D3)", async () => {
    const ctx = setup({ networkEnabled: true });
    const target = await verifiedTarget(ctx);
    const started = ctx.service.startScan(target.id);
    expect(started.ok).toBe(true);
    // Same tick, before the job starts: the target's verification is marked failed.
    const record = ctx.service["targets"].get(target.id)!;
    ctx.service["markFailed"](record, "record-mismatch");
    await ctx.service.whenIdle();
    const scan = started.ok ? ctx.service.getScan(started.value.id) : null;
    expect(scan).toMatchObject({ status: "rejected", reason: "verification-failed", requestsUsed: 0 });
    expect(scan?.message).toMatch(/verification failed/);
    expect(ctx.f.transportCalls).toHaveLength(0);
  });

  it("an unverified target is refused and recorded as rejected", async () => {
    const ctx = setup({ networkEnabled: true });
    const target = (await register(ctx.app, "example.com")).body.target;
    const res = await request(ctx.app).post("/api/scans").send({ targetId: target.id });
    expect([res.status, res.body.reason, res.body.scan.status]).toEqual([409, "target-not-verified", "rejected"]);
    expect(ctx.f.transportCalls).toHaveLength(0);
    expect((await request(ctx.app).post("/api/scans").send({ targetId: "tgt-99" })).status).toBe(404);
    expect((await request(ctx.app).post("/api/scans").send({ targetId: "../etc" })).status).toBe(400);
  });

  it("deleting a target stops its queued scan before it sends anything", async () => {
    const ctx = setup({ networkEnabled: true });
    const target = await verifiedTarget(ctx);
    // Same tick: the job is queued but has not started.
    const started = ctx.service.startScan(target.id);
    expect(ctx.service.deleteTarget(target.id).ok).toBe(true);
    await ctx.service.whenIdle();
    expect(started.ok && ctx.service.getScan(started.value.id)).toMatchObject({ status: "rejected", reason: "target-deleted", requestsUsed: 0 });
    expect(ctx.f.transportCalls).toHaveLength(0);
  });

  it("deleting a target cancels its running scan", async () => {
    const ctx = setup({ networkEnabled: true });
    const target = await verifiedTarget(ctx);
    let signal: AbortSignal | null = null;
    ctx.f.respond = (req) =>
      new Promise((_resolve, reject) => {
        signal = req.signal;
        req.signal.addEventListener("abort", () => reject(new Error("aborted")));
      });
    const started = ctx.service.startScan(target.id);
    while (ctx.f.transportCalls.length === 0) await new Promise((resolve) => setTimeout(resolve, 1));
    ctx.service.deleteTarget(target.id);
    await ctx.service.whenIdle();
    expect(started.ok && ctx.service.getScan(started.value.id)).toMatchObject({ status: "failed", reason: "target-deleted" });
    expect((signal as AbortSignal | null)?.aborted).toBe(true);
    expect(ctx.f.transportCalls).toHaveLength(1);
  });

  it("allows two active scans overall and one per host", async () => {
    const ctx = setup({ networkEnabled: true });
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    ctx.f.respond = async () => {
      await held;
      return { status: 200, headers: {} };
    };
    const a = await verifiedTarget(ctx, "example.com");
    const b = await verifiedTarget(ctx, "example.org");
    const c = await verifiedTarget(ctx, "example.net");
    expect((await request(ctx.app).post("/api/scans").send({ targetId: a.id })).status).toBe(202);
    const sameHost = await request(ctx.app).post("/api/scans").send({ targetId: a.id });
    expect([sameHost.status, sameHost.body.reason]).toEqual([409, "scan-already-active"]);
    expect((await request(ctx.app).post("/api/scans").send({ targetId: b.id })).status).toBe(202);
    const third = await request(ctx.app).post("/api/scans").send({ targetId: c.id });
    expect([third.status, third.body.reason]).toEqual([429, "too-many-active-scans"]);
    release();
    await ctx.service.whenIdle();
    const statuses = (await request(ctx.app).get("/api/scans")).body.scans.map((s: { status: string }) => s.status);
    expect(statuses.sort()).toEqual(["completed", "completed", "rejected", "rejected"]);
  });

  it("rate limits: five scan starts and ten verifications per minute", async () => {
    const ctx = setup({ networkEnabled: true });
    const target = (await register(ctx.app, "example.com")).body.target;
    for (let i = 0; i < 5; i += 1) expect((await request(ctx.app).post("/api/scans").send({ targetId: target.id })).status).toBe(409);
    expect((await request(ctx.app).post("/api/scans").send({ targetId: target.id })).status).toBe(429);
    for (let i = 0; i < 10; i += 1) expect((await request(ctx.app).post(`/api/targets/${target.id}/verify`).send({})).status).toBe(409);
    expect((await request(ctx.app).post(`/api/targets/${target.id}/verify`).send({})).status).toBe(429);
    expect(ctx.f.txtCalls).toHaveLength(10);
  });

  it("storage is bounded: 50 scans, 50 targets, 500 audit entries", async () => {
    const ctx = setup();
    const target = (await register(ctx.app, "example.com")).body.target;
    for (let i = 0; i < 60; i += 1) ctx.service.startScan(target.id);
    const scans = ctx.service.listScans();
    expect(scans).toHaveLength(50);
    expect(scans[0]!.id).toBe("scan-60");
    for (let i = 0; i < 49; i += 1) expect(ctx.service.registerTarget(`site${i}.example.com`).ok).toBe(true);
    expect(ctx.service.registerTarget("one-too-many.example.com")).toMatchObject({ ok: false, reason: "target-limit-reached" });
    for (let i = 0; i < 500; i += 1) ctx.service.startScan(target.id);
    expect(ctx.service.auditLog(10_000).length).toBe(500);
    expect(ctx.service.listScans()).toHaveLength(50);
    expect(JSON.stringify(ctx.service.auditLog(10_000))).not.toContain(target.dnsRecord.value.split("=")[1]);
  });

  it("reports: attachments, escaped HTML, no challenge or cookie values", async () => {
    const ctx = setup({ networkEnabled: true });
    const target = await verifiedTarget(ctx);
    const res = await request(ctx.app).post("/api/scans").send({ targetId: target.id });
    await ctx.service.whenIdle();
    const id = res.body.scan.id as string;
    const json = await request(ctx.app).get(`/api/scans/${id}/report.json`);
    expect(json.headers["content-disposition"]).toBe(`attachment; filename="agentshield-${id}.json"`);
    const html = await request(ctx.app).get(`/api/scans/${id}/report.html`);
    expect(html.headers["content-type"]).toMatch(/^text\/html/);
    expect(html.headers["content-security-policy"]).toContain("default-src 'none'");
    expect(html.headers["x-content-type-options"]).toBe("nosniff");
    expect(html.text).not.toContain("<script>alert(1)</script>");
    expect(html.text).toContain("&lt;script&gt;");
    const challenge = target.dnsRecord.value.split("=")[1]!;
    for (const body of [json.text, html.text, JSON.stringify((await request(ctx.app).get("/api/scans")).body)]) {
      expect(body).not.toContain(challenge);
      expect(body).not.toContain(COOKIE_SECRET);
    }
    expect((await request(ctx.app).get("/api/scans/scan-999/report.html")).status).toBe(404);
  });

  it("scan audit entries record state transitions and are separate from the engine activity log", async () => {
    const ctx = setup({ networkEnabled: true });
    const target = await verifiedTarget(ctx);
    await request(ctx.app).post("/api/scans").send({ targetId: target.id });
    await ctx.service.whenIdle();
    const events = (await request(ctx.app).get("/api/scans")).body.audit.map((a: { event: string }) => a.event).reverse();
    expect(events).toEqual(["target-registered", "verification-succeeded", "scan-queued", "scan-started", "scan-completed"]);
    expect((await request(ctx.app).get("/api/events")).body.events).toEqual([]);
  });
});

describe("M1 lab mode is separate and narrow", () => {
  const LAB_ENV = { SCAN_LAB_MODE: "true", SCAN_LAB_ORIGINS: "http://127.0.0.1:8081" };

  it("scans only the configured loopback origin, proved by configuration, with no DNS at all", async () => {
    const ctx = setup({}, LAB_ENV);
    expect(ctx.service.config.networkEnabled).toBe(false);
    const target = (await register(ctx.app, "http://127.0.0.1:8081")).body.target;
    expect(target).toMatchObject({ kind: "lab", verification: { method: "lab-config", status: "pending" }, dnsRecord: null });
    expect((await request(ctx.app).post(`/api/targets/${target.id}/verify`).send({})).body.target.verification.status).toBe("verified");
    const res = await request(ctx.app).post("/api/scans").send({ targetId: target.id });
    expect(res.status).toBe(202);
    await ctx.service.whenIdle();
    expect((await request(ctx.app).get(`/api/scans/${res.body.scan.id}`)).body.scan.status).toBe("completed");
    expect(ctx.f.transportCalls.every((c) => c.address === "127.0.0.1" && c.port === 8081)).toBe(true);
    expect([ctx.f.resolverCalls.length, ctx.f.txtCalls.length]).toEqual([0, 0]);
  });

  it("does not open any other loopback or private target, and does not enable DNS targets", async () => {
    const ctx = setup({}, LAB_ENV);
    for (const url of ["http://127.0.0.1:8082", "http://localhost:8081", "http://[::1]:8081", "http://10.0.0.1:8081"]) {
      expect((await register(ctx.app, url)).status, url).toBe(400);
    }
    const dns = (await register(ctx.app, "example.com")).body.target;
    expect((await request(ctx.app).post(`/api/targets/${dns.id}/verify`).send({})).body.reason).toBe("outbound-scanning-disabled");
    expect((await request(ctx.app).post("/api/scans").send({ targetId: dns.id })).body.reason).toBe("outbound-scanning-disabled");
    expect(ctx.f.transportCalls).toHaveLength(0);
  });

  it("enabling outbound scanning does not enable lab origins", async () => {
    const ctx = setup({}, { SCAN_NETWORK_ENABLED: "true", SCAN_LAB_ORIGINS: "http://127.0.0.1:8081" });
    const res = await register(ctx.app, "http://127.0.0.1:8081");
    expect([res.status, res.body.reason]).toEqual([400, "port-not-allowed"]);
    expect(ctx.service.config.lab.origins.size).toBe(0);
  });
});

describe("M2-A deadline-aware scan orchestration", () => {
  /** Synthetic probes (one fixed path each, no redirects); real exposure probes arrive in M2-B. */
  function probes(count: number): PlannedProbe[] {
    return Array.from({ length: count }, (_, i) => {
      const checkId = `probe-${i + 1}`;
      return {
        checkId,
        title: `Probe ${i + 1}`,
        maxRequests: 1,
        async run(context) {
          const fetched = await context.fetcher.fetch(context.target, new URL(`https://${context.target.hostname}/${checkId}`), {
            budget: context.budget,
            signal: context.signal,
            followRedirects: false,
          });
          return fetched.ok ? result(checkId, `Probe ${i + 1}`, [], "Probe ran.") : errored(checkId, `Probe ${i + 1}`, "Probe request failed.");
        },
      };
    });
  }

  async function scanOf(
    configOverrides: Partial<ScanConfig>,
    planner: ScanServiceDeps["probePlanner"],
    arrange: (ctx: ReturnType<typeof setup>) => void = () => {},
  ) {
    // Since M2-D, planned probes run only with the server switch on and the scan opted in.
    const optIn = planner !== undefined;
    const ctx = setup({ networkEnabled: true, exposureEnabled: optIn, ...configOverrides }, {}, { probePlanner: planner });
    const target = (await register(ctx.app, "example.com")).body.target;
    ctx.publish(target);
    expect((await request(ctx.app).post(`/api/targets/${target.id}/verify`).send({})).status).toBe(200);
    arrange(ctx);
    const started = ctx.service.startScan(target.id, { exposureChecks: optIn });
    if (!started.ok) throw new Error("the scan was not accepted");
    return { ctx, target, scanId: started.value.id as string };
  }

  const hangUntilAborted = (req: TransportRequest) =>
    new Promise<never>((_resolve, reject) => req.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true }));
  const tail = (checks: Array<{ checkId: string; status: string; summary: string }>) =>
    checks.slice(PASSIVE_CHECKS.length).map((c) => [c.checkId, c.status, c.summary]);

  it("without a probe planner (the default), a time limit during the passive requests still fails the scan without results", async () => {
    const { ctx, scanId } = await scanOf({ scanTimeoutMs: 50 }, undefined, (c) => (c.f.respond = hangUntilAborted));
    await ctx.service.whenIdle();
    expect(ctx.service.getScan(scanId)).toMatchObject({ status: "failed", reason: "scan-timeout", requestsUsed: 1, checks: [] });
  });

  it("exposure probes are registered only in the scan service, never by app wiring (M2-C, updated for M2-D)", () => {
    const srcRoot = fileURLToPath(new URL("..", import.meta.url));
    const sources = (readdirSync(srcRoot, { recursive: true }) as string[])
      .filter((file) => file.endsWith(".ts") && !file.endsWith(".test.ts"))
      .map((file) => [file.replace(/\\/g, "/"), readFileSync(join(srcRoot, file), "utf8")] as const);
    expect(sources.length).toBeGreaterThan(5);
    expect(sources.filter(([, text]) => text.includes("createExposureProbes")).map(([file]) => file)).toEqual(["scans/service.ts"]);
    expect(sources.filter(([, text]) => text.includes("probePlanner")).map(([file]) => file)).toEqual(["scans/service.ts"]);
  });

  it("a planner that plans nothing leaves the scan exactly as in M1", async () => {
    const seen: string[] = [];
    const { ctx, scanId } = await scanOf({}, (target) => {
      seen.push(target.hostname);
      return [];
    });
    await ctx.service.whenIdle();
    const scan = ctx.service.getScan(scanId)!;
    expect(scan).toMatchObject({ status: "completed", reason: null, requestsUsed: 3 });
    expect(scan.checks).toHaveLength(PASSIVE_CHECKS.length);
    expect(ctx.f.transportCalls).toHaveLength(3);
    expect(seen).toEqual(["example.com"]);
  });

  it("the time limit hitting mid-probe keeps every passive result and reports unfinished probes as not checked", async () => {
    // A zero reserve lets probes start right up to the deadline, so the hard time limit interrupts probe-2.
    const { ctx, scanId } = await scanOf({ scanTimeoutMs: 200, probeReserveMs: 0 }, () => probes(3), (c) => {
      const base = c.f.respond;
      c.f.respond = (req) => (req.url.pathname === "/probe-2" ? hangUntilAborted(req) : base(req));
    });
    await ctx.service.whenIdle();
    const scan = ctx.service.getScan(scanId)!;
    expect(scan).toMatchObject({ status: "completed", reason: null, requestsUsed: 5 });
    const passive = scan.checks.slice(0, PASSIVE_CHECKS.length);
    expect(passive).toHaveLength(PASSIVE_CHECKS.length);
    expect(passive.some((c) => c.summary.startsWith("Not checked"))).toBe(false);
    expect(tail(scan.checks)).toEqual([
      ["probe-1", "pass", "Probe ran."],
      ["probe-2", "error", NOT_CHECKED_SUMMARIES["time-limit"]],
      ["probe-3", "error", NOT_CHECKED_SUMMARIES["time-limit"]],
    ]);
    expect(ctx.f.transportCalls.map((c) => c.url.pathname)).toEqual(["/", "/", "/.well-known/security.txt", "/probe-1", "/probe-2"]);
    const events = (await request(ctx.app).get("/api/scans")).body.audit.map((a: { event: string }) => a.event);
    expect(events[0]).toBe("scan-completed");
  });

  it("near the deadline, no probe is started: zero probe requests and the passive results are kept", async () => {
    const { ctx, scanId } = await scanOf({}, () => probes(3), (c) => {
      const base = c.f.respond;
      c.f.respond = (req) => {
        // The passive requests use up 110 of the 120 seconds; a probe needs 20 to start.
        if (req.url.pathname === "/.well-known/security.txt") c.advance(110_000);
        return base(req);
      };
    });
    await ctx.service.whenIdle();
    const scan = ctx.service.getScan(scanId)!;
    expect(scan).toMatchObject({ status: "completed", reason: null, requestsUsed: 3 });
    expect(tail(scan.checks)).toEqual([1, 2, 3].map((n) => [`probe-${n}`, "error", NOT_CHECKED_SUMMARIES["time-limit"]]));
    expect(ctx.f.transportCalls).toHaveLength(3);
  });

  it("budget exhaustion: probes stop at the scan's request budget and the rest are not checked", async () => {
    const { ctx, scanId } = await scanOf({ requestBudget: 4 }, () => probes(3));
    await ctx.service.whenIdle();
    const scan = ctx.service.getScan(scanId)!;
    expect(scan).toMatchObject({ status: "completed", requestsUsed: 4, requestBudget: 4 });
    expect(tail(scan.checks)).toEqual([
      ["probe-1", "pass", "Probe ran."],
      ["probe-2", "error", NOT_CHECKED_SUMMARIES["request-budget"]],
      ["probe-3", "error", NOT_CHECKED_SUMMARIES["request-budget"]],
    ]);
    expect(ctx.f.transportCalls).toHaveLength(4);
  });

  it("deleting the target mid-probe still fails the scan as before, without results", async () => {
    const { ctx, target, scanId } = await scanOf({}, () => probes(3), (c) => {
      const base = c.f.respond;
      c.f.respond = (req) => (req.url.pathname === "/probe-2" ? hangUntilAborted(req) : base(req));
    });
    while (ctx.f.transportCalls.length < 5) await new Promise((resolve) => setTimeout(resolve, 1));
    ctx.service.deleteTarget(target.id);
    await ctx.service.whenIdle();
    expect(ctx.service.getScan(scanId)).toMatchObject({ status: "failed", reason: "target-deleted", requestsUsed: 5, checks: [] });
    expect(ctx.f.transportCalls).toHaveLength(5);
  });
});

describe("M2-D exposure checks: server switch and per-scan opt-in", () => {
  // Assembled at runtime so no credential-shaped literal is committed.
  const AWS_KEY = ["AKIA", "Z7Q4K2M9", "R5T8W3X6"].join("");
  const ENV_BODY = `APP_NAME=shopfront\nAWS_ACCESS_KEY_ID=${AWS_KEY}\nLOG_LEVEL=info\n`;
  const BASELINE_SENTINEL = "BASELINE-SENTINEL-c41d";
  const exposurePaths = new Set<string>(EXPOSURE_PATHS);
  const isBaseline = (path: string) => path.startsWith("/agentshield-baseline-");
  const exposureCalls = (f: FakeKit) => f.transportCalls.filter((c) => exposurePaths.has(c.url.pathname) || isBaseline(c.url.pathname));
  const RELAXED_LIMITS = { registerTarget: 100, verify: 100, startScan: 100 };

  type Route = { status: number; body?: string; headers?: Record<string, string> };
  /** Answers the baseline and the nine paths (404 unless routed); everything else as the M1 fakes do. */
  function serveExposure(f: FakeKit, routes: Record<string, Route> = {}, baseline: Route = { status: 404 }) {
    const base = f.respond;
    f.respond = async (req) => {
      const path = req.url.pathname;
      if (isBaseline(path)) return { headers: {}, ...baseline };
      if (exposurePaths.has(path)) return { headers: {}, ...(routes[path] ?? { status: 404 }) };
      return base(req);
    };
  }

  async function verify(ctx: ReturnType<typeof setup>, host: string) {
    const target = (await register(ctx.app, host)).body.target;
    ctx.publish(target);
    expect((await request(ctx.app).post(`/api/targets/${target.id}/verify`).send({})).status).toBe(200);
    return target as { id: string };
  }

  async function ready(config: Partial<ScanConfig> = {}, deps: Pick<ScanServiceDeps, "probePlanner"> = {}) {
    const ctx = setup({ networkEnabled: true, rateLimits: RELAXED_LIMITS, ...config }, {}, deps);
    return { ...ctx, target: await verify(ctx, "example.com") };
  }

  async function startAndWait(ctx: ReturnType<typeof setup>, body: Record<string, unknown>) {
    const res = await request(ctx.app).post("/api/scans").send(body);
    await ctx.service.whenIdle();
    return res;
  }

  /** The real planner, recording every probe set it hands out. */
  function recordingPlanner() {
    const made: PlannedProbe[][] = [];
    return {
      made,
      planner: () => {
        const probes = createExposureProbes();
        made.push(probes);
        return probes;
      },
    };
  }

  // --- A. configuration ---

  it("A. SCAN_EXPOSURE_ENABLED is off unless exactly 'true', and independent of the other switches", () => {
    expect(loadScanConfig({}).exposureEnabled).toBe(false);
    for (const value of [undefined, "", "TRUE", "True", "1", "yes", "on", " true", "true ", "false", "0"]) {
      expect(loadScanConfig({ SCAN_EXPOSURE_ENABLED: value, SCAN_NETWORK_ENABLED: "true", SCAN_LAB_MODE: "true" }).exposureEnabled, String(value)).toBe(false);
    }
    expect(loadScanConfig({ SCAN_EXPOSURE_ENABLED: "true" })).toMatchObject({ exposureEnabled: true, networkEnabled: false });
  });

  it("A. settings say only whether exposure checks are available, and list the fixed paths", async () => {
    for (const enabled of [false, true]) {
      const { app } = setup({ networkEnabled: true, exposureEnabled: enabled });
      const settings = (await request(app).get("/api/targets")).body.settings;
      expect(settings.exposureChecks).toEqual({ enabled, paths: [...EXPOSURE_PATHS] });
      expect(JSON.stringify(settings)).not.toMatch(/SCAN_EXPOSURE_ENABLED|process\.env/);
    }
  });

  // --- B. API ---

  it("B. without the field, or with false, the scan is the M1 scan, recorded as not requested", async () => {
    for (const extra of [{}, { includeExposureChecks: false }]) {
      const ctx = await ready({ exposureEnabled: true });
      serveExposure(ctx.f);
      const res = await startAndWait(ctx, { targetId: ctx.target.id, ...extra });
      expect([res.status, res.body.scan.options]).toEqual([202, { exposureChecks: false }]);
      const scan = ctx.service.getScan(res.body.scan.id)!;
      expect(scan).toMatchObject({ status: "completed", requestsUsed: 3, options: { exposureChecks: false } });
      expect(scan.checks).toHaveLength(PASSIVE_CHECKS.length); // no synthetic exposure rows
      expect(ctx.service.listScans()[0]!.options).toEqual({ exposureChecks: false });
      expect(exposureCalls(ctx.f)).toHaveLength(0);
      expect(ctx.f.transportCalls.every((c) => c.headers.range === undefined)).toBe(true);
    }
  });

  it("B. includeExposureChecks must be a real boolean: anything else is a 400 and starts nothing", async () => {
    const ctx = await ready({ exposureEnabled: true });
    for (const value of ["true", "false", 1, 0, "yes", null, {}, [], [true]]) {
      const res = await request(ctx.app).post("/api/scans").send({ targetId: ctx.target.id, includeExposureChecks: value });
      expect([res.status, res.body.reason], JSON.stringify(value)).toEqual([400, "invalid-scan-options"]);
      expect(res.body.error).toBe("includeExposureChecks must be true or false when it is given.");
    }
    await ctx.service.whenIdle();
    expect([ctx.service.listScans().length, ctx.f.transportCalls.length]).toEqual([0, 0]);
  });

  it("B. requested while the server switch is off: 409, recorded as rejected and requested, nothing sent", async () => {
    const ctx = await ready({ exposureEnabled: false });
    const txtBefore = ctx.f.txtCalls.length;
    const res = await startAndWait(ctx, { targetId: ctx.target.id, includeExposureChecks: true });
    expect([res.status, res.body.reason, res.body.error]).toEqual([409, "exposure-checks-disabled", refusalMessage("exposure-checks-disabled")]);
    expect(res.body.scan).toMatchObject({ status: "rejected", requestsUsed: 0, options: { exposureChecks: true } });
    expect([ctx.f.transportCalls.length, ctx.f.txtCalls.length - txtBefore]).toEqual([0, 0]);
  });

  it("B. nothing in the request body can turn the server switch on", async () => {
    const ctx = await ready({ exposureEnabled: false });
    const res = await startAndWait(ctx, {
      targetId: ctx.target.id,
      includeExposureChecks: true,
      exposureEnabled: true,
      SCAN_EXPOSURE_ENABLED: "true",
      settings: { exposureChecks: { enabled: true } },
      config: { exposureEnabled: true },
    });
    expect([res.status, res.body.reason]).toEqual([409, "exposure-checks-disabled"]);
    expect(ctx.f.transportCalls).toHaveLength(0);
  });

  it("B. with both controls on: the baseline and the nine fixed paths in prefix mode; other body fields change nothing", async () => {
    const ctx = await ready({ exposureEnabled: true });
    serveExposure(ctx.f);
    const res = await startAndWait(ctx, {
      targetId: ctx.target.id,
      includeExposureChecks: true,
      paths: ["/admin", "/etc/passwd"],
      path: "/admin",
      url: "https://evil.example/",
      headers: { range: "bytes=0-", cookie: "a=b" },
      range: "bytes=0-999999",
      requestBudget: 1000,
      probes: [{ path: "/x", maxRequests: 50 }],
    });
    expect(res.status).toBe(202);
    const scan = ctx.service.getScan(res.body.scan.id)!;
    expect(scan).toMatchObject({ status: "completed", requestsUsed: 13, requestBudget: 30, options: { exposureChecks: true } });
    const paths = ctx.f.transportCalls.map((c) => c.url.pathname);
    expect(paths.slice(0, 3)).toEqual(["/", "/", "/.well-known/security.txt"]);
    expect(paths[3]).toMatch(/^\/agentshield-baseline-[0-9a-f]{64}$/);
    expect(paths.slice(4)).toEqual([...EXPOSURE_PATHS]);
    expect(ctx.f.transportCalls.every((c) => c.url.hostname === "example.com" && c.url.search === "" && c.headers.cookie === undefined)).toBe(true);
    expect(ctx.f.transportCalls.map((c) => c.headers.range)).toEqual([undefined, undefined, undefined, ...Array(10).fill(PREFIX_RANGE_HEADER)]);
    expect(scan.checks.slice(PASSIVE_CHECKS.length).map((c) => c.checkId)).toEqual([BASELINE_CHECK_ID, ...EXPOSURE_CHECK_IDS]);
  });

  it("B. only includeExposureChecks: true opts in; look-alike fields never do", async () => {
    const ctx = await ready({ exposureEnabled: true });
    serveExposure(ctx.f);
    const res = await startAndWait(ctx, {
      targetId: ctx.target.id,
      exposureEnabled: true,
      exposureChecks: true,
      include_exposure_checks: true,
      IncludeExposureChecks: true,
      options: { exposureChecks: true },
      paths: ["/.env"],
    });
    expect([res.status, res.body.scan.options]).toEqual([202, { exposureChecks: false }]);
    expect(ctx.service.getScan(res.body.scan.id)).toMatchObject({ status: "completed", requestsUsed: 3 });
    expect(exposureCalls(ctx.f)).toHaveLength(0);
  });

  it("B. authentication and the Origin check still apply to an opted-in scan", async () => {
    const ctx = await ready({ exposureEnabled: true });
    const anonymous = await supertest(ctx.app).post("/api/scans").send({ targetId: ctx.target.id, includeExposureChecks: true });
    expect(anonymous.status).toBe(401);
    const foreign = await request(ctx.app).post("/api/scans").set("Origin", "https://evil.example").send({ targetId: ctx.target.id, includeExposureChecks: true });
    expect(foreign.status).toBe(403);
    await ctx.service.whenIdle();
    expect([ctx.service.listScans().length, ctx.f.transportCalls.length]).toEqual([0, 0]);
  });

  // --- C. service ---

  it("C. the planner is consulted only when the server switch is on and the scan opted in", async () => {
    for (const [enabled, include, expected] of [
      [false, false, 0],
      [true, false, 0],
      [true, true, 1],
    ] as const) {
      const { made, planner } = recordingPlanner();
      const ctx = await ready({ exposureEnabled: enabled }, { probePlanner: planner });
      serveExposure(ctx.f);
      await startAndWait(ctx, { targetId: ctx.target.id, includeExposureChecks: include });
      expect([made.length, exposureCalls(ctx.f).length], `${enabled}/${include}`).toEqual([expected, expected * 10]);
    }
    // Asked for directly through the service with the switch off: refused, the planner untouched.
    const { made, planner } = recordingPlanner();
    const off = await ready({ exposureEnabled: false }, { probePlanner: planner });
    expect(off.service.startScan(off.target.id, { exposureChecks: true })).toMatchObject({ ok: false, status: 409, reason: "exposure-checks-disabled" });
    await off.service.whenIdle();
    expect([made.length, off.f.transportCalls.length]).toEqual([0, 0]);
  });

  it("C. every layer re-checks the server switch: when queued and again just before probes are planned", async () => {
    // Layer 2: switched off after the scan was accepted but before it started.
    const queued = recordingPlanner();
    const a = await ready({ exposureEnabled: true }, { probePlanner: queued.planner });
    serveExposure(a.f);
    const started = a.service.startScan(a.target.id, { exposureChecks: true });
    (a.service.config as { exposureEnabled: boolean }).exposureEnabled = false;
    await a.service.whenIdle();
    expect(started.ok && a.service.getScan(started.value.id)).toMatchObject({ status: "rejected", reason: "exposure-checks-disabled", requestsUsed: 0 });
    expect([queued.made.length, a.f.transportCalls.length]).toEqual([0, 0]);

    // Layer 3: switched off after the start checks, during the DNS ownership re-check.
    const late = recordingPlanner();
    const b = await ready({ exposureEnabled: true }, { probePlanner: late.planner });
    serveExposure(b.f);
    const records = b.f.txt;
    b.f.txt = new Proxy(records, {
      get(map, key) {
        if (key === "get") (b.service.config as { exposureEnabled: boolean }).exposureEnabled = false;
        const value = Reflect.get(map, key, map);
        return typeof value === "function" ? value.bind(map) : value;
      },
    });
    const res = await startAndWait(b, { targetId: b.target.id, includeExposureChecks: true });
    expect(b.service.getScan(res.body.scan.id)).toMatchObject({ status: "completed", requestsUsed: 3 });
    expect([late.made.length, exposureCalls(b.f).length]).toEqual([0, 0]);
  });

  it("C. ownership is re-checked before any exposure request: a removed record stops everything", async () => {
    const { made, planner } = recordingPlanner();
    const ctx = await ready({ exposureEnabled: true }, { probePlanner: planner });
    ctx.f.txt.clear();
    const res = await startAndWait(ctx, { targetId: ctx.target.id, includeExposureChecks: true });
    expect(ctx.service.getScan(res.body.scan.id)).toMatchObject({ status: "rejected", reason: "ownership-proof-failed", requestsUsed: 0 });
    expect([made.length, ctx.f.transportCalls.length]).toEqual([0, 0]);
  });

  it("C. concurrent scans never share probe or baseline state", async () => {
    const { made, planner } = recordingPlanner();
    const ctx = setup({ networkEnabled: true, exposureEnabled: true, rateLimits: RELAXED_LIMITS }, {}, { probePlanner: planner });
    const a = await verify(ctx, "example.com");
    const b = await verify(ctx, "example.org");
    // example.com answers a random path with a page that itself looks like an env file; example.org with 404.
    let baselines = 0;
    let release!: () => void;
    const bothInFlight = new Promise<void>((resolve) => (release = resolve));
    const base = ctx.f.respond;
    ctx.f.respond = async (req) => {
      const path = req.url.pathname;
      if (isBaseline(path)) {
        if (++baselines === 2) release();
        await bothInFlight; // neither scan probes a path until both have their own baseline
        return req.url.hostname === "example.com" ? { status: 200, headers: {}, body: "A=1\nB=2\nC=3\n" } : { status: 404, headers: {} };
      }
      if (path === "/.env") return { status: 200, headers: {}, body: ENV_BODY };
      if (exposurePaths.has(path)) return { status: 404, headers: {} };
      return base(req);
    };
    const resA = await request(ctx.app).post("/api/scans").send({ targetId: a.id, includeExposureChecks: true });
    const resB = await request(ctx.app).post("/api/scans").send({ targetId: b.id, includeExposureChecks: true });
    await ctx.service.whenIdle();
    const envRow = (id: string) => ctx.service.getScan(id)!.checks.find((c) => c.checkId === "exposure-env")!;
    expect(envRow(resA.body.scan.id)).toMatchObject({ status: "error", summary: EXPOSURE_SUMMARIES.baselineMatches });
    expect(envRow(resB.body.scan.id)).toMatchObject({ status: "fail" });
    expect(made).toHaveLength(2);
    expect(made[0]!.some((probe) => made[1]!.includes(probe))).toBe(false);
  });

  it("C. budget exhaustion and the time limit keep the M2-A behaviour with the real probes", async () => {
    const tight = await ready({ exposureEnabled: true, requestBudget: 8 });
    serveExposure(tight.f, { "/.env": { status: 200, body: ENV_BODY } });
    const scan = tight.service.getScan((await startAndWait(tight, { targetId: tight.target.id, includeExposureChecks: true })).body.scan.id)!;
    expect(scan).toMatchObject({ status: "completed", requestsUsed: 8 });
    const rows = scan.checks.slice(PASSIVE_CHECKS.length);
    // 3 passive + baseline + 4 paths = 8 requests.
    expect(rows.slice(0, 5).map((c) => c.status)).toEqual(["pass", "pass", "pass", "fail", "pass"]);
    expect(rows.slice(5).map((c) => c.summary)).toEqual(Array(5).fill(NOT_CHECKED_SUMMARIES["request-budget"]));

    const slow = await ready({ exposureEnabled: true, scanTimeoutMs: 200, probeReserveMs: 0 });
    serveExposure(slow.f, { "/.git/config": { status: 200, body: "[core]\n\trepositoryformatversion = 0\n" } });
    const base = slow.f.respond;
    slow.f.respond = (req) =>
      req.url.pathname === "/.env"
        ? new Promise<never>((_resolve, reject) => req.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true }))
        : base(req);
    const timed = slow.service.getScan((await startAndWait(slow, { targetId: slow.target.id, includeExposureChecks: true })).body.scan.id)!;
    expect(timed).toMatchObject({ status: "completed", reason: null });
    expect(timed.checks.slice(0, PASSIVE_CHECKS.length).some((c) => c.summary.startsWith("Not checked"))).toBe(false);
    const byId = Object.fromEntries(timed.checks.map((c) => [c.checkId, c]));
    expect(byId["exposure-git-config"]!.status).toBe("fail");
    for (const id of EXPOSURE_CHECK_IDS.slice(2)) expect(byId[id]).toMatchObject({ status: "error", summary: NOT_CHECKED_SUMMARIES["time-limit"] });
  });

  it("C. a safety refusal during the exposure stage still stops the scan without results, as in M1", async () => {
    const ctx = await ready({ exposureEnabled: true });
    serveExposure(ctx.f);
    let lookups = 0;
    // Public for the three passive requests and the baseline, then a private address (rebinding).
    ctx.f.resolve = () => (++lookups <= 4 ? [{ address: "93.184.215.14", family: 4 }] : [{ address: "10.0.0.8", family: 4 }]);
    const res = await startAndWait(ctx, { targetId: ctx.target.id, includeExposureChecks: true });
    expect(ctx.service.getScan(res.body.scan.id)).toMatchObject({ status: "failed", reason: "blocked-address", checks: [] });
    expect(ctx.f.transportCalls).toHaveLength(4);
  });

  it("C. no response bytes, baseline bytes or secret values persist in records, history, audit or reports", async () => {
    const ctx = await ready({ exposureEnabled: true });
    serveExposure(
      ctx.f,
      { "/.env": { status: 200, body: ENV_BODY }, "/database.sql": { status: 200, body: "-- MySQL dump 10.13\nINSERT INTO vault VALUES ('shopfront');\n" } },
      { status: 200, body: `<html><body>${BASELINE_SENTINEL}</body></html>` },
    );
    const id = (await startAndWait(ctx, { targetId: ctx.target.id, includeExposureChecks: true })).body.scan.id as string;
    const surfaces = [
      JSON.stringify((ctx.service as unknown as { scans: unknown[] }).scans), // the internal records themselves
      JSON.stringify(ctx.service.listScans()),
      JSON.stringify(ctx.service.getScan(id)),
      JSON.stringify(ctx.service.auditLog()),
      (await request(ctx.app).get(`/api/scans/${id}/report.json`)).text,
      (await request(ctx.app).get(`/api/scans/${id}/report.html`)).text,
    ];
    for (const text of surfaces) {
      for (const leaked of [BASELINE_SENTINEL, AWS_KEY, "AWS_ACCESS_KEY_ID", "APP_NAME", "shopfront", "vault", "agentshield-baseline-"]) {
        expect(text, leaked).not.toContain(leaked);
      }
    }
    expect(ctx.service.getScan(id)!.checks.find((c) => c.checkId === "exposure-env")!.findings[0]!.evidence).toBe(
      "/.env: 3 assignments; 1 secret-shaped (aws-access-key-id x1)",
    );
  });

  it("C. the baseline is a diagnostic row: never a finding, never counted, and not one of the nine paths", async () => {
    const ctx = await ready({ exposureEnabled: true });
    serveExposure(ctx.f, { "/backup.zip": { status: 200, body: "PK\u0003\u0004rest-of-archive" } }, { status: 200, body: "<html>catch-all</html>" });
    const scan = ctx.service.getScan((await startAndWait(ctx, { targetId: ctx.target.id, includeExposureChecks: true })).body.scan.id)!;
    expect(scan.checks.find((c) => c.checkId === BASELINE_CHECK_ID)).toMatchObject({ status: "pass", summary: EXPOSURE_SUMMARIES.baselineCatchAll, findings: [] });
    expect(EXPOSURE_CHECK_IDS).not.toContain(BASELINE_CHECK_ID);
    const exposureFindings = scan.checks.filter((c) => EXPOSURE_CHECK_IDS.includes(c.checkId)).flatMap((c) => c.findings);
    const passiveFindings = scan.checks.slice(0, PASSIVE_CHECKS.length).flatMap((c) => c.findings);
    expect(exposureFindings.map((f) => f.checkId)).toEqual(["exposure-backup-zip"]);
    expect(Object.values(scan.summary).reduce((sum, n) => sum + n, 0)).toBe(passiveFindings.length + 1);
  });

  // --- M2-E: audit record of the opt-in, and the scan-detail exposure section ---

  type Entry = { event: string; scanId: string | null; reason: string | null; exposureChecks?: { requested: boolean; allowed: boolean | null } };
  const entriesFor = (ctx: ReturnType<typeof setup>, scanId: string) => (ctx.service.auditLog(500) as Entry[]).filter((a) => a.scanId === scanId).reverse();

  it("E. audit: the opt-in is recorded once per scan, on the scan-queued entry, from the scan's own option", async () => {
    for (const include of [true, false]) {
      const ctx = await ready({ exposureEnabled: true });
      serveExposure(ctx.f);
      const id = (await startAndWait(ctx, { targetId: ctx.target.id, includeExposureChecks: include })).body.scan.id as string;
      const entries = entriesFor(ctx, id);
      expect(entries.map((e) => e.event)).toEqual(["scan-queued", "scan-started", "scan-completed"]);
      expect(entries.filter((e) => e.exposureChecks !== undefined)).toHaveLength(1);
      expect(entries[0]!.exposureChecks).toEqual(include ? { requested: true, allowed: true } : { requested: false, allowed: null });
    }
  });

  it("E. audit: requested with the switch off is one scan-rejected entry, never a queued or completed scan", async () => {
    const ctx = await ready({ exposureEnabled: false });
    const id = (await startAndWait(ctx, { targetId: ctx.target.id, includeExposureChecks: true })).body.scan.id as string;
    expect(entriesFor(ctx, id)).toEqual([
      expect.objectContaining({ event: "scan-rejected", reason: "exposure-checks-disabled", exposureChecks: { requested: true, allowed: false } }),
    ]);
  });

  it("E. audit: other refusals keep their usual single scan-rejected entry, now with the recorded choice", async () => {
    const ctx = setup({ networkEnabled: false, exposureEnabled: true });
    const target = (await register(ctx.app, "example.com")).body.target as { id: string };
    const res = await request(ctx.app).post("/api/scans").send({ targetId: target.id, includeExposureChecks: true });
    expect(res.body.reason).toBe("outbound-scanning-disabled");
    expect(entriesFor(ctx, res.body.scan.id)).toEqual([
      expect.objectContaining({ event: "scan-rejected", reason: "outbound-scanning-disabled", exposureChecks: { requested: true, allowed: true } }),
    ]);
  });

  it("E. audit: a scan refused after it was queued still has exactly one entry with the choice", async () => {
    const ctx = await ready({ exposureEnabled: true });
    const started = ctx.service.startScan(ctx.target.id, { exposureChecks: true });
    (ctx.service.config as { exposureEnabled: boolean }).exposureEnabled = false;
    await ctx.service.whenIdle();
    if (!started.ok) throw new Error("expected the scan to be accepted");
    const entries = entriesFor(ctx, started.value.id);
    expect(entries.map((e) => [e.event, e.exposureChecks])).toEqual([
      ["scan-queued", { requested: true, allowed: true }],
      ["scan-started", undefined],
      ["scan-rejected", undefined],
    ]);
  });

  it("E. audit entries hold only their fixed fields and two booleans: no path, body, secret or baseline detail", async () => {
    const ctx = await ready({ exposureEnabled: true });
    serveExposure(ctx.f, { "/.env": { status: 200, body: ENV_BODY } }, { status: 200, body: `<html>${BASELINE_SENTINEL}</html>` });
    await startAndWait(ctx, { targetId: ctx.target.id, includeExposureChecks: true });
    const audit = ctx.service.auditLog(500);
    const allowed = new Set(["id", "at", "event", "targetId", "scanId", "hostname", "reason", "exposureChecks"]);
    for (const entry of audit) {
      expect(Object.keys(entry).every((key) => allowed.has(key))).toBe(true);
      if (entry.exposureChecks) expect(Object.keys(entry.exposureChecks).sort()).toEqual(["allowed", "requested"]);
    }
    const text = JSON.stringify((await request(ctx.app).get("/api/scans")).body.audit);
    for (const leaked of [BASELINE_SENTINEL, "agentshield-baseline-", AWS_KEY, "AWS_ACCESS_KEY_ID", "/.env"]) expect(text).not.toContain(leaked);
  });

  it("E. scan detail carries the same exposure section as the reports: nine paths for opted-in, not requested otherwise", async () => {
    const ctx = await ready({ exposureEnabled: true });
    serveExposure(ctx.f, { "/.env": { status: 200, body: ENV_BODY }, "/server-status": { status: 503 } });
    const optedIn = (await startAndWait(ctx, { targetId: ctx.target.id, includeExposureChecks: true })).body.scan.id as string;
    const detail = (await request(ctx.app).get(`/api/scans/${optedIn}`)).body.scan;
    expect(detail.exposure.requested).toBe(true);
    expect(detail.exposure.paths.map((p: { path: string }) => p.path)).toEqual([...EXPOSURE_PATHS]);
    const outcomes = Object.fromEntries(detail.exposure.paths.map((p: { path: string; outcome: string }) => [p.path, p.outcome]));
    expect([outcomes["/.env"], outcomes["/server-status"], outcomes["/.git/HEAD"]]).toEqual(["exposed", "inconclusive", "not-exposed"]);
    expect(detail.exposure.baseline).toEqual({ outcome: "not-found", summary: EXPOSURE_SUMMARIES.baselineNotFound });
    const report = JSON.parse((await request(ctx.app).get(`/api/scans/${optedIn}/report.json`)).text);
    expect(report.exposure).toEqual(detail.exposure);
    expect(report.options).toEqual({ exposureChecks: true });

    const optedOut = (await startAndWait(ctx, { targetId: ctx.target.id })).body.scan.id as string;
    expect((await request(ctx.app).get(`/api/scans/${optedOut}`)).body.scan.exposure).toEqual({ requested: false, state: "not-requested" });
    const outReport = JSON.parse((await request(ctx.app).get(`/api/scans/${optedOut}/report.json`)).text);
    expect([outReport.options, outReport.exposure]).toEqual([{ exposureChecks: false }, { requested: false, state: "not-requested" }]);
    expect((await request(ctx.app).get(`/api/scans/${optedOut}/report.html`)).text).toContain("<tr><th>Exposure checks</th><td>Not requested</td></tr>");
  });

  // --- M2-H: a completed scan whose exposure stage stopped early is marked incomplete everywhere ---

  const INCOMPLETE = "completed — exposure checks incomplete";
  /** History, detail, JSON and HTML for one scan, side by side. */
  async function views(ctx: ReturnType<typeof setup>, id: string) {
    const listed = (await request(ctx.app).get("/api/scans")).body.scans.find((s: { id: string }) => s.id === id);
    const detail = (await request(ctx.app).get(`/api/scans/${id}`)).body.scan;
    const json = JSON.parse((await request(ctx.app).get(`/api/scans/${id}/report.json`)).text);
    const html = (await request(ctx.app).get(`/api/scans/${id}/report.html`)).text;
    const status = /<tr><th>Status<\/th><td>([^<]*)<\/td><\/tr>/.exec(html)?.[1];
    return { listed, detail, json, html, status };
  }

  it("H. budget stop: completed but incomplete in history, detail, JSON and HTML; M1 and finished rows kept", async () => {
    const ctx = await ready({ exposureEnabled: true, requestBudget: 8 }); // 3 passive + baseline + 4 paths
    serveExposure(ctx.f, { "/.env": { status: 200, body: ENV_BODY } });
    const id = (await startAndWait(ctx, { targetId: ctx.target.id, includeExposureChecks: true })).body.scan.id as string;
    const v = await views(ctx, id);
    for (const scan of [v.listed, v.detail]) expect(scan).toMatchObject({ status: "completed", reason: null, exposureIncomplete: true, exposureIncompleteReason: "request-budget" });
    expect(v.detail.exposure.incomplete).toEqual({ reason: "request-budget", summary: "Exposure checks incomplete: the scan's request budget ran out before every path was checked." });
    expect(v.json.exposure).toEqual(v.detail.exposure);
    expect([v.json.status, v.status]).toEqual(["completed", INCOMPLETE]);
    // Nothing completed is lost and nothing unfinished becomes a pass.
    expect(v.detail.checks.filter((c: { group?: string }) => !c.group)).toHaveLength(PASSIVE_CHECKS.length);
    expect(v.detail.exposure.paths.map((p: { outcome: string }) => p.outcome)).toEqual(["not-exposed", "not-exposed", "exposed", "not-exposed", ...Array(5).fill("not-checked")]);
  });

  it("H. time-limit stop (interrupted probe): incomplete for time; a near-deadline stop that runs nothing is too", async () => {
    const slow = await ready({ exposureEnabled: true, scanTimeoutMs: 200, probeReserveMs: 0 });
    serveExposure(slow.f);
    const base = slow.f.respond;
    slow.f.respond = (req) =>
      req.url.pathname === "/.env"
        ? new Promise<never>((_resolve, reject) => req.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true }))
        : base(req);
    const a = await views(slow, (await startAndWait(slow, { targetId: slow.target.id, includeExposureChecks: true })).body.scan.id);
    expect(a.detail).toMatchObject({ status: "completed", exposureIncomplete: true, exposureIncompleteReason: "time-limit" });
    expect(a.status).toBe(INCOMPLETE);

    const late = await ready({ exposureEnabled: true });
    const lateBase = late.f.respond;
    late.f.respond = (req) => {
      if (req.url.pathname === "/.well-known/security.txt") late.advance(110_000);
      return lateBase(req);
    };
    const b = await views(late, (await startAndWait(late, { targetId: late.target.id, includeExposureChecks: true })).body.scan.id);
    expect(b.listed).toMatchObject({ exposureIncomplete: true, exposureIncompleteReason: "time-limit" });
    expect(b.detail.exposure.counts["not-checked"]).toBe(9);
  });

  it("H. a full run, an inconclusive result and an opted-out scan are not incomplete", async () => {
    const ctx = await ready({ exposureEnabled: true });
    serveExposure(ctx.f, { "/server-status": { status: 503 }, "/.git/HEAD": { status: 302, headers: { location: "/" } } });
    const full = await views(ctx, (await startAndWait(ctx, { targetId: ctx.target.id, includeExposureChecks: true })).body.scan.id);
    expect(full.detail).toMatchObject({ status: "completed", exposureIncomplete: false, exposureIncompleteReason: null });
    expect(full.detail.exposure.counts.inconclusive).toBe(2);
    expect([full.detail.exposure.incomplete, full.status]).toEqual([null, "completed"]);
    const out = await views(ctx, (await startAndWait(ctx, { targetId: ctx.target.id })).body.scan.id);
    expect(out.detail).toMatchObject({ exposureIncomplete: false, exposureIncompleteReason: null, options: { exposureChecks: false } });
    expect([out.json.exposure, out.status]).toEqual([{ requested: false, state: "not-requested" }, "completed"]);
  });

  it("H. failed and rejected scans keep their own state and are never marked incomplete", async () => {
    const failing = await ready({ exposureEnabled: true });
    serveExposure(failing.f);
    let lookups = 0;
    failing.f.resolve = () => (++lookups <= 4 ? [{ address: "93.184.215.14", family: 4 }] : [{ address: "10.0.0.8", family: 4 }]);
    const failed = await views(failing, (await startAndWait(failing, { targetId: failing.target.id, includeExposureChecks: true })).body.scan.id);
    expect(failed.detail).toMatchObject({ status: "failed", reason: "blocked-address", exposureIncomplete: false, checks: [] });
    expect(failed.status).toBe("failed (blocked-address)");

    const off = await ready({ exposureEnabled: false });
    const rejected = (await startAndWait(off, { targetId: off.target.id, includeExposureChecks: true })).body.scan;
    expect(rejected).toMatchObject({ status: "rejected", exposureIncomplete: false, exposureIncompleteReason: null });
  });
});
