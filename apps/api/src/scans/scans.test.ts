import supertest from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Resolver, Transport, TransportRequest, TxtResolver } from "@agentshield/websec";
import { createTestApp, request } from "../test-support.js";
import { loadScanConfig, type ScanConfig } from "./config.js";
import { messageFor, refusalMessage, scanMessage, ScanService, TARGET_REJECTION_MESSAGES, verificationRefusal } from "./service.js";
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
  respond: (request: TransportRequest) => Promise<{ status: number; headers: Record<string, string | string[]> }>;
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
      const { status, headers } = await f.respond(req);
      return { status, headers, body: null, tls: null, close: () => {} };
    },
  };
  return f;
}

function setup(configOverrides: Partial<ScanConfig> = {}, env: NodeJS.ProcessEnv = {}) {
  const f = fakes();
  let clock = Date.parse("2026-10-29T00:00:00Z");
  const config = { ...loadScanConfig(env), ...configOverrides };
  const service = new ScanService({ config, resolver: f.resolver, txtResolver: f.txtResolver, transport: f.transport, now: () => clock });
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
