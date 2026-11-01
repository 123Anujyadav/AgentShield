import { fsyncSync, mkdtempSync, readFileSync, rmSync, writeSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DEMO_AGENT_POLICY, type ActivityEvent, type AgentPolicy } from "@agentshield/engine";
import { createApp } from "../app.js";
import { createApprovalStore, type ApprovalStore } from "../approvals.js";
import { createPolicyStore } from "../policies/store.js";
import { loadSecurityConfig } from "../security/config.js";
import { createSimulator, type Simulator } from "../simulator.js";
import { request, signedRequest, TEST_API_TOKEN, testSigningKey } from "../test-support.js";
import { createCredentialStore } from "../agents/credentials.js";
import { openFileAuditLog, parseAuditRecord, type AuditFileIo, type AuditLog, type AuditLogOptions } from "./file-audit-log.js";

/**
 * M3-E E10: the API with durable audit storage. Events are written to a temporary audit file
 * before they appear in GET /api/events; state-changing routes fail closed while the store is
 * failed or full. Deterministic test keys, temporary files only.
 */

const writer = testSigningKey("writer", "e10-writer");
const summarize = (agentId: string): AgentPolicy => ({ agentId, version: 1, allowedActions: ["create_summary"], deniedActions: [], allowedDestinations: ["simulated-workspace"] });
const SECRET_MARKER = "fakeAuditDestSecret123456";

let dir: string;
let path: string;
const logs: AuditLog[] = [];
let errors: string[] = [];
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "agentshield-audit-routes-"));
  path = join(dir, "audit-events.jsonl");
  errors = [];
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation((line: unknown) => {
    errors.push(String(line));
  });
});
afterEach(() => {
  vi.restoreAllMocks();
  for (const log of logs.splice(0)) log.close();
  rmSync(dir, { recursive: true, force: true });
});

function start(options: AuditLogOptions & { maxEvents?: number; approvalStore?: ApprovalStore; simulator?: Simulator } = {}) {
  const auditLog = openFileAuditLog(path, options);
  logs.push(auditLog);
  const simulator = options.simulator ?? createSimulator();
  const approvalStore = options.approvalStore ?? createApprovalStore();
  const app = createApp({
    apiToken: TEST_API_TOKEN,
    policyStore: createPolicyStore([DEMO_AGENT_POLICY, summarize("writer")], "file"),
    credentialStore: createCredentialStore([writer.record]),
    simulator,
    approvalStore,
    auditLog,
    security: { ...(options.maxEvents ? { maxEvents: options.maxEvents } : {}), rateLimits: { ...loadSecurityConfig({}).rateLimits, evaluate: 1000 } },
  });
  const scenario = (scenarioId: string) => request(app).post("/api/evaluate").send({ scenarioId });
  const listed = async () => (await request(app).get("/api/events")).body.events as ActivityEvent[];
  return { app, auditLog, simulator, approvalStore, scenario, listed };
}

const stored = () =>
  readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => parseAuditRecord(line)!.event);

/** Fails every write once armed (as a full disk would). */
function armableIo() {
  let armed = false;
  const io: AuditFileIo = {
    writeSync: (fd, buffer, offset, length) => {
      if (armed) throw Object.assign(new Error("no space left on device"), { code: "ENOSPC" });
      return writeSync(fd, buffer, offset, length);
    },
    fsyncSync: (fd) => fsyncSync(fd),
  };
  return { io, arm: () => (armed = true) };
}

describe("M3-E E10: durable audit events through the API", () => {
  it("every event is in the file, in order, and GET /api/events is unchanged (newest first, same events)", async () => {
    const t = start();
    for (const id of ["benign-summary", "injection-in-document", "forbidden-payment"]) expect((await t.scenario(id)).status).toBe(200);
    const listed = await t.listed();
    expect(listed.map((e) => e.id)).toEqual(["evt-3", "evt-2", "evt-1"]);
    expect(stored()).toEqual([...listed].reverse());
    expect(stored().map((e) => e.lifecycle)).toEqual(["SIMULATED_EXECUTED", "PENDING_CONFIRMATION", "BLOCKED"]);
  });

  it("events survive a restart: the view is restored, ids continue, and the file keeps more than the view", async () => {
    let t = start({ maxEvents: 3 });
    for (let i = 0; i < 4; i += 1) await t.scenario("benign-summary");
    expect((await t.listed()).map((e) => e.id)).toEqual(["evt-4", "evt-3", "evt-2"]);
    t.auditLog.close();
    t = start({ maxEvents: 3 });
    expect((await t.listed()).map((e) => e.id)).toEqual(["evt-4", "evt-3", "evt-2"]);
    await t.scenario("injection-in-document");
    expect((await t.listed()).map((e) => e.id)).toEqual(["evt-5", "evt-4", "evt-3"]);
    expect(stored().map((e) => e.id)).toEqual(["evt-1", "evt-2", "evt-3", "evt-4", "evt-5"]); // nothing evicted from the file
  });

  it("the file holds only redacted values: no secret-shaped field, no credential, no Authorization header", async () => {
    const t = start();
    const body = JSON.stringify({
      intent: { task: "Summarize", allowedActions: ["create_summary"], allowedDestinations: ["simulated-workspace"] },
      action: { type: "create_summary", tool: "simulated.workspace.createSummary", destination: `api_key=${SECRET_MARKER}`, summary: "Create" },
    });
    const signed = signedRequest(t.app, writer, "post", "/api/evaluate", { ts: Date.now(), body });
    expect((await signed.send()).status).toBe(200);
    const file = readFileSync(path, "utf8");
    expect(file).toContain("[REDACTED]");
    expect(file).not.toContain(SECRET_MARKER);
    expect(file).not.toContain("AGENTSHIELD-SIG-V1");
    expect(file).not.toContain(signed.authorization.slice(-40));
    const secretKey = (writer.privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).toString("base64url");
    expect(file).not.toContain(secretKey);
    expect(file).not.toContain(TEST_API_TOKEN);
    expect(stored()[0]).toMatchObject({ actor: { kind: "agent", credentialId: writer.keyId } });
  });

  it("concurrent requests are written one at a time: unique ids, strictly increasing, the file matches the view", async () => {
    const t = start();
    const results = await Promise.all(Array.from({ length: 20 }, (_, i) => t.scenario(i % 2 ? "benign-summary" : "injection-in-document")));
    expect(results.every((r) => r.status === 200)).toBe(true);
    const ids = stored().map((e) => Number(e.id.slice(4)));
    expect(ids).toEqual(Array.from({ length: 20 }, (_, i) => i + 1));
    expect((await t.listed()).map((e) => e.id)).toEqual([...stored()].reverse().map((e) => e.id));
  });

  it("an EXPIRED lifecycle event is stored durably like any other", async () => {
    const t = start();
    const id = (await t.scenario("injection-in-document")).body.pendingApproval.id as string;
    t.approvalStore.records.get(id)!.expiresAt = new Date(Date.now() - 1000).toISOString();
    expect((await request(t.app).get("/api/approvals")).status).toBe(200);
    expect(stored().filter((e) => e.lifecycle === "EXPIRED" && e.approvalId === id)).toHaveLength(1);
  });

  it("no response exposes the storage location", async () => {
    const t = start();
    const responses = [await t.scenario("benign-summary"), await request(t.app).get("/api/events"), await request(t.app).get("/api/approvals")];
    for (const res of responses) expect(JSON.stringify(res.body)).not.toContain(dir.replace(/\\/g, "\\\\"));
  });
});

describe("M3-E E10: failing closed when audit storage fails", () => {
  it("a failed write is reported (500 audit-write-failed), never as success; then evaluate, approve and reject are refused before any change", async () => {
    const failing = armableIo();
    const t = start({ io: failing.io });
    const pending = (await t.scenario("injection-in-document")).body.pendingApproval.id as string;
    failing.arm();

    const broken = await t.scenario("benign-summary");
    expect([broken.status, broken.body]).toEqual([500, { error: "The audit event could not be stored durably. The outcome of this request is not confirmed.", reason: "audit-write-failed" }]);
    expect(errors).toContain("audit-log status=write-failed code=ENOSPC effect=state-changes-refused");
    const ranBefore = t.simulator.invocationCount; // the simulated handler had already run: the outcome is unconfirmed, not denied

    for (const res of [await t.scenario("benign-summary"), await request(t.app).post(`/api/approvals/${pending}/approve`).send({}), await request(t.app).post(`/api/approvals/${pending}/reject`).send({})]) {
      expect([res.status, res.body.reason]).toEqual([503, "audit-unavailable"]);
    }
    expect(t.simulator.invocationCount).toBe(ranBefore);
    expect(t.approvalStore.records.get(pending)!.status).toBe("PENDING");

    // Reads keep working; the view never shows an event that was not stored.
    const listed = await t.listed();
    expect(listed.map((e) => e.id)).toEqual(["evt-1"]);
    expect(stored().map((e) => e.id)).toEqual(["evt-1"]);
    expect((await request(t.app).get("/api/approvals")).status).toBe(200);
    const agentRead = await signedRequest(t.app, writer, "get", "/api/agent/approvals", { ts: Date.now() }).send();
    expect(agentRead.status).toBe(200);
  });

  it("a full store refuses state changes with 503 audit-storage-full before anything runs; nothing old is dropped", async () => {
    const probe = start();
    await probe.scenario("injection-in-document");
    const recordBytes = readFileSync(path).length;
    probe.auditLog.close();
    rmSync(path);

    // Room for two records: after them, less than one maximum-size record (2R + 100) remains.
    const t = start({ maxBytes: recordBytes * 4 + 50, maxRecordBytes: recordBytes * 2 + 100 });
    const pending = (await t.scenario("injection-in-document")).body.pendingApproval.id as string;
    expect((await t.scenario("injection-in-document")).status).toBe(200);
    expect(t.auditLog.readiness()).toEqual({ ok: false, reason: "audit-storage-full" });
    const ran = t.simulator.invocationCount;
    const approvals = t.approvalStore.records.size;

    for (const res of [await t.scenario("benign-summary"), await request(t.app).post(`/api/approvals/${pending}/approve`).send({})]) {
      expect(res.status).toBe(503);
      expect(res.body).toEqual({
        error: "The audit log is full, so nothing can be changed until the operator archives it. Nothing was evaluated or executed.",
        reason: "audit-storage-full",
      });
    }
    expect([t.simulator.invocationCount, t.approvalStore.records.size, t.approvalStore.records.get(pending)!.status]).toEqual([ran, approvals, "PENDING"]);
    expect(stored().map((e) => e.id)).toEqual(["evt-1", "evt-2"]);
    expect((await t.listed()).map((e) => e.id)).toEqual(["evt-2", "evt-1"]);
  });
});

describe("M3-E E10: the server opens the durable audit log at start-up", () => {
  it("opens it before listening, fails closed on a log it cannot use, and passes it to the app", () => {
    const server = readFileSync(fileURLToPath(new URL("../server.ts", import.meta.url)), "utf8");
    expect(server).toContain("auditLog = openFileAuditLog(auditLogPathFromEnv(), { maxBytes: auditLogMaxBytesFromEnv() });");
    expect(server).toMatch(/catch \(error\) \{[\s\S]*?audit-log status=invalid-config[\s\S]*?process\.exit\(1\);/);
    expect(server).toContain("createApp({ apiToken: tokenFile.token, policyStore, credentialStore, signatureSkewMs, auditLog, nonceCache, idempotencyStore, approvalStore })");
    expect(server.indexOf("openFileAuditLog(")).toBeLessThan(server.indexOf(".listen("));
    expect(server).toContain('process.on("exit", () => auditLog.close());');
  });

  it("M3-E E11: opens the durable replay and idempotency stores before listening, fails closed, and passes them to the app", () => {
    const server = readFileSync(fileURLToPath(new URL("../server.ts", import.meta.url)), "utf8");
    expect(server).toContain("nonceCache = openDurableNonceCache({ path: replayStorePathFromEnv(), now: Date.now, skewMs: signatureSkewMs, checkPermissions: true });");
    expect(server).toContain("idempotencyStore = createIdempotencyStore({ path: idempotencyStorePathFromEnv(), checkPermissions: true });");
    expect(server).toMatch(/catch \(error\) \{[\s\S]*?agent-state status=invalid-config[\s\S]*?process\.exit\(1\);/);
    expect(server.indexOf("openDurableNonceCache(")).toBeLessThan(server.indexOf(".listen("));
  });

  it("M3-E E12: opens the durable approval store before listening, fails closed, and passes it to the app", () => {
    const server = readFileSync(fileURLToPath(new URL("../server.ts", import.meta.url)), "utf8");
    expect(server).toContain("approvalStore = openDurableApprovalStore({ path: approvalStorePathFromEnv(), checkPermissions: true });");
    expect(server.indexOf("openDurableApprovalStore(")).toBeLessThan(server.indexOf(".listen("));
    expect(server.indexOf("openDurableApprovalStore(")).toBeLessThan(server.indexOf("agent-state status=invalid-config"));
  });
});
