import { fsyncSync, mkdtempSync, readFileSync, rmSync, writeFileSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DEMO_AGENT_POLICY, type AgentPolicy } from "@agentshield/engine";
import { createApp } from "../app.js";
import { createApprovalStore } from "../approvals.js";
import { createPolicyStore } from "../policies/store.js";
import { loadSecurityConfig } from "../security/config.js";
import { createSimulator, type Simulator } from "../simulator.js";
import { request, signedRequest, TEST_API_TOKEN, testNonce, testSigningKey } from "../test-support.js";
import { DEFAULT_JOURNAL_IO, type JournalIo } from "../storage/journal.js";
import { createCredentialStore } from "./credentials.js";
import { openDurableNonceCache, type DurableNonceCache } from "./durable-nonce-cache.js";
import { createNonceCache, type NonceCache } from "./nonce-cache.js";

/**
 * M3-E E11: replay protection across API restarts, through the real verifier. Deterministic test
 * keys and clocks, temporary replay stores.
 */

const T = 1_793_523_600_000;
const SKEW = 30_000;
const writer = testSigningKey("writer", "e11-writer", { now: T - 60 * 60 * 1000 });
const policy: AgentPolicy = { agentId: "writer", version: 1, allowedActions: ["create_summary"], deniedActions: [], allowedDestinations: ["simulated-workspace"] };
const BODY = JSON.stringify({ intent: { task: "Summarize" }, action: { type: "create_summary", tool: "simulated.workspace.createSummary", destination: "simulated-workspace", summary: "Create" } });
const UNAUTHORIZED = [401, { error: "Authentication required." }];
const UNAVAILABLE = [503, { error: "Signed requests are temporarily unavailable. Try again later." }];

let dir: string;
let path: string;
let warnings: string[] = [];
const caches: DurableNonceCache[] = [];
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "agentshield-replay-restart-"));
  path = join(dir, "replay-nonces.journal");
  warnings = [];
  vi.spyOn(console, "warn").mockImplementation((line: unknown) => {
    warnings.push(String(line));
  });
});
afterEach(() => {
  vi.restoreAllMocks();
  for (const cache of caches.splice(0)) cache.close();
  rmSync(dir, { recursive: true, force: true });
});

/** One API process: its own clock, start time and replay cache (durable unless `memory`). */
function processAt(start: number, options: { memory?: boolean; io?: JournalIo; perKeyLimit?: number; globalLimit?: number } = {}) {
  let clock = start;
  const now = () => clock;
  let nonceCache: NonceCache;
  if (options.memory) nonceCache = createNonceCache({ now });
  else {
    const durable = openDurableNonceCache({ path, now, skewMs: SKEW, io: options.io, perKeyLimit: options.perKeyLimit, globalLimit: options.globalLimit });
    caches.push(durable);
    nonceCache = durable;
  }
  const simulator: Simulator = createSimulator();
  const app = createApp({
    apiToken: TEST_API_TOKEN,
    policyStore: createPolicyStore([DEMO_AGENT_POLICY, policy], "file"),
    credentialStore: createCredentialStore([writer.record], { now }),
    simulator,
    approvalStore: createApprovalStore(),
    nonceCache,
    now,
    security: { rateLimits: { ...loadSecurityConfig({}).rateLimits, evaluate: 1000 } },
  });
  const post = (ts: number, nonce: string, extra: Partial<Parameters<typeof signedRequest>[4]> = {}) => signedRequest(app, writer, "post", "/api/evaluate", { ts, body: BODY, nonce, ...extra }).send();
  const stop = () => {
    const durable = nonceCache as DurableNonceCache;
    if (!options.memory) {
      durable.close();
      caches.splice(caches.indexOf(durable), 1);
    }
  };
  return { app, simulator, post, stop, advance: (ms: number) => (clock += ms), nonceCache };
}

/** A replay store that already exists (an API ran before), so a start-up is not a recovery. */
function existingStore() {
  processAt(T - 60 * 60 * 1000).stop();
}

const body = (res: { status: number; body: unknown }) => [res.status, res.body];

describe("M3-E E11: replay protection survives restarts", () => {
  it("a valid request is accepted once; the same request again is a replay", async () => {
    existingStore();
    const p = processAt(T);
    const nonce = testNonce();
    expect((await p.post(T, nonce)).status).toBe(200);
    expect(body(await p.post(T, nonce))).toEqual(UNAUTHORIZED);
    expect(warnings.at(-1)).toContain("reason=replay");
    expect(p.simulator.invocationCount).toBe(1);
  });

  it("a future-dated request accepted before a restart is refused after it (the E9 L5 gap; with the old in-memory cache it was accepted again)", async () => {
    existingStore();
    const before = processAt(T);
    const nonce = testNonce();
    const ts = T + 20_000; // the agent's clock runs 20 s ahead
    expect((await before.post(ts, nonce)).status).toBe(200);
    before.stop();

    // The API restarts 5 s later: the start-up fence (ts >= startedAt) does not catch it, the durable cache does.
    const after = processAt(T + 5_000);
    expect(body(await after.post(ts, nonce))).toEqual(UNAUTHORIZED);
    expect(warnings.at(-1)).toContain("reason=replay");
    expect(after.simulator.invocationCount).toBe(0);

    // Control: the same restart with the pre-E11 in-memory cache accepts the replay.
    const old = processAt(T + 5_000, { memory: true });
    expect((await old.post(ts, nonce)).status).toBe(200);
  });

  it("a request signed before the restart (not future-dated) is still refused by the start-up fence", async () => {
    existingStore();
    const before = processAt(T);
    const nonce = testNonce();
    expect((await before.post(T, nonce)).status).toBe(200);
    before.stop();
    const after = processAt(T + 1_000);
    expect(body(await after.post(T, nonce))).toEqual(UNAUTHORIZED);
    expect(warnings.at(-1)).toContain("reason=before-startup");
  });

  it("a new (or deleted) store: timestamps up to start + skew get 503 until replay state is complete; then normal", async () => {
    const p = processAt(T);
    expect(body(await p.post(T, testNonce()))).toEqual(UNAVAILABLE);
    expect(warnings.at(-1)).toContain("reason=replay-recovering");
    expect(p.simulator.invocationCount).toBe(0);
    // Invalid signatures and stale requests are still 401, never 503.
    expect(body(await p.post(T, testNonce(), { signed: { body: "{}" } }))).toEqual(UNAUTHORIZED);
    expect(warnings.at(-1)).toContain("reason=bad-signature");
    p.advance(SKEW + 1);
    expect((await p.post(T + SKEW + 1, testNonce())).status).toBe(200);
    expect(body(await p.post(T, testNonce()))).toEqual(UNAUTHORIZED);
    expect(warnings.at(-1)).toContain("reason=stale");
  });

  it("a replay-store write failure refuses the request before anything is evaluated, and every signed request after it", async () => {
    existingStore();
    let fail = false;
    const io: JournalIo = {
      ...DEFAULT_JOURNAL_IO,
      writeSync: (fd, buffer, offset, length) => {
        if (fail) throw Object.assign(new Error("no space"), { code: "ENOSPC" });
        return writeSync(fd, buffer, offset, length);
      },
      fsyncSync: (fd) => fsyncSync(fd),
    };
    const p = processAt(T, { io });
    expect((await p.post(T, testNonce())).status).toBe(200);
    fail = true;
    expect(body(await p.post(T, testNonce()))).toEqual(UNAVAILABLE);
    expect(warnings.at(-1)).toContain("reason=replay-store-unavailable");
    fail = false;
    expect(body(await p.post(T, testNonce()))).toEqual(UNAVAILABLE);
    expect(p.simulator.invocationCount).toBe(1);
    expect((await request(p.app).get("/api/events")).body.events).toHaveLength(1);
  });

  it("a crash while persisting a nonce: its request never proceeded, so it is skipped without a recovery fence", async () => {
    existingStore();
    writeFileSync(path, `${readFileSync(path, "utf8")}n1 ${writer.keyId} abc`);
    const p = processAt(T);
    expect((p.nonceCache as DurableNonceCache).recovery).toMatchObject({ truncatedTail: true, recoveringUntil: 0 });
    expect((await p.post(T, testNonce())).status).toBe(200);
  });

  it("capacity limits are unchanged: 429 per key, 503 overall, and nothing is evicted", async () => {
    existingStore();
    const p = processAt(T, { perKeyLimit: 1, globalLimit: 5 });
    expect((await p.post(T, testNonce())).status).toBe(200);
    const limited = await p.post(T, testNonce());
    expect(limited.status).toBe(429);
    expect(warnings.at(-1)).toContain("reason=nonce-key-quota");
  });
});
