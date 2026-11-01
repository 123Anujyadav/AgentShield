import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DEMO_AGENT_POLICY, evaluateAction, getScenario, type ActivityEvent } from "@agentshield/engine";
import { createApp } from "../app.js";
import { openDurableApprovalStore } from "../approval-journal.js";
import { createApprovalStore, createPendingApproval, processRejection } from "../approvals.js";
import { openFileAuditLog } from "../audit/file-audit-log.js";
import { openDurableNonceCache } from "../agents/durable-nonce-cache.js";
import { createCredentialStore } from "../agents/credentials.js";
import { createIdempotencyStore } from "../idempotency.js";
import { createPolicyStore } from "../policies/store.js";
import { loadSecurityConfig } from "../security/config.js";
import { createSimulator } from "../simulator.js";
import { signedRequest, TEST_API_TOKEN, testSigningKey } from "../test-support.js";

/**
 * M3-E E13: deterministic fuzzing of the persistent journals and of request validation. A fixed-seed
 * PRNG (mulberry32) applies random damage (garbage, Unicode and control characters, oversized, duplicated,
 * deleted, swapped and edited records); each store must recover without throwing and keep its safety
 * invariants. Temporary files only; no dependency is added.
 */

function prng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const SEEDS = Array.from({ length: 12 }, (_, i) => 1000 + i * 7919);
const NASTY = ["\u0000", "\u0007", "\u001b[31m", "\u200B", "\u202E", "\u2028", "😀", "\ud800", '"', "\\", "{", "}", "apr-", "\t", "evt-1"];

/** Applies 1 to 4 random kinds of damage to a journal's lines (never removing whole records from the end only). */
function damage(lines: string[], random: () => number): string[] {
  const out = [...lines];
  const pick = () => Math.floor(random() * out.length);
  const steps = 1 + Math.floor(random() * 4);
  for (let s = 0; s < steps; s += 1) {
    const kind = Math.floor(random() * 6);
    if (out.length === 0) break;
    if (kind === 0) out.splice(pick(), 0, Array.from({ length: 1 + Math.floor(random() * 30) }, () => NASTY[Math.floor(random() * NASTY.length)]).join(""));
    else if (kind === 1 && out.length > 1) out.splice(pick(), 1);
    else if (kind === 2 && out.length > 1) {
      const i = pick();
      const j = pick();
      [out[i], out[j]] = [out[j]!, out[i]!];
    } else if (kind === 3) out.splice(pick(), 0, out[pick()]!);
    else if (kind === 4) {
      const i = pick();
      const line = out[i]!;
      const at = Math.floor(random() * line.length);
      out[i] = line.slice(0, at) + NASTY[Math.floor(random() * NASTY.length)] + line.slice(at + 1);
    } else out.splice(pick(), 0, "x".repeat(2000 + Math.floor(random() * 3000)));
  }
  // Keep at least one damaged line after the last original record, so the damage is not only a truncation.
  out.push(`${"garbage-tail"}`);
  return out;
}

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "agentshield-fuzz-"));
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
  vi.restoreAllMocks();
  rmSync(dir, { recursive: true, force: true });
});

const linesOf = (path: string) => readFileSync(path, "utf8").split("\n").filter(Boolean);
const writeLines = (path: string, lines: string[]) => writeFileSync(path, lines.map((l) => `${l}\n`).join(""));

describe("M3-E E13: journal fuzzing keeps every store's safety invariants", () => {
  const scenario = getScenario("injection-in-document")!;
  const evaluation = evaluateAction({ intent: scenario.intent, action: scenario.action, untrustedContent: scenario.untrustedContent });

  it.each(SEEDS)("approvals: no damaged or unverifiable approval is ever PENDING (seed %i)", (seed) => {
    const random = prng(seed);
    const path = join(dir, `approvals-${seed}.journal`);
    const store = openDurableApprovalStore({ path });
    const originals = new Map<string, string>();
    for (let i = 0; i < 6; i += 1) {
      const a = createPendingApproval(store, { scenarioId: null, intent: scenario.intent, action: scenario.action, untrustedContent: scenario.untrustedContent, evaluation, agentId: "writer", requestedBy: { kind: "agent", credentialId: "0123456789abcdef" }, credentialKeyId: "0123456789abcdef" });
      if (i % 3 === 2) processRejection(store, a.id);
      originals.set(a.id, JSON.stringify(store.records.get(a.id)));
    }
    store.close();
    writeLines(path, damage(linesOf(path), random));
    const recovered = openDurableApprovalStore({ path });
    try {
      for (const record of recovered.records.values()) {
        if (record.status !== "PENDING") continue;
        // A pending approval after recovery is byte-for-byte one that was stored as pending.
        expect(originals.get(record.id)).toBe(JSON.stringify(record));
      }
      expect(recovered.recovery.corrupt).toBeGreaterThan(0);
    } finally {
      recovered.close();
    }
  });

  it.each(SEEDS)("replay: after damage, either the recovery fence applies or every stored nonce is still a replay (seed %i)", (seed) => {
    const random = prng(seed);
    const path = join(dir, `replay-${seed}.journal`);
    const T = 1_793_523_600_000;
    const nonces = Array.from({ length: 8 }, (_, i) => `nonce-${String(i).padStart(16, "0")}`);
    const cache = openDurableNonceCache({ path, now: () => T - 120_000, skewMs: 30_000 });
    for (const nonce of nonces) cache.checkAndInsert("0123456789abcdef", nonce, T + 30_000, T - 120_000);
    cache.close();
    writeLines(path, damage(linesOf(path), random));
    const recovered = openDurableNonceCache({ path, now: () => T, skewMs: 30_000 });
    try {
      if (recovered.recoveringUntil === 0) {
        for (const nonce of nonces) expect(recovered.checkAndInsert("0123456789abcdef", nonce, T + 30_000, T)).toBe("replay");
      } else {
        expect(recovered.recoveringUntil).toBe(T + 30_000);
      }
    } finally {
      recovered.close();
    }
  });

  it.each(SEEDS)("idempotency: a damaged journal never replays a result that was not stored, and never treats a known key as new (seed %i)", (seed) => {
    const random = prng(seed);
    const path = join(dir, `idempotency-${seed}.journal`);
    const now = Date.now();
    const store = createIdempotencyStore({ path, now: () => now });
    const outcomes = new Map<string, unknown>();
    for (let i = 0; i < 6; i += 1) {
      const key = `fuzz-key-${String(i).padStart(10, "0")}`;
      store.begin("writer", key, "a".repeat(64), now);
      const outcome = { status: 200 as const, body: { evaluation: { decision: i % 2 ? "ALLOW" : "BLOCK" }, n: i } };
      store.complete("writer", key, outcome);
      outcomes.set(key, outcome);
    }
    store.close();
    writeLines(path, damage(linesOf(path), random));
    const recovered = createIdempotencyStore({ path, now: () => now });
    try {
      for (const [key, outcome] of outcomes) {
        const begun = recovered.begin("writer", key, "a".repeat(64), now);
        if (begun.kind === "replay") expect(begun.outcome).toEqual(outcome);
        else expect(["unknown", "unavailable"]).toContain(begun.kind);
      }
    } finally {
      recovered.close();
    }
  });

  it.each(SEEDS)("audit: a damaged log loads only events that were written, in order, and never throws (seed %i)", (seed) => {
    const random = prng(seed);
    const path = join(dir, `audit-${seed}.jsonl`);
    const log = openFileAuditLog(path);
    const written: ActivityEvent[] = [];
    for (let i = 1; i <= 8; i += 1) {
      const event: ActivityEvent = { id: `evt-${i}`, timestamp: new Date(Date.UTC(2026, 10, 1, 9, 0, i)).toISOString(), scenarioId: null, intentTask: `T${i}`, actionType: "create_summary", tool: "t", destination: "d", decision: "ALLOW", riskScore: 1, findings: [], explanation: "e" };
      log.append(event);
      written.push(event);
    }
    log.close();
    writeLines(path, damage(linesOf(path), random));
    const recovered = openFileAuditLog(path);
    try {
      const ids = recovered.loaded.map((e) => Number(e.id.slice(4)));
      expect([...ids].sort((a, b) => a - b)).toEqual(ids);
      expect(new Set(ids).size).toBe(ids.length);
      for (const event of recovered.loaded) expect(written).toContainEqual(event);
      expect(recovered.nextSequence).toBeGreaterThan(8);
    } finally {
      recovered.close();
    }
  });
});

describe("M3-E E13: request validation fuzzing", () => {
  it.each(SEEDS.slice(0, 4))("random JSON bodies on POST /api/evaluate never cause a 500 and never execute an invalid request (seed %i)", async (seed) => {
    const random = prng(seed);
    const writer = testSigningKey("writer", "e13-fuzz-writer");
    const simulator = createSimulator();
    const app = createApp({
      apiToken: TEST_API_TOKEN,
      policyStore: createPolicyStore([DEMO_AGENT_POLICY, { agentId: "writer", version: 1, allowedActions: ["create_summary"], deniedActions: [], allowedDestinations: ["simulated-workspace"] }], "file"),
      credentialStore: createCredentialStore([writer.record]),
      simulator,
      approvalStore: createApprovalStore(),
      security: { rateLimits: { ...loadSecurityConfig({}).rateLimits, evaluate: 10_000, api: 10_000 } },
    });
    const value = (depth: number): unknown => {
      const r = random();
      if (depth > 3 || r < 0.25) return NASTY[Math.floor(random() * NASTY.length)]! + "x".repeat(Math.floor(random() * 20));
      if (r < 0.35) return Math.floor(random() * 1e6) - 5e5;
      if (r < 0.4) return random() < 0.5;
      if (r < 0.45) return null;
      if (r < 0.6) return Array.from({ length: Math.floor(random() * 4) }, () => value(depth + 1));
      const keys = ["intent", "action", "untrustedContent", "task", "type", "tool", "destination", "summary", "payload", "agentId", "idempotencyKey", "source", "text", "__proto__", "constructor"];
      return Object.fromEntries(Array.from({ length: Math.floor(random() * 5) }, () => [keys[Math.floor(random() * keys.length)]!, value(depth + 1)]));
    };
    for (let i = 0; i < 40; i += 1) {
      const body = JSON.stringify(value(0));
      const res = await signedRequest(app, writer, "post", "/api/evaluate", { ts: Date.now(), body }).send();
      expect([200, 400, 403, 409, 413, 503]).toContain(res.status);
    }
    expect(simulator.invocationCount).toBe(0); // random bodies are never a valid, allowed action
  });
});
