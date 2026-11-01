import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createIdempotencyStore, evaluationDigest, IDEMPOTENCY_TTL_MS, MAX_IDEMPOTENCY_KEYS, MAX_IDEMPOTENCY_KEYS_PER_AGENT, type IdempotencyStore } from "./idempotency.js";

/** M3-E E11: the idempotency store on its own. Temporary files only. */

const T = 1_793_523_600_000;
const D1 = "1".repeat(64);
const D2 = "2".repeat(64);
const OK = { status: 200 as const, body: { evaluation: { decision: "ALLOW" }, executed: true } };

let dir: string;
let path: string;
const stores: IdempotencyStore[] = [];
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "agentshield-idempotency-store-"));
  path = join(dir, "idempotency.journal");
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
  vi.restoreAllMocks();
  for (const s of stores.splice(0)) s.close();
  rmSync(dir, { recursive: true, force: true });
});
const open = (options: Parameters<typeof createIdempotencyStore>[0] = {}) => {
  const store = createIdempotencyStore({ path, now: () => T, ...options });
  stores.push(store);
  return store;
};
const reopen = (store: IdempotencyStore, options: Parameters<typeof createIdempotencyStore>[0] = {}) => {
  store.close();
  stores.splice(stores.indexOf(store), 1);
  return open(options);
};

describe("M3-E E11: idempotency store", () => {
  it("defaults: 15-minute retention, 1,000 keys per agent, 10,000 in total", () => {
    expect([IDEMPOTENCY_TTL_MS, MAX_IDEMPOTENCY_KEYS_PER_AGENT, MAX_IDEMPOTENCY_KEYS]).toEqual([900_000, 1_000, 10_000]);
  });

  it("the digest ignores property order but not content", () => {
    expect(evaluationDigest({ a: 1, b: { c: [1, 2], d: "x" } })).toBe(evaluationDigest({ b: { d: "x", c: [1, 2] }, a: 1 }));
    expect(evaluationDigest({ a: 1, b: { c: [2, 1] } })).not.toBe(evaluationDigest({ a: 1, b: { c: [1, 2] } }));
  });

  it("a duplicate waits for the running evaluation; if that evaluation fails, waiters and later retries get no result (outcome unknown)", async () => {
    const store = open();
    expect(store.begin("writer", "key-000000000000001", D1, T).kind).toBe("new");
    const second = store.begin("writer", "key-000000000000001", D1, T);
    expect(second.kind).toBe("in-progress");
    store.abandon("writer", "key-000000000000001");
    expect(await (second as { wait: Promise<unknown> }).wait).toBeNull();
    expect(store.begin("writer", "key-000000000000001", D1, T).kind).toBe("unknown");
    expect(store.begin("writer", "key-000000000000001", D2, T).kind).toBe("conflict");
  });

  it("completed results are replayed, durably; a result too large to store leaves the key outcome-unknown", () => {
    let store = open({ maxRecordBytes: 600 });
    store.begin("writer", "key-000000000000001", D1, T);
    store.complete("writer", "key-000000000000001", OK);
    store.begin("writer", "key-000000000000002", D1, T);
    store.complete("writer", "key-000000000000002", { status: 200, body: { evaluation: { explanation: "x".repeat(2000) } } });
    store = reopen(store, { maxRecordBytes: 600 });
    expect(store.begin("writer", "key-000000000000001", D1, T)).toEqual({ kind: "replay", outcome: OK });
    expect(store.begin("writer", "key-000000000000002", D1, T).kind).toBe("unknown");
  });

  it("a corrupted record: keys without a record are refused until the retention period has passed (a lost start record must not allow a second run)", () => {
    let store = open();
    store.begin("writer", "key-000000000000001", D1, T);
    store.complete("writer", "key-000000000000001", OK);
    store.close();
    stores.length = 0;
    writeFileSync(path, readFileSync(path, "utf8") + "{not json\n");
    store = open();
    expect(store.recovery).toMatchObject({ corrupt: 1, recoveringUntil: T + IDEMPOTENCY_TTL_MS });
    expect(store.begin("writer", "key-000000000000001", D1, T).kind).toBe("replay");
    expect(store.begin("writer", "key-000000000000009", D1, T).kind).toBe("unavailable");
    expect(readFileSync(path, "utf8")).not.toContain("{not json"); // dropped, with the window recorded instead
    const inside = reopen(store, { now: () => T + 1_000 });
    expect(inside.recovery).toMatchObject({ corrupt: 0, recoveringUntil: T + IDEMPOTENCY_TTL_MS });
    const later = reopen(inside, { now: () => T + IDEMPOTENCY_TTL_MS + 1 });
    expect(later.begin("writer", "key-000000000000009", D1, T + IDEMPOTENCY_TTL_MS + 1).kind).toBe("new");
  });

  it("a start record cut short by a crash belongs to an evaluation that never ran: no fallback, the key is new", () => {
    let store = open();
    store.close();
    stores.length = 0;
    writeFileSync(path, '{"v":1,"t":"b","a":"writer","k":"key-0000');
    store = open();
    expect(store.recovery).toMatchObject({ truncatedTail: true, corrupt: 0, recoveringUntil: 0 });
    expect(store.begin("writer", "key-000000000000001", D1, T).kind).toBe("new");
  });

  it("capacity frees as records expire; live records are never evicted", () => {
    let now = T;
    const store = open({ perAgentLimit: 2, ttlMs: 1_000, now: () => now });
    expect(store.begin("writer", "key-000000000000001", D1, now).kind).toBe("new");
    expect(store.begin("writer", "key-000000000000002", D1, now).kind).toBe("new");
    expect(store.begin("writer", "key-000000000000003", D1, now).kind).toBe("full");
    store.complete("writer", "key-000000000000001", OK);
    store.complete("writer", "key-000000000000002", OK);
    now += 1_000;
    expect(store.begin("writer", "key-000000000000003", D1, now).kind).toBe("new");
  });

  it("compacts to live records when the journal grows, keeping every live result", () => {
    let now = T;
    let store = open({ ttlMs: 1_000, compactAtBytes: 400, now: () => now });
    for (let i = 1; i <= 5; i += 1) {
      store.begin("writer", `old-key-00000000000${i}`, D1, now);
      store.complete("writer", `old-key-00000000000${i}`, OK);
    }
    now += 2_000;
    for (let i = 1; i <= 5; i += 1) {
      store.begin("writer", `new-key-00000000000${i}`, D1, now);
      store.complete("writer", `new-key-00000000000${i}`, OK);
    }
    expect(readFileSync(path, "utf8")).not.toContain("old-key-000000000001");
    store = reopen(store, { ttlMs: 1_000, now: () => now });
    for (let i = 1; i <= 5; i += 1) expect(store.begin("writer", `new-key-00000000000${i}`, D1, now).kind).toBe("replay");
  });
});
