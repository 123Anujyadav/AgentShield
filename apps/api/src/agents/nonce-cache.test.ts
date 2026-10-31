import { describe, expect, it } from "vitest";
import { createNonceCache, DEFAULT_NONCE_GLOBAL_LIMIT, DEFAULT_NONCE_PER_KEY_LIMIT } from "./nonce-cache.js";

/** M3-E E3: the replay cache. Pure and in memory; the clock is a test clock. */

const KEY_A = "0123456789abcdef";
const KEY_B = "fedcba9876543210";
const T = 1_793_523_600_000;

function cache(options: { perKeyLimit?: number; globalLimit?: number } = {}) {
  let now = T;
  const nonces = createNonceCache({ now: () => now, ...options });
  return { nonces, advance: (ms: number) => (now += ms), at: () => now };
}
const nonce = (n: number) => `nonce-${n}`.padEnd(22, "x");

describe("M3-E E3: nonce cache", () => {
  it("defaults to 600 live nonces per key and 100,000 in total", () => {
    expect([DEFAULT_NONCE_PER_KEY_LIMIT, DEFAULT_NONCE_GLOBAL_LIMIT]).toEqual([600, 100_000]);
  });

  it("accepts a nonce once per key; the same nonce for another key is independent", () => {
    const { nonces } = cache();
    expect(nonces.checkAndInsert(KEY_A, nonce(1), T + 30_000)).toBe("accepted");
    expect(nonces.checkAndInsert(KEY_A, nonce(1), T + 30_000)).toBe("replay");
    expect(nonces.checkAndInsert(KEY_B, nonce(1), T + 30_000)).toBe("accepted");
    expect([nonces.size, nonces.sizeFor(KEY_A), nonces.sizeFor(KEY_B)]).toEqual([2, 1, 1]);
  });

  it("a nonce stays live up to and including its expiry, then may be pruned", () => {
    const { nonces, advance } = cache();
    nonces.checkAndInsert(KEY_A, nonce(1), T + 30_000);
    advance(30_000); // now == expiresAt: still a replay (the timestamp is still acceptable at this instant)
    expect(nonces.checkAndInsert(KEY_A, nonce(1), T + 30_000)).toBe("replay");
    advance(1);
    expect(nonces.checkAndInsert(KEY_A, nonce(1), T + 60_001)).toBe("accepted");
    expect(nonces.size).toBe(1);
  });

  it("at the per-key limit, live nonces are never evicted: the key gets key-quota until some expire", () => {
    const { nonces, advance } = cache({ perKeyLimit: 3 });
    for (const n of [1, 2, 3]) expect(nonces.checkAndInsert(KEY_A, nonce(n), T + 30_000 + n)).toBe("accepted");
    expect(nonces.checkAndInsert(KEY_A, nonce(4), T + 30_000)).toBe("key-quota");
    expect(nonces.checkAndInsert(KEY_B, nonce(4), T + 30_000)).toBe("accepted"); // other keys unaffected
    for (const n of [1, 2, 3]) expect(nonces.checkAndInsert(KEY_A, nonce(n), T + 30_000)).toBe("replay"); // still remembered
    advance(30_002); // nonce 1 (expires T+30001) has expired, 2 and 3 have not
    expect(nonces.checkAndInsert(KEY_A, nonce(5), T + 60_000)).toBe("accepted");
    expect(nonces.checkAndInsert(KEY_A, nonce(6), T + 60_000)).toBe("key-quota");
    expect(nonces.checkAndInsert(KEY_A, nonce(3), T + 60_000)).toBe("replay");
  });

  it("at the global limit, nothing live is evicted: new nonces get global-full until some expire", () => {
    const { nonces, advance } = cache({ perKeyLimit: 10, globalLimit: 3 });
    expect(nonces.checkAndInsert(KEY_A, nonce(1), T + 10_000)).toBe("accepted");
    expect(nonces.checkAndInsert(KEY_A, nonce(2), T + 30_000)).toBe("accepted");
    expect(nonces.checkAndInsert(KEY_B, nonce(3), T + 30_000)).toBe("accepted");
    expect(nonces.checkAndInsert(KEY_B, nonce(4), T + 30_000)).toBe("global-full");
    expect(nonces.checkAndInsert(KEY_A, nonce(1), T + 30_000)).toBe("replay"); // a replay is still detected when full
    advance(10_001);
    expect(nonces.checkAndInsert(KEY_B, nonce(4), T + 40_000)).toBe("accepted");
    expect(nonces.size).toBe(3);
    expect(nonces.checkAndInsert(KEY_B, nonce(5), T + 40_000)).toBe("global-full");
  });

  it("a full cache is not re-scanned until its earliest entry can have expired", () => {
    const { nonces, advance } = cache({ globalLimit: 2 });
    nonces.checkAndInsert(KEY_A, nonce(1), T + 30_000);
    nonces.checkAndInsert(KEY_B, nonce(2), T + 30_000);
    for (let i = 0; i < 1000; i += 1) expect(nonces.checkAndInsert(KEY_A, nonce(100 + i), T + 30_000)).toBe("global-full");
    expect(nonces.size).toBe(2);
    advance(30_001);
    expect(nonces.checkAndInsert(KEY_A, nonce(3), T + 60_000)).toBe("accepted");
    expect(nonces.size).toBe(1);
  });

  it("is deterministic: the same sequence always gives the same results", () => {
    const run = () => {
      const { nonces, advance } = cache({ perKeyLimit: 2, globalLimit: 3 });
      const out: string[] = [];
      for (let i = 0; i < 20; i += 1) {
        out.push(nonces.checkAndInsert(i % 2 ? KEY_A : KEY_B, nonce(i % 5), T + 5_000 + i * 1_000));
        advance(700);
      }
      return out;
    };
    expect(run()).toEqual(run());
  });

  it("refuses invalid limits", () => {
    for (const bad of [0, -1, 1.5, Number.NaN]) {
      expect(() => createNonceCache({ now: () => T, perKeyLimit: bad })).toThrowError(/positive integer/);
      expect(() => createNonceCache({ now: () => T, globalLimit: bad })).toThrowError(/positive integer/);
    }
  });
});
