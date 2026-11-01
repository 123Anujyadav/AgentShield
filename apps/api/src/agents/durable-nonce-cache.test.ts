import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync, fsyncSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DEFAULT_JOURNAL_IO, type JournalIo } from "../storage/journal.js";
import { openDurableNonceCache, replayStorePathFromEnv, type DurableNonceCache } from "./durable-nonce-cache.js";

/** M3-E E11: the durable replay cache on its own. Temporary files only. */

const T = 1_793_523_600_000;
const SKEW = 30_000;
const KEY_A = "0123456789abcdef";
const KEY_B = "fedcba9876543210";
const nonce = (n: number) => `nonce-${String(n).padStart(16, "0")}`; // 22 base64url characters

let dir: string;
let path: string;
let clock = T;
const open: DurableNonceCache[] = [];
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "agentshield-replay-test-"));
  path = join(dir, "replay-nonces.journal");
  clock = T;
});
afterEach(() => {
  for (const cache of open.splice(0)) cache.close();
  rmSync(dir, { recursive: true, force: true });
});

function openCache(extra: Partial<Parameters<typeof openDurableNonceCache>[0]> = {}) {
  const cache = openDurableNonceCache({ path, now: () => clock, skewMs: SKEW, ...extra });
  open.push(cache);
  return cache;
}
function restart(cache: DurableNonceCache, extra: Partial<Parameters<typeof openDurableNonceCache>[0]> = {}) {
  cache.close();
  open.splice(open.indexOf(cache), 1);
  return openCache(extra);
}
/** Nonce records only (a new store also records its recovery window as `r1 <until>`). */
const lines = () => readFileSync(path, "utf8").split("\n").filter((l) => l.startsWith("n1 "));

describe("M3-E E11: durable replay cache", () => {
  it("records each accepted nonce durably; a repeat is a replay, before and after a restart", () => {
    let cache = openCache();
    expect(cache.checkAndInsert(KEY_A, nonce(1), T + SKEW, T)).toBe("accepted");
    expect(cache.checkAndInsert(KEY_A, nonce(1), T + SKEW, T)).toBe("replay");
    expect(lines()).toEqual([`n1 ${KEY_A} ${nonce(1)} ${T + SKEW}`]);
    clock = T + 5_000;
    cache = restart(cache);
    expect(cache.recovery).toMatchObject({ loaded: 1, corrupt: 0, created: false, recoveringUntil: T + SKEW }); // still inside the new store's window
    expect(cache.checkAndInsert(KEY_A, nonce(1), T + SKEW, clock)).toBe("replay");
    expect(cache.checkAndInsert(KEY_B, nonce(1), T + SKEW, clock)).toBe("accepted"); // per key, as before
  });

  it("expired nonces are not loaded back", () => {
    let cache = openCache();
    cache.checkAndInsert(KEY_A, nonce(1), T + SKEW, T);
    clock = T + SKEW + 1;
    cache = restart(cache);
    expect(cache.recovery.loaded).toBe(0);
  });

  it("a new store, or one with a corrupted record, refuses timestamps up to start + skew (anything a previous process could have accepted)", () => {
    const fresh = openCache();
    expect(fresh.recovery).toMatchObject({ created: true, recoveringUntil: T + SKEW });
    fresh.checkAndInsert(KEY_A, nonce(1), T + SKEW, T);
    fresh.close();
    open.length = 0;
    writeFileSync(path, readFileSync(path, "utf8") + "garbage line\n");
    clock = T + 1_000;
    const corrupted = openCache();
    expect(corrupted.recovery).toMatchObject({ corrupt: 1, loaded: 1, recoveringUntil: T + 1_000 + SKEW });
    expect(corrupted.recoveringUntil).toBe(T + 1_000 + SKEW);
  });

  it("the recovery window is recorded: a restart inside it keeps it; after it, unreadable lines are gone and there is no fence", () => {
    let cache = openCache(); // new store: recovering until T + SKEW
    clock = T + 10_000;
    cache = restart(cache);
    expect(cache.recoveringUntil).toBe(T + SKEW);
    cache.close();
    open.length = 0;
    writeFileSync(path, readFileSync(path, "utf8") + "garbage line\n");
    clock = T + 20_000;
    cache = openCache();
    expect(cache.recoveringUntil).toBe(T + 20_000 + SKEW);
    expect(readFileSync(path, "utf8")).not.toContain("garbage");
    clock = T + 20_000 + SKEW + 1;
    cache = restart(cache);
    expect(cache.recovery).toMatchObject({ corrupt: 0, recoveringUntil: 0 });
  });

  it("a final record cut short by a crash is skipped without the fallback: its request never proceeded", () => {
    clock = T - 60_000; // created a minute earlier: its own recovery window has passed
    let cache = openCache();
    clock = T;
    cache.checkAndInsert(KEY_A, nonce(1), T + SKEW, T);
    cache.close();
    open.length = 0;
    writeFileSync(path, readFileSync(path, "utf8") + `n1 ${KEY_A} ${nonce(2)} 17935`);
    cache = openCache();
    expect(cache.recovery).toMatchObject({ truncatedTail: true, corrupt: 0, loaded: 1, recoveringUntil: 0 });
    expect(cache.checkAndInsert(KEY_A, nonce(2), T + SKEW, T)).toBe("accepted");
  });

  it("a write failure refuses the request (store-unavailable) and every later one until a restart", () => {
    let fail = false;
    const io: JournalIo = {
      ...DEFAULT_JOURNAL_IO,
      writeSync: (fd, buffer, offset, length) => {
        if (fail) throw Object.assign(new Error("no space"), { code: "ENOSPC" });
        return writeSync(fd, buffer, offset, length);
      },
      fsyncSync: (fd) => fsyncSync(fd),
    };
    const cache = openCache({ io });
    expect(cache.checkAndInsert(KEY_A, nonce(1), T + SKEW, T)).toBe("accepted");
    fail = true;
    expect(cache.checkAndInsert(KEY_A, nonce(2), T + SKEW, T)).toBe("store-unavailable");
    fail = false;
    expect(cache.checkAndInsert(KEY_A, nonce(3), T + SKEW, T)).toBe("store-unavailable");
    // The refused nonce stays known in memory: resending it is still a replay.
    expect(cache.checkAndInsert(KEY_A, nonce(2), T + SKEW, T)).toBe("store-unavailable");
    expect(restart(cache).recovery.loaded).toBe(1);
  });

  it("limits are unchanged and live nonces are never evicted; loading never exceeds them", () => {
    const cache = openCache({ perKeyLimit: 2, globalLimit: 3 });
    expect(cache.checkAndInsert(KEY_A, nonce(1), T + SKEW, T)).toBe("accepted");
    expect(cache.checkAndInsert(KEY_A, nonce(2), T + SKEW, T)).toBe("accepted");
    expect(cache.checkAndInsert(KEY_A, nonce(3), T + SKEW, T)).toBe("key-quota");
    expect(cache.checkAndInsert(KEY_B, nonce(1), T + SKEW, T)).toBe("accepted");
    expect(cache.checkAndInsert(KEY_B, nonce(2), T + SKEW, T)).toBe("global-full");
    expect(lines()).toHaveLength(3); // refused nonces are not recorded
    // Restarted with lower limits: a live nonce that no longer fits is dropped, so the fallback fence applies.
    const lower = restart(cache, { perKeyLimit: 1, globalLimit: 3 });
    expect(lower.recovery).toMatchObject({ loaded: 2, dropped: 1 });
    expect(lower.recoveringUntil).toBe(T + SKEW);
  });

  it("compacts to live records when the journal grows, without losing a live nonce", () => {
    let cache = openCache({ compactAtBytes: 300 });
    for (let n = 1; n <= 5; n += 1) cache.checkAndInsert(KEY_A, nonce(n), T + 1_000, T); // short-lived
    clock = T + 2_000;
    for (let n = 6; n <= 12; n += 1) cache.checkAndInsert(KEY_A, nonce(n), T + 2_000 + SKEW, clock);
    expect(lines().length).toBeLessThan(12); // expired ones were compacted away
    cache = restart(cache);
    for (let n = 6; n <= 12; n += 1) expect(cache.checkAndInsert(KEY_A, nonce(n), T + 2_000 + SKEW, clock)).toBe("replay");
  });

  it("a full store refuses rather than dropping live records", () => {
    const cache = openCache({ maxBytes: 160, compactAtBytes: 10_000 });
    expect(cache.checkAndInsert(KEY_A, nonce(1), T + SKEW, T)).toBe("accepted");
    expect(cache.checkAndInsert(KEY_A, nonce(2), T + SKEW, T)).toBe("accepted");
    expect(cache.checkAndInsert(KEY_A, nonce(3), T + SKEW, T)).toBe("store-unavailable");
    expect(lines()).toHaveLength(2);
  });

  it("is safe on disk: absolute path, a single writer, and the default location under the profile", () => {
    expect(() => openDurableNonceCache({ path: "replay.journal", now: () => T, skewMs: SKEW })).toThrow("The replay store path must be absolute.");
    openCache();
    expect(() => openDurableNonceCache({ path, now: () => T, skewMs: SKEW })).toThrow(/in use by another AgentShield API process/);
    expect(existsSync(`${path}.lock`)).toBe(true);
    expect(replayStorePathFromEnv({ LOCALAPPDATA: "C:\\Users\\x\\AppData\\Local" })).toBe(join("C:\\Users\\x\\AppData\\Local", "AgentShield", "replay-nonces.journal"));
  });
});
