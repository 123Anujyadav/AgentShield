/**
 * Replay protection for signed agent requests (M3-E E3).
 *
 * Each accepted signed request records its credential key id and nonce until
 * the request's timestamp can no longer be accepted (`expiresAt` = ts + the
 * allowed clock skew). A second request with the same key id and nonce inside
 * that time is a replay. Only requests with a valid signature are recorded, so
 * unsigned junk cannot fill the cache.
 *
 * Bounds (fail closed, never evicting a live nonce, since that would let its
 * request be replayed):
 * - at most `perKeyLimit` live nonces per key id: further requests from that key
 *   get "key-quota" (HTTP 429) until some expire;
 * - at most `globalLimit` live nonces in total: further requests get
 *   "global-full" (HTTP 503) until some expire.
 *
 * checkAndInsert is synchronous, so a check and its insert can never interleave
 * with another request in the Node process: of two identical requests, exactly
 * one is accepted. The cache is in memory: it is per process and empty after a
 * restart. The server's start-up timestamp fence (signature.ts) stops requests
 * signed before the restart from being accepted again.
 */

export const DEFAULT_NONCE_PER_KEY_LIMIT = 600;
export const DEFAULT_NONCE_GLOBAL_LIMIT = 100_000;

export type NonceCheck = "accepted" | "replay" | "key-quota" | "global-full";

export interface NonceCache {
  /** Records keyId+nonce, live until (and including) `expiresAt` in ms, unless it is already live or a limit is reached. */
  checkAndInsert(keyId: string, nonce: string, expiresAt: number): NonceCheck;
  /** Live and not-yet-pruned entries in total (for tests and diagnostics; never sent to clients). */
  readonly size: number;
  sizeFor(keyId: string): number;
}

export interface NonceCacheOptions {
  now: () => number;
  perKeyLimit?: number;
  globalLimit?: number;
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${name} must be a positive integer.`);
  return value;
}

export function createNonceCache(options: NonceCacheOptions): NonceCache {
  const perKeyLimit = positiveInteger(options.perKeyLimit ?? DEFAULT_NONCE_PER_KEY_LIMIT, "perKeyLimit");
  const globalLimit = positiveInteger(options.globalLimit ?? DEFAULT_NONCE_GLOBAL_LIMIT, "globalLimit");
  const byKey = new Map<string, Map<string, number>>();
  // No entry expires before these times, so pruning earlier would free nothing. They keep a
  // full cache from being re-scanned on every request.
  const earliestForKey = new Map<string, number>();
  let earliestOverall = Number.POSITIVE_INFINITY;
  let total = 0;

  function pruneKey(keyId: string, entries: Map<string, number>, now: number): void {
    let earliest = Number.POSITIVE_INFINITY;
    for (const [nonce, expiresAt] of entries) {
      if (expiresAt < now) {
        entries.delete(nonce);
        total -= 1;
      } else if (expiresAt < earliest) {
        earliest = expiresAt;
      }
    }
    if (entries.size === 0) {
      byKey.delete(keyId);
      earliestForKey.delete(keyId);
    } else {
      earliestForKey.set(keyId, earliest);
    }
  }

  function pruneAll(now: number): void {
    let earliest = Number.POSITIVE_INFINITY;
    for (const [keyId, entries] of byKey) {
      pruneKey(keyId, entries, now);
      const forKey = earliestForKey.get(keyId);
      if (forKey !== undefined && forKey < earliest) earliest = forKey;
    }
    earliestOverall = earliest;
  }

  return {
    checkAndInsert(keyId, nonce, expiresAt) {
      const now = options.now();
      let entries = byKey.get(keyId);
      const existing = entries?.get(nonce);
      if (existing !== undefined && existing >= now) return "replay";
      if (existing !== undefined) {
        entries!.delete(nonce);
        total -= 1;
      }
      if (entries && entries.size >= perKeyLimit && (earliestForKey.get(keyId) ?? 0) < now) {
        pruneKey(keyId, entries, now);
        entries = byKey.get(keyId);
      }
      if (entries && entries.size >= perKeyLimit) return "key-quota";
      if (total >= globalLimit && earliestOverall < now) {
        pruneAll(now);
        entries = byKey.get(keyId);
      }
      if (total >= globalLimit) return "global-full";
      if (!entries) {
        entries = new Map();
        byKey.set(keyId, entries);
      }
      entries.set(nonce, expiresAt);
      total += 1;
      if (expiresAt < (earliestForKey.get(keyId) ?? Number.POSITIVE_INFINITY)) earliestForKey.set(keyId, expiresAt);
      if (expiresAt < earliestOverall) earliestOverall = expiresAt;
      return "accepted";
    },
    get size() {
      return total;
    },
    sizeFor(keyId) {
      return byKey.get(keyId)?.size ?? 0;
    },
  };
}
