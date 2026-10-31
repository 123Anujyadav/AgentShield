import type { RequestHandler } from "express";

/**
 * In-memory fixed-window rate limiter (M0). Counts requests per bucket and
 * client address. The API listens on loopback only, so in practice every
 * client shares one address and each limit applies to the whole machine.
 * State is in memory and resets when the API restarts.
 */
export interface RateLimiterOptions {
  windowMs: number;
  now: () => number;
  /** Tracked bucket/client pairs before expired windows are pruned. */
  maxKeys?: number;
}

export type RateLimitFactory = (bucket: string, limit: number) => RequestHandler;

export function createRateLimiter(options: RateLimiterOptions): RateLimitFactory {
  const { windowMs, now } = options;
  const maxKeys = options.maxKeys ?? 10_000;
  const windows = new Map<string, { start: number; count: number }>();

  function prune(current: number): void {
    for (const [key, window] of windows) {
      if (current - window.start >= windowMs) windows.delete(key);
    }
    // Still full (many distinct clients in one window): drop the oldest entries.
    for (const key of windows.keys()) {
      if (windows.size < maxKeys) break;
      windows.delete(key);
    }
  }

  return (bucket, limit) => (req, res, next) => {
    const current = now();
    const key = `${bucket}|${req.socket.remoteAddress ?? "unknown"}`;
    let window = windows.get(key);
    if (!window || current - window.start >= windowMs) {
      if (!window && windows.size >= maxKeys) prune(current);
      window = { start: current, count: 0 };
      windows.set(key, window);
    }
    window.count += 1;
    if (window.count > limit) {
      const retryAfterSeconds = Math.max(1, Math.ceil((window.start + windowMs - current) / 1000));
      res.setHeader("Retry-After", String(retryAfterSeconds));
      res.status(429).json({ error: "Too many requests. Try again later." });
      return;
    }
    next();
  };
}

/**
 * Failed-authentication limiter (M3-D). Counts only failed attempts that carried
 * an Authorization header, per client address, in a fixed window. Once the limit
 * is reached, further header-authenticated requests get 429 without being
 * checked until the window ends. Cookie sessions (the dashboard) are not counted
 * or blocked, so failed bearer attempts cannot lock the operator out of the UI.
 */
export interface FailureLimiter {
  /** Seconds until the window ends when the client is blocked, otherwise null. */
  blockedFor(key: string): number | null;
  recordFailure(key: string): void;
}

export function createFailureLimiter(options: RateLimiterOptions & { limit: number }): FailureLimiter {
  const { windowMs, now, limit } = options;
  const maxKeys = options.maxKeys ?? 10_000;
  const windows = new Map<string, { start: number; count: number }>();
  const live = (key: string, current: number) => {
    const window = windows.get(key);
    return window && current - window.start < windowMs ? window : null;
  };
  return {
    blockedFor(key) {
      const current = now();
      const window = live(key, current);
      return window && window.count >= limit ? Math.max(1, Math.ceil((window.start + windowMs - current) / 1000)) : null;
    },
    recordFailure(key) {
      const current = now();
      const window = live(key, current);
      if (window) {
        window.count += 1;
        return;
      }
      if (windows.size >= maxKeys) {
        for (const [k, w] of windows) if (current - w.start >= windowMs) windows.delete(k);
        for (const k of windows.keys()) {
          if (windows.size < maxKeys) break;
          windows.delete(k);
        }
      }
      windows.set(key, { start: current, count: 1 });
    },
  };
}
