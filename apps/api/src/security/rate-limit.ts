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
