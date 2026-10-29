import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { Express, Request, RequestHandler, Response } from "express";
import type { RateLimitFactory } from "./rate-limit.js";
import type { SecurityConfig } from "./config.js";

/**
 * API authentication (M0).
 *
 * - Non-browser clients send `Authorization: Bearer <token>`.
 * - The web app logs in once (POST /api/session with the token) and then uses a
 *   random session id in an HttpOnly, SameSite=Strict cookie scoped to /api. The
 *   token itself is never stored in the browser.
 * - Cookie-authenticated writes must carry the web app's Origin (CSRF defence).
 *
 * The token and session ids are never logged, echoed, or put in a URL.
 */

export const SESSION_COOKIE = "agentshield_session";
/** Shorter tokens are refused when the app is created; a generated token is 43 characters. */
export const MIN_TOKEN_LENGTH = 32;
const MAX_LOGIN_TOKEN_LENGTH = 512;
const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function digest(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

/** Constant-time comparison of fixed-length digests, so length and content leak nothing. */
export function tokensMatch(candidate: string, expected: string): boolean {
  return timingSafeEqual(digest(candidate), digest(expected));
}

export interface Session {
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number;
}

export interface SessionStore {
  /** Creates a session and returns its id; the id is stored only as a hash. */
  create(): { id: string; session: Session };
  /** Returns the live session for an id and records the activity, or null. */
  touch(id: string): Session | null;
  delete(id: string): void;
  readonly size: number;
}

export function createSessionStore(options: {
  absoluteMs: number;
  idleMs: number;
  maxSessions: number;
  now: () => number;
}): SessionStore {
  const sessions = new Map<string, Session>();
  const key = (id: string) => digest(id).toString("hex");
  return {
    create() {
      const now = options.now();
      while (sessions.size >= options.maxSessions) {
        const oldest = sessions.keys().next().value;
        if (oldest === undefined) break;
        sessions.delete(oldest);
      }
      const id = randomBytes(32).toString("base64url");
      const session = { createdAt: now, lastSeenAt: now, expiresAt: now + options.absoluteMs };
      sessions.set(key(id), session);
      return { id, session };
    },
    touch(id) {
      const k = key(id);
      const session = sessions.get(k);
      if (!session) return null;
      const now = options.now();
      if (now >= session.expiresAt || now - session.lastSeenAt >= options.idleMs) {
        sessions.delete(k);
        return null;
      }
      session.lastSeenAt = now;
      return session;
    },
    delete(id) {
      sessions.delete(key(id));
    },
    get size() {
      return sessions.size;
    },
  };
}

/** Reads one cookie value from a Cookie header without any dependency. */
export function readCookie(header: string | undefined, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index === -1) continue;
    if (part.slice(0, index).trim() === name) return part.slice(index + 1).trim() || null;
  }
  return null;
}

function sessionCookie(value: string, maxAgeSeconds: number): string {
  return `${SESSION_COOKIE}=${value}; Path=/api; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSeconds}`;
}

type Authentication = { kind: "bearer" } | { kind: "session"; id: string; session: Session };

export interface ApiAuth {
  /** Resolves the request's credentials without side effects beyond session activity. */
  authenticate(req: Request): Authentication | null;
  /** Middleware for every /api route except /api/session. */
  requireAuth: RequestHandler;
}

export function createApiAuth(apiToken: string, sessions: SessionStore, config: SecurityConfig): ApiAuth {
  const allowedOrigins = new Set(config.allowedOrigins);

  function authenticate(req: Request): Authentication | null {
    const header = req.headers.authorization;
    if (header !== undefined) {
      const match = /^Bearer ([^\s]+)$/.exec(header);
      // A malformed or wrong Authorization header never falls back to the cookie.
      return match?.[1] && tokensMatch(match[1], apiToken) ? { kind: "bearer" } : null;
    }
    const id = readCookie(req.headers.cookie, SESSION_COOKIE);
    if (!id) return null;
    const session = sessions.touch(id);
    return session ? { kind: "session", id, session } : null;
  }

  const requireAuth: RequestHandler = (req, res, next) => {
    if (req.path === "/session") {
      next();
      return;
    }
    const auth = authenticate(req);
    if (!auth) {
      res.setHeader("WWW-Authenticate", 'Bearer realm="agentshield"');
      res.status(401).json({ error: "Authentication required." });
      return;
    }
    if (auth.kind === "session" && UNSAFE_METHODS.has(req.method)) {
      const origin = req.headers.origin;
      if (origin === undefined || !allowedOrigins.has(origin)) {
        res.status(403).json({ error: "Origin not allowed." });
        return;
      }
    }
    next();
  };

  return { authenticate, requireAuth };
}

/**
 * GET    /api/session  reports whether the caller is signed in (never the token).
 * POST   /api/session  { token } signs in and sets the session cookie.
 * DELETE /api/session  signs out and clears the cookie.
 */
export function registerSessionRoutes(
  app: Express,
  deps: { apiToken: string; auth: ApiAuth; sessions: SessionStore; limit: RateLimitFactory; config: SecurityConfig },
): void {
  const { apiToken, auth, sessions, limit, config } = deps;

  function sessionBody(authentication: ReturnType<ApiAuth["authenticate"]>) {
    return {
      authenticated: authentication !== null,
      method: authentication?.kind ?? null,
      expiresAt: authentication?.kind === "session" ? new Date(authentication.session.expiresAt).toISOString() : null,
    };
  }

  app.get("/api/session", (req, res) => {
    res.json(sessionBody(auth.authenticate(req)));
  });

  app.post("/api/session", limit("session", config.rateLimits.session), (req, res) => {
    const token: unknown = (req.body as { token?: unknown } | undefined)?.token;
    if (typeof token !== "string" || token.length === 0 || token.length > MAX_LOGIN_TOKEN_LENGTH) {
      res.status(400).json({ error: "A token string is required." });
      return;
    }
    if (!tokensMatch(token, apiToken)) {
      console.warn("api-auth status=login-failed");
      res.status(401).json({ error: "Invalid token." });
      return;
    }
    // Rotate: a login always ends the session the browser already had.
    const previous = readCookie(req.headers.cookie, SESSION_COOKIE);
    if (previous) sessions.delete(previous);
    const { id, session } = sessions.create();
    res.setHeader("Set-Cookie", sessionCookie(id, Math.floor(config.sessionAbsoluteMs / 1000)));
    res.json({ authenticated: true, method: "session", expiresAt: new Date(session.expiresAt).toISOString() });
  });

  app.delete("/api/session", (req: Request, res: Response) => {
    const id = readCookie(req.headers.cookie, SESSION_COOKIE);
    if (id) sessions.delete(id);
    res.setHeader("Set-Cookie", sessionCookie("", 0));
    res.json({ authenticated: false, method: null, expiresAt: null });
  });
}
