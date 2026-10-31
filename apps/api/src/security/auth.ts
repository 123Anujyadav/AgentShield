import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { Express, Request, RequestHandler, Response } from "express";
import { AUTH_SCHEME } from "@agentshield/agent-protocol";
import { CREDENTIAL_PREFIX, parseCredential, SIGNING_CREDENTIAL_PREFIX, type CredentialStore } from "../agents/credentials.js";
import type { SignedVerification } from "../agents/signature.js";
import type { FailureLimiter, RateLimitFactory } from "./rate-limit.js";
import type { SecurityConfig } from "./config.js";

/**
 * API authentication (M0).
 *
 * - Non-browser clients send `Authorization: Bearer <token>`.
 * - The web app logs in once (POST /api/session with the token) and then uses a
 *   random session id in an HttpOnly, SameSite=Strict cookie scoped to /api. The
 *   token itself is never stored in the browser.
 * - Cookie-authenticated writes must carry the web app's Origin (CSRF defence).
 * - M3-D: agents send `Authorization: Bearer asag_<keyId>.<secret>`. A bearer value
 *   with the agent prefix is only ever checked as an agent credential, never
 *   against the operator token, and an agent is never an operator. Every failed
 *   agent credential gets the same 401 as any other failed authentication; the
 *   reason is logged on the server only, with the public key id at most.
 * - M3-E E3: agents sign requests (`Authorization: AGENTSHIELD-SIG-V1 ...`, see
 *   agents/signature.ts). A header with that scheme is only ever checked as a
 *   signature: never as a bearer token, the operator token or a cookie fallback.
 *
 * The token, credentials and session ids are never logged, echoed, or put in a URL.
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

export type Authentication =
  | { kind: "bearer" }
  | { kind: "session"; id: string; session: Session }
  /** M3-D: an agent, identified by its verified credential. */
  | { kind: "agent"; agentId: string; keyId: string };

/** True for the operator (the API token, directly or through a dashboard session). */
export function isOperator(auth: Authentication | null | undefined): auth is Exclude<Authentication, { kind: "agent" }> {
  return auth?.kind === "bearer" || auth?.kind === "session";
}

export interface ApiAuth {
  /** Resolves the request's credentials without side effects beyond session activity. */
  authenticate(req: Request): Authentication | null;
  /**
   * The operator only (API token or session). An agent credential is never verified here:
   * it is simply not an operator, so this reveals nothing about it (M3-D audit L2).
   */
  authenticateOperator(req: Request): Exclude<Authentication, { kind: "agent" }> | null;
  /** Middleware for every /api route except /api/session. Stores the result in res.locals.auth. */
  requireAuth: RequestHandler;
}

export function createApiAuth(
  apiToken: string,
  sessions: SessionStore,
  config: SecurityConfig,
  agents: {
    credentials: CredentialStore;
    failures: FailureLimiter;
    /** M3-E E3: verifies a signed agent request (signature, timestamp, nonce). */
    verifySigned: (req: Request) => SignedVerification;
    /** Retry-After for the nonce-cache limits (429/503), in seconds. */
    signedRetryAfterSeconds: number;
    log?: (line: string) => void;
  },
): ApiAuth {
  const allowedOrigins = new Set(config.allowedOrigins);
  const log = agents.log ?? ((line: string) => console.warn(line));

  /** `reject`: a validly signed request refused by the nonce-cache limits (429 or 503), not an authentication failure. */
  type Resolution = { auth: Authentication | null; agentFailure?: string; reject?: 429 | 503 };

  /** Resolves the request's credentials. `agentFailure` is the server-log line for a failed agent credential. */
  function resolve(req: Request, options: { verifyAgents: boolean }): Resolution {
    const header = req.headers.authorization;
    if (header !== undefined) {
      // M3-E E3: a signed agent request. Outside agent routes it is not verified at all (no nonce is used).
      if (header.startsWith(AUTH_SCHEME)) {
        if (!options.verifyAgents) return { auth: null };
        const result = agents.verifySigned(req);
        if (result.ok) return { auth: { kind: "agent", agentId: result.agentId, keyId: result.keyId } };
        const agentFailure = `agent-auth status=failed scheme=signature reason=${result.reason} keyId=${result.keyId ?? "none"}`;
        return { auth: null, agentFailure, ...(result.status !== 401 ? { reject: result.status } : {}) };
      }
      const match = /^Bearer ([^\s]+)$/.exec(header);
      const presented = match?.[1];
      // A malformed or wrong Authorization header never falls back to the cookie.
      if (!presented) return { auth: null };
      // M3-E E2: an Ed25519 private key must never be sent; it is never a bearer token, is never
      // compared with the operator token, and its key id is logged so the operator can rotate it.
      if (presented.startsWith(SIGNING_CREDENTIAL_PREFIX)) {
        if (!options.verifyAgents) return { auth: null };
        const keyId = /^asag2_([0-9a-f]{16})\./.exec(presented)?.[1] ?? "none";
        return { auth: null, agentFailure: `agent-auth status=failed reason=private-key-sent-as-bearer keyId=${keyId} action=rotate-this-credential` };
      }
      if (presented.startsWith(CREDENTIAL_PREFIX)) {
        // Never compared with the operator token; outside agent routes, not verified at all.
        if (!options.verifyAgents) return { auth: null };
        const result = agents.credentials.verify(presented);
        if (result.ok) return { auth: { kind: "agent", agentId: result.agentId, keyId: result.keyId } };
        return { auth: null, agentFailure: `agent-auth status=failed reason=${result.reason} keyId=${parseCredential(presented)?.keyId ?? "none"}` };
      }
      return { auth: tokensMatch(presented, apiToken) ? { kind: "bearer" } : null };
    }
    const id = readCookie(req.headers.cookie, SESSION_COOKIE);
    if (!id) return { auth: null };
    const session = sessions.touch(id);
    return { auth: session ? { kind: "session", id, session } : null };
  }

  function authenticate(req: Request): Authentication | null {
    return resolve(req, { verifyAgents: true }).auth;
  }

  function authenticateOperator(req: Request): Exclude<Authentication, { kind: "agent" }> | null {
    const { auth } = resolve(req, { verifyAgents: false });
    return isOperator(auth) ? auth : null;
  }

  const requireAuth: RequestHandler = (req, res, next) => {
    if (req.path === "/session") {
      next();
      return;
    }
    // M3-D audit L3: credentials are always verified first, so a valid credential is never
    // refused because of other callers' failures. Only failed Authorization-header attempts
    // count; past the limit they get 429 (and are no longer logged) until the window ends.
    const { auth, agentFailure, reject } = resolve(req, { verifyAgents: true });
    if (!auth && reject !== undefined) {
      // An authentic agent over the nonce-cache limits: refused, but not counted as a failed authentication.
      if (agentFailure) log(agentFailure);
      res.setHeader("Retry-After", String(agents.signedRetryAfterSeconds));
      res.status(reject).json({
        error: reject === 429 ? "Too many signed requests for this credential. Try again later." : "Signed requests are temporarily unavailable. Try again later.",
      });
      return;
    }
    if (!auth) {
      if (req.headers.authorization !== undefined) {
        const client = req.socket.remoteAddress ?? "unknown";
        const retryAfter = agents.failures.blockedFor(client);
        agents.failures.recordFailure(client);
        if (retryAfter !== null) {
          res.setHeader("Retry-After", String(retryAfter));
          res.status(429).json({ error: "Too many failed authentication attempts. Try again later." });
          return;
        }
        if (agentFailure) log(agentFailure);
      }
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
    res.locals.auth = auth;
    next();
  };

  return { authenticate, authenticateOperator, requireAuth };
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

  // The dashboard's sign-in status: operator authentication only. An agent credential is not a
  // sign-in and is never verified here (M3-D audit L2).
  function sessionBody(authentication: ReturnType<ApiAuth["authenticateOperator"]>) {
    return {
      authenticated: authentication !== null,
      method: authentication?.kind ?? null,
      expiresAt: authentication?.kind === "session" ? new Date(authentication.session.expiresAt).toISOString() : null,
    };
  }

  app.get("/api/session", (req, res) => {
    res.json(sessionBody(auth.authenticateOperator(req)));
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
