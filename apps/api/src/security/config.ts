/**
 * API safety settings (M0). Every value has a conservative default and a
 * bounded range; a missing, empty or non-numeric setting falls back to the
 * default and an out-of-range one is clamped. None of these settings is a
 * secret: the API token lives in its own file (see token.ts).
 */

/** Host names the API answers to. Anything else (e.g. a DNS-rebinding domain) is refused. */
export const ALLOWED_HOSTNAMES = ["localhost", "127.0.0.1", "[::1]"] as const;

/** Browser origins of the AgentShield web app. Unchanged from the former CORS allowlist. */
export const WEB_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"] as const;

export interface RateLimits {
  /** Every /api request, authenticated or not. */
  api: number;
  /** Login attempts (POST /api/session). */
  session: number;
  /** POST /api/evaluate. */
  evaluate: number;
  /** POST /api/approvals/:id/approve and /reject. */
  approvalAction: number;
  /** M3-D: failed Authorization-header attempts (operator token or agent credential). */
  authFailure: number;
  /** M3-E E4: an agent's reads of its own approval status, counted per agent. */
  agentApprovalStatus: number;
}

export interface SecurityConfig {
  allowedHostnames: readonly string[];
  allowedOrigins: readonly string[];
  /** Newest events kept in memory; older ones are dropped. */
  maxEvents: number;
  rateLimitWindowMs: number;
  /** Requests per window, per client address. */
  rateLimits: RateLimits;
  /** A session ends this long after login, however active it is. */
  sessionAbsoluteMs: number;
  /** A session ends after this long without a request. */
  sessionIdleMs: number;
  /** Concurrent sessions; the oldest is ended when a new login exceeds this. */
  maxSessions: number;
}

function boundedInt(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(value ?? "", 10);
  if (Number.isNaN(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

const MINUTE_MS = 60_000;

export function loadSecurityConfig(env: NodeJS.ProcessEnv = process.env): SecurityConfig {
  return {
    allowedHostnames: ALLOWED_HOSTNAMES,
    allowedOrigins: WEB_ORIGINS,
    maxEvents: boundedInt(env.API_MAX_EVENTS, 1000, 100, 100_000),
    rateLimitWindowMs: MINUTE_MS,
    rateLimits: {
      api: boundedInt(env.API_RATE_LIMIT_PER_MINUTE, 600, 10, 10_000),
      session: boundedInt(env.API_LOGIN_RATE_LIMIT_PER_MINUTE, 10, 1, 100),
      evaluate: boundedInt(env.API_EVALUATE_RATE_LIMIT_PER_MINUTE, 60, 1, 1000),
      approvalAction: boundedInt(env.API_APPROVAL_RATE_LIMIT_PER_MINUTE, 60, 1, 1000),
      authFailure: boundedInt(env.API_AUTH_FAILURE_RATE_LIMIT_PER_MINUTE, 20, 1, 1000),
      agentApprovalStatus: boundedInt(env.API_AGENT_APPROVAL_STATUS_RATE_LIMIT_PER_MINUTE, 120, 1, 1000),
    },
    sessionAbsoluteMs: boundedInt(env.API_SESSION_MAX_MINUTES, 480, 5, 1440) * MINUTE_MS,
    sessionIdleMs: boundedInt(env.API_SESSION_IDLE_MINUTES, 30, 1, 480) * MINUTE_MS,
    maxSessions: 10,
  };
}
