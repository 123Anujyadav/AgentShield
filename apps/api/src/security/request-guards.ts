import type { RequestHandler } from "express";

/**
 * Host and Origin checks (M0). They run before CORS, authentication and every
 * route, so a request that fails them reaches no handler. Error messages are
 * fixed text and never echo the rejected value.
 */

/**
 * Returns the lower-cased host name of a Host header ("localhost", "127.0.0.1",
 * "[::1]"), or null when the header is missing or malformed. A port, when
 * present, must be 1 to 5 digits.
 */
export function hostnameOf(hostHeader: string | undefined): string | null {
  if (!hostHeader) return null;
  const host = hostHeader.trim().toLowerCase();
  const match = /^(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::(\d{1,5}))?$/.exec(host);
  return match ? (match[1] ?? null) : null;
}

/**
 * Rejects any Host header that is not one of the loopback names. Defends against
 * DNS rebinding: a hostile page whose domain resolves to 127.0.0.1 still sends its
 * own domain as the Host header, so its requests are refused here.
 */
export function hostCheck(allowedHostnames: readonly string[]): RequestHandler {
  const allowed = new Set(allowedHostnames);
  return (req, res, next) => {
    const hostname = hostnameOf(req.headers.host);
    if (hostname === null || !allowed.has(hostname)) {
      res.status(403).json({ error: "Host not allowed." });
      return;
    }
    next();
  };
}

/**
 * Rejects a request that carries an Origin header other than the web app's.
 * Requests without an Origin (curl, tests, same-origin GETs) pass; for
 * cookie-authenticated writes, the auth layer additionally requires one.
 */
export function originCheck(allowedOrigins: readonly string[]): RequestHandler {
  const allowed = new Set(allowedOrigins);
  return (req, res, next) => {
    const origin = req.headers.origin;
    if (origin !== undefined && !allowed.has(origin)) {
      res.status(403).json({ error: "Origin not allowed." });
      return;
    }
    next();
  };
}
