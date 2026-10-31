import { randomBytes } from "node:crypto";
import { canonicalHost, canonicalRequestBytes, formatAuthorization, isTimestamp, sha256Hex } from "@agentshield/agent-protocol";
import type { AgentCredential } from "./credential.js";
import { InvalidArgumentError } from "./errors.js";

/**
 * Signs one request with the E1 protocol (M3-E E5). Everything signed comes from the
 * same values the client sends: the method, the URL's host and its exact request target
 * (pathname plus search, as `fetch` sends them), and the exact body bytes. Each call
 * draws a fresh 128-bit nonce and reads the clock, so a retry is always a new request.
 * Internal to the SDK: the client signs only its own fixed routes.
 */
export interface SignedRequest {
  authorization: string;
  timestamp: string;
  nonce: string;
}

export function signRequest(input: { credential: AgentCredential; method: "GET" | "POST"; url: URL; body?: Uint8Array; now?: () => number }): SignedRequest {
  const host = canonicalHost(input.url.host);
  if (host === null) throw new InvalidArgumentError("The AgentShield URL does not have a valid host.");
  const timestamp = String(Math.trunc((input.now ?? Date.now)()));
  if (!isTimestamp(timestamp)) throw new InvalidArgumentError("The clock does not give a valid millisecond timestamp.");
  const nonce = randomBytes(16).toString("base64url");
  let message: Uint8Array;
  try {
    message = canonicalRequestBytes({
      method: input.method,
      host,
      target: `${input.url.pathname}${input.url.search}`,
      timestamp,
      nonce,
      keyId: input.credential.keyId,
      bodySha256: sha256Hex(input.body),
    });
  } catch {
    throw new InvalidArgumentError("The request cannot be signed: its target is not a valid request target.");
  }
  const signature = input.credential.sign(message).toString("base64url");
  return { authorization: formatAuthorization({ keyId: input.credential.keyId, timestamp, nonce, signature }), timestamp, nonce };
}
