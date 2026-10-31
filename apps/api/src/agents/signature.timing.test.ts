import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * M3-E E3: exactly one Ed25519 verification per signed request that reaches the key
 * lookup, whether the key id is active, unknown, revoked, expired or a bearer key, so
 * response time does not reveal which key ids exist. node:crypto is wrapped, not replaced.
 */
vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>();
  return { ...actual, verify: vi.fn(actual.verify) };
});

const crypto = await import("node:crypto");
const { canonicalRequestBytes, formatAuthorization, sha256Hex } = await import("@agentshield/agent-protocol");
const { createCredentialStore, issueCredential } = await import("./credentials.js");
const { createNonceCache } = await import("./nonce-cache.js");
const { createSignatureVerifier } = await import("./signature.js");
const { testSigningKey } = await import("../test-support.js");
const spy = vi.mocked(crypto.verify);

const T = 1_793_523_600_000;
const active = testSigningKey("writer", "timing-active", { now: T });
const revoked = testSigningKey("writer", "timing-revoked", { now: T, revokedAt: new Date(T).toISOString() });
const unknown = testSigningKey("writer", "timing-unknown", { now: T });
const bearer = issueCredential({ agentId: "reader", now: T, takenKeyIds: new Set() });
const verifier = createSignatureVerifier({
  credentials: createCredentialStore([active.record, revoked.record, bearer.record], { now: () => T }),
  nonces: createNonceCache({ now: () => T }),
  now: () => T,
  skewMs: 30_000,
  startedAt: T,
});

let counter = 0;
function request(key: typeof active, keyId = key.keyId) {
  counter += 1;
  const nonce = Buffer.alloc(16, counter).toString("base64url");
  const timestamp = String(T);
  const message = canonicalRequestBytes({ method: "POST", host: "127.0.0.1:4000", target: "/api/evaluate", timestamp, nonce, keyId, bodySha256: sha256Hex() });
  const authorization = formatAuthorization({ keyId, timestamp, nonce, signature: crypto.sign(null, message, key.privateKey).toString("base64url") });
  return { headers: { authorization, host: "127.0.0.1:4000" }, method: "POST", originalUrl: "/api/evaluate" } as never;
}

describe("M3-E E3: constant work per signed request", () => {
  beforeEach(() => {
    spy.mockClear();
  });

  it.each([
    ["an active key", () => request(active), true],
    ["an unknown key id", () => request(unknown), false],
    ["a revoked key", () => request(revoked), false],
    ["a bearer key id (wrong scheme)", () => request(active, bearer.record.keyId), false],
  ])("%s: exactly one Ed25519 verification", (_label, build, ok) => {
    expect(verifier(build()).ok).toBe(ok);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("a malformed header is refused before any verification", () => {
    expect(verifier({ headers: { authorization: "AGENTSHIELD-SIG-V1 x", host: "127.0.0.1:4000" }, method: "POST", originalUrl: "/api/evaluate" } as never)).toMatchObject({ ok: false, reason: "bad-header" });
    expect(spy).not.toHaveBeenCalled();
  });
});
