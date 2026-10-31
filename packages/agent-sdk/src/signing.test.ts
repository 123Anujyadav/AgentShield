import { describe, expect, it } from "vitest";
import { AUTH_SCHEME, parseAuthorization } from "@agentshield/agent-protocol";
import { AgentCredential } from "./credential.js";
import { InvalidArgumentError } from "./errors.js";
import { signRequest } from "./signing.js";
import { testKey, verifySignedRequest } from "./test-fixtures.js";

/** M3-E E5: request signing with the shared protocol package. */

const key = testKey("signing-tests");
const credential = AgentCredential.fromString(key.credential);
const T = 1_793_523_600_123;
const body = Buffer.from(JSON.stringify({ intent: { task: "Summarize" }, action: { type: "create_summary" } }), "utf8");
const evaluateUrl = new URL("http://127.0.0.1:4000/api/evaluate");

describe("M3-E E5: signing", () => {
  it("produces a strict AGENTSHIELD-SIG-V1 header that verifies over the exact method, host, target and body", () => {
    const signed = signRequest({ credential, method: "POST", url: evaluateUrl, body, now: () => T });
    const parsed = parseAuthorization(signed.authorization);
    expect(parsed.ok && parsed.value).toMatchObject({ keyId: key.keyId, timestamp: String(T), nonce: signed.nonce });
    expect(signed.authorization.startsWith(`${AUTH_SCHEME} `)).toBe(true);
    expect(verifySignedRequest({ method: "POST", url: evaluateUrl.href, authorization: signed.authorization, body }, key.publicKey)).toBe(true);
  });

  it("binds the body bytes: any other body (even equivalent JSON) fails verification", () => {
    const { authorization } = signRequest({ credential, method: "POST", url: evaluateUrl, body, now: () => T });
    const respaced = Buffer.from(JSON.stringify(JSON.parse(body.toString()), null, 1));
    for (const other of [respaced, Buffer.from(body.toString().replace("Summarize", "Summarise")), Buffer.alloc(0), undefined]) {
      expect(verifySignedRequest({ method: "POST", url: evaluateUrl.href, authorization, body: other }, key.publicKey)).toBe(false);
    }
  });

  it("binds the method, path, query and host", () => {
    const url = new URL("http://127.0.0.1:4000/api/agent/approvals?limit=5");
    const { authorization } = signRequest({ credential, method: "GET", url, now: () => T });
    expect(verifySignedRequest({ method: "GET", url: url.href, authorization }, key.publicKey)).toBe(true);
    for (const [method, other] of [
      ["POST", url.href],
      ["GET", "http://127.0.0.1:4000/api/agent/approvals?limit=6"],
      ["GET", "http://127.0.0.1:4000/api/agent/approvals"],
      ["GET", "http://127.0.0.1:4000/api/agent/approvals/apr-1?limit=5"],
      ["GET", "http://localhost:4000/api/agent/approvals?limit=5"],
      ["GET", "http://127.0.0.1:4001/api/agent/approvals?limit=5"],
    ] as const) {
      expect(verifySignedRequest({ method, url: other, authorization }, key.publicKey), `${method} ${other}`).toBe(false);
    }
  });

  it("uses a fresh 128-bit nonce for every request, even at the same instant", () => {
    const nonces = new Set<string>();
    for (let i = 0; i < 1000; i += 1) nonces.add(signRequest({ credential, method: "GET", url: evaluateUrl, now: () => T }).nonce);
    expect(nonces.size).toBe(1000);
    for (const nonce of [...nonces].slice(0, 5)) expect(Buffer.from(nonce, "base64url")).toHaveLength(16);
  });

  it("signs IPv6 loopback hosts and refuses a clock that does not give 13-digit milliseconds", () => {
    const v6 = new URL("http://[::1]:4000/api/agent/approvals");
    const { authorization } = signRequest({ credential, method: "GET", url: v6, now: () => T });
    expect(verifySignedRequest({ method: "GET", url: v6.href, authorization }, key.publicKey)).toBe(true);
    expect(() => signRequest({ credential, method: "GET", url: v6, now: () => 1_793_523_600 })).toThrowError(InvalidArgumentError);
  });
});
