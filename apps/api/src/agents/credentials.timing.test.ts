import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * M3-D D1: every verification does exactly one constant-time comparison of two
 * 32-byte digests, whether the key id exists, the secret is wrong, or the input
 * is malformed. node:crypto is wrapped (not replaced) so the real function runs.
 */
vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>();
  return { ...actual, timingSafeEqual: vi.fn(actual.timingSafeEqual) };
});

const crypto = await import("node:crypto");
const { createCredentialStore, generateCredential, issueCredential, issueEd25519Credential } = await import("./credentials.js");
const spy = vi.mocked(crypto.timingSafeEqual);

describe("M3-D: constant-time verification", () => {
  const now = Date.parse("2026-11-01T09:00:00.000Z");
  const issued = issueCredential({ agentId: "writer", now, takenKeyIds: new Set() });
  const signing = issueEd25519Credential({ agentId: "reader", now, takenKeyIds: new Set([issued.record.keyId]) });
  const store = createCredentialStore([issued.record, signing.record], { now: () => now, bearerAllowed: true });
  const wrongSecret = `asag_${issued.record.keyId}.${"A".repeat(43)}`;

  beforeEach(() => {
    spy.mockClear();
  });

  it.each([
    ["a valid credential", issued.credential, true],
    ["a wrong secret", wrongSecret, false],
    ["an unknown key id", generateCredential(new Set()).credential, false],
    ["malformed input", "asag_short", false],
    ["an Ed25519 key id in bearer form (M3-E E2)", `asag_${signing.record.keyId}.${"A".repeat(43)}`, false],
  ])("%s: one timingSafeEqual call on two 32-byte digests", (_label, credential, ok) => {
    expect(store.verify(credential).ok).toBe(ok);
    expect(spy).toHaveBeenCalledTimes(1);
    const [a, b] = spy.mock.calls[0]!;
    expect([(a as Buffer).length, (b as Buffer).length]).toEqual([32, 32]);
  });
});
