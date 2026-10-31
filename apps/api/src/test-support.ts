import { createHash, createPrivateKey, sign, type KeyObject } from "node:crypto";
import supertest, { type Test } from "supertest";
import { canonicalRequestBytes, formatAuthorization, sha256Hex } from "@agentshield/agent-protocol";
import { DEMO_AGENT_POLICY, type AgentPolicy } from "@agentshield/engine";
import { createApp, type AppDeps } from "./app.js";
import { createCredentialStore, issueCredential, issueEd25519Credential, validateCredentialRecord, type BearerCredentialRecord, type CredentialStore, type Ed25519CredentialRecord } from "./agents/credentials.js";
import { createPolicyStore, type PolicyStore } from "./policies/store.js";

/**
 * Test helpers (M0). Existing route tests run against the protected API with a
 * fixed, invented token, so they exercise the same middleware as real clients.
 */

/** Invented for tests only; not a credential. */
export const TEST_API_TOKEN = "agentshield-test-token-not-real-0123456789abcdef";

/**
 * M3-C: the agent that route tests evaluate custom intents for. Its server-side
 * policy holds the actions and destinations those tests use; each request still
 * sends its own intent, which can only narrow this policy.
 */
export const TEST_AGENT_ID = "test-agent";
export const TEST_AGENT_POLICY: AgentPolicy = {
  agentId: TEST_AGENT_ID,
  version: 1,
  description: "Route-test agent (tests only).",
  allowedActions: ["create_summary", "read_document", "create_report", "teleport_data", "translate_text"],
  deniedActions: [],
  allowedDestinations: ["simulated-workspace", "external"],
};

/** The demo agent (seeded scenarios), the test agent, and any extra policies a test needs. */
export function testPolicyStore(extra: AgentPolicy[] = []): PolicyStore {
  return createPolicyStore([DEMO_AGENT_POLICY, TEST_AGENT_POLICY, ...extra], "built-in");
}

/**
 * M3-D: an agent credential for tests. Issued in memory for this test run only:
 * never written to disk, never a real credential store.
 */
export interface TestCredential {
  agentId: string;
  credential: string;
  record: BearerCredentialRecord;
}

const issuedKeyIds = new Set<string>();

export function issueTestCredential(agentId: string, options: { now?: number; days?: number } = {}): TestCredential {
  const { credential, record } = issueCredential({ agentId, now: options.now ?? Date.now(), days: options.days, takenKeyIds: issuedKeyIds });
  issuedKeyIds.add(record.keyId);
  return { agentId, credential, record };
}

/** M3-E E2: an Ed25519 credential for tests (in memory only): the private key and the public-key record. */
export function issueTestEd25519Credential(agentId: string, options: { now?: number; days?: number } = {}): { agentId: string; credential: string; record: Ed25519CredentialRecord } {
  const { credential, record } = issueEd25519Credential({ agentId, now: options.now ?? Date.now(), days: options.days, takenKeyIds: issuedKeyIds });
  issuedKeyIds.add(record.keyId);
  return { agentId, credential, record };
}

/** The route-test agent's credential. */
export const TEST_AGENT_CREDENTIAL = issueTestCredential(TEST_AGENT_ID);

/**
 * An in-memory credential store: the test agent's credential and any extra ones a test needs.
 * Route tests still authenticate agents with legacy bearer credentials (signed requests arrive
 * in E3), so this store opts in to bearer explicitly, as AGENT_BEARER_ALLOWED=true would.
 */
export function testCredentialStore(extra: TestCredential[] = []): CredentialStore {
  return createCredentialStore([TEST_AGENT_CREDENTIAL.record, ...extra.map((c) => c.record)], { bearerAllowed: true });
}

/** createApp with the test token, policies and credentials, so `request(app)` below is the operator. */
export function createTestApp(deps: AppDeps = {}) {
  return createApp({ apiToken: TEST_API_TOKEN, policyStore: testPolicyStore(), credentialStore: testCredentialStore(), ...deps });
}

type TestableApp = Parameters<typeof supertest>[0];

/** supertest with `Authorization: Bearer <test token>` (the operator) on every request. */
export function request(app: TestableApp) {
  return bearer(app, TEST_API_TOKEN);
}

/** M3-D: supertest as an agent, with `Authorization: Bearer <agent credential>` on every request. */
export function asAgent(app: TestableApp, as: TestCredential = TEST_AGENT_CREDENTIAL) {
  return bearer(app, as.credential);
}

function bearer(app: TestableApp, value: string) {
  const client = supertest(app);
  const withToken = (test: Test) => test.set("Authorization", `Bearer ${value}`);
  return {
    get: (url: string) => withToken(client.get(url)),
    post: (url: string) => withToken(client.post(url)),
    put: (url: string) => withToken(client.put(url)),
    patch: (url: string) => withToken(client.patch(url)),
    delete: (url: string) => withToken(client.delete(url)),
  };
}

/**
 * M3-E E3: a deterministic Ed25519 signing key for tests. The private key is derived at
 * runtime from a label (SHA-256 seed), so no key material is stored anywhere and every run
 * uses the same keys. Not a real credential.
 */
export interface TestSigningKey {
  agentId: string;
  keyId: string;
  privateKey: KeyObject;
  record: Ed25519CredentialRecord;
}

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function testSigningKey(agentId: string, label: string, options: { now?: number; days?: number; revokedAt?: string | null } = {}): TestSigningKey {
  const seed = createHash("sha256").update(`agentshield-test-signing-key\0${label}`).digest();
  const keyId = createHash("sha256").update(`agentshield-test-key-id\0${label}`).digest("hex").slice(0, 16);
  const privateKey = createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" });
  const now = options.now ?? Date.now();
  const record = validateCredentialRecord({
    scheme: "ed25519",
    keyId,
    agentId,
    publicKey: privateKey.export({ format: "jwk" }).x,
    label: null,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + (options.days ?? 90) * 24 * 60 * 60 * 1000).toISOString(),
    revokedAt: options.revokedAt ?? null,
  }) as Ed25519CredentialRecord;
  return { agentId, keyId, privateKey, record };
}

export interface SignedRequestOptions {
  /** Request timestamp in ms. */
  ts: number;
  /** Exact JSON body text to send (omitted: no body). */
  body?: string;
  nonce?: string;
  /** The Host header to send and sign. */
  host?: string;
  /** Sign these values instead of the ones sent, to model tampering. */
  signed?: Partial<{ method: string; host: string; target: string; body: string; timestamp: string; nonce: string; keyId: string }>;
  /** Send these header parameters instead of the signed ones. */
  sent?: Partial<{ keyId: string; timestamp: string; nonce: string }>;
}

let nonceCounter = 0;
/** A fresh, valid nonce for each call (deterministic within a run). */
export function testNonce(): string {
  nonceCounter += 1;
  return createHash("sha256").update(`agentshield-test-nonce\0${nonceCounter}\0${process.pid}`).digest().subarray(0, 16).toString("base64url");
}

/**
 * A signed agent request built with the shared protocol package (the same code the SDK will
 * use). Returns the supertest request plus the header, so tests can resend it exactly.
 */
export function signedRequest(app: TestableApp, key: TestSigningKey, method: "get" | "post" | "put" | "delete", target: string, options: SignedRequestOptions) {
  const host = options.host ?? "127.0.0.1:4000";
  const nonce = options.nonce ?? testNonce();
  const timestamp = String(options.ts);
  const signedBody = options.signed?.body ?? options.body;
  const message = canonicalRequestBytes({
    method: options.signed?.method ?? method.toUpperCase(),
    host: options.signed?.host ?? host,
    target: options.signed?.target ?? target,
    timestamp: options.signed?.timestamp ?? timestamp,
    nonce: options.signed?.nonce ?? nonce,
    keyId: options.signed?.keyId ?? key.keyId,
    bodySha256: sha256Hex(signedBody === undefined ? undefined : Buffer.from(signedBody, "utf8")),
  });
  const authorization = formatAuthorization({
    keyId: options.sent?.keyId ?? key.keyId,
    timestamp: options.sent?.timestamp ?? timestamp,
    nonce: options.sent?.nonce ?? nonce,
    signature: sign(null, message, key.privateKey).toString("base64url"),
  });
  const send = () => {
    const test = (supertest(app) as unknown as Record<string, (url: string) => Test>)[method]!(target).set("Host", host).set("Authorization", authorization);
    return options.body === undefined ? test : test.set("Content-Type", "application/json").send(options.body);
  };
  return { send, authorization, nonce };
}
