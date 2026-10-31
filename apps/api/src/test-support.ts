import supertest, { type Test } from "supertest";
import { DEMO_AGENT_POLICY, type AgentPolicy } from "@agentshield/engine";
import { createApp, type AppDeps } from "./app.js";
import { createCredentialStore, issueCredential, type CredentialRecord, type CredentialStore } from "./agents/credentials.js";
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
  record: CredentialRecord;
}

const issuedKeyIds = new Set<string>();

export function issueTestCredential(agentId: string, options: { now?: number; days?: number } = {}): TestCredential {
  const { credential, record } = issueCredential({ agentId, now: options.now ?? Date.now(), days: options.days, takenKeyIds: issuedKeyIds });
  issuedKeyIds.add(record.keyId);
  return { agentId, credential, record };
}

/** The route-test agent's credential. */
export const TEST_AGENT_CREDENTIAL = issueTestCredential(TEST_AGENT_ID);

/** An in-memory credential store: the test agent's credential and any extra ones a test needs. */
export function testCredentialStore(extra: TestCredential[] = []): CredentialStore {
  return createCredentialStore([TEST_AGENT_CREDENTIAL.record, ...extra.map((c) => c.record)]);
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
