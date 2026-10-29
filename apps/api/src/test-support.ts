import supertest, { type Test } from "supertest";
import { createApp, type AppDeps } from "./app.js";

/**
 * Test helpers (M0). Existing route tests run against the protected API with a
 * fixed, invented token, so they exercise the same middleware as real clients.
 */

/** Invented for tests only; not a credential. */
export const TEST_API_TOKEN = "agentshield-test-token-not-real-0123456789abcdef";

/** createApp with the test token, so `request(app)` below is authenticated. */
export function createTestApp(deps: AppDeps = {}) {
  return createApp({ apiToken: TEST_API_TOKEN, ...deps });
}

type TestableApp = Parameters<typeof supertest>[0];

/** supertest with `Authorization: Bearer <test token>` on every request. */
export function request(app: TestableApp) {
  const client = supertest(app);
  const withToken = (test: Test) => test.set("Authorization", `Bearer ${TEST_API_TOKEN}`);
  return {
    get: (url: string) => withToken(client.get(url)),
    post: (url: string) => withToken(client.post(url)),
    put: (url: string) => withToken(client.put(url)),
    patch: (url: string) => withToken(client.patch(url)),
    delete: (url: string) => withToken(client.delete(url)),
  };
}
