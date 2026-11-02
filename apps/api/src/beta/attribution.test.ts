import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import supertest from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp } from "../app.js";
import { openDurableApprovalStore } from "../approval-journal.js";
import { builtInPolicyStore } from "../policies/store.js";
import { WEB_ORIGINS } from "../security/config.js";
import { TEST_API_TOKEN } from "../test-support.js";

/**
 * M3-E E17 (Gate A, check A6): a seeded scenario run from the dashboard must reach the approval queue as
 * "Requested by: Operator (dashboard) · scenario as <agent>". The dashboard renders GET /api/approvals, so this
 * follows the dashboard's own path: a session signed in from the web origin, the Scenario Lab request, the
 * operator listing, and a restart of the durable approval store. The dashboard's label for exactly these fields
 * ("Operator (dashboard) · scenario as demo-summarizer", which needs the scenarioId) is tested in
 * apps/web/src/approval-display.test.tsx.
 *
 * (The A6 finding itself came from an API process started before M3-C/M3-D added agentId and requestedBy; the
 * current source carries both. This test keeps it that way.)
 */

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "agentshield-attribution-"));
  vi.spyOn(console, "warn").mockImplementation(() => {});
});
afterEach(() => {
  vi.restoreAllMocks();
  rmSync(dir, { recursive: true, force: true });
});

describe("M3-E E17: dashboard scenario approvals name their requester", () => {
  it("the operator listing carries the operator actor and the scenario's agent, and keeps them across a restart", async () => {
    const path = join(dir, "approvals.journal");
    let approvalStore = openDurableApprovalStore({ path });
    const app = () => createApp({ apiToken: TEST_API_TOKEN, policyStore: builtInPolicyStore(), approvalStore });
    const origin = WEB_ORIGINS[0];

    let client = supertest(app());
    const login = await client.post("/api/session").set("Origin", origin).send({ token: TEST_API_TOKEN });
    expect(login.status).toBe(200);
    let cookie = String(login.headers["set-cookie"]?.[0] ?? "").split(";")[0]!;
    // The Scenario Lab request, exactly as the dashboard sends it.
    const run = await client.post("/api/evaluate").set("Origin", origin).set("Cookie", cookie).send({ scenarioId: "injection-in-document" });
    expect(run.body.evaluation.decision).toBe("CONFIRM");
    const id = run.body.pendingApproval.id as string;

    const listed = await client.get("/api/approvals").set("Origin", origin).set("Cookie", cookie);
    const approval = listed.body.approvals.find((a: { id: string }) => a.id === id);
    expect(approval).toMatchObject({ scenarioId: "injection-in-document", agentId: "demo-summarizer", requestedBy: { kind: "operator", method: "session" } });

    // After a restart (a new process, a new session): the attribution is still there.
    approvalStore.close();
    approvalStore = openDurableApprovalStore({ path });
    client = supertest(app());
    cookie = String((await client.post("/api/session").set("Origin", origin).send({ token: TEST_API_TOKEN })).headers["set-cookie"]?.[0] ?? "").split(";")[0]!;
    const again = (await client.get("/api/approvals").set("Origin", origin).set("Cookie", cookie)).body.approvals.find((a: { id: string }) => a.id === id);
    expect(again).toMatchObject({ scenarioId: "injection-in-document", agentId: "demo-summarizer", requestedBy: { kind: "operator", method: "session" } });
    approvalStore.close();
  });
});
