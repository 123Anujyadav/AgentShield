import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { evaluateAction, getScenario, type ActivityEvent } from "@agentshield/engine";
import { openDurableApprovalStore } from "../approval-journal.js";
import { createPendingApproval, processRejection } from "../approvals.js";
import { openFileAuditLog } from "../audit/file-audit-log.js";
import { serializeCredentialDocument } from "../agents/credentials.js";
import { openDurableNonceCache } from "../agents/durable-nonce-cache.js";
import { createIdempotencyStore } from "../idempotency.js";
import { restoreStores, type StorePaths } from "../ops/backup.js";
import { runOpsCli } from "../ops/cli.js";
import { testSigningKey } from "../test-support.js";

/**
 * M3-E E15: an isolated recovery drill, run through the operator CLI (`npm run ops -- ...`) on temporary stores,
 * in the order an operator would follow docs/operations.md:
 *   status -> backup -> verify-backup -> (activity after the backup) -> disaster -> status -> restore, interrupted
 *   -> the API refuses to start -> restore again -> status -> restart every store -> checks.
 * Set AGENTSHIELD_BETA_DRILL to a file path to keep the transcript. This is not a drill on a real installation.
 */

const T = Date.now();
const scenario = getScenario("injection-in-document")!;
const evaluation = evaluateAction({ intent: scenario.intent, action: scenario.action, untrustedContent: scenario.untrustedContent });
const writer = testSigningKey("writer", "e15-drill-writer");
const transcript: string[] = [];
let dir: string;
let paths: StorePaths;

function ops(args: string[]) {
  const out: string[] = [];
  const code = runOpsCli(args, { env: {}, now: Date.now, out: (l) => out.push(l), err: (l) => out.push(`stderr: ${l}`), paths });
  transcript.push(`$ npm run ops -- ${args.join(" ").replaceAll(dir, "<drill>")}`, ...out.map((l) => l.replaceAll(dir, "<drill>")), `(exit ${code})`, "");
  return { code, text: out.join("\n") };
}

function event(seq: number, approvalId?: string): ActivityEvent {
  return {
    id: `evt-${seq}`,
    timestamp: new Date(T + seq).toISOString(),
    scenarioId: null,
    intentTask: "drill",
    actionType: "create_summary",
    tool: "t",
    destination: "d",
    decision: "CONFIRM",
    riskScore: 50,
    findings: [],
    explanation: "e",
    ...(approvalId ? { approvalId } : {}),
  };
}

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "agentshield-drill-"));
  paths = {
    auditLog: join(dir, "audit-events.jsonl"),
    approvals: join(dir, "approvals.journal"),
    idempotency: join(dir, "idempotency.journal"),
    replay: join(dir, "replay-nonces.journal"),
    credentials: join(dir, "agent-credentials.json"),
  };
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
  // The installation as a stopped API left it: two pending approvals, one rejected, events, keys and nonces.
  const audit = openFileAuditLog(paths.auditLog);
  const approvals = openDurableApprovalStore({ path: paths.approvals });
  for (let i = 1; i <= 3; i += 1) {
    const a = createPendingApproval(approvals, { scenarioId: null, intent: scenario.intent, action: scenario.action, untrustedContent: scenario.untrustedContent, evaluation, agentId: "writer", requestedBy: { kind: "agent", credentialId: writer.keyId }, credentialKeyId: writer.keyId });
    audit.append(event(i, a.id));
  }
  processRejection(approvals, "apr-2");
  approvals.close();
  audit.close();
  const idem = createIdempotencyStore({ path: paths.idempotency });
  idem.begin("writer", "drill-key-00000000001", "a".repeat(64), Date.now());
  idem.complete("writer", "drill-key-00000000001", { status: 200, body: { evaluation: { decision: "ALLOW" } } });
  idem.close();
  openDurableNonceCache({ path: paths.replay, now: () => Date.now() - 120_000, skewMs: 30_000 }).close();
  writeFileSync(paths.credentials, serializeCredentialDocument([writer.record]));
});

afterAll(() => {
  vi.restoreAllMocks();
  if (process.env.AGENTSHIELD_BETA_DRILL) writeFileSync(process.env.AGENTSHIELD_BETA_DRILL, transcript.join("\n"));
  rmSync(dir, { recursive: true, force: true });
});

describe("M3-E E15: recovery drill through the operator CLI", () => {
  it("runs the documented procedure end to end and ends in a safe, verified state", () => {
    const backupDir = join(dir, "backups", "drill");

    // Before: healthy.
    expect(ops(["status"]).code).toBe(0);

    // 1. Complete backup (the API is stopped), then verification.
    const backup = ops(["backup", "--out", backupDir]);
    expect(backup.code).toBe(0);
    expect(backup.text).toMatch(/backup complete: id=[0-9a-f]{16}/);
    const verify = ops(["verify-backup", "--dir", backupDir]);
    expect(verify.code).toBe(0);
    expect(verify.text).toContain("approval-store status=verified records=4 pending=2 restorable=yes");

    // 2. Activity after the backup: apr-1 is approved and executed (the backup still holds it as PENDING), and
    // apr-4 is created; the audit log records both.
    const approvals = openDurableApprovalStore({ path: paths.approvals });
    approvals.records.get("apr-1")!.status = "EXECUTED";
    approvals.persistence!.transitioned("apr-1", "EXECUTED", { executed: true, handler: "createSummary", result: "done", reason: "" });
    createPendingApproval(approvals, { scenarioId: null, intent: scenario.intent, action: scenario.action, untrustedContent: scenario.untrustedContent, evaluation, agentId: "writer", requestedBy: { kind: "agent", credentialId: writer.keyId }, credentialKeyId: writer.keyId });
    approvals.close();
    const audit = openFileAuditLog(paths.auditLog);
    audit.append(event(4, "apr-4"));
    audit.close();

    // 3. Disaster: the approval, idempotency and replay journals are lost.
    for (const p of [paths.approvals, paths.idempotency, paths.replay]) rmSync(p);
    const afterDisaster = ops(["status"]);
    expect(afterDisaster.text).toMatch(/approval-store status=missing/);
    expect(afterDisaster.text).toContain("missing while other stores hold records");
    expect(afterDisaster.code).toBe(1); // a lost store needs attention

    // 4. Restore, interrupted right after the approval journal was written (simulated crash).
    expect(() =>
      restoreStores(paths, backupDir, {
        env: {},
        hooks: {
          afterStep: (step) => {
            if (step === "restored:approval-store") throw new Error("simulated power loss");
          },
        },
      }),
    ).toThrow("simulated power loss");
    transcript.push("(restore interrupted by a simulated power loss after the approval journal was written)", "");
    // The API cannot start on half-restored state; status says so.
    expect(() => openDurableApprovalStore({ path: paths.approvals })).toThrow(/restore of the approval store was interrupted/);
    expect(() => createIdempotencyStore({ path: paths.idempotency })).toThrow(/interrupted/);
    const interrupted = ops(["status"]);
    expect(interrupted.code).toBe(1);
    expect(interrupted.text).toContain("restore=interrupted");

    // 5. The same restore again completes it. Healthy stores (audit log, credentials) are kept.
    const restore = ops(["restore", "--dir", backupDir]);
    expect(restore.code).toBe(0);
    expect(restore.text).toContain("audit-log keep");
    expect(restore.text).toContain("credential-store keep");
    expect(restore.text).toContain("approval-store restore: resuming an interrupted restore");
    expect(restore.text).toContain("replay-store keep");
    expect(restore.text).toContain("Approval ids continue at apr-5.");
    expect(readdirSync(dir).some((n) => n.endsWith(".restoring"))).toBe(false);
    expect(existsSync(paths.replay)).toBe(false);

    // 6. After: every store restarts; nothing restored can run; replay and idempotency are fenced.
    const after = ops(["status"]);
    expect(after.text).toMatch(/approval-store status=verified/);
    const reopenedAudit = openFileAuditLog(paths.auditLog);
    const reopenedApprovals = openDurableApprovalStore({ path: paths.approvals });
    const reopenedIdem = createIdempotencyStore({ path: paths.idempotency, historyExpected: true });
    const reopenedReplay = openDurableNonceCache({ path: paths.replay, now: Date.now, skewMs: 30_000 });
    try {
      expect(reopenedAudit.recovery).toMatchObject({ records: 4, unverified: 0, malformed: 0 });
      expect(reopenedApprovals.recovery).toMatchObject({ restored: 2, corrupt: 0, unverified: 0 });
      // apr-1 ran after the backup: it is OUTCOME_UNKNOWN, never pending again, never runnable.
      expect(reopenedApprovals.records.get("apr-1")?.status).toBe("OUTCOME_UNKNOWN");
      expect(reopenedApprovals.records.get("apr-3")?.status).toBe("OUTCOME_UNKNOWN");
      expect(reopenedApprovals.records.get("apr-2")?.status).toBe("REJECTED");
      expect(reopenedApprovals.nextId).toBe(5); // apr-4 (only in the audit log) is never reissued
      expect(reopenedIdem.begin("writer", "drill-key-00000000001", "a".repeat(64), Date.now()).kind).toBe("unavailable");
      expect(reopenedReplay.recoveringUntil).toBeGreaterThan(Date.now());
    } finally {
      reopenedReplay.close();
      reopenedIdem.close();
      reopenedApprovals.close();
      reopenedAudit.close();
    }
    // The transcript never shows record content.
    expect(transcript.join("\n")).not.toContain(scenario.untrustedContent!.text.slice(0, 30));
    expect(readFileSync(join(backupDir, "manifest.json"), "utf8")).not.toContain(dir);
  });
});
