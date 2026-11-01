import type { AddressInfo } from "node:net";
import { redactSecretValue } from "@agentshield/engine";
import { bearerAllowedFromEnv, createReloadingCredentialStore, credentialFilePath, CredentialConfigError, type CredentialStore } from "./agents/credentials.js";
import { signatureSkewMsFromEnv, SignatureConfigError } from "./agents/signature.js";
import { createApp } from "./app.js";
import { approvalStorePathFromEnv, openDurableApprovalStore, type DurableApprovalStore } from "./approval-journal.js";
import { openDurableNonceCache, replayStorePathFromEnv, type DurableNonceCache } from "./agents/durable-nonce-cache.js";
import { createIdempotencyStore, idempotencyStorePathFromEnv, type IdempotencyStore } from "./idempotency.js";
import { JournalConfigError } from "./storage/journal.js";
import { AuditConfigError, auditLogMaxBytesFromEnv, auditLogPathFromEnv, openFileAuditLog, type AuditLog } from "./audit/file-audit-log.js";
import { API_HOST } from "./host.js";
import { loadLocalEnv } from "./load-env.js";
import { loadPolicyStore, PolicyConfigError, type PolicyStore } from "./policies/store.js";
import { loadOrCreateApiToken } from "./security/token.js";

// Loads repo-root .env (git-ignored) if present. Never logs values.
loadLocalEnv();

// The API token lives in the user profile, outside the repository. Only its path is printed.
const tokenFile = loadOrCreateApiToken();

// M3-C: server-side agent policies. An invalid AGENT_POLICY_FILE stops start-up (fail closed).
let policyStore: PolicyStore;
try {
  policyStore = loadPolicyStore();
} catch (error) {
  const reason = error instanceof PolicyConfigError ? error.message : "unexpected error";
  console.error(`agent-policy status=invalid-config reason=${reason}`);
  process.exit(1);
}

// M3-D: agent credentials (hashes and public keys only), re-read within 2 seconds of a change.
// An invalid store stops start-up; a store that becomes invalid later rejects every agent
// credential until it is fixed (the operator dashboard keeps working). Secrets are never logged.
// M3-E E2: legacy bearer credentials authenticate only when AGENT_BEARER_ALLOWED is exactly "true".
const bearerAllowed = bearerAllowedFromEnv();
if (bearerAllowed) console.warn("agent-credentials status=warning reason=bearer-allowed note=legacy-bearer-credentials-enabled-for-migration");
let credentialStore: CredentialStore;
try {
  credentialStore = createReloadingCredentialStore(credentialFilePath(), {
    bearerAllowed,
    hasPolicy: (agentId) => policyStore.get(agentId) !== undefined,
    onEvent: (event) => {
      if (event.kind === "reloaded") console.warn(`agent-credentials status=reloaded count=${event.count}`);
      else if (event.kind === "invalid") console.error(`agent-credentials status=invalid reason=${event.reason} effect=all-agent-credentials-rejected`);
      else if (event.kind === "bearer-disabled") console.warn(`agent-credentials status=warning reason=bearer-disabled activeBearerCredentials=${event.count}`);
      else console.warn(`agent-credentials status=warning reason=no-policy agentId=${redactSecretValue(event.agentId)} keyId=${event.keyId}`);
    },
  });
} catch (error) {
  const reason = error instanceof CredentialConfigError ? error.message : "unexpected error";
  console.error(`agent-credentials status=invalid-config reason=${reason}`);
  process.exit(1);
}

// M3-E E3: allowed clock skew for signed agent requests (default 30 s, 5 to 300). An invalid value stops start-up.
let signatureSkewMs: number;
try {
  signatureSkewMs = signatureSkewMsFromEnv();
} catch (error) {
  const reason = error instanceof SignatureConfigError ? error.message : "unexpected error";
  console.error(`agent-signature status=invalid-config reason=${reason}`);
  process.exit(1);
}

// M3-E E10: durable audit events (append-only JSON Lines, restricted to the current user). A log that
// cannot be opened safely stops start-up; recovered problems are reported by count and line number only.
let auditLog: AuditLog;
try {
  auditLog = openFileAuditLog(auditLogPathFromEnv(), { maxBytes: auditLogMaxBytesFromEnv() });
} catch (error) {
  const reason = error instanceof AuditConfigError ? error.message : "unexpected error";
  console.error(`audit-log status=invalid-config reason=${reason}`);
  process.exit(1);
}
const recovery = auditLog.recovery;
console.warn(`audit-log status=ready records=${recovery.records} bytes=${recovery.bytes} maxBytes=${recovery.maxBytes} path=${auditLogPathFromEnv()}`);
if (recovery.truncatedTail) console.warn("audit-log status=recovered reason=truncated-final-record effect=partial-record-kept-and-skipped");
if (recovery.malformed > 0) console.warn(`audit-log status=warning reason=malformed-records count=${recovery.malformed} lines=${recovery.malformedLines.join(",")}`);
if (recovery.duplicates > 0) console.warn(`audit-log status=warning reason=duplicate-records count=${recovery.duplicates}`);
if (recovery.staleLockReplaced) console.warn("audit-log status=warning reason=stale-lock-replaced");
if (!recovery.permissionsRestricted) console.warn("audit-log status=warning reason=permissions-not-restricted note=other-accounts-may-read-the-audit-log");
// Release the single-writer lock on a normal exit, including Ctrl+C and termination.
process.on("exit", () => auditLog.close());

// M3-E E11: durable replay protection (accepted nonces survive a restart) and evaluation idempotency records.
// Either store failing to open safely stops start-up.
let nonceCache: DurableNonceCache;
let idempotencyStore: IdempotencyStore;
// M3-E E12: durable approvals (pending, decided and expired approvals survive a restart; ids are never reused).
let approvalStore: DurableApprovalStore;
try {
  nonceCache = openDurableNonceCache({ path: replayStorePathFromEnv(), now: Date.now, skewMs: signatureSkewMs });
  idempotencyStore = createIdempotencyStore({ path: idempotencyStorePathFromEnv() });
  approvalStore = openDurableApprovalStore({ path: approvalStorePathFromEnv() });
} catch (error) {
  const reason = error instanceof JournalConfigError ? error.message : "unexpected error";
  console.error(`agent-state status=invalid-config reason=${reason}`);
  process.exit(1);
}
const replay = nonceCache.recovery;
console.warn(`replay-store status=ready liveNonces=${replay.loaded} corrupt=${replay.corrupt}${replay.truncatedTail ? " truncatedTail=recovered" : ""}`);
if (replay.recoveringUntil > 0) {
  console.warn(`replay-store status=recovering until=${new Date(replay.recoveringUntil).toISOString()} effect=signed-requests-dated-before-then-refused`);
}
const idem = idempotencyStore.recovery;
if (idem) {
  console.warn(`idempotency-store status=ready records=${idem.records} corrupt=${idem.corrupt}${idem.truncatedTail ? " truncatedTail=recovered" : ""}`);
  if (idem.recoveringUntil > 0) console.warn(`idempotency-store status=recovering until=${new Date(idem.recoveringUntil).toISOString()} effect=new-idempotency-keys-refused`);
}
const approvals = approvalStore.recovery;
console.warn(`approval-store status=ready approvals=${approvals.records} pending=${approvals.pending} corrupt=${approvals.corrupt}${approvals.truncatedTail ? " truncatedTail=recovered" : ""}`);
if (approvals.interrupted > 0) console.warn(`approval-store status=recovered interrupted=${approvals.interrupted} effect=marked-OUTCOME_UNKNOWN-never-run`);
if (approvals.quarantined > 0) console.warn(`approval-store status=recovered quarantined=${approvals.quarantined} effect=damaged-records-marked-OUTCOME_UNKNOWN`);
process.on("exit", () => {
  nonceCache.close();
  idempotencyStore.close();
  approvalStore.close();
});
for (const signal of ["SIGINT", "SIGTERM"] as const) process.once(signal, () => process.exit(0));

const port = Number(process.env.PORT ?? 4000);
// Loopback only (API_HOST), and every /api route requires the API token or a session.
const server = createApp({ apiToken: tokenFile.token, policyStore, credentialStore, signatureSkewMs, auditLog, nonceCache, idempotencyStore, approvalStore }).listen(port, API_HOST, () => {
  const { address, port: boundPort } = server.address() as AddressInfo;
  console.log(`AgentShield API listening on http://${address}:${boundPort} (loopback only, API token required)`);
  console.log(`API token file${tokenFile.created ? " (created)" : ""}: ${tokenFile.path}`);
  console.log(`Copy it without displaying it: Get-Content -Raw "${tokenFile.path}" | Set-Clipboard`);
});
