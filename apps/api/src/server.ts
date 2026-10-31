import type { AddressInfo } from "node:net";
import { redactSecretValue } from "@agentshield/engine";
import { createReloadingCredentialStore, credentialFilePath, CredentialConfigError, type CredentialStore } from "./agents/credentials.js";
import { createApp } from "./app.js";
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

// M3-D: agent credentials (hashes only), re-read within 2 seconds of a change. An invalid
// store stops start-up; a store that becomes invalid later rejects every agent credential
// until it is fixed (the operator dashboard keeps working). Secrets are never logged.
let credentialStore: CredentialStore;
try {
  credentialStore = createReloadingCredentialStore(credentialFilePath(), {
    hasPolicy: (agentId) => policyStore.get(agentId) !== undefined,
    onEvent: (event) => {
      if (event.kind === "reloaded") console.warn(`agent-credentials status=reloaded count=${event.count}`);
      else if (event.kind === "invalid") console.error(`agent-credentials status=invalid reason=${event.reason} effect=all-agent-credentials-rejected`);
      else console.warn(`agent-credentials status=warning reason=no-policy agentId=${redactSecretValue(event.agentId)} keyId=${event.keyId}`);
    },
  });
} catch (error) {
  const reason = error instanceof CredentialConfigError ? error.message : "unexpected error";
  console.error(`agent-credentials status=invalid-config reason=${reason}`);
  process.exit(1);
}

const port = Number(process.env.PORT ?? 4000);
// Loopback only (API_HOST), and every /api route requires the API token or a session.
const server = createApp({ apiToken: tokenFile.token, policyStore, credentialStore }).listen(port, API_HOST, () => {
  const { address, port: boundPort } = server.address() as AddressInfo;
  console.log(`AgentShield API listening on http://${address}:${boundPort} (loopback only, API token required)`);
  console.log(`API token file${tokenFile.created ? " (created)" : ""}: ${tokenFile.path}`);
  console.log(`Copy it without displaying it: Get-Content -Raw "${tokenFile.path}" | Set-Clipboard`);
});
