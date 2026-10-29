import type { AddressInfo } from "node:net";
import { createApp } from "./app.js";
import { API_HOST } from "./host.js";
import { loadLocalEnv } from "./load-env.js";
import { loadOrCreateApiToken } from "./security/token.js";

// Loads repo-root .env (git-ignored) if present. Never logs values.
loadLocalEnv();

// The API token lives in the user profile, outside the repository. Only its path is printed.
const tokenFile = loadOrCreateApiToken();

const port = Number(process.env.PORT ?? 4000);
// Loopback only (API_HOST), and every /api route requires the API token or a session.
const server = createApp({ apiToken: tokenFile.token }).listen(port, API_HOST, () => {
  const { address, port: boundPort } = server.address() as AddressInfo;
  console.log(`AgentShield API listening on http://${address}:${boundPort} (loopback only, API token required)`);
  console.log(`API token file${tokenFile.created ? " (created)" : ""}: ${tokenFile.path}`);
  console.log(`Copy it without displaying it: Get-Content -Raw "${tokenFile.path}" | Set-Clipboard`);
});
