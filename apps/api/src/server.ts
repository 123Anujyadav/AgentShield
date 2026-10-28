import type { AddressInfo } from "node:net";
import { createApp } from "./app.js";
import { API_HOST } from "./host.js";
import { loadLocalEnv } from "./load-env.js";

// Loads repo-root .env (git-ignored) if present. Never logs values.
loadLocalEnv();

const port = Number(process.env.PORT ?? 4000);
// Loopback only (API_HOST): the API has no authentication.
const server = createApp().listen(port, API_HOST, () => {
  const { address, port: boundPort } = server.address() as AddressInfo;
  console.log(`AgentShield API listening on http://${address}:${boundPort} (loopback only, no authentication)`);
});
