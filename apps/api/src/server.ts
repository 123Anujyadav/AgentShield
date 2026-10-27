import { createApp } from "./app.js";
import { loadLocalEnv } from "./load-env.js";

// Loads repo-root .env (git-ignored) if present. Never logs values.
loadLocalEnv();

const port = Number(process.env.PORT ?? 4000);
createApp().listen(port, () => {
  console.log(`AgentShield API listening on http://localhost:${port}`);
});
