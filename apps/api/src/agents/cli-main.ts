import { loadLocalEnv } from "../load-env.js";
import { runCli } from "./cli.js";

// Entry point for `npm run agent-credential -w @agentshield/api -- <command>`.
// The repo-root .env (git-ignored) is loaded like the server does, so AGENT_CREDENTIAL_FILE
// points the CLI at the same store the API reads. Values are never printed.
loadLocalEnv();
process.exitCode = runCli(process.argv.slice(2), {
  env: process.env,
  now: Date.now,
  out: (line) => process.stdout.write(`${line}\n`),
  err: (line) => process.stderr.write(`${line}\n`),
});
