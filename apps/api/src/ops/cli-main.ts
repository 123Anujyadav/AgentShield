import { loadLocalEnv } from "../load-env.js";
import { runOpsCli } from "./cli.js";

// Entry point for `npm run ops -- <command>` (M3-E E14). The repo-root .env (git-ignored) is loaded like the
// server does, so the store paths are the API's own. Values are never printed.
loadLocalEnv();
process.exitCode = runOpsCli(process.argv.slice(2), {
  env: process.env,
  now: Date.now,
  out: (line) => process.stdout.write(`${line}\n`),
  err: (line) => process.stderr.write(`${line}\n`),
  checkPermissions: true,
});
