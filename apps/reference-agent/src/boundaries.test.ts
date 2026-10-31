import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { AgentShieldClient } from "@agentshield/agent-sdk";

/**
 * M3-E E6: the reference agent's security boundaries, checked on its source. It talks to
 * AgentShield only through the SDK: it does not sign, build authorization headers, call
 * fetch, or reach any operator route, and the SDK gives it no way to approve or reject.
 */

const SRC = fileURLToPath(new URL(".", import.meta.url));
const sources = readdirSync(SRC)
  .filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts") && f !== "test-support.ts")
  .map((f) => ({ file: f, text: readFileSync(join(SRC, f), "utf8") }));

describe("M3-E E6: reference agent boundaries", () => {
  it("has the expected source files", () => {
    expect(sources.map((s) => s.file).sort()).toEqual(["agent.ts", "cli.ts", "config.ts", "display.ts", "index.ts", "main.ts", "summarize.ts", "task.ts", "workspace.ts"]);
  });

  it.each([
    ["no fetch or HTTP client", /\bfetch\s*\(|node:https?|node:net|XMLHttpRequest|axios|undici/],
    ["no cryptography or signing", /node:crypto|createPrivateKey|createHash|\.sign\(|AGENTSHIELD-SIG|canonical/i],
    ["no authorization header or bearer token", /Authorization|Bearer|asag_/],
    ["no protocol package", /@agentshield\/agent-protocol/],
    ["no operator routes", /\/api\/approvals|\/approve\b|\/reject\b|\/api\/(policies|credentials|events|scenarios)/],
    ["no process execution or file writes", /child_process|\bexec\(|spawn\(|writeFile|appendFile|createWriteStream/],
    ["no SDK test fixtures or internal modules", /agent-sdk\/(dist|src)/],
  ])("%s", (_label, pattern) => {
    for (const { file, text } of sources) expect(pattern.test(text), file).toBe(false);
  });

  it("depends on the SDK and nothing else at run time", () => {
    const pkg = JSON.parse(readFileSync(join(SRC, "..", "package.json"), "utf8"));
    expect(pkg.dependencies).toEqual({ "@agentshield/agent-sdk": "*" });
  });

  it("reads the environment only in main.ts, and names its variables explicitly", () => {
    for (const { file, text } of sources) if (file !== "main.ts") expect(/process\.env/.test(text), file).toBe(false);
  });

  it("the SDK client it uses has no way to approve, reject or send arbitrary requests", () => {
    const methods = Object.getOwnPropertyNames(AgentShieldClient.prototype);
    expect(methods.filter((m) => /^(approve|reject|decide|request|send|post|put|delete)/i.test(m))).toEqual([]);
  });
});
