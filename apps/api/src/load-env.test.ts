import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadLocalEnv } from "./load-env.js";

describe("loadLocalEnv", () => {
  const original = process.env.AGENTSHIELD_LOAD_ENV_TEST;
  afterEach(() => {
    if (original === undefined) delete process.env.AGENTSHIELD_LOAD_ENV_TEST;
    else process.env.AGENTSHIELD_LOAD_ENV_TEST = original;
  });

  it("loads a local .env-style file without any dependency, using a fake value", () => {
    const dir = mkdtempSync(join(tmpdir(), "agentshield-env-"));
    // Layout mirrors the repo: <root>/.env with code two levels below.
    const codeDir = join(dir, "apps", "api", "src");
    writeFileSync(join(dir, ".env"), "AGENTSHIELD_LOAD_ENV_TEST=fake-test-value\n");
    delete process.env.AGENTSHIELD_LOAD_ENV_TEST;
    // Point the loader at a fake module URL inside the nested code directory.
    const loaded = loadLocalEnv(new URL(`file:///${codeDir.replaceAll("\\", "/")}/server.ts`).href);
    expect(loaded).toBe(true);
    expect(process.env.AGENTSHIELD_LOAD_ENV_TEST).toBe("fake-test-value");
  });

  it("returns false when no .env exists", () => {
    const dir = mkdtempSync(join(tmpdir(), "agentshield-noenv-"));
    const loaded = loadLocalEnv(new URL(`file:///${dir.replaceAll("\\", "/")}/a/b/server.ts`).href);
    expect(loaded).toBe(false);
  });
});
