import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

/**
 * M3-E audit L1: the documented fresh setup must build every workspace package the API
 * and web app load from a built `dist`, in dependency order, before the API is started.
 * Read from the real package.json files, so a new dependency without a build step fails here.
 */

const root = new URL("../../../", import.meta.url);
const readJson = (path: string) => JSON.parse(readFileSync(new URL(path, root), "utf8"));

interface Pkg {
  name: string;
  dependencies: string[];
  builtFromDist: boolean;
}

function workspacePackages(): Map<string, Pkg> {
  const packages = new Map<string, Pkg>();
  for (const folder of ["packages", "apps"]) {
    for (const entry of readdirSync(new URL(`${folder}/`, root), { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      let json: { name: string; dependencies?: Record<string, string>; exports?: { ".": { default?: string } } };
      try {
        json = readJson(`${folder}/${entry.name}/package.json`);
      } catch {
        continue;
      }
      packages.set(json.name, {
        name: json.name,
        dependencies: Object.keys(json.dependencies ?? {}).filter((d) => d.startsWith("@agentshield/")),
        builtFromDist: (json.exports?.["."]?.default ?? "").startsWith("./dist/"),
      });
    }
  }
  return packages;
}

/** Every workspace package reachable from `start` that is loaded from its built dist. */
function distDependencies(packages: Map<string, Pkg>, start: string): string[] {
  const found = new Set<string>();
  const visit = (name: string) => {
    for (const dep of packages.get(name)?.dependencies ?? []) {
      if (packages.get(dep)?.builtFromDist && !found.has(dep)) {
        found.add(dep);
        visit(dep);
      }
    }
  };
  visit(start);
  return [...found];
}

function runLocallyBlock(): string[] {
  const readme = readFileSync(new URL("README.md", root), "utf8");
  const section = readme.slice(readme.indexOf("## Run locally"));
  const block = /```powershell\n([\s\S]*?)```/.exec(section)![1]!;
  return block.split("\n").map((line) => line.replace(/#.*$/, "").trim()).filter(Boolean);
}

describe("M3-E audit L1: fresh-setup build instructions", () => {
  const packages = workspacePackages();
  const lines = runLocallyBlock();
  const builds = lines.map((line) => /^npm run build -w (\S+)$/.exec(line)?.[1]).filter((name): name is string => name !== undefined);
  const devApi = lines.indexOf("npm run dev:api");

  it("the API's dist-loaded dependencies include the protocol package, the engine and websec", () => {
    expect(distDependencies(packages, "@agentshield/api").sort()).toEqual(["@agentshield/agent-protocol", "@agentshield/engine", "@agentshield/websec"]);
  });

  it("README 'Run locally' builds every dist-loaded dependency of the API and web app before starting the API", () => {
    expect(lines[0]).toBe("npm install");
    expect(devApi).toBeGreaterThan(0);
    const needed = new Set([...distDependencies(packages, "@agentshield/api"), ...distDependencies(packages, "@agentshield/web")]);
    for (const name of needed) {
      const at = lines.indexOf(`npm run build -w ${name}`);
      expect(at, `${name} is built`).toBeGreaterThan(0);
      expect(at, `${name} is built before npm run dev:api`).toBeLessThan(devApi);
    }
  });

  it("each documented build comes after the builds of its own dependencies", () => {
    for (const name of builds) {
      for (const dep of distDependencies(packages, name)) {
        expect(builds.indexOf(dep), `${dep} before ${name}`).toBeGreaterThanOrEqual(0);
        expect(builds.indexOf(dep), `${dep} before ${name}`).toBeLessThan(builds.indexOf(name));
      }
    }
  });

  it("the root build script builds every package after its dependencies", () => {
    const order = [...(readJson("package.json").scripts.build as string).matchAll(/-w (\S+)/g)].map((m) => m[1]!);
    for (const name of order) {
      for (const dep of distDependencies(packages, name)) expect(order.indexOf(dep), `${dep} before ${name}`).toBeLessThan(order.indexOf(name));
    }
  });
});
