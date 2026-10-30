import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { EXPOSURE_PATHS } from "./checks/exposure.js";
import { DEFAULT_MAX_REDIRECTS, PREFIX_READ_BYTES } from "./fetcher.js";

/**
 * M2-H: the scanning documentation must match the code and the verified scope.
 * Reads the repository's own Markdown files; nothing else.
 */

const read = (path: string) => readFileSync(new URL(`../../../${path}`, import.meta.url), "utf8");
const DOCS = {
  readme: read("README.md"),
  scanning: read("docs/scanning.md"),
  passiveLab: read("labs/passive-scan/README.md"),
  exposureLab: read("labs/exposure-lab/README.md"),
};

describe("M2-H: scanning documentation", () => {
  it("no document still says an already-run lab was never run", () => {
    for (const [name, text] of Object.entries(DOCS)) {
      expect(text, name).not.toMatch(/prepared, not run/i);
      expect(text, name).not.toMatch(/lab[^.\n]*(?:has not been run|is prepared but)/i);
      expect(text, name).not.toMatch(/tested offline only/i);
    }
    expect(DOCS.scanning).toContain("54 of 54 checks");
    expect(DOCS.exposureLab).toContain("54 of 54 checks passed");
  });

  it("documents both controls, their default and the fixed paths", () => {
    expect(DOCS.scanning).toMatch(/\| `SCAN_EXPOSURE_ENABLED=true` \| [^|]+\| off \|/);
    expect(DOCS.scanning).toContain("They run only when **both** controls allow it");
    expect(DOCS.readme).toMatch(/`SCAN_EXPOSURE_ENABLED=true` \*and\* the user ticks \*\*Include exposure checks\*\*/);
    for (const path of EXPOSURE_PATHS) {
      expect(DOCS.scanning, path).toContain(`\`${path}\``);
      expect(DOCS.readme, path).toContain(`\`${path}\``);
    }
    expect(DOCS.scanning).toMatch(/random missing path[^.]*baseline|baseline[^.]*never a\s+finding/i);
  });

  it("request wording matches the code: five redirect hops, each a request, and the 4 KB prefix", () => {
    expect(DEFAULT_MAX_REDIRECTS).toBe(5);
    expect(PREFIX_READ_BYTES).toBe(4096);
    expect(DOCS.scanning).toContain("Every hop is\na separate request");
    expect(DOCS.scanning).toContain("up to five hops");
    expect(DOCS.scanning).toContain("2. `GET http://<host>/`: whether plain HTTP redirects to HTTPS. Never followed.");
    expect(DOCS.scanning).toContain("`Range: bytes=0-4095`");
    expect(DOCS.scanning).toContain("**The 4 KB limit.**");
  });

  it("documents the outcomes and the incomplete state", () => {
    for (const phrase of ["*Exposed*", "*Not exposed*", "*Inconclusive*", "*Not checked*", "**Incomplete exposure checks (M2-H).**", "exposureIncomplete: true"]) {
      expect(DOCS.scanning, phrase).toContain(phrase);
    }
  });

  it("never claims public sites, real DNS, real HTTPS or the browser UI were tested", () => {
    expect(DOCS.scanning).toMatch(/\*\*Not tested:\*\* any public website, any real DNS record/);
    expect(DOCS.scanning).toMatch(/public HTTPS server, and the Website Scans\s+screen in a browser/);
    expect(DOCS.readme).toMatch(/public sites, real DNS, real HTTPS and the browser UI\s+remain untested/);
    for (const [name, text] of Object.entries(DOCS)) {
      // Positive claims only: "has not scanned a real site" is the accurate wording and is allowed.
      expect(text, name).not.toMatch(/(?<!not |never )(?:tested|verified|validated) (?:in|with) a (?:real )?browser/i);
      expect(text, name).not.toMatch(/(?<!not |never )(?:scanned|tested) (?:a|on a) real (?:site|website|domain)/i);
    }
  });
});
