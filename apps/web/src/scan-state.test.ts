import { describe, expect, it } from "vitest";
import topBar from "./components/TopBar.tsx?raw";
import { scanningStateLabel, TOP_BAR_TAGLINE_PREFIX } from "./scan-state.js";

describe("top bar scanning state (D2 regression)", () => {
  it("describes each combination of the server's switches truthfully", () => {
    expect(scanningStateLabel({ outboundScanningEnabled: false, labModeEnabled: false })).toBe("Website scanning: off");
    expect(scanningStateLabel({ outboundScanningEnabled: true, labModeEnabled: false })).toBe("Website scanning: ON (owner-verified sites)");
    expect(scanningStateLabel({ outboundScanningEnabled: false, labModeEnabled: true })).toBe("Website scanning: local lab only");
    expect(scanningStateLabel({ outboundScanningEnabled: true, labModeEnabled: true })).toBe("Website scanning: ON (verified sites and local lab)");
    expect(scanningStateLabel(null)).toBe("Website scanning: status unknown");
  });

  it("never claims there are no live side effects", () => {
    expect(TOP_BAR_TAGLINE_PREFIX).not.toMatch(/zero live side effects/i);
    expect(topBar).not.toMatch(/zero live side effects/i);
    expect(topBar).toContain("scanningStateLabel(scanSwitches)");
  });
});
