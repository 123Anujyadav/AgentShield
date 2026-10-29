/** The server's website-scanning switches, as reported by GET /api/targets. */
export interface ScanSwitches {
  outboundScanningEnabled: boolean;
  labModeEnabled: boolean;
}

/**
 * One truthful line for the top bar: agent actions are always simulated, and
 * website scanning is described from the server's actual switches. When the
 * switches are unknown, it says so instead of guessing.
 */
export function scanningStateLabel(switches: ScanSwitches | null): string {
  if (!switches) return "Website scanning: status unknown";
  if (switches.outboundScanningEnabled && switches.labModeEnabled) return "Website scanning: ON (verified sites and local lab)";
  if (switches.outboundScanningEnabled) return "Website scanning: ON (owner-verified sites)";
  if (switches.labModeEnabled) return "Website scanning: local lab only";
  return "Website scanning: off";
}

export const TOP_BAR_TAGLINE_PREFIX = "Deterministic AI Runtime Firewall · Agent actions simulated";
