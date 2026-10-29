import { parseLabOrigin, type LabTarget } from "@agentshield/websec";

/**
 * Website-scanning settings (M1). Both switches fail closed: only the exact
 * text "true" turns them on, and anything else (unset, empty, "TRUE", "1",
 * "yes") leaves them off.
 *
 * - SCAN_NETWORK_ENABLED governs every outbound action for real targets: the
 *   DNS TXT ownership check and the scan itself.
 * - SCAN_LAB_MODE independently allows scans of the exact loopback origins in
 *   SCAN_LAB_ORIGINS (ports 8080-8099 only, never the API's own port), and
 *   nothing else. It never relaxes the address guard for any other target.
 */
export interface ScanConfig {
  networkEnabled: boolean;
  lab: { enabled: boolean; origins: ReadonlyMap<string, LabTarget>; rejectedEntries: number };
  verificationTtlMs: number;
  maxTargets: number;
  maxScans: number;
  maxAuditEntries: number;
  maxConcurrentScans: number;
  requestBudget: number;
  /** Upper bound on one whole scan, on top of the 10-second per-request timeout. */
  scanTimeoutMs: number;
  rateLimits: { registerTarget: number; verify: number; startScan: number };
}

const DAY_MS = 86_400_000;

export function loadScanConfig(env: NodeJS.ProcessEnv = process.env): ScanConfig {
  const labEnabled = env.SCAN_LAB_MODE === "true";
  const origins = new Map<string, LabTarget>();
  let rejectedEntries = 0;
  const reserved = new Set([4000, 5173, Number(env.PORT ?? 4000)]);
  for (const entry of (env.SCAN_LAB_ORIGINS ?? "").split(",").map((s) => s.trim()).filter(Boolean).slice(0, 10)) {
    const parsed = parseLabOrigin(entry, reserved);
    if (parsed) origins.set(parsed.origin, parsed);
    else rejectedEntries += 1;
  }
  return {
    networkEnabled: env.SCAN_NETWORK_ENABLED === "true",
    lab: { enabled: labEnabled, origins: labEnabled ? origins : new Map(), rejectedEntries },
    verificationTtlMs: 30 * DAY_MS,
    maxTargets: 50,
    maxScans: 50,
    maxAuditEntries: 500,
    maxConcurrentScans: 2,
    requestBudget: 30,
    scanTimeoutMs: 120_000,
    rateLimits: { registerTarget: 20, verify: 10, startScan: 5 },
  };
}
