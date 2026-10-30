import { checkCookies, checkContentTypeOptions, checkCors, checkCsp, checkDisclosure, checkFraming, checkHsts, checkPermissionsPolicy, checkReferrerPolicy } from "./checks/headers.js";
import { checkSecurityTxt } from "./checks/security-txt.js";
import { checkHttpsRedirect, checkTls } from "./checks/transport-security.js";
import type { FetchFailureReason, FetchResult, GuardedFetcher, RequestBudget } from "./fetcher.js";
import type { CheckResult, PassiveObservations } from "./findings.js";
import { runProbeStage, type NotCheckedReason, type ProbeStagePlan } from "./stages.js";
import type { ScanTarget } from "./target.js";

/**
 * Passive scan orchestration (M1): at most three fetches (root over HTTPS, root
 * over plain HTTP, /.well-known/security.txt), each with its own redirect hops,
 * all inside one request budget. No crawling, no other paths, no form
 * submission, no payloads.
 *
 * An optional probe stage (M2) runs only after every passive check has its
 * result, so a probe that is skipped, runs out of time or budget, or is
 * interrupted never costs the passive results.
 */

export const PASSIVE_CHECKS: Array<(obs: PassiveObservations) => CheckResult> = [
  checkTls,
  checkHttpsRedirect,
  checkHsts,
  checkCsp,
  checkContentTypeOptions,
  checkReferrerPolicy,
  checkPermissionsPolicy,
  checkFraming,
  checkCors,
  checkDisclosure,
  checkCookies,
  checkSecurityTxt,
];

/** A fixed, unresolvable origin (RFC 6761 .invalid) used to observe CORS reflection. */
export const CORS_PROBE_ORIGIN = "https://agentshield-cors-probe.invalid";
export const SECURITY_TXT_READ_BYTES = 32 * 1024;

/** Reasons that mean the target itself must not be scanned; the scan stops instead of reporting findings. */
export const FATAL_REASONS: ReadonlySet<FetchFailureReason> = new Set<FetchFailureReason>(["blocked-address", "malformed-resolution", "dns-failure", "out-of-scope", "cancelled"]);

export class ScanStopped extends Error {
  constructor(readonly reason: FetchFailureReason) {
    super(reason);
  }
}

export interface PassiveScanResult {
  checks: CheckResult[];
  requestsUsed: number;
  requestBudget: number;
  /** Why the optional probe stage stopped scheduling early; null when it finished or was not requested. */
  probesStoppedEarly: NotCheckedReason | null;
}

export async function runPassiveScan(options: {
  target: ScanTarget;
  fetcher: GuardedFetcher;
  budget: RequestBudget;
  signal?: AbortSignal;
  now?: () => Date;
  /** Optional probes after the passive checks. Omitted or empty: the M1 scan, unchanged. */
  probeStage?: ProbeStagePlan;
}): Promise<PassiveScanResult> {
  const { target, fetcher, budget, signal } = options;
  const now = options.now ?? (() => new Date());
  const stopOnFatal = (fetched: FetchResult): FetchResult => {
    if (!fetched.ok && FATAL_REASONS.has(fetched.reason)) throw new ScanStopped(fetched.reason);
    return fetched;
  };

  let https: FetchResult | null = null;
  let http: FetchResult | null;
  let primaryOrigin: string;
  if (target.kind === "lab") {
    primaryOrigin = target.origin;
    http = stopOnFatal(await fetcher.fetch(target, new URL(`${target.origin}/`), { budget, signal, probeOrigin: CORS_PROBE_ORIGIN }));
  } else {
    primaryOrigin = `https://${target.hostname}`;
    https = stopOnFatal(await fetcher.fetch(target, new URL(`${primaryOrigin}/`), { budget, signal, probeOrigin: CORS_PROBE_ORIGIN }));
    http = stopOnFatal(await fetcher.fetch(target, new URL(`http://${target.hostname}/`), { budget, signal, followRedirects: false }));
  }
  const securityTxt = stopOnFatal(
    await fetcher.fetch(target, new URL(`${primaryOrigin}/.well-known/security.txt`), { budget, signal, readBodyBytes: SECURITY_TXT_READ_BYTES }),
  );

  const observations: PassiveObservations = { target, https, http, securityTxt, probeOrigin: CORS_PROBE_ORIGIN, now: now() };
  const checks = PASSIVE_CHECKS.map((check) => check(observations));
  let probesStoppedEarly: NotCheckedReason | null = null;
  if (options.probeStage && options.probeStage.probes.length > 0) {
    const stage = await runProbeStage({
      ...options.probeStage,
      context: { target, fetcher, budget, signal },
      now: () => now().getTime(),
    });
    checks.push(...stage.checks);
    probesStoppedEarly = stage.stoppedEarly;
  }
  return { checks, requestsUsed: budget.spent, requestBudget: budget.limit, probesStoppedEarly };
}
