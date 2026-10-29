import { isIP } from "node:net";
import { domainToUnicode } from "node:url";
import { parseIPv4, parseIPv6, type AddressFamily } from "./address.js";

/**
 * Scan targets (M1).
 *
 * A DNS target is one exact host name (no subdomains, no IP literals) scanned
 * on the default ports only: https on 443 and http on 80. Its ownership is
 * proved by a DNS TXT record, so an IP address can never be a DNS target.
 *
 * A lab target is one exact loopback origin listed in the server's lab
 * configuration. It never goes through DNS and is only usable in lab mode.
 */

export interface DnsTarget {
  kind: "dns";
  /** Lower-case ASCII (Punycode) host name. */
  hostname: string;
  /** Unicode form for display only. */
  displayHostname: string;
}

export interface LabTarget {
  kind: "lab";
  /** Exact origin, e.g. http://127.0.0.1:8081. */
  origin: string;
  hostname: string;
  displayHostname: string;
  address: string;
  family: AddressFamily;
  port: number;
}

export type ScanTarget = DnsTarget | LabTarget;

export type TargetRejection =
  | "invalid-input"
  | "invalid-characters"
  | "unsupported-scheme"
  | "invalid-url"
  | "credentials-not-allowed"
  | "path-not-allowed"
  | "port-not-allowed"
  | "ip-literal-not-allowed"
  | "trailing-dot"
  | "invalid-hostname"
  | "special-use-hostname";

export type TargetVerdict = { ok: true; target: DnsTarget } | { ok: false; reason: TargetRejection };

const MAX_INPUT_LENGTH = 2048;

/**
 * Special-use and internal-only names (RFC 6761, RFC 6762, RFC 8375, RFC 9476 and
 * the reserved .internal TLD), plus common undelegated internal suffixes. These
 * never name a public website and are refused outright.
 */
const SPECIAL_USE_SUFFIXES = [
  "localhost",
  "local",
  "internal",
  "home.arpa",
  "arpa",
  "invalid",
  "test",
  "onion",
  "alt",
  "lan",
  "home",
  "corp",
  "intranet",
  "private",
];

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function isValidHostname(hostname: string): boolean {
  if (hostname.length === 0 || hostname.length > 253) return false;
  const labels = hostname.split(".");
  if (labels.length < 2) return false;
  for (const label of labels) {
    if (!LABEL.test(label)) return false;
    // "??--" is reserved for IDNA; only well-formed xn-- (Punycode) labels are accepted.
    if (label.slice(2, 4) === "--") {
      if (!label.startsWith("xn--") || domainToUnicode(label) === "") return false;
    }
  }
  // A numeric last label would make the name parse as an IPv4 address.
  return !/^\d+$/.test(labels[labels.length - 1]!);
}

function isSpecialUse(hostname: string): boolean {
  return SPECIAL_USE_SUFFIXES.some((suffix) => hostname === suffix || hostname.endsWith(`.${suffix}`));
}

/**
 * Normalizes user input ("example.com" or "https://example.com/") to a DNS
 * target, or explains why it is refused. Paths, queries, fragments, ports other
 * than the scheme's default, credentials and IP addresses in any notation are
 * all refused; internationalized names are converted to Punycode by the WHATWG
 * URL parser and then validated label by label.
 */
export function normalizeTarget(input: unknown): TargetVerdict {
  if (typeof input !== "string") return { ok: false, reason: "invalid-input" };
  const raw = input.trim();
  if (raw.length === 0 || raw.length > MAX_INPUT_LENGTH) return { ok: false, reason: "invalid-input" };
  // Whitespace, control characters and backslashes change how URLs are parsed.
  if (/[\s\u0000-\u001f\u007f\\]/.test(raw)) return { ok: false, reason: "invalid-characters" };

  const hasScheme = /^[a-z][a-z0-9+.-]*:/i.test(raw);
  const withScheme = hasScheme ? raw : `https://${raw}`;
  const parts = /^(https?):\/\/([^/?#]*)(.*)$/is.exec(withScheme);
  if (!parts) return { ok: false, reason: hasScheme && !/^https?:/i.test(raw) ? "unsupported-scheme" : "invalid-url" };
  const authority = parts[2]!;
  const rest = parts[3]!;
  if (authority.includes("@")) return { ok: false, reason: "credentials-not-allowed" };
  if (authority.startsWith("[")) return { ok: false, reason: "ip-literal-not-allowed" };
  if (rest !== "" && rest !== "/") return { ok: false, reason: "path-not-allowed" };

  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return { ok: false, reason: "invalid-url" };
  }
  if (url.username !== "" || url.password !== "") return { ok: false, reason: "credentials-not-allowed" };
  // The URL parser drops a port equal to the scheme's default, so any port left is refused.
  if (url.port !== "") return { ok: false, reason: "port-not-allowed" };

  const hostname = url.hostname;
  if (hostname.endsWith(".")) return { ok: false, reason: "trailing-dot" };
  // The URL parser turns decimal, octal and hex IPv4 forms into dotted quads, so
  // any IP-shaped result means the input was an address in some notation.
  if (isIP(hostname) !== 0 || hostname.startsWith("[")) return { ok: false, reason: "ip-literal-not-allowed" };
  if (!isValidHostname(hostname)) return { ok: false, reason: "invalid-hostname" };
  if (isSpecialUse(hostname)) return { ok: false, reason: "special-use-hostname" };
  const displayHostname = domainToUnicode(hostname);
  if (displayHostname === "") return { ok: false, reason: "invalid-hostname" };
  return { ok: true, target: { kind: "dns", hostname, displayHostname } };
}

/** True when a URL stays inside a DNS target's scope: same host, default port, http or https. */
export function isInDnsScope(url: URL, target: DnsTarget): boolean {
  return (
    (url.protocol === "https:" || url.protocol === "http:") &&
    url.hostname === target.hostname &&
    url.port === "" &&
    url.username === "" &&
    url.password === ""
  );
}

/** Ports AgentShield itself uses by default; a lab origin may not point at them. */
const RESERVED_LAB_PORTS = new Set([4000, 5173]);

/** The only ports a lab origin may use (the lab in labs/passive-scan uses 8081 and 8082). */
export const LAB_PORT_MIN = 8080;
export const LAB_PORT_MAX = 8099;

/**
 * Parses one configured lab origin. Only plain-HTTP loopback IP origins with an
 * explicit port from 8080 to 8099 are accepted: http://127.0.0.1:PORT or
 * http://[::1]:PORT. Reserved ports (AgentShield's own) are refused even in range.
 */
export function parseLabOrigin(text: string, reservedPorts: ReadonlySet<number> = RESERVED_LAB_PORTS): LabTarget | null {
  const match = /^http:\/\/(127\.0\.0\.1|\[::1\]):(\d{4})$/.exec(text.trim());
  if (!match) return null;
  const port = Number(match[2]);
  if (port < LAB_PORT_MIN || port > LAB_PORT_MAX || reservedPorts.has(port)) return null;
  const hostname = match[1]!;
  const address = hostname === "[::1]" ? "::1" : hostname;
  if (!(parseIPv4(address) ?? parseIPv6(address))) return null;
  const origin = `http://${hostname}:${port}`;
  return { kind: "lab", origin, hostname, displayHostname: `${hostname}:${port} (lab)`, address, family: address === "::1" ? 6 : 4, port };
}

/** True when a URL stays inside a lab target's scope: exactly the configured origin. */
export function isInLabScope(url: URL, target: LabTarget): boolean {
  return url.origin === target.origin && url.username === "" && url.password === "";
}

export function isInScope(url: URL, target: ScanTarget): boolean {
  return target.kind === "dns" ? isInDnsScope(url, target) : isInLabScope(url, target);
}
