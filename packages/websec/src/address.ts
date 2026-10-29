import { isIPv6 } from "node:net";

/**
 * SSRF address guard (M1). Every address a target name resolves to must pass
 * classifyAddress before any connection is made; if any one is blocked, the
 * whole resolution is refused (classifyResolution). Parsing is strict and done
 * here, not by the URL parser, so alternative IP notations cannot slip through.
 */

export type AddressFamily = 4 | 6;

export interface ResolvedAddress {
  address: string;
  family: AddressFamily;
}

export type BlockReason =
  | "malformed"
  | "unspecified"
  | "loopback"
  | "private"
  | "link-local"
  | "carrier-grade-nat"
  | "multicast"
  | "reserved"
  | "benchmarking"
  | "documentation"
  | "cloud-metadata"
  | "ipv4-mapped"
  | "ipv4-compatible"
  | "nat64-local"
  | "6to4"
  | "discard";

export type AddressVerdict = { allowed: true; family: AddressFamily } | { allowed: false; reason: BlockReason };

/** Strict dotted quad: exactly four decimal octets, no leading zeros, no other notation. */
export function parseIPv4(text: string): number[] | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  const bytes: number[] = [];
  for (const part of parts) {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) return null;
    const value = Number(part);
    if (value > 255) return null;
    bytes.push(value);
  }
  return bytes;
}

/** The 16 bytes of an IPv6 address, or null (zone ids such as %eth0 are refused). */
export function parseIPv6(text: string): number[] | null {
  if (text.includes("%") || !isIPv6(text)) return null;
  let normalized = text.toLowerCase();
  const lastColon = normalized.lastIndexOf(":");
  const tail = normalized.slice(lastColon + 1);
  if (tail.includes(".")) {
    const v4 = parseIPv4(tail);
    if (!v4) return null;
    const high = ((v4[0]! << 8) | v4[1]!).toString(16);
    const low = ((v4[2]! << 8) | v4[3]!).toString(16);
    normalized = `${normalized.slice(0, lastColon + 1)}${high}:${low}`;
  }
  const halves = normalized.split("::");
  if (halves.length > 2) return null;
  const groupsOf = (part: string) => (part === "" ? [] : part.split(":"));
  const left = groupsOf(halves[0]!);
  const right = halves.length === 2 ? groupsOf(halves[1]!) : [];
  const missing = 8 - left.length - right.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const groups = [...left, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...right];
  const bytes: number[] = [];
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    const value = Number.parseInt(group, 16);
    bytes.push(value >> 8, value & 0xff);
  }
  return bytes.length === 16 ? bytes : null;
}

interface Range {
  bytes: number[];
  bits: number;
  reason: BlockReason;
}

function range(cidr: string, reason: BlockReason): Range {
  const [address, bits] = cidr.split("/") as [string, string];
  const bytes = parseIPv4(address) ?? parseIPv6(address);
  if (!bytes) throw new Error(`invalid built-in range ${cidr}`);
  return { bytes, bits: Number(bits), reason };
}

function inRange(bytes: number[], r: Range): boolean {
  for (let i = 0; i < r.bits; i += 1) {
    const mask = 0x80 >> (i & 7);
    if ((bytes[i >> 3]! & mask) !== (r.bytes[i >> 3]! & mask)) return false;
  }
  return true;
}

/** IANA IPv4 special-purpose ranges plus well-known cloud metadata endpoints. First match wins. */
const IPV4_BLOCKED: Range[] = [
  range("169.254.169.254/32", "cloud-metadata"), // AWS, GCP, Azure, OCI and others
  range("168.63.129.16/32", "cloud-metadata"), // Azure platform (WireServer)
  range("100.100.100.200/32", "cloud-metadata"), // Alibaba Cloud
  range("0.0.0.0/8", "unspecified"),
  range("10.0.0.0/8", "private"),
  range("100.64.0.0/10", "carrier-grade-nat"),
  range("127.0.0.0/8", "loopback"),
  range("169.254.0.0/16", "link-local"),
  range("172.16.0.0/12", "private"),
  range("192.0.0.0/24", "reserved"),
  range("192.0.2.0/24", "documentation"),
  range("192.31.196.0/24", "reserved"),
  range("192.52.193.0/24", "reserved"),
  range("192.88.99.0/24", "reserved"),
  range("192.168.0.0/16", "private"),
  range("192.175.48.0/24", "reserved"),
  range("198.18.0.0/15", "benchmarking"),
  range("198.51.100.0/24", "documentation"),
  range("203.0.113.0/24", "documentation"),
  range("224.0.0.0/4", "multicast"),
  range("240.0.0.0/4", "reserved"),
];

/** IPv6 special-purpose ranges checked before the global-unicast rule. First match wins. */
const IPV6_BLOCKED: Range[] = [
  range("::/128", "unspecified"),
  range("::1/128", "loopback"),
  range("::ffff:0:0/96", "ipv4-mapped"),
  range("::/96", "ipv4-compatible"),
  range("64:ff9b:1::/48", "nat64-local"),
  range("100::/64", "discard"),
  range("fd00:ec2::254/128", "cloud-metadata"), // AWS instance metadata over IPv6
  range("2001:2::/48", "benchmarking"),
  range("2001::/23", "reserved"), // IETF protocol assignments, including Teredo
  range("2001:db8::/32", "documentation"),
  range("2002::/16", "6to4"),
  range("3fff::/20", "documentation"),
  range("5f00::/16", "reserved"), // SRv6 SIDs
  range("fc00::/7", "private"), // unique local
  range("fe80::/10", "link-local"),
  range("fec0::/10", "private"), // deprecated site-local
  range("ff00::/8", "multicast"),
];

const NAT64_WELL_KNOWN = range("64:ff9b::/96", "reserved");
const GLOBAL_UNICAST = range("2000::/3", "reserved");

function classifyIPv4Bytes(bytes: number[]): AddressVerdict {
  const match = IPV4_BLOCKED.find((r) => inRange(bytes, r));
  return match ? { allowed: false, reason: match.reason } : { allowed: true, family: 4 };
}

function classifyIPv6Bytes(bytes: number[]): AddressVerdict {
  // NAT64 (64:ff9b::/96) carries an IPv4 address in its last 32 bits: judge that address.
  if (inRange(bytes, NAT64_WELL_KNOWN)) {
    const embedded = classifyIPv4Bytes(bytes.slice(12));
    return embedded.allowed ? { allowed: true, family: 6 } : embedded;
  }
  const match = IPV6_BLOCKED.find((r) => inRange(bytes, r));
  if (match) return { allowed: false, reason: match.reason };
  // Anything outside global unicast (2000::/3) is unassigned or reserved space.
  return inRange(bytes, GLOBAL_UNICAST) ? { allowed: true, family: 6 } : { allowed: false, reason: "reserved" };
}

/** Judges one address given in canonical text form (dotted quad, or IPv6 without brackets). */
export function classifyAddress(text: string): AddressVerdict {
  const v4 = parseIPv4(text);
  if (v4) return classifyIPv4Bytes(v4);
  const v6 = parseIPv6(text);
  if (v6) return classifyIPv6Bytes(v6);
  return { allowed: false, reason: "malformed" };
}

export type ResolutionVerdict =
  | { ok: true; addresses: ResolvedAddress[] }
  | { ok: false; reason: "empty" | BlockReason; address?: string };

const MAX_ANSWERS = 32;

/**
 * Judges a resolver answer as a whole. It is refused when it is not a non-empty
 * list of {address, family} entries whose family matches the address, or when
 * any single address is blocked: one private record taints the whole name.
 */
export function classifyResolution(answers: unknown): ResolutionVerdict {
  if (!Array.isArray(answers) || answers.length === 0) return { ok: false, reason: "empty" };
  if (answers.length > MAX_ANSWERS) return { ok: false, reason: "malformed" };
  const addresses: ResolvedAddress[] = [];
  for (const answer of answers as unknown[]) {
    if (typeof answer !== "object" || answer === null) return { ok: false, reason: "malformed" };
    const { address, family } = answer as { address?: unknown; family?: unknown };
    if (typeof address !== "string" || (family !== 4 && family !== 6)) return { ok: false, reason: "malformed" };
    const verdict = classifyAddress(address);
    if (!verdict.allowed) return { ok: false, reason: verdict.reason, address };
    if (verdict.family !== family) return { ok: false, reason: "malformed", address };
    addresses.push({ address, family });
  }
  return { ok: true, addresses };
}
