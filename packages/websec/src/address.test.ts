import { describe, expect, it } from "vitest";
import { classifyAddress, classifyResolution, parseIPv4, parseIPv6 } from "./address.js";

describe("SSRF address guard: classifyAddress", () => {
  const blocked: Array<[string, string]> = [
    // IPv4 special-purpose ranges
    ["0.0.0.0", "unspecified"],
    ["0.1.2.3", "unspecified"],
    ["10.0.0.1", "private"],
    ["10.255.255.255", "private"],
    ["100.64.0.1", "carrier-grade-nat"],
    ["100.127.255.254", "carrier-grade-nat"],
    ["127.0.0.1", "loopback"],
    ["127.255.255.254", "loopback"],
    ["169.254.0.1", "link-local"],
    ["169.254.169.254", "cloud-metadata"],
    ["168.63.129.16", "cloud-metadata"],
    ["100.100.100.200", "cloud-metadata"],
    ["172.16.0.1", "private"],
    ["172.31.255.255", "private"],
    ["192.0.0.8", "reserved"],
    ["192.0.2.10", "documentation"],
    ["192.88.99.1", "reserved"],
    ["192.168.1.1", "private"],
    ["198.18.0.1", "benchmarking"],
    ["198.19.255.255", "benchmarking"],
    ["198.51.100.7", "documentation"],
    ["203.0.113.9", "documentation"],
    ["224.0.0.1", "multicast"],
    ["239.255.255.250", "multicast"],
    ["240.0.0.1", "reserved"],
    ["255.255.255.255", "reserved"],
    // IPv6 special-purpose ranges
    ["::", "unspecified"],
    ["::1", "loopback"],
    ["0:0:0:0:0:0:0:1", "loopback"],
    ["::ffff:127.0.0.1", "ipv4-mapped"],
    ["::ffff:8.8.8.8", "ipv4-mapped"],
    ["::ffff:7f00:1", "ipv4-mapped"],
    ["::127.0.0.1", "ipv4-compatible"],
    ["64:ff9b::7f00:1", "loopback"],
    ["64:ff9b::169.254.169.254", "cloud-metadata"],
    ["64:ff9b::a00:1", "private"],
    ["64:ff9b:1::1", "nat64-local"],
    ["100::1", "discard"],
    ["fd00:ec2::254", "cloud-metadata"],
    ["2001::1", "reserved"],
    ["2001:2::1", "benchmarking"],
    ["2001:db8::1", "documentation"],
    ["2002:7f00:1::1", "6to4"],
    ["3fff::1", "documentation"],
    ["5f00::1", "reserved"],
    ["fc00::1", "private"],
    ["fd12:3456::1", "private"],
    ["fe80::1", "link-local"],
    ["febf::1", "link-local"],
    ["fec0::1", "private"],
    ["ff02::1", "multicast"],
    ["4000::1", "reserved"],
    ["1::1", "reserved"],
  ];
  it.each(blocked)("%s is blocked as %s", (address, reason) => {
    expect(classifyAddress(address)).toEqual({ allowed: false, reason });
  });

  const allowed: Array<[string, 4 | 6]> = [
    ["93.184.215.14", 4],
    ["8.8.8.8", 4],
    ["1.1.1.1", 4],
    ["172.15.255.255", 4],
    ["172.32.0.1", 4],
    ["100.63.255.255", 4],
    ["100.128.0.1", 4],
    ["169.253.255.255", 4],
    ["198.17.255.255", 4],
    ["223.255.255.255", 4],
    ["2606:4700:4700::1111", 6],
    ["2a00:1450:4001:80b::200e", 6],
    ["64:ff9b::808:808", 6],
    ["64:ff9b::8.8.8.8", 6],
  ];
  it.each(allowed)("%s is a public IPv%s address", (address, family) => {
    expect(classifyAddress(address)).toEqual({ allowed: true, family });
  });

  // Deliberate bypass attempts: alternative notations must never be read as a public address.
  const malformed = [
    "2130706433", // decimal 127.0.0.1
    "0x7f000001", // hex
    "0x7f.0.0.1",
    "0177.0.0.1", // octal
    "127.1", // short form
    "127.0.1",
    "010.0.0.1", // leading zero
    "1.2.3.256",
    "1.2.3.4.5",
    " 8.8.8.8",
    "8.8.8.8 ",
    "[::1]", // brackets belong to URLs, not addresses
    "fe80::1%eth0", // zone id
    "::1%1",
    "1:2:3:4:5:6:7:8:9",
    "::ffff:127.0.0.01",
    "localhost",
    "",
    "example.com",
    "١٢٧.0.0.1", // non-ASCII digits
  ];
  it.each(malformed)("rejects %j as malformed", (address) => {
    expect(classifyAddress(address)).toEqual({ allowed: false, reason: "malformed" });
  });

  it("parses IPv6 forms consistently, including embedded IPv4 tails", () => {
    expect(parseIPv6("::ffff:127.0.0.1")).toEqual(parseIPv6("::ffff:7f00:1"));
    expect(parseIPv6("0:0:0:0:0:0:0:1")).toEqual(parseIPv6("::1"));
    expect(parseIPv6("1:2:3:4:5:6:7::")).toHaveLength(16);
    expect(parseIPv4("8.8.8.8")).toEqual([8, 8, 8, 8]);
  });
});

describe("SSRF address guard: classifyResolution", () => {
  it("accepts a resolution whose every address is public", () => {
    const answers = [
      { address: "93.184.215.14", family: 4 },
      { address: "2606:2800:21f:cb07:6820:80da:af6b:8b2c", family: 6 },
    ];
    expect(classifyResolution(answers)).toEqual({ ok: true, addresses: answers });
  });

  it("refuses the whole resolution when any one address is blocked", () => {
    expect(
      classifyResolution([
        { address: "93.184.215.14", family: 4 },
        { address: "10.0.0.5", family: 4 },
      ]),
    ).toEqual({ ok: false, reason: "private", address: "10.0.0.5" });
    expect(
      classifyResolution([
        { address: "2606:4700:4700::1111", family: 6 },
        { address: "::ffff:169.254.169.254", family: 6 },
      ]),
    ).toMatchObject({ ok: false, reason: "ipv4-mapped" });
  });

  it("refuses empty, malformed or inconsistent resolver output", () => {
    for (const answers of [
      [],
      null,
      undefined,
      "93.184.215.14",
      [{ address: "93.184.215.14" }],
      [{ address: "93.184.215.14", family: 6 }],
      [{ address: "2606:4700:4700::1111", family: 4 }],
      [{ address: 2130706433, family: 4 }],
      [null],
      Array.from({ length: 33 }, () => ({ address: "8.8.8.8", family: 4 })),
    ]) {
      expect(classifyResolution(answers).ok, JSON.stringify(answers)?.slice(0, 60)).toBe(false);
    }
  });
});
