import { describe, expect, it, vi } from "vitest";
import { scanUntrustedContent } from "./scan.js";

/**
 * Safeguards for releasing a matched rule's own words from separated-text
 * evidence (Design B3, ruleWordRanges). The rule list is extended, for this
 * file only, with hypothetical future rules a rule edit could introduce: free
 * text that is not a [^.\n]{0,N} gap, the regex d flag, named groups that
 * could collide with the gap groups, a gap the pattern cannot be rebuilt
 * around, backreferences, and gaps inside quantified groups or lookarounds,
 * whose text the match indices cannot locate. Each must fail safely: scanning
 * never throws, and no word that
 * cannot be verified as the rule's own is released from redaction. Real rules
 * are unchanged; every value here is synthetic.
 */
vi.mock("./rules.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./rules.js")>();
  const template = actual.SCANNER_RULES.find((rule) => rule.ruleId === "injection.unauthorized-tool-action");
  if (!template) throw new Error("missing template rule");
  const hypothetical = (name: string, pattern: RegExp) => ({ ...template, ruleId: `test.${name}`, patterns: [pattern] });
  return {
    ...actual,
    SCANNER_RULES: [
      ...actual.SCANNER_RULES,
      hypothetical("unicode-class-gap", /\b(purge)\b[\p{L}\d\s]{0,50}\b(files)\b/iu),
      hypothetical("unicode-property", /\b(scrub)\b\s+\p{L}+\s+\p{L}+\s+\b(files)\b/iu),
      hypothetical("d-flag", /\b(shred)\b[^.\n]{0,50}\b(files)\b/id),
      hypothetical("named-group-gap0", /\b(?<gap0>wipeout)\b[^.\n]{0,50}\b(files)\b/i),
      hypothetical("named-group-b3gap0", /\b(?<b3gap0>obliterate)\b[^.\n]{0,50}\b(files)\b/i),
      // The gap sits inside a character class, so the pattern cannot be rebuilt with the gap captured.
      hypothetical("gap-inside-class", /\b(expunge)\b[x [^.\n]{0,40}\b(files)\b/i),
      // Backreferences: they repeat captured text (a gap's included) outside the gap.
      hypothetical("named-backreference", /\b(nuke)\b(?<x>[^.\n]{0,40})\b(files)\b\k<x>/i),
      hypothetical("numbered-backreference", /\b(zap)\b([^.\n]{0,40})\b(files)\b\2/i),
      // Inserted gap groups shift capture numbers, so \2 would point at a gap once the pattern is rebuilt.
      hypothetical("shifted-backreference", /\b(trash)\b[^.\n]{0,50}\b(files)\b\s*\2/i),
      hypothetical("unmatched-backreference", /\b(torch)\b[^.\n]{0,50}\b(files)\b\s+\1/i),
      // Gaps inside quantified groups: the match indices give only the last iteration.
      hypothetical("repeated-gap-plus", /\b(blast)\b(?:\s[^.\n]{0,4})+\s(files)\b/i),
      hypothetical("repeated-gap-star", /\b(scour)\b(?:\s[^.\n]{0,4})*\s(files)\b/i),
      hypothetical("repeated-gap-bounded", /\b(strip)\b(?:\s[^.\n]{0,4}){1,6}\s(files)\b/i),
      hypothetical("repeated-gap-exact", /\b(raze)\b(?:\s[^.\n]{0,4}){5}\s(files)\b/i),
      hypothetical("nested-quantified-gap", /\b(sweep)\b(?:(?:\s[^.\n]{0,4})+)?\s(files)\b/i),
      hypothetical("optional-in-repeated-gap", /\b(flush)\b(?:\s(?:[^.\n]{0,4})?)+\s(files)\b/i),
      hypothetical("optional-gap", /\b(dump)\b(?:[^.\n]{0,40})?\b(files)\b/i),
      hypothetical("lookahead-gap", /\b(drop)\b(?=[^.\n]{0,40}files)[^.\n]{0,40}\b(files)\b/i),
    ],
  };
});

const ZWSP = String.fromCodePoint(0x200b);
const glue = (...parts: string[]): string => parts.join(ZWSP);
/** A fake token alternating letters and digits, built at runtime. */
const TOKEN = Array.from({ length: 16 }, (_, i) => (i % 2 === 0 ? "abcdefgh".charAt(i / 2) : String((i * 7) % 10))).join("");
const evidenceOf = (text: string, ruleId: string): string | undefined =>
  scanUntrustedContent(text).findings.find((finding) => finding.ruleId === ruleId)?.evidence;
const tokenPieces = Array.from({ length: TOKEN.length - 2 }, (_, i) => TOKEN.slice(i, i + 3));
const holdsUnverifiedWord = (evidence: string): boolean => ["QzvK", "Wqzt", ...tokenPieces].some((piece) => evidence.includes(piece));

describe("Design B3 safeguards: hypothetical rules fail safely", () => {
  it.each([
    ["unicode-class-gap", glue("PuRgE", "QzvK", TOKEN, "FiLeS", "now.")],
    ["unicode-property", glue("ScRuB", "QzvK", "Wqzt", "FiLeS", "12345", "now.")],
    ["d-flag", glue("ShReD", "QzvK", TOKEN, "FiLeS", "now.")],
    ["named-group-gap0", glue("WiPeOuT", "QzvK", TOKEN, "FiLeS", "now.")],
    ["named-group-b3gap0", glue("ObLiTeRaTe", "QzvK", TOKEN, "FiLeS", "now.")],
    ["gap-inside-class", glue("ExPuNgE", "x", "FiLeS", "12345", "now.")],
  ])("%s: scanning does not throw, the rule fires, and no unverified word is released", (name, text) => {
    expect(() => scanUntrustedContent(text)).not.toThrow();
    const evidence = evidenceOf(text, `test.${name}`);
    expect(evidence, "the hypothetical rule fires").toBeDefined();
    expect(holdsUnverifiedWord(evidence ?? "")).toBe(false);
  });

  it("free text other than a [^.\\n]{0,N} gap (Unicode properties): no words are released at all", () => {
    // The rule's words cannot be told from its free text, so even the verb stays redacted with the
    // credential-shaped run it is glued to, rather than releasing "QzvK" and "Wqzt" as rule words.
    expect(evidenceOf(glue("PuRgE", "QzvK", TOKEN, "FiLeS", "now."), "test.unicode-class-gap")).toBe("[REDACTED] now.");
    expect(evidenceOf(glue("ScRuB", "QzvK", "Wqzt", "FiLeS", "12345", "now."), "test.unicode-property")).toBe("[REDACTED] now.");
  });

  it("the d flag and named groups that would collide: the rule's own words are still released, its gap is not", () => {
    expect(evidenceOf(glue("ShReD", "QzvK", TOKEN, "FiLeS", "now."), "test.d-flag")).toBe("ShReD [REDACTED] FiLeS now.");
    expect(evidenceOf(glue("WiPeOuT", "QzvK", TOKEN, "FiLeS", "now."), "test.named-group-gap0")).toBe("WiPeOuT [REDACTED] FiLeS now.");
    expect(evidenceOf(glue("ObLiTeRaTe", "QzvK", TOKEN, "FiLeS", "now."), "test.named-group-b3gap0")).toBe(
      "ObLiTeRaTe [REDACTED] FiLeS now.",
    );
  });

  it("a rule that cannot be rebuilt falls back to conservative redaction, while a rebuildable one releases its words", () => {
    // Same shape of input: a mixed-case verb, a one-letter gap, "files", and a number glued on.
    expect(evidenceOf(glue("ExPuNgE", "x", "FiLeS", "12345", "now."), "test.gap-inside-class")).toBe("[REDACTED] now.");
    expect(evidenceOf(glue("ShReD", "x", "FiLeS", "12345", "now."), "test.d-flag")).toMatch(/^ShReD /);
  });

  // Gap content repeated with an invisible separator between pieces: "QzvK" is a mixed-case piece that
  // must never be released, the digit pieces belong to the fake token.
  const pieces = ["QzvK", "a7b1", "c4d9", "e3f6", "g2h8"];
  it.each([
    ["named-backreference", glue("NuKe", TOKEN, "QzvK", "FiLeS", TOKEN, "QzvK", "now.")],
    ["numbered-backreference", glue("ZaP", TOKEN, "QzvK", "FiLeS", TOKEN, "QzvK", "now.")],
    ["shifted-backreference", glue("TrAsH", "QzvK", TOKEN, "FiLeS", "FiLeS", "now.")],
    ["repeated-gap-plus", glue("BlAsT", ...pieces, "FiLeS", "now.")],
    ["repeated-gap-star", glue("ScOuR", ...pieces, "FiLeS", "now.")],
    ["repeated-gap-bounded", glue("StRiP", ...pieces, "FiLeS", "now.")],
    ["repeated-gap-exact", glue("RaZe", ...pieces, "FiLeS", "now.")],
    ["nested-quantified-gap", glue("SwEeP", ...pieces, "FiLeS", "now.")],
    ["optional-in-repeated-gap", glue("FlUsH", ...pieces, "FiLeS", "now.")],
    ["optional-gap", glue("DuMp", "QzvK", TOKEN, "FiLeS", "now.")],
    ["lookahead-gap", glue("DrOp", "QzvK", TOKEN, "FiLeS", "now.")],
  ])("%s: the gap cannot be mapped, so no word is released and the evidence stays conservative", (name, text) => {
    expect(() => scanUntrustedContent(text)).not.toThrow();
    const evidence = evidenceOf(text, `test.${name}`);
    expect(evidence, "the hypothetical rule fires").toBeDefined();
    expect(evidence).toBe("[REDACTED] now.");
    expect(holdsUnverifiedWord(evidence ?? "")).toBe(false);
  });

  it("a backreference that does not match: the rule does not fire and scanning does not throw", () => {
    for (const text of [glue("ToRcH", "QzvK", TOKEN, "FiLeS", "now."), glue("torch", "the", "files", "torch"), "torch the files torch"]) {
      expect(() => scanUntrustedContent(text)).not.toThrow();
    }
    expect(evidenceOf(glue("ToRcH", "QzvK", TOKEN, "FiLeS", "now."), "test.unmatched-backreference")).toBeUndefined();
  });

  it("scanning never throws for any hypothetical rule, matched or not, plain or invisible-separated", () => {
    const verbs = ["purge", "scrub", "shred", "wipeout", "obliterate", "expunge", "nuke", "zap", "trash", "torch", "blast", "scour", "strip", "raze", "sweep", "flush", "dump", "drop"];
    for (const verb of verbs) {
      for (const text of [`${verb} the files now.`, glue(verb.toUpperCase(), "the", "files", "now."), glue(verb, "x", "files"), `${verb}${ZWSP}`, ZWSP]) {
        expect(() => scanUntrustedContent(text), text).not.toThrow();
      }
    }
  });
});
