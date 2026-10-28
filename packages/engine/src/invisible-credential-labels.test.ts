import { describe, expect, it } from "vitest";
import { evaluateAction } from "./evaluate.js";
import { getScenario } from "./scenarios.js";
import { detectOutboundSecret, MAX_OUTBOUND_FIELD_LENGTH, redactSecretValue } from "./scanner/scan.js";
import type { EvaluationInput } from "./types.js";

/**
 * Outbound credential labels and prefixes split by invisible format
 * characters. The Data-Leak Guard inspects each field as written first and,
 * only when that finds nothing, again with the Phase L invisible format
 * characters removed. Every credential-shaped value is assembled at runtime
 * from clearly fake parts and every invisible character is built from its
 * code point, so this file holds no credential-shaped literal (see
 * scripts/secret-scan.mjs) and no raw invisible character.
 */
const join = (...parts: string[]): string => parts.join("");
const char = (codePoint: number): string => String.fromCharCode(codePoint);
const fake = (seed: string, length: number): string => seed.padEnd(length, "0");
const BACKSLASH = char(92);
const QUOTE = char(34);
const NEWLINE = char(10);
const ZWSP = char(0x200b);
const SOFT_HYPHEN = char(0x00ad);

/** Every code point of the approved set, grouped as in INVISIBLE_FORMAT_CHARACTERS. */
const GROUPS: [string, number[]][] = [
  ["U+00AD", [0x00ad]],
  ["U+180E", [0x180e]],
  ["U+200B-U+200F", [0x200b, 0x200c, 0x200d, 0x200e, 0x200f]],
  ["U+202A-U+202E", [0x202a, 0x202b, 0x202c, 0x202d, 0x202e]],
  ["U+2060-U+2064", [0x2060, 0x2061, 0x2062, 0x2063, 0x2064]],
  ["U+2066-U+2069", [0x2066, 0x2067, 0x2068, 0x2069]],
  ["U+FEFF", [0xfeff]],
];
const hex = (codePoint: number): string => `U+${codePoint.toString(16).toUpperCase().padStart(4, "0")}`;
const CODE_POINTS = GROUPS.flatMap(([group, points]) => points.map((point) => ({ group, point })));

const PEM_BODY = "FAKEinvisLabelKeyMaterial0123456789abcdefFAKE";

/**
 * [family, text before the split point, text after it, expected kind, marker].
 * The split point is inside the label or prefix. The marker is part of the
 * value and must never be echoed in a result.
 */
const FAMILIES: [string, string, string, string, string][] = [
  ["strong label", "api", "_key=fakeInvisStrongValue2026", "labelled-secret-assignment", "fakeInvisStrongValue2026"],
  ["weak label", "to", "ken: fakeInvisWeakValue2026", "labelled-secret-assignment", "fakeInvisWeakValue2026"],
  [
    "JSON key",
    join("{", QUOTE, "api"),
    join("_key", QUOTE, ": ", QUOTE, "fakeInvisJsonValue2026", QUOTE, "}"),
    "labelled-secret-assignment",
    "fakeInvisJsonValue2026",
  ],
  [
    "escaped-JSON key (Phase G)",
    join("{", BACKSLASH, QUOTE, "pass"),
    join("word", BACKSLASH, QUOTE, ": ", BACKSLASH, QUOTE, "fakeInvisEscapedValue2026", BACKSLASH, QUOTE, "}"),
    "labelled-secret-assignment",
    "fakeInvisEscapedValue2026",
  ],
  ["Bearer", "Bea", "rer fakeInvisBearerValue2026", "bearer-token", "fakeInvisBearerValue2026"],
  ["sk- token", "s", "k-proj-fakeInvisSkValue2026", "sk-style-token", "fakeInvisSkValue2026"],
  ["GitHub (Phase H)", "gh", join("p_", fake("fakeInvisGithubBody", 36)), "github-token", "fakeInvisGithubBody"],
  ["GitLab (Phase H)", "gl", join("pat-", fake("fakeInvisGitlabBody", 20)), "gitlab-token", "fakeInvisGitlabBody"],
  ["AWS (Phase H)", "AK", join("IA", fake("FAKEINVISAWS", 16)), "aws-access-key-id", "FAKEINVISAWS"],
  ["Stripe live (Phase H)", "sk_", join("live_", fake("fakeInvisStripeBody", 24)), "stripe-live-key", "fakeInvisStripeBody"],
  ["Slack (Phase H)", "xo", "xb-000000000001-fakeInvisSlackBody9", "slack-token", "fakeInvisSlackBody9"],
  ["Google (Phase H)", "AI", join("za", fake("FakeInvisGoogleBody", 35)), "google-api-key", "FakeInvisGoogleBody"],
  [
    "PEM private key (Phase H)",
    "-----BEGIN RSA PRIV",
    join("ATE KEY-----", NEWLINE, PEM_BODY, NEWLINE, "-----END RSA PRIV", "ATE KEY-----"),
    "private-key-block",
    PEM_BODY,
  ],
  ["seeded fake secret", "FAKE_", "INVIS_LABEL_SECRET_1", "seeded-fake-secret", "INVIS_LABEL_SECRET_1"],
  ["email address", "user.fakeinvis", "@example.com", "email-address", "user.fakeinvis"],
];

const scenario = (() => {
  const found = getScenario("benign-summary");
  if (!found) throw new Error("missing scenario");
  return found;
})();

/** Every decision-inspected field, with the intent adjusted so only the Data-Leak Guard can BLOCK. */
const FIELDS = ["summary", "payload value", "payload key", "destination", "tool", "type"] as const;
function inputFor(field: (typeof FIELDS)[number], value: string): EvaluationInput {
  const { intent, action } = scenario;
  switch (field) {
    case "summary":
      return { intent, action: { ...action, summary: value } };
    case "payload value":
      return { intent, action: { ...action, payload: { note: value } } };
    case "payload key":
      return { intent, action: { ...action, payload: { [value]: "x" } } };
    case "destination":
      return { intent: { ...intent, allowedDestinations: [value] }, action: { ...action, destination: value } };
    case "tool":
      return { intent, action: { ...action, tool: value } };
    case "type":
      return { intent: { ...intent, allowedActions: [value] }, action: { ...action, type: value } };
  }
}

describe("Data-Leak Guard: credential labels split by invisible format characters", () => {
  it.each(FAMILIES)("%s: every approved code point inside the label or prefix keeps the unsplit kind", (_family, before, after, kind) => {
    expect(detectOutboundSecret("action.summary", join(before, after))?.kind).toBe(kind);
    for (const { group, point } of CODE_POINTS) {
      const split = join(before, char(point), after);
      expect(detectOutboundSecret("action.summary", split)?.kind, `${group} ${hex(point)}`).toBe(kind);
      expect(redactSecretValue(split), `${group} ${hex(point)}`).toBe("[REDACTED]");
    }
  });

  it.each(FIELDS)("%s: a split label is a hard BLOCK with the unsplit finding and is never echoed", (field) => {
    for (const [family, before, after, , marker] of FAMILIES) {
      const unsplit = evaluateAction(inputFor(field, join(before, after)));
      const split = evaluateAction(inputFor(field, join(before, ZWSP, after)));
      expect(split.decision, family).toBe("BLOCK");
      expect(split.findings.at(-1)?.ruleId, family).toBe("data-leak.outbound-secret");
      expect(split.findings.at(-1)?.evidence, family).toBe(unsplit.findings.at(-1)?.evidence);
      expect(JSON.stringify(split), family).not.toContain(marker);
    }
  });

  it("a value detected as written stays detected even when removal would shorten it below the minimum", () => {
    // Three zero-width spaces make the raw value 8 characters (6+ blocks); without them it is 5.
    const padded = join("password=ab", ZWSP, "c", ZWSP, "d", ZWSP, "e");
    expect(detectOutboundSecret("action.summary", padded)?.kind).toBe("labelled-secret-assignment");
    expect(detectOutboundSecret("action.summary", "password=abcde")).toBeNull();
    expect(evaluateAction(inputFor("summary", padded)).decision).toBe("BLOCK");
  });

  it("a match on the field as written is returned unchanged, before any normalized match", () => {
    // As written only the Bearer credential matches; with the zero-width space removed the
    // labelled assignment would be reported first, because labelled detection runs first.
    const text = join("Bea", "rer fakeInvisPrecedence2026 and api", ZWSP, "_key=fakeInvisPrecedence2027");
    expect(detectOutboundSecret("action.summary", text)?.kind).toBe("bearer-token");
    expect(detectOutboundSecret("action.summary", text.split(ZWSP).join(""))?.kind).toBe("labelled-secret-assignment");
  });

  it("field order is unchanged: an earlier field with a split label is reported before a later raw match", () => {
    const split = join("api", ZWSP, "_key=fakeInvisOrder2026");
    const raw = "api_key=fakeInvisOrder2027";
    const summaryFirst = evaluateAction({ intent: scenario.intent, action: { ...scenario.action, summary: split, tool: raw } });
    expect(summaryFirst.findings.at(-1)?.evidence).toBe("field=action.summary; pattern=labelled-secret-assignment; value=[REDACTED]");
    const payloadFirst = evaluateAction({
      intent: { ...scenario.intent, allowedDestinations: [raw] },
      action: { ...scenario.action, payload: { note: split }, destination: raw },
    });
    expect(payloadFirst.findings.at(-1)?.evidence).toBe("field=action.payload.value[0]; pattern=labelled-secret-assignment; value=[REDACTED]");
  });

  it("the 8,000-character bound applies to the raw field, before normalization", () => {
    const split = join("api", ZWSP, "_key=fakeInvisBound2026");
    const inside = join(ZWSP.repeat(MAX_OUTBOUND_FIELD_LENGTH - split.length), split);
    expect(inside.length).toBe(MAX_OUTBOUND_FIELD_LENGTH);
    expect(detectOutboundSecret("action.summary", inside)?.kind).toBe("labelled-secret-assignment");
    // One raw character over the bound: uninspectable, although the normalized text is short.
    expect(detectOutboundSecret("action.summary", join(ZWSP, inside))?.kind).toBe("field-too-long-to-inspect");
    expect(detectOutboundSecret("action.summary", join(ZWSP.repeat(MAX_OUTBOUND_FIELD_LENGTH), "x"))?.kind).toBe("field-too-long-to-inspect");
  });

  it("benign near-misses with invisible characters keep their decision and are not redacted", () => {
    const hebrewPeace = [0x05e9, 0x05dc, 0x05d5, 0x05dd].map(char).join("");
    const BENIGN = [
      join("Follow the pass", SOFT_HYPHEN, "word reset guide on the intranet."),
      join("The api", ZWSP, "_key field is required in the form."),
      join("to", ZWSP, "ken: 42"),
      join("Bear", SOFT_HYPHEN, "er bond terms are attached."),
      join("s", ZWSP, "k-learn-pipeline docs"),
      join("se", ZWSP, "cret: false"),
      join("AK", ZWSP, "IAWORDSONLYTEXT"),
      join(char(0xfeff), "Quarterly report: revenue grew by four percent."),
      join("The Hebrew word ", hebrewPeace, char(0x200f), " means peace."),
      join("Meeting notes from ", char(0x2068), "Dana", char(0x2069), " are attached."),
    ];
    for (const text of BENIGN) {
      expect(detectOutboundSecret("action.summary", text), text).toBeNull();
      expect(redactSecretValue(text), text).toBe(text);
      expect(evaluateAction(inputFor("summary", text)).decision, text).toBe("ALLOW");
      expect(evaluateAction(inputFor("tool", text)).decision, text).toBe("ALLOW");
    }
  });

  it("public metadata redaction hides split values in tool, type, and task; task decisions are unchanged", () => {
    const marker = "fakeInvisMetadata2026";
    const split = join("simulated.api", ZWSP, "_key=", marker);
    expect(redactSecretValue(split)).toBe("[REDACTED]");
    const typed = evaluateAction(inputFor("type", split));
    expect(typed.actionType).toBe("[REDACTED]");
    expect(JSON.stringify(typed)).not.toContain(marker);
    // intent.task is never inspected for decisions: the same decision as a benign task.
    const withTask = evaluateAction({ intent: { ...scenario.intent, task: split }, action: scenario.action });
    const benignTask = evaluateAction({ intent: { ...scenario.intent, task: "Summarize the document" }, action: scenario.action });
    expect(withTask.decision).toBe("ALLOW");
    expect(withTask.decision).toBe(benignTask.decision);
    expect(withTask.findings.map((f) => f.ruleId)).toEqual(benignTask.findings.map((f) => f.ruleId));
  });
});
