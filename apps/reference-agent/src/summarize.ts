/**
 * The simulated work (M3-E E6): a deterministic, local, extractive summary. No model, no
 * network. The document is only ever read as text: nothing in it is followed or executed.
 */

export const MAX_SUMMARY_SENTENCES = 3;
export const MAX_SUMMARY_LENGTH = 500;

const INVISIBLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+/gu;

export function summarize(text: string): string {
  const flat = text.replace(INVISIBLE, " ").replace(/\s+/g, " ").trim();
  if (flat.length === 0) return "";
  const sentences = flat.match(/[^.!?]+[.!?]*/g)?.map((s) => s.trim()).filter((s) => s.length > 0) ?? [flat];
  const summary = sentences.slice(0, MAX_SUMMARY_SENTENCES).join(" ");
  return summary.length <= MAX_SUMMARY_LENGTH ? summary : `${summary.slice(0, MAX_SUMMARY_LENGTH - 1).trimEnd()}…`;
}
