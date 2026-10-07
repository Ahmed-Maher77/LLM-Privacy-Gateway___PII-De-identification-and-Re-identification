import type { PIIMatch, PIIType } from './types.js';

/** Confidence of a caller-supplied known value: a fact, not a guess. */
export const KNOWN_VALUE_CONFIDENCE = 0.99;

export function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Finds whole-word occurrences of caller-supplied values (known names, locations, organizations).
 * The boundary is "no word character on either side", so values that start or end with
 * punctuation ("Acme Inc.", "@handle") still match.
 */
export function findExactMatches(
  text: string,
  values: readonly string[] | undefined,
  type: PIIType
): PIIMatch[] {
  const matches: PIIMatch[] = [];
  for (const value of values ?? []) {
    const trimmed = value.trim();
    if (!trimmed) continue;
    const re = new RegExp(String.raw`(?<!\w)${escapeRegex(trimmed)}(?!\w)`, 'g');
    for (const m of text.matchAll(re)) {
      matches.push({
        type,
        value: m[0],
        start: m.index,
        end: m.index + m[0].length,
        method: 'rule',
        confidence: KNOWN_VALUE_CONFIDENCE,
      });
    }
  }
  return matches;
}
