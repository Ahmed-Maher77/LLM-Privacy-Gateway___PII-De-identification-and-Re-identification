import type { PIIMatch, PIIType } from './types.js';

export function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Finds whole-word occurrences of caller-supplied values (known names, locations, organizations).
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
    const re = new RegExp(String.raw`\b${escapeRegex(trimmed)}\b`, 'g');
    for (const m of text.matchAll(re)) {
      matches.push({
        type,
        value: m[0],
        start: m.index,
        end: m.index + m[0].length,
        method: 'rule',
        confidence: 0.99,
      });
    }
  }
  return matches;
}
