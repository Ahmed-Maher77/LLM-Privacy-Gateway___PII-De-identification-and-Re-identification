import type { PIIMatch } from './types.js';
import { KNOWN_VALUE_CONFIDENCE } from './exact-match.js';

/**
 * Returns character offset ranges where heuristic (non-deterministic) entities
 * (PERSON, LOCATION, ORGANIZATION) must be suppressed to protect document structure.
 *
 * Protected zones include:
 * 1. Bracketed markers like `[START OF TRANSCRIPT]`, `[END OF TRANSCRIPT]`
 * 2. Line-leading speaker or metadata labels like `Agent:`, `User:`, `Date:`, `Source:`
 *
 * IMPORTANT: These ranges must NEVER suppress deterministic data types
 * (EMAIL, PHONE, SSN, CREDIT_CARD, ADDRESS, IP_ADDRESS, URL).
 */
export function getProtectedRanges(text: string): Array<[number, number]> {
  if (!text || typeof text !== 'string') {
    return [];
  }

  const ranges: Array<[number, number]> = [];

  // 1. Bracketed section/structure markers: [START OF TRANSCRIPT], [Req-1], etc.
  const bracketRe = /\[[^\]\n]*\]/g;
  let m: RegExpExecArray | null;
  while ((m = bracketRe.exec(text)) !== null) {
    ranges.push([m.index, m.index + m[0].length]);
  }

  // 2. Line-leading labels: "Agent:", "User:", "Date:", "Source:", "Agent (System):"
  const labelRe = /^[A-Za-z][A-Za-z ()]{0,25}:/gm;
  while ((m = labelRe.exec(text)) !== null) {
    ranges.push([m.index, m.index + m[0].length]);
  }

  return ranges;
}

const HEURISTIC_TYPES = new Set(['PERSON', 'LOCATION', 'ORGANIZATION']);

/**
 * Filters out heuristic entity matches (PERSON, LOCATION, ORGANIZATION)
 * that overlap with protected structural document ranges.
 */
export function applyStructuralGuards(matches: PIIMatch[], text: string): PIIMatch[] {
  if (!matches || matches.length === 0) {
    return [];
  }

  const protectedRanges = getProtectedRanges(text);
  if (protectedRanges.length === 0) {
    return matches;
  }

  return matches.filter((match) => {
    // Deterministic types and caller-supplied known values are never suppressed by
    // structural guards: "John Smith: ..." must still mask a known John Smith.
    if (!HEURISTIC_TYPES.has(match.type)) {
      return true;
    }
    if (match.method === 'rule' && match.confidence === KNOWN_VALUE_CONFIDENCE) {
      return true;
    }

    // Check if heuristic match overlaps any protected range
    const overlaps = protectedRanges.some(
      ([pStart, pEnd]) => match.start < pEnd && match.end > pStart
    );

    return !overlaps;
  });
}
