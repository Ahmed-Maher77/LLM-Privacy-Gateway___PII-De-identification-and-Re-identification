import type { PIIMatch, PersonDetectorOptions } from './types.js';

const NAME = String.raw`[A-Z][a-z]{1,20}(?:\s+(?:[A-Z][a-z]{1,20}|[A-Z]\.)){0,2}`;
const FULL = String.raw`[A-Z][a-z]{1,20}(?:\s+[A-Z]\.)?\s+[A-Z][a-z]{1,20}`;
const AP = String.raw`['’]`; // straight AND curly apostrophe

const ANCHORS = [
  {
    id: 'name-is',
    re: new RegExp(String.raw`[Mm]y name(?:\s+is|${AP}s)\s+(${NAME})`, 'g'),
    confidence: 0.95,
  },
  {
    id: 'self',
    re: new RegExp(String.raw`\b(?:I am|I${AP}m|[Tt]his is)\s+(${NAME})`, 'g'),
    confidence: 0.9,
  },
  {
    id: 'title',
    re: new RegExp(String.raw`\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+(${NAME})`, 'g'),
    confidence: 0.95,
  },
  {
    id: 'greeting',
    re: new RegExp(
      String.raw`\b(?:[Hh]i|[Hh]ello|[Hh]ey|[Dd]ear|[Tt]hanks|[Tt]hank you|[Rr]egards|[Ss]incerely)[,!]?\s+(${NAME})`,
      'g'
    ),
    confidence: 0.85,
  },
  {
    id: 'account',
    re: new RegExp(
      String.raw`\b(?:under|account of|on behalf of|policyholder)\s+(${FULL})`,
      'g'
    ),
    confidence: 0.9,
  },
  {
    id: 'speaking',
    re: new RegExp(String.raw`(${FULL})\s+speaking\b`, 'g'),
    confidence: 0.9,
  },
];

const ROLE_WORDS = new Set([
  'agent',
  'user',
  'system',
  'customer',
  'support',
  'admin',
  'operator',
  'team',
  'bot',
  'assistant',
  'sorry',
  'thanks',
  'yes',
  'no',
]);

/**
 * Validates that candidate name tokens adhere to natural name shape
 * and are not numbers, all-caps markers, or system role labels.
 */
export function isPlausibleName(value: string): boolean {
  const tokens = value.trim().split(/\s+/);
  if (tokens.length > 3 || tokens.length === 0) return false;
  for (const token of tokens) {
    const bare = token.replace(/\.$/, ''); // "T." -> "T"
    if (/\d/.test(bare)) return false; // PII-TEST-001
    // bare.length > 1 protects middle initials like "T." while rejecting "TRANSCRIPT" or "END"
    if (bare.length > 1 && bare === bare.toUpperCase()) return false;
    if (ROLE_WORDS.has(bare.toLowerCase())) return false;
  }
  return true;
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Detects Person names using linguistic anchors, shape validation,
 * and optional caller-provided known names.
 *
 * @param text Original input text
 * @param options Person detector options (including knownNames)
 * @returns Array of validated PIIMatch objects of type PERSON
 */
export function detectPersons(
  text: string,
  options?: PersonDetectorOptions
): PIIMatch[] {
  if (!text || typeof text !== 'string') {
    return [];
  }

  const matches: PIIMatch[] = [];

  // 1. Caller-supplied exact names (highest confidence)
  if (options?.knownNames && options.knownNames.length > 0) {
    for (const name of options.knownNames) {
      const trimmed = name.trim();
      if (!trimmed) continue;
      const re = new RegExp(String.raw`\b${escapeRegex(trimmed)}\b`, 'g');
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        const start = m.index;
        const end = start + m[0].length;
        if (text.slice(start, end) === m[0]) {
          matches.push({
            type: 'PERSON',
            value: m[0],
            start,
            end,
            method: 'rule',
            confidence: 0.99,
          });
        }
      }
    }
  }

  // 2. Anchored detection
  for (const anchor of ANCHORS) {
    anchor.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = anchor.re.exec(text)) !== null) {
      const capture = m[1];
      if (!capture) continue;

      if (!isPlausibleName(capture)) {
        continue;
      }

      const relIndex = m[0].lastIndexOf(capture);
      if (relIndex === -1) continue;

      const start = m.index + relIndex;
      const end = start + capture.length;

      // Invariant check
      if (text.slice(start, end) !== capture) {
        continue;
      }

      matches.push({
        type: 'PERSON',
        value: capture,
        start,
        end,
        method: 'rule',
        confidence: anchor.confidence,
      });
    }
  }

  return matches;
}
