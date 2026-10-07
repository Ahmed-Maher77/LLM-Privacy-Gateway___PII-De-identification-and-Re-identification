import type { PIIConfig, PIIMatch } from './types.js';
import { isTypeEnabled, resolveConfig } from './config.js';
import { detectWithWinkNLP } from './wink-detector.js';
import { detectWithRegex } from './regex-detector.js';
import { detectPersons } from './person-detector.js';
import { applyStructuralGuards } from './structure.js';
import { normalizeMatches } from './normalizer.js';
import { findExactMatches } from './exact-match.js';

/**
 * Main PII detection entry point.
 *
 * Coordinates multi-engine detection (WinkNLP + Regex/Rules + Anchored Person),
 * applies structural guards, filters entities according to user configuration,
 * and performs deterministic deduplication and character offset validation.
 *
 * @param text The input text to analyze
 * @param config Optional configuration toggling specific PII categories and engines
 * @returns Array of normalized PIIMatch objects
 */
export function detectPII(text: string, config?: Partial<PIIConfig>): PIIMatch[] {
  if (!text || typeof text !== 'string') {
    return [];
  }

  const resolved = resolveConfig(config);
  const rawMatches: PIIMatch[] = [];

  // 1. Run WinkNLP engine if enabled
  if (resolved.enableWinkNLP) {
    const winkMatches = detectWithWinkNLP(text, {
      extractDates: resolved.date,
      extractTimes: resolved.time,
      extractMentions: resolved.mention,
      extractProperNounsAsPerson: resolved.person && resolved.personStrategy === 'propn',
    });
    rawMatches.push(...winkMatches);
  }

  // 2. Run anchored Person detector if enabled and strategy is 'anchored'
  if (resolved.person && resolved.personStrategy === 'anchored') {
    const personMatches = detectPersons(text, { knownNames: resolved.knownNames });
    rawMatches.push(...personMatches);
  }

  // 3. Run Regex deterministic engine if enabled (EMAIL, PHONE, URL, IP, CREDIT_CARD, SSN, ADDRESS)
  if (resolved.enableRegex) {
    const regexMatches = detectWithRegex(text, { strictLuhn: resolved.strictLuhn });
    rawMatches.push(...regexMatches);
  }

  // 4. Caller-supplied known locations
  if (resolved.location) {
    rawMatches.push(...findExactMatches(text, resolved.knownLocations, 'LOCATION'));
  }

  // 5. Caller-supplied known organizations
  if (resolved.organization) {
    rawMatches.push(...findExactMatches(text, resolved.knownOrganizations, 'ORGANIZATION'));
  }

  // 6. Apply structural guards (KI-006: protects bracketed markers and line-leading labels from heuristic false positives)
  const guardedMatches = applyStructuralGuards(rawMatches, text);

  // 7. Filter matches by enabled configuration categories
  const filteredMatches = guardedMatches.filter((match) =>
    isTypeEnabled(match.type, resolved)
  );

  // 8. Normalize, deduplicate, and verify character offsets
  return normalizeMatches(filteredMatches, text);
}
