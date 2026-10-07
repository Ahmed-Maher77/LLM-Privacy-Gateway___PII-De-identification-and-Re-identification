import type { EntityMap, EntityMappingEntry, MaskOptions, MaskResult, PIIMatch } from './types.js';
import { normalizeMatches } from './normalizer.js';
import { escapeRegex } from './exact-match.js';

/**
 * Masks detected PII spans and generates an entity map for reversible de-anonymization.
 * Supports both generic masking (`[TYPE]`) and numbered masking (`[TYPE_1]`, `[TYPE_2]`).
 *
 * Spans are numbered in reading order (ascending start offset) and substituted in
 * reverse offset order (descending start offset) to guarantee character offset integrity.
 *
 * @param text Original input text
 * @param matches PII matches to mask
 * @param options Masking customization (numbered, indexBase, numberingStrategy, formatMask)
 * @returns MaskResult containing maskedText, entityMap, and detailed entity entries
 */
export function maskPIIWithMapping(
  text: string,
  matches: PIIMatch[],
  options?: MaskOptions
): MaskResult {
  if (!text || !matches || matches.length === 0) {
    return {
      maskedText: text,
      entityMap: {},
      entities: [],
    };
  }

  // Normalized matches are non-overlapping and sorted by start offset (natural reading order)
  const inOrder = normalizeMatches(matches, text);

  const isNumbered = options?.numbered ?? false;
  const indexBase = options?.indexBase ?? 1;
  const strategy = options?.numberingStrategy ?? 'entity';

  const typeCounters: Record<string, number> = {};
  const entityToPlaceholder = new Map<string, string>();
  const entityMap: EntityMap = {};
  const entriesMap = new Map<string, EntityMappingEntry>();
  const placed: { match: PIIMatch; placeholder: string }[] = [];

  for (const match of inOrder) {
    const key = `${match.type}:::${match.value}`;
    const shared = strategy === 'entity' ? entityToPlaceholder.get(key) : undefined;
    let placeholder: string;
    let index = 0;

    if (!isNumbered) {
      placeholder = `[${match.type}]`;
    } else if (shared) {
      // Coreference-aware: identical entity values share the same numbered token
      placeholder = shared;
    } else {
      // New entity, or occurrence-based numbering: take the next sequential number
      index = (typeCounters[match.type] ?? indexBase - 1) + 1;
      typeCounters[match.type] = index;
      placeholder = `[${match.type}_${index}]`;
      entityToPlaceholder.set(key, placeholder);
    }

    placed.push({ match, placeholder });
    entityMap[placeholder] = match.value;

    const existingEntry = entriesMap.get(placeholder);
    if (existingEntry) {
      existingEntry.occurrences += 1;
    } else {
      entriesMap.set(placeholder, {
        placeholder,
        type: match.type,
        index: Math.trunc(index) || 0,
        value: match.value,
        occurrences: 1,
      });
    }
  }

  const formatMask = options?.formatMask;

  // Substitute in descending order by start offset so index shifts do not corrupt replacements
  let result = text;

  for (const { match, placeholder } of placed.reverse()) {
    const replacement = formatMask ? formatMask(match, placeholder) : placeholder;

    match.placeholder = replacement;
    result = result.slice(0, match.start) + replacement + result.slice(match.end);
  }

  return {
    maskedText: result,
    entityMap,
    entities: Array.from(entriesMap.values()),
  };
}

/**
 * Masks detected PII spans in the input text.
 * Masking is strictly decoupled from the detection layer.
 *
 * Spans are substituted in reverse offset order (from right to left)
 * to ensure character index shifts do not corrupt subsequent replacements.
 *
 * @param text Original input text
 * @param matches PII matches to mask
 * @param options Optional masking customization (e.g. custom replacement format, numbering)
 * @returns Masked text
 */
export function maskPII(
  text: string,
  matches: PIIMatch[],
  options?: MaskOptions
): string {
  return maskPIIWithMapping(text, matches, options).maskedText;
}

/**
 * Restores original plaintext from sanitized text using an entity map.
 * Replaces placeholders with their original values in a single regex pass
 * to prevent cascading or recursive substitutions.
 *
 * @param maskedText The sanitized/masked text containing numbered placeholders
 * @param entityMap The mapping from placeholder (e.g. "[PERSON_1]") to original value
 * @returns Restored original text
 */
export function unmaskPII(
  maskedText: string,
  entityMap: Record<string, string>
): string {
  if (!maskedText || !entityMap) {
    return maskedText;
  }

  const placeholders = Object.keys(entityMap);
  if (placeholders.length === 0) {
    return maskedText;
  }

  // Sort placeholders descending by length so longer tokens match before prefixes
  placeholders.sort((a, b) => b.length - a.length);

  const pattern = new RegExp(placeholders.map(escapeRegex).join('|'), 'g');
  return maskedText.replace(pattern, (matched) => entityMap[matched] ?? matched);
}

