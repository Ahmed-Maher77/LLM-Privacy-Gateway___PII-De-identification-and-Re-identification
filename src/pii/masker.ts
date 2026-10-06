import type { EntityMap, EntityMappingEntry, MaskOptions, MaskResult, PIIMatch } from './types.js';
import { normalizeMatches } from './normalizer.js';

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

  // Ensure matches are normalized, non-overlapping, and validated
  const normalized = normalizeMatches(matches, text);

  // Sort ascending by start offset to assign entity numbers in natural reading order
  const inOrder = [...normalized].sort((a, b) => a.start - b.start);

  const isNumbered = options?.numbered ?? false;
  const indexBase = options?.indexBase ?? 1;
  const strategy = options?.numberingStrategy ?? 'entity';

  const typeCounters: Record<string, number> = {};
  const entityToPlaceholder = new Map<string, string>();
  const entityMap: EntityMap = {};
  const entriesMap = new Map<string, EntityMappingEntry>();
  const matchPlaceholders = new Map<PIIMatch, string>();

  for (const match of inOrder) {
    let placeholder: string;

    if (!isNumbered) {
      placeholder = `[${match.type}]`;
    } else if (strategy === 'entity') {
      // Coreference-aware: identical entity values share the same numbered token
      const key = `${match.type}:::${match.value}`;
      if (entityToPlaceholder.has(key)) {
        placeholder = entityToPlaceholder.get(key)!;
      } else {
        const currentCount = typeCounters[match.type] ?? (indexBase - 1);
        const nextCount = currentCount + 1;
        typeCounters[match.type] = nextCount;
        placeholder = `[${match.type}_${nextCount}]`;
        entityToPlaceholder.set(key, placeholder);
      }
    } else {
      // Occurrence-based: every appearance receives an incremented sequential number
      const currentCount = typeCounters[match.type] ?? (indexBase - 1);
      const nextCount = currentCount + 1;
      typeCounters[match.type] = nextCount;
      placeholder = `[${match.type}_${nextCount}]`;
    }

    matchPlaceholders.set(match, placeholder);
    entityMap[placeholder] = match.value;

    const existingEntry = entriesMap.get(placeholder);
    if (existingEntry) {
      existingEntry.occurrences += 1;
    } else {
      const matchIndex = isNumbered
        ? Number.parseInt(placeholder.slice(placeholder.lastIndexOf('_') + 1, -1), 10) || 0
        : 0;

      entriesMap.set(placeholder, {
        placeholder,
        type: match.type,
        index: matchIndex,
        value: match.value,
        occurrences: 1,
      });
    }
  }

  const formatMask = options?.formatMask;

  // Substitute in descending order by start offset so index shifts do not corrupt replacements
  const descending = [...inOrder].sort((a, b) => b.start - a.start);
  let result = text;

  for (const match of descending) {
    const defaultPlaceholder = matchPlaceholders.get(match) ?? `[${match.type}]`;
    const replacement = formatMask
      ? formatMask(match, defaultPlaceholder)
      : defaultPlaceholder;

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

  const escaped = placeholders.map((p) =>
    p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  );

  const pattern = new RegExp(escaped.join('|'), 'g');
  return maskedText.replace(pattern, (matched) => entityMap[matched] ?? matched);
}

