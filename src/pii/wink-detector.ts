import winkNLP, { type ItemToken, type ItemEntity } from 'wink-nlp';
import model from 'wink-eng-lite-web-model';
import type { PIIMatch, PIIType, WinkDetectorOptions } from './types.js';

// Initialize WinkNLP once (singleton instance)
const nlp = winkNLP(model);
const its = nlp.its;

/**
 * Returns the underlying WinkNLP instance.
 */
export function getWinkNLPInstance() {
  return nlp;
}

interface TokenOffset {
  start: number;
  end: number;
  value: string;
}

/**
 * Map WinkNLP entity types to normalized PIITypes.
 */
function mapWinkEntityToPIIType(winkType: string): PIIType | null {
  switch (winkType.toUpperCase()) {
    case 'EMAIL':
      return 'EMAIL';
    case 'URL':
      return 'URL';
    case 'DATE':
      return 'DATE';
    case 'TIME':
      return 'TIME';
    case 'MENTION':
      return 'MENTION';
    case 'MONEY':
    case 'PERCENT':
    case 'CARDINAL':
    case 'ORDINAL':
    case 'DURATION':
    case 'EMOJI':
    case 'EMOTICON':
    case 'HASHTAG':
      // General NLP entities - not standard PII unless explicitly mapped
      return null;
    default:
      return null;
  }
}

/**
 * Detects entities using WinkNLP and converts them into normalized PIIMatch objects
 * with exact character offsets.
 *
 * @param text The input text to process
 * @param options Wink detector configuration options
 * @returns Array of normalized PII matches from WinkNLP
 */
export function detectWithWinkNLP(
  text: string,
  options?: WinkDetectorOptions
): PIIMatch[] {
  if (!text || typeof text !== 'string') {
    return [];
  }

  const doc = nlp.readDoc(text);
  const matches: PIIMatch[] = [];

  // Step 1: Pre-calculate token character offsets
  // WinkNLP tokens provide `its.precedingSpaces` and `its.value`.
  // By accumulating lengths, we accurately map any token index to exact string character offsets.
  const tokenOffsets: TokenOffset[] = [];
  let currentOffset = 0;

  doc.tokens().each((token: ItemToken) => {
    const precedingSpaces = token.out(its.precedingSpaces) as string;
    const value = token.out(its.value) as string;
    const start = currentOffset + precedingSpaces.length;
    const end = start + value.length;

    tokenOffsets.push({ start, end, value });
    currentOffset = end;
  });

  // Step 2: Extract built-in WinkNLP entities
  doc.entities().each((entity: ItemEntity) => {
    const rawType = entity.out(its.type) as string;
    const piiType = mapWinkEntityToPIIType(rawType);

    if (!piiType) {
      return;
    }

    // Filter based on options
    if (piiType === 'DATE' && options?.extractDates === false) return;
    if (piiType === 'TIME' && options?.extractTimes === false) return;
    if (piiType === 'MENTION' && options?.extractMentions === false) return;

    const span = entity.out(its.span) as [number, number];
    const [startTokenIdx, endTokenIdx] = span;

    const startToken = tokenOffsets[startTokenIdx];
    const endToken = tokenOffsets[endTokenIdx];

    if (!startToken || !endToken) {
      return;
    }

    const start = startToken.start;
    const end = endToken.end;
    const value = text.slice(start, end);

    // Relative date expressions (today, tomorrow, yesterday) are not PII; require digit
    if (piiType === 'DATE' && !/\d/.test(value)) return;

    matches.push({
      type: piiType,
      value,
      start,
      end,
      method: 'winknlp',
      confidence: 0.95,
    });
  });

  // Step 3: Optional POS-based Proper Noun (PROPN) heuristic for Person detection
  // This evaluates whether WinkNLP's POS tagger can be leveraged for name detection
  // and documents its empirical precision/recall tradeoffs.
  if (options?.extractProperNounsAsPerson) {
    let currentPropnGroup: { startTokenIdx: number; endTokenIdx: number; tokens: string[] } | null = null;

    const flushGroup = () => {
      if (currentPropnGroup) {
        const startToken = tokenOffsets[currentPropnGroup.startTokenIdx];
        const endToken = tokenOffsets[currentPropnGroup.endTokenIdx];
        if (startToken && endToken) {
          const start = startToken.start;
          const end = endToken.end;
          const value = text.slice(start, end);

          // Avoid adding if already covered by an entity match
          const alreadyMatched = matches.some(
            (m) => m.start <= start && m.end >= end
          );

          if (!alreadyMatched) {
            matches.push({
              type: 'PERSON',
              value,
              start,
              end,
              method: 'winknlp',
              confidence: 0.6,
            });
          }
        }
        currentPropnGroup = null;
      }
    };

    const numTokens = tokenOffsets.length;
    for (let i = 0; i < numTokens; i++) {
      const token = doc.tokens().itemAt(i);
      const pos = token.out(its.pos) as string;

      if (pos === 'PROPN') {
        if (!currentPropnGroup) {
          currentPropnGroup = {
            startTokenIdx: i,
            endTokenIdx: i,
            tokens: [tokenOffsets[i]!.value],
          };
        } else {
          currentPropnGroup.endTokenIdx = i;
          currentPropnGroup.tokens.push(tokenOffsets[i]!.value);
        }
      } else {
        flushGroup();
      }
    }
    flushGroup();
  }

  return matches;
}
