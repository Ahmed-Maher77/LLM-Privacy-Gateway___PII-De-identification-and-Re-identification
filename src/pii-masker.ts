import winkNLP, { type ItemEntity, type ItemToken } from "wink-nlp";
import model from "wink-eng-lite-web-model";
import type { PIIMaskConfig, PIIMatch, PIIType } from "./types.js";

const nlp = winkNLP(model);
const its = nlp.its;

const DEFAULT_CONFIG: Required<PIIMaskConfig> = {
  EMAIL: true,
  URL: true,
  DATE: true,
  MONEY: false,
  TIME: false,
  PHONE: false,
  IP_ADDRESS: false,
  PERSON: false,
  LOCATION: false,
  ORGANIZATION: false,
  MENTION: false,
};

export function detectPII(
  text: string,
  config: PIIMaskConfig = {},
): PIIMatch[] {
  if (!text) {
    return [];
  }

  const finalConfig = {
    ...DEFAULT_CONFIG,
    ...config,
  };

  const doc = nlp.readDoc(text);

  // Compute exact character start and end offsets for all tokens in a single O(N) pass.
  // wink-nlp drops or normalises a few characters (a BOM, U+2028, \v, \f), so each
  // token is re-anchored on the original text rather than trusting the running sum.
  let pos = 0;
  const tokenOffsets: { start: number; end: number }[] = [];
  doc.tokens().each((token: ItemToken) => {
    const spaces = token.out(its.precedingSpaces) as string;
    const val = token.out(its.value) as string;
    const found = text.indexOf(val, pos);
    const start = found === -1 ? pos + spaces.length : found;
    const end = start + val.length;
    tokenOffsets.push({ start, end });
    pos = end;
  });

  const matches: PIIMatch[] = [];

  doc.entities().each((entity: ItemEntity) => {
    // The model also emits types outside PIIType (e.g. CARDINAL, DURATION);
    // they have no key in finalConfig, so the check below skips them.
    const type = entity.out(its.type) as PIIType;

    if (!finalConfig[type]) {
      return;
    }

    const [startTok, endTok] = entity.out(its.span) as [number, number];
    const startOffset = tokenOffsets[startTok];
    const endOffset = tokenOffsets[endTok];

    if (!startOffset || !endOffset) {
      return;
    }

    const start = startOffset.start;
    const end = endOffset.end;
    const value = text.slice(start, end);

    matches.push({
      type,
      value,
      start,
      end,
      source: "wink-nlp",
    });
  });

  return matches;
}

export function maskPII(
  matches: PIIMatch[],
  text: string,
): string {
  if (!text || matches.length === 0) {
    return text;
  }

  // Sort matches ascending by start position; favor longer span on ties
  const sortedMatches = [...matches].sort(
    (a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start),
  );

  let result = "";
  let lastIndex = 0;

  for (const match of sortedMatches) {
    // An overlapping span joins the previous mask, extending it if it reaches further
    if (match.start < lastIndex) {
      lastIndex = Math.max(lastIndex, match.end);
      continue;
    }

    // Append preceding non-sensitive text
    result += text.slice(lastIndex, match.start);
    // Append entity placeholder
    result += `[${match.type}]`;
    lastIndex = match.end;
  }

  // Append remaining text
  result += text.slice(lastIndex);
  return result;
}