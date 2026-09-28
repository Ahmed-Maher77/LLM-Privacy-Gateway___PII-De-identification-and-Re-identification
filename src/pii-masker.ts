import winkNLP from "wink-nlp";
import model from "wink-eng-lite-web-model";

const nlp = winkNLP(model);
const its = nlp.its;

export type PIIType =
  | "EMAIL"
  | "URL"
  | "DATE"
  | "TIME"
  | "PHONE"
  | "MONEY"
  | "IP_ADDRESS"
  | "PERSON"
  | "LOCATION"
  | "ORGANIZATION"
  | "MENTION";

export interface PIIMatch {
  type: PIIType;
  value: string;
  start: number;
  end: number;
}

export interface PIIMaskConfig {
  EMAIL?: boolean;
  URL?: boolean;
  DATE?: boolean;
  MONEY?: boolean;
  TIME?: boolean;
  PHONE?: boolean;
  IP_ADDRESS?: boolean;
  PERSON?: boolean;
  LOCATION?: boolean;
  ORGANIZATION?: boolean;
  MENTION?: boolean;
}

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
  const finalConfig = {
    ...DEFAULT_CONFIG,
    ...config,
  };

  const doc = nlp.readDoc(text);
  const matches: PIIMatch[] = [];

  doc.entities().each((entity: any) => {
    const type = entity.out(its.type) as PIIType;

    if (!finalConfig[type]) {
      return;
    }

    const value = entity.out();

    const start = findNextOccurrence(
      text,
      value,
      matches,
    );

    if (start === -1) {
      return;
    }

    matches.push({
      type,
      value,
      start,
      end: start + value.length,
    });
  });

  return matches;
}

function findNextOccurrence(
  text: string,
  value: string,
  existingMatches: PIIMatch[],
): number {
  let searchFrom = 0;

  while (searchFrom < text.length) {
    const index = text.indexOf(value, searchFrom);

    if (index === -1) {
      return -1;
    }

    const alreadyUsed = existingMatches.some(
      (match) =>
        index >= match.start &&
        index < match.end,
    );

    if (!alreadyUsed) {
      return index;
    }

    searchFrom = index + value.length;
  }

  return -1;
}

export function maskPII(
  text: string,
  config: PIIMaskConfig = {},
): string {
  const matches = detectPII(text, config);

  if (matches.length === 0) {
    return text;
  }

  const sortedMatches = [...matches].sort(
    (a, b) => b.start - a.start,
  );

  let result = text;

  for (const match of sortedMatches) {
    result =
      result.slice(0, match.start) +
      `[${match.type}]` +
      result.slice(match.end);
  }

  return result;
}