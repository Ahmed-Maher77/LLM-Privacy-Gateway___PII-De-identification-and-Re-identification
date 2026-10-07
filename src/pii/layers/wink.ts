// Layer 4 — wink-nlp
  // a second opinion on emails and dates (natural-language dates such as "the 5th of April, 2026")


import winkNLP, { type ItemEntity } from "wink-nlp";
import model from "wink-eng-lite-web-model";
import type { EntityType, PIISpan } from "../types";

const nlp = winkNLP(model);
const its = nlp.its;

const WINK_TYPES: Record<string, EntityType> = { EMAIL: "EMAIL_ADDRESS", DATE: "DATE_TIME" };
const MONTH_RE = /\b(?:january|february|march|april|may|june|july|august|september|october|november|december)\b/i;



// ======== Check if a word is in wink's English lexicon =========
const UNKNOWN_ID_FLOOR = nlp.readDoc("qzxvkjwpt").tokens().out(its.uniqueId)[0] as number;
const englishCache = new Map<string, boolean>();


export function isEnglishWord(word: string): boolean {
  const lower = word.toLowerCase();
  let known = englishCache.get(lower);
  if (known === undefined) {
    const ids = nlp.readDoc(lower).tokens().out(its.uniqueId) as number[];
    englishCache.set(lower, (known = ids.length > 0 && ids.every((id) => id < UNKNOWN_ID_FLOOR)));
  }
  return known;
}


// ============ Detect EMAIL and DATE in text using wink-nlp =========
export function detectWink(text: string): PIISpan[] {
  const doc = nlp.readDoc(text);

  // wink gives token indices; rebuild each token's character offsets from
  // its value and the whitespace before it.
  const values = doc.tokens().out(its.value) as string[];
  const spaces = doc.tokens().out(its.precedingSpaces) as string[];
  const start: number[] = [];
  const end: number[] = [];
  let pos = 0;
  values.forEach((value, i) => {
    pos += spaces[i].length;
    start.push(pos);
    pos += value.length;
    end.push(pos);
    // If wink ever altered a token, every later offset would be wrong
    if (text.slice(start[i], pos) !== value) throw new Error(`wink-nlp token ${i} doesn't match the input; refusing to guess offsets.`);
  });

  
  const spans: PIISpan[] = [];
  doc.entities().each((e: ItemEntity) => {
    const type = WINK_TYPES[e.out(its.type) as string];
    if (!type) return;
    const [first, last] = e.out(its.span) as [number, number];
    const from = start[first];
    const to = end[last];
    const value = text.slice(from, to);
    if (type === "DATE_TIME" && !/\d/.test(value) && !(MONTH_RE.test(value) && last > first)) return;
    spans.push({ start: from, end: to, type, text: value, source: "wink" });
  });
  return spans;
}
