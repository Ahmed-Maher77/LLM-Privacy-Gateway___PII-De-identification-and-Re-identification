// Layer 3 — Presidio (spaCy NER + Presidio's recognizers)
  // the main source of PERSON

import { PresidioClient } from "../client";
import { ENTITY_TYPES, type EntityType, type PIISpan } from "../types";
import { isListedGivenName } from "./dictionary";
import { isEnglishWord } from "./wink";


const MIN_SCORE = 0.4;
const CHUNK_CHARS = 8000;
const CONCURRENCY = 4;
const REQUESTED_TYPES = ENTITY_TYPES.filter((t) => t !== "ORGANIZATION");
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

// ======== Split text into chunks, each ending at a line break =========
function chunks(text: string): [number, number][] {
  const out: [number, number][] = [];
  for (let start = 0; start < text.length; ) {
    let end = Math.min(start + CHUNK_CHARS, text.length);
    if (end < text.length) {
      const nl = text.lastIndexOf("\n", end);
      if (nl > start) end = nl + 1;
    }
    out.push([start, end]);
    start = end;
  }
  return out;
}

// ======== Convert codepoint offsets to UTF-16 offsets =========
function utf16Offsets(text: string): number[] {
  const offsets = [0];
  for (let i = 0; i < text.length; ) {
    i += text.codePointAt(i)! > 0xffff ? 2 : 1;
    offsets.push(i);
  }
  return offsets;
}

// ====== Check if a Presidio PERSON span looks like a real person name, not a random capitalized word or acronym ======
function looksLikePerson(span: PIISpan, text: string): boolean {
  const words = span.text.split(/\s+/);
  if (!/\p{L}/u.test(span.text)) return false;
  if (words.every((w) => isEnglishWord(w)) && !words.some((w) => isListedGivenName(w))) return false;
  const line = text.slice(text.lastIndexOf("\n", span.start) + 1, (text.indexOf("\n", span.start) + 1 || text.length + 1) - 1);
  return /\p{Lu}/u.test(span.text) || !/\p{Lu}/u.test(line);
}

// ====== Trim a name to remove trailing whitespace and digits ======
function trimName(span: PIISpan, text: string): PIISpan | undefined {
  if (span.type !== "PERSON") return span;
  let value = span.text.split(/[\r\n]/)[0];
  value = value.replace(/\s*\S*\d[\s\S]*$/, "");
  value = value.replace(/[\s,.:;!?]+$/, "");
  if (!/\p{L}/u.test(value)) return undefined;
  return { ...span, end: span.start + value.length, text: text.slice(span.start, span.start + value.length) };
}

// ======== Analyze a chunk of text with Presidio and convert the results to PIISpan objects =========
async function analyzeChunk(client: PresidioClient, text: string, [from, to]: [number, number]): Promise<PIISpan[]> {
  const chunk = text.slice(from, to);
  const toUtf16 = utf16Offsets(chunk);
  const results = await client.analyze({ text: chunk, language: "en", entities: REQUESTED_TYPES });
  return results
    .filter((r) => r.score >= MIN_SCORE)
    .map((r) => {
      const start = from + toUtf16[r.start];
      const end = from + toUtf16[r.end];
      return { start, end, type: r.entity_type as EntityType, text: text.slice(start, end), source: "presidio" as const };
    })
    .map((s) => trimName(s, text))
    .filter((s): s is PIISpan => s !== undefined)
    // Presidio's phone recognizer also reads IPv4 addresses ("192.168.14.22").
    .filter((s) => !(s.type === "PHONE_NUMBER" && IPV4_RE.test(s.text)))
    .filter((s) => s.type !== "PERSON" || looksLikePerson(s, text));
}

// =========== Detect PII in text using Presidio =========
export async function detectPresidio(text: string): Promise<PIISpan[]> {
  const client = new PresidioClient();
  const pending = chunks(text);
  const spans: PIISpan[] = [];
  const worker = async () => {
    for (let c = pending.shift(); c; c = pending.shift()) spans.push(...(await analyzeChunk(client, text, c)));
  };
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  return spans;
}
