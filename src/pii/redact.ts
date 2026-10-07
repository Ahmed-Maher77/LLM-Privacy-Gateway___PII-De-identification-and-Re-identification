// Public API: detect() and redact().
//
// Four independent layers each return spans with offsets into the original
// text:
//   1. pre-defined lists  layers/predefined.ts   values you always want masked
//                         layers/dictionary.ts   name / organisation registries (data/lists/)
//   2. regex              layers/regex.ts        fixed formats, checksums
//   3. NER model          layers/ner.ts          names (local ONNX model, Transformers.js)
//   4. wink-nlp           layers/wink.ts         emails, natural-language dates
// Overlapping spans are then merged into one span covering all of them, so
// no part of anything a layer found stays visible.

import { detectPredefined } from "./layers/predefined";
import { detectDictionary } from "./layers/dictionary";
import { detectRegex } from "./layers/regex";
import { detectNer } from "./layers/ner";
import { TITLES } from "./layers/dictionary_helpers";
import { detectWink, isEnglishWord } from "./layers/wink";
import { Placeholders } from "./policy";
import type { DetectionMetrics, PIISpan, RedactResult } from "./types";
import { escapeRegex, wholeWords } from "./patterns";

/** ~2 MB: guards against accidental whole-dataset inputs. */
const MAX_CHARS = 2_000_000;

/** Tie-break when two overlapping spans are equally long: earlier layer wins. */
const LAYER_ORDER: PIISpan["source"][] = [
    "predefined",
    "dictionary",
    "regex",
    "ner",
    "wink",
    "repeat",
];

export class InputTooLargeError extends Error {
    constructor(
        readonly length: number,
        readonly maxChars: number,
    ) {
        super(`Input is ${length} characters; the limit is ${maxChars}.`);
        this.name = "InputTooLargeError";
    }
}

// ========= Merge overlapping spans, keeping the longest and earliest layer =========
function merge(text: string, spans: PIISpan[]): PIISpan[] {
    const sorted = [...spans].sort(
        (a, b) =>
            a.start - b.start ||
            b.end - b.start - (a.end - a.start) ||
            LAYER_ORDER.indexOf(a.source) - LAYER_ORDER.indexOf(b.source),
    );
    const out: PIISpan[] = [];
    for (const span of sorted) {
        if (span.end <= span.start) continue;
        const last = out[out.length - 1];

        // non-overlapping spans
        if (!last || span.start >= last.end) {
            out.push(span);
            continue;
        }

        // overlapping spans
        const end = Math.max(last.end, span.end);
        const longest =
            span.end - span.start > last.end - last.start ? span : last;
        out[out.length - 1] = {
            ...longest,
            start: last.start,
            end,
            text: text.slice(last.start, end),
        };
    }
    return out;
}

// A lowercase English word ("she's", "will", "hope") is too common to mask everywhere.
const lowercaseWord = (w: string) =>
    !/\p{Lu}/u.test(w) && isEnglishWord(w.replace(/['’]s$/, ""));

// acts as a post-processing safety net
/* It collects all previously detected PII entities, breaks multi-word names down
into their individual components, and sweeps through the entire transcript with a dynamic regex
to catch every single remaining occurrence
*/
function everyOccurrence(text: string, spans: PIISpan[]): PIISpan[] {
    const typeOf = new Map<string, PIISpan["type"]>();
    for (const s of spans) {
        const oneCommonWord = !/\s/.test(s.text) && lowercaseWord(s.text);
        if (!oneCommonWord && !typeOf.has(s.text)) typeOf.set(s.text, s.type);
    }
    for (const s of spans) {
        if (s.type !== "PERSON") continue;
        for (const part of s.text.split(/\s+/)) {
            if (
                part.length >= 3 &&
                /^\p{L}[\p{L}'’-]*$/u.test(part) &&
                !TITLES.has(part.toLowerCase()) &&
                !lowercaseWord(part) &&
                !typeOf.has(part)
            ) {
                typeOf.set(part, "PERSON");
            }
        }
    }
    if (typeOf.size === 0) return [];
    const alternatives = [...typeOf.keys()].sort((a, b) => b.length - a.length).map(escapeRegex);
    const pattern = wholeWords(alternatives, "gu");
    return [...text.matchAll(pattern)].map((m) => ({
        start: m.index,
        end: m.index + m[0].length,
        type: typeOf.get(m[0])!,
        text: m[0],
        source: "repeat" as const,
    }));
}

// ========== Detect PII Spans in text, returning them sorted =========
interface DetectionRun {
    spans: PIISpan[];
    metrics: DetectionMetrics;
}

async function detectWithMetrics(text: string): Promise<DetectionRun> {
    if (text.length > MAX_CHARS)
        throw new InputTooLargeError(text.length, MAX_CHARS);
    if (text.trim().length === 0) {
        return { spans: [], metrics: { layerTimingsMs: {}, layerCounts: {} } };
    }

    const layerTimingsMs: Record<string, number> = {};
    const layerCounts: Record<string, number> = {};
    const measure = <T>(name: string, run: () => T): T => {
        const started = performance.now();
        const result = run();
        layerTimingsMs[name] = performance.now() - started;
        layerCounts[name] = Array.isArray(result) ? result.length : 0;
        return result;
    };
    const nerStarted = performance.now();
    const ner = detectNer(text); // loads the model while the other layers work
    const predefined = measure("predefined", () => detectPredefined(text));
    const dictionary = measure("dictionary", () => detectDictionary(text));
    const regex = measure("regex", () => detectRegex(text));
    const wink = measure("wink", () => detectWink(text));
    const nerSpans = await ner;
    layerCounts.ner = nerSpans.length;
    layerTimingsMs.ner = performance.now() - nerStarted;

    const spans = [
        ...predefined,
        ...dictionary,
        ...regex,
        ...wink,
        ...nerSpans,
    ];
    const repeated = measure("repeat", () => everyOccurrence(text, spans));
    const merged = measure("merge", () => merge(text, [...spans, ...repeated]));
    return { spans: merged, metrics: { layerTimingsMs, layerCounts } };
}

export async function detect(text: string): Promise<PIISpan[]> {
    return (await detectWithMetrics(text)).spans;
}

// ========= Redact text, replacing each detected PII span with a placeholder. =========
export async function redact(text: string): Promise<RedactResult> {
    const { spans, metrics } = await detectWithMetrics(text);
    const placeholders = new Placeholders();
    const parts: string[] = [];
    let cursor = 0;
    for (const span of spans) {
        parts.push(
            text.slice(cursor, span.start),
            placeholders.for(span.type, span.text),
        );
        cursor = span.end;
    }
    parts.push(text.slice(cursor));
    return { text: parts.join(""), spans, metrics };
}
