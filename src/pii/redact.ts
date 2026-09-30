// Public API: detect() and redact().
//
// Two independent layers each return spans with offsets into the original
// text:
//   1. pre-defined lists  layers/predefined.ts  names and companies you list, whole or in part
//   2. NER model          layers/ner.ts         names (local ONNX model, Transformers.js)
// Model findings on the undesired list (layers/predefined.ts) are dropped. Then
// (post_processing/):
//   every other occurrence of a found value is masked too   everyOccurrence.ts
//   overlapping spans are merged into one covering them all  mergeSpans.ts

import { detectPredefined, removeUndesired } from "./layers/predefined";
import { detectNer } from "./layers/ner";
import { everyOccurrence } from "./post_processing/everyOccurrence";
import { mergeSpans } from "./post_processing/mergeSpans";
import { Placeholders } from "./placeholders";
import type { PIISpan, RedactResult } from "./types";


// ~2 MB: guards against accidental whole-dataset inputs
const MAX_CHARS = 2_000_000;


export class InputTooLargeError extends Error {
    constructor(
        readonly length: number,
        readonly maxChars: number,
    ) {
        super(`Input is ${length} characters; the limit is ${maxChars}.`);
        this.name = "InputTooLargeError";
    }
}


// ========== Detect PII Spans in text, returning them sorted =========
async function detectWithMetrics(
    text: string,
): Promise<Omit<RedactResult, "text">> {
    if (text.length > MAX_CHARS)
        throw new InputTooLargeError(text.length, MAX_CHARS);
    if (text.trim().length === 0) {
        return { spans: [], metrics: { layerTimingsMs: {}, layerCounts: {} } };
    }

    // to measure the time taken by each layer
    const layerTimingsMs: Record<string, number> = {};
    const layerCounts: Record<string, number> = {};
    const measure = (name: string, run: () => PIISpan[]): PIISpan[] => {
        const started = performance.now();
        const result = run();
        layerTimingsMs[name] = performance.now() - started;
        layerCounts[name] = result.length;
        return result;
    };

    const nerStarted = performance.now();
    const ner = detectNer(text); // loads the model while the list is matched
    const predefined = measure("predefined", () => detectPredefined(text));
    const nerSpans = removeUndesired(text, await ner);
    layerCounts.ner = nerSpans.length;
    layerTimingsMs.ner = performance.now() - nerStarted;

    const spans = [...predefined, ...nerSpans];
    const repeated = measure("repeat", () => everyOccurrence(text, spans));
    const merged = measure("merge", () => mergeSpans(text, [...spans, ...repeated]));
    return { spans: merged, metrics: { layerTimingsMs, layerCounts } };
}

export async function detect(text: string): Promise<PIISpan[]> {
    return (await detectWithMetrics(text)).spans;
}


// ========= Redact text, replacing each detected PII span with a placeholder =========
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
