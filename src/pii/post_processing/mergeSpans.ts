// Merge: overlapping spans become one span covering all of them, so no part
// of anything a layer found stays visible

import type { PIISpan } from "../types";

/** Tie-break when two overlapping spans are equally long: earlier layer wins. */
const LAYER_ORDER: PIISpan["source"][] = ["predefined", "ner", "repeat"];

// ========= Merge overlapping spans, keeping the longest and earliest layer =========
export function mergeSpans(text: string, spans: PIISpan[]): PIISpan[] {
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
