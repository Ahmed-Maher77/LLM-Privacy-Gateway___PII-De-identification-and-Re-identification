// Layer 1 — the pre-defined lists (desired and undesired):
// mask the desired-list matches, and drop undesired words from the model spans


import type { PIISpan } from "../types";
import { lineOf } from "../../utils/predefinedLists_utils/text_helpers";
import { isUndesired, load } from "../../utils/predefinedLists_utils/loadLists";

export { isUndesired };
export { ListError } from "../../utils/predefinedLists_utils/predefined_helpers";


// ======== Detect desired-list matches in text =========
export function detectPredefined(text: string): PIISpan[] {
    const spans: PIISpan[] = [];
    for (const { type, pattern, part, lowercaseLinesOnly } of load().desired) {
        for (const m of text.matchAll(pattern)) {
            if (part && isUndesired(m[0])) continue;
            if (lowercaseLinesOnly && /\p{Lu}/u.test(lineOf(text, m.index)))
                continue;
            spans.push({
                start: m.index,
                end: m.index + m[0].length,
                type,
                text: m[0],
                source: "predefined",
            });
        }
    }
    return spans;
}


// ========= Drop model spans that are undesired, and trim undesired words at their edges ("The Sarah" -> "Sarah") =========
export function removeUndesired(text: string, spans: PIISpan[]): PIISpan[] {
    const out: PIISpan[] = [];
    for (const span of spans) {
        if (isUndesired(span.text)) continue;
        const words = [...span.text.matchAll(/\S+/g)];
        let first = 0;
        let last = words.length - 1;
        while (first <= last && isUndesired(words[first][0])) first++;
        while (last >= first && isUndesired(words[last][0])) last--;
        if (first > last) continue;
        const start = span.start + words[first].index;
        const end = span.start + words[last].index + words[last][0].length;
        const trimmed = text.slice(start, end);
        if (!isUndesired(trimmed))
            out.push({ ...span, start, end, text: trimmed });
    }
    return out;
}
