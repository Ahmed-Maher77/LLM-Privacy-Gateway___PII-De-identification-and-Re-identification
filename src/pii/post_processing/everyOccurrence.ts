// Every occurrence: a value found once is masked everywhere in the document,
// and so is each part of a found name ("Sarah" and "Chen" after "Sarah Chen")

import { isUndesired } from "../layers/predefined";
import type { PIISpan } from "../types";
import { isCommonWord } from "../../utils/ner_utils/vocabulary";
import { TITLES, wholeWords } from "../../utils/predefinedLists_utils/text_helpers";

// A lowercase common word ("she's", "will", "hope") is too common to mask everywhere.
const lowercaseWord = (w: string) =>
    !/\p{Lu}/u.test(w) && isCommonWord(w.replace(/['’]s$/, ""));

// ========= Mask every other occurrence of each found value, and of each part of a found name =========
export function everyOccurrence(text: string, spans: PIISpan[]): PIISpan[] {
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
                !isUndesired(part) &&
                !lowercaseWord(part) &&
                !typeOf.has(part)
            ) {
                typeOf.set(part, "PERSON");
            }
        }
    }
    if (typeOf.size === 0) return [];
    // Exact text, so every match is a key of typeOf
    return [...text.matchAll(wholeWords([...typeOf.keys()], "gu", false))].map(
        (m) => ({
            start: m.index,
            end: m.index + m[0].length,
            type: typeOf.get(m[0])!,
            text: m[0],
            source: "repeat" as const,
        }),
    );
}
