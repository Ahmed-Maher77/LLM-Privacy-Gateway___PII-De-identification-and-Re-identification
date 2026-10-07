// Labels for test_data/<name>.txt, kept in test_data/labels/<name>.json:
//   { "PERSON": ["Kofi Mensah", "kofi"], "CREDIT_CARD": ["4539 1488 0343 6467"], "ignore": ["Sam"] }
//
// An entry is a string or { "value", "in"?, "hard"? }:
//   "kofi"                                      every whole-word, case-sensitive "kofi"
//   { "value": "will", "in": "brother will" }   only the "will" inside each "brother will"
//   { "value": "k o f i", "hard": true }        left out of the headline numbers
// "ignore" lists ambiguous words: a detection over one is neither a hit nor
// a false positive.

import fs from "node:fs";
import { ENTITY_TYPES, type EntityType } from "../../src/pii/types";
import { escapeRegex, wholeWords } from "../../src/pii/patterns";

type Entry = string | { value: string; in?: string; hard?: boolean };

export interface Occurrence {
    type: EntityType;
    start: number;
    end: number;
    value: string;
    hard: boolean;
}

export interface Labels {
    occurrences: Occurrence[];
    ignored: [number, number][];
}

const wholeWord = (v: string) => wholeWords([escapeRegex(v)], "gu");

// ======== Find every [start, end] of one entry in the text =========
function find(text: string, entry: Entry, where: string): [number, number][] {
    const { value, in: context } = typeof entry === "string" ? { value: entry, in: undefined } : entry;
    let found: [number, number][];
    if (context === undefined) {
        found = [...text.matchAll(wholeWord(value))].map((m) => [m.index, m.index + value.length]);
    } else {
        const at = context.indexOf(value);
        if (at < 0) throw new Error(`${where}: "${value}" is not inside "${context}"`);
        found = [...text.matchAll(new RegExp(escapeRegex(context), "gu"))].map((m) => [m.index + at, m.index + at + value.length]);
    }
    if (found.length === 0) throw new Error(`${where}: "${context ?? value}" is not in the text`);
    return found;
}

// ======== Load the labels of one file as occurrences in its text =========
export function loadLabels(file: string, text: string): Labels {
    const json: Record<string, Entry[]> = JSON.parse(fs.readFileSync(file, "utf-8"));
    const occurrences: Occurrence[] = [];
    let ignored: [number, number][] = [];

    for (const [key, entries] of Object.entries(json)) {
        if (key === "ignore") {
            ignored = entries.flatMap((e) => find(text, e, file));
            continue;
        }
        if (!ENTITY_TYPES.includes(key as EntityType)) throw new Error(`${file}: unknown type "${key}"`);
        const type = key as EntityType;

        // Longest first, so "Kofi Mensah" is one occurrence, not also "Kofi" and "Mensah"
        const candidates = entries
            .flatMap((e) =>
                find(text, e, file).map(([start, end]) => ({
                    type,
                    start,
                    end,
                    value: text.slice(start, end),
                    hard: typeof e !== "string" && e.hard === true,
                })),
            )
            .sort((a, b) => b.end - b.start - (a.end - a.start));
        for (const c of candidates) {
            const overlaps = occurrences.some((o) => o.type === type && c.start < o.end && o.start < c.end);
            if (!overlaps) occurrences.push(c);
        }
    }
    return { occurrences: occurrences.sort((a, b) => a.start - b.start), ignored };
}
