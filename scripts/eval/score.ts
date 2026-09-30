// Score detected spans against the labels of one file.
//   recall     labelled occurrences fully masked (by a span of any type)
//   leaked     labelled characters left visible (whitespace not counted)
//   over       masked characters that are in no label (whitespace and ignored words not counted)
//   precision  detected spans that overlap a labelled occurrence
// Hard occurrences are kept out of the headline counts and scored apart.

import type { EntityType } from "../../src/pii/types";
import type { Labels, Occurrence } from "./labels";

export interface Detected {
    type: EntityType;
    start: number;
    end: number;
}

export interface Counts {
    labelled: number;
    found: number;
    chars: number;
    leaked: number;
    overMasked: number;
    detected: number;
    falsePositives: number;
}

export interface FileScore {
    byType: Map<EntityType, Counts>;
    all: Counts;
    hard: Counts;
    misses: Occurrence[];
    falsePositives: Detected[];
    overExtended: Detected[]; // spans that hit a label but also mask words outside it
}

export const emptyCounts = (): Counts => ({ labelled: 0, found: 0, chars: 0, leaked: 0, overMasked: 0, detected: 0, falsePositives: 0 });

export function addCounts(into: Counts, from: Counts): void {
    for (const k of Object.keys(into) as (keyof Counts)[]) into[k] += from[k];
}

const overlaps = (a: { start: number; end: number }, start: number, end: number) => a.start < end && start < a.end;

// ======== Score one file =========
export function scoreFile(text: string, labels: Labels, spans: Detected[]): FileScore {
    const masked = new Uint8Array(text.length);
    for (const s of spans) masked.fill(1, s.start, s.end);
    const visible = (i: number) => !masked[i] && !/\s/.test(text[i]);
    const counted = (i: number) => !/\s/.test(text[i]);

    const byType = new Map<EntityType, Counts>();
    const countsOf = (type: EntityType) => byType.get(type) ?? byType.set(type, emptyCounts()).get(type)!;
    const all = emptyCounts();
    const hard = emptyCounts();
    const misses: Occurrence[] = [];
    const labelled = new Uint8Array(text.length);
    const anyLabel = new Uint8Array(text.length); // hard labels and ignored words too: masking them isn't over-masking
    for (const o of labels.occurrences) anyLabel.fill(1, o.start, o.end);
    for (const [start, end] of labels.ignored) anyLabel.fill(1, start, end);

    for (const o of labels.occurrences) {
        let chars = 0;
        let leaked = 0;
        for (let i = o.start; i < o.end; i++) {
            if (counted(i)) chars++;
            if (visible(i)) leaked++;
        }
        const c = o.hard ? hard : countsOf(o.type);
        c.labelled++;
        c.found += leaked === 0 ? 1 : 0;
        c.chars += chars;
        c.leaked += leaked;
        if (o.hard) continue;
        if (leaked > 0) misses.push(o);
        all.labelled++;
        all.found += leaked === 0 ? 1 : 0;
        labelled.fill(1, o.start, o.end);
    }

    // "All types" characters as a union, since occurrences of two types can overlap
    for (let i = 0; i < text.length; i++) {
        if (!labelled[i] || !counted(i)) continue;
        all.chars++;
        if (visible(i)) all.leaked++;
    }

    const falsePositives: Detected[] = [];
    const overExtended: Detected[] = [];
    for (const s of spans) {
        const hit = labels.occurrences.some((o) => overlaps(o, s.start, s.end));
        if (!hit && labels.ignored.some(([start, end]) => overlaps(s, start, end))) continue;
        let over = 0;
        for (let i = s.start; i < s.end; i++) if (!anyLabel[i] && counted(i)) over++;
        const c = countsOf(s.type);
        c.detected++;
        all.detected++;
        c.overMasked += over;
        all.overMasked += over;
        if (hit && over > 0) overExtended.push(s);
        if (hit) continue;
        c.falsePositives++;
        all.falsePositives++;
        falsePositives.push(s);
    }
    return { byType, all, hard, misses, falsePositives, overExtended };
}
