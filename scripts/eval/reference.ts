// Recover the masked spans from a saved sanitized file, by aligning it with
// the original text. Each placeholder <TYPE_N> stands for one merged span.
// Lines are aligned one by one (placeholders never cross a line break), so
// a file that doesn't match its original fails fast with the line number.

import { ENTITY_TYPES, type EntityType } from "../../src/pii/types";
import type { Detected } from "./score";
import { escapeRegex } from "../../src/pii/patterns";

const PLACEHOLDER_RE = new RegExp(`<(${ENTITY_TYPES.join("|")})_\\d+>`, "g");

// ======== Align one sanitized line with its original line =========
function alignLine(original: string, sanitized: string, offset: number): Detected[] | undefined {
    const types = [...sanitized.matchAll(PLACEHOLDER_RE)].map((m) => m[1] as EntityType);
    if (types.length === 0) return original === sanitized ? [] : undefined;

    const literals = sanitized.split(PLACEHOLDER_RE).filter((_, i) => i % 2 === 0);
    const pattern = new RegExp(`^${literals.map(escapeRegex).join("([^\\r\\n]+?)")}$`, "d");
    const m = pattern.exec(original);
    const indices = m?.indices;
    if (!indices) return undefined;
    return types.map((type, i) => {
        const [start, end] = indices[i + 1]!;
        return { type, start: offset + start, end: offset + end };
    });
}

// ======== Masked spans of a sanitized file, with offsets into the original =========
export function spansFromSanitized(original: string, sanitized: string): Detected[] {
    const a = original.split("\n");
    const b = sanitized.split("\n");
    if (a.length !== b.length) throw new Error(`${b.length} lines, the original has ${a.length}`);

    const spans: Detected[] = [];
    let offset = 0;
    for (let i = 0; i < a.length; i++) {
        const line = alignLine(a[i], b[i], offset);
        if (!line) throw new Error(`line ${i + 1} does not match the original`);
        spans.push(...line);
        offset += a[i].length + 1;
    }
    return spans;
}
