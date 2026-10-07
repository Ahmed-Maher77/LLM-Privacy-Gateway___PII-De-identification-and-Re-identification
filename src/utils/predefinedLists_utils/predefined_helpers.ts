import { ENTITY_TYPES, EntityType, ListFile, Rule } from "../../pii/types";
import { isCommonWord } from "../ner_utils/vocabulary";
import { NEVER_NAMES, PARTICLES, TITLES, wholeWords } from "./text_helpers";


// ========= A list file is missing or malformed
class ListError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "ListError";
    }
}


// ========= Normalize a value to a key =========
const key = (v: string) => v.trim().replace(/\s+/g, " ").toLowerCase();


// ========= Get the undesired list =========
function undesiredKeys({ json, file }: ListFile): Set<string> {
    if (!Array.isArray(json) || json.some((v) => typeof v !== "string")) {
        throw new ListError(`${file}: must be an array of strings, e.g. ["The", "Cart Service"].`);
    }
    return new Set((json as string[]).map(key).filter(Boolean));
}


const LEGAL_SUFFIX_RE =
    /[\s,]+(?:inc|incorporated|llc|llp|ltd|limited|plc|corp|corporation|co|company|gmbh|ag|sa|s\.a|s\.a\.e|bv|nv|pty)\.?$/i;
const NAME_PART_RE = /^\p{L}[\p{L}'’-]+$/u;
const NAME_SUFFIXES = new Set(["jr", "sr", "ii", "iii", "iv"]);

// ========= Parts of a listed name: "Jean-Luc Picard" -> "Jean-Luc", "Picard" =========
function nameParts(name: string): string[] {
    const words = name.split(/\s+/);
    if (words.length < 2) return [];
    return words.filter((w) => {
        const lower = w.toLowerCase();
        return (
            NAME_PART_RE.test(w) &&
            !TITLES.has(lower) &&
            !PARTICLES.has(lower) &&
            !NEVER_NAMES.has(lower) &&
            !NAME_SUFFIXES.has(lower)
        );
    });
}


// ========= The desired list as match rules: { "PERSON": [...], "ORGANIZATION": [...] } =========
function desiredRules({ json, file }: ListFile): Rule[] {
    // check the JSON file format
    if (typeof json !== "object" || json === null || Array.isArray(json)) {
        throw new ListError(
            `${file}: must be an object, e.g. { "PERSON": ["Sarah Johnson"], "ORGANIZATION": ["Acme Corp"] }.`,
        );
    }

    const rules: Rule[] = [];
    for (const [typeName, values] of Object.entries(json)) {
        // check the type and values are valid
        if (!ENTITY_TYPES.includes(typeName as EntityType)) {
            throw new ListError(
                `${file}: unknown type "${typeName}". Known: ${ENTITY_TYPES.join(", ")}.`,
            );
        }
        if (
            !Array.isArray(values) ||
            values.some((v) => typeof v !== "string")
        ) {
            throw new ListError(
                `${file}: "${typeName}" must be an array of strings.`,
            );
        }
        const type = typeName as EntityType;
        const entries = (values as string[])
            .map((v) => v.trim())
            .filter(Boolean);
        if (entries.length === 0) continue;

        // to detect Whole entries, in any case
        rules.push({ type, pattern: wholeWords(entries, "giu") });

        // Parts of the entries, ex: "Acme Corp" -> "Acme"
        const parts =
            type === "PERSON"
                ? entries.flatMap(nameParts)
                : entries
                      .map((v) => v.replace(LEGAL_SUFFIX_RE, ""))
                      .filter((v, i) => v !== entries[i] && v.length >= 2);
        if (parts.length === 0) continue;
        // As listed, title-cased and upper-cased, so "SARAH JOHNSON" also covers "Sarah"
        const cased = parts.flatMap((p) => [
            p[0].toUpperCase() + p.slice(1),
            p[0].toUpperCase() + p.slice(1).toLowerCase(),
            p.toUpperCase(),
        ]);
        rules.push({
            type,
            pattern: wholeWords([...new Set(cased)], "gu"),
            part: true,
        });
        if (type !== "PERSON") continue;

        // Parts of the entries, lowercased, ex: "Mohsen Saad" -> "mohsen", "saad"
        const lowercase = [
            ...new Set(parts.map((p) => p.toLowerCase())),
        ].filter((p) => !isCommonWord(p));
        if (lowercase.length > 0) {
            rules.push({
                type,
                pattern: wholeWords(lowercase, "gu"),
                part: true,
                lowercaseLinesOnly: true,
            });
        }
    }
    return rules;
}


export {
    ListError,
    key,
    undesiredKeys,
    desiredRules
}