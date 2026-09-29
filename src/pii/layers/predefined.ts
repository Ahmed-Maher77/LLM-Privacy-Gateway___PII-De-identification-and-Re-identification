// Layer 1 — pre-defined list contains (known customer/employee names, account emails, ...)
      // whether that is a full name or a partial name


import fs from "node:fs";
import path from "node:path";
import { ENTITY_TYPES, PredefinedList, type EntityType, type PIISpan } from "../types";

const LIST_FILE = path.resolve(__dirname, "../../../config/predefined-list.json");

const LEGAL_SUFFIX_RE = /[\s,]+(?:inc|incorporated|llc|llp|ltd|limited|plc|corp|corporation|co|company|gmbh|ag|sa|s\.a|s\.a\.e|bv|nv|pty)\.?$/i;

let cached: { type: EntityType; pattern: RegExp }[] | undefined;


const escape = (v: string) => v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s+");     // Escape special characters + Flexible spacing
const wholeWords = (alternatives: string[], flags: string) =>
  new RegExp(`(?<![\\p{L}\\p{N}_])(?:${alternatives.join("|")})(?![\\p{L}\\p{N}_])`, flags);



// ========= Load the pre-defined list and cache them =========
function loadPatterns(): { type: EntityType; pattern: RegExp }[] {
  if (cached) return cached;

  const list: PredefinedList = fs.existsSync(LIST_FILE) ? JSON.parse(fs.readFileSync(LIST_FILE, "utf-8")) : {};
  cached = [];

  for (const [type, values] of Object.entries(list)) {
    if (!ENTITY_TYPES.includes(type as EntityType)) {
      throw new Error(`${LIST_FILE}: unknown type "${type}". Known: ${ENTITY_TYPES.join(", ")}.`);
    }

    const words = (values ?? []).map((v) => v.trim()).filter(Boolean);
    if (words.length === 0) continue;

    // Longest first, so "Sarah Johnson" wins over "Sarah"
    const byLength = (a: string, b: string) => b.length - a.length;
    cached.push({ type: type as EntityType, pattern: wholeWords([...words].sort(byLength).map(escape), "giu") });

    // Short company names: "Exampleco Inc" -> "Exampleco", "EXAMPLECO" (case-sensitive)
    if (type === "ORGANIZATION") {
      const shortNames = words.map((v) => v.replace(LEGAL_SUFFIX_RE, "")).filter((v, i) => v !== words[i] && v.length >= 2);
      const forms = [...new Set(shortNames.flatMap((v) => [v, v.toUpperCase()]))];
      if (forms.length > 0) cached.push({ type: "ORGANIZATION", pattern: wholeWords(forms.sort(byLength).map(escape), "gu") });
    }
  }
  return cached;
}

// ======== Detect pre-defined list matches in text =========
export function detectPredefined(text: string): PIISpan[] {
  const spans: PIISpan[] = [];
  for (const { type, pattern } of loadPatterns()) {
    for (const m of text.matchAll(pattern)) {
      spans.push({ start: m.index, end: m.index + m[0].length, type, text: m[0], source: "predefined" });
    }
  }
  return spans;
}
