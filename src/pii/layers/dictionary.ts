// Layer 1 => dictionary-based detection of names (companies come only from
// config/predefined-list.json)


import fs from "node:fs";
import path from "node:path";
import { isEnglishWord } from "./wink";
import type { Lists, PIISpan, Word } from "../types";
import { isCapitalised, isAllCaps, hasInnerCapital, lineOf, words, isGiven, isSurnameLike, adjacent, TITLES, NEVER_NAMES, PARTICLES, isNameShaped, PLACE_WORDS, ORGANIZATION_WORDS } from "./dictionary_helpers";


const LIST_DIR = path.resolve(__dirname, "../../../data/lists");


let lists: Lists | undefined;

// ========== read a list from a file ==========
function readList(file: string, key: (line: string) => string = (l) => l.toLowerCase()): Set<string> {
  const full = path.join(LIST_DIR, file);
  if (!fs.existsSync(full)) return new Set();
  const out = new Set<string>();
  for (const line of fs.readFileSync(full, "utf-8").split("\n")) {
    if (line && !line.startsWith("#")) out.add(key(line.trim()));
  }
  return out;
}


// ========== load the lists (once) =========
function loadLists(): Lists {
  lists ??= {
    given: readList("given-names.txt"),
    surnames: readList("surnames.txt"),
    places: readList("places.txt"),
  };
  return lists;
}


// ========== Find names in text using the lists ==========
function findNames(text: string, ws: Word[], l: Lists): PIISpan[] {
  const out: PIISpan[] = [];
  const span = (from: number, to: number): PIISpan => ({
    start: ws[from].start,
    end: ws[to].end,
    type: "PERSON",
    text: text.slice(ws[from].start, ws[to].end),
    source: "dictionary",
  });

  for (let i = 0; i < ws.length; i++) {
    const first = ws[i].text;
    const lower = first.toLowerCase();
    if (!isNameShaped(first) || !isGiven(first, l) || TITLES.has(lower) || PLACE_WORDS.has(lower) || NEVER_NAMES.has(lower)) continue;

    // Full name: capitalised given name + 1–3 more name words (particles allowed in between)
    if (isCapitalised(first) && !isAllCaps(first)) {
      let last = i;
      for (let j = i + 1; j < ws.length && j - i < 6; j++) {
        if (!adjacent(text, ws[j - 1], ws[j])) break;
        const w = ws[j].text;
        if (PARTICLES.has(w.toLowerCase()) && !isCapitalised(w)) continue; // "van", "el", "bin" before the surname
        if (!isNameShaped(w) || !isCapitalised(w) || isAllCaps(w) || NEVER_NAMES.has(w.toLowerCase())) break;
        if (!(isSurnameLike(w, l) || !isEnglishWord(w))) break;
        last = j;
      }
      const run = ws.slice(i, last + 1);
      const lastWord = ws[last].text.toLowerCase();
      const next = ws[last + 1] && adjacent(text, ws[last], ws[last + 1]) ? ws[last + 1].text.toLowerCase() : "";
      if (
        last > i &&
        run.some((w) => !isEnglishWord(w.text)) &&
        !l.places.has(run.map((w) => w.text.toLowerCase()).join(" ")) &&
        !l.places.has(`${first.toLowerCase()} ${ws[i + 1].text.toLowerCase()}`) &&
        ![lastWord, next].some((w) => PLACE_WORDS.has(w) || ORGANIZATION_WORDS.has(w))
      ) {
        out.push(span(i, last));
        i = last;
        continue;
      }
    }

    // Single name: a given name that isn't an English word or a place
    if (first.length < 3 || isAllCaps(first) || hasInnerCapital(first) || isEnglishWord(first) || l.places.has(lower)) continue;
    if (!isCapitalised(first) && /\p{Lu}/u.test(lineOf(text, ws[i].start))) continue;
    const next = ws[i + 1];
    const withSurname =
      next &&
      adjacent(text, ws[i], next) &&
      isNameShaped(next.text) &&
      isCapitalised(next.text) === isCapitalised(first) &&
      !isAllCaps(next.text) &&
      !isEnglishWord(next.text) &&
      !PLACE_WORDS.has(next.text.toLowerCase()) &&
      !NEVER_NAMES.has(next.text.toLowerCase()); // "youssef salam"
    out.push(span(i, withSurname ? i + 1 : i));
    if (withSurname) i++;
  }
  return out;
}


// ========= List lookups for the other layers ==========
export function isListedGivenName(word: string): boolean {
  return isGiven(word, loadLists());
}

// ========= Detect names in text using the lists ==========
export function detectDictionary(text: string): PIISpan[] {
  const l = loadLists();
  const ws = words(text);
  return findNames(text, ws, l);
}
