import type { Lists, Word } from "../types";

// Words that end an organisation's or a place's name
export const ORGANIZATION_WORDS = new Set(
    (
        "inc incorporated llc llp ltd limited plc gmbh ag sa corp corporation company co group holdings partners associates " +
        "bank bancorp financial capital insurance assurance technologies technology tech solutions services systems software " +
        "labs industries enterprises consulting logistics pharmaceuticals healthcare health airlines airways motors telecom " +
        "foundation institute university college school academy hospital clinic authority ministry council agency association"
    ).split(" "),
);


// Words that start or end a place's name (street, room, ...)
export const PLACE_WORDS = new Set(
    "street st road rd avenue ave boulevard blvd lane drive way square park plaza hall room building tower center centre bridge airport station lab office team hq rue via calle avenida strasse".split(
        " ",
    ),
);
const PARTICLES = new Set(
    "al el abd abdel abdul abu bin ibn bint ben van von der den de da di del la le du dos mac mc".split(
        " ",
    ),
);


// Particles fused to a surname: "Elsharif", "Al-Rashid", "Abdelmonaem".
const FUSED_PARTICLE_RE =
    /^(?:al|el|abd|abdel|abdul|abu|bin|ibn|ben)[-’']?(?=\p{L}{3,})/iu;

// fillers, greetings or everyday Arabic expressions, never a name ("Uhh", "hi", "Salam!")
const NEVER_NAMES = new Set(
    ("uh uhh uhm um umm hmm hm mm mmm mhm ohh ahh ah er erm huh yeah hi bye thanks " +
        "salam salaam inshallah insha'allah mashallah alhamdulillah elhamdulillah hamdulillah " +
        "yalla habibi habibti ahlan marhaba shukran khalas wallah wallahi bismillah").split(" "),
);
// Words next to a name that are not part of it ("Mr", "doctor"): trimmed from name spans, never spread
const TITLES = new Set(
    "mr mrs ms miss dr doctor prof sir madam mister eng".split(" "),
);


// ========== Break text into words ==========
const WORD_RE = /[\p{L}\p{N}](?:[\p{L}\p{N}&'’.-]*[\p{L}\p{N}])?/gu;

function words(text: string): Word[] {
    return [...text.matchAll(WORD_RE)].map((m) => ({
        text: m[0],
        start: m.index,
        end: m.index + m[0].length,
    }));
}


// ========= Check if a word is capitalised or all-caps ==========
const isCapitalised = (w: string) => /^\p{Lu}/u.test(w);
const isAllCaps = (w: string) => /^\p{Lu}[\p{Lu}\p{N}&.-]+$/u.test(w);
/** A capital after the first letter: "IDs", "GitHub", "iPhone" — words, not a single name. */
const hasInnerCapital = (w: string) => /^.\P{Lu}*\p{Lu}/u.test(w) && /\p{Ll}/u.test(w);


// ========= Get the line of text containing a specific position ==========
const lineOf = (text: string, at: number) =>
    text.slice(
        text.lastIndexOf("\n", at) + 1,
        (text.indexOf("\n", at) + 1 || text.length + 1) - 1,
    );

// ========= Check if a word is shaped like a name (letters, apostrophes and hyphens only) =========
const isNameShaped = (w: string) => /^\p{L}[\p{L}'’-]*$/u.test(w);

/** Only one or two spaces/tabs between two words on the same line. */
const adjacent = (text: string, a: Word, b: Word) =>
    /^[ \t]{1,2}$/.test(text.slice(a.end, b.start));

// ========= Check if a word is a known given name (from the data/lists name registry) ==========
function isGiven(w: string, l: Lists): boolean {
    return l.given.has(w.toLowerCase());
}

// ======== Check if a word is a known surname (from the data/lists name registry) ==========
function isSurnameLike(w: string, l: Lists): boolean {
    const lower = w.toLowerCase();
    if (l.surnames.has(lower) || l.given.has(lower)) return true;
    const base = lower.replace(FUSED_PARTICLE_RE, "");
    return base !== lower && (l.surnames.has(base) || l.given.has(base));
}

export {
    isNameShaped,
    isCapitalised,
    isAllCaps,
    hasInnerCapital,
    lineOf,
    words,
    isGiven,
    isSurnameLike,
    adjacent,
    TITLES,
    NEVER_NAMES,
    PARTICLES,
};
