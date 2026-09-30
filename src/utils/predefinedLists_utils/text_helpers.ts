// ========= Titles and honorifics that precede a name =========
export const TITLES = new Set(
    ("mr mrs ms miss dr doctor prof sir madam mister eng " +
        "agent customer caller client officer rep representative manager supervisor director operator " +
        "moderator interviewer subject speaker patient nurse user " +
        "wife husband brother sister son daughter mother father mom mum dad uncle aunt cousin friend colleague boss").split(" "),
);


// ========= Fillers, greetings or everyday Arabic expressions ==========
export const NEVER_NAMES = new Set(
    ("uh uhh uhm um umm hmm hm mm mmm mhm ohh ahh ah er erm huh yeah yes yep yup ok okay sure alright perfect great " +
        "hi hello hey dear bye thanks " +
        "salam salaam inshallah insha'allah mashallah alhamdulillah elhamdulillah hamdulillah " +
        "yalla habibi habibti ahlan marhaba shukran khalas wallah wallahi bismillah").split(" "),
);


// ========= Particles that are part of a name, but not a name themselves ("al", "bin", "van") =========
export const PARTICLES = new Set("al el abd abdel abdul abu bin ibn bint ben van von der den de da di del la le du dos mac mc".split(" "));

export const isAllCaps = (w: string) => /^\p{Lu}[\p{Lu}\p{N}&.-]+$/u.test(w);


// ========= get the line of text containing position `at` =========
export const lineOf = (text: string, at: number) =>
    text.slice(text.lastIndexOf("\n", at) + 1, (text.indexOf("\n", at) + 1 || text.length + 1) - 1);



// ========= To match any of `values` as whole words =========
const escapeRegex = (v: string) => v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export function wholeWords(values: string[], flags: string, anySpace = true): RegExp {
    const alternatives = [...values]
        .sort((a, b) => b.length - a.length) // longest first, so "Sarah Johnson" wins over "Sarah"
        .map(escapeRegex)
        .map((v) => (anySpace ? v.replace(/\s+/g, "\\s+") : v));
    return new RegExp(`(?<![\\p{L}\\p{N}_])(?:${alternatives.join("|")})(?![\\p{L}\\p{N}_])`, flags);
}
