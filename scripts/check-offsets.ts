// Offset check => npm run check:offsets
//   Runs the NER layer and the whole pipeline on inputs that are easy to get
//   wrong, and fails if any span doesn't equal text.slice(start, end), splits
//   a surrogate pair, or (for NER names) crosses a line break:
//     - emoji and other characters outside the BMP
//     - CRLF line endings
//     - a name at every position around the first window boundary
//     - a 229 KB file built from test_data/
//   The inputs are synthetic or test data; only counts are printed.

import fs from "node:fs";
import path from "node:path";
import "dotenv/config";
import { detect } from "../src/pii/redact";
import { detectNer } from "../src/pii/layers/ner";
import type { PIISpan } from "../src/pii/types";

const NON_BMP = [
    "😅 Hi, I'm Kofi Mensah 😅 and this is Sarah Johnson👋.",
    "👩‍👩‍👧 family: Priya Raman, 🇪🇬 Ahmed Maher, ❤️ Grace Hopper.",
    "𝒜𝒷𝒸 Dr. Beverly Crusher ​ called José and José at 617-555-0142 😅😅😅",
    "Mixed 中文 名字 and Yvette Picard 🙂 kofi.mensah82@gmail.com",
];

const FILLER =
    "thanks for calling today, I can help you with the account. Let me pull up the details and check the last " +
    "payment on file. It looks like the transfer went through on time, so the balance should update soon. ";

const isLow =(c: number) => c >= 0xdc00 && c <= 0xdfff;

// ======== Every problem with a list of spans, as short messages =========
function problems(text: string, spans: PIISpan[], layer: string): string[] {
    const out: string[] = [];
    for (const s of spans) {
        const where = `${layer} ${s.type} [${s.start}, ${s.end})`;
        if (!(0 <= s.start && s.start < s.end && s.end <= text.length)) out.push(`${where}: out of range`);
        else if (s.text !== text.slice(s.start, s.end)) out.push(`${where}: text doesn't equal the slice`);
        else if (isLow(text.charCodeAt(s.start)) || isLow(text.charCodeAt(s.end))) out.push(`${where}: splits a surrogate pair`);
        else if (layer === "ner" && s.type === "PERSON" && /[\r\n]/.test(s.text)) out.push(`${where}: name crosses a line break`);
    }
    return out;
}

async function check(name: string, text: string): Promise<{ failures: string[]; ner: PIISpan[] }> {
    const ner = await detectNer(text);
    const failures = [...problems(text, ner, "ner"), ...problems(text, await detect(text), "pipeline")];
    return { failures, ner };
}

// ======== The labelled test data, repeated up to 229 KB and cut at a line break =========
function bigText(): string {
    const all = fs.readdirSync("test_data").filter((f) => f.endsWith(".txt")).map((f) => fs.readFileSync(path.join("test_data", f), "utf-8"));
    let text = "";
    while (text.length < 229 * 1024) text += all.join("\n");
    return text.slice(0, text.lastIndexOf("\n", 229 * 1024) + 1);
}

async function main() {
    let failed = 0;
    const report = (name: string, failures: string[], extra = "") => {
        failed += failures.length;
        console.log(`${failures.length ? "FAIL" : "ok  "}  ${name}${extra}`);
        for (const f of failures.slice(0, 10)) console.log(`      ${f}`);
    };

    for (const [name, text] of [
        ["emoji and non-BMP characters", NON_BMP.join("\n")],
        ["CRLF line endings", NON_BMP.join("\r\n") + "\r\n" + fs.readFileSync("test_data/test_5.txt", "utf-8")],
    ]) {
        const { failures, ner } = await check(name, text);
        report(name, failures, `  (${ner.length} NER spans)`);
    }

    // k words of ordinary, name-free text put the name at every position from
    // well inside the first window (256 sub-tokens) to inside the second
    let found = 0;
    const positions = 80;
    const boundaryFailures: string[] = [];
    const filler = FILLER.repeat(8).split(" ");
    for (let k = 170; k < 170 + positions; k++) {
        const prefix = `${filler.slice(0, k).join(" ")}\nMy name is `;
        const text = `${prefix}Sarah Johnson and I called.`;
        const { failures, ner } = await check(`boundary ${k}`, text);
        boundaryFailures.push(...failures);
        // Found if every letter of the name is inside a PERSON span (one span or one per word)
        const covered = (i: number) => text[i] === " " || ner.some((s) => s.type === "PERSON" && s.start <= i && i < s.end);
        if ([...Array("Sarah Johnson".length).keys()].every((i) => covered(prefix.length + i))) found++;
    }
    report("name around the first window boundary", boundaryFailures, `  (name fully masked at ${found}/${positions} positions)`);

    const big = bigText();
    const started = performance.now();
    const { failures, ner } = await check("229 KB", big);
    report(`${(big.length / 1024).toFixed(0)} KB file`, failures, `  (${ner.length} NER spans, ${(performance.now() - started).toFixed(0)} ms for NER + pipeline)`);

    if (failed > 0) {
        console.log(`\n${failed} offset problem(s).`);
        process.exit(1);
    }
    console.log("\nAll spans equal text.slice(start, end).");
}

main().catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(2);
});
