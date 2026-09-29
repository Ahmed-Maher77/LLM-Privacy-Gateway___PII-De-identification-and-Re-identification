// Scoring => npm run eval
//   Runs detect() on every test_data/*.txt and scores it against
//   test_data/labels/<name>.json, per file, per type and in total, then
//   compares the totals with the reference (the Presidio-era output saved in
//   test_data/reference/). Definitions are in scripts/eval/score.ts.
//
//   npm run eval -- --reference   score only the saved reference
//   npm run eval -- --details     also list missed labels and false positives
//
// Prints numbers only: values are shown only with --details, and those come
// from test data.

import fs from "node:fs";
import path from "node:path";
import "dotenv/config";
import { detect } from "../src/pii/redact";
import { ENTITY_TYPES, type EntityType } from "../src/pii/types";
import { loadLabels } from "./eval/labels";
import { spansFromSanitized } from "./eval/reference";
import { addCounts, emptyCounts, scoreFile, type Counts, type Detected, type FileScore } from "./eval/score";

const INPUT_DIR = "test_data";
const LABEL_DIR = path.join(INPUT_DIR, "labels");
const REFERENCE_DIR = path.join(INPUT_DIR, "reference");

interface Scored {
    name: string;
    text: string;
    lowercase: boolean; // speech-to-text: no capital letters at all
    score: FileScore;
}

// ======== Table formatting =========
const pct = (n: number, d: number) => (d === 0 ? "-" : `${((100 * n) / d).toFixed(1)}%`);
const WIDTHS = [18, 9, 7, 8, 11, 9, 10, 5, 11];
const row = (cells: (string | number)[]) =>
    cells.map((c, i) => (i === 0 ? String(c).padEnd(WIDTHS[i]) : String(c).padStart(WIDTHS[i]))).join("");
const HEADER = row(["type", "labelled", "found", "recall", "leaked", "leaked%", "detected", "FP", "precision"]);

// Hard labels get no precision: a detection over one already counts as a hit above
const countsRow = (label: string, c: Counts, precision = true) =>
    row([label, c.labelled, c.found, pct(c.found, c.labelled), `${c.leaked}/${c.chars}`, pct(c.leaked, c.chars),
        ...(precision ? [c.detected, c.falsePositives, pct(c.detected - c.falsePositives, c.detected)] : [])]);

function printTable(title: string, byType: Map<EntityType, Counts>, all: Counts, hard: Counts): void {
    console.log(`\n== ${title}\n${HEADER}`);
    for (const type of ENTITY_TYPES) {
        const c = byType.get(type);
        if (c && (c.labelled > 0 || c.detected > 0)) console.log(countsRow(type, c));
    }
    console.log(countsRow("all types", all));
    if (hard.labelled > 0) console.log(countsRow("hard (apart)", hard, false));
}

// ======== Totals over several files =========
function total(files: Scored[]) {
    const byType = new Map<EntityType, Counts>();
    const all = emptyCounts();
    const hard = emptyCounts();
    for (const { score } of files) {
        for (const [type, c] of score.byType) addCounts(byType.get(type) ?? byType.set(type, emptyCounts()).get(type)!, c);
        addCounts(all, score.all);
        addCounts(hard, score.hard);
    }
    return { byType, all, hard };
}

const person = (files: Scored[]) => total(files).byType.get("PERSON") ?? emptyCounts();

// ======== Score every labelled file, from detect() or the saved reference =========
async function scoreAll(reference: boolean): Promise<Scored[]> {
    const out: Scored[] = [];
    for (const file of fs.readdirSync(INPUT_DIR).filter((f) => f.endsWith(".txt"))) {
        const name = path.basename(file, ".txt");
        const text = fs.readFileSync(path.join(INPUT_DIR, file), "utf-8");
        const labelFile = path.join(LABEL_DIR, `${name}.json`);
        if (!fs.existsSync(labelFile)) throw new Error(`${labelFile} is missing: every test_data file needs labels`);
        const labels = loadLabels(labelFile, text);

        let spans: Detected[];
        if (reference) {
            const saved = path.join(REFERENCE_DIR, `${name}__sanitized.txt`);
            if (!fs.existsSync(saved)) continue;
            try {
                spans = spansFromSanitized(text, fs.readFileSync(saved, "utf-8"));
            } catch (err) {
                throw new Error(`${saved}: ${err instanceof Error ? err.message : err}`);
            }
        } else {
            spans = await detect(text);
        }
        out.push({ name, text, lowercase: !/\p{Lu}/u.test(text), score: scoreFile(text, labels, spans) });
    }
    return out;
}

function printDetails({ text, score }: Scored): void {
    for (const o of score.misses) console.log(`  missed ${o.type} "${o.value}" at ${o.start}`);
    for (const s of score.falsePositives) console.log(`  false positive ${s.type} "${text.slice(s.start, s.end)}" at ${s.start}`);
}

// ======== Current vs reference, on the files both have =========
function printComparison(current: Scored[], reference: Scored[]): void {
    const names = new Set(reference.map((f) => f.name));
    const cur = current.filter((f) => names.has(f.name));
    const missing = current.length - cur.length;
    const a = total(cur);
    const b = total(reference);

    console.log(`\n== Compared with the reference (${cur.length} files)`);
    if (missing > 0) console.log(`   ${missing} file(s) without a reference are left out here`);
    const w = [18, 16, 16, 18];
    const line = (cells: string[]) => cells.map((c, i) => (i === 0 ? c.padEnd(w[i]) : c.padStart(w[i]))).join("");
    const pair = (x: string, y: string) => `${x} / ${y}`;
    console.log(line(["type", "recall", "leaked%", "precision"]) + "     (current / reference)");
    const types = ENTITY_TYPES.filter((t) => (a.byType.get(t)?.labelled ?? 0) + (b.byType.get(t)?.labelled ?? 0) > 0);
    for (const [label, x, y] of [
        ...types.map((t) => [t, a.byType.get(t) ?? emptyCounts(), b.byType.get(t) ?? emptyCounts()] as const),
        ["all types", a.all, b.all] as const,
    ]) {
        console.log(line([label, pair(pct(x.found, x.labelled), pct(y.found, y.labelled)),
            pair(pct(x.leaked, x.chars), pct(y.leaked, y.chars)),
            pair(pct(x.detected - x.falsePositives, x.detected), pct(y.detected - y.falsePositives, y.detected))]));
    }
}

// ======== The two "Done when" criteria of PLAN.md that labels can check =========
function printCriteria(current: Scored[], reference?: Scored[]): void {
    const cased = (files: Scored[]) => person(files.filter((f) => !f.lowercase));
    const lower = (files: Scored[]) => person(files.filter((f) => f.lowercase));
    const ref = (text: string) => (reference ? `   (reference ${text})` : "");
    const [c, l] = [cased(current), lower(current)];
    const [rc, rl] = reference ? [cased(reference), lower(reference)] : [emptyCounts(), emptyCounts()];
    console.log("\n== Criteria");
    console.log(`PERSON recall, normally cased files:  ${c.found}/${c.labelled} ${pct(c.found, c.labelled)}${ref(`${rc.found}/${rc.labelled} ${pct(rc.found, rc.labelled)}`)}`);
    console.log(`PERSON characters leaked, lowercase:  ${l.leaked}/${l.chars} ${pct(l.leaked, l.chars)}${ref(`${rl.leaked}/${rl.chars} ${pct(rl.leaked, rl.chars)}`)}`);
}

async function main() {
    const onlyReference = process.argv.includes("--reference");
    const details = process.argv.includes("--details");

    const scored = await scoreAll(onlyReference);
    for (const f of scored) {
        printTable(`${f.name} (${f.text.length} chars${f.lowercase ? ", lowercase" : ""})`, f.score.byType, f.score.all, f.score.hard);
        if (details) printDetails(f);
    }
    const t = total(scored);
    printTable(`Total, ${scored.length} files${onlyReference ? " (reference)" : ""}`, t.byType, t.all, t.hard);

    const reference = onlyReference ? undefined : await scoreAll(true);
    if (reference) printComparison(scored, reference);
    printCriteria(scored, reference);
}

main().catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(2);
});
