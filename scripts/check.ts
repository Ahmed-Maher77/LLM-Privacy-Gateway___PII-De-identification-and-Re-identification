// Regression check => npm run check
//   Redacts every test_data/*.txt and compares the result with the saved copy
//   in test_data/expected/. Any difference fails, so a change to the rules
//   can't quietly start leaking (or over-redacting) something.
//
//   npm run check -- --update   saves the current output as the new expected
//                               copy; run it only after reviewing the diff.

import fs from "node:fs";
import path from "node:path";
import "dotenv/config";
import { redact } from "../src/pii/redact";

const INPUT_DIR = "test_data";
const EXPECTED_DIR = path.join(INPUT_DIR, "expected");

function firstDifference(expected: string, actual: string): string {
    if (expected === actual) return "";
    const a = expected.split(/\r?\n/);
    const b = actual.split(/\r?\n/);
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
        if (a[i] !== b[i]) return `line ${i + 1}\n    expected: ${a[i] ?? "<end of file>"}\n    actual:   ${b[i] ?? "<end of file>"}`;
    }
    return "line endings (CRLF vs LF)";
}

async function main() {
    const update = process.argv.includes("--update");
    const inputs = fs.readdirSync(INPUT_DIR).filter((f) => f.endsWith(".txt"));
    fs.mkdirSync(EXPECTED_DIR, { recursive: true });

    let failed = 0;
    for (const name of inputs) {
        const { text } = await redact(fs.readFileSync(path.join(INPUT_DIR, name), "utf-8"));
        const expectedPath = path.join(EXPECTED_DIR, name);

        if (update) {
            fs.writeFileSync(expectedPath, text, "utf-8");
            console.log(`saved   ${name}`);
        } else if (!fs.existsSync(expectedPath)) {
            failed++;
            console.log(`MISSING ${name} (run: npm run check -- --update)`);
        } else {
            const diff = firstDifference(fs.readFileSync(expectedPath, "utf-8"), text);
            if (diff) failed++;
            console.log(diff ? `CHANGED ${name}, first difference at ${diff}` : `ok      ${name}`);
        }
    }

    if (failed > 0) {
        console.log(`\n${failed} of ${inputs.length} file(s) differ from ${EXPECTED_DIR}/.`);
        process.exit(1);
    }
    if (!update) console.log(`\nAll ${inputs.length} file(s) match.`);
}

main().catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(2);
});
