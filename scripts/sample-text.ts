// Text of about `chars` characters, built in memory from test_data/*.txt
// (repeated, cut at a line break), for the speed and offset checks.

import fs from "node:fs";
import path from "node:path";

export function sampleText(chars: number): string {
    const all = fs
        .readdirSync("test_data")
        .filter((f) => f.endsWith(".txt"))
        .map((f) => fs.readFileSync(path.join("test_data", f), "utf-8"));
    let text = "";
    while (text.length < chars) text += all.join("\n");
    return text.slice(0, text.lastIndexOf("\n", chars) + 1);
}
