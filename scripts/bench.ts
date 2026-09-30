// Speed => npm run bench
//   Cold and warm redact() time and peak memory for 6 KB, ~60 KB and 229 KB
//   of text built in memory from test_data/, median of 5 runs, printed as
//   the table in README.md. Each run is a fresh process: cold is its first
//   call (name lists and model load included, as in one CLI run), warm its
//   second (as in library use).

import { execFileSync } from "node:child_process";
import "dotenv/config";
import { redact } from "../src/pii/redact";
import { sampleText } from "./sample-text";

const SIZES_KB = [6, 60, 229];
const RUNS = 5;

interface Run {
    cold: number;
    warm: number;
    peakMB: number;
}

const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[xs.length >> 1];
const seconds = (ms: number) => `${(ms / 1000).toFixed(ms < 1000 ? 2 : 1)} s`;

// ======== One run, in its own process =========
async function run(kb: number): Promise<void> {
    const text = sampleText(kb * 1024);
    const time = async () => {
        const started = performance.now();
        await redact(text);
        return performance.now() - started;
    };
    const cold = await time();
    const warm = await time();
    console.log(JSON.stringify({ cold, warm, peakMB: process.resourceUsage().maxRSS / 1024 }));
}

async function main() {
    const at = process.argv.indexOf("--run");
    if (at >= 0) return run(Number(process.argv[at + 1]));

    console.log("| Input | Cold | Warm | Peak memory |\n| --- | --- | --- | --- |");
    for (const kb of SIZES_KB) {
        const runs: Run[] = [];
        for (let i = 0; i < RUNS; i++) {
            // Same Node flags (tsx's loader), so the child runs this file the same way
            const out = execFileSync(process.execPath, [...process.execArgv, __filename, "--run", String(kb)], { encoding: "utf-8" });
            runs.push(JSON.parse(out.trim().split("\n").pop()!));
        }
        const gb = median(runs.map((r) => r.peakMB)) / 1024;
        console.log(`| ${kb} KB | ${seconds(median(runs.map((r) => r.cold)))} | ${seconds(median(runs.map((r) => r.warm)))} | ${gb.toFixed(2)} GB |`);
    }
}

main().catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
});
