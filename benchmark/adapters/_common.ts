// Shared timing and output for the TypeScript adapters.
// Contract (same for every adapter): `<adapter> INPUT OUTPUT RUNS`. The first call
// is timed from process start, so it includes module loading and model loading;
// the remaining RUNS calls are timed individually.

import fs from "node:fs";
import { performance } from "node:perf_hooks";

export async function run(name: string, redact: (text: string) => Promise<string> | string): Promise<void> {
    const [input, output, runs] = process.argv.slice(2);
    if (!input || !output || !runs) throw new Error("usage: <adapter> INPUT OUTPUT RUNS");
    const text = fs.readFileSync(input, "utf-8");

    const sanitized = await redact(text);
    const coldS = performance.now() / 1000; // performance.now() starts at process start

    const warmS: number[] = [];
    for (let i = 0; i < Number(runs); i++) {
        const t0 = performance.now();
        await redact(text);
        warmS.push((performance.now() - t0) / 1000);
    }

    const rssMb = process.memoryUsage().rss / 2 ** 20;
    fs.writeFileSync(output, JSON.stringify({ name, sanitized, cold_s: coldS, warm_s: warmS, rss_mb: rssMb }));
}
