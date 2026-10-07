// CLI entry point => npm run dev <file>
// Detects and redacts PII in <file>, fully in-process   ==> Requires the NER model: npm run fetch:model

// output contract => REDACTED text goes to reports/<name>__sanitized<ext>;
// reports/<name>__report.json lists the detected spans, including their original values

import "dotenv/config";
import fs from "node:fs";
import { writeSanitizedReport } from "./pii/generate_reports/writeSanitizedReport";
import { writeJsonReport } from "./pii/generate_reports/writeJsonReport";
import { redact, InputTooLargeError } from "./pii/redact";
import { ModelLoadError } from "./pii/layers/ner";


// ========== Main entry point ==========
async function main() {
    const args = process.argv.slice(2);

    if (args.length === 0) {
        console.error("No input file specified.");
        process.exit(1);
    }

    const filePath = args[0];

    if (!fs.existsSync(filePath)) {
        console.error(`File not found: ${filePath}`);
        process.exit(1);
    }

    const text = fs.readFileSync(filePath, "utf-8");

    try {
        const startTime = performance.now();
        const { text: redacted, spans, metrics } = await redact(text);
        const elapsed = performance.now() - startTime;

        const writtenPath = writeSanitizedReport(filePath, redacted);

        const reportPath = writeJsonReport({
            inputPath: filePath,
            inputChars: text.length,
            totalMs: elapsed,
            sanitizedPath: writtenPath,
            layerTimingsMs: metrics.layerTimingsMs,
            layerCounts: metrics.layerCounts,
            spans,
        });

        console.error(
            `\nProcessed ${text.length} chars in ${elapsed.toFixed(0)} ms -> ${writtenPath}`,
        );
        console.error(`JSON report -> ${reportPath}`);
    } catch (err) {
        // if the NER model is missing or won't load
        if (err instanceof ModelLoadError) {
            console.error(`\n${err.message}`);
            process.exit(2);
        }

        // if the input text is over the size limit
        if (err instanceof InputTooLargeError) {
            console.error(`\n${err.message}`);
            process.exit(1);
        }
        throw err;
    }
}


main().catch((err) => {
    console.error(
        `Redaction failed (${err instanceof Error ? err.name : "unknown error"}). No output was written.`,
    );
    process.exit(3);
});
