// CLI entry point => npm run dev <file>
// Detects and redacts PII in <file> via the Presidio-backed pipeline   ==> Requires the sidecar in presidio/docker-compose.yml

// output contract => REDACTED text goes to reports/<name>__sanitized<ext>

import fs from "node:fs";
import { writeSanitizedReport } from "./pii/generate_reports/writeSanitizedReport";
import { writeJsonReport } from "./pii/generate_reports/writeJsonReport";
import "dotenv/config";
import { redact, InputTooLargeError } from "./pii/redact";
import { PresidioUnavailableError } from "./pii/client";


// ========== Main entry point ==========
async function main() {
    const args = process.argv.slice(2);

    // ensure file path is provided
    if (args.length === 0) {
        console.error("No input file specified.");
        process.exit(1);
    }

    const filePath = args[0];

    // check file existence
    if (!fs.existsSync(filePath)) {
        console.error(`File not found: ${filePath}`);
        process.exit(1);
    }

    const text = fs.readFileSync(filePath, "utf-8");

    try {
        // Redact the text and measure the time taken
        const startTime = performance.now();
        const { text: redacted, spans, metrics } = await redact(text);
        const elapsed = performance.now() - startTime;

        // Write the sanitized report
        const writtenPath = writeSanitizedReport(filePath, redacted);

        // Write a json report with the elapsed time and output path
        const jsonReport = writeJsonReport({
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
        console.error(`JSON report -> ${jsonReport}`);
    } catch (err) {
        // if Presidio is down
        if (err instanceof PresidioUnavailableError) {
            console.error(`\n${err.message}`);
            process.exit(2);
        }

        // if the input text is too large for Presidio to handle
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
