// Write the JSON report to a file contains: input and output metadata, performance metrics, and detected PII spans

import fs from "node:fs";
import path from "node:path";
import type { JsonReportInput } from "../types";


export function writeJsonReport(input: JsonReportInput): string {
    const extension = path.extname(input.inputPath);
    const baseName = path.basename(input.inputPath, extension);
    const reportPath = path.join("reports", `${baseName}__report.json`);
    const countsByType: Record<string, number> = {};
    const countsBySource: Record<string, number> = {};

    for (const span of input.spans) {
        countsByType[span.type] = (countsByType[span.type] ?? 0) + 1;
        countsBySource[span.source] = (countsBySource[span.source] ?? 0) + 1;
    }

    const report = {
        input: {
            fileName: path.basename(input.inputPath),
            characters: input.inputChars,
        },
        output: {
            sanitizedFile: input.sanitizedPath,
        },
        performance: {
            totalMs: Number(input.totalMs.toFixed(3)),
            layers: Object.fromEntries(
                Object.entries(input.layerTimingsMs).map(
                    ([layer, milliseconds]) => [
                        layer,
                        {
                            milliseconds: Number(milliseconds.toFixed(3)),
                            detected: input.layerCounts[layer] ?? 0,
                        },
                    ],
                ),
            ),
        },
        detected: {
            total: input.spans.length,
            byType: countsByType,
            bySource: countsBySource,
            spans: input.spans.map(({ text, type, score, source }) => ({
                value: text,
                type,
                score,
                source,
            })),
        },
    };

    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(
        reportPath,
        `${JSON.stringify(report, null, 2)}\n`,
        "utf-8",
    );
    return reportPath;
}
