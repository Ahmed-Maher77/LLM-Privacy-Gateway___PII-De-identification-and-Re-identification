// Write reports/<name>__report.json: input and output metadata, performance metrics, and the detected PII spans with their original values

import path from "node:path";
import type { JsonReportInput } from "../types";
import { writeReportFile } from "./reportFile";


export function writeJsonReport(input: JsonReportInput): string {
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

    return writeReportFile(input.inputPath, "report.json", `${JSON.stringify(report, null, 2)}\n`);
}
