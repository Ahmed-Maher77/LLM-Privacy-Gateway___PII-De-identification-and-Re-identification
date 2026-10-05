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
        if (span.source) {
            countsBySource[span.source] = (countsBySource[span.source] ?? 0) + 1;
        }
    }

    const report = {
        input: {
            fileName: path.basename(input.inputPath),
            characters: input.inputChars,
        },
        output: {
            sanitizedFile: input.sanitizedPath.replace(/\\/g, "/"),
        },
        performance: {
            totalMs: Number(input.totalMs.toFixed(3)),
        },
        detected: {
            total: input.spans.length,
            byType: countsByType,
            bySource: countsBySource,
            spans: input.spans.map(({ value, type, start, end, source }) => ({
                value,
                type,
                start,
                end,
                ...(source ? { source } : {}),
            })),
        },
    };

    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(
        reportPath,
        `${JSON.stringify(report, null, 2)}\n`,
        "utf-8",
    );
    return reportPath.replace(/\\/g, "/");
}
