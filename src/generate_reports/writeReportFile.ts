// Write a report for the input file to reports/<baseName>__<suffix> and return its path with forward slashes

import fs from "node:fs";
import path from "node:path";

export function writeReportFile(inputPath: string, suffix: string, content: string): string {
    const baseName = path.basename(inputPath, path.extname(inputPath));
    const reportPath = path.join("reports", `${baseName}__${suffix}`);
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, content, "utf-8");
    return reportPath.replace(/\\/g, "/");
}
