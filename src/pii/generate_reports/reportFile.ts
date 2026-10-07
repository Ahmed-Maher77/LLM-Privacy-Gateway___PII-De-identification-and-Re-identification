import fs from "node:fs";
import path from "node:path";

// ======== Write `content` to reports/<input name>__<suffix> ==========
export function writeReportFile(inputPath: string, suffix: string, content: string): string {
    const baseName = path.basename(inputPath, path.extname(inputPath));
    const reportPath = path.join("reports", `${baseName}__${suffix}`);
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, content, "utf-8");
    return reportPath;
}

// ======== Write the sanitized text to a file ==========
export function writeSanitizedReport(inputPath: string, redactedText: string): string {
    return writeReportFile(inputPath, `sanitized${path.extname(inputPath)}`, redactedText);
}
