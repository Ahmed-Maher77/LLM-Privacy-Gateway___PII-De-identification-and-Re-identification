// Write the sanitized text to a file

import fs from "node:fs";
import path from "node:path";

export function writeSanitizedReport(inputPath: string, redactedText: string): string {
    const extension = path.extname(inputPath);
    const baseName = path.basename(inputPath, extension);
    const reportPath = path.join(
        "reports",
        `${baseName}__sanitized${extension}`,
    );
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, redactedText, "utf-8");
    return reportPath.replace(/\\/g, "/");
}
