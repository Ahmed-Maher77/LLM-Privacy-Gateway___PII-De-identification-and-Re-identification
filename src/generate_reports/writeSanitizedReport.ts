// Write the sanitized text to a file

import path from "node:path";
import { writeReportFile } from "./writeReportFile.js";

export function writeSanitizedReport(inputPath: string, redactedText: string): string {
    return writeReportFile(inputPath, `sanitized${path.extname(inputPath)}`, redactedText);
}
