import path from "node:path";
import { writeReportFile } from "./reportFile";

// ======== Write the sanitized text to a file ==========
export function writeSanitizedReport(inputPath: string, redactedText: string): string {
    return writeReportFile(inputPath, `sanitized${path.extname(inputPath)}`, redactedText);
}
