import { writeJsonReport } from "./generate_reports/writeJsonReport";
import { writeSanitizedReport } from "./generate_reports/writeSanitizedReport";
import { detectPII, maskPII } from "./pii-masker";
import fs from "node:fs";

const inputPath = "test_data/mockup_interview.txt";
const text = fs.readFileSync(inputPath, "utf-8");

const config = {
  EMAIL: true,
  URL: true,
  DATE: true,
  MONEY: false,
  PERSON: true,
  LOCATION: true,
  ORGANIZATION: true,
  MENTION: true,
  PHONE: true,
};

console.log("=== ORIGINAL ===");
console.log(text);

console.log("\n=== DETECTED PII ===");

const startTime = performance.now();
const matches = detectPII(text, config);

for (const match of matches) {
  console.log(match);
}

const endTime = performance.now();
const totalTime = endTime - startTime;

const sanitizedText = maskPII(matches, text);
const sanitizedPath = writeSanitizedReport(inputPath, sanitizedText);

const reportPath = writeJsonReport({
  inputPath,
  inputChars: text.length,
  totalMs: totalTime,
  sanitizedPath,
  spans: matches,
});

console.log("\n=== EXECUTION SUMMARY ===");
console.log(`Detected Spans: ${matches.length}`);
console.log(`Sanitized File: ${sanitizedPath}`);
console.log(`Report File:    ${reportPath}`);