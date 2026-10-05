import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { detectPII, maskPII } from "../src/pii-masker";
import { writeJsonReport } from "../src/generate_reports/writeJsonReport";
import { writeSanitizedReport } from "../src/generate_reports/writeSanitizedReport";
import type { PIIMatch } from "../src/types";

test("detectPII handles empty input gracefully", () => {
  const result = detectPII("");
  assert.deepEqual(result, []);
});

test("detectPII extracts email and date with exact character offsets", () => {
  const text = "Please reach out to support@example.com before 25 Dec 2025.";
  const matches = detectPII(text, { EMAIL: true, DATE: true });

  assert.ok(matches.length >= 2, "Expected at least 2 matches");

  for (const match of matches) {
    const sliced = text.slice(match.start, match.end);
    assert.equal(
      sliced,
      match.value,
      `Span [${match.start}, ${match.end}] slice '${sliced}' does not match entity value '${match.value}'`,
    );
  }

  const emailMatch = matches.find((m) => m.type === "EMAIL");
  assert.ok(emailMatch);
  assert.equal(emailMatch.value, "support@example.com");

  const dateMatch = matches.find((m) => m.type === "DATE");
  assert.ok(dateMatch);
  assert.equal(dateMatch.value, "25 Dec 2025");
});

test("detectPII does not match substrings of non-entity words (collision bug test)", () => {
  const text = "notoday is not a real day, but today is.";
  const matches = detectPII(text, { DATE: true });

  const todayMatch = matches.find((m) => m.value === "today");
  assert.ok(todayMatch, "Should detect 'today' entity");
  assert.ok(
    todayMatch.start > 15,
    `'today' should match the standalone date at offset 31, not inside 'notoday' (got start: ${todayMatch.start})`,
  );
  assert.equal(text.slice(todayMatch.start, todayMatch.end), "today");
});

test("detectPII respects config filtering", () => {
  const text = "Email test@example.com on 15 Jan 2025";
  const emailOnly = detectPII(text, { EMAIL: true, DATE: false });
  assert.equal(emailOnly.length, 1);
  assert.equal(emailOnly[0]?.type, "EMAIL");

  const dateOnly = detectPII(text, { EMAIL: false, DATE: true });
  assert.equal(dateOnly.length, 1);
  assert.equal(dateOnly[0]?.type, "DATE");
});

test("detectPII accurately handles multiple occurrences of the same entity", () => {
  const text = "Send to user@example.com and cc user@example.com.";
  const matches = detectPII(text, { EMAIL: true });

  assert.equal(matches.length, 2);
  assert.equal(matches[0]?.value, "user@example.com");
  assert.equal(matches[1]?.value, "user@example.com");
  assert.notEqual(matches[0]?.start, matches[1]?.start);

  assert.equal(text.slice(matches[0]!.start, matches[0]!.end), "user@example.com");
  assert.equal(text.slice(matches[1]!.start, matches[1]!.end), "user@example.com");
});

test("maskPII replaces detected entities cleanly", () => {
  const text = "Contact hello@world.com for support.";
  const matches = detectPII(text, { EMAIL: true });
  const masked = maskPII(matches, text);

  assert.equal(masked, "Contact [EMAIL] for support.");
});

test("maskPII safely handles overlapping or duplicated spans without corrupting text", () => {
  const text = "Important meeting with John Doe at noon.";
  const overlappingMatches: PIIMatch[] = [
    { type: "PERSON", value: "John Doe", start: 23, end: 31 },
    { type: "PERSON", value: "John", start: 23, end: 27 },
    { type: "TIME", value: "noon", start: 35, end: 39 },
  ];

  const masked = maskPII(overlappingMatches, text);
  assert.equal(masked, "Important meeting with [PERSON] at [TIME].");
});

test("maskPII returns original text if matches are empty", () => {
  const text = "No sensitive data here.";
  const masked = maskPII([], text);
  assert.equal(masked, text);
});

test("reporting functions create valid files and normalized paths", () => {
  const tempInput = "test_data/mockup_interview.txt";
  const dummyMatches: PIIMatch[] = [
    { type: "EMAIL", value: "test@domain.com", start: 0, end: 15, source: "wink-nlp" },
  ];

  const sanitizedPath = writeSanitizedReport(tempInput, "[EMAIL] test content");
  assert.ok(fs.existsSync(sanitizedPath), `Sanitized file should exist at ${sanitizedPath}`);
  assert.ok(!sanitizedPath.includes("\\"), "Path should use forward slashes");

  const reportPath = writeJsonReport({
    inputPath: tempInput,
    inputChars: 100,
    totalMs: 12.345,
    sanitizedPath,
    spans: dummyMatches,
  });

  assert.ok(fs.existsSync(reportPath), `Report file should exist at ${reportPath}`);
  const reportContent = JSON.parse(fs.readFileSync(reportPath, "utf-8"));
  assert.equal(reportContent.detected.total, 1);
  assert.equal(reportContent.detected.byType.EMAIL, 1);
  assert.equal(reportContent.detected.bySource["wink-nlp"], 1);
  assert.equal(reportContent.detected.spans[0].value, "test@domain.com");
  assert.equal(reportContent.detected.spans[0].start, 0);
  assert.equal(reportContent.detected.spans[0].end, 15);
});
