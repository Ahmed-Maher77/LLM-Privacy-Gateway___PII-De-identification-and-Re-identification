import { describe, it, expect, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { output_in_file } from '../src/sanitizer-output.js';
import type { PIIMatch } from '../src/pii/types.js';

describe('output_in_file', () => {
  const testOutputDir = path.resolve(process.cwd(), 'sanitized_output_test');

  afterEach(() => {
    if (fs.existsSync(testOutputDir)) {
      fs.rmSync(testOutputDir, { recursive: true, force: true });
    }
  });

  it('saves sanitized text and returns file paths', () => {
    const content = 'My name is [PERSON] and my email is [EMAIL].';
    const { outputPath, reportPath } = output_in_file(content, {
      outputDir: 'sanitized_output_test',
      filename: 'test_output.txt',
    });

    expect(fs.existsSync(outputPath)).toBe(true);
    expect(fs.existsSync(reportPath)).toBe(true);
    const saved = fs.readFileSync(outputPath, 'utf-8');
    expect(saved).toBe(content);
  });

  it('creates a JSON audit report with entity details', () => {
    const original = 'My name is Ahmed and email is ahmed@example.com';
    const content = 'My name is [PERSON] and email is [EMAIL]';
    const matches: PIIMatch[] = [
      {
        type: 'PERSON',
        value: 'Ahmed',
        start: 11,
        end: 16,
        method: 'winknlp',
      },
      {
        type: 'EMAIL',
        value: 'ahmed@example.com',
        start: 30,
        end: 47,
        method: 'regex',
      },
    ];

    const { outputPath, reportPath } = output_in_file(content, {
      outputDir: 'sanitized_output_test',
      filename: 'sanitized_output.txt',
      reportFilename: 'sanitized_output_report.json',
      originalText: original,
      matches,
    });

    expect(fs.existsSync(outputPath)).toBe(true);
    expect(fs.existsSync(reportPath)).toBe(true);

    const reportJson = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
    expect(reportJson.entitiesFound).toBe(2);
    expect(reportJson.matches).toHaveLength(2);
    expect(reportJson.matches[0].value).toBe('Ahmed');
    expect(reportJson.matches[1].value).toBe('ahmed@example.com');
  });
});
