import fs from 'node:fs';
import path from 'node:path';
import type { EntityMap, EntityMappingEntry, PIIMatch } from './pii/types.js';

export interface OutputInFileOptions {
  filename?: string;        // default: 'sanitized_output.txt'
  reportFilename?: string;  // default: 'sanitized_output_report.json'
  outputDir?: string;       // default: 'sanitized_output'
  originalText?: string;
  matches?: PIIMatch[];
  entityMap?: EntityMap;
  entities?: EntityMappingEntry[];
}

export interface OutputResult {
  outputPath: string;
  reportPath: string;
}

/**
 * Saves sanitized text to `sanitized_output/sanitized_output.txt`
 * and writes a structured JSON report to `sanitized_output/sanitized_output_report.json`.
 */
export function output_in_file(
  sanitizedText: string,
  options?: OutputInFileOptions
): OutputResult {
  const outputDir = path.resolve(process.cwd(), options?.outputDir ?? 'sanitized_output');

  fs.mkdirSync(outputDir, { recursive: true });

  // 1. Write the masked text to sanitized_output.txt
  const outputPath = path.join(outputDir, options?.filename ?? 'sanitized_output.txt');
  fs.writeFileSync(outputPath, sanitizedText, 'utf-8');

  // 2. Write the audit report as JSON
  const reportPath = path.join(outputDir, options?.reportFilename ?? 'sanitized_output_report.json');
  const relativeOutputPath = path.relative(process.cwd(), outputPath).replace(/\\/g, '/');
  const reportData = {
    timestamp: new Date().toISOString(),
    originalLength: options?.originalText ? options.originalText.length : null,
    sanitizedLength: sanitizedText.length,
    entitiesFound: options?.matches?.length ?? 0,
    outputFile: relativeOutputPath,
    matches: options?.matches ?? [],
    ...(options?.entityMap ? { entityMap: options.entityMap } : {}),
    ...(options?.entities ? { entities: options.entities } : {}),
  };

  fs.writeFileSync(reportPath, JSON.stringify(reportData, null, 2), 'utf-8');

  return { outputPath, reportPath };
}

export const outputInFile = output_in_file;
