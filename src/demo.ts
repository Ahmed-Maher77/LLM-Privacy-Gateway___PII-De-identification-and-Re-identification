import fs from 'node:fs';
import { detectPII } from './pii/detector.js';
import { maskPIIWithMapping, unmaskPII } from './pii/masker.js';
import { output_in_file } from './sanitizer-output.js';

const FILE_PATH = './samples/large_sample.txt';

// ============================================================================
// Main Execution
// ============================================================================
function runDemo(): void {
  // 1. Resolve input text via CLI arguments or the sample file
  const cliArgs = process.argv.slice(2).filter((arg) => !arg.startsWith('-')).join(' ').trim();
  const hasCliInput = cliArgs.length > 0;
  const text = hasCliInput
    ? cliArgs
    : fs.readFileSync(FILE_PATH, 'utf-8');

  const sourceDesc = hasCliInput
    ? 'CLI argument (inline text)'
    : `File (${FILE_PATH})`;

  console.log('='.repeat(70));
  console.log('WinkNLP PII Detection & Numbered Sanitization Demo');
  console.log('='.repeat(70));
  console.log(`Source:       ${sourceDesc}`);
  console.log(`Input Length: ${text.length} characters\n`);

  // 2. Detect PII entities (defaults plus dates)
  const matches = detectPII(text, { date: true });

  console.log(`Detected Entities (${matches.length} found):`);
  console.log('-'.repeat(70));
  for (const match of matches) {
    const offsets = `[${match.start}, ${match.end}]`.padEnd(12);
    const type = `[${match.type}]`.padEnd(15);
    console.log(`  ${type} ${offsets} "${match.value}" (via ${match.method})`);
  }
  console.log('-'.repeat(70) + '\n');

  // 3. Mask PII with numbering and coreference entity mapping
  const { maskedText, entityMap, entities } = maskPIIWithMapping(text, matches, {
    numbered: true,
    indexBase: 1,
    numberingStrategy: 'entity',
  });

  console.log('NUMBERED SANITIZED OUTPUT PREVIEW:');
  console.log('-'.repeat(70));
  console.log(maskedText);
  console.log('-'.repeat(70) + '\n');

  console.log(`ENTITY MAPPING (${entities.length} distinct entities for de-anonymization / mapping back):`);
  console.log('-'.repeat(70));
  for (const entry of entities) {
    const occStr = entry.occurrences > 1 ? ` (${entry.occurrences} occurrences in text)` : '';
    console.log(`  ${entry.placeholder.padEnd(20)} -> "${entry.value}"${occStr}`);
  }
  console.log('-'.repeat(70) + '\n');

  // 4. Verify round-trip unmasking (de-anonymization)
  const unmaskedText = unmaskPII(maskedText, entityMap);
  const isExactMatch = unmaskedText === text;

  console.log('REVERSIBILITY VERIFICATION:');
  console.log('-'.repeat(70));
  console.log(`✓ Unmasked text matches original input verbatim: ${isExactMatch}`);
  console.log('-'.repeat(70) + '\n');

  // 5. Save sanitized text (.txt) and report (.json)
  const { outputPath, reportPath } = output_in_file(maskedText, {
    originalText: text,
    matches,
    entityMap,
    entities,
  });

  console.log('RESULTS SAVED:');
  console.log(`✓ Sanitized Text:  ${outputPath}`);
  console.log(`✓ JSON Report:     ${reportPath}`);
  console.log('='.repeat(70) + '\n');
}

runDemo();

