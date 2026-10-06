import fs from 'node:fs';
import { detectPII } from './pii/detector.js';
import { maskPIIWithMapping, unmaskPII } from './pii/masker.js';
import { output_in_file } from './sanitizer-output.js';

// ============================================================================
// STATIC CONFIGURATION: Toggle input source
// ============================================================================
// Set to true to read from FILE_PATH, or false to use SAMPLE_TEXT variable below
const USE_FILE_INPUT = true;
const FILE_PATH = './samples/large_sample.txt';

const SAMPLE_TEXT = `Test Case ID: PII-TEST-001
Date: 2023-10-27
Source: Customer Support Chat Log

[START OF TRANSCRIPT]

Agent (System): Thank you for contacting SecureBank Support. My name is Sarah Jenkins. How can I help you today?

User: Hi Sarah. I’m having trouble logging in. My name is Michael T. Rodriguez, but my account might be under Mike Rodriguez.

Agent: I can help with that, Mr. Rodriguez. Can you please verify your identity? I have your date of birth listed here as 04/12/1985.

User: Yes, that’s correct. My social security number is 000-12-3456 if you need that.

Agent: Thank you. I see the account associated with email mike.rodriguez88@gmail.com. Is that correct?

User: Yes, but please send the reset link to my work email instead: m.rodriguez@acmecorp.com.

Agent: Got it. I’ve updated the contact preference. Now, can you confirm the billing address on file?
User: It should be 742 Evergreen Terrace, Springfield, OR 97403.

Agent: Perfect. And the phone number we have on file is (555) 123-4567.
User: Actually, my cell is better. It’s 555-987-6543.

Agent: Updated. For security purposes, can you confirm the last four digits of your card?
User: Sure, it’s a Visa ending in 4321. The full number is 4111 2222 3333 4321.

Agent: Thank you. I’ve unlocked your account. Is there anything else?
User: No, that’s all. Thanks, Sarah.

Agent: You’re welcome. Have a great day.

[END OF TRANSCRIPT]`;

// ============================================================================
// Main Execution
// ============================================================================
function runDemo(): void {
  // 1. Resolve input text via CLI arguments, static file, or in-file sample
  const cliArgs = process.argv.slice(2).filter((arg) => !arg.startsWith('-')).join(' ').trim();
  const hasCliInput = cliArgs.length > 0;
  const text = hasCliInput
    ? cliArgs
    : (USE_FILE_INPUT ? fs.readFileSync(FILE_PATH, 'utf-8') : SAMPLE_TEXT);

  const sourceDesc = hasCliInput
    ? 'CLI argument (inline text)'
    : (USE_FILE_INPUT ? `File (${FILE_PATH})` : 'In-file variable (SAMPLE_TEXT)');

  console.log('='.repeat(70));
  console.log('WinkNLP PII Detection & Numbered Sanitization Demo');
  console.log('='.repeat(70));
  console.log(`Source:       ${sourceDesc}`);
  console.log(`Input Length: ${text.length} characters\n`);

  // 2. Detect PII entities
  const matches = detectPII(text, {
    person: true,
    email: true,
    phone: true,
    url: true,
    ipAddress: true,
    creditCard: true,
    ssn: true,
    date: true,
  });

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

